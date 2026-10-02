# Delegate work-per-call budget

A Freenet node stops a delegate call after **5 seconds of wall clock**
(`RuntimeConfig::max_execution_seconds` in freenet-core). A Harvest handler
that needs longer does not fail loudly. The node answers the web app with an
error that names no request and no delegate, and the flow waiting on the
answer hangs (harvest#204).

That is how the launch blocker fixed by harvest#203 reached the live network.
`GetStoreSubkeys` generated an RSA-2048 key inside the delegate on every call,
taking 0.85 s to over 5 s depending on the store key. Nothing in CI could see
it. Native unit tests run about 7x faster than the delegate WASM and have no
limit at all.

This harness closes that gap. It runs the **committed** delegate
(`ui/public/contracts/harvest_delegate.wasm`) under wasmtime with **fuel
metering**, drives it through what the Harvest web app and the node send it,
and fails if any single call consumes more than the budget.

It is its own cargo workspace, like `tests/rehearsal`, so building or locking
it can never move a dependency version the contracts and the delegate compile
against, and therefore can never re-key an artifact.

## Why fuel and not a timer

Fuel counts the WebAssembly instructions the guest executes. The same WASM
fed the same inputs burns the same fuel on every machine and every run. The
host here hands the delegate a seeded RNG and a fixed clock, and every fixture
is built without OS randomness, so the numbers are reproducible to the unit:
repeated runs produce byte-identical output. A wall-clock assertion would be
a flaky test, and flaky tests are broken tests.

The budget is the only place wall-clock time enters, and it enters once, at
calibration (below).

## Running it

A run takes under half a minute on #216's delegate. On a delegate without
the per-call scan bound (V29) it takes about seven minutes: the 64-store
published-script calls are over 800 billion fuel each, and the spaced run
then stops the scenario at the harness's 1,000-billion fuel ceiling.

```sh
cargo run --release --locked --manifest-path tests/delegate-budget/Cargo.toml
# another build of the delegate:
cargo run --release --locked --manifest-path tests/delegate-budget/Cargo.toml -- --wasm path/to/harvest_delegate.wasm
# recalibrate (also times each call unmetered, best of N runs):
cargo run --release --locked --manifest-path tests/delegate-budget/Cargo.toml -- --calibrate 5
```

Exit codes:

* 0: every call is within budget.
* 1: at least one call is over budget.
* 2: the harness could not drive the delegate.

Exit 2 covers a step that was refused or errored, and a delegate that imports
a host function this host does not provide. Each step asserts the answer
variant and that it is not an `Err`, because a refused request is cheap and
would pass the budget for the wrong reason.

## What the host is

`src/host.rs` is the node's side of the delegate ABI, mirroring freenet-core's
`wasm_runtime/delegate/execution.rs` and `native_api.rs` for the nine imports
the delegate declares:

* the seven `freenet_delegate_secrets` functions, with the node's return codes
* `freenet_rand.__frnt__rand__rand_bytes`
* `freenet_time.__frnt__time__utc_now`

Each call works as on the node:

1. A fresh instance.
2. `__frnt_set_id`.
3. Parameters, origin and inbound message are written through
   `__frnt__initiate_buffer`, bincode-encoded with freenet-stdlib 0.8.5, the
   version the delegate is built on.
4. `process(params, origin, inbound)` runs. Only this call is metered.

Also as on the node: linear memory is capped at 256 MiB (4096 pages, the
node's `ResourceLimiter`), the error codes are the node's
(`native_api::error_codes`), and `list_secrets` never shows a key in the
node's reserved `\0freenet-migrate/` namespace.

Application messages carry the Harvest web app's `MessageOrigin::WebApp`.
Contract notifications and the background runs (lifecycle, wake-up) carry no
origin, as the node sends them.

## What it drives

Crypto-heavy handlers first, then the handlers whose cost grows with stored
state, filled to their caps. The caps are read from the delegate's own source
(`MAX_STORE_KEYS`, `MAX_ARMS`, `MAX_KNOWN_STORES`, `MAX_BUYER_CONVERSATIONS`,
`SEEN_CAP`), so raising one there raises the fixture with it; a renamed
constant fails the run.

The ledger and the watch delegation are crate-private types, seeded through
mirrors in `src/fixtures.rs`. Most of their fields are `serde(default)`, so a
mirror that drifts still decodes. The harness therefore compares each
mirror's field names with a copy the delegate wrote itself (the first
store's ledger after its mailbox scans, the merged ledger after the import,
a delegation and one of its watches after `NodeStarted` rewrites them), and
fails the run on any difference.

| step | why it is here |
|---|---|
| `CreateStoreKey` to the 64-key cap, `GetStoreSubkeys` x8 | the #203 call. Its old cost depended on the store key, so one key proves nothing. Every key is created so the export below carries all of them |
| `SignStoreUpdate`, `WrapStoreKeyFor`, `UnwrapStoreKey` | store-key custody. The vault signature is made as the Ghost Key vault makes it |
| `InitEncryptionKey`, `DeriveConversationKeys` with 512 peers, store key and Ghost Key | 512 is the mailbox cap (`MAX_MESSAGES`), the most senders one request can name |
| `RegisterStore`, `ListStores` | registry |
| `SetPaymentXpub`, `DeriveOrderAddress`, `PeekOrderAddresses (10)`, `DeriveOrderAddress` with a foreign published script | BIP-32 derivation. The foreign script forces the full 100-index `PUBLISHED_INDEX_GAP` scan |
| `SetPaymentXpub` and `DeriveOrderAddress` with a seller's published scripts, run after the export (the payment key does not look at it): one full store (`MAX_ORDERS`, 4096) contiguous from the counter, driven to the end; every store full (64 x 4096), ONE call each; one full store with the scripts `PUBLISHED_INDEX_GAP` apart, 32 calls each | the counter is raised past every published order before an address is handed out, and every match pushes the scan's give-up point `PUBLISHED_INDEX_GAP` further. Since #216 one call derives at most `FLOOR_SCAN_BUDGET` (384) indices, keeps the count, and answers that it is still catching up; the web app asks again, and so does the harness, requiring the count to move on each time and the final count (or the address handed out) to be one past the last published script. The 64-store input is real: since #181 a seller has one store per Ghost Key, but one delegate holds one payment key for every store, and the web app's `published_payment_scripts` sends every owned store's scripts. Its per-call cost grows with the request (decoding about 6 MiB, building the set of scripts), not with the scan, so one call shows it. The spaced run takes about 1,400 calls to finish; 32 show its per-call bound. The scripts are derived by the delegate's own `bip32.rs`, compiled into the harness and checked against the delegate's next ten addresses, and the counter is put back after each run |
| instant checkout deciding a request against a full store: an instant `OrderRequest` in the first store's mailbox, then the store GET it asks for answered (with the GET's context) by a store of 4096 paid orders, each with a genuine SPV payment proof (about 18 MiB), on addresses contiguous from the counter; repeated while `decide` refuses with `CatchingUp` | `decide` raises the counter past every script the store has published before it invoices. The harness requires every run that publishes nothing to have kept a higher count short of the store's end (the `CatchingUp` refusal is the one that does), and the last run to publish exactly one order, paying the address one past the store's last. `decide` does not check an order's signature, so the orders are signed by a fixture key at their real size |
| `ArmAutoInvoice` to the 16-arm cap (each watching the 10 upcoming addresses), forced `Heartbeat`, `GetWatchKey`; then every other arm's ledger seeded at its caps (`SEEN_CAP`, `ANSWERED_CAP`, `STATUSES_CAP` for both statuses and oversold orders, `SALES_CAP`, `GAP_ORDERS_CAP`, 99 invoices today) in the delegate's own encoding, and one re-arm that must read the seeded count back | instant checkout. Every arm is taken and full, so the wake-up, resubscribe and export walk the worst state the caps allow |
| tip notification, then a mailbox notification with 512 unread short messages from 512 buyers (the COUNT cap), in the contract's canonical order and passing its `verify` | instant checkout opening every unread message (one X25519 + AES-GCM each). The harness checks the tip was cached and decodes the ledger to check all 512 were recorded as read, so a refused scan cannot pass as a cheap one |
| a second mailbox notification at the BYTE cap: 512 new messages, each size class as full as `SIZE_CLASS_CAPS` allows (24/64/128/296, about 3.3 MiB of ciphertext), canonical order, passing `verify` | anyone can write to a store's mailbox, and decoding, hashing and decrypting grow with bytes. 2.6x the budget on V29, fixed in #216: see below |
| a third mailbox notification at the byte cap, each plaintext a valid message with an extra field of one-byte integers (`hostile_mailbox`) | anyone can encrypt their own plaintext to a store's inbox, and this one is the slowest to decode. The harness decrypts every message natively with the delegate's key and associated data first (a message the delegate cannot open is refused cheaply), and checks afterwards that every one of its digests is in the ledger's seen list (the list is already at `SEEN_CAP`, so its length proves nothing) |
| the watch delegations at their caps (`MAX_DELEGATIONS`, each with `WATCHED_CAP` watches that all count, and its subscription lists full), seeded straight into the secret store in the delegate's own encoding, for bridges every store trusts; then the tip read's answer (every store's status), a re-arm, a forced `Heartbeat`, the wake-up (also with every mailbox waiting) and `NodeStarted` | every store's status and heartbeat walks every delegation's watches, and the wake-up looks at each delegation for its one read. The harness checks every status counts the delegation's watches, that the wake-up went on to a canary read, and that the node start rewrote every delegation |
| `Installed`, `NodeStarted`, heartbeat wake-up (also with every store's mailbox waiting to be re-read) | runs the node starts on its own. Each must answer (resubscribes, a heartbeat), so an early return cannot pass; the waiting wake-up must ask for every store's mailbox |
| one of that wake-up's mailbox reads answered, with the context it carried, by the first store's mailbox at the byte cap with slow plaintexts none of it read yet | the read the wake-up asks for is decided as a mailbox change is (`on_mailbox_retry`). The harness checks the answer recorded some of its messages as read |
| `StoreBuyerConversation` x256, `ListBuyerConversations (256)` | the buyer's conversation cap; the harness checks 256 come back |
| `KeepPurchase` (paid, genuine SPV proof) into an empty store, then 1022 seeded straight into the secret store in the delegate's own encoding, then `KeepPurchase` of the 1024th at the last conversation, then `ListKeptPurchases (1024)` | the kept-purchase cap. A keep ends by listing everything kept, so a keep into a full store is its worst case. The harness checks all 1024 come back |
| `KeepPurchase` naming a conversation this node does not hold, store full | the lookup misses and the scan of every conversation runs to the end before the keep is refused. The harness checks the refusal is that one ("does not hold the conversation") |
| `RememberStore` to the 1024 cap, `ListRememberedStores (1024)` | the buyer's remembered stores; the harness checks 1024 come back |
| `ImportMigratedSecret` of one full ledger into another | what a successor does with each ledger a predecessor exports: decode both, merge, encode. The harness checks the outcome is `Written` and that the ledger written holds the incoming ledger's newest sale, with `sales`, `gap_orders`, `statuses` and `oversold` at their caps |
| `ExportSecrets` | the migration export with the state above, run last because it disarms instant checkout. The harness checks it carries at least as many entries as were seeded, and every seeded instant-checkout ledger by key |

## Calibration

The budget is **4,000,000,000 fuel per call**: about one second of this
delegate's work on the reference machine, a fifth of the node's 5 s limit.

Measured on **nova** (Intel i9-9900K, 3.6 GHz base, 16 threads) on 2026-09-30
with `--calibrate 5`, at a load average of 9-13 from other work. The
unmetered runs use an engine configured like the node's: Cranelift
`OptLevel::None` and epoch interruption on. Time spent in host functions is
measured separately and was under 3 ms for every call, so these rates are the
guest's own:

| workload | calls | fuel/s |
|---|---|---:|
| arithmetic-heavy crypto (RSA prime search, X25519, secp256k1, Ed25519) | `GetStoreSubkeys` (old), `DeriveConversationKeys`, mailbox scan, BIP-32 derivation, `KeepPurchase` | 9.5 - 11.2 billion |
| allocation- and copy-heavy (CBOR decode and encode of large records) | `ListKeptPurchases (1024)` | 5.0 billion |
| same | `ExportSecrets` | 4.1 billion |

The two kinds differ by more than 2x. One likely reason: wasmtime charges a
`memory.copy` or `memory.fill` one unit of fuel however many bytes it moves. The budget takes the **slowest** measured rate, so 4.0 billion fuel is
about 1.0 s for copy-heavy code and about 0.4 s for crypto. Calls under 1 ms
are too short to time reliably and were not used.

Cross-check against the live network. The #203 probe timed the old
`GetStoreSubkeys` on a real 0.2.140 node on nova at 0.85-4.6 s (load about 9).
This harness puts the same delegate's eight keys at 10.2-49.7 billion fuel and
1.04-5.15 s unmetered, the same range.

What the 5x margin is for (fuel sees none of these):

* a slower CPU than nova
* a node under load. The limit is wall clock, and nova at load 9-18 turned 1
  timeout in 30 into 7 in 30 in the #203 investigation
* host-function time on a real node, whose secret store is encrypted and on
  disk
* the bulk-memory undercount above

**To recalibrate** after a wasmtime or freenet-core engine change, or on new
reference hardware: run with `--calibrate 5`, read the `fuel/s (guest)`
column, and set `BUDGET_FUEL` in `src/main.rs` to one second at the slowest
rate among calls that take at least about 50 ms. Update this section.

## Evidence the check catches the bug

Same harness, same scenario, two builds of the delegate:

| delegate | `GetStoreSubkeys`, 8 store keys | result |
|---|---|---|
| main before #203 (blake3 `d8088bf5…`, the build live when the bug was found) | 10,167,507,014 - 49,739,927,758 fuel (2.5x - 12.4x budget), 1.0 - 5.1 s unmetered | **exit 1**, all eight over |
| #203, committed on main since (blake3 `cbe71dd9…`, RSA derivation removed) | 2,455,085 - 2,457,153 fuel (0.06%) | exit 0 |

Largest calls with every cap above filled, on the delegate main shipped
before #216 (`cbe71dd9…`, V29) and on #216's (`7270ec63…` before the scan
bound, `69a6d296…` with it), committed since. Both columns are one run each
of the harness at commit `c4e9a29`, so every row is the same scenario. A run
of several calls is shown as its most expensive call:

| call | V29 | #216 |
|---|---:|---:|
| `SetPaymentXpub`, 64 full stores' published scripts (262,144), one call | 834,583,191,788 (**20864.6%, over**) | 7,849,863,318 (**196.2%, over**), still catching up |
| `DeriveOrderAddress`, same | 834,576,950,789 (**20864.4%, over**) | 7,842,882,740 (**196.1%, over**), still catching up |
| `SetPaymentXpub`, one full store's published scripts (4,096) | 13,050,325,660 (**326.3%, over**), 1 call | 1,322,330,495 (33.1%), 11 calls |
| `DeriveOrderAddress`, same | 13,049,967,370 (**326.2%, over**), 1 call | 1,315,349,403 (32.9%), 11 calls |
| `SetPaymentXpub`, one full store's scripts 100 apart | past the 1,000-billion ceiling (stops the scenario) | 1,322,007,531 (33.1%), 32 calls, not finished |
| `DeriveOrderAddress`, same | (not reached) | 1,315,026,815 (32.9%), 32 calls, not finished |
| instant decide against a store of 4,096 paid orders | 26,110,253,849 (**652.8%, over**), 1 run | 8,722,602,646 (**218.1%, over**), 11 runs (10 at about 7.65 billion) |
| heartbeat wake-up, 8 full watch delegations | 105,767,562,302 (**2644.2%, over**) | 1,844,244,959 (46.1%) |
| same, every store's mailbox waiting to be re-read | 105,758,544,149 (**2644.0%, over**) | 1,933,038,739 (48.3%) |
| tip read answered, 8 full watch delegations | 101,067,360,752 (**2526.7%, over**) | 1,207,268,765 (30.2%) |
| `ArmAutoInvoice`, 8 full watch delegations | 6,330,624,918 (**158.3%, over**) | 232,229,633 (5.8%) |
| forced `Heartbeat`, 8 full watch delegations | 6,132,743,453 (**153.3%, over**) | 170,641,580 (4.3%) |
| mailbox notification at the byte cap, plaintexts built to be slow to decode | 13,710,079,810 (**342.8%, over**) | 1,963,465,605 (49.1%) a run, 7 runs |
| the wake-up's mailbox read answered, same mailbox | 13,640,295,281 (**341.0%, over**) | 1,866,648,169 (46.7%) a run |
| mailbox notification at the byte cap | 10,389,383,503 (**259.7%, over**) | 1,359,137,965 (34.0%) a run, 7 runs |
| `ExportSecrets`, 16 full ledgers | 8,074,625,933 (**201.9%, over**) | 1,083,357,132 (27.1%) |
| heartbeat wake-up, 16 full ledgers | 7,659,484,431 (**191.5%, over**) | 1,044,678,002 (26.1%), with 15 of the 16 retry flags missing (the seeded ledgers'; a missing flag means reading the ledger, the worst case) |
| same, every store's mailbox waiting to be re-read | 7,660,135,838 (**191.5%, over**) | 168,491,440 (4.2%) |
| `KeepPurchase`, the 1024th | 3,192,943,691 (79.8%) | 2,216,880,431 (55.4%) |
| mailbox notification, 512 short messages | 3,189,665,483 (79.7%) | 794,658,923 (19.9%) a run, 4 runs |
| `ImportMigratedSecret`, full ledger into a full ledger | 3,079,750,200 (77.0%) | 1,254,631,664 (31.4%) |
| mailbox notification, one instant request | 2,940,227,930 (73.5%) | 134,960,678 (3.4%) |
| `ListKeptPurchases (1024)` | 2,906,374,863 (72.7%) | 2,201,595,405 (55.0%) |

**#216 is still over budget in two places.** The published-script scan is
bounded per call since `FLOOR_SCAN_BUDGET` (384 derivations, about 1.2
billion fuel), and one store's scripts, contiguous or spaced, now cost a
third of the budget a call. What is left grows with the INPUT, not the scan:

* One request carrying every store's scripts (262,144, about 6 MiB) costs
  about 2x the budget before the scan starts.
* Instant checkout's `decide` against a store of 4,096 paid orders (about
  18 MiB of state) costs about 1.9x the budget on every catch-up run and
  2.2x on the run that invoices, most of it in reading the store rather
  than in the 384 derivations.

The fixes belong in the delegate; until they land this harness is red on
#216.

**The V29 over-budget rows were real findings, not harness artefacts.**

* The byte-cap mailbox: any buyer can fill a store's mailbox this way, and
  instant checkout's first scan of it did 2.6x the budget: the sort hashed
  every ciphertext on every comparison, the mailbox was decoded generically
  (ciphertexts are CBOR integer arrays, not byte strings), and every new
  message was decrypted in one run.
* The wake-up and the export decoded every arm's whole ledger (the wake-up
  twice). A busy seller's ledgers reach these caps over weeks of instant
  orders, and the wake-up runs every few minutes: if it runs past the node's
  limit, heartbeats stop and the store reads as closed.
* Every store's status and heartbeat decoded every delegation and, per
  watch of every watch, the payment key and every arm
  (`watch_delegation::vouched`), so the work grew as stores x delegations x
  watches x stores. A seller who has delegated watching for a few bridges
  gets there by using it: the watches accumulate as addresses are refilled.

#216 fixes them in the delegate (a re-key): each digest once, a bounded and
randomly ordered opening per mailbox run with a retry flag the wake-up
reads, the delegations and payment key read once per run, a status that
reads only the ledger fields it shows, and an export written without the
stdlib's per-byte encoding. The PR has the details.

Apart from those two, every call on #216 is within budget. The ones to watch each grow with
a collection; at the caps the largest use 46-55% of the budget (`KeepPurchase`
into a full store, `ListKeptPurchases (1024)`, the slow-plaintext mailbox run
and its retry read, and the wake-up with full watch delegations).

Secret writes are judged too (`BUDGET_WRITES`, 64 per call): on a node each
is an encrypted, fsync'd file write that fuel does not see. The most any call
makes today is 18 (the wake-up with watch delegations: one per arm, and the
delegation it reads for).

## What it does not cover

* **Handlers not driven**:
  * `SetWatchDelegation` and `UpdateWatchDelegation` need a Ghost Key
    certificate under Freenet's authority. The delegations are seeded
    instead: the delegation is signed by the Ghost Key as the vault signs it,
    and the certificate is `tests/fixtures/ghostkey-certificate.pem`, which
    the paths measured never check. A wake-up that SENDS a watch request
    (signs an inbox entry) is not driven.
  * The rest of the instant-checkout decide path: a batch of up to 16
    instant requests (one is driven), and the store UPDATE answer.
  * A mailbox full of instant `OrderRequest`s: unlike the texts above, these
    are not marked read and are reopened on every notification.
  * `ImportMigratedSecret` of the RSA key (`harvest:rsa_pk:*`, which
    parses an RSA key; the ledger import is driven above),
    `ExportBuyerConversation`
    and `ImportBuyerConversation`, and the migration markers
    (`GetMigrationMarker`, `SetMigrationMarker`, `GetPredecessorMarker`,
    `RecordPredecessorMarker`).
  * `GetRsaPublicKey`, `SetStoreArchived`, `ForgetBuyerConversation`,
    `MarkConversationBackedUp`.
  * The Bitcoin delegate's `Watch`, `Unwatch`, `ListWatched`,
    `AssociateOrder`, `ConfigureBridge`, `GetBridge`, `GetPaymentXpub`.
  * `CreateListing`, which is a stub.

  To add one, add a step to `scenario()` in `src/main.rs` with real inputs,
  and assert its answer (or the state it writes).
* **Record sizes.** Kept purchases are seeded at the size a minimal paid
  order has. A record may be much larger (`MAX_KEPT_PURCHASE_BYTES`, with a
  complaint and longer proofs); wasmtime charges a bulk copy one unit of fuel
  whatever its size, so larger records cost more time than fuel shows.
* **Host time beyond writes.** Fuel bounds guest work and `BUDGET_WRITES`
  bounds writes; secret reads are reported (the "host calls" column, up to
  about 4,600 for the export) but not judged. On a node each read is a file
  read and a decrypt.
* **Slow hardware.** The 5x margin is measured on a desktop-class CPU. A
  Raspberry Pi-class peer can run unoptimised Cranelift code several times
  slower, which uses most of that margin on its own; the calls at 46-55% are
  then the ones at risk.
* **Anything but one call.** The node's limit is per call. A flow that makes
  many calls is bounded per call, not in total.
