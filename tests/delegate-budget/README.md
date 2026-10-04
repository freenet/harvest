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

A run takes about a minute and a half on #216's delegate. On V29 it takes
about seven minutes: the 64-store published-script calls are over 800
billion fuel each, and the spaced run then stops the scenario at the
harness's 1,000-billion fuel ceiling.

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
| instant checkout deciding a request against a full store: an instant `OrderRequest` in the first store's mailbox, then the store GET it asks for answered (with the GET's context) by a store of 4096 paid orders, each with a genuine SPV payment proof (about 18 MiB), on addresses contiguous from the counter; repeated while `decide` refuses with `CatchingUp` | `decide` adds the store's published scripts to those the delegate holds and moves the payment key's scan on by a budget before it invoices; until the scan is complete it refuses (`CatchingUp`) and the request waits. The harness requires every run that publishes nothing to have been refused for that reason (the store's status says so), and the last run to publish exactly one order, paying the address one past the store's last. `decide` does not check an order's signature, so the orders are signed by a fixture key at their real size. |
| a heartbeat wake-up with one full store's scripts held and none scanned, the first with every store's mailbox waiting to be re-read too, repeated until the catch-up is complete (each wake-up must move it on), then one more | a wake-up moves the payment key's catch-up on by itself (`advance_on_wakeup`, `WAKEUP_SCAN_BUDGET`), on top of all its other work, so instant checkout catches up with no tab open. The one after must change nothing. The scan's cursor is read from the delegate's secret (`[tag_len u16][tag][generation u32][base u32][at u32]`, mirrored); a cursor of another shape fails the run |
| `ArmAutoInvoice` to the 16-arm cap (each watching the 10 upcoming addresses), forced `Heartbeat`, `GetWatchKey`; then every other arm's ledger seeded at its caps (`SEEN_CAP`, `ANSWERED_CAP`, `STATUSES_CAP` for both statuses and oversold orders, `SALES_CAP`, `GAP_ORDERS_CAP`, 99 invoices today) in the delegate's own encoding, and one re-arm that must read the seeded count back | instant checkout. Every arm is taken and full, so the wake-up, resubscribe and export walk the worst state the caps allow |
| tip notification, then a mailbox notification with 512 unread short messages from 512 buyers (the COUNT cap), in the contract's canonical order and passing its `verify` | instant checkout opening every unread message (one X25519 + AES-GCM each). The harness checks the tip was cached and decodes the ledger to check all 512 were recorded as read, so a refused scan cannot pass as a cheap one |
| a second mailbox notification at the BYTE cap: 512 new messages, each size class as full as `SIZE_CLASS_CAPS` allows (24/64/128/296, about 3.3 MiB of ciphertext), canonical order, passing `verify` | anyone can write to a store's mailbox, and decoding, hashing and decrypting grow with bytes. 3.5x the budget on V29, fixed in #216: see below |
| a third mailbox notification at the byte cap, each plaintext a valid message with an extra field of one-byte integers (`hostile_mailbox`) | anyone can encrypt their own plaintext to a store's inbox, and this one is the slowest to decode. The harness decrypts every message natively with the delegate's key and associated data first (a message the delegate cannot open is refused cheaply), and checks afterwards that every one of its digests is in the ledger's seen list (the list is already at `SEEN_CAP`, so its length proves nothing) |
| the watch delegations at their caps (`MAX_DELEGATIONS`, each with `WATCHED_CAP` watches that all count, and its subscription lists full), seeded straight into the secret store in the delegate's own encoding, for bridges every store trusts; then the tip read's answer (every store's status), a re-arm, a forced `Heartbeat`, the wake-up (also with every mailbox waiting) and `NodeStarted` | every store's status and heartbeat walks every delegation's watches, and the wake-up looks at each delegation for its one read. The harness checks every status counts the delegation's watches, that the wake-up went on to a canary read, and that the node start rewrote every delegation |
| `Installed`, `NodeStarted`, heartbeat wake-up (also with every store's mailbox waiting to be re-read) | runs the node starts on its own. Each must answer (resubscribes, a heartbeat), so an early return cannot pass; the waiting wake-up must ask for every store's mailbox |
| one of that wake-up's mailbox reads answered, with the context it carried, by the first store's mailbox at the byte cap with slow plaintexts none of it read yet | the read the wake-up asks for is decided as a mailbox change is (`on_mailbox_retry`). The harness checks the answer recorded some of its messages as read |
| `StoreBuyerConversation` x256, `ListBuyerConversations (256)` | the buyer's conversation cap; the harness checks 256 come back |
| `KeepPurchase` (paid, genuine SPV proof) into an empty store, then 1022 seeded straight into the secret store in the delegate's own encoding, then `KeepPurchase` of the 1024th at the last conversation, then `ListKeptPurchases (1024)` | the kept-purchase cap. A keep ends by listing everything kept, so a keep into a full store is its worst case. The harness checks all 1024 come back |
| `KeepPurchase` naming a conversation this node does not hold, store full | the lookup misses and the scan of every conversation runs to the end before the keep is refused. The harness checks the refusal is that one ("does not hold the conversation") |
| `RememberStore` to the 1024 cap, `ListRememberedStores (1024)` | the buyer's remembered stores; the harness checks 1024 come back |
| `ImportMigratedSecret` of one full ledger into another | what a successor does with each ledger a predecessor exports: decode both, merge, encode. The harness checks the outcome is `Written` and that the ledger written holds the incoming ledger's newest sale, with `sales`, `gap_orders`, `statuses` and `oversold` at their caps |
| `ExportSecrets` | the migration export with the state above, after every instant-checkout step because it disarms instant checkout. The harness checks it carries at least as many entries as were seeded, and every seeded instant-checkout ledger by key |
| a seller's published scripts, after the export (the payment key does not look at it), each run from the same secrets (the key active, and the one script the foreign-script step above sent already held: since #216 a script sent with `DeriveOrderAddress` is kept like any other): sent as `AddPublishedScripts` requests of `MAX_SCRIPTS_PER_REQUEST` (4096), then `SetPaymentXpub` (with `resume` when asked again) or `DeriveOrderAddress`, repeated while the delegate answers `CATCHING_UP_PREFIX`. One full store contiguous from the counter, driven to the end; every store full (64 x 4096 = `MAX_HELD`), 64 additions each measured and then ONE scan call; one full store with its scripts `PUBLISHED_INDEX_GAP` apart, 32 calls | no address is handed out, and no key made active, until the counter is past every published script the delegate holds; every match pushes the scan's give-up point `PUBLISHED_INDEX_GAP` further, so the scan is cut into budgets (`FLOOR_SCAN_BUDGET`). The harness requires the scan's cursor (in the refusal, `{counter}/{cursor}`) to move on with every call and the final count, or the address handed out, to be one past the last script. The 64-store input is real: one delegate holds one payment key for every store, and the web app sends every owned store's scripts. The spaced run takes about 1,400 calls to finish; 32 show its per-call bound. The scripts are derived by the delegate's own `bip32.rs`, compiled into the harness and checked against the delegate's next ten addresses. A delegate without `AddPublishedScripts` (V29) is sent the scripts with the request, as its web app did |
| a new device: a key that is not the active one, entered after its store's 4096 scripts are sent; then a stale resume | the new key's scan runs in the pending slot while the active key goes on: after one call the harness checks the new key is pending beside the active one, and at the end that it is active at count 4096 with the pending slot emptied. Then tab A's new key part-way, tab B enters another key, and tab A's `resume` must be refused with `KEY_SUPERSEDED_PREFIX` and change nothing. Not on V29, which has no pending slot |

## Calibration

The budget is **3,000,000,000 fuel per call**: about one second of this
delegate's work on the reference machine, a fifth of the node's 5 s limit.

Measured on **nova** (Intel i9-9900K, 3.6 GHz base, 16 threads) on
2026-10-02 with `--calibrate 5`, on the delegate #216 shipped (`ed88aa21…`, V30), at a
load average of 10-13 from other work. The unmetered runs use an engine
configured like the node's (`create_engine` in freenet-core's
`engine/wasmtime_engine.rs`): Cranelift `OptLevel::None`, epoch
interruption on, and the node's memory layout, a 256 MiB reservation with a
64 KiB guard and no growth reservation. That layout makes Cranelift emit an
explicit bounds check on memory accesses, which the default 4 GiB layout
elides: it changes no fuel count, but measured side by side with the
default layout it slows the guest by about 30%. Time spent in host functions
is measured separately and was under 5 ms for every call, so these rates
are the guest's own:

| workload | calls | fuel/s |
|---|---|---:|
| arithmetic-heavy crypto (X25519, secp256k1, Ed25519, BIP-32) | `DeriveConversationKeys`, `ListBuyerConversations`, the published-script scans, mailbox scans | 5.7 - 7.5 billion |
| allocation- and copy-heavy (CBOR decode and encode of large records) | `ImportMigratedSecret`, `AddPublishedScripts`, `ListKeptPurchases (1024)`, `KeepPurchase` into a full store | 3.9 - 4.2 billion |
| same | `ExportSecrets` | 3.1 billion |

Two more runs the same day gave the export 2.9 and 3.1 billion. The two
kinds differ by about 2x. One likely reason: wasmtime charges a
`memory.copy` or `memory.fill` one unit of fuel however many bytes it
moves. The budget takes the **slowest** measured rate, rounded down, so 3.0
billion fuel is about 1.0 s for copy-heavy code and about 0.4 s for crypto.
Calls under about 50 ms are too short to time reliably on a loaded machine
and were not used.

Until 2026-10-02 the budget was 4,000,000,000, calibrated on 2026-09-30 with
wasmtime's default memory layout (the export then ran at 4.1 billion fuel/s).
That budget was optimistic by the 30% above, and instant checkout's decide
was held to a tighter 70% of it as a margin for that. With the budget taken
from the node's layout every call is held to the same 100%.

Cross-check against the live network. The #203 probe timed the old
`GetStoreSubkeys` on a real 0.2.140 node on nova at 0.85-4.6 s (load about 9).
This harness put the same delegate's eight keys at 10.2-49.7 billion fuel and
1.04-5.15 s unmetered, the same range. That comparison was made on
2026-09-30 with the default memory layout and has not been repeated with
the node's.

What the 5x margin under the node's 5 s limit is for (fuel sees none of
these):

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
| main before #203 (blake3 `d8088bf5…`, the build live when the bug was found) | 10,167,507,014 - 49,739,927,758 fuel (3.4x - 16.6x the budget), 1.0 - 5.1 s unmetered | **exit 1**, all eight over |
| #203, committed on main since (blake3 `cbe71dd9…`, RSA derivation removed) | 2,455,085 - 2,457,153 fuel (0.08%) | exit 0 |

Largest calls with every cap above filled, on the delegate main shipped
before #216 (`cbe71dd9…`, V29) and on the one #216 shipped (`ed88aa21…`,
V30), against the 3,000,000,000 budget. Both columns are one run each of the
harness at commit `e3497ab`, so every row is the same scenario. The third
column is the delegate committed on `fix/delegate-rekey-batch2` after
#215 was merged in (`9c8b3b3e…`, built at `71cd80a`), one run of the harness
there: its fixtures are fuller (every arm carries the window it read clear,
every kept conversation and every seller store its sent digests at their
caps), which is most of why the wake-ups and `ExportSecrets` move. A row of
several calls shows its most expensive call. V29 is sent the published
scripts with each request, as its web app did; it has no
`AddPublishedScripts`, pending slot or wake-up catch-up:

| call | V29 | #216 (`ed88aa21…`, V30) | this branch (`9c8b3b3e…`) |
|---|---:|---:|---:|
| instant decide against a store of 4,096 paid orders | 26,110,253,849 (**870.3%, over**) | 2,551,629,593 (85.1%), 11 runs | 2,578,928,712 (86.0%) |
| heartbeat wake-up, 8 full watch delegations | 105,767,562,302 (**3525.6%, over**) | 1,845,602,573 (61.5%) | 1,658,531,024 (55.3%) |
| same, every store's mailbox waiting to be re-read | 105,758,544,149 (**3525.3%, over**) | 1,934,399,600 (64.5%) | 1,757,456,404 (58.6%) |
| tip read answered, 8 full watch delegations | 101,067,360,752 (**3368.9%, over**) | 607,539,117 (20.3%) | 740,490,991 (24.7%) |
| `ArmAutoInvoice`, 8 full watch delegations | 6,330,624,918 (**211.0%, over**) | 192,676,953 (6.4%) | 304,238,894 (10.1%) |
| forced `Heartbeat`, 8 full watch delegations | 6,132,743,453 (**204.4%, over**) | 170,783,473 (5.7%) | 281,045,054 (9.4%) |
| heartbeat wake-up moving one store's catch-up on, to the end | (not on V29: no `AddPublishedScripts`) | 2,229,458,742 (74.3%), 32 wake-ups | 1,744,641,102 (58.2%) |
| same, the first of them with every store's mailbox waiting to be re-read | (not on V29: no `AddPublishedScripts`) | 2,284,126,244 (76.1%) | 1,839,122,928 (61.3%) |
| heartbeat wake-up once that catch-up is complete | (not on V29: no `AddPublishedScripts`) | 551,384,208 (18.4%) | 907,953,374 (30.3%) |
| `SetPaymentXpub`, one full store's published scripts (4,096) | 13,050,327,747 (**435.0%, over**) | 1,221,560,677 (40.7%), 11 calls | 1,221,581,753 (40.7%) |
| `DeriveOrderAddress`, same | 13,049,967,370 (**435.0%, over**) | 1,213,923,367 (40.5%), 11 calls | 1,213,944,417 (40.5%) |
| `SetPaymentXpub`, a new key, its store's 4,096 scripts (pending, then made active) | (not on V29: no `AddPublishedScripts`) | 1,222,212,045 (40.7%), 11 calls | 1,222,215,811 (40.7%) |
| `AddPublishedScripts`, 4,096 scripts, the 64th chunk of 64 full stores | (not on V29: no `AddPublishedScripts`) | 445,154,360 (14.8%), 64 chunks | 445,158,076 (14.8%) |
| `SetPaymentXpub`, 64 full stores' scripts held (262,144), one call | 834,583,189,262 (**27819.4%, over**) | 1,228,125,142 (40.9%) | 1,228,146,218 (40.9%) |
| `DeriveOrderAddress`, same | 834,576,950,789 (**27819.2%, over**) | 1,220,487,832 (40.7%) | 1,220,508,882 (40.7%) |
| `SetPaymentXpub`, one full store's scripts 100 apart (32 calls, not finished) | past the 1,000-billion ceiling (stops the scenario) | 1,221,493,862 (40.7%), 32 calls | 1,221,514,968 (40.7%) |
| `DeriveOrderAddress`, same | (not reached) | 1,213,856,649 (40.5%), 32 calls | 1,213,877,729 (40.5%) |
| mailbox notification at the byte cap, plaintexts built to be slow to decode | 13,710,079,810 (**457.0%, over**) | 1,963,482,942 (65.4%), 7 runs | 1,984,622,730 (66.2%) |
| the wake-up's mailbox read answered, same mailbox | 13,640,295,281 (**454.7%, over**) | 1,866,657,821 (62.2%) | 1,877,984,277 (62.6%) |
| mailbox notification at the byte cap | 10,389,383,503 (**346.3%, over**) | 1,359,155,301 (45.3%), 7 runs | 1,380,157,941 (46.0%) |
| `ExportSecrets`, 16 full ledgers | 8,074,583,065 (**269.2%, over**) | 1,083,991,246 (36.1%) | 1,471,095,035 (49.0%) |
| heartbeat wake-up, 16 full ledgers | 7,659,484,431 (**255.3%, over**) | 456,289,297 (15.2%) | 594,141,505 (19.8%) |
| same, every store's mailbox waiting to be re-read | 7,660,135,838 (**255.3%, over**) | 169,034,647 (5.6%) | 307,069,538 (10.2%) |
| `KeepPurchase`, the 1024th | 3,192,943,691 (**106.4%, over**) | 2,217,682,277 (73.9%) | 2,217,700,871 (73.9%) |
| mailbox notification, 512 short messages | 3,189,665,483 (**106.3%, over**) | 794,676,259 (26.5%), 4 runs | 815,650,004 (27.2%) |
| `ImportMigratedSecret`, full ledger into a full ledger | 3,079,750,200 (**102.7%, over**) | 1,255,545,434 (41.9%) | 1,255,577,063 (41.9%) |
| mailbox notification, one instant request | 2,940,227,930 (98.0%) | 135,079,615 (4.5%) | 160,962,441 (5.4%) |
| `ListKeptPurchases (1024)` | 2,906,374,863 (96.9%) | 2,202,396,247 (73.4%) | 2,202,396,316 (73.4%) |
| `DeriveConversationKeys`, 512 peers | (not driven) | (not driven) | 2,667,647,586 (88.9%) |
| `ListBuyerConversations`, 256, every digest cap full | (not driven) | (not driven) | 1,329,857,890 (44.3%) |
| mailbox notification, 512 instant requests from 512 buyers | (not driven) | (not driven) | 1,352,164,704 (45.1%) |

**The V29 over-budget rows were real findings, not harness artefacts.**

* The byte-cap mailbox: any buyer can fill a store's mailbox this way, and
  instant checkout's first scan of it did 3.5x the budget: the sort hashed
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
* The counter was raised past a seller's published orders in one call, with
  every script sent in that request: one derivation per index, about 3.2
  million fuel each, so one full store's orders were 4.4x the budget and
  every store's far past the node's limit. Instant checkout's decide did the
  same scan and decoded every order's payment proof as well.

#216 fixes them in the delegate (a re-key): each digest once, a bounded and
randomly ordered opening per mailbox run with a retry flag the wake-up
reads, the delegations and payment key read once per run, a status that
reads only the ledger fields it shows, an export written without the
stdlib's per-byte encoding, published scripts held by the delegate and
scanned a bounded number of indices a call (and a wake-up), and a light
read of the store for decide. The PR has the details.

**Every call on the delegates measured since #216 is within budget.** The published-script
scan is cut into budgets (`FLOOR_SCAN_BUDGET`, 384 derivations, and 128 a
wake-up) and the scripts are held by the delegate rather than sent with
every request, so the scan costs about 41% a call whatever the scripts, and
feeding the full 262,144 costs at most 15% a request. Instant checkout reads
a store in one light pass and feeds its scripts once.

The calls to watch each grow with a collection: instant checkout's decide
against a full store of 4,096 paid orders (about 85%), a wake-up moving the
payment counter's catch-up on (about 76%), `KeepPurchase` into a full store
and `ListKeptPurchases (1024)` (about 74%), and the slow-plaintext mailbox
run, its retry read and the wake-up with full watch delegations (about
62-65%). The aim for such a call is about 60%
of the budget at its cap; that is a guideline, and these are accepted: the
budget is itself a fifth of the node's 5 s limit, taken at the slowest rate
measured with the node's engine. Until 2026-10-02 decide was held to 70% of
an older budget that was 30% too generous (see Calibration); that ceiling
is gone.

**The next re-key (harvest#198 lane, branch `fix/delegate-rekey-batch2`)**
moves one row: `DeriveConversationKeys` for 512 peers, store key and Ghost
Key, from 1,506,290,189 (50.2%) on the delegate #216 shipped (`ed88aa21…`, V30) to
2,667,647,573 (88.9%), now the largest call. The delegate refuses twins of a
buyer's X25519 tag, which costs a subgroup check per peer; the check is
variable time, since dalek's constant-time `is_torsion_free` put it at
100.6%. Instant checkout checks only an opened instant request, so the
mailbox rows do not move (one instant request: 4.5% to 4.6%). Both columns
from one harness build, run on each WASM with `--wasm`.

The same branch adds the sent-digest and read-state requests. With every
kept conversation's digests at their cap (128 each, seeded in the
delegate's encoding): `ListBuyerConversations (256)` 44.3% (34.3% without
digests), `NoteBuyerSent` and `MarkConversationSeen` under 0.1%; with every
store's seller digests at their cap (1,024 each, 64 stores):
`NoteSellerSent` under 0.1%, `ListSellerSent (1024)` 0.6%.

harvest#198 on the same branch raises the window (`MAX_UPCOMING_ADDRESSES`)
from 10 to 25, so every call that derives it costs more: `ArmAutoInvoice`
2.2% to 5.4%, `PeekOrderAddresses` 2.1% to 5.3%, the tip read with full
delegations 20.3% to 24.2%, the plain heartbeat wake-up 15.2% to 18.9%.
The wake-up with full delegations first doubled (61.5% to 122.9%, over),
because each delegation derived the window twice; it is now derived once
per wake-up for every delegation, and that row is 43.9% (the catch-up
wake-ups 50.3-53.4%, from 74.4-76.2%).

Review round 1 of the same branch gives every arm a second list of up to
25 scripts (`vetted_scripts`, the window read clear), which every arm read
decodes: the wake-up with full delegations 43.9% to 55.3%, the catch-up
wake-ups to 58.2-61.3%, the plain wake-up 18.9% to 19.8%.

A mailbox full of valid instant requests, 512 buyers, each request paying
the subgroup check on its tag in `open_instant`: 45.1% of a call for the
run that opens them.

Secret writes are judged too (`BUDGET_WRITES`, 64 per call): on a node each
is an encrypted, fsync'd file write that fuel does not see. The most any call
makes today is 18 (the wake-up with watch delegations: one per arm, and the
delegation it reads for).

## What it does not cover

* **Listing photos (#215).** Instant checkout's decide reads a store whose
  one listing names no images. A listing may name up to
  `MAX_IMAGES_HARD` (8) photo references, and nothing caps how many
  listings a store holds, so a store of many photographed listings adds
  per-call cost (the light store read passes over every listing's terms)
  that no row here measures; there is no cap to fill it to.
* **Handlers not driven**:
  * `SetWatchDelegation` and `UpdateWatchDelegation` need a Ghost Key
    certificate under Freenet's authority. The delegations are seeded
    instead: the delegation is signed by the Ghost Key as the vault signs it,
    and the certificate is `tests/fixtures/ghostkey-certificate.pem`, which
    the paths measured never check. A wake-up that SENDS a watch request
    (signs an inbox entry) is not driven.
  * The rest of the instant-checkout decide path: a batch of up to 16
    instant requests (one is driven), and the store UPDATE answer.
  * Published scripts past `MAX_HELD` (the oldest dropped), and
    `DeriveOrderAddress` carrying scripts itself on #216 (an older web app):
    the harness sends them as `AddPublishedScripts`.
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
* **Mirror drift below the top level.** The ledger and watch-delegation
  mirrors are compared with the delegate's own encoding by top-level field
  names only (and, for a delegation, one watch's field names). A nested type
  that gains, loses or retypes a field (`Sale`, `Oversold`, the delegation
  body) is not caught there; only where a step's answer depends on it.
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
  slower, which uses most of that margin on its own; the calls at 73-85% are
  then the ones at risk.
* **Anything but one call.** The node's limit is per call. A flow that makes
  many calls is bounded per call, not in total.
