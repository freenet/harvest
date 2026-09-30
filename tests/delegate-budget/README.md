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

Application messages carry the Harvest web app's `MessageOrigin::WebApp`.
Contract notifications and the background runs (lifecycle, wake-up) carry no
origin, as the node sends them.

## What it drives

Crypto-heavy handlers first, then the handlers whose cost grows with stored
state, filled to their caps:

| step | why it is here |
|---|---|
| `CreateStoreKey` x8, `GetStoreSubkeys` x8 | the #203 call. Its old cost depended on the store key, so one key proves nothing |
| `SignStoreUpdate`, `WrapStoreKeyFor`, `UnwrapStoreKey` | store-key custody. The vault signature is made as the Ghost Key vault makes it |
| `InitEncryptionKey`, `DeriveConversationKeys` with 512 peers, store key and Ghost Key | 512 is the mailbox cap (`MAX_MESSAGES`), the most senders one request can name |
| `RegisterStore`, `ListStores` | registry |
| `SetPaymentXpub`, `DeriveOrderAddress`, `PeekOrderAddresses (10)`, `DeriveOrderAddress` with a foreign published script | BIP-32 derivation. The foreign script forces the full 100-index `PUBLISHED_INDEX_GAP` scan |
| `ArmAutoInvoice`, forced `Heartbeat`, `GetWatchKey` | instant checkout |
| tip notification, then a mailbox notification with 512 unread messages from 512 buyers | instant checkout opening every unread message (one X25519 + AES-GCM each). The harness checks the tip was cached and the 512 messages were recorded as read, so a refused scan cannot pass as a cheap one |
| `Installed`, `NodeStarted`, heartbeat wake-up | runs the node starts on its own |
| `StoreBuyerConversation` x256, `ListBuyerConversations (256)` | the buyer's conversation cap |
| `KeepPurchase` (paid, genuine SPV proof), `ListKeptPurchases (1024)` | the kept-purchase cap. The other 1023 are seeded straight into the secret store in the delegate's own encoding. The harness checks all 1024 come back |
| `ExportSecrets` | the migration export, run last because it disarms instant checkout |

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
| main before #203 (sha256 `d8088bf5…`, the build live when the bug was found) | 10,167,507,014 - 49,739,927,758 fuel (2.5x - 12.4x budget), 1.0 - 5.1 s unmetered | **exit 1**, all eight over |
| #203 (sha256 `cbe71dd9…`, RSA derivation removed) | 2,455,085 - 2,457,153 fuel (0.06%) | exit 0 |

Largest other calls, identical on both builds:

| call | fuel | share of budget |
|---|---:|---:|
| `ListKeptPurchases (1024)` | 2,906,374,095 | 72.7% |
| `ExportSecrets` with every cap full | 2,731,662,535 | 68.3% |
| mailbox notification, 512 unread | 2,543,487,928 | 63.6% |
| `DeriveConversationKeys (512 peers)` | 1,524,552,047 | 38.1% |
| `ListBuyerConversations (256)` | 1,048,280,976 | 26.2% |

These are within budget. They are also the handlers to watch: each grows with
a collection, and at that collection's cap the top three already use 64-73% of
the budget.

## What it does not cover

* **Handlers not driven**:
  * `SetWatchDelegation` and `UpdateWatchDelegation` need a Ghost Key
    certificate.
  * The instant-checkout follow-ups: the store GET answer that decides a batch
    of up to 16 instant orders, and the store UPDATE answer.
  * Conversation export and import, migration markers and secret import.
  * `CreateListing`, which is a stub.

  To add one, add a step to `scenario()` in `src/main.rs` with real inputs,
  and assert its answer.
* **Host time.** Fuel bounds guest work only. A handler that makes thousands
  of secret-store calls is reported with its host call count but judged only
  on its fuel.
* **Anything but one call.** The node's limit is per call. A flow that makes
  many calls is bounded per call, not in total.
