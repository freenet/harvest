# Contract work-per-call budget on an update

A Freenet node stops any contract call after **5 seconds of wall clock**
(`RuntimeConfig::max_execution_seconds` in freenet-core). An update to a
contract at its caps that costs most of that fails on a busy peer, and every
peer hosting the contract pays it for every update. harvest#226 found this on
a node: a one-message delta onto a full mailbox took 3.4 to 3.7 s, and a
merge of a 405-message mailbox was refused at load 20 (`WASM execution timed
out ... elapsed_ms=5011`). Native unit tests cannot see it. They run several
times faster than the contract WASM on the node and have no limit at all.

This harness is the contract counterpart of `tests/delegate-budget`. It runs
the **committed** contracts (`ui/public/contracts/{mailbox,store,index,
reputation}_contract.wasm`) under wasmtime with **fuel metering**, drives each
one through the calls a node makes for one UPDATE against a state at its caps,
and fails if any single call consumes more than the budget.

It is its own cargo workspace, like `tests/rehearsal` and
`tests/delegate-budget`, so building or locking it can never move a dependency
version the contracts compile against, and therefore can never re-key an
artifact.

## Why fuel and not a timer

Fuel counts the WebAssembly instructions the guest executes. The same WASM fed
the same inputs burns the same fuel on every machine and every run. Every
fixture is built from fixed seeds, BLAKE3 output and a fixed clock, with no OS
randomness, so repeated runs produce byte-identical output. A wall-clock
assertion would be a flaky test. Wall clock enters once, at calibration
(below).

## Running it

A run takes about five minutes, most of it the store and reputation states
(about 40 MB each).

```sh
cargo run --release --locked --manifest-path tests/contract-budget/Cargo.toml
# other builds of the contracts (all four file names must be present):
cargo run --release --locked --manifest-path tests/contract-budget/Cargo.toml -- --wasm-dir path/to/contracts
# recalibrate (also times each call unmetered, best of N runs):
cargo run --release --locked --manifest-path tests/contract-budget/Cargo.toml -- --calibrate 3
```

Each call prints one line: contract, case, call, fuel used, the budget, the
share of the budget, and `pass` or `FAIL`.

Exit codes:

* 0: every call is within budget.
* 1: at least one call is over budget, ran past the harness's fuel ceiling,
  or trapped (out of the node's 256 MiB of memory, a panic). On a node the
  update fails there too, so a trap is a failure of the contract, recorded as
  such, and the run goes on to the next case.
* 2: the harness could not drive the contracts: a contract imports a host
  function this host does not provide, a fixture the contract refuses
  (`validate_state` not `Valid`, `update_state` an `Err` or no new state), an
  update that changes nothing, or an empty fan-out delta. A refused or no-op
  update is cheap and would pass the budget for the wrong reason.

## What the host is

`src/host.rs` is the node's side of the contract ABI, mirroring freenet-core's
`wasm_runtime/contract.rs`, `runtime.rs` and `native_api.rs`:

1. A fresh instance per call, as `prepare_contract_call` makes one.
2. `__frnt_set_id`.
3. Each argument written through `__frnt__initiate_buffer` as the node's
   streaming protocol writes it (`write_streaming_buf`): a buffer of at most
   64 KiB (`STREAMING_BUF_CAP`) holding a `[total_len: u32]` header and as much
   of the argument as fits. The rest is handed over on demand through the one
   import the contracts declare, `freenet_contract_io.__frnt__fill_buffer`,
   with the node's semantics (`fill_buffer_impl`). A 7 MB state is read in
   about a hundred refills, as on the node.
4. Parameters, state and summary bytes go in as they are; the update list and
   the related-contracts map are bincode-encoded with freenet-stdlib 0.8.5, as
   the node encodes them (`write_contract_buf_serialized`).
5. The entry point runs. Only this call is metered.

Also as on the node: linear memory is capped at 256 MiB (4096 pages), the
table at 10,000 elements, and the result is read from the guest's
`ContractInterfaceResult`. An import the host does not provide fails
instantiation (exit 2).

## What a node runs for one update

From freenet-core's upsert path (`contract/executor/runtime/executor_impl.rs`):

| call | when |
|---|---|
| `validate_state (incoming state)` | a full state arrives (`UpdateData::State`: a PUT onto an existing contract, a resync, the migration's forward). The node validates it before merging |
| `update_state` | every update (`attempt_state_update`) |
| `validate_state (merged state)` | every update that produced a new state (`fetch_related_for_validation`) |
| `summarize_state (merged state)` | the changed state is committed and fanned out; the node summarizes it |
| `get_state_delta (to a co-host holding the old state)` | the fan-out computes each co-host's delta against its summary. The summary of the held state is computed unmetered first |
| `update_state (idempotency probe, 1 in 32)` | a full-state merge is re-run, sampled 1 in 32, with the merged state as the held one (`maybe_probe_idempotency`) |

Each is a separate guest call under the node's 5 s limit, so each is judged
on its own. A node with no peers runs only the first three, which is the
cross-check below.

## The cases

Every held state is built through `harvest_common`'s own merge code
(`apply_delta`) and checked natively with `verify`, so it is a state the
contract would hold. Every signature is genuine. Each contract has a one-item
delta and a full-state merge of a second, different state at the same caps,
arranged so the merge result differs from the held state and stays at the
caps. The module docs in `src/cases/` say what is at which cap and why.

* **Mailbox** (`cases/mailbox.rs`): 512 messages (`MAX_MESSAGES`), every size
  class at its cap (296, 128, 64, 24), each ciphertext
  `SIZE_BUCKETS[class] + AEAD_TAG_BYTES` bytes, about 3.3 MiB of ciphertext
  and 6.7 MB of state. The largest classes are the newest, so the merge keeps
  every class full. Delta: one text message, the smallest bucket. State: a
  second mailbox at the same caps, interleaved in time, so the merge keeps
  half of each.
* **Store** (`cases/store.rs`): 4096 paid orders (`MAX_ORDERS`), each with a
  genuine one-claim SPV payment proof and one despatch; 64 backing slots
  (`MAX_BACKINGS`) at the 4096-byte certificate cap, 32 retired and 32 with
  `MAX_SCOPES_PER_BACKER` copies; the closure; 64 listings with 8 photos
  each (`MAX_IMAGES_HARD`) and 16 KiB descriptions. The contract caps neither
  the listing count nor description length; 64 listings keep every state
  under the node's 50 MiB `MAX_STATE_SIZE` (the orders alone are about 34
  MB). Delta: one new listing, as the UI sends it. State: a diverged replica
  of the same store.
* **Index** (`cases/index.rs`): 64 entries (`MAX_INDEX_ENTRIES`), each with
  the genuine 1634-byte Ghost Key certificate. Delta: one entry the cap
  keeps. State: a second index at the cap.
* **Reputation** (`cases/reputation.rs`): 146 complaints (`MAX_COMPLAINTS`),
  each at the payment-proof caps (32 claims, about 260 KB of claims, 24
  following headers), about 40 MB. Delta: one complaint the cap keeps.
  State: a second record at the cap, interleaved by date.

## Calibration

The budget is **2,200,000,000 fuel per call**: about one second of contract
work on the reference machine, a fifth of the node's 5 s limit.

Measured on **nova** (Intel i9-9900K, 3.6 GHz base, 16 threads) on
2026-10-04 with `--calibrate 3`, on the contracts committed at main
`b84af10`, at a load average of 15 to 21 from other work. The unmetered runs
use an engine configured like the node's (`create_engine` in freenet-core's
`engine/wasmtime_engine.rs`): Cranelift `OptLevel::None`, epoch interruption
on, and the node's memory layout (a 256 MiB reservation with a 64 KiB guard,
which makes Cranelift emit explicit bounds checks). Time in the host (the
refills) was under 11 ms for every call, so these rates are the guest's own.
Best of three runs per call:

| workload | calls | fuel/s |
|---|---|---:|
| CBOR decode and verify of a large state | every `validate_state` (mailbox, store, index, reputation) | 3.9 - 5.3 billion |
| decode, merge, re-encode | mailbox and index `update_state`, store and reputation delta `update_state` | 3.7 - 5.2 billion |
| decode, hash every entry, encode | every `summarize_state` and `get_state_delta` | 3.4 - 4.4 billion |
| index idempotency probe (288 ms) | one call | 2.8 billion |
| reputation full-state merge, two 40 MB states (41 s) | one call | **2.28 billion** |

As in `tests/delegate-budget`, the budget takes the **slowest** measured
rate among calls that take at least about 50 ms, rounded down: 2.2 billion
fuel is about 1.0 s for the slowest, memory-heavy kind of call and 0.4 to
0.65 s for the rest. The slowest kind is likely slow per unit of fuel for
the reason the delegate's export is: wasmtime charges one unit of fuel for a
`memory.copy` however many bytes it moves. A call over the budget would
plausibly take more than about 1 s on the node.

Cross-check against the node measurements in harvest#226 (an isolated node
with no peers runs `update_state` and `validate_state (merged state)` for a
delta, and validates the incoming state first for a full state):

| operation | node (0.2.140, load 7-20) | this harness, unmetered, same calls summed |
|---|---|---|
| one-message delta onto the full mailbox | 3.4 - 3.7 s | 1.36 + 0.91 = 2.3 s |
| merge of a 405-message state onto the full mailbox (here 512) | 4.7 - 5.3 s, one refusal at 5.0 s | 0.85 + 2.87 + 0.90 = 4.6 s |

The node figures include host work fuel does not see (reading and writing
the 6.7 MB state, bincode framing, the executor), so the harness reading
lower is the expected direction. The order of magnitude agrees.

What the 5x margin under the node's limit is for: a slower CPU than nova, a
node under load (the limit is wall clock), host time on the node, and the
bulk-memory undercount above.

**To recalibrate** after a wasmtime or freenet-core engine change, or on new
reference hardware: run with `--calibrate 3` (it takes about 20 minutes with
the store and reputation cases), read the `fuel/s (guest)` column, and set
`BUDGET_FUEL` in `src/main.rs` to one second at the slowest rate among calls
that take at least about 50 ms. Update this section.

## Results on main

One run on the contracts committed at main `b84af10` (mailbox `64fd7bfe…`,
store `8e95714f…`, index `44bcc983…`, reputation `eab59c4e…`). Two runs gave
byte-identical output. Exit 1.

| contract | case | call | fuel | of budget |
|---|---|---|---:|---:|
| mailbox | 512 at caps + one-message delta | `update_state` | 7,047,116,660 | **320.3%, over** |
| | | `validate_state` (merged) | 3,492,099,944 | **158.7%, over** |
| | | `summarize_state` | 2,604,376,919 | **118.4%, over** |
| | | `get_state_delta` | 2,612,617,701 | **118.8%, over** |
| mailbox | 512 at caps + another 512-at-caps state | `validate_state` (incoming) | 3,492,067,406 | **158.7%, over** |
| | | `update_state` | 14,431,300,536 | **656.0%, over** |
| | | `validate_state` (merged) | 3,492,113,584 | **158.7%, over** |
| | | `summarize_state` | 2,604,370,461 | **118.4%, over** |
| | | `get_state_delta` | 3,086,033,491 | **140.3%, over** |
| | | `update_state` (probe) | 13,963,247,058 | **634.7%, over** |
| store | 4096 orders at caps + one-listing delta | `update_state` | 21,611,070,191 | **982.3%, over** |
| | | `validate_state` (merged) | 78,305,660,794 | **3559.3%, over** |
| | | `summarize_state` | 22,714,056,829 | **1032.5%, over** |
| | | `get_state_delta` | 22,777,989,162 | **1035.4%, over** |
| store | 4096 orders at caps + another at-caps state | `validate_state` (incoming) | 78,235,392,360 | **3556.2%, over** |
| | | `update_state` | 38,237,818,783 | **trapped: out of memory** |
| index | 64 at cap + one-entry delta | `update_state` | 261,405,173 | 11.9% |
| | | `validate_state` (merged) | 533,298,274 | 24.2% |
| | | `summarize_state` | 284,166,760 | 12.9% |
| | | `get_state_delta` | 284,013,531 | 12.9% |
| index | 64 at cap + another 64-at-cap state | `validate_state` (incoming) | 533,259,130 | 24.2% |
| | | `update_state` | 773,760,439 | 35.2% |
| | | `validate_state` (merged) | 533,519,944 | 24.3% |
| | | `summarize_state` | 284,147,928 | 12.9% |
| | | `get_state_delta` | 269,293,239 | 12.2% |
| | | `update_state` (probe) | 812,185,165 | 36.9% |
| reputation | 146 at caps + one-complaint delta | `update_state` | 27,832,881,198 | **1265.1%, over** |
| | | `validate_state` (merged) | 65,198,494,403 | **2963.6%, over** |
| | | `summarize_state` | 21,812,402,455 | **991.5%, over** |
| | | `get_state_delta` | 21,852,525,961 | **993.3%, over** |
| reputation | 146 at caps + another 146-at-caps state | `validate_state` (incoming) | 65,196,599,101 | **2963.5%, over** |
| | | `update_state` | 93,808,946,886 | **4264.0%, over** |
| | | `validate_state` (merged) | 65,200,810,601 | **2963.7%, over** |
| | | `summarize_state` | 21,814,546,156 | **991.6%, over** |
| | | `get_state_delta` | 24,623,394,521 | **1119.2%, over** |
| | | `update_state` (probe) | 71,521,517,873 | **3251.0%, over** |

What these say:

* **The mailbox** is the harvest#226 finding, reproduced: every call on a
  full mailbox is over, the one-message delta's `update_state` at 3.2x. Two
  causes were found by native profiling: `Vec<u8>` fields encoded as CBOR
  integer arrays (the 3.3 MiB of ciphertext is a 6.7 MB state), and
  `dedupe_identical_entries` sorting with `sort_by_key(entry_digest)`, which
  re-hashes every message on each comparison.
* **The store** at its caps is a state of about 41 MB, 34 MB of it the 4096
  paid orders, whose byte fields are CBOR integer arrays too. Every call is
  10 to 36 times over, and the full-state merge runs out of the node's 256
  MiB of WASM memory inside `StoreStateV1::apply_delta` (cloning the
  orders' `BTreeMap`), so on a node such a merge cannot complete at all.
* **The reputation record** at its complaint cap (146 complaints at the
  payment-proof caps, about 40 MB) is 10 to 43 times over. Smaller
  complaints do not bring it within budget: in a separate run with 146
  one-claim complaints (about 15.7 KB each) `validate_state` was 4.07
  billion fuel and the full-state merge 5.55 billion, both over (that run
  was measured against the earlier 3.0 billion budget, and is not one of
  the cases).
* **The index** is within budget at its cap, at most 37%. With every
  certificate padded to the 4096-byte bound (which only the Ghost Key's
  holder can write), the full-state merge was 1.51 billion and the probe
  1.60 billion, still within.

## What it does not cover

* **Host time.** Fuel bounds guest work. The refills are host calls; they are
  counted under `--calibrate` and were a small share of every call.
* **Bulk memory.** wasmtime charges a `memory.copy` or `memory.fill` one unit
  of fuel however many bytes it moves, so copy-heavy code costs more time
  than its fuel shows. The calibration rate is taken on these contracts'
  own calls, which is where this shows up.
* **Related contracts.** No Harvest contract asks for one on these paths, so
  the related-contracts map is always empty.
* **A PUT onto an empty contract** (`validate_state` of the incoming state,
  then the store). The merge cases cover the larger cost.
* **Anything but one call.** The node's limit is per call. An update is
  several calls, bounded one at a time, not in total.
