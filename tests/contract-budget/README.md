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
# one contract, or the cases whose name contains a string:
cargo run --release --locked --manifest-path tests/contract-budget/Cargo.toml -- --only mailbox --case tied
# the gating logic's own tests:
cargo test --release --locked --manifest-path tests/contract-budget/Cargo.toml
```

Each call prints one line: contract, case, call, fuel used, the budget, the
share of the budget, and `pass`, `FAIL` (a gating contract's call is over)
or `WARN` (a report-only contract's call is over; see "Which contracts
gate").

Exit codes:

* 0: every call of a gating contract is within budget.
* 1: at least one gating call is over budget, ran past the harness's fuel
  ceiling, or trapped (out of the node's 256 MiB of memory, a panic). On a
  node the update fails there too, so a trap is a failure of the contract,
  recorded as such, and the run goes on to the next case.
* 2: the harness could not drive the contracts: a contract imports a host
  function this host does not provide, or a gating contract refuses a
  fixture (`validate_state` not `Valid`, `update_state` an `Err` or no new
  state), makes no change, sends an empty fan-out delta, or accepts a delta
  it must refuse. A refused or no-op update is cheap and would pass the
  budget for the wrong reason.

A report-only contract never causes exit 1 or 2 by itself: its over-budget
calls, traps and refusals are each a `::warning::` with the reason, the
reason is kept in the step summary, and the run goes on to the next case.

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
   with the node's semantics (`fill_buffer_impl`). A 3.55 MB mailbox state is
   read in 54 refills, as on the node.
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
| `get_state_delta (to a new subscriber, empty summary)` | a peer that holds nothing summarizes its absent state as zero bytes and is sent the whole state, re-encoded |
| `update_state (must refuse)` | a delta the contract must refuse; only this call runs, and it must answer an error |
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
  and 3.55 MB of state (6.7 MB before harvest#226 made the byte fields CBOR
  byte strings). The largest classes are the newest, so the merge keeps
  every class full. Six cases:
  * one text message, the smallest bucket, as a delta;
  * a second mailbox at the same caps as a full state, interleaved in time,
    so the merge keeps half of each;
  * the largest delta the contract accepts: as many messages of the largest
    size class as encode within `MAX_DELTA_BYTES` (4,227,072 bytes), which
    is 64 of them (the class cap keeps 24);
  * `MAX_MESSAGES` (512) messages of the largest size class, about 34 MB,
    under the node's 50 MiB limit, which the contract must refuse on the
    delta's length, so the refusal must be cheap;
  * 513 messages, which the contract must refuse from the CBOR array head
    before decoding, so the refusal must be cheap;
  * adversarial ties, as a one-message delta and as a full state: every
    message shares one timestamp, one nonce, one conversation and one
    sender, and differs only in its ciphertext. Anyone can write these to
    an open-write mailbox and the contract keeps all of them. Every
    ordering the contract applies then falls through to the entry digest,
    which a build that hashes per comparison recomputes on every
    comparison.
* **Store** (`cases/store.rs`): `MAX_ORDERS` paid orders (256; 4096 until step 2), each with a
  genuine one-claim SPV payment proof and one despatch; 64 backing slots
  (`MAX_BACKINGS`) at the 4096-byte certificate cap, 32 retired and 32 with
  `MAX_SCOPES_PER_BACKER` copies; the closure; the pause; `MAX_LISTINGS`
  listings (128; 512 until step 2) each at `MAX_LISTING_BYTES` (32 KiB) with every field at
  its largest (8 photos, full choices and regions) and the description
  padded to the bound. Every state stays under the node's 50 MiB
  `MAX_STATE_SIZE`. Delta: one new listing, the newest, as the UI sends it.
  State: a diverged replica of the same store.
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

## Which contracts gate

`Kind::gates` in `src/cases/mod.rs`. The mailbox and the Ghost Key index
gate: an over-budget call fails the run. The store and reputation are
**report-only**: they are measured and printed on every run, an over-budget
call is a `::warning::` naming the issue that will make it gate, and the run
does not fail on it.

* The store gates once harvest#230 (store caps and byte strings) is fixed;
  its target is both store cases under 100% at the new caps. At 256 orders
  `validate_state` is still 293% to 338% (see "The store at step 2's caps"),
  so it does not gate yet.
* Reputation gates once harvest#228 is fixed.

Making a contract gate is part of the change that brings it within budget.

## After harvest#226 (mailbox)

The mailbox's byte fields are CBOR byte strings, each message's digest is
computed once and carried through dedupe, cap and canonical order, and a
delta of more than `MAX_MESSAGES` is refused from its array head. Three
builds of the mailbox, each column one run of this harness (the main column
with main's `harvest-common`, so its fixtures are in main's encoding):

* main `b84af10`, mailbox `64fd7bfe…`;
* `1927e43`, mailbox `70c52ef1…`: byte strings, dedupe hashed once;
* `c8b2dee`, mailbox `4f53c9ef…`: every digest once, oversized delta refused.

| case | call | main | `70c52ef1` | `4f53c9ef` |
|---|---|---:|---:|---:|
| one-message delta | `update_state` | 320.3% | 30.1% | 12.4% |
| | `validate_state` (merged) | 158.7% | 6.8% | 6.8% |
| | `summarize_state` | 118.4% | 11.3% | 11.3% |
| | `get_state_delta`, co-host | 118.8% | 11.7% | 11.7% |
| | `get_state_delta`, new subscriber | 161.2% | 12.3% | 12.3% |
| another 512-at-caps state | `validate_state` (incoming) | 158.7% | 6.8% | 6.8% |
| | `update_state` | 656.0% | 59.4% | 23.9% |
| | idempotency probe | 634.7% | 59.4% | 23.8% |
| | `get_state_delta`, new subscriber | 161.2% | 12.3% | 12.3% |
| 512-message top-class delta (34 MB) | `update_state` | 3356.9% | 290.4% | **107.3%, over** (refused at `5f4cd2b9`: 6.8%) |
| 64-message top-class delta (at `MAX_DELTA_BYTES`) | `update_state` | | | 24.1% at `5f4cd2b9` |
| 513-message delta | `update_state` (must refuse) | accepted, 347.2% | accepted, 36.6% | refused, 2.2% |
| 512 tied + one-message delta | `update_state` | 227.6% | 65.7% | 12.2% |
| | `validate_state` (merged) | 176.4% | 24.6% | 24.6% |
| 512 tied + another tied state | `update_state` | 423.3% | **112.7%, over** | 23.5% |
| | idempotency probe | 409.7% | **104.1%, over** | 23.6% |

The tied cases are the evidence that the per-comparison digest was a real
cost: on `70c52ef1`, whose dedupe already hashed once, the tied merge is
still over budget, and on `4f53c9ef` it is 23.5%. `validate_state` on a tied
state is 24.6% where an untied one is 6.8%, because `verify` checks the
canonical order pairwise and every pair ties through to two digests; that
is within budget.

**The largest accepted delta was still over on `4f53c9ef`**: 512 top-class
messages in one delta (34 MB) cost 2.36 billion fuel in `update_state`,
107.3% of the budget. Anyone can send one to an open-write mailbox. The
mailbox at `5f4cd2b9` (`56334e8`) refuses a delta longer than
`MAX_DELTA_BYTES` (4,227,072 bytes, `MAX_MAILBOX_BYTES + 512 * 64`) on its
length, before reading its head or decoding it. The largest delta it
accepts is then 64 top-class messages: `update_state` 530,037,599 fuel,
24.1%. Refusing the 34 MB delta costs 148,668,860 fuel (6.8%), against
49,462,517 (2.2%) for the 513 small messages: the contract's own check is on
the length, but the stdlib glue decodes the bincode update list, copying all
34 MB in through the streaming buffer, before the contract sees it. Every
other mailbox figure at `5f4cd2b9` is the same as at `4f53c9ef`, to within
a few units of fuel, and every gating call is within budget (exit 0).

The other contracts measured the same on `c8b2dee` as on main, to the unit
of fuel. That includes the store, whose WASM moved to `35a45555…` with no
change of behaviour.

The mailbox at `4f53c9ef` recalibrated on nova on 2026-10-04 (`--calibrate 7
--only mailbox`, load 27 to 45): 3.4 to 5.4 billion fuel/s, the largest
delta 4.88 billion fuel/s (489 ms). A `--calibrate 3` run at load 37 to 50
read as low as 1.67 billion fuel/s on 150 ms calls; with seven runs those
same calls read 4.1 to 4.9 billion, so the low readings were the load. The
budget's derivation holds: the mailbox is not slower per unit of fuel than
the 2.28 billion fuel/s the budget is taken from, so for the mailbox the
budget is about 0.45 s of work.

## Results on main

One run (at the former store caps, 4096 orders) on the contracts committed at main `b84af10` (mailbox `64fd7bfe…`,
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
* **The store** at its caps (4096 orders when measured; 256 since step 2) is a state of about 41 MB, 34 MB of it the 4096
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

## The store at step 2's caps

Step 2 (`feat/store-pause-one-backup`) caps a store's listings (first 512, then
128, each at most 32 KiB as encoded), writes every signed record's signed payload and
signature as a CBOR byte string, verifies each payment proof's signed tip once
per distinct tip, and has `is_canonical_cbor` compare without copying the
state. The store fixture follows: the capped number of listings at the per-listing
bound, every field at its largest, and the pause. Store case only
(report-only), budget 2.2 billion fuel a call.

**At the current caps** (256 paid orders, 128 listings; store wasm blake3
`a4cf4e03`), as percentages of the budget:

| case | call | of budget |
|---|---|---:|
| 256 orders at caps + one-listing delta | `update_state` | 36.8% |
| | `validate_state` (merged) | **322.0%, over (WARN)** |
| | `summarize_state` | 39.3% |
| | `get_state_delta` (co-host) | 39.6% |
| | `get_state_delta` (new subscriber) | 33.3% |
| 256 orders at caps + another at-caps state | `validate_state` (incoming) | **322.0%, over** |
| | `update_state` | **286.6%, over** |
| | `validate_state` (merged) | **325.7%, over** |
| | `summarize_state` | 39.8% |
| | `get_state_delta` (co-host) | 36.4% |
| | `get_state_delta` (new subscriber) | 33.8% |
| | `update_state` (idempotency probe) | **175.3%, over** |
| 256 Paid orders of 8 KiB (`MAX_PAID_ORDER_BYTES`) + one-listing delta | `update_state` | 42.5% |
| | `validate_state` (merged) | **338.1%, over** |
| | `summarize_state` | 45.6% |
| | `get_state_delta` (co-host) | 45.9% |
| | `get_state_delta` (new subscriber) | 39.0% |
| 256 orders at caps + 64 Paid padded to 256 KiB (kept unpaid) | `update_state` | **450.9%, over** |
| | `validate_state` | **293.1%, over** |
| | `summarize_state` | 34.0% |
| | `get_state_delta` (co-host) | 33.9% |
| | `get_state_delta` (new subscriber) | 28.6% |

No call in these states ran out of memory. The delta and summary calls are
within budget in every one; `validate_state` (and the full-state
`update_state`) is over. The case stays report-only, so each is a warning and
the run does not fail on it. Fuel is not the node's limit, which is wall
clock: with 256 orders at the 8 KiB bound and 128 listings full at 32 KiB,
a PUT took at most 1.82 s and a one-listing delta at most 2.15 s, and a
merge under 2 s a call, in 3 of 3 runs (the wall-time runs that chose the
caps, recorded in the `# Why 256` note on `harvest_common::store::MAX_ORDERS`).

**Measured at the former caps** (4096 paid orders, 512 listings), kept for
comparison:

| case | call | fuel | of budget |
|---|---|---:|---:|
| 4096 paid orders, 512 listings + one-listing delta | `update_state` | 9,068,670,705 | 412.2% |
| | `validate_state` (merged) | 63,004,974,814 | 2863.9% |
| | `summarize_state` | 10,132,725,316 | 460.6% |
| | `get_state_delta` (co-host) | 10,198,398,557 | 463.6% |
| | `get_state_delta` (new subscriber) | | **trapped: out of memory** |
| same + another at-caps state | `validate_state` (incoming) | 63,002,853,934 | 2863.8% |
| | `update_state` | | **trapped: out of memory** |

The node caps a contract's linear memory at 256 MiB (freenet-core
`DEFAULT_MAX_MEMORY_PAGES`, 4,096 pages of 64 KiB, `wasm_runtime/engine.rs`).
Before the copy-free check, `validate_state` itself ran out of it at these
caps. Measured on the same orders by listing count at 32 KiB: with 256
listings only the full merge runs out; with 128 every call completes.

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
