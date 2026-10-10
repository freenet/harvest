# Merge-law sweep

`fdev verify-merge` checks that a contract's `merge`, `update_state`, `summarize`
and `delta` obey the laws the network relies on: that two peers reaching the same
pair of states converge, that a delta brings a receiver up to the sender, that an
update is deterministic, and so on. It needs a *corpus* — real states, real
transitions and real delta steps — because it does not invent state itself.

This directory holds the two things that must survive: the **generator** that
builds those corpora from the contracts' own types, and the **runner** that says
which corpora are swept and which properties are asked of each.

The corpora themselves are NOT committed: the full set is about 550 MB, and it is
reproducible from `gen/` in a few minutes. `.gitignore` excludes them.

Nothing here runs in CI. It is a pre-merge gate a human or an agent runs when a
contract, or `common/`, changes. The seeded merge-law unit tests in `common/` run
in `cargo test` and are the cheap continuous half of the same job.

## Running it

Build the contract WASM first — the sweep checks compiled bytes, not source:

```bash
./scripts/build-contract-wasm.sh
tests/merge-laws/run.sh                       # every corpus in the list
tests/merge-laws/run.sh . index-clash index-adv   # just these two
```

`MAX_CASES` bounds each property (default 2000). `OUT` redirects the results
tree. `PER_PROPERTY=0` skips the per-property breakdown and only runs the two
whole-corpus passes.

## Regenerating the corpora

Required whenever the contract WASM moves — which is any change to `contracts/`,
`common/`, or a dependency version that re-keys an artifact.

```bash
cd tests/merge-laws/gen
cargo build --release
./target/release/harvest-merge-corpus ../corpus          # all of them
./target/release/harvest-merge-corpus ../corpus index    # one family
```

`gen/` is deliberately its OWN cargo workspace, like `tests/rehearsal`: it must
never be able to move a dependency version the contracts compile against, because
that would re-key an artifact as a side effect of running the test tooling.

The family names the generator takes (`store`, `claim`, `triad`, `triadcap`,
`reputation`, `mailbox`, `review`, `rr`, `backing`, `review98`, `index`,
`copies`, `retire98`, `fulfilment`, `status`, `request`, `presence`, `paidcap`,
`listcap`, `pause`) are not the same as the corpus names the runner takes; one
family writes several corpora.

## Step 2's caps and the pause

Step 2 added store rules that no corpus exercised until its review round 2
said so. Each family below writes one corpus, built through the store's own
`apply_delta`, and checks the merge laws natively on a subset of it before
writing (`native_laws_total`).

- **`store-paidcap`** (`paidcap`) -- the item rule `as_kept`: a `Paid` record
  stays paid only on the canonical minimal proof, within
  `MAX_PAID_ORDER_BYTES` (8 KiB), and is otherwise kept as its unpaid terms.
  A state holding a padded `Paid` does not verify, so the raw records ride
  in hand-built DELTAS (that is where the WASM meets the rule), and the
  states hold what the store keeps. For the same orders the deltas carry an
  honest minimal `Paid` (two proofs), the same payment padded with `ScannedTo`
  claims (non-minimal, still under 8 KiB), a minimal `Paid` just over 8 KiB
  and one just under it (filler outputs, sized to the byte), the unpaid terms
  and a cancellation, alone and mixed in one delta in both orders. Two
  `MAX_ORDERS` states whose four oldest orders, the first any newer order
  cuts, arrived honest, padded, over and under, so the cap and the rule meet.
  And the migration fold's result over a RECOVERED base of 300 orders and 130
  listings (`fold_store`, which models `merge_store_reporting_discard`,
  including `normalize_carried`; the driver calls
  `merge_with_local(recovered, &local)`, so the unverified side is the base).
- **`store-listcap`** (`listcap`) -- `MAX_LISTINGS` (128) newest by
  `(created_at, id)`: 100 newer listings, 40 created in the same second and
  8 older, spread over states of at most 128 so a union of two crosses the cap
  and the cut runs through the tie (the 28 smallest ids of it are kept). One
  listing either side of `MAX_LISTING_BYTES` (32 KiB); the one over is only
  ever in a delta, since a state cannot hold it.
- **`store-pause`** (`pause`) -- `PauseV1`, one store-key-signed slot: the
  higher revision, then the smaller encoding. Several revisions, equal
  revisions with opposite `paused`, `u64::MAX`, a pause beside a listing and
  beside the closed flag, every ordered pair merged, and deltas carrying two
  pauses for the slot in both orders.

`store-listcap` shows a few inconclusive cases in the bundle run
(`delta_idempotence`, `delta_permutation_invariance`): fdev applies the delta
carrying only the over-bound listing to the empty store, and the contract
refuses it ("an update that claims a store must carry something its owner
signed"), since the listing is dropped and nothing signed is left. That is the
right answer, not a gap.

**fdev pairs at most 24 states and samples at most 24 transitions**
(`max_states_paired`, `max_transitions` in freenet-core's
`conformance/generator.rs`), strided over the corpus. A corpus of 85 states
(`store-paidcap`) therefore checks the pairwise and triple state laws on about
a quarter of its states (those at index `floor(i * n / 24)`). The delta laws
see every distinct delta. Keep a corpus near 24 states when the state laws
are the point.

## The presence contract

`presence` (`gen_presence`) covers the store presence contract
(`contracts/presence-contract`, rules in `common/src/presence.rs`): the whole
state is at most one signed heartbeat, kept by larger `seq` then smaller
canonical encoding. That is a single-slot total order, unlike mailbox's list
or index's per-slot map, so it needs no cap corpus (there is nothing to grow
past a bound).

- **`presence`** — HONEST: several heartbeats at different `seq`, a same-`seq`
  tie decided by encoding rather than by `at_ms` or `taking_orders`, and both
  `taking_orders` values, plus the pairwise merges and delta steps.
- **`presence-adv`** — states the contract must REFUSE (another key's
  signature, a tampered payload under a genuine signature, a non-canonical
  encoding — trailing byte and unknown map key, same `noncanon` helper as
  `store-noncanon`/`mailbox-noncanon`), beside boundary values it must ACCEPT
  (`seq` at `u64::MAX`, `at_ms` at 0) to stress the ordering and tie-break at
  the ends of the type rather than test a refusal. No pairwise merges: like
  `index-bad`, only states.

## Two ways this sweep has lied

Both are the same shape — it passed while covering less than it claimed — and
both are the reason the corpus list lives in `run.sh` in the repo rather than in
whoever-ran-it-last's shell history.

**A corpus absent from the list is never swept.** Through the whole of #101's
first round, `index-clash` and `index-adv` were not in it. The round's riskiest
change was the delta bound and the rewritten clash comparison, so the two corpora
built to attack exactly that were the two not running, and the sweep reported
clean. Add a corpus to `corpora` in the same change that adds it to `gen/`.

**A concurrent rebuild used to corrupt a run, and no longer can.** The sweep
runs for minutes. Rebuilding contract WASM in the same worktree meanwhile
replaced the files it was reading, and the symptom was not a loud failure --
it was one corpus producing no output at all, which reads exactly like a real
refusal. The author of this note walked into it twice, so the coupling is
removed rather than documented: `run.sh` snapshots the WASM into the results
directory before any corpus runs and reads only that copy, and writes the
BLAKE3 hashes to `results/wasm-hashes.txt` so a reported number always names
the bytes it describes.

**A stale bundle silently drops every delta law.** The state pass is driven by
`--state`/`--transition` files; the `delta_*` laws can only be fed from the
generator's `bundle-in.bin`, because the CLI has no `--delta`. A bundle embeds
the WASM it was generated against, and `fdev` refuses a hash mismatch — so a
stale bundle makes the *second* pass fail loudly, and it is only visible if you
read that line. Running the first pass alone looks like a clean sweep of
everything, and is a clean sweep of half of it.

## Known standing violations

`store-adv` (6), on `state_commutativity` and `reconciliation_cycle`. This is
**pre-existing and tracked as
[#81](https://github.com/freenet/harvest/issues/81)** — equal-version store info
lets two peers keep different state. It appears with identical counts and
properties in sweeps going back weeks; a change is a regression only if it moves
that number or adds a corpus to the list.

`reputation-adv` carried 8 of these until #143 (harvest#53 Phase C), from the
record's unsigned certificate field. The reputation contract now accepts only
empty or a genuine Ghost Key certificate in its one canonical armour
(`check_owner_certificate`), so the corpus's divergent certificates are refused
and the count is 0 (sweep at #143's contracts, 40 corpora, 2026-09-23).
First-writer-wins between two genuine certificates is still #81.

`reputation-cap` (#143 review round 5, R5-C) exercises the record's cap: a full
record of late complaints, honest complaints dated near their payments, a far
second statement by one of those buyers whose terms encode smaller, and the
full record once the honest ones arrive. It is zero violations and zero
inconclusive; the generator itself asserts the associativity it is built
around, so a corpus that stops exercising it fails to generate.
Everything else is expected to be zero violations. Corpora that deliberately mix refused states with valid ones (`index-bad`, `presence-adv`, the other `-bad` corpora) also show inconclusive cases, since a refused state cannot be merged; zero inconclusive is expected only of the rest.
