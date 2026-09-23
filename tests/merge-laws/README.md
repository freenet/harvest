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
`copies`, `retire98`, `fulfilment`) are not the same as the corpus names the runner takes; one
family writes several corpora.

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
and the count is 0 (sweep at #143's contracts, 39 corpora, 2026-09-23).
First-writer-wins between two genuine certificates is still #81.
Everything else is expected to be zero violations and zero inconclusive.
