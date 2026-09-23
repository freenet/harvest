#!/usr/bin/env bash
# Re-run the `fdev verify-merge` merge-law sweep for the Harvest contracts.
#
#   run.sh [REPO] [CORPUS...]
#
# REPO is the worktree whose WASM is checked; it defaults to the worktree this
# script lives in. With no CORPUS arguments the FULL list below runs.
#
# See README.md. Two things that have bitten this sweep before, both of which
# let it pass while covering less than it claimed:
#
#   * A corpus missing from `corpora` is a corpus the sweep never touches. The
#     adversarial index corpora were absent for a whole round (#101 re-review),
#     which is exactly where that round's riskiest change lived. That is why
#     this list is in the repo rather than in a shell history.
#   * A bundle embeds the WASM it was generated against. `--wasm` overrides it
#     and fdev REFUSES a hash mismatch, so a stale bundle makes the second run
#     fail loudly -- but running only the first (state) pass would silently
#     skip every delta law. Regenerate the corpora whenever contract WASM moves.
#   * The WASM is SNAPSHOTTED into the results dir before any corpus runs, and
#     only the snapshot is read. A rebuild in the same worktree during a sweep
#     used to replace the files mid-run, which shows up as one corpus producing
#     no output at all -- indistinguishable from a real refusal. The hashes are
#     written to results/wasm-hashes.txt so a number always names its bytes.
set -uo pipefail
W="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${1:-$(cd "$W"/../.. && pwd)}"; shift || true
MAX="${MAX_CASES:-2000}"
corpora=("$@")
if [ ${#corpora[@]} -eq 0 ]; then
  corpora=(
    store store-empty store-adv store-cap store-cap2 store-claim store-noncanon
    store-rr store-triad store-triadcap store-v0
    store-backing store-backing-adv store-backing-bad
    store-copies store-copies-bad
    store-fulfilment store-fulfilment-cap store-fulfilment-bad
    store-r98cap store-r98race store-r98retire
    store-status store-status-bad
    reputation reputation-empty reputation-adv reputation-rr reputation-cap
    mailbox mailbox-empty mailbox-adv mailbox-cap mailbox-cap2 mailbox-cap3
    mailbox-noncanon mailbox-rr
    index index-cap index-bad index-clash index-adv
  )
fi
props=(state_idempotence state_commutativity state_associativity emitted_state_validity update_determinism summary_determinism delta_determinism delta_idempotence delta_permutation_invariance self_delta_empty whole_state_self_delta reconciliation_cycle path_agreement transition_path_agreement)
OUT="${OUT:-$W/results}"; mkdir -p "$OUT"

# Snapshot the WASM before reading a single corpus, and read only the copy.
#
# The sweep runs for minutes and used to read $REPO/target/... live. A cargo
# build in the same worktree replaces those files underneath it, and the
# result is not a loud failure -- it is one corpus silently producing no
# output, which reads exactly like a real refusal. That happened twice to the
# author of the README note warning about it, so the coupling is removed
# instead of documented: nothing this script reads can be rewritten while it
# runs. The hashes go in the results, so a reported number always names the
# bytes it describes.
SNAP="$OUT/wasm"; mkdir -p "$SNAP"
for a in store_contract reputation_contract mailbox_contract index_contract; do
  src="$REPO/target/wasm32-unknown-unknown/release/$a.wasm"
  [ -f "$src" ] && cp "$src" "$SNAP/$a.wasm"
done
if command -v b3sum >/dev/null 2>&1; then
  (cd "$SNAP" && b3sum ./*.wasm) > "$OUT/wasm-hashes.txt" 2>/dev/null
  echo "WASM under test (BLAKE3):"; sed 's/^/  /' "$OUT/wasm-hashes.txt"
fi
for c in "${corpora[@]}"; do
  contract="${c%%-*}_contract"
  wasm="$SNAP/$contract.wasm"
  if [ ! -f "$wasm" ]; then
    echo "== $c: NO WASM for $contract -- run scripts/build-contract-wasm.sh first"; continue
  fi
  C="${CORPUS_ROOT:-$W/corpus}/$c"
  if [ ! -d "$C" ]; then
    echo "== $c: MISSING CORPUS at $C -- regenerate (see README.md)"; continue
  fi
  args=(--wasm "$wasm" --params "$C/params.bin")
  for f in "$C"/states/*.cbor; do args+=(--state "$f"); done
  while read -r b r; do [ -n "$b" ] && args+=(--transition "$C/states/$b.cbor" "$C/states/$r.cbor"); done < "$C/transitions.txt"
  rm -rf "$OUT/$c"; mkdir -p "$OUT/$c/props"
  printf '%q ' fdev verify-merge "${args[@]}" --max-cases "$MAX" --json --evidence-out "$OUT/$c/evidence" --bundle-out "$OUT/$c/bundle.bin" > "$OUT/$c/command.txt"
  RUST_LOG=error fdev verify-merge "${args[@]}" --max-cases "$MAX" --json \
    --evidence-out "$OUT/$c/evidence" --bundle-out "$OUT/$c/bundle.bin" > "$OUT/$c/all.json" 2> "$OUT/$c/all.stderr"
  echo "== $c: $(jq -c '{states:.corpus_states,cases:.cases_run,holds,violations,inconclusive}' "$OUT/$c/all.json")"
  # Second run from the generator's bundle, which ALSO carries delta steps
  # (delta + base summary + result): the only way to feed the delta_* laws,
  # since the CLI has no --delta flag. Same states and transitions otherwise.
  bargs=(--bundle "$C/bundle-in.bin" --wasm "$wasm")
  printf '%q ' fdev verify-merge "${bargs[@]}" --max-cases "$MAX" --json --evidence-out "$OUT/$c/evidence-bundle" > "$OUT/$c/command-bundle.txt"
  RUST_LOG=error fdev verify-merge "${bargs[@]}" --max-cases "$MAX" --json --evidence-out "$OUT/$c/evidence-bundle" 2>"$OUT/$c/bundle.stderr" | sed -n '/^{/,$p' > "$OUT/$c/all-bundle.json"
  echo "   bundle run: $(jq -c '{states:.corpus_states,deltas:.corpus_deltas,summaries:.corpus_summaries,cases:.cases_run,holds,violations,inconclusive}' "$OUT/$c/all-bundle.json")"
  if [ "${PER_PROPERTY:-1}" = 1 ]; then
    for p in "${props[@]}"; do
      RUST_LOG=error fdev verify-merge "${bargs[@]}" --max-cases "$MAX" --property "$p" --json 2>"$OUT/$c/props/$p.stderr" | sed -n '/^{/,$p' > "$OUT/$c/props/$p.json"
      r="$(jq -c '{cases:.cases_run,holds,violations,inconclusive}' "$OUT/$c/props/$p.json" 2>/dev/null)"
      [ -z "$r" ] && r="NOT RUN: $(grep -o 'no cases could be generated[^.]*' "$OUT/$c/props/$p.stderr" | head -1)"
      printf '   %-30s %s\n' "$p" "$r"
    done
  fi
done
