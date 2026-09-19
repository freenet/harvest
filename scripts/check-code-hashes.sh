#!/usr/bin/env bash
# Print each artifact's current ADDRESS -- code hash AND parameter bytes -- and
# REFUSE if one of the code hashes is already recorded as a superseded
# generation in `legacy/`.
#
# WHY AN ADDRESS AND NOT JUST A CODE HASH.
#
# A contract lives at `BLAKE3(BLAKE3(wasm) || parameters)`, so the compiled
# bytes are only HALF of its identity. This script used to print the code hash
# alone, as did CI's drift guard, which meant a change touching only a
# parameter struct moved every published instance while both guards said
# "unchanged" -- truthfully, because the WASM really was byte-identical.
#
# `StoreParameters` shedding two fields is exactly that: its CBOR went from 109
# bytes to 56, every published store re-keyed, and the only symptom would have
# been the migration probe walking addresses that never existed and reporting a
# clean "nothing to migrate". The address comes from
# `common/src/bin/harvest-addresses.rs`, which encodes the live parameter
# structs with the same encoder the app publishes with; both this script and
# `.github/workflows/contract-drift.yml` call it, so there is one derivation
# rather than two that drift.
#
# WHAT THE REFUSAL CATCHES, and why it is a hard failure rather than a note.
#
# `legacy/*.toml` lists SUPERSEDED generations only; the current generation is
# derived at runtime from the WASM this build ships and is deliberately never
# written down. So the current hash appearing in a registry means one of two
# things, and both are bugs:
#
#   * the outgoing hash was appended and the artifact was then NOT rebuilt, so
#     the registry describes a generation that is still live -- the probe would
#     walk to its own instance, find its own state, and report a successful
#     migration having moved nothing; or
#   * the change that moved the hash was reverted after the entry was recorded.
#
# Either way the lineage no longer describes reality, and nothing says so at
# runtime: every path reports success.
#
# The intended order is: run this, append the hash it prints, THEN rebuild
# (`cargo make sync-wasm`).
#
# NOTE the registries record CODE HASHES, not addresses, because that is what
# `freenet_migrate` derives a predecessor from -- it re-derives the address by
# pairing each recorded hash with parameter bytes. So the refusal below is
# still a code-hash check. A parameters-only change leaves every registry entry
# intact and still re-keys everything, which is why the ADDRESS column exists
# and why `ui/src/migrate.rs` carries `LAST_LEGACY_STORE_PARAM_GENERATION`.
#
# Assumes the artifacts are already built -- `cargo make code-hashes` depends
# on the build task, and CI runs the build script in the same job. It does NOT
# build them itself, because building here would mean a second build path for
# bytes that are network addresses, which is the thing
# `scripts/build-contract-wasm.sh` exists to prevent.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(cd "$here/.." && pwd)"
out="${1:-$workspace/target/wasm32-unknown-unknown/release}"

# artifact:registry. Keep in step with the artifact list in
# build-contract-wasm.sh, with the table in harvest-addresses.rs, and with the
# tables in ui/build.rs; an artifact missing here is an artifact this guard
# does not watch.
pairs=(
  "store_contract:legacy/store_contract.toml"
  "reputation_contract:legacy/reputation_contract.toml"
  "mailbox_contract:legacy/mailbox_contract.toml"
  "index_contract:legacy/index_contract.toml"
  "harvest_delegate:legacy/harvest_delegate.toml"
)

# `--locked` for the same reason the contract build uses it: the address
# depends on the resolved dependency versions, so an unpinned resolve is not
# the thing being published. The escape hatch matches the build script's.
locked=(--locked)
if [ "${HARVEST_ALLOW_UNLOCKED:-0}" = "1" ]; then
  locked=()
fi

addresses="$(cargo run "${locked[@]}" --quiet \
  --manifest-path "$workspace/Cargo.toml" \
  -p harvest-common --features harvest-common/address-guard \
  --bin harvest-addresses -- "$out")" || {
  echo "error: could not derive the contract addresses." >&2
  echo "       Are the artifacts built? Run 'cargo make build-contract-wasm'." >&2
  exit 1
}

field() { # artifact, column index
  printf '%s\n' "$addresses" | grep -v '^#' | awk -F'\t' -v a="$1" -v f="$2" '$1 == a { print $f }'
}

bad=0
printf '%-22s %-64s %-10s %-44s %s\n' artifact "current code hash" "params" "address" registry
for pair in "${pairs[@]}"; do
  a="${pair%%:*}"
  reg="$workspace/${pair#*:}"

  h="$(field "$a" 3)"
  plen="$(field "$a" 4)"
  addr="$(field "$a" 6)"
  # An artifact the tool did not report is an artifact this guard cannot
  # check. Never a skip: "no row, nothing to check" is how a guard stops
  # being able to fail.
  if [ -z "$h" ] || [ -z "$addr" ]; then
    echo "error: harvest-addresses reported no address for $a" >&2
    bad=1
    continue
  fi
  # A missing registry is a failure, never a skip, for the same reason.
  if [ ! -f "$reg" ]; then
    echo "error: no migration registry at $reg" >&2
    bad=1
    continue
  fi

  printf '%-22s %-64s %-10s %-44s %s\n' "$a" "$h" "${plen}B" "$addr" "${pair#*:}"
  if grep -q "$h" "$reg"; then
    echo "error: ${a}'s CURRENT code hash is already recorded as superseded in ${pair#*:}." >&2
    echo "       Either the artifact was not rebuilt after the entry was added," >&2
    echo "       or the change that moved it was reverted. The registries list" >&2
    echo "       superseded generations only -- never the live one." >&2
    bad=1
  fi
done

echo
if [ "$bad" != 0 ]; then
  exit 1
fi
echo "No current hash is recorded as superseded."
echo "If a hash above differs from the one you last published, that generation"
echo "is now superseded: append it to its registry BEFORE rebuilding."
echo
echo "If the ADDRESS moved while the code hash did not, the parameter encoding"
echo "changed. No registry entry describes that -- every recorded generation is"
echo "re-derived from today's parameters -- so the split has to be handled in"
echo "ui/src/migrate.rs the way LAST_LEGACY_STORE_PARAM_GENERATION handles the"
echo "store's. Skipping it fails silently: every probe returns NotFound and the"
echo "sweep reports a clean migration having looked at addresses that never"
echo "existed."
