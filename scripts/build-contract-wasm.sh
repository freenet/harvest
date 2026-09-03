#!/usr/bin/env bash
# Build every Harvest contract and delegate to WASM, reproducibly, and print
# each artifact's BLAKE3 code hash.
#
# WHY THIS EXISTS. A Freenet contract's address is derived from the hash of its
# compiled WASM (`BLAKE3(BLAKE3(wasm) || parameters)`), so the compiled bytes
# ARE the identity of every store, reputation and mailbox contract, and of the
# harvest delegate. Anything that changes codegen moves the address and orphans
# whatever lived at the old one: a direct dependency bump, a TRANSITIVE bump, a
# rustc upgrade, or a stray RUSTFLAG. None of those show up as a source diff.
#
# Two things make the build deterministic, and both are load-bearing:
#
#   1. rust-toolchain.toml pins the exact compiler. Toolchain drift is the
#      largest single source of silent re-keys.
#   2. --remap-path-prefix strips machine-specific absolute paths. Without it
#      the checkout directory and `$CARGO_HOME` leak into panic-location
#      strings baked into the binary, so the same source produces different
#      bytes on two machines. The artifacts committed under
#      `ui/public/contracts/` today were built WITHOUT this and carry
#      `/home/<user>/.cargo/registry/...` strings; they are therefore not
#      reproducible by anyone else. `-Zremap-path-scope`/`trim-paths` would be
#      tidier but is unstable on the pinned stable toolchain.
#
# This is the ONE build path for these artifacts. `cargo make sync-wasm` calls
# it, and CI's drift guard calls it, so the hashes CI reports are the hashes a
# publish would deploy. Do not add a second `cargo build` for these crates.
#
# Usage:
#   scripts/build-contract-wasm.sh            # build + print code hashes
#   scripts/build-contract-wasm.sh --sync     # also copy into ui/public/contracts/
#
# Environment:
#   HARVEST_ALLOW_UNLOCKED=1   build without --locked (only for building an
#                              older commit that predates the committed
#                              Cargo.lock; never for a normal build, because
#                              re-resolving dependencies changes the address)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(cd "$here/.." && pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"

sync=0
for arg in "$@"; do
  case "$arg" in
    --sync) sync=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# The four artifacts whose compiled bytes are network addresses. Keep in step
# with the workspace members under contracts/ and delegates/; a crate missing
# from this list is a crate the drift guard does not watch.
crates=(reputation-contract store-contract mailbox-contract harvest-delegate)
artifacts=(reputation_contract store_contract mailbox_contract harvest_delegate)

# `ghostkey_delegate.wasm` is deliberately absent: it is vendored from
# freenet/ghostkeys, not built here, so nothing in this workspace can move it.
# (It has its own problem -- see freenet/harvest#5 -- but not this one.)

locked=(--locked)
if [ "${HARVEST_ALLOW_UNLOCKED:-0}" = "1" ]; then
  locked=()
  echo "warning: building WITHOUT --locked; dependency resolution is not pinned" >&2
elif [ ! -f "$workspace/Cargo.lock" ]; then
  echo "error: no Cargo.lock. The compiled address depends on the resolved" >&2
  echo "       dependency versions, so an unpinned build is not meaningful." >&2
  echo "       Run 'cargo generate-lockfile' and commit the result, or set" >&2
  echo "       HARVEST_ALLOW_UNLOCKED=1 if you are deliberately building an" >&2
  echo "       older commit that predates it." >&2
  exit 1
fi

# Order matters: rustc applies the FIRST matching prefix, so the checkout has
# to be remapped before the broader home directories that may contain it.
export RUSTFLAGS="\
--remap-path-prefix=$workspace=/harvest \
--remap-path-prefix=$cargo_home=/cargo \
--remap-path-prefix=$rustup_home=/rustup \
${RUSTFLAGS:-}"

cd "$workspace"

# One invocation for all four. This is NOT cosmetic: cargo unifies features
# across the packages it is asked to build in a single invocation, so building
# a subset can resolve different features and produce different bytes than
# building them together.
cargo build "${locked[@]}" --release --target wasm32-unknown-unknown \
  $(printf -- '-p %s ' "${crates[@]}")

out="$workspace/target/wasm32-unknown-unknown/release"

if ! command -v b3sum >/dev/null 2>&1; then
  echo "error: b3sum not found. It is needed to report the BLAKE3 code hash," >&2
  echo "       which is what the contract address is derived from." >&2
  echo "       Install with: cargo install b3sum --locked" >&2
  exit 1
fi

echo
echo "BLAKE3 code hashes (the contract address is BLAKE3(code_hash || parameters)):"
for a in "${artifacts[@]}"; do
  f="$out/$a.wasm"
  [ -f "$f" ] || { echo "error: expected artifact not built: $f" >&2; exit 1; }
  printf '  %-22s %s\n' "$a" "$(b3sum "$f" | cut -d' ' -f1)"
done

if [ "$sync" = 1 ]; then
  mkdir -p "$workspace/ui/public/contracts"
  for a in "${artifacts[@]}"; do
    cp "$out/$a.wasm" "$workspace/ui/public/contracts/$a.wasm"
  done
  echo
  echo "Synced to ui/public/contracts/. Every address above is now what the UI"
  echo "embeds; if any of them moved, plan the migration before publishing."
fi
