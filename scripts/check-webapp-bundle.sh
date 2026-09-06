#!/bin/bash
# Publish gate: refuse a webapp archive that is not self-consistent.
#
# WHY THIS EXISTS
#
# dx writes CONTENT-HASHED asset filenames, so a changed build lands beside its
# predecessor rather than replacing it. Nothing prunes the old one and the
# publish task tars the whole directory, so the bundle is append-only across
# builds: it grows a full UI wasm on every publish, indefinitely. The live
# Harvest container was measured carrying TEN copies, 37.7 MB uncompressed,
# where Delta and River carry one each (harvest#4).
#
# The wasted bytes are the smaller cost. With several wasms in the bundle, "did
# my fix ship?" can no longer be answered by grepping the bundle, because a grep
# for a new symbol hits a stale copy just as readily as the live one. Checking
# reachability here is what keeps grep-the-bundle an honest deploy check.
#
# Ported from delta's scripts/check-webapp-bundle.sh (delta#70, delta#46),
# which was written against the identical dx behaviour. Both incidents its
# comments describe are load-bearing; read them before simplifying anything
# here.
#
# WHAT IT ASSERTS
#
# Every file in the archive is accounted for, in one of exactly two ways:
#
#   REQUIRED  - a fixed-name file the app needs at runtime. These cannot be
#               covered by reachability: contracts/*.wasm are fetched via a path
#               the app builds at run time, so their names appear nowhere in the
#               bundle. Their absence is checked directly instead.
#
#   ACCOUNTED - carries a dx content hash in its name (check 0) AND is
#               referenced, transitively, from index.html (check 1).
#
# Both are needed and neither is redundant: hash-shape catches an unhashed stray
# whatever any file happens to contain, and reachability catches a HASHED orphan
# from an earlier build -- the harvest#4 bug -- which hash-shape cannot
# distinguish from the live one.
set -euo pipefail

ARCHIVE="${1:?usage: check-webapp-bundle.sh <webapp.tar.xz>}"
[ -f "$ARCHIVE" ] || { echo "FAILED: no such archive: $ARCHIVE"; exit 1; }
# Absolute: the checks below run from inside a temp extraction dir.
ARCHIVE="$(cd "$(dirname "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
tar -xJf "$ARCHIVE" -C "$WORK"
cd "$WORK"

fail() { echo "FAILED: $*"; exit 1; }

# Fixed-name files the app needs. index.html is first because everything else
# is judged relative to it. harvest-logo.svg is REQUIRED rather than a
# reachability candidate because it is not content-hashed: it is copied in by
# build-ui and referenced from harvest.css by a fixed name.
REQUIRED=(
    index.html
    harvest.css
    harvest-logo.svg
    contracts/store_contract.wasm
    contracts/reputation_contract.wasm
    contracts/mailbox_contract.wasm
    contracts/harvest_delegate.wasm
    contracts/ghostkey_delegate.wasm
)

MISSING=()
for f in "${REQUIRED[@]}"; do
    [ -f "$f" ] || MISSING+=("$f")
done
if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "FAILED: the archive is missing ${#MISSING[@]} file(s) the app needs:"
    printf '          %s\n' "${MISSING[@]}"
    exit 1
fi

mapfile -t ALL < <(find . -type f -printf '%P\n' | sort)

dir_of() { case "$1" in */*) printf '%s' "${1%/*}" ;; *) printf '' ;; esac; }

CANDIDATES=()
for f in "${ALL[@]}"; do
    skip=""
    for r in "${REQUIRED[@]}"; do [ "$f" = "$r" ] && { skip=1; break; }; done
    [ -n "$skip" ] || CANDIDATES+=("$f")
done
[ "${#CANDIDATES[@]}" -gt 0 ] || fail "archive contains no app assets -- the build produced nothing"

# CHECK 0: every non-required file must carry a dx content hash in its name.
#
# PRIMARY check because it involves no parsing, so nothing a file happens to
# contain can talk it out of a refusal. In delta this caught dx's staged
# UNHASHED wasm-bindgen output, which the reachability scan below had laundered
# into "reachable" via a substring coincidence -- the loader legitimately
# contains wasm-bindgen's default name. If dx ever changes its hash format this
# starts refusing everything, which is loud rather than silent: the correct
# direction for a publish gate to fail.
UNHASHED=()
for f in "${CANDIDATES[@]}"; do
    [[ "${f##*/}" =~ -dxh[0-9a-f]+\.[A-Za-z0-9]+$ ]] || UNHASHED+=("$f")
done
if [ "${#UNHASHED[@]}" -gt 0 ]; then
    echo "FAILED: ${#UNHASHED[@]} file(s) carry no dx content hash and are not required files:"
    for f in "${UNHASHED[@]}"; do
        echo "          $f ($(stat -c%s "$f") bytes)"
    done
    echo "        dx names every bundled asset <name>-dxh<hash>.<ext>. An unhashed"
    echo "        file here is a stray, or a fixed-name file that belongs in"
    echo "        REQUIRED above. See harvest#4."
    exit 1
fi

# CHECK 1: transitive reachability from index.html, for orphans that DO carry a
# hash (a previous build's asset, which check 0 cannot distinguish). Files are
# scanned as text because the loader names its wasm. References resolve RELATIVE
# TO THE REFERRER: a candidate is reached if the referrer contains its full
# archive path, or its bare basename AND the two share a directory.
declare -A REACHED=()
FRONTIER=("index.html")
while [ "${#FRONTIER[@]}" -gt 0 ]; do
    current="${FRONTIER[0]}"
    FRONTIER=("${FRONTIER[@]:1}")
    current_dir="$(dir_of "$current")"
    for f in "${CANDIDATES[@]}"; do
        [ -n "${REACHED[$f]:-}" ] && continue
        if grep -aqF -- "$f" "$current" \
           || { [ "$(dir_of "$f")" = "$current_dir" ] && grep -aqF -- "${f##*/}" "$current"; }; then
            REACHED[$f]=1
            FRONTIER+=("$f")
        fi
    done
done

UNREACHED=()
for f in "${CANDIDATES[@]}"; do
    [ -n "${REACHED[$f]:-}" ] || UNREACHED+=("$f")
done
if [ "${#UNREACHED[@]}" -gt 0 ]; then
    echo "FAILED: ${#UNREACHED[@]} file(s) in the bundle are unreachable from index.html:"
    for f in "${UNREACHED[@]}"; do
        echo "          $f ($(stat -c%s "$f") bytes)"
    done
    echo "        These are stale copies from earlier builds -- the harvest#4 bug."
    echo "        Every published byte should be reachable. Clean the dx output"
    echo "        directory and rebuild."
    exit 1
fi

# The chain must actually resolve, so an asset-less bundle cannot pass check 1
# vacuously.
JS_REF=""
for f in "${CANDIDATES[@]}"; do
    case "$f" in *.js) if grep -aqF -- "${f##*/}" index.html; then JS_REF="$f"; break; fi ;; esac
done
[ -n "$JS_REF" ] || fail "index.html references no js in the bundle -- there is no entry point"

WASM_REF=""
for f in "${CANDIDATES[@]}"; do
    case "$f" in *.wasm) if grep -aqF -- "${f##*/}" "$JS_REF"; then WASM_REF="$f"; break; fi ;; esac
done
[ -n "$WASM_REF" ] || fail "$JS_REF references no wasm in the bundle -- the loader has nothing to load"

# Staleness guard: if the build output this archive was made from is still on
# disk, the archive must describe it. Catches a gate inspecting a tarball from
# an earlier build -- a gate that ran, but not against the thing being
# published. Skipped when the tree is absent.
BUILD_DIR="$(dirname "$ARCHIVE")/../dx/harvest-ui/release/web/public"
if [ -d "$BUILD_DIR" ]; then
    on_disk="$(find "$BUILD_DIR" -type f -printf '%P\n' | sort)"
    in_archive="$(printf '%s\n' "${ALL[@]}")"
    [ "$on_disk" = "$in_archive" ] || fail \
        "archive contents do not match the build output at $BUILD_DIR -- this archive is stale"
fi

echo "Bundle OK: index.html -> $JS_REF -> $WASM_REF"
echo "  ${#ALL[@]} file(s): ${#REQUIRED[@]} required, ${#CANDIDATES[@]} reachable from index.html"
echo "  archive:   $(du -h "$ARCHIVE" | cut -f1) compressed"
echo "  extracted: $(du -sh . | cut -f1)"
