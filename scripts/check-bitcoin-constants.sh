#!/usr/bin/env bash
# Compare this build's Bitcoin ADDRESSING constants against a running bridge.
#
# WHY THIS EXISTS
#
# A contract lives at BLAKE3(BLAKE3(wasm) || parameters), so rebuilding the
# Bitcoin contracts re-keys them. Harvest pins the resulting values as
# build-time constants in ui/src/gateway/bitcoin_config.rs, because the gateway
# CSP forbids the published app from asking a bridge at runtime (harvest#29) --
# correctly, since a Freenet webapp reaches the network through its node.
#
# On 2026-09-06 both constants were found stale, one by five generations
# (harvest#30). Nothing caught it: they were WELL-FORMED, and the only test
# asserted well-formedness. The failure was not silence, which is what makes it
# nasty -- the superseded tip contract still exists and still holds its last
# state, so the app rendered a chain tip ~400 blocks old as though it were
# current, and every invoice named an address contract that was never
# published.
#
# This script is the stopgap gate until pointer records land. It cannot run in
# CI (there is no bridge there), so it runs at PUBLISH time, which is the
# moment the cost is actually incurred.
#
# EXIT CODES -- distinguished on purpose:
#   0  checked, and the constants match
#   1  checked, and they DISAGREE, or a constant could not be read at all
#   2  could NOT check (no bridge reachable)
#
# 2 is separate from 0 because "I could not look" must never be recorded as "it
# is fine". That conflation is the defect this whole file exists to answer.

set -uo pipefail

BRIDGE_URL="${1:-${HARVEST_BRIDGE_URL:-http://127.0.0.1:8431}}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO_ROOT/ui/src/gateway/bitcoin_config.rs"

if [ ! -f "$CONFIG" ]; then
  echo "error: cannot find $CONFIG" >&2
  exit 1
fi

# Read the constants out of the source. Anchored so a rename or reshuffle makes
# the extraction FAIL rather than silently return nothing -- an empty value
# compared against an empty value would otherwise "match".
#
# The tip id is read from the Signet arm specifically; the constant is a
# per-network match and grepping the whole function would pick up whichever
# arm came first.
built_tip="$(sed -n 's/.*BitcoinNetwork::Signet => Some("\([1-9A-HJ-NP-Za-km-z]*\)").*/\1/p' "$CONFIG" | head -1)"
built_addr="$(sed -n '/pub const ADDRESS_CONTRACT_CODE_HASH_HEX/,/;/p' "$CONFIG" \
              | sed -n 's/.*"\([0-9a-f]\{64\}\)".*/\1/p' | head -1)"

if [ -z "$built_tip" ] || [ -z "$built_addr" ]; then
  echo "error: could not read the constants out of $CONFIG." >&2
  echo "       tip='$built_tip' addr='$built_addr'" >&2
  echo "       This script's extraction has drifted from the source. Fix the" >&2
  echo "       extraction -- do NOT treat an unreadable constant as a pass." >&2
  exit 1
fi

status="$(curl -fsS --max-time 10 "$BRIDGE_URL/v1/status" 2>/dev/null)" || status=""
if [ -z "$status" ]; then
  echo "could not reach a bridge at $BRIDGE_URL, so the constants were NOT checked." >&2
  echo "  built tip contract (signet): $built_tip" >&2
  echo "  built address code hash:     $built_addr" >&2
  echo "  Start a bridge, pass one as \$1, or set HARVEST_BRIDGE_URL." >&2
  exit 2
fi

live_tip="$(printf '%s' "$status" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for n in d.get("networks",[]):
    if n.get("network")=="signet":
        print(n.get("tip_contract_id") or "")
        break
' 2>/dev/null)"
live_addr="$(printf '%s' "$status" | python3 -c '
import json,sys
print(json.load(sys.stdin).get("address_code_hash") or "")
' 2>/dev/null)"

if [ -z "$live_tip" ] || [ -z "$live_addr" ]; then
  echo "error: the bridge at $BRIDGE_URL answered, but not with the fields" >&2
  echo "       this check needs (signet tip_contract_id, address_code_hash)." >&2
  echo "       Treating that as a failure rather than a pass." >&2
  exit 1
fi

rc=0
if [ "$built_tip" != "$live_tip" ]; then
  echo "MISMATCH: signet tip contract" >&2
  echo "  built:  $built_tip" >&2
  echo "  bridge: $live_tip" >&2
  rc=1
fi
if [ "$built_addr" != "$live_addr" ]; then
  echo "MISMATCH: address contract code hash" >&2
  echo "  built:  $built_addr" >&2
  echo "  bridge: $live_addr" >&2
  rc=1
fi

if [ "$rc" -ne 0 ]; then
  echo "" >&2
  echo "This build's addressing constants disagree with the bridge at $BRIDGE_URL." >&2
  echo "Publishing it would show stale chain data as though it were live and" >&2
  echo "issue invoices that can never be observed as paid. See harvest#30." >&2
  echo "Update ui/src/gateway/bitcoin_config.rs before publishing." >&2
  exit 1
fi

echo "bitcoin constants match the bridge at $BRIDGE_URL"
echo "  signet tip contract:      $built_tip"
echo "  address contract code hash: $built_addr"
