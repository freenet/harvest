#!/usr/bin/env bash
# Rehearse the harvest delegate's secret migration (harvest#123) against a
# NETWORK-MODE node, the way a user's node runs.
#
# Usage:
#   tests/rehearsal/delegate-rehearsal.sh <newui-dir> <work-dir>
#
# <newui-dir> holds the build under test, signed with the real key:
#   webapp.tar.xz, webapp.metadata   (from `cargo make sign-webapp`, target/webapp/)
#   harvest_delegate.wasm            (ui/public/contracts/harvest_delegate.wasm of that build)
# Restore published-contract/last-version after signing: a rehearsal is not a publish.
#
# Needs on PATH: freenet, fdev, node (with Playwright; set PLAYWRIGHT_MODULE to
# its path if it is not resolvable), b3sum, curl, git. Builds the harness
# (`cargo build --bin delegate`) if it is missing.
#
# # Why network mode, and why this is a script in the repo
#
# The first rehearsals ran on `freenet local` from a script outside the repo,
# and passed while real walks were broken (harvest#150). A `freenet local` node
# answers a message to a delegate it never registered with
# `DelegateError::Missing`; a `freenet network` node answers the SAME message
# with an empty `DelegateResponse` (freenet-core `contract.rs`, "Delegate not
# found in store (expected for migration probes)"). The app waited for the
# first shape only, so on every real node the first generation the node never
# ran cost a 20 s timeout and stopped the walk: nothing older was imported,
# and the walk was never complete, so the encryption-key mint it gates never
# ran. `freenet local` could not show that, and nothing checked whether the
# walk stopped. So this runs an isolated network-mode gateway (`--is-gateway
# --skip-load-from-network`, which never loads a gateway list and so has no
# peer to join) and fails on a walk that stops, as well as on a secret that
# does not arrive.
#
# # Scenarios, each on a fresh node
#
#   skipped:  the second-newest predecessor holds the data and the newest was
#             never registered: a user who skipped a release. The walk must
#             pass the unregistered generation and import the older one.
#   newest:   the newest predecessor holds the data (the common upgrade); every
#             older generation is unregistered and must not stop the walk.
#
# In both the walk must report the seeded generation `imported`, must reach a
# verdict on every generation (no "stopped", "current delegate unavailable",
# "incomplete", or "did not reach every generation"), and the current
# delegate must then answer every seeded secret value for value and hold the
# seeded generation sealed `Done`.
#
# First, on its own node: every generation from V5, registered, answers the
# walk's two predecessor calls with a message (see `answers_all`).
set -euo pipefail

NEWUI=$(readlink -f "$1")
WORK=$(readlink -f "$2")
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
PORT=${REHEARSAL_WS_PORT:-7697}
NETPORT=${REHEARSAL_NET_PORT:-31697}
CONTAINER=$(cat "$REPO/published-contract/contract-id.txt")
HARNESS=$HERE/target/debug/delegate
# Always (incremental, so cheap): a stale binary would check an old harness.
(cd "$HERE" && cargo build --quiet --bin delegate)
mkdir -p "$WORK"

# Oldest first, as the registry lists them: "V<n> <code_hash> <delegate_key>".
mapfile -t ROWS < <(awk -F'"' '/^version/{v=$2} /^code_hash/{c=$2} /^delegate_key/{print v, c, $2}' \
  "$REPO/legacy/harvest_delegate.toml")
NEWEST=(${ROWS[-1]})
SECOND=(${ROWS[-2]})

# A superseded generation's WASM, out of git history by hash (as
# `legacy/README.md` prescribes; the registries record hashes, not commits).
wasm_by_hash() {
  local want=$1 out=$2 path=ui/public/contracts/harvest_delegate.wasm sha
  for sha in $(git -C "$REPO" log --all --format=%H -- "$path"); do
    git -C "$REPO" show "$sha:$path" > "$out" 2>/dev/null || continue
    [ "$(b3sum --no-names "$out")" = "$want" ] && return 0
  done
  echo "no revision of $path hashes to $want" >&2
  return 1
}

NODE_PID=
stop_node() {
  [ -n "$NODE_PID" ] || return 0
  kill "$NODE_PID" 2>/dev/null || true
  for _ in $(seq 1 30); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 1; done
  if kill -0 "$NODE_PID" 2>/dev/null; then echo "node $NODE_PID did not stop" >&2; exit 1; fi
  NODE_PID=
}
trap stop_node EXIT

start_node() {
  local d=$1
  rm -rf "$d"; mkdir -p "$d"/{config,data,log,cache}
  if ss -ltn | grep -q "127.0.0.1:$PORT "; then echo "port $PORT is in use" >&2; exit 1; fi
  # No `setsid`: in a script (no job control) the background child is the
  # node itself, so `$!` is its pid from the start, and a node that never
  # binds is still stopped by the EXIT trap rather than left running.
  FREENET_WEBAPP_CACHE_DIR=$d/cache freenet network --is-gateway --skip-load-from-network \
    --disable-auto-update --public-network-address 127.0.0.1 --public-network-port "$NETPORT" \
    --network-port "$NETPORT" --ws-api-address 127.0.0.1 --ws-api-port "$PORT" \
    --config-dir "$d/config" --data-dir "$d/data" --log-dir "$d/log" > "$d/stdout.log" 2>&1 < /dev/null &
  NODE_PID=$!
  for _ in $(seq 1 90); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 1; done
  local owner
  owner=$(ss -ltnp | grep "127.0.0.1:$PORT " | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2 || true)
  [ "$owner" = "$NODE_PID" ] || { echo "the node did not start, or port $PORT is not ours (see $d/stdout.log)" >&2; exit 1; }
  echo "   node pid $NODE_PID, network mode, gateway isolated"
}

URL="ws://127.0.0.1:$PORT/v1/contract/command?encodingProtocol=native"
PAGE="http://127.0.0.1:$PORT/v1/contract/web/$CONTAINER/"
token() { curl -s "$PAGE" | grep -oE 'freenetBridge\("[1-9A-HJ-NP-Za-km-z]+"' | head -1 | cut -d'"' -f2; }
publish_ui() {
  fdev --node-url "$URL" publish --code "$REPO/published-contract/web_container_contract.wasm" \
    --parameters "$REPO/published-contract/webapp.parameters" contract \
    --webapp-archive "$NEWUI/webapp.tar.xz" --webapp-metadata "$NEWUI/webapp.metadata" 2>&1 \
    | grep -qE "Contract (published|updated) successfully"
}

FAILED=0
scenario() {
  local name=$1 gen=$2 code=$3 key=$4
  local d=$WORK/$name
  echo "== scenario $name: $gen ($code) holds the data"
  start_node "$d/node"
  publish_ui || { echo "   FAIL: could not publish the UI under test"; FAILED=1; stop_node; return; }
  wasm_by_hash "$code" "$d/predecessor.wasm"
  # Seeded through the predecessor's own handlers, before the app first loads.
  "$HARNESS" seed "$URL&authToken=$(token)" "$d/predecessor.wasm" "$d/seeded.json" > "$d/seed.log" 2>&1 \
    || { echo "   FAIL: seeding $gen (see $d/seed.log)"; FAILED=1; stop_node; return; }
  node "$HERE/load-ui.js" "$PAGE" "$d/load.log" 150 || true
  local walk
  walk=$(grep -oE "delegate migration: V[0-9]+.*" "$d/load.log" | head -1 || true)
  echo "   ${walk:-(no walk line)}"
  local ok=1
  [ -n "$walk" ] || ok=0
  grep -qE "(: |, )$gen: imported [1-9]" <<< "$walk" || { echo "   FAIL: $gen was not imported"; ok=0; }
  if grep -qE "stopped|current delegate unavailable|incomplete" <<< "$walk" \
      || grep -q "did not reach every generation" "$d/load.log"; then
    echo "   FAIL: the walk did not reach a verdict on every generation"; ok=0
  fi
  if "$HARNESS" check "$URL&authToken=$(token)" "$NEWUI/harvest_delegate.wasm" "$d/seeded.json" "$key" \
      > "$d/check.txt" 2>&1; then
    grep -E "^(OK|FAIL)" "$d/check.txt" | sed 's/^/   /'
  else
    grep -E "^(OK|FAIL)|panicked|assertion" "$d/check.txt" | sed 's/^/   /'
    echo "   FAIL: the current delegate did not answer every seeded secret (see $d/check.txt)"; ok=0
  fi
  local peers
  peers=$(cat "$d"/node/log/*.log 2>/dev/null | grep -c "Adding connection to peer" || true)
  [ "$peers" = 0 ] || { echo "   FAIL: the node connected to $peers peer(s); it was not isolated"; ok=0; }
  stop_node
  if [ "$ok" = 1 ]; then echo "   PASS"; else FAILED=1; fi
}

# Every generation the walk asks (V5 on), registered on today's node, must
# answer both predecessor calls with a message: the app reads an empty answer
# as "not registered", which is right only if a registered one never gives
# one. A generation that no longer runs on this node fails here too.
answers_all() {
  local d=$WORK/answers row v code key n
  echo "== every exporting generation answers the probe and the export with a message"
  start_node "$d/node"
  publish_ui || { echo "   FAIL: could not publish the UI under test"; FAILED=1; stop_node; return; }
  for row in "${ROWS[@]}"; do
    read -r v code key <<< "$row"
    n=${v#V}
    [ "$n" -ge 5 ] || continue
    wasm_by_hash "$code" "$d/$v.wasm"
    if "$HARNESS" answers "$URL&authToken=$(token)" "$d/$v.wasm" "$n" > "$d/$v.txt" 2>&1; then
      echo "   $v: yes"
    else
      echo "   FAIL: $(grep -E "probe:|export:|panicked" "$d/$v.txt" | tr '\n' ' ')"; FAILED=1
    fi
  done
  stop_node
}

echo "== build under test: delegate $(b3sum --no-names "$NEWUI/harvest_delegate.wasm" | cut -c1-8)"
answers_all
scenario skipped "${SECOND[0]}" "${SECOND[1]}" "${SECOND[2]}"
scenario newest "${NEWEST[0]}" "${NEWEST[1]}" "${NEWEST[2]}"
if [ "$FAILED" = 0 ]; then echo "DELEGATE REHEARSAL PASSED"; else echo "DELEGATE REHEARSAL FAILED"; exit 1; fi
