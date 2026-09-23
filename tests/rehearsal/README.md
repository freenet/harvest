# Migration rehearsal against a live node

Everything in `ui/src/migrate.rs` is otherwise proven by unit tests that hand
the probe its answers. This harness makes a real Freenet node give those
answers instead: it plants a seller's store at superseded generations, walks
the lineage as the current build, and checks what comes back.

It compiles the **real** `ui/src/migrate.rs` (via `#[path]`) and runs the
**same** registry codegen `ui/build.rs` runs, so the ids it walks are the ids
the app walks. It is its own cargo workspace, so building it can never move a
dependency version the contracts compile against -- which would re-key the
artifacts it exists to check.

## What it establishes

1. **The addresses agree.** `migrate::store_candidate_ids` and the node's own
   derivation (`WrappedContract::key()`) produce the same instance ids, with
   the legacy parameter encoding derived here independently of `migrate.rs`'s
   private copy of it. Measured: 109 bytes for generations <=
   `LAST_LEGACY_STORE_PARAM_GENERATION`, 56 for the current shape.
2. **A populated predecessor is recovered.** State is planted at two
   generations, and the fold carries BOTH forward -- checked by comparing
   actual field values (`info.version`, `store_name`, listing titles) and by
   re-verifying every recovered listing's signature, never by a count or an
   `Ok`.
3. **The forward PUT is accepted by the current contract**, and repeating it
   against an already-populated successor neither duplicates nor drops
   anything.
4. **Scenario 1b, the control:** the same lineage derived with today's
   parameters -- what the code would do without the generation split -- finds
   nothing at five addresses and reports a clean "nothing to migrate" over a
   populated store. That is the silent data loss the split exists to prevent,
   demonstrated rather than argued.
5. **Nothing-to-find seals nothing.** A seller with no predecessor state takes
   the seed-local path, and the seal decision is `Retry`.

## Running it

```sh
freenet local --ws-api-port 7599 \
  --config-dir /tmp/rehearsal-node/config --data-dir /tmp/rehearsal-node/data &
cargo run -- ws://127.0.0.1:7599
```

The predecessor WASM comes out of git history by hash (the registries record
hashes, not commits), so no artifacts need to be checked in or passed on the
command line.

## Read this before pointing it at a network-mode node

**`freenet network` rewrites your `gateways.toml`.** Starting a node with
`gateways = []` in its config dir, expecting an isolated peer, produces a node
whose gateway file has been replaced with the real bootstrap list and which
joins the live network -- and whose PUTs are relayed onto it at `htl=10`. That
happened during the first run of this harness: three rehearsal contracts went
onto the production network through nova's gateways before anyone noticed.

So: **verify what the node wrote, not what you passed it.** After startup,
`cat <config-dir>/gateways.toml` and check the log for
`freenet::ring: Adding connection to peer`. No connections means isolated.

`freenet local` does not do this and is the safe default -- at the cost below.

## Two things this cannot check, and why

* **`freenet local` never answers `NotFound`.** It answers
  `client error: missing contract: <id>`; `ContractResponse::NotFound` is only
  produced by the network GET path when its retry loop exhausts
  (`operations/get/op_ctx_task.rs`). The app drops error responses, so on a
  local node every absent predecessor costs a full `PROBE_TIMEOUT_MS` (12s)
  before being recorded as unresolved, and `unresolved` is then never empty --
  **so a walk can never seal against a local node.** That is safe, and it looks
  exactly like a broken migration. The seed-local and sealable outcomes were
  observed on a network-mode node.
* **The durable marker cannot be exercised from here.** The harvest delegate
  requires `MessageOrigin::WebApp(_)`, which the node attests only for a
  webapp-served frame; a native websocket client gets
  `execution error, cause missing message origin`. So `GetMigrationMarker` /
  `SetMigrationMarker` -- the repeat gate that replaced `localStorage` because
  that failed silently -- is still unproven against a live node. Closing that
  gap needs the app in a browser.

## The delegate secret migration: `delegate-rehearsal.sh`

The walk in `ui/src/delegate_migrate.rs` runs in the browser, so its
rehearsal loads the real app: `delegate-rehearsal.sh <newui-dir> <work-dir>`
seeds a superseded delegate generation through its own handlers
(`src/bin/delegate.rs seed`), loads the build under test in headless
Chromium (`load-ui.js`), and asks the current delegate for every seeded
secret (`check`). The script header says what `<newui-dir>` holds.

**It runs a `freenet network` node, not `freenet local`, and that is the
point of it.** A local node answers a message to a delegate it never
registered with `DelegateError::Missing`; a network node answers the same
message with an empty response. The first delegate rehearsals ran on
`freenet local` and passed while every real walk stopped at the first
generation its node never ran (harvest#150). The node is an isolated
gateway (`--is-gateway --skip-load-from-network`), which never loads a
gateway list, and the script fails if its log shows a peer connection.

It fails on a walk that reports `stopped` or `current delegate unavailable`,
not only on a missing secret: the newest-predecessor scenario imports every
secret before it stops, so checking values alone passes a broken walk.

## Not wired into CI

It needs a live node, which is a separate decision from running it.
