# Bitcoin integration — status and known gaps

What works, and — more usefully — what does not, including pre-existing
Harvest gaps that block the full buyer-side scenario and are unrelated to
Bitcoin.

> **Two claims in this document were false and are corrected in place below,
> on 9 September 2026.** It said no path in the UI issues an order, and that
> buyer-seller messaging is not implemented with no callers outside its own
> tests. Both had been overtaken by the code and neither was updated, so a
> reader using this file to decide what to build next was being pointed at work
> already done. Corrected rather than deleted, because the gap between a status
> document and the tree is the thing worth recording: a status file nobody
> re-checks is worse than no status file, since it is read as current.

## Working

- Orders in the store contract, with a monotonic status lattice and merge laws
  asserted on exact bytes.
- `AwaitingPayment → Paid` gated on bridge-signed Bitcoin evidence that any
  peer re-verifies (raw transaction, Merkle branch, block-header work) rather
  than on a bare seller signature. The re-verification fixes the amount and the
  destination out of the transaction the txid commits to, so a bridge cannot
  misreport what a real transaction paid. **The bridge is trusted for chain
  state**: nothing anchors a header to Bitcoin, and confirmation depth is
  arithmetic over the claim's asserted block height and a bridge-signed tip, so
  a trusted bridge key can assert a payment that never happened. See
  `freenet-bitcoin`'s `docs/trust-boundaries.md`.
- The store contract reaches a paid order's `BitcoinAddressContract` through
  Freenet's real related-contract mechanism, respecting the one-round limit —
  as a strictly additive cross-check that can never make valid state invalid.
- A private watch list in the delegate, never written to any contract.
- A Payments UI that subscribes to contracts and updates live.
- The bridge is deployed and observing real signet payments.
- A buyer can open a seller's store from a share link: `begin_browsing()` is
  called from `store_link::open_store_from_url`, which parses a store id out of
  the page's hash or query string, GETs the contract, and reports a failure
  rather than sitting on "Loading store…" forever.
- `mailbox_to_store` is populated, by `AppState::register_store_mailbox`. Only
  for the user's own stores: the mapping comes from the delegate's
  `StoreRegistration`, and `StoreInfoV1` names a store's reputation contract
  but not its mailbox, so it cannot be recovered from contract state for a
  store being browsed as a buyer.

## Blocking gaps for the full end-to-end scenario

### 1. A store's bridge choice is no longer permanent — but nothing issues orders yet

**The permanence is fixed.** The trusted-bridge list used to be
`StoreParameters::trusted_bitcoin_bridges`, and a contract's key is
`BLAKE3(BLAKE3(wasm) || parameters)`, so it was frozen at the store's address
for the store's whole life. `create_store_contracts` supplied an empty list
every time, which meant `verify_payment_proof` rejected with
`NoTrustedBridges` and **no order on any store this app created could ever
validate as `Paid`** — fail-closed, which is right, and permanent, which was
fatal. A bridge that went away could not be replaced either.

The list (and the paired `bitcoin_address_code_hash`) now live on
`payment::Order`, inside what the seller signs. So each invoice names the
bridges that settle it, a later invoice may name different ones, and
`StoreParameters` is back to holding only the seller's key — which genuinely
is the store's identity, and is correctly immutable. Moving the list to
mutable *state* instead would have been worse: `OrdersV1::verify` re-checks
every order on every state validation, so rotating a shared mutable list would
retroactively invalidate the whole historical order book.

**This is no longer open, and the text above is corrected.** It said no path in
the UI issues an order at all. There are now two live call sites for
`store_ops::submit_order_by_id` (`ui/src/state.rs:2863` and `:4390`), so orders
are issued and a bridge set is chosen at invoice time. The requirement it named
still holds: an order that names no bridges is unpayable, and that is now a
per-invoice mistake rather than a permanent property of the store.

The buyer side of the same move is already in place. Because the bridge set is
per-invoice, checking a store's address once no longer tells a buyer who will
observe their payment, so `OrderCard` reads it per order and warns when an
invoice names a bridge this build does not recognise
(`components::bitcoin_view::unrecognised_bridges`).

### 2. A watch is recorded and nothing is ever asked to synchronize it

`WatchForm` builds a `WatchedPayment`, the delegate persists it and answers
`Ok`, and that is the end of it. No bridge is sent a `WatchRequest`, so
`contract_id` stays `None`, no `BitcoinAddressContract` is subscribed, and no
transaction can appear for a manually watched address.

Both places the request could be made are closed:

- **The delegate cannot.** `OutboundDelegateMsg` has no HTTP variant — the
  whole set is application messages, user input, context, and contract
  GET/PUT/UPDATE/SUBSCRIBE. A delegate has no outbound HTTP capability at all.
- **The page cannot, once published.** A webapp is served with `connect-src`
  limited to its own gateway, so `fetch` to a bridge URL is refused. This is
  the same refusal that turned the tip-contract id into a build-time constant
  (see `gateway::bitcoin_config`'s module docs). It works under `dx serve`,
  where no CSP applies, which is why `bitcoin_bridge_http` exists at all.

The UI now says so rather than showing "Waiting for bridge to sync…"
indefinitely (`state::WatchSyncStatus`). Actually closing it needs a route
from a published webapp to a bridge — a contract-mediated request queue, or a
gateway-side proxy — not a smaller change to either side.

Note this does **not** affect order-driven payment watching end to end: the
tip contract and any address contract whose id is already known are subscribed
over the gateway like any other contract, and that path works.

### 3. Buyer-seller messaging — IMPLEMENTED (this section was wrong)

This section said messaging was not implemented, that
`messaging::encrypt_message`/`decrypt_message` had no callers outside their own
tests, and that `StoreInfoV1` publishes no encryption key. All three are false
and were false when written or shortly after.

`StoreInfoV1::encryption_public_key` exists (`common/src/store.rs:114`), and
the message functions have production callers: `ui/src/messaging.rs:547`, `:709`
and `:861`, plus `ui/src/state.rs:10422`. The conversation path is real, using
X25519 plus AES-GCM with a direction-separated key per side, and the mailbox
contract it writes to has a real capacity cap.

What is genuinely still missing in this area is narrower and lives elsewhere:
the pre-signed confession the complaint path needs is not built, and neither is
anything that files, cures or expires a complaint. See
`design/incentive-mechanism.md`, whose Part 5 marks what exists and what does
not.

### 4. No migration registry — this change re-keys the store contract

Adding `OrdersV1` to `StoreStateV1` changes the store contract's WASM, which
changes its code hash, which changes every store's contract key. Harvest has
**no `legacy_*.toml` registry** and has not adopted `freenet-migrate`. The only
migration mechanism that exists is `LEGACY_HARVEST_WEBAPP_CONTRACT_IDS`, which
covers the *webapp container* id and nothing else.

So any store published under the previous contract WASM is orphaned by this
change. Harvest's README describes the project as early scaffolding, so the
practical blast radius is probably zero today — but the gap should be closed
**before** anyone publishes stores they care about, because the fix is
mechanical beforehand and a data-loss incident afterwards. See the
`freenet-app-migration` skill.

## Smaller things found and fixed along the way

- **The delegate WASM did not link at all.** `rsa`'s `OsRng` pulls in
  `getrandom`, whose `custom` feature was enabled workspace-wide with no
  backend ever registered, so `cargo build --target wasm32-unknown-unknown -p
  harvest-delegate` failed at link time with `undefined symbol:
  __getrandom_custom` — at HEAD, before any Bitcoin work. Fixed by registering
  a backend over `freenet_stdlib::rand::rand_bytes`.
- **Updates were never actually live.** `on_contract_update` parsed
  `UpdateNotification` delta bytes as though they were full state. For any
  composable state the delta is a different wire shape, so every delta silently
  failed to parse and was dropped. Fixed by re-GETting full state on
  notification. This affected store and listing updates too, not just Bitcoin.
- **The committed contract WASM matched no build of this source.** All four
  artifacts under `ui/public/contracts/` differed from a fresh build and
  carried 45/63/24/43 absolute `/home/...` paths from the machine that made
  them. Since the UI embeds them with `include_bytes!`, the deployed contract
  was not the reviewed source. Rebuilt reproducibly, and `ci.yml`'s
  `wasm-staleness` job now compares the committed bytes against a fresh build
  on every PR.
- **A store edit published before its state arrived was silently discarded.**
  The next version was computed as `local.version + 1` with "no local state"
  answering 1, which is reachable on any reload — so a seller could retype
  details into an empty-looking form and have the update dropped as stale by
  last-writer-wins while the UI reported success.

## Not done

- The bridge is loopback-only with open authorization. Public exposure needs
  Ghost Key auth, rate limiting, and a TLS route first.
- No canonical bridge URL is published, so first run defaults to the user's own
  machine.
- `ui/assets/harvest.css` imports Google Fonts, which the gateway CSP blocks —
  so production Harvest has been falling back to default fonts app-wide. Real,
  pre-existing, and outside this change's scope.
