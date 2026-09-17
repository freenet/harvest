# Bitcoin integration — status and known gaps

What works, and — more usefully — what does not, including pre-existing
Harvest gaps that block the full buyer-side scenario and are unrelated to
Bitcoin.

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

**What remains open is a different gap:** no path in the UI issues an order at
all, so nothing yet chooses a bridge set at invoice time. When that path is
built it has to supply one; an order that names none is unpayable, exactly as
before, but now that is a per-invoice mistake rather than a permanent property
of the store.

The buyer side of the same move is already in place. Because the bridge set is
per-invoice, checking a store's address once no longer tells a buyer who will
observe their payment, so `OrderCard` reads it per order and warns when an
invoice names a bridge this build does not recognise
(`components::bitcoin_view::unrecognised_bridges`).

### 2. Asking the bridge to watch an address

**Order-driven watching is done (#59).** Nothing used to tell the bridge an
invoice's payment address existed, so no order could reach Paid. Now the
seller's tab sends the request through the bridge's request inbox, a Freenet
contract. There is no HTTP path, which the published app's CSP would refuse
anyway (#29).

- **Which contracts.** The bridge signs a generation pointer for its address
  contract, its inbox and its tip contract. `bitcoin_generation` resolves them,
  and refreshes them every ten minutes, so a bridge that redeploys while a tab
  is open is followed. There is no build-time fallback. Until the address
  generation resolves, `order_for_invoice` refuses to issue an invoice (#30).
- **What is sent.** `state::AppState::watches_wanted` picks the seller's own
  unpaid, anchored orders that name the bridge, up to a day of blocks past the
  payable window, and only under a Ghost Key the vault has listed for this app.
  `bitcoin_inbox::InboxTracker::plan` batches them. Each request is sealed to
  the bridge, bound to the store's verified seller key, signed by the ghostkey
  delegate, and submitted with the floor it was dated against. It is renewed
  every 12h, since a watch lasts about a day, and sent again if it left the
  inbox unread.
- **What it leaves alone.** The inbox is fetched only by a node with an order
  to watch. Background signing waits, for up to ten minutes at a stretch, while
  the seller signs anything of their own, and goes one Ghost Key at a time. If
  the vault refuses a watch request, does not answer it within five minutes, or
  signs it with the wrong key, that key is not asked again until the page is
  reloaded, and the seller is told once. A listed key's grant includes signing,
  so no prompt appears in normal use. A grant revoked while the tab is open is
  the exception: the key is still listed here, so the vault prompts once. If
  the seller allows it, the grant is back and watching continues; otherwise
  the key is stopped. A withdrawn inbox is told to the seller too.

Known limits:

- **A payment mined before the bridge reads the request is not found.** The
  request carries the order's anchor as `scan_from_height`, but the bridge does
  not act on it yet (freenet-bitcoin#7). Typically the request goes out within
  about a minute of the invoice and the bridge polls its inbox every 30
  seconds, but that is not a bound: the seller's own signing, a key the vault
  refused, or a request the network dropped all delay it.
- **Requests that are never read are noticed, not repaired.** A request that
  leaves the inbox unread is sent again, but nothing more is done about it.
  If a key's requests for scripts it still wants go unread for two hours,
  either because each expires unread and is sent again or because entries sit
  in this node's copy of the inbox, the seller is told, once for as long as it
  lasts. The causes (a request that never reaches the bridge's node, a bridge
  that refuses it, a node serving a copy it has stopped following, a bridge
  that is not running) are outside what the tab can fix. After the tab has not
  been running (a laptop asleep) the two hours start again, since a read that
  happened meanwhile may have left no trace. Requests that cannot be sent at
  all, because the inbox is never served, are not covered by this notice.
- **Tracking is in memory.** A reload sends every wanted request once more,
  which is an early renewal. Pointer floors are not persisted either, so on the
  first resolve after a load a peer could serve a genuine but superseded
  pointer. A refresh may not correct that promptly: the node can answer it from
  the copy it holds.
- **What the inbox makes public.** The scripts are sealed to the bridge.
  Each entry names the Ghost Key that signed it, which is the store's public
  seller key, and the ciphertext length gives the number of scripts. So an
  observer can link a store to the bridge it uses and see when the seller's tab
  sends requests. Since only a node with open invoices fetches the inbox, its
  subscription also tells peers on that path that this node has some. The
  payment addresses themselves were already public in the store contract.

**Manual watches are still not sent.** `WatchForm` builds a `WatchedPayment`,
the delegate persists it privately, and nothing asks a bridge to synchronize
it, so `contract_id` stays `None`. The UI says so (`state::WatchSyncStatus`)
rather than waiting forever. The inbox route above could carry these too.
Whether it should is a privacy question: an order's address is public anyway,
and a private watch list's is not.

### 3. Buyer-seller messaging is not implemented

`messaging::encrypt_message`/`decrypt_message` have no callers outside their
own tests, and nothing sends anything to a mailbox contract. The missing piece
is the seller's X25519 public key: `StoreInfoV1` publishes a certificate and a
reputation contract id and no encryption key, so a buyer has nothing to derive
a conversation key against.

`MessageView` used to claim "Messages are end-to-end encrypted" while
discarding whatever was typed; it now says messaging is unavailable. The
mailbox contract itself is real and stores messages — nothing in this app can
put one there or read one back.

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
- `ui/assets/harvest.css` imports Google Fonts, which the gateway CSP blocks —
  so production Harvest has been falling back to default fonts app-wide. Real,
  pre-existing, and outside this change's scope.
