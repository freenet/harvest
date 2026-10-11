//! Bitcoin payment-watch handlers for the Harvest delegate.
//!
//! Everything here operates on `harvest_common::bitcoin_delegate` types. See
//! that module's doc comment for the full argument, in short: a watch list is
//! **private local state**. It must never be written to a Freenet contract,
//! because a contract is reachable by anyone who knows the key and is
//! replicated indefinitely -- turning "who is watching which Bitcoin
//! address" into a permanent, globally enumerable index. Every value this
//! file persists goes through the delegate host's secret store
//! ([`crate::secrets::CtxSecrets`] over `DelegateCtx::{get,set}_secret`),
//! which is per-user, encrypted, and never leaves this machine.
//!
//! # Every request here is gated on the caller
//!
//! The store is per-USER, not per-app: any web app the user has ever opened on
//! this node can address this delegate (its key is the hash of WASM that is
//! committed in this repository, under empty parameters), and the host does not
//! slice the secret namespace by origin. So the only thing separating a hostile
//! page from the seller's payment key is [`crate::origin::authorize`], which
//! [`handle`] applies before it looks at the request at all. See that module.
//!
//! # Manual watches and order-driven watches are the same watch
//!
//! [`watch_order_payment`] exists so that a Harvest order acquiring a
//! Bitcoin destination can start a watch without the user doing anything.
//! It calls the exact same [`apply_watch`] the `Watch` request handler uses,
//! and writes to the exact same secret. The only difference is which fields
//! get populated (`order_id` set, `label` left `None`). Nothing about
//! automating this changes its privacy: the watch is still local-only,
//! still invisible to the bridge until (and unless) something asks the
//! bridge to synchronize the script, and still invisible to any contract.
//!
//! # No scheduled wakeup, and no HTTPS from a delegate
//!
//! A delegate cannot wake itself up on a timer (freenet-core#3972), and
//! under `freenet local` a delegate's own contract GET/PUT/SUBSCRIBE calls
//! are silently no-ops (freenet-core#5273). Nothing here is designed to
//! depend on the delegate later doing something on its own initiative --
//! every response is computed synchronously from the request that triggered
//! it. Separately, a delegate has no way to make an outbound HTTPS call at
//! all (there is no such `OutboundDelegateMsg` variant), so actually talking
//! to a bridge is the UI's job: it reads the `BridgeEndpoint` back from
//! `GetBridge`/`ConfigureBridge` and speaks to that URL directly.

use freenet_migrate::SecretStore;
use freenet_stdlib::prelude::{DelegateError, MessageOrigin};

use harvest_common::bitcoin_delegate::{
    BitcoinDelegateRequest, BitcoinDelegateResponse, BridgeEndpoint, DerivedAddress,
    PaymentXpubStatus, WatchedPayment, MAX_UPCOMING_ADDRESSES,
};
use harvest_common::{from_cbor, to_cbor, OrderId};

use freenet_bitcoin_common::BitcoinNetwork;

use crate::bip32::{AccountXpub, MAX_ORDER_INDEX};

/// Secret key holding the whole watch list, as CBOR of `Vec<WatchedPayment>`.
///
/// Versioned because this crate has no separate secret-migration registry
/// (unlike the contract-WASM re-key path documented next to
/// `harvest_common::LEGACY_HARVEST_WEBAPP_CONTRACT_IDS`): the version number
/// in the key itself IS the migration mechanism. If `WatchedPayment`'s shape
/// ever changes incompatibly, add a `v2` key, have the loader fall back to
/// reading `v1` and upgrading it in memory, and write future saves under
/// `v2` -- don't reuse `v1` for an incompatible shape.
pub(crate) const BITCOIN_WATCHES_KEY: &[u8] = b"harvest:bitcoin:watches:v1";

/// Secret key holding the configured bridge, as CBOR of `Option<BridgeEndpoint>`.
pub(crate) const BITCOIN_BRIDGE_KEY: &[u8] = b"harvest:bitcoin:bridge:v1";

/// Secret key holding the seller's payment xpub and derivation counter, as
/// CBOR of `Option<PaymentXpubStatus>`.
///
/// Versioned for the same reason as [`BITCOIN_WATCHES_KEY`]: this crate has no
/// secret-migration registry, so the version in the key IS the mechanism.
///
/// # The counter is a floor the network can raise, not the whole answer
///
/// This record lives on one device. A reinstall, a second machine, or a
/// delegate re-key (which strands every secret here -- see
/// `legacy/harvest_delegate.toml`) starts it again at 0, while the same
/// wallet key's low addresses already sit on published, possibly paid,
/// orders. That is harvest#77: a fresh install issued index 0 again and the
/// new invoice settled itself against the old invoice's payment.
///
/// So the delegate holds the scripts of the seller's own published orders,
/// sent by the UI as additions and by instant checkout from each store it
/// answers for ([`crate::published_set`]), and [`advance_scan`] moves the
/// counter past the highest index whose script it finds there before
/// [`issue_next_address`] hands one out. The counter is then the maximum of
/// what this device handed out and what the network shows.
///
/// That recovers the highest index ever PUBLISHED, which is not the highest
/// ever HANDED OUT: an index whose invoice was abandoned before it was
/// published, on a device that is gone, is invisible to it, and so is an
/// order pruned from the store at `MAX_ORDERS`. Both can be issued again.
/// Two more layers sit behind this one. The UI reads the derived address's
/// own contract before signing and skips an address that holds any claim
/// (`AppState::check_address_before_signing`), which catches any address
/// that was registered with the bridge. And the store contract settles an
/// order only with a payment that confirmed inside its window
/// (`harvest_common::payment::Order::payment_window`), so a payment made
/// before a reissued order cannot settle it, and a new order's payment
/// cannot settle an older one anchored more than `PAYMENT_WINDOW_BLOCKS`
/// earlier. What is left when all three miss is two orders on one address
/// whose windows overlap, which one payment in the overlap settles BOTH:
/// a wrongly-settled order, not merely a reused address.
pub(crate) const BITCOIN_PAYMENT_XPUB_KEY: &[u8] = b"harvest:bitcoin:payment-xpub:v1";

/// Secret key holding a payment key the seller has entered whose catch-up
/// scan is not finished yet (harvest#206), as CBOR of
/// `Option<PaymentXpubStatus>`: the key and the count its scan has reached.
///
/// # Why it is not simply the active key
///
/// [`BITCOIN_PAYMENT_XPUB_KEY`] is what every address is handed out from, by
/// this tab, by the seller's other tabs and by instant checkout. A tab keeps,
/// per key, the published scripts the delegate has already accounted for
/// and the ones it found foreign, and leaves both out of its next address
/// request (`AppState::order_address_request`). Saving a NEW key as active
/// at a part-way count would leave those tabs filtering by the OLD key's
/// record: the new key's published scripts, foreign to the old key, are left
/// out, the scan from the part-way count finds nothing and completes, and
/// the next index handed out is one of the new key's published orders
/// (harvest#77). So a new key's part-way count is kept here, the active key
/// and its counter stay exactly as they were, and the key is promoted, and
/// this slot dropped, only when a scan for it completes.
///
/// # A slot lost in a migration
///
/// Imported as a standalone secret (`import::Family::Standalone`): into this
/// same slot, never as the active key, so a migration can never promote a
/// part-way count. A successor that does not get it simply starts that key's
/// catch-up again from 0; the count in it is only ever a floor (one past a
/// published order of that key), so resuming from an older one is safe too.
pub(crate) const BITCOIN_PAYMENT_XPUB_PENDING_KEY: &[u8] =
    b"harvest:bitcoin:payment-xpub-pending:v1";

fn load_watches<S: SecretStore>(store: &S) -> Vec<WatchedPayment> {
    store
        .get_secret(BITCOIN_WATCHES_KEY)
        .and_then(|bytes| from_cbor(&bytes).ok())
        .unwrap_or_default()
}

fn save_watches<S: SecretStore>(store: &mut S, watches: &[WatchedPayment]) {
    if let Ok(bytes) = to_cbor(&watches) {
        store.set_secret(BITCOIN_WATCHES_KEY, &bytes);
    }
}

fn load_bridge<S: SecretStore>(store: &S) -> Option<BridgeEndpoint> {
    store
        .get_secret(BITCOIN_BRIDGE_KEY)
        .and_then(|bytes| from_cbor::<Option<BridgeEndpoint>>(&bytes).ok())
        .flatten()
}

fn save_bridge<S: SecretStore>(store: &mut S, endpoint: &BridgeEndpoint) {
    if let Ok(bytes) = to_cbor(&Some(endpoint.clone())) {
        store.set_secret(BITCOIN_BRIDGE_KEY, &bytes);
    }
}

pub(crate) fn load_payment_xpub<S: SecretStore>(store: &S) -> Option<PaymentXpubStatus> {
    store
        .get_secret(BITCOIN_PAYMENT_XPUB_KEY)
        .and_then(|bytes| from_cbor::<Option<PaymentXpubStatus>>(&bytes).ok())
        .flatten()
}

/// The key held in [`BITCOIN_PAYMENT_XPUB_PENDING_KEY`], if any.
pub(crate) fn load_pending_payment_xpub<S: SecretStore>(store: &S) -> Option<PaymentXpubStatus> {
    store
        .get_secret(BITCOIN_PAYMENT_XPUB_PENDING_KEY)
        .and_then(|bytes| from_cbor::<Option<PaymentXpubStatus>>(&bytes).ok())
        .flatten()
}

/// Keep a key's part-way count in the pending slot, refusing if the host
/// did not take the write (the seller would otherwise see progress that was
/// not kept).
fn save_pending_payment_xpub<S: SecretStore>(
    store: &mut S,
    status: &PaymentXpubStatus,
) -> Result<(), String> {
    let bytes = to_cbor(&Some(status.clone()))
        .map_err(|e| format!("could not encode the payment key record: {e}"))?;
    if !store.set_secret(BITCOIN_PAYMENT_XPUB_PENDING_KEY, &bytes) {
        return Err("the node refused to store the payment key's progress".to_string());
    }
    Ok(())
}

/// Empty the pending slot, once its key is active or another key has been
/// set in full. Written over with empty bytes rather than removed (this
/// handler's store has no removal). A write the host refuses leaves a stale part-way count behind,
/// which is harmless: it is only read for a `SetPaymentXpub` of that same
/// key, as a floor to resume from, and it is never handed out from.
fn clear_pending_payment_xpub<S: SecretStore>(store: &mut S) {
    // Empty bytes: what `import` treats as no slot at all.
    if store
        .get_secret(BITCOIN_PAYMENT_XPUB_PENDING_KEY)
        .is_some_and(|held| !held.is_empty())
    {
        store.set_secret(BITCOIN_PAYMENT_XPUB_PENDING_KEY, &[]);
    }
}

/// The `Err` a request answers while its key's scan has not caught up:
/// [`harvest_common::bitcoin_delegate::CATCHING_UP_PREFIX`], the counter and
/// the cursor, and a sentence. The UI asks again by itself on seeing the
/// prefix and shows the figures as progress.
pub(crate) fn catching_up_error(progress: &Progress) -> String {
    format!(
        "{}{}/{}; the published orders this key is checked against are still being \
         scanned, a bounded number of addresses a request, and the next request goes on \
         from here",
        harvest_common::bitcoin_delegate::CATCHING_UP_PREFIX,
        progress.counter,
        progress.cursor
    )
}

/// Whether two account keys are the same key, as [`apply_set_payment_xpub`]
/// decides it: parsed, network ignored.
fn same_account(a: &str, b: &str) -> bool {
    matches!(
        (AccountXpub::parse(a), AccountXpub::parse(b)),
        (Ok(a), Ok(b)) if a == b
    )
}

/// Persist the xpub record, refusing if the host did not take the write.
///
/// Both failures are propagated rather than swallowed the way the other savers
/// swallow theirs, and the difference matters: a dropped watch-list write costs
/// a watch the user can re-add, but a dropped counter write means the next
/// derivation hands out the SAME index again -- two invoices on one address,
/// which is the failure this whole path exists to prevent. So either failure
/// turns into a failed derivation rather than an address the caller believes is
/// fresh.
///
/// `SecretStore::set_secret` reports whether the host accepted the write; this
/// crate already depends on that in `markers::set_marker`. The real host's
/// `set_secret` always answers `false` off the `wasm32` target, which is why
/// these handlers take a store rather than a `DelegateCtx` -- see
/// [`crate::secrets`].
pub(crate) fn save_payment_xpub<S: SecretStore>(
    store: &mut S,
    status: &PaymentXpubStatus,
) -> Result<(), String> {
    let bytes = to_cbor(&Some(status.clone()))
        .map_err(|e| format!("could not encode the payment key record: {e}"))?;
    // A different key (or the first): every armed window was read under
    // something else, and is forgotten (`auto_invoice::forget_armed_scripts`).
    // Before the write, so a key never becomes active beside a window read
    // under another one.
    let key_changes = load_payment_xpub(store)
        .is_none_or(|held| held.xpub != status.xpub || held.network != status.network);
    if key_changes && !crate::auto_invoice::forget_armed_scripts(store) {
        return Err(
            "the node refused to clear the armed instant-checkout windows, so the new payment \
             key was not made active -- an arm left naming the old key's addresses could \
             invoice from them again after a change back"
                .to_string(),
        );
    }
    if !store.set_secret(BITCOIN_PAYMENT_XPUB_KEY, &bytes) {
        return Err(
            "the node refused to store the payment key record, so no address was issued -- \
             issuing one anyway would hand out an index the delegate still believes is unused"
                .to_string(),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pure watch-list logic.
//
// Kept free of any store on purpose: separating "how the watch list changes"
// from "where it's persisted" lets the interesting logic be asserted on
// directly. (The handlers around them are testable too, since they take an
// `impl SecretStore` rather than the host's `DelegateCtx` -- see
// `crate::secrets` for why that distinction exists at all.)
// ---------------------------------------------------------------------------

/// Insert `watch`, replacing any existing entry with the same
/// `WatchedPayment::key()` (network + script). Shared by manual `Watch`
/// requests and [`watch_order_payment`] -- the only difference between the
/// two call sites is which fields the caller filled in.
fn apply_watch(watches: &mut Vec<WatchedPayment>, watch: WatchedPayment) -> WatchedPayment {
    let key = watch.key();
    watches.retain(|w| w.key() != key);
    watches.push(watch.clone());
    watch
}

/// Remove the watch for `network`/`script_pubkey`, if any. Returns whether
/// something was actually removed; the caller treats "nothing to remove" as
/// success either way, since asking to stop watching something nobody was
/// watching is not an error.
fn apply_unwatch(
    watches: &mut Vec<WatchedPayment>,
    network: BitcoinNetwork,
    script_pubkey: &[u8],
) -> bool {
    let before = watches.len();
    watches.retain(|w| !(w.network == network && w.script_pubkey == script_pubkey));
    watches.len() != before
}

/// Attach an order to an existing watch. Errors if there is no watch for
/// that network/script yet -- the UI is expected to `Watch` before it
/// `AssociateOrder`s, since associating is about labelling an existing
/// private watch, not creating one.
fn apply_associate_order(
    watches: &mut [WatchedPayment],
    network: BitcoinNetwork,
    script_pubkey: &[u8],
    order_id: OrderId,
    expected_amount_sats: u64,
) -> Result<(), String> {
    match watches
        .iter_mut()
        .find(|w| w.network == network && w.script_pubkey == script_pubkey)
    {
        Some(w) => {
            w.order_id = Some(order_id);
            w.expected_amount_sats = Some(expected_amount_sats);
            Ok(())
        }
        None => Err("no watch for that network/script -- call Watch first".into()),
    }
}

/// Validate an account xpub and build the record to store for it.
///
/// # The counter is kept when the key is the same one
///
/// A fresh key starts at 0, because an index only means anything relative to
/// the key it derives from. **Re-setting the key already in use does NOT
/// restart the count**, and that distinction is the whole of this function's
/// risk: restarting would re-issue addresses that already have live invoices
/// against them, which is precisely the reuse this feature exists to prevent.
///
/// It is not a corner case. The seller reaches it through an ordinary button:
/// the only visible reason to touch the payment key is to correct the NETWORK,
/// signet and testnet4 being indistinguishable from the key itself (see
/// [`crate::bip32::AccountXpub::accepts_network`]), and correcting it means
/// re-pasting the same key. The form cannot show them what is already set --
/// it holds a public key, but showing it back would be a privacy leak into the
/// page -- so they cannot even tell they are re-entering it.
///
/// Sameness is decided on the PARSED key, not the string: the same account key
/// re-exported by a wallet can differ in whitespace or case and still be the
/// same 78 bytes.
///
/// The comparison deliberately ignores the network. A key filed under the
/// wrong test network derives byte-identical addresses (all of `tb1…`), so the
/// indices already handed out are real addresses in that wallet whatever the
/// record says the network was -- re-filing it must not hand them out twice.
fn apply_set_payment_xpub(
    xpub: &str,
    network: BitcoinNetwork,
    existing: Option<&PaymentXpubStatus>,
) -> Result<PaymentXpubStatus, String> {
    let account = AccountXpub::parse(xpub)?;
    if !account.accepts_network(network) {
        return Err(format!(
            "that account key is not for {}. Check the network your wallet exported it \
             for -- a mainnet key here would put real bitcoin on your invoices.",
            network.as_str()
        ));
    }
    // Derive index 0 now rather than at the first invoice. A key that parses
    // but cannot derive would otherwise be discovered only when a seller was
    // halfway through issuing an invoice to a waiting buyer.
    account.order_address(0, network)?;

    let next_index = existing
        .filter(|held| AccountXpub::parse(&held.xpub).is_ok_and(|held| held == account))
        .map_or(0, |held| held.next_index);

    Ok(PaymentXpubStatus {
        xpub: xpub.trim().to_string(),
        network,
        next_index,
    })
}

/// How many consecutive indices past the last match [`advance_scan`]
/// derives before concluding there are no more published orders above it.
///
/// Published orders are not contiguous: an invoice abandoned after its address
/// was derived burns an index that no order names. A seller would have to
/// abandon this many invoices IN A ROW, then publish one, for the scan to stop
/// short of it -- and even then the store contract refuses to let that old
/// order's payment settle a new one. Each step is one public-key derivation,
/// so this is also the cost the scan adds to every invoice on a device whose
/// count is already current (one more for each address handed out, and the
/// whole gap again after scripts are added). Defined in `harvest-common`.
pub(crate) use harvest_common::bitcoin_delegate::PUBLISHED_INDEX_GAP;

/// The whole catch-up, run to its end against `published` from `status`'s
/// counter, in a store of its own: what the unit tests below state the
/// floor's rules against. Returns the counter reached.
#[cfg(test)]
fn apply_published_floor(
    status: &mut PaymentXpubStatus,
    published: &[Vec<u8>],
) -> Result<u32, String> {
    let mut store = crate::secrets::MemSecrets::default();
    save_payment_xpub(&mut store, status)?;
    add_published(&mut store, published)?;
    loop {
        let progress = advance_scan(&mut store, Slot::Active, status, FLOOR_SCAN_BUDGET)
            .map_err(String::from)?;
        if progress.complete {
            return Ok(status.next_index);
        }
    }
}

/// How many indices one call's scan may derive (#206). Each is a public-key
/// derivation, about 3.2 million units of the node's fuel, so this is about a
/// third of a call. A device whose counter is far behind its published orders
/// (a new device for a busy key; a store holds up to 256 orders) catches up
/// over several calls, the cursor saved after each, rather than in one call
/// the node would stop.
pub(crate) const FLOOR_SCAN_BUDGET: u32 = 384;

/// How many indices a scheduled wake-up's scan may derive: a run that also
/// signs heartbeats and reads the bridge, so a smaller share than a
/// request's. Enough that instant checkout catches up with no tab open.
pub(crate) const WAKEUP_SCAN_BUDGET: u32 = 128;

/// Which key's scan: the active key, or the one held pending
/// ([`BITCOIN_PAYMENT_XPUB_PENDING_KEY`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Active,
    Pending,
}

impl Slot {
    fn cursor_key(self) -> &'static [u8] {
        match self {
            Slot::Active => crate::published_set::CURSOR_ACTIVE_KEY,
            Slot::Pending => crate::published_set::CURSOR_PENDING_KEY,
        }
    }

    fn save_status<S: SecretStore>(
        self,
        store: &mut S,
        status: &PaymentXpubStatus,
    ) -> Result<(), String> {
        match self {
            Slot::Active => save_payment_xpub(store, status),
            Slot::Pending => save_pending_payment_xpub(store, status),
        }
    }
}

/// How far a key's scan has got ([`advance_scan`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Progress {
    /// One past the last published index matched: what is handed out next.
    pub counter: u32,
    /// Every index in `[counter, cursor)` has been derived and is not a held
    /// script.
    pub cursor: u32,
    /// The scan has gone [`PUBLISHED_INDEX_GAP`] past the counter with no
    /// match (or nothing is held, or the key has no indices left): only now
    /// may an address be handed out, or a pending key made active.
    pub complete: bool,
}

/// Why [`advance_scan`] could not go on.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ScanError {
    /// The key does not parse or derive.
    Key(String),
    /// A counter the scan raised could not be kept: nothing after it was
    /// written, and nothing may be handed out.
    NotSaved(String),
}

impl From<ScanError> for String {
    fn from(e: ScanError) -> String {
        match e {
            ScanError::Key(e) | ScanError::NotSaved(e) => e,
        }
    }
}

fn is_complete(counter: u32, cursor: u32, nothing_held: bool) -> bool {
    nothing_held
        || cursor >= counter.saturating_add(PUBLISHED_INDEX_GAP)
        || cursor > MAX_ORDER_INDEX
}

/// Where `slot`'s scan stands for `status` without deriving anything: the
/// saved cursor when it is for this key and the held scripts have not
/// changed since, else the counter (a script added since may sit at any
/// index from the counter up).
fn cursor_for<S: SecretStore>(
    store: &S,
    slot: Slot,
    status: &PaymentXpubStatus,
    generation: u32,
) -> u32 {
    crate::published_set::Cursor::load(store, slot.cursor_key())
        .filter(|c| {
            c.tag == status.xpub.as_bytes()
                && c.generation == generation
                && status.next_index >= c.base
        })
        .map_or(status.next_index, |c| c.at.max(status.next_index))
}

/// Whether the active key's scan is known to be complete, from what is
/// kept, without deriving: for the status a store shows. A cursor that does
/// not say so (none kept, scripts added since) reads as not known.
pub(crate) fn active_scan_known_complete<S: SecretStore>(store: &S) -> bool {
    let Some(status) = load_payment_xpub(store) else {
        return false;
    };
    let Some((generation, held)) = crate::published_set::published_meta(store) else {
        return false;
    };
    let cursor = cursor_for(store, Slot::Active, &status, generation);
    is_complete(status.next_index, cursor, held == 0)
}

/// A scheduled wake-up's share of the catch-up: the active key's scan moved
/// on by [`WAKEUP_SCAN_BUDGET`], so instant checkout catches up with no tab
/// open. Nothing is handed out. Errors are left for the next request to
/// report.
pub(crate) fn advance_on_wakeup<S: SecretStore>(store: &mut S) {
    if let Some(mut status) = load_payment_xpub(store) {
        let _ = advance_scan(store, Slot::Active, &mut status, WAKEUP_SCAN_BUDGET);
    }
}

/// Move `slot`'s scan on by at most `budget` derivations.
///
/// From the cursor, each index's script is looked for among the held
/// published scripts ([`crate::published_set`]). A match raises the counter
/// to one past it and the scan goes on from there; the scan is complete once
/// it has gone [`PUBLISHED_INDEX_GAP`] past the counter with no match. That
/// is the scan harvest#77 has always made, cut into budgets and run against
/// every script the delegate has been sent rather than those one request
/// carried.
///
/// A matched script stays held: below this key's counter it never matches
/// again, and the next key entered (or this one entered afresh, starting at
/// 0) needs it. Written in this order: the raised counter first (refused,
/// nothing else is written: [`ScanError::NotSaved`]); then the cursor
/// (refused, the next scan starts again from the counter).
pub(crate) fn advance_scan<S: SecretStore>(
    store: &mut S,
    slot: Slot,
    status: &mut PaymentXpubStatus,
    budget: u32,
) -> Result<Progress, ScanError> {
    use crate::published_set::{digest, Cursor, DigestList, PUBLISHED_KEY};
    let published = DigestList::load(store, PUBLISHED_KEY)
        .map_err(|_| ScanError::NotSaved(UNREADABLE_PUBLISHED.to_string()))?;
    let generation = published.generation();
    let start = status.next_index;
    let mut cursor = cursor_for(store, slot, status, generation);

    let mut counter = status.next_index;
    let mut derived = 0;
    let nothing_held = published.is_empty();
    if !is_complete(counter, cursor, nothing_held) {
        let chain = AccountXpub::parse(&status.xpub)
            .and_then(|a| a.external_chain())
            .map_err(ScanError::Key)?;
        while derived < budget && !is_complete(counter, cursor, nothing_held) {
            let d = digest(&chain.script_at(cursor).map_err(ScanError::Key)?);
            derived += 1;
            if published.contains(&d) {
                // Never lower: the cursor is at or above the counter
                // (`cursor_for`), and this holds whatever changes there.
                counter = counter.max(cursor + 1);
            }
            cursor += 1;
        }
    }
    if counter != start {
        let mut raised = status.clone();
        raised.next_index = counter;
        slot.save_status(store, &raised)
            .map_err(ScanError::NotSaved)?;
        *status = raised;
    }
    if derived > 0 {
        store.set_secret(
            slot.cursor_key(),
            &Cursor {
                tag: status.xpub.as_bytes().to_vec(),
                generation,
                // No held script in `[counter, cursor)`: valid while the
                // counter is not set below this.
                base: counter,
                at: cursor,
            }
            .encode(),
        );
    }
    Ok(Progress {
        counter,
        cursor,
        complete: is_complete(counter, cursor, nothing_held),
    })
}

/// What a refusal says when the held published scripts do not read
/// (`published_set::Unreadable`): nothing is handed out, and nothing is
/// written over them.
pub(crate) const UNREADABLE_PUBLISHED: &str =
    "the published orders' addresses this delegate holds could not be read, so no address \
     can be checked against them; nothing was handed out";

/// Add published scripts to those held ([`crate::published_set`]), every
/// one, this device's own orders included, and mark each as sent now. Any
/// added sends every key's scan back to its counter. `Err` when the held
/// list does not read (it is never written over) or the host refused the
/// write: the scripts are not held, and the caller must not go on as though
/// they were.
pub(crate) fn add_published<S: SecretStore>(
    store: &mut S,
    scripts: &[Vec<u8>],
) -> Result<usize, String> {
    use crate::published_set::{digest, DigestList, PUBLISHED_KEY};
    let fresh: Vec<_> = scripts
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| digest(s))
        .collect();
    if fresh.is_empty() {
        return Ok(0);
    }
    let mut published =
        DigestList::load(store, PUBLISHED_KEY).map_err(|_| UNREADABLE_PUBLISHED.to_string())?;
    let inserted = published.insert(&fresh);
    // Written only when it changed (a script added, or one held stamped as
    // sent again): a pass of scripts all held recently writes nothing and
    // so cannot be refused. A write that was needed and refused fails the
    // addition, re-stamps included: the UI would otherwise count those
    // scripts sent while their stamps were never kept, and near the cap
    // eviction could take them (#206 review, codex).
    if inserted.changed && !crate::published_set::save_published(store, &published) {
        return Err(
            "the node refused to store the published orders' addresses, so none can be \
             checked against them yet"
                .to_string(),
        );
    }
    Ok(inserted.added)
}

/// Why [`issue_next_address`] handed nothing out.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum NotIssued {
    /// No payment key is set.
    NoKey,
    /// The active key's scan has not caught up yet; it went on by a budget.
    CatchingUp(Progress),
    /// The caller's check turned the address down (instant checkout: not a
    /// watched one). Nothing was spent.
    Declined,
    /// The key cannot hand out another address, or does not derive.
    Failed(String),
    /// A counter could not be kept, so nothing was handed out.
    NotSaved(String),
}

impl NotIssued {
    /// The `Err` a `DeriveOrderAddress` answers.
    pub(crate) fn message(&self) -> String {
        match self {
            NotIssued::NoKey => "no payment key is set for this store yet. Add your wallet's \
                                 native SegWit account key before issuing an invoice."
                .to_string(),
            NotIssued::CatchingUp(progress) => catching_up_error(progress),
            NotIssued::Declined => "that address was turned down".to_string(),
            NotIssued::Failed(e) | NotIssued::NotSaved(e) => e.clone(),
        }
    }
}

/// **The one way an address is handed out** (#206). Every path that spends
/// an index -- an invoice (`DeriveOrderAddress`), a raise past used
/// addresses (the same request, harvest#183), and instant checkout
/// (`auto_invoice::decide`) -- comes through here, and nothing else calls
/// [`apply_derive_order_address`] or raises the counter to hand an index
/// out (`only_the_choke_point_hands_out_an_index` pins it).
///
/// It moves the active key's scan on by at most `budget`, and refuses until
/// the scan is complete: until every script the delegate holds has been
/// looked for up to [`PUBLISHED_INDEX_GAP`] past the counter. Then it
/// derives the address at the counter, lets `accept` turn it down (nothing
/// spent), and saves the counter past it BEFORE returning it.
pub(crate) fn issue_next_address<S: SecretStore>(
    store: &mut S,
    budget: u32,
    accept: impl FnOnce(&DerivedAddress) -> bool,
) -> Result<DerivedAddress, NotIssued> {
    let mut status = load_payment_xpub(store).ok_or(NotIssued::NoKey)?;
    let progress = advance_scan(store, Slot::Active, &mut status, budget).map_err(|e| match e {
        ScanError::Key(e) => NotIssued::Failed(e),
        ScanError::NotSaved(e) => NotIssued::NotSaved(e),
    })?;
    if !progress.complete {
        return Err(NotIssued::CatchingUp(progress));
    }
    let mut next = status.clone();
    let derived = apply_derive_order_address(&mut next).map_err(NotIssued::Failed)?;
    if !accept(&derived) {
        return Err(NotIssued::Declined);
    }
    // Saved BEFORE the address leaves here. If persisting fails the address
    // is discarded rather than returned, because a caller that received it
    // may show it to a buyer while the delegate still believes the index is
    // unused.
    save_payment_xpub(store, &next).map_err(NotIssued::NotSaved)?;
    Ok(derived)
}

/// Hand out the next address and advance the counter.
///
/// Takes `&mut` and mutates BEFORE returning, so an index is consumed by
/// being handed out rather than by the invoice that asked for it succeeding.
/// That is the conservative direction: an abandoned invoice burns an index
/// (harmless, and bounded by the wallet's gap limit), whereas advancing only
/// on success would re-issue an address that had already been shown to a
/// buyer.
fn apply_derive_order_address(status: &mut PaymentXpubStatus) -> Result<DerivedAddress, String> {
    if status.next_index > MAX_ORDER_INDEX {
        return Err(
            "this account key has handed out every address it can. Set a fresh account \
             key to keep issuing invoices."
                .to_string(),
        );
    }
    let account = AccountXpub::parse(&status.xpub)?;
    let index = status.next_index;
    let (script_pubkey, address) = account.order_address(index, status.network)?;
    status.next_index = index + 1;
    Ok(DerivedAddress {
        index,
        network: status.network,
        script_pubkey,
        address,
    })
}

/// The next `count` addresses [`apply_derive_order_address`] would hand out,
/// from the counter on, without moving it. At most
/// [`MAX_UPCOMING_ADDRESSES`], and never past [`MAX_ORDER_INDEX`].
pub(crate) fn upcoming_addresses(
    status: &PaymentXpubStatus,
    count: u32,
) -> Result<Vec<DerivedAddress>, String> {
    let account = AccountXpub::parse(&status.xpub)?;
    let mut out = Vec::new();
    let mut index = status.next_index;
    while out.len() < count.min(MAX_UPCOMING_ADDRESSES) as usize && index <= MAX_ORDER_INDEX {
        let (script_pubkey, address) = account.order_address(index, status.network)?;
        out.push(DerivedAddress {
            index,
            network: status.network,
            script_pubkey,
            address,
        });
        index += 1;
    }
    Ok(out)
}

/// Add or refresh a watch because a Harvest order now has a Bitcoin payment
/// destination, rather than because the user manually asked to watch an
/// address. Uses [`apply_watch`], the exact same storage and upsert logic a
/// manual `Watch` request goes through.
///
/// Still private: creating this watch touches no contract and is invisible
/// to anyone but this machine, exactly like a manual watch. See this
/// module's doc comment for why that invariant matters.
///
/// Not yet called anywhere in this crate: wiring an incoming order/payment
/// notification to this function is order-tracking's job, not the Bitcoin
/// watch-list's, and lands in a separate change. `#[allow(dead_code)]` is
/// deliberate here rather than a signal to remove the function.
#[allow(dead_code)]
pub fn watch_order_payment<S: SecretStore>(
    store: &mut S,
    network: BitcoinNetwork,
    script_pubkey: Vec<u8>,
    address: String,
    order_id: OrderId,
    expected_amount_sats: u64,
    added_at_ms: u64,
) -> WatchedPayment {
    let mut watches = load_watches(store);
    let watch = apply_watch(
        &mut watches,
        WatchedPayment {
            network,
            script_pubkey,
            address,
            label: None,
            order_id: Some(order_id),
            expected_amount_sats: Some(expected_amount_sats),
            contract_id: None,
            added_at_ms,
            bridge_synced: false,
            last_error: None,
        },
    );
    save_watches(store, &watches);
    watch
}

/// The `KEY_SUPERSEDED_PREFIX` answer to a resumed `SetPaymentXpub` whose key
/// is no longer the one held pending.
fn superseded_error() -> String {
    format!(
        "{}another payment key was entered since this one, so this one was not saved",
        harvest_common::bitcoin_delegate::KEY_SUPERSEDED_PREFIX
    )
}

/// Answer `SetPaymentXpub`: add the scripts it carries, then scan the key
/// against everything held, and make it the active key only once that scan
/// is complete (#206).
///
/// # Which slot the key's scan lives in
///
/// * The active key itself (entered again, say to correct the network): the
///   active counter and cursor, as every address request moves them.
/// * Any other key, or when none is held: the pending slot
///   ([`BITCOIN_PAYMENT_XPUB_PENDING_KEY`]), with the active key, its
///   counter and its scan left exactly as they were; promoted, with its
///   cursor, once its scan is complete. A newer submission of another key
///   replaces the one pending, unless the request is a `resume` of a
///   catch-up, which then answers [`KEY_SUPERSEDED_PREFIX`] and writes
///   nothing, so two tabs entering two keys cannot keep restarting each
///   other.
///
/// Until it is complete the answer is `Err` ([`catching_up_error`]), so the
/// UI shows progress and asks again; nothing is handed out from a key whose
/// scan is not complete, whichever slot it is in.
///
/// [`KEY_SUPERSEDED_PREFIX`]: harvest_common::bitcoin_delegate::KEY_SUPERSEDED_PREFIX
fn set_payment_key<S: SecretStore>(
    store: &mut S,
    xpub: &str,
    network: BitcoinNetwork,
    published_scripts: &[Vec<u8>],
    resume: bool,
) -> Result<PaymentXpubStatus, String> {
    let active = load_payment_xpub(store);
    let pending = load_pending_payment_xpub(store);
    let is_active = active
        .as_ref()
        .is_some_and(|held| same_account(&held.xpub, xpub));
    let is_pending = !is_active
        && pending
            .as_ref()
            .is_some_and(|held| same_account(&held.xpub, xpub));
    if resume && !is_active && !is_pending {
        return Err(superseded_error());
    }
    let (slot, existing) = if is_active {
        (Slot::Active, active.as_ref())
    } else if is_pending {
        (Slot::Pending, pending.as_ref())
    } else {
        // A count only means anything for its own key: another key starts
        // at 0 (`apply_set_payment_xpub`).
        (Slot::Pending, None)
    };
    let mut status = apply_set_payment_xpub(xpub, network, existing)?;
    add_published(store, published_scripts)?;
    if existing != Some(&status) {
        // A new pending key, or a corrected network: kept before the scan,
        // so a part-way count has a key to belong to.
        slot.save_status(store, &status)?;
    }
    let progress =
        advance_scan(store, slot, &mut status, FLOOR_SCAN_BUDGET).map_err(String::from)?;
    if !progress.complete {
        return Err(catching_up_error(&progress));
    }
    if slot == Slot::Pending {
        save_payment_xpub(store, &status)?;
        // Its scan goes with it: the cursor is tagged with the key.
        if let Some(cursor) = store.get_secret(crate::published_set::CURSOR_PENDING_KEY) {
            store.set_secret(crate::published_set::CURSOR_ACTIVE_KEY, &cursor);
        }
    }
    // Whatever was pending is over, this key's own part-way slot included:
    // this key was set in full.
    if slot == Slot::Pending || pending.is_some() {
        clear_pending_payment_xpub(store);
    }
    Ok(status)
}

/// Answer one Bitcoin request, for the Harvest web app only.
///
/// # Why every variant below is behind the gate, reads included
///
/// The obvious one is [`BitcoinDelegateRequest::SetPaymentXpub`]: it decides
/// which wallet every invoice this store ever issues pays into. An ungated
/// write there is not a leak, it is a redirection of the seller's income to
/// whoever asked last -- silently, since the buyer's checks all still pass
/// (the seller's own signature and ghostkey certificate are genuine; only the
/// destination changed). `ConfigureBridge`, `Watch`, `Unwatch`,
/// `AssociateOrder` and `DeriveOrderAddress` are gated for the same reason in
/// milder form: each writes state the seller relies on, and `DeriveOrderAddress`
/// additionally burns an address index per call.
///
/// The reads are gated too, and that is a deliberate decision rather than
/// caution by default. Each answers with something whose whole value is that it
/// is private:
///
/// * `ListWatched` is the address-watch list -- the exact "who is watching
///   which Bitcoin address" index this module's header says must never become
///   enumerable. Handing it to a page that merely asked is the same disclosure
///   by a shorter route.
/// * `GetPaymentXpub` is worse than it looks: an account xpub derives EVERY
///   address the store will ever issue, so one read links the seller's whole
///   present and future payment history, and it cannot be undone by rotating
///   anything after the fact.
/// * `GetBridge` names the endpoint this user's node talks to, which is a
///   network-location fact about the seller.
///
/// The cost of gating reads is that a legitimate non-Harvest caller would
/// break, so: there is none. This delegate is published by, and only by, the
/// Harvest web app; no other app has a reason to hold Harvest's watch list, and
/// the sibling `harvest_common::bitcoin_delegate` types are not a public
/// integration surface. If one ever should exist, it wants an explicit
/// consent-carrying request, not a hole left open on the chance somebody turns
/// up.
pub fn handle<S: SecretStore>(
    store: &mut S,
    origin: Option<&MessageOrigin>,
    request: BitcoinDelegateRequest,
) -> Result<BitcoinDelegateResponse, DelegateError> {
    // Before the request is even looked at: a refused caller learns nothing
    // about which variants exist or which of them this build supports.
    crate::origin::authorize(origin)?;

    Ok(match request {
        BitcoinDelegateRequest::Watch { request_id, watch } => {
            let mut watches = load_watches(store);
            let watch = apply_watch(&mut watches, watch);
            save_watches(store, &watches);
            BitcoinDelegateResponse::Watched {
                request_id,
                result: Ok(watch),
            }
        }

        BitcoinDelegateRequest::Unwatch {
            request_id,
            network,
            script_pubkey,
        } => {
            let mut watches = load_watches(store);
            if apply_unwatch(&mut watches, network, &script_pubkey) {
                save_watches(store, &watches);
            }
            BitcoinDelegateResponse::Unwatched {
                request_id,
                result: Ok(()),
            }
        }

        BitcoinDelegateRequest::ListWatched => BitcoinDelegateResponse::WatchList {
            watches: load_watches(store),
        },

        BitcoinDelegateRequest::AssociateOrder {
            request_id,
            network,
            script_pubkey,
            order_id,
            expected_amount_sats,
        } => {
            let mut watches = load_watches(store);
            let result = apply_associate_order(
                &mut watches,
                network,
                &script_pubkey,
                order_id,
                expected_amount_sats,
            );
            if result.is_ok() {
                save_watches(store, &watches);
            }
            BitcoinDelegateResponse::OrderAssociated { request_id, result }
        }

        BitcoinDelegateRequest::ConfigureBridge {
            request_id,
            endpoint,
        } => {
            save_bridge(store, &endpoint);
            BitcoinDelegateResponse::BridgeConfigured {
                request_id,
                result: Ok(()),
            }
        }

        BitcoinDelegateRequest::GetBridge => BitcoinDelegateResponse::Bridge {
            endpoint: load_bridge(store),
        },

        BitcoinDelegateRequest::SetPaymentXpub {
            request_id,
            xpub,
            network,
            published_scripts,
            resume,
        } => BitcoinDelegateResponse::PaymentXpubSet {
            request_id,
            result: set_payment_key(store, &xpub, network, &published_scripts, resume),
            // Nothing for the UI to account for any more: the delegate
            // holds every script it is sent (`crate::published_set`).
            matched_scripts: Vec::new(),
        },

        BitcoinDelegateRequest::GetPaymentXpub => BitcoinDelegateResponse::PaymentXpub {
            status: load_payment_xpub(store),
        },

        BitcoinDelegateRequest::DeriveOrderAddress {
            request_id,
            published_scripts,
        } => BitcoinDelegateResponse::OrderAddress {
            request_id,
            // An older UI's scripts are additions like any others; held
            // first, so the address is past them too.
            result: add_published(store, &published_scripts).and_then(|_| {
                issue_next_address(store, FLOOR_SCAN_BUDGET, |_| true).map_err(|e| e.message())
            }),
            matched_scripts: Vec::new(),
        },

        BitcoinDelegateRequest::AddPublishedScripts {
            request_id,
            scripts,
        } => BitcoinDelegateResponse::PublishedScriptsAdded {
            request_id,
            result: add_published(store, &scripts).map(|_| ()),
        },

        BitcoinDelegateRequest::PeekOrderAddresses { request_id, count } => {
            BitcoinDelegateResponse::UpcomingAddresses {
                request_id,
                result: match load_payment_xpub(store) {
                    None => Err("no payment key is set yet".to_string()),
                    Some(status) => upcoming_addresses(&status, count),
                },
            }
        }

        // `BitcoinDelegateRequest` is `#[non_exhaustive]` in harvest-common,
        // so this match must keep a wildcard even though every variant that
        // exists today is handled above. A future variant added on the
        // other side of the workspace then fails here with a clean error
        // instead of failing to compile this crate.
        _ => {
            return Err(DelegateError::Other(
                "unsupported bitcoin request variant for this delegate version".into(),
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn watch(
        network: BitcoinNetwork,
        script: u8,
        label: Option<&str>,
    ) -> WatchedPayment {
        WatchedPayment {
            network,
            script_pubkey: vec![0x00, 0x14, script],
            address: format!("addr-{script}"),
            label: label.map(|s| s.to_string()),
            order_id: None,
            expected_amount_sats: Some(50_000),
            contract_id: None,
            added_at_ms: 1_700_000_000_000,
            bridge_synced: false,
            last_error: None,
        }
    }

    #[test]
    fn watch_then_list_roundtrips() {
        let mut watches = Vec::new();
        let inserted = apply_watch(&mut watches, watch(BitcoinNetwork::Signet, 1, Some("rent")));
        assert_eq!(watches, vec![inserted]);
    }

    #[test]
    fn watching_the_same_script_twice_replaces_rather_than_duplicates() {
        let mut watches = Vec::new();
        apply_watch(&mut watches, watch(BitcoinNetwork::Signet, 1, Some("rent")));
        apply_watch(
            &mut watches,
            watch(BitcoinNetwork::Signet, 1, Some("rent (renamed)")),
        );
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].label.as_deref(), Some("rent (renamed)"));
    }

    #[test]
    fn unwatch_of_an_unknown_script_removes_nothing_but_is_not_an_error() {
        let mut watches = vec![watch(BitcoinNetwork::Signet, 1, None)];
        let removed = apply_unwatch(&mut watches, BitcoinNetwork::Signet, &[0x00, 0x14, 0xff]);
        assert!(!removed, "no matching watch should be found");
        assert_eq!(watches.len(), 1, "the unrelated watch must survive");
        // The handler-level contract (see `handle`) always returns
        // `result: Ok(())` for Unwatch regardless of `removed`, which is the
        // property this test exists to pin: unwatching something you were
        // never watching is success, not an error.
    }

    #[test]
    fn unwatch_of_a_known_script_removes_it() {
        let mut watches = vec![watch(BitcoinNetwork::Signet, 1, None)];
        let removed = apply_unwatch(&mut watches, BitcoinNetwork::Signet, &[0x00, 0x14, 0x01]);
        assert!(removed);
        assert!(watches.is_empty());
    }

    #[test]
    fn associate_order_attaches_to_an_existing_watch() {
        let mut watches = vec![watch(BitcoinNetwork::Signet, 1, None)];
        let order_id = OrderId([7u8; 32]);
        apply_associate_order(
            &mut watches,
            BitcoinNetwork::Signet,
            &[0x00, 0x14, 0x01],
            order_id.clone(),
            12_345,
        )
        .expect("watch exists");
        assert_eq!(watches[0].order_id, Some(order_id));
        assert_eq!(watches[0].expected_amount_sats, Some(12_345));
    }

    #[test]
    fn associate_order_on_a_script_never_watched_is_an_error() {
        let mut watches: Vec<WatchedPayment> = Vec::new();
        let result = apply_associate_order(
            &mut watches,
            BitcoinNetwork::Signet,
            &[0x00, 0x14, 0x01],
            OrderId([1u8; 32]),
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn the_same_script_on_two_networks_is_two_distinct_watches() {
        let mut watches = Vec::new();
        apply_watch(&mut watches, watch(BitcoinNetwork::Bitcoin, 1, None));
        apply_watch(&mut watches, watch(BitcoinNetwork::Signet, 1, None));
        assert_eq!(watches.len(), 2);
    }

    /// Manual watches and order-driven watches must go through the same
    /// upsert so they can never diverge in behavior -- this pins that
    /// `watch_order_payment`'s core logic literally is `apply_watch`, not a
    /// parallel reimplementation of it.
    #[test]
    fn order_driven_watch_shares_apply_watch_with_manual_watch() {
        let mut watches = Vec::new();
        apply_watch(
            &mut watches,
            watch(BitcoinNetwork::Signet, 1, Some("manual label")),
        );

        let order_id = OrderId([9u8; 32]);
        let order_watch = WatchedPayment {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 1],
            address: "addr-1".into(),
            label: None,
            order_id: Some(order_id.clone()),
            expected_amount_sats: Some(99),
            contract_id: None,
            added_at_ms: 1,
            bridge_synced: false,
            last_error: None,
        };
        apply_watch(&mut watches, order_watch);

        // Same key => the manual watch's private label is gone now, exactly
        // as it would be if the same `Watch` request had been replayed --
        // there is only one code path, not two with different semantics.
        assert_eq!(watches.len(), 1);
        assert_eq!(watches[0].order_id, Some(order_id));
    }

    /// The BIP-84 account key for the specification's own test mnemonic,
    /// re-encoded under the test-network version so it can stand in for a
    /// seller's signet wallet export.
    fn signet_vpub() -> String {
        vpub_with_chain_code(0)
    }

    /// A DIFFERENT account key: same public point, a different chain code, so
    /// it parses and derives an entirely different set of addresses. Standing
    /// in for "the seller moved to another wallet", which is the only case
    /// where restarting the index count is correct.
    fn another_signet_vpub() -> String {
        vpub_with_chain_code(0xAA)
    }

    fn vpub_with_chain_code(xor: u8) -> String {
        let mut bytes = bs58::decode(
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        )
        .with_check(None)
        .into_vec()
        .expect("the BIP-84 vector must decode");
        bytes[..4].copy_from_slice(&0x045f_1cf6u32.to_be_bytes());
        bytes[13] ^= xor;
        bs58::encode(bytes).with_check().into_string()
    }

    #[test]
    fn a_valid_account_key_starts_the_counter_at_zero() {
        let status = apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None)
            .expect("a BIP-84 test-network key must be accepted");
        assert_eq!(status.next_index, 0);
        assert_eq!(status.network, BitcoinNetwork::Signet);
    }

    /// The seller's declared network has to agree with the key's own version,
    /// or a mainnet key gets filed as a signet one and the next invoice asks
    /// for real bitcoin.
    #[test]
    fn a_key_for_the_wrong_network_is_refused() {
        let err = apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Bitcoin, None)
            .expect_err("must refuse");
        assert!(err.contains("bitcoin"), "unhelpful error: {err}");
    }

    /// THE property. An index is consumed by being handed out, so no two
    /// invoices can be given one script -- see `bip32`'s module docs for why
    /// sharing one would let a single payment settle two orders.
    #[test]
    fn each_derivation_consumes_its_index_and_yields_a_new_script() {
        let mut status =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");

        let mut seen = std::collections::HashSet::new();
        for expected_index in 0..8u32 {
            let derived = apply_derive_order_address(&mut status).expect("derive");
            assert_eq!(derived.index, expected_index);
            assert_eq!(status.next_index, expected_index + 1);
            assert!(
                seen.insert(derived.script_pubkey.clone()),
                "index {expected_index} reused a script"
            );
            assert!(derived.address.starts_with("tb1q"), "{}", derived.address);
        }
    }

    /// Moving to a DIFFERENT wallet restarts the count: indices only mean
    /// anything relative to the key they derive from, so carrying the old one
    /// forward would skip addresses in the new wallet for nothing.
    #[test]
    fn setting_a_genuinely_new_key_restarts_the_counter() {
        let mut held =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        apply_derive_order_address(&mut held).expect("derive");
        apply_derive_order_address(&mut held).expect("derive");
        assert_eq!(held.next_index, 2);

        let replaced =
            apply_set_payment_xpub(&another_signet_vpub(), BitcoinNetwork::Signet, Some(&held))
                .expect("accepted");
        assert_eq!(replaced.next_index, 0);
    }

    /// Re-setting the key ALREADY IN USE must not restart the count, or every
    /// address already on a live invoice is handed out a second time -- the
    /// exact reuse this feature exists to prevent.
    ///
    /// The seller reaches this through an ordinary button. The one visible
    /// reason to touch the payment key is to correct the network (signet and
    /// testnet4 are indistinguishable from the key itself), and correcting it
    /// means re-pasting the same key.
    #[test]
    fn re_setting_the_same_key_keeps_the_counter() {
        let mut held =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        let first = apply_derive_order_address(&mut held).expect("derive");
        apply_derive_order_address(&mut held).expect("derive");
        assert_eq!(held.next_index, 2);

        let mut again = apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, Some(&held))
            .expect("accepted");
        assert_eq!(
            again.next_index, 2,
            "re-setting the same key must not re-issue addresses that already have invoices"
        );
        let next = apply_derive_order_address(&mut again).expect("derive");
        assert_ne!(
            next.script_pubkey, first.script_pubkey,
            "the address after a re-set must not be one already handed out"
        );
    }

    /// Sameness is decided on the parsed key, not the string. A wallet
    /// re-exporting the same account key can differ in surrounding whitespace,
    /// and treating that as a new key would restart the count.
    #[test]
    fn a_re_pasted_key_is_recognised_despite_whitespace() {
        let mut held =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        apply_derive_order_address(&mut held).expect("derive");

        let padded = format!("  {}\n", signet_vpub());
        let again =
            apply_set_payment_xpub(&padded, BitcoinNetwork::Signet, Some(&held)).expect("accepted");
        assert_eq!(again.next_index, 1);
    }

    /// Re-filing the same key under a different test network must not restart
    /// either. Signet, testnet4 and regtest derive byte-identical addresses,
    /// so the indices already handed out are live addresses in that wallet
    /// whatever the record says the network was.
    #[test]
    fn re_filing_the_same_key_under_another_test_network_keeps_the_counter() {
        let mut held =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        apply_derive_order_address(&mut held).expect("derive");
        apply_derive_order_address(&mut held).expect("derive");

        let refiled = apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Testnet4, Some(&held))
            .expect("accepted");
        assert_eq!(refiled.network, BitcoinNetwork::Testnet4);
        assert_eq!(refiled.next_index, 2);
    }

    /// Running off the end of public derivation must refuse rather than wrap,
    /// because wrapping means handing out index 0 a second time.
    #[test]
    fn exhausting_the_key_refuses_rather_than_wrapping() {
        let mut status =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        status.next_index = crate::bip32::MAX_ORDER_INDEX + 1;

        let err = apply_derive_order_address(&mut status).expect_err("must refuse");
        assert!(err.contains("every address"), "unhelpful error: {err}");
        assert_eq!(
            status.next_index,
            crate::bip32::MAX_ORDER_INDEX + 1,
            "a refused derivation must not advance the counter"
        );
    }

    // -----------------------------------------------------------------
    // Recovering the counter from the store's published orders (harvest#77)
    // -----------------------------------------------------------------

    /// The scripts `key` derives at `indices`, standing in for the store's
    /// published orders.
    fn published_at(key: &str, indices: &[u32]) -> Vec<Vec<u8>> {
        let chain = AccountXpub::parse(key)
            .expect("parse")
            .external_chain()
            .expect("chain");
        indices
            .iter()
            .map(|&i| chain.script_at(i).expect("derive"))
            .collect()
    }

    /// The scan before #206 bounded it, kept verbatim as the reference.
    fn floor_unbounded(status: &mut PaymentXpubStatus, published: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut remaining: std::collections::HashSet<&[u8]> =
            published.iter().map(Vec::as_slice).collect();
        let mut matched = Vec::new();
        if remaining.is_empty() {
            return matched;
        }
        let chain = AccountXpub::parse(&status.xpub)
            .unwrap()
            .external_chain()
            .unwrap();
        let mut index = status.next_index;
        let mut give_up_at = index.saturating_add(PUBLISHED_INDEX_GAP);
        while index <= MAX_ORDER_INDEX && index < give_up_at && !remaining.is_empty() {
            let script = chain.script_at(index).unwrap();
            if remaining.remove(script.as_slice()) {
                matched.push(script);
                status.next_index = index + 1;
                give_up_at = status.next_index.saturating_add(PUBLISHED_INDEX_GAP);
            }
            index += 1;
        }
        matched
    }

    /// `key` with its chain code replaced: another valid key of the same
    /// network, deriving entirely different addresses.
    fn variant_of(key: &str, byte: u8) -> String {
        let mut bytes = bs58::decode(key).with_check(None).into_vec().unwrap();
        bytes[13..45].copy_from_slice(&[byte; 32]);
        bs58::encode(bytes).with_check().into_string()
    }

    /// #206, #183: the delegate-owned catch-up, run to completion, hands out
    /// as its first address exactly the counter the unbounded reference scan
    /// reaches over the same scripts from the last point the counter was set
    /// other than by the scan. Over random published sets (contiguous runs,
    /// gaps up to and past `PUBLISHED_INDEX_GAP`, scripts below the counter,
    /// foreign scripts, a second key's real scripts, runs longer than one
    /// call), arriving in random chunks in random order, with scans of
    /// random budgets between them, addresses handed out between chunks
    /// (each never one already held, and published afterwards), the counter
    /// now and then set lower, and the key switched to another and back.
    /// So no arrival order, budget or switch lets an address below the true
    /// floor out. Mutated red by not sending a scan back to its counter when
    /// a script is added, by resuming past the cursor, and by reading a
    /// cursor saved for a higher counter.
    #[test]
    fn the_catch_up_reaches_the_unbounded_floor_whatever_the_arrival() {
        let key = signet_vpub();
        let other = variant_of(&key, 0x5a);
        let chain = AccountXpub::parse(&key).unwrap().external_chain().unwrap();
        let other_chain = AccountXpub::parse(&other)
            .unwrap()
            .external_chain()
            .unwrap();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n.max(1)
        };
        for round in 0..32 {
            let start = next(50) as u32;
            let mut indices = Vec::new();
            let mut at = start;
            let count = 1 + next(if round % 3 == 0 { 900 } else { 60 });
            for _ in 0..count {
                // Mostly close; sometimes a gap of up to the limit; now and
                // then one of the limit or more (exactly the limit is still
                // reached, more is past it and ends the scan there).
                at += match next(40) {
                    0 => PUBLISHED_INDEX_GAP + next(20) as u32,
                    1..=3 => next(u64::from(PUBLISHED_INDEX_GAP)) as u32,
                    _ => 1 + next(3) as u32,
                };
                indices.push(at);
            }
            if start > 0 {
                indices.push(start - 1);
            }
            let mut published: Vec<Vec<u8>> = indices
                .iter()
                .map(|&i| chain.script_at(i).unwrap())
                .collect();
            published.push(vec![0x00, 0x14, round as u8]);
            for i in 0..next(30) as u32 {
                published.push(other_chain.script_at(i * 3).unwrap());
            }
            for i in (1..published.len()).rev() {
                let j = next(i as u64 + 1) as usize;
                published.swap(i, j);
            }

            let mut store = crate::secrets::MemSecrets::default();
            let mut status = PaymentXpubStatus {
                xpub: key.clone(),
                network: BitcoinNetwork::Signet,
                next_index: start,
            };
            save_payment_xpub(&mut store, &status).unwrap();
            // Where the counter was last set other than by the scan.
            let mut set_at = start;
            let mut held: Vec<Vec<u8>> = Vec::new();
            let mut handed_out: Vec<Vec<u8>> = Vec::new();
            let mut rest = published.as_slice();
            while !rest.is_empty() {
                let take = (1 + next(rest.len() as u64 / 2 + 1) as usize).min(rest.len());
                add_published(&mut store, &rest[..take]).unwrap();
                held.extend_from_slice(&rest[..take]);
                rest = &rest[take..];
                match next(4) {
                    0 => {
                        advance_scan(&mut store, Slot::Active, &mut status, 1 + next(400) as u32)
                            .unwrap();
                    }
                    1 => {
                        if let Ok(d) =
                            issue_next_address(&mut store, 1 + next(400) as u32, |_| true)
                        {
                            assert!(!held.contains(&d.script_pubkey), "round {round}");
                            handed_out.push(d.script_pubkey);
                            set_at = d.index + 1;
                        }
                    }
                    2 if round % 4 == 1 => {
                        // Set lower, as a counter restored from elsewhere.
                        let mut lowered = load_payment_xpub(&store).unwrap();
                        lowered.next_index = lowered.next_index.saturating_sub(1 + next(40) as u32);
                        save_payment_xpub(&mut store, &lowered).unwrap();
                        set_at = lowered.next_index;
                    }
                    _ => {}
                }
            }
            // What was handed out is published too, by now.
            add_published(&mut store, &handed_out).unwrap();
            if round % 5 == 2 {
                // Switched to another key and back: the key starts again at 0.
                for xpub in [&other, &key] {
                    let mut tries = 0;
                    while set_payment_key(&mut store, xpub, BitcoinNetwork::Signet, &[], tries > 0)
                        .is_err()
                    {
                        tries += 1;
                        assert!(tries < 200, "round {round}: no end");
                    }
                }
                set_at = 0;
            }
            let mut all = published.clone();
            all.extend(handed_out.iter().cloned());
            let mut reference = PaymentXpubStatus {
                xpub: key.clone(),
                network: BitcoinNetwork::Signet,
                next_index: set_at,
            };
            floor_unbounded(&mut reference, &all);
            let mut calls = 0;
            let first = loop {
                match issue_next_address(&mut store, FLOOR_SCAN_BUDGET, |_| true) {
                    Ok(d) => break d,
                    Err(NotIssued::CatchingUp(_)) => {}
                    Err(e) => panic!("round {round}: {e:?}"),
                }
                calls += 1;
                assert!(calls < 100, "round {round}: no end");
            };
            assert_eq!(first.index, reference.next_index, "round {round}");
            assert!(!all.contains(&first.script_pubkey), "round {round}");
        }
    }

    /// **The reported case.** A fresh install holds no count, the same key is
    /// entered, and the store already publishes orders at indices 0-2. The
    /// next invoice must be index 3, not 0.
    #[test]
    fn a_fresh_install_resumes_past_the_stores_published_orders() {
        let published = published_at(&signet_vpub(), &[0, 1, 2]);
        let mut status =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        assert_eq!(status.next_index, 0, "the device genuinely knows nothing");

        assert_eq!(apply_published_floor(&mut status, &published), Ok(3));
        let derived = apply_derive_order_address(&mut status).expect("derive");
        assert_eq!(derived.index, 3);
        assert!(
            !published.contains(&derived.script_pubkey),
            "the new invoice was given an address a published order already names"
        );
    }

    /// A stale device -- one that handed out a few addresses and then fell
    /// behind another device on the same key -- takes the network's count.
    /// Burned indices between published orders do not stop the scan.
    #[test]
    fn a_stale_device_takes_the_higher_published_count() {
        let mut status =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        status.next_index = 1;
        // Index 4 and 40 published elsewhere; 5-39 burned by abandoned invoices.
        let published = published_at(&signet_vpub(), &[0, 4, 40]);
        assert_eq!(apply_published_floor(&mut status, &published), Ok(41));
    }

    /// Each match pushes the give-up point on, so published orders spaced
    /// less than the gap apart are all found however far the run goes -- the
    /// second one here is past `PUBLISHED_INDEX_GAP` from the START.
    #[test]
    fn each_match_extends_the_scan() {
        let mut status =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        let first = PUBLISHED_INDEX_GAP - 10;
        let second = first + PUBLISHED_INDEX_GAP - 10;
        let published = published_at(&signet_vpub(), &[first, second]);
        assert_eq!(
            apply_published_floor(&mut status, &published),
            Ok(second + 1)
        );
    }

    /// And never the other way: a device AHEAD of the network (addresses
    /// derived, invoices not yet published) keeps its count, or it would hand
    /// out an address already shown to a buyer.
    #[test]
    fn a_device_ahead_of_the_network_keeps_its_count() {
        let mut status =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        status.next_index = 10;
        let published = published_at(&signet_vpub(), &[0, 1, 2]);
        assert_eq!(apply_published_floor(&mut status, &published), Ok(10));
    }

    /// Orders paid into some OTHER wallet raise nothing, so a seller who
    /// moved to a new wallet starts it at 0 as before.
    #[test]
    fn orders_from_another_key_do_not_move_the_count() {
        let mut status =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        let elsewhere = published_at(&another_signet_vpub(), &[0, 1, 2, 3]);
        assert_eq!(apply_published_floor(&mut status, &elsewhere), Ok(0));
    }

    /// KNOWN LIMIT, pinned so it is a decision rather than a surprise: a
    /// published order more than [`PUBLISHED_INDEX_GAP`] indices past the
    /// last one found is not found. Reaching it takes that many abandoned
    /// invoices in a row; the store contract's payment window still stops
    /// that order's payment settling a new one.
    #[test]
    fn a_published_order_beyond_the_gap_is_not_found() {
        let mut status =
            apply_set_payment_xpub(&signet_vpub(), BitcoinNetwork::Signet, None).expect("accepted");
        let within = published_at(&signet_vpub(), &[PUBLISHED_INDEX_GAP - 1]);
        assert_eq!(
            apply_published_floor(&mut status.clone(), &within),
            Ok(PUBLISHED_INDEX_GAP)
        );
        let beyond = published_at(&signet_vpub(), &[PUBLISHED_INDEX_GAP]);
        assert_eq!(apply_published_floor(&mut status, &beyond), Ok(0));
    }

    /// A private label must never end up in anything shaped for the wire to
    /// a bridge. This mirrors
    /// `harvest_common::bitcoin_delegate::tests::the_bridge_watch_request_has_nowhere_to_put_a_private_label`,
    /// but starting from a watch that went through *this* crate's storage
    /// round-trip, so it also pins that nothing added here (e.g. a future
    /// helper that assembles a bridge request from a stored watch) smuggles
    /// the label along.
    #[test]
    fn a_stored_labels_watch_never_leaks_into_a_bridge_watch_request() {
        let mut watches = Vec::new();
        let stored = apply_watch(
            &mut watches,
            watch(BitcoinNetwork::Signet, 1, Some("secret rent label")),
        );

        let bridge_request = freenet_bitcoin_common::WatchRequest {
            network: stored.network,
            script_pubkey: stored.script_pubkey.clone(),
            scan_from_height: None,
        };
        let encoded = freenet_bitcoin_common::to_cbor(&bridge_request).unwrap();
        let haystack = String::from_utf8_lossy(&encoded).to_string();
        assert!(
            !haystack.contains("secret rent label"),
            "a private label reached the bridge wire format"
        );
    }
}

// ---------------------------------------------------------------------------
// Origin gating.
//
// These drive `handle` against a real (in-memory) secret store rather than the
// `apply_*` functions, because the property under test is not "what does the
// watch list do" but "whose request was allowed to touch it". A test that
// called `apply_set_payment_xpub` directly would pass no matter what the gate
// did.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod origin_gating_tests {
    use super::tests::watch;
    use super::*;
    use crate::origin::test_origins::{a_different_web_app, harvest};
    use crate::secrets::MemSecrets;
    use freenet_bitcoin_common::BridgeId;
    use harvest_common::bitcoin_delegate::BridgeAuthMode;

    /// The BIP-84 specification's account key, as the seller's own.
    const SELLERS_KEY: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    /// A DIFFERENT, equally valid account key, standing in for the attacker's
    /// own wallet.
    ///
    /// Built by replacing only the chain code, which leaves the version, the
    /// depth and the public point untouched -- so it parses and derives exactly
    /// as well as the seller's, while deriving entirely different addresses.
    /// That difference is the whole point of the fixture: it is what makes the
    /// assertions below able to fail. A test that "set a new key" by passing
    /// the SAME key twice asserts nothing, because the after-state matches the
    /// before-state whether the write happened or not.
    fn attackers_key() -> String {
        let mut bytes = bs58::decode(SELLERS_KEY)
            .with_check(None)
            .into_vec()
            .expect("the fixture key decodes");
        bytes[13..45].copy_from_slice(&[0xab; 32]);
        bs58::encode(bytes).with_check().into_string()
    }

    fn set_xpub(key: &str) -> BitcoinDelegateRequest {
        BitcoinDelegateRequest::SetPaymentXpub {
            request_id: 1,
            xpub: key.to_string(),
            network: BitcoinNetwork::Bitcoin,
            published_scripts: Vec::new(),
            resume: false,
        }
    }

    /// The stored key, read straight out of the secret store rather than
    /// through a request -- so a gate on the read path cannot mask what a write
    /// did or did not do.
    fn stored_key(store: &MemSecrets) -> Option<String> {
        load_payment_xpub(store).map(|status| status.xpub)
    }

    fn seller_sets(store: &mut MemSecrets, key: &str) {
        let response = handle(store, Some(&harvest()), set_xpub(key))
            .expect("the Harvest web app is authorized");
        match response {
            BitcoinDelegateResponse::PaymentXpubSet { result, .. } => {
                result.expect("the seller's own key must be accepted");
            }
            other => panic!("expected PaymentXpubSet, got {other:?}"),
        }
    }

    /// **The security property.** Another web app cannot redirect the seller's
    /// income.
    ///
    /// This is not a leak but a payment-destination hijack: every invoice
    /// issued afterwards would derive its address from the attacker's account
    /// key, while the buyer's checks all still pass -- the seller's signature
    /// and ghostkey certificate are genuine, and only the destination changed.
    /// The delegate's address is publicly derivable, so any web app the seller
    /// has ever opened on this node could send this request.
    ///
    /// Mutated red by removing the `authorize` call from `handle`.
    #[test]
    fn another_web_app_cannot_redirect_the_sellers_payments() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);

        let refusal = handle(
            &mut store,
            Some(&a_different_web_app()),
            set_xpub(&attackers_key()),
        )
        .expect_err("a foreign web app must be refused");
        let DelegateError::Other(message) = refusal else {
            panic!("expected a refusal message");
        };
        assert!(
            message.contains("Harvest web app"),
            "the refusal must say why: {message}"
        );

        assert_eq!(
            stored_key(&store).as_deref(),
            Some(SELLERS_KEY),
            "the seller's payment key was overwritten by another web app"
        );
        assert_ne!(
            stored_key(&store).as_deref(),
            Some(attackers_key().as_str()),
            "invoices would now pay the attacker"
        );
    }

    /// The other half, without which the test above could pass on a delegate
    /// that refuses everyone: the genuine caller still gets through, and the
    /// value that changes is the one that matters.
    #[test]
    fn the_harvest_web_app_can_still_set_the_payment_key() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        assert_eq!(stored_key(&store).as_deref(), Some(SELLERS_KEY));

        // A genuinely DIFFERENT key, so the assertion below fails if the write
        // silently did nothing.
        let replacement = attackers_key();
        seller_sets(&mut store, &replacement);
        assert_eq!(
            stored_key(&store).as_deref(),
            Some(replacement.as_str()),
            "the seller could not change their own payment key"
        );
    }

    /// A caller the node could not attest is refused too. `origin: None` is
    /// what the runtime supplies when it cannot say who is asking, and it must
    /// not be read as "probably the app".
    #[test]
    fn an_unattested_caller_cannot_set_the_payment_key() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);

        handle(&mut store, None, set_xpub(&attackers_key()))
            .expect_err("an unattested caller must be refused");
        assert_eq!(
            stored_key(&store).as_deref(),
            Some(SELLERS_KEY),
            "an unattested caller overwrote the seller's payment key"
        );
    }

    /// The reads are gated as well. An account xpub derives every address the
    /// store will ever issue, so one successful read links the seller's whole
    /// payment history, past and future.
    #[test]
    fn another_web_app_cannot_read_the_payment_key_or_the_watch_list() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        handle(
            &mut store,
            Some(&harvest()),
            BitcoinDelegateRequest::Watch {
                request_id: 2,
                watch: watch(BitcoinNetwork::Signet, 1, Some("rent")),
            },
        )
        .expect("the seller may watch an address");

        for request in [
            BitcoinDelegateRequest::GetPaymentXpub,
            BitcoinDelegateRequest::ListWatched,
            BitcoinDelegateRequest::GetBridge,
        ] {
            handle(&mut store, Some(&a_different_web_app()), request)
                .expect_err("a foreign web app must not read Harvest's private state");
        }

        // ...and the seller can still read their own.
        match handle(
            &mut store,
            Some(&harvest()),
            BitcoinDelegateRequest::ListWatched,
        )
        .expect("the seller may list their own watches")
        {
            BitcoinDelegateResponse::WatchList { watches } => assert_eq!(watches.len(), 1),
            other => panic!("expected a WatchList, got {other:?}"),
        }
    }

    /// The remaining mutating requests are gated too, so the fix is not
    /// specific to the one variant that prompted it.
    #[test]
    fn no_mutating_request_survives_a_foreign_origin() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);

        let mutations = vec![
            BitcoinDelegateRequest::Watch {
                request_id: 3,
                watch: watch(BitcoinNetwork::Signet, 2, Some("attacker")),
            },
            BitcoinDelegateRequest::Unwatch {
                request_id: 4,
                network: BitcoinNetwork::Signet,
                script_pubkey: vec![0x00, 0x14, 0x01],
            },
            BitcoinDelegateRequest::AssociateOrder {
                request_id: 5,
                network: BitcoinNetwork::Signet,
                script_pubkey: vec![0x00, 0x14, 0x01],
                order_id: OrderId([1u8; 32]),
                expected_amount_sats: 1,
            },
            BitcoinDelegateRequest::ConfigureBridge {
                request_id: 6,
                endpoint: BridgeEndpoint {
                    url: "https://attacker.example/bridge".into(),
                    bridge_id: BridgeId([0xcd; 32]),
                    network: BitcoinNetwork::Bitcoin,
                    auth: BridgeAuthMode::Open,
                },
            },
            BitcoinDelegateRequest::DeriveOrderAddress {
                request_id: 7,
                published_scripts: Vec::new(),
            },
        ];

        let before = load_watches(&store);
        let before_bridge = load_bridge(&store);
        let before_index = load_payment_xpub(&store).map(|s| s.next_index);

        for request in mutations {
            handle(&mut store, Some(&a_different_web_app()), request)
                .expect_err("a foreign web app must not mutate Harvest's private state");
        }

        assert_eq!(load_watches(&store), before, "the watch list was changed");
        assert_eq!(load_bridge(&store), before_bridge, "the bridge was changed");
        assert_eq!(
            load_payment_xpub(&store).map(|s| s.next_index),
            before_index,
            "an address index was consumed by a caller that had no business asking"
        );
    }

    /// harvest#77 through `handle`, the way the UI drives it: a brand new
    /// secret store (fresh install), the same key re-entered, and the store's
    /// published orders sent along with both requests. The count shown after
    /// the key is set, and the address the next invoice gets, both follow the
    /// published record.
    #[test]
    fn a_fresh_install_does_not_reissue_a_published_address() {
        let chain = crate::bip32::AccountXpub::parse(SELLERS_KEY)
            .expect("parse")
            .external_chain()
            .expect("chain");
        let published: Vec<Vec<u8>> = (0..3)
            .map(|i| chain.script_at(i).expect("derive"))
            .collect();

        let mut store = MemSecrets::default();
        match handle(
            &mut store,
            Some(&harvest()),
            BitcoinDelegateRequest::SetPaymentXpub {
                request_id: 1,
                xpub: SELLERS_KEY.to_string(),
                network: BitcoinNetwork::Bitcoin,
                published_scripts: published.clone(),
                resume: false,
            },
        )
        .expect("authorized")
        {
            BitcoinDelegateResponse::PaymentXpubSet { result, .. } => {
                assert_eq!(result.expect("accepted").next_index, 3);
            }
            other => panic!("expected PaymentXpubSet, got {other:?}"),
        }

        // The counter as stored, then wound back as if this device had lost
        // it again, so the derive request has to recover it on its own.
        let mut wound_back = load_payment_xpub(&store).expect("stored");
        wound_back.next_index = 0;
        save_payment_xpub(&mut store, &wound_back).expect("store");

        match handle(
            &mut store,
            Some(&harvest()),
            BitcoinDelegateRequest::DeriveOrderAddress {
                request_id: 2,
                published_scripts: published.clone(),
            },
        )
        .expect("authorized")
        {
            BitcoinDelegateResponse::OrderAddress { result, .. } => {
                let derived = result.expect("derived");
                assert_eq!(derived.index, 3);
                assert!(!published.contains(&derived.script_pubkey));
            }
            other => panic!("expected OrderAddress, got {other:?}"),
        }
        assert_eq!(load_payment_xpub(&store).map(|s| s.next_index), Some(4));
    }

    /// Step 2: a manual invoice still goes out while the store is paused.
    /// `DeriveOrderAddress` reads no store's pause; a paused seller answering
    /// a request by hand is acting on purpose. Mutated red by refusing it
    /// while any store reads as paused.
    #[test]
    fn a_manual_invoice_still_goes_out_while_paused() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        crate::auto_invoice::note_store_read(
            &mut store,
            &[1; 32],
            Some(&crate::auto_invoice::Refusal::StorePaused),
        );
        match handle(
            &mut store,
            Some(&harvest()),
            BitcoinDelegateRequest::DeriveOrderAddress {
                request_id: 2,
                published_scripts: Vec::new(),
            },
        )
        .expect("authorized")
        {
            BitcoinDelegateResponse::OrderAddress { result, .. } => {
                result.expect("derived while paused");
            }
            other => panic!("expected OrderAddress, got {other:?}"),
        }
    }

    /// **PR #83 review, Should Fix 8.** A stale device, not a fresh one: it
    /// holds this key with a count of 1, another device has since published
    /// orders up to index 4, and the seller re-enters the same key. Through
    /// `handle`, the count comes back as 5, and the next address is index 5.
    #[test]
    fn a_stale_device_re_entering_the_same_key_takes_the_published_count() {
        let chain = crate::bip32::AccountXpub::parse(SELLERS_KEY)
            .expect("parse")
            .external_chain()
            .expect("chain");
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        let mut held = load_payment_xpub(&store).expect("stored");
        held.next_index = 1;
        save_payment_xpub(&mut store, &held).expect("store");

        let published: Vec<Vec<u8>> = (0..5)
            .map(|i| chain.script_at(i).expect("derive"))
            .collect();
        match handle(
            &mut store,
            Some(&harvest()),
            BitcoinDelegateRequest::SetPaymentXpub {
                request_id: 3,
                xpub: SELLERS_KEY.to_string(),
                network: BitcoinNetwork::Bitcoin,
                published_scripts: published.clone(),
                resume: false,
            },
        )
        .expect("authorized")
        {
            BitcoinDelegateResponse::PaymentXpubSet { result, .. } => {
                assert_eq!(result.expect("accepted").next_index, 5);
            }
            other => panic!("expected PaymentXpubSet, got {other:?}"),
        }
        match handle(
            &mut store,
            Some(&harvest()),
            BitcoinDelegateRequest::DeriveOrderAddress {
                request_id: 4,
                published_scripts: Vec::new(),
            },
        )
        .expect("authorized")
        {
            BitcoinDelegateResponse::OrderAddress { result, .. } => {
                assert_eq!(result.expect("derived").index, 5);
            }
            other => panic!("expected OrderAddress, got {other:?}"),
        }
    }

    /// #206: setting a key whose published orders are past one call's scan
    /// keeps the count reached and answers Err, never Ok (on Ok the UI would
    /// leave the scripts not yet reached out of its next address request);
    /// entered again, it goes on, and answers Ok once caught up. Mutated red
    /// by answering Ok from a scan left short.
    #[test]
    fn a_key_set_past_one_scan_is_entered_again_until_caught_up() {
        let chain = crate::bip32::AccountXpub::parse(SELLERS_KEY)
            .expect("parse")
            .external_chain()
            .expect("chain");
        let last = super::FLOOR_SCAN_BUDGET + 50;
        let sent: Vec<Vec<u8>> = (0..=last)
            .map(|i| chain.script_at(i).expect("derive"))
            .collect();
        let mut store = MemSecrets::default();
        let set = |store: &mut MemSecrets, id: u64| match handle(
            store,
            Some(&harvest()),
            BitcoinDelegateRequest::SetPaymentXpub {
                request_id: id,
                xpub: SELLERS_KEY.into(),
                network: BitcoinNetwork::Bitcoin,
                published_scripts: sent.clone(),
                resume: false,
            },
        )
        .expect("authorized")
        {
            BitcoinDelegateResponse::PaymentXpubSet {
                result,
                matched_scripts,
                ..
            } => (result, matched_scripts),
            other => panic!("{other:?}"),
        };
        let (first, matched) = set(&mut store, 1);
        let e = first.unwrap_err();
        assert_eq!(reached(&e), Some(super::FLOOR_SCAN_BUDGET), "{e}");
        assert!(matched.is_empty(), "nothing reported on Err");
        // No key was held: the part-way count is kept pending, and nothing
        // is active to hand an address out from.
        assert_eq!(load_payment_xpub(&store), None);
        assert_eq!(
            load_pending_payment_xpub(&store).unwrap().next_index,
            super::FLOOR_SCAN_BUDGET,
            "the count reached is kept"
        );
        let (second, _) = set(&mut store, 2);
        assert_eq!(second.expect("caught up").next_index, last + 1);
        assert_eq!(load_payment_xpub(&store).unwrap().next_index, last + 1);
        assert_eq!(
            load_pending_payment_xpub(&store),
            None,
            "dropped once active"
        );
    }

    /// The count a catching-up `Err` carries, read the way the UI reads it.
    fn reached(e: &str) -> Option<u32> {
        e.strip_prefix(harvest_common::bitcoin_delegate::CATCHING_UP_PREFIX)?
            .split(['/', ';'])
            .next()?
            .parse()
            .ok()
    }

    /// The scripts of indices `range` of `key`'s external chain.
    fn scripts_of(key: &str, range: std::ops::Range<u32>) -> Vec<Vec<u8>> {
        let chain = crate::bip32::AccountXpub::parse(key)
            .expect("parse")
            .external_chain()
            .expect("chain");
        range.map(|i| chain.script_at(i).expect("derive")).collect()
    }

    fn set_with(
        store: &mut MemSecrets,
        key: &str,
        id: u64,
        sent: &[Vec<u8>],
    ) -> (Result<PaymentXpubStatus, String>, Vec<Vec<u8>>) {
        match handle(
            store,
            Some(&harvest()),
            BitcoinDelegateRequest::SetPaymentXpub {
                request_id: id,
                xpub: key.into(),
                network: BitcoinNetwork::Bitcoin,
                published_scripts: sent.to_vec(),
                resume: false,
            },
        )
        .expect("authorized")
        {
            BitcoinDelegateResponse::PaymentXpubSet {
                result,
                matched_scripts,
                ..
            } => (result, matched_scripts),
            other => panic!("{other:?}"),
        }
    }

    fn derive_with(
        store: &mut MemSecrets,
        id: u64,
        sent: &[Vec<u8>],
    ) -> Result<DerivedAddress, String> {
        match handle(
            store,
            Some(&harvest()),
            BitcoinDelegateRequest::DeriveOrderAddress {
                request_id: id,
                published_scripts: sent.to_vec(),
            },
        )
        .expect("authorized")
        {
            BitcoinDelegateResponse::OrderAddress { result, .. } => result,
            other => panic!("{other:?}"),
        }
    }

    /// #206, the cross-tab case. The seller's key K1 is active, at a count
    /// past its published orders. Tab A sets a different key K2, whose
    /// published orders (from another device) run past one call's scan, so
    /// the set is left short. Tab B, which has sent its scripts already and
    /// so sends none, asks for an address. It must get K1's next address,
    /// never K2's index past the part-way count, which a K2 order already
    /// names. Mutated red by saving a short scan for another key as the
    /// active key.
    #[test]
    fn a_key_left_short_is_not_handed_out_from_by_another_tab() {
        let k2 = attackers_key();
        let k1_orders = scripts_of(SELLERS_KEY, 0..11);
        let k2_orders = scripts_of(&k2, 0..super::FLOOR_SCAN_BUDGET + 50);
        let everything: Vec<Vec<u8>> = k1_orders.iter().chain(&k2_orders).cloned().collect();
        let mut store = MemSecrets::default();
        let (k1, _) = set_with(&mut store, SELLERS_KEY, 1, &everything);
        assert_eq!(k1.expect("K1 set").next_index, 11);

        // Tab A: K2, left short.
        let (short, _) = set_with(&mut store, &k2, 2, &everything);
        assert_eq!(reached(&short.unwrap_err()), Some(super::FLOOR_SCAN_BUDGET));

        // Tab B: nothing to add.
        let derived = derive_with(&mut store, 3, &[]).expect("an address");
        assert!(
            !k2_orders.contains(&derived.script_pubkey),
            "index {} of K2 is a published order (harvest#77)",
            derived.index
        );
        assert_eq!(derived.index, 11);
        assert_eq!(derived.script_pubkey, scripts_of(SELLERS_KEY, 11..12)[0]);
        let active = load_payment_xpub(&store).expect("K1 still active");
        assert!(same_account(&active.xpub, SELLERS_KEY));
        assert_eq!(active.next_index, 12);
    }

    /// #206: a key left short is held pending, and setting it again resumes
    /// from the count it reached (not from 0) and, once complete, makes it
    /// the active key and drops the pending slot. Setting the active key
    /// again in full also drops whatever was pending. Mutated red by
    /// resuming from 0, and by not dropping the slot.
    #[test]
    fn a_pending_key_resumes_and_is_promoted_when_caught_up() {
        let k2 = attackers_key();
        let last = super::FLOOR_SCAN_BUDGET + 200;
        let k2_orders = scripts_of(&k2, 0..last + 1);
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);

        let (first, _) = set_with(&mut store, &k2, 1, &k2_orders);
        assert_eq!(reached(&first.unwrap_err()), Some(super::FLOOR_SCAN_BUDGET));
        assert_eq!(
            load_pending_payment_xpub(&store).map(|p| p.next_index),
            Some(super::FLOOR_SCAN_BUDGET)
        );
        assert!(same_account(
            &load_payment_xpub(&store).unwrap().xpub,
            SELLERS_KEY
        ));
        assert_eq!(load_payment_xpub(&store).unwrap().next_index, 0);

        // Resumed: from 384, one more call reaches the end. From 0 it would
        // be short again.
        let (second, _) = set_with(&mut store, &k2, 2, &k2_orders);
        assert_eq!(second.expect("caught up").next_index, last + 1);
        let active = load_payment_xpub(&store).unwrap();
        assert!(same_account(&active.xpub, &k2));
        assert_eq!(active.next_index, last + 1);
        assert_eq!(load_pending_payment_xpub(&store), None);

        // K1 left short now, then K2 (active) set again in full: the pending
        // K1 is over.
        let k1_orders = scripts_of(SELLERS_KEY, 0..super::FLOOR_SCAN_BUDGET + 5);
        let (k1, _) = set_with(&mut store, SELLERS_KEY, 3, &k1_orders);
        assert!(k1.is_err());
        assert!(load_pending_payment_xpub(&store).is_some());
        let (again, _) = set_with(&mut store, &k2, 4, &k2_orders);
        assert_eq!(again.expect("still caught up").next_index, last + 1);
        assert_eq!(load_pending_payment_xpub(&store), None);
    }

    /// #206: the ACTIVE key set again, left short, keeps advancing the
    /// active counter (see the argument in `handle`), and nothing is held
    /// pending for it.
    #[test]
    fn the_active_key_left_short_advances_its_own_counter() {
        let orders = scripts_of(SELLERS_KEY, 0..super::FLOOR_SCAN_BUDGET + 20);
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        let (short, _) = set_with(&mut store, SELLERS_KEY, 1, &orders);
        assert_eq!(reached(&short.unwrap_err()), Some(super::FLOOR_SCAN_BUDGET));
        assert_eq!(
            load_payment_xpub(&store).unwrap().next_index,
            super::FLOOR_SCAN_BUDGET
        );
        assert_eq!(load_pending_payment_xpub(&store), None);
    }

    /// Another valid account key, different from both the seller's and
    /// `attackers_key` (`byte` picks its chain code).
    fn another_key(byte: u8) -> String {
        let mut bytes = bs58::decode(SELLERS_KEY)
            .with_check(None)
            .into_vec()
            .expect("the fixture key decodes");
        bytes[13..45].copy_from_slice(&[byte; 32]);
        bs58::encode(bytes).with_check().into_string()
    }

    fn add_with(store: &mut MemSecrets, id: u64, scripts: &[Vec<u8>]) -> Result<(), String> {
        match handle(
            store,
            Some(&harvest()),
            BitcoinDelegateRequest::AddPublishedScripts {
                request_id: id,
                scripts: scripts.to_vec(),
            },
        )
        .expect("authorized")
        {
            BitcoinDelegateResponse::PublishedScriptsAdded { result, .. } => result,
            other => panic!("{other:?}"),
        }
    }

    /// #206 (D1): the boundary. A scan of a dense run stops after its 384th
    /// index matched, so the counter sits on index 384, which no scan has
    /// derived, and which a published order names. A stale tab that adds
    /// nothing (it believes its scripts are all sent) then asks for an
    /// address: it must never get 384, or any index the held scripts name.
    /// The answer is "catching up" until the scan is through, then the index
    /// past every published one. Mutated red by handing out from a scan that
    /// is not complete, and by scanning only the request's scripts.
    #[test]
    fn a_stale_tab_that_adds_nothing_never_gets_a_held_index() {
        // Long enough that the stale tab's own request cannot finish the
        // scan either.
        let last = super::FLOOR_SCAN_BUDGET * 2 + 116;
        let orders = scripts_of(SELLERS_KEY, 0..last + 1);
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        // Tab A enters the same key again with every script: left short at
        // the boundary.
        let (short, _) = set_with(&mut store, SELLERS_KEY, 1, &orders);
        let e = short.unwrap_err();
        assert_eq!(reached(&e), Some(super::FLOOR_SCAN_BUDGET), "{e}");
        assert!(orders.contains(&scripts_of(SELLERS_KEY, 384..385)[0]));
        // Tab B, adding nothing.
        let mut asks = 0;
        let derived = loop {
            asks += 1;
            assert!(asks < 5, "no end");
            match derive_with(&mut store, 10 + asks, &[]) {
                Ok(d) => break d,
                Err(e) => assert!(reached(&e).is_some(), "{e}"),
            }
        };
        assert!(
            !orders.contains(&derived.script_pubkey),
            "{}",
            derived.index
        );
        assert_eq!(derived.index, last + 1);
    }

    /// #206: scripts arriving in chunks, with address requests between
    /// them: no address handed out ever names a script already held, and
    /// once every chunk is in, the next is past them all. A chunk arriving
    /// after a scan finished sends it back over the new scripts. Mutated red
    /// by not restarting the scan when scripts are added.
    #[test]
    fn no_address_names_a_held_script_while_chunks_arrive() {
        let orders = scripts_of(SELLERS_KEY, 0..1000);
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        let mut held: Vec<Vec<u8>> = Vec::new();
        let mut handed_out = Vec::new();
        // Highest indices first, so an early complete scan is overtaken.
        for (n, chunk) in orders.rchunks(300).enumerate() {
            add_with(&mut store, n as u64, chunk).expect("held");
            held.extend_from_slice(chunk);
            for ask in 0..3 {
                if let Ok(d) = derive_with(&mut store, 100 + 10 * n as u64 + ask, &[]) {
                    assert!(!held.contains(&d.script_pubkey), "index {}", d.index);
                    handed_out.push(d.index);
                }
            }
        }
        let derived = loop {
            if let Ok(d) = derive_with(&mut store, 999, &[]) {
                break d;
            }
        };
        assert!(derived.index >= 1000, "{}", derived.index);
        // Some went out before the low chunks arrived: those are the
        // scripts the delegate had not been sent, which nothing can cover.
        assert!(!handed_out.is_empty());
    }

    /// #206 (D4): a newer key replaces the one pending, and the older one
    /// entered afresh starts again from 0. Entered as a `resume` of its old
    /// catch-up it is refused as superseded instead, and nothing is written,
    /// so two tabs with two keys cannot keep restarting each other. Mutated
    /// red by resuming over another key's pending slot.
    #[test]
    fn a_newer_key_replaces_the_pending_one() {
        let k2 = attackers_key();
        let k3 = another_key(0xcd);
        let mut orders = scripts_of(&k2, 0..super::FLOOR_SCAN_BUDGET + 50);
        orders.extend(scripts_of(&k3, 0..super::FLOOR_SCAN_BUDGET + 50));
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        assert!(set_with(&mut store, &k2, 1, &orders).0.is_err());
        assert!(same_account(
            &load_pending_payment_xpub(&store).unwrap().xpub,
            &k2
        ));
        assert!(set_with(&mut store, &k3, 2, &[]).0.is_err());
        let pending = load_pending_payment_xpub(&store).unwrap();
        assert!(same_account(&pending.xpub, &k3));
        assert_eq!(pending.next_index, super::FLOOR_SCAN_BUDGET);

        // K2 resumed: superseded, nothing written.
        let before = store.get_secret(BITCOIN_PAYMENT_XPUB_PENDING_KEY);
        let resumed = match handle(
            &mut store,
            Some(&harvest()),
            BitcoinDelegateRequest::SetPaymentXpub {
                request_id: 3,
                xpub: k2.clone(),
                network: BitcoinNetwork::Bitcoin,
                published_scripts: Vec::new(),
                resume: true,
            },
        )
        .unwrap()
        {
            BitcoinDelegateResponse::PaymentXpubSet { result, .. } => result,
            other => panic!("{other:?}"),
        };
        assert!(resumed
            .unwrap_err()
            .starts_with(harvest_common::bitcoin_delegate::KEY_SUPERSEDED_PREFIX));
        assert_eq!(store.get_secret(BITCOIN_PAYMENT_XPUB_PENDING_KEY), before);

        // K2 entered afresh: from 0 again, over K3.
        let (again, _) = set_with(&mut store, &k2, 4, &[]);
        assert_eq!(reached(&again.unwrap_err()), Some(super::FLOOR_SCAN_BUDGET));
        assert!(same_account(
            &load_pending_payment_xpub(&store).unwrap().xpub,
            &k2
        ));
        assert!(same_account(
            &load_payment_xpub(&store).unwrap().xpub,
            SELLERS_KEY
        ));
    }

    /// #206 review: K2's orders are held; K3, with none, completes and is
    /// made active; K2 entered again at the same generation must not read
    /// K3's cursor (which says "nothing held from 0 to 100") and hand out
    /// K2's index 0. Mutated red by not checking the cursor's key.
    #[test]
    fn a_cursor_is_never_read_for_another_key() {
        let k2 = attackers_key();
        let k3 = another_key(0xcd);
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        add_with(&mut store, 1, &scripts_of(&k2, 0..5)).unwrap();
        assert!(
            set_with(&mut store, &k3, 2, &[]).0.is_ok(),
            "K3 has no orders"
        );
        let (k2_set, _) = set_with(&mut store, &k2, 3, &[]);
        assert_eq!(k2_set.expect("set").next_index, 5);
    }

    /// #206 review: this device's own orders are held like any other, so
    /// a key switched away from and back to resumes past them, whichever
    /// tab sends them and when. (A filter that dropped them as "issued by
    /// the active key" lost them for good: retired.)
    #[test]
    fn the_keys_own_orders_are_held_after_a_switch_back() {
        let k2 = attackers_key();
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        let own: Vec<Vec<u8>> = (0..3)
            .map(|i| derive_with(&mut store, i, &[]).unwrap().script_pubkey)
            .collect();
        add_with(&mut store, 10, &own).unwrap();
        assert!(set_with(&mut store, &k2, 11, &[]).0.is_ok());
        let (back, _) = set_with(&mut store, SELLERS_KEY, 13, &[]);
        assert_eq!(back.expect("set").next_index, 3);
    }

    /// #206 review: after a complete scan, addresses handed out walk the
    /// counter past the cursor; a held script below the counter there (this
    /// device's own, published later) never lowers it, and the next address
    /// is the next index. Mutated red by letting a match set the counter
    /// below where it was.
    #[test]
    fn handing_out_past_the_cursor_never_lowers_the_counter() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        add_with(&mut store, 1, &scripts_of(SELLERS_KEY, 0..1)).unwrap();
        let first = derive_with(&mut store, 2, &[]).unwrap();
        assert_eq!(first.index, 1);
        let mut last = first.index;
        for id in 0..PUBLISHED_INDEX_GAP + 5 {
            last = derive_with(&mut store, 10 + u64::from(id), &[])
                .unwrap()
                .index;
        }
        // Published now: an index between the old cursor and the counter.
        add_with(&mut store, 3, &scripts_of(SELLERS_KEY, 103..104)).unwrap();
        let next = derive_with(&mut store, 4, &[]).unwrap();
        assert_eq!(next.index, last + 1);
    }

    /// #206 review: a held list that does not read is never taken for an
    /// empty one: no address goes out, nothing is written over it, and the
    /// key is not made active over it. Mutated red by loading it as empty.
    #[test]
    fn an_unreadable_held_list_hands_nothing_out() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        store.set_secret(crate::published_set::PUBLISHED_KEY, b"\x07garbage");
        let e = derive_with(&mut store, 1, &[]).unwrap_err();
        assert!(e.contains("could not be read"), "{e}");
        assert!(add_with(&mut store, 2, &scripts_of(SELLERS_KEY, 0..2)).is_err());
        assert_eq!(
            store
                .get_secret(crate::published_set::PUBLISHED_KEY)
                .as_deref(),
            Some(&b"\x07garbage"[..]),
            "not written over"
        );
        assert!(set_with(&mut store, &attackers_key(), 3, &[]).0.is_err());
        assert!(same_account(
            &load_payment_xpub(&store).unwrap().xpub,
            SELLERS_KEY
        ));
        assert_eq!(load_payment_xpub(&store).unwrap().next_index, 0);
    }

    /// #206 review: the held list's count is written, checked, before the
    /// list: refused, the list is not written either and the addition fails,
    /// so a count can never name an older generation than the list (which
    /// would let the store's status call a scan complete that is not).
    /// Mutated red by not checking the count's write.
    #[test]
    fn a_refused_count_write_adds_nothing() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        add_with(&mut store, 1, &scripts_of(SELLERS_KEY, 0..2)).unwrap();
        let before = store.get_secret(crate::published_set::PUBLISHED_KEY);
        store.refused_prefix = Some(crate::published_set::PUBLISHED_META_KEY.to_vec());
        assert!(add_with(&mut store, 2, &scripts_of(SELLERS_KEY, 5..7)).is_err());
        assert_eq!(
            store.get_secret(crate::published_set::PUBLISHED_KEY),
            before
        );
    }

    /// #206 review: scripts all held recently are not written again, so a
    /// host refusing writes refuses nothing: the address still goes out. A
    /// re-send that has to stamp scripts again (held long enough ago) needs
    /// the write, and a refused one fails the request: nothing goes out and
    /// the UI does not count them sent. Mutated red by rewriting the list on
    /// every addition, and by answering Ok when a needed re-stamp was not
    /// kept.
    #[test]
    fn scripts_already_held_write_nothing_and_refuse_nothing() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        let orders = scripts_of(SELLERS_KEY, 0..3);
        add_with(&mut store, 1, &orders).unwrap();
        let writes = store.write_log.len();
        add_with(&mut store, 2, &orders).unwrap();
        assert!(
            !store.write_log[writes..]
                .iter()
                .any(|k| k.as_slice() == crate::published_set::PUBLISHED_KEY),
            "nothing written"
        );
        store.refused_prefix = Some(b"harvest:bitcoin:published".to_vec());
        let derived = derive_with(&mut store, 3, &orders).expect("an address");
        assert_eq!(derived.index, 3);
        // Held long enough ago to be stamped again: the write is needed,
        // and refused it fails the request.
        store.refused_prefix = None;
        let mut held =
            crate::published_set::DigestList::load(&store, crate::published_set::PUBLISHED_KEY)
                .unwrap();
        held.age_for_test(crate::published_set::MAX_HELD as u64);
        crate::published_set::save_published(&mut store, &held);
        store.refused_prefix = Some(b"harvest:bitcoin:published".to_vec());
        assert!(
            derive_with(&mut store, 4, &orders).is_err(),
            "the stamps were not kept"
        );
        assert!(add_with(&mut store, 5, &orders).is_err());
        assert_eq!(load_payment_xpub(&store).unwrap().next_index, 4);
    }

    /// #206 review: a held-list write the node refuses: an address request
    /// carrying scripts hands nothing out.
    #[test]
    fn a_refused_held_list_write_hands_nothing_out() {
        let mut store = MemSecrets::refusing_writes_under(b"harvest:bitcoin:published".to_vec());
        store.refused_prefix = None;
        seller_sets(&mut store, SELLERS_KEY);
        store.refused_prefix = Some(b"harvest:bitcoin:published".to_vec());
        let e = derive_with(&mut store, 1, &scripts_of(SELLERS_KEY, 0..3)).unwrap_err();
        assert!(e.contains("refused"), "{e}");
        assert_eq!(load_payment_xpub(&store).unwrap().next_index, 0);
    }

    /// #206: a scheduled wake-up moves the active key's scan on by its
    /// budget, with nothing handed out, so instant checkout catches up with
    /// no tab open. Mutated red by dropping the wake-up's scan.
    #[test]
    fn a_wakeup_moves_the_scan_on() {
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        add_with(&mut store, 1, &scripts_of(SELLERS_KEY, 0..1000)).unwrap();
        crate::background::on_background(
            &mut store,
            &crate::node_glue::BackgroundRun::Wakeup {
                tag: crate::node_glue::HEARTBEAT_TAG.to_vec(),
            },
            1_800_000_000_000,
        );
        assert_eq!(
            load_payment_xpub(&store).unwrap().next_index,
            super::WAKEUP_SCAN_BUDGET
        );
    }

    /// The delegate's source with every `#[cfg(test)]` item removed. Braces
    /// inside string and character literals and comments are not counted.
    fn non_test(source: &str) -> String {
        /// The change in brace depth over `line`, ignoring literals and
        /// comments.
        fn depth_change(line: &str) -> i32 {
            let mut depth = 0;
            let mut chars = line.chars().peekable();
            let mut in_string = false;
            while let Some(c) = chars.next() {
                if in_string {
                    match c {
                        '\\' => {
                            chars.next();
                        }
                        '"' => in_string = false,
                        _ => {}
                    }
                    continue;
                }
                match c {
                    '"' => in_string = true,
                    '/' if chars.peek() == Some(&'/') => break,
                    '\'' => {
                        // A character literal ('{', '\''), or a lifetime.
                        let rest: String = chars.clone().take(3).collect();
                        if rest.starts_with('\\') {
                            chars.nth(2);
                        } else if rest.chars().nth(1) == Some('\'') {
                            chars.nth(1);
                        }
                    }
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            depth
        }
        let mut out = String::new();
        let mut lines = source.lines();
        while let Some(line) = lines.next() {
            if line.trim_start() == "#[cfg(test)]" {
                let mut depth = 0;
                let mut opened = false;
                for item in lines.by_ref() {
                    let change = depth_change(item);
                    opened |= change != 0 || item.contains('{');
                    depth += change;
                    if (opened && depth <= 0) || (!opened && item.trim_end().ends_with(';')) {
                        break;
                    }
                }
                out.push('\n');
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Every use of `pattern` in `code`, as the item it is in: the nearest
    /// `fn`, `struct` or `const` above it.
    fn uses(code: &str, pattern: &str) -> Vec<String> {
        let lines: Vec<&str> = code.lines().collect();
        let mut found = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            for _ in line.matches(pattern) {
                let item = lines[..=i]
                    .iter()
                    .rev()
                    .find_map(|l| {
                        let t = l.trim_start();
                        let t = t
                            .strip_prefix("pub(crate) ")
                            .or_else(|| t.strip_prefix("pub "))
                            .unwrap_or(t);
                        let t = t
                            .strip_prefix("fn ")
                            .or_else(|| t.strip_prefix("struct "))
                            .or_else(|| t.strip_prefix("const "))?;
                        Some(
                            t.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                                .next()
                                .unwrap_or_default()
                                .to_string(),
                        )
                    })
                    .unwrap_or_default();
                found.push(item);
            }
        }
        found
    }

    /// Every use of `pattern` in the delegate's non-test source, walked
    /// recursively, as `file::item`, sorted.
    fn uses_in_delegate(pattern: &str) -> Vec<String> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
        let mut files = Vec::new();
        walk(root, &mut files);
        let mut found = Vec::new();
        for path in files {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .to_string();
            let code = non_test(&std::fs::read_to_string(&path).unwrap());
            found.extend(
                uses(&code, pattern)
                    .into_iter()
                    .map(|item| format!("{name}::{item}")),
            );
        }
        found.sort();
        found
    }

    /// #206: only the choke point hands out an index. In the delegate's
    /// non-test source (every file, walked recursively, `#[cfg(test)]`
    /// items removed), each way of deriving an address, writing the
    /// counter, or building a counter is used only where it is allowed:
    /// `apply_derive_order_address` only in `issue_next_address`; an
    /// address derived (`.order_address(`) only there and where nothing is
    /// handed out (validating a key, listing the next addresses); the
    /// counter saved only by the choke point, the scan and a key's set; the
    /// counter's secret written only by its saver; a counter built or moved
    /// only by those, a migration's merge, and `decide`'s mirror of what the
    /// choke point just handed out; `mem::replace(&mut` nowhere; and the
    /// counter's secret named (or spelled out) only where it is defined,
    /// loaded, saved and sorted on import, so no local bound to it can be
    /// written elsewhere. Fails for any new use. Mutated red by the review's
    /// bypass (an `order_address` call, a counter built by literal, and
    /// `save_payment_xpub` in a new function), and by each of: a path call
    /// `AccountXpub::order_address(`, a `mem::replace(&mut` of the counter,
    /// and a write through a local bound to the key.
    #[test]
    fn only_the_choke_point_hands_out_an_index() {
        let pinned: &[(&str, &[&str])] = &[
            (
                "apply_derive_order_address(",
                &[
                    "bitcoin.rs::apply_derive_order_address",
                    "bitcoin.rs::issue_next_address",
                ],
            ),
            // Any call, method or path (`AccountXpub::order_address(..)`).
            (
                "order_address(",
                &[
                    "bip32.rs::order_address",
                    "bitcoin.rs::apply_derive_order_address",
                    "bitcoin.rs::apply_derive_order_address",
                    "bitcoin.rs::apply_set_payment_xpub",
                    "bitcoin.rs::issue_next_address",
                    "bitcoin.rs::upcoming_addresses",
                ],
            ),
            ("mem::replace(&mut", &[]),
            // The counter's secret, named or spelled out: a local bound to it
            // can only be bound where it is named.
            (
                "BITCOIN_PAYMENT_XPUB_KEY",
                &[
                    // Its definition, and the pending slot's doc naming it.
                    "bitcoin.rs::BITCOIN_PAYMENT_XPUB_KEY",
                    "bitcoin.rs::BITCOIN_PAYMENT_XPUB_KEY",
                    "bitcoin.rs::load_payment_xpub",
                    "bitcoin.rs::save_payment_xpub",
                    // A comparison, choosing the import's family.
                    "import.rs::family",
                ],
            ),
            ("payment-xpub:v1", &["bitcoin.rs::BITCOIN_PAYMENT_XPUB_KEY"]),
            (
                "save_payment_xpub(",
                &[
                    "bitcoin.rs::issue_next_address",
                    "bitcoin.rs::save_status",
                    "bitcoin.rs::set_payment_key",
                ],
            ),
            (
                ".save_status(",
                &["bitcoin.rs::advance_scan", "bitcoin.rs::set_payment_key"],
            ),
            (
                "set_secret(BITCOIN_PAYMENT_XPUB_KEY",
                &["bitcoin.rs::save_payment_xpub"],
            ),
            (
                ".next_index = ",
                &[
                    "auto_invoice.rs::decide_one",
                    "bitcoin.rs::advance_scan",
                    "bitcoin.rs::apply_derive_order_address",
                    "import.rs::import_payment_xpub",
                ],
            ),
            ("next_index += ", &[]),
            (
                "next_index:",
                &[
                    "watch_delegation.rs::Vouching",
                    "watch_delegation.rs::canary_floor",
                    "watch_delegation.rs::of",
                ],
            ),
            (
                "PaymentXpubStatus {",
                &["bitcoin.rs::apply_set_payment_xpub"],
            ),
        ];
        let wrong: Vec<String> = pinned
            .iter()
            .filter_map(|(pattern, allowed)| {
                let found = uses_in_delegate(pattern);
                (found != allowed.iter().map(|a| a.to_string()).collect::<Vec<_>>())
                    .then(|| format!("{pattern}: {found:?}"))
            })
            .collect();
        assert!(wrong.is_empty(), "{wrong:#?}");
        let auto = non_test(include_str!("auto_invoice.rs"));
        let mirror = auto
            .find("xpub.next_index = derived.index + 1")
            .expect("the mirror");
        let issue = auto
            .find("crate::bitcoin::issue_next_address(")
            .expect("the call");
        assert!(
            issue < mirror,
            "the mirror follows the choke point's answer"
        );
    }

    /// The scraper ignores braces in literals and comments: a test item
    /// holding a `"{"` does not hide the code after it.
    #[test]
    fn the_scraper_skips_test_items_whole() {
        let source = "fn a() {}\n#[cfg(test)]\nfn t() {\n    let s = \"{\"; // }\n    let c = '{';\n}\nfn b() { order_address(1) }\n";
        let code = non_test(source);
        assert!(!code.contains("fn t"));
        assert_eq!(uses(&code, "order_address("), ["b"]);
    }

    /// #206: a pending slot that a migration does not carry only restarts
    /// that key's catch-up; one it does carry lands in the pending slot,
    /// never as the active key. Either way the active key is untouched and
    /// no address is handed out from a part-way count. Mutated red by
    /// importing the pending slot into the active key.
    #[test]
    fn a_pending_slot_lost_or_carried_in_a_migration_never_promotes() {
        let k2 = attackers_key();
        let k2_orders = scripts_of(&k2, 0..super::FLOOR_SCAN_BUDGET + 50);
        let mut old = MemSecrets::default();
        seller_sets(&mut old, SELLERS_KEY);
        assert!(set_with(&mut old, &k2, 1, &k2_orders).0.is_err());
        let active = old.get_secret(BITCOIN_PAYMENT_XPUB_KEY).unwrap();
        let pending = old.get_secret(BITCOIN_PAYMENT_XPUB_PENDING_KEY).unwrap();

        // Lost: the successor holds K1 only, and K2 starts again from 0.
        let mut lost = MemSecrets::default();
        crate::import::import_secret(&mut lost, BITCOIN_PAYMENT_XPUB_KEY, &active);
        let (again, _) = set_with(&mut lost, &k2, 2, &k2_orders);
        assert_eq!(reached(&again.unwrap_err()), Some(super::FLOOR_SCAN_BUDGET));
        assert!(same_account(
            &load_payment_xpub(&lost).unwrap().xpub,
            SELLERS_KEY
        ));

        // Carried: in the pending slot, K1 still active. The pending slot
        // first, as an export lists it (its key sorts first).
        let mut carried = MemSecrets::default();
        crate::import::import_secret(&mut carried, BITCOIN_PAYMENT_XPUB_PENDING_KEY, &pending);
        crate::import::import_secret(&mut carried, BITCOIN_PAYMENT_XPUB_KEY, &active);
        let held = load_payment_xpub(&carried).unwrap();
        assert!(same_account(&held.xpub, SELLERS_KEY));
        assert_eq!(held.next_index, 0);
        assert_eq!(
            load_pending_payment_xpub(&carried).map(|p| p.next_index),
            Some(super::FLOOR_SCAN_BUDGET)
        );
        let derived = derive_with(&mut carried, 3, &[]).expect("K1's address");
        assert_eq!(derived.script_pubkey, scripts_of(SELLERS_KEY, 0..1)[0]);
    }

    /// #206: a counter far behind its published orders catches up over
    /// several requests, each deriving at most `FLOOR_SCAN_BUDGET` indices and
    /// saving the count it reached, and NO address is handed out until the
    /// scan is complete; then the one handed out is past every published
    /// order. Mutated red by handing one out from a scan left short, by not
    /// saving the progress, and without the budget.
    #[test]
    fn a_far_behind_counter_catches_up_before_any_address_goes_out() {
        let published: Vec<u32> = (0..super::FLOOR_SCAN_BUDGET * 2 + 50).collect();
        let chain = crate::bip32::AccountXpub::parse(SELLERS_KEY)
            .expect("parse")
            .external_chain()
            .expect("chain");
        let sent: Vec<Vec<u8>> = published
            .iter()
            .map(|&i| chain.script_at(i).expect("derive"))
            .collect();
        let mut store = MemSecrets::default();
        seller_sets(&mut store, SELLERS_KEY);
        let mut asks = 0;
        let derived = loop {
            asks += 1;
            assert!(asks <= 4, "no progress");
            match handle(
                &mut store,
                Some(&harvest()),
                BitcoinDelegateRequest::DeriveOrderAddress {
                    request_id: asks,
                    published_scripts: sent.clone(),
                },
            )
            .expect("authorized")
            {
                BitcoinDelegateResponse::OrderAddress { result: Ok(d), .. } => break d,
                BitcoinDelegateResponse::OrderAddress { result: Err(e), .. } => {
                    assert!(
                        e.starts_with(harvest_common::bitcoin_delegate::CATCHING_UP_PREFIX),
                        "{e}"
                    );
                    let count = load_payment_xpub(&store).unwrap().next_index;
                    assert_eq!(
                        count,
                        super::FLOOR_SCAN_BUDGET * asks as u32,
                        "progress saved"
                    );
                }
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(asks, 3, "two short scans, then the address");
        assert_eq!(derived.index, *published.last().unwrap() + 1);
    }
}
