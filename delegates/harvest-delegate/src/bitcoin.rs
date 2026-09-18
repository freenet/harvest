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
    PaymentXpubStatus, WatchedPayment,
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
/// So every derivation is also handed the scripts of the seller's own
/// published orders, and [`apply_published_floor`] moves the counter past
/// the highest index whose script it finds there. The counter is then the
/// maximum of what this device handed out and what the network shows.
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

fn load_payment_xpub<S: SecretStore>(store: &S) -> Option<PaymentXpubStatus> {
    store
        .get_secret(BITCOIN_PAYMENT_XPUB_KEY)
        .and_then(|bytes| from_cbor::<Option<PaymentXpubStatus>>(&bytes).ok())
        .flatten()
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
fn save_payment_xpub<S: SecretStore>(
    store: &mut S,
    status: &PaymentXpubStatus,
) -> Result<(), String> {
    let bytes = to_cbor(&Some(status.clone()))
        .map_err(|e| format!("could not encode the payment key record: {e}"))?;
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

/// How many consecutive indices past the last match [`apply_published_floor`]
/// derives before concluding there are no more published orders above it.
///
/// Published orders are not contiguous: an invoice abandoned after its address
/// was derived burns an index that no order names. A seller would have to
/// abandon this many invoices IN A ROW, then publish one, for the scan to stop
/// short of it -- and even then the store contract refuses to let that old
/// order's payment settle a new one. Each step is one public-key derivation,
/// so this is also the cost the scan adds to every invoice on a device whose
/// count is already current.
pub(crate) const PUBLISHED_INDEX_GAP: u32 = 100;

/// Raise `status.next_index` past every index of this key whose script
/// appears in `published`, and return the new value.
///
/// `published` is the payment scripts of the seller's own published orders
/// (see [`BitcoinDelegateRequest::DeriveOrderAddress`]). Scripts derived from
/// some other key never match and are ignored, which is what keeps a seller
/// who moved to a new wallet starting that wallet at 0.
///
/// Scans forward FROM the counter, not from 0: an index below the counter is
/// already covered, so matching it could not raise anything. It stops after
/// [`PUBLISHED_INDEX_GAP`] consecutive indices with no match, or when every
/// published script has been matched, or at [`MAX_ORDER_INDEX`]. Never lowers
/// the counter: a device ahead of the network (invoices derived but not yet
/// published) keeps its count.
fn apply_published_floor(
    status: &mut PaymentXpubStatus,
    published: &[Vec<u8>],
) -> Result<u32, String> {
    let mut remaining: std::collections::HashSet<&[u8]> =
        published.iter().map(Vec::as_slice).collect();
    if remaining.is_empty() {
        return Ok(status.next_index);
    }
    let chain = AccountXpub::parse(&status.xpub)?.external_chain()?;

    let mut index = status.next_index;
    // The first index the scan may give up at: `PUBLISHED_INDEX_GAP` past the
    // start, and pushed on by each match.
    let mut give_up_at = index.saturating_add(PUBLISHED_INDEX_GAP);
    while index <= MAX_ORDER_INDEX && index < give_up_at && !remaining.is_empty() {
        let script = chain.script_at(index)?;
        if remaining.remove(script.as_slice()) {
            status.next_index = index + 1;
            give_up_at = status.next_index.saturating_add(PUBLISHED_INDEX_GAP);
        }
        index += 1;
    }
    Ok(status.next_index)
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
        } => {
            let existing = load_payment_xpub(store);
            let result =
                apply_set_payment_xpub(&xpub, network, existing.as_ref()).and_then(|mut status| {
                    apply_published_floor(&mut status, &published_scripts)?;
                    save_payment_xpub(store, &status)?;
                    Ok(status)
                });
            BitcoinDelegateResponse::PaymentXpubSet { request_id, result }
        }

        BitcoinDelegateRequest::GetPaymentXpub => BitcoinDelegateResponse::PaymentXpub {
            status: load_payment_xpub(store),
        },

        BitcoinDelegateRequest::DeriveOrderAddress {
            request_id,
            published_scripts,
        } => {
            let result = match load_payment_xpub(store) {
                None => Err(
                    "no payment key is set for this store yet. Add your wallet's native \
                     SegWit account key before issuing an invoice."
                        .to_string(),
                ),
                // Raised to the network's count FIRST, so the index handed out
                // is past every published order of this key (harvest#77).
                Some(mut status) => apply_published_floor(&mut status, &published_scripts)
                    .and_then(|_| apply_derive_order_address(&mut status))
                    .and_then(|derived| {
                        // Save the advanced counter BEFORE the address leaves
                        // here. If persisting fails the address is discarded
                        // rather than returned, because a caller that received it
                        // may show it to a buyer while the delegate still believes
                        // the index is unused.
                        save_payment_xpub(store, &status)?;
                        Ok(derived)
                    }),
            };
            BitcoinDelegateResponse::OrderAddress { request_id, result }
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
}
