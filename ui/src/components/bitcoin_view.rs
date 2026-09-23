//! The Bitcoin/Payments section: live chain data, Harvest orders grouped by
//! payment status (payments-first -- this is Harvest's story, not a block
//! explorer), and the user's private watch list.
//!
//! # Realtime, end to end
//!
//! Nothing here polls. `crate::gateway::bitcoin_ops::subscribe_contract`
//! issues a GET with `subscribe: true` for a chain-tip or address contract;
//! `crate::gateway::response_handler` routes the resulting
//! `UpdateNotification`s back through `AppState::on_contract_state` (via a
//! re-GET -- see that module's long comment on why), which folds fresh
//! `BitcoinTipStateV1`/`BitcoinAddressStateV1` bytes into
//! `AppState.bitcoin.tips` / `.addresses`. Those are plain fields read here
//! through the `APP_STATE` global signal, so Dioxus re-renders this
//! component automatically whenever a block arrives or a watched address's
//! claims change -- no timer anywhere in this file.

use dioxus::prelude::*;

use freenet_bitcoin_common::BitcoinNetwork;
use harvest_common::payment::{AuthorizedOrder, OrderStatus};
use harvest_common::{BridgeEndpoint, WatchedPayment};

use crate::gateway::{bitcoin_address, bitcoin_config, bitcoin_ops, APP_STATE};
use crate::state::{watch_sync_status, AddressView, BitcoinState, TipView, TxRowStatus};

#[component]
pub fn BitcoinView() -> Element {
    let app_state = APP_STATE.read();
    let network = active_network(&app_state.bitcoin);
    let tip = app_state.bitcoin.tips.get(&network).cloned();
    let bridge_loaded = app_state.bitcoin.bridge_loaded;
    let bridge = app_state.bitcoin.bridge.clone();
    let orders = my_orders(&app_state);
    let watches = app_state.bitcoin.watches.clone();
    let watches_loaded = app_state.bitcoin.watches_loaded;
    let has_ghostkey = !app_state.ghostkeys.is_empty();

    // A brand-new user has neither -- that's the first-run case, and it
    // gets the expanded live-data panel instead of an empty table. Once
    // either appears, the compact status bar plus payments-first layout
    // takes over.
    let show_first_run = watches_loaded
        && watches.is_empty()
        && orders.is_empty()
        && app_state.kept_purchases.is_empty();

    rsx! {
        div {
            h2 { "Payments" }

            div { class: "info-box",
                p {
                    "A bridge attests what it saw on chain, and anyone can check the signed "
                    "evidence it carries \u{2014} so neither buyer nor seller has to be taken at "
                    "their word about a payment. You do have to trust the bridge itself for what "
                    "is on the chain. Orders here show real payment status as it confirms."
                }
            }

            BridgeStatusBar { bridge_loaded, bridge: bridge.clone(), network, tip: tip.clone() }

            if show_first_run {
                FirstRunPanel { bridge_loaded, bridge, network, tip, has_ghostkey }
            } else {
                if !orders.is_empty() {
                    OrdersSection { orders, app_state_snapshot: app_state.bitcoin.clone() }
                }
                WatchListSection { watches, network, has_ghostkey }
            }
        }
    }
}

/// Which network the section currently shows: whatever the user is already
/// watching something on, else the configured bridge's network, else the
/// build's default demo network.
fn active_network(bitcoin: &BitcoinState) -> BitcoinNetwork {
    if let Some(w) = bitcoin.watches.first() {
        return w.network;
    }
    if let Some(b) = &bitcoin.bridge {
        return b.network;
    }
    bitcoin_config::default_network()
}

/// Every order in the stores this node's own Ghost Keys own: the seller's
/// own book, across every store of theirs whose state has loaded.
///
/// # Only the SELLER's orders
///
/// This used to include orders naming one of our fingerprints as the buyer.
/// `buyer_fingerprint` is written by the seller, and each card shows a
/// payment address, so any seller could put an address in front of a buyer
/// here that the buyer's own node never kept (review round 3 of #143,
/// P1-A). A buyer's orders are shown only on the store page's purchase card,
/// which shows an address only once the buyer's node keeps the order
/// (`docs/complaint-threat-model.md` section 3.1). Ownership is by this
/// node's own store registrations, not by the order's `seller_fingerprint`,
/// which is seller-written too.
///
/// A buyer's own purchases, paid or not, are on the store page's purchase
/// card, which checks the order is really theirs (`AppState::paid_copy`);
/// this tab lists nothing it cannot check that way. Round 4 briefly listed
/// a buyer's settled orders here by `buyer_fingerprint`, and round 5 took it
/// out again: a seller can mint a `Paid` order naming any fingerprint, and
/// the tab would have shown it as this buyer's (model 3.3).
///
/// An order still awaiting payment is left out when its store is not
/// `payable` -- closed, or unbacked (harvest#93 review, Must Fix 2): its card
/// would show a payment address nobody should use. Settled orders stay, as
/// history.
pub(crate) fn my_orders(app_state: &crate::state::AppState) -> Vec<AuthorizedOrder> {
    let mut orders: Vec<AuthorizedOrder> = app_state
        .browsing_stores
        .iter()
        .filter(|(id, _)| app_state.store_owner_fingerprint(id).is_some())
        .flat_map(|(_, s)| {
            s.orders
                .iter()
                .filter(move |o| s.payable() || o.status != OrderStatus::AwaitingPayment)
        })
        .cloned()
        .collect();
    // Newest first.
    orders.sort_by_key(|o| std::cmp::Reverse(o.order.created_at));
    orders
}

// ---------------------------------------------------------------------------
// Bridge / chain-tip status
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum BridgeHealth {
    /// `GetBridge` has answered and no bridge is configured. Real state of
    /// the world today: there is no canonical default bridge published
    /// anywhere yet (`freenet-bitcoin/deploy/` is empty), so this is
    /// expected, not an error -- say so plainly rather than looking broken.
    NotConfigured,
    /// A bridge is configured but we haven't yet learned its tip contract
    /// id (still waiting on `GetBridge`, or the bridge's tip pointer has not
    /// resolved), or we have the id but no data has arrived from the
    /// subscription yet.
    WaitingForData,
    Online,
    Stale,
}

fn bridge_health(
    bridge_loaded: bool,
    bridge: &Option<BridgeEndpoint>,
    network: BitcoinNetwork,
    tip: &Option<TipView>,
) -> BridgeHealth {
    // Health is judged on whether CHAIN DATA is arriving, not on whether a
    // bridge endpoint happens to be configured in the delegate.
    //
    // Those are different things: tip data reaches us by subscribing to the
    // public tip contract, which needs no endpoint and no credential at all.
    // Judging on the endpoint made the bar report "no bridge configured" while
    // live blocks were visibly streaming in beside it -- the status
    // contradicting the data directly under it.
    //
    // An endpoint is needed to ask a bridge to START WATCHING a new address,
    // which is a separate question surfaced at the point the user tries it.
    let Some(tip) = tip else {
        return if bridge_loaded && bridge.is_none() {
            BridgeHealth::NotConfigured
        } else {
            BridgeHealth::WaitingForData
        };
    };
    let Some(last_block_time) = tip.last_block_time else {
        return BridgeHealth::WaitingForData;
    };
    // Regtest blocks are manually mined and may be minutes or days apart --
    // recency says nothing about health there, so don't call it stale.
    if network == BitcoinNetwork::Regtest {
        return BridgeHealth::Online;
    }
    let age = (now_unix_seconds() - last_block_time as i64).max(0);
    // 6x the ~10-minute target interval: generous enough that ordinary
    // variance in block timing never falsely reads as "stale".
    if age < 60 * 60 {
        BridgeHealth::Online
    } else {
        BridgeHealth::Stale
    }
}

#[component]
fn BridgeStatusBar(
    bridge_loaded: bool,
    bridge: Option<BridgeEndpoint>,
    network: BitcoinNetwork,
    tip: Option<TipView>,
) -> Element {
    let health = bridge_health(bridge_loaded, &bridge, network, &tip);
    let (dot_class, label) = match health {
        BridgeHealth::NotConfigured => (
            "btc-dot unknown",
            "No chain data yet -- no bridge is publishing for this network".to_string(),
        ),
        BridgeHealth::WaitingForData => (
            "btc-dot unknown",
            "Connecting to the Bitcoin bridge…".to_string(),
        ),
        BridgeHealth::Online => ("btc-dot online", "Online".to_string()),
        BridgeHealth::Stale => (
            "btc-dot offline",
            "No recent blocks -- bridge may be behind".to_string(),
        ),
    };

    rsx! {
        div { class: "btc-status-bar",
            span { class: "{dot_class}" }
            span { class: "btc-status-text", "{label}" }
            span { class: "btc-status-network", "{network.as_str()}" }
            if let Some(t) = &tip {
                if let Some(height) = t.tip_height {
                    span { class: "btc-status-sep", "·" }
                    span { class: "btc-status-text", "Tip height {height}" }
                }
                if let Some(bt) = t.last_block_time {
                    span { class: "btc-status-sep", "·" }
                    span { class: "btc-status-text", "Last block {relative_time_ago(bt)}" }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// First-run panel
// ---------------------------------------------------------------------------

#[component]
fn FirstRunPanel(
    bridge_loaded: bool,
    bridge: Option<BridgeEndpoint>,
    network: BitcoinNetwork,
    tip: Option<TipView>,
    has_ghostkey: bool,
) -> Element {
    rsx! {
        div { class: "card",
            h3 { "Live on {network.as_str()}" }
            match &tip {
                Some(t) if !t.recent_blocks.is_empty() => rsx! {
                    RecentBlocksList { blocks: t.recent_blocks.clone() }
                },
                _ => rsx! {
                    p { class: "text-muted text-italic",
                        "No chain data yet. "
                        if !bridge_loaded {
                            "Connecting…"
                        } else if bridge.is_none() {
                            "This build has no Bitcoin bridge configured for {network.as_str()} yet."
                        } else {
                            "Waiting for the bridge to report the chain tip…"
                        }
                    }
                },
            }

            div { class: "info-box", style: "margin-top: 16px;",
                p {
                    "A curated demo address isn't configured for this build yet -- once a bridge is live, "
                    "this is where you'd see a public address's activity update in real time with no "
                    "credential at all."
                }
            }
        }

        WatchForm { network, has_ghostkey }
    }
}

#[component]
fn RecentBlocksList(blocks: Vec<crate::state::BlockRow>) -> Element {
    rsx! {
        div { class: "btc-block-list",
            for block in blocks {
                div { class: "btc-block-row", key: "{block.height}",
                    span { class: "btc-block-height", "#{block.height}" }
                    span { class: "btc-block-txcount", "{block.tx_count} tx" }
                    span { class: "btc-block-time text-muted", "{relative_time_ago(block.block_time)}" }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Orders (payments-first)
// ---------------------------------------------------------------------------

#[component]
fn OrdersSection(orders: Vec<AuthorizedOrder>, app_state_snapshot: BitcoinState) -> Element {
    let awaiting: Vec<&AuthorizedOrder> = orders
        .iter()
        .filter(|o| o.status == OrderStatus::AwaitingPayment)
        .collect();
    let paid: Vec<&AuthorizedOrder> = orders
        .iter()
        .filter(|o| o.status == OrderStatus::Paid)
        .collect();
    let other: Vec<&AuthorizedOrder> = orders
        .iter()
        .filter(|o| {
            matches!(
                o.status,
                OrderStatus::Cancelled | OrderStatus::PaymentReversed
            )
        })
        .collect();

    rsx! {
        div {
            h3 { "Your orders" }
            if !awaiting.is_empty() {
                p { class: "section-count", "Awaiting payment" }
                for order in &awaiting {
                    OrderCard {
                        key: "{order.order.id}",
                        order: (*order).clone(),
                        live: live_address_for_order(&app_state_snapshot, &order.order),
                    }
                }
            }
            if !paid.is_empty() {
                p { class: "section-count", "Paid" }
                for order in &paid {
                    OrderCard {
                        key: "{order.order.id}",
                        order: (*order).clone(),
                        live: live_address_for_order(&app_state_snapshot, &order.order),
                    }
                }
            }
            if !other.is_empty() {
                p { class: "section-count", "Other" }
                for order in &other {
                    OrderCard {
                        key: "{order.order.id}",
                        order: (*order).clone(),
                        live: live_address_for_order(&app_state_snapshot, &order.order),
                    }
                }
            }
        }
    }
}

/// If we happen to be watching this order's payment address, its live claim
/// data -- lets an `AwaitingPayment` order show "payment seen, unconfirmed"
/// the moment it hits the mempool, well before the store contract's own
/// `Paid` transition (which needs a fully-formed, sufficiently-confirmed
/// proof) lands.
pub(crate) fn live_address_for_order(
    bitcoin: &BitcoinState,
    order: &harvest_common::payment::Order,
) -> Option<AddressView> {
    // The order's OWN terms first. `Order::bitcoin_address_instance_id`
    // derives the address contract from the code hash and payment parameters
    // the seller signed, so what is displayed is the address the order
    // actually names.
    //
    // This used to go only through the watch list, and that had two problems.
    // A buyer holds no watch -- the buy flow creates none -- so a purchase
    // card read "Awaiting payment" however much had already arrived at the
    // address, which is exactly the evidence a person needs to sanity-check
    // the blockers that stop them paying the wrong order. And the watch route
    // matches on `(network, script_pubkey)` and then trusts the `contract_id`
    // STRING the watch carries: an identity from a different source than the
    // terms being displayed, so where the two disagree a buyer was shown some
    // other address's balance under this order.
    if let Some(view) = order
        .bitcoin_address_instance_id()
        .and_then(|id| bitcoin.addresses.get(id.as_slice()))
    {
        return Some(view.clone());
    }

    // Fall back to the watch list for an order that names no contract build.
    // `bitcoin_address_code_hash` is optional and absent on every order
    // issued before it existed, and a seller watching their own address by
    // hand is what the watch list is for.
    let watch = bitcoin
        .watches
        .iter()
        .find(|w| w.network == order.network && w.script_pubkey == order.payment_script_pubkey)?;
    let contract_id_bs58 = watch.contract_id.as_deref()?;
    let bytes = bs58::decode(contract_id_bs58).into_vec().ok()?;
    bitcoin.addresses.get(&bytes).cloned()
}

/// The bridges named by this invoice that this build does not recognise.
///
/// # Why a buyer has to look at this, per invoice
///
/// The trusted-bridge set used to be a store *parameter*, hashed into the
/// store's contract address. That was fatal in one direction (frozen for the
/// store's life, so a store created with no bridge could never take a payment)
/// but convenient in another: checking the store's address once told you the
/// bridges for every order it would ever issue.
///
/// It is now per-order, under the seller's signature. That is what makes
/// rotation possible, and it moves one check onto the buyer: two invoices from
/// the same store may name different observers, so the bridge set has to be
/// read per invoice rather than once per store. This function is that check,
/// and `OrderCard` surfaces its answer — an invoice whose "Paid" verdict would
/// rest on a signature from a stranger says so on its face, before the buyer
/// sends any coin.
///
/// `bitcoin_config::TRUSTED_BRIDGE_ID_BS58` is the compiled-in trust policy:
/// whose signature on a Bitcoin fact this build believes.
pub(crate) fn unrecognised_bridges(order: &harvest_common::payment::Order) -> Vec<String> {
    order
        .trusted_bridges
        .iter()
        .map(|b| b.to_bs58())
        .filter(|id| id != bitcoin_config::TRUSTED_BRIDGE_ID_BS58 && !recognised_for_test(id))
        .collect()
}

#[cfg(test)]
thread_local! {
    /// Bridges a test recognises on its own thread, in addition to the
    /// build's. A test cannot sign a claim as the build's bridge (nobody
    /// here has its key), so a test of a rule that needs a RECOGNISED bridge
    /// to have signed the evidence recognises the one its fixture signs
    /// with, for as long as it holds the [`RecognisedForTest`] guard.
    static RECOGNISED_FOR_TEST: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// A bridge recognised for a test, until this is dropped (review round 3,
/// testing lens: without a reset, a thread the harness reuses would carry one
/// test's recognition into the next). Held by the test, or by the
/// `AppState` a fixture built (`AppState::test_guards`).
#[cfg(test)]
#[must_use = "the bridge is recognised only while the guard is held"]
#[derive(Debug)]
pub(crate) struct RecognisedForTest(String);

#[cfg(test)]
impl Drop for RecognisedForTest {
    fn drop(&mut self) {
        RECOGNISED_FOR_TEST.with(|ids| {
            let mut ids = ids.borrow_mut();
            if let Some(at) = ids.iter().position(|held| *held == self.0) {
                ids.remove(at);
            }
        });
    }
}

/// Treat bridge `id` as recognised on this thread while the guard lives.
#[cfg(test)]
pub(crate) fn recognise_for_test(id: freenet_bitcoin_common::BridgeId) -> RecognisedForTest {
    let id = id.to_bs58();
    RECOGNISED_FOR_TEST.with(|ids| ids.borrow_mut().push(id.clone()));
    RecognisedForTest(id)
}

#[cfg(test)]
fn recognised_for_test(id: &str) -> bool {
    RECOGNISED_FOR_TEST.with(|ids| ids.borrow().iter().any(|held| held == id))
}

/// Whether any bridge is recognised for a test on this thread.
#[cfg(test)]
pub(crate) fn any_recognised_for_test() -> bool {
    RECOGNISED_FOR_TEST.with(|ids| !ids.borrow().is_empty())
}

#[cfg(not(test))]
fn recognised_for_test(_id: &str) -> bool {
    false
}

/// Short, quotable form of a bridge id, for a line that has to fit on a card.
pub(crate) fn short_bridge(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Whether the address an invoice DISPLAYS is the script that would SETTLE it.
///
/// # Why a card has to check this
///
/// An `Order` carries both forms, and the seller's signature covers both --
/// so a signature proves the seller wrote them, not that they agree. Every
/// verification path uses `payment_script_pubkey`
/// (`harvest_common::payment::verify_payment_proof`); the human reads
/// `payment_address`. Nothing else in the system compares them.
///
/// That was tolerable while orders appeared only in the user's own payments
/// panel, where both fields came from their own delegate. It is not now: a
/// store's invoices render to any buyer who opens the link, so a seller could
/// publish an invoice displaying an address they control while the script that
/// settles it is unrelated. The buyer pays, the coin arrives where they were
/// told to send it, the order never reaches `Paid`, and the public record says
/// the buyer never paid.
///
/// `None` means the address could not be parsed at all -- unreadable rather
/// than proven wrong, which the card reports differently.
fn address_matches_script(order: &harvest_common::payment::Order) -> Option<bool> {
    bitcoin_address::address_to_script_pubkey(&order.payment_address, order.network)
        .ok()
        .map(|script| script == order.payment_script_pubkey)
}

/// Order builders for the destination-check test. Not `#[cfg(test)]` on the
/// module itself, because the test lives in a sibling module and needs to see
/// it.
#[cfg(test)]
pub(super) mod __address_check_test_support {
    use harvest_common::listing::ListingId;
    use harvest_common::payment::{Order, OrderId};

    pub fn order_paying(address: &str, script_pubkey: Vec<u8>) -> Order {
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: "buyer".to_string(),
            seller_fingerprint: "seller".to_string(),
            amount_sats: 50_000,
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            payment_script_pubkey: script_pubkey,
            payment_address: address.to_string(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: None,
            created_at,
        }
        .with_derived_id()
    }
}

/// What an invoice's card has to say about its own payment destination.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DestinationNote {
    /// The address denotes exactly the script that settles this order.
    Agrees,
    /// The address is well-formed and denotes a DIFFERENT script.
    Contradicts,
    /// The address cannot be parsed for this network, so nothing can be said
    /// about it -- which is itself a reason not to pay it.
    Unreadable,
}

impl DestinationNote {
    pub(crate) fn of(order: &harvest_common::payment::Order) -> Self {
        match address_matches_script(order) {
            Some(true) => DestinationNote::Agrees,
            Some(false) => DestinationNote::Contradicts,
            None => DestinationNote::Unreadable,
        }
    }

    /// Whether the address is safe to put in front of somebody to pay.
    fn payable(self) -> bool {
        self == DestinationNote::Agrees
    }
}

/// One invoice, as both the seller's payments panel and a buyer looking at
/// the store see it. Shared rather than duplicated: the bridge warning below
/// is the check a buyer has to make before parting with coin, and a second
/// copy of this card is how one of them ends up without it.
#[component]
pub(crate) fn OrderCard(order: AuthorizedOrder, live: Option<AddressView>) -> Element {
    let o = &order.order;
    let destination = DestinationNote::of(o);
    let unrecognised = unrecognised_bridges(o);
    let bridge_note = if o.trusted_bridges.is_empty() {
        BridgeNote::None
    } else if unrecognised.is_empty() {
        BridgeNote::Recognised(
            o.trusted_bridges
                .iter()
                .map(|b| short_bridge(&b.to_bs58()))
                .collect::<Vec<_>>()
                .join(", "),
        )
    } else {
        BridgeNote::Unrecognised(
            unrecognised
                .iter()
                .map(|id| short_bridge(id))
                .collect::<Vec<_>>()
                .join(", "),
        )
    };
    let reading = AddressReading::of(o, live.as_ref());
    // All of this is about the seller's own orders; see
    // `AppState::settlement_hold` and `refresh_same_address_orders`.
    let (hold, late_is_another_orders, paid_maybe_twins, tip_height) = {
        let state = APP_STATE.read();
        let tip_height = state
            .bitcoin
            .tips
            .get(&o.network)
            .and_then(|tip| tip.tip_height);
        let hold = state
            .withheld_settlements
            .contains_key(&o.id)
            .then(|| state.settlement_hold(o))
            .flatten();
        let late = reading
            .after_window
            .is_some_and(|height| !state.orders_whose_window_holds(&o.id, &[height]).is_empty());
        // Only when it is actually possible: the payment this order was
        // settled on confirmed inside another own order's window too.
        let paid_maybe_twins: String = if order.status == OrderStatus::Paid {
            state
                .orders_whose_window_holds(&o.id, &reading.in_window_heights)
                .iter()
                .map(|id| id.short())
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            String::new()
        };
        (hold, late, paid_maybe_twins, tip_height)
    };
    // Where the order stands after the payment question (harvest#53):
    // reader-side windows against this reader's own tip.
    let (sight, despatch) = {
        let state = APP_STATE.read();
        (state.payment_sight(&order), state.despatch_of(&order))
    };
    let stage = crate::fulfilment::order_stage(&order, despatch.as_ref(), tip_height, sight);
    let stage_note = stage
        .describe(tip_height, order.status)
        .or_else(|| crate::fulfilment::closed_window_note(&order, tip_height, sight));
    let offers_address = crate::fulfilment::offers_payment_address(&order, tip_height);
    let (status_class, status_text) = card_pill(order.status, &reading, hold.is_some(), stage);
    let order_id = o.id.clone();

    rsx! {
        div { class: "listing-card",
            div { class: "listing-header",
                span { class: "listing-price", "{format_sats(o.amount_sats)}" }
                span { class: "{status_class}", "{status_text}" }
            }
            p { class: "text-muted", "Order {o.id.short()} · {o.network.as_str()}" }
            if let Some(note) = stage_note {
                p { class: if stage.needs_attention() { "text-warning" } else { "" }, "{note}" }
            }
            if order.status == OrderStatus::AwaitingPayment {
                if let Some(note) = reading.outside_note(late_is_another_orders) {
                    p { class: "text-warning", "{note}" }
                }
            }
            if let Some(hold) = hold {
                p { class: "text-warning",
                    "{hold.explain(o.amount_sats, reading.in_window_sats)}"
                }
                button {
                    class: "btn btn-sm btn-primary",
                    onclick: move |_| {
                        APP_STATE.write().confirm_paid(&order_id);
                    },
                    "Confirm paid"
                }
            }
            if !paid_maybe_twins.is_empty() {
                p { class: "text-warning",
                    "Your invoice {paid_maybe_twins} uses this same address, and \
                     the payment that settled this one also falls inside its window. One \
                     payment cannot pay for both invoices: check your wallet for a separate \
                     payment per invoice before shipping both."
                }
            }
            // The address is only offered when it is the script that settles
            // this order. Showing one that is not would be handing somebody a
            // destination whose payment the order can never recognise -- see
            // `address_matches_script`.
            if !offers_address {
                // Nothing to pay: the stage note above says why. The address
                // of a cancelled, lapsed or settled order is not offered, so
                // nobody sends coin the order will not recognise or does not
                // need (harvest#53).
            } else if destination.payable() {
                // A readonly input rather than a paragraph, so the address can
                // be selected and copied without hand-transcribing 42
                // characters -- the same thing the store share link does, and
                // for the same reason. A clipboard button is not the
                // alternative it looks like: the app runs in the gateway's
                // sandboxed iframe, where the clipboard API is not reliably
                // available, and a copy button that silently does nothing is
                // worse than a field that visibly works.
                // A textarea rather than an input, so the whole address is
                // visible at once. In an input, 42-62 characters of bech32
                // scroll sideways at this width: a buyer cannot check the
                // destination they are paying, and a partial selection pastes
                // a truncated address, which sends coin nowhere an order can
                // recognise. That is the failure this panel exists to avoid.
                textarea {
                    class: "copy-field",
                    readonly: true,
                    spellcheck: false,
                    rows: 2,
                    aria_label: "Payment address, select to copy",
                    // `value`, not a text child: a text child is the initial
                    // content, and this card re-renders with a different
                    // address when another invoice is issued.
                    value: "{o.payment_address}",
                }
            } else {
                p { class: "text-warning",
                    match destination {
                        DestinationNote::Contradicts => "This invoice's payment address is not \
                             the destination that would settle it. Paying the address shown \
                             would send coin somewhere this order cannot recognise, so it is \
                             withheld. Ask the seller to reissue the invoice.",
                        _ => "This invoice's payment address cannot be read for its network, so \
                             it cannot be checked against the destination that would settle the \
                             order. It is withheld rather than shown. Ask the seller to reissue \
                             the invoice.",
                    }
                }
            }
            match bridge_note {
                BridgeNote::None => rsx! {
                    p { class: "text-warning",
                        "This invoice names no Bitcoin bridge, so no payment to it can ever \
                         be proven. Ask the seller to reissue it."
                    }
                },
                BridgeNote::Unrecognised(ids) => rsx! {
                    p { class: "text-warning",
                        "This invoice will be settled by a bridge this app does not \
                         recognise ({ids}). Its payment status would rest on a signature \
                         you have no reason to trust — check with the seller before paying."
                    }
                },
                BridgeNote::Recognised(ids) => rsx! {
                    p { class: "text-muted", "Settled by bridge {ids}" }
                },
            }
        }
    }
}

/// The pill an order card shows, once the order's stage is known: a lapsed
/// invoice's pill says so, rather than "Awaiting payment" above a line saying
/// it can no longer be paid (harvest#53 review).
pub(crate) fn card_pill(
    status: OrderStatus,
    reading: &AddressReading,
    awaiting_confirmation: bool,
    stage: crate::fulfilment::OrderStage,
) -> (&'static str, &'static str) {
    match stage {
        crate::fulfilment::OrderStage::Lapsed { .. } => ("btc-pill cancelled", "Lapsed"),
        _ => status_pill(status, reading, awaiting_confirmation),
    }
}

/// The pill an order card shows: class and text.
///
/// Split out of the component so the reading it depends on is testable; see
/// [`AddressReading`] for why it is not the raw address balance.
///
/// Not the paid style while a provable payment is waiting on the seller's
/// confirmation (`AppState::settlement_hold`): it may be another invoice's.
pub(crate) fn status_pill(
    status: OrderStatus,
    reading: &AddressReading,
    awaiting_confirmation: bool,
) -> (&'static str, &'static str) {
    match status {
        OrderStatus::AwaitingPayment if awaiting_confirmation => {
            ("btc-pill pending", "Payment seen, confirm to mark paid")
        }
        OrderStatus::AwaitingPayment => {
            // The paid style only for the full amount: anyone can send dust
            // to a published address (PR #83 round 2, Should Fix 5).
            if reading.in_window_sats > 0 && reading.in_window_sats >= reading.amount_sats {
                ("btc-pill paid", "Payment seen on chain")
            } else if reading.in_window_sats > 0 {
                ("btc-pill pending", "Partial payment seen")
            } else if reading.pending_sats > 0 {
                ("btc-pill pending", "Payment seen, unconfirmed")
            } else {
                ("btc-pill waiting", "Awaiting payment")
            }
        }
        OrderStatus::Paid => ("btc-pill paid", "Paid"),
        OrderStatus::PaymentReversed => ("btc-pill reversed", "Payment reversed"),
        OrderStatus::Cancelled => ("btc-pill cancelled", "Cancelled"),
    }
}

/// What an order's address shows, read against THAT ORDER's payment window.
///
/// # Why the card cannot just read the address balance
///
/// A balance is per script, and a script can carry more than one order's
/// money when an address has been issued twice (harvest#77). The card used to
/// light up "Payment seen on chain" for any confirmed balance at all, so a
/// seller looking at a reissued address saw a new invoice as paid by the old
/// invoice's payment, and the harm #77 is about (goods shipped for money that
/// paid for something else) survived through the pill even though the store
/// contract refused to settle the order (PR #83 review, Must Fix 2).
///
/// So confirmed value is split by [`Order::payment_window`], the same window
/// the verifier applies, using each transaction's current (winning)
/// confirmation height -- the same one the verifier judges. What falls
/// outside the window is reported separately, which is also how the seller
/// learns WHY a funded address does not settle the order (Should Fix 6):
/// `settled_orders` cannot say, because it only ever publishes successes.
///
/// [`Order::payment_window`]: harvest_common::payment::Order::payment_window
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct AddressReading {
    /// What the order asks for, so the pill can tell a payment from dust.
    pub amount_sats: u64,
    /// The order names no anchor block, so nothing can settle it.
    pub no_anchor: bool,
    /// Confirmed value inside the order's window: what can settle it.
    pub in_window_sats: u64,
    /// The confirmation heights of that value.
    pub in_window_heights: Vec<u32>,
    /// Unconfirmed value. Not window-checked, because an unconfirmed
    /// transaction has no height yet; the pill says only "unconfirmed".
    pub pending_sats: u64,
    /// Value in mempool rows only. Unlike `pending_sats`, never overlaps
    /// `in_window_sats`; see [`Self::sight`].
    pub unconfirmed_sats: u64,
    /// Highest confirmation height of value that confirmed at or before the
    /// anchor, if any.
    pub before_order: Option<u32>,
    /// Lowest confirmation height of value that confirmed after the window
    /// closed, if any.
    pub after_window: Option<u32>,
}

impl AddressReading {
    pub(crate) fn of(order: &harvest_common::payment::Order, live: Option<&AddressView>) -> Self {
        let window = order.payment_window();
        let base = Self {
            amount_sats: order.amount_sats,
            no_anchor: window.is_none(),
            ..Self::default()
        };
        let Some(live) = live else {
            return base;
        };
        let mut reading = Self {
            pending_sats: live.pending_sats,
            ..base
        };
        // No anchor: nothing can settle this order (the verifier refuses it),
        // so no confirmed value is counted as its payment.
        for tx in &live.txs {
            let TxRowStatus::Confirmed { anchor_height } = tx.status else {
                if tx.status == TxRowStatus::Unconfirmed {
                    reading.unconfirmed_sats =
                        reading.unconfirmed_sats.saturating_add(tx.value_sats);
                }
                continue;
            };
            match &window {
                Some(w) if w.contains(&anchor_height) => {
                    reading.in_window_heights.push(anchor_height);
                    reading.in_window_sats = reading.in_window_sats.saturating_add(tx.value_sats);
                }
                Some(w) if anchor_height > *w.end() => {
                    reading.after_window = Some(
                        reading
                            .after_window
                            .map_or(anchor_height, |h| h.min(anchor_height)),
                    );
                }
                None => {}
                Some(_) => {
                    reading.before_order = Some(
                        reading
                            .before_order
                            .map_or(anchor_height, |h| h.max(anchor_height)),
                    );
                }
            }
        }
        reading
    }

    /// What this reading shows that would settle `order`: the full amount
    /// confirmed inside its window, or unconfirmed value making up the
    /// amount while the window is still open for it to confirm in. Partial
    /// value and dust are nothing here -- see
    /// [`crate::fulfilment::PaymentSight`].
    ///
    /// Unconfirmed value is not window-checked (an unconfirmed transaction
    /// has no height), which is why it only counts while a payment sent now
    /// could still confirm in the window.
    pub(crate) fn sight(
        &self,
        order: &harvest_common::payment::Order,
        tip_height: Option<u32>,
    ) -> crate::fulfilment::PaymentSight {
        let covered = self.in_window_sats > 0 && self.in_window_sats >= self.amount_sats;
        // Mempool rows only, NOT `pending_sats`: that figure also counts a
        // confirmed output this reader's tip has not yet reached, which is
        // already in `in_window_sats`, so adding the two counted one payment
        // twice (review round 3).
        let in_flight = order.payment_window().is_some()
            && crate::fulfilment::accepts_new_payment(order, tip_height)
            && self.unconfirmed_sats > 0
            && self.in_window_sats.saturating_add(self.unconfirmed_sats) >= self.amount_sats;
        crate::fulfilment::PaymentSight {
            covered,
            in_flight,
            ambiguous: false,
        }
    }

    /// What to tell the seller when the address holds confirmed value that is
    /// not this order's payment.
    /// `late_is_another_orders`: a payment after this invoice's window falls
    /// inside another of the seller's invoices' windows on this address, so
    /// it is not presumed to be this buyer's late payment.
    pub(crate) fn outside_note(&self, late_is_another_orders: bool) -> Option<String> {
        if self.no_anchor {
            return Some(
                "This invoice names no Bitcoin block it was made at, so no payment can ever \
                 settle it. Issue a new invoice."
                    .to_string(),
            );
        }
        let paid_in_window = self.in_window_sats > 0 && self.in_window_sats >= self.amount_sats;
        if let Some(height) = self.before_order {
            return Some(if paid_in_window {
                // A valid payment is also here: no reason to reissue.
                format!(
                    "This address also holds an older payment, confirmed in block {height} \
                     before this invoice was made. That one paid for something else; only the \
                     payment made after this invoice counts for it."
                )
            } else {
                format!(
                    "This address already holds a payment that confirmed in block {height}, \
                     before this invoice was made. It paid for something else and does not \
                     settle this invoice, so do not ship against it. Issue a new invoice, \
                     which gets a new address."
                )
            });
        }
        self.after_window.map(|height| {
            let whose = if late_is_another_orders {
                "It falls inside another of your invoices' windows on this address, so it may \
                 be that invoice's payment."
            } else {
                "It is probably this buyer's late payment: check your wallet and settle it \
                 with them directly."
            };
            format!(
                "A payment to this address confirmed in block {height}, after this invoice's \
                 payment window closed, so Harvest will not mark it paid. {whose}"
            )
        })
    }
}

/// What `OrderCard` has to say about an invoice's bridge set.
enum BridgeNote {
    /// No bridge named: the invoice can never be proven paid.
    None,
    /// Every named bridge is one this build trusts.
    Recognised(String),
    /// At least one named bridge is a stranger.
    Unrecognised(String),
}

#[cfg(test)]
mod payable_tests {
    use super::*;

    fn order(status: OrderStatus, seed: u8) -> AuthorizedOrder {
        let ts = chrono::DateTime::from_timestamp(1_700_000_000 + seed as i64, 0).unwrap();
        let order = harvest_common::payment::Order {
            id: harvest_common::payment::OrderId([0u8; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "me".into(),
            amount_sats: 1,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, seed],
            payment_address: "tb1qtest".into(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: None,
            created_at: ts,
        }
        .with_derived_id();
        AuthorizedOrder {
            order,
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// Must Fix 2: an order awaiting payment at a closed or unbacked store is
    /// not listed under "Your orders", where its card would show the address;
    /// a settled one still is. Mutated red by dropping the `payable` filter.
    #[test]
    fn an_awaiting_order_at_a_store_not_to_be_paid_is_not_listed() {
        let mut state = crate::state::AppState::default();
        state.ghostkeys.push(ghostkey_common::GhostKeyInfo {
            fingerprint: "me".into(),
            label: None,
            notary_info: String::new(),
            verifying_key_bytes: None,
            backed_up: false,
        });
        let awaiting = order(OrderStatus::AwaitingPayment, 1);
        let cancelled = order(OrderStatus::Cancelled, 2);
        state.my_stores.insert(
            "me".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: vec![1; 32],
                reputation_contract_id: vec![2; 32],
                mailbox_contract_id: vec![3; 32],
                store_contract_key: None,
                store_verifying_key: None,
            }],
        );
        let store = state.browsing_stores.entry(vec![1; 32]).or_default();
        store.orders = vec![awaiting.clone(), cancelled.clone()];
        store.store_verifying_key = Some([7; 32]);
        assert_eq!(my_orders(&state).len(), 2, "a payable store lists both");

        for make_unpayable in [
            |s: &mut crate::state::BrowsingStore| s.closed = true,
            |s: &mut crate::state::BrowsingStore| s.store_verifying_key = None,
        ] {
            let mut state = state.clone();
            make_unpayable(state.browsing_stores.get_mut(&vec![1u8; 32]).unwrap());
            let shown = my_orders(&state);
            assert_eq!(shown.len(), 1);
            assert_eq!(shown[0].status, OrderStatus::Cancelled);
        }
    }
}

#[cfg(test)]
mod bridge_check_tests {
    use freenet_bitcoin_common::BridgeId;
    use harvest_common::listing::ListingId;
    use harvest_common::payment::{Order, OrderId};

    use super::{bitcoin_config, unrecognised_bridges};

    fn order_trusting(bridges: Vec<BridgeId>) -> Order {
        let ts = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: "buyer".into(),
            seller_fingerprint: "seller".into(),
            amount_sats: 50_000,
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa, 0xbb],
            payment_address: "tb1qtest".into(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: bridges,
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: None,
            created_at: ts,
        }
        .with_derived_id()
    }

    fn known_bridge() -> BridgeId {
        let bytes = bs58::decode(bitcoin_config::TRUSTED_BRIDGE_ID_BS58)
            .into_vec()
            .expect("the compiled-in bridge id must be valid base58");
        let mut a = [0u8; 32];
        a.copy_from_slice(&bytes);
        BridgeId(a)
    }

    /// The buyer's side of the same coin as the bridge check: an `Order`
    /// carries the address a human reads AND the script that settles it, the
    /// seller's signature covers both, and nothing else in the system compares
    /// them. A store's invoices now render to any buyer who opens the link, so
    /// a seller could display an address they control while the settling
    /// script is unrelated -- the buyer pays where they were told, and the
    /// public record says they never paid.
    #[test]
    fn an_address_that_is_not_the_settling_script_is_not_offered() {
        use super::{DestinationNote, __address_check_test_support::order_paying};

        let honest = order_paying(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            crate::gateway::bitcoin_address::address_to_script_pubkey(
                "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
                freenet_bitcoin_common::BitcoinNetwork::Signet,
            )
            .expect("a valid signet address"),
        );
        assert_eq!(DestinationNote::of(&honest), DestinationNote::Agrees);
        assert!(DestinationNote::of(&honest).payable());

        // Same displayed address, a script that pays somewhere else.
        let lying = order_paying(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            vec![0x00, 0x14, 0xde, 0xad, 0xbe, 0xef],
        );
        assert_eq!(DestinationNote::of(&lying), DestinationNote::Contradicts);
        assert!(
            !DestinationNote::of(&lying).payable(),
            "an address that is not the settling script must not be offered to pay"
        );

        // An address that cannot be read at all says so separately: unchecked
        // is not the same claim as proven wrong, and neither is payable.
        let unreadable = order_paying("not-an-address", vec![0x00, 0x14, 0xaa]);
        assert_eq!(
            DestinationNote::of(&unreadable),
            DestinationNote::Unreadable
        );
        assert!(!DestinationNote::of(&unreadable).payable());
    }

    #[test]
    fn a_bridge_this_build_trusts_raises_nothing() {
        assert!(unrecognised_bridges(&order_trusting(vec![known_bridge()])).is_empty());
    }

    /// The regression this whole check exists for. Moving the bridge set into
    /// the order made rotation possible and made a buyer's one-time check of
    /// the store address insufficient: a second invoice from the same store
    /// may name an observer the buyer has never heard of. If that goes
    /// unflagged, the buyer pays against a "Paid" verdict resting on a
    /// stranger's signature.
    #[test]
    fn a_bridge_this_build_has_never_heard_of_is_flagged() {
        let stranger = BridgeId([7u8; 32]);
        let flagged = unrecognised_bridges(&order_trusting(vec![stranger]));
        assert_eq!(flagged, vec![stranger.to_bs58()]);
    }

    /// A known bridge alongside a stranger must still flag the stranger --
    /// mixing one trusted observer in does not launder the other.
    #[test]
    fn a_stranger_mixed_in_with_a_known_bridge_is_still_flagged() {
        let stranger = BridgeId([7u8; 32]);
        let flagged = unrecognised_bridges(&order_trusting(vec![known_bridge(), stranger]));
        assert_eq!(flagged, vec![stranger.to_bs58()]);
    }
}

// ---------------------------------------------------------------------------
// Watch list (secondary)
// ---------------------------------------------------------------------------

#[component]
fn WatchListSection(
    watches: Vec<WatchedPayment>,
    network: BitcoinNetwork,
    has_ghostkey: bool,
) -> Element {
    // Manual watches only -- ones tied to an order are already visible above
    // and would otherwise be shown twice.
    let manual: Vec<&WatchedPayment> = watches.iter().filter(|w| w.order_id.is_none()).collect();

    rsx! {
        div { style: "margin-top: 24px;",
            h3 { "Watched addresses" }
            if manual.is_empty() {
                p { class: "text-muted text-italic", "Not watching any addresses yet." }
            } else {
                for watch in &manual {
                    WatchRow { key: "{watch.key()}", watch: (*watch).clone() }
                }
            }
            WatchForm { network, has_ghostkey }
        }
    }
}

#[component]
fn WatchRow(watch: WatchedPayment) -> Element {
    let app_state = APP_STATE.read();
    let live = watch
        .contract_id
        .as_deref()
        .and_then(|id| bs58::decode(id).into_vec().ok())
        .and_then(|bytes| app_state.bitcoin.addresses.get(&bytes).cloned());
    drop(app_state);

    let mut unwatching = use_signal(|| false);
    let network = watch.network;
    let script_pubkey = watch.script_pubkey.clone();

    rsx! {
        div { class: "identity-card",
            div {
                p { class: "identity-name",
                    if let Some(label) = &watch.label { "{label}" } else { "{watch.address}" }
                }
                p { class: "seller-id", "{watch.address}" }
                // What this row can honestly say about the watch. Not
                // "Waiting for bridge to sync…", which described a wait that
                // never ends -- see `state::WatchSyncStatus`.
                if let Some(message) = watch_sync_status(&watch).message() {
                    p { class: "text-warning", "{message}" }
                }
                if let Some(l) = &live {
                    p { class: "text-muted",
                        if l.confirmed_sats > 0 { "{format_sats(l.confirmed_sats)} confirmed" }
                        if l.pending_sats > 0 { " · {format_sats(l.pending_sats)} pending" }
                        if l.confirmed_sats == 0 && l.pending_sats == 0 { "No activity yet" }
                    }
                    for tx in l.txs.iter().take(5) {
                        TxRowView { key: "{tx.txid_display}", tx: tx.clone() }
                    }
                }
            }
            button {
                class: "btn btn-outline btn-sm",
                disabled: *unwatching.read(),
                onclick: move |_| {
                    unwatching.set(true);
                    let network = network;
                    let script_pubkey = script_pubkey.clone();
                    spawn(async move {
                        if let Err(e) = bitcoin_ops::unwatch(network, script_pubkey).await {
                            APP_STATE
                                .write()
                                .notifications
                                .push(format!("Couldn't stop watching: {e}"));
                        }
                        unwatching.set(false);
                    });
                },
                if *unwatching.read() { "Stopping…" } else { "Unwatch" }
            }
        }
    }
}

#[component]
fn TxRowView(tx: crate::state::TxRow) -> Element {
    let status_text = match tx.status {
        TxRowStatus::Unconfirmed => "unconfirmed".to_string(),
        TxRowStatus::Confirmed { .. } => "confirmed".to_string(),
        TxRowStatus::Retracted => "reversed".to_string(),
    };
    rsx! {
        p { class: "btc-tx-row text-muted",
            span { class: "btc-tx-id", "{tx.txid_display}" }
            span { class: "btc-tx-amount", "{format_sats(tx.value_sats)}" }
            span { class: "btc-tx-status", "{status_text}" }
        }
    }
}

// ---------------------------------------------------------------------------
// Watch form + Ghost Key gate
// ---------------------------------------------------------------------------

#[component]
fn WatchForm(network: BitcoinNetwork, has_ghostkey: bool) -> Element {
    let mut address = use_signal(String::new);
    let mut label = use_signal(String::new);
    let mut error = use_signal(|| Option::<String>::None);
    let mut show_gate = use_signal(|| false);
    let mut submitting = use_signal(|| false);

    rsx! {
        div { class: "card",
            h4 { "Watch a Bitcoin address" }
            // Said before the click, not after it. A manual watch is recorded
            // privately and that is all it is: only invoice addresses are sent
            // to a bridge, so no transactions follow. See
            // `state::WatchSyncStatus`.
            p { class: "text-muted",
                "This records the address privately on this device. Harvest asks a bridge "
                "to watch invoice addresses only, so no transactions will appear for an "
                "address added here."
            }
            div { class: "form-group",
                input {
                    class: "form-input",
                    placeholder: "Bitcoin address",
                    value: "{address}",
                    oninput: move |e| {
                        address.set(e.value());
                        error.set(None);
                    },
                }
            }
            div { class: "form-group",
                input {
                    class: "form-input",
                    placeholder: "Label (optional, never leaves this device)",
                    value: "{label}",
                    oninput: move |e| label.set(e.value()),
                }
            }
            if let Some(e) = error.read().clone() {
                p { class: "text-warning", "{e}" }
            }
            if *show_gate.read() {
                GhostKeyGate { on_dismiss: move |_| show_gate.set(false) }
            } else {
                button {
                    class: "btn btn-primary",
                    disabled: *submitting.read() || address.read().trim().is_empty(),
                    onclick: move |_| {
                        if !has_ghostkey {
                            show_gate.set(true);
                            return;
                        }
                        let raw_address = address.read().clone();
                        match bitcoin_address::address_to_script_pubkey(&raw_address, network) {
                            Ok(script_pubkey) => {
                                error.set(None);
                                submitting.set(true);
                                let label_value = {
                                    let l = label.read().clone();
                                    (!l.trim().is_empty()).then_some(l)
                                };
                                let watch = WatchedPayment {
                                    network,
                                    script_pubkey,
                                    address: raw_address,
                                    label: label_value,
                                    order_id: None,
                                    expected_amount_sats: None,
                                    contract_id: None,
                                    added_at_ms: now_unix_millis(),
                                    bridge_synced: false,
                                    last_error: None,
                                };
                                address.set(String::new());
                                label.set(String::new());
                                spawn(async move {
                                    if let Err(e) = bitcoin_ops::watch(watch).await {
                                        APP_STATE
                                            .write()
                                            .notifications
                                            .push(format!("Couldn't send watch request: {e}"));
                                    }
                                    submitting.set(false);
                                });
                            }
                            Err(e) => error.set(Some(e)),
                        }
                    },
                    if *submitting.read() { "Watching…" } else { "Watch address" }
                }
            }
        }
    }
}

/// Shown only when the user tries to start a NEW watch and has no Ghost Key
/// connected -- public/demo data above needs no credential at all, this
/// gate is specifically for adding a new watch backed by Freenet.org's
/// bridge.
#[component]
fn GhostKeyGate(on_dismiss: EventHandler<()>) -> Element {
    rsx! {
        div { class: "info-box",
            p {
                "Recording a watch is gated on holding a Ghost Key, which is what a bridge "
                "would check before agreeing to synchronize an address for you. A Ghost Key "
                "just proves you've supported the network -- a bridge learns nothing else "
                "about you. No bridge is asked anything today; see the note above the form."
            }
            div { style: "margin-top: 12px; display: flex; gap: 8px; align-items: center;",
                button {
                    class: "btn btn-primary",
                    onclick: move |_| super::my_store::connect_ghostkey(),
                    "Use Ghost Key"
                }
                a {
                    class: "btn btn-outline",
                    href: "https://freenet.org/ghostkey/create/",
                    target: "_blank",
                    rel: "noopener noreferrer",
                    "Learn more"
                }
                button {
                    class: "btn btn-outline btn-sm",
                    onclick: move |_| on_dismiss.call(()),
                    "Cancel"
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

pub(crate) fn format_sats(sats: u64) -> String {
    format!("{:.8} BTC", sats as f64 / 100_000_000.0)
}

#[cfg(target_arch = "wasm32")]
fn now_unix_millis() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_unix_millis() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn now_unix_seconds() -> i64 {
    (now_unix_millis() / 1000) as i64
}

/// Browser-clock relative time, e.g. "3 minutes ago". `unix_secs` is a
/// Bitcoin block header timestamp -- Bitcoin's clock, never trusted as
/// authoritative on its own, only ever compared against the local clock for
/// display. See `freenet_bitcoin_common::tip_state`'s doc comment on why
/// contracts themselves may never read a host clock; this is the UI doing
/// exactly the comparison that comment says is fine.
fn relative_time_ago(unix_secs: u32) -> String {
    let delta = (now_unix_seconds() - unix_secs as i64).max(0);
    if delta < 60 {
        "just now".to_string()
    } else if delta < 3600 {
        let m = delta / 60;
        format!("{m} minute{} ago", if m == 1 { "" } else { "s" })
    } else if delta < 86_400 {
        let h = delta / 3600;
        format!("{h} hour{} ago", if h == 1 { "" } else { "s" })
    } else {
        let d = delta / 86_400;
        format!("{d} day{} ago", if d == 1 { "" } else { "s" })
    }
}

#[cfg(test)]
mod live_address_tests {
    use super::*;
    use crate::state::{AddressView, BitcoinState};
    use harvest_common::payment::Order;
    use harvest_common::WatchedPayment;

    fn order() -> Order {
        let mut order = __address_check_test_support::order_paying(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            vec![0x00, 0x14, 0xaa],
        );
        // The build's own hash, so the derived instance id is the one the
        // real path would compute.
        order.bitcoin_address_code_hash = Some([42u8; 32]);
        order.with_derived_id()
    }

    /// A watch matching this order's destination, but naming some OTHER
    /// address contract -- the disagreement this lookup used to resolve in
    /// the watch's favour.
    fn a_watch_pointing_at(order: &Order, contract_id: [u8; 32]) -> WatchedPayment {
        WatchedPayment {
            network: order.network,
            script_pubkey: order.payment_script_pubkey.clone(),
            address: order.payment_address.clone(),
            label: None,
            order_id: None,
            expected_amount_sats: None,
            contract_id: Some(bs58::encode(contract_id).into_string()),
            added_at_ms: 0,
            bridge_synced: true,
            last_error: None,
        }
    }

    fn a_view(confirmed_sats: u64) -> AddressView {
        AddressView {
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            claims: Vec::new(),
            scanned_to: Some(800_000),
            confirmed_sats,
            pending_sats: 0,
            txs: Vec::new(),
        }
    }

    /// **A buyer sees the state of the address they are about to pay, with no
    /// watch entry.**
    ///
    /// This is the tell the buy flow had none of. A buyer with no
    /// `WatchedPayment` -- and the buy flow creates none -- saw "Awaiting
    /// payment" whatever had already arrived at the address. That is bad on
    /// its own and worse alongside the one-commitment-many-buyers hole: the
    /// blocker that now stops the second buyer paying is a rule, and this is
    /// the evidence a person can check it against.
    ///
    /// Resolved from the order's OWN signed terms, so what is displayed is
    /// the address the order actually names.
    #[test]
    fn a_buyer_sees_the_address_state_without_holding_a_watch() {
        let order = order();
        let mut bitcoin = BitcoinState::default();
        assert!(
            bitcoin.watches.is_empty(),
            "the point of this test is that there is no watch"
        );
        bitcoin.addresses.insert(
            order
                .bitcoin_address_instance_id()
                .expect("the fixture names a build")
                .to_vec(),
            a_view(50_000),
        );

        assert_eq!(
            live_address_for_order(&bitcoin, &order).map(|v| v.confirmed_sats),
            Some(50_000)
        );
    }

    /// **A watch whose contract id disagrees with the order's terms does not
    /// decide what the buyer is shown.**
    ///
    /// The old lookup matched a watch on `(network, script_pubkey)` and then
    /// trusted the `contract_id` string the watch carried -- an identity from
    /// a different source than the terms being displayed. Where the two
    /// disagree, that showed a buyer some other address's balance under this
    /// order. The order's own parameters are the identity now, and a watch is
    /// only consulted when they yield nothing.
    #[test]
    fn a_watch_pointing_elsewhere_does_not_override_the_orders_own_terms() {
        let order = order();
        let mut bitcoin = BitcoinState::default();
        bitcoin
            .watches
            .push(a_watch_pointing_at(&order, [0x99u8; 32]));
        bitcoin.addresses.insert(vec![0x99u8; 32], a_view(999_999));
        bitcoin.addresses.insert(
            order
                .bitcoin_address_instance_id()
                .expect("the fixture names a build")
                .to_vec(),
            a_view(50_000),
        );

        assert_eq!(
            live_address_for_order(&bitcoin, &order).map(|v| v.confirmed_sats),
            Some(50_000),
            "the order's own terms decide which address is shown"
        );
    }

    /// **An order naming no contract build still resolves through a watch.**
    ///
    /// `bitcoin_address_code_hash` is optional and absent on every order
    /// issued before it existed, and a seller watching their own address by
    /// hand is the case the watch list was built for. Removing that path
    /// would be a regression dressed as a tightening.
    #[test]
    fn an_order_with_no_build_still_resolves_through_a_watch() {
        let mut order = order();
        order.bitcoin_address_code_hash = None;
        let mut bitcoin = BitcoinState::default();
        bitcoin
            .watches
            .push(a_watch_pointing_at(&order, [0x99u8; 32]));
        bitcoin.addresses.insert(vec![0x99u8; 32], a_view(777));

        assert_eq!(
            live_address_for_order(&bitcoin, &order).map(|v| v.confirmed_sats),
            Some(777)
        );
    }
}

#[cfg(test)]
mod address_reading_tests {
    use super::AddressReading;
    use crate::state::{AddressView, TxRow, TxRowStatus};
    use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor, BlockHash};
    use harvest_common::payment::{Order, OrderId, PAYMENT_WINDOW_BLOCKS};

    fn order_anchored_at(height: u32) -> Order {
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller".into(),
            amount_sats: 10_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa],
            payment_address: "tb1qexample".into(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: Some(BlockAnchor {
                height,
                hash: BlockHash([1u8; 32]),
            }),
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("time"),
        }
        .with_derived_id()
    }

    fn address_with(confirmed_at: &[(u32, u64)]) -> AddressView {
        AddressView {
            network: BitcoinNetwork::Signet,
            claims: Vec::new(),
            scanned_to: Some(10_000),
            confirmed_sats: confirmed_at.iter().map(|(_, v)| v).sum(),
            pending_sats: 0,
            txs: confirmed_at
                .iter()
                .map(|&(anchor_height, value_sats)| TxRow {
                    txid_display: format!("tx{anchor_height}"),
                    value_sats,
                    status: TxRowStatus::Confirmed { anchor_height },
                })
                .collect(),
        }
    }

    /// **PR #83 review, Must Fix 2.** The #77 address: an old invoice's
    /// payment confirmed at 100 and a new invoice was issued at 150 on the
    /// same address. The card must not read that balance as this invoice's
    /// payment, and must say why.
    #[test]
    fn a_payment_older_than_the_invoice_does_not_light_the_paid_pill() {
        let order = order_anchored_at(150);
        let reading = AddressReading::of(&order, Some(&address_with(&[(100, 10_000)])));
        assert_eq!(
            reading.in_window_sats, 0,
            "the old payment counted as this invoice's"
        );
        assert_eq!(
            super::status_pill(
                harvest_common::payment::OrderStatus::AwaitingPayment,
                &reading,
                false
            ),
            ("btc-pill waiting", "Awaiting payment"),
            "the card read a payment older than the invoice as this invoice's"
        );
        let note = reading
            .outside_note(false)
            .expect("the seller must be told");
        assert!(note.contains("block 100"), "{note}");
        assert!(note.contains("do not ship"), "{note}");
    }

    /// The window edges match the verifier's: the anchor block is outside,
    /// the next block and the last block of the window are inside, the block
    /// after it is outside.
    #[test]
    fn the_card_applies_the_verifiers_window() {
        let order = order_anchored_at(150);
        let last = 150 + PAYMENT_WINDOW_BLOCKS;
        for (height, counts) in [(150, false), (151, true), (last, true), (last + 1, false)] {
            let reading = AddressReading::of(&order, Some(&address_with(&[(height, 7)])));
            assert_eq!(
                reading.in_window_sats > 0,
                counts,
                "a payment at block {height} for an order anchored at 150"
            );
        }
        let late = AddressReading::of(&order, Some(&address_with(&[(last + 1, 7)])));
        assert!(late
            .outside_note(false)
            .expect("said")
            .contains("window closed"));
    }

    /// And the ordinary case is untouched: a payment after the anchor lights
    /// the pill and says nothing extra.
    #[test]
    fn a_payment_inside_the_window_reads_as_seen() {
        let order = order_anchored_at(150);
        let reading = AddressReading::of(&order, Some(&address_with(&[(151, 10_000)])));
        assert_eq!(reading.in_window_sats, 10_000);
        assert_eq!(reading.in_window_heights, vec![151]);
        assert_eq!(reading.outside_note(false), None);
    }

    /// **PR #83 round 2, Should Fix 5.** Dust inside the window is not a
    /// payment: the paid style needs the full amount.
    #[test]
    fn dust_inside_the_window_reads_as_partial_not_paid() {
        use harvest_common::payment::OrderStatus;
        let order = order_anchored_at(150);
        let dust = AddressReading::of(&order, Some(&address_with(&[(151, 546)])));
        assert_eq!(
            super::status_pill(OrderStatus::AwaitingPayment, &dust, false),
            ("btc-pill pending", "Partial payment seen")
        );
        let full = AddressReading::of(&order, Some(&address_with(&[(151, 10_000)])));
        assert_eq!(
            super::status_pill(OrderStatus::AwaitingPayment, &full, false),
            ("btc-pill paid", "Payment seen on chain")
        );
        // Not the paid style while the seller's confirmation is awaited.
        assert_ne!(
            super::status_pill(OrderStatus::AwaitingPayment, &full, true).0,
            "btc-pill paid"
        );
    }

    /// harvest#53 review round 2: only a payment that would SETTLE the order
    /// is in sight. Dust and part-payments are not -- anyone can send dust to
    /// a public address -- and unconfirmed value counts only while the window
    /// is still open for it to confirm in.
    #[test]
    fn only_a_settling_payment_is_in_sight() {
        let order = order_anchored_at(150);
        let window_end = order.payment_window().expect("anchored").end().to_owned();
        let dust = AddressReading::of(&order, Some(&address_with(&[(151, 546)])));
        assert!(!dust.sight(&order, Some(160)).settles());
        let full = AddressReading::of(&order, Some(&address_with(&[(151, 10_000)])));
        assert!(full.sight(&order, Some(window_end + 50)).covered);
        let with_mempool = |confirmed: u64, unconfirmed: u64| {
            let mut view = address_with(&[(151, confirmed)]);
            view.txs.push(TxRow {
                txid_display: "mempool".into(),
                value_sats: unconfirmed,
                status: TxRowStatus::Unconfirmed,
            });
            view.pending_sats = unconfirmed;
            view
        };
        let pending = AddressReading::of(&order, Some(&with_mempool(4_000, 6_000)));
        assert!(pending.sight(&order, Some(160)).in_flight);
        assert!(pending.sight(&order, None).in_flight);
        assert!(
            !pending.sight(&order, Some(window_end)).settles(),
            "value still in flight at the window's end can never settle it"
        );
        assert!(
            !AddressReading::of(&order, Some(&with_mempool(4_000, 5_999)))
                .sight(&order, Some(160))
                .settles()
        );
        // Review round 3: `pending_sats` also counts a CONFIRMED output the
        // reader's tip has not reached (the address state arriving before
        // the tip reads every confirmation as zero deep). That output is
        // already in the window total; counting it again read a 6k
        // underpayment of a 10k invoice as 12k.
        let mut before_tip = address_with(&[(151, 6_000)]);
        before_tip.pending_sats = 6_000;
        assert!(!AddressReading::of(&order, Some(&before_tip))
            .sight(&order, Some(160))
            .settles());
    }

    /// harvest#53 review: a lapsed invoice's pill does not say "Awaiting
    /// payment" above a line saying it can no longer be paid.
    #[test]
    fn a_lapsed_invoice_pills_as_lapsed() {
        use crate::fulfilment::OrderStage;
        use harvest_common::payment::OrderStatus;
        let order = order_anchored_at(150);
        let nothing = AddressReading::of(&order, None);
        assert_eq!(
            super::card_pill(
                OrderStatus::AwaitingPayment,
                &nothing,
                false,
                OrderStage::Lapsed { closed_at: 2_214 }
            ),
            ("btc-pill cancelled", "Lapsed")
        );
        assert_eq!(
            super::card_pill(
                OrderStatus::AwaitingPayment,
                &nothing,
                false,
                OrderStage::AwaitingPayment {
                    settle_until: 2_214
                }
            ),
            ("btc-pill waiting", "Awaiting payment")
        );
    }

    /// Round 2, Consider: the notes say the right thing in each case. An
    /// older payment beside a valid one does not tell the seller to reissue;
    /// a late one is called the buyer's probable late payment; an order with
    /// no anchor says so rather than blaming an older payment.
    #[test]
    fn each_note_names_its_own_reason() {
        let order = order_anchored_at(150);
        let both = AddressReading::of(&order, Some(&address_with(&[(100, 10_000), (151, 10_000)])));
        let note = both
            .outside_note(false)
            .expect("the older payment is mentioned");
        assert!(!note.contains("Issue a new invoice"), "{note}");

        let late = AddressReading::of(
            &order,
            Some(&address_with(&[(150 + PAYMENT_WINDOW_BLOCKS + 1, 10_000)])),
        );
        assert!(late
            .outside_note(false)
            .expect("said")
            .contains("late payment"));
        // Round 3, Should Fix 4: not presumed late when it falls in another
        // own invoice's window on this address.
        let theirs = late.outside_note(true).expect("said");
        assert!(!theirs.contains("late payment"), "{theirs}");
        assert!(theirs.contains("another of your invoices"), "{theirs}");

        let mut anchorless = order_anchored_at(150);
        anchorless.anchor = None;
        let reading = AddressReading::of(&anchorless, Some(&address_with(&[(100, 10_000)])));
        let note = reading.outside_note(false).expect("said");
        assert!(note.contains("names no Bitcoin block"), "{note}");
        assert_eq!(reading.before_order, None);
    }
}
