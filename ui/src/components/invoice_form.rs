//! The seller's orders at a store, the payout wallet (payment key) form, and
//! the controls on an order: Mark as sent, and cancelling an unpaid invoice.
//! Invoices are no longer issued from a form here: buyers pay through Buy
//! now, and a request the store did not answer is answered by hand from the
//! message thread (`buy_view::AcceptRequest`).
//!
//! # Why the seller issues the invoice
//!
//! `AuthorizedOrder::verify_terms` checks a ghostkey-scoped SELLER signature
//! over the whole `Order`, so a buyer cannot create one -- "buyer clicks Buy"
//! needs buyer-to-seller messaging, which is a separate decision. A seller
//! handing over an invoice needs nothing that does not already exist, and it
//! is how a small seller works anyway: here is what you owe, here is where to
//! pay it.
//!
//! # What the seller has to be told, and is
//!
//! **An invoice reaches Paid only while a bridge is watching its address, and
//! that watch has to be kept alive.** Harvest asks the bridge through its
//! request inbox when the invoice is issued, and renews the request while the
//! seller has Harvest open (`AppState::queue_due_watch_requests`). The bridge
//! drops a watch about a day after the request that last asked for it, and it
//! does not look back over blocks it scanned while not watching
//! (freenet-bitcoin#7), so a payment made during a lapse is never picked up.
//! Since harvest#179 the seller's delegate renews its own watches on its
//! wake-ups, with no tab open, so the page no longer warns the seller to
//! open Harvest more than once a day.

use dioxus::prelude::*;
use freenet_bitcoin_common::BitcoinNetwork;

use crate::gateway::{bitcoin_config, bitcoin_ops, APP_STATE};

/// The networks the picker offers.
///
/// Exactly the ones this build can settle a payment on
/// ([`bitcoin_config::settleable_networks`]), not every network Bitcoin has.
/// Offering the others would let a seller file a mainnet key and issue
/// real-money invoices naming a bridge that watches signet: they would look
/// entirely normal and could never be shown to have been paid, which is the
/// failure mode `bitcoin_config`'s own header exists to prevent.
///
/// `order_for_invoice` refuses such a network too, so this is the second of
/// two gates rather than the only one -- but a choice that always fails at
/// submit is a worse way to learn than one that is not offered.
fn offered_networks() -> &'static [BitcoinNetwork] {
    bitcoin_config::settleable_networks()
}

/// The seller's orders at one store: first each paid order still to send, on
/// a card that says what to pack, where to send it and by when, with Mark as
/// sent on it (the 2026-09-27 friction report); then the rest, as issued.
///
/// There is no "Issue an invoice" control any more: every listing has one
/// fixed price and buyers pay through Buy now (Ian, 2026-09-26), so an
/// invoice with no buyer's request behind it has nobody to pay it.
#[component]
pub fn StorePayments(store_contract_id: Vec<u8>, seller_fingerprint: String) -> Element {
    // One buyer conversation open at a time, so the guidance line above its
    // reply box is on screen once (`message_view::SELLER_GUIDANCE`).
    let open_thread = use_signal(|| None as super::message_view::OpenThread);
    let (to_send, others, titles, requests, live, needs_reissue, loaded, inbox, questions, homes) = {
        let state = APP_STATE.read();
        let store = state.browsing_stores.get(&store_contract_id);
        // The same list as "Needs you" (`AppState::seller_orders_to_send`).
        let to_send = state.seller_orders_to_send(&store_contract_id, &seller_fingerprint);
        let others: Vec<_> = invoices_issued_by(
            store.map(|s| s.orders.as_slice()).unwrap_or_default(),
            &seller_fingerprint,
            |id| state.withheld_settlements.contains_key(id),
        )
        .into_iter()
        .filter(|o| !to_send.iter().any(|t| t.order.id == o.order.id))
        .collect();
        // Decided once, here, against this node's own view of the chain --
        // the same read `payment_blockers` makes on the buyer's side, so the
        // two cannot disagree about whether an order has aged out.
        let needs_reissue: std::collections::HashSet<harvest_common::payment::OrderId> = others
            .iter()
            .filter(|order| state.needs_reissue(order))
            .map(|order| order.order.id.clone())
            .collect();
        // What each other order was for, from the buyer's request, so a row
        // names the item rather than only a reference; and, for a paid one,
        // where it went (review of #205, U1: after Mark as sent the address
        // was on no screen, in exactly the window a buyer may say it never
        // arrived). Hidden once the complaint window closes.
        let requests: std::collections::HashMap<
            harvest_common::payment::OrderId,
            crate::state::SellerRequest,
        > = others
            .iter()
            .zip(state.seller_order_requests(&store_contract_id, &others))
            .map(|(order, request)| (order.order.id.clone(), request))
            .collect();
        let titles: std::collections::HashMap<harvest_common::payment::OrderId, String> = requests
            .iter()
            .filter_map(|(id, request)| match request {
                crate::state::SellerRequest::Found(r) => Some((
                    id.clone(),
                    format!(
                        "{} \u{00d7} {}",
                        r.title.as_deref().unwrap_or("An item no longer listed"),
                        r.quantity
                    ),
                )),
                _ => None,
            })
            .collect();
        // Each order's conversation goes under its card; one with no card
        // of its own, if it holds a question or a request waiting for a hand
        // answer, goes under Questions (the round-6 critique: no mailbox
        // dump under the orders).
        let inbox = super::message_view::seller_inbox(&state, &store_contract_id);
        let listed: Vec<&harvest_common::payment::AuthorizedOrder> =
            to_send.iter().chain(others.iter()).collect();
        let listed_ids: Vec<&harvest_common::payment::OrderId> =
            listed.iter().map(|order| &order.order.id).collect();
        let questions = super::message_view::seller_questions(&inbox, &listed_ids);
        let sending: std::collections::HashSet<&harvest_common::payment::OrderId> =
            to_send.iter().map(|order| &order.order.id).collect();
        let homes = super::message_view::thread_homes(&inbox, &listed, |order| {
            sending.contains(&order.order.id)
        });
        (
            to_send,
            others,
            titles,
            requests,
            // Cloned once outside the render loop below; taking a fresh read
            // guard per order would be a borrow per row for no gain.
            state.bitcoin.clone(),
            needs_reissue,
            // "No orders yet" and "this store's state has not arrived" look
            // alike through an empty list.
            state.store_details_are_resolved(&store_contract_id),
            inbox,
            questions,
            homes,
        )
    };
    // This order's conversation, if it is shown under this card; else
    // whether it is shown under another of the buyer's orders
    // (`message_view::thread_homes`: one that needs the seller, then the
    // newest). Looked up in one map built per render, not by a scan of
    // every conversation per card (review after 01f2bcf).
    let by_order = inbox.by_order();
    let thread_for = |id: &harvest_common::payment::OrderId| {
        by_order
            .get(id)
            .map(|thread| ((*thread).clone(), homes.get(&thread.tag) == Some(id)))
    };
    // Where a card's conversation is shown under another order: that
    // conversation and the order it is under, for the pointer button.
    let elsewhere = |id: &harvest_common::payment::OrderId| {
        thread_for(id)
            .filter(|(_, home)| !home)
            .and_then(|(thread, _)| homes.get(&thread.tag).cloned().map(|home| (thread, home)))
    };

    rsx! {
        div { class: "card",
            h3 { "Orders" }
            if !loaded {
                p { class: "text-muted text-italic", "Loading this store\u{2019}s orders\u{2026}" }
            } else if to_send.is_empty() && others.is_empty() {
                p { class: "text-muted", "No orders yet. Paid orders appear here." }
            }
            for order in to_send.iter() {
                SellerOrderCard {
                    key: "{order.order.id}",
                    store_contract_id: store_contract_id.clone(),
                    order: order.clone(),
                    thread: thread_for(&order.order.id).filter(|(_, home)| *home).map(|(t, _)| t),
                    elsewhere: elsewhere(&order.order.id),
                    open_thread,
                }
            }
            if !others.is_empty() {
                h4 { class: "orders-earlier", "Other orders" }
                for order in others.iter() {
                    // One keyed node per invoice, wrapping both, because a
                    // `key` is only honoured on the first node of a block.
                    // One group per order, so its title, card, address and
                    // controls read as one thing (the msg1 screenshots: the
                    // address sat loose below the card).
                    div { key: "{order.order.id}", class: "earlier-order",
                        // Said above the card rather than inside it, because
                        // it is about what the SELLER should do and
                        // `OrderCard` is shared with the buyer's view. An
                        // order's anchor is fixed at signing, so an unpaid
                        // one eventually stops being payable -- and without
                        // this the only party who can fix that never learns
                        // of it.
                        if needs_reissue.contains(&order.order.id) {
                            p { class: "text-warning",
                                "Invoice {order.order.id.short()} has expired: it is too old for a \
                                 buyer's software to accept, so nobody can pay it now. Cancel it; \
                                 the buyer can order again."
                            }
                        }
                        if let Some(what) = titles.get(&order.order.id) {
                            h4 { class: "order-title", "{what}" }
                        }
                        // The address and controls inside the order's own box.
                        super::bitcoin_view::OrderCard {
                            order: order.clone(),
                            live: super::bitcoin_view::live_address_for_order(&live, &order.order),
                            footer: rsx! {
                                if matches!(
                                    order.status,
                                    harvest_common::payment::OrderStatus::Paid
                                        | harvest_common::payment::OrderStatus::PaymentReversed
                                ) {
                                    if let Some(request) = requests.get(&order.order.id) {
                                        SellerRequestView { request: request.clone(), quiet_when_missing: true }
                                    }
                                }
                                if order.status == harvest_common::payment::OrderStatus::AwaitingPayment {
                                    CancelInvoice {
                                        store_contract_id: store_contract_id.clone(),
                                        order_id: order.order.id.clone(),
                                    }
                                }
                                // A paid order past every window can still be marked
                                // as sent late, which extends the buyer's time to
                                // report a problem (`despatch_preconditions`); the
                                // control hides itself once a despatch is recorded.
                                if order.status == harvest_common::payment::OrderStatus::Paid {
                                    MarkDespatched {
                                        store_contract_id: store_contract_id.clone(),
                                        order_id: order.order.id.clone(),
                                    }
                                }
                                match (thread_for(&order.order.id), elsewhere(&order.order.id)) {
                                    (Some((thread, true)), _) => rsx! {
                                        super::message_view::SellerThreadToggle {
                                            store_contract_id: store_contract_id.clone(),
                                            thread,
                                            under: Some(order.order.id.clone()),
                                            open_thread,
                                        }
                                    },
                                    (_, Some((thread, home))) => rsx! {
                                        super::message_view::SellerThreadPointer { thread, home, open_thread }
                                    },
                                    _ => rsx! {},
                                }
                            },
                        }
                    }
                }
            }
            // At most two quiet lines, never a card per entry (round-6
            // critique 10-3), inside the card they are about (msg1 critique
            // MSG-9): what could not be read, and buyer text held back for
            // coming with neither a Ghost Key nor a paid order.
            if inbox.unreadable > 0 {
                p { class: "text-muted small", "{super::message_view::SOME_UNREADABLE}" }
            }
            if inbox.held_back > 0 {
                p { class: "text-muted small",
                    "{super::message_view::hidden_unvouched_line(inbox.held_back)}"
                }
            }
        }
        if !questions.is_empty() {
            super::message_view::SellerQuestions {
                store_contract_id: store_contract_id.clone(),
                threads: questions,
                open_thread,
            }
        }
    }
}

/// One paid order still to send, as the seller packs it: what, how many,
/// where to, by when, and Mark as sent. What to pack and where come from the
/// buyer's Buy now request (`AppState::seller_order_request`); an order
/// without one, or with two that differ, says where to look instead. The
/// warnings a seller needs before sending stay on the card: one payment
/// that may also have settled another order (harvest#77), and an order
/// paid after it sold out.
#[component]
pub(crate) fn SellerOrderCard(
    store_contract_id: Vec<u8>,
    order: harvest_common::payment::AuthorizedOrder,
    /// This order's conversation with its buyer, when this device can read
    /// it: shown under the card behind a Messages button.
    #[props(default)]
    thread: Option<super::message_view::SellerThread>,
    /// Which conversation is open on this screen (`StorePayments`); `None`
    /// where the card is shown without its conversation.
    #[props(default)]
    open_thread: Option<Signal<super::message_view::OpenThread>>,
    /// The buyer's conversation, when it is shown under another of their
    /// order cards (`message_view::thread_homes`: one that needs the seller,
    /// then the newest), and that order: the card shows a button naming it.
    #[props(default)]
    elsewhere: Option<(
        super::message_view::SellerThread,
        harvest_common::payment::OrderId,
    )>,
) -> Element {
    use crate::state::SellerRequest;
    let (request, tip_height, stage, twins, oversold) = {
        let state = APP_STATE.read();
        let tip = state
            .bitcoin
            .tips
            .get(&order.order.network)
            .and_then(|t| t.tip_height);
        let stage = crate::fulfilment::order_stage(
            &order,
            state.despatch_of(&order).as_ref(),
            tip,
            state.payment_sight(&order),
        );
        let oversold = matches!(
            state.auto_invoice.status.get(&store_contract_id),
            Some(Ok(status)) if status.oversold.contains(&order.order.id)
        );
        (
            state.seller_order_request(&store_contract_id, &order),
            tip,
            stage,
            state.paid_twins(&order),
            oversold,
        )
    };
    let now = crate::state::now_ms();
    let what = match &request {
        SellerRequest::Found(r) => format!(
            "{} \u{00d7} {}",
            r.title.as_deref().unwrap_or("An item no longer listed"),
            r.quantity
        ),
        _ => format!("Order {}", order.order.id.short()),
    };
    let send_by = match (stage, tip_height) {
        _ if oversold => None,
        // The date is on the pill ("Send by 4 Oct"), so the line says only
        // how long is left (round-6 critique: the same fact twice).
        (crate::fulfilment::OrderStage::AwaitingDespatch { despatch_by, .. }, Some(tip)) => Some((
            false,
            format!(
                "{} to send it.",
                crate::fulfilment::time_left(despatch_by.saturating_sub(tip))
            ),
        )),
        (crate::fulfilment::OrderStage::DespatchWindowClosed { despatch_by, .. }, Some(tip)) => {
            Some((
                true,
                format!(
                    "The date to send it by, about {}, has passed. Send it now, and mark it as \
                     sent.",
                    crate::fulfilment::approx_date(despatch_by, tip, now)
                ),
            ))
        }
        (_, None) => Some((
            false,
            "Paid. The date to send it by shows once your node has caught up with Bitcoin."
                .to_string(),
        )),
        (_, Some(_)) => Some((false, "Paid. Send it soon.".to_string())),
    };
    // The card's one badge says what to do and by when: every card here is
    // paid (the 2026-09-30 critique).
    let pill = match (stage, tip_height) {
        _ if oversold => "Sold out".to_string(),
        (crate::fulfilment::OrderStage::AwaitingDespatch { despatch_by, .. }, Some(tip)) => {
            format!(
                "Send by {}",
                crate::fulfilment::approx_date(despatch_by, tip, now)
            )
        }
        (crate::fulfilment::OrderStage::DespatchWindowClosed { .. }, _) => "Send now".to_string(),
        _ => "To send".to_string(),
    };
    let amount = super::pay_card::amount_text(order.order.amount_sats, order.order.network);
    let test = super::pay_card::is_test_network(order.order.network);

    rsx! {
        div { class: "listing-card seller-order",
            div { class: "listing-header",
                h4 { "{what}" }
                // Amber: this is what needs the seller (round 4 of #197).
                span { class: "btc-pill needs", "{pill}" }
            }
            p {
                "{amount}"
                if test {
                    span { class: "test-coins", "{super::pay_card::TEST_COIN_NOTE}" }
                }
                span { class: "text-muted small", " \u{00b7} order {order.order.id.short()}" }
            }
            if oversold {
                p { class: "text-warning",
                    strong { "Paid after it sold out. " }
                    "The item went to another buyer, or you marked it sold out or took it down, \
                     before this payment arrived. Refund the buyer, or make one and send it. \
                     Message them either way."
                }
            }
            if !twins.is_empty() {
                p { class: "text-warning",
                    "Your order {twins.join(\", \")} uses this same payment address, and the \
                     payment that settled this one also falls inside its window. One payment \
                     can\u{2019}t pay for both: check your wallet for a separate payment per \
                     order before sending both."
                }
            }
            if let Some((late, line)) = send_by {
                p { class: if late { "text-warning" } else { "" }, strong { "{line}" } }
            }
            SellerRequestView { request: request.clone() }
            MarkDespatched {
                store_contract_id: store_contract_id.clone(),
                order_id: order.order.id.clone(),
            }
            if let (Some((thread, home)), Some(open_thread)) = (elsewhere, open_thread) {
                super::message_view::SellerThreadPointer { thread, home, open_thread }
            }
            if let (Some(thread), Some(open_thread)) = (thread, open_thread) {
                super::message_view::SellerThreadToggle {
                    store_contract_id: store_contract_id.clone(),
                    thread,
                    under: Some(order.order.id.clone()),
                    open_thread,
                }
            }
        }
    }
}

/// What the buyer asked for, as an order card shows it
/// (`AppState::seller_order_request`): the request, each version of it when
/// they differ, or where to look when it can't be read here.
/// `quiet_when_missing` says nothing in that last case (an older order).
#[component]
pub(crate) fn SellerRequestView(
    request: crate::state::SellerRequest,
    #[props(default)] quiet_when_missing: bool,
) -> Element {
    use crate::state::SellerRequest;
    match request {
        SellerRequest::Found(request) => rsx! {
            RequestView { request }
        },
        SellerRequest::Conflict(versions) => rsx! {
            p { class: "text-warning",
                "The buyer sent more than one version of this order. Ask them which is right \
                 before sending."
            }
            for (i , version) in versions.into_iter().enumerate() {
                div { key: "{i}", class: "request-card",
                    p { class: "order-label", "Version {i + 1}: {version.quantity}" }
                    RequestView { request: version }
                }
            }
        },
        SellerRequest::NotFound if quiet_when_missing => rsx! {},
        SellerRequest::NotFound => rsx! {
            p { class: "text-muted",
                "This order\u{2019}s details can\u{2019}t be read on this device. Open Harvest \
                 where you set up the store, or ask the buyer."
            }
        },
    }
}

/// Where to send it, the buyer's picks named by their group, and the note:
/// every field a version of an order can differ in (review of #205, L2).
/// After the complaint window the address reads
/// [`crate::fulfilment::ADDRESS_HIDDEN`] and the note is gone.
#[component]
pub(crate) fn RequestView(request: crate::state::SellerOrderRequest) -> Element {
    rsx! {
        p { class: "order-label", "Send to" }
        p { class: "order-ship-to", "{request.shipping}" }
        if let Some(region) = &request.region {
            p { class: "text-muted small", "Delivery region: {region}" }
        }
        if !request.choices.is_empty() {
            p { class: "text-muted small", "{request.choices.join(\" \u{00b7} \")}" }
        }
        if !request.note.trim().is_empty() {
            p { class: "order-label", "Note from the buyer" }
            p { class: "order-ship-to", "{request.note}" }
        }
    }
}

/// The seller's control to cancel one unpaid invoice (harvest#53).
///
/// Two steps, because the second one is permanent: a cancellation cannot be
/// withdrawn, and the confirmation says the one thing a seller might not
/// expect -- that a payment already on its way still counts.
///
/// Offered for an unpaid invoice whether or not its payment window has
/// closed. A lapsed invoice needs no cancelling, but saying so in public
/// costs nothing and is what a stranger reading the store can see without
/// a chain tip of their own.
#[component]
fn CancelInvoice(
    store_contract_id: Vec<u8>,
    order_id: harvest_common::payment::OrderId,
) -> Element {
    let mut confirming = use_signal(|| false);
    let mut problem = use_signal(|| Option::<String>::None);
    let (pending, sent, unsignable) = {
        let state = APP_STATE.read();
        (
            state.cancellation_pending(&store_contract_id, &order_id),
            state.cancellation_sent(&store_contract_id, &order_id),
            state.store_key_refusal(&store_contract_id),
        )
    };
    let short = order_id.short();

    if pending {
        return rsx! {
            p { class: "text-muted", "Cancelling invoice {short}\u{2026}" }
        };
    }
    // Said instead of a button the delegate would refuse: this device holds
    // no key that can sign for the store, as `MarkDespatched` does (#136
    // review, round 5).
    if let Some(why) = unsignable {
        return rsx! {
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "Invoice {short} cannot be cancelled from this device yet: {why}"
            }
        };
    }
    if sent {
        return rsx! {
            p { class: "text-muted",
                "Cancellation of invoice {short} sent. It shows here once the store has it."
            }
        };
    }
    rsx! {
        if let Some(why) = problem() {
            p { class: "text-warning", "{why}" }
        }
        if confirming() {
            p { class: "text-warning",
                "Cancel this invoice? The buyer will see that it\u{2019}s cancelled, and it "
                "goes on your store\u{2019}s public record. You can\u{2019}t undo it. If they "
                "have already paid, or pay anyway, the payment still counts and you owe them "
                "the goods."
            }
            button {
                class: "btn btn-sm btn-primary",
                onclick: {
                    let store_contract_id = store_contract_id.clone();
                    let order_id = order_id.clone();
                    move |_| {
                        confirming.set(false);
                        let result = APP_STATE
                            .write()
                            .cancel_invoice(&store_contract_id, &order_id);
                        problem.set(result.err());
                    }
                },
                "Yes, cancel it"
            }
            button {
                class: "btn btn-sm btn-outline",
                onclick: move |_| confirming.set(false),
                "Keep it"
            }
        } else {
            button {
                class: "btn btn-sm btn-outline",
                onclick: move |_| {
                    problem.set(None);
                    confirming.set(true);
                },
                "Cancel invoice"
            }
        }
    }
}

/// The seller's control to record that a paid order has been sent
/// (harvest#53 Phase B).
///
/// Two steps, like the cancel, because the record is public and permanent.
/// Hidden once a despatch of the order is on record
/// (`AppState::despatch_recorded`), read from the same source as the
/// card's stage line, which then says so.
#[component]
pub(crate) fn MarkDespatched(
    store_contract_id: Vec<u8>,
    order_id: harvest_common::payment::OrderId,
) -> Element {
    let mut confirming = use_signal(|| false);
    let mut problem = use_signal(|| Option::<String>::None);
    let (recorded, pending, sent, refusal) = {
        let state = APP_STATE.read();
        (
            state.despatch_recorded(&store_contract_id, &order_id),
            state.despatch_pending(&store_contract_id, &order_id),
            state.despatch_sent(&store_contract_id, &order_id),
            state.despatch_refusal(&store_contract_id, &order_id),
        )
    };
    let short = order_id.short();

    if recorded {
        return rsx! {};
    }
    if pending {
        return rsx! {
            p { class: "text-muted", "Marking order {short} as sent\u{2026}" }
        };
    }
    if sent {
        return rsx! {
            p { class: "text-muted",
                "Order {short} marked as sent. It shows here once the store has it."
            }
        };
    }
    // Said instead of a button that would refuse when pressed: no store key
    // on this device, or no chain data recent enough to anchor it.
    if let Some(why) = refusal {
        return rsx! {
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "This order can\u{2019}t be marked as sent yet: {why}"
            }
        };
    }
    rsx! {
        if let Some(why) = problem() {
            p { class: "text-warning", "{why}" }
        }
        if confirming() {
            p { class: "text-warning",
                "Mark as sent? The buyer will see that it\u{2019}s on its way. You can\u{2019}t "
                "undo this, so only do it once it has actually gone."
            }
            button {
                class: "btn btn-sm btn-primary",
                onclick: {
                    let store_contract_id = store_contract_id.clone();
                    let order_id = order_id.clone();
                    move |_| {
                        confirming.set(false);
                        let result = APP_STATE
                            .write()
                            .despatch_order(&store_contract_id, &order_id);
                        problem.set(result.err());
                    }
                },
                "Yes, it has been sent"
            }
            button {
                class: "btn btn-sm btn-outline",
                onclick: move |_| confirming.set(false),
                "Not yet"
            }
        } else {
            button {
                class: "btn btn-sm btn-primary",
                onclick: move |_| {
                    problem.set(None);
                    confirming.set(true);
                },
                "Mark as sent"
            }
        }
    }
}

/// The invoices on a store that THIS seller issued, newest first, less the
/// Buy now orders nobody has paid ([`crate::fulfilment::is_unpaid_buy_now`]):
/// the seller hears of a Buy now once it is paid. Except one whose payment
/// is `withheld` for the seller to confirm (`AppState::settlement_hold`):
/// its card is where they confirm it, so it is shown while it waits
/// (review round 1 of harvest#177).
///
/// A store contract carries every order, and the seller's panel is about
/// their own. The filter is on `seller_fingerprint` rather than on ownership
/// of the store because the two can differ in exactly the case that matters:
/// a seller with more than one connected Ghost Key sees one panel per
/// identity, and showing another identity's invoices under this one would
/// invite them to act on an invoice they cannot cancel.
fn invoices_issued_by(
    orders: &[harvest_common::payment::AuthorizedOrder],
    seller_fingerprint: &str,
    withheld: impl Fn(&harvest_common::payment::OrderId) -> bool,
) -> Vec<harvest_common::payment::AuthorizedOrder> {
    let mut mine: Vec<_> = orders
        .iter()
        .filter(|o| o.order.seller_fingerprint == seller_fingerprint)
        .filter(|o| !crate::fulfilment::is_unpaid_buy_now(o) || withheld(&o.order.id))
        .cloned()
        .collect();
    mine.sort_by_key(|o| std::cmp::Reverse(o.order.created_at));
    mine
}

/// The payout wallet, as My store > Settings shows it.
#[component]
pub fn PayoutWallet() -> Element {
    let (xpub, xpub_loaded, catching_up) = {
        let state = APP_STATE.read();
        (
            state.bitcoin.payment_xpub.clone(),
            state.bitcoin.payment_xpub_loaded,
            !state.catch_up_lines().is_empty(),
        )
    };
    rsx! {
        // What it means, above the panel (U1); the progress itself is in the
        // notification bar, shown once (#206 review).
        if catching_up {
            p { class: "text-muted",
                "Harvest is checking your key against your earlier orders, a few hundred \
                 addresses at a time, and carries on by itself: keep this page open until it \
                 has finished. The key on file, if any, stays in use until a new one is saved, \
                 and invoices wait."
            }
        }
        PaymentKeyPanel { xpub, xpub_loaded }
    }
}

/// Show the configured payment key, or take one.
#[component]
fn PaymentKeyPanel(xpub: Option<harvest_common::PaymentXpubStatus>, xpub_loaded: bool) -> Element {
    let mut editing = use_signal(|| false);

    // Not "no key configured" -- we have not asked yet. Prompting here would
    // tell a seller who already has one that they do not.
    if !xpub_loaded {
        return rsx! {
            p { class: "text-muted text-italic", "Checking your payment key\u{2026}" }
        };
    }

    rsx! {
        match xpub {
            Some(status) if !editing() => rsx! {
                p { class: "text-muted",
                    "Paying into your "
                    strong { "{status.network.as_str()}" }
                    " wallet. "
                    "{status.next_index} address(es) from this key are already taken, \
                     counting the orders your stores have published, so the next invoice \
                     gets a new one. "
                    "This key is shared by every store and every Ghost Key in this app."
                }
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| editing.set(true),
                    "Change payment key"
                }
            },
            _ => rsx! {
                PaymentKeyForm {
                    // Replacing a key restarts the address count, which is
                    // correct but worth saying out loud.
                    replacing: xpub.is_some(),
                    on_done: move |_| editing.set(false),
                }
            },
        }
    }
}

#[component]
fn PaymentKeyForm(replacing: bool, on_done: EventHandler<()>) -> Element {
    let mut xpub = use_signal(String::new);
    let mut network = use_signal(bitcoin_config::default_network);

    rsx! {
        div { class: "form-group",
            p {
                "Paste your wallet's "
                strong { "native SegWit (BIP-84) account public key" }
                ". It starts with "
                code { "zpub" }
                " on mainnet or "
                code { "vpub" }
                " on signet and testnet. Harvest derives a fresh receiving "
                "address from it for each invoice, so no address is ever reused."
            }
            p {
                "In your wallet's settings, set the "
                strong { "gap limit" }
                " to 100. Buyers who press Buy now and never pay still use up addresses, and "
                "a wallet left at the usual 20 can miss a payment that comes after them."
            }
            p { class: "text-muted",
                "This is a "
                strong { "public" }
                " key: it can produce addresses and nothing else. Harvest never holds "
                "anything that could spend your coins: the key that can spend stays in "
                "your wallet, which is also what lets you spend what buyers send."
            }
            if replacing {
                p { class: "text-warning",
                    "Entering a DIFFERENT key starts its addresses from the beginning, which "
                    "is correct: addresses only mean anything relative to the key they come "
                    "from. Entering a key you have used before, here or on another device, "
                    "does not reuse its addresses: Harvest skips past every address your "
                    "stores' published orders already name. Either way, invoices you have "
                    "already issued are unaffected: they name an address, not a key."
                }
            }

            label { class: "form-label", "Account public key" }
            input {
                class: "form-input",
                r#type: "text",
                placeholder: "vpub…",
                value: "{xpub}",
                oninput: move |e| xpub.set(e.value()),
            }

            label { class: "form-label", "Network" }
            select {
                class: "form-select field-fit",
                value: "{network().as_str()}",
                onchange: move |e| {
                    if let Some(picked) =
                        offered_networks().iter().find(|n| n.as_str() == e.value())
                    {
                        network.set(*picked);
                    }
                },
                for option in offered_networks() {
                    option { value: "{option.as_str()}", "{option.as_str()}" }
                }
            }

            // On its own row: beside the content-sized network picker it
            // read as part of it (round-6 critique).
            div { class: "form-actions",
                button {
                    class: "btn btn-primary",
                    disabled: xpub().trim().is_empty(),
                    onclick: move |_| {
                        save_payment_key(xpub().trim().to_string(), network());
                        xpub.set(String::new());
                        on_done.call(());
                    },
                    "Save payment key"
                }
            }
        }
    }
}

fn save_payment_key(xpub: String, network: BitcoinNetwork) {
    // Every send it makes reports its own failure, and withdraws what it
    // registered (`state::spawn_bitcoin_requests`).
    bitcoin_ops::set_payment_xpub(xpub, network);
}

/// The confirmations a seller typed, or why an order may not require that
/// many. Used by the accept control in `buy_view`, so every hand-issued
/// order refuses the same values.
///
/// At least one: accepting zero would count a payment as settled while it is
/// still only in the mempool. At most
/// [`harvest_common::payment::MAX_REQUIRED_CONFIRMATIONS`]: an order needing
/// more could not read as paid in time for a complaint about it, so buyers'
/// software refuses to pay it (`docs/complaint-threat-model.md` section 4).
pub(crate) fn parse_required_confirmations(input: &str) -> Result<u32, String> {
    use harvest_common::payment::MAX_REQUIRED_CONFIRMATIONS;
    match input.trim().parse::<u32>() {
        Ok(n) if n > MAX_REQUIRED_CONFIRMATIONS => Err(format!(
            "At most {MAX_REQUIRED_CONFIRMATIONS} confirmations, about a day of blocks. An \
             order needing more could not count as paid in time for a buyer to complain about \
             it, so buyers will not pay it."
        )),
        Ok(n) if n > 0 => Ok(n),
        _ => Err(
            "At least one confirmation. Accepting zero would count a payment as settled \
             while it is still only in the mempool, where it can still be replaced."
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};

    fn order(seller: &str, minutes: i64) -> AuthorizedOrder {
        let created_at =
            chrono::DateTime::from_timestamp(1_700_000_000 + minutes * 60, 0).expect("timestamp");
        AuthorizedOrder {
            order: Order {
                request_id: None,
                id: OrderId([0u8; 32]),
                buyer_fingerprint: "buyer".to_string(),
                seller_fingerprint: seller.to_string(),
                amount_sats: 1_000,
                network: BitcoinNetwork::Signet,
                payment_script_pubkey: vec![0x00, 0x14, minutes as u8],
                payment_address: format!("tb1qexample{minutes}"),
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
            .with_derived_id(),
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status: OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// A store contract carries every order it has ever seen. A seller's panel
    /// showing another identity's invoices would offer them actions on an
    /// invoice they cannot sign for.
    #[test]
    fn a_sellers_panel_shows_only_their_own_invoices() {
        let orders = vec![order("me", 1), order("someone-else", 2), order("me", 3)];

        let mine = invoices_issued_by(&orders, "me", |_| false);

        assert_eq!(mine.len(), 2);
        assert!(mine.iter().all(|o| o.order.seller_fingerprint == "me"));
    }

    /// Newest first: the invoice a seller just issued is the one they are
    /// looking for.
    #[test]
    fn invoices_are_listed_newest_first() {
        let orders = vec![order("me", 1), order("me", 3), order("me", 2)];

        let mine = invoices_issued_by(&orders, "me", |_| false);

        let addresses: Vec<&str> = mine
            .iter()
            .map(|o| o.order.payment_address.as_str())
            .collect();
        assert_eq!(
            addresses,
            vec!["tb1qexample3", "tb1qexample2", "tb1qexample1"]
        );
    }

    /// An unpaid Buy now is not an order, as the seller sees it: left out
    /// while it awaits payment, and when it was cancelled unpaid. Once paid it
    /// is listed. An invoice the seller issued by hand (no request id) is
    /// always listed. Mutated red by dropping the `is_unpaid_buy_now` filter,
    /// and by widening it to every `AwaitingPayment` order.
    #[test]
    fn an_unpaid_buy_now_is_not_on_the_sellers_list() {
        let buy_now = |minutes: i64, status: OrderStatus| {
            let mut o = order("me", minutes);
            o.order.request_id = Some([minutes as u8; 32]);
            o.status = status;
            o
        };
        let orders = vec![
            order("me", 1),
            buy_now(2, OrderStatus::AwaitingPayment),
            buy_now(3, OrderStatus::Cancelled),
            buy_now(4, OrderStatus::Paid),
            buy_now(5, OrderStatus::PaymentReversed),
        ];
        let shown: Vec<i64> = invoices_issued_by(&orders, "me", |_| false)
            .iter()
            .map(|o| o.order.payment_script_pubkey[2] as i64)
            .collect();
        assert_eq!(shown, vec![5, 4, 1]);
        // One whose payment waits for the seller to confirm it is shown:
        // its card is where they do. Mutated red by dropping the exception.
        let waiting = orders[1].order.id.clone();
        let shown: Vec<i64> = invoices_issued_by(&orders, "me", |id| *id == waiting)
            .iter()
            .map(|o| o.order.payment_script_pubkey[2] as i64)
            .collect();
        assert_eq!(shown, vec![5, 4, 2, 1]);
    }

    #[test]
    fn a_seller_with_no_invoices_gets_an_empty_list() {
        assert!(invoices_issued_by(&[], "me", |_| false).is_empty());
        assert!(invoices_issued_by(&[order("someone-else", 1)], "me", |_| false).is_empty());
    }

    /// **The seller's forms refuse what a buyer would refuse to pay**
    /// (`docs/complaint-threat-model.md` section 4, TM-C): zero, and more
    /// than `MAX_REQUIRED_CONFIRMATIONS`, each with a reason. Red if either
    /// bound is dropped.
    #[test]
    fn the_confirmations_input_refuses_zero_and_more_than_the_cap() {
        use harvest_common::payment::MAX_REQUIRED_CONFIRMATIONS;
        assert_eq!(parse_required_confirmations(" 1 "), Ok(1));
        assert_eq!(
            parse_required_confirmations(&MAX_REQUIRED_CONFIRMATIONS.to_string()),
            Ok(MAX_REQUIRED_CONFIRMATIONS)
        );
        let too_many = parse_required_confirmations(&(MAX_REQUIRED_CONFIRMATIONS + 1).to_string())
            .expect_err("over the cap");
        assert!(too_many.contains("At most 144"), "{too_many}");
        for refused in ["0", "", "two", "-1"] {
            let why = parse_required_confirmations(refused).expect_err(refused);
            assert!(why.contains("At least one"), "{refused}: {why}");
        }
    }
}
