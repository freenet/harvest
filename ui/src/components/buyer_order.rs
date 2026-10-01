//! One of the buyer's orders (page structure P4), and the step to report a
//! problem with it (P5). The order page says where the purchase stands and
//! offers the one thing the buyer can do about it now: pay it, report a
//! problem once that is possible, or buy it again once it has expired.
//!
//! Everything that decides whether a payment address may be shown is the
//! old purchase card's, unchanged (`buy_view::PayPanel`, `KeepBeforePaying`,
//! `bitcoin_view::OrderCard`); this page only places it.

use dioxus::prelude::*;
use harvest_common::payment::OrderId;

use super::buy_view::{ComplaintOffer, ComplaintTarget, PendingAnswer};
use super::order_status::{self, Status};
use super::router::{go, OrderAt, Page};
use crate::gateway::APP_STATE;
use crate::state::BuyerPurchase;

/// P4.
#[component]
pub(crate) fn BuyerOrderPage(at: OrderAt, order: OrderId) -> Element {
    match at {
        OrderAt::Store(store) => rsx! { StoreOrder { store, order } },
        OrderAt::Kept(store_key) => rsx! { KeptOrder { store_key, order } },
    }
}

/// The progress line: Ordered, Paid, Sent, Complete, up to `step`.
#[component]
fn Progress(step: usize) -> Element {
    rsx! {
        ol { class: "progress", aria_label: "Where this order is",
            for (i , label) in ["Ordered", "Paid", "Sent", "Complete"].iter().enumerate() {
                li {
                    class: if i <= step { "on" } else { "" },
                    aria_current: if i == step { "step" } else { "false" },
                    "{label}"
                }
            }
        }
    }
}

/// What the page knows about the purchase, worked out once per render.
#[derive(Clone, PartialEq)]
struct OrderFacts {
    purchase: BuyerPurchase,
    status: Status,
    item: String,
    listing: Option<harvest_common::listing::ListingId>,
    picture: Option<String>,
    ship_to: Option<crate::state::SellerOrderRequest>,
    store_name: String,
    held: bool,
    complaint: ComplaintOffer,
    bitcoin: crate::state::BitcoinState,
    open_pill: &'static str,
    open: bool,
    trust: Option<String>,
}

#[component]
fn StoreOrder(store: Vec<u8>, order: OrderId) -> Element {
    // The stores this device has used, loaded in the background, since only
    // a loaded store recalls this device's conversations (a reload lands
    // here before Purchases has asked for them).
    use_effect(|| crate::store_link::load_visited_stores(false, true));
    // A Buy now waiting for its answer says "not answering" after a while
    // with nobody touching anything.
    #[allow(unused_mut)]
    let mut clock = use_signal(|| 0u32);
    #[cfg(target_arch = "wasm32")]
    use_future(move || async move {
        loop {
            gloo_timers::future::TimeoutFuture::new(5_000).await;
            clock += 1;
        }
    });
    let _ = clock();

    let pending = super::buy_view::PENDING_BUYS.read().get(&order).cloned();
    let facts = {
        let state = APP_STATE.read();
        let now = crate::state::now_ms();
        state
            .buyer_purchases(&store)
            .into_iter()
            .find(|p| p.order_id == order)
            .map(|purchase| {
                let listing = state.purchase_listing(&store, &purchase);
                let item = match &listing {
                    Some((_, Some(title), q)) => format!("{title} \u{00d7} {q}"),
                    Some((_, None, q)) => format!("An item no longer listed \u{00d7} {q}"),
                    None => match pending.as_ref() {
                        Some(p) => format!("{} \u{00d7} {}", p.title, p.quantity),
                        None => format!("Order {}", purchase.order_id.short()),
                    },
                };
                let open = state.buyer_open(&store, now);
                let trust = state
                    .browsing_stores
                    .get(&store)
                    .filter(|b| b.info.is_some())
                    .map(super::store_view::trust_line);
                OrderFacts {
                    status: order_status::buyer_status(&state, &store, &purchase),
                    picture: listing.as_ref().and_then(|(l, t, _)| {
                        super::item_image::listing_image(l, t.as_deref().unwrap_or_default())
                    }),
                    listing: listing.map(|(l, _, _)| l),
                    item,
                    ship_to: state.purchase_ship_to(&store, &purchase),
                    store_name: state.store_name_of(&store).label(),
                    held: state.browsing_stores.get(&store).is_some_and(|s| {
                        s.conversations
                            .iter()
                            .any(|c| c.buyer_public_key == purchase.conversation)
                    }),
                    complaint: if purchase.paid.is_some() {
                        super::buy_view::complaint_offer(
                            &state,
                            &ComplaintTarget::AtStore {
                                store_contract_id: store.clone(),
                                purchase: Box::new(purchase.clone()),
                            },
                        )
                    } else {
                        ComplaintOffer::Refused(String::new())
                    },
                    bitcoin: state.bitcoin.clone(),
                    open_pill: open.pill(),
                    open: open == crate::state::BuyerOpen::Open,
                    trust,
                    purchase,
                }
            })
    };
    let back = rsx! {
        super::seller_pages::BackTo { label: "Purchases".to_string(), page: Page::Purchases }
    };
    let Some(facts) = facts else {
        // Not here yet: a Buy now this tab just sent, waiting for the store,
        // or a page reloaded before its store arrived.
        let store_name = APP_STATE.read().store_name_of(&store).label();
        return match pending {
            Some(pending) => {
                let answer = super::buy_view::pending_answer(&APP_STATE.read(), &pending);
                rsx! {
                    {back}
                    div { class: "page-title",
                        h2 { "{pending.title} \u{00d7} {pending.quantity}" }
                        span { class: "pill", "Placed" }
                    }
                    p { class: "page-meta", "From {store_name} \u{00b7} just now" }
                    Progress { step: 0 }
                    div { class: "panel panel-strong",
                        match answer {
                            PendingAnswer::Waiting | PendingAnswer::Accepted => rsx! {
                                p { strong { "Getting the payment details from {store_name}\u{2019}s store\u{2026}" } }
                                p { class: "text-muted small",
                                    "This usually takes a few seconds. Nothing has been charged."
                                }
                            },
                            PendingAnswer::Declined(reason) => rsx! {
                                p { class: "text-warning", "The seller\u{2019}s store couldn\u{2019}t take this order: {reason}" }
                                p { class: "text-muted small", "You haven\u{2019}t been charged anything." }
                                button {
                                    class: "btn btn-outline",
                                    onclick: {
                                        let store = store.clone();
                                        let listing = pending.listing.clone();
                                        move |_| go(Page::Item { store: store.clone(), listing: listing.clone() })
                                    },
                                    "Back to the item"
                                }
                            },
                            PendingAnswer::NotResponding => rsx! {
                                p { class: "text-muted",
                                    "{store_name}\u{2019}s store hasn\u{2019}t answered yet. You haven\u{2019}t been \
                                     charged anything. If it answers later, the payment details appear here and \
                                     under Purchases."
                                }
                            },
                        }
                    }
                }
            }
            None => {
                let loading = APP_STATE.read().store_name_of(&store)
                    == crate::state::StoreName::Loading
                    || !APP_STATE.read().background_loads.is_empty();
                rsx! {
                    {back}
                    if loading {
                        p { class: "text-muted text-italic", "Loading your order\u{2026}" }
                    } else {
                        p { class: "text-muted",
                            "This order isn\u{2019}t on this device. Your purchases are kept on the \
                             device you bought from, unless you restore a backup here."
                        }
                    }
                }
            }
        };
    };

    let purchase = facts.purchase.clone();
    let short = purchase.order_id.short();
    let amount = purchase
        .commitment
        .as_ref()
        .or(purchase.paid.as_ref())
        .map(|o| (o.order.amount_sats, o.order.network));
    let ordered = purchase
        .commitment
        .as_ref()
        .or(purchase.paid.as_ref())
        .map(|o| order_status::short_date(o.order.created_at));
    let can_pay = order_status::buyer_can_pay(&purchase, facts.status);
    let just_bought = pending.is_some();
    let asked = pending.as_ref().map(|p| p.sent.asked_sats);
    let holds = pending.as_ref().is_some_and(|p| p.holds_stock);
    let pill_class = if can_pay {
        "pill pill-needs"
    } else {
        facts.status.pill_class()
    };
    let message_to = if facts.held {
        Page::Conversation {
            store: store.clone(),
            tag: Some(purchase.conversation),
        }
    } else {
        super::store_view::conversation_page(&APP_STATE.read(), &store)
    };
    let settled = purchase
        .paid
        .clone()
        .or_else(|| purchase.settled().cloned());

    rsx! {
        {back}
        div { class: "page-title",
            super::item_image::RowThumb { src: facts.picture.clone() }
            h2 { "{facts.item}" }
            span { class: "{pill_class}", "{facts.status.label()}" }
        }
        p { class: "page-meta",
            "From {facts.store_name}"
            if let Some(ref date) = ordered {
                " \u{00b7} ordered {date}"
            }
            " \u{00b7} order {short}"
        }
        if let Some(step) = facts.status.step() {
            Progress { step }
        }
        div { class: "two-col",
            div { class: "col-main",
                match facts.status {
                    Status::WaitingForPayment | Status::CantBePaid | Status::Placed => rsx! {
                        div { class: if can_pay { "panel panel-strong" } else { "panel" },
                            if can_pay {
                                if let Some((sats, network)) = amount {
                                    h3 { class: "panel-h", "Pay {super::pay_card::money(sats, network)}" }
                                }
                                // Only a counted listing holds stock, and only
                                // for the hour.
                                if holds {
                                    p { class: "text-muted small",
                                        "Pay soon: this item is kept for you for about an hour. If it sells out \
                                         before your payment is confirmed, the seller either sends it anyway or refunds you."
                                    }
                                }
                            }
                            super::buy_view::PayPanel {
                                store_contract_id: store.clone(),
                                purchase: purchase.clone(),
                                bitcoin: facts.bitcoin.clone(),
                                just_bought,
                                asked_sats: asked,
                            }
                        }
                    },
                    Status::Expired => rsx! {
                        div { class: "panel",
                            p { "This order expired before it was paid. Nothing was charged." }
                            if let Some(listing) = facts.listing.clone() {
                                button {
                                    class: "btn btn-primary",
                                    onclick: {
                                        let store = store.clone();
                                        move |_| go(Page::Item { store: store.clone(), listing: listing.clone() })
                                    },
                                    "Buy it again"
                                }
                            }
                        }
                    },
                    _ => rsx! {
                        div { class: "panel",
                            if let Some(order) = settled.clone() {
                                super::buy_view::SettledPurchase { order, bitcoin: facts.bitcoin.clone() }
                            }
                            if let Some(line) = super::buy_view::complaint_line(&facts.complaint, &short) {
                                p { class: "text-muted small", "{line}" }
                            }
                            if facts.complaint == ComplaintOffer::Open {
                                button {
                                    class: "btn btn-outline",
                                    onclick: {
                                        let store = store.clone();
                                        let order = purchase.order_id.clone();
                                        move |_| go(Page::Report { at: OrderAt::Store(store.clone()), order: order.clone() })
                                    },
                                    "Report a problem"
                                }
                            }
                        }
                    },
                }
                if let Some((sats, network)) = amount {
                    h3 { class: "sec-lbl", "Details" }
                    div { class: "bill",
                        span { "{facts.item}" }
                        span {}
                        if let Some(ref ship) = facts.ship_to {
                            if let Some(ref region) = ship.region {
                                span { class: "text-muted", "Delivery to {region}" }
                                span {}
                            }
                            for choice in ship.choices.iter() {
                                span { class: "text-muted", "{choice}" }
                                span {}
                            }
                        }
                        strong { "Total" }
                        strong { "{super::pay_card::money(sats, network)}" }
                    }
                }
                if let Some(ref ship) = facts.ship_to {
                    h3 { class: "sec-lbl", "Sending to" }
                    p { class: "order-ship-to", "{ship.shipping}" }
                    if !ship.note.trim().is_empty() {
                        p { class: "text-muted small", "Your note: {ship.note}" }
                    }
                }
            }
            aside { class: "col-side",
                p { class: "side-lbl", "Seller" }
                p { class: "side-name", "{facts.store_name}" }
                p { class: "small",
                    span { class: if facts.open { "pill pill-open" } else { "pill" }, "{facts.open_pill}" }
                }
                if let Some(ref trust) = facts.trust {
                    p { class: "text-muted small", "{trust}" }
                }
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| go(message_to.clone()),
                    "Message the seller"
                }
                button {
                    class: "link-btn side-link",
                    onclick: {
                        let store = store.clone();
                        move |_| super::app::show_store(store.clone())
                    },
                    "Visit store"
                }
                if purchase.cancellable() {
                    div { class: "side-cancel",
                        super::buy_view::CancelPurchase { store_contract_id: store.clone(), purchase: purchase.clone() }
                    }
                }
            }
        }
    }
}

/// An order known only from this node's kept copy: its store is not loaded
/// (re-keyed while its seller stays away, or nobody hosts it). No payment
/// address, ever: a buyer who paid while the payment went unobserved would
/// read one as a prompt to pay again (review round 6).
#[component]
fn KeptOrder(store_key: [u8; 32], order: OrderId) -> Element {
    let found = {
        let state = APP_STATE.read();
        state
            .kept_purchases
            .iter()
            .find(|k| k.store_key == store_key && k.order.order.id == order)
            .cloned()
            .map(|kept| {
                let seen_paid = state.kept_seen_paid(&kept);
                let store_name = state
                    .browsing_stores
                    .iter()
                    .find(|(_, s)| s.owner == Some(store_key))
                    .map(|(id, _)| state.store_name_of(id).label());
                let complaint = super::buy_view::complaint_offer(
                    &state,
                    &ComplaintTarget::Kept {
                        store_key,
                        order_id: order.clone(),
                    },
                );
                (
                    kept,
                    seen_paid,
                    store_name,
                    complaint,
                    state.bitcoin.clone(),
                )
            })
    };
    let back = rsx! {
        super::seller_pages::BackTo { label: "Purchases".to_string(), page: Page::Purchases }
    };
    let Some((kept, seen_paid, store_name, complaint, bitcoin)) = found else {
        return rsx! {
            {back}
            p { class: "text-muted", "This order isn\u{2019}t on this device." }
        };
    };
    use harvest_common::payment::OrderStatus;
    let paid = kept.order.status == OrderStatus::Paid;
    let short = order.short();
    let amount = super::pay_card::money(kept.order.order.amount_sats, kept.order.order.network);
    let status = if paid {
        Status::Paid
    } else {
        Status::WaitingForPayment
    };
    rsx! {
        {back}
        div { class: "page-title",
            h2 { "Order {short}" }
            span { class: "{status.pill_class()}", "{status.label()}" }
        }
        p { class: "page-meta",
            "From {store_name.clone().unwrap_or_else(|| \"a store you have used\".to_string())} \u{00b7} ordered {order_status::short_date(kept.order.order.created_at)} \u{00b7} {amount}"
        }
        div { class: "panel",
            if paid {
                super::buy_view::SettledPurchase { order: kept.order.clone(), bitcoin }
                if let Some(line) = super::buy_view::complaint_line(&complaint, &short) {
                    p { class: "text-muted small", "{line}" }
                }
                if complaint == ComplaintOffer::Open {
                    button {
                        class: "btn btn-outline",
                        onclick: {
                            let order = order.clone();
                            move |_| go(Page::Report { at: OrderAt::Kept(store_key), order: order.clone() })
                        },
                        "Report a problem"
                    }
                }
            } else if seen_paid {
                p { "Payment seen. Your node is keeping its proof of payment, and a problem can be reported once it has." }
            } else {
                p { "No payment seen yet. Your node keeps this order and follows what the bridge reports for its address. If you haven\u{2019}t paid, the store\u{2019}s page is where to." }
            }
            p { class: "text-muted small",
                "Its store isn\u{2019}t loaded, so this is your node\u{2019}s own copy of the order."
            }
        }
    }
}

/// P5: the one deliberate step to put a permanent complaint on a seller's
/// record.
#[component]
pub(crate) fn ReportPage(at: OrderAt, order: OrderId) -> Element {
    let (target, item, store_name, stage_line) = {
        let state = APP_STATE.read();
        match &at {
            OrderAt::Store(store) => {
                let purchase = state
                    .buyer_purchases(store)
                    .into_iter()
                    .find(|p| p.order_id == order);
                let item = purchase
                    .as_ref()
                    .and_then(|p| state.purchase_item(store, p))
                    .map(|(title, q)| {
                        format!(
                            "{} \u{00d7} {q}",
                            title.unwrap_or_else(|| "An item no longer listed".to_string())
                        )
                    })
                    .unwrap_or_else(|| format!("Order {}", order.short()));
                let stage_line = purchase
                    .as_ref()
                    .and_then(|p| p.paid.clone())
                    .and_then(|paid| {
                        order_status::stage_of(&state, &paid).describe(
                            state.tip_height(paid.order.network),
                            paid.status,
                            crate::state::now_ms(),
                            crate::fulfilment::Reader::Buyer,
                        )
                    });
                (
                    purchase.map(|p| ComplaintTarget::AtStore {
                        store_contract_id: store.clone(),
                        purchase: Box::new(p),
                    }),
                    item,
                    Some(state.store_name_of(store).label()),
                    stage_line,
                )
            }
            OrderAt::Kept(store_key) => (
                Some(ComplaintTarget::Kept {
                    store_key: *store_key,
                    order_id: order.clone(),
                }),
                format!("Order {}", order.short()),
                state
                    .browsing_stores
                    .iter()
                    .find(|(_, s)| s.owner == Some(*store_key))
                    .map(|(id, _)| state.store_name_of(id).label()),
                None,
            ),
        }
    };
    let order_page = Page::Order {
        at: at.clone(),
        order: order.clone(),
    };
    rsx! {
        super::seller_pages::BackTo { label: item.clone(), page: order_page.clone() }
        h2 { class: "page-h", "Report a problem" }
        p { class: "page-meta",
            "{item}"
            if let Some(ref name) = store_name {
                " \u{00b7} {name}"
            }
        }
        if let Some(ref line) = stage_line {
            p { class: "text-muted small", "{line}" }
        }
        match target {
            Some(target) => rsx! {
                super::buy_view::ReportForm { target, back: order_page.clone() }
            },
            None => rsx! {
                p { class: "text-muted text-italic", "Loading your order\u{2026}" }
            },
        }
    }
}
