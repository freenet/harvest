//! What needs the person using this device, and where (the header's pill and
//! its menu, page structure section G): each of their stores with work
//! waiting, and their purchases when an order waits for payment or a store
//! replied. One place: the pill goes straight there. Several: it opens a
//! short menu, so it never lands someone in the wrong place.

use dioxus::prelude::*;

use super::router::{go, Page, SellerView};
use crate::gateway::APP_STATE;
use crate::state::AppState;

/// One place something needs the person.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Place {
    /// The store's name, or "Purchases".
    pub name: String,
    /// What waits there, "1 to send · 1 waiting for your reply".
    pub detail: String,
    /// How many things: what the pill adds up.
    pub count: usize,
    pub page: Page,
}

/// "1 order", "2 orders".
pub(crate) fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// Every place something needs the person, the seller's stores first in
/// their order (`my_store::seller_stores`), then Purchases.
pub(crate) fn places(state: &AppState) -> Vec<Place> {
    let mut places: Vec<Place> = super::my_store::seller_stores(state)
        .into_iter()
        .filter(|store| store.needs_you() > 0)
        .map(|store| {
            let mut parts = Vec::new();
            if store.to_send > 0 {
                parts.push(format!("{} to send", store.to_send));
            }
            if store.replies > 0 {
                parts.push(format!("{} waiting for your reply", store.replies));
            }
            if store.requests > 0 {
                parts.push(format!("{} waiting for an invoice", store.requests));
            }
            if store.to_confirm > 0 {
                parts.push(plural(
                    store.to_confirm,
                    "payment to match",
                    "payments to match",
                ));
            }
            Place {
                count: store.needs_you(),
                detail: parts.join(" \u{00b7} "),
                page: Page::Seller {
                    store: Some(store.contract_id.clone()),
                    view: SellerView::Home,
                },
                name: store.label,
            }
        })
        .collect();
    let buyer = buyer_needs(state);
    if buyer.to_pay + buyer.replied.len() > 0 {
        let mut parts = Vec::new();
        if buyer.to_pay > 0 {
            parts.push(format!("{} to pay", buyer.to_pay));
        }
        match buyer.replied.as_slice() {
            [] => {}
            [one] => parts.push(format!("{one} replied")),
            many => parts.push(format!("{} stores replied", many.len())),
        }
        places.push(Place {
            name: "Purchases".to_string(),
            detail: parts.join(" \u{00b7} "),
            count: buyer.to_pay + buyer.replied.len(),
            // Straight to the conversations when a reply is all there is.
            page: if buyer.to_pay == 0 {
                Page::PurchaseMessages
            } else {
                Page::Purchases
            },
        });
    }
    places
}

/// What needs the person as a buyer.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct BuyerNeeds {
    /// Orders they can pay now (`order_status::buyer_can_pay`).
    pub to_pay: usize,
    /// The stores whose reply is new to them, by name, one per conversation
    /// (`message_view::is_new_reply`).
    pub replied: Vec<String>,
}

/// [`BuyerNeeds`], across every store this device has bought from or
/// written to, never one of its own.
pub(crate) fn buyer_needs(state: &AppState) -> BuyerNeeds {
    let mut needs = BuyerNeeds::default();
    for (id, store) in state.browsing_stores.iter() {
        if state.store_owner_fingerprint(id).is_some() {
            continue;
        }
        for purchase in state.buyer_purchases(id) {
            let status = super::order_status::buyer_status(state, id, &purchase);
            if super::order_status::buyer_can_pay(&purchase, status) {
                needs.to_pay += 1;
            }
        }
        for conversation in store.conversations.iter() {
            let tag = conversation.buyer_public_key;
            if let Some(summary) = super::message_view::buyer_conversation_summary(state, id, tag) {
                if super::message_view::is_new_reply(&summary, &tag) {
                    needs.replied.push(state.store_name_of(id).label());
                }
            }
        }
    }
    needs
}

/// The amber pill at the top right, and its menu when work is in more than
/// one place. Nothing at all when nothing needs the person.
#[component]
pub(crate) fn NeedsPill(places: Vec<Place>) -> Element {
    let mut open = use_signal(|| false);
    let count: usize = places.iter().map(|p| p.count).sum();
    let Some(pill) = super::app::needs_you_pill(count) else {
        return rsx! {};
    };
    let single = (places.len() == 1).then(|| places[0].page.clone());
    rsx! {
        div { class: "needs-wrap",
            // The button is the 44px tap area on a phone; the pill inside
            // stays the size of a row's pill (round-6 critique R6-4).
            button {
                class: "needs-hit",
                aria_haspopup: if single.is_none() { "true" } else { "false" },
                aria_expanded: if open() { "true" } else { "false" },
                onclick: {
                    let single = single.clone();
                    move |_| match single.clone() {
                        Some(page) => go(page),
                        None => open.toggle(),
                    }
                },
                span { class: "needs-pill", "{pill}" }
            }
            if open() && single.is_none() {
                // A click anywhere else closes it.
                button {
                    class: "needs-backdrop",
                    aria_label: "Close",
                    onclick: move |_| open.set(false),
                }
                div { class: "needs-menu", role: "menu",
                    p { class: "needs-menu-head", "Needs you" }
                    for place in places.iter() {
                        button {
                            key: "{place.page.fragment()}",
                            class: "rowcard needs-row",
                            role: "menuitem",
                            onclick: {
                                let page = place.page.clone();
                                move |_| {
                                    open.set(false);
                                    go(page.clone());
                                }
                            },
                            span { class: "rc-main",
                                span { class: "rc-name", "{place.name}" }
                                span { class: "rc-sub", "{place.detail}" }
                            }
                            span { class: "chev", aria_hidden: "true", "\u{203a}" }
                        }
                    }
                }
            }
        }
    }
}

/// The header's count, read from `APP_STATE`: what the pill shows and the
/// browser tab's title starts with.
pub(crate) fn header_places() -> Vec<Place> {
    places(&APP_STATE.read())
}
