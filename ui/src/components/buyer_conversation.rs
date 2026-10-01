//! A buyer's messages with one store (page structure P8): the thread, the
//! box to write in it, and the buyer's orders from the store beside it. One
//! conversation covers every order the buyer placed with the store, which
//! is why it is a page of its own rather than part of one order's.

use dioxus::prelude::*;

use super::router::{go, OrderAt, Page};
use crate::gateway::APP_STATE;

/// P8. `tag`: the conversation, or `None` for the one a new message starts
/// (a store with no conversation on this device yet).
#[component]
pub(crate) fn BuyerConversationPage(store: Vec<u8>, tag: Option<[u8; 32]>) -> Element {
    let mut show_ended = use_signal(|| false);
    // A reload lands here before Purchases has asked for the stores.
    use_effect(|| crate::store_link::load_visited_stores(false, true));
    let (loaded, name, keys, owned, orders, said) = {
        let state = APP_STATE.read();
        let browsing = state.browsing_stores.get(&store);
        let info = browsing.and_then(|s| s.info.as_ref());
        let key = info.and_then(|i| i.encryption_public_key);
        let identity = browsing.and_then(|s| s.seller_verifying_key);
        let orders: Vec<(Page, String, String, bool)> = tag
            .map(|tag| {
                let mut purchases: Vec<_> = state
                    .buyer_purchases(&store)
                    .into_iter()
                    .filter(|p| p.conversation == tag)
                    // Not one issued to someone else: never this buyer's
                    // order, as Purchases leaves it out too.
                    .filter(|p| {
                        !p.blockers.iter().any(|b| {
                            matches!(b, crate::state::PaymentBlocker::CommitmentNotForThisBuyer)
                        })
                    })
                    .collect();
                // Newest first, as Purchases lists them.
                purchases.sort_by_key(|p| {
                    std::cmp::Reverse(
                        p.commitment
                            .as_ref()
                            .or(p.paid.as_ref())
                            .map(|o| o.order.created_at),
                    )
                });
                purchases
                    .into_iter()
                    .map(|p| {
                        let status = super::order_status::buyer_status(&state, &store, &p);
                        let listing = state.purchase_listing(&store, &p);
                        let item = match &listing {
                            Some((_, Some(title), q)) => format!("{title}\u{a0}\u{00d7}\u{a0}{q}"),
                            Some((_, None, q)) => format!("An item no longer listed \u{00d7} {q}"),
                            None => format!("Order {}", p.order_id.short()),
                        };
                        (
                            Page::Order {
                                at: OrderAt::Store(store.clone()),
                                order: p.order_id.clone(),
                            },
                            item,
                            // With its date: two orders of one item would
                            // otherwise read alike.
                            match p.commitment.as_ref().or(p.paid.as_ref()) {
                                Some(o) => format!(
                                    "{} \u{00b7} {}",
                                    status.label(),
                                    super::order_status::short_date(o.order.created_at)
                                ),
                                None => status.label().to_string(),
                            },
                            status.ended(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let said = tag
            .and_then(|tag| super::message_view::buyer_conversation_summary(&state, &store, tag))
            .and_then(|s| s.latest_at);
        (
            info.is_some(),
            state.store_name_of(&store).label(),
            (key, identity),
            state.store_owner_fingerprint(&store).is_some(),
            orders,
            said,
        )
    };
    // Opened: the store's reply is no longer new (`message_view::is_new_reply`).
    use_effect(use_reactive!(|(tag, said)| {
        if let (Some(tag), Some(said)) = (tag, said) {
            let seen = super::message_view::SEEN_CONVERSATIONS
                .peek()
                .get(&tag)
                .copied();
            if seen != Some(said) {
                super::message_view::SEEN_CONVERSATIONS
                    .write()
                    .insert(tag, said);
            }
        }
    }));
    // A first message starts a conversation: this page then follows it,
    // so what was just sent shows here and Back is not left on an empty
    // page (review of #214).
    let started = tag.is_none().then(|| {
        APP_STATE
            .read()
            .browsing_stores
            .get(&store)
            .and_then(|s| s.conversations.last())
            .map(|c| c.buyer_public_key)
    });
    let here = store.clone();
    use_effect(use_reactive!(|(started, here)| {
        if let Some(Some(tag)) = started {
            super::router::replace(Page::Conversation {
                store: here.clone(),
                tag: Some(tag),
            });
        }
    }));
    let has_messages =
        super::message_view::buyer_thread_has_messages(&APP_STATE.read(), &store, tag);
    let unreachable =
        !loaded && APP_STATE.read().store_name_of(&store) == crate::state::StoreName::Unreachable;

    rsx! {
        super::seller_pages::BackTo { label: "Messages".to_string(), page: Page::PurchaseMessages }
        h2 { class: "page-h", "Messages with {name}" }
        div { class: "two-col",
            div { class: "col-main",
                if unreachable {
                    p { class: "text-warning", "That store didn\u{2019}t load. It may not be reachable right now." }
                } else if !loaded {
                    p { class: "text-muted text-italic", "Loading this store\u{2026}" }
                } else {
                    if has_messages {
                        super::message_view::Thread { store_contract_id: store.clone(), tag }
                    } else {
                        p { class: "text-muted", "No messages yet." }
                    }
                    if owned {
                        p { class: "text-muted small", "This is your own store." }
                    } else {
                        match keys {
                            (Some(key), Some(identity)) => rsx! {
                                super::message_view::Compose {
                                    store_contract_id: store.clone(),
                                    seller_encryption_key: key,
                                    seller_verifying_key: identity,
                                    target: tag,
                                    label: "Your message".to_string(),
                                    placeholder: format!("Write to {name}"),
                                    hint: format!(
                                        "Only {name} can read this. They see it the next time they \
                                         open Harvest, and their reply appears here, on this device."
                                    ),
                                }
                            },
                            // The seller published no key. Nothing can be
                            // encrypted to them, and putting plaintext into a
                            // world-readable contract would be worse than
                            // sending nothing.
                            (None, _) => rsx! {
                                super::message_view::Unavailable {
                                    why: "This seller has not published an encryption key, so there \
                                          is no way to send them a private message. Stores created \
                                          before Harvest supported messaging are in this state until \
                                          the seller publishes their details again."
                                        .to_string(),
                                }
                            },
                            // A key was published, but this build cannot work
                            // out where the seller's mailbox is.
                            (Some(_), None) => rsx! {
                                super::message_view::Unavailable {
                                    why: "Harvest cannot confirm this store\u{2019}s identity, so it \
                                          cannot work out where the seller\u{2019}s mailbox is. Either \
                                          the store\u{2019}s backing does not check out, or the store \
                                          was published by a newer version of Harvest than this one. \
                                          A message sent anyway could land in a stranger\u{2019}s \
                                          mailbox, so nothing is sent."
                                        .to_string(),
                                }
                            },
                        }
                    }
                }
            }
            aside { class: "col-side",
                p { class: "side-lbl", "Your orders from this store" }
                if orders.is_empty() {
                    p { class: "text-muted small", "None in this conversation." }
                }
                // Ended ones folded, as on Purchases, so this counts what
                // the store's page and the Messages list count (C2).
                for (page , item , status , _) in orders.iter().filter(|o| !o.3 || show_ended()) {
                    button {
                        key: "{page.fragment()}",
                        class: "side-row",
                        onclick: {
                            let page = page.clone();
                            move |_| go(page.clone())
                        },
                        span { class: "rc-main",
                            span { class: "side-row-name", "{item}" }
                            span { class: "rc-sub", "{status}" }
                        }
                        span { class: "chev", aria_hidden: "true", "\u{203a}" }
                    }
                }
                if orders.iter().any(|o| o.3) {
                    button {
                        class: "link-btn side-link",
                        onclick: move |_| show_ended.toggle(),
                        if show_ended() {
                            "Hide ended orders"
                        } else {
                            {format!("Show {}", super::needs::plural(orders.iter().filter(|o| o.3).count(), "ended order", "ended orders"))}
                        }
                    }
                }
                button {
                    class: "link-btn side-link",
                    onclick: {
                        let store = store.clone();
                        move |_| super::app::show_store(store.clone())
                    },
                    "View store"
                }
                if let Some(tag) = tag {
                    div { class: "side-cancel",
                        super::message_view::ForgetConversation { store_contract_id: store.clone(), tag }
                    }
                }
            }
        }
    }
}
