//! A seller's pages for one store (page structure S2 to S9): the store's
//! header (name, Open or Closed and why, the trust line, View store, Share)
//! and its tabs Home, Orders, Messages, Listings, Settings. Lists open
//! detail pages: an order row opens the order's page (Mark as sent and the
//! address are there), a conversation row opens the conversation.
//!
//! What a page shows is read from the same state and helpers the old
//! single-page dashboard used (`my_store::seller_stores`,
//! `message_view::seller_inbox`, `AppState::seller_order_requests`), so
//! moving things between pages changed where they are, not what they say.

use std::collections::HashMap;

use dioxus::prelude::*;
use harvest_common::payment::{AuthorizedOrder, OrderId};

use super::my_store::{seller_stores, SellerStore};
use super::order_status::{self, Status};
use super::router::{go, OrderFilter, Page, SellerTab, SellerView, StoreTab};
use crate::gateway::APP_STATE;
use crate::state::{AppState, SellerRequest};

/// The seller's pages: one of their stores (`store`, or the first when
/// `None`) on `view`, or opening a first store when they have none.
/// Re-render once the wait for this node's store lists runs out (counted
/// from the app's start), so a page waiting on them never says "Checking"
/// for good, as the Stores page does.
pub(crate) fn use_known_clock() {
    #[allow(unused_mut)]
    let mut clock = use_signal(|| 0u32);
    #[cfg(target_arch = "wasm32")]
    use_future(move || async move {
        let deadline = APP_STATE
            .peek()
            .session_started
            .0
            .saturating_add(crate::state::SELLER_ANSWER_WAIT_MS);
        let left = deadline.saturating_sub(crate::state::now_ms());
        if left > 0 {
            gloo_timers::future::TimeoutFuture::new(left.saturating_add(50).min(60_000) as u32)
                .await;
            clock += 1;
        }
    });
    let _ = clock();
}

#[component]
pub(crate) fn SellerPages(store: Option<Vec<u8>>, view: SellerView) -> Element {
    use_known_clock();
    let (stores, known) = {
        let state = APP_STATE.read();
        (
            seller_stores(&state),
            state.seller_known_or_waited(crate::state::now_ms()),
        )
    };
    if stores.is_empty() {
        if !known {
            return rsx! {
                p { class: "text-muted text-italic", "Checking your stores\u{2026}" }
            };
        }
        return rsx! {
            super::open_store::OpenStore { another: false }
        };
    }
    let current = match store.as_ref() {
        Some(id) => stores.iter().find(|s| &s.contract_id == id).cloned(),
        None => Some(stores[0].clone()),
    };
    let Some(current) = current else {
        // A store named by a reload or a link that is not (yet) among this
        // device's own: its registration may still be on its way.
        return rsx! {
            BackTo { label: "Stores", page: Page::Stores }
            p { class: "text-muted text-italic", "Loading your store\u{2026}" }
        };
    };
    let others: Vec<(Vec<u8>, String)> = stores
        .iter()
        .map(|s| (s.contract_id.clone(), s.label.clone()))
        .collect();
    let id = current.contract_id.clone();
    // A store closed for good is only read (harvest#181): no Listings or
    // Settings, whose controls would still sign changes to it. A link or a
    // reload to one of them opens Home.
    let view = match view {
        SellerView::Listings
        | SellerView::AddListing
        | SellerView::EditListing(_)
        | SellerView::Settings
            if current.closed =>
        {
            SellerView::Home
        }
        view => view,
    };
    rsx! {
        div { class: "seller-pages",
            StoreHeader { store: current.clone(), stores: others, tab: view.tab() }
            match view {
                SellerView::Home => rsx! { SellerHome { store: current.clone() } },
                SellerView::Orders(filter) => rsx! { SellerOrders { store: current.clone(), filter } },
                SellerView::Order(order) => rsx! { SellerOrderPage { store: current.clone(), order } },
                SellerView::Messages => rsx! { SellerMessages { store: current.clone() } },
                SellerView::Conversation(tag) => rsx! { SellerConversationPage { store: current.clone(), tag } },
                SellerView::Listings => rsx! {
                    super::seller_listings::SellerListings {
                        store_contract_id: id.clone(),
                        fingerprint: current.fingerprint.clone(),
                    }
                },
                SellerView::AddListing => rsx! {
                    super::seller_listings::ListingFormPage {
                        store_contract_id: id.clone(),
                        fingerprint: current.fingerprint.clone(),
                        editing: None,
                    }
                },
                SellerView::EditListing(listing) => rsx! {
                    super::seller_listings::ListingFormPage {
                        store_contract_id: id.clone(),
                        fingerprint: current.fingerprint.clone(),
                        editing: Some(listing),
                    }
                },
                SellerView::Settings => rsx! { SellerSettings { store: current.clone() } },
            }
        }
    }
}

/// "‹ Orders": the way back to the page a detail page was opened from. The
/// browser's Back works too; this is the one on the page.
#[component]
pub(crate) fn BackTo(label: String, page: Page) -> Element {
    rsx! {
        button {
            class: "crumb",
            onclick: move |_| go(page.clone()),
            "\u{2039} {label}"
        }
    }
}

/// The seller's page for `store` on `view`.
pub(crate) fn seller_page(store: &[u8], view: SellerView) -> Page {
    Page::Seller {
        store: Some(store.to_vec()),
        view,
    }
}

/// The pill for one of the seller's own stores that buyers can't buy from
/// for a reason the seller has to fix here, naming it, so "Closed" is never
/// said without why (#181 handoff, section D): closed for good, a Ghost Key
/// backing two stores, or the listing or payout wallet a store needs before
/// it tells buyers it is open (`instant_checkout_stores` arms a store, and
/// so starts its presence, only with a buyable instant-checkout listing, and
/// it answers orders only with a payout wallet). `None` while the store is
/// still loading, or when nothing here is missing.
pub(crate) fn closed_reason(state: &AppState, store: &SellerStore) -> Option<&'static str> {
    if store.closed {
        return Some("Closed for good");
    }
    if store.key_conflict.is_some() {
        return Some("Closed: one Ghost Key, two stores");
    }
    let browsing = state
        .browsing_stores
        .get(&store.contract_id)
        .filter(|b| b.info.is_some())?;
    let sells = browsing.listings.iter().any(|l| {
        l.listing.offers_instant_checkout()
            && state
                .listing_availability(&store.contract_id, &l.listing.id)
                .is_buyable()
    });
    let no_wallet = state.bitcoin.payment_xpub_loaded && state.bitcoin.payment_xpub.is_none();
    match (sells, no_wallet) {
        (true, false) => None,
        (true, true) => Some("Closed: add a payout wallet"),
        (false, true) if store.listings == 0 => Some("Closed: add a listing and a payout wallet"),
        (false, _) if store.listings == 0 => Some("Closed: add a listing"),
        (false, _) if store.unpriced > 0 => Some("Closed: give a listing a price"),
        (false, _) => Some("Closed: nothing left on sale"),
    }
}

/// What buyers see of the store, and whether they can buy, as its header
/// says it: the reason the seller must fix, if there is one
/// ([`closed_reason`]); else the seller's own status
/// (`presence_flow::seller_status`) for a store that sells here; else the
/// buyer's answer (`AppState::buyer_open`).
pub(crate) fn header_status(
    state: &AppState,
    store: &SellerStore,
) -> (&'static str, bool, Option<String>, Option<String>) {
    let now = crate::state::now_ms();
    if let Some(reason) = closed_reason(state, store) {
        // Closed for good says what is left; the rest are said by the pill
        // and fixed from the To do list or Finish setting up.
        let line = store.closed.then(|| {
            "Buyers can\u{2019}t buy from this store again. Its orders stay here for you to read."
                .to_string()
        });
        return (reason, false, line, None);
    }
    let store_contract_id = store.contract_id.as_slice();
    match state.instant_checkout_local(store_contract_id, now) {
        Some(local) => {
            let status = crate::presence_flow::seller_status(
                state.store_presence(store_contract_id, now),
                state.wakeups_seen_recently(now),
                &local,
            );
            // The line only when buyers can't buy, or there is a caution:
            // "Buyers can buy now" under an Open pill says it twice.
            let line = (!status.open).then(|| status.line.clone());
            (status.pill, status.open, line, status.why_not)
        }
        None => {
            let open = state.buyer_open(store_contract_id, now);
            (
                open.pill(),
                open == crate::state::BuyerOpen::Open,
                None,
                None,
            )
        }
    }
}

/// The store's header on every seller page (rule 2: status and identity in
/// the header, never a panel of their own), and the tabs under it.
#[component]
fn StoreHeader(store: SellerStore, stores: Vec<(Vec<u8>, String)>, tab: SellerTab) -> Element {
    let mut sharing = use_signal(|| false);
    let mut switching = use_signal(|| false);
    // Open or closed is judged against the clock, so the header re-renders
    // every half minute, as the store page does.
    #[allow(unused_mut)]
    let mut clock = use_signal(|| 0u32);
    #[cfg(target_arch = "wasm32")]
    use_future(move || async move {
        loop {
            gloo_timers::future::TimeoutFuture::new(30_000).await;
            clock += 1;
        }
    });
    let _ = clock();
    let (pill, open, line, why, trust) = {
        let state = APP_STATE.read();
        let (pill, open, line, why) = header_status(&state, &store);
        let trust = state
            .browsing_stores
            .get(&store.contract_id)
            .filter(|b| b.info.is_some())
            .map(super::store_view::trust_parts);
        (pill, open, line, why, trust)
    };
    let id = store.contract_id.clone();
    let orders_count = store.to_send + store.to_confirm;
    let messages_count = store.replies + store.requests;
    rsx! {
        div { class: "store-head",
            div { class: "store-head-main",
                div { class: "store-head-title",
                    h2 { class: "store-title", "{store.label}" }
                    if stores.len() > 1 {
                        div { class: "switch-wrap",
                            button {
                                class: "switch-btn",
                                aria_label: "Switch store",
                                aria_haspopup: "true",
                                aria_expanded: if switching() { "true" } else { "false" },
                                onclick: move |_| switching.toggle(),
                                "\u{25be}"
                            }
                            if switching() {
                                button {
                                    class: "needs-backdrop",
                                    aria_label: "Close",
                                    onclick: move |_| switching.set(false),
                                }
                                div { class: "needs-menu switch-menu", role: "menu",
                                    p { class: "needs-menu-head", "Your stores" }
                                    for (other , name) in stores.iter() {
                                        button {
                                            key: "{bs58::encode(other).into_string()}",
                                            class: if *other == id { "switch-row current" } else { "switch-row" },
                                            role: "menuitem",
                                            onclick: {
                                                let other = other.clone();
                                                move |_| {
                                                    switching.set(false);
                                                    go(seller_page(&other, tab.view()));
                                                }
                                            },
                                            "{name}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                    span { class: if open { "pill pill-open" } else { "pill" }, "{pill}" }
                }
                if let Some((backing, record)) = trust {
                    p { class: "trust",
                        "{backing} \u{00b7} "
                        button {
                            class: "link-btn trust-record",
                            onclick: {
                                let id = id.clone();
                                move |_| go(Page::Store { store: id.clone(), tab: StoreTab::Record })
                            },
                            "{record}"
                        }
                    }
                }
                // Why buyers can't buy, said on Home, where the seller works
                // from; the pill alone on the other tabs, so a page's own
                // task is not pushed down (critique C14).
                if tab == SellerTab::Home {
                    if let Some(line) = line {
                        p { class: "store-head-line", "{line}" }
                    }
                    if let Some(why) = why {
                        p { class: if open { "text-muted small" } else { "text-warning" }, "{why}" }
                    }
                }
            }
            div { class: "store-head-acts",
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: {
                        let id = id.clone();
                        move |_| super::app::show_store(id.clone())
                    },
                    "View store"
                }
                if store.link.is_some() && !store.closed {
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: move |_| sharing.set(true),
                        "Share"
                    }
                }
            }
        }
        div { class: "tabs", role: "tablist",
            for t in SellerTab::ALL
                .into_iter()
                .filter(|t| !store.closed || !matches!(t, SellerTab::Listings | SellerTab::Settings))
            {
                button {
                    class: if tab == t { "tab active" } else { "tab" },
                    role: "tab",
                    aria_selected: if tab == t { "true" } else { "false" },
                    onclick: {
                        let id = id.clone();
                        move |_| go(seller_page(&id, t.view()))
                    },
                    "{t.label()}"
                    // What needs the seller there, in the one colour that
                    // means it (critique S9-10).
                    if t == SellerTab::Orders && orders_count > 0 {
                        " "
                        span { class: "tab-needs", "{orders_count}" }
                    }
                    if t == SellerTab::Messages && messages_count > 0 {
                        " "
                        span { class: "tab-needs", "{messages_count}" }
                    }
                }
            }
        }
        if sharing() {
            ShareDialog { store: store.clone(), on_close: move |_| sharing.set(false) }
        }
    }
}

/// Share: one link to copy, and the store's code under it (critique 09-7).
#[component]
fn ShareDialog(store: SellerStore, on_close: EventHandler<()>) -> Element {
    rsx! {
        button {
            class: "modal-backdrop",
            aria_label: "Close",
            onclick: move |_| on_close.call(()),
        }
        div { class: "modal", role: "dialog", aria_label: "Share your store",
            h3 { "Share {store.label}" }
            p { class: "text-muted small",
                "Anyone can open this link, with or without Freenet. It offers to open your store \
                 in Freenet or straight in their browser."
            }
            if let Some(ref link) = store.link {
                super::pay_card::CopyField { label: "Link", value: link.clone(), salt: "share".to_string() }
            }
            if let Some(ref code) = store.code {
                super::pay_card::CopyField {
                    label: "Or the store code, to type into Stores",
                    value: code.clone(),
                    salt: "share".to_string(),
                }
            }
            div { class: "form-actions",
                button { class: "btn btn-sm btn-outline", onclick: move |_| on_close.call(()), "Done" }
            }
        }
    }
}

// ---- What the order and message pages share ----

/// A name for a buyer from what they typed as their address: its first line
/// up to the first comma, at most three words ("Jane Doe, 1 Main St" is
/// "Jane Doe"). `None` when there is nothing to go on, or the address is
/// hidden (`fulfilment::ADDRESS_HIDDEN`). A guess, said as one: the orders
/// listed beside a conversation are what identify the buyer (msg critique
/// MSG-10).
pub(crate) fn name_from_address(shipping: &str) -> Option<String> {
    if shipping == crate::fulfilment::ADDRESS_HIDDEN {
        return None;
    }
    let first = shipping.lines().find(|l| !l.trim().is_empty())?;
    // Up to the first comma or bracket, so a name is never cut inside one.
    let head = first.split([',', '(', ';']).next()?.trim();
    let words: Vec<&str> = head.split_whitespace().take(3).collect();
    // Whole words only, within 28 characters.
    let mut name = String::new();
    for word in words {
        if name.chars().count() + word.chars().count() + 1 > 28 && !name.is_empty() {
            break;
        }
        if !name.is_empty() {
            name.push(' ');
        }
        name.push_str(word);
    }
    (!name.is_empty() && name.chars().any(char::is_alphabetic)).then_some(name)
}

/// Everything the Orders, Messages and Home pages read about one store's
/// orders and conversations, worked out once per render.
pub(crate) struct SellerData {
    /// The seller's orders, newest first (`invoices_issued_by`).
    pub orders: Vec<AuthorizedOrder>,
    /// What each order's buyer asked for.
    pub requests: HashMap<OrderId, SellerRequest>,
    pub inbox: super::message_view::SellerInbox,
    /// A name for each conversation's buyer ([`name_from_address`], or
    /// "Buyer 2").
    pub names: HashMap<[u8; 32], String>,
    /// The conversation each order belongs to, where this device reads it.
    pub thread_of: HashMap<OrderId, [u8; 32]>,
    /// Whether the store's state has arrived: "no orders" and "not loaded
    /// yet" look alike through an empty list.
    pub loaded: bool,
    /// Requests waiting for an invoice, by conversation tag
    /// (`message_view::requests_awaiting_invoice_by_tag`): never a Buy now.
    pub invoice_requests: std::collections::BTreeMap<Vec<u8>, usize>,
}

impl SellerData {
    pub(crate) fn of(state: &AppState, store: &SellerStore) -> SellerData {
        let id = &store.contract_id;
        let orders = super::invoice_form::invoices_issued_by(
            state
                .browsing_stores
                .get(id)
                .map(|s| s.orders.as_slice())
                .unwrap_or_default(),
            &store.fingerprint,
            |order| state.withheld_settlements.contains_key(order),
        );
        let requests: HashMap<OrderId, SellerRequest> = orders
            .iter()
            .zip(state.seller_order_requests(id, &orders))
            .map(|(order, request)| (order.order.id.clone(), request))
            .collect();
        let inbox = super::message_view::seller_inbox(state, id);
        let thread_of: HashMap<OrderId, [u8; 32]> = inbox
            .by_order()
            .into_iter()
            .map(|(order, thread)| (order.clone(), thread.tag))
            .collect();
        // Named from the first of its orders with a readable address; the
        // rest numbered in the order they first wrote.
        let mut names: HashMap<[u8; 32], String> = HashMap::new();
        let mut unnamed: Vec<(Option<chrono::DateTime<chrono::Utc>>, [u8; 32])> = Vec::new();
        for thread in inbox.threads.iter() {
            // From the newest of its orders with a readable address (the
            // orders are newest first): one name for one buyer on every page.
            let named = orders
                .iter()
                .filter(|o| thread.orders.contains(&o.order.id))
                .find_map(|order| match requests.get(&order.order.id) {
                    Some(SellerRequest::Found(r)) => name_from_address(&r.shipping),
                    _ => None,
                });
            match named {
                Some(name) => {
                    names.insert(thread.tag, name);
                }
                None => unnamed.push((
                    thread
                        .entries
                        .iter()
                        .map(crate::messaging::MailboxEntry::timestamp)
                        .min(),
                    thread.tag,
                )),
            }
        }
        unnamed.sort();
        for (n, (_, tag)) in unnamed.into_iter().enumerate() {
            names.insert(tag, format!("Buyer {}", n + 1));
        }
        SellerData {
            orders,
            requests,
            inbox,
            names,
            thread_of,
            loaded: state.store_details_are_resolved(id),
            invoice_requests: super::message_view::requests_awaiting_invoice_by_tag(state, id),
        }
    }

    /// The name of `order`'s buyer: their conversation's, so one buyer has
    /// one name on every page; else from the order's own address; else "A
    /// buyer".
    pub(crate) fn buyer_of(&self, order: &OrderId) -> String {
        self.thread_of
            .get(order)
            .and_then(|t| self.names.get(t))
            .cloned()
            .or_else(|| self.ship_name_of(order))
            .unwrap_or_else(|| "A buyer".to_string())
    }

    /// Who `order` goes to, from its own address: "Send it to" names this
    /// order's recipient, who may not be the buyer (a gift).
    pub(crate) fn ship_name_of(&self, order: &OrderId) -> Option<String> {
        match self.requests.get(order) {
            Some(SellerRequest::Found(r)) => name_from_address(&r.shipping),
            _ => None,
        }
    }

    /// What `order` was for, "Stoneware mug \u{00d7} 1", or its reference
    /// when its request can't be read here.
    pub(crate) fn item_of(&self, order: &AuthorizedOrder) -> String {
        match self.requests.get(&order.order.id) {
            Some(SellerRequest::Found(r)) => format!(
                "{}\u{a0}\u{00d7}\u{a0}{}",
                r.title.as_deref().unwrap_or("An item no longer listed"),
                r.quantity
            ),
            _ => format!("Order {}", order.order.id.short()),
        }
    }

    /// The listing `order` was for, when its request names it.
    pub(crate) fn listing_of(
        &self,
        order: &OrderId,
    ) -> Option<(harvest_common::listing::ListingId, String)> {
        match self.requests.get(order) {
            Some(SellerRequest::Found(r)) => r
                .listing_id
                .clone()
                .map(|id| (id, r.title.clone().unwrap_or_default())),
            _ => None,
        }
    }

    /// Whether `order`'s buyer is waiting for the seller's reply.
    pub(crate) fn new_message(&self, order: &OrderId) -> bool {
        self.thread_of
            .get(order)
            .and_then(|tag| self.inbox.threads.iter().find(|t| t.tag == *tag))
            .is_some_and(|thread| thread.awaiting_reply)
    }
}

/// The amount, as every price reads (rule 7): "0.00010000 tBTC".
pub(crate) fn order_amount(order: &AuthorizedOrder) -> String {
    super::pay_card::money(order.order.amount_sats, order.order.network)
}

/// When `order` was paid, roughly, as a day: from its stage, else its date.
fn paid_date(state: &AppState, order: &AuthorizedOrder) -> Option<String> {
    let tip = state.tip_height(order.order.network)?;
    let paid_at = crate::fulfilment::paid_height(order)?;
    Some(crate::fulfilment::approx_date(
        paid_at,
        tip,
        crate::state::now_ms(),
    ))
}

// ---- S2: Home ----

/// One row of the Home page's To do list.
#[derive(Clone, PartialEq)]
struct TodoRow {
    title: String,
    sub: String,
    pill: Option<String>,
    thumb: Option<String>,
    page: Page,
}

/// What needs the seller in this store, as a list to work through; what is
/// left to set up; and one line of this week's numbers.
#[component]
fn SellerHome(store: SellerStore) -> Element {
    let id = store.contract_id.clone();
    let (rows, notes, setup, numbers) = {
        let state = APP_STATE.read();
        let data = SellerData::of(&state, &store);
        let mut rows: Vec<TodoRow> = Vec::new();
        // One Ghost Key behind two stores (harvest#181): nobody can buy from
        // either until one is closed for good, which is done in Settings.
        if let Some(ref conflict) = store.key_conflict {
            let n = conflict.others.len() + 1;
            rows.push(TodoRow {
                title: match conflict.closing {
                    Some(ref name) => format!("Closing {name}\u{2026}"),
                    None if n == 2 => "Close one of your two stores".to_string(),
                    None => format!("Close all but one of your {n} stores"),
                },
                sub: format!(
                    "Your Ghost Key backs {n} stores, and it can back only one, so buyers \
                     can\u{2019}t buy from any of them."
                ),
                pill: Some("Buyers can\u{2019}t buy".to_string()),
                thumb: None,
                page: seller_page(&id, SellerView::Settings),
            });
        }
        // Orders to send, the one thing a seller must not miss, soonest
        // first.
        let mut sending = state.seller_orders_to_send(&id, &store.fingerprint);
        sending.sort_by_key(|o| match order_status::stage_of(&state, o) {
            crate::fulfilment::OrderStage::AwaitingDespatch { despatch_by, .. }
            | crate::fulfilment::OrderStage::DespatchWindowClosed { despatch_by, .. } => {
                despatch_by
            }
            _ => u32::MAX,
        });
        for order in sending {
            let paid = paid_date(&state, &order)
                .map(|d| format!("Paid {d}"))
                .unwrap_or_else(|| "Paid".to_string());
            rows.push(TodoRow {
                title: format!(
                    "Send {} to {}",
                    data.item_of(&order),
                    data.ship_name_of(&order.order.id)
                        .unwrap_or_else(|| data.buyer_of(&order.order.id))
                ),
                sub: paid,
                pill: order_status::send_by_pill(&state, &order),
                thumb: data
                    .listing_of(&order.order.id)
                    .and_then(|(l, t)| super::item_image::listing_image(&l, &t)),
                page: seller_page(&id, SellerView::Order(order.order.id.clone())),
            });
        }
        // Payments held for the seller to say which order they are for.
        let sending: Vec<OrderId> = state
            .seller_orders_to_send(&id, &store.fingerprint)
            .into_iter()
            .map(|o| o.order.id)
            .collect();
        for order in data.orders.iter().filter(|o| {
            state.withheld_settlements.contains_key(&o.order.id) && !sending.contains(&o.order.id)
        }) {
            rows.push(TodoRow {
                title: format!("Say which order a payment is for: {}", data.item_of(order)),
                sub: format!("Order {}", order.order.id.short()),
                pill: Some("Payment to match".to_string()),
                thumb: None,
                page: seller_page(&id, SellerView::Order(order.order.id.clone())),
            });
        }
        // Buyers waiting for a reply, and requests waiting for an answer.
        for thread in data.inbox.threads.iter() {
            let name = data.names.get(&thread.tag).cloned().unwrap_or_default();
            if thread.awaiting_reply {
                rows.push(TodoRow {
                    title: format!("Reply to {name}"),
                    sub: thread
                        .latest_from_buyer()
                        .map(|(text, _)| format!("\u{201c}{}\u{201d}", one_line(&text)))
                        .unwrap_or_default(),
                    pill: Some("Waiting for your reply".to_string()),
                    thumb: None,
                    page: seller_page(&id, SellerView::Conversation(thread.tag)),
                });
            }
            if data
                .invoice_requests
                .get(thread.tag.as_slice())
                .is_some_and(|n| *n > 0)
            {
                rows.push(TodoRow {
                    title: format!("Answer {name}\u{2019}s order"),
                    sub: "They asked to buy. Accept to send them an order to pay.".to_string(),
                    pill: Some("Needs an invoice".to_string()),
                    thumb: None,
                    page: seller_page(&id, SellerView::Conversation(thread.tag)),
                });
            }
        }
        // Invoices nobody can pay any more, still open.
        for order in data.orders.iter().filter(|o| {
            !crate::fulfilment::is_unpaid_buy_now(o)
                && state.needs_reissue(o)
                && order_status::seller_status(&state, &id, o) == Status::WaitingForPayment
        }) {
            rows.push(TodoRow {
                title: format!("Cancel expired order {}", order.order.id.short()),
                sub: "Too old for a buyer to pay. The buyer can order again.".to_string(),
                pill: None,
                thumb: None,
                page: seller_page(&id, SellerView::Order(order.order.id.clone())),
            });
        }
        // Listings nobody can buy until they have a price. Not for a store
        // closed for good: nothing about selling is left to do there.
        if let Some(browsing) = state.browsing_stores.get(&id).filter(|_| !store.closed) {
            for listing in browsing.listings.iter().filter(|l| {
                browsing.availability(&l.listing.id)
                    != harvest_common::listing::ListingAvailability::Withdrawn
                    && !l.listing.offers_instant_checkout()
            }) {
                rows.push(TodoRow {
                    title: format!("Give {} a price", listing.listing.title),
                    sub: "Buyers can\u{2019}t buy it until it has one.".to_string(),
                    pill: None,
                    thumb: super::item_image::listing_image(
                        &listing.listing.id,
                        &listing.listing.title,
                    ),
                    page: seller_page(&id, SellerView::EditListing(listing.listing.id.clone())),
                });
            }
        }
        // Things to fix that are not a row's job: said as lines.
        let mut notes: Vec<(String, Option<(&'static str, Page)>)> = Vec::new();
        if let Some(ref refusal) = store.foreign_owner {
            notes.push((refusal.clone(), None));
        }
        if store.details_resolved && !store.closed {
            if let Some(gap) = store.gap {
                notes.push((
                    gap.message().to_string(),
                    Some(("Open Settings", seller_page(&id, SellerView::Settings))),
                ));
            }
            if !store.certificate.is_verified() {
                notes.push((
                    match store.certificate.detail() {
                        Some(why) => format!(
                            "Buyers see this store as unbacked: {} ({why}).",
                            store.certificate.label()
                        ),
                        None => format!(
                            "Buyers see this store as unbacked: {}.",
                            store.certificate.label()
                        ),
                    },
                    None,
                ));
            }
        }
        if let Some(limit) = state.wallet_gap_note_due(&id) {
            notes.push((super::my_store::wallet_gap_note(limit), None));
        }
        // A closed store's alerts are about its orders only (an oversold
        // order still needs sending), not its selling cap.
        let alerts = if store.closed {
            state.instant_checkout_order_alerts(&id)
        } else {
            state.instant_checkout_alerts(&id)
        };
        for alert in alerts {
            notes.push((alert, None));
        }
        let has_wallet = state.bitcoin.payment_xpub.is_some();
        let wallet_known = state.bitcoin.payment_xpub_loaded;
        let details_done = store.details_resolved && store.gap.is_none();
        // Nothing to set up on a store closed for good.
        let set_up = store.closed || (details_done && has_wallet && store.listings > 0);
        let setup = (!set_up).then_some(Setup {
            details: details_done,
            wallet: has_wallet,
            wallet_known,
            listing: store.listings > 0,
            resolved: store.details_resolved,
        });
        let numbers = week_numbers(&state, &store, &data);
        (rows, notes, setup, numbers)
    };

    rsx! {
        section { class: "page-sec",
            h3 { class: "sec-lbl sec-lbl-first", "To do" }
            if !store.details_resolved {
                p { class: "text-muted text-italic", "Loading this store\u{2019}s details\u{2026}" }
            } else if rows.is_empty() && notes.is_empty() {
                p { class: "text-muted", "Nothing needs you right now." }
            }
            for row in rows.iter() {
                button {
                    key: "{row.page.fragment()}-{row.title}",
                    class: "rowcard",
                    onclick: {
                        let page = row.page.clone();
                        move |_| go(page.clone())
                    },
                    super::item_image::RowThumb { src: row.thumb.clone() }
                    span { class: "rc-main",
                        span { class: "rc-name", "{row.title}" }
                        if !row.sub.is_empty() {
                            span { class: "rc-sub", "{row.sub}" }
                        }
                    }
                    if let Some(ref pill) = row.pill {
                        span { class: "rc-status",
                            span { class: "pill pill-needs", "{pill}" }
                        }
                    }
                    span { class: "chev", aria_hidden: "true", "\u{203a}" }
                }
            }
            for (note , link) in notes.iter() {
                div { class: "todo-note",
                    p { class: "text-warning", "{note}" }
                    if let Some((label, page)) = link.clone() {
                        button { class: "link-btn", onclick: move |_| go(page.clone()), "{label}" }
                    }
                }
            }
        }
        if let Some(setup) = setup {
            section { class: "page-sec",
                h3 { class: "sec-lbl", "Finish setting up" }
                ul { class: "checklist",
                    li { class: "done", "Store opened" }
                    li { class: if setup.details { "done" } else { "" },
                        "Name and description published"
                        if !setup.details && setup.resolved {
                            button {
                                class: "link-btn",
                                onclick: {
                                    let id = id.clone();
                                    move |_| go(seller_page(&id, SellerView::Settings))
                                },
                                "Open Settings"
                            }
                        }
                    }
                    li { class: if setup.wallet { "done" } else { "" },
                        "Payout wallet"
                        if !setup.wallet && setup.wallet_known {
                            button {
                                class: "link-btn",
                                onclick: {
                                    let id = id.clone();
                                    move |_| go(seller_page(&id, SellerView::Settings))
                                },
                                "Add one"
                            }
                        }
                    }
                    li { class: if setup.listing { "done" } else { "" },
                        "Your first listing"
                        if !setup.listing {
                            button {
                                class: "link-btn",
                                onclick: {
                                    let id = id.clone();
                                    move |_| go(seller_page(&id, SellerView::AddListing))
                                },
                                "Add a listing"
                            }
                        }
                    }
                }
                p { class: "text-muted small", "When it\u{2019}s ready, share your store with the Share button above." }
            }
        }
        if let Some(numbers) = numbers {
            p { class: "text-muted small week-line", "{numbers}" }
        }
    }
}

/// What is left to set up, from the store's real state.
#[derive(Clone, Copy, PartialEq)]
struct Setup {
    details: bool,
    wallet: bool,
    wallet_known: bool,
    listing: bool,
    resolved: bool,
}

/// One line for a row: a message's first line, cut at 90 characters.
pub(crate) fn one_line(text: &str) -> String {
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_default()
        .trim();
    let mut cut: String = first.chars().take(90).collect();
    if first.chars().count() > 90 || text.trim().lines().count() > 1 {
        cut.push('\u{2026}');
    }
    cut
}

/// "Last 7 days: 3 orders paid, 2 sent. 6 listings, 1 sold out." Orders by
/// their own date (the buyer's Buy now), never a guess at a block's.
fn week_numbers(state: &AppState, store: &SellerStore, data: &SellerData) -> Option<String> {
    let week_ago = chrono::Utc::now() - chrono::Duration::days(7);
    let recent: Vec<&AuthorizedOrder> = data
        .orders
        .iter()
        .filter(|o| o.order.created_at >= week_ago)
        .collect();
    let paid = recent
        .iter()
        .filter(|o| {
            matches!(
                order_status::seller_status(state, &store.contract_id, o),
                Status::Paid | Status::Sent | Status::Complete | Status::Reported
            )
        })
        .count();
    let sent = recent
        .iter()
        .filter(|o| state.despatch_recorded(&store.contract_id, &o.order.id))
        .count();
    let sold_out = state
        .browsing_stores
        .get(&store.contract_id)
        .map(|b| {
            b.listings
                .iter()
                .filter(|l| {
                    matches!(
                        b.availability(&l.listing.id),
                        harvest_common::listing::ListingAvailability::SoldOut
                            | harvest_common::listing::ListingAvailability::Available {
                                quantity: Some(0)
                            }
                    )
                })
                .count()
        })
        .unwrap_or(0);
    if !data.loaded || (store.listings == 0 && data.orders.is_empty()) {
        return None;
    }
    let mut line = format!(
        "Last 7 days: {} paid, {} sent. {}",
        super::needs::plural(paid, "order", "orders"),
        sent,
        super::needs::plural(store.listings, "listing", "listings")
    );
    if sold_out > 0 {
        line.push_str(&format!(", {sold_out} sold out"));
    }
    line.push('.');
    Some(line)
}

// ---- S3: Orders ----

/// The filter an order falls under, by where it stands.
fn filter_of(status: Status, to_send: bool) -> OrderFilter {
    if to_send {
        return OrderFilter::ToSend;
    }
    match status {
        Status::Sent => OrderFilter::Sent,
        Status::Complete => OrderFilter::Complete,
        _ => OrderFilter::All,
    }
}

/// One row of the Orders list.
#[derive(Clone, PartialEq)]
struct OrderRow {
    id: OrderId,
    item: String,
    sub: String,
    new_message: bool,
    pill: String,
    pill_class: &'static str,
    filter: OrderFilter,
    thumb: Option<String>,
    /// The block it is to be sent by, for sorting what to send soonest
    /// first.
    due: Option<u32>,
}

/// Every order in this store, filtered by what has to happen next.
#[component]
fn SellerOrders(store: SellerStore, filter: OrderFilter) -> Element {
    let id = store.contract_id.clone();
    let (rows, loaded) = {
        let state = APP_STATE.read();
        let data = SellerData::of(&state, &store);
        let rows: Vec<OrderRow> = data
            .orders
            .iter()
            .map(|order| {
                let stage = order_status::stage_of(&state, order);
                let base = order_status::from_stage(stage, order.status);
                let status = order_status::seller_status(&state, &id, order);
                let withheld = state.withheld_settlements.contains_key(&order.order.id);
                let to_send = withheld
                    || super::my_store::needs_sending(
                        order,
                        stage,
                        state.despatch_recorded(&id, &order.order.id),
                    );
                let send_by = order_status::send_by_pill(&state, order).filter(|_| to_send);
                let (pill, pill_class) = match (withheld, send_by) {
                    (true, _) => ("Payment to match".to_string(), "pill pill-needs"),
                    (false, Some(pill)) => (pill, "pill pill-needs"),
                    (false, None) => (status.label().to_string(), status.pill_class()),
                };
                let when = match base {
                    Status::WaitingForPayment | Status::Expired | Status::Cancelled => {
                        format!(
                            "ordered {}",
                            order_status::short_date(order.order.created_at)
                        )
                    }
                    _ => paid_date(&state, order)
                        .map(|d| format!("paid {d}"))
                        .unwrap_or_else(|| "paid".to_string()),
                };
                OrderRow {
                    id: order.order.id.clone(),
                    item: data.item_of(order),
                    sub: format!(
                        "{} \u{00b7} {when} \u{00b7} {}",
                        data.buyer_of(&order.order.id),
                        order_amount(order)
                    ),
                    new_message: data.new_message(&order.order.id),
                    pill,
                    pill_class,
                    filter: filter_of(base, to_send),
                    due: match stage {
                        crate::fulfilment::OrderStage::AwaitingDespatch { despatch_by, .. }
                        | crate::fulfilment::OrderStage::DespatchWindowClosed {
                            despatch_by, ..
                        } => Some(despatch_by),
                        _ => None,
                    },
                    thumb: data
                        .listing_of(&order.order.id)
                        .and_then(|(l, t)| super::item_image::listing_image(&l, &t)),
                }
            })
            .collect();
        (rows, data.loaded)
    };
    let count = |f: OrderFilter| {
        rows.iter()
            .filter(|r| f == OrderFilter::All || r.filter == f)
            .count()
    };
    let mut shown: Vec<&OrderRow> = rows
        .iter()
        .filter(|r| filter == OrderFilter::All || r.filter == filter)
        .collect();
    // What to send soonest first, as Home lists it; the rest newest first.
    if filter == OrderFilter::ToSend {
        shown.sort_by_key(|r| r.due.unwrap_or(u32::MAX));
    }
    let to_send = count(OrderFilter::ToSend);
    rsx! {
        div { class: "chips", role: "tablist",
            for (f , label) in [
                (OrderFilter::ToSend, "To send"),
                (OrderFilter::Sent, "Sent"),
                (OrderFilter::Complete, "Complete"),
                (OrderFilter::All, "All"),
            ] {
                button {
                    class: if f == filter { "chip active" } else { "chip" },
                    role: "tab",
                    aria_selected: if f == filter { "true" } else { "false" },
                    onclick: {
                        let id = id.clone();
                        move |_| go(seller_page(&id, SellerView::Orders(f)))
                    },
                    "{label}"
                    if f == OrderFilter::ToSend && to_send > 0 {
                        " "
                        span { class: "tab-needs", "{to_send}" }
                    }
                }
            }
        }
        if !loaded {
            p { class: "text-muted text-italic", "Loading this store\u{2019}s orders\u{2026}" }
        } else if shown.is_empty() {
            p { class: "text-muted empty-line",
                match filter {
                    OrderFilter::ToSend if rows.is_empty() => "No orders yet. Paid orders appear here.",
                    OrderFilter::ToSend => "Nothing to send right now.",
                    OrderFilter::Sent => "No orders marked as sent and still open for a problem report.",
                    OrderFilter::Complete => "No completed orders yet.",
                    OrderFilter::All => "No orders yet. Paid orders appear here.",
                }
            }
        }
        for row in shown {
            button {
                key: "{row.id}",
                class: "rowcard",
                onclick: {
                    let id = id.clone();
                    let order = row.id.clone();
                    move |_| go(seller_page(&id, SellerView::Order(order.clone())))
                },
                super::item_image::RowThumb { src: row.thumb.clone() }
                span { class: "rc-main",
                    span { class: "rc-name", "{row.item}" }
                    span { class: "rc-sub",
                        "{row.sub}"
                        if row.new_message {
                            " \u{00b7} "
                            strong { class: "rc-flag", "new message" }
                        }
                    }
                }
                span { class: "rc-status",
                    span { class: "{row.pill_class}", "{row.pill}" }
                }
                span { class: "chev", aria_hidden: "true", "\u{203a}" }
            }
        }
        if filter == OrderFilter::ToSend {
            p { class: "text-muted small foot-note",
                "Orders appear here once they are paid. A Buy now nobody paid is not an order."
            }
        }
    }
}

// ---- S4: one order ----

/// Everything needed to send one order, and the button to say it's sent.
#[component]
fn SellerOrderPage(store: SellerStore, order: OrderId) -> Element {
    let id = store.contract_id.clone();
    let found = {
        let state = APP_STATE.read();
        let data = SellerData::of(&state, &store);
        data.orders
            .iter()
            .find(|o| o.order.id == order)
            .cloned()
            .map(|o| {
                let stage = order_status::stage_of(&state, &o);
                let to_send = super::my_store::needs_sending(
                    &o,
                    stage,
                    state.despatch_recorded(&id, &o.order.id),
                );
                let thread = data
                    .thread_of
                    .get(&o.order.id)
                    .and_then(|tag| data.inbox.threads.iter().find(|t| t.tag == *tag))
                    .cloned();
                let name = data.buyer_of(&o.order.id);
                let others = thread
                    .as_ref()
                    .map(|t| {
                        t.orders
                            .iter()
                            .filter(|other| **other != o.order.id)
                            .filter(|other| data.orders.iter().any(|x| x.order.id == **other))
                            .count()
                    })
                    .unwrap_or(0);
                OrderView {
                    item: data.item_of(&o),
                    status: order_status::seller_status(&state, &id, &o),
                    pill: if state.withheld_settlements.contains_key(&o.order.id) {
                        Some("Payment to match".to_string())
                    } else {
                        order_status::send_by_pill(&state, &o).filter(|_| to_send)
                    },
                    paid: paid_date(&state, &o),
                    request: data
                        .requests
                        .get(&o.order.id)
                        .cloned()
                        .unwrap_or(SellerRequest::NotFound),
                    to_send,
                    history: history(&state, &o, stage),
                    needs_reissue: state.needs_reissue(&o),
                    withheld: state.withheld_settlements.contains_key(&o.order.id),
                    oversold: matches!(
                        state.auto_invoice.status.get(&id),
                        Some(Ok(status)) if status.oversold.contains(&o.order.id)
                    ),
                    twins: state.paid_twins(&o),
                    thumb: data
                        .listing_of(&o.order.id)
                        .and_then(|(l, t)| super::item_image::listing_image(&l, &t)),
                    latest: thread.as_ref().and_then(|t| t.latest_from_buyer()),
                    tag: thread.as_ref().map(|t| t.tag),
                    name,
                    others,
                    order: o,
                    live: state.bitcoin.clone(),
                }
            })
    };
    let back = rsx! {
        BackTo {
            label: "Orders".to_string(),
            page: seller_page(&id, SellerView::Orders(OrderFilter::ToSend)),
        }
    };
    let Some(view) = found else {
        return rsx! {
            {back}
            p { class: "text-muted text-italic", "This order isn\u{2019}t on this device, or it hasn\u{2019}t loaded yet." }
        };
    };
    let o = view.order.clone();
    let amount = order_amount(&o);
    let test = super::pay_card::is_test_network(o.order.network);
    let meta = match &view.paid {
        Some(paid) if view.status != Status::WaitingForPayment => format!("Paid {paid}"),
        _ => format!("Ordered {}", order_status::short_date(o.order.created_at)),
    };
    let pill_class = if view.pill.is_some() {
        "pill pill-needs"
    } else {
        view.status.pill_class()
    };
    let pill = view
        .pill
        .clone()
        .unwrap_or_else(|| view.status.label().to_string());
    rsx! {
        {back}
        div { class: "page-title",
            super::item_image::RowThumb { src: view.thumb.clone() }
            h2 { "{view.item}" }
            span { class: "{pill_class}", "{pill}" }
        }
        p { class: "page-meta",
            "{meta} \u{00b7} {amount}"
            if test {
                span { class: "test-coins", "{super::pay_card::TEST_COIN_TAG}" }
            }
            " \u{00b7} order {o.order.id.short()}"
        }
        div { class: "two-col",
            div { class: "col-main",
                if view.to_send {
                    section { class: "panel panel-strong",
                        if view.oversold {
                            p { class: "text-warning",
                                strong { "Paid after it sold out. " }
                                "The item went to another buyer, or you marked it sold out or took it \
                                 down, before this payment arrived. Refund the buyer, or make one and \
                                 send it. Message them either way."
                            }
                        }
                        if !view.twins.is_empty() {
                            p { class: "text-warning",
                                "Your order {view.twins.join(\", \")} uses this same payment address, and \
                                 the payment that settled this one also falls inside its window. One \
                                 payment can\u{2019}t pay for both: check your wallet for a separate \
                                 payment per order before sending both."
                            }
                        }
                        super::invoice_form::SellerRequestView { request: view.request.clone() }
                        super::invoice_form::MarkDespatched {
                            store_contract_id: id.clone(),
                            order_id: o.order.id.clone(),
                        }
                    }
                } else if matches!(view.status, Status::Sent | Status::Complete | Status::Reported | Status::Paid) && !view.withheld {
                    section { class: "panel",
                        if !view.twins.is_empty() {
                            p { class: "text-warning",
                                "Your order {view.twins.join(\", \")} uses this same payment address, and \
                                 the payment that settled this one also falls inside its window. One \
                                 payment can\u{2019}t pay for both: check your wallet for a separate \
                                 payment per order."
                            }
                        }
                        super::invoice_form::SellerRequestView { request: view.request.clone(), quiet_when_missing: true }
                        // A paid order past every window can still be marked
                        // as sent late; the control hides itself once a
                        // despatch is recorded.
                        if o.status == harvest_common::payment::OrderStatus::Paid {
                            super::invoice_form::MarkDespatched {
                                store_contract_id: id.clone(),
                                order_id: o.order.id.clone(),
                            }
                        }
                    }
                } else {
                    // Unpaid, or a payment held for the seller to match: the
                    // order's own card carries the address, the hold and the
                    // cancel.
                    if view.needs_reissue {
                        p { class: "text-warning",
                            "This invoice has expired: it is too old for a buyer\u{2019}s software to \
                             accept, so nobody can pay it now. Cancel it; the buyer can order again."
                        }
                    }
                    section { class: "panel",
                        super::bitcoin_view::OrderCard {
                            order: o.clone(),
                            live: super::bitcoin_view::live_address_for_order(&view.live, &o.order),
                            plain: true,
                            footer: rsx! {
                                if o.status == harvest_common::payment::OrderStatus::AwaitingPayment {
                                    super::invoice_form::CancelInvoice {
                                        store_contract_id: id.clone(),
                                        order_id: o.order.id.clone(),
                                    }
                                }
                            },
                        }
                    }
                }
                if !view.history.is_empty() {
                    h3 { class: "sec-lbl", "History" }
                    ol { class: "history",
                        for (i , line) in view.history.iter().enumerate() {
                            li { key: "{i}", "{line}" }
                        }
                    }
                }
            }
            aside { class: "col-side",
                p { class: "side-lbl", "Buyer" }
                p { class: "side-name", "{view.name}" }
                if view.others > 0 {
                    if let Some(tag) = view.tag {
                        button {
                            class: "link-btn",
                            onclick: {
                                let id = id.clone();
                                move |_| go(seller_page(&id, SellerView::Conversation(tag)))
                            },
                            {super::needs::plural(view.others, "other order from this buyer", "other orders from this buyer")}
                            " \u{203a}"
                        }
                    }
                }
                p { class: "side-lbl", "Messages" }
                match (view.tag, view.latest.clone()) {
                    (Some(tag), latest) => rsx! {
                        if let Some((text, at)) = latest {
                            div { class: "bubble side-bubble",
                                span { class: "bubble-who", "{view.name} \u{00b7} {order_status::short_date(at)}" }
                                "{one_line(&text)}"
                            }
                        } else {
                            p { class: "text-muted small", "No messages yet." }
                        }
                        button {
                            class: "btn btn-sm btn-outline",
                            onclick: {
                                let id = id.clone();
                                move |_| go(seller_page(&id, SellerView::Conversation(tag)))
                            },
                            "Message the buyer"
                        }
                    },
                    (None, _) => rsx! {
                        p { class: "text-muted small",
                            "This buyer\u{2019}s messages aren\u{2019}t on this device. Open Harvest where you set up the store to read them."
                        }
                    },
                }
            }
        }
    }
}

/// What the order page shows, worked out once.
#[derive(Clone, PartialEq)]
struct OrderView {
    order: AuthorizedOrder,
    item: String,
    status: Status,
    pill: Option<String>,
    paid: Option<String>,
    request: SellerRequest,
    to_send: bool,
    /// The order's steps so far and the next deadline, one line each.
    history: Vec<String>,
    needs_reissue: bool,
    withheld: bool,
    oversold: bool,
    twins: Vec<String>,
    thumb: Option<String>,
    latest: Option<(String, chrono::DateTime<chrono::Utc>)>,
    tag: Option<[u8; 32]>,
    name: String,
    others: usize,
    live: crate::state::BitcoinState,
}

/// An order's history on its page (S4): when it was ordered and paid, sent
/// or to be sent by, and until when the buyer can report a problem. Days
/// are worked out from blocks against this node's tip, as everywhere.
fn history(
    state: &AppState,
    order: &AuthorizedOrder,
    stage: crate::fulfilment::OrderStage,
) -> Vec<String> {
    use crate::fulfilment::{approx_date, OrderStage};
    let now = crate::state::now_ms();
    let mut lines = vec![format!(
        "Ordered {}",
        order_status::short_date(order.order.created_at)
    )];
    let Some(tip) = state.tip_height(order.order.network) else {
        return lines;
    };
    let day = |height: u32| approx_date(height, tip, now);
    if let Some(paid) = crate::fulfilment::paid_height(order) {
        lines.push(format!("Paid about {}", day(paid)));
    }
    match stage {
        OrderStage::AwaitingDespatch { despatch_by, .. } => {
            lines.push(format!("Send it by about {}", day(despatch_by)));
            lines.push(format!(
                "Once it is sent, the buyer has {} to report a problem",
                crate::fulfilment::approx_duration(crate::fulfilment::COMPLAINT_WINDOW_BLOCKS)
                    .trim_start_matches("about ")
            ));
        }
        OrderStage::DespatchWindowClosed {
            despatch_by,
            complaint_until,
        } => {
            lines.push(format!(
                "The send-by date, about {}, has passed",
                day(despatch_by)
            ));
            lines.push(format!(
                "The buyer can report a problem until about {}",
                day(complaint_until)
            ));
        }
        OrderStage::Despatched {
            despatched_at,
            complaint_until,
        } => {
            lines.push(format!("Marked as sent about {}", day(despatched_at)));
            lines.push(format!(
                "The buyer can report a problem until about {}",
                day(complaint_until)
            ));
        }
        OrderStage::Closed { closed_at } => {
            lines.push(format!(
                "Complete: the time to report a problem ended about {}",
                day(closed_at)
            ));
        }
        OrderStage::Reversed => lines.push("The payment was reversed on the chain".to_string()),
        OrderStage::Cancelled { .. } => lines.push("Cancelled".to_string()),
        OrderStage::Lapsed { closed_at } => {
            lines.push(format!("Expired unpaid about {}", day(closed_at)))
        }
        OrderStage::AwaitingPayment { .. } | OrderStage::Unknown => {}
    }
    lines
}

// ---- S5: Messages ----

/// One conversation's row.
#[derive(Clone, PartialEq)]
struct ThreadRow {
    tag: [u8; 32],
    name: String,
    latest: String,
    orders: usize,
    when: String,
    at: Option<chrono::DateTime<chrono::Utc>>,
    waiting: bool,
    request: bool,
}

/// Every conversation buyers have started with this store, the ones
/// waiting for the seller first.
#[component]
fn SellerMessages(store: SellerStore) -> Element {
    let id = store.contract_id.clone();
    let (mut rows, unreadable, held_back, loaded) = {
        let state = APP_STATE.read();
        let data = SellerData::of(&state, &store);
        let rows: Vec<ThreadRow> = data
            .inbox
            .threads
            .iter()
            // A conversation with an order of this store's and something
            // said, or one waiting for an answer; one with no order only if
            // it is a question (open, so never junk).
            .filter(|thread| {
                let said = thread
                    .lines
                    .iter()
                    .any(|l| matches!(l.item, super::message_view::ChatItem::Said(_)));
                if thread
                    .orders
                    .iter()
                    .any(|o| data.orders.iter().any(|x| x.order.id == *o))
                {
                    said || thread.waiting > 0
                } else {
                    super::message_view::is_question(thread)
                }
            })
            .map(|thread| {
                let name = data.names.get(&thread.tag).cloned().unwrap_or_default();
                let last = thread
                    .lines
                    .iter()
                    .rev()
                    .find(|l| matches!(l.item, super::message_view::ChatItem::Said(_)));
                let latest = match last {
                    Some(line) => {
                        let text = match &line.item {
                            super::message_view::ChatItem::Said(t) => one_line(t),
                            super::message_view::ChatItem::Event(t) => t.clone(),
                        };
                        let who = match line.who {
                            "Buyer" => name.clone(),
                            "You" => "You".to_string(),
                            other => other.to_string(),
                        };
                        format!("{who}: {text}")
                    }
                    None => "A request waiting for your answer".to_string(),
                };
                let at = thread
                    .entries
                    .iter()
                    .map(crate::messaging::MailboxEntry::timestamp)
                    .max();
                let orders = thread
                    .orders
                    .iter()
                    .filter(|o| data.orders.iter().any(|x| x.order.id == **o))
                    .count();
                ThreadRow {
                    tag: thread.tag,
                    latest,
                    orders,
                    when: at.map(order_status::short_date).unwrap_or_default(),
                    at,
                    waiting: thread.awaiting_reply,
                    request: data
                        .invoice_requests
                        .get(thread.tag.as_slice())
                        .is_some_and(|n| *n > 0),
                    name,
                }
            })
            .collect();
        (
            rows,
            data.inbox.unreadable,
            data.inbox.held_back,
            data.loaded,
        )
    };
    rows.sort_by_key(|r| {
        (
            std::cmp::Reverse(r.waiting || r.request),
            std::cmp::Reverse(r.at),
        )
    });
    rsx! {
        if !loaded {
            p { class: "text-muted text-italic", "Loading this store\u{2019}s messages\u{2026}" }
        } else if rows.is_empty() {
            div { class: "empty-block",
                p { "No messages yet." }
                p { class: "text-muted small", "Buyers can message you from your store or from an order." }
            }
        }
        for row in rows.iter() {
            button {
                key: "{bs58::encode(row.tag).into_string()}",
                class: "rowcard",
                onclick: {
                    let id = id.clone();
                    let tag = row.tag;
                    move |_| go(seller_page(&id, SellerView::Conversation(tag)))
                },
                span { class: "rc-main",
                    span { class: "rc-name", "{row.name}" }
                    span { class: "rc-sub",
                        "{row.latest}"
                        " \u{00b7} "
                        if row.orders == 0 {
                            "question, no order"
                        } else {
                            {super::needs::plural(row.orders, "order", "orders")}
                        }
                    }
                }
                span { class: "rc-status",
                    if row.waiting {
                        span { class: "pill pill-needs", "Waiting for your reply" }
                    } else if row.request {
                        span { class: "pill pill-needs", "Needs an invoice" }
                    }
                    span { class: "rc-when", "{row.when}" }
                }
                span { class: "chev", aria_hidden: "true", "\u{203a}" }
            }
        }
        // Once, at the foot of the list (msg critique MSG-9).
        if unreadable > 0 {
            p { class: "text-muted small foot-note", "{super::message_view::SOME_UNREADABLE}" }
        }
        if held_back > 0 {
            p { class: "text-muted small foot-note",
                "{super::message_view::hidden_unvouched_line(held_back)}"
            }
        }
    }
}

// ---- S6: one conversation ----

/// Read and answer one buyer, with their orders beside the conversation.
#[component]
fn SellerConversationPage(store: SellerStore, tag: [u8; 32]) -> Element {
    let id = store.contract_id.clone();
    let found = {
        let state = APP_STATE.read();
        let data = SellerData::of(&state, &store);
        data.inbox
            .threads
            .iter()
            .find(|t| t.tag == tag)
            .cloned()
            .map(|thread| {
                let name = data
                    .names
                    .get(&tag)
                    .cloned()
                    .unwrap_or_else(|| "this buyer".to_string());
                let orders: Vec<(OrderId, String, String)> = data
                    .orders
                    .iter()
                    .filter(|o| thread.orders.contains(&o.order.id))
                    .map(|o| {
                        let status = order_status::seller_status(&state, &id, o);
                        let stage = order_status::stage_of(&state, o);
                        let to_send = super::my_store::needs_sending(
                            o,
                            stage,
                            state.despatch_recorded(&id, &o.order.id),
                        );
                        // The ref too: one buyer's orders of one item would
                        // otherwise read alike.
                        let pill = format!(
                            "{} \u{00b7} order {}",
                            order_status::send_by_pill(&state, o)
                                .filter(|_| to_send)
                                .unwrap_or_else(|| status.label().to_string()),
                            o.order.id.short()
                        );
                        (o.order.id.clone(), data.item_of(o), pill)
                    })
                    .collect();
                (thread, name, orders)
            })
    };
    let back = rsx! {
        BackTo { label: "Messages".to_string(), page: seller_page(&id, SellerView::Messages) }
    };
    let Some((thread, name, orders)) = found else {
        return rsx! {
            {back}
            p { class: "text-muted text-italic", "This conversation isn\u{2019}t on this device, or it hasn\u{2019}t loaded yet." }
        };
    };
    rsx! {
        {back}
        h2 { class: "page-h", "Messages with {name}" }
        div { class: "two-col",
            div { class: "col-main",
                super::message_view::SellerConversation {
                    store_contract_id: id.clone(),
                    thread: thread.clone(),
                    name: name.clone(),
                }
            }
            aside { class: "col-side",
                p { class: "side-lbl", "Orders from {name}" }
                if orders.is_empty() {
                    p { class: "text-muted small", "A question, with no order." }
                }
                for (order , item , pill) in orders.iter() {
                    button {
                        key: "{order}",
                        class: "side-row",
                        onclick: {
                            let id = id.clone();
                            let order = order.clone();
                            move |_| go(seller_page(&id, SellerView::Order(order.clone())))
                        },
                        span { class: "rc-main",
                            span { class: "side-row-name", "{item}" }
                            span { class: "rc-sub", "{pill}" }
                        }
                        span { class: "chev", aria_hidden: "true", "\u{203a}" }
                    }
                }
            }
        }
    }
}

// ---- S9: Settings ----

/// The things a seller sets once and rarely changes.
#[component]
fn SellerSettings(store: SellerStore) -> Element {
    let identity = APP_STATE
        .read()
        .ghostkeys
        .iter()
        .find(|k| k.fingerprint == store.fingerprint)
        .cloned();
    let buyers_see = APP_STATE
        .read()
        .browsing_stores
        .get(&store.contract_id)
        .filter(|b| b.info.is_some())
        .map(super::store_view::trust_line);
    // Opened when Home sent the seller here to fix the details.
    let editing_details = use_signal(|| {
        store.details_resolved
            && store.gap.is_some()
            && super::my_store::store_details_need_form(store.gap)
    });
    rsx! {
        // First when it applies: Home's "Close one of your two stores" opens
        // Settings for this (harvest#181).
        if let Some(conflict) = store.key_conflict.clone() {
            section { class: "settings-sec",
                h3 { "Two stores on one Ghost Key" }
                super::my_store::KeyBacksTwoStores { conflict }
            }
        }
        section { class: "settings-sec",
            div { class: "row-between",
                h3 { "Store details" }
                if store.details_resolved {
                    super::my_store::StoreDetailsButton { store: store.clone(), editing_details, on_open_form: move |_| {} }
                }
            }
            super::my_store::StoreDetailsBody { store: store.clone(), editing_details }
        }
        section { class: "settings-sec",
            h3 { "Payout wallet" }
            super::invoice_form::PayoutWallet {}
            p { class: "text-muted small", "Harvest can create addresses but can never spend your coins." }

        }
        section { class: "settings-sec",
            h3 { "Backed by" }
            if let Some(ref identity) = identity {
                p {
                    "{super::my_store::ghost_key_name(identity)} \u{00b7} {super::my_store::describe_notary_info(&identity.notary_info)}"
                }
            }
            // What buyers read on the store page, from the same function.
            if let Some(ref buyers_see) = buyers_see {
                p { class: if store.certificate.is_verified() { "text-muted small" } else { "text-warning" },
                    "Buyers see: {buyers_see}. It is how they judge what you have at stake."
                }
            }
        }
        section { class: "settings-sec",
            h3 { "Pause the store" }
            p { class: "text-muted small", "Not available yet." }
        }
        section { class: "settings-sec",
            h3 { "Move or retire this store" }
            p { class: "text-muted small", "Not available yet." }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::name_from_address;

    /// "Closed" on one of the seller's own stores always says what to fix
    /// (#181 handoff, section D): the store sends no presence until it has
    /// a buyable listing and a payout wallet, so without a reason it read
    /// "Checking…" and then a bare "Closed". Red if any reason is dropped
    /// or a selling store is called closed.
    #[test]
    fn a_closed_own_store_says_why() {
        use super::closed_reason;
        use crate::state::{test_store_key, AppState, BrowsingStore};
        use harvest_common::listing::{
            AuthorizedListing, FixedCheckout, Listing, ListingId, ListingKind,
        };
        let listing = |n: u8, priced: bool| AuthorizedListing {
            listing: Listing {
                checkout: priced.then_some(FixedCheckout {
                    unit_sats: 10_000,
                    delivery: harvest_common::listing::DeliveryPrice::Included,
                }),
                choices: Vec::new(),
                id: ListingId([n; 32]),
                title: format!("Item {n}"),
                description: String::new(),
                kind: ListingKind::Sale,
                price: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            certificate_pem: String::new(),
        };
        let mut state = AppState::default();
        state.my_stores.insert(
            "fp".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: vec![1; 32],
                reputation_contract_id: vec![0; 32],
                mailbox_contract_id: vec![0; 32],
                store_contract_key: None,
                store_verifying_key: Some(test_store_key()),
            }],
        );
        let with = |state: &mut AppState, listings: Vec<AuthorizedListing>| {
            state.browsing_stores.insert(
                vec![1; 32],
                BrowsingStore {
                    info: Some(harvest_common::store::StoreInfoV1 {
                        version: 1,
                        certificate_pem: String::new(),
                        seller_fingerprint: "fp".into(),
                        reputation_contract_id: [0; 32],
                        store_name: "Bean Shop".into(),
                        description: String::new(),
                        encryption_public_key: None,
                        record_public_key: None,
                    }),
                    listings,
                    ..Default::default()
                },
            );
        };
        let reason = |state: &AppState| {
            let store = super::super::my_store::seller_stores(state).remove(0);
            closed_reason(state, &store)
        };

        // Still loading: nothing said against it yet.
        assert_eq!(reason(&state), None);

        state.bitcoin.payment_xpub_loaded = true;
        with(&mut state, vec![]);
        assert_eq!(
            reason(&state),
            Some("Closed: add a listing and a payout wallet")
        );
        with(&mut state, vec![listing(1, true)]);
        assert_eq!(reason(&state), Some("Closed: add a payout wallet"));

        state.bitcoin.payment_xpub = Some(harvest_common::PaymentXpubStatus {
            xpub: "vpub-placeholder".into(),
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            next_index: 0,
        });
        with(&mut state, vec![]);
        assert_eq!(reason(&state), Some("Closed: add a listing"));
        with(&mut state, vec![listing(1, false)]);
        assert_eq!(reason(&state), Some("Closed: give a listing a price"));
        with(&mut state, vec![listing(1, true)]);
        assert_eq!(
            reason(&state),
            None,
            "a store that can sell is not called closed"
        );

        state
            .browsing_stores
            .get_mut(&vec![1u8; 32])
            .unwrap()
            .closed = true;
        assert_eq!(reason(&state), Some("Closed for good"));
    }

    /// A buyer's name is the start of their address, cut at a comma or a
    /// bracket and at a whole word, never inside one (critique C3: "E2E
    /// TEST (release").
    #[test]
    fn a_name_is_the_start_of_the_address_in_whole_words() {
        assert_eq!(
            name_from_address("Jane Doe\n14 Orchard Lane").as_deref(),
            Some("Jane Doe")
        );
        assert_eq!(
            name_from_address("Jane Doe, 14 Orchard Lane").as_deref(),
            Some("Jane Doe")
        );
        assert_eq!(
            name_from_address("E2E TEST (release 0.2.139 candidate)").as_deref(),
            Some("E2E TEST")
        );
        assert_eq!(
            name_from_address("Maximiliana Wolfeschlegelsteinhausen Bergerdorff").as_deref(),
            Some("Maximiliana")
        );
        assert_eq!(name_from_address("  \n 12 ").as_deref(), None);
        assert_eq!(name_from_address(crate::fulfilment::ADDRESS_HIDDEN), None);
    }
}
