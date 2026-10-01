//! Purchases (page structure P6, P7, P9): every order this device has
//! placed, as one flat list of rows that each open the order's page; every
//! conversation with a store; and the backup. Before this a buyer's orders
//! sat in cards per store with their threads inside them.

use dioxus::prelude::*;

use super::order_status::Status;
use super::router::{go, OrderAt, Page};
use crate::gateway::APP_STATE;
use crate::state::AppState;

/// One store on My purchases.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PurchaseRow {
    pub store_contract_id: Vec<u8>,
    pub name: String,
    /// This buyer's orders from the store still standing, counted as its
    /// store page counts them (`store_view::orders_here`), so the two pages
    /// never give two numbers for one store (round-6 screenshots).
    pub orders: usize,
    /// Orders that ended unpaid: cancelled, or too old to pay.
    pub ended: usize,
    /// Conversations this device keeps with the store.
    pub conversations: usize,
}

/// The stores to list: any this device has a conversation or an order with,
/// never one of our own, named stores first by name.
pub(crate) fn purchase_rows(state: &AppState) -> Vec<PurchaseRow> {
    let mut rows: Vec<PurchaseRow> = state
        .browsing_stores
        .iter()
        .filter(|(id, _)| state.store_owner_fingerprint(id).is_none())
        .filter_map(|(id, store)| {
            let purchases = state.buyer_purchases(id);
            let counted = super::store_view::orders_here(&purchases);
            let conversations = store.conversations.len();
            if purchases.is_empty() && conversations == 0 {
                return None;
            }
            // Never a code, and "Loading…" or "Couldn't load this store"
            // rather than a vague "A store" (review of #197).
            let name = state.store_name_of(id).label();
            Some(PurchaseRow {
                store_contract_id: id.clone(),
                name,
                orders: counted.live,
                ended: counted.ended,
                conversations,
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| a.store_contract_id.cmp(&b.store_contract_id))
    });
    rows
}

/// The tabs on Purchases.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PurchasesTab {
    Orders,
    Messages,
}

/// One of the buyer's orders, as a row of Purchases (P6).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OrderRow {
    pub page: Page,
    /// "Aran skein × 1", or "Order 7SvqF" when the request isn't here.
    pub item: String,
    pub store: String,
    pub date: Option<chrono::DateTime<chrono::Utc>>,
    pub amount: Option<String>,
    pub status: Status,
    /// The buyer can pay it now: the row's one quick action, and "needs you".
    pub to_pay: bool,
    pub picture: Option<String>,
}

/// Every order this device has placed or keeps, newest first: the purchases
/// at every store it has dealt with ([`purchase_rows`]), then the kept
/// orders those don't already show (`buy_view::kept_purchases_to_list`).
pub(crate) fn order_rows(state: &AppState) -> Vec<OrderRow> {
    let mut rows: Vec<OrderRow> = Vec::new();
    let stores = purchase_rows(state);
    for store in stores.iter() {
        let id = &store.store_contract_id;
        for purchase in state.buyer_purchases(id) {
            // Not this buyer's: never an order of theirs.
            if purchase
                .blockers
                .iter()
                .any(|b| matches!(b, crate::state::PaymentBlocker::CommitmentNotForThisBuyer))
            {
                continue;
            }
            let status = super::order_status::buyer_status(state, id, &purchase);
            let order = purchase.commitment.as_ref().or(purchase.paid.as_ref());
            let listing = state.purchase_listing(id, &purchase);
            rows.push(OrderRow {
                page: Page::Order {
                    at: OrderAt::Store(id.clone()),
                    order: purchase.order_id.clone(),
                },
                item: match &listing {
                    Some((_, Some(title), q)) => format!("{title}\u{a0}\u{00d7}\u{a0}{q}"),
                    Some((_, None, q)) => format!("An item no longer listed \u{00d7} {q}"),
                    None => format!("Order {}", purchase.order_id.short()),
                },
                store: store.name.clone(),
                date: order.map(|o| o.order.created_at),
                amount: order.map(|o| super::pay_card::money(o.order.amount_sats, o.order.network)),
                to_pay: super::order_status::can_pay_now(state, id, &purchase),
                picture: listing.as_ref().and_then(|(l, t, _)| {
                    super::item_image::listing_image(l, t.as_deref().unwrap_or_default())
                }),
                status,
            });
        }
    }
    let shown = shown_order_ids(state, &stores);
    for kept in super::buy_view::kept_purchases_to_list(&state.kept_purchases, &shown) {
        let store = state
            .browsing_stores
            .iter()
            .find(|(_, s)| s.owner == Some(kept.store_key))
            .map(|(id, _)| state.store_name_of(id).label())
            .unwrap_or_else(|| "A store you have used".to_string());
        rows.push(OrderRow {
            page: Page::Order {
                at: OrderAt::Kept(kept.store_key),
                order: kept.order.order.id.clone(),
            },
            item: format!("Order {}", kept.order.order.id.short()),
            store,
            date: Some(kept.order.order.created_at),
            amount: Some(super::pay_card::money(
                kept.order.order.amount_sats,
                kept.order.order.network,
            )),
            status: super::order_status::kept_status(state, &kept),
            to_pay: false,
            picture: None,
        });
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.date));
    rows
}

/// The header of both Purchases pages: the title, the Backup button, and the
/// tabs Orders and Messages.
#[component]
fn PurchasesHead(tab: PurchasesTab, new_replies: usize) -> Element {
    rsx! {
        div { class: "page-head",
            h2 { "Purchases" }
            button { class: "btn btn-sm btn-outline", onclick: move |_| go(Page::Backup), "Backup" }
        }
        div { class: "tabs", role: "tablist",
            button {
                class: if tab == PurchasesTab::Orders { "tab active" } else { "tab" },
                role: "tab",
                aria_selected: if tab == PurchasesTab::Orders { "true" } else { "false" },
                onclick: move |_| super::router::replace(Page::Purchases),
                "Orders"
            }
            button {
                class: if tab == PurchasesTab::Messages { "tab active" } else { "tab" },
                role: "tab",
                aria_selected: if tab == PurchasesTab::Messages { "true" } else { "false" },
                onclick: move |_| super::router::replace(Page::PurchaseMessages),
                "Messages"
                if new_replies > 0 {
                    " "
                    span { class: "tab-needs", "{new_replies}" }
                }
            }
        }
    }
}

/// Re-render once the wait for the list of remembered stores runs out (from
/// the app's start), so "Checking…" cannot outlast it; and ask for every
/// store this device has used, since only a loaded store recalls this
/// device's conversations with it. Returns whether that is still under way,
/// and how many stores could not be reached.
fn use_purchases_loading() -> (bool, usize) {
    // An effect, so it runs again when the delegate's list of remembered
    // stores arrives after this page opened; loading is idempotent per store.
    use_effect(|| crate::store_link::load_visited_stores(false, true));
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
    // Still being asked for (a GET out, or a retry waiting), and could not be
    // loaded: neither is a confirmed empty history (codex on #197 round 4).
    let (pending, failed) = APP_STATE.read().visited_load_state();
    // Also while the list of remembered stores hasn't arrived: before it,
    // nothing is being loaded yet, and "Nothing yet" would read as "my
    // orders are gone" (round-6 critique R6-2).
    let loading = pending > 0
        || !APP_STATE.read().background_loads.is_empty()
        || APP_STATE
            .read()
            .remembered_stores_awaited(crate::state::now_ms());
    (loading, failed)
}

/// Whether any conversation this device keeps has no backup anywhere else:
/// the banner that sends the buyer to Backup until there is one.
pub(crate) fn backup_due(state: &AppState) -> bool {
    state
        .browsing_stores
        .iter()
        .filter(|(id, _)| state.store_owner_fingerprint(id).is_none())
        .any(|(_, store)| store.conversations.iter().any(|c| !c.backed_up))
}

/// P6: every order this device has placed, newest first, with what needs
/// the buyer on top and ended orders folded at the foot.
#[component]
pub fn PurchasesPage() -> Element {
    let (loading, failed) = use_purchases_loading();
    let mut show_ended = use_signal(|| false);
    let (rows, replies, banner) = {
        let state = APP_STATE.read();
        (
            order_rows(&state),
            // A reply belongs to a conversation, not to one of its orders:
            // its own row under "Needs you", so the rows there add up to
            // the header's count (critique C8).
            conversation_rows(&state)
                .into_iter()
                .filter(|row| row.new_reply)
                .collect::<Vec<_>>(),
            backup_due(&state),
        )
    };
    let new_replies = replies.len();
    let (needs, rest): (Vec<&OrderRow>, Vec<&OrderRow>) = rows.iter().partition(|row| row.to_pay);
    let (ended, earlier): (Vec<&OrderRow>, Vec<&OrderRow>) =
        rest.into_iter().partition(|row| row.status.ended());
    rsx! {
        PurchasesHead { tab: PurchasesTab::Orders, new_replies }
        if banner {
            p { class: "coin-note",
                "Your purchases are saved on this device only. "
                button { class: "link-btn", onclick: move |_| go(Page::Backup), "Save a backup" }
                " so you don\u{2019}t lose them."
            }
        }
        if loading {
            p { class: "text-muted text-italic", "Checking the stores you have used\u{2026}" }
        }
        if let Some(note) = unreachable_note(failed) {
            p { class: "text-warning", "{note}" }
        }
        if rows.is_empty() && !loading && failed == 0 {
            div { class: "empty-block",
                p { "No purchases yet." }
                p { class: "text-muted small", "When you buy something it is listed here." }
            }
        }
        if !needs.is_empty() || !replies.is_empty() {
            h3 { class: "sec-lbl sec-lbl-first", "Needs you" }
            for row in needs.iter() {
                OrderRowView { key: "{row.page.fragment()}", row: (*row).clone() }
            }
            for row in replies.iter() {
                button {
                    key: "{bs58::encode(row.tag).into_string()}",
                    class: "rowcard",
                    onclick: {
                        let page = Page::Conversation { store: row.store.clone(), tag: Some(row.tag) };
                        move |_| go(page.clone())
                    },
                    span { class: "rc-main",
                        span { class: "rc-name", "{row.name} replied" }
                        span { class: "rc-sub", "{row.latest}" }
                    }
                    span { class: "rc-status",
                        span { class: "pill pill-needs", "New reply" }
                    }
                    span { class: "chev", aria_hidden: "true", "\u{203a}" }
                }
            }
        }
        if !earlier.is_empty() {
            h3 { class: if needs.is_empty() && replies.is_empty() { "sec-lbl sec-lbl-first" } else { "sec-lbl" }, "Earlier" }
            for row in earlier.iter() {
                OrderRowView { key: "{row.page.fragment()}", row: (*row).clone() }
            }
        }
        if !ended.is_empty() {
            button {
                class: "link-btn",
                onclick: move |_| show_ended.toggle(),
                if show_ended() {
                    "Hide ended orders"
                } else if ended.len() == 1 {
                    "Show 1 ended order (expired or cancelled)"
                } else {
                    "Show {ended.len()} ended orders (expired or cancelled)"
                }
            }
            if show_ended() {
                for row in ended.iter() {
                    OrderRowView { key: "{row.page.fragment()}", row: (*row).clone() }
                }
            }
        }
    }
}

/// One order's row: the whole row opens its page; "Pay now" in place of the
/// status when the buyer can pay it.
#[component]
fn OrderRowView(row: OrderRow) -> Element {
    let sub = [
        Some(row.store.clone()),
        row.date.map(super::order_status::short_date),
        row.amount.clone(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" \u{00b7} ");
    rsx! {
        button {
            class: if row.status.ended() { "rowcard row-off" } else { "rowcard" },
            onclick: {
                let page = row.page.clone();
                move |_| go(page.clone())
            },
            super::item_image::RowThumb { src: row.picture.clone() }
            span { class: "rc-main",
                span { class: "rc-name", "{row.item}" }
                span { class: "rc-sub", "{sub}" }
            }
            span { class: "rc-status",
                // The row's one quick action, drawn as the button it is
                // (critique C9); the row itself is what is pressed.
                if row.to_pay {
                    span { class: "btn btn-sm btn-primary row-action", "Pay now" }
                } else {
                    span { class: "{row.status.pill_class()}", "{row.status.label()}" }
                }
            }
            span { class: "chev", aria_hidden: "true", "\u{203a}" }
        }
    }
}

/// One conversation's row on Purchases > Messages.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ConversationRow {
    pub store: Vec<u8>,
    pub tag: [u8; 32],
    pub name: String,
    pub latest: String,
    pub orders: usize,
    pub at: Option<chrono::DateTime<chrono::Utc>>,
    pub new_reply: bool,
}

/// Every conversation this device has with a store that holds a message,
/// the ones with a new reply first, then newest first.
pub(crate) fn conversation_rows(state: &AppState) -> Vec<ConversationRow> {
    let mut rows = Vec::new();
    for store in purchase_rows(state) {
        let id = &store.store_contract_id;
        let Some(browsing) = state.browsing_stores.get(id) else {
            continue;
        };
        let purchases = state.buyer_purchases(id);
        for conversation in browsing.conversations.iter() {
            let tag = conversation.buyer_public_key;
            let Some(summary) = super::message_view::buyer_conversation_summary(state, id, tag)
            else {
                continue;
            };
            let latest = summary
                .latest
                .as_ref()
                .map(|line| {
                    let text = match &line.item {
                        super::message_view::ChatItem::Said(t) => super::seller_pages::one_line(t),
                        super::message_view::ChatItem::Event(t) => t.clone(),
                    };
                    format!("{}: {text}", line.who)
                })
                .unwrap_or_else(|| "You: sending\u{2026}".to_string());
            rows.push(ConversationRow {
                store: id.clone(),
                tag,
                name: store.name.clone(),
                latest,
                // Orders still standing, as the store's page counts them
                // (round-6 R6-1): an expired or cancelled one is not.
                orders: purchases
                    .iter()
                    .filter(|p| p.conversation == tag)
                    .filter(|p| {
                        !super::order_status::buyer_status(state, id, p).ended()
                            && !p.blockers.iter().any(|b| {
                                matches!(b, crate::state::PaymentBlocker::CommitmentNotForThisBuyer)
                            })
                    })
                    .count(),
                at: summary.latest_at,
                new_reply: super::message_view::is_new_reply(&summary, &tag),
            });
        }
    }
    rows.sort_by_key(|row| (std::cmp::Reverse(row.new_reply), std::cmp::Reverse(row.at)));
    rows
}

/// P7: every conversation with a store, including questions asked before
/// buying.
#[component]
pub fn PurchaseMessagesPage() -> Element {
    let (loading, _) = use_purchases_loading();
    let rows = conversation_rows(&APP_STATE.read());
    let new_replies = rows.iter().filter(|r| r.new_reply).count();
    rsx! {
        PurchasesHead { tab: PurchasesTab::Messages, new_replies }
        if loading {
            p { class: "text-muted text-italic", "Checking the stores you have used\u{2026}" }
        } else if rows.is_empty() {
            div { class: "empty-block",
                p { "No messages." }
            }
        }
        for row in rows.iter() {
            button {
                key: "{bs58::encode(row.tag).into_string()}",
                class: "rowcard",
                onclick: {
                    let page = Page::Conversation { store: row.store.clone(), tag: Some(row.tag) };
                    move |_| go(page.clone())
                },
                span { class: "rc-main",
                    span { class: "rc-name", "{row.name}" }
                    span { class: "rc-sub",
                        "{row.latest} \u{00b7} "
                        if row.orders == 0 {
                            "question, no order"
                        } else {
                            {super::needs::plural(row.orders, "order", "orders")}
                        }
                    }
                }
                span { class: "rc-status",
                    if row.new_reply {
                        span { class: "pill pill-needs", "New reply" }
                    }
                    if let Some(at) = row.at {
                        span { class: "rc-when", "{super::order_status::short_date(at)}" }
                    }
                }
                span { class: "chev", aria_hidden: "true", "\u{203a}" }
            }
        }
        p { class: "text-muted small foot-note",
            "To ask a store something, open it and choose Message the seller."
        }
    }
}

/// One conversation this device keeps, as Backup lists it: its store, the
/// store's name, its tag, when it started and whether it is backed up.
type KeptConversation = (Vec<u8>, String, [u8; 32], i64, bool);

/// P9: keep a copy of the purchases and messages this device holds, and
/// bring one back on another device.
///
/// One backup for everything needs the approved delegate change (one backup
/// for all purchases); until it lands, each conversation, which holds that
/// store's orders and messages, is saved on its own, and this page lists
/// them.
#[component]
pub fn BackupPage() -> Element {
    let kept: Vec<KeptConversation> = {
        let state = APP_STATE.read();
        let mut kept = Vec::new();
        for (id, store) in state.browsing_stores.iter() {
            if state.store_owner_fingerprint(id).is_some() {
                continue;
            }
            for c in store.conversations.iter() {
                kept.push((
                    id.clone(),
                    state.store_name_of(id).label(),
                    c.buyer_public_key,
                    c.created_at,
                    c.backed_up,
                ));
            }
        }
        kept.sort_by(|a, b| {
            a.1.to_lowercase()
                .cmp(&b.1.to_lowercase())
                .then(a.3.cmp(&b.3))
        });
        kept
    };
    let unsaved = kept.iter().filter(|k| !k.4).count();
    rsx! {
        super::seller_pages::BackTo { label: "Purchases".to_string(), page: Page::Purchases }
        h2 { class: "page-h", "Backup" }
        p { class: "lede",
            "Your purchases and messages are saved on this device only. A backup lets you see them, \
             and report a problem, on another device."
        }
        section { class: "panel",
            h3 { class: "panel-h", "Your backups" }
            p { class: "text-muted small",
                "Each store you have bought from or written to has its own backup, which holds your \
                 orders and messages with it. Keep it private, like a password: anyone who has it \
                 can read your messages and report problems as you."
            }
            if kept.is_empty() {
                p { class: "text-muted",
                    "Nothing to back up yet: you haven\u{2019}t bought from or written to a store on this device."
                }
            } else if unsaved == 0 {
                p { class: "text-muted small", "You have saved a backup of each of them." }
            } else if unsaved == 1 {
                p { class: "text-warning", "1 of them exists on this device and nowhere else." }
            } else {
                p { class: "text-warning", "{unsaved} of them exist on this device and nowhere else." }
            }
            for (store , name , tag , created , backed_up) in kept.iter() {
                div { key: "{bs58::encode(tag).into_string()}", class: "backup-row",
                    div { class: "row-between",
                        span {
                            strong { "{name}" }
                            span { class: "text-muted small", " \u{00b7} started {started_on(*created)}" }
                        }
                        if *backed_up {
                            span { class: "pill pill-open", "Saved" }
                        } else {
                            span { class: "pill", "Not saved" }
                        }
                    }
                    super::message_view::ConversationBackupControl {
                        store_contract_id: store.clone(),
                        tag: *tag,
                        primary: !*backed_up,
                    }
                }
            }
        }
        section { class: "panel",
            h3 { class: "panel-h", "Restore from a backup" }
            super::message_view::Restore {}
        }
    }
}

/// "27 Sep", for when a conversation was started (seconds since 1970).
fn started_on(created_at: i64) -> String {
    chrono::DateTime::from_timestamp(created_at, 0)
        .map(super::order_status::short_date)
        .unwrap_or_else(|| "at an unknown time".to_string())
}

/// The kept purchases the loaded stores' purchases already show, judged
/// from the same kept copy (`AppState::kept_purchases_shown_at` of each
/// store), so a paid order is not listed twice.
pub(crate) fn shown_order_ids(
    state: &AppState,
    rows: &[PurchaseRow],
) -> Vec<([u8; 32], harvest_common::payment::OrderId)> {
    rows.iter()
        .flat_map(|row| state.kept_purchases_shown_at(&row.store_contract_id))
        .collect()
}

/// What Purchases says when some of the stores this device has used could
/// not be loaded: their purchases may be missing, rather than "Nothing yet".
fn unreachable_note(failed: usize) -> Option<String> {
    match failed {
        0 => None,
        1 => Some(
            "1 store you have used couldn\u{2019}t be reached, so purchases from it may be \
             missing here. Reload to try again."
                .to_string(),
        ),
        n => Some(format!(
            "{n} stores you have used couldn\u{2019}t be reached, so purchases from them may be \
             missing here. Reload to try again."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BrowsingStore;

    fn named(name: &str) -> BrowsingStore {
        BrowsingStore {
            info: Some(harvest_common::store::StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: String::new(),
                reputation_contract_id: [0u8; 32],
                store_name: name.to_string(),
                description: String::new(),
                encryption_public_key: None,
                record_public_key: None,
            }),
            ..Default::default()
        }
    }

    /// A store appears once this device has a conversation with it, our own
    /// stores never do, and a store merely browsed does not either.
    #[test]
    fn only_stores_we_have_dealt_with_and_do_not_own_are_listed() {
        let mut state = AppState::default();
        let mut talked = named("Beans");
        talked.conversations =
            vec![crate::messaging::BuyerConversation::open(&[9u8; 32]).expect("open")];
        state.browsing_stores.insert(vec![1u8; 32], talked.clone());
        state
            .browsing_stores
            .insert(vec![2u8; 32], named("Browsed"));
        state.browsing_stores.insert(vec![3u8; 32], talked);
        state.my_stores.insert(
            "fp".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: vec![3u8; 32],
                reputation_contract_id: vec![0u8; 32],
                mailbox_contract_id: vec![0u8; 32],
                store_contract_key: None,
                store_verifying_key: None,
            }],
        );
        let rows = purchase_rows(&state);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].store_contract_id, vec![1u8; 32]);
        assert_eq!(rows[0].name, "Beans");
        assert_eq!(rows[0].conversations, 1);
    }

    /// A background load is sent once per store, not for one already loaded
    /// or loading. One whose GET fails to go out, or times out, is sent again
    /// only after its wait (with the connection down each retry is itself a
    /// change of state that asks again), each wait longer, and a few times;
    /// the store reads as loading until the last gives up. Red retrying at
    /// once, and red never retrying a timed-out load.
    #[test]
    fn a_remembered_store_is_retried_after_a_wait_until_it_gives_up() {
        use crate::state::{store_load_retry_after, StoreName, MAX_STORE_LOAD_ATTEMPTS};
        let id = vec![1u8; 32];
        let mut state = AppState::default();
        assert!(state.begin_background_load(id.clone(), "code".into(), false));
        assert!(!state.begin_background_load(id.clone(), "code".into(), false));
        state.end_background_load_failed(&id);
        assert!(
            !state.browsing_stores.contains_key(&id),
            "placeholder taken out"
        );
        assert!(!state.background_load_due(&id, crate::state::now_ms(), false));
        assert_eq!(
            state.store_name_of(&id),
            StoreName::Loading,
            "a retry is pending"
        );
        assert_eq!(
            state.background_retry_after(&id),
            Some(store_load_retry_after(1))
        );

        let rewind = |state: &mut AppState, by: u64| {
            state.store_load_failures.get_mut(&id).unwrap().1 -= by;
        };
        rewind(&mut state, store_load_retry_after(1));
        assert!(state.begin_background_load(id.clone(), "code".into(), false));
        // This one goes out and is never answered: counted too.
        state.end_background_load_timed_out(&id);
        assert!(
            state.browsing_stores.contains_key(&id),
            "a late answer is still taken"
        );
        assert!(store_load_retry_after(2) > store_load_retry_after(1));
        rewind(&mut state, store_load_retry_after(1));
        assert!(
            !state.background_load_due(&id, crate::state::now_ms(), false),
            "the second wait is longer"
        );
        for attempt in 2..MAX_STORE_LOAD_ATTEMPTS {
            rewind(&mut state, store_load_retry_after(attempt));
            assert!(state.begin_background_load(id.clone(), "code".into(), false));
            state.end_background_load_timed_out(&id);
        }
        assert_eq!(state.background_retry_after(&id), None, "no tries left");
        rewind(
            &mut state,
            100 * store_load_retry_after(MAX_STORE_LOAD_ATTEMPTS),
        );
        assert!(!state.background_load_due(&id, crate::state::now_ms(), false));
        assert_eq!(state.store_name_of(&id), StoreName::Unreachable);

        // Its state arriving clears it all.
        state.on_contract_state(id.clone(), super::background_tests::some_store_state());
        assert!(state.store_load_failures.is_empty());
    }

    /// A failed load takes out only a placeholder nothing else has written
    /// into: state that arrived meanwhile is kept.
    #[test]
    fn a_failed_load_keeps_what_was_written_into_its_entry() {
        let mut state = AppState::default();
        assert!(state.begin_background_load(vec![2u8; 32], "code".into(), false));
        state
            .browsing_stores
            .get_mut(&vec![2u8; 32])
            .unwrap()
            .reputation_contract_id = Some(vec![9u8; 32]);
        state.end_background_load_failed(&[2u8; 32]);
        assert!(
            state.browsing_stores.contains_key(&vec![2u8; 32]),
            "written-into kept"
        );

        state.browsing_stores.insert(vec![3u8; 32], named("Loaded"));
        assert!(!state.begin_background_load(vec![3u8; 32], "code".into(), false));
    }

    /// A store loaded only to be listed is loaded again, with a
    /// subscription, when Purchases wants it or the user opens it, and it
    /// stops being "light" only when that subscribed state arrives: a
    /// subscribed GET that fails leaves it light, so it is asked again after
    /// the wait (round 2 of #197). Its answer is followed to its record
    /// while that GET is out. Red if Purchases skips a store the Stores page
    /// loaded, and red dropping the flag before the answer.
    #[test]
    fn a_listed_store_stays_listed_until_a_subscribed_answer_arrives() {
        use crate::state::store_load_retry_after;
        let id = vec![0x34u8; 32];
        let mut state = AppState::default();
        assert!(state.begin_background_load(id.clone(), "code".into(), false));
        state.on_contract_state(id.clone(), super::background_tests::some_store_state());
        assert!(state.light_stores.contains(&id), "loaded, listed only");
        assert!(!state.follows_record(&id));
        assert!(!state.background_load_due(&id, crate::state::now_ms(), false));
        assert!(state.background_load_due(&id, crate::state::now_ms(), true));

        // Purchases' subscribed GET fails to go out: still listed only, and
        // asked again once the wait is over, not before.
        assert!(state.begin_background_load(id.clone(), "code".into(), true));
        assert!(state.follows_record(&id), "its answer is followed");
        state.end_background_load_failed(&id);
        assert!(state.light_stores.contains(&id));
        assert!(!state.follows_record(&id));
        assert!(!state.background_load_due(&id, crate::state::now_ms(), true));
        state.store_load_failures.get_mut(&id).unwrap().1 -= store_load_retry_after(1);
        assert!(state.background_load_due(&id, crate::state::now_ms(), true));

        // The user opens it: one GET, and a second open does not add a
        // second wait; its answer takes it off the list-only set.
        assert!(state.begin_foreground_load(&id));
        assert!(!state.begin_foreground_load(&id), "its GET is already out");
        assert!(!state.background_load_due(&id, crate::state::now_ms(), true));
        state.on_contract_state(id.clone(), super::background_tests::some_store_state());
        assert!(!state.light_stores.contains(&id));
        assert!(state.follows_record(&id));
    }

    /// A background load's timer that fires after the store's state arrived
    /// changes nothing: no failure counted, no retry. An answer with nothing
    /// in it is a failed try.
    #[test]
    fn a_late_timer_does_nothing_once_the_store_is_in() {
        let id = vec![0x35u8; 32];
        let mut state = AppState::default();
        assert!(state.begin_background_load(id.clone(), "code".into(), false));
        state.on_contract_state(id.clone(), super::background_tests::some_store_state());
        state.end_background_load_timed_out(&id);
        state.end_background_load_failed(&id);
        assert!(state.store_load_failures.is_empty());
        assert_eq!(state.background_retry_after(&id), None);

        let empty = vec![0x36u8; 32];
        assert!(state.begin_background_load(empty.clone(), "code".into(), false));
        state.on_contract_state(empty.clone(), Vec::new());
        assert_eq!(state.store_load_failures.get(&empty).map(|f| f.0), Some(1));
    }

    /// One of our own is never loaded as only listed, and if the Stores page
    /// listed it before our store list arrived, subscribing to it as ours
    /// ends that, so its record is followed (round 2 of #197). Red without
    /// the clear in `note_store_subscribed`.
    #[test]
    fn our_own_store_is_never_only_listed() {
        let id = vec![0x37u8; 32];
        let mut state = AppState::default();
        assert!(state.begin_background_load(id.clone(), "code".into(), false));
        assert!(state.light_stores.contains(&id), "not known to be ours yet");
        state.route_own_store(&id, &[0x38u8; 32]);
        assert!(!state.light_stores.contains(&id));
        assert!(state.follows_record(&id));

        let ours = vec![0x39u8; 32];
        state.my_stores.insert(
            "fp".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: ours.clone(),
                reputation_contract_id: Vec::new(),
                mailbox_contract_id: Vec::new(),
                store_contract_key: None,
                store_verifying_key: None,
            }],
        );
        assert!(state.begin_background_load(ours.clone(), "code".into(), false));
        assert!(!state.light_stores.contains(&ours));
    }

    /// An unreachable store is said, never taken for an empty history.
    #[test]
    fn a_store_that_could_not_load_is_said() {
        assert_eq!(unreachable_note(0), None);
        assert!(unreachable_note(1)
            .unwrap()
            .starts_with("1 store you have used couldn"));
        assert!(unreachable_note(2)
            .unwrap()
            .starts_with("2 stores you have used couldn"));
    }

    /// Bytes that are not a store's state are a failed try, with its wait,
    /// like an empty answer; the page does not ask again at once (codex P1
    /// on #197 round 4).
    #[test]
    fn an_answer_that_is_not_a_store_is_a_failed_try() {
        let id = vec![0x3Au8; 32];
        let mut state = AppState::default();
        assert!(state.begin_background_load(id.clone(), "code".into(), false));
        state.on_contract_state(id.clone(), vec![0xFF, 0x00, 0x13]);
        assert_eq!(state.store_load_failures.get(&id).map(|f| f.0), Some(1));
        assert!(!state.background_load_due(&id, crate::state::now_ms(), false));
    }
}

#[cfg(test)]
mod background_tests {
    use super::*;

    pub(super) fn some_store_state() -> Vec<u8> {
        use ed25519_dalek::SigningKey;
        use harvest_common::listing::{
            AuthorizedListingStatus, ListingAvailability, ListingId, ListingStatus,
        };
        use harvest_common::store::{StoreStateV1, StoreStateV1Delta};
        let key = SigningKey::from_bytes(&[0x34; 32]);
        let params = harvest_common::StoreParameters::new(key.verifying_key());
        let status = ListingStatus {
            listing: ListingId([1u8; 32]),
            revision: 1,
            availability: ListingAvailability::SoldOut,
        };
        let (scoped_payload, signature) = harvest_common::backing::sign_with_store_key(
            &key,
            harvest_common::to_cbor(&status).unwrap(),
        )
        .unwrap();
        let mut state = StoreStateV1::default();
        freenet_scaffold::ComposableState::apply_delta(
            &mut state,
            &StoreStateV1::default(),
            &params,
            &Some(StoreStateV1Delta {
                owner: Some(key.verifying_key()),
                listing_statuses: Some(vec![AuthorizedListingStatus {
                    status,
                    scoped_payload,
                    signature,
                }]),
                ..Default::default()
            }),
        )
        .unwrap();
        harvest_common::to_cbor(&state).unwrap()
    }

    /// A store loaded in the background for My purchases does not become the
    /// store the Stores page shows, and stops reading as loading when it
    /// arrives. Mutated red by dropping the `!background` condition.
    #[test]
    fn a_background_arrival_does_not_become_the_open_store() {
        let mut state = AppState::default();
        assert!(state.begin_background_load(vec![7u8; 32], "code".into(), true));
        state.on_contract_state(vec![7u8; 32], some_store_state());
        assert_eq!(state.active_store_id, None);
        assert!(state.background_loads.is_empty());

        // A store the user opened still does.
        let mut state = AppState::default();
        state.on_contract_state(vec![8u8; 32], some_store_state());
        assert_eq!(state.active_store_id, Some(vec![8u8; 32]));
    }
}
