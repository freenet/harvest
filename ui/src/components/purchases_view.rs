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

/// A string as a JavaScript literal, for the few lines `eval` runs.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn js_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Offer `text` as a file named `name`.
#[cfg(target_arch = "wasm32")]
fn download(name: &str, text: &str) {
    let _ = document::eval(&format!(
        "const a = document.createElement('a');\
         a.href = URL.createObjectURL(new Blob([{}], {{ type: 'text/plain' }}));\
         a.download = {};\
         document.body.appendChild(a); a.click(); a.remove();",
        js_string(text),
        js_string(name)
    ));
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
    /// "Aran skein × 1", or `unnamed_order` when the item can't be named here.
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
                    None => unnamed_order(state.store_name_of(id).name()),
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
        let found = state
            .browsing_stores
            .iter()
            .find(|(_, s)| s.owner == Some(kept.store_key))
            .map(|(id, _)| state.store_name_of(id));
        let item = unnamed_order(found.as_ref().and_then(|n| n.name()));
        let store = found
            .map(|n| n.label())
            .unwrap_or_else(|| "A store you have used".to_string());
        rows.push(OrderRow {
            page: Page::Order {
                at: OrderAt::Kept(kept.store_key),
                order: kept.order.order.id.clone(),
            },
            item,
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

/// Whether any purchase or conversation this device keeps is in no backup
/// the buyer saved: the banner that sends the buyer to Backup until there
/// is one.
pub(crate) fn backup_due(state: &AppState) -> bool {
    state.not_backed_up() != (0, 0)
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

/// The id of the hidden file input "Restore from a file" opens.
const RESTORE_INPUT: &str = "purchases-backup-file";

/// P9: one file with every purchase and conversation this device keeps,
/// and bringing one back on another device (step 2; `crate::backup_flow`).
///
/// The file is made as the page opens, so saving it is one click; the
/// click is what marks what it holds as backed up, so a file never saved
/// marks nothing.
#[component]
pub fn BackupPage() -> Element {
    let mut pasting = use_signal(|| false);
    let mut paste = use_signal(String::new);
    // Made once, as the page opens.
    use_hook(|| {
        let out = APP_STATE.write().start_backup_export();
        crate::backup_flow::send_all(out);
    });
    // "Preparing" is judged against the clock: a request whose answer never
    // came stops holding the buttons once its wait is over.
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
    let (purchases, conversations, message, busy, restoring, ready, addresses, books_unread) = {
        let state = APP_STATE.read();
        let (purchases, conversations) = state.not_backed_up();
        (
            purchases,
            conversations,
            state.backup_message.clone(),
            state.backup_busy_at(crate::state::now_ms()),
            state.backup_restore.is_some(),
            state.backup_file_ready.clone(),
            state.unsent_addresses_in_backup(),
            state.seller_books_unread(),
        )
    };
    let restore = |text: String| {
        let out = APP_STATE.write().start_restore(&text);
        crate::backup_flow::send_all(out);
    };
    let save = move |copy: bool| {
        let Some((name, text)) = APP_STATE.read().ready_backup_file() else {
            return;
        };
        let made = APP_STATE
            .read()
            .backup_file_ready
            .as_ref()
            .map_or(0, |r| r.bundle.made_at_ms);
        let saved = move || {
            let out = APP_STATE.write().backup_saved_of(made);
            crate::backup_flow::send_all(out);
        };
        // Marked only once the text is on the clipboard: a copy the browser
        // refused saved nothing. A download cannot be followed that far; the
        // click that asked for it is the buyer's say-so.
        #[cfg(target_arch = "wasm32")]
        if copy {
            spawn(async move {
                let mut copied = document::eval(&format!(
                    "navigator.clipboard.writeText({}).then(\
                     () => dioxus.send(true), () => dioxus.send(false));",
                    js_string(&text)
                ));
                if copied.recv::<bool>().await.unwrap_or(false) {
                    saved();
                } else {
                    APP_STATE.write().backup_message = Some(COPY_REFUSED.to_string());
                }
            });
        } else {
            download(&name, &text);
            saved();
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (copy, &name, &text);
            saved();
        }
    };
    rsx! {
        super::seller_pages::BackTo { label: "Purchases".to_string(), page: Page::Purchases }
        div { class: "page-head",
            h2 { class: "page-h", "Backup" }
            if purchases + conversations > 0 {
                span { class: "pill", "Not backed up" }
            }
        }
        p { class: "lede",
            "Your purchases and messages are saved on this device only. A backup lets you see \
             them, and report a problem, on another device."
        }
        section { class: "panel",
            h3 { class: "panel-h", "Save a backup" }
            match unsaved_line(purchases, conversations) {
                Some(line) => rsx! { p { class: "text-warning", "{line}" } },
                None => rsx! {
                    p { class: "text-muted small", "Every purchase and conversation on this device is in a backup you saved." }
                },
            }
            p { class: "text-muted small", "{crate::backup_flow::KEEP_IT_PRIVATE}" }
            if let Some(line) = crate::backup_flow::addresses_line(addresses) {
                p { class: "text-warning", "{line}" }
            }
            if books_unread > 0 {
                p { class: "text-muted small", "{BOOKS_UNREAD}" }
            }
            div { class: "row",
                button {
                    class: "btn btn-primary",
                    disabled: ready.is_none(),
                    onclick: move |_| save(false),
                    if ready.is_some() {
                        "Save a backup file"
                    } else if busy && !restoring {
                        "Preparing your backup\u{2026}"
                    } else {
                        "Save a backup file"
                    }
                }
                if ready.is_some() {
                    button {
                        class: "link-btn",
                        onclick: move |_| save(true),
                        "Copy it as text instead"
                    }
                }
                if ready.is_none() && !busy {
                    button {
                        class: "link-btn",
                        onclick: move |_| {
                            let out = APP_STATE.write().start_backup_export();
                            crate::backup_flow::send_all(out);
                        },
                        "Try again"
                    }
                }
            }
        }
        section { class: "panel",
            h3 { class: "panel-h", "Restore from a backup" }
            p { class: "text-muted small",
                "Choose a backup file you saved. What this device already holds stays as it is."
            }
            div { class: "row",
                button {
                    class: "btn btn-outline",
                    disabled: restoring && busy,
                    onclick: move |_| {
                        #[cfg(target_arch = "wasm32")]
                        {
                            let _ = document::eval(&format!(
                                "document.getElementById({}).click();",
                                js_string(RESTORE_INPUT)
                            ));
                        }
                    },
                    "Restore from a file"
                }
                button {
                    class: "link-btn",
                    onclick: move |_| pasting.toggle(),
                    "Paste one instead"
                }
            }
            input {
                id: RESTORE_INPUT,
                r#type: "file",
                accept: ".txt,text/plain",
                style: "display: none;",
                onchange: move |_| {
                    #[cfg(target_arch = "wasm32")]
                    spawn(async move {
                        let mut read = document::eval(&format!(
                            "const input = document.getElementById({});\
                             const file = input.files && input.files[0];\
                             if (file) {{ file.text().then(t => {{ input.value = ''; dioxus.send(t); }}); }}",
                            js_string(RESTORE_INPUT)
                        ));
                        if let Ok(text) = read.recv::<String>().await {
                            restore(text);
                        }
                    });
                },
            }
            if pasting() {
                div { class: "form-group",
                    textarea {
                        class: "form-textarea",
                        rows: "4",
                        placeholder: "Paste a whole backup file, or an older one-conversation backup.",
                        value: "{paste}",
                        oninput: move |e| paste.set(e.value()),
                    }
                    button {
                        class: "btn btn-outline",
                        disabled: (restoring && busy) || paste().trim().is_empty(),
                        onclick: move |_| {
                            restore(paste());
                            paste.set(String::new());
                        },
                        "Restore"
                    }
                }
            }
        }
        if let Some(message) = message {
            p { class: "small", role: "status", "{message}" }
        }
    }
}

/// Said while a store's own orders have not been read yet.
const BOOKS_UNREAD: &str = "Your store\u{2019}s orders on this device are still loading, \
     so a backup saved now leaves them out. Open your store, then come back.";

/// Said when the browser would not put the backup on the clipboard.
const COPY_REFUSED: &str =
    "The browser did not copy the backup, so nothing is marked as saved. Use Save instead.";

/// What Backup says is not in a backup yet, or `None` when everything is.
pub(crate) fn unsaved_line(purchases: usize, conversations: usize) -> Option<String> {
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    match (purchases, conversations) {
        (0, 0) => None,
        (1, 0) => Some("1 purchase isn\u{2019}t in a backup yet.".to_string()),
        (p, 0) => Some(format!("{p} purchases aren\u{2019}t in a backup yet.")),
        (0, 1) => Some("1 conversation isn\u{2019}t in a backup yet.".to_string()),
        (0, c) => Some(format!("{c} conversations aren\u{2019}t in a backup yet.")),
        (p, c) => Some(format!(
            "{} and {} aren\u{2019}t in a backup yet.",
            plural(p, "purchase", "purchases"),
            plural(c, "conversation", "conversations")
        )),
    }
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

/// What an order is called when this device cannot say what it was for.
/// The item is named only inside the buyer's conversation with the store
/// (`Order` carries no listing id, harvest#57), and only for a Buy now
/// (`AppState::purchase_listing`): an order the seller made by hand, one
/// from a forgotten conversation, or one restored from a backup has no item
/// to show. Named by its store when the store's name is known, never by its
/// code, which says nothing to a person; the code is beside it.
pub(crate) fn unnamed_order(store: Option<&str>) -> String {
    match store {
        Some(store) => format!("An order from {store}"),
        None => "An order".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BrowsingStore;

    /// An order this device can't name is named by its store, and only by a
    /// name the store published, never "Loading…" (review of round 4); never
    /// by its code. Mutated red by passing `label()` instead of `name()`.
    #[test]
    fn an_unnamed_order_is_named_by_its_store_or_not_at_all() {
        assert_eq!(
            super::unnamed_order(Some("Bean Shop")),
            "An order from Bean Shop"
        );
        assert_eq!(super::unnamed_order(None), "An order");
        let loading = crate::state::StoreName::Loading;
        assert_eq!(super::unnamed_order(loading.name()), "An order");
    }

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
