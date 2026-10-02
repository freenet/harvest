use dioxus::prelude::*;
use harvest_common::listing::{AuthorizedListing, ListingAvailability};

use super::app::{open_seller_page, Route, SellerPage, ROUTE};
use crate::gateway::APP_STATE;
use crate::presence_flow::SellerStatus;
use crate::state::{AppState, BuyerOpen, StoreListRow, StoreName};

/// The Stores page (the 2026-09-30 redesign, after the mockup's
/// `scrStores()`): the seller's own stores, if any, each opening its
/// seller pages; a way to open a store by its link or code; the stores this
/// node has visited; and, for someone with no store, a quiet way into
/// selling. Opening any store goes to its own page ([`StorePage`]).
#[component]
pub fn StoresPage() -> Element {
    let show_archived = use_signal(|| false);
    // Whether a store is open is judged against the clock (`presence_flow`),
    // so this re-renders every half minute, as the store page does; and
    // once when the wait for `seller_known` runs out, which is kept from the
    // app's start (`AppState::session_started`), not from this page's.
    #[allow(unused_mut)]
    let mut clock = use_signal(|| 0u32);
    #[cfg(target_arch = "wasm32")]
    use_future(move || async move {
        let deadline = crate::gateway::APP_STATE
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
        loop {
            gloo_timers::future::TimeoutFuture::new(30_000).await;
            clock += 1;
        }
    });
    let _ = clock();

    // Until this node knows which stores are its own, a seller's store would
    // flash up as "Sell on Harvest" and as a store they visited (review of
    // #197), so neither list is shown yet, and the visited stores are not
    // asked for yet either: one of ours would be loaded as only listed.
    let known = APP_STATE
        .read()
        .seller_known_or_waited(crate::state::now_ms());
    // The visited stores are asked for in the background, so each row can
    // carry the store's own name rather than its code. An effect, so it runs
    // again when the delegate's list arrives after this page opened. Only
    // what the rows show: no subscription (`AppState::light_stores`).
    use_effect(move || {
        let _ = clock();
        if APP_STATE
            .read()
            .seller_known_or_waited(crate::state::now_ms())
        {
            crate::store_link::load_visited_stores(show_archived(), false);
        }
    });
    let own = own_store_rows(&APP_STATE.read(), crate::state::now_ms());
    let one = own.len() == 1;

    rsx! {
        div { class: "stores-page",
            h2 { "Stores" }
            if known && !own.is_empty() {
                h3 { class: "sec-lbl sec-lbl-first",
                    if one { "Your store" } else { "Your stores" }
                }
                for row in own.iter() {
                    OwnStoreCard { key: "{bs58::encode(&row.contract_id).into_string()}", row: row.clone() }
                }
                button {
                    class: "link-btn",
                    onclick: move |_| open_seller_page(SellerPage::AnotherStore),
                    "Open another store"
                }
            }
            h3 { class: if known && !own.is_empty() { "sec-lbl" } else { "sec-lbl sec-lbl-first" }, "Find a store" }
            FindStore {}
            if known {
                VisitedStores { show_archived }
            } else {
                p { class: "text-muted text-italic", "Checking your stores\u{2026}" }
            }
            if known && own.is_empty() {
                div { class: "card card-quiet sell-card",
                    h3 { "Sell on Harvest" }
                    p { class: "text-muted",
                        "Open a store. Harvest takes no cut, needs no account, and no company can "
                        "shut your store down."
                    }
                    button {
                        class: "link-btn",
                        onclick: move |_| open_seller_page(SellerPage::First),
                        "Open a store \u{203a}"
                    }
                }
            }
        }
    }
}

/// For each of `labels`, whether another one in the list reads the same
/// (case aside): two rows that would look alike, which then carry their
/// store code as the second line.
pub(crate) fn colliding(labels: &[String]) -> Vec<bool> {
    let lower: Vec<String> = labels.iter().map(|l| l.to_lowercase()).collect();
    lower
        .iter()
        .map(|l| lower.iter().filter(|other| *other == l).count() > 1)
        .collect()
}

/// One of this node's own stores on the Stores page. See [`own_store_rows`].
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OwnStoreRow {
    pub contract_id: Vec<u8>,
    /// Its name, or "Loading…" (`my_store::SellerStore::label`).
    pub label: String,
    /// Whether `label` is the store's own name, rather than words standing
    /// in for it.
    pub named: bool,
    /// The second line: the first line of its description, or its code when
    /// nothing else tells the card from another (no name yet and no
    /// tagline, or a name another card has too). Never the name.
    pub sub: Option<String>,
    pub status: OwnStoreStatus,
}

/// What an own store's row card says on the right: what needs the seller,
/// and whether buyers can buy. Both, when both are worth saying (critique
/// 01s-2: "2 need you" hid that the store was not taking orders).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OwnStoreStatus {
    pub needs: Needs,
    pub buyers: Buyers,
}

/// What needs the seller at one of their stores.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Needs {
    Nothing,
    /// Counted (`my_store::SellerStore::needs_you`, the header's count):
    /// "`<n> need(s) you`".
    Count(usize),
    /// Nothing counted, but the Overview's "Needs you" card lists something
    /// all the same (`my_store::overview_needs`): "Needs you".
    Look,
}

/// Whether buyers can buy from one of the seller's stores.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Buyers {
    /// Open, and the Overview says so: "up to date" when nothing needs the
    /// seller, and nothing said otherwise.
    Open,
    /// "Closed", or the seller's own status pill ("Not taking orders" when
    /// buyers see it open but this device cannot answer).
    NotOpen(&'static str),
    /// Too soon to say: "Checking…" when nothing needs the seller.
    Checking,
}

impl OwnStoreStatus {
    /// The amber pill, if something needs the seller.
    fn needs_pill(&self) -> Option<String> {
        match self.needs {
            Needs::Nothing => None,
            Needs::Count(1) => Some("1 needs you".to_string()),
            Needs::Count(n) => Some(format!("{n} need you")),
            Needs::Look => Some("Needs you".to_string()),
        }
    }

    /// The grey pill, if buyers cannot buy: said beside the amber one too.
    fn not_open_pill(&self) -> Option<&'static str> {
        match self.buyers {
            Buyers::NotOpen(pill) => Some(pill),
            _ => None,
        }
    }

    /// The quiet words, when there is no pill to show.
    fn quiet(&self) -> Option<&'static str> {
        if self.needs != Needs::Nothing {
            return None;
        }
        match self.buyers {
            Buyers::Open => Some("up to date"),
            Buyers::Checking => Some("Checking\u{2026}"),
            Buyers::NotOpen(_) => None,
        }
    }

    /// Everything the card says on the right, in order, as text.
    pub(crate) fn words(&self) -> Vec<String> {
        self.needs_pill()
            .into_iter()
            .chain(self.not_open_pill().map(str::to_string))
            .chain(self.quiet().map(str::to_string))
            .collect()
    }
}

/// The status on an own store's row card, from what needs the seller
/// (`needs_you` counted, `needs_a_look` anything else the Overview's "Needs
/// you" card lists), whether buyers can buy (`AppState::buyer_open`, the
/// same answer the store page's pill and the visited rows give) and the ONE
/// status the seller's Overview reads (`presence_flow::seller_status`,
/// `None` for a store that sells nothing here). Nothing new is judged here:
/// a store is "up to date" only where buyers can buy, the Overview would say
/// Open, and it would say "Nothing needs you right now".
pub(crate) fn own_store_status(
    needs_you: usize,
    needs_a_look: bool,
    seller: Option<&SellerStatus>,
    open: BuyerOpen,
) -> OwnStoreStatus {
    let needs = if needs_you > 0 {
        Needs::Count(needs_you)
    } else if needs_a_look {
        Needs::Look
    } else {
        Needs::Nothing
    };
    let seller_pill = seller
        .filter(|status| !status.open)
        .map(|status| status.pill);
    let buyers = match open {
        BuyerOpen::Checking => Buyers::Checking,
        BuyerOpen::Closed => Buyers::NotOpen(seller_pill.unwrap_or("Closed")),
        BuyerOpen::Open => match seller_pill {
            Some(pill) => Buyers::NotOpen(pill),
            None => Buyers::Open,
        },
    };
    OwnStoreStatus { needs, buyers }
}

/// This node's own stores, as the Stores page lists them: every store the
/// seller pages manage (`my_store::seller_stores`), in the same order.
pub(crate) fn own_store_rows(state: &AppState, now_ms: u64) -> Vec<OwnStoreRow> {
    let stores = super::my_store::seller_stores(state);
    let labels: Vec<String> = stores.iter().map(|s| s.label.clone()).collect();
    let collides = colliding(&labels);
    stores
        .into_iter()
        .zip(collides)
        .map(|(store, collides)| {
            let id = store.contract_id.clone();
            let presence = state.store_presence(&id, now_ms);
            let seller = state.instant_checkout_local(&id, now_ms).map(|local| {
                crate::presence_flow::seller_status(
                    presence,
                    state.wakeups_seen_recently(now_ms),
                    &local,
                )
            });
            let named = state.store_name_of(&id).name().is_some();
            let tagline = state
                .browsing_stores
                .get(&id)
                .and_then(|b| b.info.as_ref())
                .and_then(|info| crate::markdown::first_line(&info.description));
            let code_line = store.code.as_ref().map(|code| format!("Store code {code}"));
            let sub = if collides || (!named && tagline.is_none()) {
                code_line.or(tagline)
            } else {
                tagline
            };
            OwnStoreRow {
                status: own_store_status(
                    store.needs_you(),
                    super::my_store::overview_needs(&store, state),
                    seller.as_ref(),
                    state.buyer_open(&id, now_ms),
                ),
                named,
                sub,
                label: store.label,
                contract_id: id,
            }
        })
        .collect()
}

/// A row card for one of the seller's own stores: the whole card opens its
/// seller pages, on the Overview, whose first card is "Needs you".
#[component]
fn OwnStoreCard(row: OwnStoreRow) -> Element {
    let needs = row.status.needs_pill();
    let not_open = row.status.not_open_pill();
    let quiet = row.status.quiet();
    rsx! {
        button {
            class: "rowcard",
            onclick: {
                let id = row.contract_id.clone();
                move |_| open_seller_page(SellerPage::Store(id.clone()))
            },
            span { class: "rc-main",
                span { class: if row.named { "rc-name" } else { "rc-name rc-pending" }, "{row.label}" }
                if let Some(ref sub) = row.sub {
                    span { class: "rc-sub", "{sub}" }
                }
            }
            span { class: "rc-status",
                if let Some(needs) = needs {
                    span { class: "pill pill-needs", "{needs}" }
                }
                if let Some(not_open) = not_open {
                    span { class: "pill", "{not_open}" }
                }
                if let Some(quiet) = quiet {
                    span { class: "text-muted small", "{quiet}" }
                }
            }
            span { class: "chev", aria_hidden: "true", "\u{203a}" }
        }
    }
}

/// Whether a pasted link names a store the old way, from its fragment or
/// query string: the same check a followed link gets.
fn typed_is_old_format_link(typed: &str) -> bool {
    crate::store_link::link_sections(typed.trim()).any(crate::store_link::is_old_format_link)
}

/// What someone who typed `typed` into "Find a store" is told when it opens
/// nothing.
fn not_a_store_message(typed: &str) -> String {
    if typed_is_old_format_link(typed) {
        crate::store_link::OLD_FORMAT_LINK_MESSAGE.to_string()
    } else {
        "That doesn\u{2019}t look like a store link. Paste the whole link the seller gave \
         you, or their 16-character store code."
            .to_string()
    }
}

/// "Find a store": a link or a code, opened on the store's own page.
#[component]
fn FindStore() -> Element {
    let mut typed = use_signal(String::new);
    let mut typed_error = use_signal(|| Option::<String>::None);

    let mut open_typed = move || match crate::store_link::parse_typed_store_code(&typed()) {
        Some(params) => {
            typed_error.set(None);
            typed.set(String::new());
            crate::store_link::open_store(params);
        }
        None => typed_error.set(Some(not_a_store_message(&typed()))),
    };

    rsx! {
        div { class: "find-store",
            input {
                class: "form-input",
                r#type: "text",
                spellcheck: false,
                aria_label: "Store link or store code",
                placeholder: "Paste a link or store code",
                value: "{typed}",
                oninput: move |e| typed.set(e.value()),
                onkeydown: move |e| {
                    if e.key() == Key::Enter {
                        open_typed();
                    }
                },
            }
            button { class: "btn btn-primary", onclick: move |_| open_typed(), "Open" }
        }
        if let Some(ref why) = typed_error() {
            p { class: "text-warning", "{why}" }
        }
    }
}

/// The main and second line of a visited store's row: its name (never its
/// code), then its tagline, or when closed, "Closed right now" if only for
/// now (its seller's computer is offline) and "Closed" otherwise (mockup
/// `vrow.closed`, critique 01-3); its code instead when nothing else tells
/// it from another row (`collides`: another row reads the same; or no name
/// and no tagline), with "Closed" after it when closed, so the row still
/// says so.
fn visited_row_lines(row: &StoreListRow, collides: bool) -> (String, Option<String>) {
    let closed = match (row.closed, row.closed_for_now) {
        (false, _) => None,
        (true, true) => Some("Closed right now"),
        (true, false) => Some("Closed"),
    };
    let second = if collides || (row.name.name().is_none() && row.tagline.is_none()) {
        Some(match closed {
            Some(_) => format!("Store code {} \u{00b7} Closed", row.code),
            None => format!("Store code {}", row.code),
        })
    } else if let Some(closed) = closed {
        Some(closed.to_string())
    } else {
        row.tagline.clone()
    };
    (row.name.label(), second)
}

/// "Stores you've visited" (harvest#52): every store this node remembers
/// but its own, each opening its page, with "Remove from list".
///
/// # Remove from list, and why it says what it does not do
///
/// Removing hides a row and deletes nothing (it is the delegate's
/// `SetStoreArchived`, "Archive" until the 2026-09-30 Stores page): a
/// buyer's history with a store IS its conversations, so a "remove" that
/// removed would take them with it. Deleting a conversation is
/// `ForgetBuyerConversation`, inside the thread. So the text beside the
/// control says so, and removed stores can be shown and put back.
#[component]
fn VisitedStores(show_archived: Signal<bool>) -> Element {
    let (rows, hidden) = APP_STATE.read().store_list_rows(show_archived());
    let any_archived = hidden > 0 || rows.iter().any(|row| row.archived);
    if rows.is_empty() && !any_archived {
        return rsx! {};
    }
    let labels: Vec<String> = rows.iter().map(|row| row.name.label()).collect();
    let collides = colliding(&labels);

    rsx! {
        h3 { class: "sec-lbl", "Stores you\u{2019}ve visited" }
        if !rows.is_empty() {
            div { class: "vlist",
                for (row , collides) in rows.into_iter().zip(collides) {
                    VisitedRow { key: "{row.code}", row, collides }
                }
            }
        }
        if hidden > 0 {
            button {
                class: "link-btn",
                onclick: move |_| show_archived.set(true),
                if hidden == 1 { "Show 1 removed store" } else { "Show {hidden} removed stores" }
            }
        } else if show_archived() && any_archived {
            button {
                class: "link-btn",
                onclick: move |_| show_archived.set(false),
                "Hide removed stores"
            }
        }
        if any_archived {
            p { class: "text-muted small",
                "Removing a store only hides it from this list. Your conversations with it are kept."
            }
        }
    }
}

/// Open the store a visited row names: its page, without fetching again a
/// store already here and followed (`app::open_store_page`).
fn open_visited(code: &str) {
    let Some(params) = harvest_common::StoreParameters::from_code(code) else {
        return;
    };
    match crate::gateway::store_ops::store_instance_id(&params) {
        Ok(id) => super::app::open_store_page(id.as_bytes().to_vec()),
        Err(_) => crate::store_link::open_store(params),
    }
}

#[component]
fn VisitedRow(row: StoreListRow, collides: bool) -> Element {
    let (main, second) = visited_row_lines(&row, collides);
    let remove_title =
        (!row.archived).then_some("Hides it from this list. Your conversations with it are kept.");
    let code = row.code.clone();
    rsx! {
        div { class: if row.closed || row.archived { "vrow vrow-off" } else { "vrow" },
            button {
                class: "vrow-go",
                onclick: {
                    let code = code.clone();
                    move |_| open_visited(&code)
                },
                span { class: if row.name.name().is_some() { "rc-name" } else { "rc-name rc-pending" }, "{main}" }
                if let Some(ref second) = second {
                    span { class: "rc-sub", "{second}" }
                }
            }
            // The same "›" as a card of our own: the row opens the store
            // (critique 01-1).
            span {
                class: "chev vrow-chev",
                aria_hidden: "true",
                onclick: move |_| open_visited(&code),
                "\u{203a}"
            }
            button {
                class: "link-btn vrow-remove",
                title: remove_title,
                onclick: {
                    let code = row.code.clone();
                    let archive = !row.archived;
                    move |_| APP_STATE.write().set_store_archived(&code, archive)
                },
                if row.archived { "Put back on the list" } else { "Remove from list" }
            }
        }
    }
}

/// A store's own page (the 2026-09-30 redesign, after the mockup's
/// `scrStore()`): only that store, with a way back to Stores. Loading and a
/// link that opened nothing are said here, where the store would be.
#[component]
pub fn StorePage() -> Element {
    let app_state = APP_STATE.read();

    // `AppState::displayed_store` owns this choice, so the document title
    // (see `components::App`) cannot answer it differently.
    let store_entry = app_state
        .displayed_store()
        .map(|(id, store)| (id.clone(), store.clone()));

    // A store was opened but its state hasn't come back yet. Once
    // `store_link_error` is set, or the store is otherwise known not to have
    // arrived (`AppState::store_name_of`), the wait is over and the message
    // changes -- otherwise this reads "Loading store…" for the rest of the
    // session.
    let link_error = app_state.store_link_error.clone();
    let unreachable = store_entry.is_none()
        && app_state
            .active_store_id
            .as_ref()
            .is_some_and(|id| app_state.store_name_of(id) == StoreName::Unreachable);
    let awaiting = store_entry.is_none()
        && app_state.active_store_id.is_some()
        && link_error.is_none()
        && !unreachable;
    // On one of our own stores the banner's "Back to managing it" is the way
    // back; a crumb to Stores above it would be a second one going somewhere
    // else (critique 02s-1). Until the store has loaded there is no banner,
    // so the crumb stays until then.
    let owned = store_entry.is_some()
        && app_state
            .active_store_id
            .as_ref()
            .is_some_and(|id| app_state.store_owner_fingerprint(id).is_some());
    drop(app_state);

    rsx! {
        div { class: "store-page",
            if !owned {
                button {
                    class: "crumb",
                    onclick: move |_| *ROUTE.write() = Route::Stores,
                    "\u{2039} Stores"
                }
            }
            match store_entry {
                Some((contract_id, store)) => {
                    rsx! { LoadedStore { store: store, contract_id: contract_id } }
                }
                None if awaiting => {
                    rsx! {
                        p { class: "text-muted text-italic", "Loading store\u{2026}" }
                    }
                }
                None => {
                    match link_error {
                        Some(message) => rsx! {
                            p { class: "text-warning", "{message}" }
                        },
                        None if unreachable => rsx! {
                            p { class: "text-warning",
                                "That store didn\u{2019}t load. It may not be reachable right now."
                            }
                        },
                        None => rsx! {
                            p { class: "text-muted text-italic", "No store is open." }
                        },
                    }
                }
            }
        }
    }
}

#[component]
fn LoadedStore(store: crate::state::BrowsingStore, contract_id: Vec<u8>) -> Element {
    let info = store.info.as_ref().unwrap();
    // Counted the way the store's record (`StoreRecord`) counts them
    // (`BrowsingStore::complaint_standings`), so the trust line and the
    // record agree, and neither reads the store's status.
    let (backing_text, record_text) = trust_parts(&store);
    let unrecognised_complaints = store.complaints_under_unrecognised_bridges();
    let mut show_messages = use_signal(|| false);
    let mut show_record = use_signal(|| false);
    // A listing its seller took down is not shown to buyers at all
    // (harvest#70); one that sold out is, marked, so an old link does not
    // land on a gap.
    let listings = visible_listings(&store);
    // Read once, here, rather than inside the per-listing helper: this
    // component re-renders on every keystroke in the boxes below it, and the
    // answer cannot change between two listings of the same store.
    let owned = APP_STATE
        .read()
        .store_owner_fingerprint(&contract_id)
        .is_some();
    // Whether the store is open is judged against the clock, so this
    // re-renders every half minute: a store whose seller went offline reads
    // closed within the ten minutes the rule allows, with nobody touching
    // anything.
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
    let now = crate::state::now_ms();
    let presence = APP_STATE.read().store_presence(&contract_id, now);
    // Open only where a buyer can buy: the one answer the visited rows and
    // the seller's own cards give too (`AppState::buyer_open`; codex on
    // #197: presence alone called a store Open whose Buy controls were all
    // hidden).
    let buyer_open = APP_STATE.read().buyer_open(&contract_id, now);
    let pill = buyer_open.pill();
    let pill_open = buyer_open == BuyerOpen::Open;
    let is_closed = buyer_open == BuyerOpen::Closed;
    // Presence says open, and yet no order can be taken: why, beside the
    // Closed pill (round 2 of #197: an unbacked store read Closed with no
    // reason given).
    let cannot_take = !store.closed && presence.is_open() && !store.takes_orders();
    let name = match info.store_name.trim() {
        "" => StoreName::Unnamed.label(),
        name => name.to_string(),
    };
    // This buyer's orders from this store are on Purchases, once: here only
    // a line that goes there (critique S2-10).
    let orders_here = if owned {
        OrdersHere::default()
    } else {
        orders_here(&APP_STATE.read().buyer_purchases(&contract_id))
    };

    rsx! {
        div {
            // A seller looking at their own store sees it as a buyer would,
            // and is sent back to its seller pages to manage it rather than
            // offered a way to message themselves (entity model, wireframe F).
            if owned {
                div { class: "own-store-banner",
                    span { "This is your store, as buyers see it." }
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: {
                            let id = contract_id.clone();
                            move |_| open_seller_page(SellerPage::Store(id.clone()))
                        },
                        "Back to managing it"
                    }
                }
            }

            div { class: if is_closed { "store-header store-header-closed" } else { "store-header" },
                // Open or Closed beside the name, as buyers see it
                // (`presence_flow`; the 2026-09-26 decision, critique S2-3).
                div { class: "store-status",
                    h2 { class: "store-name", "{name}" }
                    span { class: if pill_open { "pill pill-open" } else { "pill" }, "{pill}" }
                }
                // What the seller has at stake, in a buyer's words: never a
                // key id or "Ghost Key" (mockup decision 3, critique S2-2).
                // No "Open since" and no amount: see `backing_words`.
                p { class: "trust",
                    "{backing_text} \u{00b7} "
                    // "No complaints" only once the record has been read
                    // (review round 1 of #143, P1-5). Opens the store's
                    // record, under its own heading (critique S2-4).
                    button {
                        // One neutral colour whatever the count: an alarm
                        // colour before the buyer knows what the record says
                        // told them nothing (critique 02-4).
                        class: "link-btn trust-record",
                        aria_expanded: if show_record() { "true" } else { "false" },
                        aria_controls: "store-record",
                        onclick: move |_| show_record.toggle(),
                        "{record_text}"
                    }
                }
                if store.certificate_status.is_verified() {
                    p { class: "trust-why", "{TRUST_WHY}" }
                }
                crate::markdown::Markdown {
                    source: info.description.clone(),
                    class: "store-desc",
                }

                // The verdict, spelled out. The trust line alone tells a
                // buyer that something is wrong without telling them what it
                // costs them, and this is the one line on the page that
                // decides whether the seller has anything at stake.
                if !store.certificate_status.is_verified() {
                    p { class: "text-warning",
                        "{certificate_warning(&store.certificate_status)}"
                    }
                }

                // Round 6 of #143: past the cap the count is a floor.
                if store.record_full() {
                    p { class: "text-warning",
                        "This seller's record is full: it holds {harvest_common::reputation::MAX_COMPLAINTS} \
                         complaints, the most a record can. A new complaint is kept only in place of \
                         one dated farther from its payment, so the count here may be less than \
                         every complaint ever made."
                    }
                    // harvest#144: uncounted complaints can still take a
                    // full record's places, so say how many do.
                    if unrecognised_complaints > 0 {
                        p { class: "text-warning",
                            "{unrecognised_complaints} of them are about orders paid through a Bitcoin \
                             bridge this app does not recognise, so they are not counted. Anyone can \
                             run a bridge, the seller included, so those complaints may have pushed \
                             genuine ones off the record."
                        }
                    }
                }

                // Said plainly: a closed store's key may be in someone
                // else's hands, so nothing on this page can be bought, and
                // the record stays visible (harvest#93, 6.4). Otherwise why
                // it is not open, for which Buy now is withheld below.
                if store.closed {
                    p { class: "text-warning",
                        "This store has closed. Its seller closed it because its key may be \
                         in someone else's hands, so nothing here can be bought. Its record \
                         stays visible."
                    }
                } else if cannot_take {
                    p { class: "text-warning", "{cannot_take_orders_line(&store.certificate_status)}" }
                } else if !owned {
                    if let Some(line) = presence.buyer_line() {
                        p { class: if presence.is_closed() { "text-warning" } else { "text-muted" },
                            "{line}"
                        }
                    }
                }
            }

            if show_record() {
                section {
                    class: "card store-record-card",
                    id: "store-record",
                    aria_label: "{name}\u{2019}s record",
                    div { class: "record-head",
                        h3 { "Record" }
                        button {
                            class: "link-btn",
                            onclick: move |_| show_record.set(false),
                            "Hide"
                        }
                    }
                    super::reputation_view::StoreRecord { store_contract_id: contract_id.clone() }
                }
            }

            if orders_here.live > 0 {
                p { class: "store-orders-line",
                    button {
                        class: "link-btn",
                        onclick: move |_| *ROUTE.write() = Route::Purchases,
                        "{orders_line(orders_here)}"
                    }
                }
            }

            if listings.is_empty() {
                p { class: "text-muted text-italic", "No listings yet." }
            } else {
                p { class: "section-count",
                    if listings.len() == 1 { "1 listing" } else { "{listings.len()} listings" }
                }
                for (listing , availability) in listings.iter() {
                    ListingCard {
                        key: "{listing.listing.id}",
                        listing: listing.clone(),
                        availability: availability.clone(),
                        // Only when it adds something. If the store's own
                        // certificate failed, the warning above already
                        // covers everything under it, and repeating it on
                        // every card is the kind of noise that teaches a
                        // reader to skip warnings.
                        certificate_mismatch: store.certificate_status.is_verified()
                            && store.unverified_listings.contains(&listing.listing.id),
                        // `None` disables the Buy control rather than hiding
                        // the listing. A store whose certificate does not
                        // verify, or which publishes no encryption key, can
                        // still be READ -- what it cannot be is bought from,
                        // because there is no key to encrypt an address to
                        // and no identity to hold to the order. See
                        // `BuyControl`.
                        // `None` for a listing whose OWN certificate did
                        // not verify, as well as for a store that cannot be
                        // bought from at all. The store-level check cannot
                        // see this: `buyable` is computed once per store,
                        // and a mismatched listing is a per-listing fact.
                        // And for a listing its seller has marked sold out
                        // (harvest#70): shown, never offered.
                        buyable: offered_buy(&store, &contract_id, owned, &listing.listing, availability, pill_open),
                        // A Buy now form already open stays when the store
                        // closes under it, so the pay card of an order it
                        // made does not vanish (review of #197); it just
                        // cannot send another.
                        keep_form: offered_buy(&store, &contract_id, owned, &listing.listing, availability, true),
                        // On our own store, a Buy now shown where a buyer
                        // would get one, disabled (critique 02s-2).
                        own_preview: owned
                            && offered_buy(&store, &contract_id, false, &listing.listing, availability, pill_open)
                                .is_some(),
                        closed: is_closed,
                    }
                }
            }

            // Under the listings, and quieter than any Buy now (mockup
            // `scrStore`, critique 02-1). Disabled on our own store: a seller
            // does not message themselves.
            div { class: "store-ask",
                button {
                    class: "btn btn-outline",
                    disabled: owned,
                    title: owned.then_some("This is your own store"),
                    onclick: move |_| show_messages.toggle(),
                    if show_messages() { "Hide messages" } else { "Ask the seller a question" }
                }
            }
            if show_messages() && !owned {
                super::message_view::MessageView { store_contract_id: contract_id.clone() }
            }

            // No list of the store's invoices here any more (critique S2-8,
            // S2-9): it showed a buyer other people's orders, and cancelled
            // ones under "Settled". The record is the public evidence; the
            // seller's own orders are on their Orders tab; a buyer's are on
            // Purchases, and the one a Buy now form just made stays under it.
        }
    }
}

/// A store's trust line, as buyers read it on its page: what its backing
/// shows, then its record ("Backed by a donation to Freenet · 1
/// complaint"). The one function the store page, the seller's Overview and
/// their Settings all say it with, so what the seller is told buyers see
/// cannot drift from what buyers do see (critique 12-2: Settings still said
/// "Ghostkey verified" after the store page stopped).
pub(crate) fn trust_parts(store: &crate::state::BrowsingStore) -> (&'static str, String) {
    (
        backing_words(&store.certificate_status),
        store.record_badge().1,
    )
}

/// [`trust_parts`] as one line.
pub(crate) fn trust_line(store: &crate::state::BrowsingStore) -> String {
    let (backing, record) = trust_parts(store);
    format!("{backing} \u{00b7} {record}")
}

/// The first half of a store's trust line: what its backing shows, in a
/// buyer's words.
///
/// Built only from what a reader can check. The mockup's "Open since Aug
/// 2026 · Backed by $20" is not here: the backing's block is chosen by the
/// seller and not yet checked (`harvest_common::backing::BackingStatement`,
/// "Until then it does not prove when the backing was written"), so a date
/// from it would be the seller's word; and the donation amount is
/// deliberately not read (`ghostkey_cert`, "What is deliberately NOT read
/// here").
pub(crate) fn backing_words(status: &crate::ghostkey_cert::CertificateStatus) -> &'static str {
    use crate::ghostkey_cert::CertificateStatus;
    match status {
        CertificateStatus::Verified => "Backed by a donation to Freenet",
        CertificateStatus::Absent => "Not backed by a donation",
        CertificateStatus::Invalid(_) => "Its backing doesn\u{2019}t check out",
    }
}

/// Why a store whose seller is online still cannot take an order, beside its
/// Closed pill: its backing does not hold up, or (backed) it publishes no
/// key to seal a buyer's address to (`BrowsingStore::takes_orders`).
pub(crate) fn cannot_take_orders_line(status: &crate::ghostkey_cert::CertificateStatus) -> String {
    use crate::ghostkey_cert::CertificateStatus;
    match status {
        CertificateStatus::Verified => "This store can\u{2019}t take orders yet: its seller \
             hasn\u{2019}t finished setting it up. You can look, but not buy."
            .to_string(),
        CertificateStatus::Absent => "This store can\u{2019}t take orders: nothing shows its \
             seller has anything at stake. You can look, but not buy."
            .to_string(),
        CertificateStatus::Invalid(_) => "This store can\u{2019}t take orders: the donation it \
             claims doesn\u{2019}t check out. You can look, but not buy."
            .to_string(),
    }
}

/// Under the trust line of a store whose backing checks out. After the
/// mockup's, less "for good": a full record keeps a new complaint in place
/// of an older one (`reputation::MAX_COMPLAINTS`), which the page says when
/// it happens.
const TRUST_WHY: &str = "The seller donated to Freenet to open this store. Complaints stay on \
     its record, and the seller can\u{2019}t remove them.";

/// This buyer's orders from one store, as its page counts them.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct OrdersHere {
    /// Orders still standing ([`orders_here`]).
    pub live: usize,
    /// Of those, the ones the buyer can pay now.
    pub to_pay: usize,
    /// Orders that ended unpaid: cancelled, or too old to pay.
    pub ended: usize,
}

/// Count `purchases` the way a store's page speaks of them.
///
/// **Live**: paid (`BuyerPurchase::paid`, which includes an order this node
/// has seen paid on chain before the seller marked it, and so never drops
/// out for its age or a cancel the payment beat), or published, this
/// buyer's, and neither cancelled nor too old to pay. An unpaid Buy now
/// that expired or was cancelled was never an order (critique 02-2), and a
/// cancelled invoice the seller issued by hand is not one either. One that
/// is not this buyer's (`CommitmentNotForThisBuyer`) is not counted at all.
///
/// **To pay**: live, unpaid, awaiting payment, and nothing between the buyer
/// and paying it but, at most, this node keeping its copy, which the pay
/// button does (`BuyerPurchase::ready_to_keep`). An order a blocker stands
/// in front of (a closed store, a seller whose identity cannot be read, a
/// bridge not recognised, ...) is not one the buyer can pay now, so it is
/// live and not "to pay".
pub(crate) fn orders_here(purchases: &[crate::state::BuyerPurchase]) -> OrdersHere {
    use crate::state::PaymentBlocker;
    use harvest_common::payment::OrderStatus;
    let mut counts = OrdersHere::default();
    for purchase in purchases {
        if purchase.paid.is_some() {
            counts.live += 1;
            continue;
        }
        let has = |wanted: fn(&PaymentBlocker) -> bool| purchase.blockers.iter().any(wanted);
        if has(|b| matches!(b, PaymentBlocker::CommitmentNotForThisBuyer)) {
            continue;
        }
        let Some(order) = purchase.commitment.as_ref() else {
            // Answered in the thread, not yet published: still an order.
            counts.live += 1;
            continue;
        };
        let stale = has(|b| matches!(b, PaymentBlocker::AnchorStale { .. }));
        match order.status {
            OrderStatus::Cancelled => counts.ended += 1,
            OrderStatus::AwaitingPayment if stale => counts.ended += 1,
            OrderStatus::AwaitingPayment => {
                counts.live += 1;
                if purchase.blockers.is_empty() || purchase.ready_to_keep() {
                    counts.to_pay += 1;
                }
            }
            OrderStatus::Paid | OrderStatus::PaymentReversed => counts.live += 1,
        }
    }
    counts
}

/// The one line on a store's page about this buyer's orders from it.
fn orders_line(orders: OrdersHere) -> String {
    let count = match orders.live {
        1 => "You have 1 order from this store".to_string(),
        n => format!("You have {n} orders from this store"),
    };
    match orders.to_pay {
        0 => format!("{count} \u{203a}"),
        n => format!("{count}, {n} to pay \u{203a}"),
    }
}

/// The Buy control for one listing: what [`buyable`] allows for the store,
/// less a listing whose own certificate did not verify, less one its seller
/// marked sold out (harvest#70), less one with no sats price to buy it at,
/// and none at all while the store is not open (`presence_flow`). The
/// component renders exactly this, so the tests assert what the screen does.
fn offered_buy(
    store: &crate::state::BrowsingStore,
    contract_id: &[u8],
    owned: bool,
    listing: &harvest_common::listing::Listing,
    availability: &ListingAvailability,
    open: bool,
) -> Option<Buyable> {
    buyable(store, contract_id, owned)
        .filter(|_| open)
        .filter(|_| !store.unverified_listings.contains(&listing.id))
        .filter(|_| availability.is_buyable())
        .filter(|_| listing.offers_instant_checkout())
}

/// The listings a buyer sees, with each one's availability: every listing
/// except those its seller took down (harvest#70). A sold-out one stays, so an
/// old link lands on it rather than on a gap.
fn visible_listings(
    store: &crate::state::BrowsingStore,
) -> Vec<(AuthorizedListing, ListingAvailability)> {
    let mut shown: Vec<_> = store
        .listings
        .iter()
        .map(|l| (l.clone(), store.availability(&l.listing.id)))
        .filter(|(_, availability)| *availability != ListingAvailability::Withdrawn)
        .collect();
    // What can be bought first, in the seller's order within each group:
    // a sold-out listing first pushed the only Buy now below a phone's fold
    // (round-6 critique). Stable, so the seller's order is kept.
    shown.sort_by_key(|(_, availability)| *availability == ListingAvailability::SoldOut);
    shown
}

/// What an unverified backing means for the person reading the page.
///
/// The two cases are genuinely different and must not be collapsed. A store
/// with no certificate is claiming nothing; a store whose certificate fails
/// is claiming a bond it does not have, which is worse than claiming none.
/// In a buyer's words: no key ids, no "Ghost Key" (mockup decision 3), and
/// so not the technical reason a certificate failed.
fn certificate_warning(status: &crate::ghostkey_cert::CertificateStatus) -> String {
    use crate::ghostkey_cert::CertificateStatus;
    match status {
        CertificateStatus::Verified => String::new(),
        CertificateStatus::Absent => "Nothing shows that this seller gave anything to open this \
             store, so they could abandon it and start again for free."
            .to_string(),
        CertificateStatus::Invalid(_) => "This store claims a donation that doesn\u{2019}t check \
             out. Treat the seller as anonymous: nothing here shows they have anything to lose."
            .to_string(),
    }
}

/// What a buy form needs, or `None` when this store cannot be bought from.
///
/// The three values travel together because they are useless apart: the
/// contract id says where, the encryption key is what the buyer's address is
/// sealed to, and the verifying key is the identity a published commitment
/// has to be signed by. A card holding two of the three could render a Buy
/// button that cannot complete.
#[derive(Clone, PartialEq)]
pub struct Buyable {
    store_contract_id: Vec<u8>,
    seller_encryption_key: [u8; 32],
    seller_verifying_key: [u8; 32],
}

/// Whether this store can be bought from, and with what.
///
/// The same two conditions that decide whether it can be MESSAGED, and
/// necessarily so: a purchase is a conversation. A store with no published
/// encryption key has nothing to seal a shipping address to, and one whose
/// certificate does not verify has no identity whose signature on a
/// commitment would mean anything.
///
/// **Per-store only.** A listing whose OWN certificate does not verify is a
/// per-listing fact this cannot see, and the caller filters on it -- review
/// found the Buy control being offered on exactly those listings while the
/// module comment read as though signature failure disabled buying. The
/// consequence was contained (a commitment for a listing id the seller never
/// signed) but the screen was claiming something it did not do.
fn buyable(
    store: &crate::state::BrowsingStore,
    contract_id: &[u8],
    owned: bool,
) -> Option<Buyable> {
    // A store the connected identity owns is not one to buy from: a seller
    // does not open a conversation with themselves. Passed in rather than
    // read from `APP_STATE` here, so this is a pure function of what it is
    // handed and can be asserted without a Dioxus runtime.
    if owned {
        return None;
    }
    // A closed store's key may be in someone else's hands (harvest#93): an
    // order from it could be anybody's, so nothing here is bought.
    if store.closed {
        return None;
    }
    Some(Buyable {
        store_contract_id: contract_id.to_vec(),
        seller_encryption_key: store.info.as_ref()?.encryption_public_key?,
        seller_verifying_key: store.seller_verifying_key?,
    })
}

#[component]
fn ListingCard(
    listing: AuthorizedListing,
    availability: ListingAvailability,
    certificate_mismatch: bool,
    /// What a new Buy now needs, or `None` when none may start
    /// (`offered_buy`).
    buyable: Option<Buyable>,
    /// The same, whatever the store's presence: a form already open stays
    /// open on it when the store closes, so its pay card stays.
    #[props(default)]
    keep_form: Option<Buyable>,
    /// Our own store, where a buyer would be offered Buy now: shown
    /// disabled, so the seller sees what buyers see.
    #[props(default)]
    own_preview: bool,
    /// The store is closed: greyed, as a sold-out listing is.
    #[props(default)]
    closed: bool,
) -> Element {
    let l = &listing.listing;
    let corner = availability_words(&availability, closed);
    let sold_out = !availability.is_buyable();

    rsx! {
        div { class: if sold_out || closed { "listing-card listing-sold-out" } else { "listing-card" },
            // No kind badge: every listing is a sale now, and "SALE" read as
            // "discounted" (critique S2-5). Availability in its place.
            div { class: "listing-header",
                h4 { "{l.title}" }
                if let Some(corner) = corner {
                    span { class: "listing-stock", "{corner}" }
                }
            }
            // The store verified, and this listing did not: it carries a
            // certificate that is not the seller's. Worth saying loudly,
            // precisely because everything around it checks out.
            if certificate_mismatch {
                // Neutral on purpose: the usual cause is a listing published
                // before its certificate travelled with it, not a forgery,
                // and "not this seller's" read as an accusation.
                p { class: "text-muted",
                    "This listing can\u{2019}t be verified as this seller\u{2019}s, so it can\u{2019}t be bought."
                }
            }
            crate::markdown::Markdown {
                source: l.description.clone(),
                class: "listing-desc",
            }
            // The price, then the delivery under it; no listed date, which a
            // buyer does not need (critique S2-7).
            if let Some((price, delivery)) = price_lines(l) {
                div { class: "listing-terms",
                    span { class: "listing-price", "{price}" }
                    span { class: "listing-delivery", "{delivery}" }
                }
            }
            // A listing from before every listing had a sats price (a
            // quote-only one, a gift or a request) cannot be bought: there is
            // no longer a way to ask the seller for a total. Said, so a buyer
            // is not left looking for a button.
            if !l.offers_instant_checkout() {
                p { class: "text-muted small", "{NOT_PRICED}" }
            }
            match buyable.clone().or(keep_form) {
                Some(form) => rsx! {
                    BuyControl {
                        listing: l.clone(),
                        buyable: form,
                        can_start: buyable.is_some(),
                    }
                },
                None if own_preview => rsx! {
                    div { class: "buy-control",
                        button {
                            class: "btn btn-primary btn-sm",
                            disabled: true,
                            title: "This is your own store",
                            "Buy now"
                        }
                    }
                },
                // Silence rather than a disabled button: a control that can
                // never work is worse than none, and the reason is already on
                // the page above -- the certificate warning, the store's
                // Closed pill and why, or the notice that this store
                // publishes no key to write to.
                None => rsx! {},
            }
        }
    }
}

/// What a listing's top corner says (after the mockup): "Closed" while the
/// store is, "Sold out", "`<n> left`" when the seller counts its stock, and
/// nothing for one on sale with no count.
fn availability_words(availability: &ListingAvailability, store_closed: bool) -> Option<String> {
    if store_closed {
        return Some("Closed".to_string());
    }
    match availability {
        ListingAvailability::Available { quantity: Some(0) } | ListingAvailability::SoldOut => {
            Some("Sold out".to_string())
        }
        ListingAvailability::Available { quantity: Some(n) } => Some(format!("{n} left")),
        _ => None,
    }
}

/// What a buyer is told about a listing that has no sats price.
pub(crate) const NOT_PRICED: &str =
    "Not for sale right now: the seller hasn\u{2019}t given this a price yet.";

/// The price and delivery lines a buyer reads on a listing, or `None` for a
/// listing that has no usable sats price (`Listing::offers_instant_checkout`).
///
/// Only the sats price: the free-text price some older listings carry is not
/// shown, because it is not what a buyer would pay.
pub(crate) fn price_lines(listing: &harvest_common::listing::Listing) -> Option<(String, String)> {
    use harvest_common::listing::DeliveryPrice;
    let checkout = listing
        .checkout
        .as_ref()
        .filter(|_| listing.offers_instant_checkout())?;
    let price = sats_text(checkout.unit_sats);
    let delivery = match &checkout.delivery {
        DeliveryPrice::Included => "Delivery included".to_string(),
        DeliveryPrice::ByRegion(rows) => {
            let rows: Vec<String> = rows
                .iter()
                .map(|row| {
                    if row.sats == 0 {
                        format!("{} free", row.region)
                    } else {
                        format!("{} {}", row.region, sats_text(row.sats))
                    }
                })
                .collect();
            format!("Delivery: {}", rows.join(", "))
        }
    };
    Some((price, delivery))
}

/// "25,000 sats".
pub(crate) fn sats_text(sats: u64) -> String {
    let digits = sats.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    format!("{out} sats")
}

/// The Buy button, and the form it opens.
///
/// Collapsed by default. A storefront is something people read, and a form
/// under every listing would turn a page of things to look at into a page of
/// things to fill in.
#[component]
fn BuyControl(
    listing: harvest_common::listing::Listing,
    buyable: Buyable,
    /// A new Buy now may start. False while the store is not open: no
    /// button, and a form already open stays but cannot send.
    can_start: bool,
) -> Element {
    let mut open = use_signal(|| false);
    if !can_start && !open() {
        return rsx! {};
    }

    rsx! {
        div { class: "buy-control",
            button {
                class: if open() { "btn btn-sm btn-outline" } else { "btn btn-primary btn-sm" },
                onclick: move |_| open.toggle(),
                // "Close", not "Cancel": once an order is placed the form
                // shows its pay card, and "Cancel" there read as cancelling
                // the order.
                if open() { "Close" } else { "Buy now" }
            }
            if open() {
                super::buy_view::BuyForm {
                    store_contract_id: buyable.store_contract_id.clone(),
                    listing: listing.clone(),
                    seller_encryption_key: buyable.seller_encryption_key,
                    seller_verifying_key: buyable.seller_verifying_key,
                    closed: !can_start,
                }
            }
        }
    }
}

#[cfg(test)]
mod buy_control_tests {
    use super::*;
    use harvest_common::store::StoreInfoV1;

    const STORE: &[u8] = &[4u8; 32];

    fn store_with(
        encryption_key: Option<[u8; 32]>,
        identity: Option<[u8; 32]>,
    ) -> crate::state::BrowsingStore {
        crate::state::BrowsingStore {
            info: Some(StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: "seller-fp".to_string(),
                reputation_contract_id: [0u8; 32],
                store_name: "Hot sauce".to_string(),
                description: String::new(),
                encryption_public_key: encryption_key,
                record_public_key: None,
            }),
            seller_verifying_key: identity,
            ..Default::default()
        }
    }

    /// **A store with no published encryption key cannot be bought from.**
    ///
    /// A purchase begins with a shipping address, and there is nothing to
    /// seal it to. Offering the button anyway would put the buyer's address
    /// one click from a failure they cannot fix.
    #[test]
    fn a_store_with_no_encryption_key_cannot_be_bought_from() {
        let store = store_with(None, Some([2u8; 32]));
        assert!(buyable(&store, STORE, false).is_none());
    }

    /// **A store whose identity did not verify cannot be bought from.**
    ///
    /// `seller_verifying_key` is `None` when the certificate does not check
    /// out, and it is the key a published commitment has to be signed by. A
    /// buyer who could reach the Buy button here would be sending an address
    /// to somebody whose order could never be tied to anyone.
    #[test]
    fn a_store_whose_identity_did_not_verify_cannot_be_bought_from() {
        let store = store_with(Some([1u8; 32]), None);
        assert!(buyable(&store, STORE, false).is_none());
    }

    /// **A closed store cannot be bought from**, however well its identity
    /// checks out: the key that signs its orders may be someone else's.
    #[test]
    fn a_closed_store_cannot_be_bought_from() {
        let mut store = store_with(Some([1u8; 32]), Some([2u8; 32]));
        assert!(buyable(&store, STORE, false).is_some());
        store.closed = true;
        assert!(buyable(&store, STORE, false).is_none());
    }

    /// **Your own store is not one you buy from.**
    #[test]
    fn your_own_store_is_not_one_you_buy_from() {
        let store = store_with(Some([1u8; 32]), Some([2u8; 32]));
        assert!(buyable(&store, STORE, true).is_none());
        assert!(
            buyable(&store, STORE, false).is_some(),
            "and the same store IS buyable when it is somebody else's"
        );
    }
}

#[cfg(test)]
mod listing_buy_gate_tests {
    use super::*;
    use harvest_common::listing::ListingId;

    const STORE: &[u8] = &[4u8; 32];

    /// **A listing whose own certificate did not verify cannot be bought.**
    ///
    /// The store may check out perfectly while one listing on it does not --
    /// that is exactly what `unverified_listings` records, and the card
    /// already warns about it. Offering Buy underneath that warning invites a
    /// purchase of something this seller never signed for.
    ///
    /// Written against the expression the component actually renders, since
    /// the store-level `buyable` cannot see a per-listing fact and a test of
    /// `buyable` alone would pass while the screen was wrong.
    #[test]
    fn a_listing_whose_certificate_did_not_verify_is_not_buyable() {
        let good = ListingId([1u8; 32]);
        let bad = ListingId([2u8; 32]);
        let mut store = crate::state::BrowsingStore {
            info: Some(harvest_common::store::StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: "seller-fp".to_string(),
                reputation_contract_id: [0u8; 32],
                store_name: "Hot sauce".to_string(),
                description: String::new(),
                encryption_public_key: Some([1u8; 32]),
                record_public_key: None,
            }),
            seller_verifying_key: Some([2u8; 32]),
            ..Default::default()
        };
        store.unverified_listings.insert(bad.clone());

        let for_listing = |id: &ListingId| {
            buyable(&store, STORE, false).filter(|_| !store.unverified_listings.contains(id))
        };
        assert!(
            for_listing(&good).is_some(),
            "a listing that verifies is buyable"
        );
        assert!(
            for_listing(&bad).is_none(),
            "and one whose certificate is not this seller's is not"
        );
    }
}

#[cfg(test)]
mod typed_link_tests {
    use super::typed_is_old_format_link;

    /// A pasted pre-#52 link gets the old-format notice, like a followed one.
    #[test]
    fn a_pasted_old_link_is_recognised() {
        let old = bs58::encode([5u8; 32]).into_string();
        assert!(typed_is_old_format_link(&format!(
            "http://127.0.0.1:7509/v1/contract/web/x/#store={old}"
        )));
        assert!(typed_is_old_format_link(&format!(" ?store={old}\n")));
        assert!(!typed_is_old_format_link("3Bn8xWqLd6Tz9Kf"));
        assert!(!typed_is_old_format_link(&old), "a bare id is not a link");
    }
}

#[cfg(test)]
mod availability_tests {
    use super::*;
    use harvest_common::listing::{Listing, ListingId, ListingKind, ListingStatus};

    fn listing(n: u8) -> AuthorizedListing {
        AuthorizedListing {
            listing: Listing {
                checkout: None,
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
        }
    }

    fn with_status(
        store: &mut crate::state::BrowsingStore,
        n: u8,
        availability: ListingAvailability,
    ) {
        store.listing_statuses.insert(
            ListingId([n; 32]),
            ListingStatus {
                listing: ListingId([n; 32]),
                revision: 1,
                availability,
            },
        );
    }

    /// A buyer never sees a taken-down listing, still sees a sold-out one,
    /// and sees one with no status as on sale. Mutated red by dropping the
    /// filter.
    #[test]
    fn taken_down_listings_are_hidden_and_sold_out_ones_shown() {
        let mut store = crate::state::BrowsingStore {
            listings: vec![listing(1), listing(2), listing(3)],
            ..Default::default()
        };
        with_status(&mut store, 2, ListingAvailability::SoldOut);
        with_status(&mut store, 3, ListingAvailability::Withdrawn);
        let shown: Vec<(u8, ListingAvailability)> = visible_listings(&store)
            .into_iter()
            .map(|(l, a)| (l.listing.id.0[0], a))
            .collect();
        assert_eq!(
            shown,
            vec![
                (1, ListingAvailability::Available { quantity: None }),
                (2, ListingAvailability::SoldOut),
            ]
        );
        // A sold-out listing goes after the ones on sale, which keep the
        // seller's order (round-6 critique). Red without the sort.
        let mut first_sold_out = crate::state::BrowsingStore {
            listings: vec![listing(1), listing(2), listing(3)],
            ..Default::default()
        };
        with_status(&mut first_sold_out, 1, ListingAvailability::SoldOut);
        let order: Vec<u8> = visible_listings(&first_sold_out)
            .into_iter()
            .map(|(l, _)| l.listing.id.0[0])
            .collect();
        assert_eq!(order, vec![2, 3, 1]);
    }

    /// The Buy control is offered only on a listing still on sale, by the
    /// expression the component renders. Mutated red by dropping the
    /// `is_buyable` filter.
    #[test]
    fn only_a_priced_listing_on_sale_offers_buy() {
        let store = crate::state::BrowsingStore {
            info: Some(harvest_common::store::StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: "seller-fp".to_string(),
                reputation_contract_id: [0u8; 32],
                store_name: "Pots".to_string(),
                description: String::new(),
                encryption_public_key: Some([1u8; 32]),
                record_public_key: None,
            }),
            seller_verifying_key: Some([2u8; 32]),
            ..Default::default()
        };
        let priced = priced_listing(9).listing;
        let offered = |availability: &ListingAvailability| {
            offered_buy(&store, &[4u8; 32], false, &priced, availability, true).is_some()
        };
        assert!(offered(&ListingAvailability::Available { quantity: None }));
        assert!(offered(&ListingAvailability::Available {
            quantity: Some(2)
        }));
        assert!(!offered(&ListingAvailability::Available {
            quantity: Some(0)
        }));
        assert!(!offered(&ListingAvailability::SoldOut));
        assert!(!offered(&ListingAvailability::Withdrawn));
        // A listing with no sats price (quote-only, from before every
        // listing had one) is shown and never offered: there is no way left
        // to ask the seller for a total. Mutated red by dropping the filter.
        let quote_only = listing(9).listing;
        assert!(offered_buy(
            &store,
            &[4u8; 32],
            false,
            &quote_only,
            &ListingAvailability::Available { quantity: None },
            true
        )
        .is_none());
        // A closed store offers nothing, whatever the listing. Mutated red
        // by dropping the `open` filter.
        assert!(offered_buy(
            &store,
            &[4u8; 32],
            false,
            &priced,
            &ListingAvailability::Available { quantity: None },
            false
        )
        .is_none());
    }

    fn priced_listing(n: u8) -> AuthorizedListing {
        let mut l = listing(n);
        l.listing.checkout = Some(harvest_common::listing::FixedCheckout {
            unit_sats: 25_000,
            delivery: harvest_common::listing::DeliveryPrice::Included,
        });
        l
    }

    /// What a buyer reads under a listing: the sats price and the delivery,
    /// never the old free-text price, and nothing for a listing with no
    /// sats price.
    #[test]
    fn a_listing_shows_its_sats_price_and_delivery() {
        use harvest_common::listing::{DeliveryPrice, FixedCheckout, PriceInfo, RegionPrice};
        let mut l = priced_listing(1).listing;
        l.price = Some(PriceInfo {
            amount: "9".into(),
            currency: "USD".into(),
        });
        assert_eq!(
            price_lines(&l),
            Some(("25,000 sats".to_string(), "Delivery included".to_string()))
        );
        l.checkout = Some(FixedCheckout {
            unit_sats: 1_000_000,
            delivery: DeliveryPrice::ByRegion(vec![
                RegionPrice {
                    region: "US".into(),
                    sats: 0,
                },
                RegionPrice {
                    region: "EU".into(),
                    sats: 5_000,
                },
            ]),
        });
        assert_eq!(
            price_lines(&l),
            Some((
                "1,000,000 sats".to_string(),
                "Delivery: US free, EU 5,000 sats".to_string()
            ))
        );
        l.checkout = None;
        assert_eq!(price_lines(&l), None);
        assert_eq!(sats_text(0), "0 sats");
        assert_eq!(sats_text(999), "999 sats");
        assert_eq!(sats_text(1_000), "1,000 sats");
    }
}

#[cfg(test)]
mod stores_page_tests {
    use super::*;
    use crate::presence_flow::LocalSelling;
    use harvest_common::presence::ClosedWhy;

    /// An own store's card says what the seller's Overview would: what
    /// needs the seller ("<n> need you", or "Needs you" for anything else
    /// the Overview lists), whether buyers can buy (the Overview's own pill,
    /// or "Closed"), and both when both hold (critique 01s-2); "up to date"
    /// only where nothing needs the seller, buyers can buy and the Overview
    /// reads Open; "Checking…" while it is too soon to say. Red if a store
    /// whose device cannot answer orders reads "up to date", red if one
    /// closed for good does, and red hiding "Not taking orders" behind
    /// "2 need you".
    #[test]
    fn an_own_store_card_reads_the_sellers_own_status() {
        use crate::presence_flow::StorePresence;
        let presence_open = StorePresence::Open;
        let presence_closed = StorePresence::Closed(ClosedWhy::NoHeartbeat);
        let status = |presence, local: LocalSelling| {
            crate::presence_flow::seller_status(presence, false, &local)
        };
        let ready = || LocalSelling::Ready { delegated: false };
        let blocked = || LocalSelling::Blocked("no wallet".to_string());
        let (open, closed, checking) = (BuyerOpen::Open, BuyerOpen::Closed, BuyerOpen::Checking);
        let words = |needs, look, seller: Option<SellerStatus>, buyers| {
            own_store_status(needs, look, seller.as_ref(), buyers).words()
        };

        // Both, when something waits and buyers cannot buy.
        assert_eq!(
            words(2, false, Some(status(presence_open, blocked())), open),
            vec!["2 need you", "Not taking orders"]
        );
        assert_eq!(
            words(1, false, Some(status(presence_closed, ready())), closed),
            vec!["1 needs you", "Closed"]
        );
        // Something waits and buyers can buy: only what waits.
        assert_eq!(
            words(2, false, Some(status(presence_open, ready())), open),
            vec!["2 need you"]
        );
        assert_eq!(words(0, true, None, open), vec!["Needs you"]);
        assert_eq!(words(0, true, None, checking), vec!["Needs you"]);
        // Nothing waits.
        assert_eq!(
            words(0, false, Some(status(presence_open, ready())), open),
            vec!["up to date"]
        );
        assert_eq!(
            words(0, false, Some(status(presence_open, blocked())), open),
            vec!["Not taking orders"],
            "buyers see it open, but nobody answers their orders"
        );
        assert_eq!(
            words(0, false, Some(status(presence_closed, ready())), closed),
            vec!["Closed"]
        );
        // Closed for good (or unable to take an order) while its presence
        // still reads open: closed, not "up to date".
        assert_eq!(
            words(0, false, Some(status(presence_open, ready())), closed),
            vec!["Closed"]
        );
        assert_eq!(
            words(
                0,
                false,
                Some(status(StorePresence::Checking, ready())),
                checking
            ),
            vec!["Checking\u{2026}"]
        );
        // A store that sells nothing here: what buyers see.
        assert_eq!(words(0, false, None, open), vec!["up to date"]);
        assert_eq!(words(0, false, None, closed), vec!["Closed"]);
    }

    fn row(name: StoreName, tagline: Option<&str>) -> StoreListRow {
        StoreListRow {
            code: "3Bn8xWqLd6Tz9Kf2".to_string(),
            name,
            tagline: tagline.map(str::to_string),
            archived: false,
            closed: false,
            closed_for_now: false,
        }
    }

    /// A visited store's row: its name, then its tagline. Its code is the
    /// second line only where nothing else tells it from another row (no
    /// name and no tagline, or a main line another row has too), and never
    /// the name. Red with the code shown only for an unreachable store,
    /// which let two "Loading…" rows look alike (review of #197).
    #[test]
    fn a_visited_row_names_the_store_and_never_by_its_code() {
        let named = StoreName::Named("Bean Shop".to_string());
        let tagline = Some("Hand-thrown stoneware");
        let code = Some("Store code 3Bn8xWqLd6Tz9Kf2".to_string());
        assert_eq!(
            visited_row_lines(&row(named.clone(), tagline), false),
            (
                "Bean Shop".to_string(),
                Some("Hand-thrown stoneware".to_string())
            )
        );
        assert_eq!(
            visited_row_lines(&row(named, tagline), true),
            ("Bean Shop".to_string(), code.clone()),
            "another row is called Bean Shop too"
        );
        for name in [
            StoreName::Unreachable,
            StoreName::Loading,
            StoreName::Unnamed,
        ] {
            let (main, second) = visited_row_lines(&row(name.clone(), None), false);
            assert!(!main.contains("3Bn8"), "{main:?}");
            assert_eq!(second, code, "{name:?}");
        }
        assert_eq!(
            visited_row_lines(&row(StoreName::Loading, None), false).0,
            "Loading\u{2026}"
        );
    }

    /// A closed row says so: "Closed right now" only when it is closed for
    /// now (its seller's computer offline), "Closed" when closed for good
    /// or unable to take an order, and "Closed" after the code when the
    /// code is its second line. Red saying "right now" for a store closed
    /// for good, and red with a closed row that says Closed nowhere.
    #[test]
    fn a_closed_row_says_why_honestly() {
        let named = StoreName::Named("Tea".to_string());
        let mut for_now = row(named.clone(), Some("Loose tea"));
        for_now.closed = true;
        for_now.closed_for_now = true;
        assert_eq!(
            visited_row_lines(&for_now, false).1.as_deref(),
            Some("Closed right now")
        );
        let mut for_good = for_now.clone();
        for_good.closed_for_now = false;
        assert_eq!(
            visited_row_lines(&for_good, false).1.as_deref(),
            Some("Closed")
        );
        assert_eq!(
            visited_row_lines(&for_good, true).1.as_deref(),
            Some("Store code 3Bn8xWqLd6Tz9Kf2 \u{00b7} Closed")
        );
    }

    /// Rows whose main lines read the same, case aside, are the ones that
    /// collide; a line on its own does not.
    #[test]
    fn rows_that_read_alike_collide() {
        let labels = ["Bean Shop", "bean shop", "Loading\u{2026}", "Tea"].map(String::from);
        assert_eq!(colliding(&labels), vec![true, true, false, false]);
    }

    /// An own store's full row: its name, and as the second line its
    /// tagline, or its code while it has no name and no tagline, or when
    /// another card reads the same. Asserted as whole rows, so the tagline
    /// and the code cannot trade places unnoticed.
    #[test]
    fn own_store_rows_are_named_with_a_tagline_or_their_code() {
        use crate::state::test_store_key;
        let registration = |id: u8| harvest_common::StoreRegistration {
            store_contract_id: vec![id; 32],
            reputation_contract_id: vec![0u8; 32],
            mailbox_contract_id: vec![0u8; 32],
            store_contract_key: None,
            store_verifying_key: Some(test_store_key()),
        };
        let code = harvest_common::store::store_code(
            &ed25519_dalek::VerifyingKey::from_bytes(&test_store_key()).unwrap(),
        );
        let loaded = |name: &str, description: &str| crate::state::BrowsingStore {
            info: Some(harvest_common::store::StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: String::new(),
                reputation_contract_id: [0u8; 32],
                store_name: name.to_string(),
                description: description.to_string(),
                encryption_public_key: None,
                record_public_key: None,
            }),
            ..Default::default()
        };
        let mut state = AppState::default();
        state.my_stores.insert(
            "fp".into(),
            vec![registration(1), registration(2), registration(3)],
        );
        state
            .browsing_stores
            .insert(vec![1u8; 32], loaded("Pots", "Hand-thrown **stoneware**."));
        state
            .browsing_stores
            .insert(vec![2u8; 32], loaded("Cups", ""));
        let rows: Vec<(String, bool, Option<String>)> =
            own_store_rows(&state, crate::state::now_ms())
                .into_iter()
                .map(|r| (r.label, r.named, r.sub))
                .collect();
        assert_eq!(
            rows,
            vec![
                ("Cups".to_string(), true, None),
                (
                    "Loading\u{2026}".to_string(),
                    false,
                    Some(format!("Store code {code}"))
                ),
                (
                    "Pots".to_string(),
                    true,
                    Some("Hand-thrown stoneware.".to_string())
                ),
            ]
        );

        // Two cards with one name: each carries its code, not its tagline.
        state
            .browsing_stores
            .insert(vec![2u8; 32], loaded("Pots", "Cups too"));
        let subs: Vec<Option<String>> = own_store_rows(&state, crate::state::now_ms())
            .into_iter()
            .filter(|r| r.label == "Pots")
            .map(|r| r.sub)
            .collect();
        assert_eq!(subs, vec![Some(format!("Store code {code}")); 2]);
    }

    /// "Find a store" keeps today's two messages: an old-format link is
    /// told it cannot be opened any more, anything else is told what a store
    /// code looks like.
    #[test]
    fn find_a_store_says_why_nothing_opened() {
        let old = bs58::encode([5u8; 32]).into_string();
        assert_eq!(
            not_a_store_message(&format!(
                "http://127.0.0.1:7509/v1/contract/web/x/#store={old}"
            )),
            crate::store_link::OLD_FORMAT_LINK_MESSAGE
        );
        assert_eq!(
            not_a_store_message("hello"),
            "That doesn\u{2019}t look like a store link. Paste the whole link the seller gave \
             you, or their 16-character store code."
        );
    }
}

#[cfg(test)]
mod store_page_tests {
    use super::*;
    use crate::ghostkey_cert::CertificateStatus;
    use harvest_common::presence::ClosedWhy;

    /// The store-level half of the Buy control and the pill agree: a store
    /// takes orders (`BrowsingStore::takes_orders`, which `buyer_open`
    /// reads) exactly when `buyable` offers one to a buyer. Red if the pill
    /// could say Open over a page whose Buy controls are all hidden.
    #[test]
    fn the_pill_and_the_buy_control_agree() {
        for closed in [false, true] {
            for key in [None, Some([1u8; 32])] {
                for identity in [None, Some([2u8; 32])] {
                    let mut store = crate::state::BrowsingStore {
                        info: Some(harvest_common::store::StoreInfoV1 {
                            version: 1,
                            certificate_pem: String::new(),
                            seller_fingerprint: String::new(),
                            reputation_contract_id: [0u8; 32],
                            store_name: "Pots".to_string(),
                            description: String::new(),
                            encryption_public_key: key,
                            record_public_key: None,
                        }),
                        seller_verifying_key: identity,
                        ..Default::default()
                    };
                    store.closed = closed;
                    assert_eq!(
                        store.takes_orders(),
                        buyable(&store, &[4u8; 32], false).is_some(),
                        "closed {closed}, key {key:?}, identity {identity:?}"
                    );
                }
            }
        }
    }

    /// **A buyer never sees "Ghost Key", a key id, or a figure the app
    /// cannot check** (mockup decision 3, critique S2-2): the trust line and
    /// its warnings say what the backing shows in plain words, and name no
    /// amount and no date.
    #[test]
    fn the_trust_line_is_in_a_buyers_words() {
        let invalid = CertificateStatus::Invalid(
            "not a readable Ghost Key certificate: bad armour".to_string(),
        );
        for status in [
            CertificateStatus::Verified,
            CertificateStatus::Absent,
            invalid,
        ] {
            for text in [
                backing_words(&status).to_string(),
                certificate_warning(&status),
                cannot_take_orders_line(&status),
            ] {
                let lower = text.to_lowercase();
                assert!(
                    !lower.contains("ghost") && !lower.contains("certificate"),
                    "{text:?}"
                );
                assert!(!text.contains('$'), "no amount: {text:?}");
                assert!(
                    names_no_date(&text),
                    "no date (a backing's date is the seller's word): {text:?}"
                );
            }
        }
        assert!(!TRUST_WHY.to_lowercase().contains("ghost"));
        assert!(names_no_date(TRUST_WHY));
        assert!(
            !TRUST_WHY.contains("their name"),
            "a backing is pseudonymous, so no \"under their name\""
        );
        assert_eq!(
            backing_words(&CertificateStatus::Verified),
            "Backed by a donation to Freenet"
        );
    }

    /// No digit, no month and no "since": no date, however written.
    fn names_no_date(text: &str) -> bool {
        const MONTHS: [&str; 12] = [
            "january",
            "february",
            "march",
            "april",
            "may",
            "june",
            "july",
            "august",
            "september",
            "october",
            "november",
            "december",
        ];
        let lower = text.to_lowercase();
        let month = lower.split(|c: char| !c.is_alphabetic()).any(|word| {
            MONTHS
                .iter()
                .any(|m| word == *m || (word.len() == 3 && m.starts_with(word)))
        });
        !text.chars().any(|c| c.is_ascii_digit()) && !lower.contains("since") && !month
    }

    /// The trust line the store page shows in two parts is the one line
    /// the seller's Overview and Settings say buyers see: one function, so
    /// they cannot disagree again (critique 12-2).
    #[test]
    fn the_trust_line_is_one_for_the_page_and_the_seller() {
        let mut store = crate::state::BrowsingStore {
            certificate_status: CertificateStatus::Verified,
            record: crate::state::RecordLoad::Loaded,
            ..Default::default()
        };
        assert_eq!(
            trust_line(&store),
            "Backed by a donation to Freenet \u{00b7} No complaints"
        );
        let (backing, record) = trust_parts(&store);
        assert_eq!(trust_line(&store), format!("{backing} \u{00b7} {record}"));
        store.certificate_status = CertificateStatus::Absent;
        store.record = crate::state::RecordLoad::Loading;
        assert_eq!(
            trust_line(&store),
            "Not backed by a donation \u{00b7} Record loading"
        );
        assert!(!trust_line(&store).to_lowercase().contains("ghost"));
    }

    /// A listing's corner: Closed while the store is, else Sold out, else
    /// how many are left when the seller counts them.
    #[test]
    fn a_listing_corner_says_what_a_buyer_can_get() {
        let on_sale = ListingAvailability::Available { quantity: None };
        let three = ListingAvailability::Available { quantity: Some(3) };
        assert_eq!(availability_words(&three, false).as_deref(), Some("3 left"));
        assert_eq!(availability_words(&on_sale, false), None);
        assert_eq!(
            availability_words(&ListingAvailability::Available { quantity: Some(0) }, false)
                .as_deref(),
            Some("Sold out")
        );
        assert_eq!(
            availability_words(&ListingAvailability::SoldOut, false).as_deref(),
            Some("Sold out")
        );
        assert_eq!(availability_words(&three, true).as_deref(), Some("Closed"));
    }

    #[test]
    fn the_orders_line_counts_in_words() {
        let line = |live, to_pay| {
            orders_line(OrdersHere {
                live,
                to_pay,
                ended: 0,
            })
        };
        assert_eq!(line(1, 0), "You have 1 order from this store \u{203a}");
        assert_eq!(
            line(3, 1),
            "You have 3 orders from this store, 1 to pay \u{203a}"
        );
    }

    /// Only live orders count, and "to pay" only what the buyer can pay now
    /// (see `orders_here`). Red counting every purchase, and red on each
    /// case round 4 of #197 found: a payment seen on chain, an early
    /// blocker, a cancelled hand invoice.
    #[test]
    fn only_live_orders_are_counted() {
        use crate::state::{BuyerPurchase, PaymentBlocker};
        use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};
        let purchase = |n: u8, buy_now: bool, status: OrderStatus, stale: bool| BuyerPurchase {
            order_id: OrderId([n; 32]),
            conversation: [0u8; 32],
            commitment: Some(AuthorizedOrder {
                order: Order {
                    request_id: buy_now.then_some([n; 32]),
                    id: OrderId([n; 32]),
                    buyer_fingerprint: String::new(),
                    seller_fingerprint: String::new(),
                    amount_sats: 1,
                    network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                    payment_script_pubkey: vec![n],
                    payment_address: String::new(),
                    required_confirmations: 1,
                    payment_hash: None,
                    trusted_bridges: Vec::new(),
                    bitcoin_address_code_hash: None,
                    anchor: None,
                    order_binding: None,
                    listing_tag: None,
                    buyer_receipt_key: None,
                    created_at: chrono::DateTime::UNIX_EPOCH,
                },
                scoped_payload: Vec::new(),
                signature: Vec::new(),
                status,
                payment_proof: None,
                status_scoped_payload: None,
                status_signature: None,
            }),
            blockers: if stale {
                vec![PaymentBlocker::AnchorStale {
                    anchor_height: 1,
                    tip_height: 1000,
                }]
            } else {
                Vec::new()
            },
            paid: None,
        };
        let with_blocker = |mut p: BuyerPurchase, b: PaymentBlocker| {
            p.blockers.push(b);
            p
        };
        let seen_paid = |mut p: BuyerPurchase| {
            p.paid = p.commitment.clone();
            p
        };
        let count = |purchases: Vec<BuyerPurchase>| orders_here(&purchases);

        // Paid, awaiting (to pay), and an expired or cancelled Buy now.
        assert_eq!(
            count(vec![
                purchase(1, true, OrderStatus::Paid, false),
                purchase(2, true, OrderStatus::AwaitingPayment, false),
                purchase(3, true, OrderStatus::AwaitingPayment, true),
                purchase(4, true, OrderStatus::Cancelled, false),
            ]),
            OrdersHere {
                live: 2,
                to_pay: 1,
                ended: 2
            }
        );
        // A hand invoice: expired is not one to pay, cancelled is not one at
        // all; both ended unpaid.
        assert_eq!(
            count(vec![purchase(5, false, OrderStatus::AwaitingPayment, true)]),
            OrdersHere {
                ended: 1,
                ..OrdersHere::default()
            }
        );
        assert_eq!(
            count(vec![purchase(6, false, OrderStatus::Cancelled, false)]),
            OrdersHere {
                ended: 1,
                ..OrdersHere::default()
            }
        );
        // Seen paid on chain before the seller marked it: an order, not one
        // to pay, whatever its age or a cancel it beat. Red without the
        // `paid` check.
        assert_eq!(
            count(vec![
                seen_paid(purchase(7, true, OrderStatus::AwaitingPayment, true)),
                seen_paid(purchase(8, true, OrderStatus::Cancelled, false)),
            ]),
            OrdersHere {
                live: 2,
                to_pay: 0,
                ended: 0
            }
        );
        // An early blocker: an order, but not one the buyer can pay now.
        assert_eq!(
            count(vec![with_blocker(
                purchase(9, true, OrderStatus::AwaitingPayment, false),
                PaymentBlocker::StoreClosed
            )]),
            OrdersHere {
                live: 1,
                to_pay: 0,
                ended: 0
            }
        );
        // Only keeping its copy stands in the way: the pay button does that.
        assert_eq!(
            count(vec![with_blocker(
                purchase(10, true, OrderStatus::AwaitingPayment, false),
                PaymentBlocker::PurchaseNotKept
            )]),
            OrdersHere {
                live: 1,
                to_pay: 1,
                ended: 0
            }
        );
        // Not this buyer's order: not counted.
        assert_eq!(
            count(vec![with_blocker(
                purchase(11, true, OrderStatus::AwaitingPayment, false),
                PaymentBlocker::CommitmentNotForThisBuyer
            )]),
            OrdersHere::default()
        );
    }
}
