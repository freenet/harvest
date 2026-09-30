use dioxus::prelude::*;
use harvest_common::listing::{AuthorizedListing, ListingAvailability};

use super::app::{open_seller_page, Route, SellerPage, ROUTE};
use crate::gateway::APP_STATE;
use crate::presence_flow::{SellerStatus, StorePresence};
use crate::state::{AppState, StoreListRow, StoreName};

/// The Stores page (the 2026-09-30 redesign, after the mockup's
/// `scrStores()`): the seller's own stores, if any, each opening its
/// seller pages; a way to open a store by its link or code; the stores this
/// node has visited; and, for someone with no store, a quiet way into
/// selling. Opening any store goes to its own page ([`StorePage`]).
#[component]
pub fn StoresPage() -> Element {
    let show_archived = use_signal(|| false);
    // The visited stores are asked for in the background, so each row can
    // carry the store's own name rather than its code. An effect, so it runs
    // again when the delegate's list arrives after this page opened.
    use_effect(move || crate::store_link::load_visited_stores(show_archived()));
    // Whether a store is open is judged against the clock (`presence_flow`),
    // so this re-renders every half minute, as the store page does.
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

    let own = own_store_rows(&APP_STATE.read(), crate::state::now_ms());
    let one = own.len() == 1;

    rsx! {
        div { class: "stores-page",
            h2 { "Stores" }
            if !own.is_empty() {
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
            h3 { class: if own.is_empty() { "sec-lbl sec-lbl-first" } else { "sec-lbl" }, "Find a store" }
            FindStore {}
            VisitedStores { show_archived }
            if own.is_empty() {
                div { class: "card card-quiet sell-card",
                    h3 { "Sell on Harvest" }
                    p { class: "text-muted",
                        "Open a store. Harvest takes no cut, needs no account, and nobody can take "
                        "your store down."
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

/// One of this node's own stores on the Stores page. See [`own_store_rows`].
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OwnStoreRow {
    pub contract_id: Vec<u8>,
    /// Its name, or "Loading…" (`my_store::SellerStore::label`).
    pub label: String,
    /// Whether `label` is the store's own name, rather than words standing
    /// in for it.
    pub named: bool,
    /// Its code: the second line while it has no name, since nothing else
    /// tells two such cards apart. Never the name.
    pub code: Option<String>,
    /// The first line of its description.
    pub tagline: Option<String>,
    pub status: OwnStoreStatus,
}

/// What an own store's row card says on the right.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum OwnStoreStatus {
    /// Something needs the seller (`my_store::SellerStore::needs_you`, the
    /// count on the Stores tab): "<n> need(s) you".
    NeedsYou(usize),
    /// Nothing counted, but the Overview's "Needs you" card lists something
    /// all the same (`my_store::overview_needs`): "Needs you".
    NeedsALook,
    /// Open, and nothing waiting: "up to date".
    UpToDate,
    /// Buyers cannot buy: the seller's own status pill ("Closed", or "Not
    /// taking orders" when buyers see it open but this device cannot answer).
    NotOpen(&'static str),
    /// Too soon to say whether buyers can reach it.
    Checking,
}

impl OwnStoreStatus {
    fn text(&self) -> String {
        match self {
            OwnStoreStatus::NeedsYou(1) => "1 needs you".to_string(),
            OwnStoreStatus::NeedsYou(n) => format!("{n} need you"),
            OwnStoreStatus::NeedsALook => "Needs you".to_string(),
            OwnStoreStatus::UpToDate => "up to date".to_string(),
            OwnStoreStatus::NotOpen(pill) => pill.to_string(),
            OwnStoreStatus::Checking => "Checking\u{2026}".to_string(),
        }
    }
}

/// The status on an own store's row card, from what needs the seller
/// (`needs_you` counted, `needs_a_look` anything else the Overview's "Needs
/// you" card lists) and the ONE status the seller's Overview reads
/// (`presence_flow::seller_status`, `None` for a store that sells nothing
/// here) or, failing that, what buyers see (`presence`). Nothing new is
/// judged here: a store is "up to date" only where the Overview would say
/// Open and "Nothing needs you right now".
pub(crate) fn own_store_status(
    needs_you: usize,
    needs_a_look: bool,
    seller: Option<&SellerStatus>,
    presence: StorePresence,
) -> OwnStoreStatus {
    if needs_you > 0 {
        return OwnStoreStatus::NeedsYou(needs_you);
    }
    if needs_a_look {
        return OwnStoreStatus::NeedsALook;
    }
    match (seller, presence) {
        (Some(status), _) if status.open => OwnStoreStatus::UpToDate,
        (_, StorePresence::Checking) => OwnStoreStatus::Checking,
        (Some(status), _) => OwnStoreStatus::NotOpen(status.pill),
        (None, StorePresence::Open) => OwnStoreStatus::UpToDate,
        (None, StorePresence::Closed(_)) => OwnStoreStatus::NotOpen("Closed"),
    }
}

/// This node's own stores, as the Stores page lists them: every store the
/// seller pages manage (`my_store::seller_stores`), in the same order.
pub(crate) fn own_store_rows(state: &AppState, now_ms: u64) -> Vec<OwnStoreRow> {
    super::my_store::seller_stores(state)
        .into_iter()
        .map(|store| {
            let id = store.contract_id.clone();
            let presence = state.store_presence(&id, now_ms);
            let seller = state.instant_checkout_local(&id, now_ms).map(|local| {
                crate::presence_flow::seller_status(
                    presence,
                    state.wakeups_seen_recently(now_ms),
                    &local,
                )
            });
            OwnStoreRow {
                status: own_store_status(
                    store.needs_you(),
                    super::my_store::overview_needs(&store, state),
                    seller.as_ref(),
                    presence,
                ),
                tagline: state
                    .browsing_stores
                    .get(&id)
                    .and_then(|b| b.info.as_ref())
                    .and_then(|info| crate::markdown::first_line(&info.description)),
                named: state.store_name_of(&id).name().is_some(),
                code: store.code.clone(),
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
    let status = row.status.text();
    rsx! {
        button {
            class: "rowcard",
            onclick: {
                let id = row.contract_id.clone();
                move |_| open_seller_page(SellerPage::Store(id.clone()))
            },
            span { class: "rc-main",
                span { class: if row.named { "rc-name" } else { "rc-name rc-pending" }, "{row.label}" }
                if let Some(ref tagline) = row.tagline {
                    span { class: "rc-sub", "{tagline}" }
                } else if let (false, Some(code)) = (row.named, row.code.as_ref()) {
                    span { class: "rc-sub", "Store code {code}" }
                }
            }
            span { class: "rc-r",
                match row.status {
                    OwnStoreStatus::NeedsYou(_) | OwnStoreStatus::NeedsALook => rsx! { span { class: "pill pill-needs", "{status}" } },
                    OwnStoreStatus::NotOpen(_) => rsx! { span { class: "pill", "{status}" } },
                    _ => rsx! { span { class: "text-muted small", "{status}" } },
                }
                span { class: "chev", aria_hidden: "true", "\u{203a}" }
            }
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
        "That is not a store code. A store code is 16 letters and digits, the part of a \
         store link after \"store=\"."
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

/// The main and second line of a visited store's row.
fn visited_row_lines(row: &StoreListRow) -> (String, Option<String>) {
    let second = if row.closed {
        Some("Closed right now".to_string())
    } else {
        match row.name {
            // Nothing else tells two unreachable rows apart, so the code is
            // given, as the second line and never as the name.
            StoreName::Unreachable => Some(format!("Store code {}", row.code)),
            _ => row.tagline.clone(),
        }
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

    rsx! {
        h3 { class: "sec-lbl", "Stores you\u{2019}ve visited" }
        if !rows.is_empty() {
            div { class: "vlist",
                for row in rows {
                    VisitedRow { key: "{row.code}", row }
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

#[component]
fn VisitedRow(row: StoreListRow) -> Element {
    let (main, second) = visited_row_lines(&row);
    rsx! {
        div { class: if row.closed || row.archived { "vrow vrow-off" } else { "vrow" },
            button {
                class: "vrow-go",
                onclick: {
                    let code = row.code.clone();
                    move |_| {
                        if let Some(params) = harvest_common::StoreParameters::from_code(&code) {
                            crate::store_link::open_store(params);
                        }
                    }
                },
                span { class: if row.name.name().is_some() { "rc-name" } else { "rc-name rc-pending" }, "{main}" }
                if let Some(ref second) = second {
                    span { class: "rc-sub", "{second}" }
                }
            }
            if row.closed {
                span { class: "pill", "Closed" }
            }
            button {
                class: "link-btn vrow-remove",
                title: if row.archived { "" } else { "Hides it from this list. Your conversations with it are kept." },
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
    drop(app_state);

    rsx! {
        div { class: "store-page",
            button {
                class: "crumb",
                onclick: move |_| *ROUTE.write() = Route::Stores,
                "\u{2039} Stores"
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
    let (record_class, record_text) = store.record_badge();
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
    let presence = APP_STATE
        .read()
        .store_presence(&contract_id, crate::state::now_ms());
    let (pill, pill_open) = open_pill(store.closed, presence);
    // This buyer's orders from this store are on Purchases, once: here only
    // a line that goes there (critique S2-10).
    let orders_here = if owned {
        0
    } else {
        APP_STATE.read().buyer_purchases(&contract_id).len()
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

            div { class: if store.closed || presence.is_closed() { "store-header store-header-closed" } else { "store-header" },
                // Open or Closed beside the name, as buyers see it
                // (`presence_flow`; the 2026-09-26 decision, critique S2-3).
                div { class: "store-status",
                    h2 { class: "store-name", "{info.store_name}" }
                    span { class: if pill_open { "pill pill-open" } else { "pill" }, "{pill}" }
                }
                // What the seller has at stake, in a buyer's words: never a
                // key id or "Ghost Key" (mockup decision 3, critique S2-2).
                // No "Open since" and no amount: see `backing_words`.
                p { class: "trust",
                    "{backing_words(&store.certificate_status)} \u{00b7} "
                    // "No complaints" only once the record has been read
                    // (review round 1 of #143, P1-5). Opens the store's
                    // record, under its own heading (critique S2-4).
                    button {
                        class: "link-btn trust-record {record_class}",
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
                    aria_label: "{info.store_name}\u{2019}s record",
                    div { class: "row-between",
                        h3 { "{info.store_name}\u{2019}s record" }
                        button {
                            class: "link-btn",
                            onclick: move |_| show_record.set(false),
                            "Hide"
                        }
                    }
                    super::reputation_view::StoreRecord { store_contract_id: contract_id.clone() }
                }
            }

            if orders_here > 0 {
                p { class: "store-orders-line",
                    button {
                        class: "link-btn",
                        onclick: move |_| *ROUTE.write() = Route::Purchases,
                        "{orders_line(orders_here)}"
                    }
                }
            }

            if !owned {
                div { class: "store-ask",
                    button {
                        class: if show_messages() { "btn btn-sm btn-outline" } else { "btn btn-primary" },
                        onclick: move |_| show_messages.toggle(),
                        if show_messages() { "Hide messages" } else { "Ask the seller a question" }
                    }
                }

                if show_messages() {
                    super::message_view::MessageView { store_contract_id: contract_id.clone() }
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
                        buyable: offered_buy(&store, &contract_id, owned, &listing.listing, availability, presence.is_open()),
                        closed: store.closed || presence.is_closed(),
                    }
                }
            }

            // No list of the store's invoices here any more (critique S2-8,
            // S2-9): it showed a buyer other people's orders, and cancelled
            // ones under "Settled". The record is the public evidence; the
            // seller's own orders are on their Orders tab; a buyer's are on
            // Purchases, and the one a Buy now form just made stays under it.
        }
    }
}

/// The pill beside a store's name, as buyers see it, and whether it reads
/// open: "Open" only while `presence_flow` says buyers can buy, "Closed"
/// when it says not or the seller has closed the store for good, and
/// "Checking" while it is too soon to say.
pub(crate) fn open_pill(closed_for_good: bool, presence: StorePresence) -> (&'static str, bool) {
    if closed_for_good {
        return ("Closed", false);
    }
    match presence {
        StorePresence::Open => ("Open", true),
        StorePresence::Checking => ("Checking", false),
        StorePresence::Closed(_) => ("Closed", false),
    }
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

/// Under the trust line of a store whose backing checks out. After the
/// mockup's, less "for good": a full record keeps a new complaint in place
/// of an older one (`reputation::MAX_COMPLAINTS`), which the page says when
/// it happens.
const TRUST_WHY: &str = "The seller donated to Freenet to open this store under their name. \
     Complaints stay on its record, and the seller can\u{2019}t remove them.";

/// The one line on a store's page about this buyer's orders from it.
fn orders_line(orders: usize) -> String {
    match orders {
        1 => "You have 1 order from this store \u{203a}".to_string(),
        n => format!("You have {n} orders from this store \u{203a}"),
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
    store
        .listings
        .iter()
        .map(|l| (l.clone(), store.availability(&l.listing.id)))
        .filter(|(_, availability)| *availability != ListingAvailability::Withdrawn)
        .collect()
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
    buyable: Option<Buyable>,
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
            match buyable {
                Some(buyable) => rsx! {
                    BuyControl {
                        listing: l.clone(),
                        buyable: buyable,
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
/// store is, "Sold out", "<n> left" when the seller counts its stock, and
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
fn BuyControl(listing: harvest_common::listing::Listing, buyable: Buyable) -> Element {
    let mut open = use_signal(|| false);

    rsx! {
        div { style: "margin-top: 0.75rem;",
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

    /// An own store's card says what the seller's Overview would: the
    /// count of what needs them first, "up to date" only where the Overview
    /// reads Open, the Overview's own pill where buyers cannot buy, and
    /// "Checking" while it is too soon to say. Red if a store whose device
    /// cannot answer orders reads "up to date".
    #[test]
    fn an_own_store_card_reads_the_sellers_own_status() {
        let open = StorePresence::Open;
        let closed = StorePresence::Closed(ClosedWhy::NoHeartbeat);
        let status = |presence, local: LocalSelling| {
            crate::presence_flow::seller_status(presence, false, &local)
        };
        let ready = || LocalSelling::Ready { delegated: false };
        let blocked = || LocalSelling::Blocked("no wallet".to_string());

        // Something waiting wins, whatever else is true.
        assert_eq!(
            own_store_status(2, false, Some(&status(closed, blocked())), closed),
            OwnStoreStatus::NeedsYou(2)
        );
        assert_eq!(
            own_store_status(0, false, Some(&status(open, ready())), open),
            OwnStoreStatus::UpToDate
        );
        assert_eq!(
            own_store_status(0, false, Some(&status(open, blocked())), open),
            OwnStoreStatus::NotOpen("Not taking orders"),
            "buyers see it open, but nobody answers their orders"
        );
        assert_eq!(
            own_store_status(0, false, Some(&status(closed, ready())), closed),
            OwnStoreStatus::NotOpen("Closed")
        );
        assert_eq!(
            own_store_status(
                0,
                false,
                Some(&status(StorePresence::Checking, ready())),
                StorePresence::Checking
            ),
            OwnStoreStatus::Checking
        );
        // A store that sells nothing here: what buyers see.
        assert_eq!(
            own_store_status(0, false, None, open),
            OwnStoreStatus::UpToDate
        );
        assert_eq!(
            own_store_status(0, false, None, closed),
            OwnStoreStatus::NotOpen("Closed")
        );
        assert_eq!(
            own_store_status(0, false, None, StorePresence::Checking),
            OwnStoreStatus::Checking
        );

        // Nothing counted, but the Overview's card lists something (an
        // unpriced listing, say): never "up to date". Red without the flag.
        assert_eq!(
            own_store_status(0, true, Some(&status(open, ready())), open),
            OwnStoreStatus::NeedsALook
        );
        assert_eq!(
            own_store_status(0, true, None, open),
            OwnStoreStatus::NeedsALook
        );
        assert_eq!(OwnStoreStatus::NeedsALook.text(), "Needs you");
        assert_eq!(OwnStoreStatus::NeedsYou(1).text(), "1 needs you");
        assert_eq!(OwnStoreStatus::NeedsYou(3).text(), "3 need you");
        assert_eq!(OwnStoreStatus::UpToDate.text(), "up to date");
    }

    fn row(name: StoreName, closed: bool) -> StoreListRow {
        StoreListRow {
            code: "3Bn8xWqLd6Tz9Kf2".to_string(),
            name,
            tagline: Some("Hand-thrown stoneware".to_string()),
            archived: false,
            closed,
        }
    }

    /// A visited store's row: its name, then its tagline, or "Closed right
    /// now" when closed. The code appears only as the second line of a store
    /// that could not be loaded, where nothing else tells two rows apart,
    /// and never as the name.
    #[test]
    fn a_visited_row_names_the_store_and_never_by_its_code() {
        let named = StoreName::Named("Bean Shop".to_string());
        assert_eq!(
            visited_row_lines(&row(named.clone(), false)),
            (
                "Bean Shop".to_string(),
                Some("Hand-thrown stoneware".to_string())
            )
        );
        assert_eq!(
            visited_row_lines(&row(named, true)),
            (
                "Bean Shop".to_string(),
                Some("Closed right now".to_string())
            )
        );
        let (main, second) = visited_row_lines(&row(StoreName::Unreachable, false));
        assert!(!main.contains("3Bn8"), "{main:?}");
        assert_eq!(second.as_deref(), Some("Store code 3Bn8xWqLd6Tz9Kf2"));
        let (main, _) = visited_row_lines(&row(StoreName::Loading, false));
        assert_eq!(main, "Loading\u{2026}");
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
        assert!(not_a_store_message("hello").starts_with("That is not a store code."));
    }
}

#[cfg(test)]
mod store_page_tests {
    use super::*;
    use crate::ghostkey_cert::CertificateStatus;
    use harvest_common::presence::ClosedWhy;

    /// Open or Closed beside the name, as buyers see it: Open only while
    /// buyers can buy, Closed when not or when the seller closed the store
    /// for good, whatever its presence says. Red if a store closed for good
    /// reads Open.
    #[test]
    fn the_pill_says_open_only_while_buyers_can_buy() {
        assert_eq!(open_pill(false, StorePresence::Open), ("Open", true));
        assert_eq!(open_pill(true, StorePresence::Open), ("Closed", false));
        assert_eq!(
            open_pill(false, StorePresence::Closed(ClosedWhy::NoHeartbeat)),
            ("Closed", false)
        );
        assert_eq!(
            open_pill(false, StorePresence::Checking),
            ("Checking", false)
        );
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
            ] {
                let lower = text.to_lowercase();
                assert!(
                    !lower.contains("ghost") && !lower.contains("certificate"),
                    "{text:?}"
                );
                assert!(!text.contains('$'), "no amount: {text:?}");
            }
        }
        assert!(!TRUST_WHY.to_lowercase().contains("ghost"));
        assert_eq!(
            backing_words(&CertificateStatus::Verified),
            "Backed by a donation to Freenet"
        );
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
        assert_eq!(orders_line(1), "You have 1 order from this store \u{203a}");
        assert_eq!(orders_line(3), "You have 3 orders from this store \u{203a}");
    }
}
