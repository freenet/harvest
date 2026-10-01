use dioxus::prelude::*;

use super::bitcoin_view::BitcoinView;
use super::router::{go, NavTab, Page, StoreTab, PAGE};
use crate::gateway::{ConnectionStatus, CONNECTION_STATUS};

/// Show a store's own page: the store opened by a link, a typed code, a row
/// of the Stores page, a purchase's store, or the seller's "View store".
/// Opening the page asks for the store's state if it is not here
/// ([`load_store_for_page`]).
pub(crate) fn show_store(store_contract_id: Vec<u8>) {
    go(Page::Store {
        store: store_contract_id,
        tab: StoreTab::Items,
    });
}

/// How [`load_store_for_page`] asks for a store.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Opening {
    /// Its state is here and followed: nothing to ask for.
    Loaded,
    /// Not here, or here only to be listed (`AppState::light_stores`): asked
    /// for by its code, which fetches it with a subscription and remembers it.
    ByCode(harvest_common::store::StoreParameters),
    /// No code known for it anywhere: fetched by its address, which still
    /// gives up after a while.
    ById,
}

/// How to ask for the store `store_contract_id`: see [`Opening`]. Its code is
/// looked for where this node may hold it: the codes stores were opened
/// under, the remembered stores (removed ones too), and this node's own
/// stores' keys.
pub(crate) fn opening_for(state: &crate::state::AppState, store_contract_id: &[u8]) -> Opening {
    let loaded = state
        .browsing_stores
        .get(store_contract_id)
        .is_some_and(|store| store.info.is_some());
    if loaded && !state.light_stores.contains(store_contract_id) {
        return Opening::Loaded;
    }
    let id_of = |params: &harvest_common::store::StoreParameters| {
        crate::gateway::store_ops::store_instance_id(params)
            .ok()
            .map(|id| id.as_bytes().to_vec())
    };
    let known = state.store_codes.get(store_contract_id).cloned();
    let remembered = || {
        state.remembered_stores.iter().flatten().find_map(|s| {
            let params = harvest_common::store::StoreParameters::from_code(&s.store_code)?;
            (id_of(&params).as_deref() == Some(store_contract_id)).then(|| s.store_code.clone())
        })
    };
    let own = || {
        state
            .my_stores
            .values()
            .flatten()
            .filter(|r| r.store_contract_id == store_contract_id)
            .find_map(|r| r.store_verifying_key)
            .and_then(|key| ed25519_dalek::VerifyingKey::from_bytes(&key).ok())
            .map(|key| harvest_common::store::store_code(&key))
    };
    match known
        .or_else(remembered)
        .or_else(own)
        .and_then(|code| harvest_common::store::StoreParameters::from_code(&code))
    {
        Some(params) => Opening::ByCode(params),
        None => Opening::ById,
    }
}

/// Ask for the state of a store a page is about to show, when it is not
/// here (a store page, an item, an order or a conversation opened by a
/// button, Back, or a reload). Its fetch gives up after a while
/// (`store_link::fetch_store_id`), so a page never says "Loading" for good.
/// Does nothing for a store already here and followed.
pub(crate) fn load_store_for_page(store_contract_id: &[u8]) {
    let opening = opening_for(&crate::gateway::APP_STATE.peek(), store_contract_id);
    let Ok(bytes) = <[u8; 32]>::try_from(store_contract_id) else {
        crate::gateway::APP_STATE
            .write()
            .note_store_link_failed(store_contract_id, "That store can\u{2019}t be opened.");
        return;
    };
    let id = freenet_stdlib::prelude::ContractInstanceId::new(bytes);
    match opening {
        Opening::Loaded => {}
        Opening::ByCode(params) => {
            crate::gateway::APP_STATE
                .write()
                .note_store_code(store_contract_id.to_vec(), params.code().to_string());
            crate::store_link::fetch_store_id(id);
        }
        Opening::ById => crate::store_link::fetch_store_id(id),
    }
}

/// Show a store's own page from a button that names it by id: the same as
/// [`show_store`], kept for the callers that name it so.
pub(crate) fn open_store_page(store_contract_id: Vec<u8>) {
    show_store(store_contract_id);
}

/// A followed link named a store the old way: the store page says so.
pub(crate) fn show_old_format_link() {
    crate::gateway::APP_STATE.write().note_old_format_link();
    super::router::replace(Page::Store {
        store: Vec::new(),
        tab: StoreTab::Items,
    });
}

/// The pill at the top right, when anything needs the person using this
/// device: as a seller (`my_store::SellerStore::needs_you`) or as a buyer
/// (an order to pay, a store that replied). The browser tab's title carries
/// the same count.
pub(crate) fn needs_you_pill(count: usize) -> Option<String> {
    match count {
        0 => None,
        1 => Some("1 needs you".to_string()),
        n => Some(format!("{n} need you")),
    }
}

#[component]
pub fn App() -> Element {
    let page = PAGE();
    let connection_status = CONNECTION_STATUS.read().clone();
    // What needs the person, as a seller and as a buyer, rides on the header,
    // visible from every page: a buyer's order arriving is the one thing a
    // seller must not miss, and a store's reply the one a buyer would.
    let places = super::needs::header_places();
    let needs_count: usize = places.iter().map(|p| p.count).sum();
    let current_tab = page.nav_tab();
    // Back and Forward, for the life of the page.
    use_hook(super::router::listen_for_back);

    #[cfg(all(target_arch = "wasm32", not(feature = "no-sync")))]
    {
        use futures::StreamExt;

        use_effect(|| {
            wasm_bindgen_futures::spawn_local(async {
                let mut rx = match crate::gateway::connect().await {
                    Ok(rx) => rx,
                    Err(e) => {
                        dioxus::logger::tracing::error!("Failed to connect: {}", e);
                        *CONNECTION_STATUS.write() = ConnectionStatus::Error(e);
                        return;
                    }
                };

                dioxus::logger::tracing::info!("Connected -- registering delegates");

                // If this page was opened from a shared store link, fetch and
                // subscribe to that store now. It needs only the websocket:
                // a buyer following a seller's link has no ghostkey and needs
                // neither delegate to read a store. Otherwise the page its
                // fragment names (a reload, or a link to a page), with the
                // store it shows asked for now the websocket is up.
                if !super::router::start() {
                    crate::store_link::open_store_from_url();
                }

                let harvest_wasm = include_bytes!("../../public/contracts/harvest_delegate.wasm");
                let harvest_key = match crate::gateway::register_delegate(harvest_wasm).await {
                    Ok(key) => {
                        dioxus::logger::tracing::info!("Harvest delegate registered: {:?}", key);
                        Some(key)
                    }
                    Err(e) => {
                        dioxus::logger::tracing::error!(
                            "Failed to register harvest delegate: {}",
                            e
                        );
                        None
                    }
                };

                // Step 3: Register the ghostkey delegate, then ASK IT WHAT WE
                // ALREADY HAVE.
                //
                // An earlier version deliberately skipped `ListGhostKeys` here,
                // reasoning that the vault auto-grants only the importing
                // webapp, so for any other webapp the list is empty until the
                // user approves a `RequestAnyAccess` prompt. The premise is
                // true. The conclusion does not follow, and skipping the call
                // is what made the user re-approve on EVERY page load.
                //
                // Approving `RequestAnyAccess` PERSISTS a grant: the delegate
                // calls `permissions::grant_third_party`, which saves
                // `{ReadPublic, Sign}` for this requestor against that
                // fingerprint. `handle_list` then returns exactly the keys the
                // requestor holds `ReadPublic` on. The grant is keyed by
                // `SignatureRequestor::WebApp(ContractInstanceId)`, and this
                // app's contract id is fixed, so it survives a reload.
                //
                // So the list is empty only BEFORE the first approval -- when
                // an empty answer is exactly right and the My Store empty state
                // offers "Choose a Ghost Key". Afterwards it returns the shared
                // key with no prompt at all.
                //
                // `RequestAnyAccess` raises a user prompt every single time by
                // construction; it is the wrong thing to call when you only
                // want to know what you already have. Ask first, prompt only if
                // the answer is empty.
                let gk_wasm = include_bytes!("../../public/contracts/ghostkey_delegate.wasm");
                let ghostkey_key = match crate::gateway::register_delegate(gk_wasm).await {
                    Ok(key) => {
                        dioxus::logger::tracing::info!("Ghostkey delegate registered: {:?}", key);
                        Some(key)
                    }
                    Err(e) => {
                        dioxus::logger::tracing::error!(
                            "Failed to register ghostkey delegate: {}",
                            e
                        );
                        None
                    }
                };

                // Nothing talks to either delegate until the node says its
                // registration is done (harvest#162, harvest#163): sent earlier,
                // a message can overtake the registration and be refused as a
                // missing delegate, with nothing to retry it. A delegate's key
                // is what everything else checks before sending, so it is set
                // only then. In one task and in this order, Harvest first: the
                // ghostkey's answers (the shared identities) start Harvest work
                // (the store list, the migrations), which must find the Harvest
                // delegate usable. Spawned, because the answers are read by the
                // response loop below.
                wasm_bindgen_futures::spawn_local(async move {
                    // Both deadlines start now, so a slow Harvest answer does
                    // not push the ghostkey's back.
                    let harvest_wait = harvest_key
                        .clone()
                        .map(|key| (crate::gateway::delegate_registered(&key), key));
                    let ghostkey_wait = ghostkey_key
                        .clone()
                        .map(|key| (crate::gateway::delegate_registered(&key), key));
                    if let Some((harvest_wait, key)) = harvest_wait {
                        if !harvest_wait.await {
                            dioxus::logger::tracing::warn!(
                                "The node did not confirm the Harvest delegate's registration; \
                                 going ahead"
                            );
                        }
                        crate::gateway::APP_STATE.write().harvest_delegate_key = Some(key);
                        harvest_delegate_ready().await;
                    }
                    if let Some((ghostkey_wait, key)) = ghostkey_wait {
                        if !ghostkey_wait.await {
                            dioxus::logger::tracing::warn!(
                                "The node did not confirm the ghostkey delegate's registration; \
                                 going ahead"
                            );
                        }
                        crate::gateway::APP_STATE.write().ghostkey_delegate_key = Some(key.clone());
                        ghostkey_delegate_ready(key).await;
                    }
                    // Carry the harvest delegate's secrets over from its earlier
                    // generations (harvest#123), now that the delegates are
                    // registered and the loop that reads the answers is running.
                    crate::gateway::delegate_migrate_ops::start();
                });

                // Find out which generation of the bridge's address contract,
                // request inbox and tip to use. Needs only the websocket, and no
                // invoice can be issued until the address generation resolves.
                // Started here, just before the loop that reads the answers,
                // because a pointer GET's timeout starts when it is sent: begun
                // before the delegates above were registered, a slow
                // registration would time every first attempt out unanswered.
                crate::gateway::bitcoin_generation_ops::start();

                dioxus::logger::tracing::info!("Starting response loop");
                while let Some(response) = rx.next().await {
                    crate::gateway::response_handler::handle_response(response);
                }

                dioxus::logger::tracing::warn!("Response loop ended (connection lost)");
                *CONNECTION_STATUS.write() = ConnectionStatus::Disconnected;
            });
        });
    }

    // Update document title based on current view
    {
        let app_state = crate::gateway::APP_STATE.read();
        // Ask the same question `StorePage` asks, through the same helper.
        // Reading `browsing_stores` directly here picked the map's first
        // loaded entry, so once a second store loaded the page was titled
        // after a store the user was not looking at.
        let store_name = app_state
            .displayed_store()
            .and_then(|(_, store)| store.info.as_ref())
            .map(|info| info.store_name.trim())
            // An unnamed store keeps the plain title, not "Harvest - ".
            .filter(|name| !name.is_empty());

        let on_store = matches!(page, Page::Store { .. } | Page::Item { .. });
        crate::document_title::set_counted_title(needs_count, store_name.filter(|_| on_store));
    }

    // A dot while all is well; words only when the connection is not.
    let (status_class, status_words) = match &connection_status {
        ConnectionStatus::Connected => ("harvest-status connected", None),
        ConnectionStatus::Connecting => (
            "harvest-status connecting",
            Some("Connecting\u{2026}".to_string()),
        ),
        ConnectionStatus::Error(_) => ("harvest-status error", Some(connection_status.to_string())),
        ConnectionStatus::Disconnected => ("harvest-status", Some("Disconnected".to_string())),
    };

    rsx! {
        div { class: "harvest-app",
            header { class: "harvest-header",
                button {
                    class: "harvest-title-group",
                    aria_label: "Harvest, to Stores",
                    onclick: move |_| go(Page::Stores),
                    img {
                        class: "harvest-logo",
                        src: "harvest-logo.svg",
                        alt: "Harvest",
                    }
                    h1 { class: "harvest-title", "Harvest" }
                }
                div { class: "harvest-header-right",
                    super::needs::NeedsPill { places }
                    span {
                        class: "{status_class}",
                        title: "{connection_status}",
                        role: "status",
                        span { class: "status-dot", aria_hidden: "true" }
                        if let Some(words) = status_words {
                            span { class: "status-words", "{words}" }
                        } else {
                            span { class: "visually-hidden", "Connected to Freenet" }
                        }
                    }
                }
            }
            nav { class: "harvest-nav", aria_label: "Main",
                for (tab , label , target) in [
                    (NavTab::Stores, "Stores", Page::Stores),
                    (NavTab::Purchases, "Purchases", Page::Purchases),
                ] {
                    button {
                        class: if current_tab == Some(tab) { "nav-btn active" } else { "nav-btn" },
                        aria_current: if current_tab == Some(tab) { "page" } else { "false" },
                        onclick: move |_| go(target.clone()),
                        "{label}"
                    }
                }
            }

            {notification_bar()}

            main { class: "harvest-main",
                {super::pages::page_body(page)}
            }

            // Details for whoever needs them (a developer, or a seller asked
            // which build they run), quiet at the foot of every page: a build
            // time and "Bitcoin bridge status" in every visitor's footer
            // confused first-time visitors (freenet.org/open critique).
            footer { class: "harvest-footer",
                details {
                    summary { "About this version" }
                    p { "Built {format_build_time()}." }
                }
                span { class: "sep", aria_hidden: "true", "\u{00b7}" }
                button {
                    class: "link-btn",
                    onclick: move |_| go(Page::Diagnostics),
                    "Diagnostics"
                }
            }
        }
    }
}

const BUILD_TIMESTAMP_ISO: &str = env!("BUILD_TIMESTAMP_ISO");

/// What the Harvest delegate is asked once the node has registered it: see
/// the connect flow in [`App`].
#[cfg(all(target_arch = "wasm32", not(feature = "no-sync")))]
async fn harvest_delegate_ready() {
    // A store link opened above may already have brought
    // its state back, and a store whose state arrived
    // before this point was deliberately not asked about
    // -- see `AppState::buyer_conversations_to_recall`.
    // Without this a returning buyer holds keys, on this
    // machine, to a reply they never fetch.
    crate::gateway::APP_STATE
        .write()
        .recall_conversations_for_known_stores();

    // And the stores this node remembers, remembering
    // first whatever a link opened before the delegate
    // existed (harvest#52).
    crate::gateway::APP_STATE.write().sync_remembered_stores();

    // And this buyer's kept purchases: what the payment
    // details wait on, and what a complaint rests on
    // (harvest#53 Phase C). Asked again on the watch
    // timer until an answer arrives.
    crate::gateway::APP_STATE.write().sync_kept_purchases();

    // Kick off the Bitcoin surface: bridge config (needed
    // for the first-run status panel, no credential
    // required) and the private watch list. Each of
    // these subscribes to whatever Bitcoin contracts it
    // learns about as its response arrives -- see
    // `AppState::on_bitcoin_delegate_response`.
    if let Err(e) = crate::gateway::bitcoin_ops::get_bridge().await {
        dioxus::logger::tracing::error!("Failed to fetch bridge config: {e}");
    }
    if let Err(e) = crate::gateway::bitcoin_ops::list_watched().await {
        dioxus::logger::tracing::error!("Failed to fetch watch list: {e}");
    }
    // And the seller's payment key, so "My Store" knows
    // whether it can offer to issue an invoice at all
    // rather than prompting for a key that is already set.
    if let Err(e) = crate::gateway::bitcoin_ops::get_payment_xpub().await {
        dioxus::logger::tracing::error!("Failed to fetch payment key: {e}");
        // Nothing will answer, so mark it answered. Left
        // false, `PaymentKeyPanel` sits on "Checking your
        // payment key…" for the rest of the session and
        // the seller can never reach the form to set one.
        // Showing the form when we do not know is the safe
        // direction: setting the key again is harmless
        // (the counter is preserved -- see the delegate's
        // `apply_set_payment_xpub`), being unable to set
        // it at all is not.
        crate::gateway::APP_STATE
            .write()
            .bitcoin
            .payment_xpub_loaded = true;
    }
    // And never wait on its answer forever (harvest#163): an answer can
    // still be lost, and the page would sit on "Checking your payment key".
    // Asked once more, then the form is shown.
    wasm_bindgen_futures::spawn_local(async {
        gloo_timers::future::TimeoutFuture::new(crate::state::PAYMENT_KEY_ANSWER_WAIT_MS).await;
        if crate::gateway::APP_STATE.read().bitcoin.payment_xpub_loaded {
            return;
        }
        if let Err(e) = crate::gateway::bitcoin_ops::get_payment_xpub().await {
            dioxus::logger::tracing::error!("Failed to fetch payment key again: {e}");
        }
        gloo_timers::future::TimeoutFuture::new(crate::state::PAYMENT_KEY_ANSWER_WAIT_MS).await;
        crate::gateway::APP_STATE
            .write()
            .payment_key_answer_overdue();
    });
}

/// What the ghostkey delegate is asked once the node has registered it.
#[cfg(all(target_arch = "wasm32", not(feature = "no-sync")))]
async fn ghostkey_delegate_ready(key: freenet_stdlib::prelude::DelegateKey) {
    // Restore any identity already shared with this app.
    // Failure is not user-facing: an empty or failed list
    // leaves the My Store empty state offering "Connect a
    // ghostkey", which is the same place the user would
    // have started anyway.
    match ghostkey_common::to_cbor(&ghostkey_common::GhostkeyRequest::ListGhostKeys) {
        Ok(payload) => {
            if let Err(e) = crate::gateway::send_delegate_message(&key, payload).await {
                dioxus::logger::tracing::warn!(
                    "Could not ask the vault for already-shared identities: {e}"
                );
            }
        }
        Err(e) => dioxus::logger::tracing::error!("Failed to encode ListGhostKeys: {e}"),
    }
}

fn format_build_time() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        use js_sys::Date;
        let date = Date::new(&wasm_bindgen::JsValue::from_str(BUILD_TIMESTAMP_ISO));
        let year = date.get_full_year();
        let month = date.get_month() + 1;
        let day = date.get_date();
        let hours = date.get_hours();
        let minutes = date.get_minutes();
        format!("{year}-{month:02}-{day:02} {hours:02}:{minutes:02}")
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        BUILD_TIMESTAMP_ISO.to_string()
    }
}

fn notification_bar() -> Element {
    let app_state = crate::gateway::APP_STATE.read();
    // Notices that last only while something is under way (harvest#166)
    // come after the ones that stay, and end by themselves.
    let progress = app_state.progress_notices();
    // Each notice once, however often it was raised, and each with a way to
    // put it away: before, they stacked up to eight deep above every screen
    // and never left (the 2026-09-27 friction report).
    let (notices, hidden) = distinct_notices(&app_state.notifications);
    if notices.is_empty() && progress.is_empty() {
        return rsx! {};
    }

    rsx! {
        div { class: "notification-bar",
            for notice in notices {
                div { key: "{notice}", class: "notice-row",
                    p { "{notice}" }
                    button {
                        class: "link-btn notice-dismiss",
                        aria_label: "Dismiss this notice",
                        onclick: {
                            let notice = notice.clone();
                            move |_| crate::gateway::APP_STATE.write().dismiss_notification(&notice)
                        },
                        "Dismiss"
                    }
                }
            }
            for notice in progress.iter() {
                p { "{notice}" }
            }
            if hidden > 0 {
                p { class: "text-muted small",
                    if hidden == 1 { "1 older notice isn\u{2019}t shown." } else { "{hidden} older notices aren\u{2019}t shown." }
                }
            }
        }
    }
}

/// Each notice once, in the order last raised; at most the latest
/// [`NOTICES_SHOWN`] distinct ones, and how many older ones are not shown.
fn distinct_notices(notifications: &[String]) -> (Vec<String>, usize) {
    // Deduplicated at each notice's LATEST raising, so one raised again
    // moves to the end and is shown (codex, round 2 of #190).
    let mut seen = std::collections::HashSet::new();
    let mut distinct: Vec<String> = notifications
        .iter()
        .rev()
        .filter(|n| seen.insert(n.as_str()))
        .cloned()
        .collect();
    distinct.reverse();
    let hidden = distinct.len().saturating_sub(NOTICES_SHOWN);
    (distinct.into_iter().skip(hidden).collect(), hidden)
}

/// How many distinct notices the bar shows at once: the latest. Nothing is
/// dropped from the list itself; the bar just never becomes a wall again.
const NOTICES_SHOWN: usize = 5;

#[cfg(test)]
mod notice_tests {
    /// A notice raised again is shown once. Red without the dedupe.
    #[test]
    fn a_repeated_notice_shows_once() {
        let raised = ["a", "b", "a", "a", "c", "b"].map(String::from);
        assert_eq!(
            super::distinct_notices(&raised).0,
            ["a", "c", "b"].map(String::from),
            "each at its latest raising"
        );
        // Past the cap, the latest are shown, and the rest counted.
        let many: Vec<String> = (0..9).map(|n| n.to_string()).collect();
        assert_eq!(
            super::distinct_notices(&many),
            (["4", "5", "6", "7", "8"].map(String::from).to_vec(), 4)
        );
        // A hidden notice raised again is shown.
        let mut again = many.clone();
        again.push("0".into());
        assert!(super::distinct_notices(&again).0.contains(&"0".to_string()));
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;
    use dioxus::prelude::{ReadableExt, ScopeId, VirtualDom};

    /// Run `f` where the app's global signals live, each test in a fresh
    /// app, so nothing one test navigates to is seen by another.
    fn in_app(f: impl FnOnce()) {
        fn empty() -> Element {
            rsx! {}
        }
        let mut dom = VirtualDom::new(empty);
        dom.rebuild_in_place();
        dom.in_scope(ScopeId::ROOT, f);
    }

    fn params(seed: u8) -> harvest_common::store::StoreParameters {
        harvest_common::store::StoreParameters::new(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key(),
        )
    }

    fn id_of(params: &harvest_common::store::StoreParameters) -> Vec<u8> {
        crate::gateway::store_ops::store_instance_id(params)
            .expect("derive")
            .as_bytes()
            .to_vec()
    }

    /// **Every way of opening a store lands on the store's own page**, never
    /// on the Stores list with the store under it (critique S1-5, S2-1): a
    /// followed link, a typed code and a visited row all go through
    /// `store_link::open_store`; Purchases' "Open store" and "See your store
    /// as buyers do" through `show_store`; an old-format link says so on the
    /// store page. Red with `open_store` leaving the route alone, as the
    /// Stores page's embedded store did.
    #[test]
    fn every_way_of_opening_a_store_lands_on_its_own_page() {
        in_app(|| {
            assert_eq!(*PAGE.peek(), Page::Stores, "the app opens on Stores");
            let linked = params(7);
            crate::store_link::open_store(linked.clone());
            assert_eq!(*PAGE.peek(), store_page(id_of(&linked)));
            {
                let state = crate::gateway::APP_STATE.peek();
                assert_eq!(state.active_store_id, Some(id_of(&linked)));
                assert_eq!(
                    state.store_codes.get(&id_of(&linked)).map(String::as_str),
                    Some(linked.code()),
                    "remembered once it loads, under the code it was opened by"
                );
            }

            // Back to Stores, then a store opened from Purchases or from
            // the seller's own pages, by its id.
            go(Page::Stores);
            open_store_page(vec![9u8; 32]);
            assert_eq!(*PAGE.peek(), store_page(vec![9u8; 32]));
            assert_eq!(
                crate::gateway::APP_STATE.peek().active_store_id,
                Some(vec![9u8; 32])
            );
            // One whose state is not here but whose code is known is opened
            // by its code, which asks for it (and, on wasm, gives up after a
            // while) rather than waiting on nothing.
            let known = params(10);
            crate::gateway::APP_STATE
                .write()
                .note_store_code(id_of(&known), known.code().to_string());
            go(Page::Stores);
            open_store_page(id_of(&known));
            assert_eq!(*PAGE.peek(), store_page(id_of(&known)));
            assert_eq!(
                crate::gateway::APP_STATE.peek().active_store_id,
                Some(id_of(&known))
            );

            // A link from before store codes: the store page says why.
            go(Page::Stores);
            show_old_format_link();
            assert!(matches!(*PAGE.peek(), Page::Store { .. }));
            assert_eq!(
                crate::gateway::APP_STATE.peek().store_link_error.as_deref(),
                Some(crate::store_link::OLD_FORMAT_LINK_MESSAGE)
            );
            // Opening a store after that clears it.
            crate::store_link::open_store(params(8));
            assert_eq!(crate::gateway::APP_STATE.peek().store_link_error, None);
        });
    }

    /// The page for a store's own items.
    fn store_page(id: Vec<u8>) -> Page {
        Page::Store {
            store: id,
            tab: StoreTab::Items,
        }
    }

    /// The seller's pages and opening a store are reached from Stores, and
    /// keep its tab lit; an order, a conversation and the backup light
    /// Purchases; the footer's diagnostics light neither.
    #[test]
    fn each_page_lights_the_tab_it_is_reached_from() {
        use super::super::router::{OrderAt, SellerView};
        in_app(|| {
            go(Page::Seller {
                store: Some(vec![3u8; 32]),
                view: SellerView::Home,
            });
            assert_eq!(PAGE.peek().nav_tab(), Some(NavTab::Stores));
        });
        assert_eq!(Page::Stores.nav_tab(), Some(NavTab::Stores));
        assert_eq!(store_page(vec![1u8; 32]).nav_tab(), Some(NavTab::Stores));
        assert_eq!(
            Page::OpenStore { another: true }.nav_tab(),
            Some(NavTab::Stores)
        );
        assert_eq!(Page::Purchases.nav_tab(), Some(NavTab::Purchases));
        assert_eq!(Page::Backup.nav_tab(), Some(NavTab::Purchases));
        assert_eq!(
            Page::Order {
                at: OrderAt::Kept([1u8; 32]),
                order: harvest_common::payment::OrderId([2u8; 32]),
            }
            .nav_tab(),
            Some(NavTab::Purchases)
        );
        assert_eq!(Page::Diagnostics.nav_tab(), None);
    }

    /// What needs the seller rides on the Stores tab, from every page, and
    /// only when there is some.
    #[test]
    fn the_header_pill_says_what_needs_the_seller() {
        assert_eq!(needs_you_pill(0), None);
        assert_eq!(needs_you_pill(1).as_deref(), Some("1 needs you"));
        assert_eq!(needs_you_pill(2).as_deref(), Some("2 need you"));
    }

    fn loaded() -> crate::state::BrowsingStore {
        crate::state::BrowsingStore {
            info: Some(harvest_common::store::StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: String::new(),
                reputation_contract_id: [0u8; 32],
                store_name: "Pots".to_string(),
                description: String::new(),
                encryption_public_key: None,
                record_public_key: None,
            }),
            ..Default::default()
        }
    }

    /// How a store named by its id is opened: shown as it is when its state
    /// is here and followed (no second fetch); otherwise by its code, found
    /// among the codes stores were opened under, the remembered stores
    /// (removed ones too) or this node's own stores' keys; and by its address
    /// when no code is known. Red if a store with no code in `store_codes`
    /// is shown without anything fetching it (Gemini and skeptical on #197).
    #[test]
    fn a_store_named_by_id_is_opened_the_way_that_can_end() {
        use crate::state::AppState;
        let p = params(11);
        let id = id_of(&p);

        let mut state = AppState::default();
        assert_eq!(opening_for(&state, &id), Opening::ById, "nothing known");

        state.browsing_stores.insert(id.clone(), loaded());
        assert_eq!(opening_for(&state, &id), Opening::Loaded, "no re-open");
        state.light_stores.insert(id.clone());
        assert_eq!(
            opening_for(&state, &id),
            Opening::ById,
            "listed only, and no code known: fetched again, followed"
        );

        let mut state = AppState::default();
        state.store_codes.insert(id.clone(), p.code().to_string());
        assert_eq!(opening_for(&state, &id), Opening::ByCode(p.clone()));

        let state = AppState {
            remembered_stores: Some(vec![harvest_common::RememberedStore {
                store_code: p.code().to_string(),
                archived: true,
            }]),
            ..Default::default()
        };
        assert_eq!(
            opening_for(&state, &id),
            Opening::ByCode(p.clone()),
            "a removed one"
        );

        let own_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]).verifying_key();
        let mut state = AppState::default();
        state.my_stores.insert(
            "fp".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: id.clone(),
                reputation_contract_id: Vec::new(),
                mailbox_contract_id: Vec::new(),
                store_contract_key: None,
                store_verifying_key: Some(own_key.to_bytes()),
            }],
        );
        assert_eq!(opening_for(&state, &id), Opening::ByCode(p), "one of ours");
    }

    /// A store opened by its address alone still reaches an end: it reads
    /// as loading while its fetch is out, and as not loaded once the fetch
    /// gives up, never "Loading" for good.
    #[test]
    fn a_store_opened_by_its_address_reaches_an_end() {
        use crate::state::StoreName;
        in_app(|| {
            let id = vec![12u8; 32];
            open_store_page(id.clone());
            assert_eq!(*PAGE.peek(), store_page(id.clone()));
            assert!(crate::gateway::APP_STATE
                .peek()
                .foreground_loads
                .contains(&id));
            assert_eq!(
                crate::gateway::APP_STATE.peek().store_name_of(&id),
                StoreName::Loading
            );
            // What its timer does on wasm when the wait is over.
            crate::gateway::APP_STATE.write().end_foreground_load(&id);
            assert_eq!(
                crate::gateway::APP_STATE.peek().store_name_of(&id),
                StoreName::Unreachable
            );

            // A loaded store is only shown: nothing is fetched again.
            let loaded_id = vec![13u8; 32];
            crate::gateway::APP_STATE
                .write()
                .browsing_stores
                .insert(loaded_id.clone(), loaded());
            open_store_page(loaded_id.clone());
            assert_eq!(
                crate::gateway::APP_STATE.peek().active_store_id,
                Some(loaded_id.clone())
            );
            assert!(!crate::gateway::APP_STATE
                .peek()
                .foreground_loads
                .contains(&loaded_id));
        });
    }
}
