use dioxus::prelude::*;

use super::bitcoin_view::BitcoinView;
use super::my_store::MyStore;
use super::purchases_view::MyPurchases;
use super::store_view::StoreView;
use crate::gateway::{ConnectionStatus, CONNECTION_STATUS};

/// The top-level pages (harvest#93 phase 2: Stores / My purchases / My
/// store). The Bitcoin diagnostics that used to be the "Payments" tab are
/// reached from the footer: a seller's orders live in My store and a buyer's
/// in My purchases, so what remains there is for someone checking the bridge.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Route {
    Stores,
    Purchases,
    MyStore,
    Diagnostics,
}

/// The page on screen, global so that a control on one page can send the
/// seller to another ("See your store as buyers do", "Open store").
pub(crate) static ROUTE: GlobalSignal<Route> = GlobalSignal::new(|| Route::Stores);

/// Show a store's own page, as a buyer sees it.
pub(crate) fn open_store_page(store_contract_id: Vec<u8>) {
    crate::gateway::APP_STATE.write().active_store_id = Some(store_contract_id);
    *ROUTE.write() = Route::Stores;
}

#[component]
pub fn App() -> Element {
    let current_route = ROUTE();
    let connection_status = CONNECTION_STATUS.read().clone();
    // A buyer's request arriving is the one thing a seller must not miss, so
    // its count rides on the navigation, visible from every page.
    let waiting = super::my_store::requests_needing_seller(&crate::gateway::APP_STATE.read());
    let my_store_label = match waiting {
        0 => "My store".to_string(),
        n => format!("My store ({n})"),
    };

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
                // neither delegate to read a store.
                crate::store_link::open_store_from_url();

                let harvest_wasm = include_bytes!("../../public/contracts/harvest_delegate.wasm");
                match crate::gateway::register_delegate(harvest_wasm).await {
                    Ok(key) => {
                        dioxus::logger::tracing::info!("Harvest delegate registered: {:?}", key);
                        crate::gateway::APP_STATE.write().harvest_delegate_key = Some(key);

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
                    }
                    Err(e) => {
                        dioxus::logger::tracing::error!(
                            "Failed to register harvest delegate: {}",
                            e
                        );
                    }
                }

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
                // offers "Connect a ghostkey". Afterwards it returns the shared
                // key with no prompt at all.
                //
                // `RequestAnyAccess` raises a user prompt every single time by
                // construction; it is the wrong thing to call when you only
                // want to know what you already have. Ask first, prompt only if
                // the answer is empty.
                let gk_wasm = include_bytes!("../../public/contracts/ghostkey_delegate.wasm");
                match crate::gateway::register_delegate(gk_wasm).await {
                    Ok(key) => {
                        dioxus::logger::tracing::info!("Ghostkey delegate registered: {:?}", key);
                        crate::gateway::APP_STATE.write().ghostkey_delegate_key = Some(key.clone());

                        // Restore any identity already shared with this app.
                        // Failure is not user-facing: an empty or failed list
                        // leaves the My Store empty state offering "Connect a
                        // ghostkey", which is the same place the user would
                        // have started anyway.
                        match ghostkey_common::to_cbor(
                            &ghostkey_common::GhostkeyRequest::ListGhostKeys,
                        ) {
                            Ok(payload) => {
                                if let Err(e) =
                                    crate::gateway::send_delegate_message(&key, payload).await
                                {
                                    dioxus::logger::tracing::warn!(
                                        "Could not ask the vault for already-shared identities: {e}"
                                    );
                                }
                            }
                            Err(e) => dioxus::logger::tracing::error!(
                                "Failed to encode ListGhostKeys: {e}"
                            ),
                        }
                    }
                    Err(e) => {
                        dioxus::logger::tracing::error!(
                            "Failed to register ghostkey delegate: {}",
                            e
                        );
                    }
                }

                // Find out which generation of the bridge's address contract,
                // request inbox and tip to use. Needs only the websocket, and no
                // invoice can be issued until the address generation resolves.
                // Started here, just before the loop that reads the answers,
                // because a pointer GET's timeout starts when it is sent: begun
                // before the delegates above were registered, a slow
                // registration would time every first attempt out unanswered.
                crate::gateway::bitcoin_generation_ops::start();

                // Carry the harvest delegate's secrets over from its earlier
                // generations (harvest#123). Started here for the same reason
                // as the line above: every call has a deadline, and the loop
                // below is what reads the answers.
                crate::gateway::delegate_migrate_ops::start();

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
        // Ask the same question `StoreView` asks, through the same helper.
        // Reading `browsing_stores` directly here picked the map's first
        // loaded entry, so once a second store loaded the page was titled
        // after a store the user was not looking at.
        let store_name = app_state
            .displayed_store()
            .and_then(|(_, store)| store.info.as_ref())
            .map(|info| info.store_name.as_str());

        match (&current_route, store_name) {
            (Route::Stores, Some(name)) => crate::document_title::set_store_title(name),
            _ => crate::document_title::set_default_title(),
        }
    }

    let status_class = match &connection_status {
        ConnectionStatus::Connected => "harvest-status connected",
        ConnectionStatus::Connecting => "harvest-status connecting",
        ConnectionStatus::Error(_) => "harvest-status error",
        ConnectionStatus::Disconnected => "harvest-status",
    };

    rsx! {
        div { class: "harvest-app",
            header { class: "harvest-header",
                div { class: "harvest-title-group",
                    img {
                        class: "harvest-logo",
                        src: "harvest-logo.svg",
                        alt: "Harvest",
                    }
                    h1 { class: "harvest-title", "Harvest" }
                }
                span { class: "{status_class}", "{connection_status}" }
            }
            nav { class: "harvest-nav", aria_label: "Main",
                for (route , label) in [
                    (Route::Stores, "Stores".to_string()),
                    (Route::Purchases, "My purchases".to_string()),
                    (Route::MyStore, my_store_label.clone()),
                ]
                {
                    button {
                        class: if current_route == route { "nav-btn active" } else { "nav-btn" },
                        aria_current: if current_route == route { "page" } else { "false" },
                        onclick: move |_| *ROUTE.write() = route,
                        "{label}"
                    }
                }
            }

            {notification_bar()}

            match current_route {
                Route::Stores => rsx! { StoreView {} },
                Route::Purchases => rsx! { MyPurchases {} },
                Route::MyStore => rsx! { MyStore {} },
                Route::Diagnostics => rsx! { BitcoinView {} },
            }

            footer { class: "harvest-footer",
                span { "Built: {format_build_time()}" }
                button {
                    class: "link-btn",
                    onclick: move |_| *ROUTE.write() = Route::Diagnostics,
                    "Bitcoin bridge status"
                }
            }
        }
    }
}

const BUILD_TIMESTAMP_ISO: &str = env!("BUILD_TIMESTAMP_ISO");

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
    if app_state.notifications.is_empty() {
        return rsx! {};
    }

    rsx! {
        div { class: "notification-bar",
            for notification in &app_state.notifications {
                p { "{notification}" }
            }
        }
    }
}
