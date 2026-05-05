use dioxus::prelude::*;

use super::my_store::MyStore;
use super::reputation_view::ReputationView;
use super::store_view::StoreView;
use crate::gateway::{ConnectionStatus, CONNECTION_STATUS};

#[derive(Clone, PartialEq)]
enum Route {
    Browse,
    MyStore,
    Reputation,
}

#[component]
pub fn App() -> Element {
    let mut current_route = use_signal(|| Route::Browse);
    let connection_status = CONNECTION_STATUS.read().clone();

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

                let harvest_wasm = include_bytes!("../../public/contracts/harvest_delegate.wasm");
                match crate::gateway::register_delegate(harvest_wasm).await {
                    Ok(key) => {
                        dioxus::logger::tracing::info!("Harvest delegate registered: {:?}", key);
                        crate::gateway::APP_STATE.write().harvest_delegate_key = Some(key);
                    }
                    Err(e) => {
                        dioxus::logger::tracing::error!(
                            "Failed to register harvest delegate: {}",
                            e
                        );
                    }
                }

                // Step 3: Register the ghostkey delegate. We deliberately
                // do NOT call `ListGhostKeys` on startup any more: the
                // vault now auto-grants only the importing webapp (the
                // Ghostkey Vault itself) on key import, so for any other
                // webapp `ListGhostKeys` returns an empty list until the
                // user explicitly approves a `RequestAnyAccess` prompt.
                // The "Connect a ghostkey" button on the My Store empty
                // state triggers that prompt; the response folds the
                // shared key into APP_STATE.ghostkeys.
                let gk_wasm = include_bytes!("../../public/contracts/ghostkey_delegate.wasm");
                match crate::gateway::register_delegate(gk_wasm).await {
                    Ok(key) => {
                        dioxus::logger::tracing::info!("Ghostkey delegate registered: {:?}", key);
                        crate::gateway::APP_STATE.write().ghostkey_delegate_key = Some(key);
                    }
                    Err(e) => {
                        dioxus::logger::tracing::error!(
                            "Failed to register ghostkey delegate: {}",
                            e
                        );
                    }
                }

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
        let store_name = app_state
            .browsing_stores
            .values()
            .find_map(|s| s.info.as_ref())
            .map(|i| i.store_name.as_str());

        match (&current_route(), store_name) {
            (Route::Browse, Some(name)) => crate::document_title::set_store_title(name),
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
                nav { class: "harvest-nav",
                    span { class: "{status_class}", "{connection_status}" }
                    button {
                        class: if current_route() == Route::Browse { "nav-btn active" } else { "nav-btn" },
                        onclick: move |_| current_route.set(Route::Browse),
                        "Browse"
                    }
                    button {
                        class: if current_route() == Route::MyStore { "nav-btn active" } else { "nav-btn" },
                        onclick: move |_| current_route.set(Route::MyStore),
                        "My Store"
                    }
                    button {
                        class: if current_route() == Route::Reputation { "nav-btn active" } else { "nav-btn" },
                        onclick: move |_| current_route.set(Route::Reputation),
                        "Reputation"
                    }
                }
            }

            {notification_bar()}

            match current_route() {
                Route::Browse => rsx! { StoreView {} },
                Route::MyStore => rsx! { MyStore {} },
                Route::Reputation => rsx! { ReputationView {} },
            }

            // Footer with build timestamp
            footer { class: "harvest-footer",
                span { "Built: {format_build_time()}" }
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
