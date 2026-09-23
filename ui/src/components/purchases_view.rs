//! My purchases: every store this device has bought from or written to, in
//! one place (harvest#93 phase 2). Before this a buyer's orders sat under each
//! store's own page, so finding one meant remembering which store it was.

use dioxus::prelude::*;

use crate::gateway::APP_STATE;
use crate::state::AppState;

/// One store on My purchases.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PurchaseRow {
    pub store_contract_id: Vec<u8>,
    pub name: String,
    /// Orders the seller has published for this buyer.
    pub orders: usize,
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
            let orders = state.buyer_purchases(id).len();
            let conversations = store.conversations.len();
            if orders == 0 && conversations == 0 {
                return None;
            }
            let name = store
                .info
                .as_ref()
                .map(|info| info.store_name.trim().to_string())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "A store".to_string());
            Some(PurchaseRow {
                store_contract_id: id.clone(),
                name,
                orders,
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

#[component]
pub fn MyPurchases() -> Element {
    // The stores this device has used, loaded in the background, since only
    // a loaded store recalls this device's conversations with it.
    // An effect, so it runs again when the delegate's list of remembered
    // stores arrives after this page opened; loading is idempotent per store.
    use_effect(|| {
        let codes: Vec<String> = APP_STATE
            .read()
            .store_list_rows(false)
            .0
            .into_iter()
            .map(|row| row.code)
            .collect();
        for code in codes {
            crate::store_link::load_remembered_store(&code);
        }
    });
    let rows = purchase_rows(&APP_STATE.read());
    let loading = !APP_STATE.read().background_loads.is_empty();
    let any_kept = !APP_STATE.read().kept_purchases.is_empty();
    // The orders the store cards below already show, so the kept list does
    // not show them a second time.
    let shown = shown_order_ids(&APP_STATE.read(), &rows);

    rsx! {
        div {
            h2 { "My purchases" }
            p { class: "text-muted small",
                "Kept by the Freenet node on this device, not in the network, so they do not follow "
                "you to another computer. A conversation can be backed up from inside it."
            }
            if rows.is_empty() && loading {
                p { class: "text-muted text-italic", "Checking the stores you have used\u{2026}" }
            } else if rows.is_empty() && !any_kept {
                div { class: "card empty-state",
                    p { "Nothing yet." }
                    p {
                        "When you ask a store a question or buy something, it is listed here. "
                        "Open a store from Stores to start."
                    }
                }
            }
            for row in rows {
                div { class: "card purchase-store", key: "{bs58::encode(&row.store_contract_id).into_string()}",
                    div { class: "row-between",
                        h3 { class: "purchase-store-name", "{row.name}" }
                        button {
                            class: "btn btn-sm btn-outline",
                            onclick: {
                                let id = row.store_contract_id.clone();
                                move |_| super::app::open_store_page(id.clone())
                            },
                            "Open store"
                        }
                    }
                    p { class: "text-muted small",
                        {summary(row.orders, row.conversations)}
                    }
                    super::buy_view::Purchases { store_contract_id: row.store_contract_id.clone() }
                }
            }
            // Every purchase this node keeps, from the kept records alone
            // (R5-B of #143), with the complaint control: a store re-keyed
            // while its seller stays away, or one nobody hosts, still leaves
            // the buyer these. On this page since the Payments tab became
            // the footer's diagnostics (harvest#93 phase 2).
            super::buy_view::KeptPurchases { shown }
        }
    }
}

/// The kept purchases the store cards on this page already show, with their
/// complaint control (`AppState::kept_purchases_shown_at` of each row).
pub(crate) fn shown_order_ids(
    state: &AppState,
    rows: &[PurchaseRow],
) -> Vec<([u8; 32], harvest_common::payment::OrderId)> {
    rows.iter()
        .flat_map(|row| state.kept_purchases_shown_at(&row.store_contract_id))
        .collect()
}

fn summary(orders: usize, conversations: usize) -> String {
    let orders = match orders {
        0 => "No orders yet".to_string(),
        1 => "1 order".to_string(),
        n => format!("{n} orders"),
    };
    let conversations = match conversations {
        0 => String::new(),
        1 => " · 1 conversation".to_string(),
        n => format!(" · {n} conversations"),
    };
    format!("{orders}{conversations}")
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
    /// or loading, and a GET that fails to send is forgotten so a later visit
    /// retries; state that arrived meanwhile is kept. Mutated red by dropping
    /// the already-present check and the failure's removal.
    #[test]
    fn a_remembered_store_is_loaded_once_and_retried_after_a_failed_send() {
        let mut state = AppState::default();
        assert!(state.begin_background_load(vec![1u8; 32], "code".into()));
        assert!(!state.begin_background_load(vec![1u8; 32], "code".into()));
        state.end_background_load_failed(&[1u8; 32]);
        assert!(state.begin_background_load(vec![1u8; 32], "code".into()));

        state.browsing_stores.insert(vec![2u8; 32], named("Loaded"));
        assert!(!state.begin_background_load(vec![2u8; 32], "code".into()));
        state.end_background_load_failed(&[2u8; 32]);
        assert!(
            state.browsing_stores.contains_key(&vec![2u8; 32]),
            "arrived state kept"
        );
    }

    #[test]
    fn the_summary_counts_what_there_is() {
        assert_eq!(summary(0, 1), "No orders yet · 1 conversation");
        assert_eq!(summary(2, 0), "2 orders");
        assert_eq!(summary(1, 3), "1 order · 3 conversations");
    }
}

#[cfg(test)]
mod background_tests {
    use super::*;

    fn some_store_state() -> Vec<u8> {
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
        assert!(state.begin_background_load(vec![7u8; 32], "code".into()));
        state.on_contract_state(vec![7u8; 32], some_store_state());
        assert_eq!(state.active_store_id, None);
        assert!(state.background_loads.is_empty());

        // A store the user opened still does.
        let mut state = AppState::default();
        state.on_contract_state(vec![8u8; 32], some_store_state());
        assert_eq!(state.active_store_id, Some(vec![8u8; 32]));
    }
}
