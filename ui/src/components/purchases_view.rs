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
            // Never a code, and "Loading…" or "Couldn't load this store"
            // rather than a vague "A store" (review of #197).
            let name = state.store_name_of(id).label();
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
    use_effect(|| crate::store_link::load_visited_stores(false, true));
    let rows = purchase_rows(&APP_STATE.read());
    // Still being asked for (a GET out, or a retry waiting), and could not be
    // loaded: neither is a confirmed empty history (codex on #197 round 4).
    let (pending, failed) = APP_STATE.read().visited_load_state();
    let loading = pending > 0 || !APP_STATE.read().background_loads.is_empty();
    let any_kept = !APP_STATE.read().kept_purchases.is_empty();
    // The orders the store cards below already show, so the kept list does
    // not show them a second time.
    let shown = shown_order_ids(&APP_STATE.read(), &rows);

    rsx! {
        div {
            h2 { "Purchases" }
            p { class: "text-muted small",
                "Kept by the Freenet node on this device, not in the network, so they do not follow "
                "you to another computer. A conversation can be backed up from inside it."
            }
            if loading {
                p { class: "text-muted text-italic", "Checking the stores you have used\u{2026}" }
            }
            if let Some(note) = unreachable_note(failed) {
                p { class: "text-warning", "{note}" }
            }
            if rows.is_empty() && !loading && failed == 0 && !any_kept {
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
