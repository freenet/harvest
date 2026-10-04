//! A seller pausing their store, and resuming it (step 2).
//!
//! A pause is a store-key-signed [`StorePause`] in the store's own state, at
//! a revision above the one it replaces, so every device holding the store
//! key reads the same answer and a buyer sees "Closed for now" as soon as
//! the store's state arrives, whatever its presence says. While paused the
//! seller's delegate declines each Buy now ("This store is closed for
//! now."), keeps watching the addresses of invoices already sent, and sends
//! heartbeats saying Paused; it tells buyers at once, because the store's
//! notification reaches it. An invoice the seller writes by hand still goes
//! out ([`PAUSED_INVOICE_NOTE`]).
//!
//! The wait between asking and the state showing it is the listing
//! status's (`listing_status_flow`): the store key signing, then the
//! publish, bounded by [`crate::listing_status_flow::SAVING_WINDOW_MS`].

use harvest_common::store_pause::{AuthorizedStorePause, StorePause};

use crate::listing_status_flow::{SentStatus, SAVING_WINDOW_MS};
use crate::state::{AppState, PendingSignature};

/// Said when a pause or resume could not be signed or published.
pub(crate) const PAUSE_NOT_SAVED: &str =
    "Your store was not paused or resumed, so buyers see it as it was. Try again from Settings.";

/// Said beside an invoice the seller writes by hand while the store is
/// paused: the pause stops Buy now, not the seller.
pub(crate) const PAUSED_INVOICE_NOTE: &str = "Your store is paused; this invoice still goes out.";

/// A pause or resume waiting for the store key's signature.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingStorePause {
    pub store_contract_id: Vec<u8>,
    pub pause: StorePause,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl AppState {
    /// Whether one of our stores is paused, as its state last said (a closed
    /// store is closed, not paused).
    pub fn store_paused(&self, store_contract_id: &[u8]) -> bool {
        self.browsing_stores
            .get(store_contract_id)
            .is_some_and(|store| store.paused())
    }

    /// Whether a pause or resume of this store is still on its way.
    pub fn store_pause_pending(&self, store_contract_id: &[u8]) -> bool {
        self.store_pause_pending_at(store_contract_id, now_ms())
    }

    pub(crate) fn store_pause_pending_at(&self, store_contract_id: &[u8], now_ms: i64) -> bool {
        let signing = self.pending_signatures.iter().any(|pending| {
            matches!(pending, PendingSignature::StorePause(p)
                if p.store_contract_id == store_contract_id)
        });
        let held = self.held_pause_revision(store_contract_id);
        let publishing = self
            .store_pause_sent
            .get(store_contract_id)
            .is_some_and(|sent| {
                sent.waiting_since_ms
                    .is_some_and(|since| now_ms - since < SAVING_WINDOW_MS)
                    && held.is_none_or(|held| held < sent.revision)
            });
        signing || publishing
    }

    fn held_pause_revision(&self, store_contract_id: &[u8]) -> Option<u64> {
        self.browsing_stores
            .get(store_contract_id)
            .and_then(|store| store.pause.as_ref())
            .map(|pause| pause.revision)
    }

    /// Ask the store key to sign a pause (`paused`) or a resume.
    pub(crate) fn queue_store_pause(
        &mut self,
        store_contract_id: Vec<u8>,
        paused: bool,
    ) -> Result<(), String> {
        let now = u64::try_from(now_ms()).unwrap_or(0);
        self.queue_store_pause_at(store_contract_id, paused, now)
    }

    pub(crate) fn queue_store_pause_at(
        &mut self,
        store_contract_id: Vec<u8>,
        paused: bool,
        now_ms: u64,
    ) -> Result<(), String> {
        let store_key = self
            .work_store_key(&store_contract_id)
            .ok_or(crate::state::NO_STORE_KEY_MESSAGE)?;
        // Above anything held, asked for or sent, as a listing status is:
        // two at one revision would be settled by encoding, not by the
        // seller's last choice.
        let held = self.held_pause_revision(&store_contract_id);
        let asked = self
            .pending_signatures
            .iter()
            .filter_map(|pending| match pending {
                PendingSignature::StorePause(p) if p.store_contract_id == store_contract_id => {
                    Some(p.pause.revision)
                }
                _ => None,
            })
            .max();
        let sent = self
            .store_pause_sent
            .get(&store_contract_id)
            .map(|sent| sent.revision);
        let revision = crate::listing_status_flow::next_revision(held.max(asked).max(sent), now_ms)
            .ok_or("this store's pause is at the last revision there is")?;
        self.request_store_key_signature(
            PendingSignature::StorePause(Box::new(PendingStorePause {
                store_contract_id,
                pause: StorePause::new(store_key, revision, paused),
            })),
            store_key.to_bytes(),
        )
    }

    /// The store key signed a pause or resume: publish it.
    pub(crate) fn on_store_pause_signed(
        &mut self,
        pending: PendingStorePause,
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
    ) {
        let revision = pending.pause.revision;
        let floor = self
            .store_pause_sent
            .get(&pending.store_contract_id)
            .map_or(revision, |sent| sent.revision.max(revision));
        self.store_pause_sent.insert(
            pending.store_contract_id.clone(),
            SentStatus {
                revision: floor,
                waiting_since_ms: Some(now_ms()),
            },
        );
        let authorized = AuthorizedStorePause {
            pause: pending.pause,
            scoped_payload,
            signature,
        };
        #[cfg(target_arch = "wasm32")]
        {
            let store_id = pending.store_contract_id;
            wasm_bindgen_futures::spawn_local(async move {
                use dioxus::prelude::WritableExt;
                if let Err(e) =
                    crate::gateway::store_ops::submit_store_pause_by_id(&store_id, authorized).await
                {
                    dioxus::logger::tracing::error!("Failed to publish a store pause: {e}");
                    let mut state = crate::gateway::APP_STATE.write();
                    state.on_store_pause_publish_failed(&store_id);
                    state.notifications.push(format!("{PAUSE_NOT_SAVED} ({e})"));
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = authorized;
    }

    /// The publish failed: stop waiting, so the control is offered again.
    pub(crate) fn on_store_pause_publish_failed(&mut self, store_contract_id: &[u8]) {
        if let Some(sent) = self.store_pause_sent.get_mut(store_contract_id) {
            sent.waiting_since_ms = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{test_store_key, BrowsingStore};
    use harvest_common::StoreRegistration;

    const STORE: &[u8] = &[7u8; 32];

    fn seller_state() -> AppState {
        let mut state = AppState::default();
        state.my_stores.insert(
            "fp-seller".to_string(),
            vec![StoreRegistration {
                store_contract_id: STORE.to_vec(),
                reputation_contract_id: vec![8u8; 32],
                mailbox_contract_id: vec![9u8; 32],
                store_contract_key: None,
                store_verifying_key: Some(test_store_key()),
            }],
        );
        state
            .browsing_stores
            .insert(STORE.to_vec(), BrowsingStore::default());
        state
    }

    fn held(state: &mut AppState, revision: u64, paused: bool) {
        let owner = state.work_store_key(STORE).unwrap();
        let store = state.browsing_stores.entry(STORE.to_vec()).or_default();
        store.pause = Some(StorePause::new(owner, revision, paused));
    }

    fn queued(state: &AppState) -> Vec<StorePause> {
        state
            .pending_signatures
            .iter()
            .filter_map(|p| match p {
                PendingSignature::StorePause(p) => Some(p.pause.clone()),
                _ => None,
            })
            .collect()
    }

    /// A pause asks the store key for a revision above everything held,
    /// asked for and sent, and no lower than now; the page shows it as on
    /// its way until the state holds it. Mutated red by reusing the held
    /// revision, and by not settling on the state's echo.
    #[test]
    fn a_pause_is_signed_above_what_is_held_and_settles_on_the_echo() {
        let mut state = seller_state();
        held(&mut state, 50, false);
        state
            .queue_store_pause_at(STORE.to_vec(), true, 10)
            .unwrap();
        state
            .queue_store_pause_at(STORE.to_vec(), false, 10)
            .unwrap();
        let asked = queued(&state);
        assert_eq!(asked[0].revision, 51);
        assert!(asked[0].paused);
        assert_eq!(asked[1].revision, 52, "a second click does not reuse it");
        assert!(state.store_pause_pending_at(STORE, 0));

        let pending = match state.pending_signatures.pop_front() {
            Some(PendingSignature::StorePause(p)) => *p,
            other => panic!("{other:?}"),
        };
        state.pending_signatures.clear();
        state.on_store_pause_signed(pending, vec![1], vec![2]);
        let now = now_ms();
        assert!(
            state.store_pause_pending_at(STORE, now),
            "sent, not yet shown"
        );
        held(&mut state, 51, true);
        assert!(
            !state.store_pause_pending_at(STORE, now),
            "the state shows it"
        );
        assert!(state.store_paused(STORE));
        state
            .queue_store_pause_at(STORE.to_vec(), false, 10)
            .unwrap();
        assert_eq!(queued(&state)[0].revision, 52);
    }

    /// A closed store is closed, not paused, whatever its pause says.
    #[test]
    fn a_closed_store_is_not_paused() {
        let mut state = seller_state();
        held(&mut state, 5, true);
        assert!(state.store_paused(STORE));
        state.browsing_stores.get_mut(STORE).unwrap().closed = true;
        assert!(!state.store_paused(STORE));
    }

    /// A failed publish stops the wait at once.
    #[test]
    fn a_failed_publish_stops_waiting() {
        let mut state = seller_state();
        state
            .queue_store_pause_at(STORE.to_vec(), true, 10)
            .unwrap();
        let pending = match state.pending_signatures.pop_front() {
            Some(PendingSignature::StorePause(p)) => *p,
            other => panic!("{other:?}"),
        };
        state.on_store_pause_signed(pending, vec![1], vec![2]);
        assert!(state.store_pause_pending(STORE));
        state.on_store_pause_publish_failed(STORE);
        assert!(!state.store_pause_pending(STORE));
    }
}
