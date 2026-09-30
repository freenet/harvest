//! One Ghost Key behind two stores, and the way out: closing one of them for
//! good (harvest#181).
//!
//! # Why a seller can end up here
//!
//! A Ghost Key backs one store at a time (`docs/design/entity-model.md`,
//! section 6.2): a key found backing two stores counts for NEITHER, in every
//! reader, until one of the backings is retired. My Store now waits for the
//! key's index before offering "Create a store" (`index_flow::
//! CreationGate`), and there is no "open a second store anyway" any more, so
//! a seller should not get here by this build. They still can: an index that
//! never answered in time, a store made on a device that could not publish
//! its index entry, or a build from before this one.
//!
//! # Why the way out is closing, not retiring alone
//!
//! Retiring a backing is permanent: the retired key can never back that store
//! again, and nothing in the app can attach another key's backing to an
//! existing store (harvest#104), so a store whose only backing is retired is
//! dead for good. A retire control that did not say so was built once and
//! removed (harvest#104). So this is offered as what it is, "close this store
//! for good", confirmed, and it signs BOTH records with the store key in one
//! update: the retirement, which takes the store out of the Ghost Key's
//! count so the other store works again, and the closure, the one-way flag
//! that makes buyers' apps refuse to pay it and the seller's delegate stop
//! invoicing for it. Moving a store to another Ghost Key instead, which keeps
//! it alive, is harvest#104 and is not built.

use harvest_common::backing::{AuthorizedClosure, AuthorizedRetirement, Retirement, StoreClosure};

use crate::state::{AppState, PendingSignature};

/// A retirement of a store's backer, for the store key.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingRetirement {
    pub store_contract_id: Vec<u8>,
    pub retirement: Retirement,
}

/// A store's closure, for the store key.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingClosure {
    pub store_contract_id: Vec<u8>,
    pub closure: StoreClosure,
}

/// A store being closed for good: the two signed halves as they come back.
/// Published together, once both are here.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClosingStore {
    pub retirement: Option<AuthorizedRetirement>,
    pub closure: Option<AuthorizedClosure>,
}

/// What the seller is told when a close cannot be published.
pub(crate) const CLOSE_NOT_SAVED: &str =
    "The store could not be closed. Nothing changed; try again.";

impl AppState {
    /// The OTHER loaded stores whose current backing is the same Ghost Key as
    /// the store at `store_contract_id`, by id and name: section 6.2's
    /// conflict, as the seller needs it named. Empty when there is none.
    pub(crate) fn stores_sharing_backer(&self, store_contract_id: &[u8]) -> Vec<(Vec<u8>, String)> {
        let Some(backer) = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|s| s.backing.as_ref())
            .map(|b| b.backer)
        else {
            return Vec::new();
        };
        let mut others: Vec<(Vec<u8>, String)> = self
            .browsing_stores
            .iter()
            .filter(|(id, _)| id.as_slice() != store_contract_id)
            .filter(|(_, store)| store.backing.as_ref().is_some_and(|b| b.backer == backer))
            .map(|(id, _)| (id.clone(), self.store_name_of(id).label()))
            .collect();
        others.sort();
        others
    }

    /// Whether this device can close the store: it holds its store key, the
    /// store is not closed already, and no close is under way.
    pub(crate) fn can_close_store(&self, store_contract_id: &[u8]) -> bool {
        self.work_store_key(store_contract_id)
            .is_some_and(|key| self.holds_store_key(&key.to_bytes()))
            && !self
                .browsing_stores
                .get(store_contract_id)
                .is_some_and(|s| s.closed)
            && !self.closing_stores.contains_key(store_contract_id)
    }

    /// Close the store at `store_contract_id` for good: ask its store key to
    /// sign the retirement of its current backer and the closure.
    pub(crate) fn close_store_for_good(&mut self, store_contract_id: &[u8]) -> Result<(), String> {
        if self.closing_stores.contains_key(store_contract_id) {
            return Err("this store is already being closed".into());
        }
        let store_key = self
            .work_store_key(store_contract_id)
            .ok_or(crate::state::NO_STORE_KEY_MESSAGE)?;
        let store = self
            .browsing_stores
            .get(store_contract_id)
            .ok_or("this store has not loaded yet")?;
        if store.closed {
            return Err("this store is already closed".into());
        }
        let backer = store
            .backing
            .as_ref()
            .ok_or("this store has no current backing to take off")?
            .backer;
        let backer = ed25519_dalek::VerifyingKey::from_bytes(&backer)
            .map_err(|_| "this store's backing names no valid key".to_string())?;
        let owner = store_key;
        self.closing_stores
            .insert(store_contract_id.to_vec(), ClosingStore::default());
        let signed = self
            .request_store_key_signature(
                PendingSignature::Retirement(Box::new(PendingRetirement {
                    store_contract_id: store_contract_id.to_vec(),
                    retirement: Retirement { backer },
                })),
                owner.to_bytes(),
            )
            .and_then(|_| {
                self.request_store_key_signature(
                    PendingSignature::Closure(Box::new(PendingClosure {
                        store_contract_id: store_contract_id.to_vec(),
                        closure: StoreClosure { store: owner },
                    })),
                    owner.to_bytes(),
                )
            });
        if signed.is_err() {
            self.abandon_close(store_contract_id);
        }
        signed
    }

    /// The store key signed a store's retirement.
    pub(crate) fn on_retirement_signed(
        &mut self,
        pending: PendingRetirement,
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
    ) {
        let Some(closing) = self.closing_stores.get_mut(&pending.store_contract_id) else {
            return;
        };
        closing.retirement = Some(AuthorizedRetirement {
            retirement: pending.retirement,
            scoped_payload,
            signature,
        });
        self.publish_close_if_ready(&pending.store_contract_id);
    }

    /// The store key signed a store's closure.
    pub(crate) fn on_closure_signed(
        &mut self,
        pending: PendingClosure,
        scoped_payload: Vec<u8>,
        signature: Vec<u8>,
    ) {
        let Some(closing) = self.closing_stores.get_mut(&pending.store_contract_id) else {
            return;
        };
        closing.closure = Some(AuthorizedClosure {
            closure: pending.closure,
            scoped_payload,
            signature,
        });
        self.publish_close_if_ready(&pending.store_contract_id);
    }

    /// Publish both halves in one update once both are signed. Never one
    /// alone: a retirement without the closure leaves a dead store that its
    /// delegate may still invoice for, and a closure without the retirement
    /// leaves the Ghost Key counted at a closed store.
    fn publish_close_if_ready(&mut self, store_contract_id: &[u8]) {
        let Some(ClosingStore {
            retirement: Some(retirement),
            closure: Some(closure),
        }) = self.closing_stores.get(store_contract_id).cloned()
        else {
            return;
        };
        #[cfg(target_arch = "wasm32")]
        {
            let store_id = store_contract_id.to_vec();
            wasm_bindgen_futures::spawn_local(async move {
                use dioxus::prelude::WritableExt;
                let result =
                    crate::gateway::store_ops::submit_close_by_id(&store_id, retirement, closure)
                        .await;
                let mut state = crate::gateway::APP_STATE.write();
                state.abandon_close(&store_id);
                match result {
                    Ok(()) => state.notifications.push(
                        "The store is closed for good. Buyers can\u{2019}t buy from it any more, \
                         and your Ghost Key now counts for your other store."
                            .to_string(),
                    ),
                    Err(e) => {
                        dioxus::logger::tracing::error!("Failed to close a store: {e}");
                        state.notifications.push(format!("{CLOSE_NOT_SAVED} ({e})"));
                    }
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        self.closes_ready
            .push((store_contract_id.to_vec(), retirement, closure));
    }

    /// Forget a close: published, failed, or refused.
    pub(crate) fn abandon_close(&mut self, store_contract_id: &[u8]) {
        self.closing_stores.remove(store_contract_id);
        self.pending_signatures.retain(|pending| {
            !matches!(pending,
                PendingSignature::Retirement(p) if p.store_contract_id == store_contract_id)
                && !matches!(pending,
                PendingSignature::Closure(p) if p.store_contract_id == store_contract_id)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backing_flow::tests::{load_backed, sign, signed_backing};
    use ed25519_dalek::SigningKey;
    use harvest_common::delegate::{HarvestDelegateResponse, StoreKeySignature};

    const BACKER: u8 = 0x41;
    const KEPT: u8 = 0x51;
    const CLOSED: u8 = 0x52;

    fn store_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// One Ghost Key backing two loaded stores, the second of them ours.
    fn two_stores_one_key() -> AppState {
        let mut state = AppState::default();
        load_backed(&mut state, 1, KEPT, vec![signed_backing(KEPT, BACKER, 10)]);
        load_backed(
            &mut state,
            2,
            CLOSED,
            vec![signed_backing(CLOSED, BACKER, 11)],
        );
        state.my_stores.insert(
            "fp".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: vec![2; 32],
                reputation_contract_id: Vec::new(),
                mailbox_contract_id: Vec::new(),
                store_contract_key: None,
                store_verifying_key: Some(store_key(CLOSED).verifying_key().to_bytes()),
            }],
        );
        state
    }

    fn answer<T: serde::Serialize>(state: &mut AppState, record: &T) {
        let (scoped_payload, signature) = sign(&store_key(CLOSED), record);
        state.on_delegate_response(HarvestDelegateResponse::StoreUpdateSigned {
            request_id: 0,
            store_verifying_key: store_key(CLOSED).verifying_key().to_bytes(),
            result: Ok(StoreKeySignature {
                scoped_payload,
                signature,
            }),
        });
    }

    /// harvest#181: the conflict is named, and closing the store signs the
    /// retirement of ITS backer and its closure with its store key,
    /// publishing both together only once both are signed. With the
    /// retirement in the store's state, the Ghost Key counts again for the
    /// store that was kept. Mutated red by publishing on the first half, by
    /// retiring some other key, and by leaving the closure out.
    #[test]
    fn closing_one_of_two_stores_frees_the_ghost_key_for_the_other() {
        let mut state = two_stores_one_key();
        assert_eq!(state.stores_sharing_backer(&[2; 32]).len(), 1);
        assert!(!state.browsing_stores[&vec![1; 32]]
            .certificate_status
            .is_verified());
        assert!(state.can_close_store(&[2; 32]));
        assert!(!state.can_close_store(&[1; 32]), "not ours");

        state.close_store_for_good(&[2; 32]).expect("asked");
        assert!(!state.can_close_store(&[2; 32]), "under way");
        assert!(state.close_store_for_good(&[2; 32]).is_err(), "once");
        let backer = SigningKey::from_bytes(&[BACKER; 32]).verifying_key();
        let owner = store_key(CLOSED).verifying_key();
        answer(&mut state, &Retirement { backer });
        assert!(state.closes_ready.is_empty(), "not on one half");
        answer(&mut state, &StoreClosure { store: owner });
        let (id, retirement, closure) = state.closes_ready.pop().expect("published");
        assert_eq!(id, vec![2; 32]);
        assert_eq!(retirement.retirement.backer, backer);
        retirement.verify(&owner).expect("signed by the store key");
        closure.verify(&owner).expect("signed by the store key");

        // The update lands: the kept store's Ghost Key counts again.
        let closed = state.browsing_stores.get_mut(&vec![2; 32]).unwrap();
        closed.backing_state.retirements.records.insert(
            harvest_common::store::Bytes32(backer.to_bytes()),
            retirement,
        );
        state.refresh_backing_verdicts();
        assert!(state.browsing_stores[&vec![1; 32]]
            .certificate_status
            .is_verified());
        assert!(state.stores_sharing_backer(&[1; 32]).is_empty());
    }

    /// A refused half stops the close: nothing is published, the other half
    /// is withdrawn, the seller is told, and it can be tried again. Mutated
    /// red by not abandoning on a refusal.
    #[test]
    fn a_refused_half_stops_the_close() {
        let mut state = two_stores_one_key();
        state.close_store_for_good(&[2; 32]).expect("asked");
        let first = *state
            .pending_store_key_requests
            .keys()
            .min()
            .expect("two requests");
        state.store_key_signature_failed(first, "the delegate said no");
        assert!(state.closing_stores.is_empty());
        assert!(!state.pending_signatures.iter().any(|p| matches!(
            p,
            PendingSignature::Retirement(_) | PendingSignature::Closure(_)
        )));
        answer(
            &mut state,
            &StoreClosure {
                store: store_key(CLOSED).verifying_key(),
            },
        );
        assert!(state.closes_ready.is_empty());
        assert!(state
            .notifications
            .iter()
            .any(|n| n.starts_with(CLOSE_NOT_SAVED)));
        assert!(state.can_close_store(&[2; 32]), "can be tried again");
    }
}
