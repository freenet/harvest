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

use std::collections::BTreeMap;

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

/// A store being closed for good: whose key it is, which Ghost Key it frees,
/// and the two signed halves as they come back. Published together, once
/// both are here and both verify.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClosingStore {
    /// The store's own key, which must have signed both halves.
    pub owner: [u8; 32],
    /// The Ghost Key whose backing is being retired.
    pub backer: [u8; 32],
    /// Tells this attempt's deadline from a later attempt's.
    pub attempt: u64,
    pub retirement: Option<AuthorizedRetirement>,
    pub closure: Option<AuthorizedClosure>,
}

/// A close handed to the node, waiting for the store's state to show it.
/// Kept by store KEY: the page it was started from may name an earlier
/// generation, while the closed state arrives under the current one.
#[derive(Clone, Debug, PartialEq)]
pub struct CloseSent {
    pub backer: [u8; 32],
    pub name: String,
    /// When it was handed over (`crate::state::now_ms`).
    pub sent_ms: u64,
}

/// How long a sent close holds back another close of the same Ghost Key's
/// stores while its closed state has not arrived. The node answers an update
/// as soon as it is handed over, so a close the contract refused would
/// otherwise leave "Closing..." up, and every close button hidden, for the
/// rest of the session.
pub(crate) const CLOSE_CONFIRM_WAIT_MS: u64 = 10 * 60 * 1000;

/// Another store backed by the same Ghost Key, told apart the way a seller
/// can tell it: two stores in this state often carry the same name (a store
/// made again on a second device), so the code and what it holds are shown
/// beside the name.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SharingStore {
    /// The store's current generation where that is loaded, so a close
    /// goes to the instance buyers read.
    pub contract_id: Vec<u8>,
    pub name: String,
    pub code: String,
    pub listings: usize,
    pub orders: usize,
    /// This device holds its key and nothing blocks a close.
    pub can_close: bool,
}

/// One Ghost Key behind this store and others, as My Store shows it
/// (harvest#181).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KeyConflict {
    /// This store, described the way the others are.
    pub this: SharingStore,
    /// The other stores the same Ghost Key backs.
    pub others: Vec<SharingStore>,
    /// A store of this Ghost Key whose close is under way or sent and not
    /// yet seen, by name: while it travels, no close is offered anywhere.
    pub closing: Option<String>,
    /// A store of this Ghost Key sent to close long enough ago that it is no
    /// longer shown as under way, but whose closed state has not shown: only
    /// it may be closed (again) until it does.
    pub resend: Option<String>,
}

impl KeyConflict {
    /// The stores this device can close, this one first. Empty while a close
    /// travels.
    pub(crate) fn closable(&self) -> Vec<SharingStore> {
        if self.closing.is_some() {
            return Vec::new();
        }
        std::iter::once(&self.this)
            .chain(&self.others)
            .filter(|s| s.can_close)
            .cloned()
            .collect()
    }
}

/// Whether two store names read as the same name to a seller: what decides
/// that a close names the store by its code as well.
pub(crate) fn same_store_name(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

/// What the seller is told when a close cannot be published.
pub(crate) const CLOSE_NOT_SAVED: &str =
    "The store could not be closed. Nothing changed; try again.";

/// How long a close waits for its two signatures before giving up, so a
/// delegate that never answers cannot leave "Closing..." on screen for the
/// rest of the session.
pub(crate) const CLOSE_SIGN_TIMEOUT_MS: u32 = 60_000;

impl AppState {
    /// The OTHER stores whose current backing is the same Ghost Key as the
    /// store at `store_contract_id`: section 6.2's conflict, as the seller
    /// needs it named. Empty when there is none.
    ///
    /// Decided exactly as `refresh_backing_verdicts` decides the conflict:
    /// by store KEY, over verified backings only. `browsing_stores` can hold
    /// one store under two generation ids (the id its registration names
    /// and the current one), and comparing ids would report a store as
    /// sharing a key with itself and offer to close the seller's only store.
    pub(crate) fn stores_sharing_backer(&self, store_contract_id: &[u8]) -> Vec<SharingStore> {
        let Some(view) = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|s| s.backing.as_ref())
            .filter(|v| v.certificate_status.is_verified())
        else {
            return Vec::new();
        };
        let (owner, backer) = (view.store, view.backer);
        // One entry per other store key. An earlier generation is skipped
        // once the current one has loaded: it never receives the store's
        // later records, so after a close it would still show the retired
        // backing and keep the conflict on screen.
        let mut by_owner: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
        for (id, store) in &self.browsing_stores {
            let Some(other) = store.backing.as_ref() else {
                continue;
            };
            if other.backer != backer
                || other.store == owner
                || !other.certificate_status.is_verified()
                || self.superseded_generation(id)
            {
                continue;
            }
            by_owner.entry(other.store).or_insert_with(|| id.clone());
        }
        by_owner
            .into_iter()
            .map(|(owner, id)| self.sharing_store(id, &owner))
            .collect()
    }

    /// The conflict the store at `store_contract_id` is part of, if any.
    pub(crate) fn key_conflict(&self, store_contract_id: &[u8]) -> Option<KeyConflict> {
        let others = self.stores_sharing_backer(store_contract_id);
        if others.is_empty() {
            return None;
        }
        let view = self
            .browsing_stores
            .get(store_contract_id)?
            .backing
            .as_ref()?;
        Some(KeyConflict {
            this: self.sharing_store(store_contract_id.to_vec(), &view.store),
            closing: self.close_in_flight_for(&view.backer),
            resend: self
                .sent_close_owner(&view.backer)
                .and_then(|owner| self.closes_sent.get(&owner))
                .map(|sent| sent.name.clone()),
            others,
        })
    }

    fn sharing_store(&self, contract_id: Vec<u8>, owner: &[u8; 32]) -> SharingStore {
        let browsing = self.browsing_stores.get(&contract_id);
        SharingStore {
            name: self.store_name_of(&contract_id).label(),
            code: ed25519_dalek::VerifyingKey::from_bytes(owner)
                .map(|key| harvest_common::store::store_code(&key))
                .unwrap_or_default(),
            listings: browsing.map(|b| b.listings.len()).unwrap_or(0),
            orders: browsing
                .map(|b| {
                    b.orders
                        .iter()
                        .filter(|o| !crate::fulfilment::is_unpaid_buy_now(o))
                        .count()
                })
                .unwrap_or(0),
            can_close: self.can_close_store(&contract_id),
            contract_id,
        }
    }

    /// The name of a store whose close is under way, or sent and not yet
    /// shown in its state, among the stores `backer` backs. One close at a
    /// time per Ghost Key: the two stores' retirements are byte-identical,
    /// so two closes in flight could be answered with each other's
    /// signatures, and a seller who still saw "close the other" while the
    /// first close travelled could close both.
    pub(crate) fn close_in_flight_for(&self, backer: &[u8; 32]) -> Option<String> {
        self.closing_stores
            .iter()
            .find(|(_, closing)| closing.backer == *backer)
            .map(|(id, _)| self.close_label(id))
            .or_else(|| {
                let now = crate::state::now_ms();
                self.closes_sent
                    .iter()
                    .filter(|(owner, sent)| {
                        sent.backer == *backer
                            && now < sent.sent_ms.saturating_add(CLOSE_CONFIRM_WAIT_MS)
                            && !self.store_key_shows_closed(owner)
                    })
                    .map(|(_, sent)| sent.name.clone())
                    .next()
            })
    }

    /// The store at `store_contract_id` named as a close names it: by its
    /// name, with its code when another store the same Ghost Key backs has
    /// the same name, so "Closing ..." and a failed close say which one.
    ///
    /// Reads the backings directly rather than through
    /// [`Self::stores_sharing_backer`], whose `can_close` asks what close is
    /// in flight, which asks this.
    pub(crate) fn close_label(&self, store_contract_id: &[u8]) -> String {
        let name = self.store_name_of(store_contract_id).label();
        let Some(view) = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|s| s.backing.as_ref())
        else {
            return name;
        };
        let twin = self.browsing_stores.iter().any(|(id, other)| {
            other.backing.as_ref().is_some_and(|o| {
                o.backer == view.backer
                    && o.store != view.store
                    && o.certificate_status.is_verified()
            }) && !self.superseded_generation(id)
                && same_store_name(&self.store_name_of(id).label(), &name)
        });
        match ed25519_dalek::VerifyingKey::from_bytes(&view.store) {
            Ok(key) if twin => format!("{name} ({})", harvest_common::store::store_code(&key)),
            _ => name,
        }
    }

    /// The store key of a close sent for one of `backer`'s stores whose
    /// closed state has not shown, however long ago it was sent. Once a
    /// close has been sent, only THAT store may be closed again (a resend):
    /// the close may well have landed where this device cannot see it yet,
    /// and offering the other store then would let the seller close both.
    pub(crate) fn sent_close_owner(&self, backer: &[u8; 32]) -> Option<[u8; 32]> {
        self.closes_sent
            .iter()
            .find(|(owner, sent)| sent.backer == *backer && !self.store_key_shows_closed(owner))
            .map(|(owner, _)| *owner)
    }

    /// Whether any loaded generation of the store owned by `owner` reads
    /// closed.
    fn store_key_shows_closed(&self, owner: &[u8; 32]) -> bool {
        self.browsing_stores
            .values()
            .any(|s| s.closed && s.backing_state.owner.map(|k| k.to_bytes()) == Some(*owner))
    }

    /// Whether `store_contract_id` holds an EARLIER generation of a store
    /// whose current generation is also loaded. Such an entry is a snapshot
    /// the store has moved on from (the registration keeps subscribing the
    /// id the store was created under), so it is left out wherever a
    /// store's backing is counted.
    pub(crate) fn superseded_generation(&self, store_contract_id: &[u8]) -> bool {
        let Some(owner) = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|s| s.backing_state.owner)
        else {
            return false;
        };
        let Some(current) = current_store_id(&owner.to_bytes()) else {
            return false;
        };
        current != store_contract_id
            && self
                .browsing_stores
                .get(&current)
                .is_some_and(|s| s.backing_state.owner == Some(owner))
    }

    /// Whether this device can close the store: it holds its store key, the
    /// store is not closed already, and no close is under way for any store
    /// its Ghost Key backs.
    pub(crate) fn can_close_store(&self, store_contract_id: &[u8]) -> bool {
        let Some(store) = self.browsing_stores.get(store_contract_id) else {
            return false;
        };
        let Some(backing) = store.backing.as_ref() else {
            return false;
        };
        self.work_store_key(store_contract_id)
            .is_some_and(|key| self.holds_store_key(&key.to_bytes()))
            && !store.closed
            && self.close_in_flight_for(&backing.backer).is_none()
            && self
                .sent_close_owner(&backing.backer)
                .is_none_or(|owner| owner == backing.store)
    }

    /// Close the store at `store_contract_id` for good: ask its store key to
    /// sign the retirement of its current backer and the closure.
    pub(crate) fn close_store_for_good(&mut self, store_contract_id: &[u8]) -> Result<(), String> {
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
        if let Some(name) = self.close_in_flight_for(&backer) {
            return Err(format!(
                "{name} is already being closed; wait for it to finish"
            ));
        }
        if self
            .sent_close_owner(&backer)
            .is_some_and(|owner| owner != store_key.to_bytes())
        {
            return Err(
                "another of this Ghost Key's stores was already sent to close; send that \
                        one again, or wait for it to show as closed"
                    .into(),
            );
        }
        let backer_key = ed25519_dalek::VerifyingKey::from_bytes(&backer)
            .map_err(|_| "this store's backing names no valid key".to_string())?;
        let owner = store_key;
        let attempt = self.next_messaging_request_id();
        self.closing_stores.insert(
            store_contract_id.to_vec(),
            ClosingStore {
                owner: owner.to_bytes(),
                backer,
                attempt,
                retirement: None,
                closure: None,
            },
        );
        let signed = self
            .request_store_key_signature(
                PendingSignature::Retirement(Box::new(PendingRetirement {
                    store_contract_id: store_contract_id.to_vec(),
                    retirement: Retirement { backer: backer_key },
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
            return signed;
        }
        #[cfg(target_arch = "wasm32")]
        {
            let id = store_contract_id.to_vec();
            wasm_bindgen_futures::spawn_local(async move {
                gloo_timers::future::TimeoutFuture::new(CLOSE_SIGN_TIMEOUT_MS).await;
                use dioxus::prelude::WritableExt;
                crate::gateway::APP_STATE
                    .write()
                    .on_close_deadline(&id, attempt);
            });
        }
        Ok(())
    }

    /// The close of `store_contract_id` started as `attempt` has had its
    /// time: if its signatures are still not both back, stop it and say so.
    pub(crate) fn on_close_deadline(&mut self, store_contract_id: &[u8], attempt: u64) {
        if self
            .closing_stores
            .get(store_contract_id)
            .is_some_and(|c| c.attempt == attempt)
        {
            let label = self.close_label(store_contract_id);
            self.abandon_close(store_contract_id);
            self.notifications.push(format!(
                "{CLOSE_NOT_SAVED} ({label}: the store key did not answer)"
            ));
        }
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
    ///
    /// Both are verified against the store's key first. The contract drops
    /// a record that does not verify without an error, and the node answers
    /// an update as soon as it is handed over, so a bad signature published
    /// here would be told to the seller as a close that never happened.
    fn publish_close_if_ready(&mut self, store_contract_id: &[u8]) {
        let Some(ClosingStore {
            owner,
            backer,
            retirement: Some(retirement),
            closure: Some(closure),
            ..
        }) = self.closing_stores.get(store_contract_id).cloned()
        else {
            return;
        };
        let verified = ed25519_dalek::VerifyingKey::from_bytes(&owner)
            .ok()
            .is_some_and(|owner| {
                retirement.verify(&owner).is_ok() && closure.verify(&owner).is_ok()
            });
        let name = self.close_label(store_contract_id);
        if !verified {
            self.abandon_close(store_contract_id);
            self.notifications.push(format!(
                "{CLOSE_NOT_SAVED} ({name}: the store key's signature did not check out)"
            ));
            return;
        }
        #[cfg(target_arch = "wasm32")]
        let label = name.clone();
        self.abandon_close(store_contract_id);
        // Held until the store's state shows it closed: until then the
        // conflict is still on screen, and a second close must not start.
        self.closes_sent.insert(
            owner,
            CloseSent {
                backer,
                name,
                sent_ms: crate::state::now_ms(),
            },
        );
        #[cfg(target_arch = "wasm32")]
        {
            let store_id = store_contract_id.to_vec();
            wasm_bindgen_futures::spawn_local(async move {
                use dioxus::prelude::WritableExt;
                let result =
                    crate::gateway::store_ops::submit_close_by_id(&store_id, retirement, closure)
                        .await;
                // No notice on success: the card's "Closing..." line says it
                // while it travels, and the page says "closed for good" once
                // it lands. A notice would outlive both and sit beside a
                // store already shown closed.
                if let Err(e) = result {
                    let mut state = crate::gateway::APP_STATE.write();
                    state.closes_sent.remove(&owner);
                    dioxus::logger::tracing::error!("Failed to close a store: {e}");
                    state
                        .notifications
                        .push(format!("{CLOSE_NOT_SAVED} ({label}: {e})"));
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        self.closes_ready
            .push((store_contract_id.to_vec(), retirement, closure));
    }

    /// Forget a close in progress: published, failed, refused or timed out.
    /// Withdraws both halves, and the requests they went out under, so a
    /// late answer to either cannot be matched to a later attempt.
    pub(crate) fn abandon_close(&mut self, store_contract_id: &[u8]) {
        self.closing_stores.remove(store_contract_id);
        let ours = |pending: &PendingSignature| {
            matches!(pending,
                PendingSignature::Retirement(p) if p.store_contract_id == store_contract_id)
                || matches!(pending,
                PendingSignature::Closure(p) if p.store_contract_id == store_contract_id)
        };
        let withdrawn: Vec<Vec<u8>> = self
            .pending_signatures
            .iter()
            .filter(|p| ours(p))
            .filter_map(|p| p.signed_bytes().ok())
            .collect();
        self.pending_signatures.retain(|p| !ours(p));
        self.pending_store_key_requests
            .retain(|_, bytes| !withdrawn.contains(bytes));
    }
}

/// The id of the current generation of the store owned by `owner`.
fn current_store_id(owner: &[u8; 32]) -> Option<Vec<u8>> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(owner).ok()?;
    crate::gateway::store_ops::store_instance_id(&crate::migrate::store_params(&key))
        .ok()
        .map(|id| id.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backing_flow::tests::{load_backed, sign, signed_backing, signed_backing_with_cert};
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
        state
            .my_stores
            .insert("fp".into(), vec![registration(2, CLOSED)]);
        state
    }

    fn registration(id: u8, seed: u8) -> harvest_common::StoreRegistration {
        harvest_common::StoreRegistration {
            store_contract_id: vec![id; 32],
            reputation_contract_id: Vec::new(),
            mailbox_contract_id: Vec::new(),
            store_contract_key: None,
            store_verifying_key: Some(store_key(seed).verifying_key().to_bytes()),
        }
    }

    /// The same, with both stores' keys on this device.
    fn both_ours() -> AppState {
        let mut state = two_stores_one_key();
        state
            .my_stores
            .get_mut("fp")
            .unwrap()
            .push(registration(1, KEPT));
        state
    }

    fn answer<T: serde::Serialize>(state: &mut AppState, record: &T) {
        answer_as(state, CLOSED, CLOSED, record);
    }

    /// An answer naming the store key `named`, signed by `signer`.
    fn answer_as<T: serde::Serialize>(state: &mut AppState, named: u8, signer: u8, record: &T) {
        let (scoped_payload, signature) = sign(&store_key(signer), record);
        state.on_delegate_response(HarvestDelegateResponse::StoreUpdateSigned {
            request_id: 0,
            store_verifying_key: store_key(named).verifying_key().to_bytes(),
            result: Ok(StoreKeySignature {
                scoped_payload,
                signature,
            }),
        });
    }

    fn backer() -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[BACKER; 32]).verifying_key()
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
        assert!(
            state.pending_store_key_requests.is_empty(),
            "the other half's request is withdrawn too"
        );
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

    /// Refusing the closure half (the second request) stops the close the
    /// same way, including after the retirement half was already signed.
    /// Mutated red by abandoning only on a refused retirement.
    #[test]
    fn a_refused_closure_stops_the_close_after_the_retirement_was_signed() {
        let mut state = two_stores_one_key();
        state.close_store_for_good(&[2; 32]).expect("asked");
        let (first, second) = {
            let mut ids = state.pending_store_key_requests.keys().copied();
            (ids.next().unwrap(), ids.next().unwrap())
        };
        // The retirement is answered by its own request.
        state.pending_store_key_requests.remove(&first);
        answer(&mut state, &Retirement { backer: backer() });
        assert!(state.closing_stores[&vec![2; 32]].retirement.is_some());
        state.store_key_signature_failed(second, "the delegate said no");
        assert!(state.closing_stores.is_empty());
        assert!(state.pending_store_key_requests.is_empty());
        assert!(state.closes_ready.is_empty());
        assert!(state.can_close_store(&[2; 32]));
    }

    /// harvest#181 review: one store can sit in `browsing_stores` under two
    /// generation ids, the id its registration names and the current one.
    /// That is one store, not two, and the seller must never be offered to
    /// close it as "the other store". Mutated red by comparing ids instead
    /// of store keys.
    #[test]
    fn one_store_under_two_generation_ids_is_not_two_stores() {
        let mut state = AppState::default();
        load_backed(&mut state, 1, KEPT, vec![signed_backing(KEPT, BACKER, 10)]);
        let copy = state.browsing_stores[&vec![1; 32]].clone();
        state.browsing_stores.insert(vec![3; 32], copy);
        state.refresh_backing_verdicts();
        assert!(state.browsing_stores[&vec![1; 32]]
            .certificate_status
            .is_verified());
        assert!(state.stores_sharing_backer(&[1; 32]).is_empty());
        assert!(state.key_conflict(&[3; 32]).is_none());
    }

    /// A real second store seen under two generation ids is named once,
    /// by its CURRENT id, so a close goes where buyers read. Mutated red by
    /// keeping whichever id came first.
    #[test]
    fn another_store_is_named_once_by_its_current_id() {
        let current = current_store_id(&store_key(CLOSED).verifying_key().to_bytes()).unwrap();
        // `browsing_stores` is a HashMap with a fresh order per instance, so
        // both orders are met over these rounds.
        for _ in 0..16 {
            let mut state = two_stores_one_key();
            let copy = state.browsing_stores[&vec![2; 32]].clone();
            state.browsing_stores.insert(current.clone(), copy);
            state.refresh_backing_verdicts();
            let others = state.stores_sharing_backer(&[1; 32]);
            assert_eq!(others.len(), 1, "{others:?}");
            assert_eq!(others[0].contract_id, current);
            assert_eq!(
                others[0].code,
                harvest_common::store::store_code(&store_key(CLOSED).verifying_key())
            );
        }
    }

    /// Backings whose certificate does not verify do not count, here as in
    /// `refresh_backing_verdicts`: no conflict is claimed, and no permanent
    /// close is invited, over backings buyers ignore anyway (the store page
    /// says the store is unbacked instead). Mutated red by dropping the
    /// verified filter.
    #[test]
    fn an_unverified_backing_is_no_conflict() {
        let mut state = two_stores_one_key();
        let other = signed_backing(CLOSED, BACKER, 11);
        state.certificate_verdicts.borrow_mut().insert(
            (other.statement.certificate_pem.clone(), BACKER_VK()),
            crate::ghostkey_cert::CertificateStatus::Invalid("not this key".into()),
        );
        state.refresh_backing_verdicts();
        assert!(state.stores_sharing_backer(&[1; 32]).is_empty());
        assert!(state.key_conflict(&[1; 32]).is_none());
        assert!(state.key_conflict(&[2; 32]).is_none());
    }

    #[allow(non_snake_case)]
    fn BACKER_VK() -> [u8; 32] {
        backer().to_bytes()
    }

    /// One close at a time per Ghost Key, from the first request until the
    /// closed store's state shows it: no second close is offered or
    /// accepted meanwhile, so the seller cannot close both stores, and two
    /// byte-identical retirements are never in flight together. Mutated red
    /// by dropping the in-flight check from `can_close_store`, from
    /// `close_store_for_good`, and by forgetting a close once it is sent.
    #[test]
    fn one_close_at_a_time_per_ghost_key() {
        let mut state = both_ours();
        assert!(state.can_close_store(&[1; 32]) && state.can_close_store(&[2; 32]));
        let conflict = state.key_conflict(&[2; 32]).expect("a conflict");
        let order: Vec<Vec<u8>> = conflict
            .closable()
            .into_iter()
            .map(|s| s.contract_id)
            .collect();
        assert_eq!(order, vec![vec![2; 32], vec![1; 32]], "this store first");

        state.close_store_for_good(&[2; 32]).expect("asked");
        assert!(!state.can_close_store(&[1; 32]));
        let refused = state.close_store_for_good(&[1; 32]).unwrap_err();
        assert!(refused.contains("already being closed"), "{refused}");
        let conflict = state.key_conflict(&[1; 32]).expect("still shown");
        assert!(conflict.closing.is_some());
        assert!(conflict.closable().is_empty());

        answer(&mut state, &Retirement { backer: backer() });
        answer(
            &mut state,
            &StoreClosure {
                store: store_key(CLOSED).verifying_key(),
            },
        );
        assert_eq!(state.closes_ready.len(), 1);
        assert!(state.closing_stores.is_empty());
        assert!(
            !state.can_close_store(&[1; 32]),
            "sent, not yet seen: still one at a time"
        );
        assert!(state.key_conflict(&[1; 32]).unwrap().closing.is_some());

        state.browsing_stores.get_mut(&vec![2; 32]).unwrap().closed = true;
        assert!(state.close_in_flight_for(&BACKER_VK()).is_none());
        assert!(state.can_close_store(&[1; 32]));
    }

    /// A close whose signatures never both come back is given up at its
    /// deadline, and only that attempt's deadline counts. Mutated red by a
    /// no-op deadline and by ignoring the attempt.
    #[test]
    fn a_close_the_store_key_never_answers_is_given_up() {
        let mut state = two_stores_one_key();
        state.close_store_for_good(&[2; 32]).expect("asked");
        let attempt = state.closing_stores[&vec![2; 32]].attempt;
        state.on_close_deadline(&[2; 32], attempt + 1);
        assert!(
            !state.closing_stores.is_empty(),
            "another attempt's deadline"
        );
        state.on_close_deadline(&[2; 32], attempt);
        assert!(state.closing_stores.is_empty());
        assert!(state.pending_store_key_requests.is_empty());
        assert!(state
            .notifications
            .iter()
            .any(|n| n.starts_with(CLOSE_NOT_SAVED)));
        assert!(state.can_close_store(&[2; 32]));
    }

    /// Halves that do not verify under the store's key are not published:
    /// the contract would drop them silently and the seller would be told
    /// of a close that never happened. Mutated red by skipping the verify.
    #[test]
    fn a_close_signed_by_the_wrong_key_is_not_published() {
        let mut state = two_stores_one_key();
        state.close_store_for_good(&[2; 32]).expect("asked");
        answer_as(&mut state, CLOSED, KEPT, &Retirement { backer: backer() });
        answer_as(
            &mut state,
            CLOSED,
            KEPT,
            &StoreClosure {
                store: store_key(CLOSED).verifying_key(),
            },
        );
        assert!(state.closes_ready.is_empty());
        assert!(state.closes_sent.is_empty());
        assert!(state.closing_stores.is_empty());
        assert!(state
            .notifications
            .iter()
            .any(|n| n.starts_with(CLOSE_NOT_SAVED)));
    }

    /// Every refusal before anything is signed leaves nothing behind.
    #[test]
    fn a_close_that_cannot_start_leaves_nothing_behind() {
        let mut state = two_stores_one_key();
        assert!(state.close_store_for_good(&[9; 32]).is_err(), "not loaded");
        assert!(state.close_store_for_good(&[1; 32]).is_err(), "not ours");
        state.browsing_stores.get_mut(&vec![2; 32]).unwrap().closed = true;
        assert!(
            state.close_store_for_good(&[2; 32]).is_err(),
            "closed already"
        );
        assert!(state.closing_stores.is_empty());
        assert!(state.pending_store_key_requests.is_empty());
        assert!(state.pending_signatures.is_empty());
    }

    /// The update a close publishes, applied by the store contract's own
    /// rules: both halves land together, the store reads closed and its
    /// backer is retired. Mutated red by leaving either half out of
    /// `close_delta`.
    #[test]
    fn the_close_update_applies_both_halves() {
        use freenet_scaffold::ComposableState;
        let state = two_stores_one_key();
        let before = state.browsing_stores[&vec![2; 32]].backing_state.clone();
        assert!(!harvest_common::backing::is_closed(&before));
        assert!(before.retirements.records.is_empty());
        let owner = store_key(CLOSED).verifying_key();
        let (scoped_payload, signature) =
            sign(&store_key(CLOSED), &Retirement { backer: backer() });
        let retirement = AuthorizedRetirement {
            retirement: Retirement { backer: backer() },
            scoped_payload,
            signature,
        };
        let (scoped_payload, signature) = sign(&store_key(CLOSED), &StoreClosure { store: owner });
        let closure = AuthorizedClosure {
            closure: StoreClosure { store: owner },
            scoped_payload,
            signature,
        };
        let params = crate::migrate::store_params(&owner);
        let mut after = before.clone();
        after
            .apply_delta(
                &before,
                &params,
                &Some(crate::gateway::store_ops::close_delta(
                    owner, retirement, closure,
                )),
            )
            .expect("applies");
        after.verify(&after, &params).expect("verifies");
        assert!(harvest_common::backing::is_closed(&after));
        assert!(after
            .retirements
            .records
            .contains_key(&harvest_common::store::Bytes32(backer().to_bytes())));
    }

    /// One verified backing and one that is not, by its own certificate:
    /// neither side calls it a conflict. Mutated red by dropping either the
    /// filter on this store or the one on the others.
    #[test]
    fn a_conflict_needs_both_backings_verified() {
        let mut state = AppState::default();
        load_backed(&mut state, 1, KEPT, vec![signed_backing(KEPT, BACKER, 10)]);
        let other = signed_backing_with_cert(CLOSED, BACKER, 11, "CERT-OTHER".into());
        load_backed(&mut state, 2, CLOSED, vec![other]);
        state.certificate_verdicts.borrow_mut().insert(
            ("CERT-OTHER".into(), BACKER_VK()),
            crate::ghostkey_cert::CertificateStatus::Invalid("not this key".into()),
        );
        state.refresh_backing_verdicts();
        assert!(
            state.stores_sharing_backer(&[1; 32]).is_empty(),
            "the other is unverified"
        );
        assert!(
            state.stores_sharing_backer(&[2; 32]).is_empty(),
            "this one is unverified"
        );
    }

    /// harvest#181 review round 2: the closed store also sits under an
    /// earlier generation id, which never receives the close. Once the
    /// current generation has it, the kept store counts again on this
    /// device and no conflict is shown, and the sent close is seen as
    /// landed although it was started from the earlier id. Mutated red by
    /// counting superseded generations in either `refresh_backing_verdicts`
    /// or `stores_sharing_backer`, and by keying the sent close by id.
    #[test]
    fn a_close_that_lands_on_the_current_generation_clears_the_conflict() {
        let mut state = both_ours();
        let current = current_store_id(&store_key(CLOSED).verifying_key().to_bytes()).unwrap();
        let copy = state.browsing_stores[&vec![2; 32]].clone();
        state.browsing_stores.insert(current.clone(), copy);
        state.refresh_backing_verdicts();
        assert!(state.superseded_generation(&[2; 32]));
        assert!(!state.superseded_generation(&current));

        // Started from the earlier id, as a page may be.
        state.close_store_for_good(&[2; 32]).expect("asked");
        answer(&mut state, &Retirement { backer: backer() });
        answer(
            &mut state,
            &StoreClosure {
                store: store_key(CLOSED).verifying_key(),
            },
        );
        let (_, retirement, _) = state.closes_ready.pop().expect("published");
        assert!(state.close_in_flight_for(&BACKER_VK()).is_some());

        // The close lands on the current generation only.
        let landed = state.browsing_stores.get_mut(&current).unwrap();
        landed.closed = true;
        landed
            .backing_state
            .retirements
            .records
            .insert(harvest_common::store::Bytes32(BACKER_VK()), retirement);
        state.refresh_backing_verdicts();
        assert!(state.close_in_flight_for(&BACKER_VK()).is_none());
        assert!(state.stores_sharing_backer(&[1; 32]).is_empty());
        assert!(state.key_conflict(&[1; 32]).is_none());
        assert!(state.browsing_stores[&vec![1; 32]]
            .certificate_status
            .is_verified());
    }

    /// Two stores on one Ghost Key with the same name: what says a close is
    /// under way, and what is kept for a resend, names the store by code as
    /// well, so the seller can tell which one went. A distinct name needs
    /// none. Mutated red by naming by name alone.
    #[test]
    fn a_close_of_one_of_two_same_named_stores_names_it_by_code() {
        fn name(state: &mut AppState, id: u8, store_name: &str) {
            state.browsing_stores.get_mut(&vec![id; 32]).unwrap().info =
                Some(harvest_common::store::StoreInfoV1 {
                    version: 1,
                    certificate_pem: String::new(),
                    seller_fingerprint: String::new(),
                    reputation_contract_id: [0; 32],
                    store_name: store_name.to_string(),
                    description: String::new(),
                    encryption_public_key: None,
                    record_public_key: None,
                });
        }
        let code = harvest_common::store::store_code(&store_key(CLOSED).verifying_key());
        let mut state = both_ours();
        name(&mut state, 1, "Bean Shop");
        name(&mut state, 2, "bean shop ");
        assert_eq!(state.close_label(&[2; 32]), format!("bean shop ({code})"));
        state.close_store_for_good(&[2; 32]).expect("asked");
        assert_eq!(
            state.close_in_flight_for(&BACKER_VK()),
            Some(format!("bean shop ({code})"))
        );
        answer(&mut state, &Retirement { backer: backer() });
        answer(
            &mut state,
            &StoreClosure {
                store: store_key(CLOSED).verifying_key(),
            },
        );
        assert_eq!(
            state.closes_sent[&store_key(CLOSED).verifying_key().to_bytes()].name,
            format!("bean shop ({code})"),
            "what a resend names"
        );

        // A close the store key never answers says which store failed.
        let mut state = both_ours();
        name(&mut state, 1, "Bean Shop");
        name(&mut state, 2, "Bean Shop");
        state.close_store_for_good(&[2; 32]).expect("asked");
        let attempt = state.closing_stores[&vec![2; 32]].attempt;
        state.on_close_deadline(&[2; 32], attempt);
        assert!(
            state
                .notifications
                .iter()
                .any(|n| n.starts_with(CLOSE_NOT_SAVED)
                    && n.contains(&format!("Bean Shop ({code})"))),
            "{:?}",
            state.notifications
        );

        let mut state = both_ours();
        name(&mut state, 1, "Bean Shop");
        name(&mut state, 2, "Tea Shop");
        assert_eq!(state.close_label(&[2; 32]), "Tea Shop");
    }

    /// A sent close whose closed state never arrives (the contract refused
    /// it, or this device has not seen it) stops showing as under way after
    /// a while, but only THAT store may then be closed again: the close may
    /// have landed out of sight, and offering the other store would let the
    /// seller close both. Mutated red by dropping the expiry, and by
    /// offering the other store after it.
    #[test]
    fn a_sent_close_that_never_shows_stops_blocking() {
        let mut state = both_ours();
        state.closes_sent.insert(
            store_key(CLOSED).verifying_key().to_bytes(),
            CloseSent {
                backer: BACKER_VK(),
                name: "Bean Shop".into(),
                sent_ms: crate::state::now_ms(),
            },
        );
        assert!(!state.can_close_store(&[1; 32]));
        assert!(!state.can_close_store(&[2; 32]));
        state
            .closes_sent
            .values_mut()
            .for_each(|sent| sent.sent_ms = 0);
        assert!(state.close_in_flight_for(&BACKER_VK()).is_none());
        assert_eq!(
            state.key_conflict(&[1; 32]).unwrap().resend.as_deref(),
            Some("Bean Shop"),
            "the page says why only that store is offered"
        );
        assert!(state.can_close_store(&[2; 32]), "the same store, again");
        assert!(!state.can_close_store(&[1; 32]), "never the other one");
        assert!(state.close_store_for_good(&[1; 32]).is_err());
    }
}
