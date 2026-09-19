//! Keeping a store's key recoverable from its backing Ghost Key, and
//! recovering it on a device that has lost it (harvest#93, phase 1b).
//!
//! # What this does
//!
//! Whenever a store's state arrives, [`AppState::start_custody_for`] decides
//! one of three things, from the state alone and the Ghost Keys connected to
//! this tab:
//!
//! * **Wrap.** The store is ours (registered, with its store key), its current
//!   backing is a connected Ghost Key, and the store holds no wrapped copy for
//!   that key under Harvest's current webapp scope. The UI asks the vault for
//!   the Ghost Key's signature over `custody::wrap_message(store)`, hands it
//!   to the Harvest delegate (`WrapStoreKeyFor`), which wraps the store key
//!   and signs the copy, and publishes the copy. This covers a new store, a
//!   store whose backing changed, and a change of webapp scope.
//! * **Recover.** The store is NOT registered here with a store key, its
//!   current backing is a connected Ghost Key, and it holds a copy for that
//!   key under the current scope: this device lost the key (a delegate
//!   re-key, which does not carry secrets across) or never had it (a second
//!   device). The same vault signature goes to `UnwrapStoreKey`, which opens
//!   the copy, checks the seed IS this store's key, and keeps it; the store
//!   is then registered again, so it reappears in My Store.
//! * Nothing, otherwise.
//!
//! # The signature is a secret, and never touches the publish path
//!
//! A wrap signature opens the wrapped copy, so it is routed out of
//! `on_ghostkey_response` before anything else looks at it (`state.rs`, the
//! `SignResult` arm) and sent straight to the Harvest delegate inside a
//! redacting `WrapSignature`. The UI never holds the store key: the delegate
//! wraps and unwraps. Logging the vault's responses verbatim is fixed by
//! harvest#96 (#94), which this stack sits on.
//!
//! # Once per session
//!
//! Each (store, backing key) pair is attempted once per session
//! ([`AppState::custody_attempted`]): store state re-arrives on every update,
//! and a vault prompt the seller declined must not come back on each one. A
//! reload tries again.

use harvest_common::custody::{self, AuthorizedCopy, WrapScope};
use harvest_common::store::StoreStateV1;

use crate::state::AppState;

/// What a custody request is for.
#[derive(Clone, Debug, PartialEq)]
pub enum CustodyPurpose {
    /// Wrap this device's store key to the backer, and publish the copy.
    Wrap,
    /// Recover the store key from this copy.
    Recover(custody::WrappedStoreKey),
}

/// A custody request waiting on the vault, then on the Harvest delegate.
#[derive(Clone, Debug, PartialEq)]
pub struct CustodyRequest {
    pub store_contract_id: Vec<u8>,
    pub backer: [u8; 32],
    pub fingerprint: String,
    pub purpose: CustodyPurpose,
}

/// The copy `state` holds for `backer` under `scope`, if any.
pub(crate) fn copy_for<'a>(
    state: &'a StoreStateV1,
    backer: &ed25519_dalek::VerifyingKey,
    scope: &WrapScope,
) -> Option<&'a AuthorizedCopy> {
    state
        .copies
        .records
        .get(&AuthorizedCopy::slot_for(backer, scope))
}

impl AppState {
    /// The fingerprint of a connected Ghost Key whose verifying key is
    /// `backer`, if one is connected.
    fn connected_fingerprint(&self, backer: &[u8; 32]) -> Option<String> {
        self.ghostkeys
            .iter()
            .find(|k| k.verifying_key_bytes.as_deref() == Some(backer.as_slice()))
            .map(|k| k.fingerprint.clone())
    }

    /// Decide what custody work `store_contract_id` needs, record it, and
    /// start it. See the module docs.
    pub(crate) fn start_custody_for(&mut self, store_contract_id: &[u8]) {
        let Some(request) = self.custody_needed(store_contract_id) else {
            return;
        };
        let Some(store) = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|s| s.backing_state.owner)
        else {
            return;
        };
        let store = store.to_bytes();
        // A store's own key: ask for its subkeys too, so its details can be
        // published with them and a device can check them (see
        // `on_store_subkeys`).
        if matches!(request.purpose, CustodyPurpose::Wrap) {
            self.request_store_subkeys(store);
        }
        self.custody_attempted.insert((store, request.backer));
        let fingerprint = request.fingerprint.clone();
        self.pending_custody.insert(store, request);
        #[cfg(target_arch = "wasm32")]
        spawn_wrap_signature_request(fingerprint, store);
        #[cfg(not(target_arch = "wasm32"))]
        let _ = fingerprint;
    }

    /// The custody request a loaded store calls for, if any. Pure over the
    /// state, so it is testable without a browser.
    pub(crate) fn custody_needed(&self, store_contract_id: &[u8]) -> Option<CustodyRequest> {
        let loaded = self.browsing_stores.get(store_contract_id)?;
        let state = &loaded.backing_state;
        let owner = state.owner?;
        let backing =
            harvest_common::backing::current_backing(state, |network| self.tip_height(network))?;
        let backer = backing.statement.backer;
        let backer_bytes = backer.to_bytes();
        if self
            .custody_attempted
            .contains(&(owner.to_bytes(), backer_bytes))
            || self.pending_custody.contains_key(&owner.to_bytes())
        {
            return None;
        }
        let fingerprint = self.connected_fingerprint(&backer_bytes)?;
        let scope = WrapScope::current();
        let held = self.store_owner_key(store_contract_id) == Some(owner);
        let copy = copy_for(state, &backer, &scope);
        let purpose = match (held, copy) {
            (true, None) => CustodyPurpose::Wrap,
            (false, Some(copy)) => CustodyPurpose::Recover(copy.copy.wrapped.clone()),
            _ => return None,
        };
        Some(CustodyRequest {
            store_contract_id: store_contract_id.to_vec(),
            backer: backer_bytes,
            fingerprint,
            purpose,
        })
    }

    /// The vault signed a wrap message: send it to the Harvest delegate for
    /// the request that asked, and let go of it.
    ///
    /// Matched by the store key the message names, and by nothing else: a
    /// wrap signature nobody asked for is dropped, and nothing about it is
    /// logged.
    pub(crate) fn on_wrap_signature(&mut self, scoped_payload: Vec<u8>, signature: Vec<u8>) {
        let Some(store) = harvest_common::from_cbor::<ghostkey_common::ScopedPayload>(
            &scoped_payload,
        )
        .ok()
        .and_then(|scoped| custody::wrap_message_store(&scoped.payload)) else {
            return;
        };
        let store = store.to_bytes();
        let Some(pending) = self.pending_custody.get(&store).cloned() else {
            dioxus::logger::tracing::warn!("a wrap signature arrived that nothing asked for");
            return;
        };
        let request_id = self.next_messaging_request_id();
        let signature = harvest_common::delegate::WrapSignature(signature);
        let request = match &pending.purpose {
            CustodyPurpose::Wrap => harvest_common::HarvestDelegateRequest::WrapStoreKeyFor {
                request_id,
                store_verifying_key: store,
                backer_verifying_key: pending.backer,
                scoped_payload,
                signature,
            },
            CustodyPurpose::Recover(wrapped) => {
                harvest_common::HarvestDelegateRequest::UnwrapStoreKey {
                    request_id,
                    store_verifying_key: store,
                    backer_verifying_key: pending.backer,
                    scoped_payload,
                    signature,
                    wrapped: wrapped.clone(),
                }
            }
        };
        #[cfg(target_arch = "wasm32")]
        crate::state::spawn_harvest_request(request, "a custody request");
        #[cfg(not(target_arch = "wasm32"))]
        self.custody_sent.push(request);
    }

    /// The delegate wrapped the store key: publish the copy.
    pub(crate) fn on_store_key_wrapped(
        &mut self,
        store: [u8; 32],
        result: Result<AuthorizedCopy, String>,
    ) {
        let Some(pending) = self.pending_custody.remove(&store) else {
            return;
        };
        match result {
            Ok(copy) => {
                #[cfg(target_arch = "wasm32")]
                crate::gateway::store_ops::spawn_publish_copy(pending.store_contract_id, copy);
                #[cfg(not(target_arch = "wasm32"))]
                self.copies_to_publish.push((pending.store_contract_id, copy));
            }
            Err(why) => self.notifications.push(format!(
                "Your store's key could not be backed up to your Ghost Key: {why}. Another \
                 device will not be able to recover it until this succeeds."
            )),
        }
    }

    /// The delegate recovered the store key: register the store again, so it
    /// is this device's store once more.
    pub(crate) fn on_store_key_recovered(&mut self, store: [u8; 32], result: Result<(), String>) {
        let Some(pending) = self.pending_custody.remove(&store) else {
            return;
        };
        if let Err(why) = result {
            self.notifications.push(format!(
                "Your store's key could not be recovered from your Ghost Key: {why}"
            ));
            return;
        }
        let Some(registration) = self.recovered_registration(&pending, store) else {
            self.notifications.push(
                "Your store's key was recovered, but the store could not be registered on this \
                 device; reload to try again."
                    .into(),
            );
            return;
        };
        self.merge_store_registrations(&pending.fingerprint, vec![registration.clone()]);
        self.notifications
            .push("Recovered your store's key from your Ghost Key.".into());
        #[cfg(target_arch = "wasm32")]
        crate::state::spawn_harvest_request(
            harvest_common::HarvestDelegateRequest::RegisterStore {
                ghostkey_fingerprint: pending.fingerprint,
                store_contract_id: registration.store_contract_id,
                reputation_contract_id: registration.reputation_contract_id,
                mailbox_contract_id: registration.mailbox_contract_id,
                store_verifying_key: registration.store_verifying_key,
            },
            "the recovered store's registration",
        );
    }

    /// The registration a recovered store gets: its record from its published
    /// details, its mailbox derived from the backing Ghost Key (where the
    /// mailbox is still addressed; see `docs/design/entity-model.md`).
    fn recovered_registration(
        &self,
        pending: &CustodyRequest,
        store: [u8; 32],
    ) -> Option<harvest_common::StoreRegistration> {
        let loaded = self.browsing_stores.get(&pending.store_contract_id)?;
        let reputation = loaded.info.as_ref()?.reputation_contract_id.to_vec();
        let backer = ed25519_dalek::VerifyingKey::from_bytes(&pending.backer).ok()?;
        let mailbox = crate::gateway::mailbox_ops::mailbox_contract_key(&backer)
            .ok()?
            .id()
            .as_bytes()
            .to_vec();
        Some(harvest_common::StoreRegistration {
            store_contract_id: pending.store_contract_id.clone(),
            reputation_contract_id: reputation,
            mailbox_contract_id: mailbox,
            store_contract_key: None,
            store_verifying_key: Some(store),
        })
    }

    /// Ask the delegate for a store key's subkeys, once per session.
    pub(crate) fn request_store_subkeys(&mut self, store: [u8; 32]) {
        if !self.store_subkeys_requested.insert(store) {
            return;
        }
        let request_id = self.next_messaging_request_id();
        #[cfg(target_arch = "wasm32")]
        crate::state::spawn_harvest_request(
            harvest_common::HarvestDelegateRequest::GetStoreSubkeys {
                request_id,
                store_verifying_key: store,
            },
            "the store's derived keys",
        );
        #[cfg(not(target_arch = "wasm32"))]
        let _ = request_id;
    }

    /// The delegate derived a store key's subkeys: record them, finish a
    /// creation or an edit that waits on them, and check them against what
    /// the store has published.
    pub(crate) fn on_store_subkeys(
        &mut self,
        store: [u8; 32],
        result: Result<harvest_common::delegate::StoreSubkeyInfo, String>,
    ) {
        let info = match result {
            Ok(info) => info,
            Err(why) => {
                // A creation waiting on these cannot finish.
                if self
                    .pending_store_creation
                    .as_ref()
                    .is_some_and(|p| p.store_verifying_key == Some(store))
                {
                    self.store_creation_failed(&format!(
                        "the store's keys could not be derived: {why}"
                    ));
                }
                self.store_subkeys_requested.remove(&store);
                return;
            }
        };
        if let Some(pending) = self.pending_store_creation.as_mut() {
            if pending.store_verifying_key == Some(store) {
                pending.rsa_public_key_der = Some(info.record_public_key.clone());
                pending.encryption_public_key = Some(info.inbox_public_key);
            }
        }
        self.check_published_record_key(&store, &info);
        self.store_subkeys.insert(store, info);
        self.start_store_creation_if_ready();
        self.start_store_edit_if_ready();
    }

    /// The record key a store publishes must be the one this device derives
    /// from its store key (harvest#93 phase 1b). RSA key generation is not a
    /// function the `rsa` crate promises to keep stable, so a mismatch is
    /// said out loud rather than trusted silently.
    fn check_published_record_key(
        &mut self,
        store: &[u8; 32],
        info: &harvest_common::delegate::StoreSubkeyInfo,
    ) {
        let published = self.browsing_stores.values().find_map(|loaded| {
            (loaded.backing_state.owner.map(|k| k.to_bytes()) == Some(*store))
                .then(|| loaded.info.as_ref()?.record_public_key.clone())
                .flatten()
        });
        if published.is_some_and(|published| published != info.record_public_key) {
            self.notifications.push(
                "This device derives a different record key for your store than the one it \
                 publishes. Do not publish from this device until this is resolved: its build \
                 of Harvest may generate keys differently."
                    .into(),
            );
        }
    }
}

/// Ask the vault for the Ghost Key's signature over a store's wrap message.
#[cfg(target_arch = "wasm32")]
fn spawn_wrap_signature_request(fingerprint: String, store: [u8; 32]) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};
        let fail = |why: String| {
            dioxus::logger::tracing::warn!("custody: {why}");
            crate::gateway::APP_STATE.write().pending_custody.remove(&store);
        };
        let Ok(store_vk) = ed25519_dalek::VerifyingKey::from_bytes(&store) else {
            fail("not a store key".into());
            return;
        };
        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .ghostkey_delegate_key
            .clone()
        else {
            fail("the Ghost Key vault is not registered".into());
            return;
        };
        let request = ghostkey_common::GhostkeyRequest::SignMessage {
            fingerprint,
            message: custody::wrap_message(&store_vk),
        };
        match ghostkey_common::to_cbor(&request) {
            Ok(payload) => {
                if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
                    fail(format!("could not ask the vault: {e}"));
                }
            }
            Err(e) => fail(format!("serialize SignMessage: {e}")),
        }
    });
}
