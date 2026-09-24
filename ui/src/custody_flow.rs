//! Keeping a store's key recoverable from its backing Ghost Key, and
//! recovering it on a device that has lost it (harvest#93, phase 1b).
//!
//! # What this does
//!
//! Whenever a store's state arrives, [`AppState::start_custody_for`] decides
//! one of three things, from the state alone and the Ghost Keys connected to
//! this tab:
//!
//! * **Wrap.** The store is ours (registered, with its store key, and this
//!   device's delegate HOLDS that key), its current
//!   backing is a connected Ghost Key, and the store holds no wrapped copy for
//!   that key under Harvest's current webapp scope. The UI asks the vault for
//!   the Ghost Key's signature over `custody::wrap_message(store)`, hands it
//!   to the Harvest delegate (`WrapStoreKeyFor`), which wraps the store key
//!   and signs the copy, and publishes the copy. This covers a new store, a
//!   store whose backing changed, and a change of webapp scope.
//! * **Recover.** This device's delegate does NOT hold the store's key, one
//!   of its unretired backings is a connected Ghost Key, and it holds a copy
//!   for that key under the current scope: this device lost the key or never
//!   had it (a second device). The same vault signature goes to
//!   `UnwrapStoreKey`, which opens the copy, checks the seed IS this store's
//!   key, and keeps it; a store not registered here is then registered
//!   again, so it reappears in My Store.
//!
//!   "Not held" is what the delegate's `StoreList` answer says
//!   (`held_store_keys`), NOT the absence of a registration (harvest#138).
//!   A delegate re-key carries the registrations forward (harvest#123) and
//!   never the keys, which leave the delegate only wrapped, in custody. Read
//!   off the registration, such a device chose Wrap, which the delegate
//!   refuses for a key it lacks, and never recovered: it could sign nothing
//!   for its own store (no despatch, cancel, invoice or listing).
//! * Nothing, otherwise.
//!
//! Recovery can go through any backer whose backing is not retired, not only
//! the current one; wrapping is for the current backer. The decision runs
//! again when the connected Ghost Keys or the store registrations change, and
//! when the vault answers.
//!
//! # The signature is a secret, and never touches the publish path
//!
//! A wrap signature opens the wrapped copy, so it is routed out of
//! `on_ghostkey_response` before anything else looks at it (`state.rs`, the
//! `SignResult` arm) and sent straight to the Harvest delegate inside a
//! redacting `WrapSignature`. The UI never holds the store key: the delegate
//! wraps and unwraps. The vault's responses are logged as summaries since
//! harvest#96 (#94), which is on `main` beneath this stack: a `SignResult`
//! logs as its bare name, nothing of its payload
//! (`gateway::log_summary::ghostkey_response_summary`, pinned by
//! `a_vault_response_summary_prints_no_secret`).
//!
//! This is a property of this UI, not something the delegate enforces: the
//! Harvest web app's origin is trusted, and it supplies the wrap signature,
//! so a UI built to could open any copy it asks for.
//!
//! # One vault prompt at a time
//!
//! A vault refusal names no request, so custody is started only while
//! nothing else waits on the vault (the seller's own signatures, a watch
//! request, another custody request), and counts as the seller's own work
//! while it waits, so watch requests hold back and a refusal is not taken
//! for a watch request's. If the seller starts signing while a custody
//! prompt is open, a refusal cannot be told apart and drops both.
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

/// How long a custody request may wait on the vault and then the Harvest
/// delegate before it is given up (#99 re-check): the same bound watch
/// requests use. Without it, a send that failed, a bare delegate `Error`
/// (which names no request) or no answer at all left the request pending
/// for the session, and a pending custody request holds back watch
/// requests and every other custody request.
pub(crate) const CUSTODY_TIMEOUT_MS: u64 = crate::bitcoin_inbox::SIGNATURE_TIMEOUT_MS;

/// How many times a custody request may fail to SEND before this session
/// stops retrying it and tells the seller.
const MAX_CUSTODY_SEND_ATTEMPTS: u8 = 3;

/// A custody request waiting on the vault, then on the Harvest delegate.
#[derive(Clone, Debug, PartialEq)]
pub struct CustodyRequest {
    pub store_contract_id: Vec<u8>,
    pub backer: [u8; 32],
    pub fingerprint: String,
    pub purpose: CustodyPurpose,
    /// The id the delegate request went out under, once it has been sent.
    ///
    /// The delegate answers by store key, and a store can have a SECOND
    /// attempt under a different backer after the first timed out
    /// (`expire_custody` frees the slot and `custody_needed` picks another
    /// unretired backer). Without this, a late answer to the first attempt
    /// is matched to the second by store key alone: an old error cancels a
    /// live attempt, and an old success is registered with the wrong
    /// backer's metadata, which decides the mailbox in
    /// `recovered_registration`. `None` until the request is sent, so a
    /// request still waiting on the vault has nothing to match.
    pub request_id: Option<u64>,
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
        // One vault prompt at a time: a refusal names no request, so while
        // custody and anything else wait on the vault, nobody could tell
        // whose prompt was refused (#99 review). Deferred, not recorded as
        // attempted: `start_custody_where_needed` runs again when the vault
        // answers, and on every Ghost Key list, store list and store state.
        if self.vault_work_outstanding() {
            return;
        }
        let Some(request) = self.custody_needed(store_contract_id) else {
            self.note_unrecoverable_store_key(store_contract_id);
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
        self.custody_started_ms
            .insert(store, crate::state::now_ms());
        #[cfg(target_arch = "wasm32")]
        {
            spawn_wrap_signature_request(fingerprint, store);
            // Re-checked rather than fired once: a one-shot timer that
            // goes off a millisecond early leaves the request pending for
            // the session (#101 review), so this keeps looking while the
            // request is still there.
            wasm_bindgen_futures::spawn_local(async move {
                use dioxus::prelude::{ReadableExt, WritableExt};
                for _ in 0..4 {
                    gloo_timers::future::TimeoutFuture::new((CUSTODY_TIMEOUT_MS / 2).max(1) as u32)
                        .await;
                    crate::gateway::APP_STATE
                        .write()
                        .expire_custody(crate::state::now_ms());
                    if !crate::gateway::APP_STATE
                        .read()
                        .pending_custody
                        .contains_key(&store)
                    {
                        return;
                    }
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = fingerprint;
    }

    /// Say once per session that this device cannot sign for one of its own
    /// stores and why, when custody has nothing it can do about it
    /// (harvest#138 review).
    ///
    /// The case: the store is registered here but the delegate does not hold
    /// its key (a delegate re-key carries the registration and never the
    /// key), and no connected, unretired backer has a copy to recover it
    /// from. Without this the seller learns it only from a refused signature.
    fn note_unrecoverable_store_key(&mut self, store_contract_id: &[u8]) {
        let Some(owner) = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|s| s.backing_state.owner)
        else {
            return;
        };
        let key = owner.to_bytes();
        let unheld_and_ours =
            self.store_owner_key(store_contract_id) == Some(owner) && !self.holds_store_key(&key);
        let closed = self
            .browsing_stores
            .get(store_contract_id)
            .is_some_and(|s| s.closed);
        if !unheld_and_ours || closed || self.pending_custody.contains_key(&key) {
            return;
        }
        // Only when there is NOTHING to recover from here. A copy under a
        // connected backer that was already tried this session (declined,
        // timed out, refused) has its own message, and "connect the Ghost
        // Key" would be wrong advice for it (harvest#138 review, round 2).
        if self.a_connected_backer_has_a_copy(store_contract_id) {
            return;
        }
        if !self.store_key_unheld_announced.insert(key) {
            return;
        }
        self.notifications.push(
            "This device does not hold your store's key, so it cannot sign anything for the \
             store (despatch, cancel, invoices, listings). It is recovered from the backup \
             wrapped to a Ghost Key that backs the store, once that Ghost Key is connected \
             here. If no device ever made that backup, this device cannot sign for the store."
                .into(),
        );
    }

    /// Whether a connected Ghost Key that backs the store (and is not
    /// retired) has a copy of its key under the current scope, whether or not
    /// it was tried this session.
    fn a_connected_backer_has_a_copy(&self, store_contract_id: &[u8]) -> bool {
        let Some(state) = self
            .browsing_stores
            .get(store_contract_id)
            .map(|s| &s.backing_state)
        else {
            return false;
        };
        let scope = WrapScope::current();
        state
            .backings
            .records
            .values()
            .map(|b| b.statement.backer)
            .filter(|b| {
                !state
                    .retirements
                    .records
                    .contains_key(&harvest_common::store::Bytes32(b.to_bytes()))
            })
            .any(|backer| {
                copy_for(state, &backer, &scope).is_some()
                    && self.connected_fingerprint(&backer.to_bytes()).is_some()
            })
    }

    /// A custody request could not be SENT. Give it up, and let it be tried
    /// again a bounded number of times.
    ///
    /// `take_custody` alone released the vault but left `custody_attempted`
    /// set, so `custody_needed` refused the retry and store-key backup and
    /// recovery were off for the session after one failed send (#101
    /// re-review, marker sweep). A send failure is not a refusal -- nothing
    /// was ever asked -- so it should not be recorded like the timeout the
    /// "attempt stays recorded" rule was written for.
    ///
    /// Bounded rather than simply cleared: retries are driven by store lists,
    /// Ghost Key lists and store states, so an unbounded clear would retry at
    /// that rate and notify every time.
    pub(crate) fn on_custody_send_failed(&mut self, store: [u8; 32], why: &str) {
        let backer = self.take_custody(&store).map(|p| p.backer);
        let Some(backer) = backer else {
            return;
        };
        let failures = self
            .custody_send_failures
            .entry((store, backer))
            .or_insert(0);
        *failures = failures.saturating_add(1);
        if *failures >= MAX_CUSTODY_SEND_ATTEMPTS {
            if *failures == MAX_CUSTODY_SEND_ATTEMPTS {
                self.notifications.push(format!(
                    "Your store's key could not be backed up or recovered: {why}. Reload to try \
                     again."
                ));
            }
            return;
        }
        // Let the next store list or Ghost Key list try again.
        self.custody_attempted.remove(&(store, backer));
    }

    /// Take a custody request off the pending list, with the timestamp the
    /// timeout reads. The two are removed together everywhere: a timestamp
    /// left behind would time out the NEXT request for that store as soon
    /// as it started.
    pub(crate) fn take_custody(&mut self, store: &[u8; 32]) -> Option<CustodyRequest> {
        self.custody_started_ms.remove(store);
        self.pending_custody.remove(store)
    }

    /// Take the pending custody request for `store`, but ONLY if it is the
    /// one `request_id` answers.
    ///
    /// A store can have a second attempt under a different backer once the
    /// first has timed out, and the delegate answers by store key. Matching
    /// by store key alone let a late answer to the first attempt consume the
    /// second: an error cancelled a live attempt, and a success was
    /// registered with the wrong backer, which is what
    /// `recovered_registration` derives the mailbox from (#101 re-review,
    /// Codex P2). A mismatched answer is dropped, leaving the live attempt
    /// to its own reply or its timeout.
    pub(crate) fn take_custody_answering(
        &mut self,
        store: &[u8; 32],
        request_id: u64,
    ) -> Option<CustodyRequest> {
        match self.pending_custody.get(store) {
            // Sent, and this is its answer.
            Some(p) if p.request_id == Some(request_id) => self.take_custody(store),
            // Sent under a different id: a late answer to an attempt that is
            // already gone. Leave the live one alone.
            Some(_) => {
                dioxus::logger::tracing::warn!(
                    "a custody answer arrived for a request that is no longer pending"
                );
                None
            }
            None => None,
        }
    }

    /// Give up every custody request older than [`CUSTODY_TIMEOUT_MS`], say
    /// so, and let the vault take the next one. The attempt stays recorded,
    /// so it is not retried until a reload.
    pub(crate) fn expire_custody(&mut self, now_ms: u64) {
        let started = &self.custody_started_ms;
        let expired: Vec<[u8; 32]> = self
            .pending_custody
            .keys()
            .filter(|store| {
                // A request with no timestamp is NOT instantly expired
                // (#101 review): `start_custody_for` records one, so a
                // missing one means something else put the request there,
                // and giving it up here would be a guess. The timer that
                // fires for it re-checks, so nothing is stuck for long.
                started
                    .get(*store)
                    .is_some_and(|t| now_ms.saturating_sub(*t) >= CUSTODY_TIMEOUT_MS)
            })
            .copied()
            .collect();
        let mut news = false;
        for store in &expired {
            let request = self.pending_custody.remove(store);
            self.custody_started_ms.remove(store);
            // A recovery of a REGISTERED store whose key another attempt
            // already recovered did not fail in any sense the seller needs to
            // hear (harvest#138 review). An unregistered store is still not
            // this device's (a late success rebuilds nothing), so it is said,
            // as in `on_store_key_recovered_inner`.
            let registered = self
                .my_stores
                .values()
                .flatten()
                .any(|s| s.store_verifying_key == Some(*store));
            let already_recovered = registered
                && matches!(request.map(|r| r.purpose), Some(CustodyPurpose::Recover(_)))
                && self.store_keys_held.get(store) == Some(&true);
            news |= !already_recovered;
        }
        if news {
            self.notifications.push(
                "Backing up or recovering your store's key did not finish: the Ghost Key vault \
                 or the Harvest delegate did not answer. Reload to try again."
                    .into(),
            );
        }
        if !expired.is_empty() {
            self.start_custody_where_needed();
        }
    }

    /// Re-decide custody for every loaded store: when the Ghost Keys
    /// connected to this tab change, when the store registrations arrive,
    /// and when the vault has answered and a deferred request can start.
    pub(crate) fn start_custody_where_needed(&mut self) {
        let ids: Vec<Vec<u8>> = self.browsing_stores.keys().cloned().collect();
        for id in ids {
            self.start_custody_for(&id);
        }
    }

    /// Whether anything is waiting on the Ghost Key vault: the seller's own
    /// signatures, a watch request, or a custody request.
    fn vault_work_outstanding(&self) -> bool {
        self.user_signature_under_way()
            || self
                .pending_signatures
                .iter()
                .any(|p| matches!(p, crate::state::PendingSignature::InboxEntry(_)))
    }

    /// The custody request a loaded store calls for, if any. Pure over the
    /// state, so it is testable without a browser.
    ///
    /// Wrap is for the CURRENT backer only: that is the key readers treat
    /// as the store's. Recovery can use any backer whose backing is not
    /// retired and whose copy the store holds (#99 review): the current one
    /// first, then the others, since a device may hold an older backing
    /// Ghost Key and not the current one.
    pub(crate) fn custody_needed(&self, store_contract_id: &[u8]) -> Option<CustodyRequest> {
        // A generation this session moved our store away from stays loaded,
        // and its state lags the current one's: it is not a store to wrap or
        // recover for (harvest#164).
        if self.migrated_contract_ids.contains_key(store_contract_id) {
            return None;
        }
        let loaded = self.browsing_stores.get(store_contract_id)?;
        let state = &loaded.backing_state;
        let owner = state.owner?;
        if self.pending_custody.contains_key(&owner.to_bytes()) {
            return None;
        }
        let scope = WrapScope::current();
        let current =
            harvest_common::backing::current_backing(state, |network| self.tip_height(network))
                .map(|b| b.statement.backer);
        let attempted = |backer: &ed25519_dalek::VerifyingKey| {
            self.custody_attempted
                .contains(&(owner.to_bytes(), backer.to_bytes()))
        };
        let request = |backer: &ed25519_dalek::VerifyingKey, fingerprint, purpose| {
            Some(CustodyRequest {
                store_contract_id: store_contract_id.to_vec(),
                backer: backer.to_bytes(),
                fingerprint,
                purpose,
                request_id: None,
            })
        };
        // Ours AND held: the registration alone says the store is ours, not
        // that this delegate can sign with its key (harvest#138).
        if self.store_owner_key(store_contract_id) == Some(owner)
            && self.holds_store_key(&owner.to_bytes())
        {
            let backer = current?;
            if attempted(&backer) || copy_for(state, &backer, &scope).is_some() {
                return None;
            }
            let fingerprint = self.connected_fingerprint(&backer.to_bytes())?;
            return request(&backer, fingerprint, CustodyPurpose::Wrap);
        }
        // Not held -- never registered here, or registered and the key lost
        // to a delegate re-key: recover through any unretired backer this
        // tab has, the current one first.
        let mut backers: Vec<ed25519_dalek::VerifyingKey> = state
            .backings
            .records
            .values()
            .map(|b| b.statement.backer)
            .filter(|b| {
                !state
                    .retirements
                    .records
                    .contains_key(&harvest_common::store::Bytes32(b.to_bytes()))
            })
            .collect();
        backers.sort_by_key(|b| (Some(*b) != current, b.to_bytes()));
        backers.into_iter().find_map(|backer| {
            if attempted(&backer) {
                return None;
            }
            let copy = copy_for(state, &backer, &scope)?;
            let fingerprint = self.connected_fingerprint(&backer.to_bytes())?;
            request(
                &backer,
                fingerprint,
                CustodyPurpose::Recover(copy.copy.wrapped.clone()),
            )
        })
    }

    /// The vault signed a wrap message: send it to the Harvest delegate for
    /// the request that asked, and let go of it.
    ///
    /// Matched by the store key the message names, and by nothing else: a
    /// wrap signature nobody asked for is dropped, and nothing about it is
    /// logged.
    pub(crate) fn on_wrap_signature(&mut self, scoped_payload: Vec<u8>, signature: Vec<u8>) {
        let Some(store) =
            harvest_common::from_cbor::<ghostkey_common::ScopedPayload>(&scoped_payload)
                .ok()
                .and_then(|scoped| custody::wrap_message_store(&scoped.payload))
        else {
            return;
        };
        let store = store.to_bytes();
        let Some(pending) = self.pending_custody.get(&store).cloned() else {
            dioxus::logger::tracing::warn!("a wrap signature arrived that nothing asked for");
            return;
        };
        if self.harvest_delegate_key.is_none() {
            // Nothing would ever answer; say so rather than wait forever.
            self.take_custody(&store);
            self.notifications.push(
                "Your store's key could not be backed up or recovered: the Harvest delegate is \
                 not registered. Reload to try again."
                    .into(),
            );
            return;
        }
        let request_id = self.next_messaging_request_id();
        if let Some(pending) = self.pending_custody.get_mut(&store) {
            pending.request_id = Some(request_id);
        }
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
        spawn_custody_request(store, request);
        #[cfg(not(target_arch = "wasm32"))]
        self.custody_sent.push(request);
    }

    /// The delegate wrapped the store key: publish the copy.
    pub(crate) fn on_store_key_wrapped(
        &mut self,
        store: [u8; 32],
        request_id: u64,
        result: Result<AuthorizedCopy, String>,
    ) {
        let Some(pending) = self.take_custody_answering(&store, request_id) else {
            return;
        };
        match result {
            Ok(copy) => {
                #[cfg(target_arch = "wasm32")]
                crate::gateway::store_ops::spawn_publish_copy(pending.store_contract_id, copy);
                #[cfg(not(target_arch = "wasm32"))]
                self.copies_to_publish
                    .push((pending.store_contract_id, copy));
            }
            Err(why) => self.notifications.push(format!(
                "Your store's key could not be backed up to your Ghost Key: {why}. Another \
                 device will not be able to recover it until this succeeds."
            )),
        }
        // The vault is free again, so the store that was deferred behind
        // this one can start (#101 re-review S3): `start_custody_for`
        // refuses while ANY custody request is pending, so without this a
        // second store waits for an unrelated event or a reload.
        self.start_custody_where_needed();
    }

    /// The delegate recovered the store key: register the store again, so it
    /// is this device's store once more.
    pub(crate) fn on_store_key_recovered(
        &mut self,
        store: [u8; 32],
        request_id: u64,
        result: Result<(), String>,
    ) {
        self.on_store_key_recovered_inner(store, request_id, result);
        // Every exit above releases the vault, so the store deferred behind
        // this one can start (#101 re-review S3). Done here rather than at
        // each `return` so a later early exit cannot forget it.
        self.start_custody_where_needed();
    }

    fn on_store_key_recovered_inner(
        &mut self,
        store: [u8; 32],
        request_id: u64,
        result: Result<(), String>,
    ) {
        // Matched by KEY, not by the contract id the request named: a store
        // migration can rewrite the registration's contract id while the
        // vault prompt is open (harvest#138 review).
        let registered = self
            .my_stores
            .values()
            .flatten()
            .any(|s| s.store_verifying_key == Some(store));
        // What a success MEANS -- the delegate now holds the key -- is acted
        // on once, on the transition to held, whichever request it answers
        // and in whatever order the answers of several attempts arrive
        // (harvest#138 review, rounds 2-4). Tying it to the matched request
        // instead lost the follow-up for a late answer, or reported it twice
        // when a second attempt was live.
        let known_held = self.store_keys_held.get(&store) == Some(&true);
        if result.is_ok() {
            self.store_keys_held.insert(store, true);
            if registered && !known_held {
                self.after_registered_store_key_recovered(store);
            }
        }
        let Some(pending) = self.take_custody_answering(&store, request_id) else {
            return;
        };
        if let Err(why) = result {
            // An attempt that failed after another already recovered a
            // registered store's key is not news, and saying it would be
            // false. An unregistered store is still not this device's store
            // (a late success rebuilds nothing), so its failure is said.
            if !(registered && self.store_keys_held.get(&store) == Some(&true)) {
                self.notifications.push(format!(
                    "Your store's key could not be recovered from your Ghost Key: {why}"
                ));
            }
            return;
        }
        if registered {
            // Handled on the transition above; the registration came across a
            // delegate re-key and is kept as it is.
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
        // Check what this device derives against what the store publishes
        // before anything is published from here (#99 review).
        self.request_store_subkeys(store);
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

    /// A registered store's key is held again (harvest#138): say so, and redo
    /// what failed while it was missing.
    ///
    /// The registration came across a delegate re-key and only the key did
    /// not. It already names this store's own contracts, where a
    /// registration rebuilt here would derive the mailbox from the recovering
    /// backer (see `recovered_registration`), so it is kept as it is.
    fn after_registered_store_key_recovered(&mut self, store: [u8; 32]) {
        self.notifications
            .push("Recovered your store's key from your Ghost Key.".into());
        self.request_store_subkeys(store);
        // Buyers' messages failed to open while the key was missing
        // (`DeriveConversationKeys` answers an error, which is retried only on
        // the next mailbox update): ask again now, or a quiet store's inbox
        // stays unreadable for the session.
        let ids: Vec<Vec<u8>> = self
            .my_stores
            .values()
            .flatten()
            .filter(|s| s.store_verifying_key == Some(store))
            .map(|s| s.store_contract_id.clone())
            .collect();
        for id in ids {
            self.ask_for_conversation_keys(&id);
        }
    }

    /// The registration a recovered store gets: its record from its published
    /// details, its mailbox derived from the backing Ghost Key (where the
    /// mailbox is still addressed; see `docs/design/entity-model.md`).
    ///
    /// KNOWN LIMIT (#99 re-check), left for the phase that re-addresses the
    /// mailbox by the store key (1d): the mailbox is derived from the
    /// RECOVERING backer, and the store's mailbox was made by the Ghost Key
    /// that created it. They are the same Ghost Key until a store has had a
    /// second backer, which nothing in the UI does yet (no rotation
    /// control); once it can, a device recovering through the second backer
    /// would register a mailbox the store never used.
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
        // Sent through the path that clears the marker when the send fails
        // (#101 review): the marker is what stops a second ask, so leaving
        // it set after a failed send means the delegate is never asked
        // again this session and a creation waiting on the answer hangs.
        #[cfg(target_arch = "wasm32")]
        spawn_subkeys_request(
            store,
            harvest_common::HarvestDelegateRequest::GetStoreSubkeys {
                request_id,
                store_verifying_key: store,
            },
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
                // A creation or an edit waiting on these cannot finish.
                // Previously this released a creation and said nothing at
                // all when an edit was parked, which wedged the vault for
                // the session (#101 re-review, lens B).
                if !self.release_waiters_on_subkeys(store, &why) {
                    self.notifications.push(format!(
                        "Your store's derived keys could not be derived: {why}. Reload to try \
                         again."
                    ));
                }
                return;
            }
        };
        self.check_published_record_key(&store, &info);
        self.store_subkeys.insert(store, info);
        self.fill_creation_from_subkeys(store);
        self.start_store_creation_if_ready();
        self.start_store_edit_if_ready();
    }

    /// A store's subkeys will not arrive. Release everything waiting on them.
    ///
    /// Both failure paths must do this: the delegate answering `Err`, and the
    /// request failing to send. Neither released a parked EDIT (#101
    /// re-review, lens B), and that one is the dangerous omission.
    /// `start_store_edit_if_ready` parks the edit in `pending_store_edit` and
    /// asks for the subkeys; `pending_store_edit.is_some()` feeds
    /// `user_signature_under_way()`, which gates `vault_work_outstanding()`.
    /// So ONE failed subkeys request stopped every custody wrap and recovery
    /// and every Bitcoin watch request for the rest of the session, with no
    /// timeout on the edit and nothing but a reload to clear it. A realistic
    /// trigger is a device whose delegate re-keyed: it still holds the
    /// registration, so `store_owner_key` answers, but the delegate no longer
    /// holds the store key -- which is the very situation custody recovery
    /// exists to repair.
    ///
    /// Returns whether it already told the seller something, so the caller
    /// does not say it twice.
    fn release_waiters_on_subkeys(&mut self, store: [u8; 32], why: &str) -> bool {
        self.store_subkeys_requested.remove(&store);
        let mut said = false;
        if self
            .pending_store_creation
            .as_ref()
            .is_some_and(|p| p.store_verifying_key == Some(store))
        {
            self.store_creation_failed(&format!("the store's keys could not be derived: {why}"));
            said = true;
        }
        // Matched the way `start_store_edit_if_ready` chose the store it
        // asked for, so this releases that edit and no other.
        let edit_id = self
            .pending_store_edit
            .as_ref()
            .map(|e| e.store_contract_id.clone());
        let edit_is_this_store = edit_id
            .as_deref()
            .and_then(|id| self.work_store_key(id))
            .is_some_and(|key| key.to_bytes() == store);
        if edit_is_this_store {
            self.pending_store_edit = None;
            self.notifications.push(format!(
                "Your store's details were not published: the keys it publishes them with \
                 could not be derived ({why})."
            ));
            said = true;
        }
        said
    }

    /// The `GetStoreSubkeys` request could not be SENT.
    ///
    /// Split out of `spawn_subkeys_request` so the state change is testable
    /// off-target (#101 re-review B4). Clearing the marker alone left
    /// `store_creation_in_flight` set, so `begin_store_creation` refused
    /// every later attempt and only a reload recovered.
    ///
    /// This and the delegate's `Err` answer now release the SAME things,
    /// through `release_waiters_on_subkeys`. An earlier version of this
    /// comment claimed they already did; they did not, and the difference
    /// was a parked edit that nothing freed (#101 re-review, lens B).
    pub(crate) fn on_subkeys_request_failed(&mut self, store: [u8; 32], why: &str) {
        if !self.release_waiters_on_subkeys(store, why) {
            // Nothing was waiting: a custody check asked. Say so rather than
            // leaving the seller with a screen that never fills.
            self.notifications.push(format!(
                "Your store's derived keys could not be asked for: {why}. Reload to try again."
            ));
        }
    }

    /// Check the record key again for the store `store_contract_id`, if this
    /// device has derived its store's subkeys.
    pub(crate) fn recheck_record_key(&mut self, store_contract_id: &[u8]) {
        let Some(owner) = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|s| s.backing_state.owner)
            .map(|k| k.to_bytes())
        else {
            return;
        };
        if let Some(info) = self.store_subkeys.get(&owner).cloned() {
            self.check_published_record_key(&owner, &info);
        }
    }

    /// Fill the pending creation for the store key `store` from the subkeys
    /// this session holds for it.
    ///
    /// Returns whether a creation was FILLED, which is what the caller acts
    /// on (#101 review): it asks the delegate when this says no, and
    /// answering "the subkeys are here" for a creation that is not this
    /// store's would leave that creation waiting on a request nobody made.
    pub(crate) fn fill_creation_from_subkeys(&mut self, store: [u8; 32]) -> bool {
        let Some(info) = self.store_subkeys.get(&store).cloned() else {
            return false;
        };
        let Some(pending) = self.pending_store_creation.as_mut() else {
            return false;
        };
        if pending.store_verifying_key != Some(store) {
            return false;
        }
        pending.rsa_public_key_der = Some(info.record_public_key);
        pending.encryption_public_key = Some(info.inbox_public_key);
        true
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
            // Blocked, not only reported (#99 review): an edit from here
            // would publish a record key that is not the store's. Said once,
            // not on every state arrival.
            if !self.record_key_mismatch.insert(*store) {
                return;
            }
            self.notifications.push(
                "This device derives a different record key for your store than the one it \
                 publishes, so it will not publish the store's details: its build of Harvest \
                 may generate keys differently. Publish from a device that agrees."
                    .into(),
            );
        } else {
            self.record_key_mismatch.remove(store);
        }
    }
}

/// Ask the Harvest delegate for a store's derived keys; if the request
/// cannot be sent, forget that it was asked so a retry asks again.
#[cfg(target_arch = "wasm32")]
fn spawn_subkeys_request(store: [u8; 32], request: harvest_common::HarvestDelegateRequest) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};
        let fail = |why: String| {
            dioxus::logger::tracing::warn!("the store's derived keys were not asked for: {why}");
            crate::gateway::APP_STATE
                .write()
                .on_subkeys_request_failed(store, &why);
        };
        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .harvest_delegate_key
            .clone()
        else {
            fail("the Harvest delegate is not registered".into());
            return;
        };
        match harvest_common::to_cbor(&request) {
            Ok(payload) => {
                if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await
                {
                    fail(format!("could not reach the Harvest delegate: {e}"));
                }
            }
            Err(e) => fail(format!("could not encode the request: {e}")),
        }
    });
}

/// Send a custody request to the Harvest delegate; if it cannot be sent,
/// give the request up and say so, rather than leave it pending (#99
/// re-check).
#[cfg(target_arch = "wasm32")]
fn spawn_custody_request(store: [u8; 32], request: harvest_common::HarvestDelegateRequest) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};
        let fail = |why: String| {
            dioxus::logger::tracing::warn!("custody: {why}");
            crate::gateway::APP_STATE
                .write()
                .on_custody_send_failed(store, &why);
        };
        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .harvest_delegate_key
            .clone()
        else {
            fail("the Harvest delegate is not registered".into());
            return;
        };
        match harvest_common::to_cbor(&request) {
            Ok(payload) => {
                if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await
                {
                    fail(format!("could not reach the Harvest delegate: {e}"));
                }
            }
            Err(e) => fail(format!("could not encode the request: {e}")),
        }
    });
}

/// Ask the vault for the Ghost Key's signature over a store's wrap message.
#[cfg(target_arch = "wasm32")]
fn spawn_wrap_signature_request(fingerprint: String, store: [u8; 32]) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};
        let fail = |why: String| {
            dioxus::logger::tracing::warn!("custody: {why}");
            crate::gateway::APP_STATE
                .write()
                .on_custody_send_failed(store, &why);
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
                if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await
                {
                    fail(format!("could not ask the vault: {e}"));
                }
            }
            Err(e) => fail(format!("serialize SignMessage: {e}")),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backing_flow::tests::{load_backed, sign, signed_backing};
    use ed25519_dalek::{Signer as _, SigningKey};
    use harvest_common::custody::{StoreKeyCopy, WrappedStoreKey};
    use harvest_common::{HarvestDelegateRequest, HarvestDelegateResponse, StoreRegistration};

    const FINGERPRINT: &str = "fp-backer";
    const STORE: u8 = 0x71;
    const BACKER: u8 = 0x41;
    const ID: u8 = 1;

    fn store_vk() -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[STORE; 32]).verifying_key()
    }

    fn backer_vk() -> ed25519_dalek::VerifyingKey {
        SigningKey::from_bytes(&[BACKER; 32]).verifying_key()
    }

    fn connect_backer(state: &mut AppState) {
        state.ghostkeys.push(ghostkey_common::GhostKeyInfo {
            fingerprint: FINGERPRINT.to_string(),
            label: None,
            notary_info: String::new(),
            verifying_key_bytes: Some(backer_vk().to_bytes().to_vec()),
            backed_up: false,
        });
    }

    fn register(state: &mut AppState) {
        state.my_stores.insert(
            FINGERPRINT.to_string(),
            vec![StoreRegistration {
                store_contract_id: vec![ID; 32],
                reputation_contract_id: vec![ID + 1; 32],
                mailbox_contract_id: vec![ID + 2; 32],
                store_contract_key: None,
                store_verifying_key: Some(store_vk().to_bytes()),
            }],
        );
    }

    fn wrapped() -> WrappedStoreKey {
        WrappedStoreKey {
            scheme: custody::SCHEME_V1,
            ciphertext: vec![0xc0; custody::WRAPPED_LEN_V1],
        }
    }

    fn add_copy(state: &mut AppState, scope: WrapScope) {
        let copy = StoreKeyCopy {
            store: store_vk(),
            backer: backer_vk(),
            scope,
            wrapped: wrapped(),
        };
        let (scoped_payload, signature) = sign(&SigningKey::from_bytes(&[STORE; 32]), &copy);
        let authorized = AuthorizedCopy {
            copy,
            scoped_payload,
            signature,
        };
        let loaded = state.browsing_stores.get_mut(&vec![ID; 32]).unwrap();
        loaded
            .backing_state
            .copies
            .records
            .insert(AuthorizedCopy::slot_for(&backer_vk(), &scope), authorized);
    }

    /// A store owned by `STORE`, currently backed by `BACKER`, which is
    /// connected to this tab.
    fn backed_store() -> AppState {
        let mut state = AppState::default();
        load_backed(
            &mut state,
            ID,
            STORE,
            vec![signed_backing(STORE, BACKER, 10)],
        );
        connect_backer(&mut state);
        state.harvest_delegate_key = Some(freenet_stdlib::prelude::DelegateKey::new(
            [0xA1; 32],
            freenet_stdlib::prelude::CodeHash::new([0xA1; 32]),
        ));
        state
    }

    /// Mark the store's pending custody request as SENT under `id`, which is
    /// what `on_wrap_signature` does once the vault has signed. Tests that
    /// answer the delegate directly skip that step, and an answer is only
    /// matched to a request that was actually sent (#101 re-review, Codex P2).
    fn sent_under(state: &mut AppState, store: [u8; 32], id: u64) {
        state
            .pending_custody
            .get_mut(&store)
            .expect("a pending custody request")
            .request_id = Some(id);
    }

    fn purpose(state: &AppState) -> Option<CustodyPurpose> {
        state.custody_needed(&[ID; 32]).map(|r| r.purpose)
    }

    /// The four cases the decision distinguishes. Mutated red by swapping the
    /// `held` arms of the match, and by dropping the scope from `copy_for`.
    #[test]
    fn custody_wraps_a_held_key_and_recovers_a_lost_one() {
        // Held, no copy: wrap.
        let mut state = backed_store();
        register(&mut state);
        assert_eq!(purpose(&state), Some(CustodyPurpose::Wrap));
        // Held, copy under the current scope: nothing to do.
        add_copy(&mut state, WrapScope::current());
        assert_eq!(purpose(&state), None);

        // Held, copy only under an older scope: wrap again for this one.
        let mut state = backed_store();
        register(&mut state);
        add_copy(&mut state, WrapScope([0xee; 32]));
        assert_eq!(purpose(&state), Some(CustodyPurpose::Wrap));

        // Not held, copy: recover it.
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        assert_eq!(purpose(&state), Some(CustodyPurpose::Recover(wrapped())));

        // Not held, no copy: nothing a device can do.
        let state = backed_store();
        assert_eq!(purpose(&state), None);
    }

    /// Custody needs the backing Ghost Key in this tab's vault, and asks once
    /// per (store, backer) per session. Mutated red by dropping each guard.
    #[test]
    fn custody_needs_the_backer_connected_and_asks_once() {
        let mut state = backed_store();
        register(&mut state);
        state.ghostkeys.clear();
        assert_eq!(purpose(&state), None, "the backer is not connected");

        connect_backer(&mut state);
        state.start_custody_for(&[ID; 32]);
        assert!(state.pending_custody.contains_key(&store_vk().to_bytes()));
        assert_eq!(purpose(&state), None, "one request at a time");

        state.pending_custody.clear();
        assert_eq!(purpose(&state), None, "a declined prompt is not re-asked");
    }

    /// A store with a custody request in flight gets no second one, even for
    /// a backer not yet attempted (its backing changed mid-request).
    /// Mutated red by removing the in-flight check.
    #[test]
    fn a_store_with_a_request_in_flight_gets_no_second_one() {
        let mut state = backed_store();
        register(&mut state);
        state.pending_custody.insert(
            store_vk().to_bytes(),
            CustodyRequest {
                store_contract_id: vec![ID; 32],
                backer: [0; 32],
                fingerprint: "another".into(),
                purpose: CustodyPurpose::Wrap,
                request_id: None,
            },
        );
        assert_eq!(purpose(&state), None);
    }

    /// A device that does not hold the key can recover through a backer
    /// that is not the current one, as long as its backing is not retired;
    /// wrapping is only ever for the current backer (#99 review). Mutated
    /// red by considering the current backer alone.
    #[test]
    fn recovery_can_use_any_unretired_backer() {
        const OLD: u8 = 0x42;
        let mut state = AppState::default();
        // BACKER is current (higher block); OLD backed it earlier.
        load_backed(
            &mut state,
            ID,
            STORE,
            vec![
                signed_backing(STORE, BACKER, 10),
                signed_backing(STORE, OLD, 5),
            ],
        );
        let old = SigningKey::from_bytes(&[OLD; 32]).verifying_key();
        state.ghostkeys.push(ghostkey_common::GhostKeyInfo {
            fingerprint: "fp-old".to_string(),
            label: None,
            notary_info: String::new(),
            verifying_key_bytes: Some(old.to_bytes().to_vec()),
            backed_up: false,
        });
        let copy = StoreKeyCopy {
            store: store_vk(),
            backer: old,
            scope: WrapScope::current(),
            wrapped: wrapped(),
        };
        let (scoped_payload, signature) = sign(&SigningKey::from_bytes(&[STORE; 32]), &copy);
        state
            .browsing_stores
            .get_mut(&vec![ID; 32])
            .unwrap()
            .backing_state
            .copies
            .records
            .insert(
                AuthorizedCopy::slot_for(&old, &WrapScope::current()),
                AuthorizedCopy {
                    copy,
                    scoped_payload,
                    signature,
                },
            );
        let request = state.custody_needed(&[ID; 32]).expect("recovers");
        assert_eq!(request.backer, old.to_bytes());
        assert_eq!(request.fingerprint, "fp-old");
        assert_eq!(request.purpose, CustodyPurpose::Recover(wrapped()));

        // Holding the key, the old backer is not wrapped for.
        register(&mut state);
        assert_eq!(purpose(&state), None, "the current backer is not connected");
    }

    /// Custody waits while anything else waits on the vault, and counts as
    /// the seller's own vault work while it waits (#99 review). Mutated red
    /// by dropping the deferral and by not counting custody.
    #[test]
    fn custody_is_the_only_vault_prompt_while_it_waits() {
        let mut state = backed_store();
        register(&mut state);
        state
            .pending_signatures
            .push_back(crate::backing_flow::tests::pending_backing_statement());
        state.start_custody_for(&[ID; 32]);
        assert!(
            state.pending_custody.is_empty(),
            "deferred behind the vault"
        );
        assert!(
            state.custody_attempted.is_empty(),
            "deferred, not recorded as tried"
        );

        state.pending_signatures.clear();
        state.start_custody_where_needed();
        assert!(
            !state.pending_custody.is_empty(),
            "started once the vault is free"
        );
        assert!(
            state.user_signature_under_way(),
            "and counts as the seller's"
        );
    }

    /// A listing waiting on its certificate holds custody back, and the
    /// certificate's arrival starts it again: nothing else necessarily
    /// would, and backup or recovery would then wait for a reload (#118
    /// review).
    ///
    /// Mutated red by removing `start_custody_where_needed` from the
    /// `Certificate` arm.
    #[test]
    fn a_certificate_arriving_starts_custody_deferred_behind_a_listing() {
        let mut state = backed_store();
        register(&mut state);
        state
            .listings_awaiting_certificate
            .push(crate::state::ListingAwaitingCertificate {
                since_ms: crate::state::now_ms(),
                pending: crate::state::PendingListing {
                    fingerprint: FINGERPRINT.to_string(),
                    listing: harvest_common::listing::Listing {
                        checkout: None,
                        choices: Vec::new(),
                        id: harvest_common::listing::ListingId([0; 32]),
                        title: "Beans".to_string(),
                        description: String::new(),
                        kind: harvest_common::listing::ListingKind::Sale,
                        price: None,
                        created_at: chrono::Utc::now(),
                    }
                    .with_derived_id(),
                    store_contract_id: Some(vec![ID; 32]),
                    certificate_pem: String::new(),
                },
            });
        state.start_custody_where_needed();
        assert!(
            state.pending_custody.is_empty(),
            "deferred behind the listing"
        );

        state.on_ghostkey_response(ghostkey_common::GhostkeyResponse::Certificate {
            fingerprint: FINGERPRINT.to_string(),
            certificate_pem: "CERT".to_string(),
        });
        assert!(state.listings_awaiting_certificate.is_empty());
        assert!(
            !state.pending_custody.is_empty(),
            "started once the vault is free"
        );
    }

    /// Custody is decided again when the Ghost Keys connected to the tab
    /// arrive, not only when store state does (#99 review). Mutated red by
    /// removing the call from the `GhostKeyList` arm.
    #[test]
    fn a_ghost_key_list_starts_custody() {
        let mut state = backed_store();
        register(&mut state);
        let keys = state.ghostkeys.clone();
        state.ghostkeys.clear();
        state.start_custody_where_needed();
        assert!(state.pending_custody.is_empty());
        state.on_ghostkey_response(ghostkey_common::GhostkeyResponse::GhostKeyList { keys });
        assert!(!state.pending_custody.is_empty());
    }

    /// Custody is decided again when the store registrations arrive: a
    /// store list naming the store's key makes this device a holder, so the
    /// key is wrapped (#99 review). Mutated red by removing the call from
    /// the `StoreList` arm.
    #[test]
    fn a_store_list_starts_custody() {
        let mut state = backed_store();
        state.start_custody_where_needed();
        assert!(state.pending_custody.is_empty(), "not held, no copy");
        state.on_delegate_response(HarvestDelegateResponse::StoreList {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            stores: vec![StoreRegistration {
                store_contract_id: vec![ID; 32],
                reputation_contract_id: vec![ID + 1; 32],
                mailbox_contract_id: vec![ID + 2; 32],
                store_contract_key: None,
                store_verifying_key: Some(store_vk().to_bytes()),
            }],
            held_store_keys: Some(vec![store_vk().to_bytes()]),
        });
        assert_eq!(
            state
                .pending_custody
                .get(&store_vk().to_bytes())
                .map(|r| r.purpose.clone()),
            Some(CustodyPurpose::Wrap)
        );
    }

    /// The store list for a device whose delegate re-keyed: the registration
    /// came across (harvest#123), the key did not, and the delegate says so.
    fn store_list_holding(held: Vec<[u8; 32]>) -> HarvestDelegateResponse {
        HarvestDelegateResponse::StoreList {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            stores: vec![StoreRegistration {
                store_contract_id: vec![ID; 32],
                reputation_contract_id: vec![ID + 1; 32],
                mailbox_contract_id: vec![ID + 2; 32],
                store_contract_key: None,
                store_verifying_key: Some(store_vk().to_bytes()),
            }],
            held_store_keys: Some(held),
        }
    }

    /// harvest#138 F1: a store registered here whose key the delegate does
    /// NOT hold is recovered from its copy, not wrapped. Deciding on the
    /// registration, the device wrapped (refused: no key) or, with a copy
    /// already published, did nothing, so it never recovered and could sign
    /// nothing for its own store after a delegate re-key. Reproduced live
    /// against the published main: `f1-repro-main.txt` in the PR.
    ///
    /// Mutated red by deciding on the registration alone again.
    #[test]
    fn a_registered_store_whose_key_is_not_held_is_recovered() {
        // Copy published, key lost: recover it.
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.on_delegate_response(store_list_holding(Vec::new()));
        assert_eq!(state.store_owner_key(&[ID; 32]), Some(store_vk()));
        assert_eq!(
            state
                .pending_custody
                .get(&store_vk().to_bytes())
                .map(|r| r.purpose.clone()),
            Some(CustodyPurpose::Recover(wrapped()))
        );

        // No copy anywhere, key lost: nothing can be done, and wrapping a key
        // the delegate lacks is not tried.
        let mut state = backed_store();
        state.on_delegate_response(store_list_holding(Vec::new()));
        assert!(state.pending_custody.is_empty());

        // The same store list saying the key IS held, with the copy there:
        // nothing to do, as before.
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.on_delegate_response(store_list_holding(vec![store_vk().to_bytes()]));
        assert!(state.pending_custody.is_empty());
    }

    /// One store list, two stores: each key's held state is its own
    /// (harvest#138 review). Mutated red by applying one answer to every key.
    #[test]
    fn a_store_list_records_each_keys_held_state_on_its_own() {
        let mut state = AppState::default();
        let other = SigningKey::from_bytes(&[0x72; 32])
            .verifying_key()
            .to_bytes();
        state.on_delegate_response(HarvestDelegateResponse::StoreList {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            stores: vec![
                StoreRegistration {
                    store_contract_id: vec![ID; 32],
                    reputation_contract_id: vec![ID + 1; 32],
                    mailbox_contract_id: vec![ID + 2; 32],
                    store_contract_key: None,
                    store_verifying_key: Some(store_vk().to_bytes()),
                },
                StoreRegistration {
                    store_contract_id: vec![9; 32],
                    reputation_contract_id: vec![10; 32],
                    mailbox_contract_id: vec![11; 32],
                    store_contract_key: None,
                    store_verifying_key: Some(other),
                },
            ],
            held_store_keys: Some(vec![other]),
        });
        assert!(!state.holds_store_key(&store_vk().to_bytes()));
        assert!(state.holds_store_key(&other));
    }

    /// A registered store whose key this device lacks, with nothing custody
    /// can recover it from, is SAID, once per session, rather than left to a
    /// refused signature (harvest#138 review). Mutated red by removing the
    /// call and by removing the once-only guard.
    #[test]
    fn an_unrecoverable_store_key_is_said_once() {
        let mut state = backed_store();
        state.on_delegate_response(store_list_holding(Vec::new()));
        let said = |state: &AppState| {
            state
                .notifications
                .iter()
                .filter(|n| n.contains("does not hold your store's key"))
                .count()
        };
        assert_eq!(said(&state), 1);
        state.start_custody_where_needed();
        state.start_custody_where_needed();
        assert_eq!(said(&state), 1, "once per session");

        // Held, or recoverable: nothing said.
        let mut state = backed_store();
        state.on_delegate_response(store_list_holding(vec![store_vk().to_bytes()]));
        add_copy(&mut state, WrapScope::current());
        state.start_custody_where_needed();
        assert_eq!(said(&state), 0);
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.on_delegate_response(store_list_holding(Vec::new()));
        assert_eq!(said(&state), 0, "recovering instead");
    }

    /// A recovery that succeeds after its request was given up still says the
    /// delegate holds the key (harvest#138 review). Mutated red by marking
    /// held only for a matched answer.
    #[test]
    fn a_late_recovery_answer_still_marks_the_key_held() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.on_delegate_response(store_list_holding(Vec::new()));
        // A late answer while a DIFFERENT attempt is live leaves it alone.
        state
            .pending_custody
            .get_mut(&store_vk().to_bytes())
            .expect("an attempt is live")
            .request_id = Some(5);
        state.store_subkeys_requested.clear();
        let recovered = |state: &AppState| {
            state
                .notifications
                .iter()
                .filter(|n| n.contains("Recovered your store's key"))
                .count()
        };
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 77,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(()),
        });
        assert!(state.holds_store_key(&store_vk().to_bytes()));
        assert!(
            state.pending_custody.contains_key(&store_vk().to_bytes()),
            "the live attempt is left to its own answer"
        );
        // The follow-up runs on the transition to held, once (rounds 2-4).
        assert_eq!(recovered(&state), 1);
        assert!(state
            .store_subkeys_requested
            .contains(&store_vk().to_bytes()));
        // The live attempt then fails: not news, and not said.
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 5,
            store_verifying_key: store_vk().to_bytes(),
            result: Err("the vault refused".into()),
        });
        assert!(state.pending_custody.is_empty());
        assert!(!state
            .notifications
            .iter()
            .any(|n| n.contains("could not be recovered")));
        // A live attempt that then times out is not "did not finish" either.
        state.pending_custody.insert(
            store_vk().to_bytes(),
            CustodyRequest {
                store_contract_id: vec![ID; 32],
                backer: backer_vk().to_bytes(),
                fingerprint: FINGERPRINT.to_string(),
                purpose: CustodyPurpose::Recover(wrapped()),
                request_id: Some(9),
            },
        );
        state.custody_started_ms.insert(store_vk().to_bytes(), 0);
        state.expire_custody(CUSTODY_TIMEOUT_MS);
        assert!(!state
            .notifications
            .iter()
            .any(|n| n.contains("did not finish")));
        // A further success is not said twice.
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 6,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(()),
        });
        assert_eq!(recovered(&state), 1);
    }

    /// An UNREGISTERED store is not made this device's by a late success,
    /// so a live attempt's failure afterwards is still said (round 5).
    /// Mutated red by hiding every failure once the key is held.
    #[test]
    fn an_unregistered_stores_failure_is_said_after_a_late_success() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.start_custody_for(&[ID; 32]);
        sent_under(&mut state, store_vk().to_bytes(), 5);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 77,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(()),
        });
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 5,
            store_verifying_key: store_vk().to_bytes(),
            result: Err("bad copy".into()),
        });
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("could not be recovered")));

        // And the same for a timeout instead of a failure.
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.start_custody_for(&[ID; 32]);
        sent_under(&mut state, store_vk().to_bytes(), 5);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 77,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(()),
        });
        state.expire_custody(u64::MAX);
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("did not finish")));
    }

    /// A recovery that was tried and failed, with the copy there and the
    /// backer connected, is not told to "connect the Ghost Key": it has its
    /// own message (harvest#138 review, round 2). Mutated red by ignoring
    /// whether a connected backer has a copy.
    #[test]
    fn a_failed_recovery_is_not_called_unrecoverable() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.on_delegate_response(store_list_holding(Vec::new()));
        sent_under(&mut state, store_vk().to_bytes(), 0);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 0,
            store_verifying_key: store_vk().to_bytes(),
            result: Err("the vault refused".into()),
        });
        state.start_custody_where_needed();
        assert!(
            !state
                .notifications
                .iter()
                .any(|n| n.contains("does not hold your store's key")),
            "{:?}",
            state.notifications
        );
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("could not be recovered")));
    }

    /// The registration is found by its KEY: a store migration that rewrote
    /// its contract id while the vault prompt was open does not make the
    /// recovery rebuild it (harvest#138 review). Mutated red by matching on
    /// the contract id the request named.
    #[test]
    fn a_registration_moved_to_a_new_contract_id_is_still_kept() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.on_delegate_response(store_list_holding(Vec::new()));
        sent_under(&mut state, store_vk().to_bytes(), 0);
        // With its details loaded, so a rebuilt registration WOULD be made.
        state.browsing_stores.get_mut(&vec![ID; 32]).unwrap().info =
            Some(harvest_common::store::StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: FINGERPRINT.to_string(),
                reputation_contract_id: [0x0e; 32],
                store_name: "Bean Shop".to_string(),
                description: String::new(),
                encryption_public_key: None,
                record_public_key: None,
            });
        state.my_stores.get_mut(FINGERPRINT).unwrap()[0].store_contract_id = vec![0x3d; 32];
        let before = state.my_stores[FINGERPRINT].clone();
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 0,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(()),
        });
        assert_eq!(state.my_stores[FINGERPRINT], before);
    }

    /// Buyers' messages that could not be opened while the key was missing
    /// are asked about again once it is recovered (harvest#138 review).
    /// Mutated red by not asking.
    #[test]
    fn recovering_a_registered_stores_key_asks_for_its_conversation_keys_again() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.on_delegate_response(store_list_holding(Vec::new()));
        state
            .browsing_stores
            .get_mut(&vec![ID; 32])
            .unwrap()
            .mailbox_messages
            .push(harvest_common::mailbox::EncryptedMessage {
                conversation_id: harvest_common::mailbox::ConversationId([4; 32]),
                sender_public_key: vec![0x55; 32],
                ciphertext: vec![1, 2, 3],
                timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                nonce: [0; 24],
            });
        state.pending_conversation_key_requests.clear();
        sent_under(&mut state, store_vk().to_bytes(), 0);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 0,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(()),
        });
        assert!(
            state
                .pending_conversation_key_requests
                .values()
                .any(|asked| asked.contains(&vec![0x55; 32])),
            "{:?}",
            state.pending_conversation_key_requests
        );
    }

    /// A store list from a delegate that predates `held_store_keys` says
    /// nothing about holding, and the registration is taken as held, which
    /// is what every earlier build did (harvest#138). Mutated red by reading
    /// the missing field as "none held".
    #[test]
    fn a_store_list_that_says_nothing_about_holding_leaves_the_key_held() {
        let mut state = backed_store();
        state.on_delegate_response(HarvestDelegateResponse::StoreList {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            stores: vec![StoreRegistration {
                store_contract_id: vec![ID; 32],
                reputation_contract_id: vec![ID + 1; 32],
                mailbox_contract_id: vec![ID + 2; 32],
                store_contract_key: None,
                store_verifying_key: Some(store_vk().to_bytes()),
            }],
            held_store_keys: None,
        });
        assert!(state.holds_store_key(&store_vk().to_bytes()));
        assert_eq!(
            state
                .pending_custody
                .get(&store_vk().to_bytes())
                .map(|r| r.purpose.clone()),
            Some(CustodyPurpose::Wrap)
        );
    }

    /// Recovering the key of a store that is already registered here keeps
    /// the registration it has (harvest#138): it names the store's real
    /// mailbox, where a rebuilt one would derive it from the recovering
    /// backer. The key is then held, so custody neither recovers nor wraps
    /// again. Mutated red by rebuilding the registration and by not marking
    /// the key held.
    #[test]
    fn recovering_a_registered_stores_key_keeps_its_registration() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.on_delegate_response(store_list_holding(Vec::new()));
        let before = state.my_stores[FINGERPRINT].clone();
        let request_id = state
            .pending_custody
            .get(&store_vk().to_bytes())
            .expect("recovery started")
            .request_id;
        assert_eq!(request_id, None, "not sent yet");
        sent_under(&mut state, store_vk().to_bytes(), 0);

        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 0,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(()),
        });

        assert_eq!(state.my_stores[FINGERPRINT], before);
        assert!(state.holds_store_key(&store_vk().to_bytes()));
        assert!(state.pending_custody.is_empty());
        state.custody_attempted.clear();
        assert_eq!(
            state.custody_needed(&[ID; 32]),
            None,
            "held, copy published"
        );
        assert!(state
            .store_subkeys_requested
            .contains(&store_vk().to_bytes()));
    }

    /// A custody request that nothing answers is given up after
    /// `CUSTODY_TIMEOUT_MS`, and the seller told, so it does not hold the
    /// vault for the session (#99 re-check). Mutated red by keeping it.
    #[test]
    fn an_unanswered_custody_request_times_out() {
        let mut state = backed_store();
        register(&mut state);
        state.start_custody_for(&[ID; 32]);
        let started = state.custody_started_ms[&store_vk().to_bytes()];
        state.expire_custody(started + CUSTODY_TIMEOUT_MS - 1);
        assert!(!state.pending_custody.is_empty(), "not yet");
        state.expire_custody(started + CUSTODY_TIMEOUT_MS);
        assert!(state.pending_custody.is_empty());
        assert!(!state.user_signature_under_way(), "the vault is free again");
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("did not finish")));
    }

    /// Store details that arrive after the subkeys are checked too, and the
    /// block lifts when a later check agrees (#99 re-check). Mutated red by
    /// not re-checking, and by never clearing the block.
    #[test]
    fn a_record_key_block_follows_the_published_details() {
        let mut state = backed_store();
        state.on_delegate_response(subkeys(vec![9, 9, 9]));
        assert!(
            state.record_key_mismatch.is_empty(),
            "nothing published yet"
        );

        let set_published = |state: &mut AppState, key: Vec<u8>| {
            state.browsing_stores.get_mut(&vec![ID; 32]).unwrap().info =
                Some(harvest_common::store::StoreInfoV1 {
                    version: 1,
                    certificate_pem: String::new(),
                    seller_fingerprint: FINGERPRINT.to_string(),
                    reputation_contract_id: [0x0e; 32],
                    store_name: "Bean Shop".to_string(),
                    description: String::new(),
                    encryption_public_key: None,
                    record_public_key: Some(key),
                });
        };
        set_published(&mut state, vec![1, 2, 3]);
        state.recheck_record_key(&[ID; 32]);
        assert!(state.record_key_mismatch.contains(&store_vk().to_bytes()));

        set_published(&mut state, vec![9, 9, 9]);
        state.recheck_record_key(&[ID; 32]);
        assert!(state.record_key_mismatch.is_empty(), "lifted");
    }

    /// `fill_creation_from_subkeys` says whether it FILLED a creation, not
    /// whether the subkeys exist (#101 review): a creation for another
    /// store is not filled, and the caller must go on to ask. Mutated red
    /// by answering true for a creation of a different store.
    #[test]
    fn filling_a_creation_answers_whether_it_filled_one() {
        let mut state = backed_store();
        let other = SigningKey::from_bytes(&[0x7e; 32])
            .verifying_key()
            .to_bytes();
        state.store_subkeys.insert(
            other,
            harvest_common::delegate::StoreSubkeyInfo {
                inbox_public_key: [0x1b; 32],
                record_public_key: vec![0x2e; 4],
            },
        );
        assert!(
            !state.fill_creation_from_subkeys(other),
            "no creation at all"
        );

        state.pending_store_creation = Some(crate::state::PendingStoreCreation {
            another_store: false,
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            seller_verifying_key_bytes: backer_vk().to_bytes(),
            certificate_pem: String::new(),
            store_name: "Bean Shop".into(),
            description: String::new(),
            rsa_public_key_der: None,
            encryption_public_key: None,
            store_verifying_key: Some(store_vk().to_bytes()),
            store_key_request: Some(1),
            carried_listings: Vec::new(),
        });
        assert!(
            !state.fill_creation_from_subkeys(other),
            "another store's keys fill nothing"
        );
        assert!(state
            .pending_store_creation
            .as_ref()
            .unwrap()
            .rsa_public_key_der
            .is_none());
    }

    /// A custody request taken off the pending list takes its timestamp
    /// with it, so the NEXT request for that store is not expired the
    /// moment it starts (#101 review). Mutated red by leaving the
    /// timestamp behind.
    #[test]
    fn a_finished_custody_request_leaves_no_timestamp_behind() {
        let mut state = backed_store();
        register(&mut state);
        state.start_custody_for(&[ID; 32]);
        sent_under(&mut state, store_vk().to_bytes(), 0);
        let started = state.custody_started_ms[&store_vk().to_bytes()];
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyWrapped {
            request_id: 0,
            store_verifying_key: store_vk().to_bytes(),
            result: Err("no".into()),
        });
        assert!(state.pending_custody.is_empty());
        assert!(state.custody_started_ms.is_empty(), "and its timestamp");

        // A request with no timestamp is not expired on sight.
        state.pending_custody.insert(
            store_vk().to_bytes(),
            CustodyRequest {
                store_contract_id: vec![ID; 32],
                backer: [0; 32],
                fingerprint: "fp".into(),
                purpose: CustodyPurpose::Wrap,
                request_id: None,
            },
        );
        state.expire_custody(started + CUSTODY_TIMEOUT_MS * 10);
        assert!(!state.pending_custody.is_empty(), "not a guess");
    }

    /// With no Harvest delegate registered, a wrap signature is not left
    /// waiting forever: the request is dropped and the seller told (#99
    /// review). Mutated red by removing the check.
    #[test]
    fn with_no_harvest_delegate_custody_is_dropped_and_said() {
        let mut state = backed_store();
        register(&mut state);
        state.start_custody_for(&[ID; 32]);
        state.harvest_delegate_key = None;
        state.on_ghostkey_response(wrap_sign_result());
        assert!(state.pending_custody.is_empty());
        assert!(state.custody_sent.is_empty());
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("Harvest delegate is not registered")));
    }

    /// A retired backing is the custody tombstone: a store whose only
    /// backing is retired asks for nothing, even with its copy still visible
    /// to a stale reader.
    #[test]
    fn a_store_with_no_current_backing_needs_no_custody() {
        let mut state = AppState::default();
        load_backed(&mut state, ID, STORE, Vec::new());
        connect_backer(&mut state);
        register(&mut state);
        assert_eq!(purpose(&state), None);
    }

    fn wrap_sign_result() -> ghostkey_common::GhostkeyResponse {
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                freenet_stdlib::prelude::ContractInstanceId::new(WrapScope::current().0),
            ),
            payload: custody::wrap_message(&store_vk()),
        };
        let scoped_payload = ghostkey_common::to_cbor(&scoped).expect("encode");
        let signature = SigningKey::from_bytes(&[BACKER; 32])
            .sign(&scoped_payload)
            .to_bytes()
            .to_vec();
        ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload,
            signature,
            certificate_pem: "CERT".to_string(),
        }
    }

    /// The wrap signature is a secret: it goes to the Harvest delegate and
    /// nowhere else, and never consumes a signature something else is
    /// waiting for. Mutated red by removing the `is_wrap_message` routing in
    /// the `SignResult` arm.
    #[test]
    fn a_wrap_signature_goes_to_the_delegate_and_never_to_the_signing_queue() {
        let mut state = backed_store();
        register(&mut state);
        state.start_custody_for(&[ID; 32]);
        state
            .pending_signatures
            .push_back(crate::backing_flow::tests::pending_backing_statement());

        state.on_ghostkey_response(wrap_sign_result());

        assert_eq!(state.pending_signatures.len(), 1, "the queue is untouched");
        match state.custody_sent.as_slice() {
            [HarvestDelegateRequest::WrapStoreKeyFor {
                store_verifying_key,
                backer_verifying_key,
                ..
            }] => {
                assert_eq!(*store_verifying_key, store_vk().to_bytes());
                assert_eq!(*backer_verifying_key, backer_vk().to_bytes());
            }
            other => panic!("expected one WrapStoreKeyFor, got {other:?}"),
        }
    }

    /// A wrap signature nobody asked for is dropped, not forwarded.
    #[test]
    fn an_unrequested_wrap_signature_is_dropped() {
        let mut state = backed_store();
        state.on_ghostkey_response(wrap_sign_result());
        assert!(state.custody_sent.is_empty());
    }

    /// The same signature on a device without the key asks the delegate to
    /// unwrap the copy the store holds.
    #[test]
    fn recovery_sends_the_stores_copy_to_unwrap() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.start_custody_for(&[ID; 32]);
        state.on_ghostkey_response(wrap_sign_result());
        match state.custody_sent.as_slice() {
            [HarvestDelegateRequest::UnwrapStoreKey { wrapped: sent, .. }] => {
                assert_eq!(*sent, wrapped())
            }
            other => panic!("expected one UnwrapStoreKey, got {other:?}"),
        }
    }

    /// A recovered key makes the store this device's again: registered under
    /// its backer, with its store key, its published record and the mailbox
    /// its backer addresses. Mutated red by skipping the merge.
    #[test]
    fn a_recovered_store_is_registered_again() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.browsing_stores.get_mut(&vec![ID; 32]).unwrap().info =
            Some(harvest_common::store::StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: FINGERPRINT.to_string(),
                reputation_contract_id: [0x0e; 32],
                store_name: "Bean Shop".to_string(),
                description: String::new(),
                encryption_public_key: None,
                record_public_key: None,
            });
        state.start_custody_for(&[ID; 32]);
        sent_under(&mut state, store_vk().to_bytes(), 0);
        assert_eq!(state.store_owner_key(&[ID; 32]), None);

        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 0,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(()),
        });

        assert_eq!(state.store_owner_key(&[ID; 32]), Some(store_vk()));
        let registration = &state.my_stores[FINGERPRINT][0];
        assert_eq!(registration.reputation_contract_id, vec![0x0e; 32]);
        let mailbox = crate::gateway::mailbox_ops::mailbox_contract_key(&backer_vk())
            .unwrap()
            .id()
            .as_bytes()
            .to_vec();
        assert_eq!(registration.mailbox_contract_id, mailbox);
        assert!(state.pending_custody.is_empty());
        assert!(
            state
                .store_subkeys_requested
                .contains(&store_vk().to_bytes()),
            "the recovered key's record key is checked against the published one"
        );
    }

    /// A subkeys request that cannot be SENT releases a creation waiting on
    /// it (#101 re-review B4). Before this, only the marker was cleared, so
    /// `store_creation_in_flight` stayed set and `begin_store_creation`
    /// refused every later attempt for the session.
    ///
    /// Mutated red by dropping the `store_creation_failed` call, and by
    /// dropping the `store_subkeys_requested.remove`.
    #[test]
    fn a_subkeys_send_failure_releases_the_creation() {
        let mut state = AppState::default();
        state.store_creation_in_flight = Some("fp".to_string());
        state.pending_store_creation = Some(crate::state::PendingStoreCreation {
            another_store: false,
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            seller_verifying_key_bytes: backer_vk().to_bytes(),
            certificate_pem: String::new(),
            store_name: "Bean Shop".into(),
            description: String::new(),
            rsa_public_key_der: None,
            encryption_public_key: None,
            store_verifying_key: Some(store_vk().to_bytes()),
            store_key_request: Some(1),
            carried_listings: Vec::new(),
        });
        state.store_subkeys_requested.insert(store_vk().to_bytes());

        state.on_subkeys_request_failed(store_vk().to_bytes(), "the delegate is not registered");

        assert!(
            state.store_creation_in_flight.is_none(),
            "a creation that can never finish must not hold the single-flight marker"
        );
        assert!(state.pending_store_creation.is_none());
        assert!(
            !state
                .store_subkeys_requested
                .contains(&store_vk().to_bytes()),
            "a retry must be able to ask again"
        );
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("not registered")));
    }

    /// The same failure with no creation waiting says so and asks nothing
    /// else to fail: a custody check or an edit wanted the keys.
    #[test]
    fn a_subkeys_send_failure_without_a_creation_only_reports() {
        let mut state = AppState::default();
        state.store_subkeys_requested.insert(store_vk().to_bytes());
        state.on_subkeys_request_failed(store_vk().to_bytes(), "could not reach the delegate");
        assert!(state.store_creation_in_flight.is_none());
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("could not reach the delegate")));
    }

    /// Custody runs one store at a time, and the NEXT one starts when the
    /// first answers (#101 re-review S3). `start_custody_for` refuses while
    /// any custody request is pending, so `start_custody_where_needed`
    /// starts exactly one; without the restart in the response handlers the
    /// rest waited for an unrelated event or a reload.
    ///
    /// Mutated red by removing the `start_custody_where_needed()` call from
    /// `on_store_key_wrapped`.
    #[test]
    fn the_next_store_s_custody_starts_when_the_first_answers() {
        const ID2: u8 = 2;
        const STORE2: u8 = 0x72;
        let store2_vk = SigningKey::from_bytes(&[STORE2; 32]).verifying_key();

        let mut state = backed_store();
        register(&mut state);
        // A second store under the same Ghost Key, also held by this device.
        load_backed(
            &mut state,
            ID2,
            STORE2,
            vec![signed_backing(STORE2, BACKER, 10)],
        );
        state
            .my_stores
            .get_mut(FINGERPRINT)
            .unwrap()
            .push(StoreRegistration {
                store_contract_id: vec![ID2; 32],
                reputation_contract_id: vec![ID2 + 1; 32],
                mailbox_contract_id: vec![ID2 + 2; 32],
                store_contract_key: None,
                store_verifying_key: Some(store2_vk.to_bytes()),
            });

        state.start_custody_where_needed();
        assert_eq!(
            state.pending_custody.len(),
            1,
            "one vault prompt at a time (#99 review)"
        );
        let first = *state.pending_custody.keys().next().unwrap();
        let second = if first == store_vk().to_bytes() {
            store2_vk.to_bytes()
        } else {
            store_vk().to_bytes()
        };

        // The first answers. The second must then start on its own.
        // The id is what the sent request went out under; set it as
        // `on_wrap_signature` would.
        state.pending_custody.get_mut(&first).unwrap().request_id = Some(7);
        state.on_store_key_wrapped(first, 7, Err("no".into()));
        assert!(
            state.pending_custody.contains_key(&second),
            "the deferred store's custody must start when the vault frees up"
        );
    }

    /// **Custody does not act on a generation this session moved our store
    /// away from (harvest#164).** It stays loaded with stale state, and
    /// asking the vault to wrap or recover for it would put up a prompt on
    /// every load. Mutated red by dropping the check.
    #[test]
    fn custody_leaves_an_earlier_generation_alone() {
        let mut state = backed_store();
        register(&mut state);
        assert!(
            state.custody_needed(&[ID; 32]).is_some(),
            "precondition: this store calls for custody"
        );
        // The session moved the store on; the earlier id stays loaded.
        state
            .migrated_contract_ids
            .insert(vec![ID; 32], vec![0x77; 32]);
        assert!(state.custody_needed(&[ID; 32]).is_none());
    }

    /// The same for an edit parked under the store's earlier id and failing
    /// after this session moved the store (harvest#164): the release finds
    /// it by that id. Mutated red by an exact-id owner lookup.
    #[test]
    fn a_subkeys_failure_releases_an_edit_parked_while_moving() {
        let (earlier, current) = crate::state::test_store_generations();
        let mut state = crate::state::AppState::default();
        state.my_stores.insert(
            FINGERPRINT.to_string(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: earlier.clone(),
                reputation_contract_id: vec![2; 32],
                mailbox_contract_id: vec![3; 32],
                store_contract_key: None,
                store_verifying_key: Some(crate::state::test_store_key()),
            }],
        );
        state.pending_store_edit = Some(crate::state::PendingStoreEdit {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            store_contract_id: earlier.clone(),
            reputation_contract_id: [2; 32],
            next_version: 4,
            details: Default::default(),
        });
        state
            .store_subkeys_requested
            .insert(crate::state::test_store_key());
        state.adopt_migrated_contract_id(&earlier, current);
        state.on_subkeys_request_failed(crate::state::test_store_key(), "no key here");
        assert!(state.pending_store_edit.is_none());
    }

    /// A subkeys failure releases a parked EDIT, not just a creation (#101
    /// re-review, lens B).
    ///
    /// This is the dangerous one: `pending_store_edit.is_some()` feeds
    /// `user_signature_under_way()`, which gates `vault_work_outstanding()`,
    /// so an edit nothing releases stops all custody and all watch requests
    /// for the session. There is no timeout on it.
    ///
    /// Mutated red by dropping the edit release from
    /// `release_waiters_on_subkeys`, for both the send failure and the
    /// delegate's error.
    #[test]
    fn a_subkeys_failure_releases_a_parked_edit_and_unblocks_the_vault() {
        for delegate_answered in [false, true] {
            let mut state = backed_store();
            register(&mut state);
            state.pending_store_edit = Some(crate::state::PendingStoreEdit {
                ghostkey_fingerprint: FINGERPRINT.to_string(),
                store_contract_id: vec![ID; 32],
                reputation_contract_id: [2; 32],
                next_version: 4,
                details: Default::default(),
            });
            state.store_subkeys_requested.insert(store_vk().to_bytes());
            assert!(
                state.user_signature_under_way(),
                "a parked edit holds the vault"
            );

            if delegate_answered {
                state.on_store_subkeys(store_vk().to_bytes(), Err("no key here".into()));
            } else {
                state.on_subkeys_request_failed(store_vk().to_bytes(), "no key here");
            }

            assert!(
                state.pending_store_edit.is_none(),
                "the edit must be released (delegate_answered = {delegate_answered})"
            );
            assert!(
                !state.user_signature_under_way(),
                "and the vault must be free again (delegate_answered = {delegate_answered})"
            );
            assert!(
                state
                    .notifications
                    .iter()
                    .any(|n| n.contains("no key here")),
                "and the seller must be told (delegate_answered = {delegate_answered})"
            );
        }
    }

    /// A custody request that fails to SEND is retried, a bounded number of
    /// times, and then stops and says so once (#101 re-review, marker sweep).
    ///
    /// Before this, one failed send left `custody_attempted` set and
    /// store-key backup was off for the session. Mutated red by dropping the
    /// `custody_attempted.remove`, and by removing the cap.
    #[test]
    fn a_custody_send_failure_retries_a_bounded_number_of_times() {
        let mut state = backed_store();
        register(&mut state);
        let key = (store_vk().to_bytes(), backer_vk().to_bytes());

        for attempt in 1..MAX_CUSTODY_SEND_ATTEMPTS {
            state.start_custody_for(&[ID; 32]);
            assert!(
                state.pending_custody.contains_key(&store_vk().to_bytes()),
                "attempt {attempt} must start"
            );
            state.on_custody_send_failed(store_vk().to_bytes(), "no delegate");
            assert!(
                !state.custody_attempted.contains(&key),
                "attempt {attempt} must be retryable"
            );
            assert!(
                state.notifications.is_empty(),
                "and must not nag on attempt {attempt}"
            );
        }

        // The last permitted attempt gives up and says so, once.
        state.start_custody_for(&[ID; 32]);
        state.on_custody_send_failed(store_vk().to_bytes(), "no delegate");
        assert!(
            state.custody_attempted.contains(&key),
            "past the cap it stops retrying"
        );
        assert_eq!(
            state
                .notifications
                .iter()
                .filter(|n| n.contains("no delegate"))
                .count(),
            1,
            "and says so exactly once"
        );

        // Nothing restarts it, and nothing says it again.
        state.start_custody_where_needed();
        assert!(state.pending_custody.is_empty());
    }

    /// A late answer to a custody attempt that has already timed out does
    /// NOT consume the attempt that replaced it (#101 re-review, Codex P2).
    ///
    /// The delegate answers by store key, and a store can have a second
    /// attempt under a different backer once the first expires. Matching by
    /// store key alone let the stale error cancel the live attempt, and a
    /// stale success register the wrong backer -- which is what the mailbox
    /// is derived from. Mutated red by matching on the store key alone.
    #[test]
    fn a_late_custody_answer_does_not_consume_the_next_attempt() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.start_custody_for(&[ID; 32]);
        // Attempt A is sent under id 1.
        state
            .pending_custody
            .get_mut(&store_vk().to_bytes())
            .unwrap()
            .request_id = Some(1);
        // It times out; attempt B replaces it, sent under id 2.
        state.take_custody(&store_vk().to_bytes());
        state.custody_attempted.clear();
        state.start_custody_for(&[ID; 32]);
        state
            .pending_custody
            .get_mut(&store_vk().to_bytes())
            .unwrap()
            .request_id = Some(2);

        // A's answer arrives late. It must be ignored.
        state.on_store_key_recovered(store_vk().to_bytes(), 1, Err("stale".into()));
        assert!(
            state.pending_custody.contains_key(&store_vk().to_bytes()),
            "a stale answer must not cancel the live attempt"
        );
        assert!(state.my_stores.is_empty(), "and must not register anything");

        // B's own answer settles it.
        state.on_store_key_recovered(store_vk().to_bytes(), 2, Err("real".into()));
        assert!(state.pending_custody.is_empty());
        assert!(state.notifications.iter().any(|n| n.contains("real")));
    }

    /// A failed recovery registers nothing and says so.
    #[test]
    fn a_failed_recovery_registers_nothing() {
        let mut state = backed_store();
        add_copy(&mut state, WrapScope::current());
        state.start_custody_for(&[ID; 32]);
        sent_under(&mut state, store_vk().to_bytes(), 0);
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyRecovered {
            request_id: 0,
            store_verifying_key: store_vk().to_bytes(),
            result: Err("wrong key".into()),
        });
        assert!(state.my_stores.is_empty());
        assert!(state.notifications.iter().any(|n| n.contains("wrong key")));
    }

    /// A wrapped copy is published to the store it came from.
    #[test]
    fn a_wrapped_copy_is_published() {
        let mut state = backed_store();
        register(&mut state);
        state.start_custody_for(&[ID; 32]);
        sent_under(&mut state, store_vk().to_bytes(), 0);
        let copy = AuthorizedCopy {
            copy: StoreKeyCopy {
                store: store_vk(),
                backer: backer_vk(),
                scope: WrapScope::current(),
                wrapped: wrapped(),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
        };
        state.on_delegate_response(HarvestDelegateResponse::StoreKeyWrapped {
            request_id: 0,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(Box::new(copy.clone())),
        });
        assert_eq!(state.copies_to_publish, vec![(vec![ID; 32], copy)]);
    }

    fn subkeys(record: Vec<u8>) -> HarvestDelegateResponse {
        HarvestDelegateResponse::StoreSubkeys {
            request_id: 0,
            store_verifying_key: store_vk().to_bytes(),
            result: Ok(harvest_common::delegate::StoreSubkeyInfo {
                inbox_public_key: [0x1b; 32],
                record_public_key: record,
            }),
        }
    }

    /// A device that derives a different record key from the one the store
    /// publishes says so; one that agrees says nothing. Mutated red by
    /// removing the comparison.
    #[test]
    fn a_record_key_that_disagrees_with_the_published_one_is_reported() {
        for (derived, warned) in [(vec![1, 2, 3], false), (vec![9, 9, 9], true)] {
            let mut state = backed_store();
            state.browsing_stores.get_mut(&vec![ID; 32]).unwrap().info =
                Some(harvest_common::store::StoreInfoV1 {
                    version: 1,
                    certificate_pem: String::new(),
                    seller_fingerprint: FINGERPRINT.to_string(),
                    reputation_contract_id: [0x0e; 32],
                    store_name: "Bean Shop".to_string(),
                    description: String::new(),
                    encryption_public_key: None,
                    record_public_key: Some(vec![1, 2, 3]),
                });
            state.on_delegate_response(subkeys(derived));
            assert_eq!(
                state
                    .notifications
                    .iter()
                    .any(|n| n.contains("different record key")),
                warned
            );
            assert_eq!(
                state.record_key_mismatch.contains(&store_vk().to_bytes()),
                warned,
                "and a mismatch blocks publishing (#99 review)"
            );
        }
    }
}
