//! Reading and keeping up each Ghost Key's index (harvest#93, phase 1c).
//!
//! # ONLY the user's own Ghost Keys
//!
//! This tab reads the index of a Ghost Key the user holds, and no other
//! (#101 review). The index's job is "my devices find my stores". Reading a
//! stranger's index, and then loading every store it lists, would let anyone
//! publish a graph of keys, indexes and stores and make a visitor's tab walk
//! it: entries are cheap to make (a certificate is only length-checked), each
//! loaded store would lead to another index, and `refresh_backing_verdicts`
//! runs over every loaded store, so the work grows faster than the graph. So
//! nothing here follows an index that is not the user's, and nothing follows
//! a store to another key's index.
//!
//! # What the index is used for here
//!
//! * **Finding the user's own stores.** For every Ghost Key connected to
//!   this tab, the UI reads the key's index and loads every store it lists.
//!   That is how a device that knows only the Ghost Key finds the stores
//!   behind it; custody (`custody_flow`) then recovers the store key from a
//!   store the key backs, which registers the store again. The Harvest
//!   delegate's store list stays, as a cache of what this device knows.
//! * **One current store per Ghost Key, for the keys the user holds.**
//!   Loading those stores is what `refresh_backing_verdicts` needs to apply
//!   decision 6.2 across them, which is the case that matters to a seller:
//!   they are the one who can retire a backing. A buyer keeps the rule over
//!   the stores their tab has loaded, as before; a buyer never enumerates a
//!   seller's other stores.
//! * **Keeping our own index complete.** When one of OUR stores loads (this
//!   device holds its store key) and its current backer is connected here,
//!   the store's backing statement is published into that key's index if the
//!   index does not already hold it. That covers a new store, a moved store,
//!   and every store made before the index existed (the migration of phase
//!   1a/1b stores onto the index), with no vault prompt: an entry is the
//!   backer's half of the store's own backing.
//!
//! # What an index is NOT taken for
//!
//! An entry is signed by the Ghost Key alone, so it can name any store key.
//! It is only a place to look. Whether the key backs the store, whether that
//! backing is retired and whether it is current come from the store's own
//! state, as before.

use std::collections::HashSet;

use harvest_common::ghostkey_index::{GhostKeyIndexV1, IndexEntry, IndexParameters};

use crate::state::AppState;

/// One Ghost Key's index as this tab knows it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IndexView {
    /// The Ghost Key the index belongs to.
    pub ghost_key: [u8; 32],
    /// Its state, once it has arrived and verified.
    pub index: Option<GhostKeyIndexV1>,
    /// The node answered that nothing is stored at the current index
    /// (harvest#181): no store yet, unless the key's index migration walk
    /// finds an earlier generation's.
    pub absent: bool,
}

/// How a Ghost Key's index migration walk ended, as "Create a store" needs
/// to know it (harvest#181).
#[derive(Clone, Debug, PartialEq)]
pub enum IndexWalkEnd {
    /// Every earlier generation answered and none held an index, or the
    /// delegate says the lineage was carried forward already, so the
    /// current index is the whole answer.
    Empty,
    /// An earlier generation's index was recovered. `complete` is false
    /// when some other earlier generation never answered: its stores are
    /// followed and counted, but they may not be all of them.
    Recovered {
        index: GhostKeyIndexV1,
        complete: bool,
    },
    /// Some earlier generation never answered: nothing is known, and the
    /// gate waits out [`INDEX_SETTLE_WAIT_MS`] rather than reading silence as
    /// "no store".
    Unknown,
}

/// How long My Store waits for a Ghost Key's index to settle before it
/// offers "Create a store" anyway, with a warning (harvest#181). An index
/// that never answers (silence is how Freenet often reports a contract
/// nobody published) must not keep a new seller from ever starting.
pub const INDEX_SETTLE_WAIT_MS: u32 = 60_000;

/// Whether a Ghost Key may create a store now (harvest#181, section 6.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreationGate {
    /// Nothing says it backs a store: offer "Create a store".
    Ready,
    /// Still finding out whether it already backs a store.
    Checking,
    /// A loaded store's current backing is this key: it is recovered, not
    /// created again.
    BacksStore(String),
    /// The check did not finish in time: offer it, and say so.
    Unconfirmed,
    /// The key's index lists a store (by its code) that has not loaded in
    /// the wait: the key has a store, so creation is not offered.
    ListsUnloadedStore(String),
}

/// How many times a store's index entry publish may fail before this
/// session gives up on it and tells the seller. Small on purpose: the
/// retry is driven by store-state arrivals, which are frequent.
const MAX_INDEX_PUBLISH_ATTEMPTS: u8 = 3;

impl AppState {
    /// Read `ghost_key`'s index, once per session, and keep following it.
    ///
    /// Refused for a Ghost Key the user does not hold (#101 review): see
    /// the module docs.
    pub(crate) fn watch_ghostkey_index(&mut self, ghost_key: [u8; 32]) {
        let Some(fingerprint) = self.connected_ghost_key(&ghost_key) else {
            return;
        };
        // My Store waits for the index before offering "Create a store"
        // (harvest#181), but not for ever. Started before anything below
        // can return, and kept per Ghost Key, not per view: a failed GET
        // drops the view, and a wait kept on it would be dropped too,
        // leaving "Checking" up until the vault reconnects.
        if self.index_waits_started.insert(fingerprint.clone()) {
            #[cfg(target_arch = "wasm32")]
            wasm_bindgen_futures::spawn_local(async move {
                gloo_timers::future::TimeoutFuture::new(INDEX_SETTLE_WAIT_MS).await;
                use dioxus::prelude::WritableExt;
                crate::gateway::APP_STATE
                    .write()
                    .on_index_wait_elapsed(&fingerprint);
            });
            #[cfg(not(target_arch = "wasm32"))]
            let _ = fingerprint;
        }
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&ghost_key) else {
            return;
        };
        let Ok(key) = crate::gateway::index_ops::index_contract_key(&vk) else {
            return;
        };
        let id = key.id().as_bytes().to_vec();
        if self.ghostkey_indexes.contains_key(&id) {
            return;
        }
        self.ghostkey_indexes.insert(
            id.clone(),
            IndexView {
                ghost_key,
                index: None,
                absent: false,
            },
        );
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = crate::gateway::get_contract_by_id(&id).await {
                dioxus::logger::tracing::warn!("could not read a Ghost Key's index: {e}");
                // The entry was claimed BEFORE the GET, and it is what stops
                // a second attempt. Leaving it after a failed send disabled
                // index discovery for the session on exactly the device that
                // needs it -- a fresh one, recovering (#101 re-review, Codex
                // P2 and lens B). Same defect shape as the publish marker.
                use dioxus::prelude::WritableExt;
                crate::gateway::APP_STATE.write().on_index_watch_failed(&id);
            }
        });
    }

    /// Read the index of every Ghost Key connected to this tab.
    pub(crate) fn watch_connected_indexes(&mut self) {
        let keys: Vec<[u8; 32]> = self
            .ghostkeys
            .iter()
            .filter_map(|k| k.verifying_key_bytes.as_deref())
            .filter_map(|b| <[u8; 32]>::try_from(b).ok())
            .collect();
        for key in keys {
            self.watch_ghostkey_index(key);
        }
    }

    /// If `contract_id` is a Ghost Key index this tab is following, take
    /// its state and return `true`; otherwise `false`, and the caller goes on.
    ///
    /// Routed by id, never by trying to decode: an index's CBOR is a map with
    /// one defaulted field, which a store state decode could take for an
    /// empty store.
    pub(crate) fn on_index_state(&mut self, contract_id: &[u8], state_bytes: &[u8]) -> bool {
        let Some(view) = self.ghostkey_indexes.get(contract_id) else {
            return false;
        };
        let ghost_key = view.ghost_key;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&ghost_key) else {
            return true;
        };
        let index = match harvest_common::from_cbor::<GhostKeyIndexV1>(state_bytes) {
            Ok(index) => index,
            Err(e) => {
                dioxus::logger::tracing::warn!("a Ghost Key's index did not decode: {e}");
                return true;
            }
        };
        // Not trusted because a node served it: every entry must be the Ghost
        // Key's own signed statement, or none of it is used.
        if let Err(e) = index.verify(&IndexParameters::new(vk)) {
            dioxus::logger::tracing::warn!("a Ghost Key's index did not verify: {e}");
            return true;
        }
        let stores: Vec<[u8; 32]> = index.store_keys().map(|k| k.to_bytes()).collect();
        if let Some(view) = self.ghostkey_indexes.get_mut(contract_id) {
            view.index = Some(index);
        }
        for store in stores {
            self.follow_indexed_store(&store);
        }
        // Our stores backed by this key may be missing from it.
        let ours: Vec<Vec<u8>> = self.browsing_stores.keys().cloned().collect();
        for id in ours {
            self.ensure_indexed(&id);
        }
        true
    }

    /// Load the store owned by `store_key`, if it is not loaded already.
    fn follow_indexed_store(&mut self, store_key: &[u8; 32]) {
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(store_key) else {
            return;
        };
        let Ok(id) =
            crate::gateway::store_ops::store_instance_id(&crate::migrate::store_params(&vk))
        else {
            return;
        };
        let id = id.as_bytes().to_vec();
        if !self.note_store_subscribed(&id) {
            return;
        }
        self.stores_from_my_indexes.push(id.clone());
        #[cfg(target_arch = "wasm32")]
        let store_key = *store_key;
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            // The CURRENT generation's id is derived above; a store still
            // living under a predecessor generation answers at neither it
            // nor anything this device knows (#101 re-review S4). A
            // REGISTERED store gets this from `StoresForGhostkey`; a store
            // found through the index has no registration yet, and recovery
            // is exactly what the index is for, so it needs the same probe.
            // Started here, off the response handler, because a write guard
            // is held at the call site.
            crate::gateway::migrate_ops::start_store_key_migration(&store_key);
            if let Err(e) = crate::gateway::get_contract_by_id(&id).await {
                dioxus::logger::tracing::warn!("could not load a store a Ghost Key backs: {e}");
                // `note_store_subscribed` claimed the id before the GET, so
                // a failed send meant this store was never loaded and custody
                // recovery never ran for it, for the session (#101 re-review,
                // Codex P2 and lens B).
                use dioxus::prelude::WritableExt;
                crate::gateway::APP_STATE
                    .write()
                    .on_indexed_store_load_failed(&id);
            }
        });
    }

    /// A store's state arrived: keep our own index complete.
    ///
    /// It does NOT read the store's backer's index. A store anyone can
    /// publish would otherwise send this tab to a stranger's index and on to
    /// every store that lists, each of which leads to another (#101 review).
    /// The indexes this tab reads are the user's own, read when the Ghost
    /// Keys arrive.
    pub(crate) fn on_store_state_for_index(&mut self, store_contract_id: &[u8]) {
        self.ensure_indexed(store_contract_id);
    }

    /// Publish our store's backing into its current backer's index, if this
    /// device holds the store key, the backer is connected here, and neither
    /// the index nor this session already holds it.
    pub(crate) fn ensure_indexed(&mut self, store_contract_id: &[u8]) {
        let Some(loaded) = self.browsing_stores.get(store_contract_id) else {
            return;
        };
        let Some(owner) = loaded.backing_state.owner else {
            return;
        };
        if self.store_owner_key(store_contract_id) != Some(owner) {
            return;
        }
        let Some(backing) =
            harvest_common::backing::current_backing(&loaded.backing_state, |network| {
                self.tip_height(network)
            })
        else {
            return;
        };
        let backer = backing.statement.backer;
        let entry = IndexEntry::from_backing(backing);
        if self.connected_ghost_key(&backer.to_bytes()).is_none() {
            return;
        }
        let slot = entry.slot();
        let index = self
            .ghostkey_indexes
            .values()
            .filter(|v| v.ghost_key == backer.to_bytes())
            .find_map(|v| v.index.as_ref());
        let listed = index.is_some_and(|index| index.entries.contains_key(&slot));
        // A full index keeps the smallest store keys, so a store whose key
        // sorts above every kept one will never be listed however often it
        // is published (#101 review). Say so once instead of re-publishing
        // it every session.
        let never_fits = index.is_some_and(|index| {
            index.entries.len() >= harvest_common::ghostkey_index::MAX_INDEX_ENTRIES
                && index.entries.keys().all(|kept| *kept < slot)
        });
        if never_fits {
            // Its OWN marker (#101 re-review S1). Marking the store as
            // published here is what stopped it ever being published if a
            // slot freed later in the session.
            if self.index_never_fits_notified.insert(owner.to_bytes()) {
                self.notifications.push(format!(
                    "This Ghost Key's index already lists {} stores and cannot take another, \
                     so a device that knows only the Ghost Key will not find this store. The \
                     store itself is unaffected: share its link and buyers reach it as usual.",
                    index.map_or(0, |i| i.entries.len())
                ));
            }
            return;
        }
        if listed || !self.index_entries_published.insert(owner.to_bytes()) {
            return;
        }
        let owner_bytes = owner.to_bytes();
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = crate::gateway::index_ops::publish_entry(&backer, entry).await {
                dioxus::logger::tracing::warn!(
                    "could not add a store to its Ghost Key's index: {e}"
                );
                // Let a later store or index update try again (#101
                // re-review, Codex P2): the marker means "published", and a
                // failed publish is not one.
                use dioxus::prelude::WritableExt;
                crate::gateway::APP_STATE
                    .write()
                    .on_index_publish_failed(&owner_bytes);
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        let _ = owner_bytes;
        #[cfg(not(target_arch = "wasm32"))]
        self.index_entries_to_publish
            .push((backer.to_bytes(), entry));
    }

    /// The GET for a Ghost Key's index could not be sent. Forget that we are
    /// following it, so a later `watch_connected_indexes` tries again.
    ///
    /// Split out of the spawned GET so the state change is testable
    /// off-target; only the GET needs a browser.
    pub(crate) fn on_index_watch_failed(&mut self, index_contract_id: &[u8]) {
        // Only if nothing arrived in the meantime: a state that has already
        // landed is the answer, and dropping the view would re-fetch it.
        if self
            .ghostkey_indexes
            .get(index_contract_id)
            .is_some_and(|v| v.index.is_none())
        {
            self.ghostkey_indexes.remove(index_contract_id);
        }
    }

    /// The GET for a store found through an index could not be sent. Forget
    /// that it was subscribed, so a later index update loads it again.
    pub(crate) fn on_indexed_store_load_failed(&mut self, store_contract_id: &[u8]) {
        // Only if its STATE never arrived. `browsing_stores` holds
        // PLACEHOLDER entries -- `begin_browsing` inserts one the moment a
        // link is opened -- so testing for the key alone skipped the release
        // for exactly the stores a link or a typed code had touched (marker
        // sweep, #101 re-review). The siblings test the same way:
        // `on_index_watch_failed` checks `index.is_none()` and
        // `note_store_state_unavailable` checks `info.is_some()`.
        if self
            .browsing_stores
            .get(store_contract_id)
            .is_some_and(|s| s.info.is_some())
        {
            return;
        }
        self.subscribed_stores.remove(store_contract_id);
        self.stores_from_my_indexes
            .retain(|id| id != store_contract_id);
    }

    /// A store's index entry could not be published. Forget that it was,
    /// so the next store or index update tries again (#101 re-review).
    ///
    /// Split out of the spawned publish so the state change is testable
    /// off-target; only the publish itself needs a browser.
    pub(crate) fn on_index_publish_failed(&mut self, store_key: &[u8; 32]) {
        let failures = self.index_publish_failures.entry(*store_key).or_insert(0);
        *failures = failures.saturating_add(1);
        if *failures >= MAX_INDEX_PUBLISH_ATTEMPTS {
            // Stop, and say so once. `ensure_indexed` runs on every store
            // state arrival, so clearing the marker forever would retry at
            // the store's update rate with no backoff and in silence --
            // which is its own defect, not a fix (#101 re-review, marker
            // sweep). The marker stays set, which is what stops it.
            if *failures == MAX_INDEX_PUBLISH_ATTEMPTS {
                self.notifications.push(
                    "This store could not be added to its Ghost Key's index, so a device that \
                     knows only the Ghost Key will not find it. The store itself is unaffected: \
                     share its link and buyers reach it as usual."
                        .into(),
                );
            }
            return;
        }
        self.index_entries_published.remove(store_key);
    }

    /// The node answered `NotFound` for `contract_id`. If it is a Ghost Key
    /// index this tab follows, note it; returns whether it was.
    pub(crate) fn on_index_absent(&mut self, contract_id: &[u8]) -> bool {
        match self.ghostkey_indexes.get_mut(contract_id) {
            Some(view) => {
                view.absent = true;
                true
            }
            None => false,
        }
    }

    /// The Ghost Key `fingerprint`'s index migration walk has ended.
    ///
    /// Only an ending that settles the question counts (harvest#181 review):
    /// a walk that met silence knows nothing, and one that recovered an
    /// earlier index must make that index's stores known now, because the
    /// forward PUT that would bring it to the current address may be slow,
    /// or fail.
    pub(crate) fn on_index_walk_end(&mut self, fingerprint: &str, end: IndexWalkEnd) {
        match end {
            IndexWalkEnd::Unknown => {}
            IndexWalkEnd::Empty => {
                self.index_walks_done.insert(fingerprint.to_string());
            }
            IndexWalkEnd::Recovered { index, complete } => {
                let Some(ghost_key) = self
                    .ghostkeys
                    .iter()
                    .find(|k| k.fingerprint == fingerprint)
                    .and_then(|k| k.verifying_key_bytes.as_deref())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                else {
                    return;
                };
                let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&ghost_key) else {
                    return;
                };
                // The same rule as a served index: every entry the Ghost
                // Key's own signed statement, or none of it used.
                if let Err(e) = index.verify(&IndexParameters::new(vk)) {
                    dioxus::logger::tracing::warn!(
                        "a recovered Ghost Key index did not verify: {e}"
                    );
                    return;
                }
                let stores: Vec<[u8; 32]> = index.store_keys().map(|k| k.to_bytes()).collect();
                // Kept by Ghost Key, not on the index view: a failed GET of
                // the current index drops the view, and the recovery must
                // not go with it.
                self.recovered_indexes.insert(ghost_key, index);
                if complete {
                    self.index_walks_done.insert(fingerprint.to_string());
                }
                for store in stores {
                    self.follow_indexed_store(&store);
                }
            }
        }
    }

    /// The wait for the Ghost Key `fingerprint`'s index to settle is over.
    pub(crate) fn on_index_wait_elapsed(&mut self, fingerprint: &str) {
        self.index_waits_elapsed.insert(fingerprint.to_string());
    }

    /// Whether the Ghost Key `fingerprint` (verifying key `backer`) may
    /// create a store now (harvest#181).
    ///
    /// Decision 6.2 is that a Ghost Key backs one store at a time, and the
    /// seller's other devices' stores are found through the key's index. So
    /// "Create a store" waits until this device knows what the key already
    /// backs: the delegate's store list has answered, the index has settled
    /// (its state arrived, or the node found none and the key's index
    /// migration walk found no earlier one), and every store it lists has
    /// loaded or been given up on. A loaded store the key currently backs
    /// is recovered by custody rather than created again.
    pub(crate) fn store_creation_gate(&self, fingerprint: &str, backer: &[u8; 32]) -> CreationGate {
        if let Some(name) = self.store_backed_by(backer, None) {
            return CreationGate::BacksStore(name);
        }
        let view = self
            .ghostkey_indexes
            .values()
            .find(|v| v.ghost_key == *backer);
        let waited = self.index_waits_elapsed.contains(fingerprint);
        let recovered = self.recovered_indexes.get(backer);
        let walked = self.index_walks_done.contains(fingerprint);
        let listed: Vec<ed25519_dalek::VerifyingKey> = view
            .and_then(|v| v.index.as_ref())
            .into_iter()
            .chain(recovered)
            .flat_map(|index| index.store_keys())
            .collect();
        // An index that lists a store this device has not loaded is a
        // positive answer: the key has a store. It is never read as silence,
        // however long the store takes (harvest#181 review).
        if let Some(store) = listed.iter().find(|s| !self.indexed_store_settled(s)) {
            if waited {
                return CreationGate::ListsUnloadedStore(harvest_common::store::store_code(store));
            }
            return CreationGate::Checking;
        }
        // The current index has answered (state or NotFound) AND the walk
        // over earlier generations ended conclusively. Neither alone: a
        // current index can be written by a new device before an older
        // generation's stores are carried forward, and a recovered older
        // index says nothing about the current one. A recovery only adds
        // the stores it lists, above.
        let settled = walked && view.is_some_and(|v| v.index.is_some() || v.absent);
        match (
            settled && self.store_lists_answered.contains(fingerprint),
            waited,
        ) {
            (true, _) => CreationGate::Ready,
            (false, true) => CreationGate::Unconfirmed,
            (false, false) => CreationGate::Checking,
        }
    }

    /// Whether a store an index lists has loaded, or its load was given up.
    fn indexed_store_settled(&self, store_key: &ed25519_dalek::VerifyingKey) -> bool {
        let Ok(id) =
            crate::gateway::store_ops::store_instance_id(&crate::migrate::store_params(store_key))
        else {
            return true;
        };
        let id = id.as_bytes().to_vec();
        self.browsing_stores
            .get(&id)
            .is_some_and(|store| store.info.is_some() || store.backing_state.owner.is_some())
            || self.store_state_unavailable.contains(&id)
    }

    /// The fingerprint of a connected Ghost Key whose verifying key is `key`.
    pub(crate) fn connected_ghost_key(&self, key: &[u8; 32]) -> Option<String> {
        self.ghostkeys
            .iter()
            .find(|k| k.verifying_key_bytes.as_deref() == Some(key.as_slice()))
            .map(|k| k.fingerprint.clone())
    }

    /// The store keys `ghost_key`'s index lists, if it has arrived.
    #[allow(dead_code)]
    pub(crate) fn indexed_stores(&self, ghost_key: &[u8; 32]) -> Option<HashSet<[u8; 32]>> {
        self.ghostkey_indexes
            .values()
            .find(|v| v.ghost_key == *ghost_key)
            .and_then(|v| v.index.as_ref())
            .map(|index| index.store_keys().map(|k| k.to_bytes()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backing_flow::tests::{load_backed, signed_backing};
    use ed25519_dalek::SigningKey;

    const BACKER: u8 = 0x41;

    fn backer_vk() -> [u8; 32] {
        SigningKey::from_bytes(&[BACKER; 32])
            .verifying_key()
            .to_bytes()
    }

    fn index_id(key: [u8; 32]) -> Vec<u8> {
        crate::gateway::index_ops::index_contract_key(
            &ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap(),
        )
        .unwrap()
        .id()
        .as_bytes()
        .to_vec()
    }

    fn store_id(seed: u8) -> Vec<u8> {
        crate::gateway::store_ops::store_instance_id(&crate::migrate::store_params(
            &SigningKey::from_bytes(&[seed; 32]).verifying_key(),
        ))
        .unwrap()
        .as_bytes()
        .to_vec()
    }

    fn index_of(stores: &[u8]) -> GhostKeyIndexV1 {
        let mut index = GhostKeyIndexV1::default();
        let entries: Vec<IndexEntry> = stores
            .iter()
            .map(|s| IndexEntry::from_backing(&signed_backing(*s, BACKER, 10)))
            .collect();
        index
            .apply_delta(
                &IndexParameters::new(
                    ed25519_dalek::VerifyingKey::from_bytes(&backer_vk()).unwrap(),
                ),
                &entries,
            )
            .unwrap();
        index
    }

    fn connect(state: &mut AppState, key: [u8; 32]) {
        state.ghostkeys.push(ghostkey_common::GhostKeyInfo {
            fingerprint: "fp".into(),
            label: None,
            notary_info: String::new(),
            verifying_key_bytes: Some(key.to_vec()),
            backed_up: false,
        });
    }

    /// harvest#181: "Create a store" waits until this device knows what the
    /// Ghost Key already backs. Nothing known: checking. The delegate's list
    /// and a `NotFound` index are not enough until the key's index migration
    /// walk has finished (an earlier generation may hold its stores). An
    /// index that lists a store waits for that store; the store, once loaded
    /// and backed by the key, is recovered rather than created again; and
    /// the wait ends in "unconfirmed", not a permanent block. Mutated red by
    /// ignoring the walk, by ignoring unloaded listed stores, by ignoring the
    /// delegate's list, and by never ending the wait.
    #[test]
    fn store_creation_waits_until_the_key_is_known() {
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        let checking = || CreationGate::Checking;
        assert_eq!(state.store_creation_gate("fp", &backer_vk()), checking());
        state.watch_ghostkey_index(backer_vk());
        let id = index_id(backer_vk());
        assert_eq!(state.store_creation_gate("fp", &backer_vk()), checking());
        state.store_lists_answered.insert("fp".into());
        assert!(state.on_index_absent(&id));
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            checking(),
            "an earlier index generation may still hold its stores"
        );
        // A walk that met silence knows nothing (harvest#181 review).
        state.on_index_walk_end("fp", IndexWalkEnd::Unknown);
        assert_eq!(state.store_creation_gate("fp", &backer_vk()), checking());
        state.on_index_walk_end("fp", IndexWalkEnd::Empty);
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Ready
        );

        // The delegate's own list has not answered: not yet.
        state.store_lists_answered.clear();
        assert_eq!(state.store_creation_gate("fp", &backer_vk()), checking());
        state.store_lists_answered.insert("fp".into());

        // An index listing a store waits for it, then the store is the key's.
        let bytes = harvest_common::to_cbor(&index_of(&[0x71])).unwrap();
        state.on_contract_state(id.clone(), bytes);
        assert_eq!(state.store_creation_gate("fp", &backer_vk()), checking());
        load_backed(&mut state, 9, 0x71, vec![signed_backing(0x71, BACKER, 10)]);
        state
            .browsing_stores
            .insert(store_id(0x71), state.browsing_stores[&vec![9; 32]].clone());
        assert!(matches!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::BacksStore(_)
        ));

        // Silence for the whole wait: offered, with the warning.
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.watch_ghostkey_index(backer_vk());
        assert!(
            state.index_waits_started.contains("fp"),
            "the wait is started"
        );
        state.on_index_wait_elapsed("fp");
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Unconfirmed
        );
    }

    /// The wait belongs to the Ghost Key, not to the index view: a GET that
    /// could not be sent drops the view, and the gate still ends its wait
    /// instead of showing "Checking" until the vault reconnects. Mutated red
    /// by keeping the wait on the view.
    #[test]
    fn a_failed_index_read_still_ends_the_wait() {
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.store_lists_answered.insert("fp".into());
        state.watch_ghostkey_index(backer_vk());
        state.on_index_watch_failed(&index_id(backer_vk()));
        assert!(state.ghostkey_indexes.is_empty());
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Checking
        );
        state.on_index_wait_elapsed("fp");
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Unconfirmed
        );
    }

    /// An earlier generation's index, recovered by the walk, counts at once:
    /// the gate waits for the stores it lists and follows them, without
    /// waiting on the forward PUT that may never land. One that does not
    /// verify is ignored and settles nothing. Mutated red by marking the
    /// walk done without the recovered stores, and by skipping the verify.
    #[test]
    fn a_recovered_index_holds_creation_back_for_its_stores() {
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.store_lists_answered.insert("fp".into());
        state.watch_ghostkey_index(backer_vk());
        let id = index_id(backer_vk());
        assert!(state.on_index_absent(&id));

        let mut forged = index_of(&[0x71]);
        let foreign = IndexEntry::from_backing(&signed_backing(0x72, 0x42, 10));
        forged.entries.insert(foreign.slot(), foreign);
        state.on_index_walk_end(
            "fp",
            IndexWalkEnd::Recovered {
                index: forged,
                complete: true,
            },
        );
        assert!(state.stores_from_my_indexes.is_empty());
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Checking,
            "a recovery that does not verify settles nothing"
        );

        state.on_index_walk_end(
            "fp",
            IndexWalkEnd::Recovered {
                index: index_of(&[0x71]),
                complete: true,
            },
        );
        assert!(state.stores_from_my_indexes.contains(&store_id(0x71)));
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Checking,
            "its store has not loaded"
        );
        // However long it takes: the key has a store, so no Create.
        state.on_index_wait_elapsed("fp");
        assert!(matches!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::ListsUnloadedStore(_)
        ));
        load_backed(&mut state, 9, 0x71, vec![signed_backing(0x71, BACKER, 10)]);
        state
            .browsing_stores
            .insert(store_id(0x71), state.browsing_stores[&vec![9; 32]].clone());
        assert!(matches!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::BacksStore(_)
        ));
    }

    /// A recovery from a walk where another earlier generation never
    /// answered follows its stores but does not settle the gate; a
    /// recovery that arrives after the current index's view was dropped (a
    /// failed GET) is kept all the same, but settles nothing until the
    /// CURRENT index answers: an older generation says nothing about it.
    /// Mutated red by settling on an incomplete recovery, by settling on a
    /// recovery without the current index, and by keeping the recovery on
    /// the view.
    #[test]
    fn an_incomplete_or_viewless_recovery_is_kept_but_settles_nothing() {
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.store_lists_answered.insert("fp".into());
        state.watch_ghostkey_index(backer_vk());
        state.on_index_watch_failed(&index_id(backer_vk()));
        state.on_index_walk_end(
            "fp",
            IndexWalkEnd::Recovered {
                index: index_of(&[]),
                complete: false,
            },
        );
        assert!(state.recovered_indexes.contains_key(&backer_vk()));
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Checking,
            "another generation never answered"
        );
        state.on_index_walk_end(
            "fp",
            IndexWalkEnd::Recovered {
                index: index_of(&[]),
                complete: true,
            },
        );
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Checking,
            "the current index has not answered"
        );
        state.watch_ghostkey_index(backer_vk());
        assert!(state.on_index_absent(&index_id(backer_vk())));
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Ready
        );
    }

    /// A current index that has arrived does not settle the gate until the
    /// walk over earlier generations ends: a new device can write the
    /// current index before an older generation's stores are carried
    /// forward (codex, round 3). Mutated red by settling on the current
    /// index alone.
    #[test]
    fn a_current_index_waits_for_the_walk() {
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.store_lists_answered.insert("fp".into());
        state.watch_ghostkey_index(backer_vk());
        let bytes = harvest_common::to_cbor(&index_of(&[])).unwrap();
        state.on_contract_state(index_id(backer_vk()), bytes);
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Checking
        );
        state.on_index_walk_end("fp", IndexWalkEnd::Empty);
        assert_eq!(
            state.store_creation_gate("fp", &backer_vk()),
            CreationGate::Ready
        );
    }

    /// "Create store" sent from a form opened under an earlier answer is
    /// refused while the gate is checking or the key backs a store, and goes
    /// on otherwise (here to the next refusal: no block loaded). Mutated red
    /// by not checking the gate.
    #[test]
    fn creating_a_store_rechecks_the_gate() {
        let details = || crate::state::StoreDetails {
            store_name: "Bean Shop".into(),
            description: String::new(),
        };
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.watch_ghostkey_index(backer_vk());
        assert_eq!(
            state.begin_own_store_creation("fp".into(), backer_vk(), details()),
            Err(crate::backing_flow::STILL_CHECKING_GHOST_KEY.to_string())
        );
        assert!(state.store_creation_in_flight.is_none());

        state.on_index_wait_elapsed("fp");
        assert_eq!(
            state.begin_own_store_creation("fp".into(), backer_vk(), details()),
            Err(crate::backing_flow::NO_BLOCK_FOR_BACKING.to_string()),
            "past the gate"
        );

        load_backed(&mut state, 9, 0x71, vec![signed_backing(0x71, BACKER, 10)]);
        let refused = state
            .begin_own_store_creation("fp".into(), backer_vk(), details())
            .unwrap_err();
        assert!(refused.contains("already has a store"), "{refused}");
    }

    /// A connected Ghost Key's index is read, and every store it lists is
    /// loaded: how a device that knows only the key finds its stores.
    /// Mutated red by not following the listed stores.
    #[test]
    fn a_ghost_keys_index_leads_to_every_store_it_lists() {
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.on_ghostkey_response(ghostkey_common::GhostkeyResponse::GhostKeyList {
            keys: state.ghostkeys.clone(),
        });
        assert!(state.ghostkey_indexes.contains_key(&index_id(backer_vk())));

        let bytes = harvest_common::to_cbor(&index_of(&[0x71, 0x72])).unwrap();
        state.on_contract_state(index_id(backer_vk()), bytes);
        assert!(state.stores_from_my_indexes.contains(&store_id(0x71)));
        assert!(state.stores_from_my_indexes.contains(&store_id(0x72)));
        // Routed as an index, not taken for a store.
        assert!(!state.browsing_stores.contains_key(&index_id(backer_vk())));
    }

    /// An index holding an entry the Ghost Key did not sign is not used at
    /// all. Mutated red by skipping the verify.
    #[test]
    fn an_index_that_does_not_verify_is_ignored() {
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.watch_ghostkey_index(backer_vk());
        let mut index = index_of(&[0x71]);
        // Another key's backing, filed in this key's index.
        let foreign = IndexEntry::from_backing(&signed_backing(0x72, 0x42, 10));
        index.entries.insert(foreign.slot(), foreign);
        state.on_contract_state(
            index_id(backer_vk()),
            harvest_common::to_cbor(&index).unwrap(),
        );
        assert!(state.stores_from_my_indexes.is_empty());
        assert!(state.ghostkey_indexes[&index_id(backer_vk())]
            .index
            .is_none());
    }

    /// A store that loads does NOT send this tab to its backer's index
    /// (#101 review): anyone can publish a store naming any Ghost Key, and
    /// following it would walk a stranger's graph. Mutated red by watching
    /// the backer's index from the store path, and by dropping the
    /// user-holds-the-key check in `watch_ghostkey_index`.
    #[test]
    fn a_loaded_store_does_not_lead_to_a_strangers_index() {
        let mut state = AppState::default();
        load_backed(&mut state, 1, 0x71, vec![signed_backing(0x71, BACKER, 10)]);
        state.on_store_state_for_index(&[1u8; 32]);
        assert!(state.ghostkey_indexes.is_empty(), "no stranger's index");

        // Nor by asking directly: the key is not one the user holds.
        state.watch_ghostkey_index(backer_vk());
        assert!(state.ghostkey_indexes.is_empty());

        // Once it IS the user's key, it is read.
        connect(&mut state, backer_vk());
        state.watch_ghostkey_index(backer_vk());
        assert!(state.ghostkey_indexes.contains_key(&index_id(backer_vk())));
    }

    /// Our store, backed by a connected Ghost Key, is published into that
    /// key's index once, and not while the index already lists it. Mutated
    /// red by never publishing, and by publishing again.
    #[test]
    fn our_store_is_added_to_its_backers_index_once() {
        let store_key = SigningKey::from_bytes(&[0x71; 32])
            .verifying_key()
            .to_bytes();
        let mut state = AppState::default();
        load_backed(&mut state, 1, 0x71, vec![signed_backing(0x71, BACKER, 10)]);
        state.my_stores.insert(
            "fp".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: vec![1; 32],
                reputation_contract_id: vec![2; 32],
                mailbox_contract_id: vec![3; 32],
                store_contract_key: None,
                store_verifying_key: Some(store_key),
            }],
        );
        // Not connected: nothing published (only the backer can say so).
        state.ensure_indexed(&[1u8; 32]);
        assert!(state.index_entries_to_publish.is_empty());

        connect(&mut state, backer_vk());
        state.ensure_indexed(&[1u8; 32]);
        state.ensure_indexed(&[1u8; 32]);
        assert_eq!(state.index_entries_to_publish.len(), 1, "once");
        let (ghost, entry) = &state.index_entries_to_publish[0];
        assert_eq!(*ghost, backer_vk());
        assert_eq!(entry.statement.store.to_bytes(), store_key);
        entry
            .verify(&ed25519_dalek::VerifyingKey::from_bytes(&backer_vk()).unwrap())
            .expect("an entry the index contract accepts");

        // A fresh session whose index already lists it publishes nothing.
        let mut again = state.clone();
        again.index_entries_to_publish.clear();
        again.index_entries_published.clear();
        again.watch_ghostkey_index(backer_vk());
        again.on_contract_state(
            index_id(backer_vk()),
            harvest_common::to_cbor(&index_of(&[0x71])).unwrap(),
        );
        again.ensure_indexed(&[1u8; 32]);
        assert!(again.index_entries_to_publish.is_empty());
    }

    /// A Ghost Key's index is read once per session: a second ask does not
    /// throw away the index that has arrived (#101 review). Mutated red by
    /// dropping the dedup.
    #[test]
    fn an_index_is_read_once_per_session() {
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.watch_ghostkey_index(backer_vk());
        state.on_contract_state(
            index_id(backer_vk()),
            harvest_common::to_cbor(&index_of(&[0x71])).unwrap(),
        );
        assert!(state.ghostkey_indexes[&index_id(backer_vk())]
            .index
            .is_some());
        state.watch_ghostkey_index(backer_vk());
        assert!(
            state.ghostkey_indexes[&index_id(backer_vk())]
                .index
                .is_some(),
            "asking again must not discard what arrived"
        );
    }

    /// A store whose key sorts after every entry of a FULL index is never
    /// listed, so it is not published again every session; the seller is
    /// told once what to do instead (#101 review). Mutated red by
    /// publishing anyway.
    #[test]
    fn a_store_that_cannot_fit_a_full_index_is_not_republished() {
        use harvest_common::ghostkey_index::MAX_INDEX_ENTRIES;
        let store_key = SigningKey::from_bytes(&[0x71; 32])
            .verifying_key()
            .to_bytes();
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        load_backed(&mut state, 1, 0x71, vec![signed_backing(0x71, BACKER, 10)]);
        state.my_stores.insert(
            "fp".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: vec![1; 32],
                reputation_contract_id: vec![2; 32],
                mailbox_contract_id: vec![3; 32],
                store_contract_key: None,
                store_verifying_key: Some(store_key),
            }],
        );
        // An index full of keys that all sort BELOW this store's key.
        let smaller: Vec<u8> = (0u8..=255)
            .filter(|s| SigningKey::from_bytes(&[*s; 32]).verifying_key().to_bytes() < store_key)
            .take(MAX_INDEX_ENTRIES)
            .collect();
        assert_eq!(smaller.len(), MAX_INDEX_ENTRIES, "enough smaller keys");
        state.watch_ghostkey_index(backer_vk());
        state.on_contract_state(
            index_id(backer_vk()),
            harvest_common::to_cbor(&index_of(&smaller)).unwrap(),
        );

        state.ensure_indexed(&[1u8; 32]);
        state.ensure_indexed(&[1u8; 32]);
        assert!(
            state.index_entries_to_publish.is_empty(),
            "publishing it cannot make it fit"
        );
        assert_eq!(
            state
                .notifications
                .iter()
                .filter(|n| n.contains("cannot take another"))
                .count(),
            1,
            "said once"
        );

        // A slot frees later in the same session: the entry must then be
        // published (#101 re-review S1). It was not, because the "said
        // once" marker was the same set as the "published once" gate.
        // Mutated red by marking `index_entries_published` in the
        // `never_fits` branch again.
        let fewer: Vec<u8> = smaller
            .iter()
            .copied()
            .take(MAX_INDEX_ENTRIES - 1)
            .collect();
        state.on_contract_state(
            index_id(backer_vk()),
            harvest_common::to_cbor(&index_of(&fewer)).unwrap(),
        );
        state.ensure_indexed(&[1u8; 32]);
        assert_eq!(
            state.index_entries_to_publish.len(),
            1,
            "a freed slot must be taken"
        );
    }

    /// A failed GET does not leave the index marked as followed, or an
    /// indexed store marked as subscribed (#101 re-review, Codex P2 and
    /// lens B). Both markers are claimed BEFORE the send, and both gate
    /// every later attempt, so a transient failure disabled index discovery
    /// for the session -- on a fresh device, which is the one that needs it.
    ///
    /// Mutated red by dropping each `remove`.
    #[test]
    fn a_failed_index_or_store_get_is_retried() {
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        state.watch_ghostkey_index(backer_vk());
        let id = index_id(backer_vk());
        assert!(state.ghostkey_indexes.contains_key(&id), "followed");

        state.on_index_watch_failed(&id);
        assert!(
            !state.ghostkey_indexes.contains_key(&id),
            "a failed GET must not hold the index for the session"
        );
        state.watch_ghostkey_index(backer_vk());
        assert!(state.ghostkey_indexes.contains_key(&id), "and can retry");

        // An index whose state HAS arrived is not dropped by a late failure.
        state.on_contract_state(id.clone(), harvest_common::to_cbor(&index_of(&[])).unwrap());
        state.on_index_watch_failed(&id);
        assert!(
            state.ghostkey_indexes.contains_key(&id),
            "state that arrived wins over a late send failure"
        );

        // The same for a store reached through an index.
        let store_id = vec![0x33u8; 32];
        assert!(state.note_store_subscribed(&store_id));
        state.stores_from_my_indexes.push(store_id.clone());
        state.on_indexed_store_load_failed(&store_id);
        assert!(
            state.note_store_subscribed(&store_id),
            "a failed GET must not hold the store for the session"
        );
        assert!(!state.stores_from_my_indexes.contains(&store_id));

        // A PLACEHOLDER entry is not arrived state. `begin_browsing` inserts
        // one the moment a link is opened, so testing `contains_key` skipped
        // the release for exactly the stores a link had touched (#101
        // re-review, marker sweep). Mutated red by testing for the key.
        let placeholder = vec![0x44u8; 32];
        assert!(state.note_store_subscribed(&placeholder));
        state
            .browsing_stores
            .entry(placeholder.clone())
            .or_default();
        assert!(
            state.browsing_stores[&placeholder].info.is_none(),
            "a placeholder holds no details"
        );
        state.on_indexed_store_load_failed(&placeholder);
        assert!(
            state.note_store_subscribed(&placeholder),
            "a placeholder must not block the release"
        );

        // But a store whose details HAVE arrived is left alone.
        let loaded = vec![0x55u8; 32];
        assert!(state.note_store_subscribed(&loaded));
        let info = harvest_common::store::StoreInfoV1 {
            version: 1,
            certificate_pem: String::new(),
            seller_fingerprint: String::new(),
            reputation_contract_id: [0; 32],
            store_name: "Loaded".to_string(),
            description: String::new(),
            encryption_public_key: None,
            record_public_key: None,
        };
        state
            .browsing_stores
            .entry(loaded.clone())
            .or_default()
            .info = Some(info);
        state.on_indexed_store_load_failed(&loaded);
        assert!(
            !state.note_store_subscribed(&loaded),
            "state that arrived wins over a late send failure"
        );
    }

    /// A publish that FAILS is not remembered as one, so a later store or
    /// index update tries again (#101 re-review, Codex P2). Mutated red by
    /// dropping the `remove` in `on_index_publish_failed`.
    #[test]
    fn a_failed_index_publish_is_retried() {
        let store_key = SigningKey::from_bytes(&[0x71; 32])
            .verifying_key()
            .to_bytes();
        let mut state = AppState::default();
        connect(&mut state, backer_vk());
        load_backed(&mut state, 1, 0x71, vec![signed_backing(0x71, BACKER, 10)]);
        state.my_stores.insert(
            "fp".into(),
            vec![harvest_common::StoreRegistration {
                store_contract_id: vec![1; 32],
                reputation_contract_id: vec![2; 32],
                mailbox_contract_id: vec![3; 32],
                store_contract_key: None,
                store_verifying_key: Some(store_key),
            }],
        );
        state.ensure_indexed(&[1u8; 32]);
        assert_eq!(state.index_entries_to_publish.len(), 1);
        state.ensure_indexed(&[1u8; 32]);
        assert_eq!(state.index_entries_to_publish.len(), 1, "published once");

        state.on_index_publish_failed(&store_key);
        state.ensure_indexed(&[1u8; 32]);
        assert_eq!(
            state.index_entries_to_publish.len(),
            2,
            "a failed publish must be retried"
        );

        // But NOT forever. `ensure_indexed` runs on every store state
        // arrival, so an unbounded clear is a retry storm with nothing said
        // (#101 re-review, marker sweep). Mutated red by removing the cap.
        for _ in 0..MAX_INDEX_PUBLISH_ATTEMPTS {
            state.on_index_publish_failed(&store_key);
            state.ensure_indexed(&[1u8; 32]);
        }
        let settled = state.index_entries_to_publish.len();
        for _ in 0..5 {
            state.on_index_publish_failed(&store_key);
            state.ensure_indexed(&[1u8; 32]);
        }
        assert_eq!(
            state.index_entries_to_publish.len(),
            settled,
            "past the cap it stops retrying"
        );
        assert_eq!(
            state
                .notifications
                .iter()
                .filter(|n| n.contains("will not find it"))
                .count(),
            1,
            "and says so exactly once"
        );
    }

    /// A store this device cannot sign for is never published by it.
    #[test]
    fn a_store_we_do_not_hold_is_not_published() {
        let mut state = AppState::default();
        load_backed(&mut state, 1, 0x71, vec![signed_backing(0x71, BACKER, 10)]);
        connect(&mut state, backer_vk());
        state.ensure_indexed(&[1u8; 32]);
        assert!(state.index_entries_to_publish.is_empty());
    }

    /// The wasm-only wiring the gate and the close depend on, pinned by
    /// source because no host test can run it (harvest#181 review). Red
    /// if any of these calls is deleted or loosened.
    #[test]
    fn the_wasm_only_wiring_for_one_store_per_ghost_key_is_in_place() {
        // The non-test source, with comment lines dropped (so a call that is
        // commented out does not count), and whitespace squashed.
        let code = |src: &str| -> String {
            // The first test module, not the first `#[cfg(test)]`:
            // message_view.rs has a test-only counter far above the code
            // this reads.
            let src = src.find("#[cfg(test)]\nmod ").map_or(src, |at| &src[..at]);
            src.lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<String>()
                .split_whitespace()
                .collect()
        };
        let migrate = code(include_str!("gateway/migrate_ops.rs"));
        for needle in [
            // A silent candidate marks the walk as knowing nothing...
            "probe.any_unknown=true;",
            // ...which ends it as Unknown, never Empty, and leaves a
            // recovery incomplete.
            "_ifprobe.any_unknown=>(None,crate::index_flow::IndexWalkEnd::Unknown),",
            "freenet_migrate::Outcome::Indeterminate{..}=>{(None,crate::index_flow::IndexWalkEnd::Unknown)}",
            "crate::index_flow::IndexWalkEnd::Recovered{index:merged,complete:!probe.any_unknown&&!truncated_fold,},",
            "super::APP_STATE.write().on_index_walk_end(&fingerprint,end);",
            // The marker skip settles the walk too.
            ".on_index_walk_end(&fingerprint,crate::index_flow::IndexWalkEnd::Empty);",
        ] {
            assert!(migrate.contains(needle), "migrate_ops lost: {needle}");
        }
        assert!(
            !migrate.contains("on_index_walk_done"),
            "the walk is never marked done regardless of how it ended"
        );
        let handler = code(include_str!("gateway/response_handler.rs"));
        assert!(handler.contains("APP_STATE.write().on_index_absent(instance_id.as_bytes());"));
        let this = code(include_str!("index_flow.rs"));
        assert!(this.contains(".on_index_wait_elapsed(&fingerprint);"));
        // The wait starts before anything in the watch can return early.
        let watch = &this[this.find("fnwatch_ghostkey_index(").expect("the watch")..];
        assert!(
            watch
                .find("self.index_waits_started.insert(")
                .expect("the wait")
                < watch
                    .find("VerifyingKey::from_bytes(&ghost_key)")
                    .expect("the key parse"),
            "the index wait must start before the watch can return"
        );
        let closure = code(include_str!("closure_flow.rs"));
        assert!(closure.contains(".on_close_deadline(&id,attempt);"));
        assert!(
            closure.contains("ifletErr(e)=result{letmutstate=crate::gateway::APP_STATE.write();state.closes_sent.remove(&owner);"),
            "a close that could not be sent must not hold back the next one"
        );
        let messages = code(include_str!("components/message_view.rs"));
        let counted = &messages[messages
            .find("fnrequests_awaiting_invoice_by_tag(")
            .expect("the count")..];
        assert!(
            counted.contains("ifstore.closed{returnDefault::default();}unanswered_by_tag("),
            "a closed store's requests are not counted"
        );
        let my_store = code(include_str!("components/my_store.rs"));
        assert!(
            my_store.contains(".begin_own_store_creation(fingerprint.clone(),vk_bytes,details);")
        );
        assert!(my_store.contains("}elseiflegacy_movable&&gate_open{"));
        assert!(my_store
            .contains("letgate=APP_STATE.read().store_creation_gate(&fingerprint,&vk_bytes);"));
        assert_eq!(
            my_store.matches("another_store").count(),
            1,
            "the UI never asks for a second store on purpose"
        );
        assert!(my_store.contains("another_store:false,"));
        // The UI rewords the delegate's refusal by matching its text.
        assert!(
            include_str!("../../delegates/harvest-delegate/src/handlers.rs")
                .contains("open a second store under this one on")
        );
    }
}
