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
}

impl AppState {
    /// Read `ghost_key`'s index, once per session, and keep following it.
    ///
    /// Refused for a Ghost Key the user does not hold (#101 review): see
    /// the module docs.
    pub(crate) fn watch_ghostkey_index(&mut self, ghost_key: [u8; 32]) {
        if self.connected_ghost_key(&ghost_key).is_none() {
            return;
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
            },
        );
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = crate::gateway::get_contract_by_id(&id).await {
                dioxus::logger::tracing::warn!("could not read a Ghost Key's index: {e}");
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

    /// A store's index entry could not be published. Forget that it was,
    /// so the next store or index update tries again (#101 re-review).
    ///
    /// Split out of the spawned publish so the state change is testable
    /// off-target; only the publish itself needs a browser.
    pub(crate) fn on_index_publish_failed(&mut self, store_key: &[u8; 32]) {
        self.index_entries_published.remove(store_key);
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
}
