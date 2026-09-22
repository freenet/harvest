//! Importing a predecessor delegate's secrets into this one (harvest#123).
//!
//! # Where this sits
//!
//! A delegate's secrets are node-local and keyed by the delegate's own
//! address, so a re-key strands every one of them. [`crate::migration`] is the
//! half every generation from V5 on ships: it answers a successor's request to
//! export. This is the other half, the successor's: the web app asks each
//! predecessor to export (it is the only party that can talk to both), then
//! hands the secrets here one at a time, and `freenet-migrate`'s
//! `migrate_delegate_secrets` decides which predecessors and in what order.
//!
//! # Why every secret goes through this delegate's own rules
//!
//! A raw `(key, value)` copy is wrong for any secret whose value is a
//! COLLECTION: copying never-clobber hides what the predecessor held
//! (ghostkeys lost credentials behind an index that way), and overwriting
//! deletes what the successor gained (Delta lost sites that way). Harvest has
//! three such collections -- a Ghost Key's store registrations, the
//! transaction index and the Bitcoin watch list -- and each is merged here by
//! the identity its own handler uses. Two families are capped, and an import
//! must not push either past its cap. Everything else stands alone and is
//! copied only if this delegate does not already hold it.
//!
//! # Never-clobber is load-bearing
//!
//! The UI walks predecessors under `UnionAllGenerations`, newest first, so
//! that a generation the node never ran (and so cannot answer) does not stop
//! an older one's secrets being recovered. The crate's promise that the
//! NEWEST generation's value wins a shared key rests entirely on the writer
//! declining a key it already holds: an overwriting writer would install the
//! oldest value with a clean report. So nothing here overwrites.
//!
//! # The markers
//!
//! The completion marker is `freenet-migrate`'s public format
//! (`PRED_DONE_MARKER_KEY_PREFIX`), so a future node-side copy-forward that
//! writes the same bytes is honoured. The in-progress marker is the crate's
//! internal format, reproduced here; only this delegate reads it. Both sit in
//! the crate's reserved `\0freenet-migrate/` namespace, outside `harvest:`, so
//! an export never carries them onward: a marker says "THIS delegate imported
//! that predecessor", which is not true of the next one.

use freenet_migrate::{
    SecretStore, PRED_DONE_MARKER_KEY_PREFIX, PRED_DONE_MARKER_VALUE_DATA,
    PRED_DONE_MARKER_VALUE_EMPTY,
};
use harvest_common::bitcoin_delegate::WatchedPayment;
use harvest_common::delegate::{
    HarvestDelegateResponse, PredecessorMarkerState, SecretImport, StoreRegistration,
};
use harvest_common::{from_cbor, to_cbor};

/// `freenet-migrate`'s in-progress marker prefix (crate-private there; see the
/// module docs for why reproducing it is sound).
const PRED_WIP_PREFIX: &[u8] = b"\0freenet-migrate/v1/pred-wip:";

fn done_key(predecessor: &[u8; 32]) -> Vec<u8> {
    [PRED_DONE_MARKER_KEY_PREFIX, predecessor.as_slice()].concat()
}

fn wip_key(predecessor: &[u8; 32]) -> Vec<u8> {
    [PRED_WIP_PREFIX, predecessor.as_slice()].concat()
}

fn flag(value: &[u8]) -> bool {
    // Anything but the explicit "empty" value reads as data-bearing, as the
    // crate's own reader does: the conservative direction.
    value != PRED_DONE_MARKER_VALUE_EMPTY
}

/// Answer `GetPredecessorMarker`. A completion marker wins over an
/// in-progress one, as in the crate.
pub(crate) fn get_marker<S: SecretStore>(
    store: &S,
    predecessor: [u8; 32],
) -> HarvestDelegateResponse {
    let marker = if let Some(value) = store.get_secret(&done_key(&predecessor)) {
        Some(PredecessorMarkerState::Done {
            had_data: flag(&value),
        })
    } else {
        store
            .get_secret(&wip_key(&predecessor))
            .map(|value| PredecessorMarkerState::InProgress {
                saw_data: flag(&value),
            })
    };
    HarvestDelegateResponse::PredecessorMarker {
        predecessor,
        marker,
    }
}

/// Answer `RecordPredecessorMarker`, reporting a refused write.
pub(crate) fn record_marker<S: SecretStore>(
    store: &mut S,
    predecessor: [u8; 32],
    marker: PredecessorMarkerState,
) -> HarvestDelegateResponse {
    let (key, data) = match marker {
        PredecessorMarkerState::InProgress { saw_data } => (wip_key(&predecessor), saw_data),
        PredecessorMarkerState::Done { had_data } => (done_key(&predecessor), had_data),
    };
    let value = if data {
        PRED_DONE_MARKER_VALUE_DATA
    } else {
        PRED_DONE_MARKER_VALUE_EMPTY
    };
    HarvestDelegateResponse::PredecessorMarkerRecorded {
        predecessor,
        marker,
        recorded: store.set_secret(&key, value),
    }
}

/// Answer `ImportMigratedSecret`.
pub(crate) fn import<S: SecretStore>(
    store: &mut S,
    predecessor: [u8; 32],
    key: Vec<u8>,
    value: &[u8],
) -> HarvestDelegateResponse {
    let outcome = import_secret(store, &key, value);
    HarvestDelegateResponse::MigratedSecretImported {
        predecessor,
        key,
        outcome,
    }
}

/// Import one secret by the rules of its family. See the module docs.
pub(crate) fn import_secret<S: SecretStore>(
    store: &mut S,
    key: &[u8],
    value: &[u8],
) -> SecretImport {
    use harvest_common::migration::SECRET_KEY_PREFIX;

    if !key.starts_with(SECRET_KEY_PREFIX) {
        // An export covers `harvest:` only, so this is not something any
        // predecessor sends. Refused rather than written: it could name
        // anything in this delegate's namespace, including the migration
        // markers above.
        return SecretImport::Permanent("not a Harvest secret".into());
    }
    if key.starts_with(crate::store_keys::STORE_KEY_PREFIX.as_bytes()) {
        // Never exported (`migration::WithoutStoreKeys`); a store key comes
        // back through custody instead. Refused in case one ever arrives.
        return SecretImport::Permanent("store keys are recovered through custody".into());
    }
    if key.starts_with(b"harvest:stores:") {
        return merge_list(
            store,
            key,
            value,
            |held: &mut Vec<StoreRegistration>, incoming| {
                let mut added = false;
                for registration in incoming {
                    match held
                        .iter_mut()
                        .find(|s| s.store_contract_id == registration.store_contract_id)
                    {
                        Some(existing) => {
                            if existing.store_verifying_key.is_none()
                                && registration.store_verifying_key.is_some()
                            {
                                existing.store_verifying_key = registration.store_verifying_key;
                                added = true;
                            }
                        }
                        None => {
                            held.push(registration);
                            added = true;
                        }
                    }
                }
                added
            },
        );
    }
    if key == crate::handlers::TX_INDEX_KEY {
        return merge_list(store, key, value, |held: &mut Vec<String>, incoming| {
            let before = held.len();
            for id in incoming {
                if !held.contains(&id) {
                    held.push(id);
                }
            }
            held.len() != before
        });
    }
    if key == crate::bitcoin::BITCOIN_WATCHES_KEY {
        return merge_list(
            store,
            key,
            value,
            |held: &mut Vec<WatchedPayment>, incoming| {
                let before = held.len();
                for watch in incoming {
                    // The identity `bitcoin::handle` uses: one watch per script on
                    // a network.
                    if !held.iter().any(|w| {
                        w.network == watch.network && w.script_pubkey == watch.script_pubkey
                    }) {
                        held.push(watch);
                    }
                }
                held.len() != before
            },
        );
    }
    if key.starts_with(crate::messaging::BUYER_CONVERSATION_PREFIX_STR.as_bytes()) {
        return copy_within_cap(
            store,
            key,
            value,
            crate::messaging::BUYER_CONVERSATION_PREFIX_STR.as_bytes(),
            crate::messaging::MAX_BUYER_CONVERSATIONS,
        );
    }
    if key.starts_with(crate::known_stores::KNOWN_STORE_PREFIX.as_bytes()) {
        return copy_within_cap(
            store,
            key,
            value,
            crate::known_stores::KNOWN_STORE_PREFIX.as_bytes(),
            crate::known_stores::MAX_KNOWN_STORES,
        );
    }
    copy_if_absent(store, key, value)
}

/// A standalone secret: written only if this delegate holds nothing under the
/// key.
fn copy_if_absent<S: SecretStore>(store: &mut S, key: &[u8], value: &[u8]) -> SecretImport {
    if store.has_secret(key) {
        return SecretImport::AlreadyAuthoritative;
    }
    written(store.set_secret(key, value))
}

/// A secret in a family with a cap: copied if absent and there is room.
///
/// A full family answers `Retryable`, not `Permanent`: a cap is not a
/// property of the secret, and the buyer may forget a conversation tomorrow.
/// Evicting to make room -- what a live store does -- is not an import's
/// call: it would discard something the user has now for something they had
/// before.
fn copy_within_cap<S: SecretStore>(
    store: &mut S,
    key: &[u8],
    value: &[u8],
    prefix: &[u8],
    cap: usize,
) -> SecretImport {
    if store.has_secret(key) {
        return SecretImport::AlreadyAuthoritative;
    }
    if store.list_secrets(prefix).len() >= cap {
        return SecretImport::Retryable(format!(
            "this delegate already holds the most it keeps of this kind ({cap})"
        ));
    }
    written(store.set_secret(key, value))
}

/// A secret whose value is a list: the predecessor's entries are merged into
/// the one held here by `merge`, which returns whether it added anything.
fn merge_list<S, T>(
    store: &mut S,
    key: &[u8],
    value: &[u8],
    merge: impl FnOnce(&mut Vec<T>, Vec<T>) -> bool,
) -> SecretImport
where
    S: SecretStore,
    T: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let Ok(incoming) = from_cbor::<Vec<T>>(value) else {
        return SecretImport::Permanent("the predecessor's value did not decode".into());
    };
    let mut held = match store.get_secret(key) {
        None => Vec::new(),
        Some(bytes) => match from_cbor::<Vec<T>>(&bytes) {
            Ok(held) => held,
            // Merging into what cannot be read would mean replacing it.
            Err(_) => {
                return SecretImport::Retryable("this delegate's own value did not decode".into())
            }
        },
    };
    if !merge(&mut held, incoming) {
        return SecretImport::AlreadyAuthoritative;
    }
    match to_cbor(&held) {
        Ok(bytes) => written(store.set_secret(key, &bytes)),
        Err(_) => SecretImport::Retryable("could not encode the merged value".into()),
    }
}

fn written(ok: bool) -> SecretImport {
    if ok {
        SecretImport::Written
    } else {
        SecretImport::Retryable("the node refused the write".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemSecrets;
    use harvest_common::delegate::HarvestDelegateRequest;

    const PRED: [u8; 32] = [0xAB; 32];

    fn registration(id: u8, key: Option<[u8; 32]>) -> StoreRegistration {
        StoreRegistration {
            store_contract_id: vec![id; 32],
            reputation_contract_id: vec![id + 1; 32],
            mailbox_contract_id: vec![id + 2; 32],
            store_contract_key: None,
            store_verifying_key: key,
        }
    }

    fn cbor<T: serde::Serialize>(v: &T) -> Vec<u8> {
        to_cbor(v).expect("encode")
    }

    /// A standalone secret the successor already holds is never overwritten:
    /// the newest generation's value wins only because of this. Mutated red by
    /// dropping the `has_secret` check.
    #[test]
    fn a_held_secret_is_never_overwritten() {
        let mut store = MemSecrets::default();
        store.set_secret(b"harvest:rsa_sk:fp1", b"newer");
        assert_eq!(
            import_secret(&mut store, b"harvest:rsa_sk:fp1", b"older"),
            SecretImport::AlreadyAuthoritative
        );
        assert_eq!(store.get_secret(b"harvest:rsa_sk:fp1").unwrap(), b"newer");
        assert_eq!(
            import_secret(&mut store, b"harvest:rsa_pk:fp1", b"pk"),
            SecretImport::Written
        );
        assert_eq!(store.get_secret(b"harvest:rsa_pk:fp1").unwrap(), b"pk");
    }

    /// A store registry is merged, not skipped and not replaced: a store the
    /// seller created on the new generation and one they had on the old both
    /// survive. Mutated red by never-clobbering the list, and by replacing it.
    #[test]
    fn a_store_registry_is_merged() {
        let mut store = MemSecrets::default();
        let key = b"harvest:stores:fp1";
        store.set_secret(key, &cbor(&vec![registration(1, None)]));
        let incoming = vec![registration(1, Some([9; 32])), registration(5, None)];
        assert_eq!(
            import_secret(&mut store, key, &cbor(&incoming)),
            SecretImport::Written
        );
        let held: Vec<StoreRegistration> = from_cbor(&store.get_secret(key).unwrap()).unwrap();
        assert_eq!(held.len(), 2, "{held:?}");
        assert_eq!(held[0].store_contract_id, vec![1; 32]);
        assert_eq!(
            held[0].store_verifying_key,
            Some([9; 32]),
            "a missing key is filled"
        );
        assert_eq!(held[1].store_contract_id, vec![5; 32]);
        assert_eq!(
            import_secret(&mut store, key, &cbor(&incoming)),
            SecretImport::AlreadyAuthoritative,
            "a repeat adds nothing"
        );
    }

    /// The transaction index and the watch list merge by their identities.
    #[test]
    fn the_transaction_index_and_watch_list_are_merged() {
        let mut store = MemSecrets::default();
        store.set_secret(crate::handlers::TX_INDEX_KEY, &cbor(&vec!["a".to_string()]));
        assert_eq!(
            import_secret(
                &mut store,
                crate::handlers::TX_INDEX_KEY,
                &cbor(&vec!["a".to_string(), "b".to_string()])
            ),
            SecretImport::Written
        );
        let held: Vec<String> =
            from_cbor(&store.get_secret(crate::handlers::TX_INDEX_KEY).unwrap()).unwrap();
        assert_eq!(held, vec!["a".to_string(), "b".to_string()]);

        let watch = |script: u8, label: &str| WatchedPayment {
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            script_pubkey: vec![script; 22],
            address: String::new(),
            label: Some(label.into()),
            order_id: None,
            expected_amount_sats: None,
            contract_id: None,
            added_at_ms: 0,
            bridge_synced: false,
            last_error: None,
        };
        let key = crate::bitcoin::BITCOIN_WATCHES_KEY;
        store.set_secret(key, &cbor(&vec![watch(1, "mine")]));
        assert_eq!(
            import_secret(
                &mut store,
                key,
                &cbor(&vec![watch(1, "theirs"), watch(2, "old")])
            ),
            SecretImport::Written
        );
        let held: Vec<WatchedPayment> = from_cbor(&store.get_secret(key).unwrap()).unwrap();
        assert_eq!(held.len(), 2);
        assert_eq!(
            held[0].label.as_deref(),
            Some("mine"),
            "the successor's own watch stands"
        );
    }

    /// A capped family is not pushed past its cap, and a full one is
    /// retryable, never "already authoritative" (which would seal the
    /// predecessor with the secret left behind). Mutated red by dropping the
    /// cap check and by answering `AlreadyAuthoritative` when full.
    #[test]
    fn a_full_family_is_retryable_and_not_overfilled() {
        let mut store = MemSecrets::default();
        let prefix = crate::known_stores::KNOWN_STORE_PREFIX;
        for i in 0..crate::known_stores::MAX_KNOWN_STORES {
            store.set_secret(format!("{prefix}{i:016}").as_bytes(), b"x");
        }
        let key = format!("{prefix}ZZZZZZZZZZZZZZZZ");
        assert!(matches!(
            import_secret(&mut store, key.as_bytes(), b"x"),
            SecretImport::Retryable(_)
        ));
        assert_eq!(
            store.list_secrets(prefix.as_bytes()).len(),
            crate::known_stores::MAX_KNOWN_STORES
        );
    }

    /// A refused write is retryable, never success. Mutated red by answering
    /// `Written` regardless.
    #[test]
    fn a_refused_write_is_retryable() {
        let mut store = MemSecrets::refusing_writes();
        assert!(matches!(
            import_secret(&mut store, b"harvest:rsa_sk:fp1", b"sk"),
            SecretImport::Retryable(_)
        ));
        assert!(matches!(
            import_secret(
                &mut store,
                b"harvest:stores:fp1",
                &cbor(&vec![registration(1, None)])
            ),
            SecretImport::Retryable(_)
        ));
    }

    /// Nothing outside `harvest:` and no store key is written, so an import
    /// cannot forge a migration marker or plant a signing key. Mutated red by
    /// dropping each refusal.
    #[test]
    fn foreign_keys_and_store_keys_are_refused() {
        let mut store = MemSecrets::default();
        let marker = done_key(&PRED);
        assert!(matches!(
            import_secret(&mut store, &marker, b"1"),
            SecretImport::Permanent(_)
        ));
        assert!(!store.has_secret(&marker));
        let store_key = format!("{}abc", crate::store_keys::STORE_KEY_PREFIX);
        assert!(matches!(
            import_secret(&mut store, store_key.as_bytes(), b"seed"),
            SecretImport::Permanent(_)
        ));
        assert!(store.is_empty());
    }

    /// Markers round-trip in the crate's format, and `Done` wins over an
    /// in-progress marker. Mutated red by swapping the two keys.
    #[test]
    fn markers_round_trip_and_done_wins() {
        let mut store = MemSecrets::default();
        let get = |store: &MemSecrets| match get_marker(store, PRED) {
            HarvestDelegateResponse::PredecessorMarker { marker, .. } => marker,
            other => panic!("{other:?}"),
        };
        assert_eq!(get(&store), None);
        record_marker(
            &mut store,
            PRED,
            PredecessorMarkerState::InProgress { saw_data: true },
        );
        assert_eq!(
            get(&store),
            Some(PredecessorMarkerState::InProgress { saw_data: true })
        );
        record_marker(
            &mut store,
            PRED,
            PredecessorMarkerState::Done { had_data: false },
        );
        assert_eq!(
            get(&store),
            Some(PredecessorMarkerState::Done { had_data: false })
        );
        assert_eq!(
            store.get_secret(
                &freenet_migrate::predecessor_done_marker(
                    &freenet_stdlib::prelude::DelegateKey::new(
                        PRED,
                        freenet_stdlib::prelude::CodeHash::new([0; 32])
                    ),
                    false
                )
                .0
            ),
            Some(PRED_DONE_MARKER_VALUE_EMPTY.to_vec()),
            "the completion marker is the crate's public format"
        );
    }

    /// The markers are outside `harvest:`, so no export carries them to a
    /// further successor.
    #[test]
    fn markers_are_outside_the_export_prefix() {
        for key in [done_key(&PRED), wip_key(&PRED)] {
            assert!(!key.starts_with(harvest_common::migration::SECRET_KEY_PREFIX));
        }
    }

    /// Every request is gated to the Harvest web app: an import writes
    /// secrets. Mutated red by removing `authorize` from `handlers::handle`.
    #[test]
    fn another_web_app_cannot_import() {
        let mut store = MemSecrets::default();
        let response = crate::handlers::handle(
            &mut store,
            Some(&crate::origin::test_origins::a_different_web_app()),
            HarvestDelegateRequest::ImportMigratedSecret {
                predecessor: PRED,
                key: b"harvest:rsa_sk:fp1".to_vec(),
                value: harvest_common::delegate::MigratedSecretValue(b"sk".to_vec()),
            },
        );
        assert!(
            matches!(response, HarvestDelegateResponse::Error { .. }),
            "{response:?}"
        );
        assert!(store.is_empty());
    }
}
