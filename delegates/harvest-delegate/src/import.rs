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

use crate::secrets::RemovableSecrets;

/// `freenet-migrate`'s in-progress marker prefix (crate-private there; see the
/// module docs for why reproducing it is sound).
const PRED_WIP_PREFIX: &[u8] = b"\0freenet-migrate/v1/pred-wip:";

/// The TRAVELLING record that a predecessor's secrets were folded into this
/// generation: `harvest:folded:` and the predecessor's key in hex.
///
/// The completion marker above is per-successor and must not travel -- it
/// says THIS delegate imported that predecessor. This one says something that
/// stays true for whoever imports this delegate's export in full: everything
/// the predecessor held, bar what this generation since deleted, is in what
/// you just imported. So it sits under `harvest:`, is exported, and a later
/// generation that finds it treats that predecessor as done
/// ([`get_marker`]). Without it every delegate re-key would walk every
/// generation back to V5 again and bring back what a newer one deleted -- a
/// forgotten conversation, an unwatched address -- because each generation's
/// seals stay behind with it.
///
/// Hex, never raw bytes: a key run through a lossy UTF-8 conversion aliases.
pub(crate) fn folded_key(predecessor: &[u8; 32]) -> Vec<u8> {
    let mut key = b"harvest:folded:".to_vec();
    key.extend_from_slice(hex_lower(predecessor).as_bytes());
    key
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

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
    } else if let Some(value) = store.get_secret(&folded_key(&predecessor)) {
        // Folded into a generation this delegate has imported: its data came
        // in with that one.
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
///
/// # A `Done` is written LAST
///
/// Sealing a predecessor is three writes: the travelling records it carried
/// (staged by [`import`] until now), its own travelling record, and the
/// completion marker. The completion marker goes last, because once it is
/// down `get_marker` answers `Done` and this predecessor is never offered
/// again -- so a travelling record that failed after it would be missing for
/// good, and the next re-key would walk this predecessor again and bring back
/// what was deleted since. Written last, any failure leaves the marker absent,
/// the crate retries the whole seal next load, and every write here is
/// idempotent. A travelling record that landed without its marker already
/// reads as done ([`get_marker`]), which is true: it is written only once
/// every item of this predecessor landed.
pub(crate) fn record_marker<S: SecretStore + RemovableSecrets>(
    store: &mut S,
    predecessor: [u8; 32],
    marker: PredecessorMarkerState,
) -> HarvestDelegateResponse {
    let recorded = match marker {
        PredecessorMarkerState::InProgress { saw_data } => {
            store.set_secret(&wip_key(&predecessor), data_value(saw_data))
        }
        PredecessorMarkerState::Done { had_data } => {
            promote_staged(store, &predecessor)
                && store.set_secret(&folded_key(&predecessor), data_value(had_data))
                && store.set_secret(&done_key(&predecessor), data_value(had_data))
        }
    };
    HarvestDelegateResponse::PredecessorMarkerRecorded {
        predecessor,
        marker,
        recorded,
    }
}

fn data_value(data: bool) -> &'static [u8] {
    if data {
        PRED_DONE_MARKER_VALUE_DATA
    } else {
        PRED_DONE_MARKER_VALUE_EMPTY
    }
}

/// Where a travelling record imported from `predecessor` waits until that
/// predecessor is sealed. Outside `harvest:`, so it is never exported while
/// staged.
fn staged_prefix(predecessor: &[u8; 32]) -> Vec<u8> {
    let mut key = b"\0harvest/folded-staged/".to_vec();
    key.extend_from_slice(hex_lower(predecessor).as_bytes());
    key.push(b'/');
    key
}

/// Turn the travelling records staged from `predecessor` into real ones.
/// Answers whether every one landed; the staged copies are then removed,
/// best effort (one left behind is re-promoted, harmlessly, next time).
fn promote_staged<S: SecretStore + RemovableSecrets>(
    store: &mut S,
    predecessor: &[u8; 32],
) -> bool {
    let prefix = staged_prefix(predecessor);
    let staged = store.list_secrets(&prefix);
    for key in &staged {
        let Some(value) = store.get_secret(key) else {
            return false;
        };
        let real = [b"harvest:folded:".as_slice(), &key[prefix.len()..]].concat();
        if !store.set_secret(&real, &value) {
            return false;
        }
    }
    for key in &staged {
        store.remove_secret(key);
    }
    true
}

/// Answer `ImportMigratedSecret`.
pub(crate) fn import<S: SecretStore>(
    store: &mut S,
    predecessor: [u8; 32],
    key: Vec<u8>,
    value: &[u8],
) -> HarvestDelegateResponse {
    let outcome = if family(&key) == Family::Folded {
        stage_folded(store, &predecessor, &key, value)
    } else {
        import_secret(store, &key, value)
    };
    HarvestDelegateResponse::MigratedSecretImported {
        predecessor,
        key,
        outcome,
    }
}

/// Which import rule a secret key falls under.
///
/// An explicit enum rather than a chain of prefix tests, so that every key
/// shape this delegate writes is decided on purpose: `every_key_shape_has_a_family`
/// fails for a new shape until somebody says which rule it needs. The shape
/// that falls through silently is the ghostkeys/Delta failure -- a list
/// imported as a standalone value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    /// Not a Harvest secret, or a store key (recovered through custody).
    Refused,
    /// A Ghost Key's store registrations: merged by store contract id.
    StoreRegistry,
    /// The Bitcoin watch list: merged by (network, script).
    Watches,
    /// Half of a Ghost Key's RSA reputation keypair: only ever imported so
    /// that the two halves held afterwards are a pair.
    RsaHalf,
    /// The payment key and its derivation counter: the counter is raised to
    /// the higher of the two when both sides hold the same key.
    PaymentXpub,
    /// A buyer's kept conversation: capped.
    BuyerConversation,
    /// A remembered store: capped.
    KnownStore,
    /// A travelling "folded into" record: staged until the predecessor
    /// carrying it is sealed.
    Folded,
    /// Everything else: written only if absent.
    Standalone,
}

/// The rule for `key`.
pub(crate) fn family(key: &[u8]) -> Family {
    use harvest_common::migration::SECRET_KEY_PREFIX;
    if !key.starts_with(SECRET_KEY_PREFIX)
        || key.starts_with(crate::store_keys::STORE_KEY_PREFIX.as_bytes())
    {
        // An export covers `harvest:` only, so a foreign key is not something
        // any predecessor sends, and it could name anything in this
        // delegate's namespace, the migration markers above included. A store
        // key is never exported (`migration::WithoutStoreKeys`); custody
        // recovers it.
        Family::Refused
    } else if key.starts_with(b"harvest:stores:") {
        Family::StoreRegistry
    } else if key == crate::bitcoin::BITCOIN_WATCHES_KEY {
        Family::Watches
    } else if key == crate::bitcoin::BITCOIN_PAYMENT_XPUB_KEY {
        Family::PaymentXpub
    } else if key.starts_with(b"harvest:rsa_sk:") || key.starts_with(b"harvest:rsa_pk:") {
        Family::RsaHalf
    } else if key.starts_with(crate::messaging::BUYER_CONVERSATION_PREFIX_STR.as_bytes()) {
        Family::BuyerConversation
    } else if key.starts_with(crate::known_stores::KNOWN_STORE_PREFIX.as_bytes()) {
        Family::KnownStore
    } else if key.starts_with(b"harvest:folded:") {
        Family::Folded
    } else {
        Family::Standalone
    }
}

/// Stage a travelling record carried by `predecessor` until that predecessor
/// is sealed ([`record_marker`]).
///
/// Written straight through, it would take effect in the same walk, before
/// the predecessor carrying it is known to be complete: if that predecessor
/// then ended `Incomplete` (an item refused), the record would still make
/// this delegate skip the generation it names -- whose own copy of the
/// refused item the crate deliberately offers next.
fn stage_folded<S: SecretStore>(
    store: &mut S,
    predecessor: &[u8; 32],
    key: &[u8],
    value: &[u8],
) -> SecretImport {
    let named = &key[b"harvest:folded:".len()..];
    let staged = [staged_prefix(predecessor).as_slice(), named].concat();
    written(store.set_secret(&staged, value))
}

/// Import one secret by the rules of its family. See the module docs.
pub(crate) fn import_secret<S: SecretStore>(
    store: &mut S,
    key: &[u8],
    value: &[u8],
) -> SecretImport {
    match family(key) {
        Family::Refused => SecretImport::Permanent("not an importable Harvest secret".into()),
        Family::StoreRegistry => merge_list(
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
        ),
        Family::Watches => merge_list(
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
        ),
        Family::RsaHalf => import_rsa_half(store, key, value),
        Family::PaymentXpub => import_payment_xpub(store, key, value),
        Family::BuyerConversation => copy_within_cap(
            store,
            key,
            value,
            crate::messaging::BUYER_CONVERSATION_PREFIX_STR.as_bytes(),
            crate::messaging::MAX_BUYER_CONVERSATIONS,
        ),
        Family::KnownStore => crate::known_stores::import(store, key, value),
        // Only reached if a caller bypasses `import`; staging needs the
        // predecessor, so a direct copy is the one wrong answer.
        Family::Folded => SecretImport::Permanent("a travelling record needs its carrier".into()),
        Family::Standalone => copy_if_absent(store, key, value),
    }
}

/// The public half a PKCS#1 private key implies, as `handle_init_reputation_keys`
/// stores it.
fn rsa_public_of(sk_der: &[u8]) -> Option<Vec<u8>> {
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
    let sk = rsa::RsaPrivateKey::from_pkcs1_der(sk_der).ok()?;
    sk.to_public_key()
        .to_pkcs1_der()
        .ok()
        .map(|d| d.as_bytes().to_vec())
}

/// Import one half of a Ghost Key's RSA reputation keypair so that whatever
/// this delegate holds afterwards is a PAIR.
///
/// The two halves are separate secrets (`handle_init_reputation_keys` writes
/// them one after the other), and importing each never-clobber on its own can
/// leave a private key from one generation beside a public key from another:
/// `GetRsaPublicKey` then advertises a key whose private half is not held.
/// So a half is written only if this delegate holds the matching half or
/// neither; a half that contradicts the one held is refused `Permanent` --
/// the held key is authoritative, and the contradiction is a property of the
/// bytes, stable over time.
fn import_rsa_half<S: SecretStore>(store: &mut S, key: &[u8], value: &[u8]) -> SecretImport {
    if store.has_secret(key) {
        return SecretImport::AlreadyAuthoritative;
    }
    let is_private = key.starts_with(b"harvest:rsa_sk:");
    let fingerprint = &key[b"harvest:rsa_sk:".len()..];
    let other_key = [
        if is_private {
            &b"harvest:rsa_pk:"[..]
        } else {
            &b"harvest:rsa_sk:"[..]
        },
        fingerprint,
    ]
    .concat();
    if let Some(other) = store.get_secret(&other_key) {
        let pair = if is_private {
            rsa_public_of(value).is_some_and(|public| public == other)
        } else {
            rsa_public_of(&other).is_some_and(|public| public == value)
        };
        if !pair {
            return SecretImport::Permanent(
                "this delegate holds the other half of a different RSA keypair for this identity"
                    .into(),
            );
        }
    }
    written(store.set_secret(key, value))
}

/// Import the payment key and its derivation counter.
///
/// Never-clobber would be wrong in one case that matters: the seller entered
/// the SAME account key on the new generation before the walk ran, so the new
/// record restarted the counter (or recovered only the highest PUBLISHED
/// index), while the predecessor's counter also covers addresses handed out
/// and not yet published. Then the higher counter is taken; a lower one is
/// never written back, and a different key on either side leaves this
/// delegate's own record alone.
fn import_payment_xpub<S: SecretStore>(store: &mut S, key: &[u8], value: &[u8]) -> SecretImport {
    use harvest_common::bitcoin_delegate::PaymentXpubStatus;
    let Ok(incoming) = from_cbor::<Option<PaymentXpubStatus>>(value) else {
        return SecretImport::Permanent("the predecessor's payment key did not decode".into());
    };
    let Some(incoming) = incoming else {
        return SecretImport::AlreadyAuthoritative;
    };
    let held = match store.get_secret(key) {
        None => None,
        Some(bytes) => match from_cbor::<Option<PaymentXpubStatus>>(&bytes) {
            Ok(held) => held,
            Err(_) => {
                return SecretImport::Retryable(
                    "this delegate's own payment key did not decode".into(),
                )
            }
        },
    };
    let merged = match held {
        None => incoming,
        Some(mut held) => {
            if held.xpub != incoming.xpub
                || held.network != incoming.network
                || held.next_index >= incoming.next_index
            {
                return SecretImport::AlreadyAuthoritative;
            }
            held.next_index = incoming.next_index;
            held
        }
    };
    match to_cbor(&Some(merged)) {
        Ok(bytes) => written(store.set_secret(key, &bytes)),
        Err(_) => SecretImport::Retryable("could not encode the payment key".into()),
    }
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
        store.set_secret(b"harvest:x25519_sk:fp1", b"newer");
        assert_eq!(
            import_secret(&mut store, b"harvest:x25519_sk:fp1", b"older"),
            SecretImport::AlreadyAuthoritative
        );
        assert_eq!(
            store.get_secret(b"harvest:x25519_sk:fp1").unwrap(),
            b"newer"
        );
        assert_eq!(
            import_secret(&mut store, b"harvest:x25519_sk:fp2", b"other"),
            SecretImport::Written
        );
        assert_eq!(
            store.get_secret(b"harvest:x25519_sk:fp2").unwrap(),
            b"other"
        );
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

    /// The watch list merges by its identities.
    #[test]
    fn the_watch_list_is_merged() {
        let mut store = MemSecrets::default();

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
        let prefix = crate::messaging::BUYER_CONVERSATION_PREFIX_STR;
        for i in 0..crate::messaging::MAX_BUYER_CONVERSATIONS {
            store.set_secret(format!("{prefix}{i:016}").as_bytes(), b"x");
        }
        let key = format!("{prefix}ZZZZZZZZZZZZZZZZ");
        assert!(matches!(
            import_secret(&mut store, key.as_bytes(), b"x"),
            SecretImport::Retryable(_)
        ));
        assert_eq!(
            store.list_secrets(prefix.as_bytes()).len(),
            crate::messaging::MAX_BUYER_CONVERSATIONS
        );
    }

    /// A refused write is retryable, never success. Mutated red by answering
    /// `Written` regardless.
    #[test]
    fn a_refused_write_is_retryable() {
        let mut store = MemSecrets::refusing_writes();
        assert!(matches!(
            import_secret(&mut store, b"harvest:x25519_sk:fp1", b"sk"),
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
        for key in [done_key(&PRED), wip_key(&PRED), staged_prefix(&PRED)] {
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

    /// A real RSA keypair in the encoding the retired `InitReputationKeys`
    /// stored (PKCS#1 DER, both halves). A predecessor delegate may still
    /// hold one; this delegate no longer mints them (harvest#53 Phase C).
    /// Fresh per call, so two calls never share a key.
    fn rsa_pair(_fp: &str) -> (Vec<u8>, Vec<u8>) {
        use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
        let sk = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).expect("rsa keygen");
        (
            sk.to_pkcs1_der().expect("sk der").as_bytes().to_vec(),
            sk.to_public_key()
                .to_pkcs1_der()
                .expect("pk der")
                .as_bytes()
                .to_vec(),
        )
    }

    /// Both halves of a predecessor's keypair arrive when this delegate holds
    /// neither, in either order.
    #[test]
    fn an_rsa_pair_is_imported_whole() {
        let (sk, pk) = rsa_pair("fp1");
        let mut store = MemSecrets::default();
        assert_eq!(
            import_secret(&mut store, b"harvest:rsa_pk:fp1", &pk),
            SecretImport::Written
        );
        assert_eq!(
            import_secret(&mut store, b"harvest:rsa_sk:fp1", &sk),
            SecretImport::Written
        );
        let mut store = MemSecrets::default();
        assert_eq!(
            import_secret(&mut store, b"harvest:rsa_sk:fp1", &sk),
            SecretImport::Written
        );
        assert_eq!(
            import_secret(&mut store, b"harvest:rsa_pk:fp1", &pk),
            SecretImport::Written
        );
    }

    /// **The half that would make a mismatched pair is refused.** A delegate
    /// holding one half of ITS keypair must not gain the other half of a
    /// predecessor's: `GetRsaPublicKey` would advertise one key while blind
    /// signatures used another. Mutated red by dropping the pair check.
    #[test]
    fn a_half_from_another_keypair_is_refused() {
        let (sk_old, pk_old) = rsa_pair("old");
        let (sk_new, pk_new) = rsa_pair("new");
        let mut store = MemSecrets::default();
        store.set_secret(b"harvest:rsa_sk:fp1", &sk_new);
        assert!(matches!(
            import_secret(&mut store, b"harvest:rsa_pk:fp1", &pk_old),
            SecretImport::Permanent(_)
        ));
        assert!(!store.has_secret(b"harvest:rsa_pk:fp1"));
        assert_eq!(
            import_secret(&mut store, b"harvest:rsa_pk:fp1", &pk_new),
            SecretImport::Written,
            "the matching half is accepted"
        );
        let mut store = MemSecrets::default();
        store.set_secret(b"harvest:rsa_pk:fp1", &pk_new);
        assert!(matches!(
            import_secret(&mut store, b"harvest:rsa_sk:fp1", &sk_old),
            SecretImport::Permanent(_)
        ));
        assert!(!store.has_secret(b"harvest:rsa_sk:fp1"));
    }

    fn xpub(key: &str, next_index: u32) -> Vec<u8> {
        cbor(&Some(harvest_common::bitcoin_delegate::PaymentXpubStatus {
            xpub: key.into(),
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            next_index,
        }))
    }

    fn held_index(store: &MemSecrets) -> u32 {
        from_cbor::<Option<harvest_common::bitcoin_delegate::PaymentXpubStatus>>(
            &store
                .get_secret(crate::bitcoin::BITCOIN_PAYMENT_XPUB_KEY)
                .unwrap(),
        )
        .unwrap()
        .unwrap()
        .next_index
    }

    /// The same payment key on both sides keeps the HIGHER counter, so an
    /// address the predecessor handed out is not handed out again. A
    /// different key, or a lower counter, leaves this delegate's record
    /// alone. Mutated red by never-clobbering, and by taking the lower.
    #[test]
    fn the_payment_counter_is_raised_never_lowered() {
        let key = crate::bitcoin::BITCOIN_PAYMENT_XPUB_KEY;
        let mut store = MemSecrets::default();
        store.set_secret(key, &xpub("vpubA", 2));
        assert_eq!(
            import_secret(&mut store, key, &xpub("vpubA", 7)),
            SecretImport::Written
        );
        assert_eq!(held_index(&store), 7);
        assert_eq!(
            import_secret(&mut store, key, &xpub("vpubA", 3)),
            SecretImport::AlreadyAuthoritative
        );
        assert_eq!(held_index(&store), 7);
        assert_eq!(
            import_secret(&mut store, key, &xpub("vpubB", 50)),
            SecretImport::AlreadyAuthoritative
        );
        assert_eq!(
            held_index(&store),
            7,
            "another key's counter says nothing about this one"
        );
        let mut empty = MemSecrets::default();
        assert_eq!(
            import_secret(&mut empty, key, &xpub("vpubA", 4)),
            SecretImport::Written
        );
    }

    /// Every key shape this delegate writes has a family decided on purpose.
    /// A new shape fails here until somebody says which rule it needs.
    #[test]
    fn every_key_shape_has_a_family() {
        let expected = [
            Family::RsaHalf,
            Family::RsaHalf,
            Family::StoreRegistry,
            Family::Standalone, // x25519 secret
            Family::Watches,
            Family::Standalone, // bridge config
            Family::PaymentXpub,
            Family::Standalone, // migration and notice markers
            Family::BuyerConversation,
            Family::KnownStore,
            Family::Refused,    // store key
            Family::Standalone, // unfinished store creation
            Family::Folded,     // travelling "folded into" record
        ];
        let shapes = crate::handlers::all_secret_key_shapes("fp1");
        assert_eq!(
            shapes.len(),
            expected.len(),
            "a key shape was added or removed: decide its import family here"
        );
        for (shape, want) in shapes.iter().zip(expected) {
            assert_eq!(family(shape), want, "{}", String::from_utf8_lossy(shape));
        }
    }

    /// A predecessor list that does not decode is refused; this delegate's
    /// own list that does not decode is left alone and retried, never
    /// replaced.
    #[test]
    fn an_undecodable_list_is_never_merged_over() {
        let key = b"harvest:stores:fp1";
        let mut store = MemSecrets::default();
        assert!(matches!(
            import_secret(&mut store, key, b"not cbor"),
            SecretImport::Permanent(_)
        ));
        store.set_secret(key, b"corrupt");
        assert!(matches!(
            import_secret(&mut store, key, &cbor(&vec![registration(1, None)])),
            SecretImport::Retryable(_)
        ));
        assert_eq!(store.get_secret(key).unwrap(), b"corrupt");
    }

    /// A refused marker write is reported, so the UI does not seal a
    /// predecessor whose `Done` never landed.
    #[test]
    fn a_refused_marker_write_is_reported() {
        let mut store = MemSecrets::refusing_writes();
        match record_marker(
            &mut store,
            PRED,
            PredecessorMarkerState::Done { had_data: true },
        ) {
            HarvestDelegateResponse::PredecessorMarkerRecorded { recorded, .. } => {
                assert!(!recorded)
            }
            other => panic!("{other:?}"),
        }
    }

    /// **Deletions stay deleted across the next re-key.** Sealing a
    /// predecessor `Done` also writes a record that travels in this
    /// delegate's export, and a later generation that imports it treats that
    /// predecessor as done instead of walking it again (which would bring
    /// back a conversation forgotten here). Mutated red by not writing the
    /// travelling record, and by not reading it in `get_marker`.
    #[test]
    fn a_folded_predecessor_is_done_for_the_next_generation() {
        const CARRIER: [u8; 32] = [0xC1; 32];
        let mut this = MemSecrets::default();
        record_marker(
            &mut this,
            PRED,
            PredecessorMarkerState::Done { had_data: true },
        );
        let travelling = folded_key(&PRED);
        assert!(travelling.starts_with(harvest_common::migration::SECRET_KEY_PREFIX));
        let value = this.get_secret(&travelling).expect("the travelling record");

        // The next generation imports this one's export (this generation is
        // CARRIER to it), travelling record included.
        let mut next = MemSecrets::default();
        match import(&mut next, CARRIER, travelling.clone(), &value) {
            HarvestDelegateResponse::MigratedSecretImported { outcome, .. } => {
                assert_eq!(outcome, SecretImport::Written)
            }
            other => panic!("{other:?}"),
        }
        let marker = |store: &MemSecrets| match get_marker(store, PRED) {
            HarvestDelegateResponse::PredecessorMarker { marker, .. } => marker,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            marker(&next),
            None,
            "staged, not in effect, while its carrier is not sealed"
        );
        record_marker(
            &mut next,
            CARRIER,
            PredecessorMarkerState::Done { had_data: true },
        );
        assert_eq!(
            marker(&next),
            Some(PredecessorMarkerState::Done { had_data: true })
        );

        // An in-progress marker writes no travelling record.
        let mut other = MemSecrets::default();
        record_marker(
            &mut other,
            [9; 32],
            PredecessorMarkerState::InProgress { saw_data: true },
        );
        assert!(!other.has_secret(&folded_key(&[9; 32])));
    }

    /// A store that refuses writes to keys with one prefix.
    #[derive(Default)]
    struct RefusingPrefix {
        inner: MemSecrets,
        prefix: Vec<u8>,
    }

    impl SecretStore for RefusingPrefix {
        fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.inner.list_secrets(prefix)
        }
        fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.get_secret(key)
        }
        fn has_secret(&self, key: &[u8]) -> bool {
            self.inner.has_secret(key)
        }
        fn set_secret(&mut self, key: &[u8], value: &[u8]) -> bool {
            !key.starts_with(&self.prefix) && self.inner.set_secret(key, value)
        }
    }

    impl RemovableSecrets for RefusingPrefix {
        fn remove_secret(&mut self, key: &[u8]) -> bool {
            self.inner.remove_secret(key)
        }
    }

    /// **A `Done` whose travelling record did not land is not written.**
    /// Otherwise the predecessor reads as done forever and its travelling
    /// record is never retried, so the next re-key walks it again. Mutated
    /// red by writing the completion marker first.
    #[test]
    fn a_failed_travelling_write_leaves_the_predecessor_unsealed() {
        let mut store = RefusingPrefix {
            prefix: b"harvest:folded:".to_vec(),
            ..Default::default()
        };
        match record_marker(
            &mut store,
            PRED,
            PredecessorMarkerState::Done { had_data: true },
        ) {
            HarvestDelegateResponse::PredecessorMarkerRecorded { recorded, .. } => {
                assert!(!recorded)
            }
            other => panic!("{other:?}"),
        }
        match get_marker(&store, PRED) {
            HarvestDelegateResponse::PredecessorMarker { marker, .. } => {
                assert_eq!(marker, None, "not sealed, so the next load seals it again")
            }
            other => panic!("{other:?}"),
        }
    }

    /// A predecessor sealed as empty travels as empty.
    #[test]
    fn a_travelling_record_keeps_the_data_flag() {
        let mut store = MemSecrets::default();
        record_marker(
            &mut store,
            PRED,
            PredecessorMarkerState::Done { had_data: false },
        );
        store.remove_secret(&done_key(&PRED));
        match get_marker(&store, PRED) {
            HarvestDelegateResponse::PredecessorMarker { marker, .. } => {
                assert_eq!(
                    marker,
                    Some(PredecessorMarkerState::Done { had_data: false })
                )
            }
            other => panic!("{other:?}"),
        }
    }

    /// A remembered store archived on the predecessor stays archived even
    /// when the connect path already remembered it here, unarchived. Mutated
    /// red by never-clobbering the record.
    #[test]
    fn an_archived_store_stays_archived() {
        let code = "3Bn8xWqLd6Tz9Kf2";
        let key = crate::known_stores::known_store_key(code);
        let mut store = MemSecrets::default();
        crate::known_stores::remember(&mut store, code);
        let mut predecessor = MemSecrets::default();
        crate::known_stores::set_archived(&mut predecessor, code, true);
        let archived = predecessor.get_secret(&key).unwrap();
        assert_eq!(
            import_secret(&mut store, &key, &archived),
            SecretImport::Written
        );
        assert_eq!(store.get_secret(&key).unwrap(), archived);
        assert_eq!(
            import_secret(&mut store, &key, &archived),
            SecretImport::AlreadyAuthoritative,
            "a repeat changes nothing"
        );
    }
}
