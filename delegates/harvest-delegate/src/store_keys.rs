//! Store keys: the Ed25519 key each store owns itself by (harvest#93, phase
//! 1a).
//!
//! # What lives here
//!
//! One secret per store key, `harvest:store_sk:{base58 verifying key}`, holding
//! the 32-byte seed. [`create`] mints one from the host's RNG and answers the
//! public half; [`sign`] signs one of a store's own records with it. The seed
//! is not handed out: no request returns it, the UI only ever holds a
//! signature, and the export to a successor generation hides this family
//! (`crate::migration::WithoutStoreKeys`). Phase 1b's custody adds the one
//! way a copy leaves: wrapped, to a backing Ghost Key, in store state.
//!
//! The key starts with `harvest:` for the reason `handlers.rs` gives: a key
//! outside that prefix is silently left behind by every future delegate
//! migration. `handlers::all_secret_key_shapes` lists it.
//!
//! # The custody seam (phase 1b)
//!
//! In phase 1a a store key lives on the device that created it and nowhere
//! else. Phase 1b wraps it to each backing Ghost Key in the store's own state
//! (docs/design/entity-model.md, section 3, "Store key custody"), so any
//! device holding a backing Ghost Key can recover it. That arrives here as
//! two more requests, `WrapStoreKeyFor` and `UnwrapStoreKey`, and both go
//! through the two functions below and nothing else:
//!
//! * [`load`] is the only reader of this secret family. Wrapping a key for a
//!   new backer reads the seed through it.
//! * [`keep`] is the only writer. Unwrapping a recovered key writes the seed
//!   through it, after checking the seed against the store key, exactly as
//!   [`create`] does for a fresh one.
//!
//! So adding custody adds callers, not a second place that knows where a
//! store key is kept or how.
//!
//! # What losing this delegate's secrets costs, until then
//!
//! A delegate re-key moves this secret out of reach unless the export
//! handshake carries it forward (see `crate::migration`), and nothing drives
//! that handshake yet. A store whose key is lost can no longer be signed for:
//! its listings, details and orders stay readable, but nothing new can be
//! published to it. Phase 1b's custody is what makes the key recoverable from
//! any backing Ghost Key; this is recorded in `docs/untested-invariants.md`.

use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_migrate::SecretStore;
use harvest_common::custody;
use harvest_common::delegate::{HarvestDelegateResponse, RequestId, StoreKeySignature};

/// Where every store key's secret lives.
pub(crate) const STORE_KEY_PREFIX: &str = "harvest:store_sk:";

/// Where the store key of a Ghost Key's unfinished store creation is
/// remembered, until `RegisterStore` names it (#98 review, M1). Holds the
/// 32-byte verifying key, not a secret; an empty value means none.
pub(crate) const CREATION_PREFIX: &str = "harvest:store_creation:";

/// The secret key a Ghost Key's unfinished creation is remembered under.
pub(crate) fn creation_secret(fingerprint: &str) -> Vec<u8> {
    format!("{CREATION_PREFIX}{fingerprint}").into_bytes()
}

/// The store key of `fingerprint`'s unfinished store creation, if one is
/// remembered and this delegate still holds its key.
pub(crate) fn unfinished_creation<S: SecretStore>(
    secrets: &S,
    fingerprint: &str,
) -> Option<SigningKey> {
    let bytes: [u8; 32] = secrets
        .get_secret(&creation_secret(fingerprint))?
        .try_into()
        .ok()?;
    load(secrets, &VerifyingKey::from_bytes(&bytes).ok()?)
}

/// `fingerprint`'s store creation finished with the store key `store`:
/// forget it, so the next creation mints a new key. A registration naming
/// another key (an older store re-registered) leaves it alone.
pub(crate) fn finish_creation<S: SecretStore>(
    secrets: &mut S,
    fingerprint: &str,
    store: &[u8; 32],
) {
    if secrets
        .get_secret(&creation_secret(fingerprint))
        .is_some_and(|held| held.as_slice() == store.as_slice())
    {
        secrets.set_secret(&creation_secret(fingerprint), &[]);
    }
}

/// How many store keys one delegate holds.
///
/// A seller has one store and, rarely, a few; this bounds what a UI stuck in a
/// loop of `CreateStoreKey` could write. Past it a new key is refused out loud,
/// never an old one dropped: an old one is a store its owner can no longer
/// sign for once it is gone.
pub(crate) const MAX_STORE_KEYS: usize = 64;

/// The secret key a store key's seed is kept under.
pub(crate) fn store_key_secret(store: &VerifyingKey) -> Vec<u8> {
    format!(
        "{STORE_KEY_PREFIX}{}",
        bs58::encode(store.as_bytes()).into_string()
    )
    .into_bytes()
}

/// The store key whose public half is `store`, if this delegate holds it.
///
/// The seed is checked against `store` on the way out, so a corrupted or
/// misfiled secret is "not held" rather than a key that signs for some other
/// store.
pub(crate) fn load<S: SecretStore>(secrets: &S, store: &VerifyingKey) -> Option<SigningKey> {
    let seed: [u8; 32] = secrets
        .get_secret(&store_key_secret(store))?
        .try_into()
        .ok()?;
    let key = SigningKey::from_bytes(&seed);
    (key.verifying_key() == *store).then_some(key)
}

/// Keep `key`, under its own verifying key. Whether the write landed.
pub(crate) fn keep<S: SecretStore>(secrets: &mut S, key: &SigningKey) -> bool {
    secrets.set_secret(&store_key_secret(&key.verifying_key()), key.as_bytes())
}

/// Mint a store key, or, for a Ghost Key whose last store creation did not
/// finish, answer the key that creation minted (see `CreateStoreKey`).
pub(crate) fn create<S: SecretStore>(
    secrets: &mut S,
    request_id: RequestId,
    fingerprint: Option<&str>,
) -> HarvestDelegateResponse {
    let refuse = |message: String| HarvestDelegateResponse::StoreKeyCreated {
        request_id,
        result: Err(message),
    };
    if let Some(key) = fingerprint.and_then(|fp| unfinished_creation(secrets, fp)) {
        return HarvestDelegateResponse::StoreKeyCreated {
            request_id,
            result: Ok(key.verifying_key().to_bytes()),
        };
    }
    let held = secrets.list_secrets(STORE_KEY_PREFIX.as_bytes()).len();
    if held >= MAX_STORE_KEYS {
        return refuse(format!(
            "this delegate already holds {held} store keys, the most it keeps; no new store \
             can be created on this device"
        ));
    }
    let mut seed = [0u8; 32];
    // The host's RNG, through the `getrandom` registration in `lib.rs`: the
    // same source the conversation keys come from.
    if let Err(e) = getrandom::getrandom(&mut seed) {
        return refuse(format!("no randomness available to make a store key: {e}"));
    }
    let key = SigningKey::from_bytes(&seed);
    if !keep(secrets, &key) {
        return refuse("the store key could not be saved, so no store was created".into());
    }
    if let Some(fp) = fingerprint {
        // Written before the UI can publish anything under this key, so a
        // retry from any tab resumes it. Best effort: without it a retry
        // mints a new key, which is what happened before.
        secrets.set_secret(&creation_secret(fp), key.verifying_key().as_bytes());
    }
    HarvestDelegateResponse::StoreKeyCreated {
        request_id,
        result: Ok(key.verifying_key().to_bytes()),
    }
}

/// Sign one of a store's own records with its store key.
pub(crate) fn sign<S: SecretStore>(
    secrets: &S,
    request_id: RequestId,
    store_verifying_key: [u8; 32],
    payload: Vec<u8>,
) -> HarvestDelegateResponse {
    let answer = |result| HarvestDelegateResponse::StoreUpdateSigned {
        request_id,
        store_verifying_key,
        result,
    };
    let Ok(store) = VerifyingKey::from_bytes(&store_verifying_key) else {
        return answer(Err("that is not a store key".into()));
    };
    let Some(key) = load(secrets, &store) else {
        return answer(Err(
            "this device does not hold the key for that store, so it cannot sign for it".into(),
        ));
    };
    answer(
        harvest_common::backing::sign_with_store_key(&key, payload).map(
            |(scoped_payload, signature)| StoreKeySignature {
                scoped_payload,
                signature,
            },
        ),
    )
}

/// Wrap the store key to a backing Ghost Key, and sign the copy with the
/// store key (harvest#93 phase 1b).
///
/// The vault's signature is checked (`custody::WrapSecret::from_sign_result`:
/// the wrap message for THIS store, under the current webapp scope, verifying
/// under the backing key), used, and dropped with the `WrapSecret` at the end
/// of this call. It is never kept.
pub(crate) fn wrap_for<S: SecretStore>(
    secrets: &S,
    request_id: RequestId,
    store_verifying_key: [u8; 32],
    backer_verifying_key: [u8; 32],
    scoped_payload: &[u8],
    signature: &[u8],
) -> HarvestDelegateResponse {
    let answer = |result: Result<custody::AuthorizedCopy, String>| {
        HarvestDelegateResponse::StoreKeyWrapped {
            request_id,
            store_verifying_key,
            result: result.map(Box::new),
        }
    };
    answer((|| {
        let store = VerifyingKey::from_bytes(&store_verifying_key)
            .map_err(|_| "that is not a store key".to_string())?;
        let backer = VerifyingKey::from_bytes(&backer_verifying_key)
            .map_err(|_| "that is not a Ghost Key".to_string())?;
        let key = load(secrets, &store)
            .ok_or("this device does not hold the key for that store, so it cannot wrap it")?;
        let scope = custody::WrapScope::current();
        let secret = custody::WrapSecret::from_sign_result(
            scoped_payload,
            signature,
            &backer,
            &store,
            scope,
        )
        .map_err(|e| format!("the vault's signature is not a wrap signature: {e}"))?;
        let wrapped = custody::wrap_store_key(&key, &secret).map_err(|e| e.to_string())?;
        let copy = custody::StoreKeyCopy {
            store,
            backer,
            scope,
            wrapped,
        };
        let payload = harvest_common::to_cbor(&copy)?;
        let (scoped_payload, signature) =
            harvest_common::backing::sign_with_store_key(&key, payload)?;
        Ok(custody::AuthorizedCopy {
            copy,
            scoped_payload,
            signature,
        })
    })())
}

/// Recover a store key from a wrapped copy, and keep it (harvest#93 phase
/// 1b). The one writer besides [`create`], through [`keep`], and only after
/// `custody::unwrap_store_key` has checked the seed IS the store's key.
pub(crate) fn unwrap<S: SecretStore>(
    secrets: &mut S,
    request_id: RequestId,
    store_verifying_key: [u8; 32],
    backer_verifying_key: [u8; 32],
    scoped_payload: &[u8],
    signature: &[u8],
    wrapped: &custody::WrappedStoreKey,
) -> HarvestDelegateResponse {
    let answer = |result| HarvestDelegateResponse::StoreKeyRecovered {
        request_id,
        store_verifying_key,
        result,
    };
    let recovered = (|| {
        let store = VerifyingKey::from_bytes(&store_verifying_key)
            .map_err(|_| "that is not a store key".to_string())?;
        let backer = VerifyingKey::from_bytes(&backer_verifying_key)
            .map_err(|_| "that is not a Ghost Key".to_string())?;
        let secret = custody::WrapSecret::from_sign_result(
            scoped_payload,
            signature,
            &backer,
            &store,
            custody::WrapScope::current(),
        )
        .map_err(|e| format!("the vault's signature is not a wrap signature: {e}"))?;
        custody::unwrap_store_key(wrapped, &secret).map_err(|e| e.to_string())
    })();
    match recovered {
        Err(why) => answer(Err(why)),
        Ok(key) => {
            let held = secrets
                .list_secrets(STORE_KEY_PREFIX.as_bytes())
                .contains(&store_key_secret(&key.verifying_key()));
            if !held && secrets.list_secrets(STORE_KEY_PREFIX.as_bytes()).len() >= MAX_STORE_KEYS {
                return answer(Err(format!(
                    "this delegate already holds {MAX_STORE_KEYS} store keys, the most it keeps"
                )));
            }
            if keep(secrets, &key) {
                answer(Ok(()))
            } else {
                answer(Err("the recovered store key could not be saved".into()))
            }
        }
    }
}

/// The public halves of a store's derived keys (harvest#93 phase 1b).
pub(crate) fn subkeys<S: SecretStore>(
    secrets: &S,
    request_id: RequestId,
    store_verifying_key: [u8; 32],
) -> HarvestDelegateResponse {
    let result = (|| {
        let store = VerifyingKey::from_bytes(&store_verifying_key)
            .map_err(|_| "that is not a store key".to_string())?;
        let key =
            load(secrets, &store).ok_or("this device does not hold the key for that store")?;
        let inbox = custody::inbox_secret(&key);
        let record_public_key = custody::record_public_key_der(&key).map_err(|e| e.to_string())?;
        Ok(harvest_common::delegate::StoreSubkeyInfo {
            inbox_public_key: x25519_dalek::PublicKey::from(&inbox).to_bytes(),
            record_public_key,
        })
    })();
    HarvestDelegateResponse::StoreSubkeys {
        request_id,
        store_verifying_key,
        result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemSecrets;
    use harvest_common::backing::{Retirement, StoreClosure};
    use harvest_common::listing::verify_scoped_signature;

    fn created(secrets: &mut MemSecrets) -> VerifyingKey {
        match create(secrets, 7, None) {
            HarvestDelegateResponse::StoreKeyCreated {
                request_id: 7,
                result: Ok(bytes),
            } => VerifyingKey::from_bytes(&bytes).expect("a curve point"),
            other => panic!("expected a new store key, got {other:?}"),
        }
    }

    fn signed(response: HarvestDelegateResponse) -> Result<StoreKeySignature, String> {
        match response {
            HarvestDelegateResponse::StoreUpdateSigned { result, .. } => result,
            other => panic!("expected a signature answer, got {other:?}"),
        }
    }

    #[test]
    fn a_created_key_is_kept_and_signs_a_store_record_that_verifies() {
        let mut secrets = MemSecrets::default();
        let store = created(&mut secrets);
        let closure = StoreClosure { store };
        let signature = signed(sign(
            &secrets,
            1,
            store.to_bytes(),
            harvest_common::to_cbor(&closure).unwrap(),
        ))
        .expect("the delegate holds this key");
        verify_scoped_signature(
            &signature.scoped_payload,
            &signature.signature,
            &store,
            &closure,
        )
        .expect("verifies as the store contract verifies");
    }

    #[test]
    fn two_created_keys_differ() {
        let mut secrets = MemSecrets::default();
        assert_ne!(created(&mut secrets), created(&mut secrets));
    }

    #[test]
    fn a_key_this_delegate_does_not_hold_cannot_sign() {
        let secrets = MemSecrets::default();
        let stranger = SigningKey::from_bytes(&[5; 32]).verifying_key();
        let retirement = Retirement { backer: stranger };
        assert!(signed(sign(
            &secrets,
            1,
            stranger.to_bytes(),
            harvest_common::to_cbor(&retirement).unwrap()
        ))
        .is_err());
    }

    /// The delegate is a signing oracle for whatever the UI asks; narrowed to
    /// a store's own records, it cannot be asked to sign anything else.
    #[test]
    fn it_refuses_to_sign_anything_that_is_not_a_store_record() {
        let mut secrets = MemSecrets::default();
        let store = created(&mut secrets);
        for payload in [
            b"harvest/store-key-wrap/v1\0".to_vec(),
            b"freenet-bitcoin/inbox-entry/v1\0".to_vec(),
            vec![0xa0], // an empty CBOR map
        ] {
            assert!(
                signed(sign(&secrets, 1, store.to_bytes(), payload.clone())).is_err(),
                "signed {payload:?}"
            );
        }
    }

    #[test]
    fn a_seed_filed_under_the_wrong_key_is_not_used() {
        let mut secrets = MemSecrets::default();
        let store = SigningKey::from_bytes(&[1; 32]).verifying_key();
        // Some other key's seed, under this store's name.
        secrets.set_secret(&store_key_secret(&store), &[2u8; 32]);
        assert!(load(&secrets, &store).is_none());
    }

    #[test]
    fn a_failed_write_creates_nothing() {
        let mut secrets = MemSecrets::default();
        secrets.writes_fail = true;
        assert!(matches!(
            create(&mut secrets, 1, None),
            HarvestDelegateResponse::StoreKeyCreated { result: Err(_), .. }
        ));
    }

    /// A Ghost Key's unfinished store creation gets the SAME key back on
    /// every retry, from any tab, until the store is registered; then a new
    /// one (#98 review, M1). Mutated red by skipping the lookup in `create`
    /// and by never finishing.
    #[test]
    fn a_retried_creation_gets_the_same_store_key_until_registered() {
        let mut secrets = MemSecrets::default();
        let key = |r: HarvestDelegateResponse| match r {
            HarvestDelegateResponse::StoreKeyCreated { result: Ok(k), .. } => k,
            other => panic!("expected a store key, got {other:?}"),
        };
        let first = key(create(&mut secrets, 1, Some("fp-a")));
        assert_eq!(key(create(&mut secrets, 2, Some("fp-a"))), first, "resumed");
        assert_ne!(
            key(create(&mut secrets, 3, Some("fp-b"))),
            first,
            "per Ghost Key"
        );
        assert_ne!(key(create(&mut secrets, 4, None)), first, "an old UI mints");

        // Another key registered for fp-a does not end it; its own does.
        finish_creation(&mut secrets, "fp-a", &[9u8; 32]);
        assert_eq!(key(create(&mut secrets, 5, Some("fp-a"))), first);
        finish_creation(&mut secrets, "fp-a", &first);
        assert_ne!(
            key(create(&mut secrets, 6, Some("fp-a"))),
            first,
            "finished"
        );
    }

    #[test]
    fn creation_stops_at_the_cap_and_keeps_every_key_below_it() {
        let mut secrets = MemSecrets::default();
        let keys: Vec<VerifyingKey> = (0..MAX_STORE_KEYS).map(|_| created(&mut secrets)).collect();
        assert!(matches!(
            create(&mut secrets, 1, None),
            HarvestDelegateResponse::StoreKeyCreated { result: Err(_), .. }
        ));
        assert!(keys.iter().all(|key| load(&secrets, key).is_some()));
    }

    // --- Custody (harvest#93 phase 1b) ---------------------------------

    fn ghost() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    /// What the vault answers for `SignMessage { message }` from the Harvest
    /// web app: its signature over the scoped payload.
    fn vault_sign(key: &SigningKey, message: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer;
        let scoped = ghostkey_common::to_cbor(&ghostkey_common::ScopedPayload {
            requestor: harvest_common::expected_harvest_requestor(),
            payload: message,
        })
        .unwrap();
        let sig = key.sign(&scoped).to_bytes().to_vec();
        (scoped, sig)
    }

    fn wrapped(response: HarvestDelegateResponse) -> Result<custody::AuthorizedCopy, String> {
        match response {
            HarvestDelegateResponse::StoreKeyWrapped { result, .. } => result.map(|copy| *copy),
            other => panic!("expected a wrap answer, got {other:?}"),
        }
    }

    fn recovered(response: HarvestDelegateResponse) -> Result<(), String> {
        match response {
            HarvestDelegateResponse::StoreKeyRecovered { result, .. } => result,
            other => panic!("expected a recovery answer, got {other:?}"),
        }
    }

    /// The whole custody loop: the device that made the store wraps its key
    /// to the backing Ghost Key and signs the copy; a device that has lost
    /// every delegate secret (a delegate re-key) recovers the key from that
    /// copy with nothing but the Ghost Key's vault signature, and can sign
    /// for the store again.
    #[test]
    fn a_device_with_a_backing_ghost_key_recovers_the_store_key() {
        let mut device = MemSecrets::default();
        let store = created(&mut device);
        let (scoped, sig) = vault_sign(&ghost(), custody::wrap_message(&store));
        let copy = wrapped(wrap_for(
            &device,
            1,
            store.to_bytes(),
            ghost().verifying_key().to_bytes(),
            &scoped,
            &sig,
        ))
        .expect("the store's own device wraps its key");
        copy.verify(&store)
            .expect("a copy the store contract accepts");
        assert_eq!(copy.copy.backer, ghost().verifying_key());
        assert_eq!(copy.copy.scope, custody::WrapScope::current());

        // Everything lost.
        let mut fresh = MemSecrets::default();
        assert!(load(&fresh, &store).is_none());
        recovered(unwrap(
            &mut fresh,
            2,
            store.to_bytes(),
            ghost().verifying_key().to_bytes(),
            &scoped,
            &sig,
            &copy.copy.wrapped,
        ))
        .expect("the backing Ghost Key opens it");
        assert!(load(&fresh, &store).is_some(), "and the key is kept");
        assert!(signed(sign(
            &fresh,
            3,
            store.to_bytes(),
            harvest_common::to_cbor(&StoreClosure { store }).unwrap()
        ))
        .is_ok());
    }

    /// Only the wrap message for THIS store, signed by the named backer,
    /// opens or makes a copy. A signature the vault made for anything else,
    /// or by another Ghost Key, is refused before any key is derived.
    #[test]
    fn a_signature_that_is_not_this_stores_wrap_signature_is_refused() {
        let mut device = MemSecrets::default();
        let store = created(&mut device);
        let other_store = SigningKey::from_bytes(&[0x77; 32]).verifying_key();
        let backer = ghost().verifying_key().to_bytes();

        let (scoped, sig) = vault_sign(&ghost(), custody::wrap_message(&other_store));
        assert!(wrapped(wrap_for(
            &device,
            1,
            store.to_bytes(),
            backer,
            &scoped,
            &sig
        ))
        .is_err());

        let (scoped, sig) = vault_sign(
            &SigningKey::from_bytes(&[9; 32]),
            custody::wrap_message(&store),
        );
        assert!(wrapped(wrap_for(
            &device,
            1,
            store.to_bytes(),
            backer,
            &scoped,
            &sig
        ))
        .is_err());

        let (scoped, sig) = vault_sign(&ghost(), b"not a wrap message".to_vec());
        assert!(wrapped(wrap_for(
            &device,
            1,
            store.to_bytes(),
            backer,
            &scoped,
            &sig
        ))
        .is_err());
    }

    /// Recovery respects the 64-key cap, except for a key the delegate
    /// already holds. Mutated red by removing the cap check in `unwrap`.
    #[test]
    fn recovery_stops_at_the_cap_unless_the_key_is_already_held() {
        let mut device = MemSecrets::default();
        let store = created(&mut device);
        let (scoped, sig) = vault_sign(&ghost(), custody::wrap_message(&store));
        let copy = wrapped(wrap_for(
            &device,
            1,
            store.to_bytes(),
            ghost().verifying_key().to_bytes(),
            &scoped,
            &sig,
        ))
        .unwrap();
        let recover = |secrets: &mut MemSecrets| {
            recovered(unwrap(
                secrets,
                2,
                store.to_bytes(),
                ghost().verifying_key().to_bytes(),
                &scoped,
                &sig,
                &copy.copy.wrapped,
            ))
        };

        let mut full = MemSecrets::default();
        for _ in 0..MAX_STORE_KEYS {
            created(&mut full);
        }
        assert!(recover(&mut full).is_err(), "no 65th key");
        assert!(load(&full, &store).is_none());

        for _ in 1..MAX_STORE_KEYS {
            created(&mut device);
        }
        recover(&mut device).expect("a key already held is not a new one");
    }

    /// A copy opened under the wrong Ghost Key's signature, or a corrupt one,
    /// recovers nothing and keeps nothing.
    #[test]
    fn a_copy_that_does_not_open_keeps_nothing() {
        let mut device = MemSecrets::default();
        let store = created(&mut device);
        let (scoped, sig) = vault_sign(&ghost(), custody::wrap_message(&store));
        let mut copy = wrapped(wrap_for(
            &device,
            1,
            store.to_bytes(),
            ghost().verifying_key().to_bytes(),
            &scoped,
            &sig,
        ))
        .unwrap();
        copy.copy.wrapped.ciphertext[0] ^= 1;
        let mut fresh = MemSecrets::default();
        assert!(recovered(unwrap(
            &mut fresh,
            2,
            store.to_bytes(),
            ghost().verifying_key().to_bytes(),
            &scoped,
            &sig,
            &copy.copy.wrapped,
        ))
        .is_err());
        assert!(fresh.list_secrets(STORE_KEY_PREFIX.as_bytes()).is_empty());
    }

    /// The published subkeys are the ones the store key derives: the inbox
    /// key every device decrypts with, and the record key.
    #[test]
    fn the_subkeys_are_the_store_keys_derivations() {
        let mut device = MemSecrets::default();
        let store = created(&mut device);
        let key = load(&device, &store).unwrap();
        match subkeys(&device, 1, store.to_bytes()) {
            HarvestDelegateResponse::StoreSubkeys {
                result: Ok(info), ..
            } => {
                assert_eq!(
                    info.inbox_public_key,
                    x25519_dalek::PublicKey::from(&custody::inbox_secret(&key)).to_bytes()
                );
                assert_eq!(
                    info.record_public_key,
                    custody::record_public_key_der(&key).unwrap()
                );
            }
            other => panic!("expected subkeys, got {other:?}"),
        }
    }
}
