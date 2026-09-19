//! Store keys: the Ed25519 key each store owns itself by (harvest#93, phase
//! 1a).
//!
//! # What lives here
//!
//! One secret per store key, `harvest:store_sk:{base58 verifying key}`, holding
//! the 32-byte seed. [`create`] mints one from the host's RNG and answers the
//! public half; [`sign`] signs one of a store's own records with it. The seed
//! never leaves this delegate: no request returns it, and the only thing the
//! UI ever holds is a signature.
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
use harvest_common::delegate::{HarvestDelegateResponse, RequestId, StoreKeySignature};

/// Where every store key's secret lives.
pub(crate) const STORE_KEY_PREFIX: &str = "harvest:store_sk:";

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

/// Mint a store key.
pub(crate) fn create<S: SecretStore>(
    secrets: &mut S,
    request_id: RequestId,
) -> HarvestDelegateResponse {
    let refuse = |message: String| HarvestDelegateResponse::StoreKeyCreated {
        request_id,
        result: Err(message),
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemSecrets;
    use harvest_common::backing::{Retirement, StoreClosure};
    use harvest_common::listing::verify_scoped_signature;

    fn created(secrets: &mut MemSecrets) -> VerifyingKey {
        match create(secrets, 7) {
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
            create(&mut secrets, 1),
            HarvestDelegateResponse::StoreKeyCreated { result: Err(_), .. }
        ));
    }

    #[test]
    fn creation_stops_at_the_cap_and_keeps_every_key_below_it() {
        let mut secrets = MemSecrets::default();
        let keys: Vec<VerifyingKey> = (0..MAX_STORE_KEYS).map(|_| created(&mut secrets)).collect();
        assert!(matches!(
            create(&mut secrets, 1),
            HarvestDelegateResponse::StoreKeyCreated { result: Err(_), .. }
        ));
        assert!(keys.iter().all(|key| load(&secrets, key).is_some()));
    }
}
