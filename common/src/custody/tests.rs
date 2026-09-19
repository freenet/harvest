//! Custody cryptography tests (harvest#93 phase 1b), carried from the spike
//! with its known-answer vectors unchanged. Run with
//! `cargo test -p harvest-common --features custody custody`.
//!
//! The copies' place in store state (signatures, the tombstone, the bound,
//! the merge laws) is tested in `backing::tests` beside the backings, since
//! `StoreStateV1::normalize_backings` governs both.

use super::*;
use ed25519_dalek::SigningKey;
use ghostkey_common::{ScopedPayload, SignatureRequestor};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The fixed vector shared with the vault probe (see the spike report): a
/// Ghost Key with seed 0x42.., a store key with seed 0x51.., and the webapp
/// requestor `[7; 32]`.
fn ghost() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}
fn store() -> SigningKey {
    SigningKey::from_bytes(&[0x51; 32])
}
const SCOPE: WrapScope = WrapScope([7; 32]);

/// What the vault's `handle_sign` does: sign the CBOR of a `ScopedPayload`
/// naming the attested requestor.
fn vault_sign(gk: &SigningKey, scope: WrapScope, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use ed25519_dalek::Signer;
    let scoped = ghostkey_common::to_cbor(&ScopedPayload {
        requestor: scope.requestor(),
        payload: message.to_vec(),
    })
    .unwrap();
    let sig = gk.sign(&scoped).to_bytes().to_vec();
    (scoped, sig)
}

fn secret_for(gk: &SigningKey, st: &SigningKey, scope: WrapScope) -> WrapSecret {
    let (scoped, sig) = vault_sign(gk, scope, &wrap_message(&st.verifying_key()));
    WrapSecret::from_sign_result(
        &scoped,
        &sig,
        &gk.verifying_key(),
        &st.verifying_key(),
        scope,
    )
    .expect("a genuine wrap signature is accepted")
}

// --- Check 1: a stable signature ------------------------------------------

/// The real vault handler (`ghostkeys` `handlers.rs::handle_sign`, driven on
/// two in-memory vaults by the spike's probe) produced exactly these bytes for
/// this vector. Harvest's model of the vault must keep reproducing them: if
/// this goes red, either `ScopedPayload`'s CBOR layout or the signing moved,
/// and every wrapping key moved with it.
const VAULT_SCOPED_PAYLOAD: &str = "a269726571756573746f72a16657656241707098200707070707070707070707070707070707070707070707070707070707070707677061796c6f6164983a1868186118721876186518731874182f18731874186f18721865182d186b18651879182d1877187218611870182f187618310018c0185018c51863187a184418fa1886182918ff18f318cc18cc18e218300c18b3186218a6183d189918d9185f18c5184118451826186f184318321844185a";
const VAULT_SIGNATURE: &str = "3ba9f1deb44caf24c418a8ea531923f3b63e78cc3136c486312ffa3bcfe7e26578d7ca180f3b85f33fb7c21b1aca058aef22fc1555faf2885f71a96bd40b3406";

#[test]
fn the_wrap_signature_matches_what_the_vault_handler_emits() {
    let (scoped, sig) = vault_sign(&ghost(), SCOPE, &wrap_message(&store().verifying_key()));
    assert_eq!(hex(&scoped), VAULT_SCOPED_PAYLOAD);
    assert_eq!(hex(&sig), VAULT_SIGNATURE);
}

#[test]
fn the_wrap_signature_is_deterministic() {
    let m = wrap_message(&store().verifying_key());
    assert_eq!(
        vault_sign(&ghost(), SCOPE, &m),
        vault_sign(&ghost(), SCOPE, &m)
    );
}

/// Known answer for the whole wrap: HKDF labels, AAD layout, AES-GCM and the
/// derived nonce. Any change here is a re-wrap migration, not an edit.
const WRAPPED_V1: &str = "7c313b8a5aa0103d784eeffbdc7a65c9dc9301e17634ad300102b2485921ff40907515ec1e5a55fcc9dc331233ff920d";

#[test]
fn wrapping_has_a_known_answer_and_is_deterministic() {
    let s = secret_for(&ghost(), &store(), SCOPE);
    let a = wrap_store_key(&store(), &s).unwrap();
    let b = wrap_store_key(&store(), &secret_for(&ghost(), &store(), SCOPE)).unwrap();
    assert_eq!(
        a, b,
        "two devices wrap to the same bytes, so their writes merge to one copy"
    );
    assert_eq!(a.scheme, SCHEME_V1);
    assert_eq!(a.ciphertext.len(), WRAPPED_LEN_V1);
    assert_eq!(hex(&a.ciphertext), WRAPPED_V1);
}

#[test]
fn any_backing_device_recovers_the_store_key() {
    let wrapped = wrap_store_key(&store(), &secret_for(&ghost(), &store(), SCOPE)).unwrap();
    // "Another device": nothing shared but the Ghost Key and the store state.
    let recovered = unwrap_store_key(&wrapped, &secret_for(&ghost(), &store(), SCOPE)).unwrap();
    assert_eq!(recovered.to_bytes(), store().to_bytes());
}

/// The requestor is inside the signed bytes, so a new webapp container id is
/// a new wrapping key: the old copy does not open under the new scope, and a
/// re-wrap under the new scope is a separate copy.
#[test]
fn a_new_webapp_id_is_a_new_wrapping_key() {
    let new_scope = WrapScope([8; 32]);
    let old = secret_for(&ghost(), &store(), SCOPE);
    let new = secret_for(&ghost(), &store(), new_scope);
    let w_old = wrap_store_key(&store(), &old).unwrap();
    let w_new = wrap_store_key(&store(), &new).unwrap();
    assert_ne!(w_old, w_new);
    assert_eq!(
        unwrap_store_key(&w_old, &new).unwrap_err(),
        CustodyError::WrongKeyOrCorrupt
    );
    assert_ne!(
        AuthorizedCopy::slot_for(old.backer_vk(), &old.scope()),
        AuthorizedCopy::slot_for(new.backer_vk(), &new.scope()),
        "and a separate copy in store state"
    );
}

#[test]
fn the_current_scope_is_harvests_webapp_id() {
    let s = WrapScope::current();
    assert_eq!(
        s.requestor(),
        crate::expected_harvest_requestor(),
        "wrap signatures are scoped exactly like every other Harvest signature"
    );
}

// --- Check 2: domain separation -------------------------------------------

fn listing() -> crate::Listing {
    crate::Listing {
        id: crate::ListingId([0; 32]),
        title: "harvest/store-key-wrap/v1".into(),
        description: String::new(),
        kind: crate::listing::ListingKind::Sale,
        price: None,
        created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    }
    .with_derived_id()
}

fn store_info() -> crate::store::StoreInfoV1 {
    crate::store::StoreInfoV1 {
        version: 1,
        certificate_pem: "CERT".into(),
        seller_fingerprint: "fp".into(),
        reputation_contract_id: [7; 32],
        store_name: "harvest/store-key-wrap/v1".into(),
        description: String::new(),
        encryption_public_key: None,
    }
}

/// Every message Harvest hands `SignMessage` today (grep: `SignMessage` in
/// `ui/src`): the CBOR of a `Listing` (`components/my_store.rs`), of a
/// `StoreInfoV1` (`gateway/store_ops.rs`, `state.rs`), of an `Order`
/// (`state.rs`), and an inbox entry's `signing_payload`
/// (`b"freenet-bitcoin/inbox-entry/v1\0" || CBOR`, `state.rs`). The wrap
/// message is none of them, and none of them is a wrap message.
#[test]
fn the_wrap_message_is_no_other_signed_harvest_message() {
    let m = wrap_message(&store().verifying_key());
    assert!(is_wrap_message(&m));

    assert!(crate::from_cbor::<crate::Listing>(&m).is_err());
    assert!(crate::from_cbor::<crate::store::StoreInfoV1>(&m).is_err());
    assert!(crate::from_cbor::<crate::Order>(&m).is_err());
    assert!(freenet_bitcoin_inbox::InboxEntryBody::from_signing_payload(&m).is_err());

    // The other direction, structurally: a derived struct encodes as a CBOR
    // map (major type 5), an inbox entry starts with ASCII `f`, and the wrap
    // message starts with ASCII `h`. Disjoint first bytes, so no prefix of one
    // is ever the other, whatever the field values (the titles above even
    // contain the wrap label).
    for signed in [
        crate::to_cbor(&listing()).unwrap(),
        crate::to_cbor(&store_info()).unwrap(),
    ] {
        assert_eq!(signed[0] >> 5, 5, "a signed Harvest struct is a CBOR map");
        assert!(!is_wrap_message(&signed));
    }
    assert_eq!(m[0], b'h');
    assert_eq!(b"freenet-bitcoin/inbox-entry/v1\0"[0], b'f');
}

/// A signature Harvest legitimately obtained for something else (here, a
/// listing) cannot be turned into a wrap secret, even though it is a valid
/// Ghost Key signature under Harvest's own requestor.
#[test]
fn a_signature_for_another_purpose_is_not_a_wrap_secret() {
    let listing_bytes = crate::to_cbor(&listing()).unwrap();
    let (scoped, sig) = vault_sign(&ghost(), SCOPE, &listing_bytes);
    let err = WrapSecret::from_sign_result(
        &scoped,
        &sig,
        &ghost().verifying_key(),
        &store().verifying_key(),
        SCOPE,
    )
    .unwrap_err();
    assert!(matches!(err, CustodyError::NotAWrapSignature(_)));
}

/// Another app granted the same Ghost Key signs the same message under its
/// own attested requestor: different bytes, refused as a wrap secret.
#[test]
fn another_apps_signature_over_the_wrap_message_is_refused() {
    let m = wrap_message(&store().verifying_key());
    let (scoped, sig) = vault_sign(&ghost(), WrapScope([9; 32]), &m);
    let err = WrapSecret::from_sign_result(
        &scoped,
        &sig,
        &ghost().verifying_key(),
        &store().verifying_key(),
        SCOPE,
    )
    .unwrap_err();
    assert_eq!(
        err,
        CustodyError::NotAWrapSignature("signed for a different requestor")
    );
    // A Delegate requestor (e.g. if the Harvest DELEGATE asked the vault
    // instead of the UI) is also a different scope.
    let scoped = ghostkey_common::to_cbor(&ScopedPayload {
        requestor: SignatureRequestor::Delegate(freenet_stdlib::prelude::DelegateKey::new(
            [7; 32],
            freenet_stdlib::prelude::CodeHash::new([0; 32]),
        )),
        payload: m,
    })
    .unwrap();
    use ed25519_dalek::Signer;
    let sig = ghost().sign(&scoped).to_bytes();
    assert!(WrapSecret::from_sign_result(
        &scoped,
        &sig,
        &ghost().verifying_key(),
        &store().verifying_key(),
        SCOPE
    )
    .is_err());
}

/// One leaked wrap signature opens one store: the message names the store.
#[test]
fn one_wrap_signature_opens_one_store() {
    let other_store = SigningKey::from_bytes(&[0x52; 32]);
    let s_a = secret_for(&ghost(), &store(), SCOPE);
    let w_b = wrap_store_key(&other_store, &secret_for(&ghost(), &other_store, SCOPE)).unwrap();
    assert!(unwrap_store_key(&w_b, &s_a).is_err());
    // And the signature for store A is refused outright as B's.
    let (scoped, sig) = vault_sign(&ghost(), SCOPE, &wrap_message(&store().verifying_key()));
    assert!(WrapSecret::from_sign_result(
        &scoped,
        &sig,
        &ghost().verifying_key(),
        &other_store.verifying_key(),
        SCOPE
    )
    .is_err());
}

#[test]
fn a_tampered_or_foreign_signature_is_refused() {
    let m = wrap_message(&store().verifying_key());
    let (scoped, mut sig) = vault_sign(&ghost(), SCOPE, &m);
    sig[0] ^= 1;
    assert!(WrapSecret::from_sign_result(
        &scoped,
        &sig,
        &ghost().verifying_key(),
        &store().verifying_key(),
        SCOPE
    )
    .is_err());
    // A different Ghost Key's genuine signature does not verify as this one's.
    let other_gk = SigningKey::from_bytes(&[0x43; 32]);
    let (scoped, sig) = vault_sign(&other_gk, SCOPE, &m);
    assert!(WrapSecret::from_sign_result(
        &scoped,
        &sig,
        &ghost().verifying_key(),
        &store().verifying_key(),
        SCOPE
    )
    .is_err());
}

#[test]
fn a_wrong_or_corrupt_ciphertext_does_not_open() {
    let s = secret_for(&ghost(), &store(), SCOPE);
    let mut w = wrap_store_key(&store(), &s).unwrap();
    w.ciphertext[3] ^= 0x80;
    assert_eq!(
        unwrap_store_key(&w, &s).unwrap_err(),
        CustodyError::WrongKeyOrCorrupt
    );
    w.scheme = 2;
    assert_eq!(
        unwrap_store_key(&w, &s).unwrap_err(),
        CustodyError::UnknownScheme(2)
    );
    // A wrong store key is refused at wrap time.
    assert_eq!(
        wrap_store_key(&SigningKey::from_bytes(&[1; 32]), &s).unwrap_err(),
        CustodyError::NotThisStoresKey
    );
}

// --- Check 3: never published ---------------------------------------------

#[test]
fn a_wrap_secret_never_prints_its_signature() {
    let s = secret_for(&ghost(), &store(), SCOPE);
    let printed = format!("{s:?}");
    assert!(printed.contains("<redacted>"));
    assert!(!printed.contains(&VAULT_SIGNATURE[..16]));
    let bytes = hex(&s.signature[..]);
    assert!(!printed.contains(&bytes[..16]));
}

/// The UI's `SignResult` router must classify on this before anything else.
/// Every version of the wrap label is caught, so a future `v2` is never
/// mistaken for a publishable signature by an old router.
#[test]
fn every_wrap_version_is_recognised_as_secret() {
    assert!(is_wrap_message(b"harvest/store-key-wrap/v1\0xxxx"));
    assert!(is_wrap_message(b"harvest/store-key-wrap/v2\0xxxx"));
    assert!(!is_wrap_message(b"harvest/store-key-wra"));
    assert!(!is_wrap_message(b"freenet-bitcoin/inbox-entry/v1\0"));
}

// --- Derived keys ---------------------------------------------------------

const INBOX_PUBLIC_V1: &str = "13ae95d20701761fe6a5d73118d4b0ccc73eef55051ad6e76cf10e72c4e92055";
const RECORD_RSA_PUBLIC_BLAKE3_V1: &str =
    "d5989c3872859b6997aa1ac35fcfc097613408db35524366f2bb9dfcf6508ef5";

#[test]
fn the_inbox_key_derives_from_the_store_key_with_a_known_answer() {
    let a = x25519_dalek::PublicKey::from(&inbox_secret(&store()));
    let b = x25519_dalek::PublicKey::from(&inbox_secret(&store()));
    assert_eq!(a, b);
    assert_eq!(hex(a.as_bytes()), INBOX_PUBLIC_V1);
    let other = x25519_dalek::PublicKey::from(&inbox_secret(&SigningKey::from_bytes(&[0x52; 32])));
    assert_ne!(a, other);
    // Separated from the record seed and from the signing seed itself.
    assert_ne!(
        inbox_secret(&store()).to_bytes(),
        *record_key_seed(&store())
    );
    assert_ne!(inbox_secret(&store()).to_bytes(), store().to_bytes());
}

/// Pins today's RSA keygen from the record seed. If an `rsa` or
/// `rand_chacha` bump changes it, this goes red before a device regenerates a
/// different record key than the one published.
#[test]
fn the_record_key_derives_from_the_store_key_with_a_known_answer() {
    use rsa::pkcs1::EncodeRsaPublicKey;
    let k = record_rsa_key(&store()).unwrap();
    let der = k.to_public_key().to_pkcs1_der().unwrap();
    assert_eq!(
        blake3::hash(der.as_bytes()).to_hex().to_string(),
        RECORD_RSA_PUBLIC_BLAKE3_V1
    );
    let again = record_rsa_key(&store()).unwrap();
    assert_eq!(k, again);
}
