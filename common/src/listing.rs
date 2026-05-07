use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// What kind of listing this is.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum ListingKind {
    Sale,
    Gift,
    Request,
}

/// Price information for a listing. Freeform text -- the marketplace is payment-agnostic.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PriceInfo {
    /// e.g. "0.005", "50.00"
    pub amount: String,
    /// e.g. "BTC", "USD", "XMR"
    pub currency: String,
}

/// Unique listing identifier: first 16 bytes of BLAKE3(fingerprint || timestamp_ms || title).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ListingId(pub [u8; 16]);

impl ListingId {
    pub fn new(seller_fingerprint: &str, created_at: &DateTime<Utc>, title: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seller_fingerprint.as_bytes());
        hasher.update(&created_at.timestamp_millis().to_le_bytes());
        hasher.update(title.as_bytes());
        let hash = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        Self(id)
    }
}

impl std::fmt::Display for ListingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(&self.0).into_string())
    }
}

impl PartialOrd for ListingId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ListingId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

/// A product, service, gift, or request listing.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Listing {
    pub id: ListingId,
    pub title: String,
    pub description: String,
    pub kind: ListingKind,
    pub price: Option<PriceInfo>,
    pub created_at: DateTime<Utc>,
}

/// A listing signed by the seller's ghostkey via the ghostkey delegate.
///
/// The ghostkey delegate wraps the listing bytes in a `ScopedPayload`
/// (binding the requestor identity) before signing. Verification checks:
/// 1. Ed25519 signature over scoped_payload bytes
/// 2. The payload inside the ScopedPayload matches the CBOR of the listing
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedListing {
    pub listing: Listing,
    /// CBOR-serialized ScopedPayload from the ghostkey delegate's SignResult.
    pub scoped_payload: Vec<u8>,
    /// Ed25519 signature over the scoped_payload bytes.
    pub signature: Vec<u8>,
    /// The seller's ghostkey certificate PEM, so any verifier can check the trust chain.
    pub certificate_pem: String,
}

impl AuthorizedListing {
    /// Verify this listing's signature against a known verifying key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), String> {
        verify_scoped_signature(
            &self.scoped_payload,
            &self.signature,
            verifying_key,
            &self.listing,
        )
    }
}

/// Verify a ghostkey delegate signature (ScopedPayload format).
///
/// 1. Parse the 64-byte Ed25519 signature.
/// 2. Verify the signature over the scoped_payload bytes.
/// 3. Deserialize the ScopedPayload, check the inner payload matches the
///    CBOR encoding of `expected_data`, AND check the embedded
///    runtime-attested requestor matches the Harvest webapp contract id
///    (canonical or any legacy id).
///
/// ## What the requestor pin does
///
/// It stops a third-party webapp that the user has granted ghostkey
/// access to **via `RequestAnyAccess`** from minting Harvest-shaped
/// signatures: the ghostkey delegate binds the calling app's
/// runtime-attested `MessageOrigin::WebApp(contract_id)` into every
/// signature it produces, and Harvest rejects signatures whose
/// embedded id isn't ours.
///
/// ## What the requestor pin does NOT do
///
/// It does NOT stop an attacker who has obtained the seller's
/// **private signing key** directly (e.g. via PEM exfiltration,
/// backup leak, or a permissioned delegate that grants
/// `GhostkeyScope::Export` to a hostile app). Such an attacker can
/// fabricate a `ScopedPayload { requestor: WebApp(HARVEST_ID), ... }`
/// offline and sign it with the seller's key; nothing in the
/// signature itself is runtime-attested. The pin is a defence
/// against delegate-mediated cross-app misuse, not a defence against
/// PEM theft.
pub fn verify_scoped_signature<T: serde::Serialize>(
    scoped_payload: &[u8],
    signature_bytes: &[u8],
    verifying_key: &VerifyingKey,
    expected_data: &T,
) -> Result<(), String> {
    use ed25519_dalek::Verifier;

    // Parse signature
    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| format!("signature must be 64 bytes, got {}", signature_bytes.len()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    // Verify Ed25519 signature over the scoped_payload bytes
    verifying_key
        .verify(scoped_payload, &signature)
        .map_err(|e| format!("signature verification failed: {e}"))?;

    // Verify the inner payload matches the expected data, AND the
    // embedded requestor is one of the accepted Harvest webapp ids
    // (canonical or legacy).
    #[cfg(feature = "ghostkey")]
    {
        let scoped: ghostkey_common::ScopedPayload = crate::from_cbor(scoped_payload)
            .map_err(|e| format!("deserialize scoped payload: {e}"))?;

        let expected_bytes =
            crate::to_cbor(expected_data).map_err(|e| format!("serialize expected data: {e}"))?;

        if scoped.payload != expected_bytes {
            return Err("scoped payload content does not match expected data".into());
        }

        // Reject non-WebApp requestors outright (delegate-to-delegate
        // calls cannot have produced this signature).
        let signer_id = match &scoped.requestor {
            ghostkey_common::SignatureRequestor::WebApp(id) => id,
            other => {
                return Err(format!(
                    "signature requestor pin mismatch: expected Harvest webapp, got {other:?}"
                ));
            }
        };

        let signer_id_str = signer_id.to_string();
        if signer_id_str != crate::HARVEST_WEBAPP_CONTRACT_ID
            && !crate::LEGACY_HARVEST_WEBAPP_CONTRACT_IDS.contains(&signer_id_str.as_str())
        {
            return Err(format!(
                "signature requestor pin mismatch: expected Harvest webapp, got {signer_id_str}"
            ));
        }
    }

    // Without ghostkey-common, extract the payload AND requestor from
    // the raw CBOR structure. The contract id is compared as bytes
    // against the canonical id and any legacy ids.
    #[cfg(not(feature = "ghostkey"))]
    {
        let value: ciborium::Value = crate::from_cbor(scoped_payload)
            .map_err(|e| format!("deserialize scoped payload as CBOR: {e}"))?;

        let payload_bytes = extract_payload_from_cbor(&value)
            .ok_or("could not extract payload from scoped payload")?;

        let expected_bytes =
            crate::to_cbor(expected_data).map_err(|e| format!("serialize expected data: {e}"))?;

        if payload_bytes != expected_bytes {
            return Err("scoped payload content does not match expected data".into());
        }

        let requestor_bytes = extract_webapp_requestor_bytes_from_cbor(&value)
            .ok_or("scoped payload requestor is not WebApp(_); rejecting")?;

        let canonical_id_bytes = bs58::decode(crate::HARVEST_WEBAPP_CONTRACT_ID)
            .into_vec()
            .map_err(|e| format!("HARVEST_WEBAPP_CONTRACT_ID decode: {e}"))?;
        let mut accepted = requestor_bytes == canonical_id_bytes;
        if !accepted {
            for legacy in crate::LEGACY_HARVEST_WEBAPP_CONTRACT_IDS {
                if let Ok(legacy_bytes) = bs58::decode(legacy).into_vec() {
                    if requestor_bytes == legacy_bytes {
                        accepted = true;
                        break;
                    }
                }
            }
        }
        if !accepted {
            return Err("signature requestor pin mismatch: expected Harvest webapp".into());
        }
    }

    Ok(())
}

/// Extract the "payload" field from a CBOR-encoded ScopedPayload.
/// ScopedPayload is a struct with `requestor` and `payload` fields,
/// serialized as a CBOR map.
///
/// `Vec<u8>` via `serde::Serialize`'s default impl encodes as a CBOR
/// array of unsigned integers, not as a byte string. Accept both
/// shapes so a future switch to `#[serde(with = "serde_bytes")]` (or
/// any consumer that uses byte-string encoding) doesn't silently
/// break verification.
#[cfg(not(feature = "ghostkey"))]
fn extract_payload_from_cbor(value: &ciborium::Value) -> Option<Vec<u8>> {
    let map = value.as_map()?;
    for (key, val) in map {
        if key.as_text() == Some("payload") {
            if let Some(bytes) = val.as_bytes() {
                return Some(bytes.to_vec());
            }
            if let Some(arr) = val.as_array() {
                return arr
                    .iter()
                    .map(|v| v.as_integer().and_then(|i| u8::try_from(i).ok()))
                    .collect::<Option<Vec<u8>>>();
            }
            return None;
        }
    }
    None
}

/// Extract the contract id bytes of a `WebApp(_)` requestor from a CBOR-
/// encoded ScopedPayload. Returns `None` for any other requestor variant
/// (e.g. `Delegate(_)`), which Harvest's verifier should reject.
#[cfg(not(feature = "ghostkey"))]
fn extract_webapp_requestor_bytes_from_cbor(value: &ciborium::Value) -> Option<Vec<u8>> {
    let outer = value.as_map()?;
    // `requestor` field on the outer ScopedPayload struct.
    let requestor = outer
        .iter()
        .find(|(k, _)| k.as_text() == Some("requestor"))
        .map(|(_, v)| v)?;
    // serde-default externally-tagged enum: `{ "WebApp": <ContractInstanceId> }`.
    let requestor_map = requestor.as_map()?;
    let (variant, payload) = requestor_map.first()?;
    if variant.as_text() != Some("WebApp") {
        return None;
    }
    // ContractInstanceId is `[u8; 32]` with `serde_as`, which encodes as
    // a CBOR array of 32 unsigned-int values. Walk and collect.
    let arr = payload.as_array()?;
    arr.iter()
        .map(|v| v.as_integer().and_then(|i| u8::try_from(i).ok()))
        .collect::<Option<Vec<u8>>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Helper to create a signed listing for testing.
    ///
    /// Constructs the ScopedPayload manually via CBOR (avoiding the
    /// `freenet-stdlib` `ContractInstanceId` constructor) so the test
    /// can inject any `WebApp(id)` bytes — including the
    /// `HARVEST_WEBAPP_CONTRACT_ID` the verifier now requires, and an
    /// arbitrary mismatched id for the negative test.
    fn make_authorized_listing_with_requestor(
        signing_key: &SigningKey,
        requestor_id: [u8; 32],
    ) -> AuthorizedListing {
        let ts = DateTime::from_timestamp(1700000000, 0).unwrap();
        let listing = Listing {
            id: ListingId::new("abc123", &ts, "Widget"),
            title: "Widget".into(),
            description: "A nice widget".into(),
            kind: ListingKind::Sale,
            price: Some(PriceInfo {
                amount: "0.001".into(),
                currency: "BTC".into(),
            }),
            created_at: ts,
        };

        #[derive(serde::Serialize)]
        struct TestScopedPayload {
            requestor: TestRequestor,
            payload: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        enum TestRequestor {
            WebApp([u8; 32]),
        }

        let listing_bytes = crate::to_cbor(&listing).unwrap();
        let scoped = TestScopedPayload {
            requestor: TestRequestor::WebApp(requestor_id),
            payload: listing_bytes,
        };
        let scoped_bytes = crate::to_cbor(&scoped).unwrap();
        let signature = signing_key.sign(&scoped_bytes);

        AuthorizedListing {
            listing,
            scoped_payload: scoped_bytes,
            signature: signature.to_bytes().to_vec(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".into(),
        }
    }

    /// Returns the 32-byte contract id that signatures must carry to
    /// verify under Harvest's pinned requestor.
    fn harvest_requestor_bytes() -> [u8; 32] {
        let v = bs58::decode(crate::HARVEST_WEBAPP_CONTRACT_ID)
            .into_vec()
            .expect("HARVEST_WEBAPP_CONTRACT_ID must decode as base58");
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    fn make_authorized_listing(signing_key: &SigningKey) -> AuthorizedListing {
        make_authorized_listing_with_requestor(signing_key, harvest_requestor_bytes())
    }

    #[test]
    fn test_listing_id_deterministic() {
        let ts = DateTime::from_timestamp(1700000000, 0).unwrap();
        let id1 = ListingId::new("abc123", &ts, "Widget");
        let id2 = ListingId::new("abc123", &ts, "Widget");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_listing_id_differs_by_input() {
        let ts = DateTime::from_timestamp(1700000000, 0).unwrap();
        let id1 = ListingId::new("abc123", &ts, "Widget");
        let id2 = ListingId::new("abc123", &ts, "Gadget");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_authorized_listing_verify() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let authorized = make_authorized_listing(&signing_key);
        assert!(authorized.verify(&verifying_key).is_ok());
    }

    #[test]
    fn test_authorized_listing_wrong_key_fails() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]).verifying_key();

        let authorized = make_authorized_listing(&signing_key);
        assert!(authorized.verify(&wrong_key).is_err());
    }

    #[test]
    fn test_authorized_listing_tampered_payload_fails() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let mut authorized = make_authorized_listing(&signing_key);
        // Tamper with the listing title after signing
        authorized.listing.title = "Tampered".into();
        assert!(authorized.verify(&verifying_key).is_err());
    }

    /// Regression test: a signature whose runtime-attested requestor is
    /// some other webapp must NOT verify, even though the signature
    /// itself is mathematically valid and the payload matches. This is
    /// the "Sign grant on a shared key shouldn't impersonate Harvest"
    /// invariant — the ghostkey delegate binds the calling app's
    /// contract id into every signature, and Harvest's verifier pins
    /// that id to the published webapp's id.
    #[test]
    fn test_authorized_listing_wrong_requestor_fails() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        // Same valid signature, same payload, but signed under a
        // hostile webapp's contract id.
        let mut hostile_id = harvest_requestor_bytes();
        hostile_id[0] ^= 0xff;
        let authorized = make_authorized_listing_with_requestor(&signing_key, hostile_id);

        let result = authorized.verify(&verifying_key);
        assert!(
            result.is_err(),
            "verifier must reject signatures whose requestor isn't the Harvest webapp; got {result:?}"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("requestor"),
            "error must mention the requestor pin; got: {err}"
        );
    }

    /// Regression test: a `ScopedPayload` whose requestor is a `Delegate(_)`
    /// (rather than `WebApp(_)`) must be rejected. The verifier helper for
    /// the no-feature CBOR path explicitly returns None for non-WebApp
    /// variants; the feature-on path matches on `WebApp` and rejects
    /// otherwise. Without this test, a future delegate-to-delegate
    /// signing path could produce signatures the verifier silently
    /// accepted (depending on how the CBOR walker fell through).
    #[test]
    fn test_authorized_listing_delegate_requestor_fails() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let ts = DateTime::from_timestamp(1700000000, 0).unwrap();
        let listing = Listing {
            id: ListingId::new("abc123", &ts, "Widget"),
            title: "Widget".into(),
            description: "n/a".into(),
            kind: ListingKind::Sale,
            price: None,
            created_at: ts,
        };

        // Build a ScopedPayload whose requestor is the `Delegate(_)`
        // variant. Externally tagged: `{ "Delegate": <delegate_key_bytes> }`.
        #[derive(serde::Serialize)]
        struct TestScopedPayload {
            requestor: TestRequestor,
            payload: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        enum TestRequestor {
            #[allow(dead_code)] // keep variant for completeness
            WebApp([u8; 32]),
            Delegate(Vec<u8>),
        }
        let listing_bytes = crate::to_cbor(&listing).unwrap();
        let scoped = TestScopedPayload {
            requestor: TestRequestor::Delegate(vec![1u8; 32]),
            payload: listing_bytes,
        };
        let scoped_bytes = crate::to_cbor(&scoped).unwrap();
        let signature = signing_key.sign(&scoped_bytes);
        let authorized = AuthorizedListing {
            listing,
            scoped_payload: scoped_bytes,
            signature: signature.to_bytes().to_vec(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".into(),
        };

        let result = authorized.verify(&verifying_key);
        assert!(
            result.is_err(),
            "delegate requestor must be rejected; got {result:?}"
        );
    }

    /// Regression test for the store-info verifier path. `store.rs`
    /// calls `verify_scoped_signature` from both `verify` and
    /// `apply_delta`; the requestor pin applies to those call sites
    /// too. Tests there were previously absent.
    #[test]
    fn test_authorized_store_info_wrong_requestor_fails() {
        use crate::store::{AuthorizedStoreInfoV1, StoreInfoV1, StoreParameters, StoreStateV1};

        let signing_key = SigningKey::from_bytes(&[55u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let info = StoreInfoV1 {
            version: 1,
            certificate_pem: "test-cert".into(),
            seller_fingerprint: "fp".into(),
            reputation_contract_id: [0u8; 32],
            store_name: "TestStore".into(),
            description: "".into(),
            payment_instructions: "".into(),
        };
        let info_bytes = crate::to_cbor(&info).unwrap();

        // Sign with a hostile requestor id (NOT the harvest webapp).
        #[derive(serde::Serialize)]
        struct TestScopedPayload {
            requestor: TestRequestor,
            payload: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        enum TestRequestor {
            WebApp([u8; 32]),
        }
        let mut hostile_id = harvest_requestor_bytes();
        hostile_id[0] ^= 0xff;
        let scoped = TestScopedPayload {
            requestor: TestRequestor::WebApp(hostile_id),
            payload: info_bytes,
        };
        let scoped_bytes = crate::to_cbor(&scoped).unwrap();
        let signature = signing_key.sign(&scoped_bytes);

        let authorized = AuthorizedStoreInfoV1 {
            info,
            scoped_payload: scoped_bytes,
            signature: signature.to_bytes().to_vec(),
        };
        let parent = StoreStateV1::default();
        let params = StoreParameters {
            seller_verifying_key: verifying_key,
        };

        use freenet_scaffold::ComposableState;
        let result = authorized.verify(&parent, &params);
        assert!(
            result.is_err(),
            "store-info verifier must reject hostile-requestor signatures; got {result:?}"
        );
    }

    /// Happy-path: an `AuthorizedStoreInfoV1` signed under the canonical
    /// Harvest requestor verifies cleanly through the same composable
    /// `verify` entry point used by the store contract.
    #[test]
    fn test_authorized_store_info_verifies() {
        use crate::store::{AuthorizedStoreInfoV1, StoreInfoV1, StoreParameters, StoreStateV1};

        let signing_key = SigningKey::from_bytes(&[55u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let info = StoreInfoV1 {
            version: 1,
            certificate_pem: "test-cert".into(),
            seller_fingerprint: "fp".into(),
            reputation_contract_id: [0u8; 32],
            store_name: "TestStore".into(),
            description: "".into(),
            payment_instructions: "".into(),
        };
        let info_bytes = crate::to_cbor(&info).unwrap();

        #[derive(serde::Serialize)]
        struct TestScopedPayload {
            requestor: TestRequestor,
            payload: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        enum TestRequestor {
            WebApp([u8; 32]),
        }
        let scoped = TestScopedPayload {
            requestor: TestRequestor::WebApp(harvest_requestor_bytes()),
            payload: info_bytes,
        };
        let scoped_bytes = crate::to_cbor(&scoped).unwrap();
        let signature = signing_key.sign(&scoped_bytes);

        let authorized = AuthorizedStoreInfoV1 {
            info,
            scoped_payload: scoped_bytes,
            signature: signature.to_bytes().to_vec(),
        };
        let parent = StoreStateV1::default();
        let params = StoreParameters {
            seller_verifying_key: verifying_key,
        };

        use freenet_scaffold::ComposableState;
        assert!(authorized.verify(&parent, &params).is_ok());
    }
}
