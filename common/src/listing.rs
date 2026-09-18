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

/// Unique listing identifier: a hash of the listing's own TERMS.
///
/// # Why 32 bytes, and why the reasoning is NOT the order's
///
/// Widened alongside [`crate::payment::OrderId`] while the wire was open, but
/// the case for it is weaker and worth stating honestly rather than borrowing.
/// A collision here buys a griefing attack -- two listings under one id, and
/// readers permanently disagreeing about the price -- not a stolen payment.
/// 2^64 of work for that is a poor trade, so 16 bytes was not obviously
/// wrong.
///
/// It is 32 anyway for two reasons that are about the change rather than the
/// threat. The cost is zero at this boundary and nonzero at every later one,
/// which is the whole argument for doing the order's now. And a `ListingId`
/// then sat inside every `Order` and therefore inside the order id's own
/// preimage, so leaving the two at different widths would have invited exactly
/// the "why is this one 16?" question at the next audit. (Orders no longer
/// carry it since harvest#57; the listing an order is for travels only in the
/// encrypted conversation.)
///
/// **What it costs is different from the order's, and it is the part to
/// weigh.** An order published at the old width does not decode into this
/// generation, and orders expire in hours, so losing them is survivable. A
/// LISTING is a seller's shop and does not expire. See
/// `docs/untested-invariants.md` for what the migration actually does with
/// both, which is the same thing, and why only one of the two is comfortable.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ListingId(pub [u8; 32]);

impl ListingId {
    /// The id these terms give.
    ///
    /// # Why the identity is the content
    ///
    /// It used to be `BLAKE3(seller_fingerprint || created_at_ms || title)`
    /// -- not the price, not the description, not the kind. So one seller
    /// could sign two listings, differing in price, that shared an id.
    ///
    /// Found by looking for the shape after `OrderId` had it, and the symptom
    /// is different and arguably worse. `ListingsV1::apply_delta` is
    /// first-writer-wins: a listing whose id is already held is SKIPPED. So
    /// this is not the order case's displacement, it is a **permanent
    /// divergence**. A peer that saw the cheap copy first keeps it and
    /// thereafter excludes that id from every delta it sends and every delta
    /// it asks for; a peer that saw the dear copy keeps that; and neither can
    /// ever tell the other, because each one's summary already names the id.
    /// Two readers see two prices for one listing, for good.
    ///
    /// Deriving from the whole encoded struct with the id blanked, rather
    /// than from a chosen list of fields, for the same reason as
    /// [`crate::payment::OrderId::from_terms`]: a list is what somebody adds
    /// a field beside, which is exactly how this preimage came to omit the
    /// price.
    ///
    /// The same `#[serde(skip)]` exception applies and is the way to break
    /// it -- a skipped field is outside both this preimage and the signature
    /// comparison in [`AuthorizedListing::verify`]. See that function's
    /// counterpart on `OrderId` for the full statement.
    ///
    /// Derived the same way and at the same width as
    /// [`crate::payment::OrderId::from_terms`], which carries the argument
    /// for both.
    pub fn from_terms(listing: &Listing) -> Self {
        let mut probe = listing.clone();
        probe.id = Self([0u8; 32]);
        // Infallible: `Listing` derives `Serialize` over plain data with no
        // custom fallible encoding.
        let terms = crate::to_cbor(&probe).expect("Listing always serializes to CBOR");
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"harvest/listing-id/v2");
        hasher.update(&terms);
        Self(*hasher.finalize().as_bytes())
    }

    /// A distinct id per label, for naming a listing whose terms are not to
    /// hand.
    ///
    /// **This is not a listing's identity.** A real listing's id comes from
    /// its own terms ([`Self::from_terms`]), and
    /// [`AuthorizedListing::verify`] refuses any listing carrying anything
    /// else -- so a listing built with this is one no peer accepts, and
    /// misuse fails closed rather than quietly.
    ///
    /// It exists for two honest uses: a fixture that needs *an* id without
    /// building a whole listing, and a reference to a listing this code does
    /// not hold, such as the listing named in a buyer's request.
    ///
    /// Domain-separated from [`Self::from_terms`], so a label can never
    /// collide with a real listing's id.
    pub fn from_label(label: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"harvest/listing-id/label/v1");
        hasher.update(label.as_bytes());
        Self(*hasher.finalize().as_bytes())
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

impl Listing {
    /// Stamp this listing with the id its own terms give.
    ///
    /// Every producer must go through this, because
    /// [`AuthorizedListing::verify`] refuses a record whose id is not the one
    /// its terms give -- so a listing built any other way is one no peer will
    /// accept. Taking `self` and returning it makes the stamping part of
    /// construction rather than a step a caller can forget.
    #[must_use]
    pub fn with_derived_id(mut self) -> Self {
        self.id = ListingId::from_terms(&self);
        self
    }
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
        )?;
        // The id has to be the one these terms give, or two differently-priced
        // listings could share one and the merge would keep whichever arrived
        // first on each peer -- permanently, and differently per peer. See
        // [`ListingId::from_terms`].
        //
        // After the signature for the same reason as the order check: a
        // record altered since signing fails both, and "the seller did not
        // sign this" is the more useful thing to be told.
        let expected = ListingId::from_terms(&self.listing);
        if self.listing.id != expected {
            return Err(format!(
                "listing id {} is not the id these terms give ({expected})",
                self.listing.id
            ));
        }
        Ok(())
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
            id: ListingId([0u8; 32]),
            title: "Widget".into(),
            description: "A nice widget".into(),
            kind: ListingKind::Sale,
            price: Some(PriceInfo {
                amount: "0.001".into(),
                currency: "BTC".into(),
            }),
            created_at: ts,
        }
        .with_derived_id();

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
        let id1 = ListingId::from_label("Widget");
        let id2 = ListingId::from_label("Widget");
        assert_eq!(id1, id2);
    }

    /// Two labels are two ids. Not a listing's identity -- see
    /// `listing_identity_tests` for that -- but `from_label` still has to
    /// distinguish what it is given, or a fixture naming two listings would
    /// name one.
    #[test]
    fn test_listing_id_differs_by_input() {
        assert_ne!(
            ListingId::from_label("Widget"),
            ListingId::from_label("Gadget")
        );
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
            id: ListingId::from_label("Widget"),
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
            encryption_public_key: None,
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
        let parent = StoreStateV1 {
            owner: Some(verifying_key),
            ..Default::default()
        };
        let params = StoreParameters::new(verifying_key);

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
            encryption_public_key: None,
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
        let parent = StoreStateV1 {
            owner: Some(verifying_key),
            ..Default::default()
        };
        let params = StoreParameters::new(verifying_key);

        use freenet_scaffold::ComposableState;
        assert!(authorized.verify(&parent, &params).is_ok());
    }
}

#[cfg(test)]
mod listing_identity_tests {
    use super::*;
    use crate::store::ListingsV1;
    use ed25519_dalek::SigningKey;
    use freenet_scaffold::ComposableState;

    fn seller() -> SigningKey {
        SigningKey::from_bytes(&[41u8; 32])
    }

    fn listing_priced(price: &str) -> Listing {
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        Listing {
            id: ListingId([0u8; 32]),
            title: "Ghost Pepper".to_string(),
            description: String::new(),
            kind: ListingKind::Sale,
            price: Some(PriceInfo {
                amount: price.to_string(),
                currency: "BTC".to_string(),
            }),
            created_at,
        }
        .with_derived_id()
    }

    fn authorize(listing: Listing, signing_key: &SigningKey) -> AuthorizedListing {
        use ed25519_dalek::Signer;
        use freenet_stdlib::prelude::ContractInstanceId;

        let message = crate::to_cbor(&listing).expect("serialize");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                crate::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = crate::to_cbor(&scoped).expect("serialize scoped");
        AuthorizedListing {
            signature: signing_key.sign(&scoped_payload).to_bytes().to_vec(),
            listing,
            scoped_payload,
            certificate_pem: String::new(),
        }
    }

    /// **Two differently-priced listings cannot share an id.**
    ///
    /// The same defect `OrderId` had, found by looking for it after the order
    /// one was fixed, and with a different symptom that is arguably worse.
    /// `ListingId` hashed `(seller, created_at_ms, title)` -- not the price,
    /// the description or the kind -- so one seller could sign two listings
    /// with one id and different prices.
    ///
    /// `ListingsV1::apply_delta` is first-writer-wins: a listing whose id is
    /// already held is SKIPPED. So this is not a displacement like the order
    /// case; it is a **permanent divergence**. A peer that saw the cheap copy
    /// first keeps it and excludes the id from every later delta, a peer that
    /// saw the dear one keeps that, and neither can ever tell the other --
    /// each one's summary already names the id. Two readers see two prices
    /// for one listing, for good.
    #[test]
    fn two_differently_priced_listings_cannot_share_an_id() {
        assert_ne!(
            listing_priced("0.001").id,
            listing_priced("0.100").id,
            "two prices must be two listings"
        );
    }

    /// **The listing id derivation is pinned, and changing it costs a
    /// seller their shop.**
    ///
    /// # Read this before changing the derivation
    ///
    /// This test exists to FAIL when somebody changes how a `ListingId` is
    /// derived, because the consequence is not local to this function and is
    /// not visible from it.
    ///
    /// Every listing published by a previous generation carries an id derived
    /// the old way. `AuthorizedListing::verify` refuses any listing whose id
    /// is not the one its terms give, and `ListingsV1::apply_delta` returns
    /// on the first refusal -- so the migration's fold discards the ENTIRE
    /// predecessor generation: the listings, the orders, and the store's own
    /// name, description and certificate with them. The migration then
    /// SEALS, so there is no second attempt.
    ///
    /// That happened on this branch. It passed every gate and survived a
    /// review round, because every other fixture in this repository builds
    /// its records with the CURRENT derivation and so none of them could see
    /// it. See `harvest_ui::migrate::uncarried_tests` for what the fold does
    /// and what the seller is told.
    ///
    /// So: if you are here because this test went red, the change may still
    /// be right -- it was, on that branch -- but it is a decision about
    /// published data and not a refactor. Updating the constant is the last
    /// step, not the first.
    ///
    /// **`docs/design/migratability.md` is the requirement and the procedure.**
    /// The first question it asks is whether the new version can accept old
    /// state after all, because that is the only option costing nobody
    /// anything -- and it is what keeps ANY UI able to migrate a contract.
    /// Owner-assisted re-issue buys the data back and spends that property.
    /// Accepting the old format in `verify` is not available; the document
    /// says why, twice over.
    ///
    /// The expected value comes from this crate's own derivation rather than
    /// an outside tool, which is weaker than the `b3sum` known answers in
    /// `mailbox`: what it pins is CHANGE, not correctness.
    #[test]
    fn the_listing_id_derivation_is_pinned() {
        let created_at = DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let listing = Listing {
            id: ListingId([0u8; 32]),
            title: "Ghost Pepper".into(),
            description: "Hot".into(),
            kind: ListingKind::Sale,
            price: Some(PriceInfo {
                amount: "0.001".into(),
                currency: "BTC".into(),
            }),
            created_at,
        };
        assert_eq!(
            hex::encode(ListingId::from_terms(&listing).0),
            "abf0ddc0555aaabae4edfbc9d60ab5e7c33bf7966a9022a44efa018be2e9d5c5",
        );
    }

    /// **The id is the WHOLE digest, not a prefix of one.**
    ///
    /// Same reasoning as `payment::order_identity_tests::the_id_is_the_whole_digest`:
    /// a derivation that kept the old 16-byte truncation while the type grew
    /// would leave half the id zero and the old collision cost, and every
    /// other test here would still pass.
    #[test]
    fn the_id_is_the_whole_digest() {
        let listing = listing_priced("0.001");
        let mut probe = listing.clone();
        probe.id = ListingId([0u8; 32]);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"harvest/listing-id/v2");
        hasher.update(&crate::to_cbor(&probe).expect("serialize"));

        assert_eq!(
            ListingId::from_terms(&listing).0,
            *hasher.finalize().as_bytes()
        );
    }

    /// **A listing whose id is not its terms' id is refused.**
    ///
    /// The enforcement half: the store contract runs `verify` over every
    /// listing in every state it validates, so a hand-built record filed
    /// under another listing's id never becomes state anywhere -- which is
    /// what makes the divergence above unreachable rather than merely
    /// unlikely.
    #[test]
    fn a_listing_whose_id_is_not_its_terms_is_refused() {
        let seller = seller();
        authorize(listing_priced("0.001"), &seller)
            .verify(&seller.verifying_key())
            .expect("a listing carrying its own terms' id verifies");

        let mut forged = listing_priced("0.001");
        forged.id = listing_priced("0.100").id;
        let refused = authorize(forged, &seller)
            .verify(&seller.verifying_key())
            .expect_err("a listing whose id is not its terms' id must be refused");
        assert!(
            refused.contains("id"),
            "the refusal should say what is wrong: {refused}"
        );
    }

    /// **Two listings that differ only in price both survive a merge, in
    /// either order.**
    ///
    /// The property the id fix buys, asserted through the real `apply_delta`
    /// rather than on the ids alone: `ListingsV1` is first-writer-wins by id,
    /// so before the fix one of these was silently dropped and WHICH one
    /// depended on arrival order. Now they are two listings and both land,
    /// whichever way round they arrive.
    #[test]
    fn two_listings_differing_only_in_price_both_survive_either_order() {
        let seller = seller();
        let cheap = authorize(listing_priced("0.001"), &seller);
        let dear = authorize(listing_priced("0.100"), &seller);
        let params = crate::store::StoreParameters::new(seller.verifying_key());

        let merged = |first: &AuthorizedListing, second: &AuthorizedListing| {
            let mut state = ListingsV1::default();
            let parent = crate::store::StoreStateV1 {
                owner: Some(seller.verifying_key()),
                ..Default::default()
            };
            state
                .apply_delta(&parent, &params, &Some(vec![first.clone()]))
                .expect("first");
            state
                .apply_delta(&parent, &params, &Some(vec![second.clone()]))
                .expect("second");
            state
        };

        let one = merged(&cheap, &dear);
        let other = merged(&dear, &cheap);
        assert_eq!(one.listings.len(), 2, "both listings must survive");
        assert_eq!(
            one.listings, other.listings,
            "and the result must not depend on which arrived first"
        );
    }
}
