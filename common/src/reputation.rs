use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::feedback::{FeedbackCategory, FeedbackToken};

/// Immutable parameters for a reputation contract, set at creation time.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ReputationParameters {
    /// RSA public key in PKCS#1 DER format, for verifying blind-signed feedback tokens.
    ///
    /// `pub(crate)` on purpose -- see [`ReputationParameters::new`].
    pub(crate) rsa_public_key_der: Vec<u8>,
    /// Owner's Ed25519 verifying key (from ghostkey certificate), for identity linkage.
    pub(crate) owner_verifying_key: VerifyingKey,
}

impl ReputationParameters {
    /// The only way to build these parameters from outside `harvest-common`.
    ///
    /// The field set of this struct is hashed into the reputation contract's
    /// address, so a second place building it by hand can address a different
    /// contract. See [`crate::store::StoreParameters::new`] for the incident
    /// that argument comes from.
    pub fn new(rsa_public_key_der: Vec<u8>, owner_verifying_key: VerifyingKey) -> Self {
        Self {
            rsa_public_key_der,
            owner_verifying_key,
        }
    }

    fn rsa_verifying_key(&self) -> Result<rsa::pss::VerifyingKey<sha2::Sha256>, String> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        let key = rsa::RsaPublicKey::from_pkcs1_der(&self.rsa_public_key_der)
            .map_err(|e| format!("invalid RSA public key: {e}"))?;
        Ok(rsa::pss::VerifyingKey::<sha2::Sha256>::new(key))
    }
}

/// Domain separation for [`FeedbackEntry::entry_signature`].
const ENTRY_SIGNATURE_DOMAIN: &[u8] = b"harvest/feedback-entry/v1";
/// Domain separation for [`FeedbackEntry::digest`].
const ENTRY_DIGEST_DOMAIN: &[u8] = b"harvest/feedback-entry-digest/v1";

/// A single piece of negative feedback submitted to a seller's reputation contract.
///
/// # Every field is signed
///
/// Two signatures, over two different things:
///
/// * `signature` is the seller's RSA blind signature over the CBOR-encoded
///   `token`. It proves the seller issued this token, without the seller
///   having seen it.
/// * `entry_signature` is an Ed25519 signature by `token.entry_key` over
///   everything else: the token, the RSA signature, the category, the comment
///   and the timestamp. Only the buyer holds that key's secret.
///
/// Until harvest#22 only the first existed, so `category`, `comment` and
/// `submitted_at` rode alongside the signed token unsigned. Anyone reading a
/// published entry could re-submit the token with different words, each peer
/// kept whichever arrived first, and a seller could push a neutered variant to
/// peers that did not yet hold the real complaint and have them refuse it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FeedbackEntry {
    /// The unblinded feedback token.
    pub token: FeedbackToken,
    /// RSA-PSS blind signature over the CBOR-encoded token (RFC 9474, unblinded).
    pub signature: Vec<u8>,
    /// What went wrong.
    pub category: FeedbackCategory,
    /// Optional freeform comment from the buyer.
    pub comment: String,
    /// When the feedback was submitted.
    pub submitted_at: DateTime<Utc>,
    /// Ed25519 signature by `token.entry_key` over [`FeedbackEntry::signing_bytes`].
    pub entry_signature: Vec<u8>,
}

/// The part of a [`FeedbackEntry`] its `entry_signature` covers: all of it but
/// the signature itself.
#[derive(Serialize)]
struct SignedEntryTerms<'a> {
    token: &'a FeedbackToken,
    signature: &'a [u8],
    category: &'a FeedbackCategory,
    comment: &'a str,
    submitted_at: &'a DateTime<Utc>,
}

impl FeedbackEntry {
    /// Build an entry and sign it with the token's entry key.
    ///
    /// `entry_key` must be the secret half of `token.entry_key`, or the entry
    /// will not verify.
    pub fn sign(
        token: FeedbackToken,
        signature: Vec<u8>,
        category: FeedbackCategory,
        comment: String,
        submitted_at: DateTime<Utc>,
        entry_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        let mut entry = Self {
            token,
            signature,
            category,
            comment,
            submitted_at,
            entry_signature: Vec::new(),
        };
        entry.entry_signature = entry_key.sign(&entry.signing_bytes()).to_bytes().to_vec();
        entry
    }

    /// The bytes `entry_signature` covers: a domain tag, then the CBOR of
    /// every other field.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let terms = SignedEntryTerms {
            token: &self.token,
            signature: &self.signature,
            category: &self.category,
            comment: &self.comment,
            submitted_at: &self.submitted_at,
        };
        let mut bytes = ENTRY_SIGNATURE_DOMAIN.to_vec();
        // Infallible: plain data with no custom fallible encoding.
        bytes.extend(crate::to_cbor(&terms).expect("feedback terms always serialize"));
        bytes
    }

    /// Content digest of the whole entry, signatures included.
    ///
    /// This is what a summary names, rather than the token's nonce: two
    /// entries for one token are two different things to exchange, and a
    /// summary keyed on the nonce would tell a peer holding one variant that
    /// it already has the other, so neither would ever be sent.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ENTRY_DIGEST_DOMAIN);
        hasher.update(&crate::to_cbor(self).expect("feedback entry always serializes"));
        *hasher.finalize().as_bytes()
    }

    /// Check both signatures: the seller issued the token, and the token's
    /// entry key signed everything else.
    pub fn verify(&self, rsa_key: &rsa::pss::VerifyingKey<sha2::Sha256>) -> Result<(), String> {
        use rsa::signature::Verifier;

        let token_bytes =
            crate::to_cbor(&self.token).map_err(|e| format!("serialize token: {e}"))?;
        let signature = rsa::pss::Signature::try_from(self.signature.as_slice())
            .map_err(|e| format!("invalid RSA signature bytes: {e}"))?;
        rsa_key
            .verify(&token_bytes, &signature)
            .map_err(|e| format!("feedback signature invalid: {e}"))?;

        let entry_key = VerifyingKey::from_bytes(&self.token.entry_key)
            .map_err(|e| format!("invalid feedback entry key: {e}"))?;
        let entry_signature = ed25519_dalek::Signature::from_slice(&self.entry_signature)
            .map_err(|e| format!("invalid feedback entry signature bytes: {e}"))?;
        // `verify_strict`: rejects small-order keys and non-canonical
        // encodings, so the key's holder is the only party who can produce a
        // second valid entry for a token.
        entry_key
            .verify_strict(&self.signing_bytes(), &entry_signature)
            .map_err(|e| format!("feedback entry signature invalid: {e}"))
    }

    /// The encoding the per-token tie-break compares. See
    /// [`ReputationStateV1::apply_delta`].
    fn canonical_rank(&self) -> Vec<u8> {
        crate::to_cbor(self).expect("feedback entry always serializes")
    }
}

/// Per-seller reputation contract state. Append-only negative feedback.
///
/// # Canonical form
///
/// At most one entry per token, `feedback` strictly ascending by
/// `token.nonce`, and `used_nonces` exactly the set of those nonces. `verify`
/// refuses anything else, and `apply_delta` only ever produces this form, so
/// two peers holding the same feedback hold the same bytes.
///
/// # Two entries for one token
///
/// Only the buyer who holds the token's entry key can produce a second
/// validly-signed entry for it. If they do, both are real, and the contract
/// keeps the one whose CBOR encoding is smaller. That is a total order over
/// the entry's own bytes, so which one survives does not depend on which a
/// peer saw first: merge is commutative, associative and idempotent.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ReputationStateV1 {
    /// Owner's ghostkey certificate PEM (for verifiers to check identity chain).
    pub owner_certificate_pem: String,
    /// Negative feedback entries, strictly ascending by `token.nonce`.
    pub feedback: Vec<FeedbackEntry>,
    /// The nonces of `feedback`, kept for replay prevention.
    ///
    /// **`BTreeSet`, not `HashSet`, and that is load-bearing.** This field is
    /// part of the contract STATE, so its CBOR encoding is bytes peers compare,
    /// and it has to be a function of the contents alone.
    ///
    /// The mechanism is a COUNTER, not randomness, and the distinction matters
    /// because this contract runs on `wasm32-unknown-unknown`. `RandomState::
    /// new` caches two keys per thread and does `keys.set((k0.wrapping_add(1),
    /// k1))` on every construction, precisely so each `HashMap` gets a
    /// different iteration order. That bump is target-independent. What IS
    /// target-specific is the base: on wasm32 `std` routes to
    /// `sys::random::unsupported`, whose `hashmap_random_keys` returns a stack
    /// address and a heap address with the comment "this isn't particularly
    /// secure, but there isn't really an alternative". So there is no entropy
    /// on the target at all.
    ///
    /// Do not read that as "so it was deterministic anyway and this change was
    /// unnecessary". Two peers differ in how many sets they have built, which
    /// is their operation history, so they still encode differently. The
    /// counter is the whole defect and it survives having no entropy.
    ///
    /// Note what is NOT true: two `to_cbor` calls on ONE `HashSet` value give
    /// identical bytes. Only independently-built instances diverge, which is
    /// the shape `used_nonces_encoding_is_deterministic` uses.
    pub used_nonces: BTreeSet<[u8; 32]>,
}

/// Summary for delta computation: the digest of every entry held.
///
/// Digests, not nonces: see [`FeedbackEntry::digest`]. `BTreeSet` for the
/// same reason as [`ReputationStateV1::used_nonces`]: a summary is encoded and
/// sent, so its bytes must be a function of its contents alone.
pub type ReputationSummary = BTreeSet<[u8; 32]>;

/// Delta: new feedback entries to add.
pub type ReputationDelta = Vec<FeedbackEntry>;

impl ReputationStateV1 {
    /// Verify the entire state: every entry's signatures, and the canonical
    /// form described on the type.
    pub fn verify(&self, parameters: &ReputationParameters) -> Result<(), String> {
        let rsa_key = parameters.rsa_verifying_key()?;

        for entry in &self.feedback {
            entry.verify(&rsa_key)?;
        }

        // Strictly ascending rejects both an out-of-order list and two
        // entries for one token. Accepting either let two peers holding the
        // same feedback hold different bytes (harvest#26 is the listings form
        // of the same defect).
        for pair in self.feedback.windows(2) {
            if pair[0].token.nonce >= pair[1].token.nonce {
                return Err(
                    "feedback is not strictly ascending by token nonce (unsorted or a \
                     token used twice)"
                        .into(),
                );
            }
        }

        let nonces: BTreeSet<[u8; 32]> = self.feedback.iter().map(|e| e.token.nonce).collect();
        if nonces != self.used_nonces {
            return Err("used_nonces is not exactly the set of feedback nonces".into());
        }

        Ok(())
    }

    /// Generate a summary (the digest of every entry) for delta computation.
    pub fn summarize(&self) -> ReputationSummary {
        self.feedback.iter().map(FeedbackEntry::digest).collect()
    }

    /// Compute delta: entries whose digest the old summary does not name.
    pub fn delta(&self, old_summary: &ReputationSummary) -> Option<ReputationDelta> {
        let new_entries: Vec<_> = self
            .feedback
            .iter()
            .filter(|e| !old_summary.contains(&e.digest()))
            .cloned()
            .collect();
        if new_entries.is_empty() {
            None
        } else {
            Some(new_entries)
        }
    }

    /// Apply a delta: verify every entry, then fold them in, leaving the state
    /// in canonical form.
    pub fn apply_delta(
        &mut self,
        parameters: &ReputationParameters,
        delta: &Option<ReputationDelta>,
    ) -> Result<(), String> {
        let Some(entries) = delta else {
            return Ok(());
        };

        // Verify the WHOLE delta before committing any of it. Verifying and
        // pushing in one pass left a delta of [valid, invalid] with the valid
        // entry -- and its nonce -- already in `self` when the error returned,
        // so a caller that keeps the state it passed in would take on entries
        // from a delta it had been told to reject. Same defect, and the same
        // fix, as `store::OrdersV1::apply_delta`.
        let held: BTreeSet<[u8; 32]> = self.summarize();
        let mut incoming: Vec<&FeedbackEntry> = Vec::new();
        let mut rsa_key = None;
        for entry in entries {
            // Already held byte for byte: nothing to verify or add.
            if held.contains(&entry.digest()) {
                continue;
            }
            if rsa_key.is_none() {
                rsa_key = Some(parameters.rsa_verifying_key()?);
            }
            entry.verify(rsa_key.as_ref().expect("set just above"))?;
            incoming.push(entry);
        }

        // One slot per token. Rebuilding from `self` as well as the delta is
        // what normalises a state that arrived out of order.
        let mut by_token: BTreeMap<[u8; 32], FeedbackEntry> = BTreeMap::new();
        for entry in self.feedback.drain(..).chain(incoming.into_iter().cloned()) {
            match by_token.entry(entry.token.nonce) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(entry);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    // Two entries for one token: keep the smaller encoding,
                    // so the survivor is a function of the two entries and
                    // not of arrival order.
                    if entry.canonical_rank() < slot.get().canonical_rank() {
                        slot.insert(entry);
                    }
                }
            }
        }

        self.used_nonces = by_token.keys().copied().collect();
        self.feedback = by_token.into_values().collect();
        Ok(())
    }

    /// Merge another full state into this one: every entry, plus the
    /// certificate back-fill. This is the contract's `UpdateData::State` arm
    /// and the migration fold's merge, in one place.
    pub fn merge(
        &mut self,
        parameters: &ReputationParameters,
        other: &ReputationStateV1,
    ) -> Result<(), String> {
        // Always through `apply_delta`, even with nothing to add: it is what
        // puts `self` in canonical form, and a fold's base is a predecessor's
        // state that nothing verified.
        self.apply_delta(parameters, &Some(other.feedback.clone()))?;
        if self.owner_certificate_pem.is_empty() {
            self.owner_certificate_pem = other.owner_certificate_pem.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pss::{BlindedSigningKey, VerifyingKey as RsaVerifyingKey};
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    use crate::feedback::{FeedbackCategory, FeedbackToken};

    /// 1024 bits, not 2048: this is a signature-shape fixture, not a security
    /// claim, and key generation is the slowest thing in the test.
    fn key_pair() -> (RsaPrivateKey, ReputationParameters) {
        let mut rng = rsa::rand_core::OsRng;
        let private = RsaPrivateKey::new(&mut rng, 1024).expect("generate RSA key");
        let der = RsaPublicKey::from(&private)
            .to_pkcs1_der()
            .expect("encode public key")
            .as_bytes()
            .to_vec();
        let params = ReputationParameters {
            rsa_public_key_der: der,
            owner_verifying_key: ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key(),
        };
        (private, params)
    }

    /// The secret half of `token(nonce).entry_key`. Deterministic so a test
    /// can sign a second variant for a token it built earlier.
    fn entry_key(nonce: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[nonce.wrapping_add(100); 32])
    }

    fn token(nonce: u8) -> FeedbackToken {
        FeedbackToken {
            target_reputation_contract: [5u8; 32],
            nonce: [nonce; 32],
            entry_key: entry_key(nonce).verifying_key().to_bytes(),
        }
    }

    fn timestamp() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp")
    }

    /// An entry carrying `signature` as its RSA signature, correctly signed by
    /// the token's entry key. Whether it verifies is up to `signature`.
    fn entry(signature: Vec<u8>, nonce: u8) -> FeedbackEntry {
        FeedbackEntry::sign(
            token(nonce),
            signature,
            FeedbackCategory::NonDelivery,
            String::new(),
            timestamp(),
            &entry_key(nonce),
        )
    }

    fn rsa_sign(private: &RsaPrivateKey, nonce: u8) -> Vec<u8> {
        let mut rng = rsa::rand_core::OsRng;
        let signing_key = BlindedSigningKey::<Sha256>::new(private.clone());
        let bytes = crate::to_cbor(&token(nonce)).expect("serialize token");
        signing_key.sign_with_rng(&mut rng, &bytes).to_vec()
    }

    /// A feedback entry whose RSA-PSS and entry signatures genuinely verify.
    fn signed_entry(private: &RsaPrivateKey, nonce: u8) -> FeedbackEntry {
        entry(rsa_sign(private, nonce), nonce)
    }

    /// A second, equally genuine entry for the same token: what the buyer who
    /// holds the entry key could produce by signing twice.
    fn signed_variant(private: &RsaPrivateKey, nonce: u8, comment: &str) -> FeedbackEntry {
        FeedbackEntry::sign(
            token(nonce),
            rsa_sign(private, nonce),
            FeedbackCategory::Other("second thoughts".to_string()),
            comment.to_string(),
            timestamp(),
            &entry_key(nonce),
        )
    }

    /// The fixture has to be right, or the atomicity test below passes for the
    /// wrong reason: a "valid" entry that does not actually verify would leave
    /// nothing behind whether or not the delta is atomic.
    #[test]
    fn the_signed_fixture_actually_verifies() {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::signature::Verifier;

        let (private, params) = key_pair();
        let good = signed_entry(&private, 1);

        let public = rsa::RsaPublicKey::from_pkcs1_der(&params.rsa_public_key_der).expect("decode");
        let verifying = RsaVerifyingKey::<Sha256>::new(public);
        let bytes = crate::to_cbor(&good.token).expect("serialize token");
        let signature =
            rsa::pss::Signature::try_from(good.signature.as_slice()).expect("signature");
        verifying
            .verify(&bytes, &signature)
            .expect("the fixture signature must verify");

        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params, &Some(vec![good]))
            .expect("a genuinely signed entry must apply");
        assert_eq!(state.feedback.len(), 1);
    }

    /// A delta is all-or-nothing.
    ///
    /// The same defect as `OrdersV1::apply_delta` and `ListingsV1::apply_delta`
    /// in `store.rs`: this verified and committed in one pass, so a delta of
    /// `[valid, invalid]` pushed the valid entry -- and its nonce -- into
    /// `self` and only then returned `Err`. A caller that keeps the state it
    /// passed in would silently take on entries from a delta it had been told
    /// to reject, and the leaked nonce would then make the genuine entry
    /// undeliverable, because `used_nonces` is what suppresses a replay.
    #[test]
    fn a_delta_holding_one_invalid_entry_applies_none_of_it() {
        let (private, params) = key_pair();
        let good = signed_entry(&private, 1);
        // Too short to even parse as a signature for this modulus, so it fails
        // before any RSA work. Any rejection would do.
        let bad = entry(vec![0u8; 8], 2);

        let mut state = ReputationStateV1::default();
        let err = state
            .apply_delta(&params, &Some(vec![good.clone(), bad.clone()]))
            .expect_err("a delta carrying an unverifiable entry must be rejected");
        assert!(err.contains("signature"), "got: {err}");
        assert!(
            state.feedback.is_empty(),
            "a rejected delta must leave no feedback behind"
        );
        assert!(
            state.used_nonces.is_empty(),
            "and must not burn the nonce of an entry it did not keep"
        );

        // Order within the delta must not matter either.
        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params, &Some(vec![bad, good.clone()]))
            .expect_err("a delta carrying an unverifiable entry must be rejected");
        assert!(state.feedback.is_empty());
        assert!(state.used_nonces.is_empty());

        // And the good entry alone still applies, so the assertions above are
        // about atomicity rather than about `good` being unusable.
        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params, &Some(vec![good]))
            .expect("the valid entry alone must apply");
        assert_eq!(state.feedback.len(), 1);
        assert_eq!(state.used_nonces.len(), 1);
    }

    /// A delta naming one entry twice stores it once, and the second copy is
    /// not re-verified. Pins the dedup this file already had, so the
    /// two-pass restructuring cannot quietly drop it.
    #[test]
    fn a_delta_repeating_one_entry_stores_it_once() {
        let (private, params) = key_pair();
        let good = signed_entry(&private, 1);

        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params, &Some(vec![good.clone(), good]))
            .expect("a repeated valid entry is a duplicate, not an error");
        assert_eq!(state.feedback.len(), 1);
        assert_eq!(state.used_nonces.len(), 1);
    }
    /// **Nobody but the buyer can change what an entry says (harvest#22).**
    ///
    /// Before the entry signature, the RSA signature covered `entry.token`
    /// alone, so anyone reading a published entry could re-submit the token
    /// with different words, and each peer kept whichever it saw first. Red
    /// against that code: the neutered variant applied.
    #[test]
    fn a_third_party_cannot_rewrite_an_entry() {
        let (private, params) = key_pair();
        let genuine = signed_entry(&private, 1);
        let neutered = FeedbackEntry {
            category: FeedbackCategory::Other("no complaint".to_string()),
            comment: "actually it was fine".to_string(),
            ..genuine.clone()
        };

        let mut state = ReputationStateV1::default();
        let err = state
            .apply_delta(&params, &Some(vec![neutered.clone()]))
            .expect_err("an entry altered after signing must be refused");
        assert!(err.contains("entry signature"), "got: {err}");
        assert!(state.feedback.is_empty());

        // Nor can it ride in on a whole state.
        let forged = ReputationStateV1 {
            owner_certificate_pem: String::new(),
            used_nonces: [neutered.token.nonce].into_iter().collect(),
            feedback: vec![neutered],
        };
        forged
            .verify(&params)
            .expect_err("a state holding an altered entry must not verify");
    }

    /// Every field is covered, not only the ones the attack above changes.
    /// One mutation per field the entry signature is meant to cover.
    #[test]
    fn every_field_of_an_entry_is_signed() {
        let (private, params) = key_pair();
        let rsa_key = params.rsa_verifying_key().expect("key");
        let genuine = signed_entry(&private, 1);
        genuine.verify(&rsa_key).expect("the fixture verifies");

        let mut altered = Vec::new();
        let mut e = genuine.clone();
        e.category = FeedbackCategory::Counterfeit;
        altered.push(("category", e));
        let mut e = genuine.clone();
        e.comment = "x".to_string();
        altered.push(("comment", e));
        let mut e = genuine.clone();
        e.submitted_at = DateTime::from_timestamp(1_700_000_001, 0).expect("timestamp");
        altered.push(("submitted_at", e));
        // A second genuine RSA signature on the same token: the SELLER can
        // produce these at will, so it must not be able to mint a variant.
        let mut e = genuine.clone();
        e.signature = rsa_sign(&private, 1);
        assert_ne!(e.signature, genuine.signature, "PSS is randomized");
        altered.push(("signature", e));
        // Swapping in a key the attacker holds breaks the seller's signature.
        let mut e = genuine.clone();
        e.token.entry_key = entry_key(9).verifying_key().to_bytes();
        altered.push(("token.entry_key", e));

        for (field, entry) in altered {
            assert!(
                entry.verify(&rsa_key).is_err(),
                "changing `{field}` after signing must break verification"
            );
        }
    }

    /// **Two genuine entries for one token converge, whichever arrives first.**
    ///
    /// Only the entry key's holder can produce a second entry now, but they
    /// can, so the survivor has to be a function of the two entries rather
    /// than of arrival order. This was the known-gap test on the old code,
    /// asserting the two peers DIFFERED.
    #[test]
    fn two_signed_entries_for_one_token_converge() {
        let (private, params) = key_pair();
        let first = signed_entry(&private, 1);
        let second = signed_variant(&private, 1, "changed my mind");

        let mut saw_first = ReputationStateV1::default();
        saw_first
            .apply_delta(&params, &Some(vec![first.clone()]))
            .expect("apply");
        saw_first
            .apply_delta(&params, &Some(vec![second.clone()]))
            .expect("apply");

        let mut saw_second = ReputationStateV1::default();
        saw_second
            .apply_delta(&params, &Some(vec![second]))
            .expect("apply");
        saw_second
            .apply_delta(&params, &Some(vec![first]))
            .expect("apply");

        assert_eq!(saw_first.feedback.len(), 1, "one token, one entry");
        assert_eq!(
            crate::to_cbor(&saw_first).expect("encode"),
            crate::to_cbor(&saw_second).expect("encode"),
            "the two peers must hold identical bytes"
        );
        saw_first
            .verify(&params)
            .expect("the result is valid state");
    }

    /// **Two peers holding different entries for one token find out.**
    ///
    /// The test above applies deltas by hand. On the network a peer only sends
    /// what the other's summary does not name, so a summary keyed on the
    /// token's nonce told each peer the other already had its entry, and
    /// nothing was ever sent. This drives the real summary/delta exchange.
    #[test]
    fn peers_holding_different_entries_for_one_token_exchange_them() {
        let (private, params) = key_pair();
        let mut a = ReputationStateV1::default();
        a.apply_delta(&params, &Some(vec![signed_entry(&private, 1)]))
            .expect("apply");
        let mut b = ReputationStateV1::default();
        b.apply_delta(&params, &Some(vec![signed_variant(&private, 1, "other")]))
            .expect("apply");
        assert_ne!(a, b, "precondition: the peers disagree");

        let to_b = a.delta(&b.summarize());
        let to_a = b.delta(&a.summarize());
        assert!(
            to_b.is_some() && to_a.is_some(),
            "each summary must show the other peer something it lacks"
        );
        b.apply_delta(&params, &to_b).expect("apply");
        a.apply_delta(&params, &to_a).expect("apply");
        assert_eq!(a, b, "one exchange must leave both peers agreeing");
        assert_eq!(
            a.delta(&b.summarize()),
            None,
            "and then there is nothing left to send"
        );
    }

    /// **`verify` refuses every non-canonical form (the #26 defect, here).**
    ///
    /// Each of these used to verify, and each lets two peers holding the same
    /// feedback hold different bytes.
    #[test]
    fn verify_refuses_non_canonical_state() {
        let (private, params) = key_pair();
        let one = signed_entry(&private, 1);
        let two = signed_entry(&private, 2);
        let nonces = |es: &[&FeedbackEntry]| es.iter().map(|e| e.token.nonce).collect();

        let canonical = ReputationStateV1 {
            owner_certificate_pem: String::new(),
            feedback: vec![one.clone(), two.clone()],
            used_nonces: nonces(&[&one, &two]),
        };
        canonical
            .verify(&params)
            .expect("the canonical form verifies");

        let unsorted = ReputationStateV1 {
            feedback: vec![two.clone(), one.clone()],
            ..canonical.clone()
        };
        assert!(unsorted.verify(&params).is_err(), "out of order");

        let variant = signed_variant(&private, 1, "again");
        let two_for_one_token = ReputationStateV1 {
            feedback: vec![one.clone(), variant],
            used_nonces: nonces(&[&one]),
            ..canonical.clone()
        };
        assert!(
            two_for_one_token.verify(&params).is_err(),
            "one token twice"
        );

        let extra_nonce = ReputationStateV1 {
            feedback: vec![one.clone()],
            used_nonces: nonces(&[&one, &two]),
            ..canonical.clone()
        };
        assert!(
            extra_nonce.verify(&params).is_err(),
            "a nonce with no entry"
        );

        let missing_nonce = ReputationStateV1 {
            used_nonces: nonces(&[&one]),
            ..canonical
        };
        assert!(
            missing_nonce.verify(&params).is_err(),
            "an entry with no nonce"
        );
    }

    /// A state that arrived out of order leaves `apply_delta` canonical. The
    /// migration fold decodes predecessor state without verifying it, so this
    /// is where such a state is repaired rather than carried forward.
    #[test]
    fn apply_delta_normalises_the_state_it_is_applied_to() {
        let (private, params) = key_pair();
        let one = signed_entry(&private, 1);
        let two = signed_entry(&private, 2);
        let three = signed_entry(&private, 3);
        let mut state = ReputationStateV1 {
            owner_certificate_pem: String::new(),
            feedback: vec![three.clone(), one.clone()],
            used_nonces: [one.token.nonce, three.token.nonce].into_iter().collect(),
        };
        let before = state.clone();
        state.apply_delta(&params, &Some(vec![two])).expect("apply");
        state.verify(&params).expect("the result is canonical");

        // `merge` normalises too, even when the other side brings nothing,
        // which is the case the fold hits with an unverified base.
        let mut merged = before;
        merged
            .merge(&params, &ReputationStateV1::default())
            .expect("merge");
        merged
            .verify(&params)
            .expect("merging nothing still normalises");
    }

    /// **Two peers given the same feedback in different orders must hold
    /// byte-identical state.**
    ///
    /// This is the property `mailbox::determinism_tests::
    /// merging_is_order_independent` pins for the mailbox. Reputation had no
    /// equivalent -- and reputation is the contract whose STATE actually held
    /// a nondeterministically-encoded collection, so the guard existed on the
    /// one of the two that did not need it.
    ///
    /// Red before `used_nonces` became a `BTreeSet`. `RandomState::new` bumps
    /// a per-thread counter on EVERY construction, so two independently-built
    /// `HashSet`s iterate differently and therefore CBOR-encode differently.
    /// `apply_delta` already sorts `feedback` "deterministically by nonce for
    /// CRDT convergence"; the set beside it silently spent that sort.
    ///
    /// 32 nonces, not a handful: with only a few members two `HashSet`s can
    /// coincidentally agree on an order and the guard passes by luck. RSA
    /// signing dominates the runtime either way.
    #[test]
    fn used_nonces_encoding_is_deterministic() {
        let (private, params) = key_pair();
        let entries: Vec<_> = (1u8..33).map(|n| signed_entry(&private, n)).collect();
        let reversed: Vec<_> = entries.iter().rev().cloned().collect();

        let mut forward = ReputationStateV1::default();
        forward.apply_delta(&params, &Some(entries)).expect("apply");

        let mut backward = ReputationStateV1::default();
        backward
            .apply_delta(&params, &Some(reversed))
            .expect("apply");

        assert_eq!(
            forward.used_nonces, backward.used_nonces,
            "the two states must hold the same nonces, or this test is \
             measuring the wrong thing"
        );
        assert_eq!(
            crate::to_cbor(&forward).expect("encode"),
            crate::to_cbor(&backward).expect("encode"),
            "the same feedback in a different order must produce identical bytes"
        );
    }

    /// **State written by a predecessor generation still decodes, and
    /// normalises on the way in.**
    ///
    /// `legacy/reputation_contract.toml`'s V10 row asserts this, and a
    /// registry claim that is only reasoned about is how a migration seals
    /// over data.
    ///
    /// **The decode target is the real type, and that is the whole test.** An
    /// earlier version of this test decoded into a `BTreeSet` it named in its
    /// own body, so no change to the production types could ever move it: it
    /// tested `ciborium` and `std`. It was green under every revert, including
    /// the full one. Review caught it. If you edit this test, keep
    /// [`ReputationStateV1`] as the thing being decoded INTO.
    ///
    /// V9 wrote `used_nonces` as a `HashSet`, whose CBOR is a plain array
    /// (major type 4) in whatever order that instance chose, so both orders
    /// below are valid V9 bytes for the same state. It re-encodes rather than
    /// only comparing the decoded values, because `PartialEq` on the struct
    /// compares sets and passes under the defect; the bytes are the claim.
    #[test]
    fn predecessor_state_decodes_through_the_real_type_and_normalises() {
        /// V9's on-the-wire shape: `used_nonces` as a bare CBOR array.
        #[derive(serde::Serialize)]
        struct V9State {
            owner_certificate_pem: String,
            feedback: Vec<FeedbackEntry>,
            used_nonces: Vec<[u8; 32]>,
        }

        let ascending: Vec<[u8; 32]> = (1u8..33).map(|n| [n; 32]).collect();
        let descending: Vec<[u8; 32]> = ascending.iter().rev().copied().collect();

        let v9 = |used_nonces: Vec<[u8; 32]>| V9State {
            owner_certificate_pem: String::new(),
            feedback: Vec::new(),
            used_nonces,
        };

        let a: ReputationStateV1 =
            crate::from_cbor(&crate::to_cbor(&v9(ascending)).expect("encode")).expect("decode");
        let b: ReputationStateV1 =
            crate::from_cbor(&crate::to_cbor(&v9(descending)).expect("encode")).expect("decode");

        assert_eq!(
            a, b,
            "the same members in a different order are the same state"
        );
        assert_eq!(
            crate::to_cbor(&a).expect("encode"),
            crate::to_cbor(&b).expect("encode"),
            "predecessor bytes in any order must fold to one canonical encoding"
        );
    }

    /// **Documentary, not a guard, and labelled so deliberately.**
    ///
    /// [`ReputationStateV1::summarize`] returns `used_nonces.clone()`, so the
    /// field type and the summary alias must agree or the crate does not
    /// compile. There is therefore NO revert under which
    /// `used_nonces_encoding_is_deterministic` passes and this one fails, and
    /// it should not be counted as separate coverage.
    ///
    /// It is kept for the trap it records. Cloning a `HashSet` copies its
    /// hasher along with its contents, so summarising ONE state twice yields
    /// identical bytes even under the defect: the obvious form of this test is
    /// vacuous here. Measured, not assumed. The mailbox is not like this --
    /// its `summarize` rebuilds with `collect()`, drawing a fresh key each
    /// call -- so the same shape is a real guard there and a note here. Both
    /// files use the two-independent-states form so the weaker one cannot be
    /// copied from either.
    #[test]
    fn the_summary_encodes_the_same_for_two_independently_built_states() {
        let (private, params) = key_pair();
        let entries: Vec<_> = (1u8..33).map(|n| signed_entry(&private, n)).collect();
        let reversed: Vec<_> = entries.iter().rev().cloned().collect();

        let mut forward = ReputationStateV1::default();
        forward.apply_delta(&params, &Some(entries)).expect("apply");

        let mut backward = ReputationStateV1::default();
        backward
            .apply_delta(&params, &Some(reversed))
            .expect("apply");

        assert_eq!(
            crate::to_cbor(&forward.summarize()).expect("encode"),
            crate::to_cbor(&backward.summarize()).expect("encode"),
            "two peers holding the same nonces must send the same summary bytes"
        );
    }
}
