use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

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
}

/// A single piece of negative feedback submitted to a seller's reputation contract.
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
}

/// Per-seller reputation contract state. Append-only negative feedback.
///
/// This is naturally commutative: adding feedback entries in any order produces the
/// same final set (grow-only set with nonce-based deduplication).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ReputationStateV1 {
    /// Owner's ghostkey certificate PEM (for verifiers to check identity chain).
    pub owner_certificate_pem: String,
    /// Append-only list of negative feedback entries.
    pub feedback: Vec<FeedbackEntry>,
    /// Used nonces for replay prevention (mirrors nonces from feedback entries).
    ///
    /// **`BTreeSet`, not `HashSet`, and that is load-bearing.** This field is
    /// part of the contract STATE, so its CBOR encoding is bytes peers compare.
    /// A `HashSet` iterates in an order derived from a per-instance random
    /// seed, so it does not merely differ between peers -- it differs between
    /// two `to_cbor` calls on one node, for the same contents, in the same
    /// process (measured; `used_nonces_encoding_is_deterministic` pins it).
    /// `feedback` below is sorted for exactly this reason; a `HashSet` beside
    /// it silently spent that sort.
    pub used_nonces: BTreeSet<[u8; 32]>,
}

/// Summary for delta computation: the set of known nonces.
///
/// `BTreeSet` for the same reason as [`ReputationStateV1::used_nonces`]: a
/// summary is encoded and sent, so its bytes must be a function of its
/// contents alone.
pub type ReputationSummary = BTreeSet<[u8; 32]>;

/// Delta: new feedback entries to add.
pub type ReputationDelta = Vec<FeedbackEntry>;

impl ReputationStateV1 {
    /// Verify the entire state: all feedback entries have valid RSA signatures
    /// and consistent nonce tracking.
    pub fn verify(&self, parameters: &ReputationParameters) -> Result<(), String> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pss::{Signature, VerifyingKey as RsaVerifyingKey};
        use rsa::signature::Verifier;
        use sha2::Sha256;

        let rsa_key = rsa::RsaPublicKey::from_pkcs1_der(&parameters.rsa_public_key_der)
            .map_err(|e| format!("invalid RSA public key: {e}"))?;
        let verifying_key = RsaVerifyingKey::<Sha256>::new(rsa_key);

        for entry in &self.feedback {
            // Verify the RSA-PSS signature over the CBOR-encoded token
            let token_bytes =
                crate::to_cbor(&entry.token).map_err(|e| format!("serialize token: {e}"))?;
            let signature = Signature::try_from(entry.signature.as_slice())
                .map_err(|e| format!("invalid RSA signature bytes: {e}"))?;
            verifying_key
                .verify(&token_bytes, &signature)
                .map_err(|e| format!("feedback signature invalid: {e}"))?;

            // Verify nonce is tracked
            // nonce-identity-waiver: reputation keys identity on `token.nonce` and has the
            // same defect the mailbox re-key fixed -- see
            // `known_gap_two_feedback_variants_sharing_a_token_do_not_converge`. Parked
            // until the reputation contract's own re-key; NOT a site to copy.
            if !self.used_nonces.contains(&entry.token.nonce) {
                return Err(format!(
                    "feedback entry nonce not in used_nonces set: {:?}",
                    entry.token.nonce
                ));
            }
        }

        // Verify no duplicate nonces
        if self.feedback.len() != self.used_nonces.len() {
            return Err("feedback count does not match used_nonces count".into());
        }

        Ok(())
    }

    /// Generate a summary (set of used nonces) for delta computation.
    pub fn summarize(&self) -> ReputationSummary {
        self.used_nonces.clone()
    }

    /// Compute delta: feedback entries whose nonces are not in the old summary.
    pub fn delta(&self, old_summary: &ReputationSummary) -> Option<ReputationDelta> {
        let new_entries: Vec<_> = self
            .feedback
            .iter()
            // nonce-identity-waiver: reputation keys identity on `token.nonce` and has the
            // same defect the mailbox re-key fixed -- see
            // `known_gap_two_feedback_variants_sharing_a_token_do_not_converge`. Parked
            // until the reputation contract's own re-key; NOT a site to copy.
            .filter(|e| !old_summary.contains(&e.token.nonce))
            .cloned()
            .collect();
        if new_entries.is_empty() {
            None
        } else {
            Some(new_entries)
        }
    }

    /// Apply a delta: add new feedback entries, verifying each signature.
    pub fn apply_delta(
        &mut self,
        parameters: &ReputationParameters,
        delta: &Option<ReputationDelta>,
    ) -> Result<(), String> {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::pss::{Signature, VerifyingKey as RsaVerifyingKey};
        use rsa::signature::Verifier;
        use sha2::Sha256;

        let Some(entries) = delta else {
            return Ok(());
        };

        let rsa_key = rsa::RsaPublicKey::from_pkcs1_der(&parameters.rsa_public_key_der)
            .map_err(|e| format!("invalid RSA public key: {e}"))?;
        let verifying_key = RsaVerifyingKey::<Sha256>::new(rsa_key);

        // Verify the WHOLE delta before committing any of it. Verifying and
        // pushing in one pass left a delta of [valid, invalid] with the valid
        // entry -- and its nonce -- already in `self` when the error returned,
        // so a caller that keeps the state it passed in would take on entries
        // from a delta it had been told to reject. The burnt nonce is the
        // worse half: `used_nonces` is what suppresses a replay, so the
        // genuine entry could then never be added. Same defect, and the same
        // fix, as `store::OrdersV1::apply_delta`.
        let mut accepted: Vec<&FeedbackEntry> = Vec::new();
        // Nonces this delta has already accounted for, so a delta naming one
        // entry twice still stores it once. `self.used_nonces` used to be
        // mutated in the loop and did this job; it cannot now, because nothing
        // is committed until every entry has passed.
        let mut seen: HashSet<[u8; 32]> = HashSet::new();

        for entry in entries {
            // Reject duplicate nonces
            // nonce-identity-waiver: reputation keys identity on `token.nonce` and has the
            // same defect the mailbox re-key fixed -- see
            // `known_gap_two_feedback_variants_sharing_a_token_do_not_converge`. Parked
            // until the reputation contract's own re-key; NOT a site to copy.
            if self.used_nonces.contains(&entry.token.nonce) || !seen.insert(entry.token.nonce) {
                continue;
            }

            // Verify the RSA-PSS signature
            let token_bytes =
                crate::to_cbor(&entry.token).map_err(|e| format!("serialize token: {e}"))?;
            let signature = Signature::try_from(entry.signature.as_slice())
                .map_err(|e| format!("invalid RSA signature bytes: {e}"))?;
            verifying_key
                .verify(&token_bytes, &signature)
                .map_err(|e| format!("feedback signature invalid: {e}"))?;

            accepted.push(entry);
        }

        for entry in accepted {
            self.used_nonces.insert(entry.token.nonce);
            self.feedback.push(entry.clone());
        }

        // Sort deterministically by nonce for CRDT convergence
        self.feedback
            .sort_by(|a, b| a.token.nonce.cmp(&b.token.nonce));

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

    fn token(nonce: u8) -> FeedbackToken {
        FeedbackToken {
            target_reputation_contract: [5u8; 32],
            nonce: [nonce; 32],
        }
    }

    fn entry(signature: Vec<u8>, nonce: u8) -> FeedbackEntry {
        FeedbackEntry {
            token: token(nonce),
            signature,
            category: FeedbackCategory::NonDelivery,
            comment: String::new(),
            submitted_at: DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
        }
    }

    /// A feedback entry whose RSA-PSS signature genuinely verifies.
    fn signed_entry(private: &RsaPrivateKey, nonce: u8) -> FeedbackEntry {
        let mut rng = rsa::rand_core::OsRng;
        let signing_key = BlindedSigningKey::<Sha256>::new(private.clone());
        let bytes = crate::to_cbor(&token(nonce)).expect("serialize token");
        let signature = signing_key.sign_with_rng(&mut rng, &bytes).to_vec();
        entry(signature, nonce)
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
    /// **KNOWN GAP, found by the 2026-09-05 identity sweep and NOT fixed
    /// here: two feedback entries sharing a token do not converge.**
    ///
    /// The doc on `ReputationStateV1` says feedback is "naturally
    /// commutative: adding feedback entries in any order produces the same
    /// final set". It is not, and this is the counterexample.
    ///
    /// The RSA signature covers `entry.token` and nothing else, while
    /// `category`, `comment` and `submitted_at` ride alongside it unsigned.
    /// Identity is `token.nonce`. So anyone who reads a published entry --
    /// the contract state is public -- can re-submit the same token and
    /// signature with different words, and each peer keeps whichever it saw
    /// FIRST. Two peers that saw the two orders keep different bytes forever.
    ///
    /// The consequence is not only convergence: a seller who reads negative
    /// feedback can push a neutered variant to peers that do not hold the
    /// original yet, and those peers will refuse the real one when it
    /// arrives, because its nonce is already used.
    ///
    /// This is the same class as the mailbox's nonce identity, which the
    /// 2026-09-05 change fixed by keying on a digest of the whole entry. It
    /// is left alone here deliberately: it is a different contract with its
    /// own re-key, the fix wants its own review, and for feedback the better
    /// repair is probably to sign the whole entry rather than the token
    /// alone, so the variant cannot be constructed at all. Recorded in
    /// `docs/untested-invariants.md`.
    /// **Two peers given the same feedback in different orders must hold
    /// byte-identical state.**
    ///
    /// This is the property `mailbox::determinism_tests::
    /// merging_is_order_independent` pins for the mailbox. Reputation had no
    /// equivalent -- and reputation is the contract whose STATE actually held
    /// a nondeterministically-encoded collection, so the guard existed on the
    /// one of the two that did not need it.
    ///
    /// Red before `used_nonces` became a `BTreeSet`. A `HashSet` draws a fresh
    /// random seed per INSTANCE, so two independently-built sets holding the
    /// same nonces iterate differently and therefore CBOR-encode differently.
    /// `apply_delta` already sorts `feedback` "deterministically by nonce for
    /// CRDT convergence"; the set beside it silently spent that sort.
    #[test]
    fn used_nonces_encoding_is_deterministic() {
        let (private, params) = key_pair();
        let entries: Vec<_> = (1u8..6).map(|n| signed_entry(&private, n)).collect();
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
    /// over data. V9 wrote `used_nonces` as a `HashSet`, whose CBOR is a
    /// plain array (major type 4) in whatever order that instance chose, so
    /// BOTH orders below are valid V9 bytes for the same set. `BTreeSet`
    /// reads either, and re-encodes both identically -- which is what makes
    /// the fold from V9 pure data transfer rather than a shape change.
    #[test]
    fn predecessor_state_in_any_member_order_decodes_and_normalises() {
        let ascending: Vec<[u8; 32]> = (1u8..6).map(|n| [n; 32]).collect();
        let descending: Vec<[u8; 32]> = ascending.iter().rev().copied().collect();

        let from_ascending: BTreeSet<[u8; 32]> =
            crate::from_cbor(&crate::to_cbor(&ascending).expect("encode")).expect("decode");
        let from_descending: BTreeSet<[u8; 32]> =
            crate::from_cbor(&crate::to_cbor(&descending).expect("encode")).expect("decode");

        assert_eq!(
            from_ascending, from_descending,
            "the same members in a different order are the same set"
        );
        assert_eq!(
            crate::to_cbor(&from_ascending).expect("encode"),
            crate::to_cbor(&from_descending).expect("encode"),
            "predecessor bytes in any order must fold to one canonical encoding"
        );
    }

    /// **A summary must encode as a function of its contents alone.**
    ///
    /// Note the shape of this test, because the obvious simpler one CANNOT
    /// FAIL. [`ReputationStateV1::summarize`] returns `used_nonces.clone()`,
    /// and cloning a `HashSet` copies its hasher along with its contents, so
    /// the clone iterates in the parent's order -- summarising ONE state twice
    /// yields identical bytes even under the defect. Measured, not assumed.
    ///
    /// So the comparison has to be between summaries of two INDEPENDENTLY
    /// built states. That is the only shape that goes red here. (The mailbox
    /// is not like this: its `summarize` rebuilds the set with `collect()` on
    /// every call, so there even the same-state form would have failed. Two
    /// summary methods, two different vacuousness traps, same underlying
    /// defect -- which is why both files pin it with the independent-state
    /// form rather than the shorter one.)
    #[test]
    fn the_summary_encodes_the_same_for_two_independently_built_states() {
        let (private, params) = key_pair();
        let entries: Vec<_> = (1u8..6).map(|n| signed_entry(&private, n)).collect();
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

    #[test]
    fn known_gap_two_feedback_variants_sharing_a_token_do_not_converge() {
        let (private, params) = key_pair();
        let genuine = signed_entry(&private, 1);
        let neutered = FeedbackEntry {
            category: FeedbackCategory::Other("no complaint".to_string()),
            comment: "actually it was fine".to_string(),
            ..genuine.clone()
        };
        assert_eq!(
            genuine.token.nonce, neutered.token.nonce,
            "precondition: one token, two entries"
        );

        let mut saw_genuine_first = ReputationStateV1::default();
        saw_genuine_first
            .apply_delta(&params, &Some(vec![genuine.clone()]))
            .expect("apply");
        saw_genuine_first
            .apply_delta(&params, &Some(vec![neutered.clone()]))
            .expect("apply");

        let mut saw_neutered_first = ReputationStateV1::default();
        saw_neutered_first
            .apply_delta(&params, &Some(vec![neutered]))
            .expect("apply");
        saw_neutered_first
            .apply_delta(&params, &Some(vec![genuine]))
            .expect("apply");

        assert_ne!(
            saw_genuine_first.feedback, saw_neutered_first.feedback,
            "these two peers converged, so this known gap is CLOSED -- delete this test and \
             correct the commutativity claim on `ReputationStateV1`"
        );
    }
}
