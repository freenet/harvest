//! A seller's public record: receipted complaints against their store
//! (harvest#53 Phase C).
//!
//! # What a complaint is
//!
//! A [`Complaint`] names one PAID order of the store and one
//! [`FeedbackCategory`], signed by the order's buyer. It carries everything a
//! stranger needs to check it, so the contract checks it without reading any
//! other contract:
//!
//! * the order's terms, signed by the store key (the key this contract is
//!   addressed by), so the order is genuinely this store's;
//! * the order's payment evidence, verified against the bridges the seller
//!   signed into those terms, so the order was genuinely paid;
//! * the buyer's signature over [`ComplaintTerms`], made with the
//!   `buyer_receipt_key` the seller signed into the terms (harvest#53
//!   Phase B), so only that order's buyer can complain about it.
//!
//! One complaint per paid order: the slot is the order id. A complaint
//! therefore costs a real payment to the seller, and needs nothing from the
//! seller at complaint time, so it survives a seller who took the money and
//! vanished. This is the "receipted" row of the design's trilemma (harvest#53
//! design, section 4), decided by Ian on 2026-09-22.
//!
//! # Categories only
//!
//! No free text (section 7, decision 2). This record is permanent, public and
//! unmoderatable; a free-text channel between anonymous strangers on it is a
//! channel for extortion, off-platform contact and worse, with nobody able to
//! take anything down.
//!
//! # What the contract does NOT judge
//!
//! When. A contract has no clock, so the complaint window, and what a later
//! reversal of the payment means for a complaint, are reader-side judgements
//! (the UI's `fulfilment::complaint_standing`). The contract checks only what
//! is a function of the complaint's own bytes and the store key.

use ed25519_dalek::VerifyingKey;
use freenet_bitcoin_common::BlockAnchor;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::feedback::FeedbackCategory;
use crate::payment::{AuthorizedOrder, OrderId, OrderStatus};

/// Immutable parameters for a reputation contract, set at creation time.
///
/// The store's key alone (harvest#53 Phase C): a store's record is a function
/// of the store, the entity model's commitment. Until Phase C this also
/// carried the RSA public key the blind-signed feedback tokens were verified
/// against; see `ui/src/migrate.rs` for how the instances addressed that way
/// are still found.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ReputationParameters {
    /// The store's Ed25519 key: what the complained-about orders' terms are
    /// signed by.
    ///
    /// Named `store_key`, not `owner_verifying_key` as the RSA generations
    /// had it: this struct would otherwise encode to exactly the bytes of
    /// `MailboxParameters` for the same key, and the address guard
    /// (`address::tests::placeholders_differ_between_structs`) exists to keep
    /// two structs from being indistinguishable.
    ///
    /// `pub(crate)` on purpose -- see [`ReputationParameters::new`].
    pub(crate) store_key: VerifyingKey,
}

impl ReputationParameters {
    /// The only way to build these parameters from outside `harvest-common`.
    ///
    /// The field set of this struct is hashed into the reputation contract's
    /// address, so a second place building it by hand can address a different
    /// contract. See [`crate::store::StoreParameters::new`] for the incident
    /// that argument comes from.
    pub fn new(store_key: VerifyingKey) -> Self {
        Self { store_key }
    }

    /// The store key the record is addressed by.
    pub fn store_key(&self) -> &VerifyingKey {
        &self.store_key
    }
}

/// Which protocol a [`ComplaintTerms`] belongs to.
///
/// A single-variant enum rather than nothing, so the bytes the buyer's key
/// signs name what they are. The same key also signs `(order id, Cancelled)`
/// for the buyer's cancel (`payment::AuthorizedOrder::verify`), and a
/// signature for one must never read as the other.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum ComplaintTag {
    HarvestComplaintV1,
}

/// What the buyer's receipt key signs for a complaint.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ComplaintTerms {
    pub tag: ComplaintTag,
    pub order_id: OrderId,
    pub category: FeedbackCategory,
    /// A recent Bitcoin block: the complaint was signed no earlier than it.
    /// A lower bound only, like a despatch's anchor (`fulfilment`): every
    /// past block hash is public, so a buyer can name an early one.
    pub block_ref: BlockAnchor,
}

/// A buyer's complaint about one paid order of this store.
///
/// # Who can make a second, different complaint for one order
///
/// * The buyer, by signing again with another category or block. Both are
///   real; the slot keeps the smaller encoding, a total order over the
///   complaints' own bytes, so which survives does not depend on arrival
///   order.
/// * Anyone, by attaching different valid payment evidence for the same
///   order (evidence is signed by nobody), and the seller, by re-signing the
///   same terms. Neither can change what the buyer signed -- the order, the
///   category and the block -- so any variant they can win the slot with
///   says exactly what the buyer's did.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Complaint {
    /// The order, at `Paid`, with its seller-signed terms and its evidence.
    pub order: AuthorizedOrder,
    pub category: FeedbackCategory,
    pub block_ref: BlockAnchor,
    /// CBOR `ScopedPayload` over [`ComplaintTerms`]
    /// (`backing::store_key_envelope`).
    pub scoped_payload: Vec<u8>,
    /// The order's `buyer_receipt_key`'s signature over `scoped_payload`.
    pub buyer_signature: Vec<u8>,
}

/// Domain separation for [`Complaint::digest`].
const COMPLAINT_DIGEST_DOMAIN: &[u8] = b"harvest/complaint-digest/v1";

impl Complaint {
    /// What the buyer's key signs for this complaint.
    pub fn terms(&self) -> ComplaintTerms {
        ComplaintTerms {
            tag: ComplaintTag::HarvestComplaintV1,
            order_id: self.order.order.id.clone(),
            category: self.category.clone(),
            block_ref: self.block_ref,
        }
    }

    /// The slot this complaint occupies: its order.
    pub fn order_id(&self) -> &OrderId {
        &self.order.order.id
    }

    /// Check the complaint against the store key `owner`: a PAID order of
    /// this store, complained about by that order's buyer.
    pub fn verify(&self, owner: &VerifyingKey) -> Result<(), String> {
        if self.order.status != OrderStatus::Paid {
            return Err(format!(
                "a complaint must name a paid order, and this one is {:?}",
                self.order.status
            ));
        }
        // Terms signed by the store key, the id the terms give, nothing
        // attached that the status does not use, and payment evidence that
        // verifies against the bridges the seller signed in.
        self.order
            .verify(owner)
            .map_err(|e| format!("the complained-about order does not verify: {e}"))?;
        // Weak and malformed keys are refused here, the one place every
        // buyer act is checked against (`Order::buyer_verifying_key`).
        let buyer_key = self
            .order
            .order
            .buyer_verifying_key()?
            .ok_or("the order names no buyer key, so nobody can complain about it")?;
        let signature = <[u8; 64]>::try_from(self.buyer_signature.as_slice())
            .map(|bytes| ed25519_dalek::Signature::from_bytes(&bytes))
            .map_err(|_| "the complaint's signature is not 64 bytes".to_string())?;
        // Strict: refuses non-canonical encodings as well, so a signature
        // this accepts is one only the key's holder could have made.
        buyer_key
            .verify_strict(&self.scoped_payload, &signature)
            .map_err(|e| format!("the complaint is not signed by the order's buyer: {e}"))?;
        // The payload is these terms, and the requestor is Harvest.
        crate::listing::verify_scoped_signature(
            &self.scoped_payload,
            &self.buyer_signature,
            &buyer_key,
            &self.terms(),
        )
        .map_err(|e| format!("the complaint is not signed by the order's buyer: {e}"))
    }

    /// Content digest of the whole complaint, signatures and evidence
    /// included. What a summary names: two complaints for one order are two
    /// different things to exchange.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(COMPLAINT_DIGEST_DOMAIN);
        hasher.update(&crate::to_cbor(self).expect("a complaint always serializes"));
        *hasher.finalize().as_bytes()
    }

    /// The encoding the per-order tie-break compares. See
    /// [`ReputationStateV1::apply_delta`].
    fn canonical_rank(&self) -> Vec<u8> {
        crate::to_cbor(self).expect("a complaint always serializes")
    }
}

/// Per-store reputation contract state: append-only complaints.
///
/// # Canonical form
///
/// At most one complaint per order, `complaints` strictly ascending by order
/// id. `verify` refuses anything else, and `apply_delta` only ever produces
/// this form, so two peers holding the same complaints hold the same bytes.
///
/// # Predecessor state
///
/// The RSA generations held `feedback` and `used_nonces`. Neither key exists
/// here, so their state decodes with no complaints and its certificate kept;
/// no feedback entry was ever written outside tests
/// (`docs/untested-invariants.md`), and one could not be carried in any case,
/// since it names no order.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ReputationStateV1 {
    /// Owner's ghostkey certificate PEM (for verifiers to check identity chain).
    pub owner_certificate_pem: String,
    /// Complaints, strictly ascending by order id.
    ///
    /// `default` because the RSA generations' state has no such key and must
    /// still decode, for the migration to carry its certificate forward. It
    /// is always encoded, so `validate_state`'s canonical-bytes check still
    /// refuses a state that omits it.
    #[serde(default)]
    pub complaints: Vec<Complaint>,
}

/// Summary for delta computation: the digest of every complaint held.
///
/// `BTreeSet`, not `HashSet`: a summary is encoded and sent, so its bytes
/// must be a function of its contents alone.
pub type ReputationSummary = BTreeSet<[u8; 32]>;

/// Delta: complaints to add.
pub type ReputationDelta = Vec<Complaint>;

impl ReputationStateV1 {
    /// Verify the entire state: every complaint, and the canonical form
    /// described on the type.
    pub fn verify(&self, parameters: &ReputationParameters) -> Result<(), String> {
        for complaint in &self.complaints {
            complaint.verify(&parameters.store_key)?;
        }
        // Strictly ascending rejects both an out-of-order list and two
        // complaints for one order.
        for pair in self.complaints.windows(2) {
            if pair[0].order_id() >= pair[1].order_id() {
                return Err(
                    "complaints are not strictly ascending by order id (unsorted or an order \
                     complained about twice)"
                        .into(),
                );
            }
        }
        Ok(())
    }

    /// Generate a summary (the digest of every complaint) for delta
    /// computation.
    pub fn summarize(&self) -> ReputationSummary {
        self.complaints.iter().map(Complaint::digest).collect()
    }

    /// Compute delta: complaints whose digest the old summary does not name.
    pub fn delta(&self, old_summary: &ReputationSummary) -> Option<ReputationDelta> {
        let new: Vec<_> = self
            .complaints
            .iter()
            .filter(|c| !old_summary.contains(&c.digest()))
            .cloned()
            .collect();
        if new.is_empty() {
            None
        } else {
            Some(new)
        }
    }

    /// Apply a delta: verify every complaint, then fold them in, leaving the
    /// state in canonical form.
    ///
    /// All or nothing: the whole delta is verified before any of it is
    /// committed, so a caller that keeps the state it passed in never takes
    /// on complaints from a delta it was told to reject.
    pub fn apply_delta(
        &mut self,
        parameters: &ReputationParameters,
        delta: &Option<ReputationDelta>,
    ) -> Result<(), String> {
        let Some(complaints) = delta else {
            return Ok(());
        };

        let held: BTreeSet<[u8; 32]> = self.summarize();
        let mut incoming: Vec<&Complaint> = Vec::new();
        for complaint in complaints {
            // Already held byte for byte: nothing to verify or add. This is
            // what bounds verification work per update.
            if held.contains(&complaint.digest()) {
                continue;
            }
            complaint.verify(&parameters.store_key)?;
            incoming.push(complaint);
        }

        // One slot per order. Rebuilding from `self` as well as the delta is
        // what normalises a state that arrived out of order.
        let mut by_order: BTreeMap<OrderId, Complaint> = BTreeMap::new();
        for complaint in self
            .complaints
            .drain(..)
            .chain(incoming.into_iter().cloned())
        {
            match by_order.entry(complaint.order_id().clone()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(complaint);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    // Two complaints for one order: keep the smaller
                    // encoding, so the survivor is a function of the two and
                    // not of arrival order.
                    if complaint.canonical_rank() < slot.get().canonical_rank() {
                        slot.insert(complaint);
                    }
                }
            }
        }
        self.complaints = by_order.into_values().collect();
        Ok(())
    }

    /// Merge another full state into this one: every complaint, plus the
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
        self.apply_delta(parameters, &Some(other.complaints.clone()))?;
        if self.owner_certificate_pem.is_empty() {
            self.owner_certificate_pem = other.owner_certificate_pem.clone();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_orders::{
        authorized, block, buyer_key, complaint, complaint_by, order, paid, proof, sign_scoped,
        store_key,
    };
    use ed25519_dalek::SigningKey;

    fn params() -> ReputationParameters {
        ReputationParameters::new(store_key().verifying_key())
    }

    fn owner() -> VerifyingKey {
        store_key().verifying_key()
    }

    /// The fixture has to be right, or every refusal below passes for the
    /// wrong reason.
    #[test]
    fn a_genuine_complaint_about_a_paid_order_applies() {
        let c = complaint(1);
        c.verify(&owner()).expect("the fixture complaint verifies");
        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params(), &Some(vec![c]))
            .expect("a genuine complaint applies");
        assert_eq!(state.complaints.len(), 1);
        state
            .verify(&params())
            .expect("and the result is valid state");
    }

    /// **Only a PAID order can be complained about.** The receipted design's
    /// whole point: a complaint costs the order value. Red if the status
    /// check is removed (an unpaid order's terms and the buyer signature
    /// still verify).
    #[test]
    fn a_complaint_about_an_unpaid_or_cancelled_order_is_refused() {
        for status in [OrderStatus::AwaitingPayment, OrderStatus::Cancelled] {
            let mut unpaid = authorized(&store_key(), order(1), OrderStatus::AwaitingPayment);
            unpaid.status = status;
            let c = complaint_by(&buyer_key(1), unpaid, FeedbackCategory::NonDelivery, 200);
            let err = c
                .verify(&owner())
                .expect_err("an unpaid order must be refused");
            assert!(err.contains("paid order"), "{status:?}: {err}");
        }
    }

    /// Paid, but with the evidence stripped or forged: `AuthorizedOrder::
    /// verify` is what checks it, and the complaint must go through it.
    #[test]
    fn a_complaint_whose_payment_evidence_does_not_verify_is_refused() {
        let mut no_proof = paid(1);
        no_proof.payment_proof = None;
        let c = complaint_by(&buyer_key(1), no_proof, FeedbackCategory::NonDelivery, 200);
        assert!(c.verify(&owner()).is_err(), "Paid with no evidence");

        // Evidence for a DIFFERENT order: genuine claims, wrong script.
        let mut wrong = paid(1);
        wrong.payment_proof = Some(proof(&order(2), 1));
        let c = complaint_by(&buyer_key(1), wrong, FeedbackCategory::NonDelivery, 200);
        assert!(c.verify(&owner()).is_err(), "evidence for another order");
    }

    /// **Only the order's buyer can complain.** A stranger who reads the
    /// public paid order cannot sign for it, and neither can the seller.
    #[test]
    fn a_complaint_not_signed_by_the_orders_buyer_is_refused() {
        for (who, key) in [
            ("a stranger", SigningKey::from_bytes(&[77u8; 32])),
            ("the seller", store_key()),
            ("another order's buyer", buyer_key(2)),
        ] {
            let c = complaint_by(&key, paid(1), FeedbackCategory::NonDelivery, 200);
            let err = c.verify(&owner()).expect_err(who);
            assert!(
                err.contains("not signed by the order's buyer"),
                "{who}: {err}"
            );
        }
    }

    /// An order of ANOTHER store: its terms are genuinely signed, by that
    /// store's key, so this record's key refuses them.
    #[test]
    fn a_complaint_about_another_stores_order_is_refused() {
        let other_store = SigningKey::from_bytes(&[44u8; 32]);
        let theirs = authorized(&other_store, order(1), OrderStatus::Paid);
        let c = complaint_by(&buyer_key(1), theirs, FeedbackCategory::NonDelivery, 200);
        c.verify(&other_store.verifying_key())
            .expect("it is a genuine complaint on that store's record");
        assert!(c.verify(&owner()).is_err(), "but not on this one");
    }

    /// Nobody can complain about an order that names no buyer key, and a
    /// weak key (which anyone can sign for) is refused, not trusted.
    #[test]
    fn an_order_with_no_or_a_weak_buyer_key_takes_no_complaint() {
        let mut keyless = order(1);
        keyless.buyer_receipt_key = None;
        let keyless = keyless.with_derived_id();
        let c = complaint_by(
            &buyer_key(1),
            authorized(&store_key(), keyless, OrderStatus::Paid),
            FeedbackCategory::NonDelivery,
            200,
        );
        let err = c.verify(&owner()).expect_err("no buyer key");
        assert!(err.contains("names no buyer key"), "{err}");

        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut weak = order(1);
        weak.buyer_receipt_key = Some(identity);
        let weak = weak.with_derived_id();
        let mut c = complaint_by(
            &buyer_key(1),
            authorized(&store_key(), weak, OrderStatus::Paid),
            FeedbackCategory::NonDelivery,
            200,
        );
        // R = identity, s = 0: verifies under a weak key for any message.
        let mut forged = [0u8; 64];
        forged[0] = 1;
        c.buyer_signature = forged.to_vec();
        let err = c.verify(&owner()).expect_err("a weak buyer key");
        assert!(err.contains("weak"), "{err}");
    }

    /// Everything the buyer said is signed: changing the category, the
    /// block, or which order it names breaks the signature.
    #[test]
    fn every_field_the_buyer_states_is_signed() {
        let genuine = complaint(1);
        let mut altered = Vec::new();
        let mut c = genuine.clone();
        c.category = FeedbackCategory::Counterfeit;
        altered.push(("category", c));
        let mut c = genuine.clone();
        c.block_ref = block(201);
        altered.push(("block_ref", c));
        // Another paid order of the same buyer key would need that order to
        // name the key; this one names buyer 2, so swap in order 2 but keep
        // buyer 1's signature.
        let mut c = genuine.clone();
        c.order = paid(2);
        altered.push(("order", c));
        for (field, c) in altered {
            assert!(
                c.verify(&owner()).is_err(),
                "changing `{field}` after signing must break verification"
            );
        }
    }

    /// **A buyer's cancel signature cannot be replayed as a complaint.** The
    /// same key signs `(order id, Cancelled)` for the buyer's cancel; the
    /// complaint's tag is what keeps the two apart.
    #[test]
    fn a_cancel_signature_is_not_a_complaint() {
        let genuine = complaint(1);
        let (scoped, sig) = sign_scoped(
            &buyer_key(1),
            &(genuine.order.order.id.clone(), OrderStatus::Cancelled),
        );
        let replayed = Complaint {
            scoped_payload: scoped,
            buyer_signature: sig,
            ..genuine
        };
        assert!(replayed.verify(&owner()).is_err());
    }

    /// A delta is all-or-nothing.
    #[test]
    fn a_delta_holding_one_invalid_complaint_applies_none_of_it() {
        let good = complaint(1);
        let bad = complaint_by(
            &SigningKey::from_bytes(&[77u8; 32]),
            paid(2),
            FeedbackCategory::NonDelivery,
            200,
        );
        for delta in [vec![good.clone(), bad.clone()], vec![bad, good.clone()]] {
            let mut state = ReputationStateV1::default();
            state
                .apply_delta(&params(), &Some(delta))
                .expect_err("a delta carrying an invalid complaint is refused");
            assert!(state.complaints.is_empty(), "and leaves nothing behind");
        }
        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params(), &Some(vec![good.clone(), good]))
            .expect("the good one alone applies, once");
        assert_eq!(state.complaints.len(), 1);
    }

    /// **Two genuine complaints for one order converge, whichever arrives
    /// first**: the buyer signing twice, and a third party attaching other
    /// valid evidence to the buyer's complaint. Red if the tie-break keeps
    /// the incumbent.
    #[test]
    fn two_complaints_for_one_order_converge() {
        let first = complaint(1);
        let buyer_again = complaint_by(&buyer_key(1), paid(1), FeedbackCategory::Counterfeit, 250);
        let mut other_evidence = first.clone();
        other_evidence.order.payment_proof = Some(proof(&order(1), 2));
        other_evidence
            .verify(&owner())
            .expect("other valid evidence still verifies");
        assert_ne!(other_evidence, first);

        for second in [buyer_again, other_evidence] {
            let mut a = ReputationStateV1::default();
            a.apply_delta(&params(), &Some(vec![first.clone()]))
                .unwrap();
            a.apply_delta(&params(), &Some(vec![second.clone()]))
                .unwrap();
            let mut b = ReputationStateV1::default();
            b.apply_delta(&params(), &Some(vec![second])).unwrap();
            b.apply_delta(&params(), &Some(vec![first.clone()]))
                .unwrap();
            assert_eq!(a.complaints.len(), 1, "one order, one complaint");
            assert_eq!(
                crate::to_cbor(&a).unwrap(),
                crate::to_cbor(&b).unwrap(),
                "the two peers must hold identical bytes"
            );
        }
    }

    /// Peers holding different complaints for one order find out through the
    /// real summary/delta exchange: a summary keyed on the order id would
    /// tell each the other already had its complaint.
    #[test]
    fn peers_holding_different_complaints_for_one_order_exchange_them() {
        let mut a = ReputationStateV1::default();
        a.apply_delta(&params(), &Some(vec![complaint(1)])).unwrap();
        let mut b = ReputationStateV1::default();
        b.apply_delta(
            &params(),
            &Some(vec![complaint_by(
                &buyer_key(1),
                paid(1),
                FeedbackCategory::Misrepresented,
                300,
            )]),
        )
        .unwrap();
        assert_ne!(a, b);
        let to_b = a.delta(&b.summarize());
        let to_a = b.delta(&a.summarize());
        assert!(to_a.is_some() && to_b.is_some());
        b.apply_delta(&params(), &to_b).unwrap();
        a.apply_delta(&params(), &to_a).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.delta(&b.summarize()), None);
    }

    /// `verify` refuses every non-canonical form.
    #[test]
    fn verify_refuses_non_canonical_state() {
        let mut pair = [(1u8, complaint(1)), (2u8, complaint(2))];
        pair.sort_by(|x, y| x.1.order_id().cmp(y.1.order_id()));
        let [(first, one), (_, two)] = pair;
        let canonical = ReputationStateV1 {
            owner_certificate_pem: String::new(),
            complaints: vec![one.clone(), two.clone()],
        };
        canonical.verify(&params()).expect("canonical verifies");
        let unsorted = ReputationStateV1 {
            complaints: vec![two, one.clone()],
            ..canonical.clone()
        };
        assert!(unsorted.verify(&params()).is_err(), "out of order");
        let variant = complaint_by(
            &buyer_key(first),
            one.order.clone(),
            FeedbackCategory::Counterfeit,
            400,
        );
        let twice = ReputationStateV1 {
            complaints: vec![one, variant],
            ..canonical
        };
        assert!(twice.verify(&params()).is_err(), "one order twice");
    }

    /// A state that arrived out of order leaves `apply_delta` and `merge`
    /// canonical: the migration fold decodes predecessor state unverified.
    #[test]
    fn apply_delta_and_merge_normalise_the_state_they_are_applied_to() {
        let mut held = vec![complaint(1), complaint(3)];
        held.sort_by(|x, y| y.order_id().cmp(x.order_id()));
        let state = ReputationStateV1 {
            owner_certificate_pem: String::new(),
            complaints: held,
        };
        let mut applied = state.clone();
        applied
            .apply_delta(&params(), &Some(vec![complaint(2)]))
            .unwrap();
        applied.verify(&params()).expect("canonical after apply");
        let mut merged = state;
        merged
            .merge(&params(), &ReputationStateV1::default())
            .unwrap();
        merged
            .verify(&params())
            .expect("merging nothing still normalises");
    }

    /// **Seeded random merge laws, byte for byte**, over states built from
    /// genuine complaints, including two variants for each of two orders,
    /// and certificates that are empty or one value (a second non-empty
    /// certificate is harvest#81 and is not claimed to converge).
    #[test]
    fn seeded_random_reputations_obey_the_merge_laws() {
        use crate::merge_laws::{assert_laws, Rng};
        let mut pool: Vec<Complaint> = (1u8..=5).map(complaint).collect();
        pool.push(complaint_by(
            &buyer_key(1),
            paid(1),
            FeedbackCategory::Counterfeit,
            500,
        ));
        let mut evidence = complaint(2);
        evidence.order.payment_proof = Some(proof(&order(2), 3));
        pool.push(evidence);
        let certs = ["", "-----BEGIN CERT-----"];

        let mut rng = Rng::new(0x5eed_0053);
        let states: Vec<ReputationStateV1> = (0..120)
            .map(|_| {
                let mut s = ReputationStateV1 {
                    owner_certificate_pem: certs[rng.below(2)].to_string(),
                    ..Default::default()
                };
                s.apply_delta(&params(), &Some(rng.subset(&pool, 4)))
                    .expect("apply");
                s
            })
            .collect();
        let merge = |a: &ReputationStateV1, b: &ReputationStateV1| {
            let mut out = a.clone();
            out.merge(&params(), b).expect("merge");
            out
        };
        let enc = |s: &ReputationStateV1| crate::to_cbor(s).expect("encode");
        assert_laws(&states, 100, &mut rng, merge, enc);
        let exchange = |a: &ReputationStateV1, b: &ReputationStateV1| {
            let mut out = a.clone();
            out.apply_delta(&params(), &b.delta(&a.summarize()))
                .expect("apply");
            if out.owner_certificate_pem.is_empty() {
                out.owner_certificate_pem = b.owner_certificate_pem.clone();
            }
            out
        };
        assert_laws(&states, 100, &mut rng, exchange, enc);
    }

    /// **The RSA generations' state decodes into this type with its
    /// certificate kept** -- the reputation migration (Option A) carries
    /// exactly that forward. The decode target is the REAL type: a test that
    /// decoded into a struct named here would test `ciborium`, not the
    /// migration (the trap an earlier reputation test fell into).
    #[test]
    fn rsa_generation_state_decodes_with_its_certificate() {
        #[derive(serde::Serialize)]
        struct RsaGenerationState {
            owner_certificate_pem: String,
            feedback: Vec<u8>,
            used_nonces: Vec<[u8; 32]>,
        }
        let old = RsaGenerationState {
            owner_certificate_pem: "-----BEGIN CERT-----".into(),
            feedback: Vec::new(),
            used_nonces: Vec::new(),
        };
        let decoded: ReputationStateV1 =
            crate::from_cbor(&crate::to_cbor(&old).unwrap()).expect("decodes");
        assert_eq!(decoded.owner_certificate_pem, "-----BEGIN CERT-----");
        assert!(decoded.complaints.is_empty());
    }
}
