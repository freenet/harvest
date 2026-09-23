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
//!
//! # Full record: the latest-dated go first
//!
//! A record holds at most [`MAX_COMPLAINTS`], so it never reaches freenet-core's
//! state limit, where an honest complaint's merge would be refused (review
//! round 5 of #143, R5-C). Past that it keeps the complaints dated nearest
//! their own paid height and drops the farthest
//! ([`Complaint::distance_from_payment`]). That is an ORDER, not a window: it
//! reads only the buyer's two signed heights, and the window stays the
//! reader's. A seller filling its record with late complaints about its own
//! orders drops only its own late ones; a complaint nearer its payment than
//! all of them stays.

use ed25519_dalek::VerifyingKey;
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
    /// The Bitcoin height the buyer says the complaint was made at, which
    /// is what the reader-side window reads (`fulfilment::complaint_standing`).
    ///
    /// The buyer's own statement and nothing more: no chain can check it, so
    /// a buyer can name an in-window height after the window closed, and the
    /// window binds only the honest (`docs/complaint-threat-model.md`
    /// section 7). A height rather than a block anchor (review round 2 of
    /// #143, R2-7): readers only ever read the height, and an anchor's hash
    /// was 32 bytes of buyer-chosen free text on a permanent record.
    pub block_height: u32,
    /// The height the complaint's own evidence says the order was paid at,
    /// `payment::paid_height` over the complaint's proof. Every window a
    /// reader judges the complaint by counts from it.
    ///
    /// Signed, and checked against the proof by `Complaint::verify`, because
    /// the evidence is signed by nobody: anyone re-submitting the buyer's
    /// complaint could otherwise attach a different proof (one showing a
    /// payment the seller made to its own address earlier) and move the
    /// window's start (review of the threat model, TM-D).
    pub paid_height: u32,
}

/// A buyer's complaint about one paid order of this store.
///
/// # Who can make a second, different complaint for one order
///
/// * The buyer, by signing again with another category or block. Both are
///   real; the slot keeps the one dated nearer its payment, then the one
///   whose signed terms encode smaller (then the smaller signature), a total
///   order over the buyer's own bytes, so
///   which survives does not depend on arrival order -- and not on anything
///   the seller or a third party can vary.
/// * Anyone, by attaching different valid payment evidence for the same
///   order (evidence is signed by nobody), and the seller, by re-signing the
///   same terms. Neither can change what the buyer signed -- the order, the
///   category and the block -- and the tie-break ranks what the buyer signed
///   first, so they choose only among copies of ONE buyer statement
///   ([`Complaint::canonical_rank`]).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Complaint {
    /// The order, at `Paid`, with its seller-signed terms and its evidence.
    pub order: AuthorizedOrder,
    pub category: FeedbackCategory,
    /// See [`ComplaintTerms::block_height`].
    pub block_height: u32,
    /// See [`ComplaintTerms::paid_height`].
    pub paid_height: u32,
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
            block_height: self.block_height,
            paid_height: self.paid_height,
        }
    }

    /// The slot this complaint occupies: its order.
    pub fn order_id(&self) -> &OrderId {
        &self.order.order.id
    }

    /// Check the complaint against the store key `owner`: a PAID order of
    /// this store, complained about by that order's buyer.
    ///
    /// Reads nothing but the complaint and `owner`, which is the record's own
    /// parameter: no store state, no backing, no clock
    /// (`docs/complaint-threat-model.md` section 3). The cheap checks run
    /// first and the payment evidence last, so a forged complaint costs one
    /// signature check rather than an SPV proof (review round 2, P3).
    pub fn verify(&self, owner: &VerifyingKey) -> Result<(), String> {
        if self.order.status != OrderStatus::Paid {
            return Err(format!(
                "a complaint must name a paid order, and this one is {:?}",
                self.order.status
            ));
        }
        // The same rules the buyer checked before paying
        // (`payment::complaint_preconditions`): a real payment, and a
        // bounded order. Nothing about how the seller ENCODED the order
        // envelope is checked, because the seller can re-sign the same terms
        // in another encoding at will (review round 2, R2-1).
        crate::payment::complaint_preconditions(&self.order)
            .map_err(|e| format!("the complained-about order cannot take a complaint: {e}"))?;
        // Bounded as a whole (review round 6): the proof's tip is a byte
        // string only a bridge signs, and the order may name one the seller
        // runs. Without this one padded complaint could fill the record to
        // freenet-core's state limit under the count cap.
        let size = crate::to_cbor(self)?.len();
        if size > MAX_COMPLAINT_BYTES {
            return Err(format!(
                "a complaint may carry at most {MAX_COMPLAINT_BYTES} bytes, and this one is {size}"
            ));
        }
        // Nothing rides along that the buyer did not sign (review round 1,
        // P1-3). `verify_scoped_signature` below decodes the envelope and
        // compares its payload, which tolerates bytes after the CBOR item and
        // map keys the decoder skips; on a permanent, public record those are
        // a free-text channel (section 7, decision 2) and a way to bloat it.
        // The buyer's own software makes this envelope, so it can always be
        // exact. The ORDER's envelope is the seller's, bounded by size above
        // instead; what the seller signs into its own record is #144.
        let terms_bytes = crate::to_cbor(&self.terms())?;
        if !crate::backing::is_exact_harvest_envelope(&self.scoped_payload, &terms_bytes) {
            return Err(
                "the complaint's signed payload is not exactly the envelope of its terms".into(),
            );
        }
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
        .map_err(|e| format!("the complaint is not signed by the order's buyer: {e}"))?;
        // The evidence is the canonical minimal proof, so padding the record
        // costs real fees (TM-E), and it shows the paid height the buyer
        // signed, so nobody can move the window by swapping it (TM-D).
        let proof = self
            .order
            .payment_proof
            .as_ref()
            .ok_or("the complained-about order carries no payment evidence")?;
        crate::payment::verify_minimal_proof(&self.order.order, proof)?;
        if crate::payment::paid_height(&self.order) != Some(self.paid_height) {
            return Err(format!(
                "the complaint says the order was paid at block {}, and its evidence does not",
                self.paid_height
            ));
        }
        // Terms signed by the store key, the id the terms give, nothing
        // attached that the status does not use, and payment evidence that
        // verifies against the bridges the seller signed in. Last, because
        // it is the expensive one.
        self.order
            .verify(owner)
            .map_err(|e| format!("the complained-about order does not verify: {e}"))
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

    /// How far the height the buyer says the complaint was made at is from
    /// the height its evidence says the order was paid at, either side. Both
    /// are in the buyer's signed terms, and the paid height is checked
    /// against the proof, so nobody but the buyer sets it.
    ///
    /// What a full record keeps by (R5-C): nearest first. Either side,
    /// rather than signed, so a complaint dated before its payment does not
    /// outrank one dated after it. The honest UI dates a complaint at the
    /// tip when it is filed, which is after the payment.
    pub fn distance_from_payment(&self) -> u32 {
        self.block_height.abs_diff(self.paid_height)
    }

    /// What the per-order tie-break compares, smallest first. See
    /// [`ReputationStateV1::apply_delta`].
    ///
    /// [`Self::distance_from_payment`] comes first, so the tie-break and the
    /// full record's eviction are ONE total order; with two orders, a merge
    /// that evicts could otherwise depend on which of an order's complaints
    /// arrived first. It is a function of the buyer's signed terms.
    ///
    /// Then what the BUYER signed: the terms (order id, category,
    /// block), then the buyer's signature over them. Only when those are
    /// byte-identical -- one buyer statement -- does the rest decide, which
    /// is the order's seller signature and the payment evidence. So the
    /// seller, or anyone attaching other evidence, can only choose among
    /// copies of one statement the buyer made, never between two different
    /// statements (review round 1, P2-9: ranking on the whole encoding let
    /// the seller's re-signed terms decide which of the buyer's complaints
    /// survived).
    fn canonical_rank(&self) -> (u32, Vec<u8>, Vec<u8>, std::cmp::Reverse<u32>, Vec<u8>) {
        (
            self.distance_from_payment(),
            crate::to_cbor(&self.terms()).expect("complaint terms always serialize"),
            self.buyer_signature.clone(),
            // Among copies of ONE buyer statement, the freshest evidence
            // (review round 3): an older ladder rung of the same payment
            // verifies too, and a reader judging a reversal needs the
            // freshest claim, not whichever copy encodes smallest.
            std::cmp::Reverse(crate::payment::evidence_freshness(&self.order)),
            crate::to_cbor(self).expect("a complaint always serializes"),
        )
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

/// The largest complaint, in bytes of its CBOR encoding.
///
/// Derived from what [`Complaint::verify`] accepts, the same way as
/// `delegate::MAX_KEPT_PURCHASE_BYTES`, because a complaint holds the same
/// parts: the order's envelope and terms (`MAX_ORDER_ENVELOPE_BYTES` each,
/// `payment::complaint_preconditions`), its proof's claims
/// (`MAX_PROOF_CLAIM_BYTES`, refused past that by the verifier), and a few
/// hundred bytes of tip, signatures, terms and framing, given 16 KiB.
///
/// **Checked per complaint** by [`Complaint::verify`] (review round 6 of
/// #143): the derivation alone is not a bound, because the proof's tip is a
/// bridge-signed byte string nothing else bounds, and an order may name a
/// bridge the seller runs, which can sign a tip padded to megabytes. Enforced,
/// it is what makes [`MAX_COMPLAINTS`] a byte bound. A genuine complaint fits:
/// pinned by `delegate::tests::a_maximal_verifying_purchase_fits_the_bound`.
pub const MAX_COMPLAINT_BYTES: usize = 2 * crate::payment::MAX_ORDER_ENVELOPE_BYTES
    + crate::payment::MAX_PROOF_CLAIM_BYTES
    + 16 * 1024;

/// The bytes a record's complaints may take: 40 MiB of freenet-core's 50 MiB
/// state limit, the rest left for the certificate and the framing.
pub const RECORD_BUDGET_BYTES: usize = 40 * 1024 * 1024;

/// How many complaints one record holds (review round 5 of #143, R5-C).
///
/// # Why a count, and why this one
///
/// Without a cap, a seller with sockpuppet orders on a reused address could
/// fill its record with complaints to just under freenet-core's state limit,
/// and an honest complaint's merge would then be refused. A byte budget met
/// by walking complaints in order is not associative, whichever way the walk
/// treats one that does not fit (the mailbox found this, harvest#85). Keeping
/// the first N of a total order is: see [`ReputationStateV1::apply_delta`]. So
/// the budget is spent as a count, `RECORD_BUDGET_BYTES / MAX_COMPLAINT_BYTES`,
/// which holds even if every complaint is the largest that verifies. An
/// ordinary complaint is a few kilobytes. It binds on a flood, or on a store
/// with 146 complaints in its life; past that, a reader sees the record is
/// full (`ui/src/state.rs`, `BrowsingStore::record_full`).
///
/// Raising it later re-keys the contract and loses nothing (the migration
/// merges every complaint in). Lowering it would drop complaints.
pub const MAX_COMPLAINTS: usize = RECORD_BUDGET_BYTES / MAX_COMPLAINT_BYTES;

// Loosening a `MAX_*` bound it is derived from would lower it, and lowering it
// drops complaints a record already holds (`docs/complaint-threat-model.md`
// section 8). Raise `RECORD_BUDGET_BYTES` with it, or not at all.
const _: () = assert!(MAX_COMPLAINTS >= 146);

impl ReputationStateV1 {
    /// Verify the entire state: every complaint, and the canonical form
    /// described on the type.
    pub fn verify(&self, parameters: &ReputationParameters) -> Result<(), String> {
        if self.complaints.len() > MAX_COMPLAINTS {
            return Err(format!(
                "a record holds at most {MAX_COMPLAINTS} complaints, and this one has {}",
                self.complaints.len()
            ));
        }
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
    ///
    /// # At most [`MAX_COMPLAINTS`]
    ///
    /// Each order keeps its lowest-ranked complaint
    /// ([`Complaint::canonical_rank`]), and of those, the `MAX_COMPLAINTS`
    /// nearest their payment stay, the order id breaking ties (R5-C). That
    /// is "the first N orders of one total order over complaints", which is
    /// a function of the union of everything ever merged,
    /// so the merge stays commutative, associative and idempotent: a
    /// complaint a merge drops is one that N nearer orders already outrank,
    /// and any later merge only adds to those N. That needs the per-order
    /// tie-break to rank by distance first too, which is why
    /// `canonical_rank` does.
    pub fn apply_delta(
        &mut self,
        parameters: &ReputationParameters,
        delta: &Option<ReputationDelta>,
    ) -> Result<(), String> {
        self.apply_delta_capped(parameters, delta, MAX_COMPLAINTS)
    }

    /// [`Self::apply_delta`] with the cap as a parameter, so the tests can
    /// reach it with a handful of complaints rather than hundreds.
    fn apply_delta_capped(
        &mut self,
        parameters: &ReputationParameters,
        delta: &Option<ReputationDelta>,
        cap: usize,
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
                    // Two complaints for one order: keep the lower
                    // `canonical_rank`, so the survivor is a function of the
                    // two and not of arrival order.
                    if complaint.canonical_rank() < slot.get().canonical_rank() {
                        slot.insert(complaint);
                    }
                }
            }
        }
        let mut kept: Vec<Complaint> = by_order.into_values().collect();
        if kept.len() > cap {
            // Nearest their payment first; the order id breaks a tie, and is
            // unique here. Then back to the canonical order-id order.
            kept.sort_by(|a, b| {
                (a.distance_from_payment(), a.order_id())
                    .cmp(&(b.distance_from_payment(), b.order_id()))
            });
            kept.truncate(cap);
            kept.sort_by(|a, b| a.order_id().cmp(b.order_id()));
        }
        self.complaints = kept;
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
        authorized, buyer_key, complaint, complaint_by, order, paid, proof, proof_as_of, proof_at,
        sign_scoped, store_key,
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
        // The shared predicate itself refuses it (review round 4, P3): the
        // later check in `verify` has the same words, so the assertion above
        // alone passed with the precondition deleted.
        let precondition = crate::payment::complaint_preconditions(&c.order)
            .expect_err("the precondition refuses it");
        assert!(
            precondition.contains("names no buyer key"),
            "{precondition}"
        );

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
        c.block_height = 201;
        altered.push(("block_height", c));
        // Another paid order naming the SAME buyer key, so the only thing
        // that can refuse the swap is that the buyer's signature names order
        // 1's id (review round 1, testing #1: swapping in order 2, which
        // names buyer 2, was refused for the wrong reason).
        let mut other = order(2);
        other.buyer_receipt_key = Some(buyer_key(1).verifying_key().to_bytes());
        let other = authorized(&store_key(), other.with_derived_id(), OrderStatus::Paid);
        complaint_by(
            &buyer_key(1),
            other.clone(),
            FeedbackCategory::NonDelivery,
            200,
        )
        .verify(&owner())
        .expect("precondition: buyer 1 can complain about that order");
        let mut c = genuine.clone();
        c.order = other;
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
    /// **A forged complaint costs a signature check, not an SPV proof**
    /// (review round 2 of #143, P3). A complaint with a stranger's signature
    /// and broken evidence is refused for the signature. Red if the order,
    /// with its payment evidence, is verified first.
    #[test]
    fn a_forged_complaint_is_refused_before_its_evidence_is_checked() {
        let mut broken = paid(1);
        broken.payment_proof = Some(proof(&order(2), 1));
        let c = complaint_by(
            &SigningKey::from_bytes(&[77u8; 32]),
            broken,
            FeedbackCategory::NonDelivery,
            200,
        );
        let err = c.verify(&owner()).expect_err("forged");
        assert!(err.contains("not signed by the order's buyer"), "{err}");
    }

    /// **Nobody re-submitting the buyer's complaint can move its window**
    /// (review of the threat model, TM-D). The buyer signed the paid height
    /// its evidence gives; the seller swaps in other genuine evidence for
    /// the same order, one showing a payment at another height. The swap no
    /// longer verifies. Red if `Complaint::verify` stops comparing the
    /// signed paid height with the evidence.
    #[test]
    fn swapping_the_evidence_cannot_move_the_paid_height() {
        let genuine = complaint(1);
        let mut swapped = genuine.clone();
        swapped.order.payment_proof = Some(proof_at(&order(1), 2, 150));
        swapped
            .order
            .verify(&owner())
            .expect("precondition: the swapped evidence is genuine");
        assert_ne!(
            crate::payment::paid_height(&swapped.order),
            Some(genuine.paid_height),
            "precondition: it shows another paid height"
        );
        let err = swapped.verify(&owner()).expect_err("the window moved");
        assert!(err.contains("paid at block"), "{err}");
    }

    /// **A complaint carries the canonical minimal proof** (TM-E): padding
    /// with a repeated claim, or with a second payment the first already
    /// covers, is refused, though the verifier alone accepts both. Red if
    /// `verify_minimal_proof` is dropped from `Complaint::verify`.
    #[test]
    fn a_complaint_whose_evidence_is_padded_is_refused() {
        use crate::payment::OrderPaymentProof;
        let OrderPaymentProof::OnChain(one) = proof(&order(1), 1) else {
            panic!("on chain");
        };
        // A second payment to the same address: another transaction, so
        // another outpoint.
        let mut second = order(1);
        second.amount_sats += 1;
        let OrderPaymentProof::OnChain(other) = proof(&second, 2) else {
            panic!("on chain");
        };
        let repeated = OrderPaymentProof::OnChain(crate::payment::OnChainPaymentProof {
            claims: vec![one.claims[0].clone(), one.claims[0].clone()],
            tip: one.tip.clone(),
        });
        let covered_twice = OrderPaymentProof::OnChain(crate::payment::OnChainPaymentProof {
            claims: vec![one.claims[0].clone(), other.claims[0].clone()],
            tip: one.tip.clone(),
        });
        for (what, evidence, needle) in [
            ("repeated", repeated, "two claims about one outpoint"),
            ("covered twice", covered_twice, "already covers"),
        ] {
            let mut padded = paid(1);
            padded.payment_proof = Some(evidence);
            padded
                .verify(&owner())
                .unwrap_or_else(|e| panic!("{what}: precondition, it verifies: {e}"));
            let c = complaint_by(&buyer_key(1), padded, FeedbackCategory::NonDelivery, 200);
            let err = c.verify(&owner()).expect_err(what);
            assert!(err.contains(needle), "{what}: {err}");
        }
    }

    /// **Among copies of one buyer statement, the record keeps the freshest
    /// evidence** (review round 3). An older rung of the same payment
    /// verifies too, and may encode smaller; a reader judging a reversal
    /// needs the freshest claim. Either arrival order keeps the fresher
    /// copy. Red if the tie-break goes back to the encoding alone.
    #[test]
    fn the_record_keeps_the_freshest_evidence_for_one_statement() {
        let genuine = complaint(1);
        let mut fresher = genuine.clone();
        fresher.order.payment_proof = Some(proof_as_of(&order(1), 1, 100, 140));
        fresher
            .verify(&owner())
            .expect("a later rung of the same payment");
        // Its proof shows the paid height the buyer signed (review round 4,
        // P3: comparing the cloned field compared a value with itself).
        assert_eq!(
            crate::payment::paid_height(&fresher.order),
            Some(genuine.paid_height),
            "the same statement"
        );
        for (first, second) in [(&genuine, &fresher), (&fresher, &genuine)] {
            let mut state = ReputationStateV1::default();
            state
                .apply_delta(&params(), &Some(vec![first.clone()]))
                .expect("applies");
            state
                .apply_delta(&params(), &Some(vec![second.clone()]))
                .expect("applies");
            assert_eq!(state.complaints, vec![fresher.clone()]);
        }
    }

    /// **A complaint made by the first build that accepts complaints still
    /// verifies** (`docs/complaint-threat-model.md` section 8: the complaint
    /// format is append-only). The fixture is the frozen bytes of a record
    /// holding one genuine complaint, written once by this test with
    /// `HARVEST_WRITE_COMPLAINT_FIXTURE=1` and never regenerated. A later
    /// change that stops these bytes decoding, re-encoding identically, or
    /// verifying would erase every existing complaint at the next re-key,
    /// and the merge-law corpora would not notice, because they are
    /// regenerated. If this goes red, the change is what is wrong.
    #[test]
    fn a_complaint_from_the_first_build_still_verifies() {
        const FIXTURE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/fixtures/reputation-state-complaint-v1.cbor"
        );
        if std::env::var_os("HARVEST_WRITE_COMPLAINT_FIXTURE").is_some() {
            let state = ReputationStateV1 {
                owner_certificate_pem: String::new(),
                complaints: vec![complaint(1)],
            };
            std::fs::write(FIXTURE, crate::to_cbor(&state).expect("encodes")).expect("writes");
        }
        let bytes = std::fs::read(FIXTURE).expect("the frozen fixture is committed");
        let state: ReputationStateV1 = crate::from_cbor(&bytes).expect("still decodes");
        assert_eq!(
            crate::to_cbor(&state).expect("encodes"),
            bytes,
            "still re-encodes to the same bytes"
        );
        state.verify(&params()).expect("still verifies");
        assert_eq!(state.complaints.len(), 1);
    }

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

    /// Re-sign `payload` (already an envelope) with `key`: what a signer who
    /// wanted to smuggle bytes onto the record would publish.
    fn resign(key: &SigningKey, payload: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        use ed25519_dalek::Signer as _;
        let signature = key.sign(&payload).to_bytes().to_vec();
        (payload, signature)
    }

    /// **Nothing the buyer did not sign for rides on a complaint** (review
    /// round 1, P1-3). The envelope decoder skips bytes after the CBOR item
    /// and unknown map keys, so without the exact-envelope check a buyer
    /// could append free text, re-sign, and the complaint verified: a
    /// free-text channel on a permanent record. Red if
    /// `is_exact_harvest_envelope` is dropped from `Complaint::verify`.
    #[test]
    fn a_complaint_envelope_carrying_extra_bytes_is_refused() {
        let genuine = complaint(1);
        let terms = crate::to_cbor(&genuine.terms()).unwrap();

        // One byte after the CBOR item.
        let mut trailing = genuine.scoped_payload.clone();
        trailing.extend_from_slice(b"call me on 555-0100");
        // A map key the decoder skips.
        #[derive(serde::Serialize)]
        struct WithNote {
            requestor: crate::test_orders::TestRequestorForTests,
            payload: Vec<u8>,
            note: String,
        }
        let noted = crate::to_cbor(&WithNote {
            requestor: crate::test_orders::harvest_requestor_for_tests(),
            payload: terms,
            note: "free text".into(),
        })
        .unwrap();

        for (what, envelope) in [("trailing bytes", trailing), ("an extra key", noted)] {
            let (scoped_payload, buyer_signature) = resign(&buyer_key(1), envelope);
            let c = Complaint {
                scoped_payload,
                buyer_signature,
                ..genuine.clone()
            };
            // The loose check alone accepts it: that is the hole.
            crate::listing::verify_scoped_signature(
                &c.scoped_payload,
                &c.buyer_signature,
                &buyer_key(1).verifying_key(),
                &c.terms(),
            )
            .unwrap_or_else(|e| panic!("{what}: precondition, the loose check passes: {e}"));
            let err = c.verify(&owner()).expect_err(what);
            assert!(err.contains("not exactly the envelope"), "{what}: {err}");
        }
    }

    /// **The seller cannot switch the complaint off by re-signing the order**
    /// (review round 2 of #143, R2-1). After payment, the seller re-signs the
    /// same terms in a more compact envelope, or with bytes after it. Either
    /// is a valid store record for the same order id (and the compact one
    /// wins the store's merge, which keeps the smaller encoding), so every
    /// buyer copy taken from the store may be it. The complaint still
    /// verifies. Red if `Complaint::verify` requires the order's envelope to
    /// be exact again, as round 1's fix did.
    #[test]
    fn a_seller_re_signed_order_envelope_still_takes_the_complaint() {
        let genuine = paid(1);
        let compact = crate::test_orders::compact_envelope(&genuine.scoped_payload);
        assert!(
            compact.len() < genuine.scoped_payload.len(),
            "precondition: the compact envelope is smaller, so it wins the store's merge"
        );
        let mut padded = genuine.scoped_payload.clone();
        padded.extend_from_slice(&[0u8; 16]);
        for (what, envelope) in [("compact", compact), ("padded", padded)] {
            let mut order = genuine.clone();
            let (scoped_payload, signature) = resign(&store_key(), envelope);
            order.scoped_payload = scoped_payload;
            order.signature = signature;
            order
                .verify(&owner())
                .unwrap_or_else(|e| panic!("{what}: precondition, a valid store record: {e}"));
            assert_eq!(order.order.id, genuine.order.id, "{what}: the same order");
            complaint_by(&buyer_key(1), order, FeedbackCategory::NonDelivery, 200)
                .verify(&owner())
                .unwrap_or_else(|e| panic!("{what}: the complaint must still verify: {e}"));
        }
    }

    /// **An order the seller padded past the bound takes no complaint, and
    /// one inside it does** (`payment::complaint_preconditions`). The buyer
    /// refuses to pay the first (`PaymentBlocker::UnfitForComplaint`), so no
    /// genuine buyer holds one. Red if the envelope bound is dropped.
    #[test]
    fn an_order_envelope_past_the_bound_takes_no_complaint() {
        use crate::payment::MAX_ORDER_ENVELOPE_BYTES;
        let genuine = paid(1);
        for (len, accepted) in [
            (MAX_ORDER_ENVELOPE_BYTES, true),
            (MAX_ORDER_ENVELOPE_BYTES + 1, false),
        ] {
            let mut envelope = genuine.scoped_payload.clone();
            envelope.resize(len, 0);
            let mut order = genuine.clone();
            let (scoped_payload, signature) = resign(&store_key(), envelope);
            order.scoped_payload = scoped_payload;
            order.signature = signature;
            order
                .verify(&owner())
                .expect("precondition: the store contract accepts it");
            let verdict = complaint_by(&buyer_key(1), order, FeedbackCategory::NonDelivery, 200)
                .verify(&owner());
            if accepted {
                verdict.unwrap_or_else(|e| panic!("{len} bytes is inside the bound: {e}"));
            } else {
                let err = verdict.expect_err("past the bound");
                assert!(err.contains("a complaint may carry"), "{err}");
            }
        }
    }

    /// An order for nothing, or an on-chain order paid at zero
    /// confirmations, does not make "a complaint costs a real payment" true.
    #[test]
    fn a_complaint_about_a_free_or_unconfirmed_order_is_refused() {
        let mut free = order(1);
        free.amount_sats = 0;
        let mut unconfirmed = order(1);
        unconfirmed.required_confirmations = 0;
        let mut distant = order(1);
        distant.required_confirmations = crate::payment::MAX_REQUIRED_CONFIRMATIONS + 1;
        let mut lightning = order(1);
        lightning.payment_hash = Some([5u8; 32]);
        let mut undated = order(1);
        undated.anchor = None;
        let mut unbridged = order(1);
        unbridged.trusted_bridges.clear();
        for (what, o, needle) in [
            ("a zero amount", free, "for nothing"),
            ("zero confirmations", unconfirmed, "before any confirmation"),
            ("too many confirmations", distant, "more than the"),
            ("a Lightning order", lightning, "not an on-chain order"),
            ("no anchor", undated, "anchored to no block"),
            ("no bridge", unbridged, "names no bridge"),
        ] {
            let o = o.with_derived_id();
            let c = complaint_by(
                &buyer_key(1),
                authorized(&store_key(), o, OrderStatus::Paid),
                FeedbackCategory::NonDelivery,
                200,
            );
            let err = c.verify(&owner()).expect_err(what);
            assert!(err.contains(needle), "{what}: {err}");
        }
    }

    /// **The seller cannot choose which of the buyer's statements survives**
    /// (review round 1, P2-9). Two different buyer complaints for one order,
    /// each with several equally valid evidence variants: the survivor is
    /// always the one whose signed TERMS rank lower, whichever evidence is
    /// attached. Red if the tie-break goes back to the whole encoding, where
    /// the evidence (inside the order, encoded first) decides.
    #[test]
    fn the_tie_break_ranks_what_the_buyer_signed_first() {
        let x = complaint_by(&buyer_key(1), paid(1), FeedbackCategory::NonDelivery, 200);
        let y = complaint_by(&buyer_key(1), paid(1), FeedbackCategory::Counterfeit, 300);
        let variants = |c: &Complaint| -> Vec<Complaint> {
            (1u8..=6)
                .map(|seed| {
                    let mut v = c.clone();
                    v.order.payment_proof = Some(proof(&order(1), seed));
                    v.verify(&owner()).expect("valid evidence variant");
                    v
                })
                .collect()
        };
        // The buyer's statement dated nearer the payment, and among equal
        // distances the smaller terms (R5-C put the distance first).
        let lower_terms = std::cmp::min(
            (
                x.distance_from_payment(),
                crate::to_cbor(&x.terms()).unwrap(),
            ),
            (
                y.distance_from_payment(),
                crate::to_cbor(&y.terms()).unwrap(),
            ),
        )
        .1;
        for a in variants(&x) {
            for b in variants(&y) {
                for (first, second) in [(&a, &b), (&b, &a)] {
                    let mut state = ReputationStateV1::default();
                    state
                        .apply_delta(&params(), &Some(vec![first.clone()]))
                        .unwrap();
                    state
                        .apply_delta(&params(), &Some(vec![second.clone()]))
                        .unwrap();
                    assert_eq!(
                        crate::to_cbor(&state.complaints[0].terms()).unwrap(),
                        lower_terms,
                        "the evidence attached must not decide between two buyer statements"
                    );
                }
            }
        }
    }

    /// Order `n`'s genuine complaint, dated `after` blocks after its payment.
    fn dated(n: u8, after: u32) -> Complaint {
        let paid_at = crate::payment::paid_height(&paid(n)).expect("the fixture is paid");
        complaint_by(
            &buyer_key(n),
            paid(n),
            FeedbackCategory::NonDelivery,
            paid_at + after,
        )
    }

    /// **A full record drops the latest-dated complaints first, and never an
    /// honest one for a later one** (review round 5 of #143, R5-C). A seller
    /// fills its record past the cap with late complaints about its own
    /// orders; the buyers' complaints, dated nearer their payments, all stay,
    /// whichever arrives first and however the deltas are split. Red if the
    /// cap is dropped (the record grows past it), or if it keeps anything
    /// but the nearest (`truncate` over the order-id order keeps the
    /// seller's instead: their orders are numbered first here).
    #[test]
    fn a_full_record_drops_the_latest_dated_first() {
        const CAP: usize = 4;
        let seller_late: Vec<Complaint> =
            (1u8..=5).map(|n| dated(n, 5_000 + u32::from(n))).collect();
        let honest: Vec<Complaint> = (11u8..=13).map(|n| dated(n, 150 + u32::from(n))).collect();
        let apply = |state: &mut ReputationStateV1, complaints: Vec<Complaint>| {
            state
                .apply_delta_capped(&params(), &Some(complaints), CAP)
                .expect("genuine complaints apply");
        };
        let orders = |state: &ReputationStateV1| -> BTreeSet<OrderId> {
            state
                .complaints
                .iter()
                .map(|c| c.order_id().clone())
                .collect()
        };
        let mut want: BTreeSet<OrderId> = honest.iter().map(|c| c.order_id().clone()).collect();
        // The nearest of the seller's, which fills the one slot left.
        want.insert(seller_late[0].order_id().clone());
        // Order ids are hashes: check the order-id order would keep a
        // different set, so keeping the nearest is what this test sees.
        let by_id: BTreeSet<OrderId> = seller_late
            .iter()
            .chain(&honest)
            .map(|c| c.order_id().clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(CAP)
            .collect();
        assert_ne!(
            by_id, want,
            "precondition: the order-id order keeps another set"
        );

        let mut flood_first = ReputationStateV1::default();
        apply(&mut flood_first, seller_late.clone());
        assert_eq!(flood_first.complaints.len(), CAP, "the cap binds");
        apply(&mut flood_first, honest.clone());

        let mut honest_first = ReputationStateV1::default();
        apply(&mut honest_first, honest.clone());
        for one in seller_late.iter().rev() {
            apply(&mut honest_first, vec![one.clone()]);
        }

        let mut together = ReputationStateV1::default();
        apply(&mut together, [seller_late, honest].concat());

        for (what, state) in [
            ("flood first", &flood_first),
            ("honest first, flood one at a time", &honest_first),
            ("one delta", &together),
        ] {
            assert_eq!(orders(state), want, "{what}");
            state.verify(&params()).expect("canonical");
        }
        assert_eq!(
            crate::to_cbor(&flood_first).unwrap(),
            crate::to_cbor(&honest_first).unwrap()
        );
        assert_eq!(
            crate::to_cbor(&flood_first).unwrap(),
            crate::to_cbor(&together).unwrap()
        );
    }

    /// **A complaint dated before its payment does not outrank one dated
    /// nearer it after** (R5-C, [`Complaint::distance_from_payment`]). No
    /// honest complaint is dated before its payment, so a reader could one
    /// day stop counting those; ranked as "not late at all" they would then
    /// be a flood that pushes out honest complaints. Red if the distance
    /// becomes a saturating difference.
    #[test]
    fn a_complaint_dated_before_its_payment_does_not_outrank_a_nearer_one() {
        let paid_at = crate::payment::paid_height(&paid(2)).expect("paid");
        let early = complaint_by(&buyer_key(1), paid(1), FeedbackCategory::NonDelivery, 0);
        early
            .verify(&owner())
            .expect("it verifies: the contract reads no clock");
        assert!(
            paid_at > 50,
            "precondition: room to date one 50 blocks nearer"
        );
        let honest = dated(2, paid_at - 50);
        assert!(early.distance_from_payment() > honest.distance_from_payment());
        let mut state = ReputationStateV1::default();
        state
            .apply_delta_capped(&params(), &Some(vec![early, honest.clone()]), 1)
            .expect("applies");
        assert_eq!(state.complaints, vec![honest]);
    }

    /// **A complaint past `MAX_COMPLAINT_BYTES` is refused, whatever makes it
    /// big** (review round 6). The proof's tip is a byte string only its
    /// bridge signs, and an order may name a bridge the seller runs: padded,
    /// it still verifies, and without the bound one such complaint could fill
    /// the record under the count cap. Red if `Complaint::verify` stops
    /// bounding the whole complaint.
    #[test]
    fn a_complaint_padded_past_the_byte_bound_is_refused() {
        use crate::payment::OrderPaymentProof;
        use ed25519_dalek::Signer as _;
        let mut order = paid(1);
        let Some(OrderPaymentProof::OnChain(proof)) = order.payment_proof.as_mut() else {
            panic!("on chain");
        };
        proof.tip.body_cbor.resize(MAX_COMPLAINT_BYTES, 0);
        let mut signed = b"freenet-bitcoin/tip/v1\0".to_vec();
        signed.extend_from_slice(&proof.tip.body_cbor);
        proof.tip.signature = crate::test_orders::bridge_key()
            .sign(&signed)
            .to_bytes()
            .to_vec();
        order
            .verify(&owner())
            .expect("precondition: the padded tip still verifies");
        let c = complaint_by(&buyer_key(1), order, FeedbackCategory::NonDelivery, 200);
        let err = c.verify(&owner()).expect_err("past the byte bound");
        assert!(err.contains("and this one is"), "{err}");
    }

    /// **The real cap binds, and a record over it is refused** (R5-C). One
    /// more complaint than `MAX_COMPLAINTS`: the merge keeps
    /// `MAX_COMPLAINTS`, dropping the one dated farthest from its payment,
    /// and `verify` (the contract's `validate_state`) refuses the state that
    /// holds them all. Red if either check is removed.
    #[test]
    fn a_record_holds_at_most_max_complaints() {
        // A flood's bound, not an honest one; and the fixture numbers orders
        // with a `u8`.
        const _: () = assert!(MAX_COMPLAINTS >= 100 && MAX_COMPLAINTS < u8::MAX as usize);
        let all: Vec<Complaint> = (1u8..=(MAX_COMPLAINTS as u8 + 1))
            .map(|n| dated(n, 100 + u32::from(n)))
            .collect();
        let farthest = all.last().expect("some").order_id().clone();
        let mut state = ReputationStateV1::default();
        state
            .apply_delta(&params(), &Some(all.clone()))
            .expect("applies");
        assert_eq!(state.complaints.len(), MAX_COMPLAINTS);
        assert!(state.complaints.iter().all(|c| c.order_id() != &farthest));
        state
            .verify(&params())
            .expect("a full record is valid state (`>` not `>=` in `verify`)");

        let mut over = state.clone();
        over.complaints = all;
        over.complaints
            .sort_by(|a, b| a.order_id().cmp(b.order_id()));
        let err = over.verify(&params()).expect_err("over the cap");
        assert!(err.contains("at most"), "{err}");
    }

    /// **At the cap, the merge still obeys the merge laws, byte for byte**
    /// (R5-C). Seeded random states over a pool where the cap binds, with
    /// orders holding two buyer statements: one dated near the payment whose
    /// terms encode LARGER, one dated far whose terms encode smaller. Red if
    /// the per-order tie-break stops ranking by distance first: a merge that
    /// drops an order's near statement for its far one can then drop the
    /// order altogether, and which of its statements arrived first decides
    /// the result.
    #[test]
    fn at_the_cap_the_merge_obeys_the_merge_laws() {
        use crate::merge_laws::{assert_laws, Rng};
        const CAP: usize = 3;
        let mut pool: Vec<Complaint> = (1u8..=6).map(|n| dated(n, 100 * u32::from(n))).collect();
        for n in [2u8, 4] {
            // Far, and `Counterfeit` against `NonDelivery`: find a pair whose
            // terms order is the opposite of their distance order.
            let far = complaint_by(
                &buyer_key(n),
                paid(n),
                FeedbackCategory::Counterfeit,
                crate::payment::paid_height(&paid(n)).unwrap() + 9_000,
            );
            let near = pool
                .iter()
                .find(|c| c.order_id() == far.order_id())
                .expect("in the pool");
            assert!(
                crate::to_cbor(&far.terms()).unwrap() < crate::to_cbor(&near.terms()).unwrap(),
                "precondition: the far statement's terms encode smaller, so only the distance \
                 ranks the near one first"
            );
            pool.push(far);
        }
        let mut rng = Rng::new(0x5eed_0c5c);
        let states: Vec<ReputationStateV1> = (0..80)
            .map(|_| {
                let mut s = ReputationStateV1::default();
                s.apply_delta_capped(&params(), &Some(rng.subset(&pool, 5)), CAP)
                    .expect("apply");
                s
            })
            .collect();
        let merge = |a: &ReputationStateV1, b: &ReputationStateV1| {
            let mut out = a.clone();
            out.apply_delta_capped(&params(), &Some(b.complaints.clone()), CAP)
                .expect("merge");
            out
        };
        let enc = |s: &ReputationStateV1| crate::to_cbor(s).expect("encode");
        assert_laws(&states, 100, &mut rng, merge, enc);
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
