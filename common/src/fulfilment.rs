//! The fulfilment axis of an order: what the seller says they have done
//! after the payment (harvest#53 Phase B).
//!
//! # A second axis, not more statuses
//!
//! [`crate::payment::OrderStatus`] is payment truth, evidenced by Bitcoin, and
//! its rank is a permanent maximum under merge. A seller-signed status placed
//! in that lattice could bury a genuine reorg under the seller's own
//! assertion, which is why `Fulfilled` was deleted from it. So a despatch is a
//! separate record, in its own part of the store, keyed by the order id and
//! explicitly outside the status lattice: nothing here can change what an
//! order's payment says.
//!
//! # What the contract checks, and what it deliberately does not
//!
//! The contract checks only that the store key signed the despatch. It does
//! NOT require the order to be `Paid`: that is a rule across two records, and
//! a record whose validity depended on another record's status would be valid
//! on one replica and invalid on another until both had merged, which is how
//! replicas stop converging. Readers ignore a despatch on an order that is not
//! paid (the UI's `fulfilment::order_stage`). The one cross-record rule the
//! store does keep is structural and convergent -- a despatch is kept only
//! while its order is -- see `StoreStateV1::normalize_fulfilment`.
//!
//! # Why the anchor, and what it cannot prove
//!
//! A contract has no clock, so a despatch says WHEN only by naming a recent
//! Bitcoin block: signed no earlier than that block. That is a lower bound
//! only. Every past block hash is public, so a seller can anchor a late
//! despatch to an early block. Readers therefore never let a despatch shorten
//! the buyer's complaint window (see the UI's `fulfilment` module): the
//! window runs from the later of the despatch deadline and the despatch's own
//! anchor.
//!
//! # What is deliberately absent
//!
//! A buyer-signed "received" record. Decided on harvest#53 (section 7,
//! decision 3): silence is success and writes nothing, so no buyer can strand
//! a seller by never clicking, and nothing can be forgotten.

use ed25519_dalek::VerifyingKey;
use freenet_bitcoin_common::BlockAnchor;
use serde::{Deserialize, Serialize};

use crate::listing::verify_scoped_signature;
use crate::payment::OrderId;
use crate::store::Bytes32;

/// The seller's statement that an order's goods have been sent.
///
/// Signed by the store key, as every record the store makes is. Carries no
/// free text (no tracking number, no note): it is permanent, public and
/// unmoderatable, and anything the buyer needs to know about the parcel goes
/// in the encrypted conversation.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Despatch {
    pub order_id: OrderId,
    /// A recent Bitcoin block: the despatch was signed no earlier than it.
    /// See the module docs for what that can and cannot prove.
    pub anchor: BlockAnchor,
}

/// A [`Despatch`] signed by the store key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedDespatch {
    pub despatch: Despatch,
    /// CBOR `ScopedPayload` over `despatch`, as the store key signs it
    /// (`backing::store_key_envelope`).
    pub scoped_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AuthorizedDespatch {
    /// Whether `owner`, the store's key, signed this despatch.
    pub fn verify(&self, owner: &VerifyingKey) -> Result<(), String> {
        verify_scoped_signature(&self.scoped_payload, &self.signature, owner, &self.despatch)
            .map_err(|e| format!("despatch is not signed by the store key: {e}"))
    }
}

impl crate::backing::SignedRecord for AuthorizedDespatch {
    /// One despatch per order. A seller who signs two for one order (with
    /// different anchors) does not choose which is kept: the smaller encoding
    /// is, as for every signed set (`backing::SignedSetV1`).
    fn slot(&self) -> Bytes32 {
        Bytes32(self.despatch.order_id.0)
    }
    fn verify_for(&self, owner: &VerifyingKey) -> Result<(), String> {
        self.verify(owner)
    }
    const WHAT: &'static str = "despatch";
}

/// Every despatch a store holds, one per order it still holds.
///
/// Bounded by the store's own order cap: a despatch is kept only while its
/// order is (`StoreStateV1::normalize_fulfilment`), so there are never more
/// than `store::MAX_ORDERS`.
pub type FulfilmentV1 = crate::backing::SignedSetV1<AuthorizedDespatch>;
