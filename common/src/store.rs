use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use freenet_scaffold_macro::composable;
use serde::{Deserialize, Serialize};

use crate::listing::{verify_scoped_signature, AuthorizedListing, ListingId};
use crate::payment::{AuthorizedOrder, OrderId, OrderStatus};

/// Immutable parameters for a store contract, set at creation time.
///
/// # Why there is only one field
///
/// Parameters are hashed into the contract's address, so anything here is
/// frozen for the store's entire life. The seller's key genuinely is the
/// store's identity, so freezing it is correct.
///
/// The Bitcoin trust configuration used to live here too --
/// `trusted_bitcoin_bridges` and `bitcoin_address_code_hash` -- and being
/// frozen was fatal to it: every store the UI creates was published with an
/// empty bridge list, which made it permanently incapable of accepting an
/// on-chain payment, and a bridge that went away could never be replaced.
/// Both fields now live on [`crate::payment::Order`], where the seller's
/// signature on the invoice authenticates them and each new order may name a
/// new set. See that struct's `trusted_bridges` for the full argument,
/// including why moving them to mutable *state* would have been worse.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreParameters {
    /// The seller's Ed25519 verifying key (from their ghostkey certificate).
    ///
    /// `pub(crate)` on purpose -- see [`StoreParameters::new`].
    pub(crate) seller_verifying_key: VerifyingKey,
}

impl StoreParameters {
    /// The only way to build these parameters from outside `harvest-common`.
    ///
    /// # Why the fields are not public
    ///
    /// A contract's address is `BLAKE3(code_hash || cbor(parameters))`, so the
    /// FIELD SET of this struct is a network address. Two places building it
    /// by hand can disagree about that field set, and when they do, the PUT
    /// and the migration probe address different contracts -- silently, in the
    /// direction that reports a clean "nothing to migrate" over a seller's
    /// entire store.
    ///
    /// That is not hypothetical. `StoreParameters` gained two Bitcoin fields
    /// and lost them again; the probe went on deriving V1, the only generation
    /// ever published, at an address it never had. Removing the duplicate
    /// constructions fixed the instance. A source-scrape test was written to
    /// stop them coming back and was beaten by a type alias, which is an
    /// ordinary refactor rather than an exotic evasion.
    ///
    /// Private fields are what actually holds it: a second derivation outside
    /// this crate does not compile. Adding a field changes this signature, so
    /// the decision is made once, here, rather than in every place that
    /// happens to construct one.
    pub fn new(seller_verifying_key: VerifyingKey) -> Self {
        Self {
            seller_verifying_key,
        }
    }
}

/// Information about the store owner. Single-value, version-bumped on update.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreInfoV1 {
    /// Monotonically increasing version number for last-writer-wins.
    pub version: u32,
    /// Seller's ghostkey certificate PEM (for buyers to verify the trust chain).
    pub certificate_pem: String,
    /// Seller's ghostkey fingerprint (BLAKE3 of verifying key, bs58-encoded).
    pub seller_fingerprint: String,
    /// The seller's reputation contract ID bytes.
    pub reputation_contract_id: [u8; 32],
    /// Human-readable store name.
    pub store_name: String,
    /// Optional store description.
    pub description: String,
    /// Payment instructions (freeform, e.g. "BTC: bc1q...").
    pub payment_instructions: String,
    /// The seller's long-term X25519 public key, so a buyer has something to
    /// encrypt a message to.
    ///
    /// `None` for every store published before this field existed, and for a
    /// seller whose delegate has not minted one yet. A buyer reading `None`
    /// cannot message this seller at all, and
    /// [`crate::mailbox`] has no other route to a conversation key -- the
    /// mailbox contract is open-write and carries no key exchange of its own.
    ///
    /// The private half never leaves the seller's harvest delegate, which
    /// holds it under `harvest:x25519_sk:{fingerprint}` and answers only the
    /// derived conversation key.
    ///
    /// # `skip_serializing_if` is load-bearing, not a size optimisation
    ///
    /// [`AuthorizedStoreInfoV1::verify`] does not compare stored bytes: it
    /// re-serializes this struct and checks the result against the payload
    /// inside the signed `ScopedPayload`. A field that serializes when absent
    /// therefore changes the preimage of every signature taken before it
    /// existed, and the store contract rejects the seller's own published
    /// details with "store info signature invalid". Pinned by
    /// `wire_compat_tests::a_store_info_that_predates_the_encryption_key_re_encodes_unchanged`,
    /// which was observed red against the naive `#[serde(default)]`-only
    /// form.
    ///
    /// `serde(default)` is belt-and-braces rather than the thing that makes
    /// old bytes decode: serde's `missing_field` already answers `None` for an
    /// `Option` field carrying no default attribute, which was checked rather
    /// than assumed. What the decode test actually catches is a future field
    /// of a NON-optional type added without a default -- mutated red that way
    /// on 2026-09-05, `missing field `encryption_public_key``.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_public_key: Option<[u8; 32]>,
}

/// Store info signed by the seller's ghostkey via the ghostkey delegate.
///
/// Uses the ScopedPayload format from the ghostkey delegate's SignResult:
/// the signature is over the CBOR-encoded ScopedPayload which wraps the
/// CBOR-encoded StoreInfoV1 as its payload.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedStoreInfoV1 {
    pub info: StoreInfoV1,
    /// CBOR-serialized ScopedPayload from the ghostkey delegate's SignResult.
    pub scoped_payload: Vec<u8>,
    /// Ed25519 signature over the scoped_payload bytes.
    pub signature: Vec<u8>,
}

impl Default for AuthorizedStoreInfoV1 {
    fn default() -> Self {
        Self {
            info: StoreInfoV1 {
                version: 0,
                certificate_pem: String::new(),
                seller_fingerprint: String::new(),
                reputation_contract_id: [0u8; 32],
                store_name: String::new(),
                description: String::new(),
                payment_instructions: String::new(),
                encryption_public_key: None,
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
        }
    }
}

impl freenet_scaffold::ComposableState for AuthorizedStoreInfoV1 {
    type ParentState = StoreStateV1;
    type Summary = u32; // version number
    type Delta = AuthorizedStoreInfoV1; // full replacement
    type Parameters = StoreParameters;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        // Version 0 is the default (empty/uninitialized) state -- skip verification
        if self.info.version == 0 {
            return Ok(());
        }
        verify_scoped_signature(
            &self.scoped_payload,
            &self.signature,
            &parameters.seller_verifying_key,
            &self.info,
        )
        .map_err(|e| format!("store info signature invalid: {e}"))
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.info.version
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        if self.info.version > *old_state_summary {
            Some(self.clone())
        } else {
            None
        }
    }

    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(new_info) = delta {
            if new_info.info.version <= self.info.version {
                return Ok(()); // stale update, ignore
            }
            verify_scoped_signature(
                &new_info.scoped_payload,
                &new_info.signature,
                &parameters.seller_verifying_key,
                &new_info.info,
            )
            .map_err(|e| format!("store info delta signature invalid: {e}"))?;
            *self = new_info.clone();
        }
        Ok(())
    }
}

/// The set of listings in a store.
///
/// **Grow-only, with no removal path at all** -- not "grow-only with removal
/// by signed deletion", which this said until it was checked and which
/// describes a mechanism that has never existed. `apply_delta` only ever
/// pushes; nothing anywhere removes a listing.
///
/// That is load-bearing rather than incidental. `ui/src/migrate.rs`'s
/// `fold_all_policy` selects `FoldAll`, which resurrects anything deleted by
/// mere absence, and its soundness argument for this state is precisely that
/// absence is never a deletion. Adding a removal path here without a
/// tombstone would make folding an older generation silently reinstate every
/// listing the seller had removed.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct ListingsV1 {
    pub listings: Vec<AuthorizedListing>,
}

impl freenet_scaffold::ComposableState for ListingsV1 {
    type ParentState = StoreStateV1;
    type Summary = Vec<ListingId>;
    type Delta = Vec<AuthorizedListing>;
    type Parameters = StoreParameters;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        for authorized in &self.listings {
            authorized.verify(&parameters.seller_verifying_key)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.listings.iter().map(|l| l.listing.id.clone()).collect()
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let new_listings: Vec<_> = self
            .listings
            .iter()
            .filter(|l| !old_state_summary.contains(&l.listing.id))
            .cloned()
            .collect();
        if new_listings.is_empty() {
            None
        } else {
            Some(new_listings)
        }
    }

    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(new_listings) = delta {
            let mut known_ids: std::collections::HashSet<ListingId> =
                self.listings.iter().map(|l| l.listing.id.clone()).collect();

            // Collect first, push after. Verifying and pushing in one pass
            // left a delta of [valid, invalid] with the valid listing already
            // in `self` when the error returned -- see `OrdersV1::apply_delta`
            // for the same defect and why the call site's habit of discarding
            // the state on error is not a substitute for this.
            let mut to_add = Vec::new();
            for listing in new_listings {
                // `insert` is false for a listing already held -- including
                // one added by an EARLIER entry of this same delta, which the
                // snapshot this used to take before the loop could not see, so
                // a delta naming one listing twice stored it twice. `listings`
                // is a plain `Vec` with no uniqueness invariant of its own, so
                // that duplicate then survived every later merge and sort.
                if !known_ids.insert(listing.listing.id.clone()) {
                    continue; // already have this listing
                }
                listing.verify(&parameters.seller_verifying_key)?;
                to_add.push(listing.clone());
            }
            self.listings.extend(to_add);

            // Sort deterministically for CRDT convergence
            self.listings
                .sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        }
        Ok(())
    }
}

/// How many orders one store contract will hold.
///
/// Unlike listings, orders carry payment evidence: a `Paid` order embeds an
/// [`crate::payment::OrderPaymentProof`], which is itself a set of bridge-signed
/// claims plus a signed chain tip -- easily hundreds of bytes to a few KB per
/// order. Without a cap a popular store's state (and, worse, its per-heartbeat
/// summary -- see `OrdersV1`'s `Summary`) would grow without bound. On
/// overflow the least-relevant orders are dropped first: see
/// `enforce_order_cap`.
pub const MAX_ORDERS: usize = 4096;

/// Small state-change fingerprint for one order, used only to let
/// [`OrdersV1::delta`] detect a same-rank content change (see that impl's
/// doc comment for why one can happen). This is deliberately NOT the
/// tie-break comparator used to decide which of two same-rank records wins
/// a merge -- that comparison is over the full CBOR bytes, in
/// `merge_order` -- it only has to be cheap enough to carry in every
/// summary entry and to change whenever the record's bytes do.
fn order_content_digest(record: &AuthorizedOrder) -> [u8; 8] {
    // Infallible: `AuthorizedOrder` and everything it contains derives
    // `Serialize` over plain data (no custom fallible encoding), so CBOR
    // serialization of an in-memory value here cannot fail.
    let bytes = crate::to_cbor(record).expect("AuthorizedOrder always serializes to CBOR");
    let hash = blake3::hash(&bytes);
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash.as_bytes()[..8]);
    out
}

/// Merge one already-verified incoming order record into `orders`.
///
/// Keeps whichever of the existing and incoming record has the higher
/// [`OrderStatus::rank`]. On an exact rank tie -- which happens when two
/// peers each independently assemble a different, but individually valid,
/// proof for the same transition (e.g. two different sets of bridge claims
/// that both establish `Paid`) -- the tie is broken by comparing the CBOR
/// bytes of the two records and keeping the **smaller**. Comparing bytes
/// rather than, say, "whichever arrived first" is what makes the choice a
/// pure function of content: every replica that ends up holding both
/// candidate records picks the same winner, regardless of which one it
/// received first or via which peer.
///
/// # Why the smaller encoding, not the greater
///
/// A `Paid` transition is authorized by evidence, not by a signature over
/// the status, so any third party who can read the store can take a genuine
/// record, leave the seller's signature and the status exactly as they are,
/// staple additional VALID claims onto the payment proof and resubmit it.
/// A `Claim::ScannedTo` names no outpoint, so it changes no verdict at all
/// and is published publicly by every bridge; a handful of them is free to
/// obtain and adds hundreds of bytes.
///
/// While the greater encoding won, that resubmission was permanent -- merge
/// is a monotonic maximum, so the compact honest record could never win the
/// order back on any replica -- and repeatable, up to
/// [`crate::payment::MAX_PROOF_CLAIM_BYTES`] (256 KiB) for every order in the
/// store, re-verified on every state validation.
///
/// Preferring the smaller encoding removes the reward. It is exactly as total,
/// deterministic and content-derived as the old rule, so convergence is
/// unaffected.
///
/// # Why there is no converse attack, and what it rests on
///
/// Every record reaching this function has already passed
/// [`crate::payment::AuthorizedOrder::verify`], which pins every field a
/// third party could otherwise vary at an equal rank:
///
/// * `order`, `scoped_payload` and `signature` by `verify_terms`;
/// * `status_scoped_payload` / `status_signature` -- required and checked for
///   `Cancelled`, and required to be ABSENT for every other status;
/// * `payment_proof` -- required to verify for `Paid` / `PaymentReversed`, and
///   required to be ABSENT for the others.
///
/// That leaves `payment_proof` on an evidence-backed status as the only thing
/// an attacker may choose, and any value they choose still had to satisfy
/// `verify`. So a smaller record is not a weaker one: it establishes the same
/// status by the same rules, and the only thing an attacker gains is making
/// the state cheaper, bounded below by the smallest encoding that verifies.
///
/// **The absence requirements are load-bearing here, not hygiene.** They were
/// added because of this tie-break. `verify` used to ignore the fields a
/// status does not use, and in CBOR `None` is `0xf6` while every `Some(..)`
/// begins with an array header of `0x80..=0x9b` -- so `Some(anything)` sorts
/// BELOW `None`. A third party could set `status_scoped_payload: Some(vec![])`
/// on a genuine `Paid` record, change nothing else, and permanently own the
/// copy every replica keeps. Smaller-wins turned an ignored field into the
/// winning move.
///
/// "Every field" above is a claim about the struct as it is TODAY, and it is
/// held by the compiler rather than by this comment:
/// `verify_unused_fields_absent` destructures `AuthorizedOrder` without `..`,
/// so a new optional field does not compile until somebody has said which
/// statuses consult it, and `fields_used` is an exhaustive match, so a new
/// status does not compile until somebody has said which fields it uses. Both
/// halves are needed: this paragraph was field-complete prose over
/// status-complete enforcement until 2026-09-05, which meant the next field
/// added would have silently reopened the attack. See
/// `crate::payment::AuthorizedOrder::verify_unused_fields_absent` and
/// `order_tests::a_field_the_status_does_not_use_is_rejected`.
///
/// A digest over the order TERMS was considered instead and rejected: two
/// records for one order id normally carry identical terms, so it ties, and
/// the winner would fall back to arrival order -- which is the divergence the
/// tie-break exists to prevent.
///
/// This is a `max` over the total order `(rank, Reverse(cbor_bytes))`, so it
/// is associative, commutative and idempotent -- the three properties the
/// merge tests in this module pin directly on serialized bytes.
fn merge_order(orders: &mut BTreeMap<OrderId, AuthorizedOrder>, incoming: AuthorizedOrder) {
    let id = incoming.order.id.clone();
    let Some(existing) = orders.get(&id) else {
        orders.insert(id, incoming);
        return;
    };
    match incoming.status.rank().cmp(&existing.status.rank()) {
        std::cmp::Ordering::Greater => {
            orders.insert(id, incoming);
        }
        std::cmp::Ordering::Less => {
            // Stale: we already hold a later transition for this order.
        }
        std::cmp::Ordering::Equal => {
            let existing_bytes =
                crate::to_cbor(existing).expect("AuthorizedOrder always serializes to CBOR");
            let incoming_bytes =
                crate::to_cbor(&incoming).expect("AuthorizedOrder always serializes to CBOR");
            if incoming_bytes < existing_bytes {
                orders.insert(id, incoming);
            }
        }
    }
}

/// Drop the least-relevant orders if `orders` is over [`MAX_ORDERS`].
///
/// Priority for keeping an order is, from least to most important: first,
/// whether its status is terminal (`Cancelled`, `PaymentReversed` --
/// nothing further will ever happen to it); second,
/// how old it is (`Order::created_at`); third, its id, purely as a
/// tie-breaker so the ordering is total. Terminal orders are dropped before
/// any order still awaiting resolution, and within a tier the oldest goes
/// first.
///
/// This ranking is a pure function of the *content* of `orders`, not of the
/// sequence in which entries were inserted, so two replicas that converge
/// to the same set of orders always prune to the same subset -- which is
/// exactly what the associated test checks.
fn enforce_order_cap(orders: &mut BTreeMap<OrderId, AuthorizedOrder>) {
    if orders.len() <= MAX_ORDERS {
        return;
    }
    let mut ranked: Vec<(bool, i64, OrderId)> = orders
        .iter()
        .map(|(id, record)| {
            let terminal = matches!(
                record.status,
                OrderStatus::Cancelled | OrderStatus::PaymentReversed
            );
            // `!terminal` sorts terminal orders (false) ahead of active ones
            // (true), so they are the first candidates dropped below.
            (
                !terminal,
                record.order.created_at.timestamp_millis(),
                id.clone(),
            )
        })
        .collect();
    ranked.sort();
    let excess = orders.len() - MAX_ORDERS;
    for (_, _, id) in ranked.into_iter().take(excess) {
        orders.remove(&id);
    }
}

/// The set of orders placed against this store, keyed by [`OrderId`].
///
/// # Merge model
///
/// This is neither grow-only (like a claim set) nor last-writer-wins by an
/// explicit version counter (like [`AuthorizedStoreInfoV1`]). It is a
/// **per-key monotonic maximum on [`OrderStatus::rank`]**, the same shape as
/// `freenet_bitcoin_common::address_state::ClaimSetV1`'s per-bridge scan
/// watermark: merging two versions of the same order keeps whichever has
/// the higher rank. A maximum over a total order is always associative,
/// commutative and idempotent, which is what makes it safe to merge two
/// replicas' order sets in any order and reach the same result -- see
/// `merge_order` for the same-rank tie-break this needs on top.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct OrdersV1 {
    pub orders: BTreeMap<OrderId, AuthorizedOrder>,
}

impl freenet_scaffold::ComposableState for OrdersV1 {
    type ParentState = StoreStateV1;
    /// One `(id, status rank, content digest)` triple per order, capped at
    /// [`MAX_ORDERS`] entries.
    ///
    /// This does not use a fixed-size bucket digest the way
    /// `freenet_bitcoin_common::digest::BucketDigest` does for claim sets,
    /// because that trades away precision this state actually needs: a
    /// bucket digest can only say "something in this bucket changed", which
    /// is fine for a grow-only set (re-sending the whole bucket is a cheap
    /// no-op), but `OrdersV1` mutates a specific order's status in place, and
    /// a buyer's payment confirming needs to propagate as *that one order*,
    /// not as a resend of every order that happens to hash into the same
    /// bucket. Instead this is bounded the way `MAX_CLAIMS` bounds
    /// `ClaimSetV1`: capped at a fixed number of entries rather than a fixed
    /// number of bytes. At 25 bytes an entry (16-byte id, 1-byte rank,
    /// 8-byte digest) this is still tiny next to a single order's own
    /// encoded size once it carries an `OrderPaymentProof` -- an order can
    /// run into the hundreds of bytes to multiple KB; a summary entry never
    /// does.
    type Summary = Vec<(OrderId, u8, [u8; 8])>;
    /// Full replacement records for whichever orders are new, ahead in rank,
    /// or -- at an exact rank tie -- differ in content (see `delta`).
    type Delta = Vec<AuthorizedOrder>;
    type Parameters = StoreParameters;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        if self.orders.len() > MAX_ORDERS {
            return Err(format!(
                "order set holds {} entries, cap is {MAX_ORDERS}",
                self.orders.len()
            ));
        }
        for (id, record) in &self.orders {
            if record.order.id != *id {
                return Err("order filed under a key that is not its own id".to_string());
            }
            record
                .verify(&parameters.seller_verifying_key)
                .map_err(|e| format!("order {id} invalid: {e}"))?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.orders
            .iter()
            .map(|(id, record)| {
                (
                    id.clone(),
                    record.status.rank(),
                    order_content_digest(record),
                )
            })
            .collect()
    }

    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let old: BTreeMap<&OrderId, (u8, [u8; 8])> = old_state_summary
            .iter()
            .map(|(id, rank, digest)| (id, (*rank, *digest)))
            .collect();

        // Send an order whenever the requester's summary can't already
        // account for it: it's missing outright, it's behind in rank, or --
        // at an equal rank -- its content digest differs. That last case is
        // what keeps two peers from disagreeing forever about which of two
        // equally-ranked, independently-assembled records is current: see
        // `OrdersV1`'s doc comment. Sending in that case is always safe even
        // when our own record would in fact lose `merge_order`'s tie-break,
        // because the receiver re-runs that same tie-break on the full
        // bytes and simply keeps what it already had.
        let changed: Vec<AuthorizedOrder> = self
            .orders
            .iter()
            .filter(|(id, record)| {
                let our_rank = record.status.rank();
                match old.get(id) {
                    None => true,
                    Some((their_rank, their_digest)) => {
                        our_rank > *their_rank
                            || (our_rank == *their_rank
                                && order_content_digest(record) != *their_digest)
                    }
                }
            })
            .map(|(_, record)| record.clone())
            .collect();

        if changed.is_empty() {
            None
        } else {
            Some(changed)
        }
    }

    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(incoming) = delta else {
            return Ok(());
        };
        // Verify the WHOLE delta before merging any of it. Verifying and
        // merging in one pass left a delta of [valid, invalid] with the valid
        // record already folded into `self` when the error returned, so a
        // caller that kept the state it passed in would silently take on
        // records from a delta it had been told to reject. The contract's
        // `update_state` happens to discard the mutated value on error, but
        // that is a property of that call site, not of this function.
        for record in incoming {
            record
                .verify(&parameters.seller_verifying_key)
                .map_err(|e| format!("order {} delta invalid: {e}", record.order.id))?;
        }
        for record in incoming {
            merge_order(&mut self.orders, record.clone());
        }
        enforce_order_cap(&mut self.orders);
        Ok(())
    }
}

/// Top-level composable store state.
#[composable]
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct StoreStateV1 {
    pub info: AuthorizedStoreInfoV1,
    pub listings: ListingsV1,
    /// `#[serde(default)]` so store states written before orders existed
    /// still decode; they come back with no orders, which is what they had.
    ///
    /// Not optional: V1 (`legacy/store_contract.toml`, code hash
    /// `4d7ad3c3...`) is the only generation ever deployed, and its state has
    /// no `orders` key at all. `OrdersV1` derives `Default`, but serde does
    /// not consult `Default` for a missing field without this attribute and
    /// `#[composable]` does not add one -- so without it every real V1 state
    /// fails to decode with "missing field `orders`", and the migration probe
    /// cannot tell that from an address that was never written.
    #[serde(default)]
    pub orders: OrdersV1,
}

#[cfg(test)]
mod order_tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::{
        spv::testing::payment_proof, BitcoinNetwork, BlockAnchor, BlockHash, BridgeId, Claim,
        ClaimBody, OutPoint, SignedClaim, SignedTipEntry, TipEntryBody,
    };

    use crate::payment::{Order, OrderPaymentProof};

    fn seller_key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[22u8; 32])
    }

    /// A second, unrelated bridge -- for the tests about one store holding
    /// orders that trust different bridges.
    fn other_bridge_key() -> SigningKey {
        SigningKey::from_bytes(&[33u8; 32])
    }

    fn params(seller: &SigningKey) -> StoreParameters {
        StoreParameters {
            seller_verifying_key: seller.verifying_key(),
        }
    }

    /// The bridge set an order names. Per-order now, so every test order has
    /// to say whose observations settle it.
    fn bridges(bridge: &SigningKey) -> Vec<BridgeId> {
        vec![BridgeId(bridge.verifying_key().to_bytes())]
    }

    fn timestamp(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    fn make_order(buyer_fp: &str, created_at_secs: i64, script: &[u8]) -> Order {
        let seller_fp = "seller-fingerprint";
        let ts = timestamp(created_at_secs);
        Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: buyer_fp.into(),
            seller_fingerprint: seller_fp.into(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: script.to_vec(),
            payment_hash: None,
            payment_address: "tb1qtest".into(),
            required_confirmations: 1,
            // The bridge set now travels in the order itself, under the
            // seller's signature, rather than in the store's address.
            trusted_bridges: bridges(&bridge_key()),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            created_at: ts,
        }
        .with_derived_id()
    }

    /// 32-byte contract id that order-term / status signatures must carry
    /// under Harvest's pinned requestor, same convention as
    /// `listing::tests::harvest_requestor_bytes`.
    fn harvest_requestor_bytes() -> [u8; 32] {
        let v = bs58::decode(crate::HARVEST_WEBAPP_CONTRACT_ID)
            .into_vec()
            .expect("HARVEST_WEBAPP_CONTRACT_ID must decode as base58");
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    /// Sign `data` as a ghostkey-delegate `ScopedPayload` would, without
    /// pulling in `ghostkey-common` -- same technique as
    /// `listing::tests::make_authorized_listing_with_requestor`.
    fn sign_scoped<T: serde::Serialize>(signing_key: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
        #[derive(serde::Serialize)]
        struct TestScopedPayload {
            requestor: TestRequestor,
            payload: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        enum TestRequestor {
            WebApp([u8; 32]),
        }

        let payload = crate::to_cbor(data).unwrap();
        let scoped = TestScopedPayload {
            requestor: TestRequestor::WebApp(harvest_requestor_bytes()),
            payload,
        };
        let scoped_bytes = crate::to_cbor(&scoped).unwrap();
        let signature = signing_key.sign(&scoped_bytes).to_bytes().to_vec();
        (scoped_bytes, signature)
    }

    /// Build a fully authorized order: seller-signed terms, and -- for
    /// `Cancelled` -- a seller-signed status transition too.
    fn make_authorized_order(
        seller: &SigningKey,
        order: Order,
        status: OrderStatus,
        payment_proof: Option<OrderPaymentProof>,
    ) -> AuthorizedOrder {
        let (scoped_payload, signature) = sign_scoped(seller, &order);
        let (status_scoped_payload, status_signature) = match status {
            OrderStatus::Cancelled => {
                let (sp, sig) = sign_scoped(seller, &(order.id.clone(), status));
                (Some(sp), Some(sig))
            }
            _ => (None, None),
        };
        AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status,
            payment_proof,
            status_scoped_payload,
            status_signature,
        }
    }

    /// Build a genuine, independently-verifiable `OrderPaymentProof`
    /// establishing `order` as paid, signed by `bridge`. `prev_block_seed`
    /// varies the mined block (and therefore every byte downstream of it),
    /// which is how the equal-rank-tie-break test gets two distinct-but-both-
    /// valid proofs for the same order.
    fn make_payment_proof(
        order: &Order,
        bridge: &SigningKey,
        prev_block_seed: u8,
    ) -> OrderPaymentProof {
        let addr_params = order.bitcoin_params();
        let (spv, txid, block_hash) = payment_proof(
            &order.payment_script_pubkey,
            order.amount_sats,
            1,
            [prev_block_seed; 32],
        );

        let confirm_height = 100;
        let claim_body = ClaimBody {
            script_id: addr_params.script_id(),
            network: order.network,
            as_of: BlockAnchor {
                height: confirm_height,
                hash: block_hash,
            },
            claim: Claim::ConfirmedOutput {
                outpoint: OutPoint { txid, vout: 0 },
                value_sats: order.amount_sats,
                anchor: BlockAnchor {
                    height: confirm_height,
                    hash: block_hash,
                },
                spv,
            },
        };
        let claim = SignedClaim::sign(bridge, &claim_body).unwrap();

        let tip_height = confirm_height + order.required_confirmations - 1;
        let tip_body = TipEntryBody {
            network: order.network,
            anchor: BlockAnchor {
                height: tip_height,
                hash: BlockHash([9u8; 32]),
            },
            prev_hash: BlockHash([8u8; 32]),
            block_time: 1_700_000_000,
            tx_count: 1,
            median_time: 1_700_000_000,
        };
        let tip = SignedTipEntry::sign(bridge, &tip_body).unwrap();

        OrderPaymentProof::on_chain(vec![claim], tip)
    }

    /// A valid, bridge-signed `ScannedTo` claim for this order's script.
    ///
    /// `ScannedTo` names no outpoint, so `verify_on_chain_proof`'s fold skips
    /// it entirely: it adds nothing to the confirmed total and cannot change
    /// the confirmation depth. It is still a genuine claim about the right
    /// script, signed by a bridge the order trusts, so it passes every check
    /// the proof makes. That combination -- costs the attacker nothing,
    /// changes no verdict, adds bytes -- is what makes it padding.
    ///
    /// It is also free to obtain: a bridge publishes these into the public
    /// address contract, so anyone can harvest them. Signing with the bridge
    /// key here stands in for that harvesting, not for a stolen key.
    fn scanned_to_claim(order: &Order, bridge: &SigningKey, height: u32) -> SignedClaim {
        let body = ClaimBody {
            script_id: order.bitcoin_params().script_id(),
            network: order.network,
            as_of: BlockAnchor {
                height,
                hash: BlockHash([height as u8; 32]),
            },
            claim: Claim::ScannedTo,
        };
        SignedClaim::sign(bridge, &body).unwrap()
    }

    /// Reach into an on-chain proof to tamper with it in tests.
    fn on_chain_mut(p: &mut OrderPaymentProof) -> &mut crate::payment::OnChainPaymentProof {
        match p {
            OrderPaymentProof::OnChain(c) => c,
            other => panic!("expected an on-chain proof, got {other:?}"),
        }
    }

    fn orders_of(pairs: impl IntoIterator<Item = (OrderId, AuthorizedOrder)>) -> OrdersV1 {
        OrdersV1 {
            orders: pairs.into_iter().collect(),
        }
    }

    // -----------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------

    #[test]
    fn genuinely_paid_order_verifies() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let proof = make_payment_proof(&order, &bridge, 1);
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let state = orders_of([(order.id.clone(), record)]);
        assert!(
            state.verify(&StoreStateV1::default(), &p).is_ok(),
            "a genuinely paid order, with a real bridge-signed proof, must verify"
        );
    }

    /// The whole point of moving the bridge list off the store's address:
    /// one store, two orders, two DIFFERENT bridges, both valid.
    ///
    /// While the list was `StoreParameters::trusted_bitcoin_bridges` it was
    /// hashed into the contract id, so every order in a store was checked
    /// against one frozen list and this state was unrepresentable -- a store
    /// created with an empty list (which is every store the UI creates) could
    /// never accept a payment at all, and a dead bridge could never be
    /// replaced. Per-order, the second order simply names the new bridge.
    #[test]
    fn two_orders_in_one_store_may_trust_different_bridges() {
        let seller = seller_key();
        let p = params(&seller);

        let mut first = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        first.trusted_bridges = bridges(&bridge_key());
        // Re-stamped after changing a term: the id is derived from the terms
        // (see `OrderId`), so an order edited in place carries a stale one.
        let first = first.with_derived_id();
        let first_proof = make_payment_proof(&first, &bridge_key(), 1);

        // A second invoice, issued later, naming a different bridge -- the
        // rotation the old shape made impossible.
        let mut second = make_order("buyer-2", 1_700_000_100, &[0x00, 0x14, 0xcc, 0xdd]);
        second.trusted_bridges = bridges(&other_bridge_key());
        let second = second.with_derived_id();
        let second_proof = make_payment_proof(&second, &other_bridge_key(), 2);

        let state = orders_of([
            (
                first.id.clone(),
                make_authorized_order(&seller, first, OrderStatus::Paid, Some(first_proof)),
            ),
            (
                second.id.clone(),
                make_authorized_order(&seller, second, OrderStatus::Paid, Some(second_proof)),
            ),
        ]);
        assert!(
            state.verify(&StoreStateV1::default(), &p).is_ok(),
            "each order must be judged against the bridge set IT names, not a store-wide one"
        );
    }

    /// The other half of the same property: naming a bridge does not make
    /// somebody else's signature acceptable.
    #[test]
    fn a_proof_signed_by_a_bridge_the_order_does_not_name_is_rejected() {
        let seller = seller_key();
        let p = params(&seller);
        let mut order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        order.trusted_bridges = bridges(&bridge_key());
        // Genuinely signed -- by a bridge this order never named.
        let proof = make_payment_proof(&order, &other_bridge_key(), 1);
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("an untrusted bridge's signature must not settle this order");
        assert!(err.contains("payment proof rejected"), "got: {err}");
    }

    /// An order naming no bridge fails closed rather than accepting an
    /// unattested claim.
    #[test]
    fn an_order_naming_no_bridge_can_never_be_paid() {
        let seller = seller_key();
        let p = params(&seller);
        let mut order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let proof = make_payment_proof(&order, &bridge_key(), 1);
        order.trusted_bridges = Vec::new();
        // Re-stamped, because the id is derived from the terms: without this
        // the order would be refused for its id and the bridge rule below
        // would never be reached. See `OrderId`.
        let order = order.with_derived_id();
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("an order that names no bridge must not be provable as paid");
        assert!(err.contains("trusts no Bitcoin bridge"), "got: {err}");
    }

    /// The bridge set is only safe per-order because the seller's signature
    /// covers it. If it were carried outside the signed `Order` -- or the
    /// signature were over a subset of the fields -- anyone holding a valid
    /// order could append their own bridge and mint a payment proof.
    #[test]
    fn adding_a_bridge_to_a_signed_order_breaks_the_seller_signature() {
        let seller = seller_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let proof = make_payment_proof(&order, &bridge_key(), 1);
        let mut record =
            make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        // The attacker's own key, appended to a set the seller signed.
        record
            .order
            .trusted_bridges
            .push(BridgeId(other_bridge_key().verifying_key().to_bytes()));

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("the bridge set must be inside what the seller signed");
        assert!(
            err.contains("does not match expected data"),
            "the failure must be the SIGNATURE, not a downstream payment check: {err}"
        );
    }

    #[test]
    fn forged_proof_is_rejected() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let mut proof = make_payment_proof(&order, &bridge, 1);
        // Flip a byte in the bridge's claim signature: same claim body,
        // forged signature.
        let inner = on_chain_mut(&mut proof);
        let last = inner.claims[0].signature.len() - 1;
        inner.claims[0].signature[last] ^= 0xff;
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("a forged bridge signature must not verify");
        assert!(err.contains("invalid"), "got: {err}");
    }

    #[test]
    fn order_marked_paid_without_evidence_is_rejected() {
        let seller = seller_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, None);

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("Paid with no payment_proof must be rejected");
        assert!(err.contains("without payment evidence"), "got: {err}");
    }

    #[test]
    fn order_proof_for_a_different_script_is_rejected() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        // Genuine proof, but for a DIFFERENT script than the order's own.
        let wrong_script_order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0x99, 0x88]);
        let proof = make_payment_proof(&wrong_script_order, &bridge, 1);
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("a proof for a different script must not establish this order as paid");
        assert!(err.contains("payment proof rejected"), "got: {err}");
    }

    // -----------------------------------------------------------------
    // Reversal: what counts as evidence that a payment was undone
    // -----------------------------------------------------------------

    /// One bridge-signed `ConfirmedOutput` claim paying `value_sats` to the
    /// order's script, plus the outpoint it is about so a caller can retract
    /// it afterwards.
    ///
    /// `value_sats` is what distinguishes two claims: `payment_proof` mines a
    /// block whose only transaction pays that value to that script, so the
    /// txid -- and therefore the outpoint -- is a function of the pair. Two
    /// claims for the same value would be one outpoint, not two.
    fn confirmed_claim(
        order: &Order,
        bridge: &SigningKey,
        value_sats: u64,
        confirm_height: u32,
    ) -> (SignedClaim, OutPoint) {
        let addr_params = order.bitcoin_params();
        let (spv, txid, block_hash) =
            payment_proof(&order.payment_script_pubkey, value_sats, 1, [1u8; 32]);
        let outpoint = OutPoint { txid, vout: 0 };
        let anchor = BlockAnchor {
            height: confirm_height,
            hash: block_hash,
        };
        let body = ClaimBody {
            script_id: addr_params.script_id(),
            network: order.network,
            as_of: anchor,
            claim: Claim::ConfirmedOutput {
                outpoint,
                value_sats,
                anchor,
                spv,
            },
        };
        (SignedClaim::sign(bridge, &body).unwrap(), outpoint)
    }

    /// A confirmation the bridge signed from a chain position `as_of_height`,
    /// about a block at `confirm_height`.
    ///
    /// `confirmed_claim` always signs with `as_of == anchor`, i.e. the bridge
    /// saw the block at depth 1. This lets a test say how deep the BRIDGE
    /// claimed the block was, which is the quantity `attested_depth` carries
    /// and the only one a submitter cannot inflate.
    fn confirmed_claim_seen_from(
        order: &Order,
        bridge: &SigningKey,
        value_sats: u64,
        confirm_height: u32,
        as_of_height: u32,
    ) -> (SignedClaim, OutPoint) {
        let addr_params = order.bitcoin_params();
        let (spv, txid, block_hash) =
            payment_proof(&order.payment_script_pubkey, value_sats, 1, [1u8; 32]);
        let outpoint = OutPoint { txid, vout: 0 };
        let anchor = BlockAnchor {
            height: confirm_height,
            hash: block_hash,
        };
        let body = ClaimBody {
            script_id: addr_params.script_id(),
            network: order.network,
            as_of: BlockAnchor {
                height: as_of_height,
                hash: BlockHash([3u8; 32]),
            },
            claim: Claim::ConfirmedOutput {
                outpoint,
                value_sats,
                anchor,
                spv,
            },
        };
        (SignedClaim::sign(bridge, &body).unwrap(), outpoint)
    }

    /// The claim a real reorg produces: as of a HIGHER chain position than
    /// the confirmation it supersedes, the bridge no longer sees `outpoint`
    /// on its best chain. It carries no SPV proof because it asserts an
    /// absence, and there is nothing to prove the inclusion of.
    fn retraction_claim(
        order: &Order,
        bridge: &SigningKey,
        outpoint: OutPoint,
        as_of_height: u32,
    ) -> SignedClaim {
        let addr_params = order.bitcoin_params();
        let body = ClaimBody {
            script_id: addr_params.script_id(),
            network: order.network,
            as_of: BlockAnchor {
                height: as_of_height,
                hash: BlockHash([7u8; 32]),
            },
            claim: Claim::Retracted { outpoint },
        };
        SignedClaim::sign(bridge, &body).unwrap()
    }

    fn signed_tip(order: &Order, bridge: &SigningKey, height: u32) -> SignedTipEntry {
        SignedTipEntry::sign(
            bridge,
            &TipEntryBody {
                network: order.network,
                anchor: BlockAnchor {
                    height,
                    hash: BlockHash([9u8; 32]),
                },
                prev_hash: BlockHash([8u8; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .unwrap()
    }

    /// The poisoning attack. `PaymentReversed` outranks `Paid` and merge is a
    /// monotonic maximum on rank, so a reversal a peer accepts can never be
    /// corrected by any later proof of payment. The status is also unsigned by
    /// design, so anyone who can read the public order can submit one.
    ///
    /// An empty `claims` vector costs nothing to build and needs no bridge.
    /// It must not be evidence of anything.
    #[test]
    fn an_empty_claim_set_cannot_declare_an_order_reversed() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        // No claims at all -- the tip is genuine, but it says nothing about
        // this script.
        let proof = OrderPaymentProof::on_chain(vec![], signed_tip(&order, &bridge, 101));
        let record = make_authorized_order(
            &seller,
            order.clone(),
            OrderStatus::PaymentReversed,
            Some(proof),
        );

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("an empty claim set must not establish a reversal");
        assert!(err.contains("reversal evidence invalid"), "got: {err}");
    }

    /// The other half of the same rule, and the one that stops the fix being
    /// "reject every reversal": a genuine reorg -- a signed confirmation, then
    /// a signed retraction at a higher `as_of` -- must still be accepted.
    #[test]
    fn a_genuine_reorg_verifies_as_reversed() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        let (confirmed, outpoint) = confirmed_claim(&order, &bridge, order.amount_sats, 100);
        let retracted = retraction_claim(&order, &bridge, outpoint, 101);
        let proof = OrderPaymentProof::on_chain(
            vec![confirmed, retracted],
            signed_tip(&order, &bridge, 101),
        );

        // The proof itself must fail with `Reversed` specifically. That is the
        // error `AuthorizedOrder::verify` keys on, so nothing else will do.
        assert_eq!(
            crate::payment::verify_payment_proof(&order, &proof),
            Err(crate::payment::ProofError::Reversed)
        );

        let record = make_authorized_order(
            &seller,
            order.clone(),
            OrderStatus::PaymentReversed,
            Some(proof),
        );
        let state = orders_of([(order.id.clone(), record)]);
        assert!(
            state.verify(&StoreStateV1::default(), &p).is_ok(),
            "a bridge-signed retraction at a higher as_of is a real reversal"
        );
    }

    /// A partial reversal: the order was paid across two outpoints and only
    /// one was reorged out. What remains confirmed is non-zero but no longer
    /// covers the order, which is a reversal in every sense that matters.
    ///
    /// This case used to surface as `InsufficientValue`, and accommodating it
    /// is why `AuthorizedOrder::verify` accepted that error as evidence of a
    /// reversal -- the same error an empty claim set produces. It must report
    /// `Reversed` on its own account instead.
    #[test]
    fn a_partial_reorg_reports_reversed_not_insufficient_value() {
        let bridge = bridge_key();
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        assert_eq!(order.amount_sats, 50_000);

        // Two distinct outpoints, 30_000 + 20_000, together covering the order.
        let (big, _) = confirmed_claim(&order, &bridge, 30_000, 100);
        let (small, small_outpoint) = confirmed_claim(&order, &bridge, 20_000, 100);
        let retracted = retraction_claim(&order, &bridge, small_outpoint, 101);

        let proof = OrderPaymentProof::on_chain(
            vec![big, small, retracted],
            signed_tip(&order, &bridge, 101),
        );

        assert_eq!(
            crate::payment::verify_payment_proof(&order, &proof),
            Err(crate::payment::ProofError::Reversed),
            "30_000 of 50_000 left, with a signed retraction, is a reversal"
        );
    }

    /// A bridge-signed observation of an output the bridge has only ever seen
    /// in the mempool. Carries no SPV proof, because there is no block to
    /// prove inclusion in.
    fn mempool_claim(
        order: &Order,
        bridge: &SigningKey,
        outpoint: OutPoint,
        value_sats: u64,
        as_of_height: u32,
    ) -> SignedClaim {
        let addr_params = order.bitcoin_params();
        let body = ClaimBody {
            script_id: addr_params.script_id(),
            network: order.network,
            as_of: BlockAnchor {
                height: as_of_height,
                hash: BlockHash([6u8; 32]),
            },
            claim: Claim::MempoolOutput {
                outpoint,
                value_sats,
            },
        };
        SignedClaim::sign(bridge, &body).unwrap()
    }

    /// A reversal has to be a reversal OF something.
    ///
    /// `PaymentReversed` outranks `Paid` and merge is a monotonic maximum, so
    /// a reversal a peer accepts is permanent: no later proof of payment can
    /// displace it. The status is unsigned by design, and the order's payment
    /// address is public in the store state, so anyone at all can submit one.
    /// The evidence test is therefore the only thing between a public order
    /// and permanent poisoning, and it must establish that the order was AT
    /// SOME POINT actually covered before it reads a retraction as a reversal.
    ///
    /// Without that it was enough to show any bridge-signed retraction for
    /// this script while the current total fell short -- which for an order
    /// that was never paid is trivially true, since the current total is zero.
    /// Three ways to get such a retraction, all cheap, all covered below.
    #[test]
    fn a_retraction_of_an_unpaid_amount_is_not_a_reversal() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        assert_eq!(order.amount_sats, 50_000);

        let tip = signed_tip(&order, &bridge, 101);
        let (dust, dust_outpoint) = confirmed_claim(&order, &bridge, 1, 100);
        let dust_retracted = retraction_claim(&order, &bridge, dust_outpoint, 101);

        // (1) A bare retraction. Nothing in the proof ever says this order was
        //     paid, and "the current total is short" is true of every order
        //     that has not been paid yet.
        let bare = OrderPaymentProof::on_chain(vec![dust_retracted.clone()], tip.clone());
        assert_ne!(
            crate::payment::verify_payment_proof(&order, &bare),
            Err(crate::payment::ProofError::Reversed),
            "a retraction on its own says nothing about whether the order was ever paid"
        );

        // (2) Dust, confirmed and then retracted. Now the proof does contain a
        //     confirmation -- for 1 sat of a 50_000 sat order. An attacker can
        //     send dust to the public payment address themselves.
        let dusted = OrderPaymentProof::on_chain(vec![dust, dust_retracted.clone()], tip.clone());
        assert_ne!(
            crate::payment::verify_payment_proof(&order, &dusted),
            Err(crate::payment::ProofError::Reversed),
            "1 sat retracted is not the reversal of a 50_000 sat payment"
        );

        // (3) A full-value output the bridge only ever saw in the mempool,
        //     then evicted. This is the cheapest of the three and the only one
        //     an attacker fully controls -- no reorg needed, just a low-fee
        //     transaction they let drop out -- so it is the one that most has
        //     to be refused. A mempool sighting is not a payment.
        let (_, full_outpoint) = confirmed_claim(&order, &bridge, order.amount_sats, 100);
        let evicted = OrderPaymentProof::on_chain(
            vec![
                mempool_claim(&order, &bridge, full_outpoint, order.amount_sats, 99),
                retraction_claim(&order, &bridge, full_outpoint, 101),
            ],
            tip.clone(),
        );
        assert_ne!(
            crate::payment::verify_payment_proof(&order, &evicted),
            Err(crate::payment::ProofError::Reversed),
            "an evicted mempool transaction was never a confirmed payment"
        );

        // And the contract must refuse the record, not merely the proof --
        // `AuthorizedOrder::verify` accepts `Reversed` and nothing else, so
        // these have to come back as some other error.
        for (name, proof) in [("bare", bare), ("dusted", dusted), ("evicted", evicted)] {
            let record = make_authorized_order(
                &seller,
                order.clone(),
                OrderStatus::PaymentReversed,
                Some(proof),
            );
            let state = orders_of([(order.id.clone(), record)]);
            let err = state
                .verify(&StoreStateV1::default(), &p)
                .expect_err("a reversal of a payment that never happened must be rejected");
            assert!(
                err.contains("reversal evidence invalid"),
                "{name}: expected the reversal-evidence rejection, got: {err}"
            );
        }
    }

    /// Confirmation depth is capped at what the BRIDGE attested, not at what
    /// the submitter's tip implies.
    ///
    /// The submitter chooses the claim set, so across a reorg it can present
    /// the bridge's pre-reorg `ConfirmedOutput` and drop the `Retracted` that
    /// superseded it. Every other check still passes: the confirmation is
    /// genuinely signed, genuinely about this script, and names a
    /// self-consistent block.
    ///
    /// What turned that from a stale reading into a forgery was pairing it
    /// with a FRESH tip. Depth measured as `tip - anchor + 1` grows with the
    /// chain, so an assertion the bridge made at depth 1 and has since
    /// retracted reads as arbitrarily deep just by supplying a current tip.
    /// `OutpointStatus::confirmations_at` caps at `attested_depth` -- the
    /// depth inside the bridge's own signature -- which no submitter can
    /// inflate.
    ///
    /// Mutated red by taking rustc's suggestion when `attested_depth` was
    /// added upstream: `attested_depth: _` plus the uncapped free function
    /// `confirmations(&anchor, tip_height)` compiles, passes every other test
    /// in this workspace, and makes the order below `Paid`.
    #[test]
    fn depth_is_capped_at_what_the_bridge_attested() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);

        // Six confirmations required, so the difference between a bridge that
        // saw one and a tip that implies a hundred actually decides the order.
        let mut order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        order.required_confirmations = 6;

        // The bridge signed this at the same height as the block: it had seen
        // exactly one confirmation. That is the whole of what it attested.
        let (shallow, _) = confirmed_claim_seen_from(&order, &bridge, order.amount_sats, 100, 100);

        // ...presented against a tip a hundred blocks later.
        let stale = OrderPaymentProof::on_chain(vec![shallow], signed_tip(&order, &bridge, 200));
        assert_eq!(
            crate::payment::verify_payment_proof(&order, &stale),
            Err(crate::payment::ProofError::InsufficientConfirmations { have: 1, need: 6 }),
            "a confirmation the bridge attested at depth 1 must be worth one \
             confirmation however far ahead the supplied tip is"
        );

        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(stale));
        let state = orders_of([(order.id.clone(), record)]);
        assert!(
            state.verify(&StoreStateV1::default(), &p).is_err(),
            "and the contract must refuse the record, not just the proof"
        );

        // The honest case still settles, so this is a cap and not a refusal:
        // the bridge signed from height 105 about a block at 100, i.e. it
        // really had seen six confirmations.
        let (deep, _) = confirmed_claim_seen_from(&order, &bridge, order.amount_sats, 100, 105);
        let genuine = OrderPaymentProof::on_chain(vec![deep], signed_tip(&order, &bridge, 105));
        assert_eq!(
            crate::payment::verify_payment_proof(&order, &genuine),
            Ok(order.amount_sats),
            "a bridge that attested six confirmations still settles a six-confirmation order"
        );
    }

    /// **Pins a KNOWN GAP, not desired behaviour.** Invert this test when the
    /// gap closes.
    ///
    /// The mirror image of `a_withheld_retraction_is_not_currently_detected`,
    /// and the more damaging direction of the two, because `PaymentReversed`
    /// is permanent under merge while `Paid` can still be superseded.
    ///
    /// Requiring a reversal to show confirmations that were themselves
    /// retracted stops an order that was NEVER paid from being reversed. It
    /// does not stop a genuine payment that survived a reorg from being
    /// reported as reversed: the bridge published three claims for that
    /// outpoint, and a submitter who shows the first two and withholds the
    /// third satisfies the precondition with entirely genuine evidence.
    ///
    /// See `OnChainPaymentProof`'s doc comment for the bridge-signed
    /// claim-set commitment that would close this, and why it belongs
    /// upstream in `freenet-bitcoin` rather than here.
    #[test]
    fn a_withheld_reconfirmation_still_reads_as_a_reversal() {
        let bridge = bridge_key();
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        // The real history of a payment that was reorged and re-confirmed:
        // confirmed at 100, retracted at 101, confirmed again at 102. Same
        // outpoint throughout -- the transaction was re-mined, not replaced.
        let (confirmed, outpoint) = confirmed_claim(&order, &bridge, order.amount_sats, 100);
        let retracted = retraction_claim(&order, &bridge, outpoint, 101);
        let (reconfirmed, reconfirmed_outpoint) =
            confirmed_claim(&order, &bridge, order.amount_sats, 102);
        assert_eq!(
            outpoint, reconfirmed_outpoint,
            "the re-confirmation must be about the same outpoint, or this is a different scenario"
        );
        let tip = signed_tip(&order, &bridge, 102);

        // Complete history: the payment stands.
        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(
                    vec![confirmed.clone(), retracted.clone(), reconfirmed],
                    tip.clone(),
                ),
            ),
            Ok(order.amount_sats),
            "with the whole history the payment is current",
        );

        // The re-confirmation withheld, and nothing else changed.
        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(vec![confirmed, retracted], tip),
            ),
            Err(crate::payment::ProofError::Reversed),
            "KNOWN GAP: omitting the re-confirmation still reads as a reversal",
        );
    }

    /// Evidence that still proves payment is not evidence of a reversal.
    ///
    /// This is what stops the whole `PaymentReversed` arm being replaced by an
    /// unconditional `Ok(())`: without it, that mutation passes every other
    /// test in this workspace.
    #[test]
    fn a_reversal_backed_by_a_valid_payment_proof_is_rejected() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        // A genuine, fully valid proof of PAYMENT, submitted as a reversal.
        let proof = make_payment_proof(&order, &bridge, 1);
        let record = make_authorized_order(
            &seller,
            order.clone(),
            OrderStatus::PaymentReversed,
            Some(proof),
        );

        let state = orders_of([(order.id.clone(), record)]);
        let err = state
            .verify(&StoreStateV1::default(), &p)
            .expect_err("evidence of payment is not evidence of reversal");
        assert!(err.contains("still proves payment"), "got: {err}");
    }

    /// **Pins a KNOWN GAP, not desired behaviour.** Invert this test when the
    /// gap closes -- if it starts failing because someone made the proof
    /// complete, that is the fix landing, not a regression.
    ///
    /// The submitter picks `proof.claims`. Here the same reorg produces two
    /// bridge-signed claims, and the only difference between "paid" and
    /// "reversed" is which of them the submitter chose to hand over. Every
    /// other check passes identically in both cases: the confirmation is
    /// genuinely signed, genuinely about this script, and genuinely deep
    /// enough against the supplied tip.
    ///
    /// See `OnChainPaymentProof`'s doc comment for why this cannot be closed
    /// in `verify_on_chain_proof`, in `merge_order`, or via the related
    /// contract, and for the bridge-signed claim-set commitment that would
    /// close it.
    #[test]
    fn a_withheld_retraction_is_not_currently_detected() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        let (confirmed, outpoint) = confirmed_claim(&order, &bridge, order.amount_sats, 100);
        let retracted = retraction_claim(&order, &bridge, outpoint, 101);
        let tip = signed_tip(&order, &bridge, 101);

        // Both claims: the reorg is visible, and the order is reversed.
        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(vec![confirmed.clone(), retracted], tip.clone()),
            ),
            Err(crate::payment::ProofError::Reversed),
        );

        // The retraction withheld, and nothing else changed: the very same
        // confirmation, against the very same current tip, now validates as a
        // completed payment.
        let curated = OrderPaymentProof::on_chain(vec![confirmed], tip);
        assert_eq!(
            crate::payment::verify_payment_proof(&order, &curated),
            Ok(order.amount_sats),
            "KNOWN GAP: omitting the retraction still validates as paid",
        );

        let record =
            make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(curated));
        let state = orders_of([(order.id.clone(), record)]);
        assert!(
            state.verify(&StoreStateV1::default(), &p).is_ok(),
            "KNOWN GAP: the contract accepts the curated proof as a paid order",
        );
    }

    // -----------------------------------------------------------------
    // Bounding the claim vector
    //
    // A trusted bridge's claims are PUBLIC, so anyone can harvest genuine
    // ones and resubmit them. Each verification costs an Ed25519 check plus
    // SHA256d over up to 64 KB of transaction, and `OrdersV1::verify` re-runs
    // every order's proof on every state validation, for up to `MAX_ORDERS`
    // orders. The vector used to have no length cap, no dedup and no byte
    // budget at all.
    // -----------------------------------------------------------------

    /// A junk claim with a distinct digest, for the checks that must fire
    /// BEFORE any signature is verified. Nothing here would survive
    /// `SignedClaim::verify`, which is the point: if the bound is applied
    /// after verification these come back as `BadClaim` instead.
    fn junk_claim(seed: u32, body_len: usize) -> SignedClaim {
        let mut body_cbor = seed.to_le_bytes().to_vec();
        body_cbor.resize(body_len.max(4), 0u8);
        SignedClaim {
            body_cbor,
            bridge: BridgeId(bridge_key().verifying_key().to_bytes()),
            signature: vec![0u8; 64],
        }
    }

    /// Duplicates must cost a hash, not a signature verification.
    ///
    /// The observable form of "deduped BEFORE verifying": the count cap is on
    /// DISTINCT claims, so a proof carrying far more duplicates than the cap
    /// still verifies. Remove the dedup and the same proof is rejected as
    /// `TooManyClaims`.
    #[test]
    fn duplicate_claims_are_deduplicated_rather_than_reverified() {
        let bridge = bridge_key();
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let (confirmed, _) = confirmed_claim(&order, &bridge, order.amount_sats, 100);
        let tip = signed_tip(&order, &bridge, 100);

        // Comfortably more copies than the cap on distinct claims, and --
        // asserted, not assumed -- comfortably inside the byte budget, so a
        // failure here can only be about the dedup.
        let copies = crate::payment::MAX_PROOF_CLAIMS * 6;
        let claims = vec![confirmed; copies];
        assert!(
            crate::to_cbor(&claims).unwrap().len() < crate::payment::MAX_PROOF_CLAIM_BYTES,
            "this fixture must sit inside the byte budget, or it tests the wrong bound"
        );

        assert_eq!(
            crate::payment::verify_payment_proof(&order, &OrderPaymentProof::on_chain(claims, tip)),
            Ok(order.amount_sats),
            "{copies} copies of one genuine claim are one claim, and must cost one \
             verification -- not {copies} of them"
        );
    }

    /// The cap on distinct claims, and that it fires before verification.
    ///
    /// The claims here are junk: if the cap were applied after the
    /// verification loop this would come back `BadClaim`, having already paid
    /// for every signature check the cap exists to prevent.
    #[test]
    fn more_distinct_claims_than_the_cap_are_refused_before_any_are_verified() {
        let bridge = bridge_key();
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let tip = signed_tip(&order, &bridge, 100);

        let over = crate::payment::MAX_PROOF_CLAIMS + 1;
        let claims: Vec<SignedClaim> = (0..over as u32).map(|i| junk_claim(i, 8)).collect();

        assert_eq!(
            crate::payment::verify_payment_proof(&order, &OrderPaymentProof::on_chain(claims, tip)),
            Err(crate::payment::ProofError::TooManyClaims {
                have: over,
                cap: crate::payment::MAX_PROOF_CLAIMS,
            }),
        );
    }

    /// A count cap is not a memory bound: claim size is set by whoever made
    /// the Bitcoin transaction, and one `ConfirmedOutput` may carry a 64 KB
    /// raw transaction. Two claims can be under any count cap and still be
    /// megabytes.
    #[test]
    fn claims_over_the_byte_budget_are_refused_even_when_few() {
        let bridge = bridge_key();
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let tip = signed_tip(&order, &bridge, 100);

        // Two claims -- far under `MAX_PROOF_CLAIMS` -- but together over the
        // byte budget. A count cap alone would wave these through.
        let half = crate::payment::MAX_PROOF_CLAIM_BYTES;
        let claims = vec![junk_claim(1, half), junk_claim(2, half)];
        assert!(claims.len() < crate::payment::MAX_PROOF_CLAIMS);

        assert!(
            matches!(
                crate::payment::verify_payment_proof(
                    &order,
                    &OrderPaymentProof::on_chain(claims, tip)
                ),
                Err(crate::payment::ProofError::ClaimsTooLarge { .. })
            ),
            "a proof over the byte budget must be refused on its size, not decoded and \
             verified first"
        );
    }

    /// The bounds must not refuse an ordinary, honest proof.
    #[test]
    fn an_ordinary_proof_is_nowhere_near_either_bound() {
        let bridge = bridge_key();
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let (confirmed, _) = confirmed_claim(&order, &bridge, order.amount_sats, 100);
        let bytes = crate::to_cbor(&vec![confirmed]).unwrap().len();
        assert!(
            bytes * crate::payment::MAX_PROOF_CLAIMS < crate::payment::MAX_PROOF_CLAIM_BYTES,
            "a full complement of {} ordinary claims is {} bytes, over the {} budget -- the \
             two bounds contradict each other and honest proofs will be refused",
            crate::payment::MAX_PROOF_CLAIMS,
            bytes * crate::payment::MAX_PROOF_CLAIMS,
            crate::payment::MAX_PROOF_CLAIM_BYTES,
        );
    }

    // -----------------------------------------------------------------
    // Merge properties
    // -----------------------------------------------------------------

    #[test]
    fn status_is_monotonic_under_merge() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        let awaiting =
            make_authorized_order(&seller, order.clone(), OrderStatus::AwaitingPayment, None);
        let proof = make_payment_proof(&order, &bridge, 1);
        let paid = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));

        let mut a = orders_of([(order.id.clone(), awaiting.clone())]);
        let b = orders_of([(order.id.clone(), paid.clone())]);
        a.merge(&StoreStateV1::default(), &p, &b).unwrap();
        assert_eq!(
            a.orders[&order.id].status,
            OrderStatus::Paid,
            "merging in a higher-ranked status must adopt it"
        );

        // Merging the stale AwaitingPayment version back in must NOT
        // regress the status: rank only ever moves forward.
        let stale = orders_of([(order.id.clone(), awaiting)]);
        a.merge(&StoreStateV1::default(), &p, &stale).unwrap();
        assert_eq!(
            a.orders[&order.id].status,
            OrderStatus::Paid,
            "a stale, lower-ranked status must never overwrite a later one"
        );
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);

        let order_x = make_order("buyer-x", 1_700_000_000, &[0x00, 0x14, 0x01, 0x01]);
        let order_y = make_order("buyer-y", 1_700_000_100, &[0x00, 0x14, 0x02, 0x02]);
        let proof_x = make_payment_proof(&order_x, &bridge, 3);
        let proof_y = make_payment_proof(&order_y, &bridge, 4);

        // a: X awaiting, Y absent.
        let a = orders_of([(
            order_x.id.clone(),
            make_authorized_order(&seller, order_x.clone(), OrderStatus::AwaitingPayment, None),
        )]);
        // b: X paid (higher rank), Y awaiting.
        let b = orders_of([
            (
                order_x.id.clone(),
                make_authorized_order(
                    &seller,
                    order_x.clone(),
                    OrderStatus::Paid,
                    Some(proof_x.clone()),
                ),
            ),
            (
                order_y.id.clone(),
                make_authorized_order(&seller, order_y.clone(), OrderStatus::AwaitingPayment, None),
            ),
        ]);
        // c: X's payment reorged out (higher still), Y paid.
        //
        // `PaymentReversed` is the top rank now that `Fulfilled` is gone, and
        // unlike `Fulfilled` it has to carry real evidence -- so this builds a
        // genuine confirmation-then-retraction pair for X.
        let (x_confirmed, x_outpoint) =
            confirmed_claim(&order_x, &bridge, order_x.amount_sats, 100);
        let x_reversal = OrderPaymentProof::on_chain(
            vec![
                x_confirmed,
                retraction_claim(&order_x, &bridge, x_outpoint, 101),
            ],
            signed_tip(&order_x, &bridge, 101),
        );
        let c = orders_of([
            (
                order_x.id.clone(),
                make_authorized_order(
                    &seller,
                    order_x.clone(),
                    OrderStatus::PaymentReversed,
                    Some(x_reversal),
                ),
            ),
            (
                order_y.id.clone(),
                make_authorized_order(
                    &seller,
                    order_y.clone(),
                    OrderStatus::Paid,
                    Some(proof_y.clone()),
                ),
            ),
        ]);

        let merge = |x: &OrdersV1, y: &OrdersV1| -> OrdersV1 {
            let mut m = x.clone();
            m.merge(&StoreStateV1::default(), &p, y).unwrap();
            m
        };

        let ab_c = merge(&merge(&a, &b), &c);
        let a_bc = merge(&a, &merge(&b, &c));
        let ba_c = merge(&merge(&b, &a), &c);
        let ac_b = merge(&merge(&a, &c), &b);

        let bytes = |s: &OrdersV1| crate::to_cbor(s).unwrap();
        assert_eq!(bytes(&ab_c), bytes(&a_bc), "merge must be associative");
        assert_eq!(bytes(&ab_c), bytes(&ba_c), "merge must be commutative");
        assert_eq!(bytes(&ab_c), bytes(&ac_b), "merge must be commutative (2)");

        let idempotent = merge(&ab_c, &ab_c);
        assert_eq!(bytes(&ab_c), bytes(&idempotent), "merge must be idempotent");

        // And the converged result actually reflects the higher-ranked
        // status for both orders.
        assert_eq!(
            ab_c.orders[&order_x.id].status,
            OrderStatus::PaymentReversed
        );
        assert_eq!(ab_c.orders[&order_y.id].status, OrderStatus::Paid);
    }

    #[test]
    fn equal_rank_ties_are_broken_deterministically_and_commutatively() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        // Two independently-assembled, EACH INDIVIDUALLY VALID proofs for
        // the same order and the same status: different mined blocks, so
        // different bytes end to end, but both establish Paid.
        let proof_1 = make_payment_proof(&order, &bridge, 5);
        let proof_2 = make_payment_proof(&order, &bridge, 6);
        assert_ne!(
            crate::to_cbor(&proof_1).unwrap(),
            crate::to_cbor(&proof_2).unwrap(),
            "the two proofs must actually differ for this test to mean anything"
        );

        let record_1 =
            make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof_1));
        let record_2 =
            make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof_2));

        let a = orders_of([(order.id.clone(), record_1.clone())]);
        let b = orders_of([(order.id.clone(), record_2.clone())]);

        let mut a_then_b = a.clone();
        a_then_b.merge(&StoreStateV1::default(), &p, &b).unwrap();
        let mut b_then_a = b.clone();
        b_then_a.merge(&StoreStateV1::default(), &p, &a).unwrap();

        assert_eq!(
            crate::to_cbor(&a_then_b).unwrap(),
            crate::to_cbor(&b_then_a).unwrap(),
            "the tie-break winner must not depend on merge order"
        );

        // The winner must be whichever record has the smaller CBOR bytes --
        // see `merge_order` for why that direction and not the other.
        let expected_winner =
            if crate::to_cbor(&record_1).unwrap() < crate::to_cbor(&record_2).unwrap() {
                &record_1
            } else {
                &record_2
            };
        assert_eq!(
            crate::to_cbor(&a_then_b.orders[&order.id]).unwrap(),
            crate::to_cbor(expected_winner).unwrap(),
            "the tie-break must deterministically pick the smaller CBOR encoding"
        );

        // Idempotent: merging the winner into itself changes nothing.
        let mut winner_twice = a_then_b.clone();
        winner_twice
            .merge(&StoreStateV1::default(), &p, &a_then_b)
            .unwrap();
        assert_eq!(
            crate::to_cbor(&a_then_b).unwrap(),
            crate::to_cbor(&winner_twice).unwrap()
        );
    }

    #[test]
    fn delta_returns_none_when_summary_already_matches() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let proof = make_payment_proof(&order, &bridge, 1);
        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));
        let state = orders_of([(order.id.clone(), record)]);

        let own_summary = state.summarize(&StoreStateV1::default(), &p);
        assert!(
            state
                .delta(&StoreStateV1::default(), &p, &own_summary)
                .is_none(),
            "a requester whose summary already matches ours must get no delta"
        );
    }

    // -----------------------------------------------------------------
    // Capacity pruning
    // -----------------------------------------------------------------

    /// Cheap synthetic fixture for pruning tests: no real signatures, since
    /// `enforce_order_cap` is a structural function that never calls
    /// `verify`. Building thousands of genuinely-signed-and-proved orders
    /// just to exercise pruning would be needlessly slow.
    fn synthetic_order(
        seed: u8,
        created_at_secs: i64,
        status: OrderStatus,
    ) -> (OrderId, AuthorizedOrder) {
        let ts = timestamp(created_at_secs);
        let order = Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: format!("buyer-{seed}"),
            seller_fingerprint: "seller".into(),
            amount_sats: 1,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, seed],
            payment_address: "tb1qtest".into(),
            payment_hash: None,
            required_confirmations: 1,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            created_at: ts,
        }
        .with_derived_id();
        (
            order.id.clone(),
            AuthorizedOrder {
                order,
                scoped_payload: vec![],
                signature: vec![],
                status,
                payment_proof: None,
                status_scoped_payload: None,
                status_signature: None,
            },
        )
    }

    #[test]
    fn pruning_drops_terminal_orders_before_active_ones() {
        let mut orders: BTreeMap<OrderId, AuthorizedOrder> = BTreeMap::new();
        let (id_active, rec_active) = synthetic_order(1, 1_000, OrderStatus::AwaitingPayment);
        let (id_terminal, rec_terminal) = synthetic_order(2, 2_000, OrderStatus::Cancelled);
        orders.insert(id_active.clone(), rec_active);
        orders.insert(id_terminal.clone(), rec_terminal);

        // Force the cap down to 1 for this test by pruning a 2-entry map
        // down to `MAX_ORDERS - 1` worth of headroom is impractical to set
        // up directly (MAX_ORDERS is a real constant), so instead call the
        // pruning logic's underlying comparison directly by filling past
        // the real cap with cheap synthetic entries sharing the terminal
        // one's profile, then checking the terminal-tier one is gone and
        // the active one survives.
        for i in 3..(MAX_ORDERS as u16 + 3) {
            let (id, rec) =
                synthetic_order((i % 256) as u8, 3_000 + i as i64, OrderStatus::Cancelled);
            orders.insert(id, rec);
        }
        assert!(orders.len() > MAX_ORDERS);

        enforce_order_cap(&mut orders);
        assert_eq!(orders.len(), MAX_ORDERS);
        assert!(
            orders.contains_key(&id_active),
            "the only active (non-terminal) order must survive pruning"
        );
        assert!(
            !orders.contains_key(&id_terminal),
            "the oldest terminal order must be dropped before newer terminal ones"
        );
    }

    #[test]
    fn pruning_is_order_independent() {
        let mut entries = Vec::new();
        for i in 0..(MAX_ORDERS as u16 + 25) {
            let status = if i % 3 == 0 {
                OrderStatus::Cancelled
            } else {
                OrderStatus::AwaitingPayment
            };
            entries.push(synthetic_order((i % 256) as u8, 10_000 + i as i64, status));
        }

        let mut forward: BTreeMap<OrderId, AuthorizedOrder> = entries.iter().cloned().collect();
        let mut backward: BTreeMap<OrderId, AuthorizedOrder> =
            entries.iter().rev().cloned().collect();

        enforce_order_cap(&mut forward);
        enforce_order_cap(&mut backward);

        assert_eq!(forward.len(), MAX_ORDERS);
        assert_eq!(
            forward.keys().collect::<Vec<_>>(),
            backward.keys().collect::<Vec<_>>(),
            "pruning must depend only on content, not on insertion order"
        );
    }

    /// Padding a proof must not win the tie-break.
    ///
    /// An order's `Paid` status is not signed by anybody -- it is authorized
    /// by evidence any peer can check -- so any third party who can read the
    /// store can take a genuine `Paid` record, leave the seller's signature
    /// and the status untouched, staple extra VALID claims onto the payment
    /// proof and resubmit it. The record still verifies, and it still says
    /// exactly what it said before.
    ///
    /// While the tie-break kept the GREATER encoding, that resubmission won,
    /// permanently: merge is a monotonic maximum, so the honest compact
    /// record could never displace the padded one again, on any replica. Repeat
    /// it and every order in the store walks up toward
    /// `MAX_PROOF_CLAIM_BYTES` (256 KiB) each, which the store then re-verifies
    /// on every state validation and carries in every merge.
    #[test]
    fn a_padded_proof_does_not_displace_the_honest_record() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        let honest_proof = make_payment_proof(&order, &bridge, 5);
        let honest = make_authorized_order(
            &seller,
            order.clone(),
            OrderStatus::Paid,
            Some(honest_proof.clone()),
        );

        // The attacker's copy: same order, same seller signature, same
        // status, same evidence -- plus eight claims that change nothing.
        let mut padded_proof = honest_proof.clone();
        for height in 1..=8u32 {
            on_chain_mut(&mut padded_proof)
                .claims
                .push(scanned_to_claim(&order, &bridge, height));
        }
        let padded = make_authorized_order(
            &seller,
            order.clone(),
            OrderStatus::Paid,
            Some(padded_proof),
        );

        let honest_bytes = crate::to_cbor(&honest).unwrap();
        let padded_bytes = crate::to_cbor(&padded).unwrap();
        assert!(
            padded_bytes.len() > honest_bytes.len(),
            "the padded record must actually be bigger for this test to mean anything"
        );
        assert!(
            padded_bytes > honest_bytes,
            "padding must actually win the old greater-bytes tie-break, or this \
             test would pass for the wrong reason"
        );
        assert_eq!(
            honest.status.rank(),
            padded.status.rank(),
            "the attack works at an exact rank tie; anything else is a different bug"
        );

        // Both are individually valid -- the attacker has broken no rule.
        let honest_state = orders_of([(order.id.clone(), honest.clone())]);
        let padded_state = orders_of([(order.id.clone(), padded.clone())]);
        assert!(honest_state.verify(&StoreStateV1::default(), &p).is_ok());
        assert!(
            padded_state.verify(&StoreStateV1::default(), &p).is_ok(),
            "the padded record must still verify -- that is what makes this an \
             attack rather than a rejected update"
        );

        // Whichever way round they meet, the compact record is what survives.
        let mut honest_then_padded = honest_state.clone();
        honest_then_padded
            .merge(&StoreStateV1::default(), &p, &padded_state)
            .unwrap();
        let mut padded_then_honest = padded_state.clone();
        padded_then_honest
            .merge(&StoreStateV1::default(), &p, &honest_state)
            .unwrap();

        assert_eq!(
            crate::to_cbor(&honest_then_padded.orders[&order.id]).unwrap(),
            honest_bytes,
            "a padded resubmission must not displace the honest record"
        );
        assert_eq!(
            crate::to_cbor(&padded_then_honest.orders[&order.id]).unwrap(),
            honest_bytes,
            "and it must not survive merely by having arrived first"
        );
    }

    /// A field the status does not use must be REJECTED, not merely ignored.
    ///
    /// `verify` reads `status_scoped_payload` / `status_signature` only for
    /// `Cancelled`, and `payment_proof` only for `Paid` / `PaymentReversed`.
    /// Anywhere else those fields used to be unchecked bytes that any third
    /// party could set on a record that still verified -- and that is not
    /// harmless, because `merge_order` breaks an equal-rank tie on the full
    /// CBOR encoding and keeps the SMALLER.
    ///
    /// In CBOR `None` is `0xf6`, and every `Some(..)` here begins with an
    /// array header in `0x80..=0x9b`. So `Some(anything)` sorts BELOW `None`:
    /// an attacker could set `status_scoped_payload: Some(vec![])` on a
    /// genuine `Paid` record and permanently displace the honest copy, because
    /// merge is a monotonic maximum. Smaller-encoding-wins made that the
    /// winning move rather than a losing one, which is why this is pinned here
    /// next to the tie-break it protects and not only in `payment.rs`.
    #[test]
    fn a_field_the_status_does_not_use_is_rejected() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);

        // The byte fact the attack rests on, asserted rather than asserted-in-
        // prose: any `Some` sorts below `None` at that field position.
        assert!(
            crate::to_cbor(&Some(Vec::<u8>::new())).unwrap()
                < crate::to_cbor(&Option::<Vec<u8>>::None).unwrap(),
            "if this ever stops holding, the tie-break's exposure changes and the \
             reasoning on `merge_order` needs redoing"
        );

        let honest = make_authorized_order(
            &seller,
            order.clone(),
            OrderStatus::Paid,
            Some(make_payment_proof(&order, &bridge, 5)),
        );
        assert!(
            orders_of([(order.id.clone(), honest.clone())])
                .verify(&StoreStateV1::default(), &p)
                .is_ok(),
            "the honest record is unaffected"
        );

        // Same order, same status, same proof, plus the smallest possible
        // value in a field `Paid` never reads.
        let mut stuffed = honest.clone();
        stuffed.status_scoped_payload = Some(Vec::new());
        stuffed.status_signature = Some(Vec::new());
        assert!(
            crate::to_cbor(&stuffed).unwrap() < crate::to_cbor(&honest).unwrap(),
            "the attacker's record really does win a smaller-wins tie-break, so \
             rejecting it at verify is what has to stop this"
        );
        let err = orders_of([(order.id.clone(), stuffed)])
            .verify(&StoreStateV1::default(), &p)
            .expect_err("a Paid record carrying a status signature must be rejected");
        assert!(err.contains("status signature"), "got: {err}");

        // The same rule in the other direction: evidence on a status that
        // does not rest on evidence.
        let mut early =
            make_authorized_order(&seller, order.clone(), OrderStatus::AwaitingPayment, None);
        early.payment_proof = Some(make_payment_proof(&order, &bridge, 5));
        let err = orders_of([(order.id.clone(), early)])
            .verify(&StoreStateV1::default(), &p)
            .expect_err("an AwaitingPayment record carrying payment evidence must be rejected");
        assert!(err.contains("payment evidence"), "got: {err}");

        // And a status that DOES use a field still accepts it -- so this is a
        // narrowing, not a blanket refusal.
        let cancelled = make_authorized_order(&seller, order.clone(), OrderStatus::Cancelled, None);
        assert!(
            orders_of([(order.id.clone(), cancelled)])
                .verify(&StoreStateV1::default(), &p)
                .is_ok(),
            "Cancelled genuinely uses its status signature"
        );
    }

    /// A delta is all-or-nothing.
    ///
    /// `apply_delta` used to verify and merge in one pass, so a delta of
    /// `[valid, invalid]` left the valid record merged into `self` and *then*
    /// returned `Err`. Today the contract's `update_state` happens to throw
    /// the mutated value away on error, so nothing observes the half-applied
    /// state -- but that is a property of the call site, not of this function,
    /// and no test asserted it at either end. Anything that keeps the state it
    /// passed in (a retry, a merge helper, the migration fold) would silently
    /// take on records from a delta it was told to reject.
    #[test]
    fn a_delta_holding_one_invalid_record_applies_none_of_it() {
        use freenet_scaffold::ComposableState;

        let seller = seller_key();
        let impostor = SigningKey::from_bytes(&[44u8; 32]);
        let bridge = bridge_key();
        let p = params(&seller);

        let good_order = make_order("buyer-good", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        let good = make_authorized_order(
            &seller,
            good_order.clone(),
            OrderStatus::Paid,
            Some(make_payment_proof(&good_order, &bridge, 5)),
        );

        // Signed by somebody who is not the seller, so `verify_terms` refuses
        // it. Any rejection would do; this is the cheapest to state.
        let bad_order = make_order("buyer-bad", 1_700_000_100, &[0x00, 0x14, 0xcc, 0xdd]);
        let bad = make_authorized_order(
            &impostor,
            bad_order.clone(),
            OrderStatus::AwaitingPayment,
            None,
        );

        let mut state = OrdersV1::default();
        let err = state
            .apply_delta(
                &StoreStateV1::default(),
                &p,
                &Some(vec![good.clone(), bad.clone()]),
            )
            .expect_err("a delta carrying an invalid record must be rejected");
        assert!(
            err.contains(&bad_order.id.to_string()) || err.contains("invalid"),
            "the error should name the record that failed: {err}"
        );
        assert!(
            state.orders.is_empty(),
            "a rejected delta must leave nothing behind -- found {:?}",
            state.orders.keys().collect::<Vec<_>>()
        );

        // The valid record on its own is genuinely applicable, so the
        // assertion above is about atomicity and not about `good` being
        // unmergeable for some other reason.
        let mut state = OrdersV1::default();
        state
            .apply_delta(&StoreStateV1::default(), &p, &Some(vec![good.clone()]))
            .expect("the valid record alone must apply");
        assert_eq!(
            state.orders.keys().collect::<Vec<_>>(),
            vec![&good_order.id]
        );

        // Order within the delta must not matter either.
        let mut state = OrdersV1::default();
        state
            .apply_delta(&StoreStateV1::default(), &p, &Some(vec![bad, good]))
            .expect_err("a delta carrying an invalid record must be rejected");
        assert!(state.orders.is_empty());
    }

    /// A seller-signed listing, built the same way `make_authorized_order`
    /// builds order terms.
    fn make_listing(signer: &SigningKey, title: &str) -> AuthorizedListing {
        let ts = timestamp(1_700_000_000);
        let listing = crate::listing::Listing {
            id: ListingId([0u8; 32]),
            title: title.into(),
            description: String::new(),
            kind: crate::listing::ListingKind::Sale,
            price: None,
            created_at: ts,
        }
        .with_derived_id();
        let (scoped_payload, signature) = sign_scoped(signer, &listing);
        AuthorizedListing {
            listing,
            scoped_payload,
            signature,
            certificate_pem: String::new(),
        }
    }

    /// `ListingsV1::apply_delta` had the same half-applied shape as
    /// `OrdersV1`'s, found while fixing that one: it pushed each listing as
    /// it verified it, so a delta of `[valid, invalid]` left the valid
    /// listing in `self` and then returned `Err`.
    #[test]
    fn a_listing_delta_holding_one_invalid_entry_applies_none_of_it() {
        use freenet_scaffold::ComposableState;

        let seller = seller_key();
        let impostor = SigningKey::from_bytes(&[44u8; 32]);
        let p = params(&seller);

        let good = make_listing(&seller, "Widget");
        let bad = make_listing(&impostor, "Fake");

        let mut state = ListingsV1::default();
        state
            .apply_delta(
                &StoreStateV1::default(),
                &p,
                &Some(vec![good.clone(), bad.clone()]),
            )
            .expect_err("a listing delta carrying an unsigned entry must be rejected");
        assert!(
            state.listings.is_empty(),
            "a rejected listing delta must leave nothing behind"
        );

        let mut state = ListingsV1::default();
        state
            .apply_delta(&StoreStateV1::default(), &p, &Some(vec![good.clone()]))
            .expect("the valid listing alone must apply");
        assert_eq!(state.listings.len(), 1);
    }

    /// A delta naming the same listing twice must not store it twice.
    ///
    /// The duplicate check reads a set snapshotted BEFORE the loop, so a
    /// self-duplicating delta used to push both copies. `listings` is a `Vec`
    /// with no uniqueness invariant of its own, and merge is supposed to be
    /// idempotent, so the duplicate survived every subsequent merge and sort.
    #[test]
    fn a_listing_delta_repeating_one_listing_stores_it_once() {
        use freenet_scaffold::ComposableState;

        let seller = seller_key();
        let p = params(&seller);
        let listing = make_listing(&seller, "Widget");

        let mut state = ListingsV1::default();
        state
            .apply_delta(
                &StoreStateV1::default(),
                &p,
                &Some(vec![listing.clone(), listing.clone()]),
            )
            .expect("a repeated-but-valid listing is not an error, just a duplicate");
        assert_eq!(
            state.listings.len(),
            1,
            "the same listing twice in one delta must be stored once"
        );
    }
}

/// Decoding state that predates a field the struct has since grown.
///
/// Kept apart from `order_tests` because it is not about orders: it is about
/// the wire format staying readable across a generation boundary, which is
/// the thing the migration probe depends on and the thing nothing else here
/// checks.
#[cfg(test)]
mod wire_compat_tests {
    use super::*;

    /// A real V1 store state, as CBOR, written out byte by byte.
    ///
    /// V1 (`ded0e3a`, contract code hash `4d7ad3c3...`, the first row of
    /// `legacy/store_contract.toml`) had a two-field `StoreStateV1` -- `info`
    /// and `listings`, no `orders`. These bytes are that encoding:
    ///
    /// ```text
    /// a2                          map(2)
    ///   64 "info"                 AuthorizedStoreInfoV1
    ///   a3                          map(3)
    ///     64 "info"                 StoreInfoV1
    ///     a7                          map(7): version 1, empty strings,
    ///                                 a 32-element zero array for
    ///                                 reputation_contract_id (serde encodes
    ///                                 [u8; 32] as a tuple, i.e. an array of
    ///                                 numbers, NOT a byte string), and
    ///                                 store_name "V1 store"
    ///     6e "scoped_payload" 80    empty seq (Vec<u8> is a seq too)
    ///     69 "signature"      80    empty seq
    ///   68 "listings"             ListingsV1
    ///   a1 68 "listings" 80         map(1) holding an empty seq
    /// ```
    ///
    /// Written as a literal rather than produced by serializing a struct with
    /// the field taken out: the point is to pin today's decoder against bytes
    /// whose shape comes from somewhere other than today's types. A generated
    /// fixture would move whenever the types moved, which is exactly the
    /// change it is supposed to catch.
    const V1_STORE_STATE_CBOR: &[u8] = &[
        0xa2, 0x64, 0x69, 0x6e, 0x66, 0x6f, 0xa3, 0x64, 0x69, 0x6e, 0x66, 0x6f, 0xa7, 0x67, 0x76,
        0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x01, 0x6f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
        0x63, 0x61, 0x74, 0x65, 0x5f, 0x70, 0x65, 0x6d, 0x60, 0x72, 0x73, 0x65, 0x6c, 0x6c, 0x65,
        0x72, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x60, 0x76,
        0x72, 0x65, 0x70, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6e, 0x74,
        0x72, 0x61, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x98, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0x73, 0x74, 0x6f,
        0x72, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x68, 0x56, 0x31, 0x20, 0x73, 0x74, 0x6f, 0x72,
        0x65, 0x6b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x60, 0x74,
        0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63,
        0x74, 0x69, 0x6f, 0x6e, 0x73, 0x60, 0x6e, 0x73, 0x63, 0x6f, 0x70, 0x65, 0x64, 0x5f, 0x70,
        0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x80, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75,
        0x72, 0x65, 0x80, 0x68, 0x6c, 0x69, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x73, 0xa1, 0x68, 0x6c,
        0x69, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x80,
    ];

    /// The whole migration story rests on this: an old generation's state has
    /// to decode into the CURRENT type, or the probe finds the data, cannot
    /// read it, and reports the same "nothing here" it reports for an address
    /// that never existed.
    ///
    /// `OrdersV1` deriving `Default` is not enough on its own -- serde does
    /// not consult `Default` for a missing field without `#[serde(default)]`,
    /// and `#[composable]` does not add one.
    /// The `StoreInfoV1` map from inside [`V1_STORE_STATE_CBOR`], on its own.
    ///
    /// These are the bytes a ghostkey signature was taken over: the delegate
    /// signs `to_cbor(&info)`, and `verify_scoped_signature` re-encodes
    /// `self.info` and compares. So this is not merely an old state's
    /// encoding -- it is the exact preimage of every store-info signature
    /// ever produced before the encryption key existed.
    ///
    /// Tied to the state literal by
    /// [`the_store_info_literal_is_the_one_inside_the_state_literal`], so it
    /// cannot drift into being a plausible fiction of its own.
    const V1_STORE_INFO_CBOR: &[u8] = &[
        0xa7, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x01, 0x6f, 0x63, 0x65, 0x72, 0x74,
        0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x5f, 0x70, 0x65, 0x6d, 0x60, 0x72, 0x73, 0x65,
        0x6c, 0x6c, 0x65, 0x72, 0x5f, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72, 0x70, 0x72, 0x69, 0x6e,
        0x74, 0x60, 0x76, 0x72, 0x65, 0x70, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x63,
        0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x98, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a,
        0x73, 0x74, 0x6f, 0x72, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x68, 0x56, 0x31, 0x20, 0x73,
        0x74, 0x6f, 0x72, 0x65, 0x6b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f,
        0x6e, 0x60, 0x74, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x6e, 0x73, 0x74,
        0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x60,
    ];

    /// The two literals above are one literal, sliced.
    ///
    /// Without this, [`V1_STORE_INFO_CBOR`] would be a second hand-written
    /// fixture that could quietly stop describing the same generation as the
    /// first -- and the signature test below would then be checking a
    /// round-trip of bytes nobody ever signed.
    #[test]
    fn the_store_info_literal_is_the_one_inside_the_state_literal() {
        assert!(
            V1_STORE_STATE_CBOR
                .windows(V1_STORE_INFO_CBOR.len())
                .any(|window| window == V1_STORE_INFO_CBOR),
            "the store-info literal is not a slice of the state literal"
        );
    }

    /// **A signed record must re-encode to the bytes that were signed.**
    ///
    /// `AuthorizedStoreInfoV1::verify` does not compare stored bytes: it
    /// re-serializes `self.info` and checks the result against the payload
    /// inside the signed `ScopedPayload` (see
    /// `crate::listing::verify_scoped_signature`). So any field added to
    /// `StoreInfoV1` that SERIALIZES when absent changes that preimage, and
    /// every store info signed before the field existed stops verifying --
    /// which the store contract reports as "store info signature invalid",
    /// rejecting the seller's own published details.
    ///
    /// `#[serde(default)]` alone does not prevent this. `default` governs
    /// DEcoding; the serializer still emits the field. Only
    /// `skip_serializing_if` keeps the old preimage intact, and this test is
    /// what says so: it fails the moment a new optional field is added
    /// without one.
    ///
    /// Observed red on 2026-09-05 by adding `encryption_public_key` with
    /// `#[serde(default)]` and no `skip_serializing_if`.
    #[test]
    fn a_store_info_that_predates_the_encryption_key_re_encodes_unchanged() {
        let state: StoreStateV1 =
            crate::from_cbor(V1_STORE_STATE_CBOR).expect("the V1 state must decode");

        let re_encoded = crate::to_cbor(&state.info.info).expect("re-encode the decoded info");

        assert_eq!(
            re_encoded, V1_STORE_INFO_CBOR,
            "a store info decoded from pre-encryption-key bytes re-encoded to \
             something else, so its ghostkey signature no longer verifies"
        );
    }

    #[test]
    fn v1_store_state_decodes_without_an_orders_field() {
        let state: StoreStateV1 = crate::from_cbor(V1_STORE_STATE_CBOR)
            .expect("a V1 store state must still decode into today's StoreStateV1");

        assert_eq!(state.info.info.version, 1);
        assert_eq!(state.info.info.store_name, "V1 store");
        assert!(state.listings.listings.is_empty());
        assert!(
            state.orders.orders.is_empty(),
            "a state written before orders existed has none"
        );
    }

    /// The same requirement for `encryption_public_key`. It is a different
    /// failure from the one above: a field the decoder cannot supply makes
    /// the WHOLE state undecodable, so a store published before the key
    /// existed loses its listings, its orders and its details at once rather
    /// than merely being keyless.
    ///
    /// Removing `#[serde(default)]` alone does NOT turn this red, which was
    /// checked rather than assumed: serde's `missing_field` answers `None` for
    /// an `Option` field with no default attribute. What does turn it red is
    /// the field ceasing to be an `Option` without gaining a default --
    /// mutated that way on 2026-09-05 and observed failing with
    /// `missing field `encryption_public_key``. That is the shape a future
    /// field is most likely to arrive in, which is why the test is worth
    /// keeping despite `Option` making today's form safe by accident.
    #[test]
    fn v1_store_state_decodes_without_an_encryption_key() {
        let state: StoreStateV1 = crate::from_cbor(V1_STORE_STATE_CBOR)
            .expect("a V1 store state must still decode into today's StoreStateV1");

        assert_eq!(
            state.info.info.encryption_public_key, None,
            "a store published before sellers had an encryption key has none"
        );
        assert_eq!(
            state.info.info.store_name, "V1 store",
            "the rest of the record must survive alongside the missing field"
        );
    }
}
