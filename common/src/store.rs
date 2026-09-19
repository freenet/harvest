use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use freenet_scaffold::ComposableState;
use serde::{Deserialize, Serialize};

use crate::backing::{
    AuthorizedBacking, AuthorizedClosure, AuthorizedRetirement, BackingsV1, ClosedV1,
    RetirementsV1, SignedSetV1,
};
use crate::listing::{verify_scoped_signature, AuthorizedListing, ListingId};
use crate::payment::{AuthorizedOrder, OrderId};

/// How many base58 characters of the store key make a store code.
///
/// The store key, not a Ghost Key (harvest#93, revision 2): a store has its
/// own Ed25519 key, and Ghost Keys back it (see [`crate::backing`]). Before
/// revision 2 the code was a prefix of the seller's Ghost Key, and everything
/// below about grinding costs carries over unchanged, because it is about a
/// prefix of an Ed25519 key, whichever key that is.
///
/// 16 (harvest#52, decided by @sanity in two steps). A code pins
/// 58^16 ~= 2^93.7 keys; taking one chosen seller's address needs a keypair
/// whose public key shares that seller's code, which is about that many
/// scalar multiplications.
///
/// # Why not 12, and why the single-target figure is not the one that matters
///
/// 12 characters was the first choice, at ~2^70 against one seller. The
/// #91 review pointed out that a grinder does not have to pick its victim in
/// advance: every candidate key can be checked against EVERY live store code
/// at once, so the cost of hitting some store falls by the number of stores.
/// With 12 characters that is about 2^60 at 1,000 stores and 2^57 at 10,000
/// -- within reach -- and under the smaller-key-wins rule (see
/// [`StoreStateV1`]) a hit takes the store's address and every replica drops
/// the seller's listings and Paid orders. At 16 characters it is about 2^94
/// for one chosen seller and about 2^80 against 10,000 stores at once (2^84
/// at 1,000). A link is still well under half the 44-character contract id.
pub const STORE_CODE_LEN: usize = 16;

/// The base58 alphabet a store code is written in (Bitcoin's, which is what
/// `bs58` encodes with by default).
const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The store code a verifying key opens a store under: the first
/// [`STORE_CODE_LEN`] characters of its base58 encoding.
///
/// Every 32-byte value encodes to at least 32 base58 characters (each leading
/// zero byte is a `1`), so the slice always exists.
pub fn store_code(store_verifying_key: &VerifyingKey) -> String {
    let encoded = bs58::encode(store_verifying_key.as_bytes()).into_string();
    encoded[..STORE_CODE_LEN.min(encoded.len())].to_string()
}

/// Immutable parameters for a store contract, set at creation time.
///
/// # A prefix of the store key, not the key (harvest#52)
///
/// The store key since harvest#93. Every generation up to and including V18
/// (`legacy/store_contract.toml`) was addressed by the seller's GHOST KEY
/// instead; see `ui/src/migrate.rs` for how those are found and carried.
///
/// Parameters are hashed into the contract's address, so they are what a link
/// has to carry. The whole key made that a 44-character contract id; a
/// [`STORE_CODE_LEN`]-character prefix of it is short enough to read out, and
/// any client re-derives the full address from it and the store contract it
/// bundles, with no registry and no lookup. This is Delta's `SiteParameters`
/// mechanism.
///
/// A prefix names many keys, so the contract cannot take the owner from here.
/// It takes it from the state, [`StoreStateV1::owner`], checks that it
/// matches this code ([`StoreParameters::admits`]), and verifies everything
/// the store holds against it. See `StoreStateV1`'s docs for how two owners
/// at one address are resolved, and why that resolution converges.
///
/// # Why there is only one field
///
/// Anything here is frozen for the store's entire life. The store key
/// genuinely is the store's identity, so freezing it is correct; the Ghost
/// Key behind the store is not, which is why it is not here (a store's
/// backing can change, harvest#93). The Bitcoin
/// trust configuration used to live here too -- `trusted_bitcoin_bridges` and
/// `bitcoin_address_code_hash` -- and being frozen was fatal to it: every
/// store the UI created was published with an empty bridge list, which made
/// it permanently incapable of accepting an on-chain payment. Both fields now
/// live on [`crate::payment::Order`]; see that struct's `trusted_bridges`.
///
/// # No salt (decided on harvest#52)
///
/// A salt would give a seller whose code was taken a second address, at the
/// cost of the code no longer being derivable from the key alone. Declined:
/// taking a code needs ~2^80 work even against every store at once (above,
/// on [`STORE_CODE_LEN`]), so the escape hatch would be for a
/// case that does not realistically occur, and a seller who does meet it is
/// told plainly rather than silently failing (the UI's "already claimed by a
/// different key").
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreParameters {
    /// The store code: a prefix of the base58 store key.
    ///
    /// `pub(crate)` on purpose -- see [`StoreParameters::new`].
    ///
    /// The contract does not insist on [`STORE_CODE_LEN`] characters, only on
    /// a non-empty code the owner's key begins with. A shorter code is a
    /// different address that no link names: [`StoreParameters::new`] and
    /// [`StoreParameters::from_code`] are the only constructors, and both
    /// produce exactly [`STORE_CODE_LEN`]. Accepting any length is what lets
    /// the production contract's merge be checked with two keys that really
    /// do share a code (ground to a two-character code; sixteen cannot be
    /// ground), rather than with a test-only build.
    pub(crate) store_code: String,
}

impl StoreParameters {
    /// The only way to build these parameters from a store key.
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
    /// ever published, at an address it never had. And it changed shape again
    /// for harvest#52, from the whole key to a code, which is why
    /// `ui/src/migrate.rs` now derives every generation up to V16 under a
    /// frozen copy of the whole-key encoding.
    ///
    /// Private fields are what actually holds it: a second derivation outside
    /// this crate does not compile.
    pub fn new(store_verifying_key: VerifyingKey) -> Self {
        Self {
            store_code: store_code(&store_verifying_key),
        }
    }

    /// Parameters for a store code read from a link.
    ///
    /// `None` unless `code` is exactly [`STORE_CODE_LEN`] base58 characters.
    /// A code of any other length is refused rather than trimmed or padded:
    /// it names a different address, and a typo in a shared link should open
    /// nothing, not something else.
    pub fn from_code(code: &str) -> Option<Self> {
        if code.len() != STORE_CODE_LEN || !code.chars().all(|c| BASE58_ALPHABET.contains(c)) {
            return None;
        }
        Some(Self {
            store_code: code.to_string(),
        })
    }

    /// A test-only constructor for a code of any length, so merge laws can be
    /// exercised with two keys that genuinely share one. See the field docs.
    #[cfg(test)]
    pub(crate) fn with_code_for_test(code: &str) -> Self {
        Self {
            store_code: code.to_string(),
        }
    }

    /// The store code these parameters carry.
    pub fn code(&self) -> &str {
        &self.store_code
    }

    /// Whether `owner` may own the store at this address: its base58
    /// encoding begins with this code.
    ///
    /// An empty code admits nobody. It would admit everybody, which is not a
    /// store any link can name, and refusing it costs nothing.
    pub fn admits(&self, owner: &VerifyingKey) -> bool {
        !self.store_code.is_empty()
            && bs58::encode(owner.as_bytes())
                .into_string()
                .starts_with(&self.store_code)
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
    /// Optional store description, rendered as markdown (see the UI's
    /// `markdown` module for the subset).
    pub description: String,
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
    /// `wire_compat_tests::a_store_info_re_encodes_to_its_signed_bytes_but_for_the_removed_field`,
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
    /// The store's record (blind-signing RSA) public key, PKCS#1 DER, derived
    /// from the store key (harvest#93 phase 1b,
    /// `custody::record_public_key_der`).
    ///
    /// Published so every device holding the store key can CHECK its own
    /// derivation against it rather than trust it silently: RSA key
    /// generation is not a function the `rsa` crate promises to keep stable,
    /// so a crate bump could derive a different key from the same seed, and
    /// the record contract's address depends on it. `None` for a store
    /// published before this existed. Skipped when absent for the reason
    /// `encryption_public_key` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_public_key: Option<Vec<u8>>,
}

/// Store info signed by the store key (harvest#93; by the seller's Ghost Key
/// before revision 2).
///
/// Uses the ScopedPayload envelope the Ghost Key vault's `SignResult` uses,
/// which the Harvest delegate builds for the store key
/// ([`crate::backing::sign_with_store_key`]): the signature is over the
/// CBOR-encoded ScopedPayload, which wraps the CBOR-encoded StoreInfoV1 as its
/// payload.
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
                encryption_public_key: None,
                record_public_key: None,
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
        parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Result<(), String> {
        // Version 0 is "no details published", and it must be exactly the
        // default. Nothing signs a version-0 info, so skipping verification
        // for it (as this did until the PR #82 re-review) let anyone put a
        // name, a certificate and an encryption key into a store whose
        // seller had not published yet -- and since `apply_delta` ignores an
        // incoming version that is not higher, two such injections never
        // converged.
        if self.info.version == 0 {
            return if *self == Self::default() {
                Ok(())
            } else {
                Err("store info at version 0 must be empty: nothing signs it".into())
            };
        }
        verify_scoped_signature(
            &self.scoped_payload,
            &self.signature,
            owner_key(parent_state)?,
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
        parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        if let Some(new_info) = delta {
            if new_info.info.version <= self.info.version {
                return Ok(()); // stale update, ignore
            }
            verify_scoped_signature(
                &new_info.scoped_payload,
                &new_info.signature,
                owner_key(parent_state)?,
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

impl ListingsV1 {
    /// Put the listings in the canonical form `verify` requires: sorted by id,
    /// no id twice.
    ///
    /// `apply_delta` calls this, but the scaffold does not call `apply_delta`
    /// at all when a merge brings nothing new, so the two places that can hold
    /// a state nothing verified call it directly as well: the contract's
    /// `update_state`, before it encodes its result, and the migration fold,
    /// whose base may be a predecessor's state written under the old,
    /// permissive `verify` (harvest#26). A stable sort keeps the first of two
    /// equal ids, which is the one already held.
    pub fn normalize(&mut self) {
        self.listings
            .sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        self.listings.dedup_by(|a, b| a.listing.id == b.listing.id);
    }
}

impl freenet_scaffold::ComposableState for ListingsV1 {
    type ParentState = StoreStateV1;
    type Summary = Vec<ListingId>;
    type Delta = Vec<AuthorizedListing>;
    type Parameters = StoreParameters;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Result<(), String> {
        for authorized in &self.listings {
            authorized.verify(owner_key(parent_state)?)?;
        }
        // Canonical form: strictly ascending by id, which also means no id
        // twice. `apply_delta` only ever produces this, but a state can reach
        // a peer whole (a PUT, or `UpdateData::State`), and one that arrived
        // unsorted or with a duplicate used to verify -- so two peers holding
        // the same set of listings could hold different bytes and never agree
        // (harvest#26).
        //
        // Rejecting in `verify` is safe here only because of the re-key: the
        // new contract starts empty, and the migration fold builds its state
        // through `apply_delta`, which normalises (see below), so no state
        // this generation holds was written by the old, permissive code.
        for pair in self.listings.windows(2) {
            if pair[0].listing.id >= pair[1].listing.id {
                return Err(format!(
                    "listings are not strictly ascending by id (unsorted, or listing {} \
                     twice)",
                    pair[1].listing.id
                ));
            }
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
        parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
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
                listing.verify(owner_key(parent_state)?)?;
                to_add.push(listing.clone());
            }
            self.listings.extend(to_add);
        }

        self.normalize();
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
///
/// The full 32 bytes (PR #82 review, Should Fix 4). It was truncated to 8,
/// and two same-rank variants of one order whose truncated digests collide
/// -- about 2^32 work for a birthday search -- read as the same record in
/// each other's summaries, so the two peers holding them never exchanged
/// them. Widening it was free during this re-key.
fn order_content_digest(record: &AuthorizedOrder) -> [u8; 32] {
    // Infallible: `AuthorizedOrder` and everything it contains derives
    // `Serialize` over plain data (no custom fallible encoding), so CBOR
    // serialization of an in-memory value here cannot fail.
    let bytes = crate::to_cbor(record).expect("AuthorizedOrder always serializes to CBOR");
    *blake3::hash(&bytes).as_bytes()
}

/// Merge one already-verified incoming order record into `orders`.
///
/// Keeps whichever of the existing and incoming record has the higher
/// [`crate::payment::OrderStatus::rank`]. On an exact rank tie -- which happens when two
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

/// Drop the oldest orders if `orders` is over [`MAX_ORDERS`].
///
/// Keeps the `MAX_ORDERS` orders with the newest `Order::created_at`, with the
/// id as a tie-break so the order is total. Both come from the order's signed
/// TERMS, which `OrderId` is derived from, so every version of one order ranks
/// the same however far its status has moved.
///
/// # Why status takes no part (harvest#85)
///
/// This used to drop terminal orders (`Cancelled`, `PaymentReversed`) before
/// active ones. That made the merge non-associative, which `fdev
/// verify-merge` found. Terminal-ness is not monotone in the status rank
/// `merge_order` maximises (Awaiting 0 active, Cancelled 1 terminal, Paid 2
/// active, Reversed 3 terminal), so an order's keep-priority changed as it
/// merged. And a key pruned on one peer came back from a peer that still held
/// an older version of it, at a different priority. With P = {x Awaiting,
/// newest}, Q = {x Cancelled} and R = a full cap of older orders, `(P+Q)+R`
/// dropped x while `P+(Q+R)` kept it.
///
/// Top-N over a ranking that the per-key merge cannot change is associative:
/// a key cut from one side ranks below that side's N-th key, so it ranks below
/// the N-th key of any union containing that side and is cut again, whichever
/// version of it comes back. So is a key kept: if it is in the top N of the
/// union it was in the top N of each side that held it, so no side's version
/// of it was lost to that side's own cap. Pinned by
/// `the_order_cap_is_associative_when_a_status_changes_at_the_cap` and
/// `the_order_cap_obeys_the_merge_laws_at_the_cap`.
///
/// What it costs: an old `Paid` order can now be dropped before a newer
/// `Cancelled` one. Only the seller can sign an order, so only the seller can
/// push old orders out, by creating more than `MAX_ORDERS` new ones.
fn enforce_order_cap(orders: &mut BTreeMap<OrderId, AuthorizedOrder>) {
    if orders.len() <= MAX_ORDERS {
        return;
    }
    let mut ranked: Vec<(i64, OrderId)> = orders
        .iter()
        .map(|(id, record)| (record.order.created_at.timestamp_millis(), id.clone()))
        .collect();
    // Ascending, so the oldest come first and are the ones dropped below.
    ranked.sort();
    let excess = orders.len() - MAX_ORDERS;
    for (_, id) in ranked.into_iter().take(excess) {
        orders.remove(&id);
    }
}

/// 32 bytes that encode as ONE CBOR byte string rather than serde's default
/// for `[u8; 32]`, which is an array of 32 integers.
///
/// Used for the order summary's id and digest (PR #82 re-review). The summary
/// carries one entry per order, up to `MAX_ORDERS`, and is sent on every
/// exchange; as integer arrays each 32-byte value cost about 50 bytes on the
/// wire, and a byte string costs 34. Only the summary uses it: `OrderId`
/// itself keeps its encoding, because it is inside every signed order and
/// changing it would move every order's id and signature preimage.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Bytes32(pub [u8; 32]);

impl Serialize for Bytes32 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Bytes32;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a 32-byte byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Bytes32, E> {
                <[u8; 32]>::try_from(v)
                    .map(Bytes32)
                    .map_err(|_| E::invalid_length(v.len(), &self))
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

/// The set of orders placed against this store, keyed by [`OrderId`].
///
/// # Merge model
///
/// This is neither grow-only (like a claim set) nor last-writer-wins by an
/// explicit version counter (like [`AuthorizedStoreInfoV1`]). It is a
/// **per-key monotonic maximum on [`crate::payment::OrderStatus::rank`]**, the same shape as
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
    /// number of bytes. At 70 encoded bytes an entry (a 32-byte id and a
    /// 32-byte digest as CBOR byte strings, see [`Bytes32`], plus a 1-byte
    /// rank) this is still tiny next to a single order's own
    /// encoded size once it carries an `OrderPaymentProof` -- an order can
    /// run into the hundreds of bytes to multiple KB; a summary entry never
    /// does.
    type Summary = Vec<(Bytes32, u8, Bytes32)>;
    /// Full replacement records for whichever orders are new, ahead in rank,
    /// or -- at an exact rank tie -- differ in content (see `delta`).
    type Delta = Vec<AuthorizedOrder>;
    type Parameters = StoreParameters;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
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
                .verify(owner_key(parent_state)?)
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
                    Bytes32(id.0),
                    record.status.rank(),
                    Bytes32(order_content_digest(record)),
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
        let old: BTreeMap<[u8; 32], (u8, [u8; 32])> = old_state_summary
            .iter()
            .map(|(id, rank, digest)| (id.0, (*rank, digest.0)))
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
                match old.get(&id.0) {
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
        parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
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
                .verify(owner_key(parent_state)?)
                .map_err(|e| format!("order {} delta invalid: {e}", record.order.id))?;
        }
        for record in incoming {
            merge_order(&mut self.orders, record.clone());
        }
        enforce_order_cap(&mut self.orders);
        Ok(())
    }
}

/// The key a store's records are verified against: its owner.
///
/// Every child of [`StoreStateV1`] verifies through this, so a store with no
/// owner can hold nothing that needs a signature -- which is everything but
/// the empty default.
pub(crate) fn owner_key(parent: &StoreStateV1) -> Result<&VerifyingKey, String> {
    parent.owner.as_ref().ok_or_else(|| {
        "this store has no owner yet, so nothing in it can be verified: a store's first \
         signed record has to name the key that signed it"
            .to_string()
    })
}

/// Whether `a` wins a store address over `b`: the smaller key, by its bytes.
///
/// See [`StoreStateV1`] for why the rule is a total order on keys rather than
/// "whoever claimed first".
fn outranks(a: &VerifyingKey, b: &VerifyingKey) -> bool {
    a.as_bytes() < b.as_bytes()
}

/// A store's whole state.
///
/// # The owner, and binding a store to one key (harvest#52)
///
/// [`StoreParameters`] carry only a [`STORE_CODE_LEN`]-character prefix of
/// the store key, so the address alone does not say whose store it is.
/// The state does: [`StoreStateV1::owner`] is the full key, it must begin
/// with the code ([`StoreParameters::admits`]), and every record the store
/// holds -- its details, listings, orders, and the acceptance of each backing,
/// each retirement and the closure -- is verified against it. An
/// owner therefore arrives only alongside something it signed; a state that
/// names an owner and holds nothing it signed is refused, because a key alone
/// proves nothing (anyone can write down a curve point that begins with a
/// given code -- the cost of a code (see [`STORE_CODE_LEN`]) is the cost of a KEYPAIR, which
/// only a signature demonstrates).
///
/// # Two keys, one code: why the smaller key wins, and not the first
///
/// Delta binds a site to its first claimant and refuses any other key
/// (`SiteState::merge`). That is not convergent. "First" is not a property of
/// a state; it is an arrival order, and arrival orders differ between peers.
/// Let two keys that share a code each publish before either has seen the
/// other: every peer keeps whichever reached it first and refuses the other
/// forever, so the network splits into two stores at one address and never
/// agrees again.
///
/// So the merge here picks by a total order that every peer computes the
/// same way from the states alone: **the owner whose key bytes are smaller
/// wins the address, and the other owner's records are dropped.** With one
/// owner, the merge is the ordinary per-record one below. That is the
/// lexicographic product of a chain (owners, smallest first) with each
/// owner's own join-semilattice, which is itself a join-semilattice: the
/// result of merging any set of states is "the smallest owner among them,
/// with the join of that owner's records", whatever the order or grouping.
/// That holds for honestly signed content: the per-owner merge itself still
/// has the known unsigned-field tie cases recorded as harvest#81, and this
/// rule neither fixes nor worsens them. Pinned by `claim_tests`, and checked
/// on the built contract with `fdev verify-merge` over states that include
/// two and three owners sharing a code.
///
/// A delta between owners is everything the winner holds, measured against
/// the empty store. But a delta that was computed against a summary of the
/// SAME owner can arrive at a replica that has meanwhile switched to a
/// different, outranked owner; the replica then switches to the incoming
/// owner holding only the records in that delta, a subset of the winner's
/// store, until the next summary exchange sends it the rest. Transient, and
/// it needs two keys sharing a code to happen at all.
///
/// What it costs, stated plainly: a key with a smaller encoding that shares a
/// seller's code takes the address even after the seller has published, and
/// the seller's records stop being served. That is the same attack as
/// pre-empting a seller who has not published yet, at the same price -- a
/// keypair sharing a 16-character code, half of which rank below any given
/// key: about 2^95 for one chosen seller, about 2^81 to hit one of 10,000
/// (see [`STORE_CODE_LEN`] for why the second figure is the one that
/// matters) -- so the
/// rule adds no attack that a first-writer rule would have prevented, and it
/// is the only one of the two that converges. A seller whose address is held
/// by another key is told so, loudly (the UI's "already claimed by a
/// different key"); see the decision on harvest#52 for why there is no second
/// address to move to.
///
/// # The owner is the store key (harvest#93)
///
/// Since revision 2 the owner is the store's own key, not a Ghost Key. It
/// signs the details, listings and orders, and it accepts every backing. A
/// Ghost Key's only statement about a store is its backing, held in
/// [`StoreStateV1::backings`]; see [`crate::backing`].
///
/// # What is NOT bound here
///
/// Whether the store is backed by a Ghost Key whose certificate holds up,
/// which one is current, and whether that key also backs another store. Those
/// are reader rules ([`crate::backing::current_backing`] and
/// `ui/src/ghostkey_cert.rs`), because a certificate chain and another store's
/// state are not this contract's to check.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct StoreStateV1 {
    /// The store's owner, or `None` for a store nobody has published to.
    ///
    /// `#[serde(default)]` so the migration fold can decode a predecessor
    /// generation's state, which had no owner field: those were addressed by
    /// the whole key, and the fold names that key as their owner. A state
    /// with content and no owner never verifies here.
    #[serde(default)]
    pub owner: Option<VerifyingKey>,
    pub info: AuthorizedStoreInfoV1,
    pub listings: ListingsV1,
    /// `#[serde(default)]` so store states written before orders existed
    /// still decode; they come back with no orders, which is what they had.
    ///
    /// Not optional: V1 (`legacy/store_contract.toml`, code hash
    /// `4d7ad3c3...`) is the only generation ever deployed, and its state has
    /// no `orders` key at all. `OrdersV1` derives `Default`, but serde does
    /// not consult `Default` for a missing field without this attribute --
    /// so without it every real V1 state fails to decode with "missing field
    /// `orders`", and the migration probe cannot tell that from an address
    /// that was never written.
    #[serde(default)]
    pub orders: OrdersV1,
    /// Every Ghost Key that has ever backed this store, with the store key's
    /// acceptance of each (harvest#93). Grow-only: the contract refuses to
    /// drop one. See [`crate::backing`].
    ///
    /// `default` so a state written before backings existed still decodes,
    /// and `skip_serializing_if` so a state holding none encodes exactly as
    /// it did then: `validate_state` requires a state to re-encode to its own
    /// bytes, and an empty map written out would be bytes no earlier state
    /// had.
    #[serde(
        default,
        skip_serializing_if = "SignedSetV1::<AuthorizedBacking>::is_empty"
    )]
    pub backings: BackingsV1,
    /// Every retirement of a backing key, signed by the store key. Grow-only,
    /// like `backings`, and serialized the same way for the same reason.
    #[serde(
        default,
        skip_serializing_if = "SignedSetV1::<AuthorizedRetirement>::is_empty"
    )]
    pub retirements: RetirementsV1,
    /// The closed flag: empty, or the store key's signed closure. One-way.
    #[serde(
        default,
        skip_serializing_if = "SignedSetV1::<AuthorizedClosure>::is_empty"
    )]
    pub closed: ClosedV1,
    /// The store key, wrapped to each backing Ghost Key, one copy per
    /// (backer, webapp scope), each signed by the store key (harvest#93
    /// phase 1b). A copy is kept exactly while its backer holds a backing
    /// that is not retired: the retirement is the tombstone. See
    /// [`crate::custody`] and [`StoreStateV1::normalize_backings`].
    #[serde(
        default,
        skip_serializing_if = "SignedSetV1::<crate::custody::AuthorizedCopy>::is_empty"
    )]
    pub copies: crate::custody::CopiesV1,
}

/// What a peer tells another it already holds. See [`StoreStateV1::delta`].
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreStateV1Summary {
    /// Whose records the rest of the summary describes. A holder of a
    /// different owner's records needs all of ours or none of them, never a
    /// difference against records of another key.
    pub owner: Option<VerifyingKey>,
    pub info: <AuthorizedStoreInfoV1 as ComposableState>::Summary,
    pub listings: <ListingsV1 as ComposableState>::Summary,
    pub orders: <OrdersV1 as ComposableState>::Summary,
    /// `default` and skipped when empty, so a summary of a store with no
    /// backings is byte-for-byte what it was before they existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backings: <BackingsV1 as ComposableState>::Summary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retirements: <RetirementsV1 as ComposableState>::Summary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub closed: <ClosedV1 as ComposableState>::Summary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub copies: <crate::custody::CopiesV1 as ComposableState>::Summary,
}

/// An update to a store: one `Option` per part, plus the owner whose records
/// they are.
///
/// Field-for-field the shape `#[composable]` used to generate, with `owner`
/// added, so a delta carrying only listings is still
/// `{owner, info: None, listings: Some(..), orders: None}` and never the bare
/// inner `Vec` (see `ui/src/gateway/store_ops.rs` for what that mistake cost).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct StoreStateV1Delta {
    /// The key every record in this delta is signed by.
    ///
    /// `None` is accepted and means "the owner already held", so a delta can
    /// never CLAIM a store without naming who is claiming it.
    pub owner: Option<VerifyingKey>,
    pub info: Option<<AuthorizedStoreInfoV1 as ComposableState>::Delta>,
    pub listings: Option<<ListingsV1 as ComposableState>::Delta>,
    pub orders: Option<<OrdersV1 as ComposableState>::Delta>,
    /// `default` and skipped when absent, so a delta carrying none of the
    /// revision-2 parts encodes exactly as it did before they existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backings: Option<<BackingsV1 as ComposableState>::Delta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirements: Option<<RetirementsV1 as ComposableState>::Delta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed: Option<<ClosedV1 as ComposableState>::Delta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copies: Option<<crate::custody::CopiesV1 as ComposableState>::Delta>,
}

impl StoreStateV1 {
    /// Whether the store holds anything its owner signed.
    ///
    /// Details at version 0 are the unsigned default (`verify` requires it),
    /// so only a published version counts.
    pub fn holds_signed_content(&self) -> bool {
        self.info.info.version > 0
            || !self.listings.listings.is_empty()
            || !self.orders.orders.is_empty()
            || !self.backings.is_empty()
            || !self.retirements.is_empty()
            || !self.closed.is_empty()
            || !self.copies.is_empty()
    }

    /// Apply the store-wide bound on backings and retirements (harvest#93
    /// review, Must Fix 1, and the #98 merge-law re-check).
    ///
    /// Ranks ONE set of slots, every Ghost Key that has a backing or a
    /// retirement here, keeps the [`crate::backing::MAX_BACKINGS`] smallest
    /// by bytes, and keeps a backing or a retirement exactly when its slot
    /// is kept. A retirement need not name a backing this replica holds.
    /// Never fails, so no merge of valid states fails, and it touches
    /// nothing but these two sets: the closed flag, the details, listings
    /// and orders in the same update always land.
    ///
    /// # Why this is a merge rather than a refusal
    ///
    /// It used to be a refusal: past the bound `apply_delta` returned an
    /// error, which took the whole update down with it (a closure and a
    /// listing riding in the same delta included), and left two replicas
    /// each refusing the other for good. `fdev verify-merge` files a
    /// contract error as "inconclusive", not as a violation, which is how it
    /// passed.
    ///
    /// # Why one slot set, and not "a retirement needs its backing"
    ///
    /// The previous version kept backings by rank and then dropped every
    /// retirement whose backing was not held. That depends on arrival
    /// order: a retirement of X arriving before X's backing was dropped,
    /// and the backing, arriving next, stood unretired, while the other
    /// order kept X retired. Deltas computed against a stale summary deliver
    /// exactly that order, and the sender never resends, so a key was
    /// un-retired for good (`fdev`'s `delta_permutation_invariance`, 18
    /// violations over `store-r98race` and `store-r98retire`).
    ///
    /// # Why it obeys the merge laws, in any arrival order
    ///
    /// The ranking depends on the slot alone, never on which record a slot
    /// holds, and the kept set is the top N of the union of every slot seen,
    /// which is associative, commutative and idempotent: a slot cut from one
    /// side ranks below that side's N-th slot, so it ranks below the N-th
    /// slot of any union containing that side and is cut again. A backing
    /// and a retirement for one key share a slot, so they are kept or cut
    /// together, whichever arrived first.
    ///
    /// # Why nothing is ever un-retired
    ///
    /// A retirement is dropped only when its slot is cut, and a cut slot
    /// never ranks back in, so its backing cannot return either.
    pub(crate) fn normalize_backings(&mut self) {
        let max = crate::backing::MAX_BACKINGS;
        let slots = self.backing_slots();
        if slots.len() > max {
            let cut: BTreeSet<Bytes32> = slots.into_iter().skip(max).collect();
            for slot in &cut {
                self.backings.records.remove(slot);
                self.retirements.records.remove(slot);
            }
            self.copies
                .records
                .retain(|_, copy| !cut.contains(&Bytes32(copy.copy.backer.to_bytes())));
        }
        self.normalize_copies();
    }

    /// Every Ghost Key with a backing, a retirement or a wrapped copy here,
    /// smallest first:
    /// the slots [`Self::normalize_backings`] ranks.
    fn backing_slots(&self) -> BTreeSet<Bytes32> {
        self.backings
            .records
            .keys()
            .chain(self.retirements.records.keys())
            .copied()
            .chain(
                self.copies
                    .records
                    .values()
                    .map(|copy| Bytes32(copy.copy.backer.to_bytes())),
            )
            .collect()
    }

    /// Keep a wrapped copy of the store key unless its backer is retired, at
    /// most [`crate::custody::MAX_SCOPES_PER_BACKER`] per backer (the
    /// smallest scopes), and only while its backer's slot survives the bound
    /// in [`Self::normalize_backings`] (harvest#93 phase 1b).
    ///
    /// The retirement is the custody tombstone (section 6.3, check 4): one
    /// signed act stops a key being current and stops it recovering the store
    /// key from state, and a copy written under a new scope after the
    /// retirement, or arriving late from a stale peer, is dropped here.
    ///
    /// A copy need not name a backing this replica holds: it may arrive
    /// before its backing, and is kept either way, for the same reason a
    /// retirement is (the #98 merge-law re-check): a rule keyed on what else
    /// happened to arrive first depends on arrival order. The copy's backer
    /// takes a slot in the bound like a backing or a retirement does.
    ///
    /// Total and associative in any arrival order: the slot bound is top-N
    /// over the union of slots; the retired filter depends only on the
    /// retirements, which share their slots with the copies they drop; and
    /// the per-backer bound is top-N over scope bytes, which the per-slot
    /// merge cannot change, because a copy's slot IS its (backer, scope).
    fn normalize_copies(&mut self) {
        let retirements = &self.retirements.records;
        self.copies.records.retain(|_, copy| {
            !retirements.contains_key(&Bytes32(copy.copy.backer.to_bytes()))
        });
        let mut by_backer: BTreeMap<[u8; 32], Vec<(crate::custody::WrapScope, Bytes32)>> =
            BTreeMap::new();
        for (slot, copy) in &self.copies.records {
            by_backer
                .entry(copy.copy.backer.to_bytes())
                .or_default()
                .push((copy.copy.scope, *slot));
        }
        for (_, mut scopes) in by_backer {
            if scopes.len() > crate::custody::MAX_SCOPES_PER_BACKER {
                scopes.sort();
                for (_, slot) in scopes
                    .into_iter()
                    .skip(crate::custody::MAX_SCOPES_PER_BACKER)
                {
                    self.copies.records.remove(&slot);
                }
            }
        }
    }

    /// The parent the children are verified under. They read the owner and
    /// nothing else, so this is all of `self` they need -- and cloning a
    /// whole store, up to [`MAX_ORDERS`] orders with their payment proofs,
    /// three times per update to hand each child its parent, bought nothing.
    fn owner_only(&self) -> Self {
        Self {
            owner: self.owner,
            ..Default::default()
        }
    }

    /// Apply a delta's parts under the owner already in `self`, all or
    /// nothing.
    fn apply_parts(
        &mut self,
        parameters: &StoreParameters,
        delta: &StoreStateV1Delta,
    ) -> Result<(), String> {
        let parent = self.owner_only();
        let mut next = self.clone();
        next.info.apply_delta(&parent, parameters, &delta.info)?;
        next.listings
            .apply_delta(&parent, parameters, &delta.listings)?;
        next.orders
            .apply_delta(&parent, parameters, &delta.orders)?;
        next.backings
            .apply_delta(&parent, parameters, &delta.backings)?;
        next.retirements
            .apply_delta(&parent, parameters, &delta.retirements)?;
        next.closed
            .apply_delta(&parent, parameters, &delta.closed)?;
        next.copies
            .apply_delta(&parent, parameters, &delta.copies)?;
        next.normalize_backings();
        *self = next;
        Ok(())
    }
}

impl ComposableState for StoreStateV1 {
    type ParentState = StoreStateV1;
    type Summary = StoreStateV1Summary;
    type Delta = StoreStateV1Delta;
    type Parameters = StoreParameters;

    fn verify(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Result<(), String> {
        match &self.owner {
            Some(owner) => {
                if !parameters.admits(owner) {
                    return Err(format!(
                        "the store's owner key {} does not begin with this store's code {}",
                        bs58::encode(owner.as_bytes()).into_string(),
                        parameters.code()
                    ));
                }
                if !self.holds_signed_content() {
                    return Err(
                        "a store that names an owner must hold something that owner \
                                signed: a key alone proves nothing"
                            .into(),
                    );
                }
            }
            None => {
                if self.holds_signed_content() {
                    return Err("a store with no owner cannot hold signed records".into());
                }
            }
        }
        let parent = self.owner_only();
        self.info.verify(&parent, parameters)?;
        self.listings.verify(&parent, parameters)?;
        self.orders.verify(&parent, parameters)?;
        // The store-wide rule `normalize_backings` keeps: at most
        // `MAX_BACKINGS` Ghost Keys with a backing, a retirement or a wrapped
        // copy. A state
        // that breaks it is one no merge produces. A retirement need not
        // name a held backing (see `normalize_backings`).
        let slots = self.backing_slots().len();
        if slots > crate::backing::MAX_BACKINGS {
            return Err(format!(
                "store holds backings or retirements for {slots} Ghost Keys, the most it keeps \
                 is {}",
                crate::backing::MAX_BACKINGS
            ));
        }
        // Every wrapped copy is for a backer that is not retired, and no
        // backer has more than `MAX_SCOPES_PER_BACKER` (see
        // `normalize_copies`). A copy need not name a held backing.
        let mut per_backer: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        for copy in self.copies.records.values() {
            let backer = Bytes32(copy.copy.backer.to_bytes());
            if self.retirements.records.contains_key(&backer) {
                return Err(
                    "a wrapped copy of the store key is for a Ghost Key whose backing is retired"
                        .into(),
                );
            }
            let n = per_backer.entry(backer.0).or_default();
            *n += 1;
            if *n > crate::custody::MAX_SCOPES_PER_BACKER {
                return Err(format!(
                    "a Ghost Key has more than {} wrapped copies of the store key",
                    crate::custody::MAX_SCOPES_PER_BACKER
                ));
            }
        }
        self.copies.verify(&parent, parameters)?;
        self.backings.verify(&parent, parameters)?;
        self.retirements.verify(&parent, parameters)?;
        self.closed.verify(&parent, parameters)
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
    ) -> Self::Summary {
        let parent = self.owner_only();
        StoreStateV1Summary {
            owner: self.owner,
            info: self.info.summarize(&parent, parameters),
            listings: self.listings.summarize(&parent, parameters),
            orders: self.orders.summarize(&parent, parameters),
            backings: self.backings.summarize(&parent, parameters),
            retirements: self.retirements.summarize(&parent, parameters),
            closed: self.closed.summarize(&parent, parameters),
            copies: self.copies.summarize(&parent, parameters),
        }
    }

    /// What the holder of `old_state_summary` is missing.
    ///
    /// * We hold no owner: nothing, since an unowned store holds no records.
    /// * Same owner: the ordinary per-part difference.
    /// * The requester holds an owner that outranks ours: nothing. Our
    ///   records are the ones that lose.
    /// * The requester holds no owner, or one ours outranks: EVERYTHING,
    ///   measured against the empty store, because the requester is about to
    ///   drop what it holds and start again from ours. A difference against
    ///   another key's records would leave it holding a subset.
    fn delta(
        &self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        old_state_summary: &Self::Summary,
    ) -> Option<Self::Delta> {
        let owner = self.owner?;
        let empty;
        let base = match &old_state_summary.owner {
            Some(theirs) if *theirs == owner => old_state_summary,
            Some(theirs) if outranks(theirs, &owner) => return None,
            _ => {
                empty = Self::default().summarize(&Self::default(), parameters);
                &empty
            }
        };
        let parent = self.owner_only();
        let delta = StoreStateV1Delta {
            owner: Some(owner),
            info: self.info.delta(&parent, parameters, &base.info),
            listings: self.listings.delta(&parent, parameters, &base.listings),
            orders: self.orders.delta(&parent, parameters, &base.orders),
            backings: self.backings.delta(&parent, parameters, &base.backings),
            retirements: self
                .retirements
                .delta(&parent, parameters, &base.retirements),
            closed: self.closed.delta(&parent, parameters, &base.closed),
            copies: self.copies.delta(&parent, parameters, &base.copies),
        };
        if delta.info.is_none()
            && delta.listings.is_none()
            && delta.orders.is_none()
            && delta.backings.is_none()
            && delta.retirements.is_none()
            && delta.closed.is_none()
            && delta.copies.is_none()
        {
            None
        } else {
            Some(delta)
        }
    }

    /// Apply a delta, deciding first whose records the store holds.
    ///
    /// All or nothing: on an error `self` is unchanged.
    fn apply_delta(
        &mut self,
        _parent_state: &Self::ParentState,
        parameters: &Self::Parameters,
        delta: &Option<Self::Delta>,
    ) -> Result<(), String> {
        let Some(delta) = delta else {
            return Ok(());
        };
        let Some(incoming) = delta.owner else {
            // No owner named: the records are verified against the owner
            // already held, and against nobody if there is none, which fails.
            return self.apply_parts(parameters, delta);
        };
        if !parameters.admits(&incoming) {
            return Err(format!(
                "an update names owner {}, which does not begin with this store's code {}",
                bs58::encode(incoming.as_bytes()).into_string(),
                parameters.code()
            ));
        }
        match self.owner {
            Some(held) if held == incoming => self.apply_parts(parameters, delta),
            // The owner held outranks the one this delta speaks for, so its
            // records are another key's and are not ours to take. Not an
            // error: an error is not a merge, and the result has to be the
            // same whichever way round two peers exchange their states.
            Some(held) if outranks(&held, &incoming) => Ok(()),
            // Nobody holds the address, or the incoming owner outranks the
            // one who does: start again from nothing under the incoming owner.
            _ => {
                let mut claimed = Self {
                    owner: Some(incoming),
                    ..Default::default()
                };
                claimed.apply_parts(parameters, delta)?;
                if !claimed.holds_signed_content() {
                    return Err("an update that claims a store must carry something its \
                                owner signed"
                        .into());
                }
                *self = claimed;
                Ok(())
            }
        }
    }
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

    use crate::payment::{Order, OrderPaymentProof, OrderStatus};

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
        StoreParameters::new(seller.verifying_key())
    }

    /// The parent a child part is verified under: a store owned by the test
    /// seller. The parts read their owner from it.
    fn parent() -> StoreStateV1 {
        StoreStateV1 {
            owner: Some(seller_key().verifying_key()),
            ..Default::default()
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

    /// The block every test order is anchored to: one below the lowest
    /// height any fixture here confirms a payment at (100), so each fixture
    /// payment reads as made AFTER its order, which is what an honest buyer's
    /// payment always is. `verify_on_chain_proof` refuses a payment at or
    /// below the anchor (harvest#77); the tests that exercise that boundary
    /// set their own anchor rather than moving this one.
    const ORDER_ANCHOR_HEIGHT: u32 = 99;

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
            anchor: Some(BlockAnchor {
                height: ORDER_ANCHOR_HEIGHT,
                hash: BlockHash([0x99; 32]),
            }),
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
            state.verify(&parent(), &p).is_ok(),
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
            state.verify(&parent(), &p).is_ok(),
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
            .verify(&parent(), &p)
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
            .verify(&parent(), &p)
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
            .verify(&parent(), &p)
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
            .verify(&parent(), &p)
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
            .verify(&parent(), &p)
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
            .verify(&parent(), &p)
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
            .verify(&parent(), &p)
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
            state.verify(&parent(), &p).is_ok(),
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
                .verify(&parent(), &p)
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
            state.verify(&parent(), &p).is_err(),
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
            .verify(&parent(), &p)
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
            state.verify(&parent(), &p).is_ok(),
            "KNOWN GAP: the contract accepts the curated proof as a paid order",
        );
    }

    // -----------------------------------------------------------------
    // A payment made before the order is not the order's payment
    //
    // harvest#77: a seller reinstalled Harvest, re-entered the same wallet
    // key, and was issued index 0 again. The new invoice named an address
    // that already held a confirmed payment for an old one, and settled
    // itself without anybody paying. These pin the rule that makes that
    // impossible, whatever the derivation index does.
    // -----------------------------------------------------------------

    /// `make_order`, anchored at `height` instead of [`ORDER_ANCHOR_HEIGHT`].
    fn order_anchored_at(height: u32) -> Order {
        let mut order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        order.anchor = Some(BlockAnchor {
            height,
            hash: BlockHash([0x42; 32]),
        });
        order.with_derived_id()
    }

    /// **The reported case.** The address already held a confirmed payment of
    /// the full amount, made hours before the order was signed. It must not
    /// settle the order, at the contract layer as well as in the proof.
    #[test]
    fn a_payment_that_confirmed_before_the_order_does_not_settle_it() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        // Paid at 100 for an earlier invoice; the new order is signed at 150.
        let order = order_anchored_at(150);
        let (old_payment, _) = confirmed_claim(&order, &bridge, order.amount_sats, 100);
        let proof =
            OrderPaymentProof::on_chain(vec![old_payment], signed_tip(&order, &bridge, 160));

        assert_eq!(
            crate::payment::verify_payment_proof(&order, &proof),
            Err(crate::payment::ProofError::PaymentPredatesOrder {
                confirmed_at: 100,
                order_anchor: 150,
            })
        );

        let record = make_authorized_order(&seller, order.clone(), OrderStatus::Paid, Some(proof));
        let state = orders_of([(order.id.clone(), record)]);
        assert!(
            state.verify(&parent(), &p).is_err(),
            "the store must refuse an order settled by a payment older than the order"
        );
    }

    /// **The boundary.** A payment in the anchor block itself predates the
    /// order: the seller signed after seeing that block, and the buyer only
    /// learned the address from the signed order. The next block is the
    /// earliest an honest payment can land, and it must still settle.
    #[test]
    fn a_payment_in_the_anchor_block_does_not_settle_but_the_next_block_does() {
        let bridge = bridge_key();
        let order = order_anchored_at(150);

        let (same_block, _) = confirmed_claim(&order, &bridge, order.amount_sats, 150);
        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(vec![same_block], signed_tip(&order, &bridge, 150)),
            ),
            Err(crate::payment::ProofError::PaymentPredatesOrder {
                confirmed_at: 150,
                order_anchor: 150,
            }),
            "a payment confirmed in the block the order was anchored to came before it"
        );

        let (next_block, _) = confirmed_claim(&order, &bridge, order.amount_sats, 151);
        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(vec![next_block], signed_tip(&order, &bridge, 151)),
            ),
            Ok(order.amount_sats),
            "a payment in the block after the anchor is exactly what an honest buyer produces"
        );
    }

    /// An old payment must not TOP UP a new one either. Here the address
    /// holds 50,000 from before the order and 30,000 after: the order is
    /// short, not paid. And when the new payment does cover the order, the
    /// value reported is the new payment's alone.
    #[test]
    fn an_old_payment_does_not_count_toward_a_new_order() {
        let bridge = bridge_key();
        let order = order_anchored_at(150);
        assert_eq!(order.amount_sats, 50_000);
        let tip = signed_tip(&order, &bridge, 160);

        let (old, _) = confirmed_claim(&order, &bridge, 50_000, 100);
        let (partial, _) = confirmed_claim(&order, &bridge, 30_000, 155);
        assert!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(vec![old.clone(), partial], tip.clone()),
            )
            .is_err(),
            "30,000 paid after the order is not 50,000, whatever arrived before it"
        );

        let (full, _) = confirmed_claim(&order, &bridge, 50_001, 155);
        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(vec![old, full], tip),
            ),
            Ok(50_001),
            "only the payment made after the order is this order's"
        );
    }

    /// Judged by the fold's WINNING confirmation. A bridge that briefly
    /// followed a stale fork can leave a claim placing the payment at or
    /// below the anchor; if the fold's current answer is a block inside the
    /// window, the payment settles. The earlier every-confirmation rule let
    /// such a claim veto an honest payment forever, while a dishonest
    /// submitter could simply omit it (PR #83 review, Should Fix 5).
    #[test]
    fn a_payment_is_judged_by_its_winning_confirmation() {
        let bridge = bridge_key();
        let order = order_anchored_at(150);

        // Stale-fork sighting at 148, current chain has it at 152.
        let (stale, outpoint) = confirmed_claim(&order, &bridge, order.amount_sats, 148);
        let retracted = retraction_claim(&order, &bridge, outpoint, 149);
        let (current, current_outpoint) = confirmed_claim(&order, &bridge, order.amount_sats, 152);
        assert_eq!(
            outpoint, current_outpoint,
            "one transaction, two placements"
        );

        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(
                    vec![stale, retracted, current],
                    signed_tip(&order, &bridge, 160),
                ),
            ),
            Ok(order.amount_sats),
            "the stale placement must not veto the payment the chain now holds"
        );
    }

    /// And the other way round: if the fold's current answer is at or below
    /// the anchor, an earlier in-window placement does not rescue it.
    #[test]
    fn a_winning_confirmation_before_the_anchor_does_not_settle() {
        let bridge = bridge_key();
        let order = order_anchored_at(150);

        // Seen at 152 first; a later bridge view (as_of 160) places it at 149.
        let (early_view, outpoint) =
            confirmed_claim_seen_from(&order, &bridge, order.amount_sats, 152, 152);
        let (later_view, later_outpoint) =
            confirmed_claim_seen_from(&order, &bridge, order.amount_sats, 149, 160);
        assert_eq!(outpoint, later_outpoint);

        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(
                    vec![early_view, later_view],
                    signed_tip(&order, &bridge, 170),
                ),
            ),
            Err(crate::payment::ProofError::PaymentPredatesOrder {
                confirmed_at: 149,
                order_anchor: 150,
            })
        );
    }

    /// **The upper edge.** A payment at the last block of the window settles;
    /// one block later does not.
    #[test]
    fn a_payment_after_the_window_does_not_settle() {
        use crate::payment::PAYMENT_WINDOW_BLOCKS;
        let bridge = bridge_key();
        let order = order_anchored_at(150);
        let last = 150 + PAYMENT_WINDOW_BLOCKS;

        let (on_time, _) = confirmed_claim(&order, &bridge, order.amount_sats, last);
        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(vec![on_time], signed_tip(&order, &bridge, last)),
            ),
            Ok(order.amount_sats)
        );

        let (late, _) = confirmed_claim(&order, &bridge, order.amount_sats, last + 1);
        assert_eq!(
            crate::payment::verify_payment_proof(
                &order,
                &OrderPaymentProof::on_chain(vec![late], signed_tip(&order, &bridge, last + 1)),
            ),
            Err(crate::payment::ProofError::PaymentAfterWindow {
                confirmed_at: last + 1,
                window_end: last,
            })
        );
    }

    /// **PR #83 review, Must Fix 1: one payment must not settle two orders.**
    /// An old unpaid order A and a new order B share an address (reissued a
    /// window or more later). B's buyer pays; B settles and A does not.
    #[test]
    fn a_new_orders_payment_does_not_settle_an_old_order_on_the_same_address() {
        use crate::payment::PAYMENT_WINDOW_BLOCKS;
        let bridge = bridge_key();
        let old = order_anchored_at(100);
        let new = order_anchored_at(100 + PAYMENT_WINDOW_BLOCKS);
        assert_eq!(old.payment_script_pubkey, new.payment_script_pubkey);

        let paid_at = 100 + PAYMENT_WINDOW_BLOCKS + 1;
        let (payment, _) = confirmed_claim(&new, &bridge, new.amount_sats, paid_at);
        let tip = signed_tip(&new, &bridge, paid_at);
        let proof = OrderPaymentProof::on_chain(vec![payment], tip);

        assert_eq!(
            crate::payment::verify_payment_proof(&new, &proof),
            Ok(new.amount_sats)
        );
        assert!(
            crate::payment::verify_payment_proof(&old, &proof).is_err(),
            "the new order's payment settled the old order too"
        );
    }

    /// KNOWN LIMIT, pinned so it is a decision rather than a surprise: two
    /// orders on one address whose windows OVERLAP are both settled by one
    /// payment in the overlap. Reaching it needs an address reissued within
    /// `PAYMENT_WINDOW_BLOCKS` of an unpaid order on it, past both the
    /// derivation recovery and the UI's address-contract check.
    #[test]
    fn known_limit_overlapping_windows_on_a_reused_address_both_settle() {
        let bridge = bridge_key();
        let old = order_anchored_at(100);
        let new = order_anchored_at(150);
        let (payment, _) = confirmed_claim(&new, &bridge, new.amount_sats, 151);
        let proof = OrderPaymentProof::on_chain(vec![payment], signed_tip(&new, &bridge, 160));

        assert!(crate::payment::verify_payment_proof(&new, &proof).is_ok());
        assert!(crate::payment::verify_payment_proof(&old, &proof).is_ok());
    }
    /// The reversal direction. A reorg that retracts an OLD payment on a
    /// reused address must not read as a reversal of the NEW order, which
    /// nobody has paid: `PaymentReversed` is permanent under merge and
    /// unsigned, so this would let anyone holding the old retraction poison
    /// the new order for good.
    #[test]
    fn a_retracted_pre_order_payment_cannot_reverse_a_new_order() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = order_anchored_at(150);

        let (old, outpoint) = confirmed_claim(&order, &bridge, order.amount_sats, 100);
        let retracted = retraction_claim(&order, &bridge, outpoint, 155);
        let proof =
            OrderPaymentProof::on_chain(vec![old, retracted], signed_tip(&order, &bridge, 160));

        assert_ne!(
            crate::payment::verify_payment_proof(&order, &proof),
            Err(crate::payment::ProofError::Reversed),
            "an old payment being reorged out is not this order's payment being reversed"
        );
        let record = make_authorized_order(
            &seller,
            order.clone(),
            OrderStatus::PaymentReversed,
            Some(proof),
        );
        assert!(
            orders_of([(order.id.clone(), record)])
                .verify(&parent(), &p)
                .is_err(),
            "the store must refuse a reversal built out of a payment older than the order"
        );
    }

    /// An on-chain order that names no anchor cannot be paid: without a block
    /// to measure against, no payment can be shown to have come after it.
    /// Every order the UI issues carries one, and a buyer refuses to pay one
    /// that does not, so this refuses nothing anybody would have paid.
    #[test]
    fn an_on_chain_order_without_an_anchor_cannot_be_paid() {
        let bridge = bridge_key();
        let mut order = make_order("buyer-1", 1_700_000_000, &[0x00, 0x14, 0xaa, 0xbb]);
        order.anchor = None;
        let order = order.with_derived_id();
        let proof = make_payment_proof(&order, &bridge, 1);
        assert_eq!(
            crate::payment::verify_payment_proof(&order, &proof),
            Err(crate::payment::ProofError::NoAnchor)
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
        a.merge(&parent(), &p, &b).unwrap();
        assert_eq!(
            a.orders[&order.id].status,
            OrderStatus::Paid,
            "merging in a higher-ranked status must adopt it"
        );

        // Merging the stale AwaitingPayment version back in must NOT
        // regress the status: rank only ever moves forward.
        let stale = orders_of([(order.id.clone(), awaiting)]);
        a.merge(&parent(), &p, &stale).unwrap();
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
            m.merge(&parent(), &p, y).unwrap();
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
        a_then_b.merge(&parent(), &p, &b).unwrap();
        let mut b_then_a = b.clone();
        b_then_a.merge(&parent(), &p, &a).unwrap();

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
        winner_twice.merge(&parent(), &p, &a_then_b).unwrap();
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

        let own_summary = state.summarize(&parent(), &p);
        assert!(
            state.delta(&parent(), &p, &own_summary).is_none(),
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

    /// What `OrdersV1::apply_delta` does once every incoming record has
    /// verified: fold each into `base` by `merge_order`, then prune. The
    /// synthetic records below are unsigned, so the merge laws are pinned at
    /// this layer rather than through `apply_delta`.
    fn merge_maps(
        base: &BTreeMap<OrderId, AuthorizedOrder>,
        other: &BTreeMap<OrderId, AuthorizedOrder>,
    ) -> BTreeMap<OrderId, AuthorizedOrder> {
        let mut out = base.clone();
        for record in other.values() {
            merge_order(&mut out, record.clone());
        }
        enforce_order_cap(&mut out);
        out
    }

    /// `MAX_ORDERS` Awaiting orders, all older than anything else these
    /// tests build.
    fn full_of_old_orders() -> BTreeMap<OrderId, AuthorizedOrder> {
        (0..MAX_ORDERS as u32)
            .map(|i| {
                synthetic_order(
                    (i % 256) as u8,
                    1_000 + i as i64,
                    OrderStatus::AwaitingPayment,
                )
            })
            .collect()
    }

    /// **The cap is associative (harvest#85).**
    ///
    /// The counterexample `fdev verify-merge` found against the old cap, which
    /// dropped TERMINAL orders first: terminal-ness is not monotone in the
    /// status rank the per-key merge maximises (Awaiting 0 active, Cancelled
    /// 1 terminal, Paid 2 active, Reversed 3 terminal), so an order's
    /// keep-priority changed as it merged, and a key pruned on one side came
    /// back from a side that still held an older version of it.
    ///
    /// P = {x Awaiting, newest}, Q = {x Cancelled}, R = `MAX_ORDERS` older
    /// Awaiting orders. Under the old cap `(P+Q)+R` dropped x (Cancelled,
    /// terminal, dropped first) while `P+(Q+R)` kept x as Awaiting (Q+R
    /// dropped the Cancelled x, and P brought the Awaiting one back as the
    /// newest active order).
    #[test]
    fn the_order_cap_is_associative_when_a_status_changes_at_the_cap() {
        let (_, x_awaiting) = synthetic_order(7, 1_000_000, OrderStatus::AwaitingPayment);
        let (_, x_cancelled) = synthetic_order(7, 1_000_000, OrderStatus::Cancelled);
        assert_eq!(
            x_awaiting.order.id, x_cancelled.order.id,
            "precondition: one order"
        );
        let p: BTreeMap<_, _> = [(x_awaiting.order.id.clone(), x_awaiting)].into();
        let q: BTreeMap<_, _> = [(x_cancelled.order.id.clone(), x_cancelled)].into();
        let r = full_of_old_orders();

        let left = merge_maps(&merge_maps(&p, &q), &r);
        let right = merge_maps(&p, &merge_maps(&q, &r));
        assert_eq!(left.len(), MAX_ORDERS);
        assert_eq!(
            crate::to_cbor(&left).expect("encode"),
            crate::to_cbor(&right).expect("encode"),
            "(P+Q)+R and P+(Q+R) must be the same bytes"
        );
    }

    /// The same laws over a spread of statuses and ages at the cap, so the
    /// test above is not the only shape checked: every status on both sides
    /// of the boundary, and keys held at different statuses by different
    /// peers.
    #[test]
    fn the_order_cap_obeys_the_merge_laws_at_the_cap() {
        let statuses = [
            OrderStatus::AwaitingPayment,
            OrderStatus::Cancelled,
            OrderStatus::Paid,
            OrderStatus::PaymentReversed,
        ];
        let base = full_of_old_orders();
        // Twelve keys straddling the oldest end of `base` and the newest,
        // each held at a different status by each of three peers.
        let keys: Vec<(u8, i64)> = (0..12u8)
            .map(|k| {
                (
                    200u8.wrapping_add(k),
                    if k % 2 == 0 {
                        500 + k as i64
                    } else {
                        5_000_000 + k as i64
                    },
                )
            })
            .collect();
        let peer = |shift: usize, with_base: bool| {
            let mut m = if with_base {
                base.clone()
            } else {
                BTreeMap::new()
            };
            for (i, (seed, secs)) in keys.iter().enumerate() {
                if (i + shift).is_multiple_of(3) {
                    continue;
                }
                let (id, rec) = synthetic_order(*seed, *secs, statuses[(i + shift) % 4]);
                m.insert(id, rec);
            }
            enforce_order_cap(&mut m);
            m
        };
        // Plus the shape of the counterexample above: the same key newest and
        // Awaiting on one peer, Cancelled on another.
        let (_, x_awaiting) = synthetic_order(7, 1_000_000, OrderStatus::AwaitingPayment);
        let (_, x_cancelled) = synthetic_order(7, 1_000_000, OrderStatus::Cancelled);
        let states = [
            peer(0, true),
            peer(1, false),
            [(x_awaiting.order.id.clone(), x_awaiting)].into(),
            [(x_cancelled.order.id.clone(), x_cancelled)].into(),
            BTreeMap::new(),
        ];
        let enc = |m: &BTreeMap<OrderId, AuthorizedOrder>| crate::to_cbor(m).expect("encode");
        for a in &states {
            assert_eq!(enc(&merge_maps(a, a)), enc(a), "idempotence");
            for b in &states {
                assert_eq!(
                    enc(&merge_maps(a, b)),
                    enc(&merge_maps(b, a)),
                    "commutativity"
                );
                for c in &states {
                    assert_eq!(
                        enc(&merge_maps(&merge_maps(a, b), c)),
                        enc(&merge_maps(a, &merge_maps(b, c))),
                        "associativity"
                    );
                }
            }
        }
    }

    /// The summary names an order's content by the full 32-byte BLAKE3 of
    /// its encoding (PR #82 review, Should Fix 4), not a truncation a
    /// birthday search could collide.
    #[test]
    fn the_order_summary_digest_is_the_full_hash() {
        let (_, record) = synthetic_order(3, 1_000, OrderStatus::AwaitingPayment);
        let expected = *blake3::hash(&crate::to_cbor(&record).expect("encode")).as_bytes();
        assert_eq!(order_content_digest(&record), expected);
    }

    /// **Seeded random merge laws on the whole store, byte for byte** (PR #82
    /// review, Should Fix 3). States combine genuinely signed store details
    /// at three versions, signed listings, and signed orders at every status
    /// with two different valid Paid proofs for one order (the equal-rank
    /// tie-break). Merge is what `update_state` runs: the composable merge
    /// and then `ListingsV1::normalize`.
    #[test]
    fn seeded_random_stores_obey_the_merge_laws() {
        use crate::merge_laws::{assert_laws, Rng};
        use freenet_scaffold::ComposableState;

        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let info = |version: u32| {
            let info = StoreInfoV1 {
                version,
                certificate_pem: "CERT".into(),
                seller_fingerprint: "fp".into(),
                reputation_contract_id: [7u8; 32],
                store_name: format!("Shop v{version}"),
                description: String::new(),
                encryption_public_key: None,
                record_public_key: None,
            };
            let (scoped_payload, signature) = sign_scoped(&seller, &info);
            AuthorizedStoreInfoV1 {
                info,
                scoped_payload,
                signature,
            }
        };
        let infos: Vec<_> = (1..=3).map(info).collect();
        let listings: Vec<_> = ["A", "B", "C", "D"]
            .iter()
            .map(|t| make_listing(&seller, t))
            .collect();
        let x = make_order("buyer-x", 1_700_000_000, &[0x00, 0x14, 0x01, 0x01]);
        let y = make_order("buyer-y", 1_700_000_100, &[0x00, 0x14, 0x02, 0x02]);
        let orders = vec![
            make_authorized_order(&seller, x.clone(), OrderStatus::AwaitingPayment, None),
            make_authorized_order(&seller, x.clone(), OrderStatus::Cancelled, None),
            make_authorized_order(
                &seller,
                x.clone(),
                OrderStatus::Paid,
                Some(make_payment_proof(&x, &bridge, 3)),
            ),
            make_authorized_order(
                &seller,
                x.clone(),
                OrderStatus::Paid,
                Some(make_payment_proof(&x, &bridge, 5)),
            ),
            make_authorized_order(&seller, y.clone(), OrderStatus::AwaitingPayment, None),
        ];
        for o in &orders {
            o.verify(&seller.verifying_key())
                .expect("fixture order verifies");
        }

        let merge = |a: &StoreStateV1, b: &StoreStateV1| {
            let mut out = a.clone();
            out.merge(&a.clone(), &p, b).expect("merge");
            out.listings.normalize();
            out
        };
        let mut rng = Rng::new(0x5eed_0026);
        let states: Vec<StoreStateV1> = (0..200)
            .map(|_| {
                let mut s = StoreStateV1::default();
                if rng.below(2) == 0 {
                    s.info = infos[rng.below(infos.len())].clone();
                }
                let mut ls = ListingsV1 {
                    listings: rng.subset(&listings, 3),
                };
                ls.normalize();
                s.listings = ls;
                for o in rng.subset(&orders, 3) {
                    merge_order(&mut s.orders.orders, o);
                }
                if s.holds_signed_content() {
                    s.owner = Some(seller.verifying_key());
                }
                s.verify(&s, &p).expect("fixture state verifies");
                s
            })
            .collect();
        assert_laws(&states, 300, &mut rng, merge, |s| {
            crate::to_cbor(s).expect("encode")
        });
    }

    /// The same at the order cap: random states of synthetic orders around
    /// `MAX_ORDERS`, with shared keys at different statuses and tied
    /// `created_at`, merged at the `merge_order` + cap layer.
    #[test]
    fn seeded_random_order_sets_at_the_cap_obey_the_merge_laws() {
        use crate::merge_laws::{assert_laws, Rng};
        let statuses = [
            OrderStatus::AwaitingPayment,
            OrderStatus::Cancelled,
            OrderStatus::Paid,
            OrderStatus::PaymentReversed,
        ];
        let base = full_of_old_orders();
        let mut rng = Rng::new(0x5eed_4096);
        let mut pool = Vec::new();
        for k in 0..24u8 {
            // Half older than the whole base, half newer, some tied.
            let secs = if k % 2 == 0 {
                900 + (k / 4) as i64
            } else {
                9_000_000 + (k / 4) as i64
            };
            for status in statuses {
                pool.push(synthetic_order(100 + k, secs, status).1);
            }
        }
        let states: Vec<BTreeMap<OrderId, AuthorizedOrder>> = (0..40)
            .map(|_| {
                let mut m = if rng.below(2) == 0 {
                    base.clone()
                } else {
                    BTreeMap::new()
                };
                for rec in rng.subset(&pool, 6) {
                    merge_order(&mut m, rec);
                }
                enforce_order_cap(&mut m);
                m
            })
            .collect();
        assert!(
            states.iter().any(|m| m.len() == MAX_ORDERS),
            "some state is at the cap"
        );
        assert_laws(&states, 60, &mut rng, merge_maps, |m| {
            crate::to_cbor(m).expect("encode")
        });
    }

    /// **The order summary at the cap stays small** (PR #82 re-review). Its
    /// id and digest encode as CBOR byte strings: 70 bytes an entry, so
    /// `MAX_ORDERS` entries come to about 280 KiB, where the default integer
    /// arrays made it about 512 KiB. And it survives the round trip a peer
    /// puts it through.
    #[test]
    fn the_order_summary_at_the_cap_is_byte_strings() {
        use freenet_scaffold::ComposableState;
        let orders = OrdersV1 {
            orders: full_of_old_orders(),
        };
        let summary = orders.summarize(&parent(), &params(&seller_key()));
        let bytes = crate::to_cbor(&summary).expect("encode");
        assert!(
            bytes.len() <= MAX_ORDERS * 70 + 3,
            "summary of {} bytes for {MAX_ORDERS} orders",
            bytes.len()
        );
        let back: Vec<(Bytes32, u8, Bytes32)> = crate::from_cbor(&bytes).expect("decode");
        assert_eq!(back, summary);
        // One entry, byte for byte: array(3), bytes(32) id, rank, bytes(32).
        let one = crate::to_cbor(&summary[0]).expect("encode");
        assert_eq!(
            &one[..3],
            &[0x83, 0x58, 0x20],
            "the id is a 32-byte byte string"
        );
    }

    /// The cap keeps the newest orders by their signed `created_at`, whatever
    /// their status. See `enforce_order_cap` for why status cannot take part.
    #[test]
    fn pruning_drops_the_oldest_orders_whatever_their_status() {
        let mut orders = full_of_old_orders();
        let (id_old_paid, old_paid) = synthetic_order(250, 10, OrderStatus::Paid);
        let (id_new_cancelled, new_cancelled) =
            synthetic_order(251, 9_000_000, OrderStatus::Cancelled);
        orders.insert(id_old_paid.clone(), old_paid);
        orders.insert(id_new_cancelled.clone(), new_cancelled);

        enforce_order_cap(&mut orders);
        assert_eq!(orders.len(), MAX_ORDERS);
        assert!(
            orders.contains_key(&id_new_cancelled),
            "the newest order survives"
        );
        assert!(
            !orders.contains_key(&id_old_paid),
            "the oldest order goes, even Paid"
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
        assert!(honest_state.verify(&parent(), &p).is_ok());
        assert!(
            padded_state.verify(&parent(), &p).is_ok(),
            "the padded record must still verify -- that is what makes this an \
             attack rather than a rejected update"
        );

        // Whichever way round they meet, the compact record is what survives.
        let mut honest_then_padded = honest_state.clone();
        honest_then_padded
            .merge(&parent(), &p, &padded_state)
            .unwrap();
        let mut padded_then_honest = padded_state.clone();
        padded_then_honest
            .merge(&parent(), &p, &honest_state)
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
                .verify(&parent(), &p)
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
            .verify(&parent(), &p)
            .expect_err("a Paid record carrying a status signature must be rejected");
        assert!(err.contains("status signature"), "got: {err}");

        // The same rule in the other direction: evidence on a status that
        // does not rest on evidence.
        let mut early =
            make_authorized_order(&seller, order.clone(), OrderStatus::AwaitingPayment, None);
        early.payment_proof = Some(make_payment_proof(&order, &bridge, 5));
        let err = orders_of([(order.id.clone(), early)])
            .verify(&parent(), &p)
            .expect_err("an AwaitingPayment record carrying payment evidence must be rejected");
        assert!(err.contains("payment evidence"), "got: {err}");

        // And a status that DOES use a field still accepts it -- so this is a
        // narrowing, not a blanket refusal.
        let cancelled = make_authorized_order(&seller, order.clone(), OrderStatus::Cancelled, None);
        assert!(
            orders_of([(order.id.clone(), cancelled)])
                .verify(&parent(), &p)
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
            .apply_delta(&parent(), &p, &Some(vec![good.clone(), bad.clone()]))
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
            .apply_delta(&parent(), &p, &Some(vec![good.clone()]))
            .expect("the valid record alone must apply");
        assert_eq!(
            state.orders.keys().collect::<Vec<_>>(),
            vec![&good_order.id]
        );

        // Order within the delta must not matter either.
        let mut state = OrdersV1::default();
        state
            .apply_delta(&parent(), &p, &Some(vec![bad, good]))
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
            .apply_delta(&parent(), &p, &Some(vec![good.clone(), bad.clone()]))
            .expect_err("a listing delta carrying an unsigned entry must be rejected");
        assert!(
            state.listings.is_empty(),
            "a rejected listing delta must leave nothing behind"
        );

        let mut state = ListingsV1::default();
        state
            .apply_delta(&parent(), &p, &Some(vec![good.clone()]))
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
            .apply_delta(&parent(), &p, &Some(vec![listing.clone(), listing.clone()]))
            .expect("a repeated-but-valid listing is not an error, just a duplicate");
        assert_eq!(
            state.listings.len(),
            1,
            "the same listing twice in one delta must be stored once"
        );
    }

    /// **Version 0 carries nothing** (PR #82 re-review). `verify` used to
    /// skip version 0 entirely, so a state whose version-0 info held any
    /// unsigned name, description or encryption key validated, anyone could
    /// inject one into a store whose seller had not published details, and
    /// two different injections never converged (`apply_delta` ignores an
    /// incoming version that is not higher). Version 0 must now be exactly
    /// the default.
    #[test]
    fn version_zero_info_must_be_the_default() {
        use freenet_scaffold::ComposableState;
        let p = params(&seller_key());
        let parent = parent();
        AuthorizedStoreInfoV1::default()
            .verify(&parent, &p)
            .expect("the default verifies");

        let mut named = AuthorizedStoreInfoV1::default();
        named.info.store_name = "Totally Legit Farm".into();
        let mut keyed = AuthorizedStoreInfoV1::default();
        keyed.info.encryption_public_key = Some([0xAA; 32]);
        let padded = AuthorizedStoreInfoV1 {
            signature: vec![1],
            ..Default::default()
        };
        for (what, info) in [("a name", named), ("a key", keyed), ("a signature", padded)] {
            assert!(
                info.verify(&parent, &p).is_err(),
                "version-0 info carrying {what} must not verify"
            );
        }
    }

    /// Three listings in id order.
    fn three_sorted_listings(seller: &SigningKey) -> Vec<AuthorizedListing> {
        let mut listings = vec![
            make_listing(seller, "Alpha"),
            make_listing(seller, "Beta"),
            make_listing(seller, "Gamma"),
        ];
        listings.sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        listings
    }

    /// **`verify` refuses listings that are not in canonical form
    /// (harvest#26).**
    ///
    /// Both of these used to verify. A peer that took such a state whole (a
    /// PUT, or `UpdateData::State`) then held different bytes from a peer
    /// that reached the same set through deltas, and the two never agreed.
    #[test]
    fn verify_refuses_unsorted_or_repeated_listings() {
        use freenet_scaffold::ComposableState;

        let seller = seller_key();
        let p = params(&seller);
        let parent = parent();
        let sorted = three_sorted_listings(&seller);

        ListingsV1 {
            listings: sorted.clone(),
        }
        .verify(&parent, &p)
        .expect("the canonical form verifies");

        let mut reversed = sorted.clone();
        reversed.reverse();
        let err = ListingsV1 { listings: reversed }
            .verify(&parent, &p)
            .expect_err("unsorted listings must not verify");
        assert!(err.contains("strictly ascending"), "got: {err}");

        let repeated = vec![sorted[0].clone(), sorted[0].clone(), sorted[1].clone()];
        ListingsV1 { listings: repeated }
            .verify(&parent, &p)
            .expect_err("a listing held twice must not verify");
    }

    /// **Merging lands on canonical form whatever it started from.**
    ///
    /// `verify` now refuses a non-canonical state, so anything this code
    /// writes has to be canonical, including when the state it started from
    /// was written by the old, permissive code: the migration fold merges a
    /// predecessor's state that nothing verified. Covers both the path where
    /// the merge brings something new and the one where it brings nothing,
    /// which the scaffold skips `apply_delta` for entirely.
    #[test]
    fn merging_normalises_a_non_canonical_state() {
        use freenet_scaffold::ComposableState;

        let seller = seller_key();
        let p = params(&seller);
        let parent = parent();
        let sorted = three_sorted_listings(&seller);
        let canonical = ListingsV1 {
            listings: sorted.clone(),
        };

        // Unsorted, with a duplicate, missing one listing.
        let messy = || ListingsV1 {
            listings: vec![sorted[2].clone(), sorted[0].clone(), sorted[2].clone()],
        };

        // Brings something new.
        let mut state = messy();
        state
            .apply_delta(&parent, &p, &Some(vec![sorted[1].clone()]))
            .expect("apply");
        assert_eq!(state, canonical);

        // Brings nothing new: only `normalize` reaches this.
        let mut state = messy();
        let other = ListingsV1 {
            listings: vec![sorted[0].clone()],
        };
        state.merge(&parent, &p, &other).expect("merge");
        state.normalize();
        assert_eq!(
            state,
            ListingsV1 {
                listings: vec![sorted[0].clone(), sorted[2].clone()],
            }
        );
        state.verify(&parent, &p).expect("the result verifies");
    }

    /// **Two peers reach the same bytes whichever order they merge in.**
    ///
    /// The property #26 is about, pinned in-process. `fdev verify-merge`
    /// checks the same laws against the built WASM; this keeps a regression
    /// visible in `cargo test`.
    #[test]
    fn listing_merge_is_commutative_including_non_canonical_inputs() {
        use freenet_scaffold::ComposableState;

        let seller = seller_key();
        let p = params(&seller);
        let parent = parent();
        let sorted = three_sorted_listings(&seller);
        let a = ListingsV1 {
            listings: vec![sorted[2].clone(), sorted[0].clone()],
        };
        let b = ListingsV1 {
            listings: vec![sorted[1].clone()],
        };

        let merge = |x: &ListingsV1, y: &ListingsV1| {
            let mut out = x.clone();
            out.merge(&parent, &p, y).expect("merge");
            out.normalize();
            crate::to_cbor(&out).expect("encode")
        };
        assert_eq!(merge(&a, &b), merge(&b, &a));
        assert_eq!(merge(&a, &a), merge(&a, &ListingsV1::default()));
    }

    /// harvest#52: a store is bound to one owner key, and two keys that share
    /// a code resolve the same way on every peer. See [`StoreStateV1`].
    mod claim_tests {
        use super::*;
        use crate::merge_laws::{assert_laws, Rng};

        /// Two signing keys whose verifying keys begin with the same two
        /// base58 characters, the lower-ranked first, and that code.
        ///
        /// Sixteen characters cannot be ground (that is the point of sixteen),
        /// but nothing in the merge depends on the code's length, so two is
        /// the same rule at a size a test can reach: a birthday search over
        /// 58^2 codes finds a pair within a few hundred keys.
        pub(crate) fn two_keys_sharing_a_code() -> (SigningKey, SigningKey, String) {
            let mut seen: std::collections::HashMap<String, SigningKey> =
                std::collections::HashMap::new();
            for i in 0u32..100_000 {
                let mut seed = [0x52u8; 32];
                seed[..4].copy_from_slice(&i.to_le_bytes());
                let key = SigningKey::from_bytes(&seed);
                let code =
                    bs58::encode(key.verifying_key().as_bytes()).into_string()[..2].to_string();
                if let Some(other) = seen.remove(&code) {
                    // Ordered by the raw bytes, NOT by `outranks`: a fixture
                    // that asked the rule under test which key is "low"
                    // would agree with that rule whichever way it pointed,
                    // and every test below would pass with it flipped.
                    return if other.verifying_key().as_bytes() < key.verifying_key().as_bytes() {
                        (other, key, code)
                    } else {
                        (key, other, code)
                    };
                }
                seen.insert(code, key);
            }
            panic!("no two keys shared a two-character code in 100,000 tries");
        }

        fn owned(owner: &SigningKey, listings: Vec<AuthorizedListing>) -> StoreStateV1 {
            let mut state = StoreStateV1 {
                owner: Some(owner.verifying_key()),
                ..Default::default()
            };
            state.listings.listings = listings;
            state.listings.normalize();
            state
        }

        fn signed_info(owner: &SigningKey, version: u32) -> AuthorizedStoreInfoV1 {
            let info = StoreInfoV1 {
                version,
                certificate_pem: String::new(),
                seller_fingerprint: "fp".into(),
                reputation_contract_id: [0u8; 32],
                store_name: format!("version {version}"),
                description: String::new(),
                encryption_public_key: None,
                record_public_key: None,
            };
            let (scoped_payload, signature) = sign_scoped(owner, &info);
            AuthorizedStoreInfoV1 {
                info,
                scoped_payload,
                signature,
            }
        }

        fn merged(p: &StoreParameters, a: &StoreStateV1, b: &StoreStateV1) -> StoreStateV1 {
            let mut out = a.clone();
            out.merge(&a.clone(), p, b).expect("merge");
            out
        }

        fn bytes(state: &StoreStateV1) -> Vec<u8> {
            crate::to_cbor(state).expect("encode")
        }

        #[test]
        fn a_code_is_the_first_sixteen_base58_characters_of_the_key() {
            let key = seller_key().verifying_key();
            let p = StoreParameters::new(key);
            let encoded = bs58::encode(key.as_bytes()).into_string();
            assert_eq!(p.code(), &encoded[..STORE_CODE_LEN]);
            assert_eq!(p.code().len(), 16);
            assert!(p.admits(&key));
            assert_eq!(
                StoreParameters::from_code(p.code()),
                Some(p.clone()),
                "a code read back from a link is the same parameters, so the same address"
            );
        }

        /// A wrong-length code must open nothing rather than something else.
        #[test]
        fn a_code_of_any_other_length_or_alphabet_is_refused() {
            let code = StoreParameters::new(seller_key().verifying_key())
                .code()
                .to_string();
            assert!(
                StoreParameters::from_code(&code[..15]).is_none(),
                "too short"
            );
            assert!(
                StoreParameters::from_code(&format!("{code}1")).is_none(),
                "too long"
            );
            assert!(StoreParameters::from_code("").is_none());
            let whole = bs58::encode(seller_key().verifying_key().as_bytes()).into_string();
            assert!(
                StoreParameters::from_code(&whole).is_none(),
                "a whole key is not a code"
            );
            for bad in ['0', 'O', 'I', 'l', '-', ' ', 'é'] {
                let mut s: String = code.chars().take(15).collect();
                s.push(bad);
                assert!(
                    StoreParameters::from_code(&s).is_none(),
                    "{bad:?} is not base58"
                );
            }
        }

        #[test]
        fn a_code_admits_only_keys_that_begin_with_it() {
            let p = params(&seller_key());
            let other = bridge_key().verifying_key();
            assert!(!p.admits(&other), "another key does not share this code");
            let everything = StoreParameters::with_code_for_test("");
            assert!(
                !everything.admits(&seller_key().verifying_key()),
                "an empty code admits nobody"
            );
        }

        #[test]
        fn verify_binds_every_record_to_an_owner_the_code_admits() {
            let seller = seller_key();
            let other = bridge_key();
            let p = params(&seller);
            let own = make_listing(&seller, "Mine");

            StoreStateV1::default()
                .verify(&StoreStateV1::default(), &p)
                .expect("the empty store verifies");
            let good = owned(&seller, vec![own.clone()]);
            good.verify(&good, &p)
                .expect("an owned store with its owner's listing verifies");

            let bare = owned(&seller, vec![]);
            let refused = bare
                .verify(&bare, &p)
                .expect_err("an owner with nothing it signed proves nothing");
            assert!(refused.contains("a key alone proves nothing"), "{refused}");

            let mut ownerless = good.clone();
            ownerless.owner = None;
            let refused = ownerless
                .verify(&ownerless, &p)
                .expect_err("records need an owner");
            assert!(refused.contains("no owner cannot hold"), "{refused}");

            let squatter = owned(&other, vec![make_listing(&other, "Theirs")]);
            let refused = squatter.verify(&squatter, &p).expect_err("wrong code");
            assert!(refused.contains("does not begin with"), "{refused}");

            let forged = owned(&seller, vec![make_listing(&other, "Forged")]);
            assert!(
                forged.verify(&forged, &p).is_err(),
                "a record signed by any key but the owner is refused"
            );
        }

        #[test]
        fn the_first_owner_to_publish_claims_an_unowned_store() {
            let seller = seller_key();
            let p = params(&seller);
            let store = owned(&seller, vec![make_listing(&seller, "Mine")]);
            let empty = StoreStateV1::default();
            assert_eq!(bytes(&merged(&p, &empty, &store)), bytes(&store));
            assert_eq!(bytes(&merged(&p, &store, &empty)), bytes(&store));
        }

        #[test]
        fn the_smaller_key_wins_a_shared_code_whichever_way_round() {
            let (low, high, code) = two_keys_sharing_a_code();
            let p = StoreParameters::with_code_for_test(&code);
            let a = owned(&low, vec![make_listing(&low, "Low")]);
            let b = owned(
                &high,
                vec![make_listing(&high, "High"), make_listing(&high, "Two")],
            );
            // Each is a valid store on its own, so what follows is the rule
            // at work and not one side failing to verify.
            a.verify(&a, &p).expect("the lower key's store verifies");
            b.verify(&b, &p).expect("the higher key's store verifies");

            assert_eq!(
                bytes(&merged(&p, &a, &b)),
                bytes(&a),
                "held low, high arrives"
            );
            assert_eq!(
                bytes(&merged(&p, &b, &a)),
                bytes(&a),
                "held high, low arrives"
            );
        }

        #[test]
        fn an_update_from_an_outranked_owner_changes_nothing() {
            let (low, high, code) = two_keys_sharing_a_code();
            let p = StoreParameters::with_code_for_test(&code);
            let mut held = owned(&low, vec![make_listing(&low, "Low")]);
            let before = bytes(&held);
            held.apply_delta(
                &StoreStateV1::default(),
                &p,
                &Some(StoreStateV1Delta {
                    owner: Some(high.verifying_key()),
                    listings: Some(vec![make_listing(&high, "High")]),
                    ..Default::default()
                }),
            )
            .expect("an outranked update is not an error, or merge order would matter");
            assert_eq!(bytes(&held), before);
        }

        #[test]
        fn an_update_from_an_outranking_owner_replaces_the_store() {
            let (low, high, code) = two_keys_sharing_a_code();
            let p = StoreParameters::with_code_for_test(&code);
            let mut held = owned(
                &high,
                vec![make_listing(&high, "High"), make_listing(&high, "Two")],
            );
            let theirs = make_listing(&low, "Low");
            held.apply_delta(
                &StoreStateV1::default(),
                &p,
                &Some(StoreStateV1Delta {
                    owner: Some(low.verifying_key()),
                    listings: Some(vec![theirs.clone()]),
                    ..Default::default()
                }),
            )
            .expect("apply");
            assert_eq!(bytes(&held), bytes(&owned(&low, vec![theirs])));
        }

        #[test]
        fn an_update_naming_an_owner_but_carrying_nothing_signed_cannot_claim() {
            let seller = seller_key();
            let p = params(&seller);
            for delta in [
                StoreStateV1Delta {
                    owner: Some(seller.verifying_key()),
                    ..Default::default()
                },
                // The unsigned version-0 info is not something the owner signed.
                StoreStateV1Delta {
                    owner: Some(seller.verifying_key()),
                    info: Some(AuthorizedStoreInfoV1::default()),
                    ..Default::default()
                },
            ] {
                let mut state = StoreStateV1::default();
                assert!(state
                    .apply_delta(&StoreStateV1::default(), &p, &Some(delta))
                    .is_err());
                assert_eq!(state, StoreStateV1::default(), "and nothing changed");
            }
        }

        #[test]
        fn an_update_naming_a_key_the_code_does_not_admit_is_refused() {
            let seller = seller_key();
            let other = bridge_key();
            let mut state = StoreStateV1::default();
            let refused = state
                .apply_delta(
                    &StoreStateV1::default(),
                    &params(&seller),
                    &Some(StoreStateV1Delta {
                        owner: Some(other.verifying_key()),
                        listings: Some(vec![make_listing(&other, "Theirs")]),
                        ..Default::default()
                    }),
                )
                .expect_err("wrong code");
            assert!(refused.contains("does not begin with"), "{refused}");
            assert_eq!(state, StoreStateV1::default());
        }

        #[test]
        fn an_ownerless_update_cannot_put_records_in_an_unowned_store() {
            let seller = seller_key();
            let mut state = StoreStateV1::default();
            assert!(state
                .apply_delta(
                    &StoreStateV1::default(),
                    &params(&seller),
                    &Some(StoreStateV1Delta {
                        listings: Some(vec![make_listing(&seller, "Mine")]),
                        ..Default::default()
                    }),
                )
                .is_err());
            assert_eq!(state, StoreStateV1::default());
        }

        /// A delta between different owners is everything or nothing: the
        /// receiver either keeps its own records or starts again from ours,
        /// and a difference against another key's records would leave it
        /// with a subset.
        #[test]
        fn a_delta_across_owners_is_everything_or_nothing() {
            let (low, high, code) = two_keys_sharing_a_code();
            let p = StoreParameters::with_code_for_test(&code);
            let a = owned(
                &low,
                vec![make_listing(&low, "Low"), make_listing(&low, "Two")],
            );
            let b = owned(&high, vec![make_listing(&high, "Low")]);
            let summary = |s: &StoreStateV1| s.summarize(s, &p);

            assert!(
                b.delta(&b, &p, &summary(&a)).is_none(),
                "the loser sends nothing"
            );
            let full = a.delta(&a, &p, &summary(&b)).expect("the winner sends");
            assert_eq!(full.listings.as_ref().map(Vec::len), Some(2), "all of it");
            let mut receiver = b.clone();
            receiver
                .apply_delta(&receiver.clone(), &p, &Some(full))
                .expect("apply");
            assert_eq!(bytes(&receiver), bytes(&a));

            assert!(
                a.delta(&a, &p, &summary(&a)).is_none(),
                "nothing new, nothing sent"
            );
            let unowned = StoreStateV1::default();
            assert!(unowned.delta(&unowned, &p, &summary(&a)).is_none());
        }

        /// The laws the network needs, over random states of two owners that
        /// share a code, with details and listings from each.
        #[test]
        fn two_owners_sharing_a_code_obey_the_merge_laws() {
            let (low, high, code) = two_keys_sharing_a_code();
            let p = StoreParameters::with_code_for_test(&code);
            let pools: Vec<(
                SigningKey,
                Vec<AuthorizedListing>,
                Vec<AuthorizedStoreInfoV1>,
            )> = [low, high]
                .into_iter()
                .map(|key| {
                    let listings = ["A", "B", "C"]
                        .iter()
                        .map(|t| make_listing(&key, t))
                        .collect();
                    let infos = vec![signed_info(&key, 1), signed_info(&key, 2)];
                    (key, listings, infos)
                })
                .collect();
            let mut rng = Rng::new(0x5eed_0052);
            let states: Vec<StoreStateV1> = (0..150)
                .map(|_| {
                    let pick = rng.below(pools.len() + 1);
                    let Some((key, listings, infos)) = pools.get(pick) else {
                        return StoreStateV1::default();
                    };
                    let mut s = owned(key, rng.subset(listings, 3));
                    if rng.below(2) == 0 || s.listings.listings.is_empty() {
                        s.info = infos[rng.below(infos.len())].clone();
                    }
                    s.verify(&s, &p).expect("fixture state verifies");
                    s
                })
                .collect();
            assert!(
                states
                    .iter()
                    .any(|s| s.owner == Some(pools[0].0.verifying_key()))
                    && states
                        .iter()
                        .any(|s| s.owner == Some(pools[1].0.verifying_key())),
                "the corpus must actually hold both owners"
            );
            assert_laws(&states, 400, &mut rng, |a, b| merged(&p, a, b), bytes);

            // And the closed form: merging everything gives the lower key's
            // records and nothing of the other's.
            let all = states
                .iter()
                .fold(StoreStateV1::default(), |acc, s| merged(&p, &acc, s));
            assert_eq!(all.owner, Some(pools[0].0.verifying_key()));
            all.verify(&all, &p).expect("the converged store verifies");
        }
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

    /// **Store info written while `payment_instructions` existed still
    /// decodes.**
    ///
    /// That field was removed rather than deprecated, so every store
    /// published before this build carries a key `StoreInfoV1` no longer
    /// names. Serde ignores an unknown key unless told otherwise, which is
    /// what makes the removal safe to do without a reader-side migration --
    /// but "unless told otherwise" is one `deny_unknown_fields` away from
    /// false, and that attribute would turn every old store into an
    /// undecodable one. Hence a test rather than a comment.
    #[test]
    fn store_info_from_before_the_notes_field_was_removed_still_decodes() {
        #[derive(serde::Serialize)]
        struct OldStoreInfo {
            version: u32,
            certificate_pem: String,
            seller_fingerprint: String,
            reputation_contract_id: [u8; 32],
            store_name: String,
            description: String,
            payment_instructions: String,
            encryption_public_key: Option<[u8; 32]>,
        }
        let old = OldStoreInfo {
            version: 3,
            certificate_pem: "-----BEGIN CERT-----".into(),
            seller_fingerprint: "fingerprint".into(),
            reputation_contract_id: [7u8; 32],
            store_name: "Bean Shop".into(),
            description: "Coffee".into(),
            payment_instructions: "BTC: bc1q...".into(),
            // The shape a store published since the messaging work actually
            // has, rather than the pre-messaging one.
            encryption_public_key: Some([9u8; 32]),
        };
        let decoded: StoreInfoV1 = crate::from_cbor(&crate::to_cbor(&old).unwrap())
            .expect("a store published before the removal must still be readable");
        assert_eq!(decoded.store_name, "Bean Shop");
        assert_eq!(decoded.description, "Coffee");
        assert_eq!(
            decoded.encryption_public_key,
            Some([9u8; 32]),
            "and the fields it shares with today's shape survive"
        );
    }

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

    /// **A signed record must re-encode to the bytes that were signed, and
    /// this generation deliberately broke that for one field.**
    ///
    /// `AuthorizedStoreInfoV1::verify` does not compare stored bytes: it
    /// re-serializes `self.info` and checks the result against the payload
    /// inside the signed `ScopedPayload` (see
    /// `crate::listing::verify_scoped_signature`). So any change to what
    /// `StoreInfoV1` serializes changes that preimage, and every store info
    /// signed before the change stops verifying -- which the store contract
    /// reports as "store info signature invalid", rejecting the seller's own
    /// published details.
    ///
    /// Removing `payment_instructions` does exactly that, knowingly: a store
    /// published before this generation cannot be carried forward, and its
    /// seller has to publish their details again, which re-signs them in the
    /// new shape. That was acceptable only because no store but a test one
    /// existed; the legacy registry's V13 entry records it.
    ///
    /// The test still pins the other half, which has NOT changed: an optional
    /// field must carry `skip_serializing_if`, or it serializes as an explicit
    /// null when absent and invalidates old signatures the same way.
    /// `#[serde(default)]` alone does not prevent that -- `default` governs
    /// DEcoding. Observed red on 2026-09-05 by adding `encryption_public_key`
    /// with `#[serde(default)]` and no `skip_serializing_if`.
    #[test]
    fn a_store_info_re_encodes_to_its_signed_bytes_but_for_the_removed_field() {
        let state: StoreStateV1 =
            crate::from_cbor(V1_STORE_STATE_CBOR).expect("the V1 state must decode");

        let re_encoded = crate::to_cbor(&state.info.info).expect("re-encode the decoded info");

        // The decided break: the field is gone from the preimage.
        assert!(
            contains(V1_STORE_INFO_CBOR, b"payment_instructions"),
            "the V1 literal is the one that carried the field"
        );
        assert!(
            !contains(&re_encoded, b"payment_instructions"),
            "the removed field must not come back"
        );

        // Everything else is unchanged, so the difference really is only that
        // field: putting it back makes the old preimage again.
        assert!(
            !contains(&re_encoded, b"encryption_public_key"),
            "an absent optional field must not serialize, or every signature \
             made before it existed stops verifying"
        );
        // Byte-exact, not a length check. A length check passes a
        // LENGTH-PRESERVING change to the preimage -- switching
        // `reputation_contract_id` to `serde_bytes` turns `0x98 0x20`
        // (array(32)) into `0x58 0x20` (bytes(32)), same two bytes, every
        // signature dead -- and the doc on that field flags it as exactly the
        // change somebody will try.
        //
        // The removed key was the LAST entry, so what should remain is the
        // literal minus its final 22 bytes (`0x74`, 20 characters, `0x60`)
        // with a map header one entry smaller.
        assert_eq!(re_encoded[0], 0xa6, "one fewer entry than the V1 literal");
        // `0x74` text(20), the key itself, and `0x60` for the empty string it
        // held, worked out here rather than left as a number in a comment.
        let removed = 1 + "payment_instructions".len() + 1;
        assert_eq!(
            &re_encoded[1..],
            &V1_STORE_INFO_CBOR[1..V1_STORE_INFO_CBOR.len() - removed],
            "the only difference should be the removed key and its value"
        );
    }

    /// `slice::contains` is per-element; this is the subsequence question.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
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
