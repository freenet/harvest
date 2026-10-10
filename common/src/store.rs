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
    /// The store's record (legacy RSA) public key, PKCS#1 DER, for a store
    /// that published one between harvest#93 phase 1b and harvest#203.
    ///
    /// Only readers locating a store's reputation records from before
    /// harvest#53 Phase C use it (the UI's `reputation_locators`). Nothing is
    /// derived from the store key any more: deriving it was an RSA-2048 key
    /// generation that overran the node's 5 s limit on a delegate call
    /// (harvest#203). A new store publishes `None`, and an edit carries over
    /// whatever the store already publishes. Skipped when absent for the
    /// reason `encryption_public_key` is. (Kept at this length: this file
    /// compiles into the contracts, and a line count change moves them.)
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
    #[serde(with = "serde_bytes")]
    pub scoped_payload: Vec<u8>,
    /// Ed25519 signature over the scoped_payload bytes.
    #[serde(with = "serde_bytes")]
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
        if let Some(new_info) = self.admit(delta) {
            new_info.check_signature(owner_key(parent_state)?)?;
            *self = new_info.clone();
        }
        Ok(())
    }
}

impl AuthorizedStoreInfoV1 {
    /// The info a merge takes from `delta`: one at a higher version than
    /// held. A stale one is ignored.
    pub(crate) fn admit<'a>(&self, delta: &'a Option<Self>) -> Option<&'a Self> {
        delta
            .as_ref()
            .filter(|new_info| new_info.info.version > self.info.version)
    }

    fn check_signature(&self, owner: &VerifyingKey) -> Result<(), String> {
        verify_scoped_signature(&self.scoped_payload, &self.signature, owner, &self.info)
            .map_err(|e| format!("store info delta signature invalid: {e}"))
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
///
/// So a seller takes a listing down, or marks it sold out, with a status in
/// [`StoreStateV1::listing_statuses`] (harvest#70), never by removing it here.
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
    ///
    /// Then the caps (step 2): a listing over [`MAX_LISTING_BYTES`] is
    /// dropped, and of the rest the [`MAX_LISTINGS`] newest are kept, by
    /// `created_at` and then id. Both are pure functions of the set held,
    /// and both commute with merging: the size rule looks at one listing
    /// alone, and every listing a cut keeps outranks every one it drops, so
    /// whatever is cut from a part is cut from any union containing it.
    /// Nothing an order needs is lost: an order carries its own terms and
    /// proof, and names its listing only by an opaque tag.
    pub fn normalize(&mut self) {
        self.listings.retain(fits);
        self.listings
            .sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        self.listings.dedup_by(|a, b| a.listing.id == b.listing.id);
        if self.listings.len() > MAX_LISTINGS {
            let mut newest: Vec<(chrono::DateTime<chrono::Utc>, ListingId)> = self
                .listings
                .iter()
                .map(|l| (l.listing.created_at, l.listing.id.clone()))
                .collect();
            // The id tie-break is what the stable sort of id-sorted listings
            // gives anyway (so a mutation dropping it survives); it is
            // written out so the order does not rest on the sort above.
            newest.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            newest.truncate(MAX_LISTINGS);
            let kept: std::collections::BTreeSet<ListingId> =
                newest.into_iter().map(|(_, id)| id).collect();
            self.listings.retain(|l| kept.contains(&l.listing.id));
        }
    }
}

/// Whether one listing is within [`MAX_LISTING_BYTES`] as it encodes.
fn fits(listing: &AuthorizedListing) -> bool {
    crate::to_cbor(listing).is_ok_and(|bytes| bytes.len() <= MAX_LISTING_BYTES)
}

/// Whether `listing`, once the store key signs it and it carries
/// `certificate_pem`, is within [`MAX_LISTING_BYTES`]: what the app checks
/// before asking for a signature, so a listing the store would drop is
/// never published. Exact: the signed payload is
/// [`crate::backing::store_key_envelope`] of the listing, which is what the
/// store key signs, and a signature is 64 bytes.
pub fn listing_fits_once_signed(listing: &crate::listing::Listing, certificate_pem: &str) -> bool {
    let Ok(scoped_payload) = crate::to_cbor(listing).and_then(crate::backing::store_key_envelope)
    else {
        return false;
    };
    fits(&AuthorizedListing {
        listing: listing.clone(),
        scoped_payload,
        signature: vec![0u8; 64],
        certificate_pem: certificate_pem.to_string(),
    })
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
        // The caps first: they are cheap, and a state over them is refused
        // before a single signature is checked.
        if self.listings.len() > MAX_LISTINGS {
            return Err(format!(
                "store holds {} listings, the most it keeps is {MAX_LISTINGS}",
                self.listings.len()
            ));
        }
        if let Some(big) = self.listings.iter().find(|l| !fits(l)) {
            return Err(format!(
                "listing {} is over {MAX_LISTING_BYTES} bytes",
                big.listing.id
            ));
        }
        for authorized in &self.listings {
            authorized.verify(owner_key(parent_state)?)?;
            crate::listing_image::check_listing_images(&authorized.listing)?;
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
        // And within the caps `normalize` keeps (step 2, checked above),
        // safe for the same reason.
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
        let Some(new_listings) = delta else {
            self.normalize();
            return Ok(());
        };
        // Collect first, push after. Verifying and pushing in one pass left a
        // delta of [valid, invalid] with the valid listing already in `self`
        // when the error returned -- see `OrdersV1::apply_delta` for the same
        // defect and why the call site's habit of discarding the state on
        // error is not a substitute for this.
        let fresh = self.admit(new_listings)?;
        for listing in &fresh {
            listing.verify(owner_key(parent_state)?)?;
            crate::listing_image::check_listing_images(&listing.listing)?;
        }
        self.merge_unchecked(fresh);
        Ok(())
    }
}

impl ListingsV1 {
    /// The listings of `incoming` a merge takes: not one held, nor one the
    /// delta already named. A delta of more than [`MAX_LISTINGS`] is refused
    /// whole (step 2): no store holds more, so the rest are copies or
    /// listings the cut would drop.
    pub(crate) fn admit<'a>(
        &self,
        incoming: &'a [AuthorizedListing],
    ) -> Result<Vec<&'a AuthorizedListing>, String> {
        if incoming.len() > MAX_LISTINGS {
            return Err(format!(
                "a listing delta of {} records is more than a store holds ({MAX_LISTINGS})",
                incoming.len()
            ));
        }
        let mut known_ids: std::collections::HashSet<&ListingId> =
            self.listings.iter().map(|l| &l.listing.id).collect();
        // `insert` is false for a listing already held -- including one
        // added by an EARLIER entry of this same delta, which the snapshot
        // this used to take before the loop could not see, so a delta naming
        // one listing twice stored it twice. `listings` is a plain `Vec` with
        // no uniqueness invariant of its own, so that duplicate then survived
        // every later merge and sort.
        Ok(incoming
            .iter()
            .filter(|listing| known_ids.insert(&listing.listing.id))
            .collect())
    }

    /// Add listings WITHOUT verifying them, then sort and cut: for a caller
    /// that has, or that checks what was kept and what was not
    /// (`StoreStateV1::apply_update`).
    pub(crate) fn merge_unchecked(&mut self, listings: Vec<&AuthorizedListing>) {
        self.listings.extend(listings.into_iter().cloned());
        self.normalize();
    }
}

/// Every listing's current status, one per listing id, signed by the store key
/// (harvest#70). See [`crate::listing::ListingStatus`].
///
/// A [`crate::backing::SignedSetV1`] like the backings, with one difference:
/// two statuses for one listing resolve to the higher `revision` before the
/// smaller encoding, so a later status supersedes an earlier one. Nothing
/// removes a status by itself, and a status for a listing the store does not
/// hold is kept, since it may arrive first.
///
/// At most [`MAX_LISTING_STATUSES`], the newest by revision (step 2): see
/// there for why that many, and `SignedSetV1::cut_to_newest` for why the cut
/// obeys the merge laws.
pub type ListingStatusesV1 = crate::backing::SignedSetV1<crate::listing::AuthorizedListingStatus>;

/// The most listing statuses a store keeps (step 2): the
/// `MAX_LISTING_STATUSES` with the highest revisions, the smaller listing id
/// first between two at one revision.
///
/// A store holds one status per listing id, but every edit publishes a new
/// listing and withdraws the old one, so the ids, and their statuses, grow
/// with the edit history. Before this bound nothing stopped them, and two
/// copies of a store near [`MAX_STORE_BYTES`] could each refuse the other's
/// last edit.
///
/// # Why this many
///
/// Every reader of a status reads it for a listing the store holds (the
/// UI's listing pages and `listing_status_flow`, the delegate's `settle` and
/// light store read), and a status for a listing it cannot find is ignored.
/// So the bound must never cut a held listing's status: if it did, a listing
/// sold out or taken down would read as on sale again, since a listing with
/// no status reads that way.
///
/// Cutting held listing X's status takes this many newer statuses on other
/// listings. The app signs a status only for a listing the store holds, and
/// a revision is the time it was signed, so each of those was for a listing
/// held at some time since X's status. While X is held, fewer than
/// [`MAX_LISTINGS`] listings are newer than it, and the older ones held since
/// were held alongside X when its status was signed, fewer than
/// [`MAX_LISTINGS`] again: at most 254 in all. Twice that again leaves room
/// for clocks that disagree across a seller's devices, at about 550 bytes a
/// status (280 KB in all).
pub const MAX_LISTING_STATUSES: usize = 4 * MAX_LISTINGS;

impl crate::backing::SignedRecord for crate::listing::AuthorizedListingStatus {
    fn slot(&self) -> Bytes32 {
        Bytes32(self.status.listing.0)
    }
    fn verify_for(&self, owner: &VerifyingKey) -> Result<(), String> {
        self.verify(owner)
    }
    fn rank(&self) -> u64 {
        self.status.revision
    }
    const WHAT: &'static str = "listing status";
    const MAX_RECORDS: usize = MAX_LISTING_STATUSES;
    const CUT_TO_NEWEST: bool = true;
}

/// The most listings a store keeps (step 2): the newest, by
/// [`ListingsV1::normalize`]. Every version of a listing counts, since an
/// edit publishes a new listing and withdraws the old one, so the ones cut
/// first are usually old versions already taken down.
///
/// Sized with [`MAX_ORDERS`], by the node's 5 s limit on one contract call:
/// on a node, a store of 500 paid orders and 512 listings was refused on
/// PUT one time in three and on a one-listing delta every time, while 256
/// listings with 500 orders fitted every run (2026-10-04 wall-time matrix).
/// 128 leaves room for listings at the per-listing bound, and for paid
/// records at [`MAX_PAID_ORDER_BYTES`] (see [`MAX_ORDERS`]). The seller's own
/// delegate reads the whole store on every instant-checkout decision too,
/// within one call's budget (`tests/delegate-budget`).
pub const MAX_LISTINGS: usize = 128;

/// The most bytes one listing takes, as its signed record encodes (step 2).
/// A larger listing is dropped by [`ListingsV1::normalize`], as an item rule,
/// so with [`MAX_LISTINGS`] a store's listings take at most 4 MiB. A cap on
/// the listings' TOTAL bytes would not do: cutting a ranked list where its
/// running total passes a budget does not commute with merging (an element
/// cut in one merge can leave room for a later one that a single merge of
/// everything would also cut), so replicas could disagree.
pub const MAX_LISTING_BYTES: usize = 32 * 1024;

/// How many orders one store contract will hold.
///
/// Unlike listings, orders carry payment evidence: a `Paid` order embeds an
/// [`crate::payment::OrderPaymentProof`], which is itself a set of bridge-signed
/// claims plus a signed chain tip -- easily hundreds of bytes to a few KB per
/// order. Without a cap a popular store's state (and, worse, its per-heartbeat
/// summary -- see `OrdersV1`'s `Summary`) would grow without bound. On
/// overflow the oldest orders are dropped first: see `enforce_order_cap`.
///
/// # Why 256
///
/// It is a bound on work, and has to hold for PAID orders, which cost
/// nothing of value on signet. Every call validates every order's proof:
/// on a node, a store of 1,000 paid orders took 3 to 4 s to PUT and 4 to 6
/// s for a one-listing delta against the node's 5 s limit, and every PUT of
/// 4,096 was refused. 500 fitted every run with ordinary proofs, but a paid
/// record may take up to [`MAX_PAID_ORDER_BYTES`] (8 KiB), and with every
/// order at that bound and [`MAX_LISTINGS`] full at 32 KiB, 384 orders took
/// up to 3.1 s to PUT and 4.5 s for a one-listing delta, while 256 took at
/// most 1.8 s and 2.2 s, every run (2026-10-09 wall-time runs, step 2).
///
/// The store is the place an order lives while it is acted on: paid, sent,
/// and complained about (Ian, 2026-10-09: the store holds an order until
/// its complaint window closes, and history then lives in each side's
/// delegate). With honest traffic 256 orders outlast that window (about 21
/// days) up to about 12 instant orders a day; under Buy-now spam (100 a
/// day, see `enforce_order_cap`) an order rolls off after about 2.5 days,
/// which is why the seller's and the buyer's delegates each keep their own
/// copies.
pub const MAX_ORDERS: usize = 256;

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
///
/// Every incoming record has been through [`as_kept`] first.
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
            // Two orders under one id with DIFFERENT terms happen only for
            // orders identified by the request they answer
            // (`Order::request_id`): two answers to one request. The larger
            // amount wins before the encoding does, so a seller cannot
            // replace a paid order with a cheaper one of their own, paid
            // with a token amount, to shrink what their store shows it took.
            // It does NOT stop the opposite: a seller can publish a larger
            // version, paid to themselves, over the one a buyer paid. What
            // protects that buyer is their kept copy of the order and the
            // complaint it supports, which verify on their own, not this
            // store's record. For every other order one id means one set of
            // terms, so the amounts are equal and this changes nothing.
            match incoming.order.amount_sats.cmp(&existing.order.amount_sats) {
                std::cmp::Ordering::Greater => {
                    orders.insert(id, incoming);
                    return;
                }
                std::cmp::Ordering::Less => return,
                std::cmp::Ordering::Equal => {}
            }
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
/// An order answering a request (`Order::request_id`) can have versions with
/// different terms under one id, but never a different `created_at`: the id is
/// derived from the request AND `created_at` (`OrderId::for_request`), so the
/// rank holds for it too.
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
/// `Cancelled` one, and before a newer unpaid one. Only the store key signs
/// an order, but that does not mean only the seller decides how many there
/// are: instant checkout makes the seller's delegate sign an order for any
/// Buy now, which needs no Ghost Key and no payment, up to the delegate's
/// limits (100 a day per store). So anyone can push old orders out, at
/// about 100 a day: at `MAX_ORDERS` 256, a paid order can roll off about
/// 2.5 days after it was made. An instant-checkout answer is dated by its
/// buyer's `requested_at`; the seller's delegate answers only one within a
/// day of its own clock, and a seller answering by hand is refused one
/// further off.
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
            if record.status == crate::payment::OrderStatus::Paid && !paid_minimally(record) {
                return Err(format!(
                    "order {id} is Paid on evidence that is not the minimal proof, or past \
                     {MAX_PAID_ORDER_BYTES} bytes"
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
        let incoming = self.admit(incoming)?;
        // Verify the WHOLE delta before merging any of it. Verifying and
        // merging in one pass left a delta of [valid, invalid] with the valid
        // record already folded into `self` when the error returned, so a
        // caller that kept the state it passed in would silently take on
        // records from a delta it had been told to reject. The contract's
        // `update_state` happens to discard the mutated value on error, but
        // that is a property of that call site, not of this function.
        for record in &incoming {
            record
                .verify(owner_key(parent_state)?)
                .map_err(|e| format!("order {} delta invalid: {e}", record.order.id))?;
        }
        self.merge_unchecked(incoming);
        Ok(())
    }
}

impl OrdersV1 {
    /// The records of `incoming` a merge has to look at, each as the store
    /// keeps it: a padded `Paid` is its unpaid terms from here on
    /// (`as_kept`). One the store already holds as it is, or that came
    /// earlier in this delta, changes nothing and is left out.
    ///
    /// No honest delta carries more orders than a store holds (a whole
    /// store's is `MAX_ORDERS`); a longer one is copies, and is refused whole
    /// (review round 4 of step 2: 400 copies of one paid record cost more
    /// than twice a call's budget).
    pub(crate) fn admit(
        &self,
        incoming: &[AuthorizedOrder],
    ) -> Result<Vec<AuthorizedOrder>, String> {
        if incoming.len() > MAX_ORDERS {
            return Err(format!(
                "an order delta of {} records is more than a store holds ({MAX_ORDERS})",
                incoming.len()
            ));
        }
        let mut fresh: Vec<AuthorizedOrder> = Vec::with_capacity(incoming.len());
        for record in incoming.iter().cloned().map(as_kept) {
            if self.orders.get(&record.order.id) != Some(&record) && !fresh.contains(&record) {
                fresh.push(record);
            }
        }
        Ok(fresh)
    }

    /// Merge records WITHOUT verifying them, then cut to [`MAX_ORDERS`]: for
    /// a caller that has, or that checks what was kept and what was not
    /// (`StoreStateV1::apply_update`).
    pub(crate) fn merge_unchecked(&mut self, records: Vec<AuthorizedOrder>) {
        for record in records {
            merge_order(&mut self.orders, record);
        }
        enforce_order_cap(&mut self.orders);
    }
}

impl OrdersV1 {
    /// Every record as the store keeps it ([`as_kept`]), and at most
    /// [`MAX_ORDERS`] of them (`enforce_order_cap`): for a state written
    /// before step 2, which a migration fold carries forward without passing
    /// it through `apply_delta` (the scaffold skips it when the other side
    /// brings no new order).
    pub fn normalize(&mut self) {
        let held = std::mem::take(&mut self.orders);
        self.orders = held
            .into_iter()
            .map(|(id, record)| (id, as_kept(record)))
            .collect();
        enforce_order_cap(&mut self.orders);
    }
}

/// The most bytes a store's state, or one update to it (a delta, or a whole
/// state to merge), may take as it encodes (step 2). The contract refuses a
/// larger one on its length, before reading any of it: a delta anyone may
/// send, padded with records the store would only throw away, costs no more
/// to refuse than its length check.
///
/// Every part of a store is capped (step 2), so the largest state the caps
/// allow is a computed figure, [`AT_CAPS_BYTES`], and this is that plus
/// about 3%. Nothing honest is past it: the largest delta there is, a new
/// subscriber's whole store, is the state itself. The slack is for what
/// the contract caps by count but not by bytes, which
/// [`AT_CAPS_REST_BYTES`] measures at what the app writes (a store's
/// description, a backing's certificate, a status's count): an app that
/// writes those a little larger must not find its own store refused. Much
/// more would only be room for padding: a padded delta's cost on a node
/// grows with its bytes, outside the contract too (the node took about
/// 1.2 s to hand a 17 MB delta to it), which is why the earlier 16 and
/// 12 MiB bounds were too high (the step-2 wall-time runs).
pub const MAX_STORE_BYTES: usize = 8_600 * 1024;

/// What a store at every cap encodes to, at most: [`MAX_LISTINGS`] listings
/// of [`MAX_LISTING_BYTES`], [`MAX_ORDERS`] paid orders of
/// [`MAX_PAID_ORDER_BYTES`], and [`AT_CAPS_REST_BYTES`] for the rest.
pub const AT_CAPS_BYTES: usize =
    MAX_LISTINGS * MAX_LISTING_BYTES + MAX_ORDERS * MAX_PAID_ORDER_BYTES + AT_CAPS_REST_BYTES;

/// A store's parts besides its listings and orders, at every cap: 2,143,269
/// bytes, measured part by part on `tests/contract-budget`'s at-caps store
/// (which fails if that store encodes past [`AT_CAPS_BYTES`]). That is a despatch for each order
/// (156 KB), [`MAX_LISTING_STATUSES`] statuses (299 KB), `MAX_BACKINGS`
/// backings with 4 KiB certificates (1,394 KB) and four wrapped copies each
/// (229 KB, more than a retirement), and the store's details with a 16 KiB
/// description (65 KB).
pub const AT_CAPS_REST_BYTES: usize = 2_150 * 1024;

const _: () = assert!(MAX_STORE_BYTES >= AT_CAPS_BYTES + AT_CAPS_BYTES / 32);

/// The most bytes a `Paid` record may take, as it encodes, for the store to
/// keep it as paid (step 2): see [`as_kept`].
///
/// A minimal proof carries only the claims a payment needs, but each claim
/// carries its whole transaction, so a minimal proof is still as large as
/// the transactions behind it: 32 needed outpoints of 64 KB transactions
/// each come to the 256 KiB `MAX_PROOF_CLAIM_BYTES` allows, and on signet
/// such transactions cost nothing. Sized by measurement (step 2's wall-time
/// runs): with 500 paid orders at 16, 32 or 64 KiB and `MAX_LISTINGS`
/// listings at theirs, the node's calls ran past its time limit; at 8 KiB
/// they fitted, and `MAX_ORDERS` was then lowered to keep every call within
/// about 2.5 s. An ordinary payment fits: a segwit spend of 20 inputs, or a
/// legacy one of 9 (`the_paid_byte_bound_admits_ordinary_payments`). Before mainnet (harvest#134): an exchange's
/// batched withdrawal straight to an order's address is a legitimate payment
/// whose transaction can pass it; the store then keeps the order unpaid and
/// the seller's and buyer's own copies hold it as paid.
pub const MAX_PAID_ORDER_BYTES: usize = 8 * 1024;

/// A record as the store keeps it (step 2): a `Paid` record whose payment
/// proof is not the canonical minimal one
/// ([`crate::payment::verify_minimal_proof`], the proof a complaint must
/// carry), or that takes more than [`MAX_PAID_ORDER_BYTES`] as it encodes,
/// is kept as its unpaid terms, the seller-signed order anyone could
/// publish; every other record as it is.
///
/// # Why
///
/// Whoever publishes `Paid` first chooses its evidence, and the verifier
/// accepts any valid claims up to `MAX_PROOF_CLAIM_BYTES` (256 KiB): about
/// 200 padded orders would fill a store to freenet-core's 50 MiB state limit.
/// A minimal proof carries only the claims the payment needs, and the byte
/// bound caps what those claims' transactions may add.
///
/// # Why kept as unpaid rather than refused
///
/// It is a pure function of the one record, and idempotent, applied before
/// `merge_order`'s `max`, so merging stays commutative, associative and
/// idempotent. Refusing the delta would refuse every listing and order
/// beside it, and a migration fold would discard a whole earlier generation
/// holding one padded record. Any tab that sees the payment publishes the
/// minimal `Paid` again (`AppState::settled_orders`), which then wins on
/// rank. `PaymentReversed` is left as it is: its evidence carries a
/// retraction, which no minimal proof can (and nothing produces one yet).
pub fn as_kept(record: AuthorizedOrder) -> AuthorizedOrder {
    use crate::payment::OrderStatus;
    if record.status != OrderStatus::Paid || paid_minimally(&record) {
        return record;
    }
    AuthorizedOrder {
        status: OrderStatus::AwaitingPayment,
        payment_proof: None,
        status_scoped_payload: None,
        status_signature: None,
        ..record
    }
}

/// Whether a `Paid` record is one the store keeps as paid: the canonical
/// minimal proof, within [`MAX_PAID_ORDER_BYTES`].
fn paid_minimally(record: &AuthorizedOrder) -> bool {
    paid_within_cap(record)
        && record
            .payment_proof
            .as_ref()
            .is_some_and(|proof| crate::payment::verify_minimal_proof(&record.order, proof).is_ok())
}

/// Whether a record takes at most [`MAX_PAID_ORDER_BYTES`] as it encodes.
///
/// A proof's signed bodies and signatures alone are a floor on the record's
/// size (each of their bytes takes at least one as it encodes), so a record
/// whose proof is past the bound by that count is judged without encoding it:
/// a padded record anyone may send costs nothing more to throw away than
/// reading it did.
pub fn paid_within_cap(record: &AuthorizedOrder) -> bool {
    if proof_bytes_at_least(record) > MAX_PAID_ORDER_BYTES {
        return false;
    }
    crate::to_cbor(record).is_ok_and(|bytes| bytes.len() <= MAX_PAID_ORDER_BYTES)
}

/// A floor on the bytes `record`'s payment proof takes as it encodes: the
/// lengths of its claims' and tip's signed bodies and signatures.
fn proof_bytes_at_least(record: &AuthorizedOrder) -> usize {
    match &record.payment_proof {
        Some(crate::payment::OrderPaymentProof::OnChain(proof)) => proof
            .claims
            .iter()
            .map(|c| c.body_cbor.len() + c.signature.len())
            .sum::<usize>()
            .saturating_add(proof.tip.body_cbor.len() + proof.tip.signature.len()),
        _ => 0,
    }
}

/// The key a store's records are verified against: its owner.
///
/// Every child of [`StoreStateV1`] verifies through this, so a store with no
/// owner can hold nothing that needs a signature -- which is everything but
/// the empty default.
pub(crate) fn owner_key(parent: &StoreStateV1) -> Result<&VerifyingKey, String> {
    owner_of(&parent.owner)
}

fn owner_of(owner: &Option<VerifyingKey>) -> Result<&VerifyingKey, String> {
    owner.as_ref().ok_or_else(|| {
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
/// The first sentence above is about a delta produced by [`Self::delta`],
/// which really does carry everything the winner holds when it crosses
/// owners. It is NOT true of a HAND-BUILT single-part delta -- the app sends
/// those (`ui/gateway/store_ops::orders_delta_bytes` names one owner and one
/// order and leaves every other part `None`), so one arriving at a replica
/// holding an outranked owner switches that replica to the incoming owner
/// with that single order and no info, listings, backings or closure until
/// the next summary exchange. Same transient, same precondition of two keys
/// sharing a code, but it is reached by a second route the paragraph above
/// does not cover. Noted by the authorization lens on harvest#75; the
/// behaviour predates it.
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
    /// phase 1b). A copy is kept unless its backer is retired (the
    /// retirement is the tombstone) or its slot is cut by the store-wide
    /// bound; it need not name a backing the store holds, since it may
    /// arrive first. See
    /// [`crate::custody`] and `StoreStateV1::normalize_backings`.
    #[serde(
        default,
        skip_serializing_if = "SignedSetV1::<crate::custody::AuthorizedCopy>::is_empty"
    )]
    pub copies: crate::custody::CopiesV1,
    /// The seller's despatch of each order, signed by the store key, one per
    /// order the store still holds (harvest#53 Phase B). Outside the order
    /// status lattice on purpose; see [`crate::fulfilment`]. A despatch is
    /// kept only while its order is (`StoreStateV1::normalize_fulfilment`).
    ///
    /// `default` and skipped when empty, like the parts above, so a state
    /// holding no despatch encodes exactly as it did before they existed and
    /// every earlier generation's state decodes as it is.
    #[serde(
        default,
        skip_serializing_if = "SignedSetV1::<crate::fulfilment::AuthorizedDespatch>::is_empty"
    )]
    pub fulfilment: crate::fulfilment::FulfilmentV1,
    /// Each listing's availability, as the store key last signed it
    /// (harvest#70). Serialized like the backings, for the same reason: a
    /// state holding none encodes exactly as it did before they existed.
    #[serde(default, skip_serializing_if = "ListingStatusesV1::is_empty")]
    pub listing_statuses: ListingStatusesV1,
    /// The seller's pause, as the store key last signed it (step 2; see
    /// [`crate::store_pause`]). Empty, or one record. Skipped when empty, so
    /// a state never paused encodes exactly as before it existed.
    #[serde(default, skip_serializing_if = "crate::store_pause::PauseV1::is_empty")]
    pub pause: crate::store_pause::PauseV1,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fulfilment: <crate::fulfilment::FulfilmentV1 as ComposableState>::Summary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listing_statuses: <ListingStatusesV1 as ComposableState>::Summary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pause: <crate::store_pause::PauseV1 as ComposableState>::Summary,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fulfilment: Option<<crate::fulfilment::FulfilmentV1 as ComposableState>::Delta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_statuses: Option<<ListingStatusesV1 as ComposableState>::Delta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause: Option<<crate::store_pause::PauseV1 as ComposableState>::Delta>,
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
            || !self.fulfilment.is_empty()
            || !self.listing_statuses.is_empty()
            || !self.pause.is_empty()
    }

    /// Whether the seller has paused the store (and not resumed it). A
    /// closed store is closed whatever this says.
    pub fn paused(&self) -> bool {
        crate::store_pause::is_paused(&self.pause)
    }

    /// What a reader should take a listing's availability to be: the status
    /// the store holds for it, or on sale and uncounted when it holds none
    /// (harvest#70).
    pub fn listing_availability(
        &self,
        listing: &crate::listing::ListingId,
    ) -> crate::listing::ListingAvailability {
        self.listing_statuses
            .records
            .get(&Bytes32(listing.0))
            .map(|status| status.status.availability.clone())
            .unwrap_or_default()
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
        self.copies
            .records
            .retain(|_, copy| !retirements.contains_key(&Bytes32(copy.copy.backer.to_bytes())));
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

    /// Keep a despatch only while the store holds its order (harvest#53
    /// Phase B).
    ///
    /// The order cap (`enforce_order_cap`) drops the oldest orders; without
    /// this, their despatches would stay behind as orphans no reader could
    /// place, and the state would stop being canonical.
    ///
    /// # Why it obeys the merge laws, in any arrival order
    ///
    /// Every state this contract accepts is normalized (`verify` refuses an
    /// orphan), so a despatch never arrives without its order in the same
    /// state. The kept orders are the top `MAX_ORDERS` of the union by a
    /// ranking the per-order merge cannot change (see `enforce_order_cap`),
    /// so an order cut from one union is cut from every union containing it,
    /// and its despatch with it; an order kept is kept everywhere, and so is
    /// the merged despatch in its slot. The despatch set is therefore "every
    /// despatch seen, restricted to the kept orders" whatever the grouping.
    ///
    /// A HAND-BUILT delta carrying a despatch but not its order, arriving at
    /// a replica that does not yet hold the order, loses the despatch here.
    /// Transient: the sender's summary still lists it, so the next exchange
    /// sends it again with the order. The app sends the order alongside
    /// (`ui/gateway/store_ops::despatch_delta_bytes`) so it does not rely on
    /// that.
    ///
    /// Not a check on the order's STATUS: see [`crate::fulfilment`] for why
    /// that would break convergence.
    pub(crate) fn normalize_fulfilment(&mut self) {
        let orders = &self.orders.orders;
        self.fulfilment
            .records
            .retain(|slot, _| orders.contains_key(&OrderId(slot.0)));
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
    /// nothing. With `unchecked`, a record is merged without being verified,
    /// and is noted there instead: see [`Self::apply_update`].
    fn apply_parts(
        &mut self,
        parameters: &StoreParameters,
        delta: &StoreStateV1Delta,
        unchecked: Option<&mut Unchecked>,
    ) -> Result<(), String> {
        let parent = self.owner_only();
        let mut next = self.clone();
        let Some(unchecked) = unchecked else {
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
            next.fulfilment
                .apply_delta(&parent, parameters, &delta.fulfilment)?;
            next.listing_statuses
                .apply_delta(&parent, parameters, &delta.listing_statuses)?;
            next.pause.apply_delta(&parent, parameters, &delta.pause)?;
            next.normalize_backings();
            next.normalize_fulfilment();
            *self = next;
            return Ok(());
        };
        // The same merge, each record that `apply_delta` would verify noted
        // instead, with the owner it would be verified against.
        let owner = self.owner;
        if let Some(info) = next.info.admit(&delta.info).cloned() {
            next.info = info.clone();
            unchecked.note(move |merged| {
                if merged.info == info {
                    return Ok(());
                }
                info.check_signature(owner_of(&owner)?)
            });
        }
        if let Some(incoming) = &delta.listings {
            let fresh = next.listings.admit(incoming)?;
            for listing in &fresh {
                let listing = (*listing).clone();
                unchecked.note(move |merged| {
                    if merged.listings.listings.contains(&listing) {
                        return Ok(());
                    }
                    listing.verify(owner_of(&owner)?)?;
                    crate::listing_image::check_listing_images(&listing.listing)
                });
            }
            next.listings.merge_unchecked(fresh);
        }
        if let Some(incoming) = &delta.orders {
            let fresh = next.orders.admit(incoming)?;
            for record in &fresh {
                let record = record.clone();
                unchecked.note(move |merged| {
                    if merged.orders.orders.get(&record.order.id) == Some(&record) {
                        return Ok(());
                    }
                    record
                        .verify(owner_of(&owner)?)
                        .map_err(|e| format!("order {} delta invalid: {e}", record.order.id))
                });
            }
            next.orders.merge_unchecked(fresh);
        }
        take_unchecked(&mut next.backings, &delta.backings, owner, unchecked, |s| {
            &s.backings
        })?;
        take_unchecked(
            &mut next.retirements,
            &delta.retirements,
            owner,
            unchecked,
            |s| &s.retirements,
        )?;
        take_unchecked(&mut next.closed, &delta.closed, owner, unchecked, |s| {
            &s.closed
        })?;
        take_unchecked(&mut next.copies, &delta.copies, owner, unchecked, |s| {
            &s.copies
        })?;
        take_unchecked(
            &mut next.fulfilment,
            &delta.fulfilment,
            owner,
            unchecked,
            |s| &s.fulfilment,
        )?;
        take_unchecked(
            &mut next.listing_statuses,
            &delta.listing_statuses,
            owner,
            unchecked,
            |s| &s.listing_statuses,
        )?;
        take_unchecked(&mut next.pause, &delta.pause, owner, unchecked, |s| {
            &s.pause
        })?;
        next.normalize_backings();
        next.normalize_fulfilment();
        *self = next;
        Ok(())
    }

    /// Apply a delta, deciding first whose records the store holds. All or
    /// nothing: on an error `self` is unchanged.
    fn apply_with(
        &mut self,
        parameters: &StoreParameters,
        delta: &StoreStateV1Delta,
        unchecked: Option<&mut Unchecked>,
    ) -> Result<(), String> {
        let Some(incoming) = delta.owner else {
            // No owner named: the records are verified against the owner
            // already held, and against nobody if there is none, which fails.
            return self.apply_parts(parameters, delta, unchecked);
        };
        if !parameters.admits(&incoming) {
            return Err(format!(
                "an update names owner {}, which does not begin with this store's code {}",
                bs58::encode(incoming.as_bytes()).into_string(),
                parameters.code()
            ));
        }
        match self.owner {
            Some(held) if held == incoming => self.apply_parts(parameters, delta, unchecked),
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
                claimed.apply_parts(parameters, delta, unchecked)?;
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

    /// [`ComposableState::apply_delta`] for the store contract's
    /// `update_state`, which costs half as much (step 2): a record is merged
    /// without being verified, and noted in `unchecked`, which the caller
    /// must check against the state it ends with ([`Unchecked::check`]).
    ///
    /// # Why the result is the same
    ///
    /// The node keeps a merged state only after the contract's
    /// `validate_state` passes on it, and that verifies every record the
    /// state holds (freenet-core: `contract_ops.rs` and `executor_impl.rs`
    /// call `validate_state` on the result of every `update_state` before
    /// committing it; its `.claude/rules/contracts.md`, "WHEN updating
    /// contract state", step 3). So `apply_delta` verified each record that
    /// lands twice, once as it arrived and once in the result: half of what
    /// a new subscriber's whole-store delta cost on a node (the step-2 wall
    /// time runs).
    ///
    /// [`Unchecked::check`] verifies every noted record the final state does
    /// NOT hold as it came: one that lost its slot, was cut by a bound, or
    /// was replaced by a later update. `validate_state` verifies the rest.
    /// So every record `apply_delta` would have verified is verified, by one
    /// or the other, and an update is accepted exactly when it was before. A
    /// record the merge throws away still has to be checked: a forged order
    /// that wins its slot and is then cut by the order bound would otherwise
    /// take a genuine one with it.
    ///
    /// Everything else -- the app, the delegate, the tests -- keeps calling
    /// `apply_delta`, which verifies everything itself.
    pub fn apply_update(
        &mut self,
        parameters: &StoreParameters,
        delta: &StoreStateV1Delta,
        unchecked: &mut Unchecked,
    ) -> Result<(), String> {
        self.apply_with(parameters, delta, Some(unchecked))
    }

    /// [`ComposableState::merge`] the way [`Self::apply_update`] applies a
    /// delta.
    pub fn merge_update(
        &mut self,
        parameters: &StoreParameters,
        other: &Self,
        unchecked: &mut Unchecked,
    ) -> Result<(), String> {
        let summary = self.summarize(self, parameters);
        match other.delta(other, parameters, &summary) {
            Some(delta) => self.apply_update(parameters, &delta, unchecked),
            None => Ok(()),
        }
    }

    /// The whole state as this generation keeps it, for a state an earlier
    /// generation wrote that a migration fold carries forward: the listings
    /// sorted and capped, the orders as kept and capped, the listing
    /// statuses capped, and a despatch for a cut order cut with it. Each is
    /// what `apply_delta` does to what it touches; the fold's merge skips the
    /// parts the other side brings nothing new for. (Step 2 changed no other
    /// cap.)
    pub fn normalize_carried(&mut self) {
        self.listings.normalize();
        self.orders.normalize();
        self.listing_statuses.normalize();
        self.normalize_fulfilment();
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
        self.listing_statuses.verify(&parent, parameters)?;
        self.pause.verify(&parent, parameters)?;
        self.backings.verify(&parent, parameters)?;
        self.retirements.verify(&parent, parameters)?;
        self.closed.verify(&parent, parameters)?;
        // A despatch only for an order the store holds: the state
        // `normalize_fulfilment` keeps. One no merge produces is refused.
        if let Some(slot) = self
            .fulfilment
            .records
            .keys()
            .find(|slot| !self.orders.orders.contains_key(&OrderId(slot.0)))
        {
            return Err(format!(
                "a despatch names order {}, which this store does not hold",
                OrderId(slot.0)
            ));
        }
        self.fulfilment.verify(&parent, parameters)
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
            fulfilment: self.fulfilment.summarize(&parent, parameters),
            listing_statuses: self.listing_statuses.summarize(&parent, parameters),
            pause: self.pause.summarize(&parent, parameters),
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
            fulfilment: self.fulfilment.delta(&parent, parameters, &base.fulfilment),
            listing_statuses: self.listing_statuses.delta(
                &parent,
                parameters,
                &base.listing_statuses,
            ),
            pause: self.pause.delta(&parent, parameters, &base.pause),
        };
        if delta.info.is_none()
            && delta.listings.is_none()
            && delta.orders.is_none()
            && delta.backings.is_none()
            && delta.retirements.is_none()
            && delta.closed.is_none()
            && delta.copies.is_none()
            && delta.fulfilment.is_none()
            && delta.listing_statuses.is_none()
            && delta.pause.is_none()
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
        match delta {
            Some(delta) => self.apply_with(parameters, delta, None),
            None => Ok(()),
        }
    }
}

/// The records an update merged without verifying them
/// ([`StoreStateV1::apply_update`]), each with how to tell whether the final
/// state holds it as it came and how to verify it if not.
#[derive(Default)]
pub struct Unchecked(Vec<Check>);

/// One noted record's check against the final state.
type Check = Box<dyn FnOnce(&StoreStateV1) -> Result<(), String>>;

impl Unchecked {
    fn note(&mut self, check: impl FnOnce(&StoreStateV1) -> Result<(), String> + 'static) {
        self.0.push(Box::new(check));
    }

    /// Verify every noted record `merged` does not hold as it came. The
    /// records it does hold are left to `validate_state`, which the caller
    /// must be sure runs on `merged` before anything keeps it.
    pub fn check(self, merged: &StoreStateV1) -> Result<(), String> {
        self.0.into_iter().try_for_each(|check| check(merged))
    }
}

/// One signed-set part of [`StoreStateV1::apply_parts`] with its checks
/// noted, not run: `held_in` finds the part in the final state.
fn take_unchecked<T: crate::backing::SignedRecord + 'static>(
    set: &mut SignedSetV1<T>,
    incoming: &Option<Vec<T>>,
    owner: Option<VerifyingKey>,
    unchecked: &mut Unchecked,
    held_in: fn(&StoreStateV1) -> &SignedSetV1<T>,
) -> Result<(), String> {
    let Some(incoming) = incoming else {
        return Ok(());
    };
    let fresh = set.admit(incoming)?;
    for record in &fresh {
        let record = (*record).clone();
        unchecked.note(move |merged| {
            if held_in(merged).records.get(&record.slot()) == Some(&record) {
                return Ok(());
            }
            record.verify_for(owner_of(&owner)?)
        });
    }
    set.merge_unchecked(fresh);
    Ok(())
}

/// A delta the way the store contract's `update_state` and then the node
/// apply it (step 2): [`StoreStateV1::apply_update`], its
/// [`Unchecked::check`], then `validate_state`'s `verify` on the result.
#[cfg(test)]
fn through_the_node(
    base: &StoreStateV1,
    parameters: &StoreParameters,
    delta: &StoreStateV1Delta,
) -> Result<StoreStateV1, String> {
    let mut state = base.clone();
    let mut unchecked = Unchecked::default();
    state.apply_update(parameters, delta, &mut unchecked)?;
    unchecked.check(&state)?;
    state.verify(&state, parameters)?;
    Ok(state)
}

/// The same delta through `apply_delta`, which verifies as it merges, then
/// `verify` on the result: what the node did before step 2.
#[cfg(test)]
fn through_apply_delta(
    base: &StoreStateV1,
    parameters: &StoreParameters,
    delta: &StoreStateV1Delta,
) -> Result<StoreStateV1, String> {
    let mut state = base.clone();
    state.apply_delta(base, parameters, &Some(delta.clone()))?;
    state.verify(&state, parameters)?;
    Ok(state)
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
            request_id: None,
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
            buyer_receipt_key: None,
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

    /// [`make_payment_proof`] whose transaction also pays filler outputs
    /// until it is at least `bytes` long: still the minimal proof (one
    /// claim, the one needed), and as large as a big honest transaction
    /// makes it.
    fn make_big_payment_proof(
        order: &Order,
        bridge: &SigningKey,
        bytes: usize,
    ) -> OrderPaymentProof {
        use freenet_bitcoin_common::spv::testing::{build_tx, mine, EASIEST_BITS};
        use freenet_bitcoin_common::spv::SpvProof;
        use freenet_bitcoin_common::Txid;
        let mut outputs = vec![(order.amount_sats, order.payment_script_pubkey.clone())];
        // Up to `bytes`, but never past the 64 KiB a bridge's evidence
        // allows one transaction.
        // Fewer than 0xfd outputs: `build_tx` writes the count as one byte.
        while outputs.len() < 0xfc && build_tx(&outputs).len() < bytes {
            let mut next = outputs.clone();
            next.push((546, vec![0x6a; 250]));
            if build_tx(&next).len() > 64 * 1024 {
                break;
            }
            outputs = next;
        }
        let raw_tx = build_tx(&outputs);
        let txid = Txid(sha2_d(&raw_tx));
        let header = mine([7u8; 32], txid.0, 1_700_000_000, EASIEST_BITS);
        let block_hash = BlockHash(sha2_d(&header.0));
        let anchor = BlockAnchor {
            height: 100,
            hash: block_hash,
        };
        let claim = SignedClaim::sign(
            bridge,
            &ClaimBody {
                script_id: order.bitcoin_params().script_id(),
                network: order.network,
                as_of: anchor,
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: order.amount_sats,
                    anchor,
                    spv: SpvProof {
                        raw_tx,
                        merkle_branch: Vec::new(),
                        tx_index: 0,
                        header,
                        following_headers: Vec::new(),
                    },
                },
            },
        )
        .unwrap();
        let tip = SignedTipEntry::sign(
            bridge,
            &TipEntryBody {
                network: order.network,
                anchor: BlockAnchor {
                    height: 100 + order.required_confirmations - 1,
                    hash: BlockHash([9u8; 32]),
                },
                prev_hash: BlockHash([8u8; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .unwrap();
        OrderPaymentProof::on_chain(vec![claim], tip)
    }

    /// Bitcoin's double SHA-256.
    fn sha2_d(bytes: &[u8]) -> [u8; 32] {
        freenet_bitcoin_common::spv::testing::sha256d_pub(bytes)
    }

    /// A raw, witness-stripped transaction with `inputs` inputs, each with a
    /// `script_sig` of the given length (0 for segwit, about 107 for a
    /// legacy P2PKH signature), paying the order and a P2WPKH change.
    fn tx_with_inputs(order: &Order, inputs: usize, script_sig: usize) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&2u32.to_le_bytes());
        t.push(inputs as u8);
        for i in 0..inputs {
            t.extend_from_slice(&[i as u8 + 1; 32]);
            t.extend_from_slice(&0u32.to_le_bytes());
            t.push(script_sig as u8);
            t.extend(std::iter::repeat_n(0x30u8, script_sig));
            t.extend_from_slice(&0xffff_fffdu32.to_le_bytes());
        }
        let change: Vec<u8> = [vec![0x00, 0x14], vec![0x77; 20]].concat();
        t.push(2);
        for (value, script) in [
            (order.amount_sats, order.payment_script_pubkey.clone()),
            (1_234_567u64, change),
        ] {
            t.extend_from_slice(&value.to_le_bytes());
            t.push(script.len() as u8);
            t.extend_from_slice(&script);
        }
        t.extend_from_slice(&0u32.to_le_bytes());
        t
    }

    /// A `Paid` record on the minimal proof whose one claim carries `raw_tx`.
    fn paid_on_tx(
        seller: &SigningKey,
        bridge: &SigningKey,
        order: &Order,
        raw_tx: Vec<u8>,
    ) -> AuthorizedOrder {
        use freenet_bitcoin_common::spv::testing::{mine, sha256d_pub, EASIEST_BITS};
        use freenet_bitcoin_common::spv::SpvProof;
        use freenet_bitcoin_common::Txid;
        let txid = Txid(sha256d_pub(&raw_tx));
        let merkle_branch: Vec<[u8; 32]> = (0..12u8).map(|d| [d + 5; 32]).collect();
        let root =
            freenet_bitcoin_common::spv::merkle_root_from_branch(&txid, &merkle_branch, 1).unwrap();
        let header = mine([7u8; 32], root, 1_700_000_000, EASIEST_BITS);
        let anchor = BlockAnchor {
            height: 100,
            hash: BlockHash(sha256d_pub(&header.0)),
        };
        let claim = SignedClaim::sign(
            bridge,
            &ClaimBody {
                script_id: order.bitcoin_params().script_id(),
                network: order.network,
                as_of: anchor,
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats: order.amount_sats,
                    anchor,
                    spv: SpvProof {
                        raw_tx,
                        merkle_branch,
                        tx_index: 1,
                        header,
                        following_headers: Vec::new(),
                    },
                },
            },
        )
        .unwrap();
        let tip = SignedTipEntry::sign(
            bridge,
            &TipEntryBody {
                network: order.network,
                anchor: BlockAnchor {
                    height: 100 + order.required_confirmations - 1,
                    hash: BlockHash([9u8; 32]),
                },
                prev_hash: BlockHash([8u8; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .unwrap();
        make_authorized_order(
            seller,
            order.clone(),
            OrderStatus::Paid,
            Some(OrderPaymentProof::on_chain(vec![claim], tip)),
        )
    }

    /// Step 2: what `MAX_PAID_ORDER_BYTES` admits of honest payments. The
    /// minimal `Paid` record for a payment whose transaction has 1, 2, 5,
    /// 10 or 20 inputs (two outputs, a 12-deep Merkle branch: a block of a
    /// few thousand transactions), segwit (the witness is not part of the
    /// evidence) and legacy P2PKH. Printed with `--nocapture`; asserted: a
    /// segwit payment of 20 inputs and a legacy one of 9 are kept paid.
    /// Measured at 8 KiB (2026-10-09): segwit 3.5 KB at 1 input, 4.5 KB at
    /// 20 (about 52 bytes an input, so about 89 inputs fit); legacy 4.0 KB
    /// at 1, 8.3 KB at 10.
    #[test]
    fn the_paid_byte_bound_admits_ordinary_payments() {
        let seller = seller_key();
        let bridge = bridge_key();
        let order = make_order("sizes", 1_700_000_000, &[0x00, 0x14, 0xcc, 0xcc]);
        let size = |inputs: usize, script_sig: usize| {
            let record = paid_on_tx(
                &seller,
                &bridge,
                &order,
                tx_with_inputs(&order, inputs, script_sig),
            );
            crate::payment::verify_payment_proof(&order, record.payment_proof.as_ref().unwrap())
                .expect("a genuine proof");
            let len = crate::to_cbor(&record).unwrap().len();
            // The floor `paid_within_cap` judges by first never passes the
            // record's real size, or an honest record would be stripped
            // without being measured.
            assert!(super::proof_bytes_at_least(&record) <= len);
            assert_eq!(paid_within_cap(&record), len <= MAX_PAID_ORDER_BYTES);
            len
        };
        for inputs in [1usize, 2, 5, 10, 20] {
            eprintln!(
                "PAID-SIZE inputs {inputs}: segwit {} bytes, legacy {} bytes (bound {MAX_PAID_ORDER_BYTES})",
                size(inputs, 0),
                size(inputs, 107)
            );
        }
        assert!(size(20, 0) <= MAX_PAID_ORDER_BYTES);
        assert!(size(9, 107) <= MAX_PAID_ORDER_BYTES);
    }

    /// Review round 4 of step 2 (codex, code-first): copies of a record
    /// the store holds, or repeated within a delta, change nothing and are
    /// not verified again, so replaying a genuine record costs no signature
    /// checks; and a delta carrying more orders than a store holds is
    /// refused whole. The result is the same as the delta with each record
    /// once. (The cost is pinned in `tests/contract-budget`'s replay rows.)
    #[test]
    fn copies_change_nothing_and_a_delta_past_the_cap_is_refused() {
        let seller = seller_key();
        let p = params(&seller);
        let unpaid = |n: i64| {
            make_authorized_order(
                &seller,
                make_order(
                    &format!("copy-{n}"),
                    1_700_000_000 + n,
                    &[0x00, 0x14, 0xaa, n as u8],
                ),
                OrderStatus::AwaitingPayment,
                None,
            )
        };
        let mut held = OrdersV1::default();
        held.apply_delta(&parent(), &p, &Some(vec![unpaid(1)]))
            .unwrap();
        let mut once = held.clone();
        once.apply_delta(&parent(), &p, &Some(vec![unpaid(2)]))
            .unwrap();
        let mut copies = held.clone();
        copies
            .apply_delta(
                &parent(),
                &p,
                &Some(vec![unpaid(1), unpaid(2), unpaid(1), unpaid(2), unpaid(2)]),
            )
            .unwrap();
        assert_eq!(copies, once);
        let why = held
            .apply_delta(&parent(), &p, &Some(vec![unpaid(1); MAX_ORDERS + 1]))
            .unwrap_err();
        assert!(why.contains("more than a store holds"), "{why}");
    }

    /// Step 2: the contract's `update_state` leaves a record the result
    /// holds to `validate_state`, and verifies one it does not. A forged
    /// order the order bound cuts on arrival is in no result, so only the
    /// second check sees it, and the update is refused as `apply_delta`
    /// refused it. Mutated red by skipping `Unchecked::check`.
    #[test]
    fn a_forged_order_the_cut_drops_is_still_refused() {
        let seller = seller_key();
        let p = params(&seller);
        let unpaid = |n: i64| {
            make_authorized_order(
                &seller,
                make_order(
                    &format!("cut-{n}"),
                    1_700_000_000 + n,
                    &[0x00, 0x14, 0xbb, (n % 251) as u8, (n / 251) as u8],
                ),
                OrderStatus::AwaitingPayment,
                None,
            )
        };
        let mut held = parent();
        held.apply_delta(
            &parent(),
            &p,
            &Some(StoreStateV1Delta {
                orders: Some((1..=MAX_ORDERS as i64).map(unpaid).collect()),
                ..Default::default()
            }),
        )
        .unwrap();
        // Older than every order held, so the bound cuts it at once.
        let mut forged = unpaid(0);
        forged.signature[0] ^= 1;
        let delta = StoreStateV1Delta {
            orders: Some(vec![forged.clone()]),
            ..Default::default()
        };
        let mut merged = held.clone();
        let mut unchecked = Unchecked::default();
        merged.apply_update(&p, &delta, &mut unchecked).unwrap();
        assert!(!merged.orders.orders.contains_key(&forged.order.id));
        assert_eq!(merged, held, "the cut record changed nothing");
        let why = unchecked.check(&merged).unwrap_err();
        assert!(why.contains("delta invalid"), "{why}");
        assert!(through_the_node(&held, &p, &delta).is_err());
        assert!(through_apply_delta(&held, &p, &delta).is_err());

        // One the result holds is left to `validate_state`, which refuses it.
        let mut forged_cancel = make_authorized_order(
            &seller,
            held.orders.orders.values().next().unwrap().order.clone(),
            OrderStatus::Cancelled,
            None,
        );
        forged_cancel.status_signature.as_mut().unwrap()[0] ^= 1;
        let delta = StoreStateV1Delta {
            orders: Some(vec![forged_cancel]),
            ..Default::default()
        };
        let mut merged = held.clone();
        let mut unchecked = Unchecked::default();
        merged.apply_update(&p, &delta, &mut unchecked).unwrap();
        unchecked
            .check(&merged)
            .expect("held as it came: left to validate");
        assert!(merged.verify(&merged, &p).is_err());
        assert!(through_apply_delta(&held, &p, &delta).is_err());
    }

    /// Step 2: a forged store info that a LATER update of the same
    /// `update_state` call replaces is in no result, so `validate_state`
    /// never sees it: `Unchecked::check` must, and the call is refused as
    /// `apply_delta` refused its first update. Mutated red by skipping the
    /// info's check.
    #[test]
    fn a_forged_info_a_later_update_replaces_is_still_refused() {
        let seller = seller_key();
        let p = params(&seller);
        let info = |version: u32, forged: bool| {
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
            let (scoped_payload, mut signature) = sign_scoped(&seller, &info);
            if forged {
                signature[0] ^= 1;
            }
            AuthorizedStoreInfoV1 {
                info,
                scoped_payload,
                signature,
            }
        };
        let delta = |info: AuthorizedStoreInfoV1| StoreStateV1Delta {
            info: Some(info),
            ..Default::default()
        };
        for forged in [false, true] {
            let mut merged = parent();
            let mut unchecked = Unchecked::default();
            for update in [delta(info(1, forged)), delta(info(2, false))] {
                merged.apply_update(&p, &update, &mut unchecked).unwrap();
            }
            assert_eq!(merged.info, info(2, false), "the later info replaced it");
            let checked = unchecked.check(&merged);
            if forged {
                let why = checked.unwrap_err();
                assert!(why.contains("store info"), "{why}");
                assert!(through_apply_delta(&parent(), &p, &delta(info(1, true))).is_err());
            } else {
                checked.expect("genuine infos pass");
            }
        }
    }

    /// Step 2, seeded: genuine and forged orders, at and past the bound,
    /// against a full store, in deltas of one to several records. Every
    /// delta the node path accepts, `apply_delta` accepts, to the same state,
    /// and every one it refuses, `apply_delta` refuses. Both outcomes occur,
    /// and so does a refusal only `Unchecked::check` makes.
    #[test]
    fn the_node_path_accepts_exactly_what_apply_delta_accepts_for_orders() {
        let seller = seller_key();
        let p = params(&seller);
        let order = |n: i64, status: OrderStatus, forged: bool| {
            let mut record = make_authorized_order(
                &seller,
                make_order(
                    &format!("eq-{n}"),
                    1_700_000_000 + n,
                    &[0x00, 0x14, 0xcc, (n % 251) as u8, (n / 251) as u8],
                ),
                status,
                None,
            );
            if forged {
                match record.status_signature.as_mut() {
                    Some(signature) => signature[0] ^= 1,
                    None => record.signature[0] ^= 1,
                }
            }
            record
        };
        let mut held = parent();
        held.apply_delta(
            &parent(),
            &p,
            &Some(StoreStateV1Delta {
                orders: Some(
                    (100..100 + MAX_ORDERS as i64)
                        .map(|n| order(n, OrderStatus::AwaitingPayment, false))
                        .collect(),
                ),
                ..Default::default()
            }),
        )
        .unwrap();
        let mut pool = Vec::new();
        // Older than all held (cut), among them, and newer (kept).
        for n in [0, 1, 150, 151, 200, 400, 401] {
            for status in [OrderStatus::AwaitingPayment, OrderStatus::Cancelled] {
                for forged in [false, true] {
                    pool.push(order(n, status, forged));
                }
            }
        }
        let mut rng = crate::merge_laws::Rng::new(0x5_7e9);
        let (mut accepted, mut refused, mut by_check) = (0, 0, 0);
        for round in 0..300 {
            let records = rng.subset(&pool, 1 + round % 4);
            let delta = StoreStateV1Delta {
                orders: Some(records),
                ..Default::default()
            };
            let node = through_the_node(&held, &p, &delta);
            let checked = through_apply_delta(&held, &p, &delta);
            match (&node, &checked) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a, b);
                    accepted += 1;
                }
                (Err(_), Err(_)) => refused += 1,
                _ => panic!("the paths disagree on {delta:?}: {node:?} against {checked:?}"),
            }
            let mut merged = held.clone();
            let mut unchecked = Unchecked::default();
            if merged.apply_update(&p, &delta, &mut unchecked).is_ok()
                && unchecked.check(&merged).is_err()
            {
                by_check += 1;
            }
        }
        assert!(
            accepted > 0 && refused > 0 && by_check > 0,
            "{accepted} {refused} {by_check}"
        );
    }

    /// Step 2: a `Paid` record on the minimal proof but past
    /// `MAX_PAID_ORDER_BYTES` is kept as its unpaid terms, and a state
    /// holding one does not verify; one just under it is kept paid. Mutated
    /// red by dropping the byte bound.
    #[test]
    fn a_paid_record_past_the_byte_bound_is_kept_unpaid() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let order = make_order("big", 1_700_000_000, &[0x00, 0x14, 0xbb, 0xbb]);
        let big = make_authorized_order(
            &seller,
            order.clone(),
            OrderStatus::Paid,
            Some(make_big_payment_proof(
                &order,
                &bridge,
                MAX_PAID_ORDER_BYTES,
            )),
        );
        let small = make_authorized_order(
            &seller,
            order.clone(),
            OrderStatus::Paid,
            Some(make_big_payment_proof(
                &order,
                &bridge,
                // A claim's transaction encodes at about four bytes a byte
                // in the record: an integer array inside the bridge's
                // signed body, itself an integer array (freenet-bitcoin's
                // encoding).
                MAX_PAID_ORDER_BYTES / 8,
            )),
        );
        let proof = big.payment_proof.as_ref().unwrap();
        crate::payment::verify_minimal_proof(&order, proof).expect("still the minimal proof");
        crate::payment::verify_payment_proof(&order, proof).expect("a genuine proof");
        assert!(crate::to_cbor(&big).unwrap().len() > MAX_PAID_ORDER_BYTES);
        assert!(crate::to_cbor(&small).unwrap().len() <= MAX_PAID_ORDER_BYTES);
        assert_eq!(as_kept(big.clone()).status, OrderStatus::AwaitingPayment);
        assert_eq!(as_kept(small.clone()), small);
        assert!(orders_of([(order.id.clone(), big)])
            .verify(&parent(), &p)
            .is_err());
        assert!(orders_of([(order.id.clone(), small)])
            .verify(&parent(), &p)
            .is_ok());
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
            request_id: None,
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
            buyer_receipt_key: None,
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

    /// **Every version of a request's answer ranks the same under the cap.**
    /// Two answers to one request can differ in their terms, amount
    /// included, but not in `created_at`: the id binds it. So answers made at
    /// different times are different orders, and the cap stays associative
    /// at the boundary for versions of one. Mutated red by dropping
    /// `created_at` from `OrderId::for_request` (the two dates are then one
    /// id, and the groupings disagree).
    #[test]
    fn the_order_cap_is_associative_for_two_answers_to_one_request() {
        let answer = |seed: u8, secs: i64, amount: u64| {
            let (_, mut record) = synthetic_order(seed, secs, OrderStatus::AwaitingPayment);
            record.order.request_id = Some([0x42; 32]);
            record.order.amount_sats = amount;
            record.order.id = OrderId::from_terms(&record.order);
            (record.order.id.clone(), record)
        };
        let (newest_id, newest) = answer(7, 9_000_000, 50_000);
        let (oldest_id, oldest) = answer(8, 10, 60_000);
        let p: BTreeMap<OrderId, AuthorizedOrder> = [(newest_id.clone(), newest)].into();
        let q: BTreeMap<OrderId, AuthorizedOrder> = [(oldest_id.clone(), oldest)].into();
        let r = full_of_old_orders();
        let enc = |m: &BTreeMap<OrderId, AuthorizedOrder>| crate::to_cbor(m).expect("encode");
        assert_eq!(
            enc(&merge_maps(&merge_maps(&p, &q), &r)),
            enc(&merge_maps(&p, &merge_maps(&q, &r))),
            "associativity"
        );
        assert_eq!(
            enc(&merge_maps(&merge_maps(&q, &p), &r)),
            enc(&merge_maps(&q, &merge_maps(&p, &r))),
            "associativity, the other way round"
        );
        assert_ne!(
            newest_id, oldest_id,
            "a different date is a different order"
        );
    }

    /// An answer re-dated under the id of the original is refused: the id
    /// is re-derived from the terms, date included, so a version of one id
    /// with another `created_at` does not verify. Mutated red by dropping
    /// the date from `OrderId::for_request`.
    #[test]
    fn a_re_dated_answer_under_the_original_id_is_refused() {
        use crate::test_orders::{authorized, order, store_key};
        let mut original = order(1);
        original.request_id = Some([0x42; 32]);
        let original = original.with_derived_id();
        let mut re_dated = original.clone();
        re_dated.created_at += chrono::Duration::days(365);
        let forged = authorized(&store_key(), re_dated, OrderStatus::AwaitingPayment);
        assert!(forged.verify_terms(&store_key().verifying_key()).is_err());
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

        // Step 2: a state holding the padded record does not verify, and a
        // padded record that arrives is kept as its unpaid terms
        // (`as_kept`), whichever way round the two meet.
        let honest_state = orders_of([(order.id.clone(), honest.clone())]);
        let padded_state = orders_of([(order.id.clone(), padded.clone())]);
        assert!(honest_state.verify(&parent(), &p).is_ok());
        assert!(
            padded_state.verify(&parent(), &p).is_err(),
            "a store does not hold Paid on padded evidence"
        );
        assert_eq!(
            as_kept(padded.clone()),
            make_authorized_order(&seller, order.clone(), OrderStatus::AwaitingPayment, None),
            "kept as its unpaid terms"
        );

        let mut honest_then_padded = honest_state.clone();
        honest_then_padded
            .merge(&parent(), &p, &padded_state)
            .unwrap();
        let mut padded_then_honest = OrdersV1::default();
        padded_then_honest
            .merge(&parent(), &p, &padded_state)
            .unwrap();
        assert_eq!(
            padded_then_honest.orders[&order.id].status,
            OrderStatus::AwaitingPayment,
            "a padded Paid arriving first is held unpaid"
        );
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
            "and the minimal one replaces the unpaid terms it was kept as"
        );
        assert!(padded_then_honest.verify(&parent(), &p).is_ok());
    }

    /// Step 2: the minimal-proof rule keeps the merge laws. States reached
    /// by merging deltas that mix, for the same orders, the unpaid terms, a
    /// minimal `Paid`, a `Paid` padded in two different ways and a
    /// cancellation: merging them in any order and grouping gives the same
    /// bytes, every result verifies, and no result holds a padded `Paid`.
    /// Mutated red by keeping a padded `Paid` in `apply_delta`.
    #[test]
    fn the_minimal_proof_rule_obeys_the_merge_laws() {
        let seller = seller_key();
        let bridge = bridge_key();
        let p = params(&seller);
        let mut versions: Vec<AuthorizedOrder> = Vec::new();
        for n in 0..4u8 {
            let order = make_order(
                &format!("buyer-{n}"),
                1_700_000_000 + i64::from(n),
                &[0x00, 0x14, n, 0xbb],
            );
            let minimal = make_payment_proof(&order, &bridge, 5);
            let mut padded = minimal.clone();
            on_chain_mut(&mut padded)
                .claims
                .push(scanned_to_claim(&order, &bridge, 1));
            let mut padded_more = padded.clone();
            on_chain_mut(&mut padded_more)
                .claims
                .push(scanned_to_claim(&order, &bridge, 2));
            versions.push(make_authorized_order(
                &seller,
                order.clone(),
                OrderStatus::AwaitingPayment,
                None,
            ));
            versions.push(make_authorized_order(
                &seller,
                order.clone(),
                OrderStatus::Paid,
                Some(minimal),
            ));
            versions.push(make_authorized_order(
                &seller,
                order.clone(),
                OrderStatus::Paid,
                Some(padded),
            ));
            versions.push(make_authorized_order(
                &seller,
                order.clone(),
                OrderStatus::Paid,
                Some(padded_more),
            ));
            // Minimal, but past the byte bound.
            versions.push(make_authorized_order(
                &seller,
                order.clone(),
                OrderStatus::Paid,
                Some(make_big_payment_proof(
                    &order,
                    &bridge,
                    MAX_PAID_ORDER_BYTES,
                )),
            ));
        }
        let merge = |a: &OrdersV1, b: &OrdersV1| {
            let mut out = a.clone();
            out.merge(&parent(), &p, b).expect("merges");
            out
        };
        let mut rng = crate::merge_laws::Rng::new(0x5ec0d);
        let mut states = vec![OrdersV1::default()];
        for _ in 0..16 {
            let mut delta = OrdersV1::default();
            for _ in 0..1 + rng.below(5) {
                let v = versions[rng.below(versions.len())].clone();
                delta.orders.insert(v.order.id.clone(), v);
            }
            // Held only as the store keeps it: through `apply_delta`.
            let mut state = OrdersV1::default();
            state
                .apply_delta(&parent(), &p, &Some(delta.orders.into_values().collect()))
                .expect("applies");
            states.push(state);
        }
        for s in &states {
            s.verify(&parent(), &p).expect("every state verifies");
        }
        assert!(
            states
                .iter()
                .any(|s| s.orders.values().any(|o| o.status == OrderStatus::Paid)),
            "a minimal Paid is held somewhere"
        );
        crate::merge_laws::assert_laws(&states, 300, &mut rng, merge, |s| {
            crate::to_cbor(s).unwrap()
        });
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
            images: Vec::new(),
            checkout: None,
            choices: Vec::new(),
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

    /// The store refuses a listing whose photos break the caps
    /// (`crate::listing_image`), on BOTH ways in: a delta adding it, and a
    /// whole state holding it. Signed by the right key, so the photos are the
    /// only thing wrong.
    #[test]
    fn a_listing_with_too_many_photos_is_refused_by_delta_and_by_state() {
        use crate::listing_image::{ImageBlob, ListingImage, MAX_IMAGES_HARD};
        use freenet_scaffold::ComposableState;

        let seller = seller_key();
        let p = params(&seller);
        let with_photos = |n: usize| {
            let mut a = make_listing(&seller, "Photographed");
            a.listing.images = (0..n)
                .map(|i| ListingImage {
                    full: ImageBlob {
                        hash: Bytes32([i as u8 + 1; 32]),
                        len: 1000,
                        width: 800,
                        height: 600,
                    },
                    thumb: (i == 0).then_some(ImageBlob {
                        hash: Bytes32([200; 32]),
                        len: 100,
                        width: 400,
                        height: 300,
                    }),
                    colour: [0, 0, 0],
                    alt: String::new(),
                })
                .collect();
            a.listing = a.listing.clone().with_derived_id();
            let (scoped_payload, signature) = sign_scoped(&seller, &a.listing);
            a.scoped_payload = scoped_payload;
            a.signature = signature;
            a
        };
        let too_many = with_photos(MAX_IMAGES_HARD + 1);
        let fine = with_photos(MAX_IMAGES_HARD);

        let mut state = ListingsV1::default();
        let err = state
            .apply_delta(&parent(), &p, &Some(vec![too_many.clone()]))
            .expect_err("a delta adding a listing with nine photos must be refused");
        assert!(err.contains("photos"), "{err}");
        assert!(state.listings.is_empty());
        state
            .apply_delta(&parent(), &p, &Some(vec![fine.clone()]))
            .expect("eight photos apply");

        let whole = ListingsV1 {
            listings: vec![too_many],
        };
        let err = whole
            .verify(&parent(), &p)
            .expect_err("a state holding a listing with nine photos must not verify");
        assert!(err.contains("photos"), "{err}");
        let whole = ListingsV1 {
            listings: vec![fine],
        };
        whole.verify(&parent(), &p).expect("eight photos verify");

        // The photos are inside the signed terms: swapping one on a signed
        // listing, even for another valid reference, breaks its signature.
        let mut swapped = with_photos(2);
        swapped.listing.images[1].full.hash = Bytes32([250; 32]);
        swapped.listing = swapped.listing.clone().with_derived_id();
        let err = ListingsV1 {
            listings: vec![swapped],
        }
        .verify(&parent(), &p)
        .expect_err("a listing whose photos were changed after signing must not verify");
        assert!(
            !err.contains("photos"),
            "refused for its signature, not a cap: {err}"
        );
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

    /// harvest#53 Phase B: the buyer's cancel and the seller's despatch.
    mod fulfilment_tests {
        use super::*;
        use crate::fulfilment::{AuthorizedDespatch, Despatch};

        fn buyer_key() -> SigningKey {
            SigningKey::from_bytes(&[44u8; 32])
        }

        /// An order carrying the buyer's receipt key, as Phase B's buy flow
        /// produces.
        fn buyer_keyed_order(created_at_secs: i64) -> Order {
            let mut order = make_order("", created_at_secs, &[0x00, 0x14, 0x07, 0x07]);
            order.buyer_receipt_key = Some(buyer_key().verifying_key().to_bytes());
            order.with_derived_id()
        }

        /// `order` cancelled by `signer` over `(id, Cancelled)`.
        fn cancelled_by(
            seller: &SigningKey,
            order: &Order,
            signer: &SigningKey,
        ) -> AuthorizedOrder {
            let mut record =
                make_authorized_order(seller, order.clone(), OrderStatus::AwaitingPayment, None);
            let (sp, sig) = sign_scoped(signer, &(order.id.clone(), OrderStatus::Cancelled));
            record.status = OrderStatus::Cancelled;
            record.status_scoped_payload = Some(sp);
            record.status_signature = Some(sig);
            record
        }

        fn despatch(order: &Order, height: u32, signer: &SigningKey) -> AuthorizedDespatch {
            let despatch = Despatch {
                order_id: order.id.clone(),
                anchor: BlockAnchor {
                    height,
                    hash: BlockHash([height as u8; 32]),
                },
            };
            let (scoped_payload, signature) = sign_scoped(signer, &despatch);
            AuthorizedDespatch {
                despatch,
                scoped_payload,
                signature,
            }
        }

        fn store_with(orders: Vec<AuthorizedOrder>) -> StoreStateV1 {
            let mut s = StoreStateV1 {
                owner: Some(seller_key().verifying_key()),
                ..Default::default()
            };
            for o in orders {
                merge_order(&mut s.orders.orders, o);
            }
            s
        }

        fn delta_of(despatches: Vec<AuthorizedDespatch>) -> StoreStateV1Delta {
            StoreStateV1Delta {
                owner: Some(seller_key().verifying_key()),
                fulfilment: Some(despatches),
                ..Default::default()
            }
        }

        #[test]
        fn the_buyer_can_cancel_an_order_carrying_their_receipt_key() {
            let seller = seller_key();
            let order = buyer_keyed_order(1_700_000_000);
            let record = cancelled_by(&seller, &order, &buyer_key());
            record
                .verify(&seller.verifying_key())
                .expect("a cancel signed by the order's buyer receipt key verifies");
            // The seller's cancel of the same order still verifies too.
            cancelled_by(&seller, &order, &seller)
                .verify(&seller.verifying_key())
                .expect("the seller can still cancel");
        }

        #[test]
        fn nobody_else_can_cancel_and_an_order_without_a_buyer_key_takes_only_the_sellers() {
            let seller = seller_key();
            let stranger = SigningKey::from_bytes(&[55u8; 32]);
            let order = buyer_keyed_order(1_700_000_000);
            let err = cancelled_by(&seller, &order, &stranger)
                .verify(&seller.verifying_key())
                .expect_err("a stranger's cancel is refused");
            assert!(err.contains("neither the seller"), "{err}");

            // Before Phase B an order carried no buyer key: only the seller
            // can cancel it, whoever else signs.
            let unkeyed = make_order("", 1_700_000_000, &[0x00, 0x14, 0x07, 0x07]);
            assert!(cancelled_by(&seller, &unkeyed, &buyer_key())
                .verify(&seller.verifying_key())
                .is_err());
        }

        /// A small-order buyer key (here the identity point) accepts a
        /// signature anyone can make, so an order naming one must not take a
        /// "buyer" cancel at all: otherwise any stranger could sign as its
        /// buyer, and in Phase C file its complaint.
        #[test]
        fn a_weak_buyer_key_takes_no_buyer_signature() {
            let seller = seller_key();
            let mut identity = [0u8; 32];
            identity[0] = 1;
            assert!(ed25519_dalek::VerifyingKey::from_bytes(&identity)
                .expect("the identity point decodes")
                .is_weak());
            let mut order = make_order("", 1_700_000_000, &[0x00, 0x14, 0x07, 0x07]);
            order.buyer_receipt_key = Some(identity);
            let order = order.with_derived_id();

            // The forgery: R = identity, s = 0, over the right message.
            let mut record =
                make_authorized_order(&seller, order.clone(), OrderStatus::AwaitingPayment, None);
            let (sp, _) = sign_scoped(&seller, &(order.id.clone(), OrderStatus::Cancelled));
            let mut forged = [0u8; 64];
            forged[0] = 1;
            record.status = OrderStatus::Cancelled;
            record.status_scoped_payload = Some(sp);
            record.status_signature = Some(forged.to_vec());
            // The premise: the non-strict check really does accept this
            // forgery under the weak key, so the refusal below is what stops
            // it, not a signature that fails anyway.
            {
                use ed25519_dalek::Verifier;
                let weak = ed25519_dalek::VerifyingKey::from_bytes(&identity).unwrap();
                assert!(weak
                    .verify(
                        record.status_scoped_payload.as_ref().unwrap(),
                        &ed25519_dalek::Signature::from_bytes(&forged)
                    )
                    .is_ok());
            }
            let err = record
                .verify(&seller.verifying_key())
                .expect_err("a signature anyone can make is not the buyer's");
            assert!(err.contains("weak"), "{err}");
        }

        #[test]
        fn a_buyers_cancel_of_one_order_is_not_a_cancel_of_another() {
            let seller = seller_key();
            let order = buyer_keyed_order(1_700_000_000);
            let other = buyer_keyed_order(1_700_000_500);
            assert_ne!(order.id, other.id);
            // The buyer's signature over `order`'s id, stapled onto `other`.
            let signed = cancelled_by(&seller, &order, &buyer_key());
            let mut replayed = cancelled_by(&seller, &other, &buyer_key());
            replayed.status_scoped_payload = signed.status_scoped_payload.clone();
            replayed.status_signature = signed.status_signature.clone();
            assert!(replayed.verify(&seller.verifying_key()).is_err());
        }

        #[test]
        fn a_buyers_cancel_never_displaces_a_payment() {
            let seller = seller_key();
            let order = buyer_keyed_order(1_700_000_000);
            let paid = make_authorized_order(
                &seller,
                order.clone(),
                OrderStatus::Paid,
                Some(make_payment_proof(&order, &bridge_key(), 3)),
            );
            paid.verify(&seller.verifying_key()).expect("fixture paid");
            let mut orders = BTreeMap::new();
            merge_order(&mut orders, paid.clone());
            merge_order(&mut orders, cancelled_by(&seller, &order, &buyer_key()));
            assert_eq!(orders[&order.id].status, OrderStatus::Paid);
        }

        #[test]
        fn the_store_key_can_despatch_any_order_it_holds_and_nobody_else_can() {
            let seller = seller_key();
            let p = params(&seller);
            let order = buyer_keyed_order(1_700_000_000);
            // Unpaid on purpose: the contract does not check the order's
            // status (see `crate::fulfilment`); readers ignore it.
            let base = store_with(vec![make_authorized_order(
                &seller,
                order.clone(),
                OrderStatus::AwaitingPayment,
                None,
            )]);

            let mut kept = base.clone();
            kept.apply_delta(
                &base,
                &p,
                &Some(delta_of(vec![despatch(&order, 900, &seller)])),
            )
            .expect("the store key's despatch applies");
            assert_eq!(kept.fulfilment.records.len(), 1);
            kept.verify(&kept, &p).expect("and the result verifies");

            let stranger = SigningKey::from_bytes(&[55u8; 32]);
            let mut refused = base.clone();
            assert!(refused
                .apply_delta(
                    &base,
                    &p,
                    &Some(delta_of(vec![despatch(&order, 900, &stranger)]))
                )
                .is_err());
            assert_eq!(refused, base, "a refused delta changes nothing");
            // Not even the buyer, whose key the order names.
            assert!(refused
                .apply_delta(
                    &base,
                    &p,
                    &Some(delta_of(vec![despatch(&order, 900, &buyer_key())]))
                )
                .is_err());
        }

        #[test]
        fn a_despatch_for_an_order_the_store_does_not_hold_is_refused_or_dropped() {
            let seller = seller_key();
            let p = params(&seller);
            let held = buyer_keyed_order(1_700_000_000);
            let absent = buyer_keyed_order(1_700_000_900);
            let base = store_with(vec![make_authorized_order(
                &seller,
                held.clone(),
                OrderStatus::AwaitingPayment,
                None,
            )]);

            // A state holding an orphan is one no merge produces.
            let mut orphaned = base.clone();
            let d = despatch(&absent, 900, &seller);
            orphaned
                .fulfilment
                .records
                .insert(crate::backing::SignedRecord::slot(&d), d.clone());
            let err = orphaned
                .verify(&orphaned, &p)
                .expect_err("an orphan is refused");
            assert!(err.contains("does not hold"), "{err}");

            // A delta carrying one is applied and the orphan dropped.
            let mut merged = base.clone();
            merged
                .apply_delta(&base, &p, &Some(delta_of(vec![d])))
                .expect("a well-signed despatch is not an error");
            assert!(merged.fulfilment.is_empty());
            merged.verify(&merged, &p).expect("the result verifies");

            // With its order alongside, it is kept.
            let mut with_order = base.clone();
            let mut delta = delta_of(vec![despatch(&absent, 900, &seller)]);
            delta.orders = Some(vec![make_authorized_order(
                &seller,
                absent.clone(),
                OrderStatus::AwaitingPayment,
                None,
            )]);
            with_order
                .apply_delta(&base, &p, &Some(delta))
                .expect("applies");
            assert_eq!(with_order.fulfilment.records.len(), 1);
        }

        /// A despatch whose order the cap drops goes with it, and the
        /// despatch set obeys the merge laws at the cap. Structural, like the
        /// other cap tests: the unsigned records never meet `verify`.
        #[test]
        fn a_despatch_goes_when_the_cap_drops_its_order_and_the_laws_hold_at_the_cap() {
            type S = (
                BTreeMap<OrderId, AuthorizedOrder>,
                BTreeMap<Bytes32, AuthorizedDespatch>,
            );
            fn fake_despatch(id: &OrderId, height: u32) -> AuthorizedDespatch {
                AuthorizedDespatch {
                    despatch: Despatch {
                        order_id: id.clone(),
                        anchor: BlockAnchor {
                            height,
                            hash: BlockHash([0; 32]),
                        },
                    },
                    scoped_payload: vec![],
                    signature: vec![],
                }
            }
            // What `StoreStateV1::apply_parts` does once everything has
            // verified: merge orders and cap, union despatches keeping the
            // smaller encoding, then `normalize_fulfilment`.
            fn merge(a: &S, b: &S) -> S {
                let mut state = StoreStateV1 {
                    orders: OrdersV1 {
                        orders: merge_maps(&a.0, &b.0),
                    },
                    ..Default::default()
                };
                let mut despatches = a.1.clone();
                for (slot, d) in &b.1 {
                    match despatches.get(slot) {
                        Some(held)
                            if crate::to_cbor(held).unwrap() <= crate::to_cbor(d).unwrap() => {}
                        _ => {
                            despatches.insert(*slot, d.clone());
                        }
                    }
                }
                state.fulfilment.records = despatches;
                state.normalize_fulfilment();
                (state.orders.orders, state.fulfilment.records)
            }

            let (old_id, old) = synthetic_order(250, 10, OrderStatus::Paid);
            let (new_id, new) = synthetic_order(251, 9_000_000, OrderStatus::Paid);
            let with =
                |orders: BTreeMap<OrderId, AuthorizedOrder>, ds: &[AuthorizedDespatch]| -> S {
                    let mut state = StoreStateV1 {
                        orders: OrdersV1 { orders },
                        ..Default::default()
                    };
                    for d in ds {
                        state
                            .fulfilment
                            .records
                            .insert(Bytes32(d.despatch.order_id.0), d.clone());
                    }
                    state.normalize_fulfilment();
                    (state.orders.orders, state.fulfilment.records)
                };
            let small: S = with(
                [(old_id.clone(), old.clone()), (new_id.clone(), new.clone())].into(),
                &[fake_despatch(&old_id, 5), fake_despatch(&new_id, 7)],
            );
            assert_eq!(small.1.len(), 2, "both kept while both orders are");
            let full: S = with(full_of_old_orders(), &[]);

            let merged = merge(&small, &full);
            assert!(
                !merged.0.contains_key(&old_id),
                "the cap drops the oldest order"
            );
            assert!(
                !merged.1.contains_key(&Bytes32(old_id.0)),
                "and its despatch with it"
            );
            assert!(
                merged.1.contains_key(&Bytes32(new_id.0)),
                "the newest keeps its despatch"
            );

            // The laws, over states holding the same orders' despatches at
            // different anchors (a clash in one slot) around the cap.
            let states: Vec<S> = vec![
                small.clone(),
                full.clone(),
                with(
                    [(old_id.clone(), old.clone())].into(),
                    &[fake_despatch(&old_id, 3)],
                ),
                with(
                    [(new_id.clone(), new.clone())].into(),
                    &[fake_despatch(&new_id, 9)],
                ),
                with(BTreeMap::new(), &[]),
            ];
            let enc = |s: &S| crate::to_cbor(s).expect("encode");
            for a in &states {
                assert_eq!(enc(&merge(a, a)), enc(a), "idempotence");
                for b in &states {
                    assert_eq!(enc(&merge(a, b)), enc(&merge(b, a)), "commutativity");
                    for c in &states {
                        assert_eq!(
                            enc(&merge(&merge(a, b), c)),
                            enc(&merge(a, &merge(b, c))),
                            "associativity"
                        );
                    }
                }
            }
        }

        /// **Seeded random merge laws with both Phase B records**, through
        /// the real `merge` (signatures verified): buyer and seller cancels
        /// of one order, a payment over them, and despatches at two anchors
        /// for one order.
        #[test]
        fn seeded_random_stores_with_cancels_and_despatches_obey_the_merge_laws() {
            use crate::merge_laws::{assert_laws, Rng};
            use freenet_scaffold::ComposableState;

            let seller = seller_key();
            let p = params(&seller);
            let x = buyer_keyed_order(1_700_000_000);
            let y = buyer_keyed_order(1_700_000_100);
            let orders = vec![
                make_authorized_order(&seller, x.clone(), OrderStatus::AwaitingPayment, None),
                cancelled_by(&seller, &x, &seller),
                cancelled_by(&seller, &x, &buyer_key()),
                make_authorized_order(
                    &seller,
                    x.clone(),
                    OrderStatus::Paid,
                    Some(make_payment_proof(&x, &bridge_key(), 3)),
                ),
                make_authorized_order(&seller, y.clone(), OrderStatus::AwaitingPayment, None),
                cancelled_by(&seller, &y, &buyer_key()),
            ];
            for o in &orders {
                o.verify(&seller.verifying_key())
                    .expect("fixture order verifies");
            }
            let despatches = vec![
                despatch(&x, 900, &seller),
                despatch(&x, 950, &seller),
                despatch(&y, 901, &seller),
            ];
            let merge = |a: &StoreStateV1, b: &StoreStateV1| {
                let mut out = a.clone();
                out.merge(&a.clone(), &p, b).expect("merge");
                out.listings.normalize();
                out
            };
            let mut rng = Rng::new(0x5eed_0053);
            let states: Vec<StoreStateV1> = (0..200)
                .map(|_| {
                    let mut s = StoreStateV1::default();
                    for o in rng.subset(&orders, 3) {
                        merge_order(&mut s.orders.orders, o);
                    }
                    for d in rng.subset(&despatches, 2) {
                        let slot = crate::backing::SignedRecord::slot(&d);
                        match s.fulfilment.records.get(&slot) {
                            Some(held)
                                if crate::to_cbor(held).unwrap() <= crate::to_cbor(&d).unwrap() => {
                            }
                            _ => {
                                s.fulfilment.records.insert(slot, d);
                            }
                        }
                    }
                    s.normalize_fulfilment();
                    if s.holds_signed_content() {
                        s.owner = Some(seller.verifying_key());
                    }
                    s.verify(&s, &p).expect("fixture state verifies");
                    s
                })
                .collect();
            assert!(
                states.iter().any(|s| !s.fulfilment.is_empty()),
                "the corpus must actually hold despatches"
            );
            assert_laws(&states, 300, &mut rng, merge, |s| {
                crate::to_cbor(s).expect("encode")
            });
        }

        /// A despatch is exchanged exactly when the other side lacks it: a
        /// holder's own summary asks for nothing, and a summary without the
        /// despatch gets it (with its order, when that is missing too).
        #[test]
        fn a_despatch_travels_by_summary_and_delta_and_only_when_missing() {
            use freenet_scaffold::ComposableState;
            let seller = seller_key();
            let p = params(&seller);
            let order = buyer_keyed_order(1_700_000_000);
            let record =
                make_authorized_order(&seller, order.clone(), OrderStatus::AwaitingPayment, None);
            let without = store_with(vec![record.clone()]);
            let mut with = without.clone();
            with.apply_delta(
                &without,
                &p,
                &Some(delta_of(vec![despatch(&order, 900, &seller)])),
            )
            .expect("applies");

            assert!(
                with.delta(&with, &p, &with.summarize(&with, &p)).is_none(),
                "nothing to send to a peer that already holds it"
            );
            let d = with
                .delta(&with, &p, &without.summarize(&without, &p))
                .expect("the despatch is missing there");
            assert_eq!(d.fulfilment.as_ref().map(Vec::len), Some(1));
            assert!(d.orders.is_none(), "the order is already held there");
            let mut caught_up = without.clone();
            caught_up
                .apply_delta(&without, &p, &Some(d))
                .expect("applies");
            assert_eq!(caught_up, with);

            let empty = StoreStateV1::default();
            let d = with
                .delta(&with, &p, &empty.summarize(&empty, &p))
                .expect("everything is missing there");
            assert!(d.orders.is_some() && d.fulfilment.is_some());
            let mut fresh = empty.clone();
            fresh.apply_delta(&empty, &p, &Some(d)).expect("applies");
            assert_eq!(fresh, with);
        }

        /// A state holding no despatch encodes exactly as before the part
        /// existed, so every earlier generation's state re-encodes to its own
        /// bytes and its summary is unchanged.
        #[test]
        fn a_store_without_despatches_encodes_as_it_did() {
            let seller = seller_key();
            let p = params(&seller);
            let s = store_with(vec![make_authorized_order(
                &seller,
                buyer_keyed_order(1_700_000_000),
                OrderStatus::AwaitingPayment,
                None,
            )]);
            let bytes = crate::to_cbor(&s).unwrap();
            assert!(!contains(&bytes, b"fulfilment"));
            let summary = crate::to_cbor(&s.summarize(&s, &p)).unwrap();
            assert!(!contains(&summary, b"fulfilment"));
            let delta = crate::to_cbor(&StoreStateV1Delta {
                owner: s.owner,
                ..Default::default()
            })
            .unwrap();
            assert!(!contains(&delta, b"fulfilment"));
        }

        fn contains(haystack: &[u8], needle: &[u8]) -> bool {
            haystack.windows(needle.len()).any(|w| w == needle)
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

#[cfg(test)]
mod listing_status_tests {
    //! harvest#70: a listing's availability, signed by the store key, the
    //! highest revision kept.
    use super::*;
    use crate::backing::{sign_with_store_key, SignedRecord};
    use crate::listing::{AuthorizedListingStatus, ListingAvailability, ListingStatus};
    use crate::merge_laws::{assert_laws, Rng};
    use ed25519_dalek::SigningKey;

    fn store_key() -> SigningKey {
        SigningKey::from_bytes(&[0x61; 32])
    }

    fn params() -> StoreParameters {
        StoreParameters::new(store_key().verifying_key())
    }

    fn status(
        key: &SigningKey,
        listing: u8,
        revision: u64,
        availability: ListingAvailability,
    ) -> AuthorizedListingStatus {
        let status = ListingStatus {
            listing: ListingId([listing; 32]),
            revision,
            availability,
        };
        let (scoped_payload, signature) =
            sign_with_store_key(key, crate::to_cbor(&status).unwrap()).expect("a store record");
        AuthorizedListingStatus {
            status,
            scoped_payload,
            signature,
        }
    }

    fn state_with(statuses: Vec<AuthorizedListingStatus>) -> StoreStateV1 {
        let mut state = StoreStateV1 {
            owner: Some(store_key().verifying_key()),
            ..Default::default()
        };
        state
            .apply_delta(
                &StoreStateV1::default(),
                &params(),
                &Some(StoreStateV1Delta {
                    owner: Some(store_key().verifying_key()),
                    listing_statuses: Some(statuses),
                    ..Default::default()
                }),
            )
            .expect("statuses signed by the owner apply");
        state
    }

    fn merged(a: &StoreStateV1, b: &StoreStateV1) -> StoreStateV1 {
        let mut out = a.clone();
        out.merge(&a.clone(), &params(), b).expect("merge");
        out
    }

    fn bytes(state: &StoreStateV1) -> Vec<u8> {
        crate::to_cbor(state).expect("encode")
    }

    /// A later status supersedes an earlier one, whichever arrives first.
    /// Mutated red by making `rank` return 0 (the smaller encoding then
    /// decides, and `SoldOut` is smaller than `Available`).
    #[test]
    fn the_highest_revision_wins_in_either_order() {
        let early = status(&store_key(), 1, 5, ListingAvailability::SoldOut);
        let late = status(
            &store_key(),
            1,
            9,
            ListingAvailability::Available { quantity: Some(3) },
        );
        let a = state_with(vec![early.clone()]);
        let b = state_with(vec![late.clone()]);
        for out in [merged(&a, &b), merged(&b, &a)] {
            assert_eq!(
                out.listing_availability(&ListingId([1; 32])),
                ListingAvailability::Available { quantity: Some(3) },
            );
        }
        // And a stale status arriving later does not displace the newer one.
        let mut held = b.clone();
        held.apply_delta(
            &StoreStateV1::default(),
            &params(),
            &Some(StoreStateV1Delta {
                owner: None,
                listing_statuses: Some(vec![early]),
                ..Default::default()
            }),
        )
        .expect("a stale status is valid, and loses");
        assert_eq!(bytes(&held), bytes(&b));
    }

    /// Two statuses at one revision resolve the way every other signed
    /// record does: the smaller encoding, the same on every replica.
    #[test]
    fn equal_revisions_resolve_to_the_smaller_encoding() {
        let sold = status(&store_key(), 2, 7, ListingAvailability::SoldOut);
        let down = status(&store_key(), 2, 7, ListingAvailability::Withdrawn);
        let smaller = if crate::to_cbor(&sold).unwrap() <= crate::to_cbor(&down).unwrap() {
            ListingAvailability::SoldOut
        } else {
            ListingAvailability::Withdrawn
        };
        let a = state_with(vec![sold]);
        let b = state_with(vec![down]);
        assert_eq!(bytes(&merged(&a, &b)), bytes(&merged(&b, &a)));
        assert_eq!(
            merged(&a, &b).listing_availability(&ListingId([2; 32])),
            smaller
        );
    }

    /// No status reads as on sale, uncounted: every listing published before
    /// statuses existed.
    #[test]
    fn a_listing_with_no_status_is_available_and_uncounted() {
        let state = state_with(vec![status(
            &store_key(),
            3,
            1,
            ListingAvailability::Withdrawn,
        )]);
        assert_eq!(
            state.listing_availability(&ListingId([4; 32])),
            ListingAvailability::Available { quantity: None }
        );
        assert!(ListingAvailability::default().is_buyable());
        assert!(!ListingAvailability::Available { quantity: Some(0) }.is_buyable());
        assert!(!ListingAvailability::SoldOut.is_buyable());
        assert!(!ListingAvailability::Withdrawn.is_buyable());
    }

    /// Only the store key can say a listing sold out or was taken down.
    /// Anybody else's status is refused, and the refused delta leaves the
    /// state exactly as it was, other parts included. Mutated red by making
    /// `AuthorizedListingStatus::verify` return `Ok(())`.
    #[test]
    fn a_status_not_signed_by_the_store_key_is_refused() {
        let stranger = SigningKey::from_bytes(&[0x62; 32]);
        let held = state_with(vec![status(
            &store_key(),
            5,
            1,
            ListingAvailability::Available { quantity: Some(1) },
        )]);
        let mut attempt = held.clone();
        let refused = attempt.apply_delta(
            &StoreStateV1::default(),
            &params(),
            &Some(StoreStateV1Delta {
                owner: None,
                listing_statuses: Some(vec![status(
                    &stranger,
                    5,
                    99,
                    ListingAvailability::Withdrawn,
                )]),
                ..Default::default()
            }),
        );
        assert!(refused.is_err(), "a stranger's status must not apply");
        assert_eq!(bytes(&attempt), bytes(&held));

        // And a whole state carrying one does not verify.
        let mut forged = held.clone();
        let bad = status(&stranger, 6, 1, ListingAvailability::SoldOut);
        forged
            .listing_statuses
            .records
            .insert(Bytes32([6; 32]), bad);
        assert!(forged.verify(&StoreStateV1::default(), &params()).is_err());
    }

    /// A status filed under another listing's slot does not verify, so a
    /// valid signature over listing A cannot be made to speak for listing B.
    #[test]
    fn a_status_under_the_wrong_slot_does_not_verify() {
        let mut state = state_with(vec![]);
        state.listing_statuses.records.insert(
            Bytes32([8; 32]),
            status(&store_key(), 7, 1, ListingAvailability::Withdrawn),
        );
        assert!(state.verify(&StoreStateV1::default(), &params()).is_err());
    }

    /// A status alone is signed content: a store holding only statuses names
    /// its owner validly, and one with no owner cannot hold them.
    #[test]
    fn a_status_counts_as_signed_content() {
        let state = state_with(vec![status(
            &store_key(),
            9,
            1,
            ListingAvailability::SoldOut,
        )]);
        assert!(state.holds_signed_content());
        assert!(state.verify(&StoreStateV1::default(), &params()).is_ok());
        let mut unowned = state.clone();
        unowned.owner = None;
        assert!(unowned.verify(&StoreStateV1::default(), &params()).is_err());
    }

    /// A state holding no statuses encodes exactly as it did before they
    /// existed, so `validate_state`'s re-encoding check accepts every earlier
    /// state, and a summary or delta with none is byte-for-byte the old one.
    #[test]
    fn no_statuses_encode_as_before_they_existed() {
        let state = StoreStateV1 {
            owner: Some(store_key().verifying_key()),
            ..Default::default()
        };
        let encoded = bytes(&state);
        let as_value: ciborium::Value = crate::from_cbor(&encoded).unwrap();
        let keys: Vec<String> = as_value
            .as_map()
            .unwrap()
            .iter()
            .filter_map(|(k, _)| k.as_text().map(str::to_string))
            .collect();
        assert!(!keys.iter().any(|k| k == "listing_statuses"), "{keys:?}");
        let summary = state.summarize(&state, &params());
        let summary_bytes = crate::to_cbor(&summary).unwrap();
        let summary_value: ciborium::Value = crate::from_cbor(&summary_bytes).unwrap();
        assert!(!summary_value
            .as_map()
            .unwrap()
            .iter()
            .any(|(k, _)| k.as_text() == Some("listing_statuses")));
        let delta = crate::to_cbor(&StoreStateV1Delta::default()).unwrap();
        let delta_value: ciborium::Value = crate::from_cbor(&delta).unwrap();
        assert!(!delta_value
            .as_map()
            .unwrap()
            .iter()
            .any(|(k, _)| k.as_text() == Some("listing_statuses")));
    }

    /// The store key signs a listing status, and nothing mistakes one for
    /// another kind of store record.
    #[test]
    fn the_store_key_signs_a_listing_status() {
        let status = ListingStatus {
            listing: ListingId([1; 32]),
            revision: 3,
            availability: ListingAvailability::Available { quantity: Some(2) },
        };
        let payload = crate::to_cbor(&status).unwrap();
        assert_eq!(
            crate::backing::classify_store_key_message(&payload),
            Some(crate::backing::StoreKeyMessage::ListingStatus)
        );
        let listing = crate::listing::Listing {
            images: Vec::new(),
            checkout: None,
            choices: Vec::new(),
            id: ListingId([0; 32]),
            title: "t".into(),
            description: String::new(),
            kind: crate::listing::ListingKind::Sale,
            price: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        };
        assert_eq!(
            crate::backing::classify_store_key_message(&crate::to_cbor(&listing).unwrap()),
            Some(crate::backing::StoreKeyMessage::Listing),
            "and a listing is still a listing"
        );
    }

    /// Seeded merge laws, on bytes, over states holding clashing statuses:
    /// several revisions of one listing, equal revisions with different
    /// content, and statuses for listings nobody holds.
    #[test]
    fn merge_is_commutative_associative_and_idempotent() {
        let key = store_key();
        let mut pool = Vec::new();
        for listing in 0..3u8 {
            for revision in [1u64, 2, 2, 5] {
                for availability in [
                    ListingAvailability::Available { quantity: None },
                    ListingAvailability::Available {
                        quantity: Some(revision as u32),
                    },
                    ListingAvailability::SoldOut,
                    ListingAvailability::Withdrawn,
                ] {
                    pool.push(status(&key, listing, revision, availability));
                }
            }
        }
        let mut rng = Rng::new(0x70_70);
        let mut states = vec![state_with(vec![])];
        for _ in 0..24 {
            let picked = rng.subset(&pool, 6);
            states.push(state_with(picked));
        }
        assert_laws(&states, 300, &mut rng, merged, bytes);
    }

    /// A status on listing `n`, for the bound's tests: more listings than
    /// one byte names.
    fn status_on(key: &SigningKey, n: u16, revision: u64) -> AuthorizedListingStatus {
        let mut id = [0u8; 32];
        id[..2].copy_from_slice(&n.to_be_bytes());
        let status = ListingStatus {
            listing: ListingId(id),
            revision,
            availability: ListingAvailability::Withdrawn,
        };
        let (scoped_payload, signature) =
            sign_with_store_key(key, crate::to_cbor(&status).unwrap()).expect("a store record");
        AuthorizedListingStatus {
            status,
            scoped_payload,
            signature,
        }
    }

    /// Step 2: a store keeps its `MAX_LISTING_STATUSES` newest statuses,
    /// the smaller listing first at one revision; a delta carrying more is
    /// refused whole, and so is a state holding more, before a signature is
    /// checked. Mutated red by dropping the cut, and by ranking it oldest
    /// first.
    #[test]
    fn a_store_keeps_its_newest_statuses() {
        let key = store_key();
        let full: Vec<_> = (0..MAX_LISTING_STATUSES as u16)
            .map(|n| status_on(&key, n, 10 + u64::from(n)))
            .collect();
        let mut state = state_with(full.clone());
        assert_eq!(state.listing_statuses.records.len(), MAX_LISTING_STATUSES);
        // One newer: the oldest (listing 0) goes. One at the oldest's
        // revision on a larger listing: it goes itself.
        let newer = status_on(&key, 9_000, 1_000_000);
        let tied = status_on(&key, 9_001, 11);
        state
            .apply_delta(
                &StoreStateV1::default(),
                &params(),
                &Some(StoreStateV1Delta {
                    owner: Some(key.verifying_key()),
                    listing_statuses: Some(vec![newer.clone(), tied.clone()]),
                    ..Default::default()
                }),
            )
            .unwrap();
        let held = &state.listing_statuses.records;
        assert_eq!(held.len(), MAX_LISTING_STATUSES);
        assert!(held.contains_key(&newer.slot()));
        assert!(!held.contains_key(&full[0].slot()), "the oldest is cut");
        assert!(
            held.contains_key(&full[1].slot()),
            "revision 11, the smaller listing"
        );
        assert!(
            !held.contains_key(&tied.slot()),
            "revision 11, the larger listing"
        );

        let mut too_many = full.clone();
        too_many.push(newer);
        let why = StoreStateV1::default()
            .apply_delta(
                &StoreStateV1::default(),
                &params(),
                &Some(StoreStateV1Delta {
                    owner: Some(key.verifying_key()),
                    listing_statuses: Some(too_many.clone()),
                    ..Default::default()
                }),
            )
            .unwrap_err();
        assert!(why.contains("more than a store holds"), "{why}");

        let mut over = state.clone();
        let mut forged = status_on(&key, 9_002, 1);
        forged.signature[0] ^= 1;
        over.listing_statuses.records.insert(forged.slot(), forged);
        let why = over.verify(&over, &params()).unwrap_err();
        assert!(why.contains("the most it keeps"), "{why}");
    }

    /// Step 2: the bound obeys the merge laws on bytes, over sets whose
    /// unions cross it, with slots whose revisions differ between sides (a
    /// merge can raise a slot's rank, unlike the order cap's). At the
    /// set's own merge, which `apply_delta` runs once every record has
    /// verified: the statuses here are unsigned so a union can be large.
    #[test]
    fn the_status_bound_obeys_the_merge_laws() {
        let unsigned = |n: u16, revision: u64| {
            let mut id = [0u8; 32];
            id[..2].copy_from_slice(&n.to_be_bytes());
            AuthorizedListingStatus {
                status: ListingStatus {
                    listing: ListingId(id),
                    revision,
                    availability: ListingAvailability::SoldOut,
                },
                scoped_payload: vec![],
                signature: vec![],
            }
        };
        let mut rng = Rng::new(0x5_7a7);
        let ids = (MAX_LISTING_STATUSES + MAX_LISTING_STATUSES / 2) as u16;
        let mut sets = vec![ListingStatusesV1::default()];
        for _ in 0..12 {
            let mut set = ListingStatusesV1::default();
            let picks: Vec<AuthorizedListingStatus> = (0..MAX_LISTING_STATUSES)
                .map(|_| unsigned(rng.below(ids as usize) as u16, rng.below(40) as u64))
                .collect();
            set.merge_unchecked(&picks);
            sets.push(set);
        }
        let merge = |a: &ListingStatusesV1, b: &ListingStatusesV1| {
            let mut out = a.clone();
            out.merge_unchecked(b.records.values());
            out
        };
        assert_laws(&sets, 300, &mut rng, merge, |set: &ListingStatusesV1| {
            crate::to_cbor(set).expect("encode")
        });
        let crossed = merge(&sets[1], &sets[2]);
        assert_eq!(
            crossed.records.len(),
            MAX_LISTING_STATUSES,
            "the unions cross the bound"
        );
    }

    /// Step 2: a forged status the bound cuts on arrival is in no result, so
    /// only `Unchecked::check` sees it; the node path refuses it as
    /// `apply_delta` did. Mutated red by skipping the check.
    #[test]
    fn a_forged_status_the_cut_drops_is_still_refused() {
        let key = store_key();
        let held = state_with(
            (0..MAX_LISTING_STATUSES as u16)
                .map(|n| status_on(&key, n, 10 + u64::from(n)))
                .collect(),
        );
        let mut forged = status_on(&key, 9_000, 1);
        forged.signature[0] ^= 1;
        let delta = StoreStateV1Delta {
            listing_statuses: Some(vec![forged]),
            ..Default::default()
        };
        let mut merged = held.clone();
        let mut unchecked = Unchecked::default();
        merged
            .apply_update(&params(), &delta, &mut unchecked)
            .unwrap();
        assert_eq!(merged, held);
        assert!(unchecked.check(&merged).is_err());
        assert!(through_the_node(&held, &params(), &delta).is_err());
        assert!(through_apply_delta(&held, &params(), &delta).is_err());

        // One for a listing the store holds a NEWER status for: it loses its
        // slot, the slot still holds the genuine status, and the check must
        // look at the record, not the slot. Red with the check judging by
        // slot alone.
        let mut stale = status_on(&key, 5, 1);
        stale.signature[0] ^= 1;
        let delta = StoreStateV1Delta {
            listing_statuses: Some(vec![stale]),
            ..Default::default()
        };
        let mut merged = held.clone();
        let mut unchecked = Unchecked::default();
        merged
            .apply_update(&params(), &delta, &mut unchecked)
            .unwrap();
        assert_eq!(merged, held, "the held status keeps its slot");
        assert!(unchecked.check(&merged).is_err());
        assert!(through_the_node(&held, &params(), &delta).is_err());
        assert!(through_apply_delta(&held, &params(), &delta).is_err());
    }
}

#[cfg(test)]
mod one_order_per_request_tests {
    //! Instant checkout: an order answering a buyer request is identified by
    //! the request, so a store holds one answer per request whatever arrives
    //! in whatever order.
    use super::*;
    use crate::payment::{request_id, Order, OrderStatus};
    use crate::test_orders::{authorized, order, store_key};

    fn parent() -> StoreStateV1 {
        StoreStateV1 {
            owner: Some(store_key().verifying_key()),
            ..Default::default()
        }
    }

    /// An answer to `request`: every answer carries the buyer's
    /// `requested_at`, so they share `created_at`.
    fn answering(n: u8, request: [u8; 32], amount_sats: u64) -> Order {
        let mut o = order(n);
        o.request_id = Some(request);
        o.amount_sats = amount_sats;
        o.created_at = chrono::DateTime::from_timestamp(1_750_000_000, 0).expect("time");
        o.with_derived_id()
    }

    fn fold(records: &[AuthorizedOrder]) -> OrdersV1 {
        let mut orders = OrdersV1::default();
        let params = StoreParameters::new(store_key().verifying_key());
        for r in records {
            orders
                .apply_delta(&parent(), &params, &Some(vec![r.clone()]))
                .expect("a genuinely signed order applies");
        }
        orders
    }

    /// Two different answers to one request (two devices, or a retry that
    /// derived a second address) end as ONE order, the same one in either
    /// arrival order. Mutated red by dropping the request branch from
    /// `OrderId::from_terms` (the two then have different ids and both stay).
    #[test]
    fn two_answers_to_one_request_are_one_order_in_either_order() {
        let req = request_id(&[7; 32], &[1; 16]);
        let a = authorized(
            &store_key(),
            answering(1, req, 50_000),
            OrderStatus::AwaitingPayment,
        );
        let b = authorized(
            &store_key(),
            answering(2, req, 50_000),
            OrderStatus::AwaitingPayment,
        );
        assert_eq!(a.order.id, b.order.id, "one request, one id");
        assert_ne!(a.order.payment_script_pubkey, b.order.payment_script_pubkey);
        let ab = fold(&[a.clone(), b.clone()]);
        let ba = fold(&[b, a]);
        assert_eq!(ab.orders.len(), 1);
        assert_eq!(crate::to_cbor(&ab).unwrap(), crate::to_cbor(&ba).unwrap());
    }

    /// Different requests are different orders, even with identical terms
    /// otherwise.
    #[test]
    fn different_requests_are_different_orders() {
        let a = answering(1, request_id(&[7; 32], &[1; 16]), 50_000);
        let b = answering(1, request_id(&[7; 32], &[2; 16]), 50_000);
        assert_ne!(a.id, b.id);
        // And the routing tag is part of it: the same nonce copied into
        // another conversation is another request.
        let c = answering(1, request_id(&[8; 32], &[1; 16]), 50_000);
        assert_ne!(a.id, c.id);
    }

    /// A payment beats an unpaid duplicate, whichever arrives first, so the
    /// invoice a buyer paid is the one the store keeps.
    #[test]
    fn the_paid_answer_wins_over_an_unpaid_duplicate() {
        let req = request_id(&[7; 32], &[3; 16]);
        let paid = authorized(&store_key(), answering(1, req, 50_000), OrderStatus::Paid);
        let unpaid = authorized(
            &store_key(),
            answering(2, req, 40_000),
            OrderStatus::AwaitingPayment,
        );
        for orders in [
            fold(&[paid.clone(), unpaid.clone()]),
            fold(&[unpaid, paid.clone()]),
        ] {
            let kept = orders.orders.values().next().unwrap();
            assert_eq!(kept.status, OrderStatus::Paid);
            assert_eq!(
                kept.order.payment_script_pubkey,
                paid.order.payment_script_pubkey
            );
        }
    }

    /// At equal status the larger amount wins, so a seller cannot swap a
    /// paid order for a cheaper paid one under the same request id. Mutated
    /// red by removing the amount comparison from `merge_order` (the
    /// encoding then decides, and the smaller amount encodes smaller).
    #[test]
    fn a_cheaper_order_cannot_displace_a_paid_one() {
        let req = request_id(&[7; 32], &[4; 16]);
        let real = authorized(&store_key(), answering(1, req, 900_000), OrderStatus::Paid);
        // Same buyer and terms but the amount (and its own address), so the
        // first byte the encodings differ in is the amount's.
        let mut cheap = answering(1, req, 1);
        cheap.payment_script_pubkey = vec![0x00, 0x14, 0xee, 0xbb];
        let token = authorized(&store_key(), cheap.with_derived_id(), OrderStatus::Paid);
        assert!(
            crate::to_cbor(&token).unwrap() < crate::to_cbor(&real).unwrap(),
            "the fixture must be one the encoding tie-break alone would get wrong"
        );
        for orders in [
            fold(&[real.clone(), token.clone()]),
            fold(&[token, real.clone()]),
        ] {
            assert_eq!(
                orders.orders.values().next().unwrap().order.amount_sats,
                900_000
            );
        }
    }

    /// An order with no request id is identified by its terms exactly as
    /// before, and encodes without either new field.
    #[test]
    fn an_order_without_a_request_is_unchanged() {
        let o = order(5);
        let bytes = crate::to_cbor(&o).unwrap();
        let value: ciborium::Value = crate::from_cbor(&bytes).unwrap();
        let keys: Vec<String> = value
            .as_map()
            .unwrap()
            .iter()
            .filter_map(|(k, _)| k.as_text().map(str::to_string))
            .collect();
        assert!(
            !keys.iter().any(|k| k == "request_id" || k == "derivation"),
            "{keys:?}"
        );
        let mut probe = o.clone();
        probe.id = crate::payment::OrderId([0; 32]);
        assert_eq!(crate::payment::OrderId::from_terms(&probe), o.id);
    }
}

#[cfg(test)]
mod listing_cap_tests {
    //! Step 2: a store keeps its `MAX_LISTINGS` newest listings, none over
    //! `MAX_LISTING_BYTES`, as a pure function of the listings it holds.
    use super::*;
    use crate::merge_laws::{assert_laws, Rng};
    use crate::test_orders::{paid, sign_scoped, store_key};

    /// Listing `n`, created at `at` seconds, with `pad` bytes of description.
    /// Signed by the fixture store key when `signed`.
    fn listing(n: u32, at: i64, pad: usize, signed: bool) -> AuthorizedListing {
        let listing = crate::listing::Listing {
            images: Vec::new(),
            checkout: None,
            choices: Vec::new(),
            id: ListingId([0u8; 32]),
            title: format!("Listing {n}"),
            description: "d".repeat(pad),
            kind: crate::listing::ListingKind::Sale,
            price: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000 + at, 0).unwrap(),
        }
        .with_derived_id();
        let (scoped_payload, signature) = if signed {
            sign_scoped(&store_key(), &listing)
        } else {
            (Vec::new(), Vec::new())
        };
        AuthorizedListing {
            listing,
            scoped_payload,
            signature,
            certificate_pem: String::new(),
        }
    }

    fn held(listings: Vec<AuthorizedListing>) -> ListingsV1 {
        let mut set = ListingsV1 { listings };
        set.normalize();
        set
    }

    /// Past the cap the newest are kept, ties broken by id; a listing over
    /// the byte bound is dropped wherever it sits. Mutated red by keeping
    /// the oldest, by reversing the tie-break, and by dropping the size
    /// rule. Dropping the written-out tie-break survives, equivalently: the
    /// stable sort of id-sorted listings gives the same order.
    #[test]
    fn the_newest_listings_are_kept_and_an_oversized_one_never_is() {
        // MAX_LISTINGS + 41, two to a second, so the cut falls between two
        // listings of one second (the 41 oldest go: 20 whole seconds and
        // one of the 21st's pair). With an even count it fell between
        // seconds, and the tie-break was never exercised (round 1 of step
        // 2's review).
        let all: Vec<_> = (0..(MAX_LISTINGS as u32 + 41))
            .map(|n| listing(n, i64::from(n / 2), 0, false))
            .collect();
        let kept = held(all.clone());
        assert_eq!(kept.listings.len(), MAX_LISTINGS);
        let mut want: Vec<_> = all
            .iter()
            .map(|l| (l.listing.created_at, l.listing.id.clone()))
            .collect();
        want.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let want: BTreeSet<_> = want
            .into_iter()
            .take(MAX_LISTINGS)
            .map(|(_, id)| id)
            .collect();
        let got: BTreeSet<_> = kept.listings.iter().map(|l| l.listing.id.clone()).collect();
        assert_eq!(got, want);

        let big = listing(9_999, 1_000_000, MAX_LISTING_BYTES, false);
        let just = {
            // The largest description that still fits.
            let mut pad = MAX_LISTING_BYTES - 400;
            assert!(
                crate::to_cbor(&listing(9_998, 1_000_000, pad, false))
                    .unwrap()
                    .len()
                    <= MAX_LISTING_BYTES
            );
            while crate::to_cbor(&listing(9_998, 1_000_000, pad + 1, false))
                .unwrap()
                .len()
                <= MAX_LISTING_BYTES
            {
                pad += 1;
            }
            listing(9_998, 1_000_000, pad, false)
        };
        let kept = held(vec![big.clone(), just.clone()]);
        assert_eq!(kept.listings, vec![just], "the one at the bound stays");
    }

    /// Review round 2 of step 2 (code-first): a state over either cap is
    /// refused for the cap before a single signature is checked. Mutated red
    /// by checking the signatures first.
    #[test]
    fn a_state_over_the_caps_is_refused_before_its_signatures_are_checked() {
        let parent = StoreStateV1 {
            owner: Some(store_key().verifying_key()),
            ..Default::default()
        };
        let params = StoreParameters::new(store_key().verifying_key());
        let mut over: Vec<_> = (0..(MAX_LISTINGS as u32 + 1))
            .map(|n| listing(n, i64::from(n), 0, false))
            .collect();
        over.sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        let why = ListingsV1 { listings: over }
            .verify(&parent, &params)
            .unwrap_err();
        assert!(why.contains("the most it keeps"), "{why}");
        let big = ListingsV1 {
            listings: vec![listing(1, 0, MAX_LISTING_BYTES, false)],
        };
        let why = big.verify(&parent, &params).unwrap_err();
        assert!(why.contains("bytes"), "{why}");
    }

    /// The cut is a pure function of the listings held, so merging in any
    /// order and grouping gives the same bytes: seeded merge laws over
    /// states that each sit near the cap and together cross it, with
    /// oversized listings and tied times in the pool. Merging is what
    /// `apply_delta` does with a delta of the other's listings (signatures
    /// are checked there, not here). Mutated red by making the cut depend on
    /// arrival order (keeping what was held first).
    #[test]
    fn merging_states_that_cross_the_cap_obeys_the_merge_laws() {
        let mut pool: Vec<_> = (0..(MAX_LISTINGS as u32 * 3 / 2))
            // Ties: listings `n` and `n + MAX_LISTINGS / 2` share a time.
            .map(|n| listing(n, i64::from(n % (MAX_LISTINGS as u32 / 2)), 0, false))
            .collect();
        for n in 0..8 {
            pool.push(listing(50_000 + n, 10_000, MAX_LISTING_BYTES, false));
        }
        let mut rng = Rng::new(0x5_12);
        let mut states = vec![held(Vec::new())];
        for _ in 0..12 {
            // A window of 3/4 of the cap up to just under it, at a random
            // offset, wrapping, so any two states overlap in part and most
            // unions cross.
            let len = MAX_LISTINGS * 3 / 4 + rng.below(MAX_LISTINGS / 4 - 1);
            let at = rng.below(pool.len());
            let picked = (0..len)
                .map(|i| pool[(at + i) % pool.len()].clone())
                .collect();
            states.push(ListingsV1 { listings: picked });
        }
        for s in &mut states {
            s.normalize();
        }
        assert!(states.iter().all(|s| s.listings.len() <= MAX_LISTINGS));
        let merge = |a: &ListingsV1, b: &ListingsV1| {
            let mut out = a.clone();
            out.listings.extend(b.listings.iter().cloned());
            out.normalize();
            out
        };
        assert!(
            states.iter().any(|a| states.iter().any(|b| {
                let mut union: BTreeSet<_> =
                    a.listings.iter().map(|l| l.listing.id.clone()).collect();
                union.extend(b.listings.iter().map(|l| l.listing.id.clone()));
                union.len() > MAX_LISTINGS
            })),
            "the sweep crosses the cap"
        );
        assert_laws(&states, 200, &mut rng, merge, |s| {
            crate::to_cbor(s).unwrap()
        });
    }

    /// Through the store's own merge, with signatures checked: three
    /// signed states that together cross the cap merge to the same store
    /// whichever way round, and a state over either cap does not verify.
    #[test]
    fn the_store_merge_cuts_the_same_way_round_and_verify_holds_the_cap() {
        let params = StoreParameters::new(store_key().verifying_key());
        let state = |range: std::ops::Range<u32>| {
            let mut s = StoreStateV1 {
                owner: Some(store_key().verifying_key()),
                ..Default::default()
            };
            // In deltas of at most `MAX_LISTINGS`, the most one carries.
            let all: Vec<_> = range.map(|n| listing(n, i64::from(n), 0, true)).collect();
            for chunk in all.chunks(MAX_LISTINGS) {
                s.apply_delta(
                    &StoreStateV1::default(),
                    &params,
                    &Some(StoreStateV1Delta {
                        owner: Some(store_key().verifying_key()),
                        listings: Some(chunk.to_vec()),
                        ..Default::default()
                    }),
                )
                .expect("applies");
            }
            s
        };
        let (a, b, c) = (state(0..300), state(200..500), state(450..560));
        let merged = |x: &StoreStateV1, y: &StoreStateV1| {
            let mut out = x.clone();
            out.merge(&x.clone(), &params, y).expect("merge");
            out
        };
        let one = merged(&merged(&a, &b), &c);
        let two = merged(&a, &merged(&c, &b));
        assert_eq!(crate::to_cbor(&one).unwrap(), crate::to_cbor(&two).unwrap());
        assert_eq!(one.listings.listings.len(), MAX_LISTINGS);
        assert!(one.verify(&StoreStateV1::default(), &params).is_ok());

        let mut over = one.clone();
        over.listings.listings.push(listing(70_000, 0, 0, true));
        over.listings
            .listings
            .sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        assert!(over.verify(&StoreStateV1::default(), &params).is_err());
        let mut big = a.clone();
        big.listings
            .listings
            .push(listing(70_001, 0, MAX_LISTING_BYTES, true));
        big.listings
            .listings
            .sort_by(|a, b| a.listing.id.cmp(&b.listing.id));
        assert!(big.verify(&StoreStateV1::default(), &params).is_err());
    }

    /// Step 2: a forged listing the cap cuts on arrival is in no result, so
    /// only `Unchecked::check` sees it, and the node path refuses it as
    /// `apply_delta` does; a delta of more listings than a store holds is
    /// refused whole. Red with the check skipped, and with the count bound
    /// dropped from `ListingsV1::admit`.
    #[test]
    fn a_forged_listing_the_cut_drops_is_still_refused() {
        let params = StoreParameters::new(store_key().verifying_key());
        let mut held = StoreStateV1 {
            owner: Some(store_key().verifying_key()),
            ..Default::default()
        };
        held.apply_delta(
            &StoreStateV1::default(),
            &params,
            &Some(StoreStateV1Delta {
                owner: Some(store_key().verifying_key()),
                listings: Some(
                    (0..MAX_LISTINGS as u32)
                        .map(|n| listing(n, 100 + i64::from(n), 0, true))
                        .collect(),
                ),
                ..Default::default()
            }),
        )
        .expect("applies");
        // Older than every listing held, so the cap cuts it at once.
        let mut forged = listing(9_000, 0, 0, true);
        forged.signature[0] ^= 1;
        let delta = StoreStateV1Delta {
            listings: Some(vec![forged]),
            ..Default::default()
        };
        let mut merged = held.clone();
        let mut unchecked = Unchecked::default();
        merged
            .apply_update(&params, &delta, &mut unchecked)
            .unwrap();
        assert_eq!(merged, held, "the cut listing changed nothing");
        assert!(unchecked.check(&merged).is_err());
        assert!(through_the_node(&held, &params, &delta).is_err());
        assert!(through_apply_delta(&held, &params, &delta).is_err());

        let too_many = StoreStateV1Delta {
            listings: Some(
                (0..=MAX_LISTINGS as u32)
                    .map(|n| listing(20_000 + n, 1_000 + i64::from(n), 0, true))
                    .collect(),
            ),
            ..Default::default()
        };
        let why = held
            .clone()
            .apply_delta(&held, &params, &Some(too_many))
            .unwrap_err();
        assert!(why.contains("more than a store holds"), "{why}");
    }

    /// An open order outlives its listing: once the listing an order was
    /// made for is cut, the order is still held, still verifies with its
    /// payment proof, and the store still verifies. An order names its
    /// listing only by an opaque tag and carries its own terms. Red if the
    /// cut ever reaches into the orders, or if verifying an order needed
    /// its listing.
    #[test]
    fn an_order_outlives_its_cut_listing() {
        let params = StoreParameters::new(store_key().verifying_key());
        let oldest = listing(0, -1_000, 0, true);
        let mut order = paid(1);
        order.order.listing_tag = Some(oldest.listing.id.0);
        order.order.id = crate::payment::OrderId::from_terms(&order.order);
        // Re-sign the terms with the tag in them.
        order = crate::test_orders::authorized(
            &store_key(),
            order.order,
            crate::payment::OrderStatus::Paid,
        );
        let mut first = StoreStateV1 {
            owner: Some(store_key().verifying_key()),
            ..Default::default()
        };
        first
            .apply_delta(
                &StoreStateV1::default(),
                &params,
                &Some(StoreStateV1Delta {
                    owner: Some(store_key().verifying_key()),
                    listings: Some(vec![oldest.clone()]),
                    orders: Some(vec![order.clone()]),
                    ..Default::default()
                }),
            )
            .expect("applies");
        let newer: Vec<_> = (1..=MAX_LISTINGS as u32)
            .map(|n| listing(n, i64::from(n), 0, true))
            .collect();
        first
            .apply_delta(
                &StoreStateV1::default(),
                &params,
                &Some(StoreStateV1Delta {
                    listings: Some(newer),
                    ..Default::default()
                }),
            )
            .expect("applies");
        assert!(
            !first
                .listings
                .listings
                .iter()
                .any(|l| l.listing.id == oldest.listing.id),
            "the order's listing was cut"
        );
        let kept = first
            .orders
            .orders
            .get(&order.order.id)
            .expect("the order stays");
        assert_eq!(kept, &order);
        assert!(kept.verify_terms(&store_key().verifying_key()).is_ok());
        assert!(crate::payment::verify_payment_proof(
            &kept.order,
            kept.payment_proof.as_ref().expect("a proof")
        )
        .is_ok());
        assert!(first.verify(&StoreStateV1::default(), &params).is_ok());
    }
}

/// Step 2 (harvest#230): every signed record the store holds writes its
/// signed payload and signature as CBOR byte strings (`serde_bytes`), which
/// a store at its order cap carried as arrays of integers, about twice the
/// bytes and one decode call per byte. The bytes signed are unchanged: only
/// the outer field's encoding moved. A state written by an earlier
/// generation still decodes, and its re-encoding is what the migration fold
/// forwards (the contract accepts only its own canonical encoding).
#[cfg(test)]
mod byte_string_encoding_tests {
    use super::*;
    use crate::backing::{
        AuthorizedBacking, AuthorizedClosure, AuthorizedRetirement, BackingStatement, Retirement,
        StoreClosure,
    };
    use crate::earlier_encoding;

    /// Bytes both sides of 24, where the integer-array form goes from one
    /// byte an element to two.
    fn bytes(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(11).wrapping_add(seed))
            .collect()
    }

    /// A store holding one of every signed record, every byte field filled.
    /// Unsigned: what is tested is the encoding, not the signatures.
    fn every_record() -> StoreStateV1 {
        let owner = crate::test_orders::store_key().verifying_key();
        let backer = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        let mut order = crate::test_orders::paid(1);
        order.status_scoped_payload = Some(bytes(1, 90));
        order.status_signature = Some(bytes(2, 64));
        let mut state = StoreStateV1 {
            owner: Some(owner),
            info: AuthorizedStoreInfoV1 {
                info: StoreInfoV1 {
                    version: 1,
                    certificate_pem: String::new(),
                    seller_fingerprint: String::new(),
                    reputation_contract_id: [9; 32],
                    store_name: "Shop".into(),
                    description: String::new(),
                    encryption_public_key: None,
                    // Inside the signed details: stays an integer array.
                    record_public_key: Some(bytes(24, 40)),
                },
                scoped_payload: bytes(3, 120),
                signature: bytes(4, 64),
            },
            ..Default::default()
        };
        state.listings.listings.push(AuthorizedListing {
            listing: crate::listing::Listing {
                images: Vec::new(),
                checkout: None,
                choices: Vec::new(),
                id: ListingId([0; 32]),
                title: "Jam".into(),
                description: String::new(),
                kind: crate::listing::ListingKind::Sale,
                price: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            }
            .with_derived_id(),
            scoped_payload: bytes(5, 200),
            signature: bytes(6, 64),
            certificate_pem: String::new(),
        });
        state
            .orders
            .orders
            .insert(order.order.id.clone(), order.clone());
        let slot = Bytes32(backer.to_bytes());
        state.backings.records.insert(
            slot,
            AuthorizedBacking {
                statement: BackingStatement {
                    store: owner,
                    backer,
                    certificate_pem: String::new(),
                    network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                    block: freenet_bitcoin_common::BlockAnchor {
                        height: 1,
                        hash: freenet_bitcoin_common::BlockHash([7; 32]),
                    },
                },
                backer_scoped_payload: bytes(7, 80),
                backer_signature: bytes(8, 64),
                acceptance_scoped_payload: bytes(9, 80),
                acceptance_signature: bytes(10, 64),
            },
        );
        state.retirements.records.insert(
            slot,
            AuthorizedRetirement {
                retirement: Retirement { backer },
                scoped_payload: bytes(11, 60),
                signature: bytes(12, 64),
            },
        );
        state.closed.records.insert(
            Bytes32(owner.to_bytes()),
            AuthorizedClosure {
                closure: StoreClosure { store: owner },
                scoped_payload: bytes(13, 60),
                signature: bytes(14, 64),
            },
        );
        state.copies.records.insert(
            Bytes32([0x21; 32]),
            crate::custody::AuthorizedCopy {
                copy: crate::custody::StoreKeyCopy {
                    store: owner,
                    backer,
                    scope: crate::custody::WrapScope([3; 32]),
                    wrapped: crate::custody::WrappedStoreKey {
                        scheme: crate::custody::SCHEME_V1,
                        ciphertext: bytes(15, crate::custody::WRAPPED_LEN_V1),
                    },
                },
                scoped_payload: bytes(16, 100),
                signature: bytes(17, 64),
            },
        );
        state.fulfilment.records.insert(
            Bytes32(order.order.id.0),
            crate::fulfilment::AuthorizedDespatch {
                despatch: crate::fulfilment::Despatch {
                    order_id: order.order.id.clone(),
                    anchor: freenet_bitcoin_common::BlockAnchor {
                        height: 2,
                        hash: freenet_bitcoin_common::BlockHash([8; 32]),
                    },
                },
                scoped_payload: bytes(18, 70),
                signature: bytes(19, 64),
            },
        );
        state.listing_statuses.records.insert(
            Bytes32([0x31; 32]),
            crate::listing::AuthorizedListingStatus {
                status: crate::listing::ListingStatus {
                    listing: ListingId([0x31; 32]),
                    revision: 1,
                    availability: crate::listing::ListingAvailability::SoldOut,
                },
                scoped_payload: bytes(20, 70),
                signature: bytes(21, 64),
            },
        );
        state.pause.records.insert(
            Bytes32(owner.to_bytes()),
            crate::store_pause::AuthorizedStorePause {
                pause: crate::store_pause::StorePause::new(owner, 1, true),
                scoped_payload: bytes(22, 70),
                signature: bytes(23, 64),
            },
        );
        state
    }

    /// A state written before step 2 decodes, record for record. Red if any
    /// field loses the dual read.
    #[test]
    fn an_earlier_generations_store_still_decodes() {
        let state = every_record();
        let earlier = earlier_encoding::of(&crate::to_cbor(&state).unwrap());
        let decoded: StoreStateV1 = crate::from_cbor(&earlier).expect("decodes");
        assert_eq!(decoded, state);
    }

    /// Every outer byte field of every record is written as a byte string:
    /// 24 of them in this store. Red if any one `#[serde(with =
    /// "serde_bytes")]` is removed.
    #[test]
    fn every_records_byte_fields_are_byte_strings() {
        let state = every_record();
        let today = crate::to_cbor(&state).unwrap();
        assert_eq!(earlier_encoding::byte_string_fields(&today), 24);
        let earlier = earlier_encoding::of(&today);
        assert!(
            today.len() < earlier.len(),
            "{} vs {}",
            today.len(),
            earlier.len()
        );
    }

    /// The earlier bytes are not canonical today, and their re-encoding is:
    /// the contract refuses the earlier bytes as they are, and the
    /// migration fold forwards the state re-encoded.
    #[test]
    fn an_earlier_encoding_is_not_canonical_and_its_re_encoding_is() {
        let state = every_record();
        let earlier = earlier_encoding::of(&crate::to_cbor(&state).unwrap());
        let decoded: StoreStateV1 = crate::from_cbor(&earlier).unwrap();
        assert!(!crate::is_canonical_cbor(&decoded, &earlier));
        assert!(crate::is_canonical_cbor(
            &decoded,
            &crate::to_cbor(&decoded).unwrap()
        ));
    }
}
