//! Backing: the Ghost Keys behind a store, and the store key's own statements
//! about them (harvest#93, revision 2, phase 1a).
//!
//! # The model
//!
//! A store has its own Ed25519 key, the **store key**. It is the store's
//! [`crate::store::StoreStateV1::owner`], its store code is a prefix of it, and
//! it signs everything the store holds. A Ghost Key signs exactly one thing
//! about a store: that it **backs** it ([`BackingStatement`]). The store key
//! countersigns the statement to accept it ([`BackingAcceptance`]), so nobody
//! can attach their key, or anybody else's, to a store they do not hold.
//!
//! The store keeps every backing it has ever had and every retirement of one,
//! as two grow-only sets the contract refuses to shrink. "Previously backed by
//! a $20 Ghost Key" is part of what a buyer is judging, so the history is a
//! contract rule rather than a UI convention. A store can also be **closed**
//! ([`StoreClosure`]): a one-way flag for a store whose key must be treated as
//! exposed (docs/design/entity-model.md, section 6.4).
//!
//! # What the contract checks, and what it leaves to readers
//!
//! The contract checks what is a pure function of the state it holds: both
//! signatures on a backing, the store key's signature on a retirement and on
//! a closure, that each record names this store's owner, and the shape
//! bounds below. It never looks at another contract (section 6.7). Everything
//! that needs more than the state is a READER rule, computed here and applied
//! by the UI:
//!
//! * which backing is current ([`current_backing`]);
//! * whether a Ghost Key backs more than one store at once
//!   ([`keys_backing_several_stores`]);
//! * whether the backing's certificate chains to Freenet's master key and
//!   names the backing key, and what tier it carries (the UI's
//!   `ghostkey_cert`);
//! * whether the block reference is plausible against the reader's tip.
//!
//! # One current backing is a reader rule, not a contract rule
//!
//! Revision 2 decided a store has ONE current backing (section 6.1). The
//! contract does not enforce it: it records backings and retirements, and
//! [`current_backing`] picks one. So allowing several backings to add up
//! later, if it is ever wanted, is a change to that function, not a re-key.
//!
//! # Signing envelope
//!
//! Every signature here uses the same `ScopedPayload` envelope the Ghost Key
//! vault produces, verified by [`crate::listing::verify_scoped_signature`].
//! The Ghost Key's half comes from the vault as it always has; the store
//! key's half is built by the Harvest delegate ([`sign_with_store_key`]), with
//! the Harvest webapp as the requestor, because the delegate answers only the
//! Harvest webapp. One envelope means one verifier, and the same requestor pin
//! applies to both.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::listing::verify_scoped_signature;
use crate::store::{Bytes32, StoreParameters, StoreStateV1};

/// How many backings one store holds.
///
/// It bounds the state: each backing carries a certificate of up to
/// [`MAX_CERTIFICATE_PEM_BYTES`]. The contract does not check certificates,
/// so any Ed25519 key can sign a backing statement, and whoever holds the
/// store key can reach this bound for free. Nobody else can: every backing
/// needs the store key's acceptance.
///
/// # What happens past it: a total merge (harvest#93 review, Must Fix 1)
///
/// Two replicas can each hold [`MAX_BACKINGS`] backings whose union holds
/// more. The merge must still succeed, deterministically, and it must not
/// carry anything else in the same update down with it. So the store keeps
/// the [`MAX_BACKINGS`] backings whose Ghost Keys are SMALLEST by bytes and
/// drops the rest ([`StoreStateV1::normalize_backings`]), and a retirement
/// is kept exactly when its backing is.
///
/// Why this ranking: it depends on the slot (the Ghost Key) alone, never on
/// which of two records for that slot a replica holds, so a merge cannot
/// change a slot's rank. Top-N over a ranking the per-slot merge cannot
/// change is associative, commutative and idempotent: a slot cut from one
/// side ranks below that side's N-th slot, so it ranks below the N-th slot
/// of any union containing that side and is cut again, whichever version of
/// it returns. This is the argument `store::enforce_order_cap` rests on.
///
/// What it costs: past the bound, history is dropped (a backing, and with it
/// its retirement). A dropped slot never returns to a replica that dropped
/// it, so nothing is ever UN-retired; see
/// [`StoreStateV1::normalize_backings`]. Only the store key's holder can get
/// here, and a store whose key is in the wrong hands is closed, which this
/// bound never touches: the closed flag is its own part of the state.
pub const MAX_BACKINGS: usize = 64;

/// The largest certificate a backing may carry, in bytes of PEM text.
///
/// A Ghost Key certificate is well under this (an Ed25519 key, an RSA notary
/// certificate and signature, armoured). The bound exists so that
/// [`MAX_BACKINGS`] bounds bytes as well as entries.
pub const MAX_CERTIFICATE_PEM_BYTES: usize = 4096;

/// "I back store X": what a Ghost Key signs.
///
/// Signed by the Ghost Key through the vault's `SignMessage`, exactly as
/// listings were before revision 2, and countersigned by the store key as a
/// [`BackingAcceptance`].
///
/// The tier is not a field of its own: it is read from `certificate_pem`, the
/// Ghost Key's certificate, which carries it in the notary's info and is
/// checked against Freenet's master key by readers. A separate tier field
/// would be a second place for the store to say something about the key, and
/// one that could contradict the first.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BackingStatement {
    /// The store being backed: its store key, the full 32 bytes. Not the store
    /// code, which is a prefix many keys share.
    pub store: VerifyingKey,
    /// The Ghost Key doing the backing. It signs this statement.
    pub backer: VerifyingKey,
    /// The backer's Ghost Key certificate, so a reader can check the trust
    /// chain and read the tier. Never checked by the contract, which has no
    /// view of Freenet's master key; see the module docs.
    pub certificate_pem: String,
    /// Which chain `block` is on. A block reference without its network is
    /// ambiguous: the heights of two chains overlap.
    pub network: BitcoinNetwork,
    /// A recent Bitcoin block, chosen when the backing was made: what readers
    /// order backings by (see [`current_backing`]), and the same kind of
    /// reference an order's anchor and a complaint carry. Readers check its
    /// HEIGHT against their tip (a backing dated past it is not current yet);
    /// phase 1a does not check the hash, which is carried so a reader can
    /// check it against the tip contract's retained window later, the way an
    /// order's anchor is checked. Until then it does not prove when the
    /// backing was written.
    pub block: BlockAnchor,
}

/// The store key's acceptance of a [`BackingStatement`].
///
/// A wrapper rather than a signature over the bare statement, so the bytes the
/// store key signs are not the bytes the Ghost Key signs: two different keys
/// sign two different messages, and neither signature can stand in for the
/// other's.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BackingAcceptance {
    pub backing: BackingStatement,
}

/// A backing as the store holds it: the statement, the Ghost Key's signature,
/// and the store key's countersignature.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedBacking {
    pub statement: BackingStatement,
    /// `ScopedPayload` from the Ghost Key vault, wrapping the CBOR of
    /// `statement`.
    pub backer_scoped_payload: Vec<u8>,
    /// The Ghost Key's Ed25519 signature over `backer_scoped_payload`.
    pub backer_signature: Vec<u8>,
    /// `ScopedPayload` wrapping the CBOR of [`BackingAcceptance`].
    pub acceptance_scoped_payload: Vec<u8>,
    /// The store key's Ed25519 signature over `acceptance_scoped_payload`.
    pub acceptance_signature: Vec<u8>,
}

impl AuthorizedBacking {
    /// Whether this backing is one `owner`'s store may hold: it names that
    /// store, the Ghost Key it names signed it, and the store key accepted it.
    pub fn verify(&self, owner: &VerifyingKey) -> Result<(), String> {
        if self.statement.store != *owner {
            return Err("backing names a different store key than this store's owner".into());
        }
        if self.statement.certificate_pem.len() > MAX_CERTIFICATE_PEM_BYTES {
            return Err(format!(
                "backing certificate is {} bytes, the most a backing may carry is \
                 {MAX_CERTIFICATE_PEM_BYTES}",
                self.statement.certificate_pem.len()
            ));
        }
        verify_scoped_signature(
            &self.backer_scoped_payload,
            &self.backer_signature,
            &self.statement.backer,
            &self.statement,
        )
        .map_err(|e| format!("backing is not signed by the Ghost Key it names: {e}"))?;
        verify_scoped_signature(
            &self.acceptance_scoped_payload,
            &self.acceptance_signature,
            owner,
            &BackingAcceptance {
                backing: self.statement.clone(),
            },
        )
        .map_err(|e| format!("backing is not accepted by the store key: {e}"))
    }
}

/// The store key's statement that a Ghost Key no longer backs the store.
///
/// Per backing KEY, not per backing record, and permanent: a Ghost Key
/// retired from a store can never back it again. It must name a Ghost Key the
/// store holds a backing for (`StoreStateV1::verify`), so a store never holds
/// more retirements than backings, and a retirement is kept exactly as long
/// as its backing is (`StoreStateV1::normalize_backings`). That is what phase 1b's
/// custody needs from it -- the same retirement is the tombstone that stops
/// the retired key recovering the store key from state -- and one signed act
/// cannot then have two effects that drift apart (section 6.3, check 4).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Retirement {
    pub backer: VerifyingKey,
}

/// A [`Retirement`] signed by the store key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedRetirement {
    pub retirement: Retirement,
    pub scoped_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AuthorizedRetirement {
    pub fn verify(&self, owner: &VerifyingKey) -> Result<(), String> {
        verify_scoped_signature(
            &self.scoped_payload,
            &self.signature,
            owner,
            &self.retirement,
        )
        .map_err(|e| format!("retirement is not signed by the store key: {e}"))
    }
}

/// "This store has closed": a one-way flag, signed by the store key.
///
/// For a store whose key must be treated as exposed, where no rotation can
/// tell the seller from whoever holds the leaked key (section 6.4). Buyers'
/// software refuses to pay a closed store. Once present it never goes away:
/// the merge is an OR.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreClosure {
    /// The store being closed. Must be the owner; carried so the signed bytes
    /// name what they close.
    pub store: VerifyingKey,
}

/// A [`StoreClosure`] signed by the store key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct AuthorizedClosure {
    pub closure: StoreClosure,
    pub scoped_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AuthorizedClosure {
    pub fn verify(&self, owner: &VerifyingKey) -> Result<(), String> {
        if self.closure.store != *owner {
            return Err("closure names a different store key than this store's owner".into());
        }
        verify_scoped_signature(&self.scoped_payload, &self.signature, owner, &self.closure)
            .map_err(|e| format!("closure is not signed by the store key: {e}"))
    }
}

/// A record the store holds in a [`SignedSetV1`]: keyed, and verifiable
/// against the store's owner.
pub trait SignedRecord: Serialize + DeserializeOwned + Clone + PartialEq + std::fmt::Debug {
    /// Which slot of the set this record occupies.
    fn slot(&self) -> Bytes32;
    /// Whether the store owned by `owner` may hold this record.
    fn verify_for(&self, owner: &VerifyingKey) -> Result<(), String>;
    /// What a verify error calls this kind of record.
    const WHAT: &'static str;
}

impl SignedRecord for AuthorizedBacking {
    fn slot(&self) -> Bytes32 {
        Bytes32(self.statement.backer.to_bytes())
    }
    fn verify_for(&self, owner: &VerifyingKey) -> Result<(), String> {
        self.verify(owner)
    }
    const WHAT: &'static str = "backing";
}

impl SignedRecord for AuthorizedRetirement {
    fn slot(&self) -> Bytes32 {
        Bytes32(self.retirement.backer.to_bytes())
    }
    fn verify_for(&self, owner: &VerifyingKey) -> Result<(), String> {
        self.verify(owner)
    }
    const WHAT: &'static str = "retirement";
}

impl SignedRecord for AuthorizedClosure {
    fn slot(&self) -> Bytes32 {
        Bytes32(self.closure.store.to_bytes())
    }
    fn verify_for(&self, owner: &VerifyingKey) -> Result<(), String> {
        self.verify(owner)
    }
    // `verify` requires the closure to name the owner and to sit in its own
    // slot, so a store holds at most one: there is no bound to exceed.
    const WHAT: &'static str = "closure";
}

/// The CBOR bytes of a record, which is what two records for one slot are
/// compared by.
fn record_bytes<T: Serialize>(record: &T) -> Vec<u8> {
    // Infallible: every record derives `Serialize` over plain data.
    crate::to_cbor(record).expect("a signed record always serializes to CBOR")
}

/// A grow-only set of signed records, one per slot.
///
/// # Merge model
///
/// Union by slot. Two different records for one slot -- which needs whoever
/// signs it to have signed twice, with different content -- resolve to the
/// one whose CBOR encoding is SMALLER, the same rule and for the same reason
/// as `store::merge_order`'s equal-rank tie-break: it is a pure function of
/// content, so every replica holding both picks the same one, and it rewards
/// nobody for stapling bytes onto a genuine record. Note what that means: on
/// a clash the SMALLER encoding wins, not the newer record; a signer who
/// signs twice for one slot does not choose which one stays. A per-slot
/// minimum over a total order, united over slots, is idempotent, commutative
/// and associative, which the seeded tests in `backing::tests` check on
/// bytes.
///
/// Nothing in this type removes a slot. The one bound on the store's
/// backings, and the rule that a retirement needs its backing, are applied
/// over the whole store by `StoreStateV1::normalize_backings`; see
/// [`MAX_BACKINGS`] for why that keeps every merge total.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: DeserializeOwned"))]
pub struct SignedSetV1<T> {
    pub records: BTreeMap<Bytes32, T>,
}

impl<T> Default for SignedSetV1<T> {
    fn default() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }
}

impl<T: SignedRecord> SignedSetV1<T> {
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Fold one already-verified record in, keeping the smaller encoding on a
    /// clash. See the type's docs.
    fn merge_record(&mut self, incoming: T) {
        let slot = incoming.slot();
        match self.records.get(&slot) {
            Some(held) if record_bytes(held) <= record_bytes(&incoming) => {}
            _ => {
                self.records.insert(slot, incoming);
            }
        }
    }
}

impl<T: SignedRecord> freenet_scaffold::ComposableState for SignedSetV1<T> {
    type ParentState = StoreStateV1;
    /// One `(slot, BLAKE3 of the record's CBOR)` per record, so a same-slot
    /// record with different content still differs in the summary and is
    /// exchanged, the way `OrdersV1`'s digest does it.
    type Summary = Vec<(Bytes32, Bytes32)>;
    type Delta = Vec<T>;
    type Parameters = StoreParameters;

    fn verify(
        &self,
        parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Result<(), String> {
        if self.records.is_empty() {
            return Ok(());
        }
        let owner = crate::store::owner_key(parent_state)?;
        for (slot, record) in &self.records {
            if record.slot() != *slot {
                return Err(format!(
                    "{} filed under a slot that is not its own",
                    T::WHAT
                ));
            }
            record.verify_for(owner)?;
        }
        Ok(())
    }

    fn summarize(
        &self,
        _parent_state: &Self::ParentState,
        _parameters: &Self::Parameters,
    ) -> Self::Summary {
        self.records
            .iter()
            .map(|(slot, record)| {
                (
                    *slot,
                    Bytes32(*blake3::hash(&record_bytes(record)).as_bytes()),
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
        let theirs: BTreeMap<Bytes32, Bytes32> = old_state_summary.iter().copied().collect();
        // Sent whenever the requester's summary cannot account for it:
        // missing, or held with different bytes. Sending a record that would
        // lose the tie-break is safe; the receiver re-runs it and keeps its
        // own.
        let changed: Vec<T> = self
            .records
            .iter()
            .filter(|(slot, record)| {
                theirs.get(*slot).is_none_or(|digest| {
                    *digest != Bytes32(*blake3::hash(&record_bytes(*record)).as_bytes())
                })
            })
            .map(|(_, record)| record.clone())
            .collect();
        (!changed.is_empty()).then_some(changed)
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
        if incoming.is_empty() {
            return Ok(());
        }
        // Verify the whole delta before merging any of it, and merge into a
        // copy, so a refused delta leaves `self` exactly as it was -- the
        // discipline `OrdersV1::apply_delta` states.
        let owner = crate::store::owner_key(parent_state)?;
        for record in incoming {
            record.verify_for(owner)?;
        }
        let mut next = self.clone();
        for record in incoming {
            next.merge_record(record.clone());
        }
        // No bound is applied here. The bound on backings, and the rule that
        // a retirement needs its backing, are about the store as a whole, so
        // `StoreStateV1::normalize_backings` applies them after every part
        // has been merged; see [`MAX_BACKINGS`].
        *self = next;
        Ok(())
    }
}

/// Every backing a store holds.
pub type BackingsV1 = SignedSetV1<AuthorizedBacking>;
/// Every retirement a store holds.
pub type RetirementsV1 = SignedSetV1<AuthorizedRetirement>;
/// The closed flag: empty, or the one closure the owner signed.
pub type ClosedV1 = SignedSetV1<AuthorizedClosure>;

// ---------------------------------------------------------------------------
// Reader rules
// ---------------------------------------------------------------------------

/// The backing a reader should treat as the store's current one, if any.
///
/// # The rule
///
/// Of the backings no retirement names, the one with the HIGHEST block
/// reference, and between two at one height, the one whose backing key is
/// larger by bytes. The second clause only makes the order total; two
/// unretired backings at one height is a store its seller has left in an odd
/// state, and either answer is honest.
///
/// # Why the block reference, and why that is safe to let the seller choose
///
/// It is the only time signal a backing carries, and "current" means "most
/// recent". The seller chooses it -- both signatures are theirs -- so a seller
/// could date a backing to any block. What that buys them is nothing: with
/// one current backing, the backing they date is the one that counts, and
/// the way to make a new backing current is to retire the old one, which is
/// what the UI does when it adds one. An old backing re-dated to look new is
/// still the seller's own Ghost Key.
///
/// # Future-dated references
///
/// `tip_height` answers, for a network, the height of the newest block the
/// reader has seen. A backing whose block is above it is dated in the future,
/// which nothing honest produces, and is left out, as a complaint dated in
/// the future is not shown (section 3). Where the reader knows no tip for
/// that network, nothing is left out: the reference cannot be checked yet,
/// and refusing every backing until a tip loads would read as "unbacked"
/// rather than "still checking".
///
/// # What this does not decide
///
/// Whether the certificate holds up, or whether the key also backs another
/// store (see [`keys_backing_several_stores`]). Both need more than this
/// store's state.
pub fn current_backing(
    state: &StoreStateV1,
    tip_height: impl Fn(BitcoinNetwork) -> Option<u32>,
) -> Option<&AuthorizedBacking> {
    most_recent(
        state
            .backings
            .records
            .iter()
            .filter(|(slot, _)| !state.retirements.records.contains_key(*slot))
            .map(|(_, backing)| backing)
            .filter(|backing| {
                tip_height(backing.statement.network)
                    .is_none_or(|tip| backing.statement.block.height <= tip)
            }),
    )
}

/// The most recent of `candidates`: highest block height, then largest
/// backing key. A total order, so the answer does not depend on the order the
/// candidates come in (pinned by
/// `tests::the_most_recent_backing_does_not_depend_on_the_order_given`).
fn most_recent<'a>(
    candidates: impl Iterator<Item = &'a AuthorizedBacking>,
) -> Option<&'a AuthorizedBacking> {
    candidates.max_by_key(|backing| {
        (
            backing.statement.block.height,
            backing.statement.backer.to_bytes(),
        )
    })
}

/// Whether the store has closed. See [`StoreClosure`].
pub fn is_closed(state: &StoreStateV1) -> bool {
    !state.closed.records.is_empty()
}

/// The Ghost Keys that are the current backing of more than one store at once.
///
/// "A Ghost Key backs one store at a time" (section 6.2) is a reader rule: a
/// key found backing two stores counts for nothing at EITHER, until one of
/// the backings is retired. It cannot be a contract rule, because whether the
/// key's other backing is retired lives in another contract (section 6.7).
///
/// Takes `(store key, current backing key)` for every store the reader knows
/// about. A reader only knows the stores it has loaded, so this is only as
/// complete as that; the Ghost Key record of phase 1c is what lets a reader
/// find the rest.
pub fn keys_backing_several_stores(
    currents: impl IntoIterator<Item = (VerifyingKey, VerifyingKey)>,
) -> BTreeSet<[u8; 32]> {
    let mut stores_by_backer: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>> = BTreeMap::new();
    for (store, backer) in currents {
        stores_by_backer
            .entry(backer.to_bytes())
            .or_default()
            .insert(store.to_bytes());
    }
    stores_by_backer
        .into_iter()
        .filter(|(_, stores)| stores.len() > 1)
        .map(|(backer, _)| backer)
        .collect()
}

// ---------------------------------------------------------------------------
// Signing with the store key
// ---------------------------------------------------------------------------

/// The kinds of message the store key signs. The Harvest delegate signs only
/// these (see [`classify_store_key_message`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreKeyMessage {
    StoreInfo,
    Listing,
    Order,
    OrderStatus,
    BackingAcceptance,
    Retirement,
    Closure,
}

/// Which kind of store-key message `payload` is, or `None` if it is none of
/// them.
///
/// A payload counts only if it decodes as the type AND re-encodes to exactly
/// the same bytes, so trailing bytes or an unknown field do not ride along
/// under a store-key signature. The delegate refuses to sign anything this
/// returns `None` for: it holds a secret that signs for a whole store, and
/// narrowing it to the messages a store is made of costs nothing.
pub fn classify_store_key_message(payload: &[u8]) -> Option<StoreKeyMessage> {
    fn is<T: Serialize + DeserializeOwned>(payload: &[u8]) -> bool {
        crate::from_cbor::<T>(payload).is_ok_and(|value| crate::is_canonical_cbor(&value, payload))
    }
    if is::<crate::store::StoreInfoV1>(payload) {
        Some(StoreKeyMessage::StoreInfo)
    } else if is::<crate::listing::Listing>(payload) {
        Some(StoreKeyMessage::Listing)
    } else if is::<crate::payment::Order>(payload) {
        Some(StoreKeyMessage::Order)
    } else if is::<(crate::payment::OrderId, crate::payment::OrderStatus)>(payload) {
        Some(StoreKeyMessage::OrderStatus)
    } else if is::<BackingAcceptance>(payload) {
        Some(StoreKeyMessage::BackingAcceptance)
    } else if is::<Retirement>(payload) {
        Some(StoreKeyMessage::Retirement)
    } else if is::<StoreClosure>(payload) {
        Some(StoreKeyMessage::Closure)
    } else {
        None
    }
}

/// The `ScopedPayload` envelope around `payload`, with the Harvest webapp as
/// requestor: the same shape the Ghost Key vault signs, so
/// [`verify_scoped_signature`] verifies a store-key signature exactly as it
/// verifies a Ghost Key's.
///
/// Built with `ghostkey-common`'s own type when that feature is on, which is
/// every build that signs; the fallback mirrors its encoding (the shape the
/// test helpers across this crate already sign with).
pub fn store_key_envelope(payload: Vec<u8>) -> Result<Vec<u8>, String> {
    #[cfg(feature = "ghostkey")]
    {
        crate::to_cbor(&ghostkey_common::ScopedPayload {
            requestor: crate::expected_harvest_requestor(),
            payload,
        })
    }
    #[cfg(not(feature = "ghostkey"))]
    {
        #[derive(Serialize)]
        struct ScopedPayload {
            requestor: Requestor,
            payload: Vec<u8>,
        }
        #[derive(Serialize)]
        enum Requestor {
            WebApp([u8; 32]),
        }
        let id: [u8; 32] = bs58::decode(crate::HARVEST_WEBAPP_CONTRACT_ID)
            .into_vec()
            .map_err(|e| format!("HARVEST_WEBAPP_CONTRACT_ID decode: {e}"))?
            .try_into()
            .map_err(|_| "HARVEST_WEBAPP_CONTRACT_ID is not 32 bytes".to_string())?;
        crate::to_cbor(&ScopedPayload {
            requestor: Requestor::WebApp(id),
            payload,
        })
    }
}

/// Sign `payload` with a store key: the envelope, and the Ed25519 signature
/// over it. Returns `(scoped_payload, signature)`, the two fields every signed
/// record in a store carries.
///
/// Refuses anything [`classify_store_key_message`] does not recognise.
pub fn sign_with_store_key(
    store_key: &ed25519_dalek::SigningKey,
    payload: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use ed25519_dalek::Signer;
    if classify_store_key_message(&payload).is_none() {
        return Err("the store key signs only a store's own records, and this is not one".into());
    }
    let scoped = store_key_envelope(payload)?;
    let signature = store_key.sign(&scoped).to_bytes().to_vec();
    Ok((scoped, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge_laws::{assert_laws, Rng};
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::BlockHash;
    use freenet_scaffold::ComposableState;

    fn store_key() -> SigningKey {
        SigningKey::from_bytes(&[0x51; 32])
    }

    fn ghost(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn params() -> StoreParameters {
        StoreParameters::new(store_key().verifying_key())
    }

    /// Sign as the Ghost Key vault does: the same envelope, the Ghost Key's
    /// own signature. The vault is not a store-key signer, so this does not go
    /// through [`sign_with_store_key`], which would (rightly) refuse a bare
    /// statement.
    fn vault_sign<T: Serialize>(key: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
        let scoped = store_key_envelope(crate::to_cbor(data).unwrap()).unwrap();
        let signature = key.sign(&scoped).to_bytes().to_vec();
        (scoped, signature)
    }

    fn store_sign<T: Serialize>(key: &SigningKey, data: &T) -> (Vec<u8>, Vec<u8>) {
        sign_with_store_key(key, crate::to_cbor(data).unwrap()).expect("a store record")
    }

    fn statement(store: &SigningKey, backer: &SigningKey, height: u32) -> BackingStatement {
        BackingStatement {
            store: store.verifying_key(),
            backer: backer.verifying_key(),
            certificate_pem: format!("CERT-{}", backer.verifying_key().as_bytes()[0]),
            network: BitcoinNetwork::Signet,
            block: BlockAnchor {
                height,
                hash: BlockHash([height as u8; 32]),
            },
        }
    }

    fn backing_by(
        store: &SigningKey,
        backer: &SigningKey,
        acceptor: &SigningKey,
        height: u32,
    ) -> AuthorizedBacking {
        let statement = statement(store, backer, height);
        let (backer_scoped_payload, backer_signature) = vault_sign(backer, &statement);
        let (acceptance_scoped_payload, acceptance_signature) = store_sign(
            acceptor,
            &BackingAcceptance {
                backing: statement.clone(),
            },
        );
        AuthorizedBacking {
            statement,
            backer_scoped_payload,
            backer_signature,
            acceptance_scoped_payload,
            acceptance_signature,
        }
    }

    fn backing(backer: &SigningKey, height: u32) -> AuthorizedBacking {
        backing_by(&store_key(), backer, &store_key(), height)
    }

    fn retirement_by(signer: &SigningKey, backer: &SigningKey) -> AuthorizedRetirement {
        let retirement = Retirement {
            backer: backer.verifying_key(),
        };
        let (scoped_payload, signature) = store_sign(signer, &retirement);
        AuthorizedRetirement {
            retirement,
            scoped_payload,
            signature,
        }
    }

    fn retirement(backer: &SigningKey) -> AuthorizedRetirement {
        retirement_by(&store_key(), backer)
    }

    fn closure_by(signer: &SigningKey, store: &SigningKey) -> AuthorizedClosure {
        let closure = StoreClosure {
            store: store.verifying_key(),
        };
        let (scoped_payload, signature) = store_sign(signer, &closure);
        AuthorizedClosure {
            closure,
            scoped_payload,
            signature,
        }
    }

    fn delta_with(
        backings: Vec<AuthorizedBacking>,
        retirements: Vec<AuthorizedRetirement>,
        closed: Vec<AuthorizedClosure>,
    ) -> crate::store::StoreStateV1Delta {
        crate::store::StoreStateV1Delta {
            owner: Some(store_key().verifying_key()),
            backings: (!backings.is_empty()).then_some(backings),
            retirements: (!retirements.is_empty()).then_some(retirements),
            closed: (!closed.is_empty()).then_some(closed),
            ..Default::default()
        }
    }

    fn apply(
        state: &StoreStateV1,
        delta: crate::store::StoreStateV1Delta,
    ) -> Result<StoreStateV1, String> {
        let mut next = state.clone();
        next.apply_delta(&state.clone(), &params(), &Some(delta))?;
        next.verify(&next, &params())?;
        Ok(next)
    }

    fn with(
        backings: Vec<AuthorizedBacking>,
        retirements: Vec<AuthorizedRetirement>,
    ) -> StoreStateV1 {
        apply(
            &StoreStateV1::default(),
            delta_with(backings, retirements, vec![]),
        )
        .expect("a valid store")
    }

    #[test]
    fn a_countersigned_backing_claims_the_store_and_verifies() {
        let state = with(vec![backing(&ghost(1), 100)], vec![]);
        assert_eq!(state.owner, Some(store_key().verifying_key()));
        assert_eq!(state.backings.records.len(), 1);
        assert!(state.holds_signed_content());
    }

    #[test]
    fn a_backing_the_store_key_did_not_accept_is_refused() {
        // Accepted by some other key: anybody can make a Ghost Key sign "I
        // back store X", so without the store key's acceptance anybody could
        // attach their key to any store.
        let forged = backing_by(&store_key(), &ghost(1), &ghost(9), 100);
        let err = apply(
            &StoreStateV1::default(),
            delta_with(vec![forged], vec![], vec![]),
        )
        .expect_err("a backing needs the store key's countersignature");
        assert!(err.contains("not accepted by the store key"), "{err}");

        // And with no countersignature at all.
        let mut bare = backing(&ghost(1), 100);
        bare.acceptance_scoped_payload.clear();
        bare.acceptance_signature.clear();
        assert!(apply(
            &StoreStateV1::default(),
            delta_with(vec![bare], vec![], vec![])
        )
        .is_err());
    }

    #[test]
    fn a_backing_signed_by_the_wrong_ghost_key_is_refused() {
        // The statement names ghost 1, but ghost 2 signed it: attached by the
        // wrong key.
        let mut wrong = backing(&ghost(1), 100);
        let (scoped, sig) = vault_sign(&ghost(2), &wrong.statement);
        wrong.backer_scoped_payload = scoped;
        wrong.backer_signature = sig;
        let err = apply(
            &StoreStateV1::default(),
            delta_with(vec![wrong], vec![], vec![]),
        )
        .expect_err("the named Ghost Key must be the one that signed");
        assert!(err.contains("not signed by the Ghost Key"), "{err}");
    }

    /// A Ghost Key's "I back store X" cannot be attached to store Y, even by
    /// Y's own key: the statement names the store it backs.
    ///
    /// Mutated red by removing the `statement.store != *owner` check from
    /// `AuthorizedBacking::verify`.
    #[test]
    fn a_backing_for_another_store_is_refused() {
        let other_store = SigningKey::from_bytes(&[0x77; 32]);
        // The Ghost Key backs OTHER store, and THIS store's key countersigns
        // it: every signature is genuine and the store key accepted it.
        let elsewhere = backing_by(&other_store, &ghost(1), &store_key(), 100);
        let err = apply(
            &StoreStateV1::default(),
            delta_with(vec![elsewhere], vec![], vec![]),
        )
        .expect_err("a backing names the store it backs");
        assert!(err.contains("different store key"), "{err}");
    }

    /// A record filed under a slot that is not its own would let a store
    /// hold two backings by one Ghost Key, and let a retirement of one key
    /// sit where another's is looked up.
    ///
    /// Mutated red by removing the slot check from `SignedSetV1::verify`.
    #[test]
    fn a_record_under_someone_elses_slot_is_refused() {
        let mut state = with(vec![backing(&ghost(1), 100)], vec![]);
        let misfiled = backing(&ghost(2), 200);
        state
            .backings
            .records
            .insert(Bytes32(ghost(3).verifying_key().to_bytes()), misfiled);
        let err = state
            .verify(&state, &params())
            .expect_err("a record under another key's slot");
        assert!(err.contains("slot"), "{err}");
    }

    /// The whole state is checked, not only what arrives as a delta: a PUT
    /// or a whole-state update carrying a forged backing, retirement or
    /// closure must be refused as surely as a delta carrying one.
    ///
    /// Mutated red by removing the `backings`, `retirements` or `closed`
    /// `verify` call from `StoreStateV1::verify`.
    #[test]
    fn a_whole_state_with_a_forged_record_is_refused() {
        let base = with(vec![backing(&ghost(1), 100)], vec![]);

        let mut forged_retirement = base.clone();
        let r = retirement_by(&ghost(9), &ghost(1));
        forged_retirement.retirements.records.insert(r.slot(), r);
        assert!(forged_retirement
            .verify(&forged_retirement, &params())
            .is_err());

        let mut forged_closure = base.clone();
        let c = closure_by(&ghost(9), &store_key());
        forged_closure.closed.records.insert(c.slot(), c);
        assert!(forged_closure.verify(&forged_closure, &params()).is_err());

        let mut forged_backing = base.clone();
        let b = backing_by(&store_key(), &ghost(2), &ghost(9), 200);
        forged_backing.backings.records.insert(b.slot(), b);
        assert!(forged_backing.verify(&forged_backing, &params()).is_err());
    }

    #[test]
    fn a_retirement_or_closure_not_signed_by_the_store_key_is_refused() {
        let base = with(vec![backing(&ghost(1), 100)], vec![]);
        assert!(apply(
            &base,
            delta_with(vec![], vec![retirement_by(&ghost(1), &ghost(1))], vec![])
        )
        .is_err());
        assert!(apply(
            &base,
            delta_with(vec![], vec![], vec![closure_by(&ghost(1), &store_key())])
        )
        .is_err());
        // Signed by the store key, but closing some other store.
        let other = SigningKey::from_bytes(&[0x77; 32]);
        assert!(apply(
            &base,
            delta_with(vec![], vec![], vec![closure_by(&store_key(), &other)])
        )
        .is_err());
    }

    #[test]
    fn a_refused_record_leaves_the_state_unchanged() {
        let base = with(vec![backing(&ghost(1), 100)], vec![]);
        let mut next = base.clone();
        let forged = backing_by(&store_key(), &ghost(2), &ghost(9), 101);
        let result = next.apply_delta(
            &base,
            &params(),
            &Some(delta_with(
                vec![backing(&ghost(3), 102), forged],
                vec![],
                vec![],
            )),
        );
        assert!(result.is_err());
        assert_eq!(next, base, "all or nothing: the valid half must not land");
    }

    /// The whole point of the two sets: nothing removes an entry. A peer
    /// holding less cannot shrink a peer holding more, by state or by delta.
    #[test]
    fn nothing_removes_a_backing_a_retirement_or_the_closed_flag() {
        let full = apply(
            &with(
                vec![backing(&ghost(1), 100), backing(&ghost(2), 200)],
                vec![retirement(&ghost(1))],
            ),
            delta_with(vec![], vec![], vec![closure_by(&store_key(), &store_key())]),
        )
        .unwrap();
        let sparse = with(vec![backing(&ghost(2), 200)], vec![]);

        for (a, b) in [(&full, &sparse), (&sparse, &full)] {
            let mut merged = a.clone();
            merged.merge(&a.clone(), &params(), b).unwrap();
            assert_eq!(merged.backings.records.len(), 2);
            assert_eq!(merged.retirements.records.len(), 1);
            assert!(is_closed(&merged), "closed merges by OR");
        }
        // What the sparse peer would send the full one is nothing.
        assert!(sparse
            .delta(&sparse, &params(), &full.summarize(&full, &params()))
            .is_none());
    }

    #[test]
    fn two_records_for_one_slot_resolve_to_the_smaller_encoding_either_way() {
        let a = with(vec![backing(&ghost(1), 100)], vec![]);
        let b = with(vec![backing(&ghost(1), 200)], vec![]);
        let bytes = |s: &StoreStateV1| {
            crate::to_cbor(&s.backings.records.values().next().unwrap().clone()).unwrap()
        };
        let smaller = if bytes(&a) < bytes(&b) { &a } else { &b };
        for (x, y) in [(&a, &b), (&b, &a)] {
            let mut merged = x.clone();
            merged.merge(&x.clone(), &params(), y).unwrap();
            assert_eq!(merged.backings, smaller.backings);
        }
    }

    fn many_backings(n: usize) -> Vec<AuthorizedBacking> {
        (0..n as u32)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[..4].copy_from_slice(&(i + 1000).to_le_bytes());
                backing(&SigningKey::from_bytes(&seed), 100 + i)
            })
            .collect()
    }

    /// Past the bound the merge still succeeds (harvest#93 review, Must Fix
    /// 1): it keeps the `MAX_BACKINGS` smallest Ghost Keys, and everything
    /// else in the same update lands, the closed flag included.
    ///
    /// Mutated red by making `normalize_backings` keep the LARGEST keys, and
    /// by skipping it.
    #[test]
    fn a_union_past_the_bound_keeps_the_smallest_keys_and_everything_else() {
        let many = many_backings(MAX_BACKINGS + 3);
        let mut next = StoreStateV1::default();
        next.apply_delta(
            &StoreStateV1::default(),
            &params(),
            &Some(delta_with(
                many.clone(),
                vec![],
                vec![closure_by(&store_key(), &store_key())],
            )),
        )
        .expect("a merge past the bound never fails");
        next.verify(&next, &params())
            .expect("and yields a valid state");
        assert_eq!(next.backings.records.len(), MAX_BACKINGS);
        assert!(is_closed(&next), "the closure in the same update landed");
        let mut slots: Vec<Bytes32> = many.iter().map(|b| b.slot()).collect();
        slots.sort();
        let kept: Vec<Bytes32> = next.backings.records.keys().copied().collect();
        assert_eq!(kept, slots[..MAX_BACKINGS].to_vec(), "the smallest keys");

        // A state built past it directly does not verify.
        let mut state = next.clone();
        let largest = many
            .iter()
            .find(|b| b.slot() == slots[MAX_BACKINGS])
            .unwrap()
            .clone();
        state.backings.records.insert(largest.slot(), largest);
        assert!(state.verify(&state, &params()).is_err());
    }

    /// A retirement must name a backing the store holds, so a store never
    /// holds more retirements than backings. Mutated red by removing the
    /// check from `StoreStateV1::verify`.
    #[test]
    fn a_retirement_of_a_key_that_does_not_back_the_store_is_refused() {
        let mut state = with(vec![backing(&ghost(1), 100)], vec![]);
        let orphan = retirement(&ghost(2));
        state.retirements.records.insert(orphan.slot(), orphan);
        let err = state
            .verify(&state, &params())
            .expect_err("an orphan retirement");
        assert!(err.contains("does not back this store"), "{err}");
    }

    /// A retirement is dropped exactly when its backing is cut, and a
    /// backing once cut never comes back UN-retired: whatever a later merge
    /// brings, the slot still ranks below the kept ones.
    ///
    /// Mutated red by keeping retirements whose backing was cut.
    #[test]
    fn a_cut_backing_takes_its_retirement_and_never_returns_unretired() {
        let many = many_backings(MAX_BACKINGS + 1);
        let mut slots: Vec<Bytes32> = many.iter().map(|b| b.slot()).collect();
        slots.sort();
        let by_slot = |slot: Bytes32| many.iter().find(|b| b.slot() == slot).unwrap().clone();
        let largest = by_slot(slots[MAX_BACKINGS]);
        let largest_key = largest.statement.backer;
        let retire_largest = {
            let retirement = Retirement {
                backer: largest_key,
            };
            let (scoped_payload, signature) = store_sign(&store_key(), &retirement);
            AuthorizedRetirement {
                retirement,
                scoped_payload,
                signature,
            }
        };

        // One replica holds the largest backing, retired, and a few others.
        let a = apply(
            &StoreStateV1::default(),
            delta_with(
                vec![largest.clone(), by_slot(slots[0])],
                vec![retire_largest],
                vec![],
            ),
        )
        .unwrap();
        // Another holds the full smallest set.
        let b = with(
            slots[..MAX_BACKINGS].iter().map(|s| by_slot(*s)).collect(),
            vec![],
        );
        // A third holds the largest backing, NOT retired.
        let c = with(vec![largest.clone()], vec![]);

        let mut ab = a.clone();
        ab.merge(&a.clone(), &params(), &b).unwrap();
        assert!(!ab.backings.records.contains_key(&largest.slot()));
        assert!(
            ab.retirements.records.is_empty(),
            "the retirement went with it"
        );

        let mut abc = ab.clone();
        abc.merge(&ab.clone(), &params(), &c).unwrap();
        assert!(
            !abc.backings.records.contains_key(&largest.slot()),
            "a cut backing does not come back, retired or not"
        );
        abc.verify(&abc, &params()).unwrap();
    }

    /// The certificate bound is inclusive: exactly `MAX_CERTIFICATE_PEM_BYTES`
    /// is accepted. Mutated red by turning `>` into `>=`.
    #[test]
    fn a_certificate_of_exactly_the_bound_is_accepted() {
        let mut statement = statement(&store_key(), &ghost(1), 100);
        statement.certificate_pem = "x".repeat(MAX_CERTIFICATE_PEM_BYTES);
        let (backer_scoped_payload, backer_signature) = vault_sign(&ghost(1), &statement);
        let (acceptance_scoped_payload, acceptance_signature) = store_sign(
            &store_key(),
            &BackingAcceptance {
                backing: statement.clone(),
            },
        );
        let at_bound = AuthorizedBacking {
            statement,
            backer_scoped_payload,
            backer_signature,
            acceptance_scoped_payload,
            acceptance_signature,
        };
        apply(
            &StoreStateV1::default(),
            delta_with(vec![at_bound], vec![], vec![]),
        )
        .expect("the bound itself is allowed");
    }

    /// The tie-break is part of the key, not an accident of map order: the
    /// same candidates in either order give the same answer. Mutated red by
    /// dropping the backing key from `most_recent`'s key.
    #[test]
    fn the_most_recent_backing_does_not_depend_on_the_order_given() {
        let a = backing(&ghost(3), 300);
        let b = backing(&ghost(4), 300);
        let expected = if a.statement.backer.to_bytes() > b.statement.backer.to_bytes() {
            a.statement.backer
        } else {
            b.statement.backer
        };
        for order in [[&a, &b], [&b, &a]] {
            assert_eq!(
                most_recent(order.into_iter()).unwrap().statement.backer,
                expected
            );
        }
    }

    #[test]
    fn a_backing_whose_certificate_is_too_large_is_refused() {
        let mut statement = statement(&store_key(), &ghost(1), 100);
        statement.certificate_pem = "x".repeat(MAX_CERTIFICATE_PEM_BYTES + 1);
        let (backer_scoped_payload, backer_signature) = vault_sign(&ghost(1), &statement);
        let (acceptance_scoped_payload, acceptance_signature) = store_sign(
            &store_key(),
            &BackingAcceptance {
                backing: statement.clone(),
            },
        );
        let oversized = AuthorizedBacking {
            statement,
            backer_scoped_payload,
            backer_signature,
            acceptance_scoped_payload,
            acceptance_signature,
        };
        assert!(apply(
            &StoreStateV1::default(),
            delta_with(vec![oversized], vec![], vec![])
        )
        .is_err());
    }

    /// The seeded merge laws, byte for byte, over random stores built from a
    /// pool that includes two records for the same slot, retirements of keys
    /// that were never a backing, and the closed flag.
    #[test]
    fn seeded_random_backing_sets_obey_the_merge_laws() {
        let backings: Vec<AuthorizedBacking> = vec![
            backing(&ghost(1), 100),
            backing(&ghost(1), 150), // same slot, different bytes
            backing(&ghost(2), 200),
            backing(&ghost(3), 300),
            backing(&ghost(4), 300),
        ];
        let retirements = vec![retirement(&ghost(1)), retirement(&ghost(3))];
        let closure = closure_by(&store_key(), &store_key());

        let mut rng = Rng::new(0x1a_ba_c1);
        let mut states = vec![StoreStateV1::default()];
        for _ in 0..60 {
            let mut b = rng.subset(&backings, 4);
            let r = rng.subset(&retirements, 2);
            let c = if rng.below(3) == 0 {
                vec![closure.clone()]
            } else {
                vec![]
            };
            // Always at least one backing, so the update claims the store
            // even when its retirements name keys it does not back (which
            // `normalize_backings` then drops).
            if b.is_empty() {
                b.push(backings[rng.below(backings.len())].clone());
            }
            states.push(
                apply(&StoreStateV1::default(), delta_with(b, r, c)).expect("generated state"),
            );
        }
        assert_laws(
            &states,
            400,
            &mut rng,
            |a, b| {
                let mut merged = a.clone();
                merged.merge(&a.clone(), &params(), b).expect("merge");
                merged
                    .verify(&merged, &params())
                    .expect("a merged state verifies");
                merged
            },
            |s| crate::to_cbor(s).unwrap(),
        );
        // Inflation: a merge never loses a slot either side held.
        for _ in 0..200 {
            let (a, b) = (
                &states[rng.below(states.len())],
                &states[rng.below(states.len())],
            );
            let mut merged = a.clone();
            merged.merge(&a.clone(), &params(), b).unwrap();
            for side in [a, b] {
                assert!(side
                    .backings
                    .records
                    .keys()
                    .all(|k| merged.backings.records.contains_key(k)));
                assert!(side
                    .retirements
                    .records
                    .keys()
                    .all(|k| merged.retirements.records.contains_key(k)));
                assert!(!is_closed(side) || is_closed(&merged));
            }
        }
    }

    /// The merge laws where it matters most: unions that exceed the bound.
    /// Random stores over a pool of `MAX_BACKINGS + 8` backings, with
    /// retirements, the closed flag and a listing, merged in every grouping;
    /// every merge must succeed, verify, and carry the closure and listings
    /// of either side (harvest#93 review, Must Fix 1).
    #[test]
    fn seeded_merges_past_the_bound_obey_the_merge_laws_and_drop_nothing_else() {
        use crate::merge_laws::{assert_laws, Rng};
        let pool = many_backings(MAX_BACKINGS + 8);
        let retirements: Vec<AuthorizedRetirement> = pool
            .iter()
            .step_by(5)
            .map(|b| {
                let retirement = Retirement {
                    backer: b.statement.backer,
                };
                let (scoped_payload, signature) = store_sign(&store_key(), &retirement);
                AuthorizedRetirement {
                    retirement,
                    scoped_payload,
                    signature,
                }
            })
            .collect();
        let closure = closure_by(&store_key(), &store_key());
        let listing = {
            let listing = crate::listing::Listing {
                id: crate::listing::ListingId([0; 32]),
                title: "Beans".into(),
                description: String::new(),
                kind: crate::listing::ListingKind::Sale,
                price: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            }
            .with_derived_id();
            let (scoped_payload, signature) = store_sign(&store_key(), &listing);
            crate::listing::AuthorizedListing {
                listing,
                scoped_payload,
                signature,
                certificate_pem: String::new(),
            }
        };

        let mut rng = Rng::new(0x0ca9_5eed);
        let mut states = Vec::new();
        for _ in 0..24 {
            let mut b: Vec<AuthorizedBacking> =
                pool.iter().filter(|_| rng.below(4) != 0).cloned().collect();
            if b.is_empty() {
                b.push(pool[0].clone());
            }
            let r = rng.subset(&retirements, 6);
            let c = if rng.below(3) == 0 {
                vec![closure.clone()]
            } else {
                vec![]
            };
            let mut delta = delta_with(b, r, c);
            if rng.below(3) == 0 {
                delta.listings = Some(vec![listing.clone()]);
            }
            states.push(apply(&StoreStateV1::default(), delta).expect("generated state"));
        }
        assert!(states
            .iter()
            .any(|s| s.backings.records.len() == MAX_BACKINGS));
        let merge = |a: &StoreStateV1, b: &StoreStateV1| {
            let mut merged = a.clone();
            merged
                .merge(&a.clone(), &params(), b)
                .expect("a merge of valid states never fails");
            merged
                .verify(&merged, &params())
                .expect("and yields a valid state");
            for side in [a, b] {
                assert!(
                    !is_closed(side) || is_closed(&merged),
                    "a closure was dropped"
                );
                assert!(
                    side.listings.listings.len() <= merged.listings.listings.len(),
                    "a listing was dropped"
                );
            }
            merged
        };
        assert_laws(&states, 150, &mut rng, merge, |s| {
            crate::to_cbor(s).unwrap()
        });
    }

    #[test]
    fn the_current_backing_is_the_most_recent_unretired_one() {
        let tip = |_| Some(1_000);
        let state = with(
            vec![backing(&ghost(1), 100), backing(&ghost(2), 200)],
            vec![],
        );
        assert_eq!(
            current_backing(&state, tip).unwrap().statement.backer,
            ghost(2).verifying_key()
        );
        // Retire the newer one and the older becomes current again.
        let state = with(
            vec![backing(&ghost(1), 100), backing(&ghost(2), 200)],
            vec![retirement(&ghost(2))],
        );
        assert_eq!(
            current_backing(&state, tip).unwrap().statement.backer,
            ghost(1).verifying_key()
        );
        // All retired: unbacked.
        let state = with(vec![backing(&ghost(1), 100)], vec![retirement(&ghost(1))]);
        assert!(current_backing(&state, tip).is_none());
        assert!(current_backing(&StoreStateV1::default(), tip).is_none());
    }

    #[test]
    fn a_tie_on_height_is_broken_by_the_backing_key() {
        let state = with(
            vec![backing(&ghost(3), 300), backing(&ghost(4), 300)],
            vec![],
        );
        let expected = if ghost(3).verifying_key().to_bytes() > ghost(4).verifying_key().to_bytes()
        {
            ghost(3)
        } else {
            ghost(4)
        };
        assert_eq!(
            current_backing(&state, |_| None).unwrap().statement.backer,
            expected.verifying_key()
        );
    }

    #[test]
    fn a_future_dated_backing_is_not_current_once_the_tip_is_known() {
        let state = with(
            vec![backing(&ghost(1), 100), backing(&ghost(2), 5_000)],
            vec![],
        );
        assert_eq!(
            current_backing(&state, |_| Some(1_000))
                .unwrap()
                .statement
                .backer,
            ghost(1).verifying_key(),
            "a block above the tip is dated in the future"
        );
        assert_eq!(
            current_backing(&state, |_| None).unwrap().statement.backer,
            ghost(2).verifying_key(),
            "with no tip for that network nothing is left out"
        );
    }

    #[test]
    fn a_key_backing_two_stores_is_found_and_one_backing_one_store_is_not() {
        let (s1, s2, s3) = (ghost(0x61), ghost(0x62), ghost(0x63));
        let found = keys_backing_several_stores([
            (s1.verifying_key(), ghost(1).verifying_key()),
            (s2.verifying_key(), ghost(1).verifying_key()),
            (s3.verifying_key(), ghost(2).verifying_key()),
        ]);
        assert_eq!(found, BTreeSet::from([ghost(1).verifying_key().to_bytes()]));
        // The same store listed twice is one store, not two.
        assert!(keys_backing_several_stores([
            (s1.verifying_key(), ghost(1).verifying_key()),
            (s1.verifying_key(), ghost(1).verifying_key()),
        ])
        .is_empty());
    }

    #[test]
    fn the_store_key_signs_only_a_stores_own_records() {
        let stmt = statement(&store_key(), &ghost(1), 100);
        let accept = crate::to_cbor(&BackingAcceptance {
            backing: stmt.clone(),
        })
        .unwrap();
        assert_eq!(
            classify_store_key_message(&accept),
            Some(StoreKeyMessage::BackingAcceptance)
        );
        assert_eq!(
            classify_store_key_message(
                &crate::to_cbor(&Retirement {
                    backer: ghost(1).verifying_key()
                })
                .unwrap()
            ),
            Some(StoreKeyMessage::Retirement)
        );
        assert_eq!(
            classify_store_key_message(
                &crate::to_cbor(&StoreClosure {
                    store: store_key().verifying_key()
                })
                .unwrap()
            ),
            Some(StoreKeyMessage::Closure)
        );
        // A bare backing statement is the GHOST KEY's message. The contract
        // verifies it against the backer, so a store-key signature over it
        // would not forge a backing; it would still be the store key signing
        // bytes it has no reason ever to produce, and the delegate is a
        // signing oracle for whatever the UI asks, so it signs nothing it
        // does not have to.
        assert_eq!(
            classify_store_key_message(&crate::to_cbor(&stmt).unwrap()),
            None
        );
        // Trailing bytes do not ride along.
        let mut trailing = accept.clone();
        trailing.push(0);
        assert_eq!(classify_store_key_message(&trailing), None);
        // Nor does a custody wrap message, or arbitrary bytes.
        assert_eq!(
            classify_store_key_message(b"harvest/store-key-wrap/v1\0"),
            None
        );
        assert!(sign_with_store_key(&store_key(), crate::to_cbor(&stmt).unwrap()).is_err());
    }

    #[test]
    fn a_store_key_signature_verifies_like_a_vault_signature() {
        let retirement = Retirement {
            backer: ghost(1).verifying_key(),
        };
        let (scoped, sig) =
            sign_with_store_key(&store_key(), crate::to_cbor(&retirement).unwrap()).unwrap();
        verify_scoped_signature(&scoped, &sig, &store_key().verifying_key(), &retirement)
            .expect("the same verifier as every other record");
        // And the envelope is ghostkey-common's own type, requestor included.
        #[cfg(feature = "ghostkey")]
        {
            let decoded: ghostkey_common::ScopedPayload = crate::from_cbor(&scoped).unwrap();
            assert_eq!(decoded.requestor, crate::expected_harvest_requestor());
            assert_eq!(decoded.payload, crate::to_cbor(&retirement).unwrap());
        }
    }

    /// A state holding none of the revision-2 parts must encode exactly as
    /// it did before they existed, or every such state fails the contract's
    /// canonical-encoding check and the migration fold cannot carry it.
    #[test]
    fn a_state_without_backings_encodes_as_it_did_before_them() {
        #[derive(Serialize)]
        struct Before {
            owner: Option<VerifyingKey>,
            info: crate::store::AuthorizedStoreInfoV1,
            listings: crate::store::ListingsV1,
            orders: crate::store::OrdersV1,
        }
        let now = StoreStateV1::default();
        let before = Before {
            owner: None,
            info: Default::default(),
            listings: Default::default(),
            orders: Default::default(),
        };
        assert_eq!(
            crate::to_cbor(&now).unwrap(),
            crate::to_cbor(&before).unwrap()
        );
        let decoded: StoreStateV1 = crate::from_cbor(&crate::to_cbor(&before).unwrap()).unwrap();
        assert_eq!(decoded, now);
    }
}
