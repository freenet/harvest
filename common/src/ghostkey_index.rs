//! The Ghost Key index: a contract addressed by a Ghost Key alone, holding
//! that key's signed statements of which stores it has backed (harvest#93,
//! phase 1c; `docs/design/entity-model.md`, section 3 and decision 6.8).
//!
//! # What it is for
//!
//! A new device knows a Ghost Key and nothing else. Reading the key's index
//! gives it every store the key has backed, and from each store key the
//! store's address. That is what replaces the per-device store registry
//! (the Harvest delegate's list stays, as a cache). A reader applying "one
//! current store per Ghost Key" (decision 6.2) reads the index too, so the
//! rule covers the key's other stores and not only the ones the reader
//! happened to open.
//!
//! # What an entry is
//!
//! An [`IndexEntry`] is the very [`BackingStatement`] the Ghost Key signed
//! through the vault when it backed a store, with that signature: the
//! backer's half of the store's `AuthorizedBacking`. So publishing an entry
//! needs no second vault prompt, and anyone holding the store's state can
//! republish it.
//!
//! # What an entry does NOT say
//!
//! That the store accepted the backing, or that it is current, or that it is
//! not retired. The Ghost Key alone signs an entry, so it can list any store
//! key it likes. The index is a list of places to look; the store's own
//! state says whether the key backs it, whether that backing is retired, and
//! whether it is current. A reader never takes an entry as a backing.
//!
//! # Merge
//!
//! Grow-only, one entry per store key (the slot), the smaller CBOR encoding
//! on a clash, exactly as the store's own signed sets merge. Past
//! [`MAX_INDEX_ENTRIES`] the entries with the smallest store keys are kept:
//! top-N over a slot-only ranking, so the merge stays total and associative
//! in any arrival order (the argument `backing::MAX_BACKINGS` makes). Only
//! the Ghost Key's holder can add entries, so only that holder can reach the
//! bound. No complaints are copied here (decision 6.8), and nothing here
//! reads another contract (decision 6.7).

use std::collections::BTreeMap;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::backing::{BackingStatement, MAX_CERTIFICATE_PEM_BYTES};
use crate::listing::verify_scoped_signature;
use crate::store::Bytes32;

/// How many stores one Ghost Key's index lists.
///
/// A Ghost Key backs one store at a time (decision 6.2), and a seller who
/// moves from store to store adds one entry each time; this bounds the state
/// (each entry carries a certificate of up to `MAX_CERTIFICATE_PEM_BYTES`)
/// and what a reader follows, not honest use.
pub const MAX_INDEX_ENTRIES: usize = 64;

/// The index contract's parameters: the Ghost Key, and nothing else, so the
/// index is found from the key alone.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct IndexParameters {
    /// `pub(crate)` on purpose: see [`IndexParameters::new`].
    pub(crate) ghost_key: VerifyingKey,
}

impl IndexParameters {
    /// The only way to build these parameters from outside `harvest-common`:
    /// the field set is hashed into the index's address, so a second place
    /// building it by hand can address a different contract (the reason
    /// `StoreParameters::new` gives).
    pub fn new(ghost_key: VerifyingKey) -> Self {
        Self { ghost_key }
    }

    pub fn ghost_key(&self) -> &VerifyingKey {
        &self.ghost_key
    }
}

/// One store the Ghost Key has backed: its signed backing statement.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct IndexEntry {
    pub statement: BackingStatement,
    /// The vault's `ScopedPayload` over the statement, and the Ghost Key's
    /// signature over that: the backer's half of the store's backing.
    pub scoped_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl IndexEntry {
    /// The entry the backer's half of `backing` makes.
    pub fn from_backing(backing: &crate::backing::AuthorizedBacking) -> Self {
        Self {
            statement: backing.statement.clone(),
            scoped_payload: backing.backer_scoped_payload.clone(),
            signature: backing.backer_signature.clone(),
        }
    }

    /// The slot an entry occupies: its store key.
    pub fn slot(&self) -> Bytes32 {
        Bytes32(self.statement.store.to_bytes())
    }

    /// Whether the index of `ghost_key` may hold this entry: it is that key's
    /// backing statement, signed by it, with a bounded certificate.
    pub fn verify(&self, ghost_key: &VerifyingKey) -> Result<(), String> {
        if self.statement.backer != *ghost_key {
            return Err("index entry is a backing by another Ghost Key".into());
        }
        if self.statement.certificate_pem.len() > MAX_CERTIFICATE_PEM_BYTES {
            return Err(format!(
                "index entry certificate is {} bytes, the most one may carry is \
                 {MAX_CERTIFICATE_PEM_BYTES}",
                self.statement.certificate_pem.len()
            ));
        }
        verify_scoped_signature(
            &self.scoped_payload,
            &self.signature,
            ghost_key,
            &self.statement,
        )
        .map_err(|e| format!("index entry is not signed by its Ghost Key: {e}"))
    }
}

/// The encoding a clash and a summary are decided by.
///
/// An error is not papered over with empty bytes (#101 review): empty would
/// compare SMALLER than every real encoding, so an entry that failed to
/// serialize would win every tie-break and every digest. Every caller that
/// can refuse does; `summarize` cannot, and uses a digest of the error
/// instead, which differs from any real entry's digest.
fn entry_bytes(entry: &IndexEntry) -> Result<Vec<u8>, String> {
    crate::to_cbor(entry).map_err(|e| format!("an index entry did not serialize: {e}"))
}

/// BLAKE3 of an entry's encoding, for the summary and the tie-break.
fn digest(entry: &IndexEntry) -> Bytes32 {
    match entry_bytes(entry) {
        Ok(bytes) => Bytes32(*blake3::hash(&bytes).as_bytes()),
        // Not a real entry's digest, so a peer holding this slot asks for it
        // rather than being told nothing is missing.
        Err(_) => Bytes32([0xff; 32]),
    }
}

/// A Ghost Key's index: one entry per store key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct GhostKeyIndexV1 {
    #[serde(default)]
    pub entries: BTreeMap<Bytes32, IndexEntry>,
}

/// What a peer tells another it holds: `(store key, BLAKE3 of the entry)`.
pub type IndexSummaryV1 = Vec<(Bytes32, Bytes32)>;

/// The entries a peer is missing, or holds with different bytes.
pub type IndexDeltaV1 = Vec<IndexEntry>;

impl GhostKeyIndexV1 {
    /// The whole-state check: every entry the key's, in its own slot, within
    /// the bound.
    pub fn verify(&self, params: &IndexParameters) -> Result<(), String> {
        if self.entries.len() > MAX_INDEX_ENTRIES {
            return Err(format!(
                "index lists {} stores, the most it keeps is {MAX_INDEX_ENTRIES}",
                self.entries.len()
            ));
        }
        for (slot, entry) in &self.entries {
            if entry.slot() != *slot {
                return Err("index entry filed under a slot that is not its store key".into());
            }
            entry.verify(&params.ghost_key)?;
        }
        Ok(())
    }

    pub fn summarize(&self) -> IndexSummaryV1 {
        self.entries
            .iter()
            .map(|(slot, entry)| (*slot, digest(entry)))
            .collect()
    }

    /// Every entry the summary does not account for: missing, or held with
    /// different bytes. Sending one that loses the tie-break is safe; the
    /// receiver keeps its own.
    pub fn delta(&self, old: &IndexSummaryV1) -> Option<IndexDeltaV1> {
        let theirs: BTreeMap<Bytes32, Bytes32> = old.iter().copied().collect();
        let changed: Vec<IndexEntry> = self
            .entries
            .iter()
            .filter(|(slot, entry)| theirs.get(*slot).is_none_or(|held| *held != digest(entry)))
            .map(|(_, entry)| entry.clone())
            .collect();
        (!changed.is_empty()).then_some(changed)
    }

    /// Fold entries in. The whole delta is verified before any of it is
    /// merged, so a refused delta leaves the index as it was. Never fails on
    /// the bound: see [`Self::normalize`].
    pub fn apply_delta(
        &mut self,
        params: &IndexParameters,
        incoming: &[IndexEntry],
    ) -> Result<(), String> {
        // BEFORE any signature is checked (#101 review): a delta is a `Vec`,
        // so duplicates do not collapse into slots, and an unbounded one
        // buys as many signature verifications as the sender cares to send.
        // The most a delta can usefully carry is one entry per slot the
        // index may hold.
        let distinct: std::collections::BTreeSet<Bytes32> =
            incoming.iter().map(IndexEntry::slot).collect();
        if distinct.len() > MAX_INDEX_ENTRIES || incoming.len() > MAX_INDEX_ENTRIES {
            return Err(format!(
                "an index delta carries {} entries over {} store keys, the most it may carry is \
                 {MAX_INDEX_ENTRIES}",
                incoming.len(),
                distinct.len()
            ));
        }
        for entry in incoming {
            entry.verify(&params.ghost_key)?;
        }
        for entry in incoming {
            let slot = entry.slot();
            // Explicit, because `Result`'s own ordering puts an error FIRST:
            // comparing the encodings as `Result`s would let an entry that
            // does not serialize win every clash.
            let incoming_bytes = entry_bytes(entry)?;
            let keep_incoming = match self.entries.get(&slot) {
                Some(held) => entry_bytes(held)? > incoming_bytes,
                None => true,
            };
            if keep_incoming {
                self.entries.insert(slot, entry.clone());
            }
        }
        self.normalize();
        Ok(())
    }

    /// Merge a whole state in.
    pub fn merge(&mut self, params: &IndexParameters, other: &Self) -> Result<(), String> {
        let incoming: Vec<IndexEntry> = other.entries.values().cloned().collect();
        self.apply_delta(params, &incoming)
    }

    /// Keep the [`MAX_INDEX_ENTRIES`] entries with the smallest store keys.
    fn normalize(&mut self) {
        while self.entries.len() > MAX_INDEX_ENTRIES {
            self.entries.pop_last();
        }
    }

    /// The store keys this index lists.
    pub fn store_keys(&self) -> impl Iterator<Item = VerifyingKey> + '_ {
        self.entries.values().map(|entry| entry.statement.store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backing::store_key_envelope;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::{BitcoinNetwork, BlockAnchor, BlockHash};

    fn ghost() -> SigningKey {
        SigningKey::from_bytes(&[0x61; 32])
    }

    fn params() -> IndexParameters {
        IndexParameters::new(ghost().verifying_key())
    }

    fn store_key(i: u32) -> VerifyingKey {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&(i + 7000).to_le_bytes());
        SigningKey::from_bytes(&seed).verifying_key()
    }

    fn entry_by(signer: &SigningKey, backer: &SigningKey, store: u32, height: u32) -> IndexEntry {
        let statement = BackingStatement {
            store: store_key(store),
            backer: backer.verifying_key(),
            certificate_pem: format!("CERT-{height}"),
            network: BitcoinNetwork::Signet,
            block: BlockAnchor {
                height,
                hash: BlockHash([height as u8; 32]),
            },
        };
        let scoped = store_key_envelope(crate::to_cbor(&statement).unwrap()).unwrap();
        let signature = signer.sign(&scoped).to_bytes().to_vec();
        IndexEntry {
            statement,
            scoped_payload: scoped,
            signature,
        }
    }

    fn entry(store: u32, height: u32) -> IndexEntry {
        entry_by(&ghost(), &ghost(), store, height)
    }

    /// Fold entries in, a delta's worth at a time: one delta may not carry
    /// more than `MAX_INDEX_ENTRIES` (see `apply_delta`), so a fixture past
    /// the bound arrives in several, as it would from a peer.
    fn with(entries: Vec<IndexEntry>) -> GhostKeyIndexV1 {
        let mut state = GhostKeyIndexV1::default();
        for chunk in entries.chunks(MAX_INDEX_ENTRIES) {
            state.apply_delta(&params(), chunk).expect("valid entries");
        }
        state.verify(&params()).expect("a valid index");
        state
    }

    /// Only the Ghost Key's own signed backing statements. Mutated red by
    /// removing the backer check and the signature check.
    #[test]
    fn an_entry_is_the_ghost_keys_own_signed_statement() {
        assert!(entry(1, 10).verify(&ghost().verifying_key()).is_ok());
        let other = SigningKey::from_bytes(&[0x62; 32]);
        // Another key's statement, genuinely signed by it.
        assert!(entry_by(&other, &other, 1, 10)
            .verify(&ghost().verifying_key())
            .is_err());
        // Signed by this Ghost Key, but a statement naming another backer.
        assert!(entry_by(&ghost(), &other, 1, 10)
            .verify(&ghost().verifying_key())
            .is_err());
        // The Ghost Key's statement, signed by someone else.
        assert!(entry_by(&other, &ghost(), 1, 10)
            .verify(&ghost().verifying_key())
            .is_err());
        // A refused delta leaves the index as it was.
        let mut state = with(vec![entry(1, 10)]);
        let before = state.clone();
        assert!(state
            .apply_delta(
                &params(),
                &[entry(2, 10), entry_by(&other, &ghost(), 3, 10)]
            )
            .is_err());
        assert_eq!(state, before);
    }

    /// An entry in someone else's slot is refused by the whole-state check.
    #[test]
    fn an_entry_under_another_slot_is_refused() {
        let mut state = with(vec![entry(1, 10)]);
        let e = entry(2, 10);
        state.entries.insert(Bytes32(store_key(9).to_bytes()), e);
        assert!(state.verify(&params()).is_err());
    }

    /// A certificate is bounded, inclusively.
    #[test]
    fn the_certificate_is_bounded() {
        let mut at = entry(1, 10);
        at.statement.certificate_pem = "x".repeat(MAX_CERTIFICATE_PEM_BYTES);
        let scoped = store_key_envelope(crate::to_cbor(&at.statement).unwrap()).unwrap();
        at.signature = ghost().sign(&scoped).to_bytes().to_vec();
        at.scoped_payload = scoped;
        assert!(at.verify(&ghost().verifying_key()).is_ok());
        let mut over = at.clone();
        over.statement.certificate_pem.push('x');
        let scoped = store_key_envelope(crate::to_cbor(&over.statement).unwrap()).unwrap();
        over.signature = ghost().sign(&scoped).to_bytes().to_vec();
        over.scoped_payload = scoped;
        assert!(over.verify(&ghost().verifying_key()).is_err());
    }

    /// Two entries for one store resolve to the smaller encoding, whichever
    /// arrives first. Mutated red by keeping the incoming one.
    #[test]
    fn a_clash_resolves_to_the_smaller_encoding_either_way() {
        let a = entry(1, 10);
        let b = entry(1, 200);
        let smaller = if entry_bytes(&a) <= entry_bytes(&b) {
            &a
        } else {
            &b
        };
        let ab = with(vec![a.clone(), b.clone()]);
        let ba = with(vec![b.clone(), a.clone()]);
        assert_eq!(ab, ba);
        assert_eq!(ab.entries.values().next(), Some(smaller));
    }

    /// Past the bound the smallest store keys are kept, the merge still
    /// succeeds, and the result verifies. Mutated red by keeping the
    /// largest, and by skipping the bound.
    #[test]
    fn past_the_bound_the_smallest_store_keys_are_kept() {
        let all: Vec<IndexEntry> = (0..MAX_INDEX_ENTRIES as u32 + 5)
            .map(|i| entry(i, 10))
            .collect();
        let state = with(all.clone());
        assert_eq!(state.entries.len(), MAX_INDEX_ENTRIES);
        let mut slots: Vec<Bytes32> = all.iter().map(IndexEntry::slot).collect();
        slots.sort();
        let kept: Vec<Bytes32> = state.entries.keys().copied().collect();
        assert_eq!(kept, slots[..MAX_INDEX_ENTRIES].to_vec());
        // Over the bound, a whole state is refused.
        let mut over = state.clone();
        let extra = all
            .iter()
            .find(|e| !state.entries.contains_key(&e.slot()))
            .unwrap()
            .clone();
        over.entries.insert(extra.slot(), extra);
        assert!(over.verify(&params()).is_err());
    }

    /// A delta may not carry more than the index can hold, and the cap is
    /// applied BEFORE any signature is checked, so an oversized delta costs
    /// nothing to refuse (#101 review). A whole STATE past the bound is
    /// refused the same way, since a valid one never holds more. Mutated red
    /// by removing the cap.
    #[test]
    fn an_oversized_delta_is_refused_before_it_is_verified() {
        let mut state = GhostKeyIndexV1::default();
        // The same slot over and over: a `Vec` does not collapse duplicates.
        let repeated: Vec<IndexEntry> = (0..MAX_INDEX_ENTRIES + 1).map(|_| entry(1, 10)).collect();
        let err = state
            .apply_delta(&params(), &repeated)
            .expect_err("a delta may not be unbounded");
        assert!(err.contains("the most it may carry"), "{err}");
        assert!(state.entries.is_empty(), "and nothing is folded in");

        let many: Vec<IndexEntry> = (0..MAX_INDEX_ENTRIES as u32 + 1)
            .map(|i| entry(i, 10))
            .collect();
        assert!(state.apply_delta(&params(), &many).is_err());

        let mut oversized = GhostKeyIndexV1::default();
        for e in many {
            oversized.entries.insert(e.slot(), e);
        }
        assert!(state.merge(&params(), &oversized).is_err());
    }

    /// Seeded merge laws, past the bound, plus delta order: stale-summary
    /// deltas applied in either order give the same index.
    #[test]
    fn seeded_indexes_obey_the_merge_laws_and_delta_order() {
        use crate::merge_laws::{assert_laws, Rng};
        let pool: Vec<IndexEntry> = (0..MAX_INDEX_ENTRIES as u32 + 8)
            .flat_map(|i| [entry(i, 10), entry(i, 300)])
            .collect();
        let mut rng = Rng::new(0x1d_e7);
        let mut states = vec![GhostKeyIndexV1::default()];
        for _ in 0..24 {
            let picked: Vec<IndexEntry> =
                pool.iter().filter(|_| rng.below(3) != 0).cloned().collect();
            states.push(with(picked));
        }
        assert!(states.iter().any(|s| s.entries.len() == MAX_INDEX_ENTRIES));
        let merge = |a: &GhostKeyIndexV1, b: &GhostKeyIndexV1| {
            let mut m = a.clone();
            m.merge(&params(), b).expect("never fails");
            m.verify(&params()).expect("valid");
            m
        };
        assert_laws(&states, 200, &mut rng, merge, |s| {
            crate::to_cbor(s).unwrap()
        });

        let stale = GhostKeyIndexV1::default().summarize();
        let deltas: Vec<IndexDeltaV1> = states.iter().filter_map(|s| s.delta(&stale)).collect();
        for _ in 0..200 {
            let base = &states[rng.below(states.len())];
            let x = &deltas[rng.below(deltas.len())];
            let y = &deltas[rng.below(deltas.len())];
            let apply2 = |a: &IndexDeltaV1, b: &IndexDeltaV1| {
                let mut r = base.clone();
                r.apply_delta(&params(), a).unwrap();
                r.apply_delta(&params(), b).unwrap();
                crate::to_cbor(&r).unwrap()
            };
            assert_eq!(apply2(x, y), apply2(y, x));
        }
    }

    /// The delta carries exactly what the summary lacks, and applying it
    /// reaches the sender's state.
    #[test]
    fn a_delta_brings_the_receiver_up_to_the_sender() {
        let sender = with(vec![entry(1, 10), entry(2, 10), entry(3, 10)]);
        let receiver = with(vec![entry(1, 10)]);
        let d = sender.delta(&receiver.summarize()).expect("two missing");
        assert_eq!(d.len(), 2);
        let mut r = receiver.clone();
        r.apply_delta(&params(), &d).unwrap();
        assert_eq!(r, sender);
        assert!(sender.delta(&sender.summarize()).is_none());
    }
}
