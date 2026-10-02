//! The published payment scripts the delegate holds, and how far each key's
//! scan of them has got (harvest#77, #206).
//!
//! # Why the delegate holds them
//!
//! A device's address counter starts at 0 on a new device, while the same
//! wallet key's low addresses already sit on published, possibly paid,
//! orders. So no address is handed out until the counter has been raised
//! past every published script of that key. Until #206 every request
//! carried the scripts, and each tab left out those it believed accounted
//! for. A tab whose belief was stale (another key entered elsewhere, a scan
//! left part-way) then left out exactly the script that mattered, and the
//! address of a published order went out again. Three review rounds found
//! three variants of that. So the delegate now keeps every script it has
//! been sent, the UI only ever adds to them, and nothing a request leaves
//! out can matter.
//!
//! # What is held
//!
//! - [`PUBLISHED_KEY`]: every published script sent, as 16-byte digests,
//!   sorted, each with the order it arrived in. A script a scan has matched
//!   stays: below that key's counter it never matches again, but a key
//!   entered afresh starts at 0 and needs it, and removing it on a match
//!   would leave that key relying on whatever the tab entering it happens
//!   to know (found in review: a pending key replaced by a newer one, then
//!   entered again, was handed its own published index 0). Past [`MAX_HELD`]
//!   the oldest go: the one residual, documented with the scan.
//! - [`ISSUED_KEY`]: the digests of the addresses the active key has handed
//!   out. An addition naming one of these is dropped: it is below the
//!   counter by construction. That keeps this device's own orders, which
//!   every tab sends once they are published, out of the set above.
//! - [`CURSOR_ACTIVE_KEY`], [`CURSOR_PENDING_KEY`]: how far each key's scan
//!   has got (`bitcoin::advance_scan`).
//!
//! # Raw bytes, not CBOR
//!
//! The set can hold [`MAX_HELD`] entries, about 5 MiB. Decoding that as CBOR
//! and hashing it into a set is what the #206 harness measured at most of a
//! call. Here it is read as it is stored: a header, then fixed-size records
//! sorted by digest, searched in place.
//!
//! # Digests
//!
//! BLAKE3 of the script under a domain string, cut to 16 bytes. Two
//! published scripts with one digest would hold one entry for both, and the
//! scan would look for only one of them; at 128 bits over at most a quarter
//! of a million scripts that is not a case to plan for. A derived script
//! whose digest matches a held one it is not raises the counter past an
//! index that was free: the safe direction.

use freenet_migrate::SecretStore;

/// The published scripts held ([`DigestList`], untagged).
pub(crate) const PUBLISHED_KEY: &[u8] = b"harvest:bitcoin:published:v1";

/// The digests the active key has handed out ([`DigestList`], tagged with
/// that key). Node-local and never exported: losing it only lets this
/// device's own orders into [`PUBLISHED_KEY`], where they never match.
pub(crate) const ISSUED_KEY: &[u8] = b"harvest:bitcoin:issued:v1";

/// `[generation u32][count u32]` of [`PUBLISHED_KEY`], written with it, so
/// a store's status can tell whether a scan is complete without reading the
/// list itself. Advisory: every scan reads the list.
pub(crate) const PUBLISHED_META_KEY: &[u8] = b"harvest:bitcoin:published-meta:v1";

/// Save the published list and its [`PUBLISHED_META_KEY`]. Whether the list
/// was kept.
///
/// The count goes first: if the list is then refused, the count names a
/// generation the list does not have, which only ever reads as "changed
/// since" (a scan not known complete, `decide` feeding its store again),
/// never as "unchanged" over a list that did change.
pub(crate) fn save_published<S: SecretStore>(store: &mut S, list: &DigestList) -> bool {
    let mut meta = list.generation().to_le_bytes().to_vec();
    meta.extend_from_slice(&(list.len() as u32).to_le_bytes());
    store.set_secret(PUBLISHED_META_KEY, &meta);
    list.save(store, PUBLISHED_KEY)
}

/// The published list's generation and length, from its
/// [`PUBLISHED_META_KEY`] when that is there, else from the list.
pub(crate) fn published_meta<S: SecretStore>(store: &S) -> (u32, usize) {
    if let Some(meta) = store
        .get_secret(PUBLISHED_META_KEY)
        .filter(|m| m.len() == 8)
    {
        let generation = u32::from_le_bytes(meta[..4].try_into().expect("4 bytes"));
        let count = u32::from_le_bytes(meta[4..].try_into().expect("4 bytes"));
        return (generation, count as usize);
    }
    let list = DigestList::load(store, PUBLISHED_KEY, b"");
    (list.generation(), list.len())
}

/// How far the active key's scan has got ([`Cursor`]). Never exported:
/// losing it restarts the scan from the counter.
pub(crate) const CURSOR_ACTIVE_KEY: &[u8] = b"harvest:bitcoin:cursor-active:v1";

/// How far the pending key's scan has got ([`Cursor`]). As above.
pub(crate) const CURSOR_PENDING_KEY: &[u8] = b"harvest:bitcoin:cursor-pending:v1";

/// The most entries either list holds: what one seller can have published
/// at once, [`crate::store_keys::MAX_STORE_KEYS`] stores of
/// [`harvest_common::store::MAX_ORDERS`] orders.
pub(crate) const MAX_HELD: usize =
    crate::store_keys::MAX_STORE_KEYS * harvest_common::store::MAX_ORDERS;

pub(crate) type Digest = [u8; 16];

const RECORD: usize = 20;
const VERSION: u8 = 1;

/// The digest a script is held under.
pub(crate) fn digest(script: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"harvest published script v1\0");
    hasher.update(script);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    out
}

/// A sorted list of digests, each with the sequence number it arrived
/// under, as it is stored:
///
/// `[version u8][generation u32][next_seq u32][tag_len u16][tag][records]`,
/// each record `[digest 16][seq u32]`, sorted by digest. Integers are little
/// endian. The generation rises whenever an entry is added, which is what
/// sends every scan back to its counter ([`Cursor`]).
pub(crate) struct DigestList {
    bytes: Vec<u8>,
    records_at: usize,
}

impl DigestList {
    /// An empty list under `tag`, at generation 0.
    pub(crate) fn empty(tag: &[u8]) -> Self {
        let mut bytes = vec![VERSION];
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(tag.len() as u16).to_le_bytes());
        bytes.extend_from_slice(tag);
        let records_at = bytes.len();
        Self { bytes, records_at }
    }

    /// Read a stored list. `None` when it is not one (a cleared slot is
    /// empty bytes).
    pub(crate) fn decode(bytes: Vec<u8>) -> Option<Self> {
        if bytes.first() != Some(&VERSION) || bytes.len() < 11 {
            return None;
        }
        let tag_len = u16::from_le_bytes([bytes[9], bytes[10]]) as usize;
        let records_at = 11usize.checked_add(tag_len)?;
        if bytes.len() < records_at || !(bytes.len() - records_at).is_multiple_of(RECORD) {
            return None;
        }
        Some(Self { bytes, records_at })
    }

    /// Load the list under `key`, or an empty one under `tag` when there is
    /// none, it does not decode, or it was kept under another tag.
    pub(crate) fn load<S: SecretStore>(store: &S, key: &[u8], tag: &[u8]) -> Self {
        store
            .get_secret(key)
            .and_then(Self::decode)
            .filter(|list| list.tag() == tag)
            .unwrap_or_else(|| Self::empty(tag))
    }

    pub(crate) fn save<S: SecretStore>(&self, store: &mut S, key: &[u8]) -> bool {
        store.set_secret(key, &self.bytes)
    }

    pub(crate) fn tag(&self) -> &[u8] {
        &self.bytes[11..self.records_at]
    }

    pub(crate) fn generation(&self) -> u32 {
        u32::from_le_bytes(self.bytes[1..5].try_into().expect("4 bytes"))
    }

    fn next_seq(&self) -> u32 {
        u32::from_le_bytes(self.bytes[5..9].try_into().expect("4 bytes"))
    }

    fn set_header(&mut self, generation: u32, next_seq: u32) {
        self.bytes[1..5].copy_from_slice(&generation.to_le_bytes());
        self.bytes[5..9].copy_from_slice(&next_seq.to_le_bytes());
    }

    pub(crate) fn len(&self) -> usize {
        (self.bytes.len() - self.records_at) / RECORD
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn digest_at(&self, i: usize) -> &[u8] {
        let at = self.records_at + i * RECORD;
        &self.bytes[at..at + 16]
    }

    fn seq_at(&self, i: usize) -> u32 {
        let at = self.records_at + i * RECORD + 16;
        u32::from_le_bytes(self.bytes[at..at + 4].try_into().expect("4 bytes"))
    }

    /// Every digest held, in digest order.
    pub(crate) fn digests(&self) -> Vec<Digest> {
        (0..self.len())
            .map(|i| self.digest_at(i).try_into().expect("16 bytes"))
            .collect()
    }

    /// Whether `d` is held: a binary search over the records in place.
    pub(crate) fn contains(&self, d: &Digest) -> bool {
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.digest_at(mid).cmp(d.as_slice()) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    /// Add every digest of `new` not already held, under fresh sequence
    /// numbers in the order given, and raise the generation if any was.
    /// Past [`MAX_HELD`], the entries that arrived first go. Returns how many
    /// were added. One merge pass, however many arrive.
    pub(crate) fn insert(&mut self, new: &[Digest]) -> usize {
        self.insert_capped(new, MAX_HELD)
    }

    pub(crate) fn insert_capped(&mut self, new: &[Digest], cap: usize) -> usize {
        let mut fresh: Vec<(Digest, u32)> = Vec::new();
        let mut seq = self.next_seq();
        let mut seen = std::collections::BTreeSet::new();
        for d in new {
            if !self.contains(d) && seen.insert(*d) {
                fresh.push((*d, seq));
                seq = seq.wrapping_add(1);
            }
        }
        if fresh.is_empty() {
            return 0;
        }
        fresh.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let added = fresh.len();
        let mut out = Vec::with_capacity(self.bytes.len() + added * RECORD);
        out.extend_from_slice(&self.bytes[..self.records_at]);
        let mut fresh = fresh.into_iter().peekable();
        for i in 0..self.len() {
            let held = self.digest_at(i);
            while let Some((d, s)) = fresh.next_if(|(d, _)| d.as_slice() < held) {
                out.extend_from_slice(&d);
                out.extend_from_slice(&s.to_le_bytes());
            }
            let at = self.records_at + i * RECORD;
            out.extend_from_slice(&self.bytes[at..at + RECORD]);
        }
        for (d, s) in fresh {
            out.extend_from_slice(&d);
            out.extend_from_slice(&s.to_le_bytes());
        }
        let generation = self.generation().wrapping_add(1);
        self.bytes = out;
        self.set_header(generation, seq);
        let over = self.len().saturating_sub(cap);
        if over > 0 {
            self.evict_oldest(over);
        }
        added
    }

    /// Drop the `count` entries that arrived first: the largest ages,
    /// counted back from the next sequence number so a wrapped counter still
    /// orders them. Sequence numbers are unique (one per entry ever added),
    /// so exactly `count` go.
    fn evict_oldest(&mut self, count: usize) {
        let base = self.next_seq();
        let age = |list: &Self, i: usize| base.wrapping_sub(list.seq_at(i));
        let mut ages: Vec<u32> = (0..self.len()).map(|i| age(self, i)).collect();
        let cut = ages.len() - count;
        let threshold = *ages.select_nth_unstable(cut).1;
        let mut out = Vec::with_capacity(self.bytes.len());
        out.extend_from_slice(&self.bytes[..self.records_at]);
        for i in 0..self.len() {
            if age(self, i) >= threshold {
                continue;
            }
            let at = self.records_at + i * RECORD;
            out.extend_from_slice(&self.bytes[at..at + RECORD]);
        }
        self.bytes = out;
    }
}

/// How far one key's scan has got: every index in `[base, at)` has been
/// derived and found not to be a held script, as of the published list's
/// `generation`, where `base` was the counter when it was saved (one past
/// the last match). Kept with the key it is
/// for (`tag`, the key as stored), so a cursor is never read for another
/// key, and read only while the counter is at or above `base` (a counter
/// set lower would put unscanned indices below the cursor).
///
/// Stored as `[tag_len u16][tag][generation u32][base u32][at u32]`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Cursor {
    pub tag: Vec<u8>,
    pub generation: u32,
    pub base: u32,
    pub at: u32,
}

impl Cursor {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = (self.tag.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.base.to_le_bytes());
        out.extend_from_slice(&self.at.to_le_bytes());
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let tag_len = u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?) as usize;
        let tag = bytes.get(2..2 + tag_len)?.to_vec();
        let rest = bytes.get(2 + tag_len..)?;
        if rest.len() != 12 {
            return None;
        }
        Some(Self {
            tag,
            generation: u32::from_le_bytes(rest[..4].try_into().ok()?),
            base: u32::from_le_bytes(rest[4..8].try_into().ok()?),
            at: u32::from_le_bytes(rest[8..].try_into().ok()?),
        })
    }

    pub(crate) fn load<S: SecretStore>(store: &S, key: &[u8]) -> Option<Self> {
        store.get_secret(key).and_then(|b| Self::decode(&b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u32) -> Digest {
        digest(&n.to_le_bytes())
    }

    /// The list holds what it was given, finds it by search in place, and
    /// comes back the same from its bytes; an addition raises the
    /// generation and a repeat does not.
    #[test]
    fn the_list_holds_finds_and_round_trips() {
        let mut list = DigestList::empty(b"tag");
        assert_eq!(list.insert(&[d(3), d(1), d(2), d(1)]), 3);
        assert_eq!(list.generation(), 1);
        assert_eq!(list.insert(&[d(2)]), 0);
        assert_eq!(list.generation(), 1, "nothing new, no new generation");
        for n in 1..=3 {
            assert!(list.contains(&d(n)));
        }
        assert!(!list.contains(&d(4)));
        let back = DigestList::decode(list.bytes.clone()).expect("decodes");
        assert_eq!(back.tag(), b"tag");
        assert_eq!(back.len(), 3);
        assert!(back.contains(&d(2)));
        // Sorted after every operation.
        list.insert(&(10..60).map(d).collect::<Vec<_>>());
        for i in 1..list.len() {
            assert!(list.digest_at(i - 1) < list.digest_at(i));
        }
    }

    /// Eviction happens only past the cap, and takes the entries that
    /// arrived first, exactly as many as needed. Mutated red by evicting the
    /// newest, and by evicting below the cap.
    #[test]
    fn eviction_is_oldest_first_and_only_past_the_cap() {
        let mut list = DigestList::empty(b"");
        list.insert_capped(&(0..10).map(d).collect::<Vec<_>>(), 10);
        assert_eq!(list.len(), 10, "at the cap, nothing goes");
        list.insert_capped(&(10..13).map(d).collect::<Vec<_>>(), 10);
        assert_eq!(list.len(), 10);
        for n in 0..3 {
            assert!(!list.contains(&d(n)), "the oldest went: {n}");
        }
        for n in 3..13 {
            assert!(list.contains(&d(n)), "kept: {n}");
        }
        // In two batches arriving in one order, the earlier batch goes first.
        let mut list = DigestList::empty(b"");
        list.insert_capped(&[d(100), d(101)], 3);
        list.insert_capped(&[d(1), d(2)], 3);
        assert!(!list.contains(&d(100)));
        assert!(list.contains(&d(101)) && list.contains(&d(1)) && list.contains(&d(2)));
    }

    #[test]
    fn a_cursor_round_trips() {
        let c = Cursor {
            tag: b"vpub".to_vec(),
            generation: 7,
            base: 300,
            at: 400,
        };
        assert_eq!(Cursor::decode(&c.encode()), Some(c));
        assert_eq!(Cursor::decode(b""), None);
    }
}
