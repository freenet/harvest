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
//!   sorted, each with a sequence number for when it was last sent. A
//!   script a scan has matched stays: below that key's counter it never
//!   matches again, but a key entered afresh starts at 0 and needs it, and
//!   removing it on a match would leave that key relying on whatever the tab
//!   entering it happens to know (found in review: a pending key replaced by
//!   a newer one, then entered again, was handed its own published index
//!   0). This device's own orders are held too, like any other: an earlier
//!   filter that dropped them as "issued by the active key" dropped them for
//!   good when that key came back later (review of 36bb41b), and the cap
//!   below is the most distinct scripts a seller can have published at
//!   once, so they matter only over churn, which eviction handles.
//! - [`CURSOR_ACTIVE_KEY`], [`CURSOR_PENDING_KEY`]: how far each key's scan
//!   has got (`bitcoin::advance_scan`).
//!
//! # Eviction, the one residual
//!
//! Past [`MAX_HELD`] held scripts, those sent longest ago go first: a script
//! sent again (every tab sends every script it knows on load) is fresh
//! again. What can go is therefore a script no tab has sent for longer than
//! [`MAX_HELD`] others have been sent since: in practice an order pruned
//! from its store (a store keeps [`harvest_common::store::MAX_ORDERS`]),
//! which no tab can send any more either. A migration's imported scripts
//! count as older than every script this delegate holds, so they go before
//! any of its own.
//!
//! # A list that does not read
//!
//! A held list that is there but does not decode is never taken for an
//! empty one ([`DigestList::load`] answers [`Unreadable`]): empty would make
//! every scan complete at once and hand out addresses, and an addition
//! would write over what it could not read. Every caller refuses instead.
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

/// The published scripts held ([`DigestList`]).
pub(crate) const PUBLISHED_KEY: &[u8] = b"harvest:bitcoin:published:v1";

/// `[generation u32][count u32]` of [`PUBLISHED_KEY`], written with it, so
/// a store's status can tell whether a scan is complete without reading the
/// list itself. Advisory: every scan reads the list.
pub(crate) const PUBLISHED_META_KEY: &[u8] = b"harvest:bitcoin:published-meta:v1";

/// The held list is there and does not decode: see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unreadable;

/// Save the published list and its [`PUBLISHED_META_KEY`]. Whether both
/// were kept.
///
/// The count goes first, and a refused count stops the list being written:
/// a count left naming an older generation over a newer list could tell the
/// status a scan is complete when it is not. A count written over a list
/// that is then refused names a generation the list does not have, which
/// only ever reads as "changed since" (a scan not known complete, `decide`
/// feeding its store again).
pub(crate) fn save_published<S: SecretStore>(store: &mut S, list: &DigestList) -> bool {
    let mut meta = list.generation().to_le_bytes().to_vec();
    meta.extend_from_slice(&(list.len() as u32).to_le_bytes());
    store.set_secret(PUBLISHED_META_KEY, &meta) && list.save(store, PUBLISHED_KEY)
}

/// The published list's generation and length, from its
/// [`PUBLISHED_META_KEY`] when that is there, else from the list. `None`
/// when neither reads: treat it as changed.
pub(crate) fn published_meta<S: SecretStore>(store: &S) -> Option<(u32, usize)> {
    if let Some(meta) = store
        .get_secret(PUBLISHED_META_KEY)
        .filter(|m| m.len() == 8)
    {
        let generation = u32::from_le_bytes(meta[..4].try_into().expect("4 bytes"));
        let count = u32::from_le_bytes(meta[4..].try_into().expect("4 bytes"));
        return Some((generation, count as usize));
    }
    let list = DigestList::load(store, PUBLISHED_KEY).ok()?;
    Some((list.generation(), list.len()))
}

/// How far the active key's scan has got ([`Cursor`]). Never exported:
/// losing it restarts the scan from the counter.
pub(crate) const CURSOR_ACTIVE_KEY: &[u8] = b"harvest:bitcoin:cursor-active:v1";

/// How far the pending key's scan has got ([`Cursor`]). As above.
pub(crate) const CURSOR_PENDING_KEY: &[u8] = b"harvest:bitcoin:cursor-pending:v1";

/// The most entries the list holds: what one seller can have published
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

/// A sorted list of digests, each with the sequence number it was last sent
/// under, as it is stored:
///
/// `[version u8][generation u32][next_seq u32][tag_len u16][tag][records]`,
/// each record `[digest 16][seq u32]`, sorted by digest. Integers are little
/// endian; the tag is empty. The generation rises whenever an entry is
/// added, which is what sends every scan back to its counter ([`Cursor`]).
pub(crate) struct DigestList {
    bytes: Vec<u8>,
    records_at: usize,
}

impl DigestList {
    /// An empty list, at generation 0.
    pub(crate) fn empty() -> Self {
        let mut bytes = vec![VERSION];
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let records_at = bytes.len();
        Self { bytes, records_at }
    }

    /// Read a stored list. `None` when it is not one.
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

    /// Load the list under `key`: an empty one when none is held, and
    /// [`Unreadable`] when one is held that does not decode (never empty).
    pub(crate) fn load<S: SecretStore>(store: &S, key: &[u8]) -> Result<Self, Unreadable> {
        match store.get_secret(key) {
            None => Ok(Self::empty()),
            Some(bytes) => Self::decode(bytes).ok_or(Unreadable),
        }
    }

    pub(crate) fn save<S: SecretStore>(&self, store: &mut S, key: &[u8]) -> bool {
        store.set_secret(key, &self.bytes)
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

    /// Where `d` is held: a binary search over the records in place.
    fn position(&self, d: &[u8]) -> Option<usize> {
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.digest_at(mid).cmp(d) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    /// Every digest held, the one sent longest ago first: the order
    /// eviction takes them in.
    #[cfg(test)]
    pub(crate) fn by_age(&self) -> Vec<Digest> {
        let base = self.next_seq();
        let mut held: Vec<(u32, Digest)> = (0..self.len())
            .map(|i| {
                (
                    base.wrapping_sub(self.seq_at(i)),
                    self.digest_at(i).try_into().expect("16 bytes"),
                )
            })
            .collect();
        held.sort_by(|a, b| b.0.cmp(&a.0));
        held.into_iter().map(|(_, d)| d).collect()
    }

    /// Whether `d` is held.
    pub(crate) fn contains(&self, d: &Digest) -> bool {
        self.position(d).is_some()
    }

    /// Hold every digest of `new`, as sent now: one not held is added, one
    /// held already is marked sent now (so eviction, which takes the scripts
    /// sent longest ago, does not take a script tabs keep sending). The
    /// generation rises if any was added. Past [`MAX_HELD`], those sent
    /// longest ago go. Returns how many were added. One merge pass, however
    /// many arrive.
    pub(crate) fn insert(&mut self, new: &[Digest]) -> usize {
        self.insert_capped(new, MAX_HELD)
    }

    pub(crate) fn insert_capped(&mut self, new: &[Digest], cap: usize) -> usize {
        let mut seq = self.next_seq();
        let mut stamped: Vec<(Digest, u32)> = Vec::with_capacity(new.len());
        let mut seen = std::collections::BTreeSet::new();
        for d in new {
            if seen.insert(*d) {
                stamped.push((*d, seq));
                seq = seq.wrapping_add(1);
            }
        }
        if stamped.is_empty() {
            return 0;
        }
        let added = stamped.iter().filter(|(d, _)| !self.contains(d)).count();
        self.merge(stamped, added, cap, seq);
        added
    }

    /// Hold every digest of `new` not held already, as sent before anything
    /// held here (a migration's import): eviction takes them before any of
    /// this delegate's own. Returns how many were added.
    pub(crate) fn insert_as_oldest(&mut self, new: &[Digest]) -> usize {
        let base = self.next_seq();
        let oldest = (0..self.len())
            .map(|i| base.wrapping_sub(self.seq_at(i)))
            .max()
            .unwrap_or(0);
        let mut fresh: Vec<Digest> = new.iter().filter(|d| !self.contains(d)).copied().collect();
        fresh.sort_unstable();
        fresh.dedup();
        let added = fresh.len();
        if added == 0 {
            return 0;
        }
        let stamped: Vec<(Digest, u32)> = fresh
            .into_iter()
            .enumerate()
            .map(|(k, d)| (d, base.wrapping_sub(oldest).wrapping_sub(1 + k as u32)))
            .collect();
        self.merge(stamped, added, MAX_HELD, base);
        added
    }

    /// Merge `stamped` in (a digest held already takes the new sequence
    /// number), raise the generation if `added`, set the next sequence
    /// number, and evict past `cap`.
    fn merge(&mut self, mut stamped: Vec<(Digest, u32)>, added: usize, cap: usize, next: u32) {
        stamped.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut out = Vec::with_capacity(self.bytes.len() + added * RECORD);
        out.extend_from_slice(&self.bytes[..self.records_at]);
        let mut incoming = stamped.into_iter().peekable();
        for i in 0..self.len() {
            let held = self.digest_at(i);
            while let Some((d, s)) = incoming.next_if(|(d, _)| d.as_slice() < held) {
                out.extend_from_slice(&d);
                out.extend_from_slice(&s.to_le_bytes());
            }
            match incoming.next_if(|(d, _)| d.as_slice() == held) {
                Some((d, s)) => {
                    out.extend_from_slice(&d);
                    out.extend_from_slice(&s.to_le_bytes());
                }
                None => {
                    let at = self.records_at + i * RECORD;
                    out.extend_from_slice(&self.bytes[at..at + RECORD]);
                }
            }
        }
        for (d, s) in incoming {
            out.extend_from_slice(&d);
            out.extend_from_slice(&s.to_le_bytes());
        }
        let generation = if added > 0 {
            self.generation().wrapping_add(1)
        } else {
            self.generation()
        };
        self.bytes = out;
        self.set_header(generation, next);
        let over = self.len().saturating_sub(cap);
        if over > 0 {
            self.evict_oldest(over);
        }
    }

    /// Drop the `count` entries sent longest ago: the largest ages, counted
    /// back from the next sequence number so a wrapped counter still orders
    /// them. Sequence numbers are unique among those held, so exactly
    /// `count` go.
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
        let mut list = DigestList::empty();
        assert_eq!(list.insert(&[d(3), d(1), d(2), d(1)]), 3);
        assert_eq!(list.generation(), 1);
        assert_eq!(list.insert(&[d(2)]), 0);
        assert_eq!(list.generation(), 1, "nothing new, no new generation");
        for n in 1..=3 {
            assert!(list.contains(&d(n)));
        }
        assert!(!list.contains(&d(4)));
        let back = DigestList::decode(list.bytes.clone()).expect("decodes");
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
        let mut list = DigestList::empty();
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
        let mut list = DigestList::empty();
        list.insert_capped(&[d(100), d(101)], 3);
        list.insert_capped(&[d(1), d(2)], 3);
        assert!(!list.contains(&d(100)));
        assert!(list.contains(&d(101)) && list.contains(&d(1)) && list.contains(&d(2)));
    }

    /// #206 review: a script sent again is fresh again, so eviction takes
    /// the scripts sent longest ago, not those that arrived first; and a
    /// migration's imports go before any of this delegate's own. A re-send
    /// adds nothing, so the generation stays. Mutated red by not refreshing
    /// a re-sent script, and by importing as the newest.
    #[test]
    fn eviction_takes_what_was_sent_longest_ago() {
        let mut list = DigestList::empty();
        list.insert_capped(&[d(1), d(2), d(3)], 3);
        let generation = list.generation();
        assert_eq!(list.insert_capped(&[d(1)], 3), 0, "re-sent");
        assert_eq!(list.generation(), generation);
        list.insert_capped(&[d(4)], 3);
        assert!(list.contains(&d(1)), "sent again, so not the oldest");
        assert!(!list.contains(&d(2)));

        let mut list = DigestList::empty();
        list.insert_capped(&[d(10), d(11)], MAX_HELD);
        assert_eq!(list.insert_as_oldest(&[d(20), d(10)]), 1);
        list.insert_capped(&[d(12)], 3);
        assert!(!list.contains(&d(20)), "the import went first");
        assert!(list.contains(&d(10)) && list.contains(&d(11)) && list.contains(&d(12)));
    }

    /// #206 review: a held list that does not decode is unreadable, never
    /// empty. Mutated red by loading it as empty.
    #[test]
    fn a_list_that_does_not_read_is_not_empty() {
        let mut store = crate::secrets::MemSecrets::default();
        assert_eq!(
            DigestList::load(&store, PUBLISHED_KEY).map(|l| l.len()),
            Ok(0)
        );
        store.set_secret(PUBLISHED_KEY, b"\x07garbage");
        assert_eq!(
            DigestList::load(&store, PUBLISHED_KEY).err(),
            Some(Unreadable)
        );
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
