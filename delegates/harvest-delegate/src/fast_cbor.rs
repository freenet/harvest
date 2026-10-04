//! The two encodings this delegate moves in bulk, done by hand (#206).
//!
//! `Vec<u8>` goes through serde as a sequence, so ciborium writes and reads
//! every byte as its own CBOR integer, through the generic serde machinery.
//! Measured under the node's fuel metering that costs several hundred WASM
//! instructions a byte: decoding a full mailbox (about 3.3 MiB of ciphertext)
//! took two thirds of a call's budget before a single message was opened, and
//! exporting sixteen full instant-checkout ledgers took twice the budget.
//!
//! The bytes on the wire stay EXACTLY what ciborium writes and reads -- the
//! mailbox contract and every older delegate generation depend on them -- so
//! this module is a faster route to the same bytes, not a new format:
//!
//! * [`encode_exported`] writes `freenet_migrate::ExportedSecrets` byte for
//!   byte as ciborium does (tested against ciborium on edge-case lengths).
//! * [`decode_mailbox`] reads `MailboxStateV1` as ciborium writes it, and
//!   returns `None` on anything else, so the caller falls back to the generic
//!   decoder: it can be slow, never wrong.

use harvest_common::mailbox::{ConversationId, EncryptedMessage, MailboxStateV1};

// --- encoding --------------------------------------------------------------

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u8::MAX as u64 {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// `Vec<u8>` as ciborium writes it: an array of unsigned integers.
fn byte_seq(out: &mut Vec<u8>, bytes: &[u8]) {
    head(out, 4, bytes.len() as u64);
    for &b in bytes {
        if b < 24 {
            out.push(b);
        } else {
            out.extend_from_slice(&[0x18, b]);
        }
    }
}

fn text(out: &mut Vec<u8>, s: &str) {
    head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// `freenet_migrate::ExportedSecrets { source_generation, secrets }`,
/// encoded exactly as `ExportedSecrets::to_bytes` encodes it.
pub(crate) fn encode_exported(source_generation: u32, secrets: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let total: usize = secrets.iter().map(|(k, v)| k.len() + v.len()).sum();
    let mut out = Vec::with_capacity(64 + 2 * total + 8 * secrets.len());
    head(&mut out, 5, 2);
    text(&mut out, "source_generation");
    head(&mut out, 0, u64::from(source_generation));
    text(&mut out, "secrets");
    head(&mut out, 4, secrets.len() as u64);
    for (key, value) in secrets {
        head(&mut out, 4, 2);
        byte_seq(&mut out, key);
        byte_seq(&mut out, value);
    }
    out
}

// --- decoding --------------------------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    /// A definite-length head of `major`, and its argument.
    fn head(&mut self, major: u8) -> Option<u64> {
        let b = self.byte()?;
        if b >> 5 != major {
            return None;
        }
        match b & 0x1f {
            n @ 0..=23 => Some(u64::from(n)),
            24 => self.byte().map(u64::from),
            25 => Some(u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().ok()?,
            ))),
            26 => Some(u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().ok()?,
            ))),
            27 => Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?)),
            _ => None,
        }
    }

    fn text(&mut self) -> Option<&'a str> {
        let n = usize::try_from(self.head(3)?).ok()?;
        std::str::from_utf8(self.take(n)?).ok()
    }

    /// An array of integers each 0..=255, as ciborium writes a `Vec<u8>`
    /// (or a fixed `[u8; N]`).
    fn byte_seq(&mut self) -> Option<Vec<u8>> {
        let n = usize::try_from(self.head(4)?).ok()?;
        // Never trust a length for an allocation: each element takes at
        // least one byte of input.
        if n > self.bytes.len() - self.at {
            return None;
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            match self.byte()? {
                b @ 0..=23 => out.push(b),
                0x18 => {
                    let b = self.byte()?;
                    // ciborium never writes a value under 24 in two bytes;
                    // anything else is not its encoding.
                    if b < 24 {
                        return None;
                    }
                    out.push(b);
                }
                _ => return None,
            }
        }
        Some(out)
    }
}

impl Reader<'_> {
    /// Past one whole item, of any kind, without reading it: a head and what
    /// it counts. Indefinite lengths, and nesting past 64, are declined.
    fn skip(&mut self, depth: u32) -> Option<()> {
        if depth > 64 {
            return None;
        }
        let b = *self.bytes.get(self.at)?;
        let major = b >> 5;
        if major == 7 {
            // A simple value or a float: its size is in its head.
            self.at += match b & 0x1f {
                0..=23 => 1,
                24 => 2,
                25 => 3,
                26 => 5,
                27 => 9,
                _ => return None,
            };
            return (self.at <= self.bytes.len()).then_some(());
        }
        let n = self.head(major)?;
        match major {
            0 | 1 => Some(()),
            2 => self.take(usize::try_from(n).ok()?).map(|_| ()),
            // Text is checked as ciborium checks it, so a value it would
            // refuse is not passed over as if it were fine.
            3 => std::str::from_utf8(self.take(usize::try_from(n).ok()?)?)
                .ok()
                .map(|_| ()),
            // An array of small unsigned integers is how ciborium writes a
            // `Vec<u8>` (an SPV proof, a signature): passed over a byte or
            // two at a time without a call per element, which is what makes
            // skipping a store's payment proofs cheaper than decoding them.
            4 => (0..n).try_for_each(|_| match *self.bytes.get(self.at)? {
                0..=0x17 => {
                    self.at += 1;
                    Some(())
                }
                0x18 => {
                    self.at += 2;
                    (self.at <= self.bytes.len()).then_some(())
                }
                _ => self.skip(depth + 1),
            }),
            5 => (0..n).try_for_each(|_| {
                self.skip(depth + 1)?;
                self.skip(depth + 1)
            }),
            6 => self.skip(depth + 1),
            _ => None,
        }
    }
}

/// The encoded value of each of `wanted`'s fields in a CBOR map with text
/// keys, found without decoding the others (they are skipped by their
/// heads), or `None` when `bytes` is not one such map, wholly. A field
/// absent is absent from the answer; one present twice is declined. The
/// caller decodes each value as the type would.
pub(crate) fn map_fields<'a>(bytes: &'a [u8], wanted: &[&str]) -> Option<Vec<(usize, &'a [u8])>> {
    let mut r = Reader { bytes, at: 0 };
    let n = r.head(5)?;
    let mut found: Vec<(usize, &'a [u8])> = Vec::new();
    for _ in 0..n {
        let key = r.text()?;
        let start = r.at;
        r.skip(0)?;
        if let Some(i) = wanted.iter().position(|w| *w == key) {
            if found.iter().any(|(j, _)| *j == i) {
                return None;
            }
            found.push((i, &bytes[start..r.at]));
        }
    }
    (r.at == bytes.len()).then_some(found)
}

/// A store's state as instant checkout reads it (#206): only the fields it
/// uses (`owner`, `listings`, `orders`, `listing_statuses`, `closed`,
/// `pause`), each order with only its terms and status, each listing and
/// listing status with only the listing or the status. Everything else -- the store's info, backings, custody
/// copies, fulfilment, retirements, each order's signatures and payment
/// proof (about 4.5 KiB an order, mostly the SPV proof), and each listing's
/// signature, signed payload and certificate (step 2: the signed payload
/// repeats the listing as a byte string serde reads a byte at a time, which
/// made a listing cost about 256 instructions a byte; a listing status's
/// likewise, and statuses are kept for every listing ever published, so a
/// store that edits often holds many) -- is passed over by
/// its CBOR heads rather than decoded, and left empty. `None` for anything that is not such a state (the caller then
/// decodes it whole), including one without `info`, which a whole decode
/// requires.
///
/// What it does not do that a whole decode does: check the fields it skips
/// are well formed beyond their CBOR heads. The state comes from the store
/// contract, which validated it whole; nothing here reads them.
pub(crate) fn decode_store_light(bytes: &[u8]) -> Option<harvest_common::StoreStateV1> {
    use harvest_common::from_cbor;
    // One pass: every byte is read once, by the decoder of a field kept or
    // by `skip`. (Finding the fields first and parsing them after read the
    // payment proofs four times over.)
    let mut r = Reader { bytes, at: 0 };
    let n = r.head(5)?;
    let mut store = harvest_common::StoreStateV1::default();
    let mut seen: Vec<&str> = Vec::new();
    for _ in 0..n {
        let key = r.text()?;
        if seen.contains(&key) {
            return None;
        }
        seen.push(key);
        let start = r.at;
        if key == "orders" {
            store.orders = r.orders_light()?;
            continue;
        }
        if key == "listings" {
            store.listings = r.listings_light()?;
            continue;
        }
        if key == "listing_statuses" {
            // Only the statuses of listings held: nothing else is read, and
            // statuses are kept for every listing version ever published.
            // The listings come first as a store writes its fields; if they
            // have not, every status is kept.
            let held: Option<std::collections::BTreeSet<harvest_common::listing::ListingId>> =
                seen.contains(&"listings").then(|| {
                    store
                        .listings
                        .listings
                        .iter()
                        .map(|l| l.listing.id.clone())
                        .collect()
                });
            store.listing_statuses = r.statuses_light(held.as_ref())?;
            continue;
        }
        r.skip(0)?;
        let value = &bytes[start..r.at];
        match key {
            "owner" => store.owner = from_cbor(value).ok()?,
            "closed" => store.closed = from_cbor(value).ok()?,
            "pause" => store.pause = from_cbor(value).ok()?,
            _ => {}
        }
    }
    // A whole decode requires these.
    if r.at != bytes.len() || !seen.contains(&"info") || !seen.contains(&"listings") {
        return None;
    }
    Some(store)
}

impl Reader<'_> {
    /// `OrdersV1`, each order with only `order` and `status` decoded and the
    /// rest passed over.
    fn orders_light(&mut self) -> Option<harvest_common::store::OrdersV1> {
        use harvest_common::from_cbor;
        use harvest_common::payment::{AuthorizedOrder, OrderId, OrderStatus};
        let mut orders = harvest_common::store::OrdersV1::default();
        let fields = self.head(5)?;
        let mut seen_orders = false;
        for _ in 0..fields {
            let key = self.text()?;
            if key != "orders" || seen_orders {
                if key == "orders" {
                    return None;
                }
                self.skip(0)?;
                continue;
            }
            seen_orders = true;
            let count = self.head(5)?;
            for _ in 0..count {
                let key_at = self.at;
                self.skip(0)?;
                let id: OrderId = from_cbor(&self.bytes[key_at..self.at]).ok()?;
                let order_fields = self.head(5)?;
                let mut order = None;
                let mut status = None;
                for _ in 0..order_fields {
                    let name = self.text()?;
                    let at = self.at;
                    self.skip(0)?;
                    let value = &self.bytes[at..self.at];
                    match name {
                        "order" if order.is_none() => order = Some(from_cbor(value).ok()?),
                        "status" if status.is_none() => {
                            status = Some(from_cbor::<OrderStatus>(value).ok()?)
                        }
                        "order" | "status" => return None,
                        _ => {}
                    }
                }
                let replaced = orders.orders.insert(
                    id,
                    AuthorizedOrder {
                        order: order?,
                        scoped_payload: Vec::new(),
                        signature: Vec::new(),
                        status: status?,
                        payment_proof: None,
                        status_scoped_payload: None,
                        status_signature: None,
                    },
                );
                if replaced.is_some() {
                    // A key twice: not a map ciborium would have written.
                    return None;
                }
            }
        }
        Some(orders)
    }

    /// `ListingStatusesV1`, each status with only `status` decoded and its
    /// signature and signed payload passed over, and with `held` only the
    /// statuses of those listings.
    fn statuses_light(
        &mut self,
        held: Option<&std::collections::BTreeSet<harvest_common::listing::ListingId>>,
    ) -> Option<harvest_common::store::ListingStatusesV1> {
        use harvest_common::from_cbor;
        use harvest_common::listing::AuthorizedListingStatus;
        use harvest_common::store::Bytes32;
        let mut statuses = harvest_common::store::ListingStatusesV1::default();
        let fields = self.head(5)?;
        let mut seen_records = false;
        for _ in 0..fields {
            let key = self.text()?;
            if key != "records" || seen_records {
                if key == "records" {
                    return None;
                }
                self.skip(0)?;
                continue;
            }
            seen_records = true;
            let count = self.head(5)?;
            for _ in 0..count {
                let key_at = self.at;
                self.skip(0)?;
                let slot: Bytes32 = from_cbor(&self.bytes[key_at..self.at]).ok()?;
                if held
                    .is_some_and(|held| !held.contains(&harvest_common::listing::ListingId(slot.0)))
                {
                    self.skip(0)?;
                    continue;
                }
                let record_fields = self.head(5)?;
                let mut status = None;
                for _ in 0..record_fields {
                    let name = self.text()?;
                    let at = self.at;
                    self.skip(0)?;
                    match name {
                        "status" if status.is_none() => {
                            status = Some(from_cbor(&self.bytes[at..self.at]).ok()?)
                        }
                        "status" => return None,
                        _ => {}
                    }
                }
                let replaced = statuses.records.insert(
                    slot,
                    AuthorizedListingStatus {
                        status: status?,
                        scoped_payload: Vec::new(),
                        signature: Vec::new(),
                    },
                );
                if replaced.is_some() {
                    return None;
                }
            }
        }
        Some(statuses)
    }

    /// `ListingsV1`, each listing with only `listing` decoded and its
    /// signature, signed payload and certificate passed over.
    fn listings_light(&mut self) -> Option<harvest_common::store::ListingsV1> {
        use harvest_common::from_cbor;
        use harvest_common::listing::AuthorizedListing;
        let mut listings = harvest_common::store::ListingsV1::default();
        let fields = self.head(5)?;
        let mut seen_listings = false;
        for _ in 0..fields {
            let key = self.text()?;
            if key != "listings" || seen_listings {
                if key == "listings" {
                    return None;
                }
                self.skip(0)?;
                continue;
            }
            seen_listings = true;
            let count = usize::try_from(self.head(4)?).ok()?;
            if count > self.bytes.len() {
                return None;
            }
            for _ in 0..count {
                let listing_fields = self.head(5)?;
                let mut listing = None;
                for _ in 0..listing_fields {
                    let name = self.text()?;
                    let at = self.at;
                    self.skip(0)?;
                    match name {
                        "listing" if listing.is_none() => {
                            listing = Some(from_cbor(&self.bytes[at..self.at]).ok()?)
                        }
                        "listing" => return None,
                        _ => {}
                    }
                }
                listings.listings.push(AuthorizedListing {
                    listing: listing?,
                    scoped_payload: Vec::new(),
                    signature: Vec::new(),
                    certificate_pem: String::new(),
                });
            }
        }
        Some(listings)
    }
}

/// `MailboxStateV1` as ciborium writes it, or `None` for anything else (the
/// caller then decodes generically).
///
/// The message fields are read by name, in any order, and each must appear
/// exactly once; the timestamp is chrono's RFC 3339 string, parsed as chrono
/// parses it.
pub(crate) fn decode_mailbox(bytes: &[u8]) -> Option<MailboxStateV1> {
    let mut r = Reader { bytes, at: 0 };
    if r.head(5)? != 1 || r.text()? != "messages" {
        return None;
    }
    let n = usize::try_from(r.head(4)?).ok()?;
    if n > bytes.len() {
        return None;
    }
    // Reserved for no more than a mailbox can hold: the count is the
    // sender's word until every message has been read.
    let mut messages = Vec::with_capacity(n.min(harvest_common::mailbox::MAX_MESSAGES));
    for _ in 0..n {
        let fields = r.head(5)?;
        let mut conversation_id = None;
        let mut sender_public_key = None;
        let mut nonce = None;
        let mut ciphertext = None;
        let mut timestamp = None;
        for _ in 0..fields {
            match r.text()? {
                "conversation_id" if conversation_id.is_none() => {
                    let id: [u8; 32] = r.byte_seq()?.try_into().ok()?;
                    conversation_id = Some(ConversationId(id));
                }
                "sender_public_key" if sender_public_key.is_none() => {
                    sender_public_key = Some(r.byte_seq()?);
                }
                "nonce" if nonce.is_none() => {
                    nonce = Some(r.byte_seq()?.try_into().ok()?);
                }
                "ciphertext" if ciphertext.is_none() => ciphertext = Some(r.byte_seq()?),
                "timestamp" if timestamp.is_none() => {
                    timestamp = Some(
                        chrono::DateTime::parse_from_rfc3339(r.text()?)
                            .ok()?
                            .with_timezone(&chrono::Utc),
                    );
                }
                _ => return None,
            }
        }
        messages.push(EncryptedMessage {
            conversation_id: conversation_id?,
            sender_public_key: sender_public_key?,
            nonce: nonce?,
            ciphertext: ciphertext?,
            timestamp: timestamp?,
        });
    }
    if r.at != bytes.len() {
        return None;
    }
    Some(MailboxStateV1 { messages })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Lengths either side of every CBOR length boundary, and byte values
    /// either side of the one-byte integer boundary.
    const LENGTHS: &[usize] = &[0, 1, 23, 24, 25, 255, 256, 257, 65_535, 65_536, 70_000];

    fn bytes(len: usize, salt: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
            .collect()
    }

    /// The export is ciborium's, byte for byte, at every length boundary,
    /// for a generation on either side of every integer boundary. Mutated
    /// red by writing a byte under 24 in two bytes, or a 256-long length in
    /// one.
    #[test]
    fn the_export_encoding_is_ciboriums() {
        for &generation in &[0u32, 23, 24, 255, 256, 65_536, u32::MAX] {
            let secrets: Vec<(Vec<u8>, Vec<u8>)> = LENGTHS
                .iter()
                .enumerate()
                .map(|(i, &len)| (bytes(i + 3, i as u8), bytes(len, 200 + i as u8)))
                .collect();
            let want = freenet_migrate::ExportedSecrets {
                source_generation: generation,
                secrets: secrets.clone(),
            }
            .to_bytes()
            .unwrap();
            assert_eq!(encode_exported(generation, &secrets), want, "{generation}");
        }
        assert_eq!(
            encode_exported(5, &[]),
            freenet_migrate::ExportedSecrets {
                source_generation: 5,
                secrets: Vec::new(),
            }
            .to_bytes()
            .unwrap()
        );
    }

    fn message(i: usize, len: usize) -> EncryptedMessage {
        // Whole seconds, milliseconds (what a client writes), and arbitrary
        // nanoseconds: chrono writes each differently.
        let nanos = match i % 3 {
            0 => 0,
            1 => (i as u32 % 1_000) * 1_000_000,
            _ => (i as u32) * 1_000_003 % 1_000_000_000,
        };
        EncryptedMessage {
            conversation_id: ConversationId([i as u8; 32]),
            sender_public_key: bytes(32, i as u8),
            ciphertext: bytes(len, i as u8 ^ 0x55),
            timestamp: chrono::Utc
                .timestamp_opt(1_790_000_000 + i as i64, nanos)
                .unwrap(),
            nonce: bytes(24, i as u8).try_into().unwrap(),
        }
    }

    /// A mailbox ciborium wrote decodes to exactly what ciborium decodes, at
    /// every length boundary and with sub-second timestamps. Mutated red by
    /// dropping a field, or by reading a byte with a wrong minimum.
    #[test]
    fn the_mailbox_decoding_is_ciboriums() {
        let state = MailboxStateV1 {
            messages: LENGTHS
                .iter()
                .enumerate()
                .map(|(i, &len)| message(i, len))
                .collect(),
        };
        let bytes = harvest_common::to_cbor(&state).unwrap();
        assert_eq!(decode_mailbox(&bytes), Some(state));
        // A full mailbox: the message count's head is three bytes long.
        let full = MailboxStateV1 {
            messages: (0..harvest_common::mailbox::MAX_MESSAGES)
                .map(|i| message(i, 40 + i % 300))
                .collect(),
        };
        assert_eq!(
            decode_mailbox(&harvest_common::to_cbor(&full).unwrap()),
            Some(full)
        );
        let empty = harvest_common::to_cbor(&MailboxStateV1::default()).unwrap();
        assert_eq!(decode_mailbox(&empty), Some(MailboxStateV1::default()));
    }

    /// Anything that is not exactly what ciborium writes is declined, never
    /// read as something else: every truncation, every trailing byte, a
    /// two-byte small integer, a missing or repeated field, a wrong-sized
    /// fixed array. Declined means the caller decodes generically.
    #[test]
    fn anything_else_is_declined() {
        let state = MailboxStateV1 {
            messages: vec![message(1, 40), message(2, 300)],
        };
        let good = harvest_common::to_cbor(&state).unwrap();
        for cut in 0..good.len() {
            assert_eq!(decode_mailbox(&good[..cut]), None, "cut at {cut}");
        }
        let mut long = good.clone();
        long.push(0);
        assert_eq!(decode_mailbox(&long), None);
        // A ciphertext byte under 24 written in two bytes.
        let mut bad = good.clone();
        let at = bad
            .windows(2)
            .position(|w| w == [0x18, 0x55 ^ 2])
            .expect("a two-byte ciphertext byte")
            + 1;
        bad[at] = 3;
        assert_eq!(decode_mailbox(&bad), None);
        // One message's fields edited as CBOR values: a field twice, a field
        // missing, a 31-byte conversation id.
        type Fields = Vec<(ciborium::Value, ciborium::Value)>;
        let edited = |edit: &dyn Fn(&mut Fields)| {
            let mut value = ciborium::Value::serialized(&MailboxStateV1 {
                messages: vec![message(4, 30)],
            })
            .unwrap();
            let ciborium::Value::Map(top) = &mut value else {
                panic!()
            };
            let ciborium::Value::Array(messages) = &mut top[0].1 else {
                panic!()
            };
            let ciborium::Value::Map(fields) = &mut messages[0] else {
                panic!()
            };
            edit(fields);
            let mut out = Vec::new();
            ciborium::into_writer(&value, &mut out).unwrap();
            out
        };
        assert!(decode_mailbox(&edited(&|_| {})).is_some(), "unedited");
        assert_eq!(
            decode_mailbox(&edited(&|f| f.push(f[2].clone()))),
            None,
            "a field twice"
        );
        assert_eq!(
            decode_mailbox(&edited(&|f| {
                f.pop();
            })),
            None,
            "a field missing"
        );
        assert_eq!(
            decode_mailbox(&edited(&|f| {
                let ciborium::Value::Array(id) = &mut f[0].1 else {
                    panic!()
                };
                id.pop();
            })),
            None,
            "a 31-byte id"
        );
        // A message with one field renamed (so one missing, one unknown).
        let mut renamed = good.clone();
        let at = renamed
            .windows(5)
            .position(|w| w == b"nonce")
            .expect("a nonce field");
        renamed[at + 3] = b's';
        assert_eq!(decode_mailbox(&renamed), None);
        // Whatever ciborium makes of a mangled state, this never decodes it
        // to something different.
        for i in 0..good.len() {
            for bit in 0..8 {
                let mut m = good.clone();
                m[i] ^= 1 << bit;
                if let Some(fast) = decode_mailbox(&m) {
                    let slow: Option<MailboxStateV1> = harvest_common::from_cbor(&m).ok();
                    assert_eq!(Some(fast), slow, "flip of bit {bit} at {i}");
                }
            }
        }
    }

    /// A map's fields are found by skipping the others by their heads, for
    /// every kind of item ciborium writes (negative and large integers,
    /// floats, booleans, null, bytes, text, nested arrays and maps, tags),
    /// and the slice found is exactly the field's encoding. Truncations, a
    /// repeated field, trailing bytes and indefinite lengths are declined.
    #[test]
    fn map_fields_skips_every_kind_of_item() {
        use ciborium::Value;
        let odd = Value::Array(vec![
            Value::Integer((-5).into()),
            Value::Integer(u64::MAX.into()),
            Value::Float(1.5),
            Value::Float(f64::from(1.1f32)),
            Value::Float(0.1),
            Value::Bool(true),
            Value::Null,
            Value::Bytes(vec![1; 300]),
            Value::Text("é".repeat(40)),
            Value::Map(vec![(Value::Integer(1.into()), Value::Array(vec![]))]),
            Value::Tag(1, Box::new(Value::Integer(7.into()))),
        ]);
        let map = Value::Map(vec![
            (Value::Text("skip".into()), odd.clone()),
            (Value::Text("want".into()), odd.clone()),
            (Value::Text("also".into()), Value::Integer(3.into())),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&map, &mut bytes).unwrap();
        let found = map_fields(&bytes, &["want", "absent"]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, 0);
        let mut want = Vec::new();
        ciborium::into_writer(&odd, &mut want).unwrap();
        assert_eq!(found[0].1, want.as_slice());
        for cut in 0..bytes.len() {
            assert_eq!(map_fields(&bytes[..cut], &["want"]), None, "cut at {cut}");
        }
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(map_fields(&long, &["want"]), None);
        let twice = Value::Map(vec![
            (Value::Text("want".into()), Value::Null),
            (Value::Text("want".into()), Value::Null),
        ]);
        let mut twice_bytes = Vec::new();
        ciborium::into_writer(&twice, &mut twice_bytes).unwrap();
        assert_eq!(map_fields(&twice_bytes, &["want"]), None);
        // Each width of simple value and float, written by hand: ciborium
        // writes the shortest that holds a value, so not every width shows
        // up above.
        for skipped in [
            &[0xf4][..],
            &[0xf8, 0x20],
            &[0xf9, 0x3c, 0x00],
            &[0xfa, 0x3f, 0x8c, 0xcc, 0xcd],
            &[0xfb, 0x3f, 0xb9, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a],
        ] {
            let mut raw = vec![0xa2, 0x61, b's'];
            raw.extend_from_slice(skipped);
            raw.extend_from_slice(&[0x61, b'w', 0x01]);
            assert_eq!(
                map_fields(&raw, &["w"]),
                Some(vec![(0, &[0x01][..])]),
                "{skipped:02x?}"
            );
        }
        // Integer heads of every width, skipped.
        for skipped in [
            &[0x17][..],
            &[0x18, 0xff],
            &[0x19, 0xff, 0xff],
            &[0x1a, 0xff, 0xff, 0xff, 0xff],
            &[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ] {
            let mut raw = vec![0xa2, 0x61, b's'];
            raw.extend_from_slice(skipped);
            raw.extend_from_slice(&[0x61, b'w', 0x01]);
            assert_eq!(
                map_fields(&raw, &["w"]),
                Some(vec![(0, &[0x01][..])]),
                "{skipped:02x?}"
            );
        }
        // Nesting: 64 arrays deep is skipped, 66 is declined.
        let nested = |depth: usize| {
            let mut raw = vec![0xa1, 0x61, b's'];
            raw.extend(std::iter::repeat_n(0x81, depth));
            raw.push(0x00);
            raw
        };
        assert!(map_fields(&nested(64), &["w"]).is_some());
        assert_eq!(map_fields(&nested(66), &["w"]), None);
        // Text that is not UTF-8, skipped: declined, as ciborium refuses it.
        assert_eq!(map_fields(&[0xa1, 0x61, b's', 0x61, 0xff], &["w"]), None);
        assert_eq!(map_fields(&[0xbf, 0xff], &["want"]), None);
        assert_eq!(map_fields(&[0xa1, 0x61, b'a', 0x9f, 0xff], &["a"]), None);
    }
}
