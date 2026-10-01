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
    let mut messages = Vec::with_capacity(n);
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
        EncryptedMessage {
            conversation_id: ConversationId([i as u8; 32]),
            sender_public_key: bytes(32, i as u8),
            ciphertext: bytes(len, i as u8 ^ 0x55),
            timestamp: chrono::Utc
                .timestamp_opt(
                    1_790_000_000 + i as i64,
                    (i as u32) * 1_000_003 % 1_000_000_000,
                )
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
            .map(|p| p + 1);
        if let Some(at) = at {
            bad[at] = 3;
            assert_eq!(decode_mailbox(&bad), None);
        }
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
            let mut m = good.clone();
            m[i] ^= 0x40;
            if let Some(fast) = decode_mailbox(&m) {
                let slow: Option<MailboxStateV1> = harvest_common::from_cbor(&m).ok();
                assert_eq!(Some(fast), slow, "flip at {i}");
            }
        }
    }
}
