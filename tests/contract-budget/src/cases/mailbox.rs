//! The mailbox at its caps (harvest#226).
//!
//! Every size class is filled to its cap with bucket-padded messages: a
//! ciphertext of `SIZE_BUCKETS[class] + AEAD_TAG_BYTES` bytes, the largest a
//! message of that class can carry. The class caps sum to `MAX_MESSAGES`
//! (512), so the mailbox is at its count cap and every class cap at once,
//! about 3.3 MiB of ciphertext. Anyone can bring a mailbox here: it is
//! open-write.
//!
//! The held state is built by `MailboxStateV1::apply_delta` from empty, so
//! it is canonical and passes `verify`, exactly as the contract would hold
//! it. The contract never decrypts, so the ciphertext is deterministic
//! pseudo-random bytes, which is what real ciphertext looks like.

use anyhow::{bail, Result};
use harvest_common::mailbox::{
    ConversationId, EncryptedMessage, MailboxParameters, MailboxStateV1, AEAD_TAG_BYTES,
    MAX_MESSAGES, SENDER_KEY_BYTES, SIZE_BUCKETS, SIZE_CLASS_CAPS,
};

use super::{array, bytes, cbor, now, signing_key, Case, Kind, Update};

/// One message of size class `class`, at the top of that class. `label`
/// keeps two mailboxes' messages apart; `at` is its age in seconds before
/// [`super::now`] (the cap keeps the newest).
fn message(label: &str, i: u64, class: usize, at: i64) -> EncryptedMessage {
    EncryptedMessage {
        conversation_id: ConversationId(array(&format!("{label}/conversation"), i)),
        sender_public_key: bytes(&format!("{label}/sender"), i, SENDER_KEY_BYTES),
        ciphertext: bytes(
            &format!("{label}/ciphertext"),
            i,
            SIZE_BUCKETS[class] + AEAD_TAG_BYTES,
        ),
        timestamp: now() - chrono::Duration::seconds(at),
        nonce: array(&format!("{label}/nonce"), i),
    }
}

/// A mailbox at every cap. Its messages are dated `offset`, `offset + 2`,
/// ... seconds ago, so two mailboxes built with offsets 0 and 1 interleave
/// and a merge of the two keeps half of each.
///
/// The largest classes are the newest. The cap keeps the newest messages
/// first, so a merge of two such mailboxes keeps every class full and the
/// result is at the byte cap too. Were the small messages newest, the merge
/// would keep 512 of them and shed every large one, and the merged state
/// would be the cheap case.
fn at_cap(label: &str, offset: i64) -> Result<MailboxStateV1> {
    let mut messages = Vec::new();
    let mut i = 0u64;
    for (class, &cap) in SIZE_CLASS_CAPS.iter().enumerate().rev() {
        // Class 0's cap is the whole count cap; it gets what the larger
        // classes leave.
        let n = if class == 0 {
            MAX_MESSAGES - SIZE_CLASS_CAPS[1..].iter().sum::<usize>()
        } else {
            cap
        };
        for _ in 0..n {
            messages.push(message(label, i, class, offset + 2 * i as i64 + 60));
            i += 1;
        }
    }
    let mut state = MailboxStateV1::default();
    state
        .apply_delta(&Some(messages))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    state
        .verify()
        .map_err(|e| anyhow::anyhow!("the mailbox fixture fails verify: {e}"))?;
    let mut per_class = [0usize; 4];
    for m in &state.messages {
        let class = harvest_common::mailbox::size_class(m).expect("within MAX_MESSAGE_BYTES");
        per_class[class] += 1;
    }
    if state.messages.len() != MAX_MESSAGES || per_class[1..] != SIZE_CLASS_CAPS[1..] {
        bail!(
            "the mailbox fixture is not at its caps: {} messages, per class {per_class:?}",
            state.messages.len()
        );
    }
    Ok(state)
}

pub fn cases() -> Result<Vec<Case>> {
    let owner = signing_key("mailbox/owner", 0).verifying_key();
    let parameters = cbor(&MailboxParameters::new(owner));
    let held = at_cap("mailbox/held", 0)?;
    let held_bytes = cbor(&held);

    // (a) An ordinary buyer message: one text, the smallest bucket, newer
    // than everything held, so the cap keeps it and evicts the oldest.
    let one = vec![message("mailbox/new", 0, 0, 0)];

    // (b) A full forward of a second, different mailbox at its caps, as a
    // PUT, a resync or the migration's `send_forward` delivers it.
    let other = at_cap("mailbox/other", 1)?;

    Ok(vec![
        Case {
            kind: Kind::Mailbox,
            name: "512 at caps + one-message delta".into(),
            parameters: parameters.clone(),
            held: held_bytes.clone(),
            update: Update::Delta(cbor(&one)),
        },
        Case {
            kind: Kind::Mailbox,
            name: "512 at caps + another 512-at-caps state".into(),
            parameters,
            held: held_bytes,
            update: Update::State(cbor(&other)),
        },
    ])
}
