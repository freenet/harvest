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
    MAX_DELTA_BYTES, MAX_MESSAGES, SENDER_KEY_BYTES, SIZE_BUCKETS, SIZE_CLASS_CAPS,
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

/// A message that differs from every other built by this function only in
/// its ciphertext: one conversation, one sender, one timestamp and one
/// nonce. Anyone can write such messages to an open-write mailbox, and
/// they are distinct entries the contract keeps. Every ordering the
/// contract applies (the cap's rank, the canonical order) ties on
/// timestamp and nonce and falls through to the entry digest, which a
/// build that hashes per comparison recomputes on every comparison.
fn tied(label: &str, i: u64, class: usize) -> EncryptedMessage {
    EncryptedMessage {
        conversation_id: ConversationId(array("mailbox/tied/conversation", 0)),
        sender_public_key: bytes("mailbox/tied/sender", 0, SENDER_KEY_BYTES),
        ciphertext: bytes(
            &format!("{label}/ciphertext"),
            i,
            SIZE_BUCKETS[class] + AEAD_TAG_BYTES,
        ),
        timestamp: now() - chrono::Duration::seconds(60),
        nonce: array("mailbox/tied/nonce", 0),
    }
}

/// [`tied`] messages filling every class cap.
fn tied_at_cap(label: &str) -> Result<MailboxStateV1> {
    let mut messages = Vec::new();
    let mut i = 0u64;
    for (class, &cap) in SIZE_CLASS_CAPS.iter().enumerate() {
        let n = if class == 0 {
            MAX_MESSAGES - SIZE_CLASS_CAPS[1..].iter().sum::<usize>()
        } else {
            cap
        };
        for _ in 0..n {
            messages.push(tied(label, i, class));
            i += 1;
        }
    }
    built(messages, "the tied mailbox fixture")
}

/// `messages` through `apply_delta` from empty, checked to be at every cap.
fn built(messages: Vec<EncryptedMessage>, what: &str) -> Result<MailboxStateV1> {
    let mut state = MailboxStateV1::default();
    state
        .apply_delta(&Some(messages))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    state
        .verify()
        .map_err(|e| anyhow::anyhow!("{what} fails verify: {e}"))?;
    if state.messages.len() != MAX_MESSAGES {
        bail!("{what} holds {} messages", state.messages.len());
    }
    Ok(state)
}

/// The first [`tied`] text message the cap keeps when merged into `held`:
/// with every rank field tied, whether a newcomer survives is decided by
/// its digest, so some candidates would change nothing.
fn kept_tied_message(held: &MailboxStateV1) -> Result<EncryptedMessage> {
    for i in 0..64 {
        let m = tied("mailbox/tied/new", i, 0);
        let mut merged = held.clone();
        merged
            .apply_delta(&Some(vec![m.clone()]))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if merged.messages.contains(&m) {
            return Ok(m);
        }
    }
    bail!("no tied message among 64 candidates is kept by the cap")
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

    // (c) The largest delta the contract accepts: as many messages of the
    // largest size class, newer than everything held, as encode within
    // `MAX_DELTA_BYTES` (the contract refuses a longer delta on its length,
    // before reading it). The class cap keeps 24 of them.
    let top = |label: &str, n: u64| -> Vec<EncryptedMessage> {
        (0..n)
            .map(|i| message(label, i, SIZE_BUCKETS.len() - 1, -1 - i as i64))
            .collect()
    };
    let mut fit = 0u64;
    while cbor(&top("mailbox/largest", fit + 1)).len() <= MAX_DELTA_BYTES {
        fit += 1;
    }
    let largest = top("mailbox/largest", fit);

    // (c') `MAX_MESSAGES` messages of the largest class, about 34 MB, under
    // the node's 50 MiB limit: over `MAX_DELTA_BYTES`, so it must be refused
    // on its length, cheaply.
    let too_large = top("mailbox/too-large", MAX_MESSAGES as u64);
    if cbor(&too_large).len() <= MAX_DELTA_BYTES {
        bail!("the 512-message top-class delta fits MAX_DELTA_BYTES: update the harness");
    }

    // (d) One message more than that, which must be refused, cheaply.
    let too_many: Vec<EncryptedMessage> = (0..MAX_MESSAGES as u64 + 1)
        .map(|i| message("mailbox/too-many", i, 0, -1 - i as i64))
        .collect();

    // (e), (f) Adversarial ties: see [`tied`].
    let tied_held = tied_at_cap("mailbox/tied/held")?;
    let tied_one = vec![kept_tied_message(&tied_held)?];
    let tied_other = tied_at_cap("mailbox/tied/other")?;

    let tied_bytes = cbor(&tied_held);
    let case = |name: &str, held: &Vec<u8>, update: Update| Case {
        kind: Kind::Mailbox,
        name: name.into(),
        parameters: parameters.clone(),
        held: held.clone(),
        update,
    };
    Ok(vec![
        case(
            "512 at caps + one-message delta",
            &held_bytes,
            Update::Delta(cbor(&one)),
        ),
        case(
            "512 at caps + another 512-at-caps state",
            &held_bytes,
            Update::State(cbor(&other)),
        ),
        case(
            &format!("512 at caps + {fit}-message top-class delta (at the byte bound)"),
            &held_bytes,
            Update::Delta(cbor(&largest)),
        ),
        case(
            "512 at caps + 512-message top-class delta (refused)",
            &held_bytes,
            Update::RefusedDelta(cbor(&too_large)),
        ),
        case(
            "512 at caps + 513-message delta (refused)",
            &held_bytes,
            Update::RefusedDelta(cbor(&too_many)),
        ),
        case(
            "512 tied at caps + one-message delta",
            &tied_bytes,
            Update::Delta(cbor(&tied_one)),
        ),
        case(
            "512 tied at caps + another tied state",
            &tied_bytes,
            Update::State(cbor(&tied_other)),
        ),
    ])
}
