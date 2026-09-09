use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

/// How many messages one mailbox contract will hold.
///
/// This is the mailbox's only retention rule. That it is a count rather than
/// an age is a security property and not a preference -- see
/// [`MailboxStateV1::apply_delta`], which explains why nothing here may be
/// dropped for being old.
pub const MAX_MESSAGES: usize = 512;

/// Message size buckets for padding (bytes). Ciphertexts are padded to the next
/// bucket boundary to reduce size-based traffic analysis.
pub const SIZE_BUCKETS: &[usize] = &[1024, 4096, 16384, 65536];

/// The largest plaintext that gets padded at all.
///
/// [`pad_to_bucket`] does NOT pad data larger than this -- it returns it with
/// a length prefix and nothing else. That is not a silent hole any more:
/// [`MAX_MESSAGE_BYTES`] is set so that a message whose plaintext exceeded
/// this could not fit, and [`MailboxStateV1::apply_delta`] refuses it. So
/// every message that reaches a mailbox IS padded to a bucket, and the size
/// privacy the buckets buy holds for everything a reader can see.
pub const LARGEST_BUCKET: usize = SIZE_BUCKETS[SIZE_BUCKETS.len() - 1];

/// The AES-256-GCM authentication tag the ciphertext carries beyond its
/// plaintext.
///
/// `harvest-common` does no encryption -- that is `harvest-ui`'s `messaging`
/// -- but it has to size the envelope it stores, and the tag is part of what
/// arrives. A cipher change that altered this would make [`MAX_MESSAGE_BYTES`]
/// refuse legitimate top-bucket messages, which is the safe direction and a
/// loud one.
pub const AEAD_TAG_BYTES: usize = 16;

/// An X25519 public key, which is what a message's routing tag is.
pub const SENDER_KEY_BYTES: usize = 32;

/// A conservative upper bound on the CBOR bytes one message costs beyond its
/// two variable-length fields.
///
/// Measured at 145 bytes for an empty message and 150 for a full one (the
/// difference is CBOR's longer length prefixes), so this carries deliberate
/// slack. The slack is in the safe direction -- it over-charges, so the
/// budget binds slightly early -- and
/// `the_byte_charge_is_never_less_than_the_encoded_size` is what keeps that
/// true rather than this comment.
pub const MESSAGE_ENVELOPE_BYTES: usize = 192;

/// The largest message a mailbox will accept.
///
/// Set to exactly a full top-bucket message so that TWO things follow, rather
/// than being a round number someone picked:
///
/// * every accepted message is padded (see [`LARGEST_BUCKET`]), so the
///   bucketing actually delivers the size privacy it claims; and
/// * no single message can consume the whole of [`MAX_MAILBOX_BYTES`], which
///   is what stops one oversized entry pruning a mailbox to nothing.
///
/// It also bounds `sender_public_key`, which is a `Vec<u8>` on the wire and
/// was otherwise unbounded.
pub const MAX_MESSAGE_BYTES: usize =
    MESSAGE_ENVELOPE_BYTES + SENDER_KEY_BYTES + LARGEST_BUCKET + AEAD_TAG_BYTES;

/// How many bytes of message one mailbox contract will hold.
///
/// # Why a count cap was not a bound
///
/// [`MAX_MESSAGES`] caps entries, and each entry holds a
/// contract-controlled `ciphertext` and a contract-controlled
/// `sender_public_key`. A count cap READS like a memory bound and is not one:
/// multiply it by the largest value the other side may send. Before this
/// existed, `pad_to_bucket` stopped padding above its top bucket rather than
/// refusing, so a single message could be arbitrarily large and a mailbox
/// with it -- 512 entries of no particular size.
///
/// # Why this number
///
/// 512 messages at the smallest bucket -- which is what text traffic
/// produces -- comes to roughly 580 KiB, so honest use never reaches this and
/// the cap binds only on abuse. At the largest bucket it admits about 63
/// messages, which also bounds what a buyer pays to read a mailbox somebody
/// has flooded (see `docs/messaging-privacy.md`).
pub const MAX_MAILBOX_BYTES: usize = 4 * 1024 * 1024;

/// The bytes of a message that are authenticated but not encrypted.
///
/// # Why every field except the ciphertext is bound in
///
/// AES-GCM authenticates what it encrypts and nothing else, so before this
/// existed only `ciphertext` was protected. Every other field of
/// [`EncryptedMessage`] could be edited by anyone who could read the mailbox
/// -- which is everyone -- and the result still authenticated:
///
/// * **`nonce`.** Only its first 12 bytes are the AES-GCM nonce; bytes 12..24
///   are padding that feeds deduplication and nothing else. Randomising them
///   re-submits the same ciphertext as a new message. That is a replay, and
///   it also occupies mailbox slots the attacker cannot read but can refill
///   at will.
/// * **`timestamp`.** It is the primary key of the eviction ranking (see
///   [`enforce_message_cap`]), so re-dating a genuine message moves somebody
///   else's traffic up or down the order that decides what survives a flood.
/// * **`sender_public_key`.** The conversation's routing tag.
/// * **`conversation_id`.** The cleartext copy of the id the ciphertext also
///   carries.
///
/// Binding them costs no wire bytes: associated data is derived from fields
/// that are transmitted anyway, never sent. It is defined here rather than
/// beside the cipher because both ends must derive it identically and this is
/// the crate they share -- the same argument as
/// [`conversation_key_from_dh`], and the same silent failure if they drift.
///
/// # The layout
///
/// A domain-separating label, then fixed-width fields, then the ONE
/// variable-length field last and length-prefixed. That ordering is what
/// makes the encoding unambiguous: no two different messages can produce the
/// same bytes by shifting a boundary.
pub fn message_aad(
    conversation_id: &ConversationId,
    sender_public_key: &[u8],
    timestamp: &DateTime<Utc>,
    nonce: &[u8; 24],
) -> Vec<u8> {
    const LABEL: &[u8] = b"harvest-mailbox-envelope-v1";

    let mut aad = Vec::with_capacity(LABEL.len() + 32 + 24 + 12 + 8 + sender_public_key.len());
    aad.extend_from_slice(LABEL);
    aad.extend_from_slice(&conversation_id.0);
    aad.extend_from_slice(nonce);
    // Seconds and sub-second nanoseconds together, so the binding is exact
    // rather than truncated to whatever unit happened to be convenient. Both
    // are infallible, unlike `timestamp_nanos_opt`.
    aad.extend_from_slice(&timestamp.timestamp().to_le_bytes());
    aad.extend_from_slice(&timestamp.timestamp_subsec_nanos().to_le_bytes());
    aad.extend_from_slice(&(sender_public_key.len() as u64).to_le_bytes());
    aad.extend_from_slice(sender_public_key);
    aad
}

/// [`message_aad`] for a message that already exists, which is what the
/// decrypting side has.
pub fn message_aad_for(message: &EncryptedMessage) -> Vec<u8> {
    message_aad(
        &message.conversation_id,
        &message.sender_public_key,
        &message.timestamp,
        &message.nonce,
    )
}

/// **No single message may consume the mailbox.**
///
/// The fact `enforce_message_cap`'s prefix rule rests on, held by the
/// compiler rather than by a test: if one message could fill the budget, and
/// it ranked first -- which is free, because timestamps are unsigned -- the
/// mailbox would prune to nothing behind it. Retuning either constant into
/// that corner fails the BUILD rather than a test somebody might not run.
const _: () = assert!(
    MAX_MESSAGE_BYTES * 2 <= MAX_MAILBOX_BYTES,
    "one message must not be able to crowd out every other"
);

/// What one message costs against [`MAX_MAILBOX_BYTES`].
///
/// Both variable-length fields are charged, plus a constant envelope. It is a
/// model of the CBOR size rather than the CBOR size itself, because computing
/// the real thing means serializing every message on every merge -- and
/// because a model that can be proved to over-charge is a bound, whereas one
/// that might under-charge is a proxy. `the_byte_charge_is_never_less_than_
/// the_encoded_size` is what makes it the former.
pub fn message_bytes(message: &EncryptedMessage) -> usize {
    MESSAGE_ENVELOPE_BYTES + message.sender_public_key.len() + message.ciphertext.len()
}

/// Pad data to the next size bucket boundary. Returns the padded data.
/// The first 4 bytes encode the original length (little-endian u32) so the
/// receiver can strip padding.
///
/// **Data larger than [`LARGEST_BUCKET`] is NOT padded** -- it comes back with
/// a length prefix and nothing else, so its size is exactly its size and the
/// bucketing provides no privacy for it whatsoever.
///
/// That used to be a silent hole; it is now closed at the other end.
/// [`MAX_MESSAGE_BYTES`] is set to exactly a full top-bucket message, so a
/// message built from unpadded data cannot fit in a mailbox and
/// [`MailboxStateV1::apply_delta`] drops it. Every message a reader can see
/// has therefore been padded. Pinned by
/// `every_message_a_mailbox_accepts_has_been_padded`.
pub fn pad_to_bucket(data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let padded_len = SIZE_BUCKETS
        .iter()
        .find(|&&bucket| bucket >= len + 4) // +4 for length prefix
        .copied()
        .unwrap_or(len + 4); // if larger than all buckets, no padding

    let mut result = Vec::with_capacity(padded_len);
    result.extend_from_slice(&(len as u32).to_le_bytes());
    result.extend_from_slice(data);
    result.resize(padded_len, 0);
    result
}

/// Remove padding from bucket-padded data.
pub fn unpad_from_bucket(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 4 {
        return Err("padded data too short for length prefix".into());
    }
    let len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len + 4 > padded.len() {
        return Err(format!(
            "length prefix {len} exceeds padded data size {}",
            padded.len() - 4
        ));
    }
    Ok(padded[4..4 + len].to_vec())
}

/// Which way along a conversation a message travels.
///
/// # Why the two directions do not share a key
///
/// Both ends compute the same X25519 shared secret, so a single key derived
/// from it would encrypt and decrypt in both directions -- and then **a copy
/// of the buyer's own message reads as a reply from the seller**. Anyone can
/// read the mailbox and anyone can write to it, so mounting that is a copy
/// and a paste: no key, no relationship with either party. What the buyer
/// would see is a reply, in the seller's own mailbox, decrypting correctly,
/// saying whatever the buyer had earlier said. In the phase this mechanism
/// exists for, the thing the seller sends back is the buyer's sole
/// authorization to complain, so "a message that reads as coming from the
/// seller" is not a cosmetic confusion.
///
/// Separating the directions makes that impossible rather than detectable: a
/// buyer-to-seller ciphertext simply does not authenticate under the
/// seller-to-buyer key. It costs one BLAKE3 invocation and no wire bytes.
///
/// # What this channel guarantees, in one line
///
/// **Confidentiality yes; direction yes against third parties; authorship no;
/// freshness no.**
///
/// * **Confidentiality** — AES-256-GCM under a key derived from an X25519
///   exchange, so only the two parties read the content.
/// * **Direction, against third parties** — the two directions use different
///   keys, so nobody outside the conversation can make a message appear to
///   travel the other way.
/// * **Authorship, no** — see below. Both parties hold both keys.
/// * **Freshness, no** — `EncryptedMessage::timestamp` is chosen by whoever
///   wrote the message. It is now authenticated (see [`message_aad`]), which
///   stops a THIRD party re-dating somebody else's message, and does nothing
///   at all about an author dating their own however they like. Nothing here
///   establishes when a message was written or that it is current.
///
/// Anything built on this channel should read that line before deciding what
/// to trust.
///
/// # What it does NOT defend against, and why nothing here can
///
/// **The counterparty.** Both parties derive BOTH keys from the same
/// symmetric Diffie-Hellman secret -- the buyer needs the seller-to-buyer key
/// in order to read replies at all -- so either of them can encrypt in either
/// direction. A buyer can place a message in the seller's mailbox that
/// authenticates under the seller-to-buyer key, and the seller's own client
/// cannot tell it from something the seller wrote.
///
/// This is not a gap to close with more crypto at this layer: a symmetric DH
/// secret cannot distinguish its two holders, and only a per-message
/// signature could. So the rule is:
///
/// **Direction is a property of the CHANNEL, never evidence of authorship.
/// Anything whose authenticity matters must carry its own signature.**
///
/// That sentence is load-bearing rather than decorative. The seller's
/// pre-signed statement that a buyer needs in order to complain is Ed25519
/// signed by the seller precisely so its authenticity rests on the signature
/// and not on which key decrypted it; a future change that decided the
/// channel was enough would silently make it forgeable by the buyer it
/// protects. `harvest-ui`'s `messaging::Addressing` carries the same warning
/// at the type the UI actually reads.
///
/// Replay is separately impossible, but NOT for the reason this comment gave
/// until 2026-09-05. It said that changing the nonce to evade dedup changes
/// the AES nonce with it -- true only of the first 12 of the 24 bytes. Bytes
/// 12..24 fed deduplication and nothing else, so randomising them resubmitted
/// the same ciphertext as a new message, and it was verified working. What
/// closes it is [`message_aad`], which authenticates the whole envelope.
/// Neither of those is what direction separation guards; this guards the
/// direction.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageDirection {
    /// Written by the buyer, read by the seller.
    BuyerToSeller,
    /// Written by the seller, read by the buyer.
    SellerToBuyer,
}

impl MessageDirection {
    /// The BLAKE3 key-derivation context for this direction.
    ///
    /// Contexts are hard-coded, globally unique strings, as BLAKE3's
    /// `derive_key` requires. They carry a date and a version because
    /// changing one silently breaks every conversation in flight -- so a
    /// future change must add a context rather than edit one, and this is
    /// where a reader finds that out.
    const fn context(self) -> &'static str {
        match self {
            MessageDirection::BuyerToSeller => "harvest mailbox v1 2026-09-05 buyer-to-seller",
            MessageDirection::SellerToBuyer => "harvest mailbox v1 2026-09-05 seller-to-buyer",
        }
    }
}

/// Turn a raw X25519 shared secret into the AES-256 key one direction of a
/// conversation uses.
///
/// # Why this is in `harvest-common` rather than beside either caller
///
/// The two ends run in different crates and on different machines. A buyer's
/// browser computes it from an ephemeral secret it generated
/// (`harvest-ui`'s `messaging::BuyerConversation`); the seller's harvest
/// delegate computes it from the long-term secret it holds, because that
/// secret must not leave the delegate. If those two derivations ever disagree
/// -- one adds a domain separator, one changes hash -- nothing errors: the
/// AES-GCM tag simply fails to verify and every message in the conversation
/// reads as corrupt, on both sides, forever. There is no negotiation and no
/// version byte to catch it.
///
/// So it is written once, here, and pinned by known-answer tests whose
/// expected values came from an independent BLAKE3 implementation rather than
/// from this function.
pub fn conversation_key_from_dh(shared_secret: &[u8; 32], direction: MessageDirection) -> [u8; 32] {
    blake3::derive_key(direction.context(), shared_secret)
}

/// The value a buyer's order commitment must carry so that no OTHER buyer can
/// read it as theirs.
///
/// # The hole this closes
///
/// A published commitment named nothing that only one buyer could satisfy. So
/// a seller could accept one order, publish one commitment, and send the same
/// order id down any number of conversations: every buyer's software found the
/// commitment published, signed, fresh and for a listing they had asked about,
/// cleared every check, and showed them the same payment address. One declared
/// debt collected unbounded money.
///
/// That does not merely weaken the anti-exit-scam mechanism, it inverts it.
/// The commitment exists to make a seller's outstanding liability countable by
/// a stranger; a commitment that can absorb N payments makes the count
/// meaningless.
///
/// `docs/design/incentive-mechanism.md` and GitHub issue 8 already give the
/// answer: the buyer chooses a secret `n`, sends `H(n)` with the order, and
/// the seller publishes `H(n)` inside the commitment. The buyer's check
/// becomes "the published commitment carries MY `H(n)`", which no other buyer
/// can satisfy.
///
/// # Where `n` comes from, and why it is derived rather than drawn
///
/// `n` has to outlive the tab, or a returning buyer cannot check their own
/// order -- and there is no browser storage at all here
/// (`docs/buyer-conversation-persistence.md`). The one durable, buyer-only
/// secret this application already has is the ephemeral conversation secret
/// in the harvest delegate, which never leaves it and which the backup string
/// already carries across machines. So `n` is derived from that secret rather
/// than stored beside it: no new field on the record, no change to the backup
/// format, and a restored conversation restores its binding for free.
///
/// **The seller cannot compute it.** They hold the Diffie-Hellman *shared*
/// secret, not the buyer's private scalar, so `n` is buyer-only in the sense
/// issue 8 needs for Phase 2 filing.
///
/// **It reveals nothing.** `H(n)` is a hash of a value nobody else holds, so a
/// commitment carrying it is opaque to an observer. This is why the binding is
/// not the buyer's ephemeral PUBLIC key, which would have been the obvious
/// choice and is the mailbox routing tag -- publishing that would tie the
/// public commitment to the conversation for anyone watching.
///
/// **If the conversation secret leaks, `n` leaks.** That is not extra
/// exposure: an attacker holding the secret can already derive both direction
/// keys and read the whole conversation, and from Phase 2 the confession lives
/// in the same record.
///
/// # What it does NOT separate
///
/// One binding per CONVERSATION, not per order. Two orders a buyer places in
/// one thread carry the same binding, so this does not distinguish them from
/// each other -- their distinct order ids and the buyer's own request list do
/// that. What it distinguishes is BUYERS, which is the hole above. Per-order
/// nonces would need a durable per-order counter, which is a delegate change
/// Phase 2 can make if filing turns out to need it.
///
/// # Why this is in `harvest-common`
///
/// The same reason as [`conversation_key_from_dh`], and with the same failure
/// mode. The buyer's browser computes this from a secret it just generated;
/// the harvest delegate computes it from the stored secret on recall, because
/// that secret must not leave the delegate. If the two derivations ever
/// disagree, nothing errors -- the buyer simply finds their own commitment
/// unrecognisable after a reload and can never pay. Pinned by a known-answer
/// test whose expected value came from `b3sum` rather than from this
/// function, and by a cross-crate test that the delegate's recall answers what
/// the buyer's own conversation computes.
pub fn order_binding_from_secret(conversation_secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("harvest/order-binding/v1", conversation_secret)
}

/// Opaque conversation identifier chosen by the buyer.
///
/// Privacy: this is a random 32-byte value, NOT derived from party identities.
/// Deriving it from fingerprints would let a passive observer who knows the
/// seller's fingerprint (public on the store contract) confirm whether a
/// suspected buyer is communicating with that seller.
///
/// The buyer generates a random ConversationId and includes it in their first
/// (encrypted) message. The seller learns the ConversationId only after
/// decrypting the message.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ConversationId(pub [u8; 32]);

impl ConversationId {
    /// Generate a random conversation ID.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("getrandom should not fail");
        Self(bytes)
    }
}

/// An encrypted message in a mailbox.
///
/// The mailbox is an open-write contract: anyone can submit encrypted messages.
/// Content is opaque ciphertext; the contract validates structure, not content.
///
/// Privacy notes:
/// - Buyers MUST use a fresh ephemeral key per store to prevent cross-store linkability.
/// - Ciphertext SHOULD be padded via `pad_to_bucket()` before encryption to reduce
///   size-based traffic analysis.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct EncryptedMessage {
    pub conversation_id: ConversationId,
    /// **The BUYER's ephemeral X25519 public key for this conversation, in
    /// both directions.** The field name predates replies and is kept because
    /// renaming it changes the CBOR and orphans every mailbox already on the
    /// network.
    ///
    /// For a buyer-to-seller message it is the sender's key, which is what
    /// the name says. For a seller's reply it is the RECIPIENT's -- the
    /// seller echoes the buyer's key back rather than naming themselves.
    ///
    /// It is the conversation's routing tag: the only field in the clear that
    /// says which conversation a message belongs to.
    /// [`ConversationId`] cannot do that job because it is inside the
    /// ciphertext, which is the whole point of it.
    ///
    /// Buyers MUST use a fresh ephemeral key per store to prevent cross-store
    /// linkability.
    ///
    /// # What echoing it costs
    ///
    /// An observer can pair a reply with the message it answers, so the
    /// thread structure of a conversation is public: how many messages, in
    /// which direction, and when. What it does NOT reveal is who either party
    /// is -- the key is freshly random per conversation and tied to no
    /// identity -- or what was said.
    ///
    /// The alternative is a tag nobody can link, which costs the buyer a
    /// decryption attempt against every entry in the mailbox rather than
    /// against their own conversation. Both were considered; the leak is
    /// small next to what a public per-store mailbox reveals anyway (entry
    /// count, arrival times, padded sizes), and it is written down in
    /// `docs/messaging-privacy.md` rather than left implicit.
    pub sender_public_key: Vec<u8>,
    /// Encrypted payload (plaintext format is application-defined).
    /// SHOULD be padded to a size bucket before encryption.
    pub ciphertext: Vec<u8>,
    /// When the message was created.
    pub timestamp: DateTime<Utc>,
    /// Unique nonce for deduplication.
    pub nonce: [u8; 24],
}

/// Immutable parameters for a mailbox contract.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct MailboxParameters {
    /// The mailbox owner's Ed25519 verifying key (for identity linkage).
    ///
    /// `pub(crate)` on purpose -- see [`MailboxParameters::new`].
    pub(crate) owner_verifying_key: VerifyingKey,
}

impl MailboxParameters {
    /// The only way to build these parameters from outside `harvest-common`.
    ///
    /// The field set of this struct is hashed into the mailbox's address, so a
    /// second place building it by hand can address a different contract. See
    /// [`crate::store::StoreParameters::new`] for the incident that argument
    /// comes from.
    pub fn new(owner_verifying_key: VerifyingKey) -> Self {
        Self {
            owner_verifying_key,
        }
    }
}

/// Mailbox contract state: a collection of encrypted messages with TTL-based pruning.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub struct MailboxStateV1 {
    pub messages: Vec<EncryptedMessage>,
}

/// **What the contract treats as one message.**
///
/// # Why identity is the whole entry and not the nonce
///
/// The nonce is a field the WRITER fills in. It is public, the mailbox is
/// open-write, and the counterparty holds the conversation key -- so anyone
/// can submit a different message under somebody else's nonce, and their
/// substitute decrypts. While the nonce was the identity, that was a
/// deletion primitive: `verify` forbade a duplicate nonce, so the dedup had
/// to discard one of the two, and every field it ranked on was the writer's
/// to choose.
///
/// In Phase 2 that is not a nuisance. The seller's reply carries a pre-signed
/// confession which is the buyer's SOLE capability to file against the
/// seller's bond, and the seller knows its nonce -- so the bonded seller
/// could send it, wait for payment, and retract it.
///
/// Hashing the whole entry ends it: two entries that differ in any byte are
/// two entries, so there is no collision to resolve and nothing to displace.
/// The contract can compute this without any key, which is what makes it
/// enforceable -- a rule that only honest clients follow (deriving the nonce
/// from the message, say) binds nobody who matters.
///
/// # What it does NOT do
///
/// It does not stop the counterparty WRITING. They hold the key, so they can
/// always add a message to the conversation, and a substitute now sits beside
/// the original rather than in place of it. Nor does it make a message
/// permanently un-removable: a funded flood can still evict it under the cap
/// (`known_gap_a_funded_flood_still_evicts_every_honest_message`). What
/// changed is that retraction stopped being free, targeted and silent.
///
/// # Where it is used
///
/// Everywhere "the same message" is decided: [`MailboxStateV1::verify`],
/// [`MailboxStateV1::summarize`], [`MailboxStateV1::delta`],
/// `dedupe_identical_entries`, and the mailbox contract's own update arms,
/// which delegate rather than deciding for themselves. Clients also use it to
/// recognise their own writing (`AppState::authored_here`), which is what
/// stops a substitute being labelled as the buyer's own words.
///
/// Four sites have answered this question for themselves --
/// `dedupe_by_nonce`, `summarize`, the contract's state-merge arm, and
/// `ui/src/migrate.rs::merge_mailbox` -- each in a separate change, and only
/// the last was caught by anything other than a person. The source scrape
/// `no_production_code_compares_message_nonces_for_identity` is the tripwire
/// for a fifth. **Read its own doc comment before relying on it**: it is a
/// text scrape, it was much weaker than this sentence implied until
/// 2026-09-05, and what actually carries the property is the behavioural
/// tests.
///
/// Domain-separated, so a digest of a message can never coincide with a
/// digest of anything else this codebase hashes.
///
/// This comment described the OPPOSITE of the above for the length of one
/// commit -- it still said identity was the nonce -- because the digest was
/// promoted from a client-side aid to the contract's identity without its own
/// body changing, so nothing in the diff invited anyone to read it. See "A doc
/// comment outlives the design it described" in `docs/untested-invariants.md`.
pub fn entry_digest(message: &EncryptedMessage) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("harvest mailbox entry digest v1");
    hasher.update(&message.nonce);
    hasher.update(&message.conversation_id.0);
    hasher.update(&(message.sender_public_key.len() as u64).to_le_bytes());
    hasher.update(&message.sender_public_key);
    hasher.update(&(message.ciphertext.len() as u64).to_le_bytes());
    hasher.update(&message.ciphertext);
    hasher.update(&message.timestamp.timestamp().to_le_bytes());
    hasher.update(&message.timestamp.timestamp_subsec_nanos().to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Summary for delta computation: the set of entry digests this peer holds.
///
/// # This was a set of NONCES, and the name changed with the payload
///
/// `MailboxSummary` carried `[u8; 24]` nonces until 2026-09-05. The rename is
/// deliberate: a change of payload is a change of name.
///
/// **Two things an earlier version of this comment claimed, corrected after
/// review, because both were wrong and both are the kind of premise a later
/// decision gets built on.**
///
/// It said no contract carrying the old shape had ever been published. False:
/// `legacy/mailbox_contract.toml` records seven published generations and
/// every one of them shipped the 24-byte summary. What actually makes the old
/// shape unreachable is that the contract is content-addressed, so this change
/// re-keys it -- a V7 peer and a V8 summary never meet, because they are
/// different contracts.
///
/// It also said the two shapes "cannot be confused on the wire". Measured
/// through this crate's own `to_cbor`/`from_cbor`, that holds in one direction
/// and not the other: a non-empty 24-byte summary read as 32-byte fails with
/// "invalid length 24"; an EMPTY one decodes cleanly as an empty set; and a
/// 32-byte summary read by old code is silently TRUNCATED to 24-byte prefixes,
/// so it would answer "I hold these" for digests it has never seen. The
/// re-key is what makes that unreachable, not the encoding.
///
/// The change is the half of the fix that lives in synchronisation. While the
/// summary was a set of nonces, a peer that held ONE of two entries sharing a
/// nonce answered "I have that one" for the other and never received it -- so
/// the message could be intact in the contract and absent from that peer,
/// which from the buyer's side is the same loss.
///
/// Note what that does and does not buy, because "unretractable" was the word
/// here and it was too strong. Together with [`entry_digest`] it closes
/// retraction BY SUBSTITUTION. A funded flood still evicts a message under the
/// cap (`known_gap_a_funded_flood_still_evicts_every_honest_message`), so
/// retraction is expensive and indiscriminate rather than impossible -- though
/// not interruptible: either flood route is a single update. For Phase 2 that
/// residual is settled by the buyer persisting the confession in their own
/// delegate store on receipt AND paying only after the write is confirmed,
/// which is recorded in `docs/buyer-conversation-persistence.md` and not built
/// here.
/// **`BTreeSet`, not `HashSet`.** A summary is encoded and sent, so its
/// bytes must be a function of its contents alone; a `HashSet` iterates in an
/// order derived from a per-instance random seed and so encodes differently on
/// every call, for the same contents, in the same process. Pinned by
/// `mailbox_summary_encoding_is_deterministic`.
pub type MailboxSummaryV2 = BTreeSet<[u8; 32]>;

/// Delta: new messages to add. Unchanged in shape -- it always carried whole
/// messages, and only what counts as "already held" moved.
pub type MailboxDelta = Vec<EncryptedMessage>;

/// Keep one copy of each distinct message.
///
/// # Why this exists at all
///
/// [`MailboxStateV1::verify`] rejects a state holding the same entry twice,
/// so a state carrying one is permanently invalid: it cannot be updated,
/// cannot converge, and pruning never removes it, because pruning truncates a
/// sorted prefix and both copies sit in it together. Producing such a state
/// has to be impossible here, and it was not: the dedup set used to be
/// snapshotted from `self.messages` before the loop and never updated inside
/// it, so a delta naming one message twice stored both. One contract update,
/// no key, no relationship with either party.
///
/// # There is no longer a winner to choose
///
/// This deduplicated by NONCE until 2026-09-05, which meant two DIFFERENT
/// messages sharing one had to be resolved -- and the ~30 lines of reasoning
/// that used to live here explained how the survivor was picked by a total
/// order over the fields, since first-arrival-wins would leave two peers
/// holding different bytes forever.
///
/// All of that is gone, and its absence is the point. Every field in that
/// order was chosen by whoever wrote the message, so the resolution was
/// always the writer's to steer: submit a second message under someone's
/// nonce and the contract itself deleted theirs. Identity is now
/// [`entry_digest`] over the whole entry, so two entries that differ in any
/// byte are two entries and there is nothing to resolve. Only genuinely
/// identical copies collapse, and for those any survivor is the same bytes.
///
/// What that costs: a substitute now sits BESIDE the original rather than
/// replacing it. The mailbox is open-write, so an attacker could always add
/// an entry; what they can no longer do is remove one. See
/// `docs/messaging-privacy.md`.
/// # Convergence rests on this sort OR on `apply_delta`'s final tiebreak
///
/// **Corrected on 2026-09-05 after review; the first version of this comment
/// claimed the property lived here alone and cited a measurement that does
/// not reproduce.** What the mutation matrix actually shows:
///
/// * replacing this with an order-dependent dedup (`retain` + a `HashSet`,
///   first-wins, input order preserved) alone: **everything still passes**,
///   because `apply_delta`'s final `(nonce, entry_digest)` sort re-normalises
///   whatever order this leaves behind;
/// * removing that final tiebreak alone: **everything still passes**, because
///   this sort already ordered them;
/// * doing BOTH: **three tests fail** --
///   `two_different_messages_sharing_a_nonce_converge_and_both_survive`,
///   `a_nonce_collision_inside_one_delta_converges_and_keeps_both`, and
///   `a_retraction_that_arrives_first_does_not_keep_the_original_out`.
///
/// **So the property itself IS pinned; what is not pinned is which mechanism
/// provides it.** That distinction is the whole content of this comment. The
/// suite fails the moment convergence for a same-nonce pair actually breaks,
/// which is the guarantee that matters; it just cannot tell you, from any
/// single mutation, which of the two to keep -- because the two are mutually
/// redundant and each survives its own deletion. The earlier inference --
/// "the tiebreaks survive their own mutation, so the property lives here" --
/// was invalid for exactly that reason: single-mutation survival is symmetric
/// and attributes nothing.
///
/// **The one real exposure is deleting both.** No test objects to either
/// deletion on its own, so two changes months apart, each individually
/// justified by a green suite, end in a silent permanent divergence. This
/// comment and its twin in `apply_delta` are the only thing standing between
/// those two changes.
///
/// (`enforce_message_cap`'s digest tiebreak is a third and is redundant to
/// both: removing the two above kills the suite whether or not it is
/// present.)
fn dedupe_identical_entries(messages: &mut Vec<EncryptedMessage>) {
    messages.sort_by_key(entry_digest);
    messages.dedup_by_key(|message| entry_digest(message));
}

/// Drop the lowest-ranked messages until `messages` satisfies BOTH
/// [`MAX_MESSAGES`] and [`MAX_MAILBOX_BYTES`].
///
/// Rank is `(timestamp, nonce, entry_digest)`, highest kept. Every field is
/// chosen by whoever wrote the message, so this ordering is grindable and is
/// not offered
/// as a defence -- see [`MailboxStateV1::apply_delta`] for what the caps do
/// and do not buy. What it has to be is *total* and a pure function of
/// message content, so that two replicas holding the same set of messages keep
/// the same subset. Ranking by anything else available here has the same
/// property and the same weakness, and `(timestamp, nonce)` at least leaves a
/// mailbox carrying only honest traffic behaving as a recency window, which is
/// what the age-based rule it replaces was for.
///
/// # Why both caps are one pass, and why the walk SKIPS rather than stopping
///
/// The walk takes messages in rank order and skips any that will not fit,
/// continuing to the next. **This was a prefix walk -- stopping at the first
/// message that did not fit -- until 2026-09-05, and the prefix rule was
/// wrong.** The argument for it was that "both peers keep the same prefix of
/// the same total order" is a simpler convergence story than a greedy pack,
/// and that the simpler story is worth more than the extra bytes because
/// divergence here is silent and permanent.
///
/// The simplicity was real; the conclusion did not follow. Both rules are pure
/// functions of the SET, so both converge between two peers holding the same
/// messages -- that was never the difference. What the prefix rule broke is
/// **fold ORDER-invariance**, which is one of the properties
/// `FoldAllAck` is minted against, and which `ui/src/migrate.rs`'s
/// `fold_all_policy` asserts through freenet-migrate's own
/// `assert_fold_order_invariant`. Under a prefix walk, which messages survive
/// depends on *which large message happened to be present to block the walk*,
/// and that is a property of the fold order rather than of the byte set:
/// remove the blocker and a smaller message behind it now fits. Absorption
/// failed the same way, so re-running the migration was not a fixed point and
/// the state could flap between two sizes, each flap a PUT.
///
/// Skipping restores both, and it is the same one pass: `retain` in rank
/// order, keeping what fits. Two consequences worth stating rather than
/// discovering:
///
/// * **A lower-ranked message can now survive while a higher-ranked one is
///   dropped.** That is the thing the prefix rule was protecting, and it turns
///   out to be a benefit: an honest small message now survives a flood of
///   maximum-size entries that would previously have blocked the walk and
///   taken it. The byte-budget flood route is materially weaker for it -- see
///   `the_byte_route_no_longer_evicts_a_small_honest_message`.
/// * **The count route is unaffected**, so flooding is not defeated, only made
///   to go the cheaper way it already went
///   (`known_gap_a_funded_flood_still_evicts_every_honest_message`).
///
/// The prefix rule's one failure mode is now gone as well: it could keep
/// NOTHING if the first message did not fit. [`MAX_MESSAGE_BYTES`] is still far
/// below [`MAX_MAILBOX_BYTES`] and [`MailboxStateV1::apply_delta`] still
/// refuses an oversized message on the way in, because a single entry must
/// still be bounded -- but neither is now load-bearing against "one message
/// empties the mailbox", because a skipping walk cannot do that.
fn enforce_message_cap(messages: &mut Vec<EncryptedMessage>) {
    let over_count = messages.len() > MAX_MESSAGES;
    let over_bytes = messages.iter().map(message_bytes).sum::<usize>() > MAX_MAILBOX_BYTES;
    if !over_count && !over_bytes {
        return;
    }

    // Descending. `(timestamp, nonce)` stopped being a total order the moment
    // two entries could share both, so the digest is appended to close it.
    //
    // No test fails without this tiebreak, and it is redundant to BOTH of the
    // mechanisms named on `dedupe_identical_entries` -- removing those two
    // kills the suite whether or not this one is present. It is here so the
    // ranking is self-sufficient rather than resting on a precondition about
    // what ran before it. Kept, unobservable, and saying so rather than
    // claiming a property it does not carry.
    messages.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| b.nonce.cmp(&a.nonce))
            .then_with(|| entry_digest(b).cmp(&entry_digest(a)))
    });

    let mut bytes = 0usize;
    let mut kept = 0usize;
    messages.retain(|message| {
        if kept == MAX_MESSAGES {
            return false;
        }
        let with_this = bytes + message_bytes(message);
        if with_this > MAX_MAILBOX_BYTES {
            // Skip, do not stop. Stopping made the surviving set depend on
            // which large message happened to block the walk, which is a
            // property of the fold order rather than of the byte set, and it
            // broke `FoldAllAck`'s order-invariance and absorption.
            return false;
        }
        bytes = with_this;
        kept += 1;
        true
    });
}

impl MailboxStateV1 {
    /// Verify state: no duplicate nonces, and no more than [`MAX_MESSAGES`]
    /// messages.
    ///
    /// Age is deliberately not checked here, and the cap deliberately is. The
    /// distinction is whether a state can turn invalid while nobody touches
    /// it. A TTL check used to live here and made a mailbox permanently
    /// invalid the moment any single message aged out: `verify` rejected the
    /// WHOLE state rather than pruning, so the mailbox could never shed
    /// anything and never recover. Being over the cap is a property of the
    /// bytes rather than of the passage of time -- [`Self::apply_delta`] never
    /// produces such a state -- so rejecting it cannot strand an honest
    /// mailbox, and it is what stops a peer being handed one directly.
    pub fn verify(&self) -> Result<(), String> {
        if self.messages.len() > MAX_MESSAGES {
            return Err(format!(
                "mailbox holds {} messages, cap is {MAX_MESSAGES}",
                self.messages.len()
            ));
        }
        // Duplicate ENTRIES, not duplicate nonces. The nonce is chosen by
        // whoever wrote the message, so rejecting on it made a legal pair --
        // two different messages that happen to share one -- permanently
        // invalid, and that is what turned a nonce collision into a way of
        // destroying somebody else's message. See [`entry_digest`].
        let mut seen = HashSet::new();
        for msg in &self.messages {
            if !seen.insert(entry_digest(msg)) {
                return Err("duplicate message".into());
            }
        }
        Ok(())
    }

    pub fn summarize(&self) -> MailboxSummaryV2 {
        self.messages.iter().map(entry_digest).collect()
    }

    pub fn delta(&self, old_summary: &MailboxSummaryV2) -> Option<MailboxDelta> {
        let new_messages: Vec<_> = self
            .messages
            .iter()
            .filter(|m| !old_summary.contains(&entry_digest(m)))
            .cloned()
            .collect();
        if new_messages.is_empty() {
            None
        } else {
            Some(new_messages)
        }
    }

    /// Apply a delta: add the messages we do not hold, then bound the state
    /// by [`MAX_MESSAGES`].
    ///
    /// # Why retention is not time-based
    ///
    /// It used to be. Messages older than a 30-day TTL were dropped, measured
    /// against the newest timestamp the mailbox held rather than against a
    /// host clock -- a contract may not read one, because its verdict has to
    /// be a pure function of its inputs or two peers evaluating identical
    /// bytes at different moments disagree and never converge
    /// (`freenet_stdlib::time::now()` is deprecated for contracts for exactly
    /// this reason and is staged to trap, freenet-core#5465).
    ///
    /// Deterministic is not the same as trustworthy. The mailbox is
    /// open-write by design -- a buyer must be able to reach a seller they
    /// have no prior relationship with -- and `EncryptedMessage::timestamp` is
    /// signed by nobody. "The newest timestamp the mailbox holds" was
    /// therefore whatever the last writer typed. One message dated far in the
    /// future became the reference, immediately pruned every legitimate
    /// message as outside the window, and then discarded normally-dated
    /// arrivals until real time reached the forged date -- while the forged
    /// message itself survived, being the newest. An unauthenticated,
    /// permanent denial of a targeted mailbox for the cost of a single
    /// contract update, requiring no key and no relationship with either
    /// party.
    ///
    /// No bounded version of that idea survives the threat model, because any
    /// reference derived from message content is derived from attacker
    /// content. The k-th newest timestamp needs k forged messages; a median
    /// needs a majority, which an empty mailbox hands over for one message; a
    /// cap on how far one merge may advance the reference is not a pure
    /// function of the message SET, so two peers that received the same
    /// messages in different batches would advance it a different number of
    /// times and never converge. The reference has to be authenticated, or it
    /// has to go.
    ///
    /// It goes. Nothing is dropped here for being old.
    ///
    /// # What bounds the state instead
    ///
    /// Age was only ever a proxy for size; the comment this one replaces said
    /// so itself ("pruning resumes the moment a new message arrives, which is
    /// also the only moment the size matters"). [`MAX_MESSAGES`] bounds size
    /// directly, and [`enforce_message_cap`] chooses what goes by a total
    /// order over message content, so two replicas holding the same set keep
    /// the same subset and converge as they exchange what the other is
    /// missing.
    ///
    /// # What remains open
    ///
    /// A cap is a smaller weapon, not no weapon. One update carrying
    /// [`MAX_MESSAGES`] messages fills a mailbox -- a `MailboxDelta` is a
    /// bare `Vec` and this function merges the whole of it, so a flood is one
    /// update and not many -- and because eviction is a deterministic
    /// function of content, an attacker can pick timestamps that keep their
    /// own messages at the top of that order.
    ///
    /// What changed from the timestamp defect is the PRICE, and it is a price
    /// in bytes rather than in updates: that defect cost one message, whereas
    /// this costs a full cap's worth (about 122 KiB, measured by
    /// `known_gap_the_byte_budget_did_not_make_a_flood_cheaper`). Both are
    /// **permanent** once paid: far-future timestamps outrank honest traffic
    /// for as long as they sit there, so there is no ongoing spend. An
    /// earlier version of this paragraph said this one "scales with what an
    /// attacker spends", which read as though the cost recurred. It does not.
    ///
    /// It is reduced here, not closed.
    ///
    /// Closing it needs an authenticated retention signal. The natural one is
    /// a checkpoint signed by the mailbox owner, whose verifying key is
    /// already in `MailboxParameters`: only the owner could advance retention,
    /// and an attacker could prune nothing. This type cannot do that on its
    /// own -- neither `verify` nor `apply_delta` is given
    /// `MailboxParameters`, so a signature cannot be checked from here at all,
    /// and threading the parameters through is a change to the contract's
    /// state interface and to every caller of it. Admission control on writes
    /// (payment, or proof-of-work) is the other direction, and bounds the
    /// flood rather than the retention.
    pub fn apply_delta(&mut self, delta: &Option<MailboxDelta>) -> Result<(), String> {
        if let Some(new_messages) = delta {
            for msg in new_messages {
                // Refused rather than stored and pruned. Storing it first
                // would put it at the head of the eviction ranking (its
                // timestamp is free to choose) and prune the mailbox to
                // nothing behind it -- see `enforce_message_cap`. Dropping an
                // incoming message is recoverable in a way that invalidating
                // existing state is not, which is the same reason `verify`
                // does not check the byte budget at all.
                if message_bytes(msg) > MAX_MESSAGE_BYTES {
                    continue;
                }
                self.messages.push(msg.clone());
            }
        }

        // Everything is pushed and THEN deduplicated, rather than filtered on
        // the way in against a set captured beforehand. That shape is what
        // produced a state `verify` rejects: the set did not learn about the
        // messages the loop itself added, so one delta naming a message twice
        // stored both. Deduplicating the whole collection afterwards cannot
        // have that defect, and it also REPAIRS a state that already carries
        // a duplicate -- which matters, because this was live on `main` and a
        // mailbox on the network may be holding one now.
        //
        // It runs before the cap, not after, so a duplicate cannot occupy two
        // of the slots the cap is about to hand out.
        dedupe_identical_entries(&mut self.messages);
        enforce_message_cap(&mut self.messages);

        // Normalisation, and ONE OF TWO mechanisms that make a same-nonce
        // pair converge; `dedupe_identical_entries` is the other, and carries
        // the full mutation matrix. The digest tiebreak is what makes this a
        // total order.
        //
        // Convergence itself IS pinned: delete both mechanisms and three
        // tests fail (`two_different_messages_sharing_a_nonce_converge_and_\
        // both_survive`, `a_nonce_collision_inside_one_delta_converges_and_\
        // keeps_both`, `a_retraction_that_arrives_first_does_not_keep_the_\
        // original_out`). What is NOT pinned is this mechanism's own
        // necessity: either alone suffices, so deleting this one on its own
        // leaves the workspace green. Do not read that as evidence it is
        // dead code -- read the twin comment first.
        //
        // This comment has been wrong twice, in opposite directions, which is
        // why it is careful now. It first said "sort deterministically by
        // nonce for CRDT convergence" (it was not the only such mechanism),
        // then said it carried nothing at all (it is one of the two that do).
        // A comment attributing a property to the wrong mechanism is how the
        // next person deletes the mechanism that actually provides it.
        self.messages.sort_by(|a, b| {
            a.nonce
                .cmp(&b.nonce)
                .then_with(|| entry_digest(a).cmp(&entry_digest(b)))
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer tests for the one function both ends of a conversation
    /// must compute identically.
    ///
    /// The expected values are `b3sum --derive-key <context>` over 32 bytes
    /// of `0x07`, taken from the `b3sum` CLI rather than from this crate -- a
    /// test that asks the implementation what it does and then asserts it
    /// does that would pass under any change at all, which is exactly the
    /// failure this repository keeps finding.
    ///
    /// If these go red, do not update the constants. A changed derivation
    /// makes every existing conversation permanently undecryptable in both
    /// directions, with no error anywhere -- just AES-GCM tags that stop
    /// verifying. Add a context, do not edit one.
    ///
    /// Observed red on 2026-09-05 against the undirected predecessor
    /// (`blake3::hash`, one key for both directions).
    #[test]
    fn the_conversation_key_derivation_is_pinned() {
        assert_eq!(
            conversation_key_from_dh(&[7u8; 32], MessageDirection::BuyerToSeller),
            hex_literal("efd38d9d8791a47b0c4e3be38542cb297b25167aa680d84b9be0ef51dfe202c1"),
        );
        assert_eq!(
            conversation_key_from_dh(&[7u8; 32], MessageDirection::SellerToBuyer),
            hex_literal("6565da998392cff761fc670a61bb365826b464e99449827bd1f4631033ab96a2"),
        );
    }

    /// **The order binding derivation is pinned.**
    ///
    /// Expected value from `b3sum --derive-key "harvest/order-binding/v1"`
    /// over 32 bytes of `0x07`, not from this function. The two ends of this
    /// derivation are in different crates, and a silent disagreement leaves a
    /// buyer unable to recognise their own commitment after a reload.
    #[test]
    fn the_order_binding_derivation_is_pinned() {
        assert_eq!(
            order_binding_from_secret(&[7u8; 32]),
            hex_literal("481d7cec78bd2c8dd0f83bef532c333c639066576ff34e25fd564e2c38a7e260"),
        );
    }

    /// **The binding is not one of the conversation keys.**
    ///
    /// Stated as a property rather than left to the constants: the binding is
    /// PUBLISHED, and a derivation that collided with a direction key would
    /// put an AES key for the conversation into the store's public state.
    #[test]
    fn the_binding_is_not_a_conversation_key() {
        let secret = [7u8; 32];
        assert_ne!(
            order_binding_from_secret(&secret),
            conversation_key_from_dh(&secret, MessageDirection::BuyerToSeller),
        );
        assert_ne!(
            order_binding_from_secret(&secret),
            conversation_key_from_dh(&secret, MessageDirection::SellerToBuyer),
        );
    }

    /// **Two buyers do not share a binding.**
    ///
    /// The whole point: a commitment carrying one buyer's binding must not
    /// read as another buyer's.
    #[test]
    fn two_conversations_do_not_share_a_binding() {
        assert_ne!(
            order_binding_from_secret(&[7u8; 32]),
            order_binding_from_secret(&[8u8; 32]),
        );
    }

    /// **The two directions must not share a key.**
    ///
    /// Stated separately from the known-answer tests because it is the
    /// property, and the constants above are only one way of holding it: a
    /// future edit that changed both contexts to the same string would update
    /// two constants and keep this test red.
    #[test]
    fn the_two_directions_do_not_share_a_key() {
        let secret = [7u8; 32];
        assert_ne!(
            conversation_key_from_dh(&secret, MessageDirection::BuyerToSeller),
            conversation_key_from_dh(&secret, MessageDirection::SellerToBuyer),
            "one key for both directions means a copy of the buyer's own message reads as \
             a reply from the seller"
        );
    }

    /// Parse a hex string into 32 bytes, so the constants above can be read
    /// against `b3sum`'s output without transcribing them into byte syntax.
    fn hex_literal(hex: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        bytes.try_into().expect("32 bytes")
    }

    #[test]
    fn test_conversation_id_random_is_unique() {
        let id1 = ConversationId::random();
        let id2 = ConversationId::random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let data = b"hello harvest marketplace";
        let padded = pad_to_bucket(data);
        assert_eq!(padded.len(), 1024); // fits in first bucket
        let unpadded = unpad_from_bucket(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_bucket_selection() {
        // Small message -> 1KB bucket
        let small = vec![0u8; 100];
        assert_eq!(pad_to_bucket(&small).len(), 1024);

        // 2KB message -> 4KB bucket
        let medium = vec![0u8; 2000];
        assert_eq!(pad_to_bucket(&medium).len(), 4096);

        // 10KB message -> 16KB bucket
        let large = vec![0u8; 10000];
        assert_eq!(pad_to_bucket(&large).len(), 16384);
    }

    #[test]
    fn test_unpad_rejects_corrupt_data() {
        assert!(unpad_from_bucket(&[0, 0, 0]).is_err()); // too short
        assert!(unpad_from_bucket(&[255, 255, 0, 0]).is_err()); // length exceeds data
    }
}

#[cfg(test)]
mod determinism_tests {
    use super::*;

    fn msg(nonce: u8, secs: i64) -> EncryptedMessage {
        indexed(nonce as u32, secs)
    }

    /// A message whose nonce is derived from `i`, so a test can build more
    /// than 256 distinct ones -- which any test that exercises
    /// [`MAX_MESSAGES`] needs.
    fn indexed(i: u32, secs: i64) -> EncryptedMessage {
        let mut nonce = [0u8; 24];
        nonce[..4].copy_from_slice(&i.to_be_bytes());
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![9u8; 32],
            ciphertext: vec![0u8; 64],
            timestamp: DateTime::from_timestamp(secs, 0).unwrap(),
            nonce,
        }
    }

    /// `MAX_MESSAGES + 100` messages, so eviction actually runs.
    fn over_cap() -> Vec<EncryptedMessage> {
        let base = 1_700_000_000;
        (0..(MAX_MESSAGES as u32 + 100))
            .map(|i| indexed(i, base + i as i64))
            .collect()
    }

    /// The property the clock removal exists for: two peers that receive the
    /// same messages in different orders must end up with byte-identical
    /// state. With `Utc::now()` they could not -- each read its own wall clock
    /// and dropped a different set.
    #[test]
    fn merging_is_order_independent() {
        let forward = over_cap();
        let backward: Vec<_> = forward.iter().rev().cloned().collect();

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(forward)).unwrap();

        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(backward)).unwrap();

        assert_eq!(
            crate::to_cbor(&a).unwrap(),
            crate::to_cbor(&b).unwrap(),
            "identical messages in a different order must produce identical bytes"
        );
    }

    /// The same property across BATCHING rather than ordering, and the reason
    /// no "cap how far one merge may advance the retention reference" scheme
    /// can work here: peers do not agree on how many merges they performed, so
    /// anything counted per-merge diverges. Everything retention depends on
    /// has to be a pure function of the message set.
    #[test]
    fn merging_is_batch_independent() {
        let all = over_cap();

        let mut one_shot = MailboxStateV1::default();
        one_shot.apply_delta(&Some(all.clone())).unwrap();

        let mut dribbled = MailboxStateV1::default();
        for chunk in all.chunks(7) {
            dribbled.apply_delta(&Some(chunk.to_vec())).unwrap();
        }

        assert_eq!(
            crate::to_cbor(&one_shot).unwrap(),
            crate::to_cbor(&dribbled).unwrap(),
            "the same messages delivered in different batch sizes must produce \
             identical bytes"
        );
    }

    /// **A summary must encode as a function of its contents alone.**
    ///
    /// The two tests above pin the STATE bytes and were the only determinism
    /// guards here; the SUMMARY had none, and [`MailboxSummaryV2`] was a
    /// `HashSet` -- which draws a fresh random seed per instance, so it
    /// encoded differently on every call for the same contents.
    ///
    /// [`MailboxStateV1::summarize`] rebuilds the set with `collect()` each
    /// time, so under the defect even summarising ONE state twice differed.
    /// This still uses two independently-built states, to match the shape the
    /// reputation contract is forced into -- there `summarize` returns a
    /// `clone()`, and cloning a `HashSet` copies its hasher, so the
    /// same-state form is green under the defect and pins nothing. Keeping
    /// one shape across both files means the weaker form cannot be copied
    /// here by someone reading this as the template.
    #[test]
    fn mailbox_summary_encoding_is_deterministic() {
        let base = 1_700_000_000;
        let forward: Vec<_> = (0..12u32).map(|i| indexed(i, base + i as i64)).collect();
        let backward: Vec<_> = forward.iter().rev().cloned().collect();

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(forward)).unwrap();

        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(backward)).unwrap();

        assert_eq!(
            a.summarize(),
            b.summarize(),
            "the two mailboxes must hold the same digests, or this test is \
             measuring the wrong thing"
        );
        assert_eq!(
            crate::to_cbor(&a.summarize()).unwrap(),
            crate::to_cbor(&b.summarize()).unwrap(),
            "two peers holding the same messages must send the same summary bytes"
        );
    }

    /// Age is not a reason to drop anything any more. The message here is from
    /// the epoch and the mailbox's other traffic is from 2023; under the TTL
    /// rule this replaced, the old one was discarded.
    #[test]
    fn age_alone_never_drops_a_message() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![msg(1, 0), msg(2, base)])).unwrap();
        assert_eq!(m.messages.len(), 2);
        assert!(m.messages.iter().any(|x| x.timestamp.timestamp() == 0));
    }

    /// A mailbox under the cap keeps every message it is given.
    #[test]
    fn a_mailbox_under_the_cap_keeps_everything() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![
            msg(1, base),
            msg(2, base + 60),
            msg(3, base + 120),
        ]))
        .unwrap();
        assert_eq!(m.messages.len(), 3);
    }

    /// The regression that made a mailbox permanently unusable: `verify` used
    /// to reject the WHOLE state if any single message had aged out, so it
    /// could never shed anything and never recover.
    #[test]
    fn an_old_message_does_not_invalidate_the_whole_mailbox() {
        let mut m = MailboxStateV1::default();
        m.messages.push(msg(1, 0)); // epoch: ancient by any measure
        assert!(
            m.verify().is_ok(),
            "an aged message must not make the entire mailbox invalid"
        );
    }

    /// The cap IS checked by `verify`, unlike age: a state can only be over it
    /// if someone built it that way, and `apply_delta` never produces one.
    #[test]
    fn an_over_cap_state_is_rejected() {
        let m = MailboxStateV1 {
            messages: over_cap(),
        };
        assert!(m.verify().is_err());
    }
}

#[cfg(test)]
mod retention_security_tests {
    use super::*;

    fn msg(nonce: u8, secs: i64) -> EncryptedMessage {
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![9u8; 32],
            ciphertext: vec![0u8; 64],
            timestamp: DateTime::from_timestamp(secs, 0).unwrap(),
            nonce: [nonce; 24],
        }
    }

    /// Ten years past the honest traffic -- a value any writer may put in a
    /// message, because nothing signs it and the contract has no clock to
    /// check it against.
    const FORGED: i64 = 1_700_000_000 + 10 * 365 * 24 * 3600;

    /// The mailbox is open-write by design: a buyer must be able to reach a
    /// seller they have no prior relationship with. So one unauthenticated
    /// writer must not be able to remove another writer's message.
    #[test]
    fn one_forged_timestamp_cannot_empty_the_mailbox() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![msg(1, base), msg(2, base + 60)]))
            .unwrap();
        assert_eq!(m.messages.len(), 2, "precondition: both messages accepted");

        m.apply_delta(&Some(vec![msg(200, FORGED)])).unwrap();

        assert!(
            m.messages.iter().any(|x| x.nonce == [1u8; 24]),
            "a message dated far in the future must not evict earlier messages"
        );
        assert!(
            m.messages.iter().any(|x| x.nonce == [2u8; 24]),
            "a message dated far in the future must not evict earlier messages"
        );
    }

    /// The half that makes the damage permanent rather than momentary: after a
    /// forged message lands, normally-dated messages must still be accepted.
    /// Otherwise the channel stays dead until real time reaches the forged
    /// date.
    #[test]
    fn a_forged_timestamp_does_not_reject_later_honest_messages() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![msg(200, FORGED)])).unwrap();

        m.apply_delta(&Some(vec![msg(1, base)])).unwrap();

        assert!(
            m.messages.iter().any(|x| x.nonce == [1u8; 24]),
            "an honestly-dated message must survive a mailbox holding a forged one"
        );
    }

    /// A message whose nonce is derived from `i`, so a flood can be built out
    /// of more than 256 distinct messages.
    fn indexed(i: u32, secs: i64) -> EncryptedMessage {
        let mut nonce = [0u8; 24];
        nonce[..4].copy_from_slice(&i.to_be_bytes());
        EncryptedMessage {
            nonce,
            ..msg(0, secs)
        }
    }

    /// **THIS TEST PINS A KNOWN GAP. IF IT FAILS, THAT IS GOOD NEWS.**
    ///
    /// It asserts what the mailbox does TODAY, which is the wrong thing: a
    /// funded attacker still evicts every honest message. It exists so that
    /// closing the gap cannot happen quietly -- whoever closes it will see
    /// this go red, and the correct response is to invert the assertions and
    /// rewrite this comment, not to make the test pass again.
    ///
    /// The gap: `enforce_message_cap` ranks by `(timestamp, nonce)`, and both
    /// are chosen by whoever wrote the message. Nothing authenticates who may
    /// occupy space in an open-write mailbox, so an attacker who pays for
    /// [`MAX_MESSAGES`] contract updates, each dated later than the honest
    /// traffic, holds every slot. `MailboxStateV1::apply_delta` documents this
    /// in prose; this is the executable half.
    ///
    /// What would close it, and so break this test: admission control on
    /// writes (payment or proof-of-work), a per-sender quota, or an
    /// owner-authenticated notion of which messages are protected. Note that
    /// an owner-signed *retention checkpoint* alone would NOT break it -- that
    /// closes the separate question of reintroducing time-based retention
    /// safely, and a flood still fills the cap underneath it. Any of these
    /// needs something `apply_delta` does not currently receive, which is why
    /// the gap is open rather than merely unfixed: neither `verify` nor
    /// `apply_delta` is given `MailboxParameters`, so the owner's verifying
    /// key -- the only authenticated identity this contract has -- is not
    /// reachable from the code that would have to use it.
    ///
    /// The second half of the test is the PRICE, and it is the part that
    /// silently rots if the cap is retuned: one message short of the cap
    /// evicts nothing. That is the whole difference from the timestamp defect
    /// this replaced, where the price was one message.
    /// **The byte route no longer evicts a small honest message -- and the
    /// count route still does.**
    ///
    /// This test was added on 2026-09-05 asserting the opposite, and the
    /// assertion is inverted here rather than the test deleted, exactly as its
    /// own failure message instructed. What changed is
    /// [`enforce_message_cap`]: it skips a message that will not fit instead of
    /// stopping at it, so a small honest message now survives in the gap that
    /// a flood of maximum-size entries leaves at the end of the budget. That
    /// change was made for `FoldAllAck`'s order-invariance, and this is a
    /// second, unlooked-for benefit of it.
    ///
    /// **The flood is NOT defeated**, and nothing here should be read as
    /// saying so. The count route still evicts everything
    /// (`known_gap_a_funded_flood_still_evicts_every_honest_message`), it is
    /// cheaper anyway at about 122 KiB against roughly 4 MiB, and it is still a
    /// single update. What is gone is the claim that the byte budget offered a
    /// *cheaper in entries* route to the same result.
    ///
    /// The Phase 2 argument in `docs/buyer-conversation-persistence.md` does
    /// not depend on which route works: it depends on the flood being one
    /// update with no window to be quick in, which the count route still is.
    #[test]
    fn the_byte_route_no_longer_evicts_a_small_honest_message() {
        let base = 1_700_000_000;
        let honest = msg(9u8, base);

        // As few maximum-size entries as fill the byte budget.
        let mut flood = vec![];
        let mut total = 0usize;
        let mut i = 0i64;
        while total < MAX_MAILBOX_BYTES {
            let mut big = msg((i % 250) as u8, base + 20_000 + i);
            big.ciphertext =
                vec![7u8; MAX_MESSAGE_BYTES - message_bytes(&big) + big.ciphertext.len()];
            total += message_bytes(&big);
            flood.push(big);
            i += 1;
        }
        assert!(
            flood.len() * 4 < MAX_MESSAGES,
            "the byte route took {} entries against a count cap of {MAX_MESSAGES}",
            flood.len()
        );

        let mut state = MailboxStateV1::default();
        state
            .apply_delta(&Some(vec![honest.clone()]))
            .expect("apply");
        state.apply_delta(&Some(flood)).expect("apply");

        assert!(
            state.messages.contains(&honest),
            "an honest message was evicted by a byte-budget flood. That was true until \
             `enforce_message_cap` began skipping rather than stopping; if the prefix walk \
             has been restored, this test and the reasoning on `enforce_message_cap` and in \
             docs/buyer-conversation-persistence.md all need revisiting together"
        );
    }

    #[test]
    fn known_gap_a_funded_flood_still_evicts_every_honest_message() {
        let base = 1_700_000_000;
        let honest = || {
            vec![
                indexed(1, base),
                indexed(2, base + 60),
                indexed(3, base + 120),
            ]
        };
        // Dated after the honest traffic, which is free: nothing signs a
        // timestamp. Ranking highest-first is what makes these the survivors.
        let flood = |count: u32| -> Vec<EncryptedMessage> {
            (0..count)
                .map(|i| indexed(1_000 + i, base + 1_000_000 + i as i64))
                .collect()
        };

        // The price. One short of filling the cap, and every honest message
        // is still there -- an attacker gets nothing for a partial spend.
        let mut under = MailboxStateV1::default();
        under.apply_delta(&Some(honest())).unwrap();
        under
            .apply_delta(&Some(flood(MAX_MESSAGES as u32 - 3)))
            .unwrap();
        assert_eq!(under.messages.len(), MAX_MESSAGES);
        for honest_nonce in honest().iter().map(|m| m.nonce) {
            assert!(
                under.messages.iter().any(|m| m.nonce == honest_nonce),
                "a flood that does not fill the cap must evict nothing"
            );
        }

        // The gap. Pay for a full cap's worth and the honest messages are
        // gone. THIS IS THE ASSERTION TO INVERT when the gap closes.
        let mut over = MailboxStateV1::default();
        over.apply_delta(&Some(honest())).unwrap();
        over.apply_delta(&Some(flood(MAX_MESSAGES as u32))).unwrap();
        assert_eq!(over.messages.len(), MAX_MESSAGES);
        for honest_nonce in honest().iter().map(|m| m.nonce) {
            assert!(
                !over.messages.iter().any(|m| m.nonce == honest_nonce),
                "KNOWN GAP no longer reproduces: an honest message survived a \
                 full-cap flood. If you just made that happen, invert this \
                 assertion -- the mailbox now resists a funded flood."
            );
        }
    }

    /// Retention has to bound the state, because that is the only thing it was
    /// ever for. With time-based pruning gone, a count cap is what does it.
    #[test]
    fn the_message_cap_bounds_the_state() {
        let base = 1_700_000_000;
        let mut m = MailboxStateV1::default();
        let flood: Vec<_> = (0..MAX_MESSAGES + 50)
            .map(|i| {
                let mut msg = msg(0, base + i as i64);
                msg.nonce = {
                    let mut n = [0u8; 24];
                    n[..8].copy_from_slice(&(i as u64).to_be_bytes());
                    n
                };
                msg
            })
            .collect();
        m.apply_delta(&Some(flood)).unwrap();
        assert_eq!(m.messages.len(), MAX_MESSAGES);
    }
}

/// The byte budget: that it exists, that pruning is how it is met, and the
/// two things that would break if either changed.
#[cfg(test)]
mod byte_budget_tests {
    use super::*;

    fn total_bytes(state: &MailboxStateV1) -> usize {
        state.messages.iter().map(message_bytes).sum()
    }

    /// A message of `ciphertext` bytes, distinct by index.
    fn sized(i: u32, secs: i64, ciphertext: usize) -> EncryptedMessage {
        let mut nonce = [0u8; 24];
        nonce[..4].copy_from_slice(&i.to_be_bytes());
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![9u8; SENDER_KEY_BYTES],
            ciphertext: vec![0u8; ciphertext],
            timestamp: DateTime::from_timestamp(secs, 0).unwrap(),
            nonce,
        }
    }

    /// Enough top-bucket messages to blow the byte budget several times over
    /// while staying under the COUNT cap -- so a failure here is about bytes
    /// and cannot be the count cap doing the work.
    fn over_budget_but_under_count() -> Vec<EncryptedMessage> {
        let base = 1_700_000_000;
        let count = (MAX_MAILBOX_BYTES / MAX_MESSAGE_BYTES) * 3;
        assert!(
            count < MAX_MESSAGES,
            "this fixture must not rely on the count cap"
        );
        (0..count as u32)
            .map(|i| sized(i, base + i as i64, LARGEST_BUCKET + AEAD_TAG_BYTES))
            .collect()
    }

    /// The bound itself.
    ///
    /// Observed red on 2026-09-05 against `enforce_message_cap` as it was --
    /// count-only -- which kept every one of these.
    #[test]
    fn the_mailbox_is_bounded_in_bytes_and_not_only_in_count() {
        let flood = over_budget_but_under_count();
        let uncapped: usize = flood.iter().map(message_bytes).sum();
        assert!(
            uncapped > MAX_MAILBOX_BYTES,
            "precondition: the fixture must exceed the budget"
        );

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(flood)).unwrap();

        assert!(
            total_bytes(&m) <= MAX_MAILBOX_BYTES,
            "mailbox holds {} bytes, budget is {MAX_MAILBOX_BYTES}",
            total_bytes(&m)
        );
        assert!(
            !m.messages.is_empty(),
            "pruning to the budget must not empty the mailbox"
        );
    }

    /// **Convergence across the byte budget**, which is the property that
    /// matters: two peers given the same messages in different ORDERS must
    /// prune to byte-identical state.
    ///
    /// The existing `merging_is_order_independent` crosses the count cap
    /// only. A byte budget met by a different rule -- one that packed
    /// greedily by size, say -- could satisfy that test and diverge here.
    #[test]
    fn merging_is_order_independent_across_the_byte_budget() {
        let forward = over_budget_but_under_count();
        let backward: Vec<_> = forward.iter().rev().cloned().collect();

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(forward)).unwrap();
        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(backward)).unwrap();

        assert_eq!(
            crate::to_cbor(&a).unwrap(),
            crate::to_cbor(&b).unwrap(),
            "the same messages in a different order pruned to different state"
        );
    }

    /// **Convergence when neither cap binds**, which none of the other
    /// convergence tests reach.
    ///
    /// Every one of them uses an over-cap fixture, so all four exercise
    /// `enforce_message_cap`'s ordering and none exercises the under-cap
    /// path. That gap was found by mutation: deleting `apply_delta`'s final
    /// sort left the entire workspace green, because the dedup also orders
    /// the collection -- true, but the tests could not distinguish which
    /// mechanism was doing the work, which is the same thing as not testing
    /// either. That redundancy still holds, and is written up on
    /// `dedupe_identical_entries`.
    #[test]
    fn merging_converges_when_neither_cap_binds() {
        let base = 1_700_000_000;
        let few: Vec<_> = (0..8u32).map(|i| sized(i, base + i as i64, 512)).collect();
        assert!(few.len() < MAX_MESSAGES);
        assert!(
            few.iter().map(message_bytes).sum::<usize>() < MAX_MAILBOX_BYTES,
            "precondition: neither cap binds, so pruning does no ordering"
        );

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(few.clone())).unwrap();

        let mut b = MailboxStateV1::default();
        for message in few.iter().rev() {
            b.apply_delta(&Some(vec![message.clone()])).unwrap();
        }

        assert_eq!(
            crate::to_cbor(&a).unwrap(),
            crate::to_cbor(&b).unwrap(),
            "an under-cap merge diverged between two arrival orders"
        );
        assert_eq!(a.messages.len(), 8, "nothing was pruned");
    }

    /// The same across BATCHING, for the reason the count-cap version gives:
    /// peers do not agree on how many merges they performed, so anything
    /// counted per-merge diverges.
    #[test]
    fn merging_is_batch_independent_across_the_byte_budget() {
        let all = over_budget_but_under_count();

        let mut one_shot = MailboxStateV1::default();
        one_shot.apply_delta(&Some(all.clone())).unwrap();

        let mut dribbled = MailboxStateV1::default();
        for chunk in all.chunks(3) {
            dribbled.apply_delta(&Some(chunk.to_vec())).unwrap();
        }

        assert_eq!(
            crate::to_cbor(&one_shot).unwrap(),
            crate::to_cbor(&dribbled).unwrap(),
            "the same messages in different batch sizes pruned to different state"
        );
    }

    /// **One oversized message must not empty the mailbox.**
    ///
    /// Pruning keeps a prefix of the ranking, so if the highest-ranked
    /// message did not fit, nothing after it would be reached and the mailbox
    /// would prune to nothing. An attacker who can pick a timestamp can put
    /// their message at the top of that ranking for free, so this would have
    /// been a cheaper and more total attack than the unbounded growth the
    /// budget exists to stop.
    ///
    /// It is closed by refusing the message on the way in rather than by
    /// special-casing the pruning: `MAX_MESSAGE_BYTES` is far below
    /// `MAX_MAILBOX_BYTES`, so the first-message-does-not-fit case is
    /// unreachable.
    #[test]
    fn an_oversized_message_is_refused_rather_than_emptying_the_mailbox() {
        let base = 1_700_000_000;
        let honest = vec![sized(1, base, 1024), sized(2, base + 60, 1024)];

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(honest)).unwrap();
        assert_eq!(m.messages.len(), 2, "precondition");

        // Dated after the honest traffic, which is free, so ranking cannot
        // save us -- and larger than the whole budget.
        let mut monster = sized(99, base + 1_000_000, MAX_MAILBOX_BYTES * 2);
        monster.nonce = [0xFF; 24];
        m.apply_delta(&Some(vec![monster])).unwrap();

        assert_eq!(
            m.messages.len(),
            2,
            "an oversized message must be refused, not stored and not fatal"
        );
        assert!(total_bytes(&m) <= MAX_MAILBOX_BYTES);
    }

    /// A message with an absurd routing tag is refused by the same rule --
    /// `sender_public_key` is a `Vec<u8>` on the wire and nothing else
    /// bounds it.
    #[test]
    fn an_oversized_routing_tag_is_refused() {
        let mut message = sized(1, 1_700_000_000, 64);
        message.sender_public_key = vec![7u8; MAX_MESSAGE_BYTES];

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![message])).unwrap();
        assert!(m.messages.is_empty());
    }

    /// **The accounting must never under-charge**, or the budget is a proxy
    /// rather than a bound.
    ///
    /// Checked against the real CBOR encoding across the shapes that vary:
    /// empty, small, top-bucket, and a far-future timestamp (which encodes
    /// longer).
    #[test]
    fn the_byte_charge_is_never_less_than_the_encoded_size() {
        let mut shapes = vec![
            sized(0, 0, 0),
            sized(1, 1_700_000_000, 1024 + AEAD_TAG_BYTES),
            sized(2, 1_700_000_000, LARGEST_BUCKET + AEAD_TAG_BYTES),
        ];
        let mut late = sized(3, 253_402_300_000, LARGEST_BUCKET + AEAD_TAG_BYTES);
        late.timestamp = DateTime::from_timestamp(253_402_300_000, 999_000_000).unwrap();
        shapes.push(late);
        let mut empty_tag = sized(4, 1_700_000_000, 64);
        empty_tag.sender_public_key = Vec::new();
        shapes.push(empty_tag);

        for message in shapes {
            let encoded = crate::to_cbor(&message).unwrap().len();
            assert!(
                message_bytes(&message) >= encoded,
                "charged {} for a message that encodes to {encoded}",
                message_bytes(&message)
            );
        }
    }

    /// Every message a mailbox accepts has been padded to a bucket, so the
    /// size privacy the buckets claim holds for everything a reader sees.
    ///
    /// The link is `MAX_MESSAGE_BYTES`: it is exactly a full top-bucket
    /// message, so a message built from data `pad_to_bucket` declined to pad
    /// cannot fit. Raise the constant and this goes red.
    #[test]
    fn every_message_a_mailbox_accepts_has_been_padded() {
        // The smallest plaintext `pad_to_bucket` refuses to pad.
        let unpadded = pad_to_bucket(&vec![0u8; LARGEST_BUCKET]);
        assert!(
            unpadded.len() > LARGEST_BUCKET,
            "precondition: this size is past the top bucket"
        );

        let message = sized(1, 1_700_000_000, unpadded.len() + AEAD_TAG_BYTES);
        assert!(
            message_bytes(&message) > MAX_MESSAGE_BYTES,
            "an unpadded message must not fit in a mailbox"
        );

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![message])).unwrap();
        assert!(m.messages.is_empty());
    }

    /// **`verify` deliberately does NOT check the byte budget.**
    ///
    /// The count cap IS checked there, and the argument given for it is that
    /// `apply_delta` never produces an over-cap state, so only a hand-built
    /// state is rejected. That argument does not transfer, and the difference
    /// is what this test exists to hold: the count cap has been enforced
    /// since the mailbox existed, so no honest state was ever over it. The
    /// byte budget is NEW. Mailboxes already on the network were produced by
    /// an honest `apply_delta` under the old rules and may exceed it, and a
    /// `verify` that rejected them would make them permanently invalid --
    /// never convergeable again, with no way back. That is a worse failure
    /// than the unbounded growth being fixed, and this repository has already
    /// been bitten by exactly it once (the TTL check that rejected a whole
    /// mailbox because one message had aged out).
    ///
    /// So an over-budget state is accepted and pruned on the next merge,
    /// which only ever shrinks it.
    ///
    /// **Residual, stated rather than discovered later:** between arriving
    /// and the next update, a peer may hold an over-budget state. Nothing
    /// here bounds that; the node's own maximum state size does.
    #[test]
    fn verify_accepts_an_over_budget_state_so_an_existing_mailbox_is_never_stranded() {
        let m = MailboxStateV1 {
            messages: over_budget_but_under_count(),
        };
        assert!(
            total_bytes(&m) > MAX_MAILBOX_BYTES,
            "precondition: the fixture is over budget"
        );
        assert!(
            m.verify().is_ok(),
            "a state that was legal when it was written must not become permanently invalid"
        );
    }

    /// **THIS TEST PINS A KNOWN GAP, AND CORRECTS WHAT I FIRST CLAIMED
    /// ABOUT IT.**
    ///
    /// `enforce_message_cap` ranks by `(timestamp, nonce)`, both chosen by
    /// whoever wrote the message, so eviction is grindable. That is
    /// pre-existing and is pinned by
    /// `known_gap_a_funded_flood_still_evicts_every_honest_message`.
    ///
    /// What I claimed the byte budget changed was the PRICE -- "512 contract
    /// updates become about 63", "cheaper for the attacker". **Both halves
    /// were wrong**, and the fixture below disproves them:
    ///
    /// * A `MailboxDelta` is a bare `Vec<EncryptedMessage>` and `apply_delta`
    ///   merges the whole vector, so NEITHER route is a number of contract
    ///   updates. Both are **one**.
    /// * Measured in the currency that actually costs -- bytes on the wire --
    ///   the byte-budget route is far MORE expensive, not less. The count cap
    ///   still binds first for small messages, so **the cheapest total
    ///   eviction is unchanged by the byte budget**.
    ///
    /// I conceded a downside that does not exist and understated the
    /// pre-existing one. The security conclusion survives intact and is the
    /// part that matters: closing this needs admission control -- payment,
    /// proof-of-work, or a per-sender quota -- not a retuned cap.
    ///
    /// The assertions now measure both routes so the comment cannot drift
    /// from the fixture again, which is how the wrong claim survived: the
    /// test measured message COUNT while its comment drew a conclusion about
    /// COST.
    #[test]
    fn known_gap_the_byte_budget_did_not_make_a_flood_cheaper() {
        let base = 1_700_000_000;
        let honest: Vec<_> = (0..3).map(|i| sized(i, base + i as i64, 1024)).collect();

        // Dated after the honest traffic, which is free: nothing signs a
        // timestamp.
        let flood = |count: usize, ciphertext: usize| -> Vec<EncryptedMessage> {
            (0..count as u32)
                .map(|i| sized(1_000 + i, base + 1_000_000 + i as i64, ciphertext))
                .collect()
        };

        let cost = |messages: Vec<EncryptedMessage>, must_evict: bool| -> usize {
            let wire = crate::to_cbor(&messages).expect("cbor").len();
            let mut m = MailboxStateV1::default();
            m.apply_delta(&Some(honest.clone())).unwrap();
            m.apply_delta(&Some(messages)).unwrap();
            let survivors = honest
                .iter()
                // nonce-identity-waiver: comparing FIXTURE identity in a test,
                // not deciding "the same message" in production. The scrape
                // skips test code; this marker is belt and braces for a reader.
                .filter(|h| m.messages.iter().any(|kept| kept.nonce == h.nonce))
                .count();
            if must_evict {
                assert_eq!(
                    survivors, 0,
                    "KNOWN GAP no longer reproduces: an honest message survived a COUNT-cap \
                     flood. If you just made that happen, invert these assertions."
                );
            } else {
                assert_eq!(
                    survivors,
                    honest.len(),
                    "a byte-budget flood evicted honest messages again -- `enforce_message_cap` \
                     skips rather than stopping, so they should fit in the gap it leaves"
                );
            }
            wire
        };

        // Route A: fill the COUNT cap with the smallest messages there are.
        // This still evicts everything; it is the route that works.
        let by_count = cost(flood(MAX_MESSAGES, 64), true);
        // Route B: fill the BYTE budget with the largest. Since
        // `enforce_message_cap` began skipping rather than stopping, this no
        // longer evicts a smaller honest message at all -- it is both more
        // expensive AND less effective.
        let by_bytes = cost(
            flood(
                MAX_MAILBOX_BYTES / MAX_MESSAGE_BYTES + 1,
                LARGEST_BUCKET + AEAD_TAG_BYTES,
            ),
            false,
        );

        assert!(
            by_bytes > by_count * 10,
            "the byte-budget route is supposed to be far MORE expensive, not less: \
             {by_bytes} bytes vs {by_count}"
        );
    }
}

/// Nonce deduplication: the thing `verify` rejects a state for, and therefore
/// the thing `apply_delta` must never produce.
#[cfg(test)]
mod dedup_tests {
    use super::*;

    fn message(nonce: [u8; 24], secs: i64, ciphertext: u8) -> EncryptedMessage {
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![9u8; SENDER_KEY_BYTES],
            ciphertext: vec![ciphertext; 64],
            timestamp: DateTime::from_timestamp(secs, 0).unwrap(),
            nonce,
        }
    }

    /// **A delta naming one message twice must not brick the mailbox.**
    ///
    /// `verify` rejects a state holding a duplicate nonce, and pruning only
    /// truncates a sorted prefix -- it never removes a duplicate -- so both
    /// copies survive together and no later merge repairs it. The mailbox is
    /// then permanently invalid: it cannot be updated, cannot converge, and
    /// there is no way back.
    ///
    /// The cost is one contract update with no key and no relationship to
    /// either party, because both of the mailbox contract's update paths hand
    /// attacker bytes to this function: `UpdateData::Delta` deserialises them
    /// straight into a `MailboxDelta`, and `UpdateData::State` filters the
    /// incoming state against what is already held but not against itself.
    ///
    /// Observed red on 2026-09-05 against the snapshot-before-the-loop form,
    /// which is what shipped: `duplicate message nonce`.
    #[test]
    fn a_delta_naming_one_message_twice_leaves_a_valid_state() {
        let twice = message([7u8; 24], 1_700_000_000, 0xAA);

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(vec![twice.clone(), twice.clone()]))
            .unwrap();

        assert_eq!(m.messages.len(), 1, "one message, stored once");
        m.verify()
            .expect("apply_delta must never produce a state verify rejects");
    }

    /// The same through the path a hostile `UpdateData::State` takes: the
    /// contract filters the incoming state against what it already holds and
    /// hands the rest here, so internal duplicates arrive intact.
    #[test]
    fn a_delta_carrying_many_copies_of_one_message_leaves_a_valid_state() {
        let flood = vec![message([3u8; 24], 1_700_000_000, 0xBB); 64];

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(flood)).unwrap();

        assert_eq!(m.messages.len(), 1);
        m.verify().expect("still valid");
    }

    /// **A mailbox already bricked must repair itself on the next merge.**
    ///
    /// This defect is pre-existing on `main`, so a mailbox on the live
    /// network can be holding a duplicate right now. Fixing only the
    /// production of duplicates would leave those permanently invalid, which
    /// is the outcome the fix exists to prevent.
    #[test]
    fn an_already_duplicated_state_is_repaired_by_the_next_merge() {
        let duplicated = message([5u8; 24], 1_700_000_000, 0xCC);
        let mut m = MailboxStateV1 {
            messages: vec![duplicated.clone(), duplicated],
        };
        assert!(m.verify().is_err(), "precondition: this state is invalid");

        m.apply_delta(&None).unwrap();

        assert_eq!(m.messages.len(), 1);
        m.verify().expect("a merge must heal a state it can heal");
    }

    /// **Two DIFFERENT messages sharing a nonce must converge -- and both
    /// must survive.**
    ///
    /// A separate defect from the one above and reachable the same way: an
    /// attacker submits both, in different orders, to different peers. If the
    /// winner is decided by arrival order, the two peers keep different bytes
    /// and never converge -- which for a contract is as bad as invalidity and
    /// harder to notice.
    ///
    /// Observed red on 2026-09-05 against first-arrival-wins, which is what
    /// the snapshot form did across batches.
    ///
    /// **The second assertion was added when identity moved to
    /// [`entry_digest`].** Convergence alone stopped being the whole claim:
    /// two peers agreeing to discard the same message converges perfectly and
    /// is exactly the retraction this contract must not allow. A test whose
    /// name outlives the rule it was written for is how the next reader
    /// concludes the old rule still holds.
    #[test]
    fn two_different_messages_sharing_a_nonce_converge_and_both_survive() {
        let one = message([2u8; 24], 1_700_000_000, 0x11);
        let other = message([2u8; 24], 1_700_000_000, 0x22);

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(vec![one.clone()])).unwrap();
        a.apply_delta(&Some(vec![other.clone()])).unwrap();

        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(vec![other])).unwrap();
        b.apply_delta(&Some(vec![one])).unwrap();

        assert_eq!(
            crate::to_cbor(&a).unwrap(),
            crate::to_cbor(&b).unwrap(),
            "two peers given the same pair in different orders kept different bytes"
        );
        assert_eq!(
            a.messages.len(),
            2,
            "one message displaced the other, so a message can be retracted by submitting \
             another under its nonce"
        );
        a.verify().expect("valid");
    }

    /// And within a single delta, for the same reason.
    #[test]
    fn a_nonce_collision_inside_one_delta_converges_and_keeps_both() {
        let one = message([4u8; 24], 1_700_000_000, 0x33);
        let other = message([4u8; 24], 1_700_000_000, 0x44);

        let mut a = MailboxStateV1::default();
        a.apply_delta(&Some(vec![one.clone(), other.clone()]))
            .unwrap();
        let mut b = MailboxStateV1::default();
        b.apply_delta(&Some(vec![other, one])).unwrap();

        assert_eq!(crate::to_cbor(&a).unwrap(), crate::to_cbor(&b).unwrap());
        assert_eq!(
            a.messages.len(),
            2,
            "a collision inside one delta lost a message"
        );
    }

    /// Deduplication must not swallow distinct messages -- the guard above is
    /// only worth having if ordinary traffic still lands.
    #[test]
    fn distinct_messages_are_all_kept() {
        let base = 1_700_000_000;
        let messages: Vec<_> = (0..8u8)
            .map(|i| message([i; 24], base + i as i64, i))
            .collect();

        let mut m = MailboxStateV1::default();
        m.apply_delta(&Some(messages)).unwrap();

        assert_eq!(m.messages.len(), 8);
        m.verify().expect("valid");
    }
}

/// The message identity a client uses to recognise its own writing.
#[cfg(test)]
mod entry_digest_tests {
    use super::*;

    fn message(ciphertext: &[u8]) -> EncryptedMessage {
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![2u8; 32],
            ciphertext: ciphertext.to_vec(),
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp"),
            nonce: [3u8; 24],
        }
    }

    /// **A substitute sharing a nonce has a different digest.**
    ///
    /// This is the whole reason the digest exists: the counterparty can
    /// submit a different message under the buyer's nonce, and a client that
    /// recognised its own writing by nonce would call the substitute its own.
    #[test]
    fn a_substitute_under_the_same_nonce_has_a_different_digest() {
        let mine = message(b"what I actually wrote");
        let substitute = message(b"what they put in its place");
        assert_eq!(mine.nonce, substitute.nonce, "precondition: same nonce");
        assert_ne!(entry_digest(&mine), entry_digest(&substitute));
    }

    /// The same message digests the same, so an identical re-send is still
    /// recognised as the sender's own.
    #[test]
    fn the_same_message_has_the_same_digest() {
        assert_eq!(
            entry_digest(&message(b"hello")),
            entry_digest(&message(b"hello"))
        );
    }

    /// **Every field is covered.** A field left out is a field an attacker can
    /// vary while keeping the digest, which puts the substitution back.
    #[test]
    fn every_field_changes_the_digest() {
        let base = message(b"hello");
        let digest = entry_digest(&base);

        let mut nonce_changed = base.clone();
        nonce_changed.nonce[0] ^= 1;
        let mut id_changed = base.clone();
        id_changed.conversation_id.0[0] ^= 1;
        let mut tag_changed = base.clone();
        tag_changed.sender_public_key[0] ^= 1;
        let mut time_changed = base.clone();
        time_changed.timestamp = chrono::DateTime::from_timestamp(1_700_000_001, 0).expect("ts");
        let mut subsec_changed = base.clone();
        subsec_changed.timestamp = chrono::DateTime::from_timestamp(1_700_000_000, 7).expect("ts");

        for (what, changed) in [
            ("nonce", nonce_changed),
            ("conversation id", id_changed),
            ("routing tag", tag_changed),
            ("timestamp", time_changed),
            ("timestamp nanos", subsec_changed),
        ] {
            assert_ne!(
                digest,
                entry_digest(&changed),
                "changing the {what} left the digest alone"
            );
        }
    }

    /// Length-prefixed, so moving bytes between two variable-length fields
    /// cannot leave the digest unchanged.
    #[test]
    fn a_field_boundary_cannot_be_moved_without_changing_the_digest() {
        let mut a = message(b"");
        a.sender_public_key = b"abcd".to_vec();
        a.ciphertext = b"ef".to_vec();
        let mut b = message(b"");
        b.sender_public_key = b"abc".to_vec();
        b.ciphertext = b"def".to_vec();
        assert_ne!(entry_digest(&a), entry_digest(&b));
    }
}

/// What the CONTRACT treats as one message, and why it is not the nonce.
#[cfg(test)]
mod entry_identity_tests {
    use super::*;

    fn message(nonce: [u8; 24], ciphertext: &[u8], seconds: i64) -> EncryptedMessage {
        EncryptedMessage {
            conversation_id: ConversationId([1u8; 32]),
            sender_public_key: vec![2u8; 32],
            ciphertext: ciphertext.to_vec(),
            timestamp: chrono::DateTime::from_timestamp(seconds, 0).expect("timestamp"),
            nonce,
        }
    }

    fn mailbox(messages: Vec<EncryptedMessage>) -> MailboxStateV1 {
        let mut state = MailboxStateV1::default();
        state.apply_delta(&Some(messages)).expect("apply");
        state
            .verify()
            .expect("the contract must accept its own result");
        state
    }

    /// **A message cannot be retracted by submitting another under its
    /// nonce.**
    ///
    /// Note the qualification, which is load-bearing for Phase 2: this closes
    /// the free, targeted, silent route. It does NOT make a message
    /// permanently un-removable -- a funded flood still evicts it, at about
    /// 122 KiB across 512 entries filling the COUNT cap
    /// (`known_gap_a_funded_flood_still_evicts_every_honest_message`). The
    /// byte-budget route is both more expensive and, since
    /// `enforce_message_cap` began skipping rather than stopping, no longer
    /// effective against a smaller message
    /// (`the_byte_route_no_longer_evicts_a_small_honest_message`). **The count
    /// route is ONE update**, so there is no window to be quick in -- which is
    /// why Phase 2's answer is an ordering (persist, confirm, then pay) rather
    /// than persisting fast enough. See
    /// `docs/buyer-conversation-persistence.md`.
    ///
    /// This is the reason the contract computes identity for itself. In Phase
    /// 2 the seller's reply carries a pre-signed confession, and that
    /// confession is the buyer's SOLE capability to file against the seller's
    /// bond. It travels as an ordinary message in the seller's own mailbox,
    /// so the seller knows its nonce.
    ///
    /// While identity was the writer's nonce, the seller could send the
    /// confession, wait for payment, and then submit a different message
    /// under the same nonce: the dedup resolved the collision in favour of
    /// whichever ranked higher on fields the seller chooses, and the
    /// confession was gone from a public contract. The buyer would watch
    /// their recourse arrive and then vanish, at a moment of the seller's
    /// choosing.
    ///
    /// Storing it on receipt does not fix that -- it makes the guarantee a
    /// race between the buyer's client persisting and the seller
    /// substituting, and a race is not a foundation for "the buyer has
    /// recourse".
    #[test]
    fn a_message_cannot_be_retracted_by_submitting_another_under_its_nonce() {
        let confession = message([7u8; 24], b"I confess", 1_700_000_000);
        // Same nonce, later timestamp: what the old ranking preferred.
        let retraction = message([7u8; 24], b"I said no such thing", 1_700_000_001);

        let state = mailbox(vec![confession.clone(), retraction.clone()]);

        assert_eq!(
            state.messages.len(),
            2,
            "one message displaced the other, so the confession can be retracted"
        );
        assert!(
            state.messages.contains(&confession),
            "the message the bond rests on is gone from the mailbox"
        );
        assert!(state.messages.contains(&retraction));
    }

    /// Order does not matter: the retraction arriving first must not keep the
    /// confession out either.
    #[test]
    fn a_retraction_that_arrives_first_does_not_keep_the_original_out() {
        let confession = message([7u8; 24], b"I confess", 1_700_000_000);
        let retraction = message([7u8; 24], b"I said no such thing", 1_700_000_001);

        let forwards = mailbox(vec![confession.clone(), retraction.clone()]);
        let backwards = mailbox(vec![retraction, confession.clone()]);

        assert!(backwards.messages.contains(&confession));
        assert_eq!(
            forwards.messages, backwards.messages,
            "two peers that saw the same messages in different orders hold different bytes"
        );
    }

    /// **A true duplicate is still one message.**
    ///
    /// Deduplication has not been given up, only re-keyed: the same message
    /// twice is the same message, and a re-send must not occupy two of the
    /// cap's slots.
    #[test]
    fn the_same_message_twice_is_still_one_message() {
        let once = message([9u8; 24], b"hello", 1_700_000_000);
        let state = mailbox(vec![once.clone(), once.clone(), once]);
        assert_eq!(state.messages.len(), 1);
    }

    /// `verify` rejects a state carrying the same ENTRY twice, and accepts
    /// two different entries that happen to share a nonce.
    ///
    /// The check has not merely moved: it changed meaning. Rejecting on the
    /// nonce made a legitimate pair permanently invalid, which is what turned
    /// a nonce collision into a way of destroying a message.
    #[test]
    fn verify_rejects_a_repeated_entry_and_accepts_a_shared_nonce() {
        let one = message([7u8; 24], b"first", 1_700_000_000);
        let other = message([7u8; 24], b"second", 1_700_000_000);

        let shared_nonce = MailboxStateV1 {
            messages: vec![one.clone(), other],
        };
        shared_nonce
            .verify()
            .expect("two different messages sharing a nonce is a legal state");

        let repeated = MailboxStateV1 {
            messages: vec![one.clone(), one],
        };
        repeated
            .verify()
            .expect_err("the same entry twice must be rejected");
    }

    /// **A summary names entries, so a peer holding one of a same-nonce pair
    /// is still sent the other.**
    ///
    /// This is the half that would silently undo the rest. While a summary
    /// was a set of nonces, a peer that held the retraction would answer "I
    /// have that one" for the confession and never receive it -- the message
    /// would be intact in the contract and absent from that peer, which from
    /// the buyer's side is the same loss.
    #[test]
    fn a_peer_holding_one_of_a_shared_nonce_pair_is_sent_the_other() {
        let confession = message([7u8; 24], b"I confess", 1_700_000_000);
        let retraction = message([7u8; 24], b"I said no such thing", 1_700_000_001);

        let complete = mailbox(vec![confession.clone(), retraction.clone()]);
        let partial = mailbox(vec![retraction]);

        let delta = complete
            .delta(&partial.summarize())
            .expect("the peer is missing a message");
        assert!(
            delta.contains(&confession),
            "a peer holding one message of a shared nonce was told it had both"
        );
    }

    /// Nothing is sent to a peer that already holds everything.
    #[test]
    fn a_peer_holding_everything_is_sent_nothing() {
        let state = mailbox(vec![
            message([7u8; 24], b"one", 1_700_000_000),
            message([8u8; 24], b"two", 1_700_000_001),
        ]);
        assert!(state.delta(&state.summarize()).is_none());
    }

    /// **An over-cap set of entries sharing a nonce AND a timestamp still
    /// converges.**
    ///
    /// `apply_delta` end to end, not the cap's ranking in isolation: the
    /// ranking's own digest tiebreak is unobservable, because
    /// `dedupe_identical_entries` sorts by digest first and every later sort
    /// is stable. What this pins is that SOME step imposes a total order on a
    /// set where neither the nonce nor the timestamp distinguishes anything
    /// -- which is the shape a nonce collision creates, and which
    /// `(timestamp, nonce)` alone could not have handled.
    #[test]
    fn pruning_is_total_when_two_entries_share_a_nonce_and_a_timestamp() {
        let mut messages = Vec::new();
        for i in 0..(MAX_MESSAGES + 4) {
            // Deliberately colliding: one nonce and one timestamp across every
            // message, so only the ciphertext distinguishes them.
            messages.push(message(
                [3u8; 24],
                format!("message {i}").as_bytes(),
                1_700_000_000,
            ));
        }
        let mut reversed = messages.clone();
        reversed.reverse();

        let one = mailbox(messages);
        let other = mailbox(reversed);
        assert_eq!(
            one.messages, other.messages,
            "two peers pruned the same set to different bytes"
        );
        assert_eq!(one.messages.len(), MAX_MESSAGES);
    }
}
