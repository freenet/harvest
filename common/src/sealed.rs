//! The plaintext of buyer-seller messages, and sealing it into a mailbox
//! entry (X25519-derived conversation keys, AES-256-GCM, padded to a size
//! bucket).
//!
//! Here rather than in the UI because two parties now seal and open these
//! messages: the browser, and the seller's Harvest delegate, which answers an
//! instant-checkout request while the seller is away. One definition means the
//! two cannot drift apart, which for an AEAD format fails silently: the other
//! side simply cannot read the message.
//!
//! Behind the `sealed` feature, which the UI and the delegate enable and no
//! contract does: a contract only stores ciphertext, and compiling AES-GCM
//! into one would move its code hash (its address) for nothing.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};

use crate::mailbox::{
    message_aad, message_aad_for, pad_to_bucket, unpad_from_bucket, ConversationId,
    EncryptedMessage,
};

/// A plaintext message exchanged between buyer and seller.
/// Serialized to CBOR, padded, then encrypted.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PlaintextMessage {
    /// The conversation this message belongs to.
    pub conversation_id: ConversationId,
    /// Message content.
    pub content: MessageContent,
}

/// The content of a message: text, or one of the purchase steps.
///
/// The feedback-token exchange's two variants (`InitiateTransaction`,
/// `AcceptTransaction`) are gone with the blind signatures they carried
/// (harvest#53 Phase C). Nothing ever sent either.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MessageContent {
    /// Free-form text message.
    Text(String),
    /// Either party declining or cancelling.
    Decline { reason: String },
    /// A buyer asking to buy a listing.
    ///
    /// Step 1 of `docs/design/incentive-mechanism.md` Part 5. It rides the
    /// ordinary sealed conversation rather than a channel of its own, so the
    /// seller's mailbox is the one place a buyer's approach can arrive from.
    ///
    /// # The buyer's conversation key is not a field here
    ///
    /// It is the routing tag on the envelope
    /// ([`EncryptedMessage::sender_public_key`]), carried in the clear by
    /// every message in both directions, and the delegate files a kept
    /// conversation under the same value. Repeating it inside the plaintext
    /// would be a second source for one identity, and the two could disagree:
    /// a seller replying to the field rather than to the envelope would seal
    /// their answer under keys the buyer's thread does not read, silently.
    /// That is the same defect as trusting an echoed conversation tag, which
    /// this repository has already paid for once.
    ///
    /// # What it does NOT establish
    ///
    /// Nothing about the buyer. They have no ghostkey and no account, and
    /// this message costs nothing to send -- a seller who accepts is choosing
    /// to publish a commitment on the strength of an anonymous request. The
    /// commitment is what has to be countable, not the request.
    OrderRequest {
        listing_id: crate::listing::ListingId,
        /// How many. Not multiplied by anything here: a listing's price is a
        /// free-text `PriceInfo` in an arbitrary currency
        /// ([`crate::listing::PriceInfo`]), so no honest conversion
        /// to satoshis exists in this crate. The seller names the amount when
        /// they accept, and the buyer sees that amount before paying. The
        /// exception is an instant-checkout request (`instant` below), which
        /// is priced by the listing's fixed terms.
        quantity: u32,
        /// Where the goods should go, as the buyer typed it.
        ///
        /// This is the most identifying thing a buyer ever sends, which is
        /// why it travels inside the AEAD and never near the commitment: the
        /// published order must reveal nothing about who bought.
        shipping: String,
        /// Anything else the buyer wants to say, so a request is not a form
        /// that forces a second message beside it.
        note: String,
        /// What the seller must publish in the commitment so that no OTHER
        /// buyer reads it as theirs.
        ///
        /// [`crate::mailbox::order_binding_from_secret`] over this
        /// conversation's own secret. Sending it costs the buyer nothing --
        /// it is a hash of a value only they hold -- and without it one
        /// published commitment is payable by every buyer who was shown it.
        ///
        /// **The buyer does not check the commitment against THIS field.**
        /// Direction is not authorship, so a seller can seal a request into
        /// the buyer's own thread; a check against the mailbox copy would let
        /// the seller supply the value it is compared with. The buyer
        /// compares against what their own node derives. See
        /// `state::AppState::payment_blockers`.
        order_binding: [u8; 32],
        /// The key the seller must sign into the commitment so the buyer can
        /// later act on the order themselves: cancel it before paying, or
        /// complain after (harvest#53 Phase B). The verifying half of
        /// [`crate::mailbox::buyer_receipt_seed_from_secret`] over
        /// this conversation's secret.
        ///
        /// Checked the same way as `order_binding`: the buyer compares the
        /// published commitment against what their OWN node derives, never
        /// against this field.
        ///
        /// `serde(default)` so a request sealed by an earlier build still
        /// opens; it comes back `None`, and a commitment answering it carries
        /// no buyer key, which the buyer then refuses to pay.
        #[serde(default)]
        buyer_receipt_key: Option<[u8; 32]>,
        /// The buyer's instant-checkout selection, when they checked out
        /// against the listing's fixed terms rather than asking for a quote.
        ///
        /// `serde(default)` so a request sealed by an earlier build opens as
        /// a quote request, and skipped when absent so a quote request seals
        /// exactly as before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        instant: Option<InstantSelection>,
    },
    /// The seller has published the order commitment for a request, and this
    /// is its id.
    ///
    /// # This is a pointer, not an authority
    ///
    /// Both parties hold both direction keys (see [`Addressing`]), so nothing
    /// about this message proves the seller wrote it. What makes a commitment
    /// the seller's is the ghostkey-scoped signature on the published
    /// [`crate::payment::AuthorizedOrder`], checked against the
    /// store's own verifying key. A buyer that paid on the strength of this
    /// message alone would be paying on the strength of a message it could
    /// have written itself.
    ///
    /// The id has to be told rather than derived:
    /// `crate::payment::OrderId::from_terms` hashes terms the seller
    /// chooses, including a `created_at` they stamp, so a buyer cannot
    /// compute it.
    OrderAccepted { order_id: crate::payment::OrderId },
}

/// What a buyer picked for an instant-checkout purchase, inside their
/// [`MessageContent::OrderRequest`].
///
/// Present only when the listing offered fixed terms
/// ([`crate::listing::Listing::offers_instant_checkout`]) and the buyer used
/// them. A request without it is a quote request, answered by the seller.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InstantSelection {
    /// Chosen by the buyer, fresh per request. With the conversation's routing
    /// tag it makes the request id ([`crate::payment::request_id`]), which is
    /// what the answering order is identified by, so a resend of the same
    /// request (same nonce) can only ever be answered once.
    pub nonce: [u8; 16],
    /// The delivery region picked from the listing's table; `None` when the
    /// listing includes delivery.
    pub region: Option<String>,
    /// One option per choice group, in the listing's group order.
    pub choices: Vec<String>,
    /// The total the buyer was shown, from
    /// [`crate::listing::Listing::instant_total`]. The seller's delegate
    /// recomputes it and does not invoice when the two differ, so a listing
    /// changed after the buyer read it never yields a total they did not see.
    pub expected_total_sats: u64,
}

/// Seal `content` into a mailbox entry, refusing one the mailbox contract
/// would not accept.
///
/// `MailboxStateV1::apply_delta` refuses a message over
/// [`crate::mailbox::MAX_MESSAGE_BYTES`], and it refuses it silently. So the
/// finished message is charged with the same `message_bytes` the contract
/// uses, and an oversized one is an error here rather than a message that
/// never appears.
pub fn seal(
    key: &[u8; 32],
    tag: &[u8; 32],
    conversation_id: &ConversationId,
    content: MessageContent,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<EncryptedMessage, String> {
    let message = encrypt_message(
        &PlaintextMessage {
            conversation_id: conversation_id.clone(),
            content,
        },
        tag,
        key,
        timestamp,
    )?;
    let charged = crate::mailbox::message_bytes(&message);
    if charged > crate::mailbox::MAX_MESSAGE_BYTES {
        return Err(format!(
            "that message is too long: it comes to {charged} bytes once encrypted and padded, \
             and a mailbox will not accept more than {}. Nothing was sent.",
            crate::mailbox::MAX_MESSAGE_BYTES
        ));
    }
    Ok(message)
}

/// Encrypt a plaintext message under a conversation key.
///
/// `tag` is the conversation's routing tag -- the buyer's ephemeral public
/// key, whichever direction this message travels. See
/// [`crate::mailbox::EncryptedMessage::sender_public_key`].
///
/// Returns an `EncryptedMessage` ready to be sent to the mailbox contract.
///
/// `timestamp` is the envelope time, supplied by the caller because this crate
/// has no clock: the browser passes its own, the delegate the node's.
pub fn encrypt_message(
    plaintext: &PlaintextMessage,
    tag: &[u8; 32],
    aes_key: &[u8; 32],
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<EncryptedMessage, String> {
    // Serialize the plaintext to CBOR
    let plaintext_bytes =
        crate::to_cbor(plaintext).map_err(|e| format!("serialize plaintext: {e}"))?;

    // Pad to reduce size-based analysis
    let padded = pad_to_bucket(&plaintext_bytes);

    // The whole 24-byte mailbox nonce is drawn first, because it is bound
    // into the authenticated data below -- it cannot be assembled after the
    // ciphertext the way it used to be. Its first 12 bytes are the AES-GCM
    // nonce; the rest exist so that deduplication has more entropy than the
    // cipher needs.
    let mut mailbox_nonce = [0u8; 24];
    getrandom::getrandom(&mut mailbox_nonce).map_err(|e| format!("generate nonce: {e}"))?;

    // Every field of the message except the ciphertext, authenticated but not
    // encrypted. See `crate::mailbox::message_aad` for what each one
    // costs to leave unbound -- the sharpest is the nonce padding, whose
    // mutation was a working replay.
    let aad = message_aad(
        &plaintext.conversation_id,
        tag.as_slice(),
        &timestamp,
        &mailbox_nonce,
    );

    let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|e| format!("create cipher: {e}"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&mailbox_nonce[..12]),
            Payload {
                msg: padded.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|e| format!("encrypt: {e}"))?;

    Ok(EncryptedMessage {
        conversation_id: plaintext.conversation_id.clone(),
        sender_public_key: tag.to_vec(),
        ciphertext,
        timestamp,
        nonce: mailbox_nonce,
    })
}

/// Decrypt an encrypted message from the mailbox contract.
pub fn decrypt_message(
    encrypted: &EncryptedMessage,
    aes_key: &[u8; 32],
) -> Result<PlaintextMessage, String> {
    // The AES nonce is the first 12 bytes of the mailbox nonce; the whole 24
    // are bound into the associated data, so a change to any of the rest --
    // or to any other envelope field -- fails the tag rather than passing
    // unnoticed.
    let nonce = Nonce::from_slice(&encrypted.nonce[..12]);
    let aad = message_aad_for(encrypted);

    let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|e| format!("create cipher: {e}"))?;
    let padded = cipher
        .decrypt(
            nonce,
            Payload {
                msg: encrypted.ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|e| format!("decrypt: {e}"))?;

    // Unpad
    let plaintext_bytes = unpad_from_bucket(&padded).map_err(|e| format!("unpad: {e}"))?;

    // Deserialize from CBOR
    crate::from_cbor(&plaintext_bytes).map_err(|e| format!("deserialize plaintext: {e}"))
}
