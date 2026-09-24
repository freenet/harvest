//! Encrypted messaging for buyer-seller communication.
//!
//! Uses X25519 key exchange + AES-256-GCM for end-to-end encryption.
//! Messages are padded to size buckets before encryption to reduce
//! traffic analysis (see harvest_common::mailbox::pad_to_bucket).
//!
//! # The exchange is one-sided, and that is the design
//!
//! A buyer has no identity in Harvest -- no ghostkey, no account, nothing to
//! register -- so there is nobody to run a two-sided handshake with. Instead
//! the SELLER publishes a long-term X25519 public key in
//! [`harvest_common::store::StoreInfoV1::encryption_public_key`], and each
//! buyer generates an ephemeral keypair per message, encrypts to the seller's
//! key, and writes the result into the seller's mailbox contract along with
//! their ephemeral PUBLIC key. The seller's harvest delegate holds the
//! matching secret and answers the derived conversation key; nothing else
//! ever sees it.
//!
//! # What this channel guarantees, in one line
//!
//! **Confidentiality yes; direction yes against third parties; authorship no;
//! freshness no.** The full statement, with what each half rests on, is on
//! [`harvest_common::mailbox::MessageDirection`]. Read it before building
//! anything on top of this that has to be trusted -- in particular, anything
//! whose authenticity matters must carry its own signature rather than
//! resting on which key decrypted it.
//!
//! # Replies, and why they need no buyer mailbox
//!
//! Contract state is public and the mailbox is open-write, so the seller
//! replies **into their own mailbox**, encrypted under the same conversation
//! the buyer opened. The buyer already knows that mailbox's address -- they
//! derived it to send in the first place -- and reads their replies out of
//! it. No buyer mailbox, no buyer identity, no second contract.
//!
//! Two things make that work rather than merely sound plausible:
//!
//! * **Direction separation.** Both ends compute one X25519 shared secret, so
//!   a single key would decrypt in both directions and a copy of the buyer's
//!   own message would read as a reply from the seller. The two directions
//!   get different keys; see [`harvest_common::mailbox::MessageDirection`].
//! * **A routing tag in the clear.** The buyer's ephemeral public key rides on
//!   every message in the conversation, in both directions, so the buyer
//!   finds their own thread without attempting to decrypt the whole mailbox.
//!   What that leaks is written down on
//!   [`harvest_common::mailbox::EncryptedMessage::sender_public_key`] and in
//!   `docs/messaging-privacy.md`.
//!
//! # Surviving a reload, and what still does not
//!
//! The buyer's conversation keys used to live in the tab and nowhere else, so
//! a buyer who reloaded before the seller answered could never read that
//! reply. They are now kept by the harvest delegate, which is the only
//! durable store this application has -- `localStorage`, `sessionStorage`,
//! IndexedDB and cookies all throw inside the gateway's sandboxed iframe,
//! which carries no `allow-same-origin`. [`BuyerConversation::open`] keeps
//! the ephemeral secret for exactly that purpose, and
//! `AppState::compose_to_seller` hands it to the delegate on the first
//! message. See `docs/buyer-conversation-persistence.md`.
//!
//! Two limits survive that, and `components::message_view` says both on
//! screen rather than letting a buyer discover them:
//!
//! * **A different device is a different node.** The secret is in one node's
//!   delegate. A buyer who writes from a laptop and later opens the store on
//!   a phone has a different delegate and unreadable ciphertext.
//! * **The delegate keeps a durable local record of which stores this node
//!   messaged.** It is removable -- "forget this conversation" deletes the
//!   record outright rather than emptying it -- and removing it makes the
//!   thread permanently unreadable, which is the point. See
//!   `docs/messaging-privacy.md`.
//!
//! **Anything for a seller who has published no key.** `encryption_public_key`
//! is `None` for every store created before it existed, and for a seller whose
//! delegate has not minted one. There is no fallback: encrypting to a key that
//! does not exist is not possible, and writing plaintext into a world-readable
//! contract would be worse than sending nothing.
//!
//! **Forward secrecy against the seller's delegate.** The seller's key is
//! long-term, so anyone who later obtains it can read every message ever sent
//! to that store. The buyer's half is ephemeral, which is what stops one
//! buyer's messages linking across stores; it does not protect the archive.

use harvest_common::mailbox::{
    conversation_key_from_dh, ConversationId, EncryptedMessage, MessageDirection,
};
// The message plaintext and its sealing live in `harvest-common` so the
// seller's delegate seals and opens the same format (instant checkout).
pub use harvest_common::sealed::{
    decrypt_message, InstantSelection, MessageContent, PlaintextMessage,
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// Both keys of one conversation, derived from a single X25519 exchange.
///
/// Held together because every party needs both: the seller reads with
/// `to_seller` and writes with `from_seller`, and the buyer does the reverse.
/// Two separate values that must be derived from the same shared secret are
/// exactly the "paired fields that must co-occur" shape, so they are one
/// type.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConversationKeys {
    /// Encrypts what the buyer writes.
    pub to_seller: [u8; 32],
    /// Encrypts what the seller writes back.
    pub from_seller: [u8; 32],
}

impl ConversationKeys {
    pub fn from_shared_secret(shared_secret: &[u8; 32]) -> Self {
        Self {
            to_seller: conversation_key_from_dh(shared_secret, MessageDirection::BuyerToSeller),
            from_seller: conversation_key_from_dh(shared_secret, MessageDirection::SellerToBuyer),
        }
    }

    /// The tag a published order carries for `listing` in this conversation.
    /// See [`harvest_common::mailbox::listing_tag`].
    pub fn listing_tag(&self, listing: &harvest_common::listing::ListingId) -> [u8; 32] {
        harvest_common::mailbox::listing_tag(&self.from_seller, listing)
    }
}

/// Deliberately opaque: a `Debug` that printed these would put both
/// conversation keys into a browser console and, from there, into any log a
/// user pastes into a bug report.
impl std::fmt::Debug for ConversationKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConversationKeys(redacted)")
    }
}

/// The buyer's half of one conversation with one store.
///
/// # Why the ephemeral secret is KEPT
///
/// It was discarded in [`Self::open`], and the comment here said that was
/// deliberate -- "keeping the secret would only widen what a leak costs".
/// That reasoning is now wrong, and the correction is the whole point of this
/// type: the secret is the only thing from which the conversation's keys can
/// be re-derived after the tab is gone, and the seller's reply will, once
/// orders exist, carry the buyer's only capability to complain about the
/// seller they paid. Discarding it traded a small leak surface for the
/// silent, total loss of that capability.
///
/// So a conversation opened here holds its secret, `AppState` hands it to the
/// harvest delegate on the first message, and the delegate answers the two
/// direction keys back on the next page load.
///
/// `secret` is `None` for a conversation RECALLED from the delegate: the
/// delegate answers derived keys and never the secret it derived them from,
/// so a recalled conversation can read and write its thread but cannot be
/// re-persisted. Nothing needs it to be -- it is already stored.
#[derive(Clone, Debug, PartialEq)]
pub struct BuyerConversation {
    /// The routing tag every message in this conversation carries, in both
    /// directions.
    pub buyer_public_key: [u8; 32],
    /// Chosen once and echoed by the seller, so a decrypted message that
    /// names a different conversation can be rejected rather than displayed.
    pub conversation_id: ConversationId,
    /// When this conversation was opened, in unix seconds -- the delegate's
    /// eviction order and, on recall, which conversation with a store is the
    /// most recent one to continue.
    pub created_at: i64,
    /// Whether the buyer has said they hold a copy outside this node.
    ///
    /// `false` means the key that reads this conversation exists in exactly
    /// one place, so losing the machine loses it -- and, after Phase 2, the
    /// buyer's recourse against the seller they paid. Only the buyer saying
    /// so clears it; exporting is not saving.
    pub backed_up: bool,
    /// `Some` for a conversation opened in this tab, `None` for one recalled
    /// from the delegate. Prints as `redacted`; see
    /// [`harvest_common::ConversationSecret`].
    secret: Option<harvest_common::ConversationSecret>,
    keys: ConversationKeys,
    /// Whether the harvest delegate has SAID it is keeping this.
    ///
    /// Not "a request was sent": the delegate is the only thing that knows
    /// whether a record was written, and it can refuse -- the node can decline
    /// the write, and the store can be at its cap. A conversation this is
    /// false for dies with the tab, taking the seller's replies with it.
    ///
    /// The buy flow reads this before letting a buyer pay
    /// (`state::PaymentBlocker::ConversationNotKept`), which is the shape
    /// `docs/buyer-conversation-persistence.md` requires of Phase 2: persist
    /// what protects you, confirm the persistence, and only then part with
    /// money.
    kept: bool,
    /// The value a commitment must carry to be THIS buyer's.
    ///
    /// Computed here from the ephemeral secret when the conversation is
    /// opened, and answered by the harvest delegate from its stored copy on
    /// recall -- both through
    /// [`harvest_common::mailbox::order_binding_from_secret`], which is the
    /// only place the derivation exists. See that function for the hole it
    /// closes.
    order_binding: [u8; 32],
    /// The store contract id the delegate keeps this conversation under,
    /// when it is not the id of the store it is shown with (harvest#138).
    ///
    /// A conversation is kept under the id the store had when it was
    /// opened. After the store's contract re-keys it is recalled from that
    /// earlier id and shown with the store's current one, and a request
    /// about it (back up, mark saved, forget) must name the id it is kept
    /// under, or the delegate answers that it holds no such conversation.
    /// `None` for one kept under the store's current id.
    pub kept_under: Option<Vec<u8>>,
    /// The seed of the key this buyer signs with for orders in this
    /// conversation (harvest#53 Phase B), derived like `order_binding`:
    /// here from the secret when opened, and by the delegate on recall.
    /// All-zeros from a delegate that predates the field means none. A
    /// secret, so it prints as `redacted` ([`ReceiptSeed`]).
    receipt_seed: ReceiptSeed,
}

/// The buyer's receipt-key seed (harvest#53 Phase B). A secret -- it signs
/// for the buyer -- so `Debug` never prints it, like [`ConversationKeys`].
#[derive(Clone, Copy, PartialEq, Eq)]
struct ReceiptSeed([u8; 32]);

impl std::fmt::Debug for ReceiptSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceiptSeed(redacted)")
    }
}

impl BuyerConversation {
    /// Open a conversation with the holder of `seller_public_key`.
    pub fn open(seller_public_key: &[u8; 32]) -> Result<Self, String> {
        Self::opened_from(StaticSecret::random(), seller_public_key)
    }

    /// [`Self::open`] from a chosen secret, for this crate's tests.
    ///
    /// Exists so a fixture can hold ONE buyer across several helpers -- a
    /// commitment has to be bound to a particular conversation, and a
    /// conversation with a random secret cannot be named by a fixture built
    /// before it.
    #[cfg(test)]
    pub(crate) fn opened_from_secret_for_test(
        secret: &[u8; 32],
        seller_public_key: &[u8; 32],
    ) -> Result<Self, String> {
        Self::opened_from(StaticSecret::from(*secret), seller_public_key)
    }

    fn opened_from(secret: StaticSecret, seller_public_key: &[u8; 32]) -> Result<Self, String> {
        let buyer_public_key = *PublicKey::from(&secret).as_bytes();
        let shared = secret.diffie_hellman(&PublicKey::from(*seller_public_key));
        if !shared.was_contributory() {
            return Err(
                "this store's published encryption key is not usable (the key exchange \
                        produced no shared secret), so nothing can be encrypted to it"
                    .to_string(),
            );
        }
        Ok(Self {
            buyer_public_key,
            conversation_id: ConversationId::random(),
            created_at: chrono::Utc::now().timestamp(),
            backed_up: false,
            secret: Some(harvest_common::ConversationSecret(secret.to_bytes())),
            keys: ConversationKeys::from_shared_secret(shared.as_bytes()),
            // Nothing has been asked yet, let alone answered.
            kept: false,
            order_binding: harvest_common::mailbox::order_binding_from_secret(&secret.to_bytes()),
            kept_under: None,
            receipt_seed: ReceiptSeed(harvest_common::mailbox::buyer_receipt_seed_from_secret(
                &secret.to_bytes(),
            )),
        })
    }

    /// Rebuild a conversation the delegate kept for this node.
    ///
    /// The keys were derived inside the delegate, from the stored secret and
    /// the seller key the conversation was opened against, so this browser
    /// never sees either.
    pub fn recalled(recalled: &harvest_common::RecalledConversation) -> Self {
        Self {
            buyer_public_key: recalled.buyer_public_key,
            conversation_id: ConversationId(recalled.conversation_id),
            created_at: recalled.created_at,
            backed_up: recalled.backed_up,
            secret: None,
            keys: ConversationKeys {
                to_seller: recalled.buyer_to_seller,
                from_seller: recalled.seller_to_buyer,
            },
            // It came OUT of the delegate's store, so there is nothing left to
            // confirm. A returning buyer required to send a message before
            // they could pay would be a buyer told to do something pointless.
            kept: true,
            // The delegate derived this from the secret it kept, which this
            // browser no longer holds -- so it is carried rather than
            // recomputed. A record written before the field existed answers
            // all-zeros; that is NOT treated as a binding, because a seller
            // is free to sign all-zeros and would then match every
            // conversation in that state. See `usable_order_binding`.
            order_binding: recalled.order_binding,
            kept_under: None,
            // Carried for the same reason: the secret stayed in the delegate.
            receipt_seed: ReceiptSeed(recalled.buyer_receipt_seed),
        }
    }

    /// The value a commitment must carry to be this buyer's.
    pub fn order_binding(&self) -> [u8; 32] {
        self.order_binding
    }

    /// The key this buyer signs with for orders in this conversation, or
    /// `None` when there is none: a recalled conversation whose delegate
    /// answered no seed (all-zeros, the `serde(default)` of an older
    /// delegate). All-zeros is refused rather than used, because it is a
    /// seed ANYONE can derive the key of, and a seller who signed its public
    /// half into an order could then sign as "the buyer".
    pub fn receipt_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        (self.receipt_seed.0 != [0u8; 32])
            .then(|| ed25519_dalek::SigningKey::from_bytes(&self.receipt_seed.0))
    }

    /// The verifying half of [`Self::receipt_signing_key`]: what a
    /// commitment must carry as `buyer_receipt_key` to be payable by this
    /// buyer.
    pub fn buyer_receipt_key(&self) -> Option<[u8; 32]> {
        self.receipt_signing_key()
            .map(|key| key.verifying_key().to_bytes())
    }

    /// The tag an order this conversation asked for carries, for `listing`.
    pub fn listing_tag(&self, listing: &harvest_common::listing::ListingId) -> [u8; 32] {
        self.keys.listing_tag(listing)
    }

    /// The ephemeral secret, for this crate's tests only.
    ///
    /// Exists so a test can check that the binding computed here is the
    /// SHARED derivation applied to this conversation's own secret -- the
    /// browser half of a seam whose delegate half lives in another crate and
    /// whose failure mode is silence.
    #[cfg(test)]
    pub(crate) fn secret_for_test(&self) -> [u8; 32] {
        self.secret
            .expect("a conversation opened in this tab holds its secret")
            .0
    }

    /// The binding to compare a commitment against, or `None` when this
    /// conversation has none that identifies anybody.
    ///
    /// # All-zeros is not a binding, and treating it as one failed OPEN
    ///
    /// [`harvest_common::RecalledConversation::order_binding`] carries
    /// `#[serde(default)]`, so a delegate answer produced before the field
    /// existed decodes to all-zeros and arrives here verbatim. The other side
    /// of the comparison is a field the SELLER chooses and signs -- so a
    /// seller who signs all-zeros matched every conversation in that state at
    /// once, which is the one-commitment-many-buyers hole reopened for a
    /// population.
    ///
    /// Three comments in this repository asserted that could not happen, all
    /// of them reasoning about an *honest* commitment. The threat model is a
    /// malicious seller, who carries whatever value they like.
    ///
    /// So the absence is made explicit at the type rather than left as a
    /// sentinel value for a caller to remember: a conversation with no usable
    /// binding cannot match anything, and
    /// `state::AppState::payment_blockers` refuses rather than comparing.
    /// Pinned by `a_conversation_with_no_usable_binding_cannot_pay`.
    pub fn usable_order_binding(&self) -> Option<[u8; 32]> {
        (self.order_binding != [0u8; 32]).then_some(self.order_binding)
    }

    /// Whether this node's delegate has said it is keeping this conversation.
    pub fn is_kept(&self) -> bool {
        self.kept
    }

    /// Record that the delegate answered `Ok` to keeping this.
    ///
    /// Only the delegate's own answer calls this. Marking on dispatch would
    /// mean a refused write read as a kept conversation, which is the silent
    /// failure the whole persistence mechanism exists to prevent.
    pub fn mark_kept(&mut self) {
        self.kept = true;
    }

    /// What the delegate must be told so this conversation outlives the tab,
    /// or `None` for one it is already keeping.
    ///
    /// The delegate files the record under the PUBLIC half of this secret, so
    /// what is sent here decides the tag a later recall comes back under. It
    /// is the same tag this conversation already carries -- pinned by
    /// `the_delegate_files_a_conversation_under_the_tag_the_mailbox_carries`,
    /// because a disagreement would file the conversation under a tag no
    /// message in the mailbox has and nothing downstream could detect it.
    pub fn to_persist(
        &self,
        store_contract_id: &[u8],
        seller_public_key: &[u8; 32],
        request_id: u64,
    ) -> Option<harvest_common::HarvestDelegateRequest> {
        Some(
            harvest_common::HarvestDelegateRequest::StoreBuyerConversation {
                request_id,
                store_contract_id: store_contract_id.to_vec(),
                secret: self.secret?,
                seller_public_key: *seller_public_key,
                conversation_id: self.conversation_id.0,
                created_at: self.created_at,
            },
        )
    }

    /// Seal one message for the seller.
    pub fn seal(&self, text: String) -> Result<EncryptedMessage, String> {
        seal(
            &self.keys.to_seller,
            &self.buyer_public_key,
            &self.conversation_id,
            MessageContent::Text(text),
        )
    }

    /// Seal a request to buy a listing.
    ///
    /// Deliberately a method on the conversation rather than a free function
    /// taking keys: the request and the ordinary message must travel in the
    /// same thread, under the same tag, or the seller's acceptance comes back
    /// where the buyer is not reading.
    ///
    /// `instant` is the buyer's instant-checkout selection, or `None` for a
    /// quote request.
    pub fn request_order(
        &self,
        listing_id: &harvest_common::listing::ListingId,
        quantity: u32,
        shipping: String,
        note: String,
        instant: Option<InstantSelection>,
    ) -> Result<EncryptedMessage, String> {
        seal(
            &self.keys.to_seller,
            &self.buyer_public_key,
            &self.conversation_id,
            MessageContent::OrderRequest {
                instant,
                listing_id: listing_id.clone(),
                quantity,
                shipping,
                note,
                order_binding: self.order_binding,
                buyer_receipt_key: self.buyer_receipt_key(),
            },
        )
    }

    /// This conversation's messages, in both directions, out of a mailbox
    /// that also holds everybody else's.
    ///
    /// # Why this filters and `read_mailbox` does not
    ///
    /// A buyer is one conversation in a mailbox that may hold up to
    /// [`harvest_common::mailbox::MAX_MESSAGES`] of them. Reporting the rest
    /// as "cannot be read" would be 511 lines of noise about other people's
    /// traffic. The seller is the opposite case: unreadable entries in their
    /// OWN mailbox are something they need told about, so `read_mailbox`
    /// reports them.
    ///
    /// The tag filter is a fast path and not a security boundary. An attacker
    /// can read the tag out of the public mailbox and stamp it on anything
    /// they like -- so the AEAD is what decides, and a forged entry simply
    /// fails to authenticate. What the tag bounds is WORK: without it a buyer
    /// would attempt decryption against every entry in the mailbox.
    pub fn read(&self, messages: &[EncryptedMessage]) -> Vec<ConversationMessage> {
        self.read_with_cost(messages).0
    }

    /// [`Self::read`], and what reading cost.
    ///
    /// The cost is returned because the tag filter is a performance guard
    /// that no assertion about the OUTPUT can pin -- the AEAD refuses
    /// everything the filter would have, so deleting the filter changes only
    /// how much work happens. See
    /// `reading_a_thread_costs_the_thread_and_not_the_mailbox`.
    pub fn read_with_cost(
        &self,
        messages: &[EncryptedMessage],
    ) -> (Vec<ConversationMessage>, ReadCost) {
        let mut cost = ReadCost {
            examined: messages.len(),
            attempted: 0,
        };

        let mut thread: Vec<ConversationMessage> = messages
            .iter()
            .filter(|message| message.sender_public_key == self.buyer_public_key)
            .filter_map(|message| {
                // Addressed-to-the-buyer first: it is the one the buyer is
                // waiting for, and the common case for an entry they did not
                // write themselves.
                for (key, addressing) in [
                    (&self.keys.from_seller, Addressing::ToBuyer),
                    (&self.keys.to_seller, Addressing::ToSeller),
                ] {
                    cost.attempted += 1;
                    let Ok(plaintext) = decrypt_message(message, key) else {
                        continue;
                    };
                    // The conversation id is inside the ciphertext, so only
                    // someone holding the key could have set it. Checking it
                    // stops a reply being spliced from one of this buyer's
                    // conversations into another.
                    if plaintext.conversation_id != self.conversation_id {
                        continue;
                    }
                    return Some(ConversationMessage {
                        addressing,
                        timestamp: message.timestamp,
                        nonce: message.nonce,
                        digest: harvest_common::mailbox::entry_digest(message),
                        content: plaintext.content,
                    });
                }
                None
            })
            .collect();
        // Oldest first: a conversation reads top to bottom, unlike the
        // seller's inbox, which is a queue and reads newest first.
        thread.sort_by_key(|message| (message.timestamp, message.nonce));
        (thread, cost)
    }
}

/// What reading a mailbox cost, so the routing-tag filter can be pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ReadCost {
    /// Entries in the mailbox.
    pub examined: usize,
    /// AEAD attempts made -- at most two per entry the tag admitted, and
    /// zero for every entry it did not.
    pub attempted: usize,
}

/// Which way along a conversation a message was ADDRESSED.
///
/// # This is not authorship, and must never be shown as authorship
///
/// It says which of the two direction keys authenticated the ciphertext, and
/// nothing more. Both parties hold both keys -- the buyer needs
/// `seller_to_buyer` to read replies at all -- so either can encrypt in
/// either direction. A buyer can write a message that arrives in the seller's
/// mailbox addressed as though the seller had written it, and the reverse.
///
/// That is not fixable with more crypto here: a symmetric Diffie-Hellman
/// secret cannot distinguish its two holders, and only a per-message
/// signature could. See [`harvest_common::mailbox::MessageDirection`] for
/// what direction separation does and does not defend, and
/// `components::message_view` for the wording that does not overclaim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addressing {
    /// Encrypted under the buyer-to-seller key.
    ToSeller,
    /// Encrypted under the seller-to-buyer key.
    ToBuyer,
}

/// One message of a conversation, as the buyer sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct ConversationMessage {
    /// Which direction key authenticated it -- **not** who wrote it. See
    /// [`Addressing`].
    pub addressing: Addressing,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The mailbox nonce, which identifies nothing.
    ///
    /// It was the contract's identity for a message until 2026-09-05, and is
    /// now just a field the writer fills in -- the contract keys on
    /// [`harvest_common::mailbox::entry_digest`], and so does every client.
    /// Kept because it is part of the entry and the AEAD binds it; used to
    /// recognise nothing. See [`Self::digest`].
    pub nonce: [u8; 24],
    /// [`harvest_common::mailbox::entry_digest`] of the entry this came from:
    /// what a client compares against to know whether this is a message it
    /// sent itself. The counterparty can reproduce the nonce; they cannot
    /// reproduce this without sending the identical message.
    pub digest: [u8; 32],
    pub content: MessageContent,
}

/// Seal the seller's reply into their own mailbox.
///
/// `buyer_public_key` is echoed as the routing tag rather than replaced with
/// the seller's own key: it is what lets the buyer find their thread, and
/// naming the seller instead would tell every reader which entries are
/// replies while telling the buyer nothing.
pub fn seal_reply(
    keys: &ConversationKeys,
    buyer_public_key: &[u8],
    conversation_id: &ConversationId,
    text: String,
) -> Result<EncryptedMessage, String> {
    let tag: [u8; 32] = buyer_public_key.try_into().map_err(|_| {
        format!(
            "conversation tag is {} bytes, not 32",
            buyer_public_key.len()
        )
    })?;
    seal(
        &keys.from_seller,
        &tag,
        conversation_id,
        MessageContent::Text(text),
    )
}

/// Seal the seller's acceptance: the id of the commitment they just
/// published, addressed back down the buyer's own thread.
///
/// Sent in the seller-to-buyer direction for a reason a reader can check:
/// `an_acceptance_names_the_order_and_is_addressed_to_the_buyer` fails if this
/// uses the other key, and the buyer's side ignores an acceptance addressed
/// the other way. Both parties hold both keys, so the direction is not proof
/// of authorship -- it only stops a buyer's own composition being read back as
/// the seller's answer.
pub fn seal_order_accepted(
    keys: &ConversationKeys,
    buyer_public_key: &[u8],
    conversation_id: &ConversationId,
    order_id: &harvest_common::payment::OrderId,
) -> Result<EncryptedMessage, String> {
    let tag: [u8; 32] = buyer_public_key.try_into().map_err(|_| {
        format!(
            "conversation tag is {} bytes, not 32",
            buyer_public_key.len()
        )
    })?;
    seal(
        &keys.from_seller,
        &tag,
        conversation_id,
        MessageContent::OrderAccepted {
            order_id: order_id.clone(),
        },
    )
}

/// The one place a message is built, whichever direction it travels: the
/// shared [`harvest_common::sealed::seal`], stamped with this browser's clock.
fn seal(
    key: &[u8; 32],
    tag: &[u8; 32],
    conversation_id: &ConversationId,
    content: MessageContent,
) -> Result<EncryptedMessage, String> {
    harvest_common::sealed::seal(key, tag, conversation_id, content, chrono::Utc::now())
}

/// [`harvest_common::sealed::encrypt_message`], stamped with this browser's
/// clock.
pub fn encrypt_message(
    plaintext: &PlaintextMessage,
    tag: &[u8; 32],
    aes_key: &[u8; 32],
) -> Result<EncryptedMessage, String> {
    harvest_common::sealed::encrypt_message(plaintext, tag, aes_key, chrono::Utc::now())
}

/// [`seal`], reachable from this crate's tests.
///
/// Exists so a test can seal a message the production paths deliberately
/// cannot -- an acceptance in the buyer-to-seller direction, say, which is
/// exactly what a buyer's own composition would look like and what the buyer
/// side has to refuse.
#[cfg(test)]
pub(crate) fn seal_for_test(
    key: &[u8; 32],
    tag: &[u8; 32],
    conversation_id: &ConversationId,
    content: MessageContent,
) -> Result<EncryptedMessage, String> {
    seal(key, tag, conversation_id, content)
}

/// One message in a seller's mailbox, as far as this browser can read it.
///
/// Two variants rather than dropping what will not decrypt. The mailbox is
/// open-write -- anyone at all may deposit bytes in it -- so unreadable
/// entries are the NORMAL case, not a fault: junk, spam, messages encrypted
/// to a key this seller no longer holds. Silently hiding them would leave the
/// seller with a count that never matches what they see and no way to tell
/// "nobody wrote to me" from "I cannot read what they wrote".
///
/// `Readable` is the larger variant by the size of an instant-checkout
/// selection. One is built per mailbox message on each read, at most
/// `MAX_MESSAGES` of them, so boxing it would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum MailboxEntry {
    /// Decrypted successfully. The AES-GCM tag verified, so these bytes were
    /// written by someone holding the conversation key -- which for an
    /// honestly-derived key means the holder of `conversation`, or this
    /// seller themselves.
    Readable {
        /// The conversation's routing tag: the buyer's ephemeral public key.
        conversation: Vec<u8>,
        /// The conversation id the buyer chose, recovered from inside the
        /// ciphertext.
        ///
        /// Carried out rather than discarded because the seller needs it to
        /// reply: a reply naming a different id is refused by the buyer
        /// (`a_reply_naming_another_conversation_is_not_shown`), so the only
        /// place a seller can learn the right one is a message they decrypted.
        conversation_id: ConversationId,
        /// The mailbox nonce, which identifies nothing: public, chosen by
        /// the writer, and no longer the contract's identity for a message
        /// either. Recognition is by `digest`.
        nonce: [u8; 24],
        /// [`harvest_common::mailbox::entry_digest`]: the identity a client
        /// compares against to know whether it sent this itself.
        digest: [u8; 32],
        /// Which direction key authenticated it -- **not** who wrote it. See
        /// [`Addressing`]. A third party cannot produce either direction; the
        /// COUNTERPARTY can produce both.
        addressing: Addressing,
        timestamp: chrono::DateTime<chrono::Utc>,
        content: MessageContent,
    },
    /// Present and not readable, with the reason.
    Unreadable {
        conversation: Vec<u8>,
        nonce: [u8; 24],
        /// As on [`Self::Readable`]: the identity a client uses to recognise
        /// its own writing, which the nonce is not.
        digest: [u8; 32],
        timestamp: chrono::DateTime<chrono::Utc>,
        why: String,
    },
}

impl MailboxEntry {
    pub fn timestamp(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            MailboxEntry::Readable { timestamp, .. }
            | MailboxEntry::Unreadable { timestamp, .. } => *timestamp,
        }
    }

    /// The conversation this entry belongs to, readable or not.
    pub fn conversation(&self) -> &[u8] {
        match self {
            MailboxEntry::Readable { conversation, .. }
            | MailboxEntry::Unreadable { conversation, .. } => conversation,
        }
    }

    /// What this client compares against to know whether it sent this entry.
    pub fn digest(&self) -> [u8; 32] {
        match self {
            MailboxEntry::Readable { digest, .. } | MailboxEntry::Unreadable { digest, .. } => {
                *digest
            }
        }
    }
}

/// Read a mailbox with whatever conversation keys are on hand.
///
/// `keys` maps a conversation's routing tag to the key pair the seller's
/// delegate derived for it. A message whose tag is absent from the map is
/// [`MailboxEntry::Unreadable`] with "no key yet" rather than an error: the
/// keys arrive from the delegate a round trip after the mailbox state does,
/// so this is the ordinary state of the screen for a moment.
///
/// A message that has a key and still fails is also `Unreadable`, and the two
/// reasons are kept distinct because they mean different things -- the first
/// resolves itself, the second does not.
///
/// Pure, so the seller's whole read path is testable without a browser or a
/// node.
pub fn read_mailbox(
    messages: &[EncryptedMessage],
    keys: &std::collections::HashMap<Vec<u8>, ConversationKeys>,
) -> Vec<MailboxEntry> {
    let mut entries: Vec<MailboxEntry> = messages
        .iter()
        .map(|message| {
            let conversation = message.sender_public_key.clone();
            let digest = harvest_common::mailbox::entry_digest(message);
            let Some(pair) = keys.get(&conversation) else {
                return MailboxEntry::Unreadable {
                    conversation,
                    nonce: message.nonce,
                    digest,
                    timestamp: message.timestamp,
                    why: "waiting for the key from your delegate".to_string(),
                };
            };
            // Inbound first: it is what a seller opens their mailbox for, and
            // their own replies are the smaller half.
            let mut last_error = String::new();
            for (key, addressing) in [
                (&pair.to_seller, Addressing::ToSeller),
                (&pair.from_seller, Addressing::ToBuyer),
            ] {
                match decrypt_message(message, key) {
                    Ok(plaintext) => {
                        return MailboxEntry::Readable {
                            conversation,
                            conversation_id: plaintext.conversation_id,
                            nonce: message.nonce,
                            digest,
                            addressing,
                            timestamp: message.timestamp,
                            content: plaintext.content,
                        }
                    }
                    Err(why) => last_error = why,
                }
            }
            MailboxEntry::Unreadable {
                conversation,
                nonce: message.nonce,
                digest,
                timestamp: message.timestamp,
                why: last_error,
            }
        })
        .collect();
    // Newest first. `timestamp` is chosen by whoever wrote the message and is
    // signed by nobody (see `harvest_common::mailbox`), so this is a display
    // order and NOT evidence about when anything happened.
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.timestamp()));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use harvest_common::mailbox::MAX_MESSAGES;
    use std::collections::HashMap;
    use x25519_dalek::StaticSecret;

    /// A seller, reconstructed from nothing but a long-term secret -- which
    /// is what the harvest delegate holds. Deliberately NOT built out of this
    /// module's own types, so a test cannot pass because the buyer's half and
    /// the seller's half drifted together.
    pub(super) struct Seller {
        secret: StaticSecret,
    }

    impl Seller {
        pub(super) fn new(seed: u8) -> Self {
            Self {
                secret: StaticSecret::from([seed; 32]),
            }
        }

        pub(super) fn public_key(&self) -> [u8; 32] {
            *PublicKey::from(&self.secret).as_bytes()
        }

        /// The keys the delegate would answer for one conversation tag.
        pub(super) fn keys_for(&self, tag: &[u8]) -> ConversationKeys {
            let peer: [u8; 32] = tag.try_into().expect("32-byte tag");
            let shared = self
                .secret
                .diffie_hellman(&PublicKey::from(peer))
                .to_bytes();
            ConversationKeys {
                to_seller: conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
                from_seller: conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
            }
        }

        pub(super) fn inbox(&self, messages: &[EncryptedMessage]) -> Vec<MailboxEntry> {
            let mut keys = HashMap::new();
            for message in messages {
                if message.sender_public_key.len() == 32 {
                    keys.insert(
                        message.sender_public_key.clone(),
                        self.keys_for(&message.sender_public_key),
                    );
                }
            }
            read_mailbox(messages, &keys)
        }
    }

    fn text(entry: &MailboxEntry) -> String {
        match entry {
            MailboxEntry::Readable {
                content: MessageContent::Text(text),
                ..
            } => text.clone(),
            other => panic!("expected readable text, got {other:?}"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let seller = Seller::new(11);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let sealed = buyer.seal("Hello from buyer!".into()).expect("seal");
        assert_ne!(
            sealed.ciphertext,
            harvest_common::to_cbor(&"Hello from buyer!").unwrap()
        );

        let inbox = seller.inbox(&[sealed]);
        assert_eq!(text(&inbox[0]), "Hello from buyer!");
    }

    /// The whole buyer path, against a seller who exists only as an X25519
    /// secret -- which is all the delegate is, from this module's point of
    /// view.
    #[test]
    fn a_sealed_message_is_readable_by_the_seller_who_holds_the_secret() {
        let seller = Seller::new(17);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let sealed = buyer
            .seal("is the blue one still available?".into())
            .expect("seal");

        assert_ne!(
            sealed.sender_public_key,
            seller.public_key().to_vec(),
            "the tag must be the BUYER's key, not the seller's"
        );
        assert_eq!(sealed.sender_public_key, buyer.buyer_public_key.to_vec());

        let inbox = seller.inbox(&[sealed]);
        assert_eq!(text(&inbox[0]), "is the blue one still available?");
        match &inbox[0] {
            MailboxEntry::Readable { addressing, .. } => assert_eq!(
                addressing,
                &Addressing::ToSeller,
                "an inbound message is addressed to the seller"
            ),
            other => panic!("expected readable: {other:?}"),
        }
    }

    /// The seller replies into their own mailbox and the buyer reads it --
    /// with no buyer mailbox, no buyer identity and no second contract.
    #[test]
    fn the_seller_replies_into_their_own_mailbox_and_the_buyer_reads_it() {
        let seller = Seller::new(23);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let question = buyer.seal("do you ship to Ireland?".into()).expect("seal");

        // The seller reads it, learns the conversation, and answers.
        let keys = seller.keys_for(&question.sender_public_key);
        let reply = seal_reply(
            &keys,
            &question.sender_public_key,
            &buyer.conversation_id,
            "yes, ten euro postage".into(),
        )
        .expect("reply");

        let mailbox = vec![question.clone(), reply.clone()];
        let thread = buyer.read(&mailbox);

        assert_eq!(thread.len(), 2, "the buyer sees both halves");
        assert_eq!(
            thread[0].addressing,
            Addressing::ToSeller,
            "oldest first: the buyer's question"
        );
        assert_eq!(
            thread[1].addressing,
            Addressing::ToBuyer,
            "then the seller's reply"
        );
        assert_eq!(
            thread[1].content,
            MessageContent::Text("yes, ten euro postage".into())
        );
        assert_eq!(
            thread[0].nonce, question.nonce,
            "the buyer's own message is identified by its nonce, so a caller can tell it landed"
        );
    }

    /// **A copy of the buyer's own message must not read as a reply.**
    ///
    /// Anyone can read the mailbox and anyone can write to it, so this attack
    /// is a copy and a paste: no key, no relationship with either party. The
    /// message it would forge is the one the buyer is waiting for, and in the
    /// phase this mechanism exists for that message is the buyer's only
    /// authorization to complain.
    ///
    /// Direction separation makes it impossible rather than detectable.
    /// Observed red on 2026-09-05 by deriving both keys under
    /// `MessageDirection::BuyerToSeller`.
    #[test]
    fn a_copy_of_the_buyers_own_message_does_not_read_as_a_reply() {
        let seller = Seller::new(29);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let original = buyer.seal("I will pay tomorrow".into()).expect("seal");

        // The forgery: the same ciphertext under a nonce the mailbox has not
        // seen, so its dedup does not refuse it.
        //
        // Only bytes 12..24 are touched. The first 12 ARE the AES-GCM nonce,
        // so changing those breaks decryption for a reason that has nothing
        // to do with direction -- an earlier version of this test replaced
        // the whole 24 bytes and passed for that reason, which made it a test
        // of the wrong thing. Bytes 12..24 are dedup padding and feed nothing
        // else, so this is the mutation an attacker would actually make.
        let mut forged = original.clone();
        forged.nonce[12..].copy_from_slice(&[0xAB; 12]);

        let thread = buyer.read(&[original.clone(), forged]);

        assert!(
            thread
                .iter()
                .all(|message| message.addressing == Addressing::ToSeller),
            "a copy of the buyer's own message was presented as a reply from the seller"
        );
        // And the original is still readable, so the assertion above is not
        // passing because nothing decrypted at all.
        assert_eq!(thread.len(), 1, "the re-nonced copy does not authenticate");
        assert_eq!(
            thread[0].content,
            MessageContent::Text("I will pay tomorrow".into())
        );
    }

    /// **A message must not be replayable.**
    ///
    /// The mailbox dedupes on the full 24-byte nonce, but only the first 12
    /// are the AES-GCM nonce -- bytes 12..24 are padding that feeds dedup and
    /// nothing else. Randomise them and the same ciphertext arrives again as
    /// a new message: the buyer sees whatever they were told, twice, and an
    /// attacker chooses when.
    ///
    /// That matters beyond duplication. The eviction ranking is
    /// `(timestamp, nonce)`, so a replay is also a way to occupy mailbox
    /// slots with content the attacker cannot read but can resubmit at will.
    ///
    /// Closed by authenticating the whole envelope, not just the ciphertext:
    /// every field of `EncryptedMessage` except the ciphertext itself is
    /// bound in as AES-GCM associated data, so ANY change to any of them
    /// fails the tag. The wire layout is unchanged -- associated data is
    /// derived from the fields, never transmitted.
    ///
    /// Observed red on 2026-09-05, before the associated data existed: the
    /// replay decrypted and the buyer's thread held two identical messages.
    #[test]
    fn a_replayed_message_with_fresh_padding_does_not_authenticate() {
        let seller = Seller::new(61);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let original = buyer
            .seal("send it to the usual address".into())
            .expect("seal");

        let mut replayed = original.clone();
        replayed.nonce[12..].copy_from_slice(&[0x5A; 12]);
        assert_ne!(
            replayed.nonce, original.nonce,
            "precondition: the mailbox would treat this as a new message"
        );
        assert_eq!(
            replayed.nonce[..12],
            original.nonce[..12],
            "precondition: the AES nonce is untouched, so only the envelope binding can refuse it"
        );

        let thread = buyer.read(&[original.clone(), replayed.clone()]);
        assert_eq!(
            thread.len(),
            1,
            "a replay was accepted: the buyer sees the same message twice"
        );

        // The seller's side refuses it too, and for the same reason.
        let inbox = seller.inbox(&[original, replayed]);
        assert_eq!(inbox.len(), 2, "both entries are present in the mailbox");
        let readable = inbox
            .iter()
            .filter(|entry| matches!(entry, MailboxEntry::Readable { .. }))
            .count();
        assert_eq!(readable, 1, "only the genuine message authenticates");
    }

    /// The other envelope fields are bound too, so a message cannot be
    /// re-timestamped to change where it ranks for eviction, nor re-tagged
    /// into another conversation.
    ///
    /// Re-timestamping is the sharper of the two: the eviction ranking is
    /// `(timestamp, nonce)`, so moving a genuine message to the top of it is
    /// a way to make somebody else's traffic survive a flood -- or, with the
    /// nonce unchanged, to have it replace itself at a rank of the attacker's
    /// choosing.
    #[test]
    fn the_whole_envelope_is_authenticated() {
        let seller = Seller::new(67);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let original = buyer.seal("hello".into()).expect("seal");

        let mut re_timestamped = original.clone();
        re_timestamped.timestamp =
            chrono::DateTime::from_timestamp(2_000_000_000, 0).expect("timestamp");

        let mut re_tagged = original.clone();
        re_tagged.sender_public_key = vec![0x77; 32];

        let mut re_labelled = original.clone();
        re_labelled.conversation_id = ConversationId([0x88; 32]);

        for (what, tampered) in [
            ("timestamp", re_timestamped),
            ("routing tag", re_tagged),
            ("conversation id", re_labelled),
        ] {
            assert_eq!(
                buyer.read(&[tampered]).len(),
                0,
                "a message with an altered {what} authenticated"
            );
        }

        // And the untouched original still reads, so the assertions above are
        // not passing because nothing decrypts.
        assert_eq!(buyer.read(&[original]).len(), 1);
    }

    /// A reply carrying a different conversation id is not shown, even though
    /// it decrypts.
    ///
    /// Only the seller holds the key, so this is not an outsider attack -- it
    /// is a splice, moving an answer from one of this buyer's conversations
    /// into another. Cheap to refuse, and it makes `conversation_id` mean
    /// something rather than being carried and ignored.
    #[test]
    fn a_reply_naming_another_conversation_is_not_shown() {
        let seller = Seller::new(31);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let keys = seller.keys_for(&buyer.buyer_public_key);

        let honest = seal_reply(
            &keys,
            &buyer.buyer_public_key,
            &buyer.conversation_id,
            "yours".into(),
        )
        .expect("reply");
        let spliced = seal_reply(
            &keys,
            &buyer.buyer_public_key,
            &ConversationId([0xEE; 32]),
            "somebody else's".into(),
        )
        .expect("reply");

        let thread = buyer.read(&[honest, spliced]);
        assert_eq!(thread.len(), 1);
        assert_eq!(thread[0].content, MessageContent::Text("yours".into()));
    }

    /// A buyer sees their own conversation and nobody else's, out of a
    /// mailbox holding both.
    #[test]
    fn a_buyer_sees_only_their_own_conversation() {
        let seller = Seller::new(37);
        let alice = BuyerConversation::open(&seller.public_key()).expect("open");
        let bob = BuyerConversation::open(&seller.public_key()).expect("open");

        let mailbox = vec![
            alice.seal("alice here".into()).expect("seal"),
            bob.seal("bob here".into()).expect("seal"),
        ];

        let alices = alice.read(&mailbox);
        assert_eq!(alices.len(), 1);
        assert_eq!(alices[0].content, MessageContent::Text("alice here".into()));

        // The seller sees both, and they are separate conversations.
        let inbox = seller.inbox(&mailbox);
        assert_eq!(inbox.len(), 2);
        assert_ne!(inbox[0].conversation(), inbox[1].conversation());
    }

    /// **The worst case a buyer can be pushed into**, which is not the same
    /// as the common case.
    ///
    /// The routing tag is in the clear in a public mailbox, so an attacker
    /// can read a buyer's tag and stamp it on a full cap's worth of entries.
    /// The buyer then attempts decryption against all of them. This asserts
    /// the buyer still finds their own thread and reports nothing else --
    /// the cost of doing so is measured separately and recorded in
    /// `docs/messaging-privacy.md`.
    #[test]
    fn a_full_cap_flood_tagged_with_the_buyers_key_does_not_hide_their_thread() {
        let seller = Seller::new(41);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let mine = buyer.seal("mine".into()).expect("seal");
        let mut mailbox = vec![mine.clone()];
        for i in 0..(MAX_MESSAGES - 1) {
            let mut junk = mine.clone();
            junk.nonce = {
                let mut nonce = [0u8; 24];
                nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
                nonce
            };
            junk.ciphertext = vec![0xCD; 1024];
            mailbox.push(junk);
        }
        assert_eq!(mailbox.len(), MAX_MESSAGES);

        let thread = buyer.read(&mailbox);
        assert_eq!(thread.len(), 1, "only the real message authenticates");
        assert_eq!(thread[0].content, MessageContent::Text("mine".into()));
    }

    /// Two conversations with the same seller carry different tags, so a
    /// passive observer cannot tell they came from one buyer.
    ///
    /// This is what `EphemeralSecret` is for, and it is a property that a
    /// perfectly reasonable optimisation -- one keypair per store, reused --
    /// would silently delete.
    #[test]
    fn each_conversation_carries_a_fresh_tag() {
        let seller = Seller::new(43);
        let first = BuyerConversation::open(&seller.public_key()).expect("open");
        let second = BuyerConversation::open(&seller.public_key()).expect("open");

        assert_ne!(first.buyer_public_key, second.buyer_public_key);
        assert_ne!(first.conversation_id, second.conversation_id);

        let a = first.seal("hello".into()).expect("seal");
        let b = first.seal("hello".into()).expect("seal");
        assert_ne!(a.nonce, b.nonce, "nonces must not repeat within one thread");
    }

    /// The seller's read path, over a mailbox holding one readable message,
    /// one whose key has not arrived, one written to somebody else, and one
    /// of the seller's own replies.
    #[test]
    fn a_mailbox_is_read_with_the_keys_on_hand_and_says_so_when_it_cannot_be() {
        let seller = Seller::new(21);
        let stranger = Seller::new(99);

        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let unkeyed_buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let foreign_buyer = BuyerConversation::open(&stranger.public_key()).expect("open");

        let mine = buyer.seal("readable".into()).expect("seal");
        let unkeyed = unkeyed_buyer.seal("no key yet".into()).expect("seal");
        let foreign = foreign_buyer.seal("not for us".into()).expect("seal");
        let own_reply = seal_reply(
            &seller.keys_for(&buyer.buyer_public_key),
            &buyer.buyer_public_key,
            &buyer.conversation_id,
            "answered".into(),
        )
        .expect("reply");

        let mut keys = HashMap::new();
        keys.insert(
            mine.sender_public_key.clone(),
            seller.keys_for(&mine.sender_public_key),
        );
        // The foreign message DOES get a key -- the one our secret derives
        // against its tag -- and it is the wrong key, which is the point.
        keys.insert(
            foreign.sender_public_key.clone(),
            seller.keys_for(&foreign.sender_public_key),
        );
        keys.insert(
            own_reply.sender_public_key.clone(),
            seller.keys_for(&own_reply.sender_public_key),
        );

        let entries = read_mailbox(
            &[
                mine.clone(),
                unkeyed.clone(),
                foreign.clone(),
                own_reply.clone(),
            ],
            &keys,
        );
        assert_eq!(entries.len(), 4, "nothing may be dropped");

        // Located by (tag, timestamp) rather than by position, because
        // `read_mailbox` reorders.
        let by_nonce = |nonce: [u8; 24]| -> &MailboxEntry {
            let index = [mine.nonce, unkeyed.nonce, foreign.nonce, own_reply.nonce]
                .iter()
                .position(|candidate| *candidate == nonce)
                .expect("known nonce");
            let sources = [&mine, &unkeyed, &foreign, &own_reply];
            let source = sources[index];
            entries
                .iter()
                .find(|entry| {
                    entry.conversation() == source.sender_public_key
                        && entry.timestamp() == source.timestamp
                })
                .expect("every message must appear")
        };

        assert_eq!(text(by_nonce(mine.nonce)), "readable");
        match by_nonce(unkeyed.nonce) {
            MailboxEntry::Unreadable { why, .. } => assert!(
                why.contains("waiting"),
                "a missing key must be reported as temporary: {why}"
            ),
            other => panic!("expected an unreadable entry: {other:?}"),
        }
        match by_nonce(foreign.nonce) {
            MailboxEntry::Unreadable { why, .. } => assert!(
                !why.contains("waiting"),
                "a message that will never decrypt must not read as merely pending: {why}"
            ),
            other => panic!("a message we hold no key for must not read as decrypted: {other:?}"),
        }
        match by_nonce(own_reply.nonce) {
            MailboxEntry::Readable {
                addressing,
                content,
                ..
            } => {
                assert_eq!(
                    addressing,
                    &Addressing::ToBuyer,
                    "the seller's own reply is addressed to the buyer"
                );
                assert_eq!(content, &MessageContent::Text("answered".into()));
            }
            other => panic!("the seller must be able to read their own reply: {other:?}"),
        }
    }

    /// Newest first, so a busy mailbox shows the message that just arrived.
    #[test]
    fn a_mailbox_is_read_newest_first() {
        let at = |secs: i64, nonce: u8| EncryptedMessage {
            conversation_id: ConversationId([0u8; 32]),
            sender_public_key: vec![nonce; 32],
            ciphertext: vec![1u8; 16],
            timestamp: chrono::DateTime::from_timestamp(secs, 0).expect("timestamp"),
            nonce: [nonce; 24],
        };

        let entries = read_mailbox(&[at(100, 1), at(300, 3), at(200, 2)], &HashMap::new());
        let order: Vec<i64> = entries.iter().map(|e| e.timestamp().timestamp()).collect();
        assert_eq!(order, vec![300, 200, 100]);
    }

    /// **A message too large to be accepted must be refused where the buyer
    /// can be told**, not sealed and dispatched into silence.
    ///
    /// Found by accident on 2026-09-05: a measurement fixture asked for a
    /// message near the top padding bucket, and every one of them was
    /// silently dropped by `apply_delta` because the CBOR envelope pushed it
    /// past `MAX_MESSAGE_BYTES`. The buyer's UI would have shown "handed to
    /// your Freenet node" and the message would never have appeared --
    /// indistinguishable, from the buyer's side, from the write race.
    ///
    /// Observed red before `seal` learned to check.
    #[test]
    fn a_message_too_large_for_a_mailbox_is_refused_at_the_compose_box() {
        use harvest_common::mailbox::{message_bytes, MailboxStateV1, MAX_MESSAGE_BYTES};

        let seller = Seller::new(53);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        let error = buyer
            .seal("x".repeat(harvest_common::mailbox::LARGEST_BUCKET))
            .expect_err("a message that no mailbox would accept must be refused");
        assert!(
            error.contains("too long"),
            "the refusal must be something a compose box can show: {error}"
        );

        // The largest message that IS accepted really is accepted, so the
        // check is not simply refusing everything near the limit.
        let big = buyer
            .seal("x".repeat(60_000))
            .expect("a large but legal message must still send");
        assert!(message_bytes(&big) <= MAX_MESSAGE_BYTES);
        let mut state = MailboxStateV1::default();
        state.apply_delta(&Some(vec![big.clone()])).unwrap();
        assert_eq!(
            state.messages.len(),
            1,
            "a message the compose box accepted must be one a mailbox accepts"
        );
    }

    /// The same for the seller's side, which composes into the same mailbox
    /// under the same cap.
    #[test]
    fn an_oversized_reply_is_refused_at_the_compose_box() {
        let seller = Seller::new(59);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let keys = seller.keys_for(&buyer.buyer_public_key);

        let error = seal_reply(
            &keys,
            &buyer.buyer_public_key,
            &buyer.conversation_id,
            "x".repeat(harvest_common::mailbox::LARGEST_BUCKET),
        )
        .expect_err("must be refused");
        assert!(error.contains("too long"), "got: {error}");
    }

    /// **The routing-tag filter is a performance guard, and this pins it as
    /// one.**
    ///
    /// Correctness does not depend on it: the AEAD refuses anything not for
    /// this buyer either way, and since the envelope binding the tag is
    /// authenticated too. So no assertion about WHAT comes back can fail when
    /// the filter is deleted -- verified, 214 tests stayed green with it
    /// removed.
    ///
    /// What the filter buys is that a buyer's read costs their own thread
    /// rather than the whole mailbox. Deleting it silently turns an O(thread)
    /// read into a full trial-decrypt on every fetch, which at the byte
    /// budget is the 20.7 ms worst case in `docs/messaging-privacy.md` on
    /// every update notification. That is not a property any output can
    /// express, so the cost is measured directly instead.
    ///
    /// Observed red by deleting the `sender_public_key` filter: attempted
    /// went from 2 to 512.
    #[test]
    fn reading_a_thread_costs_the_thread_and_not_the_mailbox() {
        use harvest_common::mailbox::MAX_MESSAGES;

        let seller = Seller::new(71);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let stranger = BuyerConversation::open(&seller.public_key()).expect("open");

        let mut mailbox = vec![
            buyer.seal("mine".into()).expect("seal"),
            seal_reply(
                &seller.keys_for(&buyer.buyer_public_key),
                &buyer.buyer_public_key,
                &buyer.conversation_id,
                "answered".into(),
            )
            .expect("reply"),
        ];
        // Everyone else's traffic, which this buyer must not pay to examine.
        let noise = stranger.seal("not yours".into()).expect("seal");
        for i in 0..(MAX_MESSAGES - mailbox.len()) {
            let mut other = noise.clone();
            other.nonce = {
                let mut n = [0u8; 24];
                n[..8].copy_from_slice(&(i as u64).to_be_bytes());
                n
            };
            mailbox.push(other);
        }
        assert_eq!(mailbox.len(), MAX_MESSAGES);

        let (thread, cost) = buyer.read_with_cost(&mailbox);

        assert_eq!(thread.len(), 2, "the buyer still sees their own thread");
        assert_eq!(cost.examined, MAX_MESSAGES);

        // Three, not two: the reply key is tried first, so the buyer's OWN
        // message costs two attempts and the reply costs one. What matters is
        // the shape rather than the constant -- attempts are bounded by the
        // thread, at most two per entry the tag admitted, and do not grow with
        // the mailbox.
        assert_eq!(
            cost.attempted, 3,
            "a buyer paid to attempt decryption on somebody else's traffic: {} of {} entries",
            cost.attempted, cost.examined
        );
        assert!(
            cost.attempted <= 2 * thread.len(),
            "attempts must be bounded by the thread"
        );
        assert!(
            cost.attempted * 100 < cost.examined,
            "attempts scaled with the mailbox rather than the thread"
        );
    }

    /// **THIS TEST PINS A LIMITATION, NOT A DEFENCE.**
    ///
    /// Direction separation stops a THIRD PARTY reflecting a copied message.
    /// It cannot stop the COUNTERPARTY, because both parties derive both keys
    /// from the same symmetric Diffie-Hellman secret -- the buyer needs the
    /// seller-to-buyer key in order to read replies at all. So a buyer can
    /// place a message in the seller's mailbox that authenticates under the
    /// seller-to-buyer key, and the seller's client cannot tell it from
    /// something the seller wrote.
    ///
    /// Verified before this was written: a seller's inbox displayed
    /// "as agreed, I confess" as the seller's own reply, written by the
    /// buyer.
    ///
    /// It is not fixable with more crypto at this layer -- a symmetric secret
    /// cannot distinguish its two holders, and only a per-message signature
    /// could. So the fix is that [`Addressing`] means direction and the UI
    /// says direction, and anything whose authenticity matters carries its
    /// own signature.
    ///
    /// **If this test ever goes red, do not make it pass.** It would mean
    /// something now distinguishes the two holders, which is a real
    /// improvement -- invert the assertion and delete this comment.
    #[test]
    fn known_limit_the_counterparty_can_write_in_either_direction() {
        let seller = Seller::new(73);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");

        // The keys the BUYER holds -- the same pair the seller's delegate
        // derives, which is the whole point.
        let both_keys = seller.keys_for(&buyer.buyer_public_key);

        let forged = seal_reply(
            &both_keys,
            &buyer.buyer_public_key,
            &buyer.conversation_id,
            "as agreed, I confess".into(),
        )
        .expect("the buyer can seal in the seller's direction");

        match &seller.inbox(&[forged])[0] {
            MailboxEntry::Readable {
                addressing,
                content,
                ..
            } => {
                assert_eq!(
                    addressing,
                    &Addressing::ToBuyer,
                    "the channel cannot tell this was not the seller's own message"
                );
                assert_eq!(
                    content,
                    &MessageContent::Text("as agreed, I confess".into())
                );
            }
            other => panic!("expected a readable entry: {other:?}"),
        }
    }

    /// **THIS TEST PINS A LIMITATION, NOT A DEFENCE: a deliberate nonce
    /// collision reuses the keystream, and Harvest's AAD does not help.**
    ///
    /// AES-GCM is a stream cipher underneath, so one key plus one 12-byte
    /// nonce means two messages share a keystream: `C1 xor C2 == P1 xor P2`,
    /// and anyone who guesses one plaintext reads the other. (GHASH's
    /// authentication subkey is also recoverable, the sharper half of the
    /// classic result, not asserted here.)
    ///
    /// # Why this goes through Harvest's own construction
    ///
    /// An earlier version of this test used a bare key, a bare nonce and a
    /// bare `aes_gcm` call, and review was right that it pinned the crate
    /// rather than anything of ours -- it would have passed unchanged if
    /// Harvest's key derivation, padding and associated data had all been
    /// deleted. It now derives the key with
    /// [`conversation_key_from_dh`], pads with
    /// [`harvest_common::mailbox::pad_to_bucket`], and binds
    /// [`harvest_common::mailbox::message_aad`] exactly as
    /// [`encrypt_message`] does.
    ///
    /// That turns it into a claim about Harvest specifically, and one worth
    /// making, because the obvious reading of `message_aad` is wrong: the
    /// mailbox nonce IS bound into the associated data, which stops an
    /// envelope field being altered -- and does **nothing** about keystream
    /// reuse, because AAD authenticates and does not randomise. Two messages
    /// with the same nonce have the same AAD contribution and the same
    /// keystream.
    ///
    /// # Why it is a documented limit and not a bug
    ///
    /// [`encrypt_message`] draws all 24 nonce bytes from `getrandom` per
    /// message, so an honest client never collides -- this test has to reach
    /// past it to the cipher to construct one at all, and that freshness is
    /// pinned separately (making the nonce deterministic kills three tests).
    /// Creating the collision needs the conversation key, so the only party
    /// who can is one who can already read both messages. It buys an attacker
    /// nothing they did not have. What it rules out is a future change that
    /// derives the nonce from anything less than fresh randomness.
    ///
    /// # What routing it through Harvest does and does not buy
    ///
    /// Said plainly, because the obvious reading is too generous. The xor
    /// assertion holds for ANY key and ANY associated data -- substituting a
    /// zero key leaves it green -- so using our key derivation does not make
    /// that assertion Harvest-specific, and it cannot: the property is the
    /// cipher's. What the Harvest symbols buy is that the test tracks OUR
    /// construction rather than a textbook one, so a change to the key
    /// derivation, the padding or the AAD shape reaches this test instead of
    /// sailing past it. The one assertion here that is genuinely ours is the
    /// equal-length check on `pad_to_bucket`, which fails if the bucketing
    /// stops padding to a common size.
    ///
    /// **If this test ever goes red, do not make it pass.** Red means the
    /// construction changed -- a nonce misuse-resistant mode, say. That is an
    /// improvement: invert the assertion and update the row in
    /// `docs/untested-invariants.md`.
    #[test]
    fn known_limit_a_nonce_collision_reuses_the_keystream() {
        use aes_gcm::aead::Aead;

        // Harvest's own key, for a real conversation.
        let seller = Seller::new(41);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let keys = seller.keys_for(&buyer.buyer_public_key);
        let aes_key = keys.to_seller;

        // Harvest's own padding, so both plaintexts are the length the wire
        // would carry rather than a length chosen to make the xor line up.
        let first = harvest_common::mailbox::pad_to_bucket(b"pay to bc1qhonest");
        let second = harvest_common::mailbox::pad_to_bucket(b"pay to bc1qattacker");
        assert_eq!(
            first.len(),
            second.len(),
            "the bucketing is what makes these comparable; if it stopped padding to a \
             common size the size-privacy claim would be the bigger news"
        );

        // Harvest's own associated data, over one mailbox nonce used twice.
        let mailbox_nonce = [3u8; 24];
        let timestamp = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let aad = harvest_common::mailbox::message_aad(
            &buyer.conversation_id,
            &buyer.buyer_public_key,
            &timestamp,
            &mailbox_nonce,
        );

        let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("key");
        let seal = |plaintext: &[u8]| {
            cipher
                .encrypt(
                    Nonce::from_slice(&mailbox_nonce[..12]),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .expect("encrypt")
        };
        let c1 = seal(&first);
        let c2 = seal(&second);

        // Strip the 16-byte tag; the rest is plaintext xor keystream.
        let body = first.len();
        let ciphertext_xor: Vec<u8> = c1[..body]
            .iter()
            .zip(&c2[..body])
            .map(|(a, b)| a ^ b)
            .collect();
        let plaintext_xor: Vec<u8> = first.iter().zip(&second).map(|(a, b)| a ^ b).collect();

        assert_eq!(
            ciphertext_xor, plaintext_xor,
            "a nonce collision no longer reveals the xor of the two plaintexts -- if the \
             construction has been strengthened, invert this assertion and update \
             docs/untested-invariants.md"
        );
    }

    /// A low-order "public key" is refused rather than encrypted to under a
    /// key the whole world can compute.
    #[test]
    fn opening_a_conversation_with_an_all_zero_key_is_refused() {
        let error = BuyerConversation::open(&[0u8; 32]).expect_err("must be refused");
        assert!(
            error.contains("not usable"),
            "the refusal must say why: {error}"
        );
    }
}

#[cfg(test)]
mod buy_flow_tests {
    use super::tests::Seller;
    use super::*;
    use harvest_common::listing::ListingId;
    use harvest_common::payment::OrderId;

    /// **A buyer's request to buy reaches the seller intact.**
    ///
    /// This is step 1 of `docs/design/incentive-mechanism.md` Part 5, and it
    /// rides the same sealed conversation as any other message -- there is no
    /// second channel. The seller here is reconstructed from nothing but an
    /// X25519 secret, which is all the harvest delegate holds, so a pass
    /// cannot come from the two halves of this module drifting together.
    /// The buyer's receipt seed signs for the buyer, so neither it nor the
    /// conversation that holds it prints it (harvest#53 Phase B).
    #[test]
    fn the_receipt_seed_does_not_print_itself() {
        let secret = [0xA7u8; 32];
        let seller = Seller::new(31);
        let buyer = BuyerConversation::opened_from_secret_for_test(&secret, &seller.public_key())
            .expect("open");
        let seed = harvest_common::mailbox::buyer_receipt_seed_from_secret(&secret);
        let printed = format!("{buyer:?}");
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        let as_array = format!("{:?}", seed);
        assert!(printed.contains("ReceiptSeed(redacted)"), "{printed}");
        assert!(
            !printed.contains(&hex) && !printed.contains(&as_array),
            "{printed}"
        );
    }

    #[test]
    fn a_buyers_order_request_reaches_the_seller_intact() {
        let seller = Seller::new(31);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let listing = ListingId([7u8; 32]);

        let sealed = buyer
            .request_order(
                &listing,
                3,
                "12 Example St".into(),
                "no chilli".into(),
                None,
            )
            .expect("seal the request");

        let inbox = seller.inbox(&[sealed]);
        match &inbox[0] {
            MailboxEntry::Readable {
                content:
                    MessageContent::OrderRequest {
                        listing_id,
                        quantity,
                        shipping,
                        note,
                        order_binding,
                        buyer_receipt_key,
                        instant: None,
                    },
                ..
            } => {
                assert_eq!(listing_id, &listing);
                assert_eq!(*quantity, 3);
                assert_eq!(shipping, "12 Example St");
                assert_eq!(note, "no chilli");
                // The value that makes the seller's commitment this buyer's
                // and nobody else's -- see
                // `harvest_common::mailbox::order_binding_from_secret`.
                assert_eq!(order_binding, &buyer.order_binding());
                // And the key the buyer will sign with (harvest#53 Phase B),
                // which is the shared derivation over this conversation's
                // secret.
                let expected = ed25519_dalek::SigningKey::from_bytes(
                    &harvest_common::mailbox::buyer_receipt_seed_from_secret(
                        &buyer.secret_for_test(),
                    ),
                )
                .verifying_key()
                .to_bytes();
                assert_eq!(buyer_receipt_key, &Some(expected));
            }
            other => panic!("expected an order request, got {other:?}"),
        }
    }

    /// An instant-checkout selection reaches the seller as it was picked, so
    /// the seller's delegate prices the same region, choices and total the
    /// buyer was shown.
    #[test]
    fn an_instant_selection_reaches_the_seller_intact() {
        let seller = Seller::new(33);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let selection = InstantSelection {
            nonce: [5u8; 16],
            region: Some("EU".into()),
            choices: vec!["Fig".into(), "Large".into()],
            expected_total_sats: 12_000,
        };

        let sealed = buyer
            .request_order(
                &ListingId([7u8; 32]),
                2,
                "12 Example St".into(),
                String::new(),
                Some(selection.clone()),
            )
            .expect("seal the request");

        match &seller.inbox(&[sealed])[0] {
            MailboxEntry::Readable {
                content: MessageContent::OrderRequest { instant, .. },
                ..
            } => assert_eq!(instant, &Some(selection)),
            other => panic!("expected an order request, got {other:?}"),
        }
    }

    /// **The buyer learns which published commitment is theirs, and from
    /// which direction.**
    ///
    /// The order id is not something a buyer can derive: `OrderId::from_terms`
    /// hashes terms the seller chooses, including a `created_at` they stamp. So the acceptance has to name
    /// it, and it has to arrive addressed TO THE BUYER -- a buyer counting
    /// their own outbound messages as acceptances would let anything they
    /// composed point them at an order.
    ///
    /// This message is a POINTER and carries no authority. What makes the
    /// commitment the seller's is the ghostkey signature on the published
    /// order, checked in `state::AppState::payment_blockers`.
    #[test]
    fn an_acceptance_names_the_order_and_is_addressed_to_the_buyer() {
        let seller = Seller::new(32);
        let buyer = BuyerConversation::open(&seller.public_key()).expect("open");
        let order = OrderId([9u8; 32]);

        let reply = seal_order_accepted(
            &seller.keys_for(&buyer.buyer_public_key),
            &buyer.buyer_public_key,
            &buyer.conversation_id,
            &order,
        )
        .expect("seal the acceptance");

        let thread = buyer.read(&[reply]);
        assert_eq!(thread.len(), 1, "the buyer must be able to read it");
        assert_eq!(
            thread[0].addressing,
            Addressing::ToBuyer,
            "an acceptance the buyer wrote themselves is not an acceptance"
        );
        match &thread[0].content {
            MessageContent::OrderAccepted { order_id } => assert_eq!(order_id, &order),
            other => panic!("expected an acceptance, got {other:?}"),
        }
    }
}
