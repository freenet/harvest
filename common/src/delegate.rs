use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::feedback::FeedbackToken;
use crate::listing::{AuthorizedListing, Listing};

pub type RequestId = u64;

/// The parameters the harvest delegate is registered under.
///
/// A delegate lives at `BLAKE3(BLAKE3(wasm) || parameters)` exactly as a
/// contract does, so this value is half of its address. It is empty because the
/// delegate needs no per-instance configuration -- but "empty" is a decision,
/// not an absence, and it belongs in one place rather than being spelled
/// `Parameters::from(Vec::<u8>::new())` at each registration site. Changing it
/// re-keys the delegate and strands every secret it holds; the address guard
/// (`common/src/bin/harvest-addresses.rs`) reads this constant, so such a
/// change shows up as a moved address rather than as nothing at all.
pub const DELEGATE_PARAMETERS: &[u8] = &[];

/// Requests from the UI to the Harvest delegate.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum HarvestDelegateRequest {
    // === RSA Key Management (for feedback token blind signing) ===
    /// Generate and store an RSA-PSS keypair for a ghostkey identity's reputation.
    InitReputationKeys { ghostkey_fingerprint: String },

    /// Get the RSA public key (PKCS#1 DER) for a reputation identity.
    GetRsaPublicKey { ghostkey_fingerprint: String },

    // === Blind Signing (seller signs buyer's feedback token) ===
    /// Blind-sign a buyer's feedback token.
    BlindSignFeedbackToken {
        request_id: RequestId,
        ghostkey_fingerprint: String,
        blinded_token: Vec<u8>,
    },

    // === Buyer-to-seller messaging ===
    /// Mint (or return) this identity's long-term X25519 public key.
    ///
    /// The private half stays in the delegate under
    /// `harvest:x25519_sk:{fingerprint}`; the public half is what the seller
    /// publishes in [`crate::store::StoreInfoV1::encryption_public_key`] so a
    /// buyer has something to encrypt to. Idempotent: a second call returns
    /// the key the first one minted, because re-minting would strand every
    /// message already in flight to the old one.
    InitEncryptionKey { ghostkey_fingerprint: String },

    /// Derive the conversation keys for a batch of buyer ephemeral public
    /// keys, so the UI can decrypt what is sitting in the mailbox.
    ///
    /// # Why the delegate answers keys rather than plaintext
    ///
    /// The long-term X25519 secret is the thing that must not leave: it
    /// decrypts every conversation this seller will ever have, including ones
    /// that have not happened yet. A conversation key decrypts one buyer's
    /// messages and nothing else, and the plaintext is going to the UI in any
    /// case -- that is where the seller reads it.
    ///
    /// Doing the AEAD here instead would mean a second copy of the padding,
    /// CBOR and AES-GCM path inside the delegate, and `harvest-common` is
    /// compiled into all three contracts, so it cannot host that code without
    /// putting `aes-gcm` in every contract's WASM. One crypto path, in
    /// `harvest-ui`'s `messaging`, is the trade.
    ///
    /// # This is a DH oracle, deliberately
    ///
    /// A caller who reaches this can derive a shared secret against any
    /// public key it likes. That is what makes it a read of the seller's
    /// mailbox and why it is behind `origin::authorize` along with everything
    /// else -- see the module docs on `harvest-delegate`'s `origin`.
    DeriveConversationKeys {
        request_id: RequestId,
        ghostkey_fingerprint: String,
        /// Raw 32-byte X25519 public keys, as they appear in
        /// [`crate::mailbox::EncryptedMessage::sender_public_key`].
        peer_public_keys: Vec<Vec<u8>>,
    },

    /// Keep a buyer's conversation secret so it outlives the browser tab.
    ///
    /// # Why the delegate, and why this shape
    ///
    /// The buyer has no identity, so nothing here is keyed by a ghostkey
    /// fingerprint. And there is no browser-side storage to use instead: the
    /// Freenet webapp iframe carries no `allow-same-origin`, so the page runs
    /// on an opaque origin where `localStorage`, `sessionStorage`, IndexedDB
    /// and cookies all throw. The delegate is the only durable store this
    /// application has. See `docs/buyer-conversation-persistence.md`.
    ///
    /// The record binds the seller public key it was opened against, so
    /// [`Self::ListBuyerConversations`] derives with THAT key rather than one
    /// a caller supplies. The secret therefore never leaves the delegate, and
    /// the recall path cannot be pointed at an arbitrary peer.
    ///
    /// **There is no `buyer_public_key` field.** The conversation's routing
    /// tag is the public half of [`Self::StoreBuyerConversation::secret`], so
    /// the delegate derives it rather than being told it. A field would be a
    /// second source for one value, and the two could disagree -- storing a
    /// conversation under a tag no message in the mailbox carries, which
    /// nothing downstream could detect.
    StoreBuyerConversation {
        request_id: RequestId,
        /// The store this conversation is with, as a 32-byte contract
        /// instance id. Recoverable after a reload because it is in the URL
        /// the buyer followed.
        ///
        /// A wrong length is refused rather than stored: this value is
        /// base58-encoded into the secret's KEY, so a caller-sized id would
        /// be a caller-sized key, and the delegate's cap on how many
        /// conversations it keeps would stop bounding how many BYTES they
        /// come to.
        store_contract_id: Vec<u8>,
        /// The buyer's ephemeral X25519 secret for this conversation.
        secret: ConversationSecret,
        /// The seller key this conversation was opened against.
        seller_public_key: [u8; 32],
        conversation_id: [u8; 32],
        /// Unix seconds, from the buyer's own browser, used for one thing:
        /// which conversation is evicted when the cap is reached.
        ///
        /// The delegate does not read the host clock for this.
        /// `freenet_stdlib::time::now()` is a `MaybeUninit` transmute off
        /// wasm32 (`time.rs:7`), so a delegate that called it could not be
        /// exercised by `cargo test` without undefined behaviour -- and this
        /// value orders nothing but the caller's own records, so a skewed
        /// clock costs the caller an eviction of their own choosing.
        created_at: i64,
    },

    /// Recall every conversation stored for a store, as derived keys.
    ListBuyerConversations {
        request_id: RequestId,
        store_contract_id: Vec<u8>,
    },

    /// Discard one, permanently.
    ///
    /// The buyer's own control over the record this leaves on their node --
    /// see `docs/messaging-privacy.md`. Discarding is not reversible and
    /// makes the conversation unreadable, which is the point.
    ForgetBuyerConversation {
        request_id: RequestId,
        store_contract_id: Vec<u8>,
        /// Which conversation, by its routing tag.
        buyer_public_key: [u8; 32],
    },

    /// Hand back this store's conversation secrets in a form the buyer can
    /// save, and paste into another node.
    ///
    /// # What this answers is a capability, not a copy
    ///
    /// The string contains the X25519 secrets themselves. Anyone holding it
    /// can read that conversation, and -- once a seller's reply carries a
    /// pre-signed statement -- can file the complaint it authorizes. It is
    /// the buyer's recourse in a form they can lose, which is exactly what
    /// makes it worth having and exactly why the UI says so beside the
    /// button rather than in a tooltip.
    ///
    /// # Why one conversation and not one store
    ///
    /// This was per STORE until 2026-09-05, on the argument that a buyer
    /// normally has one conversation with a store anyway, so the two differ
    /// mainly in how many actions a complete backup takes -- and that a
    /// backup silently omitting a conversation is the expensive failure. That
    /// argument was right about the failure and wrong about when it happens:
    /// it optimises for completeness AT EXPORT TIME, and what bites is
    /// completeness OVER TIME. A store-wide string taken on Monday is
    /// silently incomplete on Tuesday, and nothing about the artefact says
    /// which conversations existed when it was taken.
    ///
    /// The marker settles it. A `backed_up` flag set from a store-wide export
    /// would falsely cover a conversation created after that export -- the
    /// "cannot silence a warning about a key it has no backup of" property,
    /// defeated through granularity rather than through permission. Per
    /// conversation it means something checkable: THIS secret exists in more
    /// than one place.
    ExportBuyerConversation {
        request_id: RequestId,
        store_contract_id: Vec<u8>,
        /// Which conversation, by routing tag.
        buyer_public_key: [u8; 32],
    },

    /// Take one saved backup string and make its conversation readable here.
    ///
    /// One string per call; a buyer restoring a machine pastes several in a
    /// row. Nothing here is stateful between calls, so the order does not
    /// matter and a failure part-way leaves what already landed.
    ///
    /// The store id is inside the string, so this needs nothing else -- a
    /// buyer on a new node has the string and nothing to relate it to.
    ImportBuyerConversation {
        request_id: RequestId,
        backup: String,
    },

    /// Record that the buyer holds a copy of THIS conversation outside this
    /// node.
    ///
    /// # Why the MARKER needs the origin gate, and not only the export
    ///
    /// The export's reason is obvious: it answers secrets. The marker's is
    /// the one that looks harmless and is not. It **silences a warning** --
    /// "this conversation exists only on this device" -- and the party that
    /// benefits from the silence is not the party that bears the loss. An app
    /// that could set this without the user holding a backup would make the
    /// warning stop for a conversation about to be lost with the machine,
    /// which is worse than never having warned: the buyer stops looking.
    ///
    /// So it is behind `origin::authorize` deliberately, for its own reason,
    /// and not merely because it sits beside the export. This mirrors the
    /// ghostkey vault, where `MarkBackedUp` is gated on the `Export` scope
    /// that only the vault is ever granted, for the same stated reason
    /// (`ghostkey-delegate/src/handlers.rs::handle_mark_backed_up`).
    ///
    /// Set only when the user says they have saved it -- exporting is not
    /// saving.
    MarkConversationBackedUp {
        request_id: RequestId,
        store_contract_id: Vec<u8>,
        /// Which conversation, by routing tag. One, matching the export: a
        /// request that marked a SET would let one saved string clear the
        /// warning on a conversation it does not contain, which is the
        /// granularity form of the defect the gate exists to prevent.
        buyer_public_key: [u8; 32],
    },

    // === Listing Management ===
    /// Create and sign a new listing using the seller's ghostkey.
    CreateListing {
        request_id: RequestId,
        ghostkey_fingerprint: String,
        listing: Listing,
    },

    // === Transaction State ===
    /// Record that a feedback token exchange has started with a buyer.
    BeginTransaction {
        request_id: RequestId,
        /// Identifier for this transaction (e.g. listing ID + buyer ephemeral key).
        transaction_id: String,
        /// Our unblinded feedback token (held locally, never sent to counterparty).
        our_token: FeedbackToken,
        /// The blinded version we sent to the counterparty for signing.
        our_blinded_token: Vec<u8>,
    },

    /// Record receipt of a blind signature on our feedback token.
    RecordBlindSignature {
        request_id: RequestId,
        transaction_id: String,
        blind_signature: Vec<u8>,
    },

    /// Get stored transaction history.
    ListTransactions,

    // === Store Registry ===
    /// Register a store's contracts with a ghostkey identity so the delegate
    /// knows which contracts to subscribe to for notifications.
    RegisterStore {
        ghostkey_fingerprint: String,
        store_contract_id: Vec<u8>,
        reputation_contract_id: Vec<u8>,
        mailbox_contract_id: Vec<u8>,
    },

    /// List all stores registered for a ghostkey identity.
    ListStores { ghostkey_fingerprint: String },

    // === Migration markers ===
    /// Has the contract migration named by `marker` already completed?
    ///
    /// `marker` is an opaque, ASCII-only id minted by
    /// `harvest-ui`'s `migrate::marker_key` -- artifact, contract instance and
    /// current code hash, hex-encoded. The delegate stores it under its own
    /// `harvest:migrate:` prefix rather than treating it as a raw secret key,
    /// so a caller cannot address anything else in the delegate's namespace
    /// with it.
    ///
    /// The answer is a plain `present: bool`, and every failure -- an
    /// unreadable store, a malformed marker, no answer at all -- has to be
    /// read as **not** present. An unreadable marker treated as "done" skips
    /// the migration; treated as "not done" it repeats a walk that only ever
    /// adds. See `harvest-ui`'s `migrate` module docs.
    GetMigrationMarker { marker: String },

    /// Record that the migration named by `marker` finished.
    ///
    /// `note` is the human-readable outcome line, stored as the marker's
    /// value so a later reader can see what sealed it. Only the presence of
    /// the key is load-bearing.
    SetMigrationMarker { marker: String, note: String },

    // === Stores this node has visited (harvest#52) ===
    /// Remember a store whose link was followed, so it is still listed after
    /// the tab is gone.
    ///
    /// Keyed by the store's CODE (see `crate::store::StoreParameters`),
    /// which is what the link carried and all a client needs to re-derive
    /// the store's address. A code of the wrong length or alphabet is
    /// refused: it is written into the secret's key, and the cap on how many
    /// stores are remembered bounds bytes only while every key is one size.
    ///
    /// Idempotent, and it never un-archives: re-opening an archived store's
    /// link shows the store without moving it back into the list, because
    /// archiving is a choice the buyer made and a link is not a reversal of
    /// it. Answered with [`HarvestDelegateResponse::RememberedStores`].
    RememberStore { store_code: String },

    /// Archive or unarchive a store: hide it from the list, or bring it back.
    ///
    /// # Archive, not remove
    ///
    /// Nothing is deleted, and that is the design rather than a
    /// half-measure (harvest#52). A buyer's history with a store IS its
    /// conversations, filed under `harvest:buyer_conv:{store}:`, so a
    /// "remove" that removed would take the conversation with it. Deleting a
    /// conversation stays `ForgetBuyerConversation`, inside the thread.
    ///
    /// Archiving a store the seller owns does NOT close it: this is this
    /// node's view preference, and the store contract is untouched.
    ///
    /// Remembers the store too, if it was not already remembered.
    SetStoreArchived { store_code: String, archived: bool },

    /// Every store this node remembers, archived ones included.
    ListRememberedStores,
}

/// A store this node remembers visiting.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct RememberedStore {
    /// The store's code, from which its address is derived.
    pub store_code: String,
    /// Hidden from the list unless the user asks to see archived stores.
    pub archived: bool,
}

/// Responses from the Harvest delegate to the UI.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum HarvestDelegateResponse {
    ReputationKeysInitialized {
        ghostkey_fingerprint: String,
        rsa_public_key_der: Vec<u8>,
    },

    RsaPublicKey {
        ghostkey_fingerprint: String,
        rsa_public_key_der: Vec<u8>,
    },

    /// This identity's long-term X25519 public key, minted or recalled.
    EncryptionKeyReady {
        ghostkey_fingerprint: String,
        /// Raw 32 bytes. A `Vec` rather than `[u8; 32]` because every other
        /// key on this wire is one, and a length mismatch is then a message
        /// the UI can report rather than a decode failure with no context.
        x25519_public_key: Vec<u8>,
    },

    /// Whether a buyer conversation was stored.
    ///
    /// A failure matters and is reported rather than swallowed: the UI has
    /// just told a buyer their message was sent, and if the secret was not
    /// kept then the seller's reply will be unreadable after a reload.
    BuyerConversationStored {
        request_id: RequestId,
        result: Result<(), String>,
        /// What had to be discarded to make room, if anything.
        ///
        /// A separate field rather than part of `result` because an eviction
        /// happens BEFORE the write and stands whether or not the write then
        /// succeeds -- reporting it only on success would lose it in exactly
        /// the case where two things went wrong.
        ///
        /// Empty on almost every call. When it is not, a conversation is
        /// permanently unreadable, and the design doc names silence here as
        /// the expensive direction: "the confession becomes unreadable and
        /// the buyer has no recourse, with no error at any layer".
        evicted: Vec<EvictedConversation>,
    },

    /// The conversations stored for one store, as keys rather than secrets.
    ///
    /// The `request_id` is what pairs this with the question, and the caller
    /// files the answer under the store IT asked about rather than the one
    /// echoed here. Same lesson as [`ConversationKey::peer_public_key`]: a
    /// consumer that trusts the payload's own idea of where it belongs will,
    /// the first time the two disagree, file one store's conversation keys
    /// against another store's mailbox.
    BuyerConversationList {
        request_id: RequestId,
        store_contract_id: Vec<u8>,
        conversations: Vec<RecalledConversation>,
    },

    /// One conversation, as a string the buyer can save.
    ///
    /// `Ok` carries the backup itself. It holds a secret: see
    /// [`HarvestDelegateRequest::ExportBuyerConversation`].
    BuyerConversationExported {
        request_id: RequestId,
        store_contract_id: Vec<u8>,
        buyer_public_key: [u8; 32],
        result: Result<String, String>,
    },

    /// What a pasted backup did.
    BuyerConversationImported {
        request_id: RequestId,
        result: Result<ImportedConversation, String>,
    },

    /// Whether this conversation is now marked as held outside this node.
    ///
    /// `Ok(true)` means it is marked; `Ok(false)` means this node does not
    /// hold that conversation, which is not an error and creates nothing. A
    /// write the node REFUSED is an `Err`, because "not marked" and "could
    /// not mark" are different situations and a boolean cannot tell them
    /// apart.
    BuyerConversationMarkedBackedUp {
        request_id: RequestId,
        store_contract_id: Vec<u8>,
        buyer_public_key: [u8; 32],
        result: Result<bool, String>,
    },

    /// Whether a conversation was actually removed.
    ///
    /// `Ok(())` means the record is gone from the node's secret store, not
    /// merely emptied -- the delegate re-reads the key afterwards and reports
    /// a failure rather than an `Ok` it cannot stand behind. A control that
    /// says "forgotten" and leaves the record is worse than no control,
    /// because the buyer stops being careful on the strength of it.
    BuyerConversationForgotten {
        request_id: RequestId,
        result: Result<(), String>,
    },

    /// Conversation keys for the peer public keys that were asked about.
    ///
    /// One entry per key the delegate could derive against, in no particular
    /// order; a peer key that was malformed is simply absent, and
    /// [`ConversationKey::peer_public_key`] is what pairs an answer with its
    /// question. Positional correlation would put one buyer's key against
    /// another buyer's messages the first time an entry was dropped.
    ConversationKeys {
        request_id: RequestId,
        /// Echoed so a reader of a node log can see which identity was asked
        /// about, and so the UI is not correlating on `request_id` alone.
        ghostkey_fingerprint: String,
        result: Result<Vec<ConversationKey>, String>,
    },

    BlindSignatureResult {
        request_id: RequestId,
        result: Result<Vec<u8>, String>,
    },

    ListingCreated {
        request_id: RequestId,
        result: Result<AuthorizedListing, String>,
    },

    TransactionRecorded {
        request_id: RequestId,
        result: Result<(), String>,
    },

    BlindSignatureRecorded {
        request_id: RequestId,
        result: Result<(), String>,
    },

    TransactionList {
        transactions: Vec<TransactionRecord>,
    },

    /// A subscribed contract's state changed (new mailbox message, feedback, etc.).
    ContractUpdate {
        contract_key: Vec<u8>,
        update_data: Vec<u8>,
    },

    /// Full contract state from a GET response.
    ContractState {
        contract_key: Vec<u8>,
        state: Vec<u8>,
    },

    StoreRegistered {
        ghostkey_fingerprint: String,
    },

    StoreList {
        ghostkey_fingerprint: String,
        stores: Vec<StoreRegistration>,
    },

    /// Every store this node remembers, sorted by code, after whichever
    /// `RememberStore`, `SetStoreArchived` or `ListRememberedStores` asked.
    ///
    /// The whole list rather than an acknowledgement, so the UI's copy is
    /// replaced by what the delegate holds rather than patched to match what
    /// it believes it asked for.
    RememberedStores {
        stores: Vec<RememberedStore>,
    },

    /// Whether the migration named by `marker` is already recorded as done.
    ///
    /// `present: false` is the answer to every uncertainty as well as to a
    /// genuine absence -- see `HarvestDelegateRequest::GetMigrationMarker`.
    MigrationMarker {
        marker: String,
        present: bool,
    },

    /// The outcome of a `SetMigrationMarker`.
    ///
    /// `recorded: false` means the host refused the write. It is reported
    /// rather than swallowed so the log says why the same walk runs again next
    /// load, but nothing has to act on it: an unwritten marker repeats a walk
    /// that only ever adds.
    MigrationMarkerRecorded {
        marker: String,
        recorded: bool,
    },

    Error {
        message: String,
    },
}

/// One buyer's ephemeral public key and BOTH conversation keys derived from
/// it.
///
/// Both, because the seller needs both: `buyer_to_seller` to read what
/// arrived, `seller_to_buyer` to write the reply. Answering only the first
/// would put the seller a second delegate round trip away from replying, and
/// answering a single undirected key would let a copy of the buyer's own
/// message read as a reply -- see [`crate::mailbox::MessageDirection`].
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ConversationKey {
    /// The buyer ephemeral public key these were derived against, echoed back
    /// so the caller does not have to rely on ordering.
    pub peer_public_key: Vec<u8>,
    /// AES-256 key for messages the buyer wrote.
    pub buyer_to_seller: [u8; 32],
    /// AES-256 key for the seller's replies.
    pub seller_to_buyer: [u8; 32],
}

/// One recalled buyer conversation: enough to read the thread, and not the
/// secret it was derived from.
///
/// The secret stays in the delegate. What the buyer's browser needs in order
/// to read and continue a conversation is the two direction keys, and a
/// secret handed back on every reload would be a secret in every browser log
/// and bug report for no gain. Pinned by
/// `the_secret_never_leaves_the_delegate`.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct RecalledConversation {
    /// The conversation's routing tag, which is what matches it to messages
    /// in the mailbox.
    pub buyer_public_key: [u8; 32],
    pub conversation_id: [u8; 32],
    /// Encrypts what the buyer writes.
    pub buyer_to_seller: [u8; 32],
    /// Encrypts what the seller writes back.
    pub seller_to_buyer: [u8; 32],
    /// The value this buyer's order commitments must carry, so that a
    /// commitment published for somebody else does not read as theirs.
    ///
    /// Derived by the delegate from the stored conversation secret via
    /// [`crate::mailbox::order_binding_from_secret`], because that secret
    /// never leaves the delegate and is the only durable, buyer-only secret
    /// this application has. See that function for what the binding closes and
    /// what it deliberately does not.
    ///
    /// This is a COMMITMENT, not the secret: it is safe in a browser and safe
    /// to publish. The preimage stays in the delegate, which is where Phase 2
    /// filing will need it.
    ///
    /// `serde(default)` so a delegate answer produced before this field
    /// existed decodes; it comes back as all-zeros. That is **not** a
    /// binding, and the reader must not compare it: a seller chooses the
    /// value they sign, so signing all-zeros would match every conversation
    /// in that state. The consumer treats it as absent -- see
    /// `harvest_ui::messaging::BuyerConversation::usable_order_binding` --
    /// rather than as a value that happens not to collide. An earlier version
    /// of this comment claimed the opposite, reasoning about an honest
    /// commitment in a check that exists for a dishonest one.
    #[serde(default)]
    pub order_binding: [u8; 32],
    /// When the buyer opened it, in unix seconds, as they reported it.
    ///
    /// Carried back so a browser that recalls several conversations with one
    /// store can continue the most recent rather than picking arbitrarily --
    /// a thread the buyer left open, resumed, rather than a new one beside
    /// it.
    pub created_at: i64,
    /// Whether this conversation arrived by import rather than being opened
    /// here.
    ///
    /// Set by the delegate, never carried in from a caller: it is a fact
    /// about where the record came from, and its whole value is that the
    /// other side cannot choose it. `created_at` CAN be chosen -- it travels
    /// in the backup string -- so anything that must not be attacker-ordered
    /// ranks on this first. See `make_room`'s eviction order.
    pub imported: bool,
    /// Whether the buyer has said they hold a copy of this outside this node.
    ///
    /// `false` means the secret exists in exactly one place, and losing the
    /// machine loses the conversation -- and, after Phase 2, the buyer's only
    /// recourse against the seller they paid. The UI warns on this; nothing
    /// but the user saying so can clear it. See
    /// [`HarvestDelegateRequest::MarkConversationBackedUp`].
    pub backed_up: bool,
}

/// A conversation the delegate discarded to stay under its cap.
///
/// `was_backed_up` is the whole point of reporting it: a discarded
/// conversation the buyer holds a backup of is recoverable and worth a
/// mention, and one they do not is gone for good and worth an alarm.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct EvictedConversation {
    pub buyer_public_key: [u8; 32],
    pub was_backed_up: bool,
}

/// What pasting one backup did.
///
/// # Why an enum and not counts
///
/// One string carries one conversation, so exactly one of these happened, and
/// the three are different situations for the buyer. `Imported` is the
/// restore working. `AlreadyHeld` is the ordinary case of pasting a backup
/// onto the node that made it, and is not a problem. `Refused` is the one
/// that needs saying out loud WITH its reason -- a conversation that did not
/// fit under the node's cap is one the buyer still cannot read, and a bare
/// count would leave them to work out what to do about it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum ImportedConversation {
    /// Not held here before, and now is.
    Imported {
        /// The store the backup belongs to, from inside the backup itself.
        store_contract_id: Vec<u8>,
        buyer_public_key: [u8; 32],
    },
    /// Already here. The held record was kept, not overwritten.
    AlreadyHeld {
        store_contract_id: Vec<u8>,
        buyer_public_key: [u8; 32],
    },
    /// Could not be taken, with the reason.
    Refused {
        store_contract_id: Vec<u8>,
        buyer_public_key: [u8; 32],
        why: String,
    },
}

impl ImportedConversation {
    /// The store this outcome is about, whichever it is.
    pub fn store_contract_id(&self) -> &[u8] {
        match self {
            Self::Imported {
                store_contract_id, ..
            }
            | Self::AlreadyHeld {
                store_contract_id, ..
            }
            | Self::Refused {
                store_contract_id, ..
            } => store_contract_id,
        }
    }

    /// The conversation this outcome is about.
    pub fn buyer_public_key(&self) -> [u8; 32] {
        match self {
            Self::Imported {
                buyer_public_key, ..
            }
            | Self::AlreadyHeld {
                buyer_public_key, ..
            }
            | Self::Refused {
                buyer_public_key, ..
            } => *buyer_public_key,
        }
    }
}

/// A buyer's ephemeral X25519 secret, on the wire between the browser that
/// generated it and the delegate that keeps it.
///
/// # Why a newtype rather than `[u8; 32]`
///
/// `HarvestDelegateRequest` derives `Debug`, and the responses are logged
/// verbatim (`gateway::response_handler::apply_delegate_response`). A bare
/// array would print, so the one secret in this protocol that a buyer cannot
/// replace would land in any console log pasted into a bug report. This type
/// prints as `ConversationSecret(redacted)` instead; pinned by
/// `a_conversation_secret_does_not_print_itself`.
///
/// `#[serde(transparent)]` so the wire encoding is exactly the 32 bytes --
/// the newtype is a compile-time and log-time property, not a format change.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(transparent)]
pub struct ConversationSecret(pub [u8; 32]);

impl core::fmt::Debug for ConversationSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ConversationSecret(redacted)")
    }
}

/// A store's contract IDs, registered with the delegate for notifications.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreRegistration {
    pub store_contract_id: Vec<u8>,
    pub reputation_contract_id: Vec<u8>,
    pub mailbox_contract_id: Vec<u8>,
    /// Serialized ContractKey for the store contract (needed for updates).
    /// This includes both the instance ID and the code hash.
    #[serde(default)]
    pub store_contract_key: Option<Vec<u8>>,
}

/// A record of a feedback token exchange, stored locally by the delegate.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct TransactionRecord {
    pub transaction_id: String,
    /// Our unblinded feedback token (can be submitted to counterparty's reputation contract).
    pub our_token: FeedbackToken,
    /// The blinded version we sent for signing.
    pub our_blinded_token: Vec<u8>,
    /// The blind signature we received (None until counterparty signs).
    pub blind_signature: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A conversation secret must not print itself.**
    ///
    /// It travels inside a `Debug`-deriving request enum, and the UI logs
    /// delegate traffic verbatim. This is the one secret in the protocol a
    /// buyer cannot replace -- lose it and the seller's reply, which after
    /// Phase 2 carries their only capability to complain, is unreadable
    /// forever.
    #[test]
    fn a_conversation_secret_does_not_print_itself() {
        let secret = ConversationSecret([7u8; 32]);
        let printed = format!("{secret:?}");
        assert_eq!(printed, "ConversationSecret(redacted)");

        // And inside the request it travels in, which is the shape that
        // actually reaches a log.
        let request = HarvestDelegateRequest::StoreBuyerConversation {
            request_id: 1,
            store_contract_id: vec![3u8; 32],
            secret,
            seller_public_key: [9u8; 32],
            conversation_id: [5u8; 32],
            created_at: 1_700_000_000,
        };
        let printed = format!("{request:?}");
        assert!(
            !printed.contains(", 7, 7,"),
            "the secret's bytes appeared in a printed request: {printed}"
        );
        assert!(printed.contains("redacted"), "{printed}");
    }

    /// The newtype is a compile-time and log-time property, not a wire
    /// change: it encodes as the bare 32 bytes.
    ///
    /// Worth pinning because the alternative -- a one-field map -- would be a
    /// silent format break for any record already written by a build that
    /// used the array.
    #[test]
    fn a_conversation_secret_encodes_as_its_bytes() {
        let bytes = [11u8; 32];
        assert_eq!(
            crate::to_cbor(&ConversationSecret(bytes)).expect("cbor"),
            crate::to_cbor(&bytes).expect("cbor"),
        );
    }
}
