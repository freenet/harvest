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
        /// The store whose inbox the peers wrote to (harvest#93 phase 1b).
        /// When set, the keys derive from that store's inbox key, which
        /// derives from the store key (`custody::inbox_secret`), so every
        /// device holding the store key reads the same messages. `None` is
        /// the per-device key of a Ghost Key, for a store made before it.
        #[serde(default)]
        store_verifying_key: Option<[u8; 32]>,
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
        /// The pasted string. Prints as `BackupString(redacted)`.
        backup: BackupString,
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
        /// The store's own key (harvest#93), which owns the store and signs
        /// for it. `None` only from a UI older than revision 2, whose stores
        /// were owned by the Ghost Key itself.
        #[serde(default)]
        store_verifying_key: Option<[u8; 32]>,
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
    ///
    /// One list per node, shared by every Ghost Key on it (and by a buyer
    /// with none): the records are keyed by store code alone.
    ListRememberedStores,

    // === Store keys (harvest#93, revision 2) ===
    /// Mint a new store key: a fresh Ed25519 key, from the host's RNG, kept in
    /// this delegate on this device. Answered with
    /// [`HarvestDelegateResponse::StoreKeyCreated`], which carries the public
    /// half only. No request returns the secret, and the export to a
    /// successor generation leaves store keys out (phase 1b recovers them
    /// from their wrapped copies instead).
    ///
    /// Phase 1b adds custody (the key wrapped to each backing Ghost Key in
    /// the store's state, so another device can recover it); until then a
    /// store key lives on the device that created it and nowhere else.
    ///
    /// # Resumable per Ghost Key (#98 review, M1)
    ///
    /// With `ghostkey_fingerprint`, the delegate remembers the key it minted
    /// for that Ghost Key's store creation until `RegisterStore` names it, and
    /// answers the SAME key to every later `CreateStoreKey` for that Ghost
    /// Key until then: from another tab, after a reload, or on a retry after
    /// a failed PUT. The store's code, and so its contract id, derives from
    /// the store key, so a retry re-publishes the same store instead of
    /// making a second one. Without it (a request from an older UI), a fresh
    /// key every time, as before.
    CreateStoreKey {
        request_id: RequestId,
        #[serde(default)]
        ghostkey_fingerprint: Option<String>,
    },

    /// Sign `payload` with the store key named by `store_verifying_key`.
    ///
    /// `payload` must be one of a store's own records, as
    /// [`crate::backing::classify_store_key_message`] recognises them; the
    /// delegate refuses anything else. Answered with
    /// [`HarvestDelegateResponse::StoreUpdateSigned`], carrying the
    /// `ScopedPayload` envelope and signature exactly as a vault `SignResult`
    /// would, so the UI files it the same way.
    SignStoreUpdate {
        request_id: RequestId,
        store_verifying_key: [u8; 32],
        payload: Vec<u8>,
    },

    // === Store-key custody (harvest#93 phase 1b) ===
    /// Wrap the store key to a backing Ghost Key, from the vault's signature
    /// over `custody::wrap_message(store)` (made under the current webapp
    /// scope), and sign the resulting copy with the store key. Answered with
    /// [`HarvestDelegateResponse::StoreKeyWrapped`]: the copy, ready to
    /// publish. The signature is a secret; the delegate drops it when done.
    WrapStoreKeyFor {
        request_id: RequestId,
        store_verifying_key: [u8; 32],
        backer_verifying_key: [u8; 32],
        scoped_payload: Vec<u8>,
        /// The vault's wrap signature: a secret. See [`WrapSignature`].
        signature: WrapSignature,
    },

    /// Recover a store key from a wrapped copy in the store's state, with the
    /// vault's signature over the wrap message. The delegate checks the
    /// signature, opens the copy, checks the seed IS this store's key, keeps
    /// it, and answers [`HarvestDelegateResponse::StoreKeyRecovered`] with no
    /// secret in it.
    UnwrapStoreKey {
        request_id: RequestId,
        store_verifying_key: [u8; 32],
        backer_verifying_key: [u8; 32],
        scoped_payload: Vec<u8>,
        /// The vault's wrap signature: a secret. See [`WrapSignature`].
        signature: WrapSignature,
        wrapped: crate::custody::WrappedStoreKey,
    },

    /// The public halves of the keys that derive from a store key: its inbox
    /// (X25519) key and its record (RSA) key. Answered with
    /// [`HarvestDelegateResponse::StoreSubkeys`].
    GetStoreSubkeys {
        request_id: RequestId,
        store_verifying_key: [u8; 32],
    },
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
    /// [`HarvestDelegateRequest::ExportBuyerConversation`]. That is why it is
    /// a [`BackupString`], which does not print itself.
    BuyerConversationExported {
        request_id: RequestId,
        store_contract_id: Vec<u8>,
        buyer_public_key: [u8; 32],
        result: Result<BackupString, String>,
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

    /// Answer to [`HarvestDelegateRequest::CreateStoreKey`]: the new store
    /// key's public half, or why none was made.
    StoreKeyCreated {
        request_id: RequestId,
        result: Result<[u8; 32], String>,
    },

    /// Answer to [`HarvestDelegateRequest::SignStoreUpdate`].
    StoreUpdateSigned {
        request_id: RequestId,
        store_verifying_key: [u8; 32],
        result: Result<StoreKeySignature, String>,
    },

    /// Answer to [`HarvestDelegateRequest::WrapStoreKeyFor`].
    StoreKeyWrapped {
        request_id: RequestId,
        store_verifying_key: [u8; 32],
        result: Result<crate::custody::AuthorizedCopy, String>,
    },

    /// Answer to [`HarvestDelegateRequest::UnwrapStoreKey`].
    StoreKeyRecovered {
        request_id: RequestId,
        store_verifying_key: [u8; 32],
        result: Result<(), String>,
    },

    /// Answer to [`HarvestDelegateRequest::GetStoreSubkeys`].
    StoreSubkeys {
        request_id: RequestId,
        store_verifying_key: [u8; 32],
        result: Result<StoreSubkeyInfo, String>,
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
///
/// `Debug` prints the peer key and redacts both conversation keys; see
/// [`Redacted`].
#[derive(Serialize, Deserialize, Clone, PartialEq)]
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
///
/// The two direction keys are still secrets -- each reads or forges one side
/// of the thread -- so `Debug` redacts them; see [`Redacted`].
#[derive(Serialize, Deserialize, Clone, PartialEq)]
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
/// `HarvestDelegateRequest` derives `Debug`, and until harvest#94 the UI
/// logged delegate traffic verbatim. A bare array would print, so the one
/// secret in this protocol that a buyer cannot replace would land in any
/// console log pasted into a bug report. This type prints as
/// `ConversationSecret(redacted)` instead; pinned by
/// `a_conversation_secret_does_not_print_itself` and
/// `no_delegate_message_prints_a_secret`.
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

/// A conversation backup string: what `ExportBuyerConversation` answers and
/// `ImportBuyerConversation` takes.
///
/// It contains the conversation's X25519 secret, so it is worth exactly as
/// much as [`ConversationSecret`] and gets the same treatment: `Debug` prints
/// `BackupString(redacted)`, so neither the response nor the request that
/// carries it can put it into a log (harvest#94).
///
/// `#[serde(transparent)]`: on the wire it is exactly the string.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct BackupString(pub String);

impl core::fmt::Debug for BackupString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BackupString(redacted)")
    }
}

/// Stands in for a secret field in a hand-written `Debug`.
///
/// The types that hold key material in this protocol write their `Debug` by
/// hand and print this in place of each secret, so the field is visibly
/// present but its bytes never reach a formatter. Pinned by
/// `no_delegate_message_prints_a_secret`.
pub(crate) struct Redacted;

impl core::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("redacted")
    }
}

impl core::fmt::Debug for ConversationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConversationKey")
            .field("peer_public_key", &self.peer_public_key)
            .field("buyer_to_seller", &Redacted)
            .field("seller_to_buyer", &Redacted)
            .finish()
    }
}

impl core::fmt::Debug for TransactionRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Destructured, so a new field does not compile until somebody
        // decides whether it may print.
        let Self {
            transaction_id,
            our_token,
            our_blinded_token: _,
            blind_signature,
            created_at,
        } = self;
        f.debug_struct("TransactionRecord")
            .field("transaction_id", transaction_id)
            .field("our_token", our_token)
            .field("our_blinded_token", &Redacted)
            .field(
                "blind_signature",
                &blind_signature.as_ref().map(|_| Redacted),
            )
            .field("created_at", created_at)
            .finish()
    }
}

impl core::fmt::Debug for RecalledConversation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Listed field by field rather than derived so a field added later is
        // left out until someone decides it is safe to print -- the failure
        // is a missing field in a log, not a key in one.
        f.debug_struct("RecalledConversation")
            .field("buyer_public_key", &self.buyer_public_key)
            .field("conversation_id", &self.conversation_id)
            .field("buyer_to_seller", &Redacted)
            .field("seller_to_buyer", &Redacted)
            // A commitment, safe to publish; see the field's docs.
            .field("order_binding", &self.order_binding)
            .field("created_at", &self.created_at)
            .field("imported", &self.imported)
            .field("backed_up", &self.backed_up)
            .finish()
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
    /// The store key that owns this store (harvest#93).
    ///
    /// `None` for a registration made before revision 2, when a store was
    /// owned by the Ghost Key it is registered under. Such a store cannot be
    /// signed for by this build; the UI moves it to a store key instead (see
    /// `ui/src/backing_flow.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_verifying_key: Option<[u8; 32]>,
}

/// A vault signature over a custody wrap message, carried from the UI to the
/// delegate (harvest#93 phase 1b).
///
/// It is a SECRET: whoever holds it can derive the key that opens a wrapped
/// copy of a store's key. This newtype exists so it cannot be printed by
/// accident: `HarvestDelegateRequest` derives `Debug`, and a bare `Vec<u8>`
/// would print. `#[serde(transparent)]`, so the wire encoding is just the
/// bytes. Same pattern as [`ConversationSecret`].
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct WrapSignature(pub Vec<u8>);

impl core::fmt::Debug for WrapSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WrapSignature(redacted)")
    }
}

/// The public halves of the keys a store key derives (harvest#93 phase 1b).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreSubkeyInfo {
    /// X25519: what buyers encrypt to (`StoreInfoV1::encryption_public_key`).
    pub inbox_public_key: [u8; 32],
    /// RSA-2048, PKCS#1 DER (`StoreInfoV1::record_public_key`).
    pub record_public_key: Vec<u8>,
}

/// A store-key signature: the envelope and the Ed25519 signature over it, the
/// two fields every signed record in a store carries.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct StoreKeySignature {
    pub scoped_payload: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A record of a feedback token exchange, stored locally by the delegate.
///
/// `Debug` redacts the blinded token and the blind signature: printed beside
/// the unblinded token they are exactly the link blind signing exists to
/// break (which buyer holds which feedback slot). The token itself redacts
/// its own key and nonce; see [`FeedbackToken`].
#[derive(Serialize, Deserialize, Clone, PartialEq)]
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
    /// It travels inside a `Debug`-deriving request enum, so any `{:?}` of
    /// that request would reach a log. This is the one secret in the protocol a
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
    // === harvest#94: nothing the delegate protocol carries prints a secret ===

    /// Every field of a sample below that must not print is filled with
    /// this byte, or with [`SECRET_TEXT`] if it is a string.
    ///
    /// **Adding a field that holds key material (or anything else that must
    /// not reach a log)? Fill it with `SECRET` / `SECRET_TEXT` in its
    /// variant's sample.** Classification below is per VARIANT, so a second
    /// secret field on a variant already marked secret-bearing is checked
    /// only if its sample carries the sentinel there too -- nothing else in
    /// this test can notice it.
    const SECRET_BYTE: u8 = 0xA7;
    const SECRET: [u8; 32] = [SECRET_BYTE; 32];
    const SECRET_TEXT: &str = "hvbk1-SECRET-BACKUP-TEXT";

    /// What a printed secret looks like: `{:?}` of a byte array is decimal,
    /// and a hand-rolled hex dump would be the other obvious slip. Three in a
    /// row, because a single `167` occurs by chance in any hash.
    ///
    /// Whitespace is removed first: `{:#?}` puts every array element on its
    /// own line, so `167, 167, 167` never appears in pretty output even when
    /// every byte of the key does.
    fn leaked(printed: &str) -> Option<&'static str> {
        let squashed: String = printed.chars().filter(|c| !c.is_whitespace()).collect();
        ["167,167,167", "a7a7a7", "A7A7A7", "SECRET"]
            .into_iter()
            .find(|needle| squashed.contains(needle))
    }

    /// Whether `value`'s wire encoding carries the sentinel secret -- proof
    /// that a sample classified as secret-bearing really holds one, so a
    /// clean `Debug` of it means something. ciborium writes a byte array as
    /// an array of integers, each `0x18 0xA7`.
    fn carries_secret<T: Serialize>(value: &T) -> bool {
        let wire = crate::to_cbor(value).expect("cbor");
        let array: Vec<u8> = [0x18, SECRET_BYTE].repeat(32);
        wire.windows(array.len()).any(|w| w == array.as_slice())
            || wire
                .windows(SECRET_TEXT.len())
                .any(|w| w == SECRET_TEXT.as_bytes())
    }

    /// Every response variant, as `(index, carries key material)`.
    ///
    /// Exhaustive with no wildcard, so a new variant does not compile until
    /// somebody decides here whether it carries a secret -- and then
    /// [`no_delegate_message_prints_a_secret`] fails until
    /// [`response_samples`] has one of it.
    fn classify_response(r: &HarvestDelegateResponse) -> (usize, bool) {
        use HarvestDelegateResponse as R;
        match r {
            R::ReputationKeysInitialized { .. } => (0, false),
            R::RsaPublicKey { .. } => (1, false),
            R::EncryptionKeyReady { .. } => (2, false),
            R::BuyerConversationStored { .. } => (3, false),
            // Both direction keys of every recalled conversation.
            R::BuyerConversationList { .. } => (4, true),
            // The backup string, which contains the X25519 secret.
            R::BuyerConversationExported { .. } => (5, true),
            R::BuyerConversationImported { .. } => (6, false),
            R::BuyerConversationMarkedBackedUp { .. } => (7, false),
            R::BuyerConversationForgotten { .. } => (8, false),
            // Both direction keys for every buyer asked about.
            R::ConversationKeys { .. } => (9, true),
            R::BlindSignatureResult { .. } => (10, false),
            R::ListingCreated { .. } => (11, false),
            R::TransactionRecorded { .. } => (12, false),
            R::BlindSignatureRecorded { .. } => (13, false),
            // Our unblinded token (nonce, entry key) beside the blinded one:
            // together they link the buyer to their feedback slot.
            R::TransactionList { .. } => (14, true),
            R::ContractUpdate { .. } => (15, false),
            R::ContractState { .. } => (16, false),
            R::StoreRegistered { .. } => (17, false),
            R::StoreList { .. } => (18, false),
            R::RememberedStores { .. } => (19, false),
            R::MigrationMarker { .. } => (20, false),
            R::MigrationMarkerRecorded { .. } => (21, false),
            R::Error { .. } => (22, false),
            // The store key's public half only; the seed never leaves.
            R::StoreKeyCreated { .. } => (23, false),
            // A signature over a store record, published as it is.
            R::StoreUpdateSigned { .. } => (24, false),
        }
    }
    const RESPONSE_VARIANTS: usize = 25;

    /// Every request variant, as for [`classify_response`].
    fn classify_request(r: &HarvestDelegateRequest) -> (usize, bool) {
        use HarvestDelegateRequest as Q;
        match r {
            Q::InitReputationKeys { .. } => (0, false),
            Q::GetRsaPublicKey { .. } => (1, false),
            Q::BlindSignFeedbackToken { .. } => (2, false),
            Q::InitEncryptionKey { .. } => (3, false),
            Q::DeriveConversationKeys { .. } => (4, false),
            // The buyer's ephemeral X25519 secret.
            Q::StoreBuyerConversation { .. } => (5, true),
            Q::ListBuyerConversations { .. } => (6, false),
            Q::ForgetBuyerConversation { .. } => (7, false),
            Q::ExportBuyerConversation { .. } => (8, false),
            // The pasted backup string.
            Q::ImportBuyerConversation { .. } => (9, true),
            Q::MarkConversationBackedUp { .. } => (10, false),
            Q::CreateListing { .. } => (11, false),
            // The unblinded token (nonce, entry key); see `TransactionList`.
            Q::BeginTransaction { .. } => (12, true),
            Q::RecordBlindSignature { .. } => (13, false),
            Q::ListTransactions => (14, false),
            Q::RegisterStore { .. } => (15, false),
            Q::ListStores { .. } => (16, false),
            Q::GetMigrationMarker { .. } => (17, false),
            Q::SetMigrationMarker { .. } => (18, false),
            Q::RememberStore { .. } => (19, false),
            Q::SetStoreArchived { .. } => (20, false),
            Q::ListRememberedStores => (21, false),
            Q::CreateStoreKey { .. } => (22, false),
            // A store record to be signed and published.
            Q::SignStoreUpdate { .. } => (23, false),
        }
    }
    const REQUEST_VARIANTS: usize = 24;

    /// A feedback token whose private parts are the sentinel. Built
    /// directly rather than with `FeedbackToken::new`, which would derive
    /// the nonce and so put a hash, not the sentinel, where it must not
    /// print.
    fn private_token() -> FeedbackToken {
        FeedbackToken {
            target_reputation_contract: [9u8; 32],
            nonce: SECRET,
            entry_key: SECRET,
        }
    }

    fn recalled() -> RecalledConversation {
        RecalledConversation {
            buyer_public_key: [1u8; 32],
            conversation_id: [2u8; 32],
            buyer_to_seller: SECRET,
            seller_to_buyer: SECRET,
            order_binding: [4u8; 32],
            created_at: 1_700_000_000,
            imported: false,
            backed_up: true,
        }
    }

    fn response_samples() -> Vec<HarvestDelegateResponse> {
        use HarvestDelegateResponse as R;
        let fp = || "fp-one".to_string();
        let store = || vec![3u8; 32];
        vec![
            R::ReputationKeysInitialized {
                ghostkey_fingerprint: fp(),
                rsa_public_key_der: vec![5u8; 8],
            },
            R::RsaPublicKey {
                ghostkey_fingerprint: fp(),
                rsa_public_key_der: vec![5u8; 8],
            },
            R::EncryptionKeyReady {
                ghostkey_fingerprint: fp(),
                x25519_public_key: vec![6u8; 32],
            },
            R::BuyerConversationStored {
                request_id: 42,
                result: Ok(()),
                evicted: vec![EvictedConversation {
                    buyer_public_key: [1u8; 32],
                    was_backed_up: false,
                }],
            },
            R::BuyerConversationList {
                request_id: 42,
                store_contract_id: store(),
                conversations: vec![recalled()],
            },
            R::BuyerConversationExported {
                request_id: 42,
                store_contract_id: store(),
                buyer_public_key: [1u8; 32],
                result: Ok(BackupString(SECRET_TEXT.to_string())),
            },
            R::BuyerConversationImported {
                request_id: 42,
                result: Ok(ImportedConversation::Imported {
                    store_contract_id: store(),
                    buyer_public_key: [1u8; 32],
                }),
            },
            R::BuyerConversationMarkedBackedUp {
                request_id: 42,
                store_contract_id: store(),
                buyer_public_key: [1u8; 32],
                result: Ok(true),
            },
            R::BuyerConversationForgotten {
                request_id: 42,
                result: Ok(()),
            },
            R::ConversationKeys {
                request_id: 42,
                ghostkey_fingerprint: fp(),
                result: Ok(vec![ConversationKey {
                    peer_public_key: vec![1u8; 32],
                    buyer_to_seller: SECRET,
                    seller_to_buyer: SECRET,
                }]),
            },
            R::BlindSignatureResult {
                request_id: 42,
                result: Ok(vec![8u8; 16]),
            },
            R::ListingCreated {
                request_id: 42,
                result: Err("not signed".into()),
            },
            R::TransactionRecorded {
                request_id: 42,
                result: Ok(()),
            },
            R::BlindSignatureRecorded {
                request_id: 42,
                result: Ok(()),
            },
            R::TransactionList {
                transactions: vec![TransactionRecord {
                    transaction_id: "tx-one".into(),
                    our_token: private_token(),
                    our_blinded_token: SECRET.to_vec(),
                    blind_signature: Some(SECRET.to_vec()),
                    created_at: DateTime::<Utc>::from_timestamp(1_700_000_000, 0)
                        .expect("timestamp"),
                }],
            },
            R::ContractUpdate {
                contract_key: store(),
                update_data: vec![13u8; 8],
            },
            R::ContractState {
                contract_key: store(),
                state: vec![14u8; 8],
            },
            R::StoreRegistered {
                ghostkey_fingerprint: fp(),
            },
            R::StoreList {
                ghostkey_fingerprint: fp(),
                stores: vec![StoreRegistration {
                    store_contract_id: store(),
                    reputation_contract_id: vec![15u8; 32],
                    mailbox_contract_id: vec![16u8; 32],
                    store_contract_key: None,
                    store_verifying_key: Some([17u8; 32]),
                }],
            },
            R::RememberedStores {
                stores: vec![RememberedStore {
                    store_code: "abcdefghijkl".into(),
                    archived: false,
                }],
            },
            R::MigrationMarker {
                marker: "marker-one".into(),
                present: true,
            },
            R::MigrationMarkerRecorded {
                marker: "marker-one".into(),
                recorded: true,
            },
            R::Error {
                message: "refused".into(),
            },
            R::StoreKeyCreated {
                request_id: 43,
                result: Ok([17u8; 32]),
            },
            R::StoreUpdateSigned {
                request_id: 44,
                store_verifying_key: [17u8; 32],
                result: Ok(StoreKeySignature {
                    scoped_payload: vec![18u8; 8],
                    signature: vec![19u8; 64],
                }),
            },
        ]
    }

    fn request_samples() -> Vec<HarvestDelegateRequest> {
        use HarvestDelegateRequest as Q;
        let fp = || "fp-one".to_string();
        let store = || vec![3u8; 32];
        vec![
            Q::InitReputationKeys {
                ghostkey_fingerprint: fp(),
            },
            Q::GetRsaPublicKey {
                ghostkey_fingerprint: fp(),
            },
            Q::BlindSignFeedbackToken {
                request_id: 42,
                ghostkey_fingerprint: fp(),
                blinded_token: vec![11u8; 16],
            },
            Q::InitEncryptionKey {
                ghostkey_fingerprint: fp(),
            },
            Q::DeriveConversationKeys {
                request_id: 42,
                ghostkey_fingerprint: fp(),
                peer_public_keys: vec![vec![1u8; 32]],
            },
            Q::StoreBuyerConversation {
                request_id: 42,
                store_contract_id: store(),
                secret: ConversationSecret(SECRET),
                seller_public_key: [9u8; 32],
                conversation_id: [2u8; 32],
                created_at: 1_700_000_000,
            },
            Q::ListBuyerConversations {
                request_id: 42,
                store_contract_id: store(),
            },
            Q::ForgetBuyerConversation {
                request_id: 42,
                store_contract_id: store(),
                buyer_public_key: [1u8; 32],
            },
            Q::ExportBuyerConversation {
                request_id: 42,
                store_contract_id: store(),
                buyer_public_key: [1u8; 32],
            },
            Q::ImportBuyerConversation {
                request_id: 42,
                backup: BackupString(SECRET_TEXT.to_string()),
            },
            Q::MarkConversationBackedUp {
                request_id: 42,
                store_contract_id: store(),
                buyer_public_key: [1u8; 32],
            },
            Q::CreateListing {
                request_id: 42,
                ghostkey_fingerprint: fp(),
                listing: Listing {
                    id: crate::listing::ListingId([17u8; 32]),
                    title: "a mug".into(),
                    description: "blue".into(),
                    kind: crate::listing::ListingKind::Sale,
                    price: None,
                    created_at: DateTime::<Utc>::from_timestamp(1_700_000_000, 0)
                        .expect("timestamp"),
                },
            },
            Q::BeginTransaction {
                request_id: 42,
                transaction_id: "tx-one".into(),
                our_token: private_token(),
                // Not the sentinel: the seller holds the blinded token
                // already, and with the token's own key and nonce redacted
                // it links nothing on its own.
                our_blinded_token: vec![11u8; 16],
            },
            Q::RecordBlindSignature {
                request_id: 42,
                transaction_id: "tx-one".into(),
                blind_signature: vec![12u8; 16],
            },
            Q::ListTransactions,
            Q::RegisterStore {
                ghostkey_fingerprint: fp(),
                store_contract_id: store(),
                reputation_contract_id: vec![15u8; 32],
                mailbox_contract_id: vec![16u8; 32],
                store_verifying_key: Some([17u8; 32]),
            },
            Q::ListStores {
                ghostkey_fingerprint: fp(),
            },
            Q::GetMigrationMarker {
                marker: "marker-one".into(),
            },
            Q::SetMigrationMarker {
                marker: "marker-one".into(),
                note: "done".into(),
            },
            Q::RememberStore {
                store_code: "abcdefghijkl".into(),
            },
            Q::SetStoreArchived {
                store_code: "abcdefghijkl".into(),
                archived: true,
            },
            Q::ListRememberedStores,
            Q::CreateStoreKey {
                request_id: 43,
                ghostkey_fingerprint: Some(fp()),
            },
            Q::SignStoreUpdate {
                request_id: 44,
                store_verifying_key: [17u8; 32],
                payload: vec![18u8; 8],
            },
        ]
    }

    /// Check one sample: classified correctly, and nothing printed from it
    /// shows the secret.
    fn check_sample<T: Serialize + core::fmt::Debug>(what: &str, value: &T, secret_bearing: bool) {
        assert_eq!(
            carries_secret(value),
            secret_bearing,
            "{what}: classified as secret-bearing={secret_bearing}, but its sample \
             {} the sentinel secret. Fill every field holding key material with \
             SECRET / SECRET_TEXT, and classify the variant by what it carries",
            if secret_bearing {
                "does not carry"
            } else {
                "carries"
            },
        );
        for printed in [format!("{value:?}"), format!("{value:#?}")] {
            if let Some(needle) = leaked(&printed) {
                panic!("{what} printed its secret ({needle:?} found): {printed}");
            }
        }
    }

    /// Every Bitcoin-surface response variant, as for [`classify_response`].
    fn classify_bitcoin_response(r: &crate::BitcoinDelegateResponse) -> (usize, bool) {
        use crate::BitcoinDelegateResponse as B;
        match r {
            B::Watched { .. } => (0, false),
            B::Unwatched { .. } => (1, false),
            B::WatchList { .. } => (2, false),
            B::OrderAssociated { .. } => (3, false),
            B::BridgeConfigured { .. } => (4, false),
            B::Bridge { .. } => (5, false),
            // The payment xpub, which links every address it derives.
            B::PaymentXpubSet { .. } => (6, true),
            B::PaymentXpub { .. } => (7, true),
            B::OrderAddress { .. } => (8, false),
        }
    }
    const BITCOIN_RESPONSE_VARIANTS: usize = 9;

    /// Every Bitcoin-surface request variant, as for [`classify_response`].
    fn classify_bitcoin_request(r: &crate::BitcoinDelegateRequest) -> (usize, bool) {
        use crate::BitcoinDelegateRequest as B;
        match r {
            B::Watch { .. } => (0, false),
            B::Unwatch { .. } => (1, false),
            B::ListWatched => (2, false),
            B::AssociateOrder { .. } => (3, false),
            B::ConfigureBridge { .. } => (4, false),
            B::GetBridge => (5, false),
            // The payment xpub, as pasted.
            B::SetPaymentXpub { .. } => (6, true),
            B::GetPaymentXpub => (7, false),
            B::DeriveOrderAddress { .. } => (8, false),
        }
    }
    const BITCOIN_REQUEST_VARIANTS: usize = 9;

    fn watch() -> crate::WatchedPayment {
        crate::WatchedPayment {
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 0xde, 0xad],
            address: "tb1qexample".into(),
            label: Some("rent".into()),
            order_id: None,
            expected_amount_sats: Some(50_000),
            contract_id: None,
            added_at_ms: 1_700_000_000_000,
            bridge_synced: false,
            last_error: None,
        }
    }

    fn xpub_status() -> crate::PaymentXpubStatus {
        crate::PaymentXpubStatus {
            xpub: SECRET_TEXT.into(),
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            next_index: 3,
        }
    }

    fn bitcoin_response_samples() -> Vec<crate::BitcoinDelegateResponse> {
        use crate::BitcoinDelegateResponse as B;
        let endpoint = crate::BridgeEndpoint {
            url: "https://bridge.example".into(),
            bridge_id: freenet_bitcoin_common::BridgeId([1u8; 32]),
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            auth: crate::BridgeAuthMode::Open,
        };
        vec![
            B::Watched {
                request_id: 42,
                result: Ok(watch()),
            },
            B::Unwatched {
                request_id: 42,
                result: Ok(()),
            },
            B::WatchList {
                watches: vec![watch()],
            },
            B::OrderAssociated {
                request_id: 42,
                result: Ok(()),
            },
            B::BridgeConfigured {
                request_id: 42,
                result: Ok(()),
            },
            B::Bridge {
                endpoint: Some(endpoint),
            },
            B::PaymentXpubSet {
                request_id: 42,
                result: Ok(xpub_status()),
                matched_scripts: vec![vec![2u8; 22]],
            },
            B::PaymentXpub {
                status: Some(xpub_status()),
            },
            B::OrderAddress {
                request_id: 42,
                result: Ok(crate::DerivedAddress {
                    index: 3,
                    network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                    script_pubkey: vec![2u8; 22],
                    address: "tb1qexample".into(),
                }),
                matched_scripts: vec![],
            },
        ]
    }

    fn bitcoin_request_samples() -> Vec<crate::BitcoinDelegateRequest> {
        use crate::BitcoinDelegateRequest as B;
        vec![
            B::Watch {
                request_id: 42,
                watch: watch(),
            },
            B::Unwatch {
                request_id: 42,
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                script_pubkey: vec![2u8; 22],
            },
            B::ListWatched,
            B::AssociateOrder {
                request_id: 42,
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                script_pubkey: vec![2u8; 22],
                order_id: crate::OrderId([5u8; 32]),
                expected_amount_sats: 50_000,
            },
            B::ConfigureBridge {
                request_id: 42,
                endpoint: crate::BridgeEndpoint {
                    url: "https://bridge.example".into(),
                    bridge_id: freenet_bitcoin_common::BridgeId([1u8; 32]),
                    network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                    auth: crate::BridgeAuthMode::Open,
                },
            },
            B::GetBridge,
            B::SetPaymentXpub {
                request_id: 42,
                xpub: SECRET_TEXT.into(),
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                published_scripts: vec![vec![2u8; 22]],
            },
            B::GetPaymentXpub,
            B::DeriveOrderAddress {
                request_id: 42,
                published_scripts: vec![],
            },
        ]
    }

    /// Run every sample through [`check_sample`] and fail on any variant
    /// `classify` knows of that has no sample.
    fn check_all<T: Serialize + core::fmt::Debug>(
        what: &str,
        samples: Vec<T>,
        classify: impl Fn(&T) -> (usize, bool),
        variants: usize,
    ) {
        let mut seen = vec![false; variants];
        for sample in samples {
            let (index, secret_bearing) = classify(&sample);
            seen[index] = true;
            check_sample(&format!("{what} variant {index}"), &sample, secret_bearing);
        }
        let missing: Vec<usize> = (0..variants).filter(|i| !seen[*i]).collect();
        assert!(
            missing.is_empty(),
            "no sample of {what} variant(s) {missing:?}"
        );
    }

    /// **No request or response the harvest delegate speaks prints a
    /// secret, under `{:?}` or `{:#?}`** (harvest#94).
    ///
    /// Covers both enums on each of its two surfaces. Every variant is
    /// sampled -- the `classify_*` functions are exhaustive, and the coverage
    /// check fails until a new variant has a sample -- and each sample puts
    /// the sentinel in every field that must not print. `carries_secret` then
    /// confirms the sentinel really is in the value, so a clean print is a
    /// redaction and not an absent secret.
    ///
    /// The UI's one-line log summaries are tested beside them in
    /// `harvest-ui`'s `gateway::log_summary`.
    #[test]
    fn no_delegate_message_prints_a_secret() {
        check_all(
            "response",
            response_samples(),
            classify_response,
            RESPONSE_VARIANTS,
        );
        check_all(
            "request",
            request_samples(),
            classify_request,
            REQUEST_VARIANTS,
        );
        check_all(
            "bitcoin response",
            bitcoin_response_samples(),
            classify_bitcoin_response,
            BITCOIN_RESPONSE_VARIANTS,
        );
        check_all(
            "bitcoin request",
            bitcoin_request_samples(),
            classify_bitcoin_request,
            BITCOIN_REQUEST_VARIANTS,
        );

        // And the secret-bearing types on their own, which is how they would
        // reach a log from anywhere but the enums.
        check_sample("RecalledConversation", &recalled(), true);
        check_sample(
            "ConversationKey",
            &ConversationKey {
                peer_public_key: vec![1u8; 32],
                buyer_to_seller: SECRET,
                seller_to_buyer: SECRET,
            },
            true,
        );
        check_sample("BackupString", &BackupString(SECRET_TEXT.into()), true);
        check_sample("ConversationSecret", &ConversationSecret(SECRET), true);
        check_sample("FeedbackToken", &private_token(), true);
        check_sample("PaymentXpubStatus", &xpub_status(), true);
    }

    /// The redaction is a `Debug` property only: a `BackupString` is exactly
    /// its text on the wire, so a backup made by an earlier build still
    /// imports and one made now still pastes into an earlier build.
    #[test]
    fn a_backup_string_encodes_as_its_text() {
        assert_eq!(
            crate::to_cbor(&BackupString("hvbk1-abc".into())).expect("cbor"),
            crate::to_cbor(&"hvbk1-abc").expect("cbor"),
        );
    }
}
