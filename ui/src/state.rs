// EVERYTHING BELOW RUNS OUTSIDE THIS BORROW, AND MUST.
//
// This handler is invoked as
// `apply_delegate_response(&mut APP_STATE.write(), ..)`
// (`gateway::response_handler`), so a write guard on APP_STATE is
// held for the whole call. Anything reached from here that takes
// another borrow panics with `AlreadyBorrowedMut`.
//
// The consequence is worse than one failed call, because this
// workspace builds with `panic = "abort"` (see the root
// Cargo.toml). There is no unwinding, so the write guard is
// NEVER DROPPED: a single re-entrant read leaves APP_STATE
// mutably borrowed for the rest of the page's life, and every
// later `read()` anywhere in the app panics too.
//
// That is exactly what happened on the first ghostkey ever
// connected. `start_reputation_migration` was called
// synchronously from this arm and panicked at
// migrate_ops.rs:258; the leaked guard then took down
// `store_ops::list_stores` (which was ALREADY correctly
// deferred) and `send_harvest_request` twice, which is why the
// harvest delegate appeared not to answer about migration
// markers.
//
// So the rule for this arm is simply: touch APP_STATE from here
// synchronously and nothing else, and do every follow-up from a
// spawned task. `spawn_local` is sufficient on its own -- it
// pushes onto a queue drained by `queueMicrotask`
// (wasm-bindgen-futures `queue.rs::schedule_task`) rather than
// polling eagerly -- and microtasks cannot run until this
// synchronous statement has returned and the guard has dropped.
//! Application state managed via Dioxus GlobalSignal.
//!
//! Centralizes all reactive state so the response handler and UI components
//! can read/write from a single source of truth.

use dioxus::logger::tracing::{info, warn};
use harvest_common::listing::AuthorizedListing;
use harvest_common::mailbox::EncryptedMessage;
use harvest_common::payment::AuthorizedOrder;
use harvest_common::reputation::FeedbackEntry;
use harvest_common::store::StoreInfoV1;
use harvest_common::{
    BitcoinDelegateResponse, BridgeEndpoint, HarvestDelegateResponse, StoreRegistration,
    WatchedPayment,
};
use std::collections::{HashMap, HashSet};

use freenet_bitcoin_common::BitcoinNetwork;

/// The main application state.
#[derive(Clone, Debug, Default)]
pub struct AppState {
    /// The harvest delegate key (set after registration during app startup).
    pub harvest_delegate_key: Option<freenet_stdlib::prelude::DelegateKey>,

    /// The ghostkey delegate key (set after registration during app startup).
    pub ghostkey_delegate_key: Option<freenet_stdlib::prelude::DelegateKey>,

    /// Stores we're currently browsing, keyed by store contract ID.
    pub browsing_stores: HashMap<Vec<u8>, BrowsingStore>,

    /// The store the Browse tab shows. `browsing_stores` also holds
    /// placeholder entries -- one is created the moment a link is opened and
    /// before any state arrives, and another whenever reputation state turns
    /// up for a store we haven't loaded -- so "whichever entry the map
    /// iterates first" is not a safe answer to "which store is on screen".
    pub active_store_id: Option<Vec<u8>>,

    /// Why the store named by a link could not be opened, if it couldn't.
    /// Without this the Browse tab sits on "Loading store..." forever: a GET
    /// that fails after it left the client is only logged, and nothing in the
    /// response path can attribute the failure back to the link that caused
    /// it. bs58 has no checksum either, so a one-character typo in a store id
    /// usually still decodes to 32 valid-looking bytes and is dispatched as a
    /// GET for a contract that does not exist.
    pub store_link_error: Option<String>,

    /// Maps reputation contract IDs back to their store contract IDs,
    /// so reputation state can be matched to the right store.
    pub reputation_to_store: HashMap<Vec<u8>, Vec<u8>>,

    /// Maps mailbox contract IDs back to their store contract IDs.
    pub mailbox_to_store: HashMap<Vec<u8>, Vec<u8>>,

    /// Our own stores (ghostkey fingerprint -> list of registrations).
    pub my_stores: HashMap<String, Vec<StoreRegistration>>,

    /// Contract ids a completed migration has superseded, as
    /// `predecessor -> successor`.
    ///
    /// See [`AppState::adopt_migrated_contract_id`] for why this has to be
    /// remembered rather than simply applied and forgotten.
    pub migrated_contract_ids: HashMap<Vec<u8>, Vec<u8>>,

    /// Store contracts we have already asked the gateway for. Every
    /// `StoreList` answer names every store the ghostkey owns, and a
    /// ghostkey re-connecting in the same session produces another answer,
    /// so without this each repeat costs a fresh GET+subscribe per store --
    /// and each of those re-triggers the reputation follow-on GET too.
    pub subscribed_stores: HashSet<Vec<u8>>,

    /// Stores we asked the gateway for and which never answered, so we know
    /// nothing is published at that address rather than merely not knowing
    /// yet.
    ///
    /// The distinction is the whole point. `browsing_stores[id].info == None`
    /// conflates "the GET is still in flight" with "there is nothing there",
    /// and publishing the seller's details needs a version one past whatever
    /// is published now -- so treating the first as the second guesses
    /// version 1 for a store the network may hold at version 5, and the
    /// contract's last-writer-wins merge drops the edit silently. See
    /// `publish_store_details`.
    pub store_state_unavailable: HashSet<Vec<u8>>,

    /// The highest store-info version we have queued for signing per store,
    /// which the contract has not necessarily accepted yet.
    ///
    /// Local state only catches up when the update round-trips, so two edits
    /// submitted before that happens would both compute the same next
    /// version and the second would lose to the first. Remembering what we
    /// asked for closes that window without waiting on the network.
    pub last_queued_store_version: HashMap<Vec<u8>, u32>,

    /// Ghostkey identities available to us. Each successful
    /// `RequestAnyAccess` response merges (deduped by fingerprint) into
    /// this list rather than replacing it, so users can connect a
    /// second key without losing visibility into the first.
    pub ghostkeys: Vec<ghostkey_common::GhostKeyInfo>,

    /// Set while a `RequestAnyAccess` is in flight, so the UI can
    /// disable the "Connect" button and rapid double-clicks don't queue
    /// multiple delegate prompts. Cleared on every terminal response
    /// (GhostKeyList success, AccessDenied, NoIdentityAvailable, Error).
    pub request_any_access_in_flight: bool,

    /// RSA public keys for our identities (fingerprint -> DER bytes).
    pub rsa_public_keys: HashMap<String, Vec<u8>>,

    /// Long-term X25519 public keys the harvest delegate holds for our own
    /// identities (fingerprint -> 32 bytes).
    ///
    /// The public half only. The private half never leaves the delegate; see
    /// `harvest-delegate`'s `messaging`. This is what gets published in
    /// `StoreInfoV1::encryption_public_key` so buyers have something to
    /// encrypt to.
    pub encryption_public_keys: HashMap<String, [u8; 32]>,

    /// Conversation keys the delegate has derived, keyed by the buyer
    /// ephemeral public key each was derived against.
    ///
    /// Not keyed by identity as well, and that is safe rather than sloppy: a
    /// key that belonged to a different identity cannot silently decrypt the
    /// wrong message, because AES-GCM authenticates -- the message would come
    /// back as `MailboxEntry::Unreadable`, not as wrong plaintext. Buyer
    /// ephemeral keys are freshly random per message in any case, so a
    /// collision needs a deliberate one.
    pub conversation_keys: HashMap<Vec<u8>, crate::messaging::ConversationKeys>,

    /// `DeriveConversationKeys` requests in flight, as request id -> the
    /// buyer public keys that request asked about.
    ///
    /// Needed so a mailbox update that arrives while a request is out does
    /// not ask again for the same keys -- mailbox state re-arrives on every
    /// update notification, so without this a busy store issues one delegate
    /// request per message per notification. Also what makes a failure
    /// recoverable: an error answer un-asks its keys, so the next mailbox
    /// update retries them.
    pub pending_conversation_key_requests: std::collections::BTreeMap<u64, Vec<Vec<u8>>>,

    /// Routing tags the delegate was asked about and declined to answer.
    ///
    /// Its omissions are PERMANENT, not transient: it drops a peer key only
    /// when the key is malformed or low-order, and both are deterministic
    /// properties of the bytes. Without remembering them, one message
    /// carrying an unusable tag puts the tab into an unbounded loop, because
    /// mailbox state re-arrives on every update notification and each arrival
    /// would ask again.
    ///
    /// A transient failure is the `Err` answer instead, where nothing was
    /// derived and nothing is recorded here, so those retry.
    pub declined_conversation_tags: HashSet<Vec<u8>>,

    /// Stores whose kept buyer conversations have already been asked for.
    ///
    /// Store state re-arrives on every update notification, so without this a
    /// buyer browsing a busy store issues one recall per notification.
    pub buyer_conversations_recalled: HashSet<Vec<u8>>,

    /// `ExportBuyerConversation` and `MarkConversationBackedUp` requests in
    /// flight, as request id -> the store AND conversation THIS browser asked
    /// about.
    ///
    /// One map for two families because both answer about a store and
    /// neither can be outstanding for the same request id. The reason they
    /// are correlated at all is the one stated on
    /// [`Self::pending_conversation_recalls`]: this file says in three places
    /// that an answer is filed where the QUESTION says it belongs, and a
    /// principle followed in three places out of five is one the next reader
    /// concludes is optional.
    pub pending_conversation_backups: std::collections::BTreeMap<u64, (Vec<u8>, [u8; 32])>,

    /// `ListBuyerConversations` requests in flight, as request id -> the
    /// store THIS browser asked about.
    ///
    /// The answer echoes a store id too, and this is the one that is used.
    /// Same lesson as the echoed conversation tag on the seller's side: a
    /// consumer that files an answer where the ANSWER says it belongs will,
    /// the first time the two disagree, put one store's conversation keys
    /// against another store's mailbox -- and a buyer reading a thread with
    /// the wrong store is the shape of mistake nothing downstream can catch.
    pub pending_conversation_recalls: std::collections::BTreeMap<u64, Vec<u8>>,

    /// `StoreBuyerConversation` requests in flight, as request id -> the
    /// store the conversation is with and its routing tag.
    ///
    /// Kept so a refusal can be reported against the store it belongs to. A
    /// refusal matters: the buyer has already been told their message was
    /// sent, and a conversation the delegate did not keep becomes unreadable
    /// the moment the tab closes.
    ///
    /// # Why the TAG is here too
    ///
    /// The answer -- [`HarvestDelegateResponse::BuyerConversationStored`] --
    /// carries a request id and nothing else, so without the tag recorded at
    /// ASK time there is no way to say which of a store's conversations was
    /// kept. Marking the store's newest conversation instead would be the
    /// familiar mistake of trusting position: a second conversation opened
    /// while the first was in flight would take the credit for the first's
    /// write, and the buy flow would then let a buyer pay against a key the
    /// delegate never stored.
    pub pending_conversation_persists: std::collections::BTreeMap<u64, (Vec<u8>, [u8; 32])>,

    /// Orders this tab has already published a `Paid` transition for.
    ///
    /// In-flight only. See [`AppState::publish_settled_orders`] for why it is
    /// deliberately not durable.
    pub settlements_submitted: HashSet<harvest_common::payment::OrderId>,

    /// `ForgetBuyerConversation` requests in flight, as request id -> the
    /// store and routing tag asked about.
    ///
    /// The conversation is dropped from this browser only when the delegate
    /// says the record is gone, so a refused removal leaves the thread on
    /// screen rather than hiding a record that is still on disk.
    pub pending_conversation_forgets: std::collections::BTreeMap<u64, (Vec<u8>, [u8; 32])>,

    /// The backup string the buyer asked for and has not dismissed, if any.
    ///
    /// Held here rather than in the component because it arrives
    /// asynchronously, from a delegate answer, long after the click that
    /// asked for it.
    pub conversation_backup_on_screen: Option<ConversationBackup>,

    /// Request ids for the messaging requests above. A separate counter from
    /// `BitcoinState::next_request_id` because they are different request
    /// enums answered by different response enums; sharing one would imply a
    /// correlation that does not exist.
    pub next_messaging_request_id: u64,

    /// Store creation pending RSA key response. When InitReputationKeys
    /// is sent, the store details are stored here. When ReputationKeysInitialized
    /// arrives, the response handler picks this up and creates the contracts.
    pub pending_store_creation: Option<PendingStoreCreation>,

    /// Signature requests sent to the ghostkey delegate and not yet
    /// answered, oldest first.
    ///
    /// A single field could not stay correct once two kinds of signature
    /// existed: publishing a store signs its info, and the seller can start a
    /// listing immediately afterwards, so both can be outstanding at once and
    /// the wrong one would consume the answer.
    ///
    /// `SignResult` carries no correlation id, but arrival order is NOT what
    /// ties an answer to its request -- the scoped payload names the bytes
    /// that were signed, and `signed_message_bytes` matches on those, so an
    /// answer that comes back out of order still finds its own request. The
    /// queue is the collection of what is outstanding, oldest first for
    /// legibility; it is not the correlation mechanism.
    pub pending_signatures: std::collections::VecDeque<PendingSignature>,

    /// Invoices the seller has asked to issue, waiting on the payment address
    /// the delegate is deriving for each, keyed by the `DeriveOrderAddress`
    /// request id.
    ///
    /// A map rather than a queue, and keyed rather than positional, for the
    /// same reason `pending_signatures` matches on signed bytes: the answer
    /// carries its own correlation (`OrderAddress::request_id`), and an
    /// address grafted onto the wrong invoice would send a buyer's payment to
    /// another buyer's order.
    ///
    /// A `BTreeMap` specifically. Request ids are allocated in issue order, so
    /// iteration is chronological rather than arbitrary -- but the reason it
    /// is worth stating is the test: with a `HashMap`, "take whichever entry
    /// comes first" is right often enough by luck that a test for the
    /// correlation passes under that mutation about half the time, which is to
    /// say it is not testing the correlation at all.
    pub pending_invoices: std::collections::BTreeMap<u64, PendingInvoice>,

    /// Ghostkey certificates by fingerprint, as the delegate reports them.
    ///
    /// A store's details carry the seller's certificate so a buyer can check
    /// the trust chain, and the certificate has to be inside the record
    /// *before* it is signed -- the copy `SignResult` returns alongside the
    /// signature arrives a round-trip too late to be part of what was signed.
    pub certificates: HashMap<String, String>,

    /// Store details the seller has entered and asked to publish, waiting on
    /// the certificate that has to travel inside the signed record. See
    /// `start_store_edit_if_ready`.
    pub pending_store_edit: Option<PendingStoreEdit>,

    /// Signed listings ready to be submitted to the store contract.
    /// The UI should pick these up and send them as contract updates.
    pub signed_listings_ready: Vec<AuthorizedListing>,

    /// Pending messages/events for the UI to display.
    pub notifications: Vec<String>,

    /// Bitcoin/Payments state: bridge config, private watch list, and live
    /// on-chain data mirrored from subscribed Bitcoin contracts.
    pub bitcoin: BitcoinState,
}

/// Details for a store being created, waiting on the two delegate responses
/// that supply the rest of its inputs. See `start_store_creation_if_ready`.
#[derive(Clone, Debug)]
pub struct PendingStoreCreation {
    pub ghostkey_fingerprint: String,
    pub seller_verifying_key_bytes: [u8; 32],
    /// Filled by the ghostkey delegate's `Certificate` (or `GhostKeyDetail`)
    /// response. Empty until it arrives.
    pub certificate_pem: String,
    pub store_name: String,
    pub description: String,
    pub payment_instructions: String,
    /// Filled by the harvest delegate's `ReputationKeysInitialized` response.
    /// `None` until it arrives.
    pub rsa_public_key_der: Option<Vec<u8>>,
    /// Filled by the harvest delegate's `EncryptionKeyReady` response.
    ///
    /// **Not** part of the readiness gate, unlike the two above. Creation
    /// waits on the certificate and the RSA key because a store without
    /// either is broken in ways only a fresh signature can repair; a store
    /// without an encryption key is one buyers cannot message, which
    /// `store_details_gap` reports and re-publishing fixes. Adding a third
    /// thing to wait on would add a third way for a creation to hang
    /// forever, and this one has a recovery path that those do not.
    ///
    /// In practice it is nearly always present: `InitEncryptionKey` goes out
    /// alongside `InitReputationKeys`, and generating a 2048-bit RSA key
    /// takes far longer than 32 random bytes. Nothing here relies on that.
    pub encryption_public_key: Option<[u8; 32]>,
}

/// Publish the three contracts of a store whose inputs are all present.
///
/// Split out of `AppState::start_store_creation_if_ready` so the gate itself
/// compiles and is testable off-target: everything below here needs a browser.
#[cfg(target_arch = "wasm32")]
fn spawn_store_creation(pending: PendingStoreCreation) {
    let PendingStoreCreation {
        ghostkey_fingerprint,
        seller_verifying_key_bytes,
        certificate_pem,
        store_name,
        description,
        payment_instructions,
        rsa_public_key_der,
        encryption_public_key,
    } = pending;
    // The gate only releases once this is `Some`; treat it as a no-op rather
    // than a panic if that ever stops being true.
    let Some(rsa_public_key_der) = rsa_public_key_der else {
        return;
    };

    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::store_ops::create_store_contracts(
            ghostkey_fingerprint,
            seller_verifying_key_bytes,
            rsa_public_key_der,
            certificate_pem,
            StoreDetails {
                store_name,
                description,
                payment_instructions,
            },
            encryption_public_key,
        )
        .await
        {
            dioxus::logger::tracing::error!("Store creation failed: {}", e);
            crate::gateway::APP_STATE
                .write()
                .notifications
                .push(format!("Store creation failed: {e}"));
        }
    });
}

/// Ask the ghostkey delegate for an identity's certificate.
#[cfg(target_arch = "wasm32")]
fn request_certificate(fingerprint: String) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::ReadableExt;

        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .ghostkey_delegate_key
            .clone()
        else {
            dioxus::logger::tracing::error!("Ghostkey delegate not registered");
            return;
        };
        let request = ghostkey_common::GhostkeyRequest::GetCertificate { fingerprint };
        let payload = match ghostkey_common::to_cbor(&request) {
            Ok(payload) => payload,
            Err(e) => {
                dioxus::logger::tracing::error!("Failed to serialize GetCertificate: {e}");
                return;
            }
        };
        if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
            dioxus::logger::tracing::error!("Failed to request certificate: {e}");
        }
    });
}

/// Ask the ghostkey delegate to sign a store's details.
///
/// The request is already queued by the time this runs, because the answer
/// can arrive as soon as the send returns and an answer matching nothing is
/// dropped. If the send itself fails, withdraw it again: nothing will ever
/// answer it.
#[cfg(target_arch = "wasm32")]
fn spawn_store_info_signature(fingerprint: String, pending: PendingStoreInfo) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};

        let queued = PendingSignature::StoreInfo(pending.clone());
        let withdraw = |reason: String| {
            dioxus::logger::tracing::error!("{reason}");
            let mut state = crate::gateway::APP_STATE.write();
            state.withdraw_pending_signature(&queued);
            state
                .notifications
                .push(format!("Could not publish your store's details: {reason}"));
        };

        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .ghostkey_delegate_key
            .clone()
        else {
            withdraw("ghostkey delegate not registered".to_string());
            return;
        };
        let message = match harvest_common::to_cbor(&pending.info) {
            Ok(message) => message,
            Err(e) => {
                withdraw(format!("serialize store details for signing: {e}"));
                return;
            }
        };
        let request = ghostkey_common::GhostkeyRequest::SignMessage {
            fingerprint,
            message,
        };
        let payload = match ghostkey_common::to_cbor(&request) {
            Ok(payload) => payload,
            Err(e) => {
                withdraw(format!("serialize SignMessage: {e}"));
                return;
            }
        };
        if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
            withdraw(format!("send store details for signing: {e}"));
        }
    });
}

/// Wrap a freshly-signed invoice as the record the store contract stores.
///
/// `AwaitingPayment`, with no proof and no status signature, is the only
/// status a newly-issued invoice may carry, and the constraint is structural
/// rather than a convention: `Paid` is authorized by bridge-signed evidence
/// rather than by anybody's say-so, and `AuthorizedOrder::verify` rejects a
/// record claiming it without evidence the whole network can check. So there
/// is nothing here for a seller to assert about payment, and this function
/// takes no argument that would let one try.
fn authorize_new_order(
    order: harvest_common::payment::Order,
    scoped_payload: Vec<u8>,
    signature: Vec<u8>,
) -> harvest_common::payment::AuthorizedOrder {
    harvest_common::payment::AuthorizedOrder {
        order,
        scoped_payload,
        signature,
        status: harvest_common::payment::OrderStatus::AwaitingPayment,
        payment_proof: None,
        status_scoped_payload: None,
        status_signature: None,
    }
}

/// Ask the harvest delegate for the next payment address.
///
/// The invoice is already registered under `request_id` by the time this runs
/// (see `AppState::issue_invoice`). If the send fails, withdraw it: nothing
/// will answer, and an entry left behind would sit in `pending_invoices`
/// forever waiting for an id that was never asked about.
#[cfg(target_arch = "wasm32")]
fn spawn_order_address_request(request_id: u64) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::WritableExt;

        if let Err(e) = crate::gateway::bitcoin_ops::derive_order_address(request_id).await {
            dioxus::logger::tracing::error!("Failed to request a payment address: {e}");
            let mut state = crate::gateway::APP_STATE.write();
            state.pending_invoices.remove(&request_id);
            state.bitcoin.in_flight.remove(&request_id);
            state
                .notifications
                .push(format!("Could not issue the invoice: {e}"));
        }
    });
}

/// Ask the ghostkey delegate to sign an invoice.
///
/// Same discipline as `spawn_store_info_signature`: the request is queued
/// before this runs, and a failed send withdraws it rather than leaving an
/// entry that would consume an unrelated signature.
#[cfg(target_arch = "wasm32")]
fn spawn_order_signature(pending: PendingOrder) {
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::{ReadableExt, WritableExt};

        let queued = PendingSignature::Order(Box::new(pending.clone()));
        let withdraw = |reason: String| {
            dioxus::logger::tracing::error!("{reason}");
            let mut state = crate::gateway::APP_STATE.write();
            state.withdraw_pending_signature(&queued);
            state
                .notifications
                .push(format!("Could not issue the invoice: {reason}"));
        };

        let Some(delegate_key) = crate::gateway::APP_STATE
            .read()
            .ghostkey_delegate_key
            .clone()
        else {
            withdraw("ghostkey delegate not registered".to_string());
            return;
        };
        // What the delegate signs is the CBOR of the order itself;
        // `AuthorizedOrder::verify_terms` checks the scoped payload wraps
        // exactly these bytes.
        let message = match harvest_common::to_cbor(&pending.order) {
            Ok(message) => message,
            Err(e) => {
                withdraw(format!("serialize the invoice for signing: {e}"));
                return;
            }
        };
        let request = ghostkey_common::GhostkeyRequest::SignMessage {
            fingerprint: pending.fingerprint.clone(),
            message,
        };
        let payload = match ghostkey_common::to_cbor(&request) {
            Ok(payload) => payload,
            Err(e) => {
                withdraw(format!("serialize SignMessage: {e}"));
                return;
            }
        };
        if let Err(e) = crate::gateway::send_delegate_message(&delegate_key, payload).await {
            withdraw(format!("send the invoice for signing: {e}"));
        }
    });
}

/// The details a seller types about their own store.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StoreDetails {
    pub store_name: String,
    pub description: String,
    pub payment_instructions: String,
}

/// Why a store the seller owns needs its details published.
///
/// Each of these is a state a store can genuinely be in today, not a
/// hypothetical: stores created before the details were ever published sit at
/// version 0, and a creation interrupted between the PUT and the signed
/// update leaves the same thing behind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreDetailsGap {
    /// Still at version 0, the uninitialized state -- nothing has ever been
    /// published, so the store has no name, no description, and no link to
    /// the seller's reputation.
    NeverPublished,
    /// Published, but with no name a buyer can read.
    NoName,
    /// Published, but naming no reputation contract, so the seller's
    /// feedback history cannot be reached from the store.
    NoReputationLink,
    /// Published, but carrying no encryption key, so no buyer can send this
    /// seller a message.
    ///
    /// Reported only when the delegate has actually produced a key -- see
    /// [`store_details_gap`]. A seller whose delegate has not answered has
    /// nothing to publish, and prompting them to fix it would be a prompt
    /// that publishing does not satisfy.
    NoEncryptionKey,
}

impl StoreDetailsGap {
    /// What to tell the seller is wrong, and what publishing will fix.
    pub fn message(self) -> &'static str {
        match self {
            StoreDetailsGap::NeverPublished => {
                "This store's details were never published. Buyers who open your link see a \
                 storefront with no name, no description and no payment instructions, and your \
                 reputation record cannot be reached from it. Publishing the details below fixes \
                 all three."
            }
            StoreDetailsGap::NoName => {
                "This store has no name. Buyers who open your link see an unnamed storefront. \
                 Publishing the details below fixes it."
            }
            StoreDetailsGap::NoReputationLink => {
                "This store does not name your reputation contract, so buyers cannot reach your \
                 feedback history from it. Publishing the details below restores the link."
            }
            StoreDetailsGap::NoEncryptionKey => {
                "This store publishes no encryption key, so buyers who open it are told they \
                 cannot message you. Publishing the details below adds the key your delegate \
                 already holds; nothing else about the store changes."
            }
        }
    }
}

/// Whether a store's published details need repairing, and why.
///
/// `None` for a store whose state has not arrived yet: absence of information
/// is not evidence of a gap, and reporting one here would flash a repair
/// prompt at every seller on every load.
/// `encryption_key_ready` says whether the harvest delegate has produced this
/// seller's X25519 public key. A missing key is only reported as a gap when
/// there is one to publish: otherwise the prompt would name a repair that
/// publishing does not perform, and would sit there permanently.
pub fn store_details_gap(
    info: Option<&StoreInfoV1>,
    encryption_key_ready: bool,
) -> Option<StoreDetailsGap> {
    let info = info?;
    if info.version == 0 {
        // Version 0 is the default state, which `AuthorizedStoreInfoV1::verify`
        // skips entirely -- nothing in it was ever signed or published.
        return Some(StoreDetailsGap::NeverPublished);
    }
    if info.store_name.trim().is_empty() {
        return Some(StoreDetailsGap::NoName);
    }
    if info.reputation_contract_id == [0u8; 32] {
        return Some(StoreDetailsGap::NoReputationLink);
    }
    // Last of the four: a store nobody can find the name of is worse than one
    // nobody can message, and only one prompt is shown at a time.
    if info.encryption_public_key.is_none() && encryption_key_ready {
        return Some(StoreDetailsGap::NoEncryptionKey);
    }
    None
}

/// Which of a store's listings carry a certificate that does not verify.
///
/// Every listing in a store normally carries the seller's one certificate, so
/// the common case is one verification for the whole page and byte-equality
/// for the rest. The fast path is sound because the verdict is a pure
/// function of `(pem, contract_id)` and the contract id is fixed here: equal
/// bytes cannot reach a different answer.
fn unverified_listings(
    listings: &[AuthorizedListing],
    contract_id: &[u8],
    store_certificate_pem: &str,
    store_status: &crate::ghostkey_cert::CertificateStatus,
) -> HashSet<harvest_common::listing::ListingId> {
    listings
        .iter()
        .filter(|authorized| {
            let verified = if authorized.certificate_pem == store_certificate_pem {
                store_status.is_verified()
            } else {
                crate::ghostkey_cert::verify_store_certificate(
                    &authorized.certificate_pem,
                    contract_id,
                )
                .is_verified()
            };
            !verified
        })
        .map(|authorized| authorized.listing.id.clone())
        .collect()
}

/// Store details entered by the seller and waiting on the certificate.
#[derive(Clone, Debug)]
pub struct PendingStoreEdit {
    pub ghostkey_fingerprint: String,
    pub store_contract_id: Vec<u8>,
    /// Taken from the seller's own `StoreRegistration`, which is the one
    /// place this survives -- the store's published state does not have it
    /// whenever there is anything to repair.
    pub reputation_contract_id: [u8; 32],
    /// One past whatever the network holds now, so the contract's
    /// last-writer-wins merge takes this over what is already there.
    pub next_version: u32,
    pub details: StoreDetails,
}

impl PendingStoreEdit {
    /// The record to sign and publish, once the certificate is known.
    ///
    /// `encryption_public_key` is attached when the delegate has produced
    /// one and left `None` when it has not. Unlike the certificate, it does
    /// NOT gate publication: a store with no key is a store buyers cannot
    /// message, which is bad, whereas a store whose details never publish at
    /// all has no name, no description and no reputation link, which is
    /// worse. `store_details_gap` reports the missing key afterwards so the
    /// seller has a route back to it.
    fn store_info(
        &self,
        certificate_pem: String,
        encryption_public_key: Option<[u8; 32]>,
    ) -> StoreInfoV1 {
        StoreInfoV1 {
            version: self.next_version,
            certificate_pem,
            seller_fingerprint: self.ghostkey_fingerprint.clone(),
            reputation_contract_id: self.reputation_contract_id,
            store_name: self.details.store_name.clone(),
            description: self.details.description.clone(),
            payment_instructions: self.details.payment_instructions.clone(),
            encryption_public_key,
        }
    }
}

/// Something waiting on the ghostkey delegate's `SignResult`.
#[derive(Clone, Debug)]
pub enum PendingSignature {
    Listing(PendingListing),
    StoreInfo(PendingStoreInfo),
    /// Boxed because it is much the largest of the three -- an `Order`
    /// carries two 32-byte ids, a script, an address, a bridge list and two
    /// optional 32-byte fields -- and every entry of the queue would
    /// otherwise be sized for it.
    Order(Box<PendingOrder>),
}

impl PendingSignature {
    /// The exact bytes this request handed the delegate as
    /// `SignMessage::message`, which is what comes back inside the
    /// `ScopedPayload`. See `signed_message_bytes`.
    fn signed_bytes(&self) -> Result<Vec<u8>, String> {
        match self {
            PendingSignature::Listing(pending) => harvest_common::to_cbor(&pending.listing),
            PendingSignature::StoreInfo(pending) => harvest_common::to_cbor(&pending.info),
            PendingSignature::Order(pending) => harvest_common::to_cbor(&pending.order),
        }
    }
}

/// What a seller has typed to issue one invoice, before it has an address.
///
/// Deliberately not an `Order`: an `Order` cannot exist without a payment
/// destination, and getting one is a round trip through the delegate. Keeping
/// the half-formed thing in its own type means there is no moment where a
/// partially-filled `Order` could be signed or published.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingInvoice {
    pub store_contract_id: Vec<u8>,
    pub seller_fingerprint: String,
    pub listing_id: harvest_common::listing::ListingId,
    /// Only for the notification the seller sees; nothing signed depends on it.
    pub listing_title: String,
    /// Ghostkey fingerprint of the buyer this invoice is for.
    ///
    /// May be empty, and often is: an invoice with no buyer named is one
    /// anyone holding the link may pay. Naming one records who it was issued
    /// to and restricts nothing, since Bitcoin cannot say who sent a payment
    /// -- the form says so where the seller types it
    /// (`components::invoice_form::InvoiceForm`).
    pub buyer_fingerprint: String,
    pub amount_sats: u64,
    pub required_confirmations: u32,
    /// The conversation this invoice ANSWERS, when it was issued against a
    /// buyer's request.
    ///
    /// `None` for an invoice the seller wrote unprompted, which is still a
    /// perfectly good invoice -- anyone holding the link may pay it.
    ///
    /// When it is `Some`, the buyer is waiting to be told which of the
    /// store's published commitments is theirs, and cannot work it out for
    /// themselves: `OrderId::new` hashes a `created_at` the seller stamps.
    /// So this travels with the invoice all the way to the signature, and the
    /// acceptance is sent from the same place the commitment is published --
    /// not left to a second action the seller has to remember.
    pub reply_to: Option<[u8; 32]>,
    /// The value the buyer's request asked to have published, so that no
    /// other buyer reads the commitment as theirs.
    ///
    /// `None` for an invoice written unprompted, which no buyer will pay
    /// through the buy flow -- see
    /// [`PaymentBlocker::CommitmentNotForThisBuyer`] -- but which is still a
    /// perfectly good invoice for somebody paying a link by hand.
    ///
    /// Taken from the request in the seller's own mailbox, and that is not a
    /// weakness: the value belongs to the buyer, a seller who altered it
    /// would publish a commitment matching nobody, and the party who checks
    /// it checks against what their OWN node derives rather than against
    /// anything in a message.
    pub order_binding: Option<[u8; 32]>,
}

/// A fully-formed invoice awaiting the seller's signature.
#[derive(Clone, Debug)]
pub struct PendingOrder {
    pub fingerprint: String,
    pub order: harvest_common::payment::Order,
    pub store_contract_id: Vec<u8>,
    /// Carried through from [`PendingInvoice::reply_to`]: the conversation
    /// whose request this order answers, if any.
    pub reply_to: Option<[u8; 32]>,
}

/// Build the invoice an address has just completed.
///
/// Pure, and separated from the response handler for the usual reason: this is
/// where the fields that decide whether an invoice can EVER be settled get
/// filled in, and it needs to be assertable without a browser.
///
/// The two Bitcoin fields are the ones with history. Both used to be store
/// PARAMETERS, hashed into the store's address and therefore frozen for its
/// life, which meant every store the UI created was permanently incapable of
/// accepting an on-chain payment. They now travel per-order under the seller's
/// signature -- so they have to be populated HERE, on every invoice, and an
/// invoice that names no bridge is unpayable from the moment it is signed
/// (`verify_payment_proof` returns `NoTrustedBridges`) with nothing about it
/// looking wrong. That is why a malformed bridge constant is an error rather
/// than an empty list.
pub fn order_for_invoice(
    pending: &PendingInvoice,
    derived: &harvest_common::DerivedAddress,
    anchor: Option<freenet_bitcoin_common::BlockAnchor>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<harvest_common::payment::Order, String> {
    use harvest_common::payment::Order;

    let trusted_bridges = crate::gateway::bitcoin_config::default_trusted_bridges(derived.network)?;
    // Refused rather than published without, and refused HERE rather than at
    // the call site, for the same reason the bridge set is: this is the one
    // place that decides whether an invoice can ever be acted on, and an
    // invoice with no anchor is one no buyer will pay
    // (`AppState::payment_blockers`). Publishing it would leave the seller
    // showing a bill to somebody whose software silently refuses it.
    let anchor = anchor.ok_or(
        "this invoice has no recent Bitcoin block to anchor to yet, so a buyer could not \
         tell how recently you took the order and would refuse to pay it. Wait for the chain \
         data to load and issue it again.",
    )?;
    Ok(Order {
        // Stamped by `with_derived_id` below, out of the finished terms. A
        // literal here would be a second place deciding an order's identity.
        id: harvest_common::payment::OrderId([0u8; 32]),
        listing_id: pending.listing_id.clone(),
        buyer_fingerprint: pending.buyer_fingerprint.clone(),
        seller_fingerprint: pending.seller_fingerprint.clone(),
        amount_sats: pending.amount_sats,
        network: derived.network,
        payment_script_pubkey: derived.script_pubkey.clone(),
        payment_address: derived.address.clone(),
        required_confirmations: pending.required_confirmations,
        // On-chain only. Lightning invoices are a separate path that nothing
        // in Harvest issues yet.
        payment_hash: None,
        trusted_bridges,
        bitcoin_address_code_hash: crate::gateway::bitcoin_config::address_contract_code_hash(),
        anchor: Some(anchor),
        // Copied from the request verbatim. An invoice written unprompted has
        // none, and no buyer will pay one through the buy flow.
        order_binding: pending.order_binding,
        created_at,
    }
    .with_derived_id())
}

/// The message a `SignResult`'s scoped payload was built around, i.e. the
/// bytes the caller originally asked to have signed.
///
/// The delegate wraps the request's `message` verbatim as
/// `ScopedPayload::payload` and signs the wrapper, and every verifier -- the
/// store contract included, via `verify_scoped_signature` -- checks that
/// inner payload against a byte-for-byte re-encoding of the object it is
/// verifying. So these bytes identify which request an answer belongs to,
/// exactly and independently of arrival order.
///
/// `None` if the payload will not deserialize, which means the answer is
/// unusable rather than merely unmatched: a signature the contract cannot
/// verify is not worth applying to anything.
fn signed_message_bytes(scoped_payload: &[u8]) -> Option<Vec<u8>> {
    harvest_common::from_cbor::<ghostkey_common::ScopedPayload>(scoped_payload)
        .ok()
        .map(|scoped| scoped.payload)
}

/// A store's own details, awaiting signature so they can be published.
///
/// `AuthorizedStoreInfoV1::verify` skips verification only at version 0, so
/// anything a buyer can actually read has to carry a real signature over the
/// ghostkey delegate's `ScopedPayload` -- the same round-trip a listing makes.
#[derive(Clone, Debug)]
pub struct PendingStoreInfo {
    pub info: StoreInfoV1,
    pub store_contract_id: Vec<u8>,
}

/// A listing awaiting signature from the ghostkey delegate.
#[derive(Clone, Debug)]
pub struct PendingListing {
    pub fingerprint: String,
    pub listing: harvest_common::listing::Listing,
    /// Store contract ID to submit the signed listing to.
    pub store_contract_id: Option<Vec<u8>>,
}

/// Why a buyer's software will not let them pay an order yet.
///
/// # Why an enum and not a message
///
/// Three reasons, and the third is the one this type exists for.
///
/// Each of these has a different remedy -- wait, come back later, walk away --
/// so a screen that collapsed them into "cannot pay" would leave a buyer with
/// no idea which. They are also the checks
/// `docs/design/incentive-mechanism.md` Part 5 step 3 requires, and a test can
/// name one and observe it rather than matching on prose.
///
/// And it is the seam Phase 2 needs. `docs/buyer-conversation-persistence.md`
/// settles that the buyer persists the seller's pre-signed confession,
/// confirms the delegate wrote it, and only THEN pays -- and warns that "a Buy
/// flow that pays first and stores after passes every test in this repository
/// and defeats the entire mechanism". Adding `ConfessionNotPersisted` here is
/// one variant and one check; every screen that renders a blocker matches
/// exhaustively, so nothing can quietly ignore it. [`Self::ConversationNotKept`]
/// is the same shape one level down and is enforced today.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaymentBlocker {
    /// The seller has published no commitment under this id.
    ///
    /// The reason the whole flow is shaped this way: an undeclared order
    /// collects no money, so a seller cannot take payment without first
    /// admitting publicly that they owe goods. See Part 5, step 2.
    CommitmentNotPublished,
    /// This store's identity key is unknown -- its ghostkey certificate did
    /// not verify, or has not arrived -- so nothing can be checked against it.
    SellerIdentityUnknown,
    /// A commitment exists under this id, but it is not this seller's.
    ///
    /// Carries the verifier's own words, because the difference between "the
    /// signature is not the seller's" and "the terms do not match what was
    /// signed" is worth showing.
    CommitmentNotTheSellers(String),
    /// The commitment does not carry the value that makes it THIS buyer's.
    ///
    /// # Why this is the check the whole flow rests on
    ///
    /// Nothing else in a commitment names a particular buyer:
    /// `buyer_fingerprint` is empty for every order the buy flow produces,
    /// because a buyer has no identity. Without this, a seller could accept
    /// one order, publish one commitment, and send its id down any number of
    /// conversations -- every buyer would find it published, signed, fresh
    /// and for a listing they had asked about, and all would pay the same
    /// address. One declared debt would collect unbounded money, which
    /// inverts the mechanism the commitment exists for: a count that does not
    /// bound the money is not a count.
    ///
    /// The comparison is against
    /// [`crate::messaging::BuyerConversation::order_binding`] -- what this
    /// node derives from its own conversation secret -- and never against the
    /// binding in the request sitting in the mailbox. Direction is not
    /// authorship, so a seller can seal a request into the buyer's own
    /// thread; comparing against that copy would let the seller supply the
    /// value it is checked against and the check would pass for everyone at
    /// once. Pinned by
    /// `a_forged_request_cannot_supply_the_binding_the_check_uses`.
    ///
    /// Covers four cases with one sentence, deliberately: bound to somebody
    /// else, bound to nothing at all, bound to all-zeros, and -- the one a
    /// review found missing -- this CONVERSATION having no usable binding,
    /// which a delegate answer predating the field produces. That last case
    /// used to pass the check, because the seller chooses the value they sign
    /// and could simply sign all-zeros back. See
    /// `crate::messaging::BuyerConversation::usable_order_binding`.
    ///
    /// All four mean the same thing to the buyer, and none is safe.
    CommitmentNotForThisBuyer,
    /// The commitment names no Bitcoin bridge, so no payment to it could ever
    /// be proven.
    ///
    /// `verify_payment_proof` answers `NoTrustedBridges` for such an order
    /// permanently, and `trusted_bridges` is per-order and seller-chosen. It
    /// was a footnote on the card, in smaller text UNDER the sentence saying
    /// the order checked out and under the payment address; a condition that
    /// decides whether money can ever be recovered belongs in the same list
    /// as everything else that decides whether to pay.
    NoTrustedBridge,
    /// The commitment names a bridge this build does not know, so its "Paid"
    /// verdict would rest on a stranger's signature.
    ///
    /// Carries the ids, because "check with the seller about bridge 7Kf2..."
    /// is actionable and "an unknown bridge" is not.
    BridgeNotRecognised(String),
    /// The address the commitment DISPLAYS is not the script that would
    /// settle it.
    ///
    /// The seller's signature covers both forms, so it proves the seller
    /// wrote them, not that they agree. Verification uses the script; the
    /// human pays the address.
    DestinationDisagrees,
    /// The address cannot be read for this network at all, so nothing can be
    /// said about it -- which is itself a reason not to pay it.
    DestinationUnreadable,
    /// The commitment names a listing this conversation never asked about.
    ///
    /// "Confirm your own order is present" is not satisfied by an order being
    /// present. Without this, a seller could answer a request for a cheap
    /// listing with a commitment against an expensive one and every other
    /// check here would pass -- the commitment being genuinely published,
    /// genuinely signed and genuinely fresh.
    ///
    /// Empty when the buyer has asked for nothing in this conversation, which
    /// is the case for a conversation that began as an ordinary question; the
    /// check then has nothing to compare against and does not fire. That is
    /// the honest answer rather than a refusal, since a seller may perfectly
    /// well invoice against a conversation that never used the buy form.
    CommitmentNotRequested,
    /// The order has already moved past awaiting payment.
    NotAwaitingPayment(harvest_common::payment::OrderStatus),
    /// The commitment carries no block anchor, so nothing in it can be dated.
    AnchorMissing,
    /// This reader cannot see the chain, so cannot judge the anchor.
    ///
    /// Deliberately distinct from every verdict below: the remedy is to wait,
    /// not to walk away.
    ChainUnknown,
    /// The anchor names a height this reader's chain has a different block at.
    AnchorOffChain,
    /// The anchor names a height this reader cannot check.
    ///
    /// Should not happen for an anchor that passed the freshness rule, since
    /// [`RECENT_BLOCKS_KEPT`] covers that whole window -- but "should not
    /// happen" is not a reason to treat unknown as verified.
    AnchorUnverifiable,
    /// The anchor is ahead of the tip this reader can see.
    AnchorAheadOfTip { anchor_height: u32, tip_height: u32 },
    /// The anchor is further behind the tip than
    /// [`harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS`].
    ///
    /// # This is expiry, and the wording must not say otherwise
    ///
    /// Two different things land here and the code cannot tell them apart: a
    /// commitment BACKDATED at signing, which is the attack the rule exists
    /// for, and one that simply AGED since it was signed, which is what
    /// happens to every honest order nobody paid in time. The anchor is
    /// stamped when the seller signs and is immutable under their signature,
    /// so the second is by far the common case.
    ///
    /// An earlier version of the sentence shown for this said "an order
    /// backdated like this reads to everyone else as already finished, so do
    /// not pay it" -- an accusation, delivered to a buyer whose seller had
    /// done nothing wrong, with `is_temporary` classifying it as walk-away
    /// and no way for either side to recover. Both are fixed: the sentence
    /// says the order expired and to ask for another, and the remedy is
    /// [`Remedy::AskTheSeller`].
    ///
    /// Refusing is still right in both cases. An expired order is one readers
    /// are about to stop counting as open exposure, so paying it buys the
    /// buyer a declaration that is going quiet either way.
    AnchorStale { anchor_height: u32, tip_height: u32 },
    /// This node has not confirmed it is keeping the key that reads this
    /// conversation.
    ///
    /// Paying now buys goods and throws away the ability to read anything the
    /// seller says afterwards -- and, from Phase 2, the confession that is the
    /// buyer's only capability to complain. See
    /// `docs/buyer-conversation-persistence.md`.
    ConversationNotKept,
}

impl PaymentBlocker {
    /// What to tell the buyer, in their terms rather than the protocol's.
    pub fn describe(&self) -> String {
        match self {
            PaymentBlocker::CommitmentNotPublished => "The seller has not yet published this \
                 order publicly. Until they do, there is no public record that they owe you \
                 anything, so do not pay."
                .to_string(),
            PaymentBlocker::SellerIdentityUnknown => "This store's identity does not check out, \
                 so nothing here can be tied to the seller. Do not pay."
                .to_string(),
            PaymentBlocker::CommitmentNotTheSellers(why) => format!(
                "The published order is not signed by this store's seller ({why}). Do not pay."
            ),
            PaymentBlocker::CommitmentNotForThisBuyer => "The published order was not issued \
                 to you. Anyone can read it, but paying it would be paying somebody else's \
                 bill -- and the seller would still owe only the one order they published. \
                 Do not pay it."
                .to_string(),
            PaymentBlocker::NoTrustedBridge => "The published order names no Bitcoin bridge, \
                 so no payment to it could ever be proven -- not by you, not by anyone. Ask \
                 the seller to reissue it."
                .to_string(),
            PaymentBlocker::BridgeNotRecognised(ids) => format!(
                "The published order would be settled by a bridge this app does not recognise \
                 ({ids}). Whether it counts as paid would rest on a signature you have no \
                 reason to trust. Check with the seller before paying."
            ),
            PaymentBlocker::DestinationDisagrees => "The address shown on the published order \
                 is not the destination that would settle it. Do not pay it -- ask the seller \
                 to reissue it."
                .to_string(),
            PaymentBlocker::DestinationUnreadable => "The published order's payment address \
                 cannot be read for its network, so nothing can be checked about it. Ask the \
                 seller to reissue it."
                .to_string(),
            PaymentBlocker::CommitmentNotRequested => "The published order is for a different \
                 listing than the one you asked about. Do not pay it -- ask the seller what it \
                 is for."
                .to_string(),
            PaymentBlocker::NotAwaitingPayment(status) => format!(
                "This order is no longer awaiting payment ({status:?}), so there is nothing \
                 to pay."
            ),
            PaymentBlocker::AnchorMissing => "The published order names no recent Bitcoin \
                 block, so there is no way to tell how long the seller has been holding it. \
                 Do not pay."
                .to_string(),
            PaymentBlocker::ChainUnknown => "Your node has not loaded Bitcoin chain data yet, \
                 so this order cannot be checked. Wait a moment and look again."
                .to_string(),
            PaymentBlocker::AnchorOffChain => "The published order is anchored to a block that \
                 is not on the chain your node sees. Do not pay."
                .to_string(),
            PaymentBlocker::AnchorUnverifiable => "Your node cannot check the block this order \
                 is anchored to. Wait for it to catch up rather than paying."
                .to_string(),
            PaymentBlocker::AnchorAheadOfTip {
                anchor_height,
                tip_height,
            } => format!(
                "The published order names block {anchor_height}, which is ahead of the \
                 {tip_height} your node has seen. Either your node is behind or the order is \
                 not genuine; wait before paying."
            ),
            PaymentBlocker::AnchorStale {
                anchor_height,
                tip_height,
            } => format!(
                "This order has expired. It was declared against Bitcoin block \
                 {anchor_height}, which is {} blocks behind the {tip_height} your node sees, \
                 and an order that old stops counting as something the seller openly owes. \
                 Ask the seller to issue it again.",
                tip_height.saturating_sub(*anchor_height)
            ),
            PaymentBlocker::ConversationNotKept => "Your node has not confirmed it is keeping \
                 the key that reads this conversation. Pay now and you may not be able to read \
                 what the seller sends afterwards. Send the seller a message to try again."
                .to_string(),
        }
    }
}

/// One purchase this buyer is party to, as their own node can see it.
#[derive(Clone, Debug, PartialEq)]
pub struct BuyerPurchase {
    pub order_id: harvest_common::payment::OrderId,
    /// The routing tag of the conversation the acceptance arrived in, so the
    /// purchase can be shown against the thread it belongs to.
    pub conversation: [u8; 32],
    /// The published commitment, or `None` when the store's state carries
    /// none under this id.
    ///
    /// The buyer is shown the AMOUNT out of this rather than out of the
    /// acceptance message: an amount named in a message is one the seller can
    /// say without publishing, and the published commitment is the only
    /// version a stranger can also count.
    pub commitment: Option<harvest_common::payment::AuthorizedOrder>,
    /// Empty when there is nothing standing between the buyer and paying.
    pub blockers: Vec<PaymentBlocker>,
}

/// State for a store we're browsing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BrowsingStore {
    pub info: Option<StoreInfoV1>,
    pub listings: Vec<AuthorizedListing>,
    /// Whether the store's published ghostkey certificate actually holds up.
    ///
    /// Reached once, in `on_contract_state`, rather than being recomputed
    /// wherever a certificate happens to be displayed. That is the whole
    /// point of holding it here: the raw `certificate_pem` never reaches a
    /// display path, so showing a store without having formed a verdict about
    /// it requires ignoring a field that says `Invalid`, rather than merely
    /// forgetting to call something.
    pub certificate_status: crate::ghostkey_cert::CertificateStatus,
    /// The seller's Ed25519 verifying key, when the store's certificate
    /// verifies against this store -- and `None` otherwise, for all three
    /// reasons `ghostkey_cert::store_verifying_key` collapses together.
    ///
    /// Held here for the same reason [`Self::certificate_status`] is, and
    /// with more force: recovering it re-parses a PEM and verifies a
    /// certificate chain including a blind-RSA notary signature, so a
    /// component that recomputed it would pay for that on every render. It is
    /// also what the mailbox address is derived from, so having exactly one
    /// place that decides it keeps "can this store be messaged" and "does
    /// this store's certificate hold up" from ever answering differently.
    ///
    /// Stored as bytes rather than a `VerifyingKey` because `BrowsingStore`
    /// derives `Default`, and there is no meaningful default curve point.
    pub seller_verifying_key: Option<[u8; 32]>,
    /// Listings whose own certificate did not verify against this store.
    ///
    /// Keyed by [`harvest_common::listing::ListingId`] rather than by position,
    /// so it cannot drift out
    /// of step with `listings` when a merge reorders them.
    pub unverified_listings: HashSet<harvest_common::listing::ListingId>,
    /// Orders placed against this store (buyer or seller side -- the store
    /// contract carries both). Payments-first UI groups these by status.
    pub orders: Vec<AuthorizedOrder>,
    /// Reputation contract ID (extracted from StoreInfoV1 on first load).
    pub reputation_contract_id: Option<Vec<u8>>,
    /// Mailbox contract ID (will be set when we know it).
    pub mailbox_contract_id: Option<Vec<u8>>,
    /// Negative feedback entries from the reputation contract.
    pub feedback: Vec<FeedbackEntry>,
    /// Encrypted messages from the mailbox contract.
    pub mailbox_messages: Vec<EncryptedMessage>,
    /// The buyer's conversations with this store, oldest first.
    ///
    /// Empty for a store this browser's node has never written to, and for
    /// the seller's own store -- a seller does not open a conversation with
    /// themselves.
    ///
    /// A `Vec` rather than one conversation because a returning buyer has
    /// both: whatever the harvest delegate kept from earlier visits, and
    /// possibly one opened in this tab. Every one of them is read, so a reply
    /// to a question asked last week is still readable; the LAST is the one a
    /// new message continues, so a thread resumes rather than forking beside
    /// itself. See `docs/buyer-conversation-persistence.md`.
    pub conversations: Vec<crate::messaging::BuyerConversation>,
    /// Messages THIS browser sent to this store, kept locally because there
    /// is nowhere else for them.
    ///
    /// This is the AUTHORSHIP record, not the message record: what this tab
    /// wrote is the only authorship anything here can establish (see
    /// [`AppState::authored_here`]). It lives for the life of the tab and no
    /// longer, and it is deliberately not persisted alongside the
    /// conversation secret -- it is not part of what a buyer loses by closing
    /// a tab, since the messages themselves come back out of the mailbox
    /// after a reload. What is lost is only the "You, from this tab" label,
    /// so a recalled thread describes its own messages by direction. Both are
    /// truthful; the second is less specific.
    pub sent_messages: Vec<SentMessage>,
}

/// A message this browser sealed and handed to the local node.
///
/// `sent_at` is when the send was attempted, not when anything was
/// delivered: nothing confirms delivery (see
/// `gateway::mailbox_ops::send_message`).
#[derive(Clone, Debug, PartialEq)]
pub struct SentMessage {
    pub text: String,
    pub sent_at: chrono::DateTime<chrono::Utc>,
    /// [`harvest_common::mailbox::entry_digest`] of the exact entry that was
    /// sealed and dispatched.
    ///
    /// **This is the authorship record.** It is first-hand knowledge -- the
    /// bytes this client produced -- and the counterparty cannot reproduce it
    /// without sending the identical message, which would not be a
    /// substitution. See [`AppState::authored_here`].
    pub digest: [u8; 32],
}

/// Enough of a conversation's routing tag to tell two apart on screen.
///
/// The whole thing is 44 characters of base58 that means nothing to a reader;
/// what a buyer needs is to match one line against another.
pub fn short_conversation_tag(tag: &[u8]) -> String {
    bs58::encode(tag).into_string().chars().take(8).collect()
}

/// One store's conversation secrets, in the form the buyer can save.
///
/// # What holding this means
///
/// It contains the secrets themselves, which is what lets it restore the
/// conversation on another machine -- and what makes it worth exactly as much
/// as the conversation it restores. Anyone holding it can read that
/// conversation and, once a seller's reply carries a pre-signed statement,
/// file the complaint it authorizes. The UI says that beside the string
/// rather than in a tooltip.
#[derive(Clone, PartialEq)]
pub struct ConversationBackup {
    pub store_contract_id: Vec<u8>,
    /// Which conversation this string covers. One conversation, so the panel
    /// shows it under that conversation and a buyer saving several can tell
    /// them apart.
    pub buyer_public_key: [u8; 32],
    /// The pasteable string. Kept out of `Debug` for the same reason
    /// `ConversationKeys` is: this is the one value in the app that must not
    /// reach a console log a user pastes into a bug report.
    backup: String,
}

impl ConversationBackup {
    pub fn text(&self) -> &str {
        &self.backup
    }
}

/// Deliberately opaque. A `Debug` that printed this would put every
/// conversation secret for a store into a browser console, and from there
/// into any log a user pastes into a bug report -- the same reasoning as
/// [`crate::messaging::ConversationKeys`], with more at stake, because this
/// one is a complete portable copy.
impl std::fmt::Debug for ConversationBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConversationBackup(redacted)")
    }
}

/// GET-and-subscribe a contract we learned about from a delegate
/// registration or from another contract's state. Failures are logged rather
/// than propagated: these are background refreshes, not user actions.
fn subscribe_in_background(what: &'static str, contract_id: Vec<u8>) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::gateway::get_contract_by_id(&contract_id).await {
            dioxus::logger::tracing::error!("Failed to subscribe to {what} contract: {e}");
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (what, contract_id);
}

/// GET-and-subscribe one of the seller's own stores, and record the answer
/// either way.
///
/// Unlike `subscribe_in_background`, a silent failure here is not harmless.
/// Whether the store's state arrives is what tells `publish_store_details`
/// which version to publish at, so "no answer" has to become a recorded
/// conclusion rather than staying indefinitely ambiguous -- otherwise a
/// store stranded mid-creation could never be repaired, and one that is
/// merely slow could be overwritten at version 1.
fn subscribe_to_own_store(contract_id: Vec<u8>) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        use dioxus::prelude::WritableExt;
        if let Err(e) = crate::gateway::get_contract_by_id(&contract_id).await {
            dioxus::logger::tracing::error!("Failed to subscribe to store contract: {e}");
            crate::gateway::APP_STATE
                .write()
                .note_store_state_unavailable(&contract_id);
            return;
        }
        // `get_contract_by_id` reports only failures to SEND the GET. One
        // that dead-ends in the network produces no response at all, so a
        // deadline is the only thing that ever ends the wait -- the same
        // reasoning, and the same deadline, as a link-opened store.
        gloo_timers::future::TimeoutFuture::new(crate::store_link::LINK_LOAD_TIMEOUT_MS).await;
        crate::gateway::APP_STATE
            .write()
            .note_store_state_unavailable(&contract_id);
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = contract_id;
}

impl AppState {
    /// Start browsing a store: prepare its state and make it the store the
    /// Browse tab shows. The caller is responsible for the GET/subscribe.
    pub fn begin_browsing(&mut self, store_contract_id: Vec<u8>) {
        self.browsing_stores
            .entry(store_contract_id.clone())
            .or_default();
        self.active_store_id = Some(store_contract_id);
        self.store_link_error = None;
    }

    /// Record that a store opened from a link could not be loaded, so the
    /// Browse tab can say so instead of showing "Loading store..." forever.
    ///
    /// Returns whether an error was recorded. Two things that look like
    /// failures aren't: a state that arrived while the timeout was still
    /// running, and a store the user has since navigated away from -- the
    /// message is shown for whichever store is active, so reporting a stale
    /// one would blame the wrong link.
    pub fn note_store_link_failed(&mut self, store_contract_id: &[u8], reason: &str) -> bool {
        if self.active_store_id.as_deref() != Some(store_contract_id) {
            return false;
        }
        if self
            .browsing_stores
            .get(store_contract_id)
            .is_some_and(|store| store.info.is_some())
        {
            return false;
        }
        warn!("Store link could not be opened: {reason}");
        self.store_link_error = Some(reason.to_string());
        true
    }

    /// Record that a migration has moved a contract, and repoint what we hold.
    ///
    /// # Why the mapping is REMEMBERED and not just applied
    ///
    /// The harvest delegate has no request that can replace a
    /// `StoreRegistration` -- `RegisterStore` appends and is a no-op for a
    /// store id it already holds (see
    /// `gateway::migrate_ops::successor_reference_is_durable`). So after a
    /// migration its registry still names the PREDECESSOR, and every
    /// `ListStores` answer for the rest of the session says so. Applying the
    /// repoint and forgetting it meant the next such answer silently un-did
    /// the migration, on a race whose timing nobody controls: the seller's
    /// mailbox id went back to a contract nothing writes to any more.
    ///
    /// Remembering it lets [`AppState::merge_store_registrations`] rewrite
    /// the stale ids as they arrive, which also stops the stale answer being
    /// filed as a SECOND store -- it matches on `store_contract_id`, so once
    /// the store has moved, the predecessor's triple no longer matches
    /// anything and used to be appended.
    ///
    /// # Why this is not a veto on the delegate
    ///
    /// Only the exact superseded id is rewritten. Any other value passes
    /// through untouched, so a delegate that has genuinely been updated --
    /// which is what the replace request above will make possible -- wins,
    /// as it should: a durable write is newer than our in-memory guess. The
    /// masking is therefore self-limiting, confined to the one value the
    /// probe has positively established is stale.
    pub fn adopt_migrated_contract_id(&mut self, predecessor: &[u8], successor: Vec<u8>) {
        if predecessor == successor {
            return;
        }
        // Keep the map flat: a later hop rewrites the target of an earlier
        // one, so resolving is a single lookup and can never chase a cycle.
        for target in self.migrated_contract_ids.values_mut() {
            if target == predecessor {
                *target = successor.clone();
            }
        }
        self.migrated_contract_ids
            .insert(predecessor.to_vec(), successor.clone());

        for stores in self.my_stores.values_mut() {
            for registration in stores.iter_mut() {
                if registration.store_contract_id == predecessor {
                    registration.store_contract_id = successor.clone();
                    // The recorded key belonged to the predecessor's code
                    // hash and is now wrong. Clearing it makes the key
                    // rebuild from the bundled contract, which is the right
                    // answer for the current generation.
                    registration.store_contract_key = None;
                }
                if registration.reputation_contract_id == predecessor {
                    registration.reputation_contract_id = successor.clone();
                }
                if registration.mailbox_contract_id == predecessor {
                    registration.mailbox_contract_id = successor.clone();
                }
            }
        }
    }

    /// Fold the delegate's answer to `ListStores` into what we already know,
    /// rather than replacing it.
    ///
    /// The delegate's registry cannot round-trip everything a registration
    /// holds. `HarvestDelegateRequest::RegisterStore` has no field for the
    /// store's `ContractKey`, so the delegate stores `None` and every
    /// registration it hands back has `store_contract_key: None`. The key is
    /// recorded exactly once, locally, when the store is created
    /// (`gateway::store_ops::create_store`) -- and it is what
    /// `submit_listing_by_id` needs. Replacing wholesale therefore left the
    /// seller with a rendered "Add Listing" button that always failed with
    /// "store may not be fully created yet", for a store created weeks ago.
    ///
    /// The answer can also be missing a store outright: `RegisterStore` and
    /// `ListStores` can be in flight at the same time, so a store created
    /// moments ago may not be in the registry yet.
    ///
    /// Nothing in Harvest deletes a store, so a registration we already hold
    /// is never stale. The invariant is "never lose a locally-known
    /// registration"; the delegate's answer only adds, and only fills in
    /// fields we don't already have.
    ///
    /// It can also be stale in a way that matters more than a missing field:
    /// after a migration the registry still names the PREDECESSOR of every id
    /// it holds, because the delegate has no request that can replace a
    /// registration. Those ids are rewritten on the way in -- see
    /// [`AppState::adopt_migrated_contract_id`], which is also where the
    /// argument for why that is not a veto on the delegate lives. Rewriting
    /// BEFORE the match is what makes it one store rather than two: the match
    /// is on `store_contract_id`, so a migrated store's predecessor triple
    /// would otherwise match nothing and be filed as a second store.
    pub fn merge_store_registrations(
        &mut self,
        ghostkey_fingerprint: &str,
        stores: Vec<StoreRegistration>,
    ) {
        // Don't create the entry for an answer that carries nothing. A
        // storeless seller would otherwise get an empty vec that says
        // "asked, owns none" and reads identically to "owns some" at every
        // `contains_key`, and the log would report keeping 0 stores.
        if stores.is_empty() {
            return;
        }

        // Taken before `known` borrows `self.my_stores` mutably. It is
        // normally empty, and never holds more than one entry per migrated
        // artifact per session.
        let migrated = self.migrated_contract_ids.clone();

        let known = self
            .my_stores
            .entry(ghostkey_fingerprint.to_string())
            .or_default();

        for mut registration in stores {
            for id in [
                &mut registration.store_contract_id,
                &mut registration.reputation_contract_id,
                &mut registration.mailbox_contract_id,
            ] {
                if let Some(successor) = migrated.get(id.as_slice()) {
                    if id.as_slice() != successor.as_slice() {
                        // The delegate cannot know this store moved. Anything
                        // it says that is NOT a superseded id passes through
                        // untouched.
                        *id = successor.clone();
                    }
                }
            }

            match known
                .iter_mut()
                .find(|s| s.store_contract_id == registration.store_contract_id)
            {
                Some(existing) => {
                    if registration.store_contract_key.is_none() {
                        registration.store_contract_key = existing.store_contract_key.take();
                    }
                    *existing = registration;
                }
                None => known.push(registration),
            }
        }
    }

    /// The store the Browse tab is showing.
    ///
    /// Prefer the store a link named; fall back to any store whose state has
    /// actually arrived. `browsing_stores` also holds placeholder entries --
    /// one is created the moment a link is opened, before any state arrives,
    /// and another whenever reputation state turns up for a store we haven't
    /// loaded -- so "whichever entry the map iterates first" picks
    /// arbitrarily among them and can show "no store" while a perfectly good
    /// one is loaded.
    ///
    /// Both `StoreView` and the document title resolve the shown store, and
    /// they answered differently until they shared this: the title took the
    /// map's first loaded entry, so with two stores open the page was titled
    /// after one the user was not looking at.
    pub fn displayed_store(&self) -> Option<(&Vec<u8>, &BrowsingStore)> {
        self.active_store_id
            .as_ref()
            .and_then(|id| self.browsing_stores.get_key_value(id))
            .filter(|(_, store)| store.info.is_some())
            .or_else(|| {
                self.browsing_stores
                    .iter()
                    .find(|(_, store)| store.info.is_some())
            })
    }

    /// Record that we have asked the gateway for a store contract. Returns
    /// `true` the first time, so the caller subscribes exactly once.
    pub fn note_store_subscribed(&mut self, store_contract_id: &[u8]) -> bool {
        self.subscribed_stores.insert(store_contract_id.to_vec())
    }

    /// Record that a store's GET went out and nothing came back within the
    /// deadline, so "no local state" now means "nothing is published there"
    /// rather than "not yet".
    ///
    /// Returns whether the conclusion was recorded. State that arrived while
    /// the deadline was still running wins: the GET answering late is not a
    /// failure, and a store that is genuinely there must never be treated as
    /// empty, because that is exactly what makes an edit publish at version 1
    /// over a higher version and vanish.
    pub fn note_store_state_unavailable(&mut self, store_contract_id: &[u8]) -> bool {
        if self
            .browsing_stores
            .get(store_contract_id)
            .is_some_and(|store| store.info.is_some())
        {
            return false;
        }
        warn!(
            "No state came back for store {:?} -- treating it as never published",
            &store_contract_id[..8.min(store_contract_id.len())]
        );
        self.store_state_unavailable
            .insert(store_contract_id.to_vec())
    }

    /// Whether the seller's own store details can be shown and edited yet:
    /// either its state has arrived, or the GET for it gave up. While
    /// neither is true the form would be filled with empty strings, which
    /// reads as lost details and invites the seller to retype them.
    pub fn store_details_are_resolved(&self, store_contract_id: &[u8]) -> bool {
        self.browsing_stores
            .get(store_contract_id)
            .is_some_and(|store| store.info.is_some())
            || self.store_state_unavailable.contains(store_contract_id)
    }

    /// Record which store a mailbox contract belongs to, and subscribe to the
    /// mailbox so its state actually arrives.
    ///
    /// `mailbox_to_store` is the only route from an incoming mailbox state
    /// back to the store it belongs to. It cannot be recovered from contract
    /// state: `StoreInfoV1` names the store's reputation contract but not its
    /// mailbox, so the mapping has to come from the delegate's
    /// `StoreRegistration` -- which means it only ever exists for our own
    /// stores, not for a store we are browsing as a buyer.
    ///
    /// A mailbox belongs to exactly one store, so a second store claiming one
    /// that is already mapped is a bug somewhere upstream. The first mapping
    /// is kept: re-pointing it would silently strand the first store's
    /// messages, since it would still show a `mailbox_contract_id` that
    /// nothing routes back to it any more.
    pub fn register_store_mailbox(&mut self, store_contract_id: &[u8], mailbox_contract_id: &[u8]) {
        if mailbox_contract_id.len() != 32 || mailbox_contract_id.iter().all(|&b| b == 0) {
            warn!("Store registration has no usable mailbox contract id -- not subscribing");
            return;
        }

        if let Some(owner) = self.mailbox_to_store.get(mailbox_contract_id) {
            if owner != store_contract_id {
                warn!(
                    "Mailbox {} is already registered to a different store -- keeping the \
                     first mapping and ignoring the second",
                    bs58::encode(mailbox_contract_id).into_string()
                );
                return;
            }
            // Already ours: every `StoreList` answer re-registers, and the
            // map doubles as the record of what we have already asked for.
            return;
        }

        self.browsing_stores
            .entry(store_contract_id.to_vec())
            .or_default()
            .mailbox_contract_id = Some(mailbox_contract_id.to_vec());
        self.mailbox_to_store
            .insert(mailbox_contract_id.to_vec(), store_contract_id.to_vec());
        subscribe_in_background("mailbox", mailbox_contract_id.to_vec());
    }

    /// Handle full contract state received from a GET response.
    pub fn on_contract_state(&mut self, contract_id: Vec<u8>, state_bytes: Vec<u8>) {
        if state_bytes.is_empty() {
            return;
        }

        // Try Bitcoin tip / address contracts first. Which one a contract id
        // names is decided when we start subscribing to it (see
        // `register_tip_contract` / `register_watch_contract`), not by
        // guessing from the bytes -- a tip and an address state are both
        // small single-field composables and could in principle both fail
        // to deserialize as each other only by luck of field naming.
        if let Some(&network) = self.bitcoin.tip_contract_network.get(&contract_id) {
            match freenet_bitcoin_common::from_cbor::<freenet_bitcoin_common::BitcoinTipStateV1>(
                &state_bytes,
            ) {
                Ok(tip_state) => {
                    self.apply_tip_state(network, &tip_state);
                    return;
                }
                // This id was registered as a tip contract when we subscribed,
                // so there is no ambiguity to fall through for: the bytes are
                // this contract's and they did not parse.
                Err(e) => warn!(
                    "{} bytes of tip state for {:?} did not decode -- the chain tip will not \
                     advance from this response. serde: {e}",
                    state_bytes.len(),
                    &contract_id[..8.min(contract_id.len())]
                ),
            }
        }
        if let Some(&network) = self.bitcoin.address_contract_network.get(&contract_id) {
            match freenet_bitcoin_common::from_cbor::<freenet_bitcoin_common::BitcoinAddressStateV1>(
                &state_bytes,
            ) {
                Ok(addr_state) => {
                    self.apply_address_state(contract_id, network, &addr_state);
                    // A payment confirming is exactly the moment an order
                    // becomes provable, and this is the only notification
                    // that says so -- the store's own state does not change
                    // when coins arrive. Every store, because the claims that
                    // just landed do not say which order they settle.
                    for store_contract_id in
                        self.browsing_stores.keys().cloned().collect::<Vec<_>>()
                    {
                        self.publish_settled_orders(&store_contract_id);
                    }
                    return;
                }
                Err(e) => warn!(
                    "{} bytes of Bitcoin address state for {:?} did not decode -- payments to \
                     this address will not be seen. serde: {e}",
                    state_bytes.len(),
                    &contract_id[..8.min(contract_id.len())]
                ),
            }
        }

        // Try store contract first.
        //
        // Which contract these bytes belong to is a guess here -- unlike the
        // tip and address cases above, nothing registered this id -- so a
        // failure to decode as a store is expected whenever the bytes are a
        // reputation or mailbox state. What is NOT expected is failing all
        // three, so each error is kept and reported together at the bottom.
        // Discarding them made "these are real bytes I cannot parse"
        // indistinguishable from "there is nothing here", which is how a
        // store state that failed to decode looked exactly like an empty
        // store.
        let store_err =
            match harvest_common::from_cbor::<harvest_common::store::StoreStateV1>(&state_bytes) {
                Err(e) => e,
                Ok(store_state) => {
                    info!(
                        "Received store state for {:?}",
                        &contract_id[..8.min(contract_id.len())]
                    );
                    let reputation_id = store_state.info.info.reputation_contract_id.to_vec();

                    // A store the seller just created, or one they own, arrives
                    // without anyone having followed a link. Show it, unless a link
                    // has already named the store this tab is for.
                    if self.active_store_id.is_none() {
                        self.active_store_id = Some(contract_id.clone());
                    }

                    // Whatever we concluded from a timeout, the state is here now.
                    self.store_state_unavailable.remove(&contract_id);

                    // Form the certificate verdicts here, before anything can be
                    // displayed. `verify_store_certificate` needs the contract id,
                    // which is what binds a certificate to THIS store: a genuine
                    // certificate issued to somebody else passes every other check
                    // there is. See `crate::ghostkey_cert`.
                    let certificate_status = crate::ghostkey_cert::verify_store_certificate(
                        &store_state.info.info.certificate_pem,
                        &contract_id,
                    );
                    // The same check, kept for the mailbox address rather
                    // than for display -- see `BrowsingStore::
                    // seller_verifying_key` for why it is not recomputed
                    // where it is used.
                    let seller_verifying_key = crate::ghostkey_cert::store_verifying_key(
                        &store_state.info.info.certificate_pem,
                        &contract_id,
                    )
                    .map(|key| key.to_bytes());
                    let unverified_listings = unverified_listings(
                        &store_state.listings.listings,
                        &contract_id,
                        &store_state.info.info.certificate_pem,
                        &certificate_status,
                    );

                    let store = self.browsing_stores.entry(contract_id.clone()).or_default();
                    store.certificate_status = certificate_status;
                    store.seller_verifying_key = seller_verifying_key;
                    store.unverified_listings = unverified_listings;
                    store.info = Some(store_state.info.info);
                    store.listings = store_state.listings.listings;
                    store.orders = store_state.orders.orders.into_values().collect();
                    store.reputation_contract_id = Some(reputation_id.clone());

                    // Register the reverse mapping so incoming reputation state
                    // can be matched to this store
                    self.reputation_to_store
                        .insert(reputation_id, contract_id.clone());

                    // Ask the delegate for whatever conversations this node
                    // has had with this store. Here rather than on the
                    // messaging tab, because the answer decides whether the
                    // seller's mailbox is subscribed at all, and a reply the
                    // buyer never fetches is the same to them as one that
                    // was never sent.
                    self.recall_buyer_conversations(&contract_id);

                    // And subscribe to the address contract of every order
                    // this node is party to, so a payment to one becomes
                    // visible. Here rather than on the payments tab, because
                    // the subscription is what fills the view a purchase card
                    // reads, and a buyer who never opens that tab still needs
                    // to see whether the address they are about to pay has
                    // already been paid. Idempotent per tab.
                    self.watch_purchase_addresses(&contract_id);

                    // And publish any order whose payment this node can now
                    // prove. Here as well as on the address path below,
                    // because the two arrive independently: the claims may be
                    // in hand before the order is, or the other way round.
                    self.publish_settled_orders(&contract_id);
                    return;
                }
            };

        // Try reputation contract
        let reputation_err = match harvest_common::from_cbor::<
            harvest_common::reputation::ReputationStateV1,
        >(&state_bytes)
        {
            Err(e) => e,
            Ok(reputation_state) => {
                info!(
                    "Received reputation state ({} entries)",
                    reputation_state.feedback.len()
                );

                // Look up which store this reputation belongs to
                if let Some(store_id) = self.reputation_to_store.get(&contract_id).cloned() {
                    if let Some(store) = self.browsing_stores.get_mut(&store_id) {
                        store.feedback = reputation_state.feedback;
                    }
                } else {
                    info!("Reputation state for unknown store -- caching by contract ID");
                    // Cache it; will be linked when the store state arrives
                    let store = self.browsing_stores.entry(contract_id).or_default();
                    store.feedback = reputation_state.feedback;
                }
                return;
            }
        };

        // Try mailbox contract
        let mailbox_err = match harvest_common::from_cbor::<harvest_common::mailbox::MailboxStateV1>(
            &state_bytes,
        ) {
            Err(e) => e,
            Ok(mailbox_state) => {
                info!(
                    "Received mailbox state ({} messages)",
                    mailbox_state.messages.len()
                );

                match self.mailbox_to_store.get(&contract_id).cloned() {
                Some(store_id) => match self.browsing_stores.get_mut(&store_id) {
                    Some(store) => {
                        store.mailbox_messages = mailbox_state.messages;
                        // The messages are ciphertext until the delegate
                        // hands over the keys, and this is the only moment we
                        // know which senders they came from. Asking again on
                        // every update is cheap: `conversation_keys_to_request`
                        // answers `None` once everything is held or in flight.
                        self.ask_for_conversation_keys(&store_id);
                    }
                    None => warn!(
                        "Mailbox {:?} maps to a store we have no state for -- dropping messages",
                        &contract_id[..8.min(contract_id.len())]
                    ),
                },
                // Only a store registered with the harvest delegate has a
                // known mailbox id, so this is expected for any mailbox we
                // subscribed to some other way -- but it means the messages
                // go nowhere, which is worth saying out loud rather than
                // falling off the end of the function silently.
                None => warn!(
                    "Mailbox state for {:?}, which belongs to no store we know -- dropping {} message(s)",
                    &contract_id[..8.min(contract_id.len())],
                    mailbox_state.messages.len()
                ),
            }
                return;
            }
        };

        // Nothing claimed these bytes. They are NOT nothing: `state_bytes` was
        // checked non-empty at the top of this function, so the node returned
        // real state for a contract we asked about and none of our types could
        // read it. Naming each decoder's error is the difference between "an
        // app we do not know" and "our own wire format has moved underneath
        // us"; the latter is silent everywhere else.
        warn!(
            "Received {} bytes of contract state for {:?} that decode as NOTHING we know -- \
             this is not an empty contract, the bytes are here and unreadable. \
             store: {store_err} | reputation: {reputation_err} | mailbox: {mailbox_err}",
            state_bytes.len(),
            &contract_id[..8.min(contract_id.len())]
        );
    }

    /// Allocate the next id for a messaging request.
    fn next_messaging_request_id(&mut self) -> u64 {
        self.next_messaging_request_id += 1;
        self.next_messaging_request_id
    }

    /// What the delegate must be asked so this store's mailbox can be read,
    /// or `None` when nothing is needed.
    ///
    /// # Why a store we do not own asks for nothing
    ///
    /// The request names one of OUR ghostkey fingerprints, and the delegate
    /// answers keys derived from THAT identity's secret. Pointed at somebody
    /// else's mailbox it would produce a full set of perfectly well-formed
    /// keys that decrypt nothing -- a screen full of "cannot be read", one
    /// delegate round trip per message, for every store the user browses.
    /// So ownership is the gate, and `my_stores` is the only source of it.
    ///
    /// # Why in-flight requests are remembered
    ///
    /// Mailbox state re-arrives on every update notification (see
    /// `gateway::response_handler`'s `UpdateNotification` arm, which re-GETs
    /// the whole state). Without tracking what is already asked, a store with
    /// 50 messages would issue 50 keys' worth of request on every single
    /// update, forever.
    pub fn conversation_keys_to_request(
        &mut self,
        store_contract_id: &[u8],
    ) -> Option<harvest_common::HarvestDelegateRequest> {
        let ghostkey_fingerprint = self.store_owner_fingerprint(store_contract_id)?;
        let store = self.browsing_stores.get(store_contract_id)?;

        let mut wanted: Vec<Vec<u8>> = Vec::new();
        for message in &store.mailbox_messages {
            let peer = &message.sender_public_key;
            // An X25519 public key is 32 bytes. Anything else the delegate
            // would decline, so the round trip buys nothing -- and the tag is
            // bounded only by `MAX_MESSAGE_BYTES`, so it is a round trip an
            // attacker can make tens of kilobytes wide.
            if peer.len() != harvest_common::mailbox::SENDER_KEY_BYTES {
                continue;
            }
            if self.conversation_keys.contains_key(peer)
                || self.declined_conversation_tags.contains(peer)
                || wanted.contains(peer)
                || self
                    .pending_conversation_key_requests
                    .values()
                    .any(|asked| asked.contains(peer))
            {
                continue;
            }
            wanted.push(peer.clone());
        }
        if wanted.is_empty() {
            return None;
        }

        let request_id = self.next_messaging_request_id();
        self.pending_conversation_key_requests
            .insert(request_id, wanted.clone());
        Some(
            harvest_common::HarvestDelegateRequest::DeriveConversationKeys {
                request_id,
                ghostkey_fingerprint,
                peer_public_keys: wanted,
            },
        )
    }

    /// Fold the delegate's answer into the cached conversation keys.
    ///
    /// # Two kinds of "not answered", and they are not the same
    ///
    /// A tag present in the request and absent from an `Ok` answer was
    /// **declined**, and the delegate's decisions are deterministic: it drops
    /// a peer key only when the key is malformed or low-order. Asking again
    /// gets the same answer forever, and since mailbox state re-arrives on
    /// every update notification, "ask again" means an unbounded loop for one
    /// attacker-supplied message. Those tags are recorded and never re-asked.
    ///
    /// An `Err` answer is the transient case -- nothing was derived, usually
    /// because the identity has no encryption key yet -- and it records
    /// nothing, so the next mailbox update tries the whole set again.
    ///
    /// This comment said the opposite until 2026-09-05, justifying re-asking
    /// by transient failure while the delegate's actual omissions were
    /// permanent.
    fn on_conversation_keys(
        &mut self,
        request_id: u64,
        ghostkey_fingerprint: String,
        result: Result<Vec<harvest_common::ConversationKey>, String>,
    ) {
        // Dropping the pending entry is what un-asks everything in it. An
        // answer to a request we are not waiting on takes nothing with it and
        // contributes nothing -- see `an_answer_to_an_unknown_request_is_ignored`.
        let Some(asked) = self.pending_conversation_key_requests.remove(&request_id) else {
            warn!("Conversation keys arrived for request {request_id}, which nothing asked for");
            return;
        };

        match result {
            Ok(keys) => {
                info!(
                    "Delegate derived {} conversation key(s) of {} asked, for {ghostkey_fingerprint}",
                    keys.len(),
                    asked.len()
                );
                // Whatever was asked about and not answered was declined, and
                // will be declined again. `asked` is used ONLY for this --
                // never to pair answers with questions, which is what the
                // echoed `peer_public_key` is for. Pairing positionally here
                // would hand one buyer's key to another buyer's messages the
                // first time an answer came back short, which is the ordinary
                // case rather than an exotic one.
                for tag in asked {
                    if !keys.iter().any(|key| key.peer_public_key == tag) {
                        self.declined_conversation_tags.insert(tag);
                    }
                }
                for key in keys {
                    self.conversation_keys.insert(
                        key.peer_public_key,
                        crate::messaging::ConversationKeys {
                            to_seller: key.buyer_to_seller,
                            from_seller: key.seller_to_buyer,
                        },
                    );
                }
            }
            // Reported rather than swallowed. The visible symptom otherwise
            // is a mailbox that stays unreadable with nothing anywhere saying
            // why, which reads to a seller as "these messages are corrupt".
            Err(why) => {
                warn!("Could not derive conversation keys for {ghostkey_fingerprint}: {why}");
                self.notifications
                    .push(format!("Could not read your messages: {why}"));
            }
        }
    }

    /// Ask the delegate for whatever conversation keys this store's mailbox
    /// still needs, if any.
    ///
    /// Safe to call on every mailbox arrival:
    /// [`Self::conversation_keys_to_request`] answers `None` when there is
    /// nothing to ask, which is the common case after the first round trip.
    pub fn ask_for_conversation_keys(&mut self, store_contract_id: &[u8]) {
        let Some(request) = self.conversation_keys_to_request(store_contract_id) else {
            return;
        };
        self.send_to_harvest_delegate("read this store's messages", &request);
    }

    /// Seal a buyer's request to buy a listing, opening a conversation if
    /// this node has none with the store.
    ///
    /// Step 1 of `docs/design/incentive-mechanism.md` Part 5. The buyer has
    /// no identity and nothing is committed by sending this: it is an ask,
    /// and the seller decides whether to publish a commitment against it.
    ///
    /// Like [`Self::compose_to_seller`], this asks the delegate to keep the
    /// conversation on the path that opens it rather than leaving that to a
    /// caller -- and here it matters more, because the answer to a request is
    /// the acceptance the buyer needs in order to pay at all.
    ///
    /// Returns the sealed message for the caller to dispatch; the dispatch
    /// needs a browser and this does not.
    pub fn request_order(
        &mut self,
        store_contract_id: &[u8],
        seller_encryption_key: &[u8; 32],
        listing_id: &harvest_common::listing::ListingId,
        quantity: u32,
        shipping: String,
        note: String,
    ) -> Result<harvest_common::mailbox::EncryptedMessage, String> {
        // Refused before anything is opened or sealed, so a rejected request
        // leaves no conversation behind for the delegate to keep and no
        // half-formed thread on screen.
        if quantity == 0 {
            return Err("say how many you want -- a quantity of zero is not an order".to_string());
        }
        if shipping.trim().is_empty() {
            return Err(
                "say where this should be sent. The seller cannot fulfil an order with no \
                 destination, and this only ever reaches them -- it is encrypted before it \
                 leaves your browser and is not part of what they publish."
                    .to_string(),
            );
        }
        let sealed = self
            .conversation_with(store_contract_id, seller_encryption_key)?
            .request_order(listing_id, quantity, shipping, note)?;
        self.keep_this_conversation(store_contract_id, seller_encryption_key);
        Ok(sealed)
    }

    /// The conversation a new message to this store continues, opening one if
    /// there is none.
    ///
    /// The LAST rather than the first: a returning buyer resumes the thread
    /// the delegate handed back instead of forking a second one beside it.
    fn conversation_with(
        &mut self,
        store_contract_id: &[u8],
        seller_encryption_key: &[u8; 32],
    ) -> Result<&crate::messaging::BuyerConversation, String> {
        let store = self
            .browsing_stores
            .entry(store_contract_id.to_vec())
            .or_default();
        if store.conversations.is_empty() {
            store
                .conversations
                .push(crate::messaging::BuyerConversation::open(
                    seller_encryption_key,
                )?);
        }
        Ok(store
            .conversations
            .last()
            .expect("just pushed if it was empty"))
    }

    /// Seal a buyer's message to a store, opening a conversation if this
    /// node has none with it.
    ///
    /// A second message continues the LAST conversation rather than opening
    /// another, which is what makes it a thread rather than a series of
    /// unrelated notes the seller cannot connect -- and what lets a reply to
    /// the first message still be readable after the second is sent. After a
    /// reload that last conversation is one the delegate handed back, so a
    /// returning buyer resumes their thread instead of forking a second one
    /// beside it (`a_new_message_continues_the_recalled_conversation`).
    ///
    /// Returns the sealed message for the caller to dispatch. Sealing and
    /// dispatching are separate because the dispatch needs a browser and this
    /// decides what gets sent.
    pub fn compose_to_seller(
        &mut self,
        store_contract_id: &[u8],
        seller_encryption_key: &[u8; 32],
        text: String,
    ) -> Result<harvest_common::mailbox::EncryptedMessage, String> {
        let sealed = self
            .conversation_with(store_contract_id, seller_encryption_key)?
            .seal(text)?;

        // Ask the delegate to keep it, before the caller dispatches anything.
        // A conversation the delegate is not keeping dies with the tab, and
        // the seller's reply dies with it -- so the request is issued on the
        // path that opens the conversation rather than left to a caller to
        // remember.
        self.keep_this_conversation(store_contract_id, seller_encryption_key);
        Ok(sealed)
    }

    /// Ask the harvest delegate to keep this store's active conversation, if
    /// it is one this browser opened and has not already had kept.
    ///
    /// Returns the request, so what is sent is testable without a browser;
    /// [`Self::keep_this_conversation`] is the half that needs one.
    pub fn conversation_to_keep(
        &mut self,
        store_contract_id: &[u8],
        seller_encryption_key: &[u8; 32],
    ) -> Option<harvest_common::HarvestDelegateRequest> {
        // Issued on every message rather than once per conversation. The
        // repeat costs one delegate write, and is otherwise inert: the
        // delegate overwrites its own record and evicts nothing
        // (`re_storing_a_held_conversation_evicts_nothing`). Tracking
        // "already kept" here would save that write and risk the opposite
        // mistake -- skipping a conversation that was never actually kept,
        // which is the silent failure this whole mechanism exists to
        // prevent.
        let request_id = self.next_messaging_request_id();
        let conversation = self
            .browsing_stores
            .get(store_contract_id)?
            .conversations
            .last()?;
        let tag = conversation.buyer_public_key;
        let request =
            conversation.to_persist(store_contract_id, seller_encryption_key, request_id)?;
        self.pending_conversation_persists
            .insert(request_id, (store_contract_id.to_vec(), tag));
        Some(request)
    }

    /// [`Self::conversation_to_keep`], dispatched.
    pub fn keep_this_conversation(
        &mut self,
        store_contract_id: &[u8],
        seller_encryption_key: &[u8; 32],
    ) {
        let Some(request) = self.conversation_to_keep(store_contract_id, seller_encryption_key)
        else {
            return;
        };
        self.send_to_harvest_delegate("keep this conversation", &request);
    }

    /// What the delegate must be asked so this store's earlier conversations
    /// come back, or `None` when it has already been asked.
    ///
    /// Asked once per store per tab: store state re-arrives on every update
    /// notification, and the answer cannot change between two of them.
    pub fn buyer_conversations_to_recall(
        &mut self,
        store_contract_id: &[u8],
    ) -> Option<harvest_common::HarvestDelegateRequest> {
        // Nothing to ask if there is nobody to ask yet, and crucially the
        // store is NOT marked as asked in that case. The connect path opens a
        // store link BEFORE it registers the harvest delegate
        // (`components::app`), so a store's state routinely arrives first --
        // and a store marked asked on a request that was never sent is a
        // buyer whose kept conversations are never recalled, with the reply
        // sitting unread in the mailbox and nothing anywhere saying why.
        // `recall_conversations_for_known_stores` covers the other order.
        self.harvest_delegate_key.as_ref()?;
        if !self
            .buyer_conversations_recalled
            .insert(store_contract_id.to_vec())
        {
            return None;
        }
        let request_id = self.next_messaging_request_id();
        self.pending_conversation_recalls
            .insert(request_id, store_contract_id.to_vec());
        Some(
            harvest_common::HarvestDelegateRequest::ListBuyerConversations {
                request_id,
                store_contract_id: store_contract_id.to_vec(),
            },
        )
    }

    /// [`Self::buyer_conversations_to_recall`], dispatched.
    pub fn recall_buyer_conversations(&mut self, store_contract_id: &[u8]) {
        let Some(request) = self.buyer_conversations_to_recall(store_contract_id) else {
            return;
        };
        self.send_to_harvest_delegate("recall this store's conversations", &request);
    }

    /// Ask for the kept conversations of every store already on screen.
    ///
    /// The other half of the ordering above: a store whose state arrived
    /// before the delegate was registered was deliberately not asked about,
    /// so it is asked here, once the delegate exists.
    pub fn recall_conversations_for_known_stores(&mut self) {
        for store_contract_id in self.browsing_stores.keys().cloned().collect::<Vec<_>>() {
            self.recall_buyer_conversations(&store_contract_id);
        }
    }

    /// Fold the delegate's kept conversations into this store's view.
    ///
    /// # Why this also subscribes to the mailbox
    ///
    /// Opening a storefront deliberately does NOT subscribe to the seller's
    /// mailbox: a subscription advertises a standing interest in it, so a
    /// reader who never messages anyone advertises nothing. A non-empty
    /// answer here is exactly the evidence that this node HAS messaged this
    /// store, so re-subscribing tells the network nothing it was not already
    /// told -- and without it a returning buyer holds the keys to a reply
    /// they never fetch.
    pub fn on_buyer_conversations(
        &mut self,
        request_id: u64,
        echoed_store_contract_id: &[u8],
        conversations: Vec<harvest_common::RecalledConversation>,
    ) {
        // Dropping the pending entry is what un-asks it. An answer nothing
        // asked for takes nothing with it and contributes nothing.
        let Some(store_contract_id) = self.pending_conversation_recalls.remove(&request_id) else {
            warn!("Conversations arrived for request {request_id}, which nothing asked for");
            return;
        };
        // Filed under the store THIS browser asked about. If the delegate
        // echoed a different one, that is a fault worth saying out loud --
        // and filing by the echo would put one store's conversation keys
        // against another store's mailbox.
        if echoed_store_contract_id != store_contract_id {
            warn!(
                "The delegate answered conversations for a different store than was asked \
                 about; filing them under the store that was asked about"
            );
        }
        let store_contract_id = store_contract_id.as_slice();
        if conversations.is_empty() {
            return;
        }
        info!(
            "The delegate kept {} conversation(s) with this store",
            conversations.len()
        );
        let store = self
            .browsing_stores
            .entry(store_contract_id.to_vec())
            .or_default();
        for recalled in conversations {
            // A conversation this browser already holds keeps its keys and
            // its secret -- but takes the delegate's word on whether a backup
            // exists, because the delegate is the only thing that knows. A
            // recall that only ADDED would leave the warning on screen after
            // the buyer had cleared it.
            if let Some(held) = store
                .conversations
                .iter_mut()
                .find(|held| held.buyer_public_key == recalled.buyer_public_key)
            {
                held.backed_up = recalled.backed_up;
                continue;
            }
            store
                .conversations
                .push(crate::messaging::BuyerConversation::recalled(&recalled));
        }
        // Oldest first, so the LAST is the one a new message continues.
        // `buyer_public_key` breaks a tie rather than leaving the order
        // dependent on which answer arrived first.
        store
            .conversations
            .sort_by_key(|held| (held.created_at, held.buyer_public_key));

        let seller = store.seller_verifying_key;
        let Some(seller) =
            seller.and_then(|key| ed25519_dalek::VerifyingKey::from_bytes(&key).ok())
        else {
            warn!(
                "This store's conversations came back, but its identity key has not been \
                 verified, so there is no mailbox address to read the replies out of"
            );
            return;
        };
        match crate::gateway::mailbox_ops::mailbox_contract_key(&seller) {
            Ok(mailbox) => self.register_store_mailbox(store_contract_id, mailbox.id().as_bytes()),
            Err(e) => warn!("Could not work out this store's mailbox address: {e}"),
        }
    }

    /// Ask the delegate for ONE conversation as a saveable string.
    ///
    /// One at a time, because a store-wide string is silently incomplete the
    /// moment the next conversation is opened and nothing about the artefact
    /// says so. See `docs/buyer-conversation-persistence.md`.
    pub fn conversation_to_export(
        &mut self,
        store_contract_id: &[u8],
        buyer_public_key: &[u8; 32],
    ) -> harvest_common::HarvestDelegateRequest {
        let request_id = self.next_messaging_request_id();
        self.pending_conversation_backups
            .insert(request_id, (store_contract_id.to_vec(), *buyer_public_key));
        harvest_common::HarvestDelegateRequest::ExportBuyerConversation {
            request_id,
            store_contract_id: store_contract_id.to_vec(),
            buyer_public_key: *buyer_public_key,
        }
    }

    /// [`Self::conversation_to_export`], dispatched.
    pub fn export_conversation(&mut self, store_contract_id: &[u8], buyer_public_key: &[u8; 32]) {
        let request = self.conversation_to_export(store_contract_id, buyer_public_key);
        self.send_to_harvest_delegate("back up this conversation", &request);
    }

    /// Put a backup on screen, or say why there is none.
    ///
    /// It is held rather than shown-and-forgotten because the buyer has to
    /// copy it somewhere, and a string that vanished on the next render would
    /// be a backup they believe they have.
    pub fn on_conversation_exported(&mut self, request_id: u64, result: Result<String, String>) {
        // Filed under the conversation this browser asked about, and an
        // answer nothing asked for is ignored. A backup is the strongest
        // thing in this protocol -- putting one on screen under the wrong
        // heading would invite the buyer to save it as that conversation's.
        let Some((store_contract_id, buyer_public_key)) =
            self.pending_conversation_backups.remove(&request_id)
        else {
            warn!("A backup arrived for request {request_id}, which nothing asked for");
            return;
        };
        match result {
            Ok(backup) => {
                self.conversation_backup_on_screen = Some(ConversationBackup {
                    store_contract_id,
                    buyer_public_key,
                    backup,
                })
            }
            // Reported rather than logged: the buyer pressed a button and
            // nothing appeared, and the reason is usually actionable ("this
            // node does not hold that conversation").
            Err(why) => {
                warn!("Could not export this conversation: {why}");
                self.notifications
                    .push(format!("That backup could not be made: {why}"));
            }
        }
    }

    /// Take the buyer's word that they have saved THIS conversation's backup.
    ///
    /// One conversation, matching the export. Marking every conversation with
    /// the store would clear the warning on ones the saved string does not
    /// contain, which is the granularity form of silencing a warning about a
    /// key nobody has a backup of.
    pub fn conversation_to_mark_backed_up(
        &mut self,
        store_contract_id: &[u8],
        buyer_public_key: &[u8; 32],
    ) -> harvest_common::HarvestDelegateRequest {
        let request_id = self.next_messaging_request_id();
        self.pending_conversation_backups
            .insert(request_id, (store_contract_id.to_vec(), *buyer_public_key));
        harvest_common::HarvestDelegateRequest::MarkConversationBackedUp {
            request_id,
            store_contract_id: store_contract_id.to_vec(),
            buyer_public_key: *buyer_public_key,
        }
    }

    /// [`Self::conversation_to_mark_backed_up`], dispatched.
    pub fn mark_conversation_backed_up(
        &mut self,
        store_contract_id: &[u8],
        buyer_public_key: &[u8; 32],
    ) {
        let request = self.conversation_to_mark_backed_up(store_contract_id, buyer_public_key);
        self.send_to_harvest_delegate("record that you have saved this", &request);
    }

    /// Fold in what marking did, by asking the delegate rather than assuming.
    ///
    /// The delegate is the only thing that knows whether the record was
    /// actually written; a refused write leaves the warning in place, which
    /// is the safe direction and is exactly what a local guess would get
    /// wrong. So this re-asks and lets the answer decide what the screen
    /// says.
    pub fn on_conversation_marked_backed_up(
        &mut self,
        request_id: u64,
        result: Result<bool, String>,
    ) {
        let Some((store_contract_id, _)) = self.pending_conversation_backups.remove(&request_id)
        else {
            warn!("A backup marking arrived for request {request_id}, which nothing asked for");
            return;
        };
        match result {
            Ok(marked) => {
                info!("conversation recorded as saved: {marked}");
                self.re_recall_buyer_conversations(&store_contract_id);
            }
            Err(why) => self.notifications.push(format!(
                "This node could not record that you have saved that backup, so it will keep \
                 warning you about it: {why}"
            )),
        }
    }

    /// Hand a pasted backup to the delegate.
    ///
    /// One string carries one conversation; a buyer restoring a machine
    /// pastes several in a row, and nothing here is stateful between them.
    pub fn conversation_to_import(
        &mut self,
        backup: String,
    ) -> harvest_common::HarvestDelegateRequest {
        harvest_common::HarvestDelegateRequest::ImportBuyerConversation {
            request_id: self.next_messaging_request_id(),
            backup,
        }
    }

    /// [`Self::conversation_to_import`], dispatched.
    pub fn import_conversation(&mut self, backup: String) {
        let request = self.conversation_to_import(backup);
        self.send_to_harvest_delegate("restore this conversation", &request);
    }

    /// Fold in what a pasted backup did, and say it in full.
    ///
    /// One string carries one conversation, so exactly one thing happened and
    /// it is named: a refused conversation is one the buyer still cannot
    /// read, and the reason is what tells them what to do about it.
    pub fn on_conversation_imported(
        &mut self,
        result: Result<harvest_common::ImportedConversation, String>,
    ) {
        use harvest_common::ImportedConversation;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(why) => {
                self.notifications
                    .push(format!("That backup could not be restored: {why}"));
                return;
            }
        };

        let tag = short_conversation_tag(&outcome.buyer_public_key());
        self.notifications.push(match &outcome {
            // Said whenever something IS restored, because the restored
            // conversation may now be the one a new message continues -- and
            // its secret is known to whoever produced the string. Nothing
            // here can tell an honest backup from one the buyer was handed,
            // so the buyer is the one who has to know. See
            // `docs/buyer-conversation-persistence.md`.
            ImportedConversation::Imported { .. } => format!(
                "Conversation {tag} was restored from that backup. Messages you send to this \
                 store from now on may continue it, and if you did not make that backup \
                 yourself, whoever gave it to you can read them."
            ),
            ImportedConversation::AlreadyHeld { .. } => format!(
                "Conversation {tag} was already on this device, and was left exactly as it was."
            ),
            ImportedConversation::Refused { why, .. } => {
                format!("Conversation {tag} could NOT be restored: {why}")
            }
        });

        // The import wrote into the DELEGATE, not into this browser. Without
        // asking again the buyer is told it worked and sees nothing.
        let store_contract_id = outcome.store_contract_id().to_vec();
        self.re_recall_buyer_conversations(&store_contract_id);
    }

    /// Ask again for a store's conversations, after something changed them.
    pub fn re_recall_buyer_conversations(&mut self, store_contract_id: &[u8]) {
        self.buyer_conversations_recalled.remove(store_contract_id);
        self.recall_buyer_conversations(store_contract_id);
    }

    /// Ask the delegate to forget one conversation, permanently.
    ///
    /// The conversation stays on screen until the delegate says the record is
    /// gone -- see [`Self::on_buyer_conversation_forgotten`].
    pub fn conversation_to_forget(
        &mut self,
        store_contract_id: &[u8],
        buyer_public_key: &[u8; 32],
    ) -> harvest_common::HarvestDelegateRequest {
        let request_id = self.next_messaging_request_id();
        self.pending_conversation_forgets
            .insert(request_id, (store_contract_id.to_vec(), *buyer_public_key));
        harvest_common::HarvestDelegateRequest::ForgetBuyerConversation {
            request_id,
            store_contract_id: store_contract_id.to_vec(),
            buyer_public_key: *buyer_public_key,
        }
    }

    /// [`Self::conversation_to_forget`], dispatched.
    pub fn forget_conversation(&mut self, store_contract_id: &[u8], buyer_public_key: &[u8; 32]) {
        let request = self.conversation_to_forget(store_contract_id, buyer_public_key);
        self.send_to_harvest_delegate("forget this conversation", &request);
    }

    /// Say what keeping a conversation cost, when it cost anything.
    ///
    /// # Why the two cases read differently
    ///
    /// A discarded conversation the buyer holds a backup of is recoverable,
    /// and saying "you can no longer read it" would be false. One they do not
    /// hold a backup of is unreadable forever, and saying anything softer
    /// would be the silence the whole mechanism exists to avoid. The delegate
    /// reports which, because it is the only place that knows.
    ///
    /// Empty on almost every message sent, so a notice here is evidence
    /// rather than noise.
    fn report_evicted_conversations(&mut self, evicted: Vec<harvest_common::EvictedConversation>) {
        for gone in evicted {
            let tag = short_conversation_tag(&gone.buyer_public_key);
            warn!("Conversation {tag} was discarded to stay under this node's cap");
            self.notifications.push(if gone.was_backed_up {
                format!(
                    "This node was full, so conversation {tag} was discarded to make room. You \
                     have a backup of it, so you can restore it -- but not while this node is \
                     still full."
                )
            } else {
                format!(
                    "This node was full, so conversation {tag} was discarded to make room. It \
                     was not backed up anywhere, so it can no longer be read by anyone, \
                     including you."
                )
            });
        }
    }

    /// Drop a conversation this browser holds, once the delegate has said the
    /// record is gone.
    ///
    /// # Why the local drop waits for the answer
    ///
    /// Dropping it on the click would show the buyer a thread that had
    /// vanished while the record was still on their disk -- the exact
    /// dishonesty the delete-rather-than-empty design exists to avoid. A
    /// refusal is reported and the thread stays, which is recoverable.
    pub fn on_buyer_conversation_forgotten(&mut self, request_id: u64, result: Result<(), String>) {
        let Some((store_contract_id, buyer_public_key)) =
            self.pending_conversation_forgets.remove(&request_id)
        else {
            warn!("A conversation was forgotten for request {request_id}, which nothing asked for");
            return;
        };
        match result {
            Ok(()) => {
                if let Some(store) = self.browsing_stores.get_mut(&store_contract_id) {
                    store
                        .conversations
                        .retain(|held| held.buyer_public_key != buyer_public_key);
                }
                self.notifications.push(
                    "That conversation is forgotten. Its messages are still in the seller's \
                     mailbox and can no longer be read by anyone, including you."
                        .to_string(),
                );
            }
            Err(why) => self.notifications.push(format!(
                "That conversation could NOT be forgotten, so it is still stored on this node: \
                 {why}"
            )),
        }
    }

    /// Send one request to the harvest delegate, reporting a failure to even
    /// reach it.
    ///
    /// The `what` is what the buyer was trying to do, so a failure can say so
    /// rather than naming a request variant.
    fn send_to_harvest_delegate(
        &mut self,
        _what: &'static str,
        _request: &harvest_common::HarvestDelegateRequest,
    ) {
        let Some(_delegate_key) = self.harvest_delegate_key.clone() else {
            warn!("Harvest delegate not registered -- cannot {_what}");
            return;
        };
        #[cfg(target_arch = "wasm32")]
        {
            let payload = match harvest_common::to_cbor(_request) {
                Ok(payload) => payload,
                Err(e) => {
                    warn!("Failed to serialize a request to {_what}: {e}");
                    return;
                }
            };
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = crate::gateway::send_delegate_message(&_delegate_key, payload).await
                {
                    dioxus::logger::tracing::error!("Failed to {_what}: {e}");
                }
            });
        }
    }

    /// The buyer's thread with this store, oldest first.
    ///
    /// Empty for a store this browser has never written to -- there is no
    /// conversation, so there is nothing in the mailbox that could be theirs.
    /// Every purchase this node is party to at `store_contract_id`, judged.
    ///
    /// One per acceptance the buyer can read in their own conversations,
    /// judged individually: a buyer can buy twice from one store, and
    /// collapsing to the newest would hide an order they still owe money on.
    ///
    /// # Why the acceptance message decides WHICH order, and nothing else
    ///
    /// The order id cannot be derived by the buyer -- `OrderId::new` hashes a
    /// `created_at` the seller stamps -- so the seller has to name it. But
    /// both parties hold both conversation direction keys, so the message
    /// carrying that name proves nothing about who wrote it. Everything that
    /// matters is therefore re-derived from the PUBLISHED commitment and this
    /// node's own view of the chain; the message is a pointer and is treated
    /// as one.
    pub fn buyer_purchases(&self, store_contract_id: &[u8]) -> Vec<BuyerPurchase> {
        use crate::messaging::{Addressing, MessageContent};

        let Some(store) = self.browsing_stores.get(store_contract_id) else {
            return Vec::new();
        };
        let mut purchases: Vec<BuyerPurchase> = Vec::new();
        for conversation in &store.conversations {
            for message in conversation.read(&store.mailbox_messages) {
                let MessageContent::OrderAccepted { order_id } = message.content else {
                    continue;
                };
                // Addressed to the buyer, or it is something the buyer could
                // have composed themselves -- see this method's doc comment
                // and `Addressing`.
                if message.addressing != Addressing::ToBuyer {
                    continue;
                }
                if purchases
                    .iter()
                    .any(|purchase| purchase.order_id == order_id)
                {
                    // The seller may repeat an acceptance; it is still one
                    // purchase, and showing it twice would read as two debts.
                    continue;
                }
                let commitment = store
                    .orders
                    .iter()
                    .find(|order| order.order.id == order_id)
                    .cloned();
                purchases.push(BuyerPurchase {
                    blockers: self.payment_blockers(store, conversation, commitment.as_ref()),
                    order_id,
                    conversation: conversation.buyer_public_key,
                    commitment,
                });
            }
        }
        purchases
    }

    /// Every listing this conversation has asked about.
    ///
    /// A set rather than the latest, because a buyer may ask about two things
    /// in one thread and the acceptance names only an order id -- so "which
    /// request does this answer" has no unambiguous answer, while "was this
    /// one of the things I asked about" does.
    fn requested_listings(
        store: &BrowsingStore,
        conversation: &crate::messaging::BuyerConversation,
    ) -> Vec<harvest_common::listing::ListingId> {
        use crate::messaging::{Addressing, MessageContent};

        conversation
            .read(&store.mailbox_messages)
            .into_iter()
            .filter(|message| message.addressing == Addressing::ToSeller)
            .filter_map(|message| match message.content {
                MessageContent::OrderRequest { listing_id, .. } => Some(listing_id),
                _ => None,
            })
            .collect()
    }

    /// Every order at this store that this node can now prove was paid, as
    /// the `Paid` record it would publish.
    ///
    /// # Why anything has to do this
    ///
    /// `verify_payment_proof`, the bridge-signed claims and the address
    /// subscription all existed and nothing CONSTRUCTED the proof they
    /// verify, so an order stayed `AwaitingPayment` however much had been
    /// paid. That is not only a wrong line on a screen: the published record
    /// is what every later mechanism reads, and Phase 2's reversal argument
    /// is arithmetic over an order's status.
    ///
    /// # Why the buyer, and why anyone may
    ///
    /// `Paid` is authorized by EVIDENCE, not by a signature over the status
    /// (see `AuthorizedOrder::verify`), so any reader holding the claims can
    /// publish the transition -- there is nothing here only the seller could
    /// sign. The buyer is simply the party who cares soonest, and the same
    /// call serves a seller looking at their own invoices.
    ///
    /// # What it will not publish
    ///
    /// An order whose status has already moved, and an order whose evidence
    /// does not carry the transition. The second is the one that matters:
    /// `assemble_on_chain_proof` verifies before it returns, so a record this
    /// produces is one the network accepts. Publishing `Paid` on evidence
    /// that fails verification is a state every peer refuses, and on the
    /// buyer's screen that looks like the payment never registering.
    ///
    /// Returns the records rather than dispatching them, so what would be
    /// published is decidable without a browser.
    pub fn settled_orders(
        &self,
        store_contract_id: &[u8],
    ) -> Vec<harvest_common::payment::AuthorizedOrder> {
        use harvest_common::payment::{assemble_on_chain_proof, OrderStatus};

        let Some(store) = self.browsing_stores.get(store_contract_id) else {
            return Vec::new();
        };
        // Not scoped to orders this node is party to, and it does not need to
        // be: `Paid` is evidence-backed, so publishing a stranger's settled
        // order would be correct if it happened. It cannot, because
        // `bitcoin.addresses` only ever holds the addresses
        // `address_contracts_to_watch` subscribed to, which ARE this node's
        // own. The scoping is the subscription's, and saying so here is
        // cheaper than a second copy of the rule that could disagree with it.
        let mut settled = Vec::new();
        for order in &store.orders {
            if order.status != OrderStatus::AwaitingPayment {
                continue;
            }
            let Some(view) = order
                .order
                .bitcoin_address_instance_id()
                .and_then(|id| self.bitcoin.addresses.get(id.as_slice()))
            else {
                continue;
            };
            let Some(tip) = self
                .bitcoin
                .tips
                .get(&order.order.network)
                .and_then(|tip| tip.signed_tip.as_ref())
            else {
                continue;
            };
            // Declines for every ordinary reason -- nothing seen yet, not
            // deep enough, short of the amount -- which is the common case
            // and not worth a line anywhere.
            let Ok(proof) = assemble_on_chain_proof(&order.order, &view.claims, tip) else {
                continue;
            };
            let mut paid = order.clone();
            paid.status = OrderStatus::Paid;
            paid.payment_proof = Some(proof);
            settled.push(paid);
        }
        settled
    }

    /// [`Self::settled_orders`], published.
    ///
    /// Each order once per tab. Between dispatching the update and the
    /// store's state coming back with it applied, every further notification
    /// would otherwise re-derive the same settlement and send it again -- one
    /// update per notification per paid order.
    ///
    /// The guard is in-flight only and deliberately not durable: after a
    /// reload the order is either `Paid` in the state that arrives, in which
    /// case `settled_orders` skips it, or it is not, in which case the
    /// earlier update did not land and re-sending is exactly right.
    ///
    /// Returns what it actually dispatched. Not decoration: the dispatch is
    /// wasm-gated, so without this a test of the guard can only look at the
    /// in-flight SET -- and a set is idempotent, so it holds one entry
    /// whether the guard skipped the second send or not. That test passed
    /// under a mutation that deleted the guard, which is the
    /// reports-success-while-measuring-nothing shape this repository is
    /// built around avoiding.
    pub fn publish_settled_orders(
        &mut self,
        store_contract_id: &[u8],
    ) -> Vec<harvest_common::payment::AuthorizedOrder> {
        let mut published = Vec::new();
        for settled in self.settled_orders(store_contract_id) {
            if !self.settlements_submitted.insert(settled.order.id.clone()) {
                continue;
            }
            published.push(settled.clone());
            info!(
                "Publishing the settled order {} -- the payment verifies",
                settled.order.id.short()
            );
            #[cfg(target_arch = "wasm32")]
            {
                let store_id = store_contract_id.to_vec();
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) =
                        crate::gateway::store_ops::submit_order_by_id(&store_id, settled).await
                    {
                        dioxus::logger::tracing::error!("Failed to publish a settled order: {e}");
                        crate::gateway::APP_STATE
                            .write()
                            .notifications
                            .push(format!(
                                "Your payment was seen on chain, but the order could not be \
                             updated to say so: {e}"
                            ));
                    }
                });
            }
        }
        published
    }

    /// The Bitcoin address contracts this node should be watching for one
    /// store, so a payment to an order it is party to becomes visible.
    ///
    /// # Why a buyer needs this at all
    ///
    /// `live_address_for_order` reads `bitcoin.addresses`, which is filled
    /// only by a subscription. Nothing subscribed on a buyer's behalf, so a
    /// purchase card read "Awaiting payment" however much had already arrived
    /// at the address. A rule that stops the wrong payment is worth having;
    /// the display that would have shown the buyer the money was already
    /// there is what lets a person check the rule.
    ///
    /// # Why it is scoped, and not just "every order in the store"
    ///
    /// A store contract carries every order it ever issued. Subscribing to
    /// all of them would advertise this node's interest in every one of a
    /// busy seller's payment addresses, for orders it has nothing to do with
    /// -- the shape `harvest_common::bitcoin_delegate` refuses to build when
    /// it declines to publish a user's watch list. So: orders this node was
    /// accepted for, and orders one of its own identities issued.
    ///
    /// Returns the ids rather than subscribing, so what is asked for is
    /// decidable without a browser. [`Self::watch_purchase_addresses`] is the
    /// half that needs one.
    pub fn address_contracts_to_watch(&self, store_contract_id: &[u8]) -> Vec<[u8; 32]> {
        let Some(store) = self.browsing_stores.get(store_contract_id) else {
            return Vec::new();
        };
        let mine: std::collections::HashSet<&str> = self
            .my_stores
            .iter()
            .filter(|(_, stores)| {
                stores
                    .iter()
                    .any(|s| s.store_contract_id == store_contract_id)
            })
            .map(|(fingerprint, _)| fingerprint.as_str())
            .collect();
        let bought: std::collections::HashSet<harvest_common::payment::OrderId> = self
            .buyer_purchases(store_contract_id)
            .into_iter()
            .map(|purchase| purchase.order_id)
            .collect();

        let mut ids = Vec::new();
        for order in &store.orders {
            let ours = bought.contains(&order.order.id)
                || mine.contains(order.order.seller_fingerprint.as_str());
            if !ours {
                continue;
            }
            // `None` for an order naming no contract build: there is nothing
            // to subscribe to, and guessing would subscribe to some other
            // contract.
            let Some(id) = order.order.bitcoin_address_instance_id() else {
                continue;
            };
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        ids
    }

    /// [`Self::address_contracts_to_watch`], subscribed.
    ///
    /// Each id once per tab: store state re-arrives on every update
    /// notification, and re-subscribing on each would be one GET per
    /// notification per order.
    pub fn watch_purchase_addresses(&mut self, store_contract_id: &[u8]) {
        for id in self.address_contracts_to_watch(store_contract_id) {
            let bytes = id.to_vec();
            self.bitcoin
                .address_contract_network
                .entry(bytes.clone())
                .or_insert_with(|| {
                    // Recorded so an incoming state routes to the right view
                    // without guessing from the bytes -- the same reason
                    // `register_watch_contract` records it.
                    crate::gateway::bitcoin_config::default_network()
                });
            if !self.bitcoin.subscribed.insert(bytes.clone()) {
                continue;
            }
            #[cfg(target_arch = "wasm32")]
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = crate::gateway::bitcoin_ops::subscribe_contract(&bytes).await {
                    dioxus::logger::tracing::error!(
                        "Failed to subscribe an order's address contract: {e}"
                    );
                }
            });
        }
    }

    /// Whether one of the SELLER's own orders has stopped being payable and
    /// should be issued again.
    ///
    /// The other side of `PaymentBlocker::AnchorStale`. An order's anchor is
    /// stamped when the seller signs and cannot be changed afterwards, so
    /// every honest order eventually ages past
    /// [`harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS`] and stops being one
    /// any buyer will pay. Without this the expiry is invisible on the only
    /// side that can fix it: the buyer is sent back to a seller who has no
    /// idea anything happened.
    ///
    /// Answers `false` when this node cannot see the chain. The judgement
    /// needs the reader's own clock, and answering `true` without one would
    /// have a seller reissuing every order every time their node was slow --
    /// the unknown-treated-as-a-verdict mistake, in the direction that
    /// creates work rather than the one that loses money.
    ///
    /// Deliberately NOT the whole of `payment_blockers`: most of those are
    /// about a particular buyer, and a seller looking at their own invoice
    /// list has no buyer in hand.
    pub fn needs_reissue(&self, order: &harvest_common::payment::AuthorizedOrder) -> bool {
        use harvest_common::payment::{OrderStatus, MAX_ANCHOR_AGE_BLOCKS};

        if order.status != OrderStatus::AwaitingPayment {
            return false;
        }
        let Some(tip_height) = self
            .bitcoin
            .tips
            .get(&order.order.network)
            .and_then(|tip| tip.tip_height)
        else {
            return false;
        };
        match order.order.anchor {
            // Nothing to date it by, so no buyer will pay it -- the same
            // verdict `order_for_invoice` refuses to create today, reached
            // here for orders issued before it did.
            None => true,
            Some(anchor) => tip_height.saturating_sub(anchor.height) > MAX_ANCHOR_AGE_BLOCKS,
        }
    }

    /// What stands between this buyer and paying one commitment.
    ///
    /// Ordered so the first blocker is the one worth showing first: what is
    /// missing, then whether it is genuine, then whether it is current, then
    /// whether this node is ready to hold what the buyer will need afterwards.
    ///
    /// It stops at the first failure of each dependent step rather than
    /// collecting everything, because the later checks are not meaningful
    /// against a commitment that failed an earlier one -- an unverified
    /// commitment's anchor is not evidence of anything.
    fn payment_blockers(
        &self,
        store: &BrowsingStore,
        conversation: &crate::messaging::BuyerConversation,
        commitment: Option<&harvest_common::payment::AuthorizedOrder>,
    ) -> Vec<PaymentBlocker> {
        use harvest_common::payment::{OrderStatus, MAX_ANCHOR_AGE_BLOCKS};

        let Some(commitment) = commitment else {
            return vec![PaymentBlocker::CommitmentNotPublished];
        };
        let Some(seller_key) = store.seller_verifying_key else {
            return vec![PaymentBlocker::SellerIdentityUnknown];
        };
        let Ok(seller_key) = ed25519_dalek::VerifyingKey::from_bytes(&seller_key) else {
            return vec![PaymentBlocker::SellerIdentityUnknown];
        };
        // `verify`, not `verify_terms`: the terms signature is what binds the
        // seller, and the rest is what stops a record whose STATUS was
        // asserted without the evidence that status requires.
        if let Err(why) = commitment.verify(&seller_key) {
            return vec![PaymentBlocker::CommitmentNotTheSellers(why)];
        }
        if commitment.status != OrderStatus::AwaitingPayment {
            return vec![PaymentBlocker::NotAwaitingPayment(commitment.status)];
        }
        // Bound to THIS buyer, and checked before anything else about the
        // terms: an order issued to somebody else is not this buyer's
        // business, whatever its listing or anchor says. Compared against
        // what this node derives, never against a value carried in a message
        // -- see `PaymentBlocker::CommitmentNotForThisBuyer`.
        // `usable_order_binding` rather than the raw value: an all-zeros
        // binding identifies nobody, and comparing it would let a seller who
        // signs all-zeros match every conversation in that state. A missing
        // input must not read as a satisfied check -- see
        // `no_missing_input_reads_as_approval`, which enumerates every other
        // input to this function against the same question.
        let Some(expected) = conversation.usable_order_binding() else {
            return vec![PaymentBlocker::CommitmentNotForThisBuyer];
        };
        if commitment.order.order_binding != Some(expected) {
            return vec![PaymentBlocker::CommitmentNotForThisBuyer];
        }
        // What this conversation actually asked about. Empty for a
        // conversation that never used the buy form, and the check then has
        // nothing to compare against -- see
        // `PaymentBlocker::CommitmentNotRequested`.
        let requested = Self::requested_listings(store, conversation);
        if !requested.is_empty() && !requested.contains(&commitment.order.listing_id) {
            return vec![PaymentBlocker::CommitmentNotRequested];
        }

        let mut blockers = Vec::new();
        match commitment.order.anchor {
            None => blockers.push(PaymentBlocker::AnchorMissing),
            Some(anchor) => match self.bitcoin.tips.get(&commitment.order.network) {
                None => blockers.push(PaymentBlocker::ChainUnknown),
                Some(tip) => match tip.tip_height {
                    None => blockers.push(PaymentBlocker::ChainUnknown),
                    Some(tip_height) if anchor.height > tip_height => {
                        blockers.push(PaymentBlocker::AnchorAheadOfTip {
                            anchor_height: anchor.height,
                            tip_height,
                        })
                    }
                    Some(tip_height) if tip_height - anchor.height > MAX_ANCHOR_AGE_BLOCKS => {
                        blockers.push(PaymentBlocker::AnchorStale {
                            anchor_height: anchor.height,
                            tip_height,
                        })
                    }
                    Some(_) => match tip.anchor_is_canonical(&anchor) {
                        Some(true) => {}
                        Some(false) => blockers.push(PaymentBlocker::AnchorOffChain),
                        None => blockers.push(PaymentBlocker::AnchorUnverifiable),
                    },
                },
            },
        }

        // Whether a payment to this order could ever be PROVEN, and whether
        // the address the buyer would type is the destination that settles
        // it. Both are decided by fields the seller chose and the seller
        // signed, and both were card footnotes until review pointed out that
        // a condition deciding whether money is recoverable belongs with
        // everything else that decides whether to pay.
        if commitment.order.trusted_bridges.is_empty() {
            blockers.push(PaymentBlocker::NoTrustedBridge);
        } else {
            let strangers =
                crate::components::bitcoin_view::unrecognised_bridges(&commitment.order);
            if !strangers.is_empty() {
                blockers.push(PaymentBlocker::BridgeNotRecognised(
                    strangers
                        .iter()
                        .map(|id| crate::components::bitcoin_view::short_bridge(id))
                        .collect::<Vec<_>>()
                        .join(", "),
                ));
            }
        }
        match crate::components::bitcoin_view::DestinationNote::of(&commitment.order) {
            crate::components::bitcoin_view::DestinationNote::Agrees => {}
            crate::components::bitcoin_view::DestinationNote::Contradicts => {
                blockers.push(PaymentBlocker::DestinationDisagrees)
            }
            crate::components::bitcoin_view::DestinationNote::Unreadable => {
                blockers.push(PaymentBlocker::DestinationUnreadable)
            }
        }

        // Last, and separate from everything above: the others are about the
        // seller's side of the bargain, this one is about whether this node is
        // ready. See `PaymentBlocker::ConversationNotKept`.
        if !conversation.is_kept() {
            blockers.push(PaymentBlocker::ConversationNotKept);
        }
        blockers
    }

    pub fn conversation_thread(
        &self,
        store_contract_id: &[u8],
    ) -> Vec<crate::messaging::ConversationMessage> {
        let Some(store) = self.browsing_stores.get(store_contract_id) else {
            return Vec::new();
        };
        // Every conversation this node has had with the store, not just the
        // one this tab opened: a reply to a question asked before the last
        // reload is the whole reason the secrets are kept at all. The reads
        // cannot overlap -- each filters the mailbox by its own routing tag,
        // and the tags are distinct -- so this concatenates rather than
        // merging.
        let mut thread: Vec<crate::messaging::ConversationMessage> = store
            .conversations
            .iter()
            .flat_map(|conversation| conversation.read(&store.mailbox_messages))
            .collect();
        thread.sort_by_key(|message| (message.timestamp, message.nonce));
        thread
    }

    /// Messages this browser handed to the node that have not yet turned up
    /// in the seller's mailbox.
    ///
    /// The distinction is the only delivery signal Harvest has. Nothing
    /// confirms an update was applied -- `UpdateResponse` carries no
    /// correlation id -- but a message that appears in the mailbox the buyer
    /// re-reads has demonstrably landed, and one that does not, has not yet.
    pub fn unconfirmed_sent(&self, store_contract_id: &[u8]) -> Vec<SentMessage> {
        let Some(store) = self.browsing_stores.get(store_contract_id) else {
            return Vec::new();
        };
        // Landed means THIS message is there, not that its nonce is: an entry
        // with the same nonce and different bytes is somebody else's message,
        // and since 2026-09-05 it sits beside this one rather than in place
        // of it -- the contract keys identity on `entry_digest`.
        //
        // There used to be a second category, `replaced_sent`, for a message
        // whose nonce was present under different bytes: it had arrived and
        // then been displaced by the contract's dedup. That state can no
        // longer arise, so it was deleted rather than left rendering a case
        // that cannot happen. It was not repointed at "an entry shares your
        // nonce" either, because that signal is FORGEABLE: the mailbox is
        // open-write and the nonce is public, so any third party can plant an
        // unreadable entry under it, and a "somebody tampered with your
        // message" notice driven by that would be one an outsider could
        // trigger against a seller they have never dealt with.
        let landed: std::collections::HashSet<[u8; 32]> = store
            .mailbox_messages
            .iter()
            .map(harvest_common::mailbox::entry_digest)
            .collect();
        store
            .sent_messages
            .iter()
            .filter(|sent| !landed.contains(&sent.digest))
            .cloned()
            .collect()
    }

    /// Seal a seller's reply to one conversation in their own mailbox.
    ///
    /// # Why this needs a message the seller has already read
    ///
    /// A reply must name the conversation id the BUYER chose: the buyer
    /// refuses one that names anything else, which is what stops an answer
    /// being spliced from one of their conversations into another. That id
    /// lives inside the ciphertext, so the only place a seller can learn it
    /// is a message they decrypted. "Reply without having read" is therefore
    /// not something that can be done, and refusing is better than sending
    /// bytes the buyer silently discards.
    pub fn compose_reply(
        &self,
        store_contract_id: &[u8],
        conversation_tag: &[u8],
        text: String,
    ) -> Result<harvest_common::mailbox::EncryptedMessage, String> {
        if self.store_owner_fingerprint(store_contract_id).is_none() {
            return Err(
                "this store is not one of yours -- only the seller can reply into its mailbox"
                    .to_string(),
            );
        }
        let keys = self
            .conversation_keys
            .get(conversation_tag)
            .ok_or("your delegate has not produced this conversation's key yet")?;

        // The newest message this seller could read in this conversation.
        // `mailbox_entries` is newest-first, so the first match is it.
        let conversation_id = self
            .mailbox_entries(store_contract_id)
            .into_iter()
            .find_map(|entry| match entry {
                crate::messaging::MailboxEntry::Readable {
                    conversation,
                    conversation_id,
                    ..
                } if conversation == conversation_tag => Some(conversation_id),
                _ => None,
            })
            .ok_or(
                "no message in this conversation has been read yet, so there is no conversation \
                 to reply to",
            )?;

        crate::messaging::seal_reply(keys, conversation_tag, &conversation_id, text)
    }

    /// Seal the seller's acceptance of a request: the id of the commitment
    /// they have just published, addressed back down the buyer's own thread.
    ///
    /// Split from the dispatch, and from the response handler that calls it,
    /// for the usual reason: what gets sealed is decidable without a browser
    /// and is the half a test can hold.
    ///
    /// # Why this errors rather than answering `None`
    ///
    /// The failure it reports -- no key for that conversation -- means a
    /// commitment has been published that the buyer will never be able to
    /// recognise as theirs. The seller believes they accepted; the buyer sees
    /// a public order book entry that means nothing to them. That is worth a
    /// notification, so it must not look like "there was nothing to do".
    pub fn acceptance_for(
        &self,
        store_contract_id: &[u8],
        conversation_tag: &[u8],
        order_id: &harvest_common::payment::OrderId,
    ) -> Result<harvest_common::mailbox::EncryptedMessage, String> {
        if self.store_owner_fingerprint(store_contract_id).is_none() {
            return Err(
                "this store is not one of yours -- only the seller can answer a request on it"
                    .to_string(),
            );
        }
        let keys = self
            .conversation_keys
            .get(conversation_tag)
            .ok_or("your delegate has not produced this conversation\'s key yet")?;
        // The newest message this seller could read in this conversation.
        // `mailbox_entries` is newest-first, so the first match is it. Same
        // derivation as `compose_reply`, and for the same reason: the
        // conversation id is inside the ciphertext, so the only honest source
        // for it is a message that has actually been decrypted.
        let conversation_id = self
            .mailbox_entries(store_contract_id)
            .into_iter()
            .find_map(|entry| match entry {
                crate::messaging::MailboxEntry::Readable {
                    conversation,
                    conversation_id,
                    ..
                } if conversation == conversation_tag => Some(conversation_id),
                _ => None,
            })
            .ok_or(
                "no message in this conversation has been read yet, so there is nothing to \
                 answer",
            )?;

        crate::messaging::seal_order_accepted(keys, conversation_tag, &conversation_id, order_id)
    }

    /// [`Self::acceptance_for`], recorded and dispatched.
    ///
    /// A failure is reported to the seller rather than logged: they have just
    /// been told their invoice went out, and the difference between "the
    /// buyer knows which order is theirs" and "the buyer is looking at an
    /// order book entry they cannot place" is one they can act on -- by
    /// sending the order number themselves.
    fn announce_acceptance(
        &mut self,
        store_contract_id: &[u8],
        reply_to: Option<[u8; 32]>,
        order_id: &harvest_common::payment::OrderId,
    ) {
        let Some(tag) = reply_to else {
            return;
        };
        let sealed = match self.acceptance_for(store_contract_id, &tag, order_id) {
            Ok(sealed) => sealed,
            Err(why) => {
                warn!("Could not tell the buyer about order {order_id}: {why}");
                self.notifications.push(format!(
                    "Invoice {} was issued, but the buyer could not be told which order is \
                     theirs: {why}. Send them the order number yourself.",
                    order_id.short()
                ));
                return;
            }
        };
        let mailbox = self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|store| store.mailbox_contract_id.clone());
        // Recorded before the dispatch and regardless of it, for the same
        // reason a reply is: this is the only authorship this browser can
        // establish, and a message the seller sent that they cannot recognise
        // afterwards reads as a stranger writing into their own mailbox.
        self.record_sent_message(
            store_contract_id,
            format!("Accepted -- invoice {} is published.", order_id.short()),
            &sealed,
        );
        match mailbox {
            Some(_mailbox) => {
                #[cfg(target_arch = "wasm32")]
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) =
                        crate::gateway::mailbox_ops::reply_to_mailbox(&_mailbox, sealed).await
                    {
                        dioxus::logger::tracing::error!("Failed to send the acceptance: {e}");
                        crate::gateway::APP_STATE
                            .write()
                            .notifications
                            .push(format!(
                                "The invoice was published, but the buyer could not be told: {e}"
                            ));
                    }
                });
            }
            None => {
                warn!("No mailbox known for this store, so the acceptance was not sent");
                self.notifications.push(format!(
                    "Invoice {} was issued, but this store\'s mailbox is not known, so the \
                     buyer could not be told which order is theirs.",
                    order_id.short()
                ));
            }
        }
    }

    /// Whether THIS browser wrote the message with this digest.
    ///
    /// # Why authorship is answered from local records and not from the
    /// message
    ///
    /// Nothing in a message establishes who wrote it. Both parties hold both
    /// direction keys, so either can encrypt in either direction, and
    /// `messaging::Addressing` says which way a message was addressed rather
    /// than who addressed it -- see
    /// [`harvest_common::mailbox::MessageDirection`].
    ///
    /// The one thing a client can know first-hand is what it sent itself.
    /// That is this. Everything else is unattributed, and
    /// `components::message_view` says so rather than labelling a
    /// counterparty-written message with the counterparty's name.
    ///
    /// # The identity compared here is the DIGEST, not the nonce
    ///
    /// This matched on the mailbox nonce until it was reviewed, and that was
    /// wrong in the way that matters: the nonce is public, the mailbox is
    /// open-write, and the counterparty holds the conversation key. So they
    /// could seal different words under a nonce this client had used, let the
    /// contract's tiebreak keep theirs, and have this browser label their
    /// words "You, from this tab". Verified by execution before the fix; the
    /// same substitution works in both directions, so a buyer could put a
    /// confession in a seller's own inbox under the seller's label.
    ///
    /// [`harvest_common::mailbox::entry_digest`] covers every field, so a
    /// substitute -- which must differ in the ciphertext or it is not a
    /// substitute -- does not match. Pinned by
    /// `a_substituted_message_is_not_shown_as_the_buyers_own` and
    /// `a_seller_is_not_credited_with_a_substituted_reply`.
    ///
    /// **This does not stop the counterparty writing**, and nothing at this
    /// layer could: the conversation key is symmetric, so they can always
    /// produce anything this client could. What it stops is their words being
    /// labelled as the buyer's. They can no longer DELETE a message either,
    /// but that is the contract's doing rather than this one's -- identity is
    /// `entry_digest`, so a substitute sits beside the original. See
    /// `docs/messaging-privacy.md`.
    ///
    /// It is per-tab, like everything else about a conversation: a reload
    /// loses it, and messages this browser really did send then read as
    /// unattributed, which is the honest direction to be wrong in.
    pub fn authored_here(&self, store_contract_id: &[u8], digest: &[u8; 32]) -> bool {
        self.browsing_stores
            .get(store_contract_id)
            .is_some_and(|store| {
                store
                    .sent_messages
                    .iter()
                    .any(|sent| &sent.digest == digest)
            })
    }

    /// Record a message this browser sent, so the buyer can see what they
    /// wrote.
    ///
    /// Local to the tab and deliberately so -- see
    /// [`BrowsingStore::sent_messages`].
    pub fn record_sent_message(
        &mut self,
        store_contract_id: &[u8],
        text: String,
        sealed: &harvest_common::mailbox::EncryptedMessage,
    ) {
        // The sealed message rather than its nonce, so the digest cannot be
        // computed from anything but the bytes that were actually dispatched.
        self.browsing_stores
            .entry(store_contract_id.to_vec())
            .or_default()
            .sent_messages
            .push(SentMessage {
                text,
                sent_at: chrono::Utc::now(),
                digest: harvest_common::mailbox::entry_digest(sealed),
            });
    }

    /// One store's mailbox, read with whatever keys are on hand.
    pub fn mailbox_entries(&self, store_contract_id: &[u8]) -> Vec<crate::messaging::MailboxEntry> {
        let Some(store) = self.browsing_stores.get(store_contract_id) else {
            return Vec::new();
        };
        crate::messaging::read_mailbox(&store.mailbox_messages, &self.conversation_keys)
    }

    /// Whether this store is one of the connected identities', and if so
    /// which identity owns it.
    pub fn store_owner_fingerprint(&self, store_contract_id: &[u8]) -> Option<String> {
        self.my_stores.iter().find_map(|(fingerprint, stores)| {
            stores
                .iter()
                .any(|store| store.store_contract_id == store_contract_id)
                .then(|| fingerprint.clone())
        })
    }

    /// Drop a queued signature request that nothing will ever answer.
    ///
    /// Matched on the bytes it asked to have signed, the same way an incoming
    /// answer is matched, so this cannot withdraw a different request that
    /// happens to sit at the same position.
    fn withdraw_pending_signature(&mut self, withdrawn: &PendingSignature) {
        let Ok(bytes) = withdrawn.signed_bytes() else {
            return;
        };
        self.pending_signatures
            .retain(|pending| !pending.signed_bytes().is_ok_and(|queued| queued == bytes));
    }

    /// Publish new details for a store the seller owns -- the entry point for
    /// both editing a working store and repairing one whose details never
    /// reached the network.
    ///
    /// Everything except what the seller typed is taken from state rather
    /// than passed in, which is what makes this safe to call from a form:
    /// the store has to be one of theirs (`my_stores` is the only source of
    /// the owning fingerprint), and the reputation contract id comes from
    /// that registration rather than from the store's published state, which
    /// is exactly the field that is missing whenever there is anything to
    /// repair.
    ///
    /// Errors are returned rather than swallowed so the form can say why
    /// nothing happened.
    pub fn publish_store_details(
        &mut self,
        store_contract_id: &[u8],
        details: StoreDetails,
    ) -> Result<(), String> {
        let (ghostkey_fingerprint, registration) = self
            .my_stores
            .iter()
            .find_map(|(fingerprint, stores)| {
                stores
                    .iter()
                    .find(|store| store.store_contract_id == store_contract_id)
                    .map(|store| (fingerprint.clone(), store))
            })
            .ok_or("this store is not one of yours -- nothing to publish details for")?;

        let reputation_contract_id: [u8; 32] = registration
            .reputation_contract_id
            .as_slice()
            .try_into()
            .map_err(|_| {
                format!(
                    "this store's reputation contract id is {} bytes, not 32 -- cannot publish \
                     details that would point buyers at nothing",
                    registration.reputation_contract_id.len()
                )
            })?;

        // One past whatever is published now -- which means knowing what is
        // published now, and refusing to guess when we do not.
        //
        // `map_or(0, ..)` used to answer "version 0" for a store whose state
        // had simply not arrived yet, and that is a reachable state, not a
        // hypothetical: after a reload `my_stores` fills from the local
        // delegate immediately while store state comes over the network. In
        // that window the seller saw a form full of empty strings, retyped
        // their details, and submitted at version 1 -- which
        // `StoreInfoV1::apply_delta` drops as stale against whatever the
        // network holds, with `return Ok(())` and no error anywhere. The UI
        // said "Publishing your store's details…" and the edit was gone.
        // Retrying recomputed 1 and lost again.
        let published_version = match self
            .browsing_stores
            .get(store_contract_id)
            .and_then(|store| store.info.as_ref())
        {
            Some(info) => info.version,
            // The GET gave up, so there is nothing published to be stale
            // against. This is the store stranded mid-creation, and it
            // publishes at version 1 as before.
            None if self.store_state_unavailable.contains(store_contract_id) => 0,
            None => {
                return Err(
                    "this store's details haven't loaded yet -- publishing now would \
                            overwrite them with a version the store contract rejects. Try again \
                            in a moment."
                        .to_string(),
                )
            }
        };

        // A second edit submitted before the first round-trips would
        // otherwise recompute the same version and lose to it, since local
        // state only catches up when the update comes back.
        let next_version = published_version
            .max(
                self.last_queued_store_version
                    .get(store_contract_id)
                    .copied()
                    .unwrap_or(0),
            )
            .saturating_add(1);

        self.pending_store_edit = Some(PendingStoreEdit {
            ghostkey_fingerprint: ghostkey_fingerprint.clone(),
            store_contract_id: store_contract_id.to_vec(),
            reputation_contract_id,
            next_version,
            details,
        });

        if !self.start_store_edit_if_ready() {
            // The certificate has to be inside the record before it is
            // signed, so ask for it and finish when it lands.
            info!("Store details are waiting on the certificate for {ghostkey_fingerprint}");
            #[cfg(target_arch = "wasm32")]
            request_certificate(ghostkey_fingerprint);
        }
        Ok(())
    }

    /// Sign and publish a pending edit once the certificate it needs is
    /// known. Returns whether it went ahead.
    ///
    /// Called both when the edit is submitted (the certificate is usually
    /// already cached by then) and whenever a certificate arrives, so
    /// neither order needs special handling.
    fn start_store_edit_if_ready(&mut self) -> bool {
        let Some(edit) = self.pending_store_edit.as_ref() else {
            return false;
        };
        let Some(certificate_pem) = self
            .certificates
            .get(&edit.ghostkey_fingerprint)
            .filter(|pem| !pem.is_empty())
            .cloned()
        else {
            return false;
        };
        let Some(edit) = self.pending_store_edit.take() else {
            return false;
        };

        let encryption_public_key = self
            .encryption_public_keys
            .get(&edit.ghostkey_fingerprint)
            .copied();
        if encryption_public_key.is_none() {
            info!(
                "Publishing store details for {} with no encryption key -- buyers will be told \
                 they cannot message this seller",
                edit.ghostkey_fingerprint
            );
        }
        let info = edit.store_info(certificate_pem, encryption_public_key);
        info!(
            "Publishing details for store {:?} at version {}",
            &edit.store_contract_id[..8.min(edit.store_contract_id.len())],
            info.version
        );
        // Remember what we asked for, so a second edit submitted before this
        // one round-trips lands past it rather than tying with it.
        let queued = self
            .last_queued_store_version
            .entry(edit.store_contract_id.clone())
            .or_insert(info.version);
        *queued = (*queued).max(info.version);
        self.queue_store_info_signature(edit.ghostkey_fingerprint, edit.store_contract_id, info);
        true
    }

    /// Queue a store-info signature request and ask the delegate for it.
    ///
    /// The queueing is deliberately not behind a target gate: it is the part
    /// that decides what gets published, so it stays testable off-target.
    /// Only the delegate round-trip needs a browser.
    fn queue_store_info_signature(
        &mut self,
        ghostkey_fingerprint: String,
        store_contract_id: Vec<u8>,
        info: StoreInfoV1,
    ) {
        let pending = PendingStoreInfo {
            info,
            store_contract_id,
        };
        self.pending_signatures
            .push_back(PendingSignature::StoreInfo(pending.clone()));

        #[cfg(target_arch = "wasm32")]
        spawn_store_info_signature(ghostkey_fingerprint, pending);
        #[cfg(not(target_arch = "wasm32"))]
        let _ = ghostkey_fingerprint;
    }

    /// Start issuing an invoice against a listing in a store the seller owns.
    ///
    /// # Why the seller issues this and not the buyer
    ///
    /// `AuthorizedOrder::verify_terms` checks a ghostkey-scoped SELLER
    /// signature over the whole `Order`, so a buyer cannot create one at all.
    /// "Buyer clicks Buy" would need buyer-to-seller messaging, which is a
    /// separate decision; a seller handing over an invoice needs nothing that
    /// does not already exist, and is how a small seller works anyway.
    ///
    /// # What this starts, and what finishes it
    ///
    /// Two round trips, neither of which can be skipped. The delegate derives
    /// a fresh payment address (`OrderAddress`), and only then is there an
    /// `Order` to sign; the ghostkey delegate signs it (`SignResult`), and
    /// only then is there something the store contract will accept. Errors are
    /// returned rather than swallowed so the form can say why nothing
    /// happened.
    pub fn issue_invoice(&mut self, invoice: PendingInvoice) -> Result<(), String> {
        if invoice.amount_sats == 0 {
            return Err("an invoice needs an amount in satoshis".to_string());
        }
        if invoice.required_confirmations == 0 {
            return Err(
                "an invoice needs at least one confirmation, or a payment could count as \
                 settled while it is still only in the mempool"
                    .to_string(),
            );
        }
        // The store has to be one of ours, and the fingerprint that signs has
        // to be the one that owns it -- the store contract verifies every
        // order against `StoreParameters::seller_verifying_key`, so an invoice
        // signed by any other identity is rejected with nothing to say why.
        let owner = self
            .my_stores
            .iter()
            .find(|(_, stores)| {
                stores
                    .iter()
                    .any(|s| s.store_contract_id == invoice.store_contract_id)
            })
            .map(|(fingerprint, _)| fingerprint.clone())
            .ok_or("this store is not one of yours -- nothing to issue an invoice on")?;
        if owner != invoice.seller_fingerprint {
            return Err(format!(
                "this store belongs to {owner}, so only that identity can issue invoices \
                 on it"
            ));
        }
        if self.bitcoin.payment_xpub.is_none() {
            return Err(
                "add your wallet's payment key before issuing an invoice, or there is \
                 nowhere for the buyer to pay"
                    .to_string(),
            );
        }

        // Register before sending, and un-register if the send fails: the
        // answer can arrive as soon as the send returns, and an `OrderAddress`
        // matching no pending invoice is dropped -- which would burn a
        // derivation index for nothing.
        let request_id = self.bitcoin.next_request_id();
        self.bitcoin.in_flight.insert(request_id);
        self.pending_invoices.insert(request_id, invoice);

        #[cfg(target_arch = "wasm32")]
        spawn_order_address_request(request_id);
        Ok(())
    }

    /// Turn a freshly-derived address into a signed, published invoice.
    ///
    /// Split from the response handler so the part that decides what gets
    /// signed is testable without a browser; only the delegate round trip
    /// below needs one.
    fn complete_invoice(&mut self, request_id: u64, derived: harvest_common::DerivedAddress) {
        let Some(invoice) = self.pending_invoices.remove(&request_id) else {
            // The index this consumed is gone either way -- see
            // `apply_derive_order_address` in the delegate on why an index is
            // spent when it is handed out. Say so rather than failing silently.
            warn!(
                "A payment address arrived for request {request_id}, which matches no \
                 invoice we are waiting on -- dropping it"
            );
            return;
        };

        // Plain `now`. There used to be a collision dance here, because
        // `OrderId` hashed only `(seller, listing, created_at_ms, buyer)` and
        // two invoices for one listing in a single millisecond were the same
        // order as far as the contract was concerned -- one silently
        // displacing the other under `merge_order`'s tie-break, taking a
        // derivation index and an address already shown to somebody. The id
        // is now derived from the whole terms, and every invoice carries a
        // distinct payment address from the delegate's own index, so two
        // invoices in one millisecond are simply two orders. That old comment
        // named this as the structural answer and deferred it; this is it.
        let created_at = chrono::Utc::now();
        // The seller's own view of the chain, which is the only anchor they
        // have. A seller whose tip contract has not answered cannot issue an
        // invoice at all -- `order_for_invoice` says so, and says why.
        let anchor = self
            .bitcoin
            .tips
            .get(&derived.network)
            .and_then(|tip| tip.current_anchor());
        let order = match order_for_invoice(&invoice, &derived, anchor, created_at) {
            Ok(order) => order,
            Err(e) => {
                self.notifications
                    .push(format!("Could not build the invoice: {e}"));
                return;
            }
        };
        info!(
            "Issuing invoice {} for '{}' ({} sats) to {}",
            order.id.short(),
            invoice.listing_title,
            order.amount_sats,
            order.payment_address
        );

        let pending = PendingOrder {
            fingerprint: invoice.seller_fingerprint,
            order,
            store_contract_id: invoice.store_contract_id,
            reply_to: invoice.reply_to,
        };
        self.pending_signatures
            .push_back(PendingSignature::Order(Box::new(pending.clone())));

        #[cfg(target_arch = "wasm32")]
        spawn_order_signature(pending);
    }

    /// Publish a new store's contracts, once every input creation needs has
    /// arrived.
    ///
    /// `initiate_store_creation` fires two requests together -- `GetCertificate`
    /// to the ghostkey delegate and `InitReputationKeys` to the harvest
    /// delegate -- and the two answer independently, in whichever order they
    /// happen to. So neither response can assume it is the last one, and the
    /// decision to proceed belongs here rather than in either handler.
    ///
    /// Before this gate, `ReputationKeysInitialized` took the pending creation
    /// and went ahead on its own. A certificate arriving second was then
    /// written into a slot already emptied, and silently discarded: the store
    /// published with an empty `certificate_pem`, leaving a buyer no trust
    /// chain to check the seller against. That was already wrong for the
    /// reputation contract; it became worse once the certificate started
    /// travelling inside the *signed* `StoreInfoV1`, where correcting it means
    /// a fresh signature rather than an edit.
    ///
    /// Waiting is the safe direction only because every response meaning the
    /// certificate will never arrive -- `Error`, `AccessDenied`,
    /// `NoIdentityAvailable`, `PermissionDenied`, `KeyNotFound` -- clears
    /// `pending_store_creation` and tells the user. Otherwise a creation sits
    /// here forever on an answer that is not coming.
    ///
    /// That claim was false in two ways when it was first written, and both
    /// are worth remembering because neither showed up as a failing test.
    /// `Error` cleared `pending_store_edit` but not `pending_store_creation`;
    /// and `KeyNotFound`, which is a flat "there is no such key" for a waiting
    /// `GetCertificate`, fell into the wildcard arm and cleared nothing at
    /// all. Underneath both, no ghostkey error reached
    /// `on_ghostkey_response` in the first place -- the gateway routed every
    /// one of them to the Harvest handler by trial CBOR decode. See
    /// `gateway::response_handler::DelegateSender`.
    fn start_store_creation_if_ready(&mut self) {
        let ready = matches!(
            self.pending_store_creation.as_ref(),
            Some(pending)
                if !pending.certificate_pem.is_empty()
                    && pending.rsa_public_key_der.is_some()
        );
        if !ready {
            return;
        }
        let Some(pending) = self.pending_store_creation.take() else {
            return;
        };

        info!(
            "Store creation inputs complete for {} -- publishing contracts",
            pending.ghostkey_fingerprint
        );

        #[cfg(target_arch = "wasm32")]
        spawn_store_creation(pending);
        #[cfg(not(target_arch = "wasm32"))]
        let _ = pending;
    }

    /// Handle a response from the harvest delegate.
    pub fn on_delegate_response(&mut self, response: HarvestDelegateResponse) {
        match response {
            HarvestDelegateResponse::ReputationKeysInitialized {
                ghostkey_fingerprint,
                rsa_public_key_der,
            } => {
                info!("RSA keys initialized for {}", ghostkey_fingerprint);
                self.rsa_public_keys
                    .insert(ghostkey_fingerprint.clone(), rsa_public_key_der.clone());
                self.start_reputation_migration(&ghostkey_fingerprint);

                if let Some(pending) = self.pending_store_creation.as_mut() {
                    if pending.ghostkey_fingerprint == ghostkey_fingerprint {
                        pending.rsa_public_key_der = Some(rsa_public_key_der);
                    }
                }
                self.start_store_creation_if_ready();
            }

            HarvestDelegateResponse::RsaPublicKey {
                ghostkey_fingerprint,
                rsa_public_key_der,
            } => {
                self.rsa_public_keys
                    .insert(ghostkey_fingerprint.clone(), rsa_public_key_der);
                self.start_reputation_migration(&ghostkey_fingerprint);
            }

            HarvestDelegateResponse::EncryptionKeyReady {
                ghostkey_fingerprint,
                x25519_public_key,
            } => match <[u8; 32]>::try_from(x25519_public_key.as_slice()) {
                Ok(key) => {
                    info!("Encryption key ready for {ghostkey_fingerprint}");
                    self.encryption_public_keys
                        .insert(ghostkey_fingerprint.clone(), key);
                    if let Some(pending) = self.pending_store_creation.as_mut() {
                        if pending.ghostkey_fingerprint == ghostkey_fingerprint {
                            pending.encryption_public_key = Some(key);
                        }
                    }
                }
                // Refused rather than padded or truncated into something the
                // seller would sign into a permanent record and no buyer
                // could use. Said out loud because the only other symptom is
                // buyers being told, on the seller's own storefront, that
                // this store cannot be messaged.
                Err(_) => {
                    let message = format!(
                        "The delegate returned a {}-byte encryption key for {ghostkey_fingerprint}, \
                         not 32. Buyers will not be able to message this store.",
                        x25519_public_key.len()
                    );
                    warn!("{message}");
                    self.notifications.push(message);
                }
            },

            HarvestDelegateResponse::ConversationKeys {
                request_id,
                ghostkey_fingerprint,
                result,
            } => self.on_conversation_keys(request_id, ghostkey_fingerprint, result),

            HarvestDelegateResponse::BuyerConversationList {
                request_id,
                store_contract_id,
                conversations,
            } => self.on_buyer_conversations(request_id, &store_contract_id, conversations),

            // A conversation the delegate did not keep dies with the tab, and
            // the buyer has already been told their message was sent -- so
            // this is said out loud rather than logged. After orders exist it
            // is the difference between having recourse against the seller
            // and silently having none.
            HarvestDelegateResponse::BuyerConversationStored {
                request_id,
                result,
                evicted,
            } => {
                let asked = self.pending_conversation_persists.remove(&request_id);
                // Said before the write's own outcome: what was discarded is
                // gone either way, and it is the sharper of the two.
                self.report_evicted_conversations(evicted);
                // The delegate SAYING it kept the record is the only thing
                // that marks it kept, and it is what the buy flow waits on
                // before letting a buyer pay -- see
                // `PaymentBlocker::ConversationNotKept`. Marking on dispatch
                // instead would make a refused write indistinguishable from a
                // successful one, which is the failure this whole mechanism
                // exists to prevent.
                if result.is_ok() {
                    if let Some((store_contract_id, tag)) = asked.as_ref() {
                        if let Some(conversation) = self
                            .browsing_stores
                            .get_mut(store_contract_id)
                            .and_then(|store| {
                                store
                                    .conversations
                                    .iter_mut()
                                    .find(|conversation| conversation.buyer_public_key == *tag)
                            })
                        {
                            conversation.mark_kept();
                        }
                    }
                }
                let store_contract_id = asked.map(|(store_contract_id, _)| store_contract_id);
                if let Err(why) = result {
                    let store = store_contract_id
                        .as_deref()
                        .and_then(|id| self.browsing_stores.get(id))
                        .and_then(|store| store.info.as_ref())
                        .map(|info| info.store_name.clone())
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or_else(|| "this store".to_string());
                    warn!("A buyer conversation was not kept: {why}");
                    self.notifications.push(format!(
                        "Your message to {store} was sent, but this node could not keep the key \
                         that reads the reply: {why}. If you close or reload this tab, any \
                         answer will be unreadable."
                    ));
                }
            }

            HarvestDelegateResponse::BuyerConversationForgotten { request_id, result } => {
                self.on_buyer_conversation_forgotten(request_id, result)
            }

            HarvestDelegateResponse::BuyerConversationExported {
                request_id, result, ..
            } => self.on_conversation_exported(request_id, result),

            HarvestDelegateResponse::BuyerConversationImported { result, .. } => {
                self.on_conversation_imported(result)
            }

            HarvestDelegateResponse::BuyerConversationMarkedBackedUp {
                request_id, result, ..
            } => self.on_conversation_marked_backed_up(request_id, result),

            HarvestDelegateResponse::StoreRegistered {
                ghostkey_fingerprint,
            } => {
                info!("Store registered for {}", ghostkey_fingerprint);
            }

            HarvestDelegateResponse::StoreList {
                ghostkey_fingerprint,
                stores,
            } => {
                info!(
                    "Delegate reports {} store(s) for {}",
                    stores.len(),
                    ghostkey_fingerprint
                );
                self.merge_store_registrations(&ghostkey_fingerprint, stores);

                // Nothing else re-fetches these after a reload: the seller's
                // own store is subscribed at creation time and never again,
                // so without this the Browse tab is empty for the very seller
                // who owns the store.
                let registrations: Vec<(Vec<u8>, Vec<u8>)> = self
                    .my_stores
                    .get(&ghostkey_fingerprint)
                    .map(|stores| {
                        stores
                            .iter()
                            .map(|s| (s.store_contract_id.clone(), s.mailbox_contract_id.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                for (store_contract_id, mailbox_contract_id) in registrations {
                    if self.note_store_subscribed(&store_contract_id) {
                        subscribe_to_own_store(store_contract_id.clone());
                    }
                    self.register_store_mailbox(&store_contract_id, &mailbox_contract_id);
                }
            }

            HarvestDelegateResponse::Error { message } => {
                self.notifications
                    .push(format!("Delegate error: {message}"));
            }

            _ => {
                info!("Unhandled delegate response: {:?}", response);
            }
        }
    }

    /// Start this identity's reputation migration, now that the delegate has
    /// produced its RSA public key.
    ///
    /// **This is the ordering constraint the migration doctrine names.**
    /// `ReputationParameters::rsa_public_key_der` IS that key, so it is an
    /// input to the reputation contract's address. Until the key is in hand
    /// there is no way to derive a predecessor reputation instance -- or the
    /// current one -- so probing earlier would walk ids belonging to nobody,
    /// find nothing, and risk sealing that verdict over a recoverable
    /// instance. The store and mailbox contracts have no such dependency and
    /// start as soon as the ghostkey is known.
    ///
    /// Called from both delegate responses that can carry the key, because
    /// which one arrives depends on whether the identity already had keys.
    /// Starting twice is a no-op: `migrate_ops` keys in-flight probes by their
    /// marker.
    pub fn start_reputation_migration(&self, _ghostkey_fingerprint: &str) {
        #[cfg(target_arch = "wasm32")]
        {
            let Some(vk) = self
                .ghostkeys
                .iter()
                .find(|k| k.fingerprint == _ghostkey_fingerprint)
                .and_then(|k| k.verifying_key_bytes.clone())
            else {
                // The vault has not shared this identity's verifying key, so
                // the owner half of the parameters is missing too. Nothing to
                // do until it does; `GhostKeyList` starts the other two
                // migrations at that point and this one retries on the next
                // key response.
                return;
            };
            crate::gateway::migrate_ops::start_reputation_migration(_ghostkey_fingerprint, &vk);
        }
    }

    /// Handle a response from the ghostkey delegate.
    pub fn on_ghostkey_response(&mut self, response: ghostkey_common::GhostkeyResponse) {
        match response {
            ghostkey_common::GhostkeyResponse::GhostKeyList { keys } => {
                info!("Received {} ghostkeys", keys.len());

                // CLEARED FIRST, and deliberately not last.
                //
                // The vault has answered; that is the whole meaning of this
                // flag. Everything below is follow-up work, and while the flag
                // sat at the END of this arm a failure in any of it left the
                // button reading "Waiting for vault..." forever, for a request
                // that had demonstrably completed. That is what happened on
                // 2026-09-06: the follow-up panicked and the user was told the
                // vault had not replied, when it had.
                self.request_any_access_in_flight = false;

                // If any ghostkey has verifying_key_bytes and we have a pending
                // store creation for it, fill in the key
                for key in &keys {
                    if let Some(ref vk_bytes) = key.verifying_key_bytes {
                        if let Some(ref mut pending) = self.pending_store_creation {
                            if pending.ghostkey_fingerprint == key.fingerprint
                                && pending.seller_verifying_key_bytes == [0u8; 32]
                                && vk_bytes.len() == 32
                            {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(vk_bytes);
                                pending.seller_verifying_key_bytes = arr;
                                info!(
                                    "Filled verifying key for pending store creation: {}",
                                    key.fingerprint
                                );
                            }
                        }
                    }
                }

                // What the follow-up work needs, captured BEFORE the merge
                // consumes `keys`. Only plain data crosses into the task below;
                // nothing holding a borrow does.
                let newly_shared: Vec<(String, Option<Vec<u8>>)> = keys
                    .iter()
                    .map(|k| (k.fingerprint.clone(), k.verifying_key_bytes.clone()))
                    .collect();
                let needs_encryption_key: Vec<String> = keys
                    .iter()
                    .map(|k| k.fingerprint.clone())
                    .filter(|f| !self.encryption_public_keys.contains_key(f))
                    .collect();

                // Merge new keys into the existing list (dedup by
                // fingerprint, prefer the newer entry). Wholesale
                // replacement would drop previously-connected keys
                // when a second `RequestAnyAccess` returns a single
                // newly-shared key.
                for key in keys {
                    if let Some(slot) = self
                        .ghostkeys
                        .iter_mut()
                        .find(|k| k.fingerprint == key.fingerprint)
                    {
                        *slot = key;
                    } else {
                        self.ghostkeys.push(key);
                    }
                }

                // Reputation migration retries for EVERY identity we know a
                // verifying key for, not just the ones just shared: both halves
                // of `ReputationParameters` must be present at once and they
                // arrive from DIFFERENT delegates in no fixed order, so whichever
                // lands second has to start the probe. Collected after the merge
                // so a key shared in this very response is included.
                let all_identities: Vec<(String, Vec<u8>)> = self
                    .ghostkeys
                    .iter()
                    .filter_map(|k| {
                        k.verifying_key_bytes
                            .clone()
                            .map(|vk| (k.fingerprint.clone(), vk))
                    })
                    .collect();

                // EVERYTHING BELOW RUNS OUTSIDE THIS BORROW, AND MUST.
                //
                // This handler is invoked as
                // `apply_delegate_response(&mut APP_STATE.write(), ..)`
                // (`gateway::response_handler`), so a write guard on APP_STATE is
                // held for the whole call. Any `APP_STATE.read()` reached from
                // here panics with `AlreadyBorrowedMut` -- and under
                // `panic = "abort"` that trap kills the rest of the handler.
                //
                // Spawning is NOT by itself enough: `spawn_local` polls the
                // future eagerly up to its first await, so a task that touches
                // APP_STATE before awaiting still runs inside the guard. That is
                // exactly how `store_ops::list_stores` -- already spawned --
                // panicked at its opening `APP_STATE.read()`. The timer await is
                // therefore load-bearing: it yields to the event loop, by which
                // point the guard is long dropped.
                //
                // Three call sites panicked this way on the first ghostkey ever
                // connected (migrate_ops.rs:258, migrate_ops.rs:421,
                // store_ops.rs:530), because this whole path is wasm-only and
                // nothing had ever executed it.
                #[cfg(target_arch = "wasm32")]
                wasm_bindgen_futures::spawn_local(async move {
                    for (fingerprint, vk) in newly_shared {
                        if let Err(e) =
                            crate::gateway::store_ops::list_stores(fingerprint.clone()).await
                        {
                            dioxus::logger::tracing::error!(
                                "Failed to list stores for {fingerprint}: {e}"
                            );
                        }
                        if let Some(vk) = vk.as_ref() {
                            crate::gateway::migrate_ops::start_identity_migration(&fingerprint, vk);
                        }
                    }

                    for (fingerprint, vk) in all_identities {
                        crate::gateway::migrate_ops::start_reputation_migration(&fingerprint, &vk);
                    }

                    for fingerprint in needs_encryption_key {
                        crate::components::ensure_encryption_key(fingerprint);
                    }
                });

                #[cfg(not(target_arch = "wasm32"))]
                {
                    let _ = (newly_shared, needs_encryption_key, all_identities);
                }
            }

            ghostkey_common::GhostkeyResponse::SignResult {
                scoped_payload,
                signature,
                certificate_pem,
            } => {
                info!("Received signature from ghostkey delegate");
                // Match the answer to its request by the bytes that were
                // signed, not by queue position. `SignResult` carries no
                // correlation id, so position is the obvious choice -- but it
                // is only correct while answers come back in the order they
                // were asked for, and it fails silently when they do not: the
                // signature is grafted onto the wrong object, and what lands
                // on the network is a record whose signature does not cover
                // it. The contract then rejects it with nothing to say about
                // why, which is indistinguishable from never having sent it.
                //
                // The scoped payload names its own request (see
                // `signed_message_bytes`), so use that instead. An answer
                // matching nothing outstanding is dropped rather than applied
                // to whatever happens to be at the head of the queue: those
                // bytes could not verify against any object we hold, so
                // there is nothing useful to do with them.
                let matched = signed_message_bytes(&scoped_payload).and_then(|message| {
                    self.pending_signatures
                        .iter()
                        .position(|pending| {
                            pending.signed_bytes().is_ok_and(|bytes| bytes == message)
                        })
                        .and_then(|at| self.pending_signatures.remove(at))
                });
                match matched {
                    Some(PendingSignature::Listing(pending)) => {
                        let authorized = AuthorizedListing {
                            listing: pending.listing,
                            scoped_payload,
                            signature,
                            certificate_pem,
                        };
                        info!(
                            "Constructed AuthorizedListing: {}",
                            authorized.listing.title
                        );

                        // Submit to the store contract if we know which one
                        #[cfg(target_arch = "wasm32")]
                        if let Some(store_id) = pending.store_contract_id {
                            let listing = authorized.clone();
                            wasm_bindgen_futures::spawn_local(async move {
                                if let Err(e) = crate::gateway::store_ops::submit_listing_by_id(
                                    &store_id, listing,
                                )
                                .await
                                {
                                    dioxus::logger::tracing::error!(
                                        "Failed to submit listing: {}",
                                        e
                                    );
                                    crate::gateway::APP_STATE
                                        .write()
                                        .notifications
                                        .push(format!("Failed to submit listing: {e}"));
                                }
                            });
                        }

                        self.signed_listings_ready.push(authorized);
                    }
                    Some(PendingSignature::StoreInfo(pending)) => {
                        let authorized = harvest_common::store::AuthorizedStoreInfoV1 {
                            info: pending.info,
                            scoped_payload,
                            signature,
                        };
                        info!(
                            "Constructed AuthorizedStoreInfoV1: {}",
                            authorized.info.store_name
                        );

                        #[cfg(target_arch = "wasm32")]
                        {
                            let store_id = pending.store_contract_id;
                            wasm_bindgen_futures::spawn_local(async move {
                                if let Err(e) = crate::gateway::store_ops::submit_store_info_by_id(
                                    &store_id, authorized,
                                )
                                .await
                                {
                                    dioxus::logger::tracing::error!(
                                        "Failed to publish store details: {}",
                                        e
                                    );
                                    crate::gateway::APP_STATE
                                        .write()
                                        .notifications
                                        .push(format!(
                                        "Store created, but its name and description could not \
                                         be published: {e}"
                                    ));
                                }
                            });
                        }
                        #[cfg(not(target_arch = "wasm32"))]
                        let _ = authorized;
                    }
                    Some(PendingSignature::Order(pending)) => {
                        let authorized =
                            authorize_new_order(pending.order, scoped_payload, signature);
                        info!(
                            "Constructed AuthorizedOrder {} for {} sats",
                            authorized.order.id.short(),
                            authorized.order.amount_sats
                        );

                        // Tell the buyer which commitment is theirs, if this
                        // invoice answers a request. Done here rather than
                        // left as a second thing for the seller to do: a
                        // published commitment nobody was told about is one
                        // the buyer cannot recognise, so accepting has to
                        // produce both halves or neither.
                        //
                        // The two are dispatched independently and may land
                        // in either order. That is safe rather than merely
                        // tolerable: a buyer holding an acceptance for a
                        // commitment that has not arrived reads
                        // `CommitmentNotPublished` and does not pay, which is
                        // the same answer they would get from a seller who
                        // never published at all.
                        self.announce_acceptance(
                            &pending.store_contract_id,
                            pending.reply_to,
                            &authorized.order.id,
                        );

                        #[cfg(target_arch = "wasm32")]
                        {
                            let store_id = pending.store_contract_id;
                            wasm_bindgen_futures::spawn_local(async move {
                                if let Err(e) = crate::gateway::store_ops::submit_order_by_id(
                                    &store_id, authorized,
                                )
                                .await
                                {
                                    dioxus::logger::tracing::error!(
                                        "Failed to publish the invoice: {}",
                                        e
                                    );
                                    crate::gateway::APP_STATE
                                        .write()
                                        .notifications
                                        .push(format!(
                                        "The invoice was signed but could not be published: {e}"
                                    ));
                                }
                            });
                        }
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            let _ = (authorized, pending.store_contract_id);
                        }
                    }
                    None => {
                        warn!(
                            "SignResult matches none of the {} outstanding signature request(s) \
                             -- dropping it",
                            self.pending_signatures.len()
                        );
                    }
                }
            }

            ghostkey_common::GhostkeyResponse::Certificate {
                fingerprint,
                certificate_pem,
            } => {
                info!("Received certificate for {}", fingerprint);
                // If we have a pending store creation for this fingerprint,
                // fill in the certificate PEM. The verifying key is extracted
                // by the store creation code from the certificate at contract
                // creation time.
                self.certificates
                    .insert(fingerprint.clone(), certificate_pem.clone());
                if let Some(ref mut pending) = self.pending_store_creation {
                    if pending.ghostkey_fingerprint == fingerprint {
                        pending.certificate_pem = certificate_pem;
                        info!("Updated pending store creation with certificate");
                    }
                }
                self.start_store_creation_if_ready();
                self.start_store_edit_if_ready();
            }

            ghostkey_common::GhostkeyResponse::GhostKeyDetail {
                fingerprint,
                certificate_pem,
                ..
            } => {
                info!("Received ghostkey detail for {}", fingerprint);
                self.certificates
                    .insert(fingerprint.clone(), certificate_pem.clone());
                // Also update pending store creation if applicable
                if let Some(ref mut pending) = self.pending_store_creation {
                    if pending.ghostkey_fingerprint == fingerprint {
                        pending.certificate_pem = certificate_pem;
                    }
                }
                self.start_store_creation_if_ready();
                self.start_store_edit_if_ready();
            }

            ghostkey_common::GhostkeyResponse::Error { message } => {
                self.notifications
                    .push(format!("Ghostkey error: {message}"));
                self.pending_signatures.clear();
                // A failed `GetCertificate` surfaces here, and a creation or
                // an edit waiting on that certificate would otherwise sit
                // unfinished and unmentioned. `start_store_creation_if_ready`
                // waits for the certificate precisely because it trusts this
                // to happen.
                self.pending_store_creation = None;
                self.pending_store_edit = None;
                self.request_any_access_in_flight = false;
            }

            // The user denied a `RequestAnyAccess` prompt. Surface a
            // notification, clear the in-flight flag so the button is
            // enabled again, and clear any pending listing/store
            // creation that was waiting on this grant. Without this
            // cleanup, a subsequent successful SignResult would
            // consume the stale pending listing.
            ghostkey_common::GhostkeyResponse::AccessDenied { .. } => {
                self.notifications.push(
                    "Ghostkey access was denied. Click 'Connect a ghostkey' again to retry.".into(),
                );
                self.request_any_access_in_flight = false;
                self.pending_signatures.clear();
                self.pending_store_creation = None;
                self.pending_store_edit = None;
            }

            // The vault has no ghostkeys at all. Tell the user where
            // to go to create one. Same cleanup as AccessDenied.
            ghostkey_common::GhostkeyResponse::NoIdentityAvailable => {
                self.notifications.push(
                    "No ghostkey identities found. Open the Ghostkey Vault to create one, then come back and click 'Connect a ghostkey'.".into(),
                );
                self.request_any_access_in_flight = false;
                self.pending_signatures.clear();
                self.pending_store_creation = None;
                self.pending_store_edit = None;
            }

            // Per-fingerprint denial: the user denied a specific-key
            // prompt, or the vault revoked the grant between connect
            // and sign. Same cleanup as the access-denial arms.
            ghostkey_common::GhostkeyResponse::PermissionDenied { fingerprint, .. } => {
                self.notifications
                    .push(format!("Ghostkey access denied for {fingerprint}."));
                self.request_any_access_in_flight = false;
                self.pending_signatures.clear();
                self.pending_store_creation = None;
                self.pending_store_edit = None;
            }

            // Terminal for a waiting `GetCertificate`: the vault is telling
            // us the key does not exist, so no certificate is coming and
            // nothing is left to wait for. This used to fall into the
            // wildcard below and clear nothing, which left a seller's store
            // creation pending forever with no message.
            ghostkey_common::GhostkeyResponse::KeyNotFound { fingerprint } => {
                self.notifications.push(format!(
                    "Ghostkey {fingerprint} was not found in the vault."
                ));
                self.request_any_access_in_flight = false;
                self.pending_signatures.clear();
                self.pending_store_creation = None;
                self.pending_store_edit = None;
            }

            // Vault-only responses Harvest doesn't act on. The
            // explicit arms above cover every user-visible failure
            // mode in the current ghostkey-common protocol; this
            // wildcard is just for vault-management responses
            // (PermissionGranted / PermissionRevoked / PermissionList /
            // VerifyResult / Deleted / LabelSet, etc).
            // A future response variant with a failure semantic
            // would slip through here -- worth re-auditing on every
            // ghostkey-common bump.
            #[allow(clippy::wildcard_enum_match_arm)]
            _ => {
                info!("Unhandled ghostkey response: {:?}", response);
            }
        }
    }

    /// Handle a response from the Bitcoin surface of the harvest delegate.
    pub fn on_bitcoin_delegate_response(&mut self, response: BitcoinDelegateResponse) {
        match response {
            BitcoinDelegateResponse::Watched { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                match result {
                    Ok(watch) => self.upsert_watch(watch),
                    Err(e) => self.notifications.push(format!(
                        "Couldn't watch address: {}",
                        friendly_bridge_error(&e)
                    )),
                }
            }

            BitcoinDelegateResponse::Unwatched { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                if let Err(e) = result {
                    self.notifications.push(format!(
                        "Couldn't stop watching: {}",
                        friendly_bridge_error(&e)
                    ));
                }
                // The delegate is authoritative on the watch list; refresh
                // from it rather than guessing locally which row to drop,
                // so a partial failure never leaves the UI out of sync.
                #[cfg(target_arch = "wasm32")]
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) = crate::gateway::bitcoin_ops::list_watched().await {
                        dioxus::logger::tracing::error!("Failed to refresh watch list: {e}");
                    }
                });
            }

            BitcoinDelegateResponse::WatchList { watches } => {
                for w in &watches {
                    self.register_watch_contract(w);
                }
                self.bitcoin.watches = watches;
                self.bitcoin.watches_loaded = true;
            }

            BitcoinDelegateResponse::OrderAssociated { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                if let Err(e) = result {
                    self.notifications
                        .push(format!("Couldn't link payment to order: {e}"));
                }
            }

            BitcoinDelegateResponse::BridgeConfigured { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                match result {
                    Ok(()) => {
                        #[cfg(target_arch = "wasm32")]
                        wasm_bindgen_futures::spawn_local(async move {
                            if let Err(e) = crate::gateway::bitcoin_ops::get_bridge().await {
                                dioxus::logger::tracing::error!(
                                    "Failed to refresh bridge config: {e}"
                                );
                            }
                        });
                    }
                    Err(e) => self
                        .notifications
                        .push(format!("Couldn't configure bridge: {e}")),
                }
            }

            BitcoinDelegateResponse::Bridge { endpoint } => {
                self.bitcoin.bridge_loaded = true;
                self.bitcoin.bridge = endpoint.clone();
                if let Some(ep) = endpoint {
                    // Covers the (currently hypothetical) case of a
                    // well-known/pinned deployment -- see
                    // `gateway::bitcoin_config`.
                    self.register_tip_contract(ep.network);
                    // The real discovery path today: ask the bridge itself
                    // over plain HTTP, which the delegate cannot do on our
                    // behalf (no outbound-HTTP host function exists for
                    // delegates). See `gateway::bitcoin_bridge_http`.
                    #[cfg(target_arch = "wasm32")]
                    {
                        let url = ep.url.clone();
                        wasm_bindgen_futures::spawn_local(async move {
                            crate::gateway::bitcoin_bridge_http::refresh_bridge_status(url).await;
                        });
                    }
                } else {
                    // No bridge configured yet -- true first run. Try the
                    // default, which is the user's OWN machine.
                    //
                    // This is what makes the first-run panel show live Bitcoin
                    // data with no credential and no configuration, for anyone
                    // running their own bridge. If none is running the fetch
                    // fails and the panel keeps saying no bridge is
                    // configured, which is the honest outcome; it never
                    // invents data.
                    #[cfg(target_arch = "wasm32")]
                    {
                        let url = crate::gateway::bitcoin_config::default_bridge_url().to_string();
                        wasm_bindgen_futures::spawn_local(async move {
                            crate::gateway::bitcoin_bridge_http::refresh_bridge_status(url).await;
                        });
                    }
                }
            }

            BitcoinDelegateResponse::PaymentXpubSet { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                match result {
                    Ok(status) => {
                        info!(
                            "Payment key recorded for {}, next index {}",
                            status.network.as_str(),
                            status.next_index
                        );
                        self.bitcoin.payment_xpub = Some(status);
                        self.bitcoin.payment_xpub_loaded = true;
                    }
                    // Every rejection here names something the seller can act
                    // on -- the wrong export, the wrong network, the wrong
                    // depth -- so it is shown verbatim rather than reduced to
                    // "invalid key".
                    Err(e) => self
                        .notifications
                        .push(format!("Couldn't use that payment key: {e}")),
                }
            }

            BitcoinDelegateResponse::PaymentXpub { status } => {
                self.bitcoin.payment_xpub = status;
                self.bitcoin.payment_xpub_loaded = true;
            }

            BitcoinDelegateResponse::OrderAddress { request_id, result } => {
                self.bitcoin.in_flight.remove(&request_id);
                match result {
                    Ok(derived) => self.complete_invoice(request_id, derived),
                    Err(e) => {
                        // Drop the invoice: without an address there is
                        // nothing to sign, and leaving it queued would leave
                        // the form looking as though something were still in
                        // progress.
                        self.pending_invoices.remove(&request_id);
                        self.notifications
                            .push(format!("Couldn't get a payment address: {e}"));
                    }
                }
                // The stored counter has advanced whatever happened here (see
                // the delegate's `apply_derive_order_address`), so re-read it
                // rather than letting the UI show a stale index.
                #[cfg(target_arch = "wasm32")]
                wasm_bindgen_futures::spawn_local(async move {
                    if let Err(e) = crate::gateway::bitcoin_ops::get_payment_xpub().await {
                        dioxus::logger::tracing::error!("Failed to refresh the payment key: {e}");
                    }
                });
            }

            // `BitcoinDelegateRequest`/`Response` are `#[non_exhaustive]` in
            // harvest-common, so a future variant lands here silently rather
            // than failing to build. Worth re-auditing on every bump.
            #[allow(clippy::wildcard_enum_match_arm)]
            _ => {
                info!("Unhandled bitcoin delegate response: {:?}", response);
            }
        }
    }

    /// Fold a chain-tip contract's state into the live view for `network`.
    fn apply_tip_state(
        &mut self,
        network: BitcoinNetwork,
        state: &freenet_bitcoin_common::BitcoinTipStateV1,
    ) {
        let recent = state.blocks.recent(RECENT_BLOCKS_KEPT);
        let last_block_time = recent.first().map(|b| b.block_time);
        let view = self.bitcoin.tips.entry(network).or_insert_with(|| TipView {
            network,
            tip_height: None,
            signed_tip: None,
            last_block_time: None,
            recent_blocks: Vec::new(),
        });
        view.tip_height = state.tip_height();
        // The signed original, kept alongside the projection: a payment proof
        // carries one and `tip_height` cannot stand in for it.
        view.signed_tip = state
            .tip_height()
            .and_then(|height| state.blocks.blocks.get(&height).cloned());
        view.last_block_time = last_block_time;
        view.recent_blocks = recent
            .into_iter()
            .map(|b| BlockRow {
                height: b.anchor.height,
                hash: b.anchor.hash,
                tx_count: b.tx_count,
                block_time: b.block_time,
            })
            .collect();
    }

    /// Fold an address contract's state into the live view for that watch.
    fn apply_address_state(
        &mut self,
        contract_id: Vec<u8>,
        network: BitcoinNetwork,
        state: &freenet_bitcoin_common::BitcoinAddressStateV1,
    ) {
        // `min_confirmations = 1`: this is the generic watch-list view, not
        // an order-specific check, so "confirmed" here means "on chain at
        // all" rather than meeting any particular order's threshold. Orders
        // apply their own `required_confirmations` via `verify_payment_proof`
        // when a payment is actually being proven.
        let tip_height = self
            .bitcoin
            .tips
            .get(&network)
            .and_then(|t| t.tip_height)
            .unwrap_or(0);
        let confirmed_sats = state.claims.confirmed_value_sats(tip_height, 1);
        let pending_sats = state.claims.pending_value_sats(tip_height, 1);

        let mut txs: Vec<TxRow> = state
            .claims
            .outpoint_statuses()
            .into_iter()
            .map(|(op, status)| {
                let (value_sats, row_status) = match status {
                    freenet_bitcoin_common::OutpointStatus::Unconfirmed { value_sats } => {
                        (value_sats, TxRowStatus::Unconfirmed)
                    }
                    // `attested_depth` is genuinely not consulted HERE, and
                    // that is worth stating rather than hiding behind `..`.
                    // This row is display-only: `anchor.height` feeds a sort
                    // key and the label "confirmed", and no confirmation
                    // COUNT is derived from it. The figures this screen gates
                    // on -- `confirmed_sats` and `pending_sats` above -- come
                    // from upstream's `confirmed_value_sats` /
                    // `pending_value_sats`, which apply the
                    // `confirmations_at` cap themselves.
                    //
                    // If this row ever grows a depth to show, it must use
                    // `status.confirmations_at(tip_height)` and not
                    // `tip_height - anchor.height`: the latter is the
                    // uncapped observed depth, which a submitter can inflate
                    // by pairing a pre-reorg confirmation with a fresh tip.
                    // See `harvest_common::payment::verify_on_chain_proof`.
                    freenet_bitcoin_common::OutpointStatus::Confirmed {
                        value_sats,
                        anchor,
                        attested_depth: _,
                    } => (
                        value_sats,
                        TxRowStatus::Confirmed {
                            anchor_height: anchor.height,
                        },
                    ),
                    freenet_bitcoin_common::OutpointStatus::Retracted => {
                        (0, TxRowStatus::Retracted)
                    }
                };
                TxRow {
                    // Reversed (big-endian) byte order -- the form block
                    // explorers and wallets display, not Bitcoin's internal
                    // little-endian order.
                    txid_display: op.txid.to_display_string(),
                    value_sats,
                    status: row_status,
                }
            })
            .collect();
        // Newest first: unconfirmed, then confirmed by descending height,
        // then retracted last.
        txs.sort_by_key(|t| std::cmp::Reverse(tx_sort_rank(&t.status)));

        let view = self
            .bitcoin
            .addresses
            .entry(contract_id)
            .or_insert_with(|| AddressView {
                network,
                claims: Vec::new(),
                scanned_to: None,
                confirmed_sats: 0,
                pending_sats: 0,
                txs: Vec::new(),
            });
        view.network = network;
        // The signed claims themselves, capped at what a proof may carry.
        // `scanned` watermarks come first: a `ScannedTo` is what lets a
        // confirmation attest any depth at all, so dropping those to keep
        // payment claims would leave a proof that cannot reach the order's
        // `required_confirmations`.
        view.claims = state
            .claims
            .scanned
            .values()
            .chain(state.claims.claims.values())
            .take(harvest_common::payment::MAX_PROOF_CLAIMS)
            .cloned()
            .collect();
        view.scanned_to = state.scanned_to();
        view.confirmed_sats = confirmed_sats;
        view.pending_sats = pending_sats;
        view.txs = txs;
    }

    /// Note that `watch` names an address contract, recording the network it
    /// belongs to and subscribing to it if we haven't already.
    fn register_watch_contract(&mut self, watch: &WatchedPayment) {
        let Some(contract_id_bs58) = watch.contract_id.as_deref() else {
            return;
        };
        let Ok(bytes) = bs58::decode(contract_id_bs58).into_vec() else {
            return;
        };
        if bytes.len() != 32 {
            return;
        }
        self.bitcoin
            .address_contract_network
            .insert(bytes.clone(), watch.network);
        if self.bitcoin.subscribed.insert(bytes.clone()) {
            #[cfg(target_arch = "wasm32")]
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = crate::gateway::bitcoin_ops::subscribe_contract(&bytes).await {
                    dioxus::logger::tracing::error!("Failed to subscribe address contract: {e}");
                }
            });
        }
    }

    /// Insert or replace a watch by its stable key, and ensure we're
    /// subscribed to its address contract.
    fn upsert_watch(&mut self, watch: WatchedPayment) {
        self.register_watch_contract(&watch);
        match self
            .bitcoin
            .watches
            .iter_mut()
            .find(|w| w.key() == watch.key())
        {
            Some(existing) => *existing = watch,
            None => self.bitcoin.watches.push(watch),
        }
    }

    /// Ensure the given network's chain-tip contract is subscribed, if we
    /// know its contract id from a well-known/pinned deployment.
    ///
    /// `crate::gateway::bitcoin_config` supplies that id, and it is no longer
    /// empty: signet names the tip contract of the bridge deployed on nova,
    /// so this is a real subscription on that network and a no-op on the
    /// other three. That constant is a stopgap and goes silently stale on any
    /// contract rebuild -- see that module's docs, which explain why the
    /// runtime `/v1/status` lookup this was meant to replace is refused by
    /// the gateway's content-security policy, and why a pointer record is the
    /// durable fix.
    ///
    /// `register_tip_contract_with_id` is the other entry point, taking an id
    /// discovered at runtime from the bridge's `/v1/status` self-report (see
    /// `gateway::bitcoin_bridge_http::refresh_bridge_status`), which works
    /// under `dx serve` where no CSP applies.
    pub fn register_tip_contract(&mut self, network: BitcoinNetwork) {
        let Some(id_bs58) = crate::gateway::bitcoin_config::well_known_tip_contract_id(network)
        else {
            return;
        };
        self.register_tip_contract_with_id(network, id_bs58);
    }

    /// Register a network's chain-tip contract id, from wherever it was
    /// discovered, and subscribe to it if we haven't already.
    pub fn register_tip_contract_with_id(&mut self, network: BitcoinNetwork, id_bs58: &str) {
        let Ok(bytes) = bs58::decode(id_bs58).into_vec() else {
            dioxus::logger::tracing::warn!(
                "Bridge reported a tip contract id that isn't valid bs58: {id_bs58}"
            );
            return;
        };
        if bytes.len() != 32 {
            dioxus::logger::tracing::warn!(
                "Bridge reported a tip contract id that isn't 32 bytes: {id_bs58}"
            );
            return;
        }
        self.bitcoin
            .tip_contract_network
            .insert(bytes.clone(), network);
        self.bitcoin.tips.entry(network).or_insert_with(|| TipView {
            network,
            tip_height: None,
            signed_tip: None,
            last_block_time: None,
            recent_blocks: Vec::new(),
        });
        if self.bitcoin.subscribed.insert(bytes.clone()) {
            #[cfg(target_arch = "wasm32")]
            wasm_bindgen_futures::spawn_local(async move {
                if let Err(e) = crate::gateway::bitcoin_ops::subscribe_contract(&bytes).await {
                    dioxus::logger::tracing::error!("Failed to subscribe tip contract: {e}");
                }
            });
        }
    }
}

/// Ordering key for a transaction row: unconfirmed first, then confirmed by
/// descending anchor height, then retracted last.
fn tx_sort_rank(status: &TxRowStatus) -> (u8, u32) {
    match status {
        TxRowStatus::Unconfirmed => (2, u32::MAX),
        TxRowStatus::Confirmed { anchor_height } => (1, *anchor_height),
        TxRowStatus::Retracted => (0, 0),
    }
}

/// Map a raw bridge/delegate error string to something a user can act on.
/// The delegate's errors are `String`s meant for logs (see
/// `BitcoinDelegateResponse::Watched`'s `Result<_, String>`), not a typed
/// error channel, so this is a best-effort keyword match rather than an
/// exhaustive mapping.
pub fn friendly_bridge_error(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.contains("ghost key") || lower.contains("ghostkey") || lower.contains("not authorized")
    {
        "This bridge is only available to Ghost Key holders. Connect a Ghost Key and try again."
            .to_string()
    } else if lower.contains("rate limit") {
        "The bridge is rate-limiting requests right now -- try again shortly.".to_string()
    } else if lower.contains("unsupported network") {
        "This bridge doesn't support that Bitcoin network.".to_string()
    } else if lower.contains("not synced") || lower.contains("still syncing") {
        "The bridge is still syncing with the Bitcoin chain -- try again shortly.".to_string()
    } else {
        raw.to_string()
    }
}

/// Whether anything is actually synchronizing a watched script, as the watch
/// row should report it.
///
/// # Why `LocalOnly` is every manual watch today
///
/// Watching an address is two separate things: recording it privately (which
/// works), and asking a bridge to synchronize the script so its transactions
/// land in a `BitcoinAddressContract` the UI can subscribe to (which nothing
/// does). The second half has no implementation and cannot get one where it
/// was assumed to live:
///
/// * The delegate cannot make the request. `OutboundDelegateMsg` has no HTTP
///   variant -- the whole set is application messages, user input, context,
///   and contract GET/PUT/UPDATE/SUBSCRIBE -- so a delegate has no outbound
///   HTTP capability at all. `handlers`' `Watch` arm persists the record and
///   answers `Watched { result: Ok(..) }`, which is the truth about what it
///   did, not a claim that a bridge was told.
/// * The page cannot make it either, once published. A webapp is served with
///   `connect-src` limited to its own gateway, so `fetch` to a bridge URL is
///   refused by the content-security policy. `gateway::bitcoin_config`'s
///   module docs record the same refusal for `/v1/status`, which is why the
///   tip contract id became a build-time constant.
///
/// So a manual watch keeps `contract_id: None` and `bridge_synced: false`
/// forever, `register_watch_contract` returns immediately because there is no
/// contract id to subscribe to, and no transaction can ever appear. Saying
/// "Waiting for bridge to sync…" describes a wait that never ends. This
/// function exists so the row says that instead.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WatchSyncStatus {
    /// A bridge reported a failure for this script.
    Failed(String),
    /// A bridge is synchronizing it and named the address contract carrying
    /// the results, so transactions can appear.
    Live,
    /// A bridge is synchronizing it but named no address contract, so there
    /// is nothing for the UI to subscribe to.
    SyncedWithoutContract,
    /// Recorded on this device and nowhere else.
    LocalOnly,
}

impl WatchSyncStatus {
    /// What to tell the user, or `None` when there is nothing to say because
    /// the watch is working.
    pub fn message(&self) -> Option<String> {
        match self {
            WatchSyncStatus::Failed(text) => Some(text.clone()),
            WatchSyncStatus::Live => None,
            WatchSyncStatus::SyncedWithoutContract => Some(
                "A bridge is watching this address but didn't say which Freenet contract \
                 carries the results, so there is nothing for Harvest to read."
                    .to_string(),
            ),
            WatchSyncStatus::LocalOnly => Some(
                "Recorded on this device only. No bridge has been asked to watch this \
                 address, so its transactions will not appear here."
                    .to_string(),
            ),
        }
    }
}

/// Classify a watch. See [`WatchSyncStatus`] for why `LocalOnly` is the
/// answer for every manual watch today.
pub fn watch_sync_status(watch: &WatchedPayment) -> WatchSyncStatus {
    if let Some(error) = watch.last_error.as_deref() {
        return WatchSyncStatus::Failed(friendly_bridge_error(error));
    }
    if !watch.bridge_synced {
        return WatchSyncStatus::LocalOnly;
    }
    // A bridge confirmed the script but the address contract is what the UI
    // actually reads, so a watch without one is not live however the bridge
    // answered.
    if watch.contract_id.is_none() {
        return WatchSyncStatus::SyncedWithoutContract;
    }
    WatchSyncStatus::Live
}

/// Bitcoin/Payments state: bridge config, the user's private watch list, and
/// live on-chain data mirrored from subscribed Bitcoin contracts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BitcoinState {
    /// The bridge the harvest delegate is configured to use, if any.
    pub bridge: Option<BridgeEndpoint>,
    /// Whether we've heard back from `GetBridge` at least once -- lets the
    /// UI distinguish "still loading" from "no bridge configured".
    pub bridge_loaded: bool,
    /// The user's private watch list, as reported by the delegate.
    pub watches: Vec<WatchedPayment>,
    pub watches_loaded: bool,
    /// The account public key invoices derive their payment addresses from.
    pub payment_xpub: Option<harvest_common::PaymentXpubStatus>,
    /// Whether `GetPaymentXpub` has answered at least once. Distinguishes "no
    /// key configured" from "we have not asked yet", so the seller is not
    /// prompted to add one before we know whether they already have.
    pub payment_xpub_loaded: bool,
    /// Bitcoin delegate request ids awaiting a response, so a specific
    /// button can show "watching..." rather than a global spinner.
    pub in_flight: HashSet<u64>,
    pub next_request_id: u64,
    /// Per-network live chain tip, once that network's tip contract is
    /// subscribed.
    pub tips: HashMap<BitcoinNetwork, TipView>,
    /// Per-contract-id live address view (claims folded into balances/txs),
    /// keyed by the address contract's instance id bytes.
    pub addresses: HashMap<Vec<u8>, AddressView>,
    /// Contract instance ids (tip and address) we've already issued a
    /// GET+subscribe for, so state churn doesn't resubscribe repeatedly.
    pub subscribed: HashSet<Vec<u8>>,
    /// Tip contract id -> network, so an incoming state/update routes to
    /// the right `TipView` without guessing from the bytes.
    pub tip_contract_network: HashMap<Vec<u8>, BitcoinNetwork>,
    /// Address contract id -> network, same purpose for `AddressView`.
    pub address_contract_network: HashMap<Vec<u8>, BitcoinNetwork>,
}

impl BitcoinState {
    /// Allocate the next request id for a `BitcoinDelegateRequest`.
    pub fn next_request_id(&mut self) -> u64 {
        self.next_request_id += 1;
        self.next_request_id
    }
}

/// Live view of one network's chain tip, mirrored from its
/// `BitcoinTipContract`.
#[derive(Clone, Debug, PartialEq)]
pub struct TipView {
    pub network: BitcoinNetwork,
    pub tip_height: Option<u32>,
    /// The tip entry as the bridge signed it.
    ///
    /// A payment proof carries one, and it is what the verifier measures
    /// confirmation depth against. The projected `tip_height` beside it is
    /// for display and cannot be put in a proof.
    pub signed_tip: Option<freenet_bitcoin_common::SignedTipEntry>,
    /// Header timestamp (Bitcoin's clock) of the most recent block. Display
    /// only -- e.g. "X minutes ago" computed against the browser's own
    /// clock, never trusted as authoritative.
    pub last_block_time: Option<u32>,
    /// Newest first.
    pub recent_blocks: Vec<BlockRow>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BlockRow {
    pub height: u32,
    /// The block's own hash.
    ///
    /// Kept because an order's anchor names a height AND a hash, and a check
    /// that compared only heights would accept an anchor from a chain this
    /// reader is not on -- which is precisely the case the hash is in the
    /// anchor for.
    pub hash: freenet_bitcoin_common::BlockHash,
    pub tx_count: u32,
    pub block_time: u32,
}

/// How many recent blocks [`TipView`] keeps.
///
/// Two consumers, and the larger wins. The Bitcoin panel renders a handful
/// for display; [`TipView::anchor_is_canonical`] has to be able to answer
/// about every height a FRESH anchor may name, which is the tip and the
/// [`harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS`] beneath it. A window that kept fewer would
/// report a perfectly good anchor as unknown, and unknown reads as "do not
/// pay" -- so the buy flow would break for no reason a user could see.
///
/// Derived from the constant rather than written as a number, so raising the
/// tolerance cannot silently outgrow the window.
pub const RECENT_BLOCKS_KEPT: usize = {
    const DISPLAYED: usize = 8;
    const FRESH: usize = harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS as usize + 1;
    if DISPLAYED > FRESH {
        DISPLAYED
    } else {
        FRESH
    }
};

impl TipView {
    /// The anchor a commitment written now should carry.
    ///
    /// `None` before this network's tip contract has answered. A seller with
    /// no tip cannot write a commitment a buyer will pay, which is why
    /// [`order_for_invoice`] refuses rather than publishing one without.
    pub fn current_anchor(&self) -> Option<freenet_bitcoin_common::BlockAnchor> {
        let newest = self.recent_blocks.first()?;
        Some(freenet_bitcoin_common::BlockAnchor {
            height: newest.height,
            hash: newest.hash,
        })
    }

    /// Whether `anchor` is on the chain THIS reader sees.
    ///
    /// `None` means unknown -- the height is outside the window kept here --
    /// which is deliberately not the same answer as "not on this chain". A
    /// caller must treat unknown as a reason to withhold payment rather than
    /// as evidence of a reorg; the two differ in what the user should be
    /// told. Same contract as
    /// `freenet_bitcoin_common::BlockSummariesV1::anchor_is_canonical`, which
    /// is the authority this mirrors.
    pub fn anchor_is_canonical(
        &self,
        anchor: &freenet_bitcoin_common::BlockAnchor,
    ) -> Option<bool> {
        let row = self
            .recent_blocks
            .iter()
            .find(|block| block.height == anchor.height)?;
        Some(row.hash == anchor.hash)
    }
}

/// Live view of one watched address, mirrored from its
/// `BitcoinAddressContract`.
#[derive(Clone, Debug, PartialEq)]
pub struct AddressView {
    pub network: BitcoinNetwork,
    /// The bridge-signed claims themselves, not just the balances folded out
    /// of them.
    ///
    /// The projection below is what a screen renders; a payment PROOF needs
    /// the signed originals, and until this field existed nothing in the app
    /// held them -- so `verify_payment_proof` and the whole bridge-claim
    /// machinery had nothing to verify, and an order stayed `AwaitingPayment`
    /// however much had been paid.
    ///
    /// Bounded by [`harvest_common::payment::MAX_PROOF_CLAIMS`], because that
    /// is the most a proof may carry: keeping more would be keeping what
    /// cannot be used. An address that exceeds it is left un-provable rather
    /// than curated, which `assemble_on_chain_proof` reports.
    pub claims: Vec<freenet_bitcoin_common::SignedClaim>,
    /// The highest height any trusted bridge has scanned this script to.
    /// `None` means "not synchronized yet", distinct from "no activity".
    pub scanned_to: Option<u32>,
    pub confirmed_sats: u64,
    pub pending_sats: u64,
    /// Newest first (see `tx_sort_rank`).
    pub txs: Vec<TxRow>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TxRow {
    pub txid_display: String,
    pub value_sats: u64,
    pub status: TxRowStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TxRowStatus {
    Unconfirmed,
    Confirmed { anchor_height: u32 },
    Retracted,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "fp-1";

    fn registration(id: u8, key: Option<Vec<u8>>) -> StoreRegistration {
        StoreRegistration {
            store_contract_id: vec![id; 32],
            reputation_contract_id: vec![id.wrapping_add(1); 32],
            mailbox_contract_id: vec![id.wrapping_add(2); 32],
            store_contract_key: key,
        }
    }

    fn store_list(stores: Vec<StoreRegistration>) -> HarvestDelegateResponse {
        HarvestDelegateResponse::StoreList {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            stores,
        }
    }

    /// The delegate cannot store a store's `ContractKey` -- `RegisterStore`
    /// has no field for it -- so every registration it hands back is keyless.
    /// Losing the key breaks "Add Listing" for a store that exists, which is
    /// what a wholesale replace did. See `merge_store_registrations`.
    #[test]
    fn a_store_list_answer_keeps_a_locally_known_contract_key() {
        let key = vec![0xAB; 40];
        let mut state = AppState::default();
        state.merge_store_registrations(FINGERPRINT, vec![registration(1, Some(key.clone()))]);

        state.on_delegate_response(store_list(vec![registration(1, None)]));

        let stores = &state.my_stores[FINGERPRINT];
        assert_eq!(stores.len(), 1);
        assert_eq!(stores[0].store_contract_key, Some(key));
    }

    /// `RegisterStore` and `ListStores` can be in flight at once, so a store
    /// created moments ago need not be in the answer at all.
    #[test]
    fn a_store_list_answer_never_drops_a_store_it_does_not_name() {
        let key = vec![0xCD; 40];
        let mut state = AppState::default();
        state.merge_store_registrations(FINGERPRINT, vec![registration(1, Some(key.clone()))]);

        state.on_delegate_response(store_list(vec![]));
        state.on_delegate_response(store_list(vec![registration(2, None)]));

        let stores = &state.my_stores[FINGERPRINT];
        assert_eq!(stores.len(), 2);
        let kept = stores
            .iter()
            .find(|s| s.store_contract_id == vec![1u8; 32])
            .expect("the locally-known store should survive");
        assert_eq!(kept.store_contract_key, Some(key));
    }

    /// An answer with nothing in it must not leave an empty vec behind: a
    /// seller who owns no store would otherwise be recorded as having an
    /// entry, which reads the same as owning one at every `contains_key`.
    #[test]
    fn an_empty_answer_records_nothing_for_a_storeless_seller() {
        let mut state = AppState::default();
        state.on_delegate_response(store_list(vec![]));

        assert!(!state.my_stores.contains_key(FINGERPRINT));
    }

    /// A completed migration must survive the next `ListStores` answer.
    ///
    /// The migration probe repoints all three ids in memory once it has
    /// recovered a store at its successor address. The harvest delegate has no
    /// request that can replace a `StoreRegistration`, so its registry still
    /// names the PREDECESSOR and will keep saying so for the life of the
    /// session. A wholesale `*existing = registration` therefore un-did the
    /// migration on a race whose timing nobody controls -- silently, and
    /// without so much as a log line.
    #[test]
    fn a_store_list_answer_does_not_revert_a_completed_migration() {
        let mut state = AppState::default();
        state.merge_store_registrations(FINGERPRINT, vec![registration(1, None)]);

        // What the probe did: store 1 -> 9, and its mailbox and reputation
        // with it.
        state.adopt_migrated_contract_id(&[1u8; 32], vec![9u8; 32]);
        state.adopt_migrated_contract_id(&[2u8; 32], vec![10u8; 32]);
        state.adopt_migrated_contract_id(&[3u8; 32], vec![11u8; 32]);

        let migrated = &state.my_stores[FINGERPRINT];
        assert_eq!(
            migrated.len(),
            1,
            "a migration moves a store, it does not add one"
        );
        assert_eq!(migrated[0].store_contract_id, vec![9u8; 32]);
        assert_eq!(migrated[0].reputation_contract_id, vec![10u8; 32]);
        assert_eq!(migrated[0].mailbox_contract_id, vec![11u8; 32]);

        // The delegate answers with the predecessor triple, because that is
        // the only thing it can say.
        state.on_delegate_response(store_list(vec![registration(1, None)]));

        let stores = &state.my_stores[FINGERPRINT];
        assert_eq!(
            stores.len(),
            1,
            "the stale answer names the same store, not a second one"
        );
        assert_eq!(
            stores[0].store_contract_id,
            vec![9u8; 32],
            "the delegate's answer must not move the store back"
        );
        assert_eq!(
            stores[0].reputation_contract_id,
            vec![10u8; 32],
            "nor its reputation contract"
        );
        assert_eq!(
            stores[0].mailbox_contract_id,
            vec![11u8; 32],
            "nor its mailbox -- this is the id the seller's messages arrive at"
        );
    }

    /// The converse: the repoint must not become a permanent veto on the
    /// delegate.
    ///
    /// Only the specific id a migration superseded is rewritten. Anything else
    /// the delegate says is taken as-is, including a value for a field the
    /// probe has repointed -- because a delegate that can say something OTHER
    /// than the stale predecessor is one that has been updated, and an update
    /// is newer than our in-memory guess.
    #[test]
    fn a_repoint_does_not_mask_a_genuinely_new_delegate_value() {
        let mut state = AppState::default();
        state.merge_store_registrations(FINGERPRINT, vec![registration(1, None)]);
        state.adopt_migrated_contract_id(&[2u8; 32], vec![10u8; 32]);

        // Not the predecessor and not the successor: a value only a durable
        // write could have produced.
        let mut fresh = registration(1, None);
        fresh.reputation_contract_id = vec![42u8; 32];
        state.on_delegate_response(store_list(vec![fresh]));

        assert_eq!(
            state.my_stores[FINGERPRINT][0].reputation_contract_id,
            vec![42u8; 32],
            "a delegate value that is not the superseded id must win"
        );
    }

    /// A registration the delegate knows about but we don't is added, key and
    /// all -- the merge is not "ignore the delegate".
    #[test]
    fn a_store_list_answer_adds_stores_we_did_not_know_about() {
        let mut state = AppState::default();
        state.on_delegate_response(store_list(vec![registration(7, None)]));

        assert_eq!(state.my_stores[FINGERPRINT].len(), 1);
        assert_eq!(
            state.my_stores[FINGERPRINT][0].store_contract_id,
            vec![7u8; 32]
        );
    }

    fn loaded_store(name: &str) -> BrowsingStore {
        BrowsingStore {
            info: Some(StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: FINGERPRINT.to_string(),
                reputation_contract_id: [0u8; 32],
                store_name: name.to_string(),
                description: String::new(),
                payment_instructions: String::new(),
                encryption_public_key: None,
            }),
            ..Default::default()
        }
    }

    /// With several stores loaded, the shown store is the active one -- not
    /// whichever the HashMap iterates first. Both `StoreView` and the
    /// document title depend on this answer.
    #[test]
    fn the_displayed_store_is_the_active_one() {
        let mut state = AppState::default();
        for byte in 1..=8u8 {
            state
                .browsing_stores
                .insert(vec![byte; 32], loaded_store(&format!("store {byte}")));
        }
        state.active_store_id = Some(vec![5u8; 32]);

        let (id, store) = state.displayed_store().expect("a store is loaded");
        assert_eq!(id, &vec![5u8; 32]);
        assert_eq!(store.info.as_ref().unwrap().store_name, "store 5");
    }

    /// A placeholder entry -- created the moment a link is opened -- is not a
    /// loaded store, and must not shadow one that is.
    #[test]
    fn a_placeholder_active_store_falls_back_to_a_loaded_one() {
        let mut state = AppState::default();
        state
            .browsing_stores
            .insert(vec![1u8; 32], loaded_store("loaded"));
        state.begin_browsing(vec![2u8; 32]);

        let (id, _) = state.displayed_store().expect("the loaded store");
        assert_eq!(id, &vec![1u8; 32]);
    }

    #[test]
    fn no_loaded_store_displays_nothing() {
        let mut state = AppState::default();
        state.begin_browsing(vec![2u8; 32]);
        assert!(state.displayed_store().is_none());
    }

    /// A `SignResult` carrying a scoped payload that names no request we
    /// made -- the bytes will not even deserialize.
    fn sign_result() -> ghostkey_common::GhostkeyResponse {
        ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            certificate_pem: String::new(),
        }
    }

    /// A `SignResult` shaped the way the ghostkey delegate answers: the
    /// request's own message, wrapped verbatim as `ScopedPayload::payload`.
    fn sign_result_for(pending: &PendingSignature) -> ghostkey_common::GhostkeyResponse {
        let scoped = ghostkey_common::ScopedPayload {
            requestor: harvest_common::expected_harvest_requestor(),
            payload: pending.signed_bytes().expect("serialize signed message"),
        };
        ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload: harvest_common::to_cbor(&scoped).expect("serialize scoped payload"),
            signature: vec![4, 5, 6],
            certificate_pem: String::new(),
        }
    }

    fn pending_listing() -> PendingSignature {
        PendingSignature::Listing(PendingListing {
            fingerprint: FINGERPRINT.to_string(),
            listing: harvest_common::listing::Listing {
                id: harvest_common::listing::ListingId([1u8; 32]),
                title: "Beans".to_string(),
                description: String::new(),
                kind: harvest_common::listing::ListingKind::Sale,
                price: None,
                created_at: chrono::Utc::now(),
            },
            store_contract_id: None,
        })
    }

    fn pending_store_info() -> PendingSignature {
        PendingSignature::StoreInfo(PendingStoreInfo {
            info: loaded_store("Bean Shop").info.expect("info"),
            store_contract_id: vec![1u8; 32],
        })
    }

    /// `SignResult` carries no correlation id, so an answer has to be matched
    /// to its request by the bytes it was signed over. Queue position cannot
    /// do it: a store's info and a listing can be outstanding at once --
    /// publishing a store signs its info, and the seller can start a listing
    /// right after -- and nothing guarantees the two delegate round-trips
    /// finish in the order they began.
    ///
    /// Answer the *second* request first. Under position-matching the store
    /// info would swallow the listing's signature and both records would go
    /// out carrying a signature that does not cover them.
    #[test]
    fn an_answer_goes_to_the_request_whose_bytes_it_carries() {
        let mut state = AppState::default();
        let listing = pending_listing();
        state.pending_signatures.push_back(pending_store_info());
        state.pending_signatures.push_back(listing.clone());

        state.on_ghostkey_response(sign_result_for(&listing));

        assert_eq!(
            state.signed_listings_ready.len(),
            1,
            "the listing's own answer must reach the listing"
        );
        assert_eq!(state.signed_listings_ready[0].listing.title, "Beans");
        assert_eq!(
            state.pending_signatures.len(),
            1,
            "the store info is still waiting for its own answer"
        );
        assert!(matches!(
            state.pending_signatures.front(),
            Some(PendingSignature::StoreInfo(_))
        ));
    }

    /// And the signature it carries has to be the one attached: the scoped
    /// payload is what the store contract re-encodes and compares against, so
    /// pairing it with the wrong record produces something no verifier
    /// accepts.
    #[test]
    fn the_signature_attached_is_the_one_that_was_answered() {
        let mut state = AppState::default();
        let listing = pending_listing();
        state.pending_signatures.push_back(listing.clone());

        state.on_ghostkey_response(sign_result_for(&listing));

        let signed = state
            .signed_listings_ready
            .first()
            .expect("a signed listing");
        assert_eq!(
            signed.scoped_payload,
            harvest_common::to_cbor(&ghostkey_common::ScopedPayload {
                requestor: harvest_common::expected_harvest_requestor(),
                payload: listing.signed_bytes().expect("signed bytes"),
            })
            .expect("serialize"),
            "the scoped payload must wrap this listing's own bytes"
        );
    }

    /// An answer with nothing queued must be dropped, not applied to
    /// whatever is queued next.
    #[test]
    fn a_signature_with_nothing_waiting_is_dropped() {
        let mut state = AppState::default();
        state.on_ghostkey_response(sign_result());
        assert!(state.signed_listings_ready.is_empty());
    }

    /// An answer that matches nothing outstanding is dropped rather than
    /// spent on whatever happens to be queued. Those bytes cannot verify
    /// against any record we hold, so applying them would publish something
    /// the contract rejects -- and would consume a request that is still
    /// legitimately waiting for its own answer.
    #[test]
    fn an_unrecognised_signature_does_not_consume_a_queued_request() {
        let mut state = AppState::default();
        state.pending_signatures.push_back(pending_listing());

        state.on_ghostkey_response(sign_result());

        assert!(
            state.signed_listings_ready.is_empty(),
            "nothing should have been signed"
        );
        assert_eq!(
            state.pending_signatures.len(),
            1,
            "the queued listing must still be waiting for its own answer"
        );
    }

    fn pending_creation() -> PendingStoreCreation {
        PendingStoreCreation {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            seller_verifying_key_bytes: [7u8; 32],
            certificate_pem: String::new(),
            store_name: "Bean Shop".to_string(),
            description: String::new(),
            payment_instructions: String::new(),
            rsa_public_key_der: None,
            encryption_public_key: None,
        }
    }

    fn rsa_keys_initialized(fingerprint: &str) -> HarvestDelegateResponse {
        HarvestDelegateResponse::ReputationKeysInitialized {
            ghostkey_fingerprint: fingerprint.to_string(),
            rsa_public_key_der: vec![9u8; 8],
        }
    }

    fn certificate(fingerprint: &str) -> ghostkey_common::GhostkeyResponse {
        ghostkey_common::GhostkeyResponse::Certificate {
            fingerprint: fingerprint.to_string(),
            certificate_pem: "-----BEGIN CERT-----".to_string(),
        }
    }

    /// A seller who has asked to create a store, with neither delegate
    /// answer in yet.
    fn state_awaiting_creation() -> AppState {
        AppState {
            pending_store_creation: Some(pending_creation()),
            ..AppState::default()
        }
    }

    /// The race this exists to close. `initiate_store_creation` asks the
    /// ghostkey delegate for the certificate and the harvest delegate for the
    /// RSA key at the same time, and they answer independently. The RSA
    /// answer used to take the pending creation and publish immediately, so a
    /// certificate arriving second was written into a slot that was already
    /// empty and thrown away -- and the store went onto the network with no
    /// certificate for a buyer to check the seller against.
    ///
    /// The RSA answer must therefore leave the creation waiting.
    #[test]
    fn the_rsa_key_alone_does_not_start_store_creation() {
        let mut state = state_awaiting_creation();

        state.on_delegate_response(rsa_keys_initialized(FINGERPRINT));

        let pending = state
            .pending_store_creation
            .as_ref()
            .expect("creation must wait for the certificate, not publish without it");
        assert!(pending.certificate_pem.is_empty());
        assert!(pending.rsa_public_key_der.is_some(), "the key was recorded");
    }

    /// The certificate landing second completes the inputs and releases the
    /// creation -- carrying the certificate with it, which is the whole point.
    #[test]
    fn the_certificate_arriving_second_is_not_lost() {
        let mut state = state_awaiting_creation();

        state.on_delegate_response(rsa_keys_initialized(FINGERPRINT));
        assert!(state.pending_store_creation.is_some());

        state.on_ghostkey_response(certificate(FINGERPRINT));

        assert!(
            state.pending_store_creation.is_none(),
            "both inputs are present, so creation must have started"
        );
    }

    /// And the other order works too: neither response is privileged, so
    /// whichever lands second is the one that releases the creation.
    #[test]
    fn the_rsa_key_arriving_second_is_not_lost() {
        let mut state = state_awaiting_creation();

        state.on_ghostkey_response(certificate(FINGERPRINT));
        let pending = state
            .pending_store_creation
            .as_ref()
            .expect("creation must wait for the RSA key");
        assert!(!pending.certificate_pem.is_empty(), "the cert was recorded");

        state.on_delegate_response(rsa_keys_initialized(FINGERPRINT));
        assert!(state.pending_store_creation.is_none());
    }

    /// Both answers name a fingerprint, and an answer for a different
    /// identity must not complete this creation's inputs.
    #[test]
    fn another_identitys_answers_do_not_start_this_creation() {
        let mut state = state_awaiting_creation();

        state.on_delegate_response(rsa_keys_initialized("someone-else"));
        state.on_ghostkey_response(certificate("someone-else"));

        let pending = state
            .pending_store_creation
            .as_ref()
            .expect("this creation is still waiting on its own answers");
        assert!(pending.certificate_pem.is_empty());
        assert!(pending.rsa_public_key_der.is_none());
    }

    const STORE_ID: [u8; 32] = [1u8; 32];
    /// `registration(1, ..)` files the store's reputation contract under this.
    const REPUTATION_ID: [u8; 32] = [2u8; 32];

    fn published_info(version: u32, name: &str, reputation_contract_id: [u8; 32]) -> StoreInfoV1 {
        StoreInfoV1 {
            version,
            certificate_pem: String::new(),
            seller_fingerprint: FINGERPRINT.to_string(),
            reputation_contract_id,
            store_name: name.to_string(),
            description: String::new(),
            payment_instructions: String::new(),
            encryption_public_key: None,
        }
    }

    /// A seller who owns one store, optionally with published details.
    fn seller_with_store(published: Option<StoreInfoV1>) -> AppState {
        let mut state = AppState {
            my_stores: HashMap::from([(FINGERPRINT.to_string(), vec![registration(1, None)])]),
            ..AppState::default()
        };
        if let Some(info) = published {
            state
                .browsing_stores
                .entry(STORE_ID.to_vec())
                .or_default()
                .info = Some(info);
        }
        state
    }

    fn typed_details() -> StoreDetails {
        StoreDetails {
            store_name: "Bean Shop".to_string(),
            description: "Coffee".to_string(),
            payment_instructions: "BTC: bc1q...".to_string(),
        }
    }

    /// The store info queued for signing, if any.
    fn queued_store_info(state: &AppState) -> Option<&StoreInfoV1> {
        state
            .pending_signatures
            .iter()
            .find_map(|pending| match pending {
                PendingSignature::StoreInfo(store_info) => Some(&store_info.info),
                PendingSignature::Listing(_) | PendingSignature::Order(_) => None,
            })
    }

    /// Version 0 is the uninitialized state: nothing was ever signed or
    /// published, so the store has no name and no reputation link. This is
    /// every store created before details were published at all, and every
    /// store left behind by a creation interrupted before its signed update.
    #[test]
    fn a_store_at_version_zero_needs_publishing() {
        assert_eq!(
            store_details_gap(Some(&published_info(0, "", [0u8; 32])), false),
            Some(StoreDetailsGap::NeverPublished)
        );
    }

    #[test]
    fn a_published_store_without_a_name_needs_repair() {
        assert_eq!(
            store_details_gap(Some(&published_info(1, "   ", REPUTATION_ID)), false),
            Some(StoreDetailsGap::NoName)
        );
    }

    /// The half nobody would notice. A store can carry a perfectly good name
    /// and still name no reputation contract, which leaves the seller's
    /// feedback history unreachable from it.
    #[test]
    fn a_published_store_without_a_reputation_link_needs_repair() {
        assert_eq!(
            store_details_gap(Some(&published_info(1, "Bean Shop", [0u8; 32])), false),
            Some(StoreDetailsGap::NoReputationLink)
        );
    }

    /// Nothing to repair means no prompt, which is what keeps this from
    /// nagging -- or republishing -- a store that is already fine.
    #[test]
    fn a_healthy_store_needs_nothing() {
        assert_eq!(
            store_details_gap(Some(&published_info(1, "Bean Shop", REPUTATION_ID)), false),
            None
        );
    }

    /// A store with no published encryption key is a store no buyer can
    /// message, and the seller has no other way to find that out: nothing in
    /// the publishing path fails, and the notice appears only on the BUYER's
    /// side of the storefront.
    #[test]
    fn a_published_store_without_an_encryption_key_needs_repair() {
        assert_eq!(
            store_details_gap(Some(&published_info(1, "Bean Shop", REPUTATION_ID)), true),
            Some(StoreDetailsGap::NoEncryptionKey)
        );
    }

    /// ...but only when there is a key to publish. Prompting a seller whose
    /// delegate has produced nothing would name a repair that publishing does
    /// not perform, and the prompt would never clear.
    #[test]
    fn no_key_to_publish_means_no_prompt_to_publish_one() {
        assert_eq!(
            store_details_gap(Some(&published_info(1, "Bean Shop", REPUTATION_ID)), false),
            None
        );
    }

    /// A store that already publishes one needs nothing.
    #[test]
    fn a_store_that_already_publishes_a_key_needs_nothing() {
        let mut info = published_info(1, "Bean Shop", REPUTATION_ID);
        info.encryption_public_key = Some([8u8; 32]);
        assert_eq!(store_details_gap(Some(&info), true), None);
    }

    /// A store whose state has not arrived yet is not a store with a gap.
    /// Reporting one here would flash the repair prompt on every load.
    #[test]
    fn a_store_that_has_not_loaded_yet_needs_nothing() {
        assert_eq!(store_details_gap(None, true), None);
    }

    /// The reputation contract id must come from the seller's own
    /// registration, not from the store's published state -- that field is
    /// all-zero in exactly the case being repaired, so copying it forward
    /// would publish a store that still points buyers at nothing.
    #[test]
    fn repairing_a_store_restores_the_reputation_link() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "-----BEGIN CERT-----".to_string());

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        let info = queued_store_info(&state).expect("details queued for signing");
        assert_eq!(
            info.reputation_contract_id, REPUTATION_ID,
            "the reputation link must come from the registration, not the empty published state"
        );
        assert_ne!(info.reputation_contract_id, [0u8; 32]);
    }

    /// The rest of the repaired record: the seller's own text, the identity
    /// fields a buyer needs, and a version past the one the contract skips
    /// verifying.
    #[test]
    fn repairing_a_store_publishes_what_the_seller_typed() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "-----BEGIN CERT-----".to_string());

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        let info = queued_store_info(&state).expect("details queued for signing");
        assert_eq!(info.version, 1, "version 0 is the unverified state");
        assert_eq!(info.store_name, "Bean Shop");
        assert_eq!(info.description, "Coffee");
        assert_eq!(info.payment_instructions, "BTC: bc1q...");
        assert_eq!(info.seller_fingerprint, FINGERPRINT);
        assert_eq!(info.certificate_pem, "-----BEGIN CERT-----");
    }

    /// Editing a store that is already published has to win the contract's
    /// last-writer-wins merge, so it lands one past whatever is there.
    #[test]
    fn editing_a_published_store_moves_past_its_current_version() {
        let mut state = seller_with_store(Some(published_info(3, "Old Name", REPUTATION_ID)));
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "cert".to_string());

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        let info = queued_store_info(&state).expect("details queued for signing");
        assert_eq!(info.version, 4);
        assert_eq!(info.store_name, "Bean Shop");
    }

    /// "No local state" has two causes and they need opposite answers, which
    /// is what the version this publishes at depends on.
    ///
    /// This is the benign one: the GET for the store ran out of time, so
    /// nothing is published at that address and version 1 is right. A store
    /// stranded mid-creation is the case that reaches it.
    #[test]
    fn a_store_confirmed_to_have_nothing_published_publishes_at_version_one() {
        let mut state = seller_with_store(None);
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "cert".to_string());
        assert!(state.note_store_state_unavailable(&STORE_ID));

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        assert_eq!(
            queued_store_info(&state).expect("queued").version,
            1,
            "nothing published means the next version is the first one"
        );
    }

    /// And this is the broken one, which the old test could not tell apart
    /// from the case above: state that simply has not arrived yet.
    ///
    /// After a reload `my_stores` fills from the local delegate immediately
    /// while store state comes over the network, so the seller saw a form of
    /// empty strings, retyped their details, and published at version 1 --
    /// which `StoreInfoV1::apply_delta` drops as stale with `return Ok(())`
    /// while the UI reported success. Retrying recomputed 1 and lost again.
    /// Refusing is the only honest answer: we do not know what to publish
    /// past.
    #[test]
    fn an_edit_before_the_store_state_arrives_is_refused_rather_than_guessed() {
        let mut state = seller_with_store(None);
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "cert".to_string());

        let error = state
            .publish_store_details(&STORE_ID, typed_details())
            .expect_err("the version is not knowable yet");

        assert!(
            error.contains("haven't loaded yet"),
            "the seller has to be told what to do about it, got: {error}"
        );
        assert!(
            queued_store_info(&state).is_none(),
            "nothing may be queued for signing at a guessed version"
        );
        assert!(
            state.pending_store_edit.is_none(),
            "and nothing may be left waiting on a certificate either"
        );
    }

    // --- certificate verdicts ------------------------------------------
    //
    // `crate::ghostkey_cert` owns whether a certificate is good; these check
    // only that the verdict is REACHED, on the right bytes, before anything
    // can be displayed. A `Verified` outcome cannot be produced here at all:
    // it needs a certificate Freenet's master key actually signed, and
    // minting one is exactly what nobody can do. So the store-level tests
    // work in the failing direction, and `unverified_listings` -- which takes
    // the store's verdict as an argument -- is exercised in both.

    fn store_state_with(
        certificate_pem: &str,
        listings: Vec<AuthorizedListing>,
    ) -> harvest_common::store::StoreStateV1 {
        harvest_common::store::StoreStateV1 {
            info: harvest_common::store::AuthorizedStoreInfoV1 {
                info: StoreInfoV1 {
                    certificate_pem: certificate_pem.to_string(),
                    ..published_info(4, "Bean Shop", REPUTATION_ID)
                },
                ..Default::default()
            },
            listings: harvest_common::store::ListingsV1 { listings },
            ..Default::default()
        }
    }

    fn listing_with(id: u8, certificate_pem: &str) -> AuthorizedListing {
        AuthorizedListing {
            listing: harvest_common::listing::Listing {
                id: harvest_common::listing::ListingId([id; 32]),
                title: "Beans".to_string(),
                description: String::new(),
                kind: harvest_common::listing::ListingKind::Sale,
                price: None,
                created_at: chrono::Utc::now(),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            certificate_pem: certificate_pem.to_string(),
        }
    }

    fn ingest(state: &mut AppState, store_state: &harvest_common::store::StoreStateV1) {
        state.on_contract_state(
            STORE_ID.to_vec(),
            harvest_common::to_cbor(store_state).expect("store state encodes"),
        );
    }

    /// The wiring this exists for. Before it, a store's `certificate_pem` was
    /// carried to the storefront and displayed without anything ever having
    /// looked at it.
    #[test]
    fn an_ingested_store_carries_a_verdict_about_its_certificate() {
        let mut state = AppState::default();
        ingest(
            &mut state,
            &store_state_with("-----BEGIN CERT-----", vec![]),
        );

        let store = state
            .browsing_stores
            .get(STORE_ID.as_slice())
            .expect("the store was ingested");
        assert!(
            matches!(
                store.certificate_status,
                crate::ghostkey_cert::CertificateStatus::Invalid(_)
            ),
            "a certificate that is not a certificate must be marked, got {:?}",
            store.certificate_status
        );
    }

    /// Absent is its own outcome, not a failure. A store that has published
    /// nothing is not claiming a bond it does not have.
    #[test]
    fn an_ingested_store_with_no_certificate_is_absent_rather_than_invalid() {
        let mut state = AppState::default();
        ingest(&mut state, &store_state_with("", vec![]));

        assert_eq!(
            state
                .browsing_stores
                .get(STORE_ID.as_slice())
                .expect("the store was ingested")
                .certificate_status,
            crate::ghostkey_cert::CertificateStatus::Absent
        );
    }

    /// Listings are verified against the store, not taken on trust from it.
    #[test]
    fn an_ingested_stores_listings_are_each_given_a_verdict() {
        let mut state = AppState::default();
        ingest(
            &mut state,
            &store_state_with(
                "-----BEGIN CERT-----",
                vec![listing_with(1, "-----BEGIN CERT-----"), listing_with(2, "")],
            ),
        );

        let store = state
            .browsing_stores
            .get(STORE_ID.as_slice())
            .expect("the store was ingested");
        assert_eq!(
            store.unverified_listings.len(),
            2,
            "neither listing carries a certificate that verifies"
        );
    }

    /// The fast path: a listing carrying the store's own certificate inherits
    /// the store's verdict rather than being re-verified. It is only sound
    /// because the verdict is a pure function of the bytes and the contract
    /// id, so this pins both directions -- a matching certificate rides the
    /// store's `Verified`, a different one does not.
    #[test]
    fn a_listing_reusing_the_stores_certificate_inherits_its_verdict() {
        let sellers = "-----BEGIN SELLER CERT-----";
        let strangers = "-----BEGIN STRANGER CERT-----";
        let listings = vec![listing_with(1, sellers), listing_with(2, strangers)];

        let marked = unverified_listings(
            &listings,
            &STORE_ID,
            sellers,
            &crate::ghostkey_cert::CertificateStatus::Verified,
        );

        assert!(
            !marked.contains(&harvest_common::listing::ListingId([1u8; 32])),
            "a listing carrying the store's own verified certificate is verified"
        );
        assert!(
            marked.contains(&harvest_common::listing::ListingId([2u8; 32])),
            "a listing carrying somebody else's certificate is not"
        );
    }

    /// And when the store's own certificate failed, nothing under it can
    /// inherit a pass.
    #[test]
    fn listings_inherit_a_failed_store_certificate_too() {
        let sellers = "-----BEGIN SELLER CERT-----";
        let listings = vec![listing_with(1, sellers)];

        let marked = unverified_listings(
            &listings,
            &STORE_ID,
            sellers,
            &crate::ghostkey_cert::CertificateStatus::Invalid("nope".to_string()),
        );

        assert!(marked.contains(&harvest_common::listing::ListingId([1u8; 32])));
    }

    /// State arriving after the deadline fired wins. Treating a store that
    /// is genuinely there as empty is exactly the failure the refusal above
    /// exists to prevent, so a late answer has to undo the conclusion.
    #[test]
    fn state_arriving_late_overrides_the_deadline_that_gave_up_on_it() {
        let mut state = seller_with_store(None);
        state.note_store_state_unavailable(&STORE_ID);
        assert!(state.store_details_are_resolved(&STORE_ID));

        // The real arrival path, not a hand-set field: whatever the deadline
        // concluded has to be undone by the state actually landing.
        let store_state = harvest_common::store::StoreStateV1 {
            info: harvest_common::store::AuthorizedStoreInfoV1 {
                info: published_info(4, "Bean Shop", REPUTATION_ID),
                ..Default::default()
            },
            ..Default::default()
        };
        state.on_contract_state(
            STORE_ID.to_vec(),
            harvest_common::to_cbor(&store_state).expect("store state encodes"),
        );
        assert!(
            !state.store_state_unavailable.contains(STORE_ID.as_slice()),
            "state that arrived has to clear the deadline's conclusion"
        );
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "cert".to_string());

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        assert_eq!(
            queued_store_info(&state).expect("queued").version,
            5,
            "the version has to come from the state that actually arrived"
        );
    }

    /// A store whose state has not arrived offers no edit form at all, so
    /// the seller never sees empty fields that look like lost details.
    #[test]
    fn a_store_is_not_editable_until_we_know_what_it_published() {
        let mut state = seller_with_store(None);
        assert!(!state.store_details_are_resolved(&STORE_ID));

        state.note_store_state_unavailable(&STORE_ID);
        assert!(state.store_details_are_resolved(&STORE_ID));

        let mut arrived = seller_with_store(Some(published_info(1, "Bean Shop", REPUTATION_ID)));
        assert!(arrived.store_details_are_resolved(&STORE_ID));
        assert!(
            !arrived.note_store_state_unavailable(&STORE_ID),
            "a deadline must not overrule state that already arrived"
        );
    }

    /// Local state only catches up when the update round-trips, so a second
    /// edit submitted before that would recompute the same version and lose
    /// to the first -- the same silent-discard shape, reachable by an
    /// impatient double-click.
    #[test]
    fn a_second_edit_lands_past_the_first_rather_than_tying_with_it() {
        let mut state = seller_with_store(Some(published_info(3, "Old Name", REPUTATION_ID)));
        state
            .certificates
            .insert(FINGERPRINT.to_string(), "cert".to_string());

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");
        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        let versions: Vec<u32> = state
            .pending_signatures
            .iter()
            .filter_map(|pending| match pending {
                PendingSignature::StoreInfo(info) => Some(info.info.version),
                PendingSignature::Listing(_) | PendingSignature::Order(_) => None,
            })
            .collect();
        assert_eq!(
            versions,
            vec![4, 5],
            "the second edit has to be past the first, not tied with it"
        );
    }

    /// The certificate travels inside the signed record, so it has to be
    /// known before signing. Without it the edit waits rather than
    /// publishing a record with no trust chain -- the same failure the
    /// creation gate exists to prevent.
    #[test]
    fn an_edit_waits_for_the_certificate() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));

        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");

        assert!(
            state.pending_signatures.is_empty(),
            "nothing may be signed before the certificate is known"
        );
        assert!(state.pending_store_edit.is_some(), "the edit is waiting");

        state.on_ghostkey_response(certificate(FINGERPRINT));

        assert!(state.pending_store_edit.is_none(), "the edit went ahead");
        let info = queued_store_info(&state).expect("details queued for signing");
        assert_eq!(info.certificate_pem, "-----BEGIN CERT-----");
        assert_eq!(info.reputation_contract_id, REPUTATION_ID);
    }

    /// `my_stores` is the only source of the owning fingerprint and of the
    /// reputation contract id, so a store that is not in it cannot be
    /// published to at all -- which is also what stops this firing for a
    /// store the user is merely browsing.
    #[test]
    fn details_cannot_be_published_for_a_store_the_user_does_not_own() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));

        let err = state
            .publish_store_details(&[9u8; 32], typed_details())
            .expect_err("a browsed store is not the seller's to publish");

        assert!(err.contains("not one of yours"), "unhelpful error: {err}");
        assert!(state.pending_store_edit.is_none());
        assert!(state.pending_signatures.is_empty());
    }

    /// An edit waiting on a certificate that will never arrive must not sit
    /// there unfinished and unmentioned.
    #[test]
    fn a_denied_prompt_clears_a_waiting_edit() {
        let mut state = seller_with_store(Some(published_info(0, "", [0u8; 32])));
        state.harvest_delegate_key = Some(delegate_key(0xA1));
        state.ghostkey_delegate_key = Some(delegate_key(0xB2));
        state
            .publish_store_details(&STORE_ID, typed_details())
            .expect("the seller owns this store");
        assert!(state.pending_store_edit.is_some());

        from_ghostkey(
            &mut state,
            &ghostkey_common::GhostkeyResponse::AccessDenied {
                requestor: harvest_common::expected_harvest_requestor(),
            },
        );

        assert!(state.pending_store_edit.is_none());
    }

    // -----------------------------------------------------------------
    // Delegate routing
    //
    // These go through `gateway::response_handler`'s real router rather than
    // calling `on_ghostkey_response` directly. Calling it directly is what
    // made the original version of `a_denied_prompt_clears_the_whole_queue`
    // green and vacuous: the handler was correct and unreachable, because the
    // router classified every ghostkey error as a Harvest one by trial CBOR
    // decode. A test that skips the router cannot see that.
    // -----------------------------------------------------------------

    fn delegate_key(seed: u8) -> freenet_stdlib::prelude::DelegateKey {
        freenet_stdlib::prelude::DelegateKey::new(
            [seed; 32],
            freenet_stdlib::prelude::CodeHash::new([seed; 32]),
        )
    }

    /// An `AppState` that knows both delegate keys, as it does once the app
    /// has finished registering them.
    fn state_with_delegates() -> AppState {
        AppState {
            harvest_delegate_key: Some(delegate_key(0xA1)),
            ghostkey_delegate_key: Some(delegate_key(0xB2)),
            ..AppState::default()
        }
    }

    /// Deliver one CBOR payload as if the gateway had reported it arriving
    /// from `from`, through the same code path the live app uses.
    fn deliver(state: &mut AppState, from: &freenet_stdlib::prelude::DelegateKey, payload: &[u8]) {
        use crate::gateway::response_handler::{
            apply_delegate_response, decode_delegate_message, delegate_sender,
        };
        let sender = delegate_sender(
            from,
            state.harvest_delegate_key.as_ref(),
            state.ghostkey_delegate_key.as_ref(),
        );
        match decode_delegate_message(sender, payload) {
            Ok(response) => apply_delegate_response(state, response),
            Err(e) => panic!("the router rejected a well-formed payload: {e}"),
        }
    }

    fn from_ghostkey(state: &mut AppState, response: &ghostkey_common::GhostkeyResponse) {
        let payload = harvest_common::to_cbor(response).expect("a response must serialize");
        deliver(state, &delegate_key(0xB2), &payload);
    }

    /// A delegate error or a denied prompt invalidates everything queued --
    /// none of it will ever be answered, and a leftover entry would consume
    /// the next unrelated signature.
    #[test]
    fn a_denied_prompt_clears_the_whole_queue() {
        let mut state = state_with_delegates();
        state.pending_signatures.push_back(pending_store_info());
        state.pending_signatures.push_back(pending_listing());

        from_ghostkey(
            &mut state,
            &ghostkey_common::GhostkeyResponse::Error {
                message: "nope".to_string(),
            },
        );
        assert!(state.pending_signatures.is_empty());
    }

    /// The bug this routing exists to prevent, stated as a property.
    ///
    /// `HarvestDelegateResponse::Error { message: String }` and
    /// `GhostkeyResponse::Error { message: String }` are byte-identical CBOR,
    /// so nothing about the payload can tell them apart. Only the key can.
    #[test]
    fn an_error_is_attributed_to_the_delegate_that_sent_it_not_to_its_shape() {
        use crate::gateway::response_handler::{
            decode_delegate_message, delegate_sender, DelegateResponse, DelegateSender,
        };

        let harvest = delegate_key(0xA1);
        let ghostkey = delegate_key(0xB2);
        let gk_error = ghostkey_common::GhostkeyResponse::Error {
            message: "vault said no".to_string(),
        };
        let hv_error = HarvestDelegateResponse::Error {
            message: "vault said no".to_string(),
        };

        let gk_bytes = harvest_common::to_cbor(&gk_error).unwrap();
        let hv_bytes = harvest_common::to_cbor(&hv_error).unwrap();
        assert_eq!(
            gk_bytes, hv_bytes,
            "the two error payloads must be indistinguishable -- if they ever \
             stop being, this test is no longer testing anything"
        );

        assert_eq!(
            delegate_sender(&ghostkey, Some(&harvest), Some(&ghostkey)),
            DelegateSender::Ghostkey
        );
        assert!(matches!(
            decode_delegate_message(DelegateSender::Ghostkey, &gk_bytes),
            Ok(DelegateResponse::Ghostkey(_))
        ));
        assert!(matches!(
            decode_delegate_message(DelegateSender::Harvest, &hv_bytes),
            Ok(DelegateResponse::Harvest(_))
        ));
    }

    /// The harvest delegate speaks two response enums over ONE key, so those
    /// two are still separated by a trial decode -- and that only works while
    /// no payload decodes as both.
    ///
    /// The messaging responses are the first variants added to that enum
    /// since the rule was written down. This checks them against it rather
    /// than trusting the comment, because the failure is silent: a
    /// `ConversationKeys` misread as a Bitcoin response would go to
    /// `on_bitcoin_delegate_response`, do nothing, and leave the seller's
    /// mailbox unreadable with no error anywhere.
    #[test]
    fn the_messaging_responses_are_not_mistakable_for_bitcoin_ones() {
        use crate::gateway::response_handler::{
            decode_delegate_message, DelegateResponse, DelegateSender,
        };

        for response in [
            HarvestDelegateResponse::EncryptionKeyReady {
                ghostkey_fingerprint: "fp".to_string(),
                x25519_public_key: vec![1u8; 32],
            },
            HarvestDelegateResponse::ConversationKeys {
                request_id: 1,
                ghostkey_fingerprint: "fp".to_string(),
                result: Ok(vec![harvest_common::ConversationKey {
                    peer_public_key: vec![2u8; 32],
                    buyer_to_seller: [3u8; 32],
                    seller_to_buyer: [4u8; 32],
                }]),
            },
            HarvestDelegateResponse::ConversationKeys {
                request_id: 2,
                ghostkey_fingerprint: "fp".to_string(),
                result: Err("nope".to_string()),
            },
        ] {
            let bytes = harvest_common::to_cbor(&response).unwrap();
            assert!(
                matches!(
                    decode_delegate_message(DelegateSender::Harvest, &bytes),
                    Ok(DelegateResponse::Harvest(_))
                ),
                "a messaging response must decode as a harvest one: {response:?}"
            );
            assert!(
                harvest_common::from_cbor::<harvest_common::BitcoinDelegateResponse>(&bytes)
                    .is_err(),
                "a messaging response also decoded as a Bitcoin one, so the trial decode \
                 that separates them is no longer sound: {response:?}"
            );
        }
    }

    /// A key belonging to neither delegate is not guessed at. Guessing is
    /// what produced the misrouting in the first place.
    #[test]
    fn a_message_from_an_unregistered_delegate_is_not_decoded() {
        use crate::gateway::response_handler::{
            decode_delegate_message, delegate_sender, DelegateSender,
        };

        let harvest = delegate_key(0xA1);
        let ghostkey = delegate_key(0xB2);
        let stranger = delegate_key(0xFF);
        assert_eq!(
            delegate_sender(&stranger, Some(&harvest), Some(&ghostkey)),
            DelegateSender::Unknown
        );

        let payload = harvest_common::to_cbor(&HarvestDelegateResponse::Error {
            message: "x".to_string(),
        })
        .unwrap();
        assert!(decode_delegate_message(DelegateSender::Unknown, &payload).is_err());
    }

    /// `start_store_creation_if_ready` waits for the certificate rather than
    /// publishing a store without one, which is only safe because every
    /// response meaning "no certificate is coming" clears the pending
    /// creation. A ghostkey `Error` is one of those, and it has to survive
    /// The follow-up work in the `GhostKeyList` arm must never be able to
    /// strand the "Waiting for vault..." button.
    ///
    /// On 2026-09-06 the flag was cleared as the LAST statement of that arm,
    /// and the follow-up above it panicked -- `AlreadyBorrowedMut`, because the
    /// arm runs inside `apply_delegate_response(&mut APP_STATE.write(), ..)`
    /// and the migration code it called took another borrow. Under
    /// `panic = "abort"` the trap killed the rest of the handler, so the flag
    /// stayed true and the user was told the vault had not answered when it
    /// had, for a request that had completed.
    ///
    /// Two orderings are pinned, and both matter:
    ///
    /// 1. the flag is cleared BEFORE the spawned follow-up, so nothing that
    ///    happens later can strand it;
    /// 2. the follow-up is spawned at all, rather than called inline -- calling
    ///    it inline is what re-enters the borrow.
    ///
    /// Pinned by reading the source because the invariant is an ORDERING, and
    /// reproducing the failure needs a held write guard plus a wasm-only call
    /// chain, neither of which exists on the host. A behavioural test here
    /// would pass just as happily under the bug, which is the trap this repo
    /// keeps walking into.
    #[test]
    fn the_vault_flag_is_cleared_before_any_follow_up_work() {
        let source = include_str!("state.rs");
        let arm = source
            .split("GhostkeyResponse::GhostKeyList { keys } => {")
            .nth(1)
            .expect("the GhostKeyList arm must still exist");

        let clear = arm
            .find("self.request_any_access_in_flight = false;")
            .expect("the GhostKeyList arm must clear the in-flight flag");
        let spawn = arm.find("spawn_local").expect(
            "the follow-up work must be SPAWNED, not called inline: \
                    calling it inline re-enters the APP_STATE write borrow this \
                    arm already holds",
        );

        assert!(
            clear < spawn,
            "request_any_access_in_flight must be cleared BEFORE the spawned \
             follow-up work. Cleared at {clear}, spawn at {spawn}. With the \
             clear afterwards, any failure in the follow-up leaves the UI \
             reading \"Waiting for vault...\" for a request that succeeded."
        );

        // Scoped to the code AFTER the spawn, not the whole arm: the
        // explanatory comment above names `list_stores` too, and matching that
        // made an earlier version of this assertion fail for the wrong reason.
        let task = &arm[spawn..];
        assert!(
            task.contains("list_stores("),
            "the follow-up work must still happen, inside the spawned task"
        );
        assert!(
            task.contains("start_reputation_migration("),
            "start_reputation_migration must run from the SPAWNED task: calling \
             it inline is the exact re-entrant read that panicked, and under \
             panic=abort that leaks the APP_STATE write guard permanently"
        );
    }

    /// the trip through the router to do its job.
    #[test]
    fn a_ghostkey_error_clears_a_waiting_store_creation() {
        let mut state = state_with_delegates();
        state.pending_store_creation = Some(PendingStoreCreation {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            seller_verifying_key_bytes: [3u8; 32],
            certificate_pem: String::new(),
            store_name: "Bean Shop".to_string(),
            description: String::new(),
            payment_instructions: String::new(),
            rsa_public_key_der: None,
            encryption_public_key: None,
        });

        from_ghostkey(
            &mut state,
            &ghostkey_common::GhostkeyResponse::Error {
                message: "no access".to_string(),
            },
        );

        assert!(
            state.pending_store_creation.is_none(),
            "a creation waiting on a certificate that will never arrive must not sit there"
        );
        assert!(
            !state.notifications.is_empty(),
            "and the seller has to be told"
        );
    }

    /// `KeyNotFound` is a flat "there is no such key" -- terminal for a
    /// waiting `GetCertificate`. It used to fall into the wildcard arm, which
    /// logs and clears nothing.
    #[test]
    fn key_not_found_clears_a_waiting_store_creation() {
        let mut state = state_with_delegates();
        state.pending_store_creation = Some(PendingStoreCreation {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            seller_verifying_key_bytes: [3u8; 32],
            certificate_pem: String::new(),
            store_name: "Bean Shop".to_string(),
            description: String::new(),
            payment_instructions: String::new(),
            rsa_public_key_der: None,
            encryption_public_key: None,
        });
        state.pending_signatures.push_back(pending_store_info());
        state.request_any_access_in_flight = true;

        from_ghostkey(
            &mut state,
            &ghostkey_common::GhostkeyResponse::KeyNotFound {
                fingerprint: FINGERPRINT.to_string(),
            },
        );

        assert!(state.pending_store_creation.is_none());
        assert!(state.pending_signatures.is_empty());
        assert!(!state.request_any_access_in_flight);
        assert!(!state.notifications.is_empty());
    }

    /// A mailbox belongs to one store. Re-pointing the map at a second one
    /// would leave the first store showing a `mailbox_contract_id` that
    /// nothing routes back to it, so its messages would vanish on arrival.
    #[test]
    fn a_mailbox_stays_with_the_first_store_that_claimed_it() {
        let mut state = AppState::default();
        state.register_store_mailbox(&[1u8; 32], &[9u8; 32]);
        state.register_store_mailbox(&[2u8; 32], &[9u8; 32]);

        assert_eq!(state.mailbox_to_store[&vec![9u8; 32]], vec![1u8; 32]);
        assert_eq!(
            state.browsing_stores[&vec![1u8; 32]].mailbox_contract_id,
            Some(vec![9u8; 32])
        );
        assert!(
            !state.browsing_stores.contains_key(&vec![2u8; 32]),
            "the losing store must not be left pointing at a mailbox it does not own"
        );
    }

    /// Re-registering the same pair is the normal case -- every `StoreList`
    /// answer does it -- and must not be reported as a collision.
    #[test]
    fn re_registering_the_same_mailbox_is_not_a_collision() {
        let mut state = AppState::default();
        state.register_store_mailbox(&[1u8; 32], &[9u8; 32]);
        state.register_store_mailbox(&[1u8; 32], &[9u8; 32]);

        assert_eq!(state.mailbox_to_store[&vec![9u8; 32]], vec![1u8; 32]);
        assert_eq!(state.mailbox_to_store.len(), 1);
    }

    /// A link whose store never arrives has to end in a message, not in
    /// "Loading store..." forever. See `note_store_link_failed`.
    #[test]
    fn a_store_that_never_arrives_becomes_an_error() {
        let mut state = AppState::default();
        state.begin_browsing(vec![9u8; 32]);
        assert_eq!(state.store_link_error, None);

        assert!(state.note_store_link_failed(&[9u8; 32], "didn't load"));
        assert_eq!(state.store_link_error.as_deref(), Some("didn't load"));
    }

    /// A store whose state arrived while the timeout was still running is not
    /// a failure, and must not be reported as one.
    #[test]
    fn a_store_that_did_arrive_is_not_reported_as_failed() {
        let mut state = AppState::default();
        state.begin_browsing(vec![9u8; 32]);
        state
            .browsing_stores
            .get_mut(&vec![9u8; 32])
            .expect("begin_browsing creates the entry")
            .info = Some(StoreInfoV1 {
            version: 1,
            certificate_pem: String::new(),
            seller_fingerprint: FINGERPRINT.to_string(),
            reputation_contract_id: [0u8; 32],
            store_name: "Loaded".to_string(),
            description: String::new(),
            payment_instructions: String::new(),
            encryption_public_key: None,
        });

        assert!(!state.note_store_link_failed(&[9u8; 32], "didn't load"));
        assert_eq!(state.store_link_error, None);
    }

    /// Opening another link clears the previous failure, or the error from a
    /// dead link outlives it.
    #[test]
    fn opening_another_link_clears_a_previous_error() {
        let mut state = AppState::default();
        state.begin_browsing(vec![9u8; 32]);
        state.note_store_link_failed(&[9u8; 32], "didn't load");
        state.begin_browsing(vec![10u8; 32]);
        assert_eq!(state.store_link_error, None);
    }

    /// A timeout that fires for a store the user has already navigated away
    /// from must not blame the link they are looking at now.
    #[test]
    fn a_timeout_for_an_abandoned_store_is_ignored() {
        let mut state = AppState::default();
        state.begin_browsing(vec![9u8; 32]);
        state.begin_browsing(vec![10u8; 32]);

        assert!(!state.note_store_link_failed(&[9u8; 32], "didn't load"));
        assert_eq!(state.store_link_error, None);
    }

    /// Every `StoreList` answer names every store, and a ghostkey
    /// reconnecting produces another answer, so the GET+subscribe has to be
    /// deduped the way `register_store_mailbox` already dedupes its own.
    #[test]
    fn a_store_is_only_subscribed_once() {
        let mut state = AppState::default();
        assert!(state.note_store_subscribed(&[1u8; 32]));
        assert!(!state.note_store_subscribed(&[1u8; 32]));
        assert!(state.note_store_subscribed(&[2u8; 32]));

        state.on_delegate_response(store_list(vec![registration(3, None)]));
        state.on_delegate_response(store_list(vec![registration(3, None)]));
        assert_eq!(state.subscribed_stores.len(), 3);
    }

    // -----------------------------------------------------------------
    // What a watch row can honestly say
    // -----------------------------------------------------------------

    /// A watch exactly as `WatchForm` builds one and the delegate stores it.
    fn manual_watch() -> WatchedPayment {
        WatchedPayment {
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, 0xde, 0xad],
            address: "tb1qexample".to_string(),
            label: None,
            order_id: None,
            expected_amount_sats: None,
            contract_id: None,
            added_at_ms: 1_700_000_000_000,
            bridge_synced: false,
            last_error: None,
        }
    }

    /// The bug this replaced: the row said "Waiting for bridge to sync…"
    /// for a watch that nothing had asked a bridge about, and nothing ever
    /// would -- neither the delegate (no outbound HTTP in
    /// `OutboundDelegateMsg`) nor the page (the gateway's CSP limits
    /// `connect-src` to its own gateway). A wait that never ends must not be
    /// described as a wait.
    #[test]
    fn a_watch_nobody_asked_a_bridge_about_says_so() {
        let status = watch_sync_status(&manual_watch());
        assert_eq!(status, WatchSyncStatus::LocalOnly);
        let message = status.message().expect("a dead watch has to say so");
        assert!(
            message.contains("No bridge has been asked"),
            "the row must name the missing step, got: {message}"
        );
        assert!(
            !message.to_lowercase().contains("waiting"),
            "nothing is being waited for, got: {message}"
        );
    }

    /// A bridge that answered and named the address contract carrying the
    /// results is the one case with nothing to warn about.
    #[test]
    fn a_synced_watch_with_an_address_contract_has_nothing_to_report() {
        let watch = WatchedPayment {
            bridge_synced: true,
            contract_id: Some("11111111111111111111111111111111".to_string()),
            ..manual_watch()
        };
        assert_eq!(watch_sync_status(&watch), WatchSyncStatus::Live);
        assert_eq!(watch_sync_status(&watch).message(), None);
    }

    /// `bridge_synced` alone is not enough. The UI reads transactions out of
    /// the address contract, so a watch without one shows nothing however
    /// the bridge answered -- and must not be reported as working.
    #[test]
    fn a_synced_watch_with_no_address_contract_is_not_live() {
        let watch = WatchedPayment {
            bridge_synced: true,
            ..manual_watch()
        };
        assert_eq!(
            watch_sync_status(&watch),
            WatchSyncStatus::SyncedWithoutContract
        );
        assert!(watch_sync_status(&watch).message().is_some());
    }

    /// An error the bridge reported outranks everything else, and arrives
    /// already translated -- the row renders it verbatim.
    #[test]
    fn a_bridge_error_is_reported_in_the_users_terms() {
        let watch = WatchedPayment {
            last_error: Some("not authorized".to_string()),
            ..manual_watch()
        };
        assert_eq!(
            watch_sync_status(&watch),
            WatchSyncStatus::Failed(friendly_bridge_error("not authorized"))
        );
        assert!(watch_sync_status(&watch)
            .message()
            .expect("a failure has to say so")
            .contains("Ghost Key"));
    }
}

/// The seller-issued invoice path: everything from "the seller filled in the
/// form" to "a signed order is on its way to the store contract", minus the
/// two delegate round trips a browser would carry.
#[cfg(test)]
mod invoice_tests {
    use super::*;

    use freenet_bitcoin_common::BitcoinNetwork;
    use harvest_common::listing::ListingId;
    use harvest_common::{DerivedAddress, PaymentXpubStatus};

    const SELLER: &str = "seller-fp";
    const STORE_ID: [u8; 32] = [9u8; 32];

    fn listing_id() -> ListingId {
        ListingId::from_label("Widget")
    }

    fn invoice() -> PendingInvoice {
        PendingInvoice {
            store_contract_id: STORE_ID.to_vec(),
            seller_fingerprint: SELLER.to_string(),
            listing_id: listing_id(),
            listing_title: "Widget".to_string(),
            buyer_fingerprint: "buyer-fp".to_string(),
            reply_to: None,
            order_binding: None,
            amount_sats: 50_000,
            required_confirmations: 1,
        }
    }

    fn derived(index: u32) -> DerivedAddress {
        DerivedAddress {
            index,
            network: BitcoinNetwork::Signet,
            script_pubkey: vec![0x00, 0x14, index as u8],
            address: format!("tb1qexample{index}"),
        }
    }

    /// A block anchor at `height`, whose hash is a function of the height so
    /// two different heights never accidentally share one.
    pub(super) fn anchor(height: u32) -> freenet_bitcoin_common::BlockAnchor {
        let mut hash = [0u8; 32];
        hash[..4].copy_from_slice(&height.to_le_bytes());
        freenet_bitcoin_common::BlockAnchor {
            height,
            hash: freenet_bitcoin_common::BlockHash(hash),
        }
    }

    /// A seller who owns `STORE_ID` and has a payment key configured.
    fn seller_with_a_store() -> AppState {
        let mut state = AppState::default();
        state.my_stores.insert(
            SELLER.to_string(),
            vec![StoreRegistration {
                store_contract_id: STORE_ID.to_vec(),
                reputation_contract_id: vec![10u8; 32],
                mailbox_contract_id: vec![11u8; 32],
                store_contract_key: None,
            }],
        );
        state.bitcoin.payment_xpub = Some(PaymentXpubStatus {
            xpub: "vpub-placeholder".to_string(),
            network: BitcoinNetwork::Signet,
            next_index: 0,
        });
        state.bitcoin.payment_xpub_loaded = true;
        // A seller who cannot see the chain cannot anchor a commitment, and
        // `order_for_invoice` refuses to publish one without. That is
        // deliberate, and pinned by
        // `a_seller_who_cannot_see_the_chain_cannot_issue_an_invoice`; here
        // it is set up so the other tests exercise the ordinary path.
        state
            .bitcoin
            .tips
            .insert(BitcoinNetwork::Signet, tip_at(TIP_HEIGHT));
        state
    }

    /// The height every test in this module treats as the current tip.
    pub(super) const TIP_HEIGHT: u32 = 800_000;

    /// A tip view holding the window this build actually keeps, newest first.
    ///
    /// Sized from [`RECENT_BLOCKS_KEPT`] rather than from a number, so a
    /// change to the freshness tolerance cannot leave these fixtures too
    /// small to observe what they attest -- the case where an anchor inside
    /// the tolerance would fall outside the fixture's window and read as
    /// unknown.
    pub(super) fn tip_at(height: u32) -> TipView {
        TipView {
            network: BitcoinNetwork::Signet,
            tip_height: Some(height),
            signed_tip: None,
            last_block_time: None,
            recent_blocks: (0..RECENT_BLOCKS_KEPT as u32)
                .map(|back| {
                    let at = anchor(height - back);
                    BlockRow {
                        height: at.height,
                        hash: at.hash,
                        tx_count: 1,
                        block_time: 0,
                    }
                })
                .collect(),
        }
    }

    fn address_answer(request_id: u64, index: u32) -> BitcoinDelegateResponse {
        BitcoinDelegateResponse::OrderAddress {
            request_id,
            result: Ok(derived(index)),
        }
    }

    /// A `SignResult` shaped the way the ghostkey delegate answers: the
    /// request's own message, wrapped verbatim as `ScopedPayload::payload`.
    fn sign_result_for(pending: &PendingSignature) -> ghostkey_common::GhostkeyResponse {
        let scoped = ghostkey_common::ScopedPayload {
            requestor: harvest_common::expected_harvest_requestor(),
            payload: pending.signed_bytes().expect("serialize signed message"),
        };
        ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload: harvest_common::to_cbor(&scoped).expect("serialize scoped payload"),
            signature: vec![4, 5, 6],
            certificate_pem: String::new(),
        }
    }

    fn queued_order(state: &AppState) -> harvest_common::payment::Order {
        state
            .pending_signatures
            .iter()
            .find_map(|pending| match pending {
                PendingSignature::Order(order) => Some(order.order.clone()),
                _ => None,
            })
            .expect("an invoice should be queued for signing")
    }

    /// The regression that made the whole payment path unreachable in the
    /// other direction: an invoice naming no bridge can never be proven paid
    /// -- `verify_payment_proof` returns `NoTrustedBridges` -- and nothing
    /// about it looks wrong until a buyer has already sent coin. Every store
    /// the UI created was in exactly that state while the bridge list was a
    /// store parameter.
    #[test]
    fn an_issued_invoice_names_the_bridges_that_can_settle_it() {
        let order = order_for_invoice(
            &invoice(),
            &derived(0),
            Some(anchor(800_000)),
            chrono::Utc::now(),
        )
        .expect("the build's constants must be usable");

        assert!(
            !order.trusted_bridges.is_empty(),
            "an invoice with no trusted bridge can never be proven paid"
        );
        assert_eq!(
            order.trusted_bridges[0].to_bs58(),
            crate::gateway::bitcoin_config::TRUSTED_BRIDGE_ID_BS58
        );
        // The other field that moved onto the order for the same reason. It
        // is optional by design, but the build knows its own value, so an
        // invoice that omits it has silently lost the store contract's
        // related-contract cross-check.
        assert!(
            order.bitcoin_address_code_hash.is_some(),
            "the build knows the address contract's code hash; an invoice should carry it"
        );
    }

    /// **An invoice carries the seller's own view of the chain tip.**
    ///
    /// The anchor is what lets a buyer tell how recently the seller took the
    /// order on. `created_at` cannot do that job: the seller stamps it, and a
    /// seller-chosen timestamp as a freshness source is the mistake this
    /// repository has made and corrected three times.
    #[test]
    fn an_issued_invoice_carries_a_block_anchor() {
        let mut state = seller_with_a_store();
        state.issue_invoice(invoice()).expect("accepted");
        let request_id = *state.pending_invoices.keys().next().expect("one entry");
        state.on_bitcoin_delegate_response(address_answer(request_id, 0));

        let queued = state
            .pending_signatures
            .iter()
            .find_map(|pending| match pending {
                PendingSignature::Order(order) => Some(order.order.clone()),
                _ => None,
            })
            .expect("an invoice should be queued for signing");

        assert_eq!(
            queued.anchor,
            Some(anchor(TIP_HEIGHT)),
            "the invoice must be anchored to the newest block the seller can see"
        );
    }

    /// **A seller who cannot see the chain issues nothing at all.**
    ///
    /// The alternative is worse than it looks: an unanchored invoice is one
    /// every buyer's software refuses (`payment_blockers` answers
    /// `AnchorMissing`), so the seller would be showing somebody a bill that
    /// silently cannot be paid -- the same shape as the bridge-less invoices
    /// that made every early store permanently unable to take money.
    ///
    /// Observed red by making `order_for_invoice` fall back to
    /// `anchor: None` instead of refusing:
    ///
    /// ```text
    /// panicked at ui/src/state.rs:5883:9:
    /// an invoice with no anchor must not reach the signing queue
    /// ```
    #[test]
    fn a_seller_who_cannot_see_the_chain_cannot_issue_an_invoice() {
        let mut state = seller_with_a_store();
        state.bitcoin.tips.clear();
        state.issue_invoice(invoice()).expect("accepted");
        let request_id = *state.pending_invoices.keys().next().expect("one entry");
        state.on_bitcoin_delegate_response(address_answer(request_id, 0));

        assert!(
            state.pending_signatures.is_empty(),
            "an invoice with no anchor must not reach the signing queue"
        );
        let notice = state
            .notifications
            .last()
            .expect("the seller must be told why nothing was issued");
        assert!(
            notice.contains("Bitcoin block"),
            "the notice must name what is missing: {notice}"
        );
    }

    /// The address the delegate derived has to be the one the invoice
    /// actually asks the buyer to pay, in BOTH forms -- verification uses the
    /// script and the buyer reads the address.
    #[test]
    fn an_issued_invoice_carries_the_derived_destination() {
        let derived = derived(3);
        let order = order_for_invoice(
            &invoice(),
            &derived,
            Some(anchor(800_000)),
            chrono::Utc::now(),
        )
        .expect("build");

        assert_eq!(order.payment_script_pubkey, derived.script_pubkey);
        assert_eq!(order.payment_address, derived.address);
        assert_eq!(order.network, derived.network);
    }

    /// Register-before-send, so an answer that arrives the instant the send
    /// returns finds its invoice rather than being dropped.
    #[test]
    fn issuing_an_invoice_registers_it_before_anything_is_sent() {
        let mut state = seller_with_a_store();
        state.issue_invoice(invoice()).expect("should be accepted");

        assert_eq!(state.pending_invoices.len(), 1);
        let request_id = *state.pending_invoices.keys().next().expect("one entry");
        assert!(
            state.bitcoin.in_flight.contains(&request_id),
            "the request should show as in flight"
        );
    }

    /// The correlation that matters. Two invoices can be in flight at once,
    /// and an address grafted onto the wrong one would ask a buyer to pay
    /// against another buyer's order.
    #[test]
    fn an_address_completes_the_invoice_that_asked_for_it() {
        let mut state = seller_with_a_store();

        let mut first = invoice();
        first.amount_sats = 10_000;
        first.buyer_fingerprint = "buyer-one".to_string();
        let mut second = invoice();
        second.amount_sats = 20_000;
        second.buyer_fingerprint = "buyer-two".to_string();

        state.issue_invoice(first).expect("accepted");
        let first_id = *state.pending_invoices.keys().next().expect("one entry");
        state.issue_invoice(second).expect("accepted");
        let second_id = *state
            .pending_invoices
            .keys()
            .find(|id| **id != first_id)
            .expect("two entries");

        // Answer the SECOND one first: `OrderAddress` is matched by its id,
        // not by arrival order, so out-of-order answers are the case that has
        // to work -- and answering the LATER one first is what distinguishes
        // a real lookup from "take whichever invoice is at hand".
        state.on_bitcoin_delegate_response(address_answer(second_id, 5));

        let order = queued_order(&state);
        assert_eq!(order.amount_sats, 20_000);
        assert_eq!(order.buyer_fingerprint, "buyer-two");
        assert_eq!(order.payment_address, derived(5).address);
        assert!(
            state.pending_invoices.contains_key(&first_id),
            "the other invoice must still be waiting for its own address"
        );

        // And the one left behind gets its OWN address, not the leftover.
        state.on_bitcoin_delegate_response(address_answer(first_id, 9));
        let both: Vec<(String, String)> = state
            .pending_signatures
            .iter()
            .filter_map(|pending| match pending {
                PendingSignature::Order(o) => Some((
                    o.order.buyer_fingerprint.clone(),
                    o.order.payment_address.clone(),
                )),
                _ => None,
            })
            .collect();
        assert_eq!(
            both,
            vec![
                ("buyer-two".to_string(), derived(5).address),
                ("buyer-one".to_string(), derived(9).address),
            ],
            "each invoice must carry the address derived for it"
        );
        assert!(state.pending_invoices.is_empty());
    }

    /// An answer for an invoice nobody is waiting on is dropped, not applied
    /// to whatever happens to be pending.
    #[test]
    fn an_unmatched_address_is_dropped() {
        let mut state = seller_with_a_store();
        state.issue_invoice(invoice()).expect("accepted");
        let waiting = *state.pending_invoices.keys().next().expect("one entry");

        state.on_bitcoin_delegate_response(address_answer(waiting + 1000, 0));

        assert!(state.pending_invoices.contains_key(&waiting));
        assert!(
            state.pending_signatures.is_empty(),
            "nothing should have been queued for signing"
        );
    }

    /// A refusal from the delegate clears the invoice rather than leaving the
    /// form looking as though something were still in progress.
    #[test]
    fn a_refused_address_clears_the_invoice() {
        let mut state = seller_with_a_store();
        state.issue_invoice(invoice()).expect("accepted");
        let waiting = *state.pending_invoices.keys().next().expect("one entry");

        state.on_bitcoin_delegate_response(BitcoinDelegateResponse::OrderAddress {
            request_id: waiting,
            result: Err("no payment key is set".to_string()),
        });

        assert!(state.pending_invoices.is_empty());
        assert!(state.pending_signatures.is_empty());
        assert!(!state.notifications.is_empty(), "the seller must be told");
    }

    /// The signature answer has to find the invoice it belongs to by the bytes
    /// that were signed, not by queue position -- a store edit or a listing
    /// can be outstanding at the same time.
    #[test]
    fn a_signature_finds_its_invoice_among_other_outstanding_requests() {
        let mut state = seller_with_a_store();
        state
            .pending_signatures
            .push_back(PendingSignature::Listing(PendingListing {
                fingerprint: SELLER.to_string(),
                listing: harvest_common::listing::Listing {
                    id: listing_id(),
                    title: "Other".to_string(),
                    description: String::new(),
                    kind: harvest_common::listing::ListingKind::Sale,
                    price: None,
                    created_at: chrono::Utc::now(),
                },
                store_contract_id: None,
            }));
        state.issue_invoice(invoice()).expect("accepted");
        let waiting = *state.pending_invoices.keys().next().expect("one entry");
        state.on_bitcoin_delegate_response(address_answer(waiting, 0));
        assert_eq!(state.pending_signatures.len(), 2);

        let order_request = state
            .pending_signatures
            .iter()
            .find(|p| matches!(p, PendingSignature::Order(_)))
            .expect("the invoice is queued")
            .clone();
        state.on_ghostkey_response(sign_result_for(&order_request));

        assert_eq!(
            state.pending_signatures.len(),
            1,
            "only the invoice's request should have been consumed"
        );
        assert!(matches!(
            state.pending_signatures.front(),
            Some(PendingSignature::Listing(_))
        ));
    }

    /// The store contract verifies every order against the store's own
    /// `seller_verifying_key`, so an invoice signed by any other connected
    /// identity is rejected with nothing to say why. Refuse it here, where
    /// there is something to say.
    #[test]
    fn only_the_stores_owner_can_issue_invoices_on_it() {
        let mut state = seller_with_a_store();
        let mut wrong = invoice();
        wrong.seller_fingerprint = "somebody-else".to_string();

        let err = state.issue_invoice(wrong).expect_err("must refuse");
        assert!(err.contains(SELLER), "unhelpful error: {err}");
        assert!(state.pending_invoices.is_empty());
    }

    #[test]
    fn a_store_that_is_not_ours_is_refused() {
        let mut state = seller_with_a_store();
        let mut elsewhere = invoice();
        elsewhere.store_contract_id = vec![42u8; 32];

        let err = state.issue_invoice(elsewhere).expect_err("must refuse");
        assert!(err.contains("not one of yours"), "unhelpful error: {err}");
    }

    /// Without a payment key there is nowhere for the buyer to pay, and the
    /// delegate would refuse anyway -- but a form error is a better answer
    /// than a burned round trip and a notification.
    #[test]
    fn an_invoice_without_a_payment_key_is_refused_up_front() {
        let mut state = seller_with_a_store();
        state.bitcoin.payment_xpub = None;

        let err = state.issue_invoice(invoice()).expect_err("must refuse");
        assert!(err.contains("payment key"), "unhelpful error: {err}");
        assert!(state.pending_invoices.is_empty());
    }

    #[test]
    fn an_invoice_for_nothing_is_refused() {
        let mut state = seller_with_a_store();
        let mut free = invoice();
        free.amount_sats = 0;
        assert!(state.issue_invoice(free).is_err());
    }

    /// Zero confirmations would let a payment count as settled while it is
    /// still only in the mempool, i.e. while it can still be replaced.
    #[test]
    fn an_invoice_requiring_no_confirmations_is_refused() {
        let mut state = seller_with_a_store();
        let mut instant = invoice();
        instant.required_confirmations = 0;
        assert!(state.issue_invoice(instant).is_err());
    }

    /// "No key configured" and "we have not asked yet" have to stay distinct,
    /// or the seller is prompted to add a key they may already have.
    #[test]
    fn the_delegate_reports_the_key_it_stored() {
        let mut state = AppState::default();
        assert!(!state.bitcoin.payment_xpub_loaded);

        state.on_bitcoin_delegate_response(BitcoinDelegateResponse::PaymentXpub { status: None });
        assert!(
            state.bitcoin.payment_xpub_loaded,
            "an empty answer is still an answer -- it means no key is set"
        );
        assert!(state.bitcoin.payment_xpub.is_none());

        state.on_bitcoin_delegate_response(BitcoinDelegateResponse::PaymentXpubSet {
            request_id: 1,
            result: Ok(PaymentXpubStatus {
                xpub: "vpub-placeholder".to_string(),
                network: BitcoinNetwork::Signet,
                next_index: 4,
            }),
        });
        assert_eq!(
            state.bitcoin.payment_xpub.as_ref().map(|s| s.next_index),
            Some(4)
        );
    }

    /// Two invoices for the same listing, both with the buyer field blank --
    /// which the form offers as the normal way to write an invoice anyone may
    /// pay -- collide on `OrderId` if their addresses are handled in the same
    /// millisecond, because the id hashes only
    /// `(seller, listing, created_at_ms, buyer)`.
    ///
    /// The contract's merge then keeps whichever record has the greater CBOR
    /// bytes at equal rank, so the loser disappears with no error anywhere,
    /// taking a derivation index and an address that has already been shown to
    /// somebody.
    #[test]
    fn two_invoices_handled_in_one_millisecond_get_distinct_ids() {
        let mut state = seller_with_a_store();

        let mut anonymous = invoice();
        anonymous.buyer_fingerprint = String::new();
        state.issue_invoice(anonymous.clone()).expect("accepted");
        let first_id = *state.pending_invoices.keys().next().expect("one entry");
        anonymous.amount_sats = 99_000;
        state.issue_invoice(anonymous).expect("accepted");
        let second_id = *state
            .pending_invoices
            .keys()
            .find(|id| **id != first_id)
            .expect("two entries");

        state.on_bitcoin_delegate_response(address_answer(first_id, 0));
        state.on_bitcoin_delegate_response(address_answer(second_id, 1));

        let ids: Vec<_> = state
            .pending_signatures
            .iter()
            .filter_map(|pending| match pending {
                PendingSignature::Order(o) => Some(o.order.id.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(
            ids[0], ids[1],
            "two invoices sharing an id means one of them silently vanishes on merge"
        );
    }

    /// **Two invoices for one listing are two orders, because their
    /// destinations differ.**
    ///
    /// This replaces three tests of `unused_invoice_timestamp`, a
    /// collision-avoidance dance that is now deleted. It existed because
    /// `OrderId` hashed only `(seller, listing, created_at_ms, buyer)`, so two
    /// invoices for one listing in one millisecond WERE one order and one of
    /// them silently vanished on merge -- taking a derivation index and an
    /// address already shown to somebody. The id now covers the whole terms,
    /// and the delegate hands out a distinct payment address per invoice, so
    /// the collision it guarded is not reachable and the guard's own
    /// timestamp-advancing behaviour is no longer a thing to test.
    ///
    /// Asserted at the same instant, which is the case the old guard existed
    /// for.
    #[test]
    fn two_invoices_at_one_instant_are_two_orders() {
        let mut anonymous = invoice();
        anonymous.buyer_fingerprint = String::new();
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");

        let one =
            order_for_invoice(&anonymous, &derived(0), Some(anchor(800_000)), now).expect("build");
        let other =
            order_for_invoice(&anonymous, &derived(1), Some(anchor(800_000)), now).expect("build");

        assert_ne!(one.payment_address, other.payment_address);
        assert_ne!(
            one.id, other.id,
            "two invoices sharing an id means one of them silently vanishes on merge"
        );
    }

    /// **An issued invoice carries the id its own terms give.**
    ///
    /// The seller's half of the rule the contract enforces: an order stamped
    /// any other way is one `AuthorizedOrder::verify` refuses, so it would be
    /// signed, published and then rejected by every peer with nothing on the
    /// seller's screen saying why.
    #[test]
    fn an_issued_invoice_carries_the_id_its_terms_give() {
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let order =
            order_for_invoice(&invoice(), &derived(0), Some(anchor(800_000)), now).expect("build");
        assert_eq!(
            order.id,
            harvest_common::payment::OrderId::from_terms(&order)
        );
    }

    /// A rejected key is reported verbatim: every rejection the delegate can
    /// produce names something the seller can fix (the wrong export, the
    /// wrong network, the wrong depth), and reducing it to "invalid key"
    /// throws that away.
    #[test]
    fn a_rejected_payment_key_is_reported_to_the_seller() {
        let mut state = AppState::default();
        state.on_bitcoin_delegate_response(BitcoinDelegateResponse::PaymentXpubSet {
            request_id: 1,
            result: Err("that is a legacy account key (xpub/tpub)".to_string()),
        });

        assert!(state.bitcoin.payment_xpub.is_none());
        assert!(state
            .notifications
            .iter()
            .any(|n| n.contains("legacy account key")));
    }
}

#[cfg(test)]
mod authorized_order_tests {
    use super::*;

    use freenet_bitcoin_common::BitcoinNetwork;
    use harvest_common::listing::ListingId;
    use harvest_common::payment::{Order, OrderId, OrderStatus};

    fn order() -> Order {
        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let listing_id = ListingId::from_label("Widget");
        Order {
            id: OrderId([0u8; 32]),
            listing_id,
            buyer_fingerprint: "buyer".to_string(),
            seller_fingerprint: "seller".to_string(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 0xaa],
            payment_address: "tb1qexample".to_string(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: vec![freenet_bitcoin_common::BridgeId([3u8; 32])],
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            created_at,
        }
        .with_derived_id()
    }

    /// A seller may say what is owed and where; they may NOT say it was paid.
    /// `Paid` outranks everything a seller can assert and is evidenced by
    /// bridge-signed observations, so a record claiming it without proof is
    /// rejected by `AuthorizedOrder::verify` -- with nothing to say why, which
    /// is indistinguishable from the invoice never having been sent.
    #[test]
    fn a_newly_issued_invoice_only_ever_awaits_payment() {
        let authorized = authorize_new_order(order(), vec![1, 2, 3], vec![4, 5, 6]);

        assert_eq!(authorized.status, OrderStatus::AwaitingPayment);
        assert!(
            authorized.payment_proof.is_none(),
            "there is no payment to prove yet"
        );
        assert!(
            authorized.status_scoped_payload.is_none() && authorized.status_signature.is_none(),
            "the only seller-signed status transition is Cancelled, which this is not"
        );
    }

    /// The signature the delegate returned has to travel with the record
    /// verbatim: `verify_terms` checks it over the scoped payload, and the
    /// scoped payload against a re-encoding of the order.
    #[test]
    fn the_signature_travels_with_the_terms_it_covers() {
        let authorized = authorize_new_order(order(), vec![1, 2, 3], vec![4, 5, 6]);

        assert_eq!(authorized.scoped_payload, vec![1, 2, 3]);
        assert_eq!(authorized.signature, vec![4, 5, 6]);
        assert_eq!(authorized.order, order());
    }
}

/// The seller's side of buyer-to-seller messaging: asking the delegate for
/// the conversation keys, and reading the mailbox with them.
///
/// Every one of these runs on the host. The only wasm-gated part of the path
/// is the delegate send itself, which is why the decisions live here rather
/// than in `gateway`.
#[cfg(test)]
mod mailbox_read_tests {
    use super::*;
    use harvest_common::mailbox::{conversation_key_from_dh, EncryptedMessage, MessageDirection};
    use harvest_common::ConversationKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    const OURS: &[u8] = &[1u8; 32];
    const A_STRANGERS: &[u8] = &[2u8; 32];
    const FINGERPRINT: &str = "fp1";

    fn registration(store_contract_id: &[u8]) -> StoreRegistration {
        StoreRegistration {
            store_contract_id: store_contract_id.to_vec(),
            reputation_contract_id: vec![3u8; 32],
            mailbox_contract_id: vec![4u8; 32],
            store_contract_key: None,
        }
    }

    /// A store the connected identity owns, plus a stranger's store, both
    /// holding `messages`.
    fn state_with(messages: Vec<EncryptedMessage>) -> AppState {
        let mut state = AppState::default();
        state
            .my_stores
            .insert(FINGERPRINT.to_string(), vec![registration(OURS)]);
        for id in [OURS, A_STRANGERS] {
            state
                .browsing_stores
                .entry(id.to_vec())
                .or_default()
                .mailbox_messages = messages.clone();
        }
        state
    }

    /// The seller, and a buyer who wrote to them.
    struct Conversation {
        seller: StaticSecret,
        message: EncryptedMessage,
    }

    fn conversation(text: &str) -> Conversation {
        // One seller, distinct buyers: each call opens a fresh
        // `BuyerConversation`, so the routing tags differ.
        let seller = StaticSecret::from([21u8; 32]);
        let message =
            crate::messaging::BuyerConversation::open(PublicKey::from(&seller).as_bytes())
                .expect("open")
                .seal(text.to_string())
                .expect("seal");
        Conversation { seller, message }
    }

    impl Conversation {
        /// The answer the delegate would give for this buyer's key.
        fn answer(&self) -> ConversationKey {
            let peer: [u8; 32] = self
                .message
                .sender_public_key
                .clone()
                .try_into()
                .expect("32 bytes");
            let shared = self
                .seller
                .diffie_hellman(&PublicKey::from(peer))
                .to_bytes();
            ConversationKey {
                peer_public_key: self.message.sender_public_key.clone(),
                buyer_to_seller: conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
                seller_to_buyer: conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
            }
        }
    }

    fn peer_keys(request: &harvest_common::HarvestDelegateRequest) -> Vec<Vec<u8>> {
        match request {
            harvest_common::HarvestDelegateRequest::DeriveConversationKeys {
                peer_public_keys,
                ..
            } => peer_public_keys.clone(),
            other => panic!("expected DeriveConversationKeys, got {other:?}"),
        }
    }

    fn request_id(request: &harvest_common::HarvestDelegateRequest) -> u64 {
        match request {
            harvest_common::HarvestDelegateRequest::DeriveConversationKeys {
                request_id, ..
            } => *request_id,
            other => panic!("expected DeriveConversationKeys, got {other:?}"),
        }
    }

    /// The whole seller path: a message arrives, keys are asked for, the
    /// answer comes back, and the message becomes readable.
    #[test]
    fn the_delegates_answer_makes_the_mailbox_readable() {
        let conversation = conversation("is the blue one still available?");
        let mut state = state_with(vec![conversation.message.clone()]);

        // Before the keys arrive, the message is present and unreadable --
        // not missing, which is what a seller would otherwise see as "nobody
        // has written to me".
        let before = state.mailbox_entries(OURS);
        assert_eq!(before.len(), 1);
        assert!(matches!(
            before[0],
            crate::messaging::MailboxEntry::Unreadable { .. }
        ));

        let request = state
            .conversation_keys_to_request(OURS)
            .expect("the seller must ask for the key");
        assert_eq!(
            peer_keys(&request),
            vec![conversation.message.sender_public_key.clone()]
        );

        state.on_delegate_response(HarvestDelegateResponse::ConversationKeys {
            request_id: request_id(&request),
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            result: Ok(vec![conversation.answer()]),
        });

        match &state.mailbox_entries(OURS)[..] {
            [crate::messaging::MailboxEntry::Readable { content, .. }] => assert_eq!(
                content,
                &crate::messaging::MessageContent::Text(
                    "is the blue one still available?".to_string()
                )
            ),
            other => panic!("the seller should be able to read it now: {other:?}"),
        }
    }

    /// **A buyer must not ask for keys against a stranger's mailbox.**
    ///
    /// The request names one of OUR identities, so the delegate would answer
    /// keys derived from our secret -- well-formed, and useless against
    /// somebody else's messages. Every message would report "cannot be read",
    /// after one delegate round trip per message per update notification, for
    /// every store the user opens.
    #[test]
    fn a_store_we_do_not_own_asks_for_nothing() {
        let conversation = conversation("hello");
        let mut state = state_with(vec![conversation.message]);

        assert!(
            state.conversation_keys_to_request(A_STRANGERS).is_none(),
            "browsing a store must not send the delegate a key request"
        );
        // Ours does ask, so the assertion above is about ownership rather
        // than about the fixture having no messages.
        assert!(state.conversation_keys_to_request(OURS).is_some());
    }

    /// Mailbox state re-arrives on every update notification, so asking again
    /// for a key already held would mean one delegate request per message per
    /// notification, forever.
    #[test]
    fn a_key_already_held_is_not_asked_for_again() {
        let conversation = conversation("hello");
        let mut state = state_with(vec![conversation.message.clone()]);

        let request = state.conversation_keys_to_request(OURS).expect("asks once");
        state.on_delegate_response(HarvestDelegateResponse::ConversationKeys {
            request_id: request_id(&request),
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            result: Ok(vec![conversation.answer()]),
        });

        assert!(
            state.conversation_keys_to_request(OURS).is_none(),
            "the key is already held; asking again is pure churn"
        );
    }

    /// The same, for a request that has gone out and not yet been answered.
    #[test]
    fn a_key_already_in_flight_is_not_asked_for_twice() {
        let conversation = conversation("hello");
        let mut state = state_with(vec![conversation.message]);

        assert!(state.conversation_keys_to_request(OURS).is_some());
        assert!(
            state.conversation_keys_to_request(OURS).is_none(),
            "a second update notification must not re-ask for a key already in flight"
        );
    }

    /// An error answer un-asks its keys, so the next mailbox update tries
    /// again.
    ///
    /// Without this the failure is permanent for the life of the tab: the
    /// keys stay recorded as in-flight against a request that will never be
    /// answered, and the seller's mailbox reads as unreadable forever with no
    /// way to retry short of a reload.
    #[test]
    fn an_error_answer_lets_the_next_update_retry() {
        let conversation = conversation("hello");
        let mut state = state_with(vec![conversation.message]);

        let request = state.conversation_keys_to_request(OURS).expect("asks once");
        state.on_delegate_response(HarvestDelegateResponse::ConversationKeys {
            request_id: request_id(&request),
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            result: Err("no encryption key for ghostkey fp1".to_string()),
        });

        assert!(
            state.conversation_keys_to_request(OURS).is_some(),
            "a failed derivation must be retryable"
        );
    }

    /// **A tag the delegate declined is never asked about again.**
    ///
    /// This test asserted the OPPOSITE when it was written, and the reasoning
    /// behind that was wrong. I justified re-asking by transient failure --
    /// but the delegate's omissions are not transient. It drops a peer key
    /// only when the key is malformed or low-order (`harvest-delegate`'s
    /// `messaging::derive_conversation_keys`), and both are deterministic
    /// properties of the bytes: the same tag will be dropped every time.
    ///
    /// Because mailbox state re-arrives on every update notification, that
    /// made ONE message carrying an unusable tag enough to put the seller's
    /// tab into an unbounded loop -- a fresh `DeriveConversationKeys` on
    /// every update, for the life of the tab, never answered.
    ///
    /// Transient failure is a different case and still retries: it is the
    /// `Err` answer, where nothing was derived, covered by
    /// `an_error_answer_lets_the_next_update_retry`.
    ///
    /// Observed red against the "stays askable" behaviour this replaces.
    #[test]
    fn a_tag_the_delegate_declined_is_not_asked_about_again() {
        let answered = conversation("answered");
        let declined = conversation("declined");
        let mut state = state_with(vec![answered.message.clone(), declined.message.clone()]);

        let request = state.conversation_keys_to_request(OURS).expect("asks");
        assert_eq!(peer_keys(&request).len(), 2);

        state.on_delegate_response(HarvestDelegateResponse::ConversationKeys {
            request_id: request_id(&request),
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            result: Ok(vec![answered.answer()]),
        });

        assert!(
            state.conversation_keys_to_request(OURS).is_none(),
            "a tag the delegate will never answer was asked about again"
        );
        // And it stays that way however many update notifications arrive.
        for _ in 0..5 {
            assert!(state.conversation_keys_to_request(OURS).is_none());
        }
    }

    /// A tag that could not possibly be a public key is not sent to the
    /// delegate at all.
    ///
    /// The delegate would drop it, so the round trip buys nothing -- and the
    /// tag is bounded only by `MAX_MESSAGE_BYTES`, so it is a round trip that
    /// can carry tens of kilobytes of an attacker's choosing.
    #[test]
    fn a_tag_that_cannot_be_a_public_key_is_never_asked_about() {
        let good = conversation("good");
        let mut junk = good.message.clone();
        junk.nonce = [0xEE; 24];
        junk.sender_public_key = vec![0u8; 60_000];

        let mut state = state_with(vec![good.message.clone(), junk]);

        let request = state.conversation_keys_to_request(OURS).expect("asks");
        assert_eq!(
            peer_keys(&request),
            vec![good.message.sender_public_key.clone()],
            "an impossible tag was sent to the delegate"
        );
    }

    /// Two messages from one buyer share a sender key, so the delegate is
    /// asked about it once.
    #[test]
    fn one_buyer_is_asked_about_once() {
        let conversation = conversation("first");
        let mut twice = conversation.message.clone();
        twice.nonce = [99u8; 24];
        let mut state = state_with(vec![conversation.message.clone(), twice]);

        let request = state.conversation_keys_to_request(OURS).expect("asks");
        assert_eq!(peer_keys(&request).len(), 1);
    }

    /// An answer to a request id we are not waiting on is ignored rather than
    /// folded in.
    #[test]
    fn an_answer_to_an_unknown_request_is_ignored() {
        let conversation = conversation("hello");
        let mut state = state_with(vec![conversation.message.clone()]);

        state.on_delegate_response(HarvestDelegateResponse::ConversationKeys {
            request_id: 4242,
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            result: Ok(vec![conversation.answer()]),
        });

        assert!(
            state.conversation_keys.is_empty(),
            "a key nothing asked for must not be adopted"
        );
    }

    /// The certificate verdict and the key the mailbox address is derived
    /// from are formed together, from the same call, when a store's state
    /// arrives -- so a store the buyer is told is unverified can never also
    /// be one the compose box is offered for.
    ///
    /// This is the wiring rather than the check; the check is
    /// `ghostkey_cert::a_stolen_certificate_yields_no_key_to_derive_a_mailbox_from`.
    /// What it catches is `on_contract_state` setting one and not the other,
    /// which was the shape of the whole class of defect this repository keeps
    /// finding: two facts about the same thing, decided in two places.
    ///
    /// Observed red on 2026-09-05 by leaving `seller_verifying_key` unset.
    #[test]
    fn an_unverified_store_yields_no_key_to_message_it_with() {
        let mut state = AppState::default();
        let store_state = harvest_common::store::StoreStateV1::default();

        state.on_contract_state(
            vec![5u8; 32],
            harvest_common::to_cbor(&store_state).expect("cbor"),
        );

        let store = state
            .browsing_stores
            .get(&vec![5u8; 32])
            .expect("the store state should have been adopted");
        assert!(
            !store.certificate_status.is_verified(),
            "precondition: a default store carries no certificate"
        );
        assert_eq!(
            store.seller_verifying_key, None,
            "a store whose certificate does not verify must name no mailbox"
        );
    }

    /// **The answer is paired by echoed tag, not by position.**
    ///
    /// The delegate drops peer keys it cannot use -- malformed, or low-order
    /// -- so a SHORT answer is ordinary rather than exceptional, and the
    /// delegate's own test calls the positional case "the mutation that
    /// matters". But that test proves the DELEGATE echoes the tag. It cannot
    /// prove the consumer uses it, and the consumer is the only side that
    /// could correlate positionally, because it is the side holding the list
    /// of what was asked.
    ///
    /// So the guard lived on one side of the boundary and the thing it
    /// guarded on the other. Verified: replacing the echo with
    /// `asked.into_iter().zip(keys)` passed all 216 tests.
    ///
    /// Observed red on 2026-09-05 with exactly that mutation.
    #[test]
    fn a_short_answer_does_not_hand_one_buyers_key_to_another() {
        let first = conversation("first");
        let second = conversation("second");
        let mut state = state_with(vec![first.message.clone(), second.message.clone()]);

        let request = state.conversation_keys_to_request(OURS).expect("asks");
        let asked = peer_keys(&request);
        assert_eq!(asked.len(), 2, "precondition: both tags were asked about");
        assert_eq!(
            asked[0], first.message.sender_public_key,
            "precondition: the FIRST tag asked about is the one left unanswered below, \
             so a positional pairing would misfile the answer rather than drop it"
        );

        // The delegate answers only the SECOND. Positional correlation would
        // file that key under the first tag.
        state.on_delegate_response(HarvestDelegateResponse::ConversationKeys {
            request_id: request_id(&request),
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            result: Ok(vec![second.answer()]),
        });

        assert!(
            !state
                .conversation_keys
                .contains_key(&first.message.sender_public_key),
            "a key was filed under a tag the delegate did not answer"
        );
        let filed = state
            .conversation_keys
            .get(&second.message.sender_public_key)
            .expect("the answered tag must have its key");
        assert_eq!(filed.to_seller, second.answer().buyer_to_seller);
        assert_eq!(filed.from_seller, second.answer().seller_to_buyer);
    }

    /// The same, end to end: with the answer REORDERED, both buyers'
    /// messages still decrypt.
    ///
    /// A positional pairing survives the test above only by luck of which tag
    /// was dropped; it cannot survive this one at all, because every key is
    /// present and simply in the wrong order.
    #[test]
    fn a_reordered_answer_still_decrypts_both_buyers() {
        let first = conversation("from the first buyer");
        let second = conversation("from the second buyer");
        let mut state = state_with(vec![first.message.clone(), second.message.clone()]);

        let request = state.conversation_keys_to_request(OURS).expect("asks");
        state.on_delegate_response(HarvestDelegateResponse::ConversationKeys {
            request_id: request_id(&request),
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            // Reversed relative to the order they were asked in.
            result: Ok(vec![second.answer(), first.answer()]),
        });

        let readable: Vec<String> = state
            .mailbox_entries(OURS)
            .into_iter()
            .filter_map(|entry| match entry {
                crate::messaging::MailboxEntry::Readable {
                    content: crate::messaging::MessageContent::Text(text),
                    ..
                } => Some(text),
                _ => None,
            })
            .collect();

        assert_eq!(
            readable.len(),
            2,
            "both buyers' messages must decrypt regardless of the answer's order: {readable:?}"
        );
        assert!(readable.contains(&"from the first buyer".to_string()));
        assert!(readable.contains(&"from the second buyer".to_string()));
    }

    /// The delegate's `EncryptionKeyReady` lands where publishing reads it.
    #[test]
    fn the_encryption_key_is_recorded_for_publishing() {
        let mut state = AppState::default();
        state.on_delegate_response(HarvestDelegateResponse::EncryptionKeyReady {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            x25519_public_key: vec![7u8; 32],
        });
        assert_eq!(
            state.encryption_public_keys.get(FINGERPRINT),
            Some(&[7u8; 32])
        );
    }

    /// **The encryption key is filed under the fingerprint the DELEGATE
    /// named**, not under whichever identity happens to be in flight.
    ///
    /// The same producer/consumer split as
    /// `a_short_answer_does_not_hand_one_buyers_key_to_another`: the delegate
    /// has a test proving two identities get different keys, and that test
    /// cannot say anything about where the consumer files them. A key filed
    /// under the wrong identity is published in that identity's signed store
    /// details, so every buyer encrypts to a key the seller cannot read --
    /// permanently, in a record they cannot retract.
    ///
    /// Observed red by filing under `pending_store_creation`'s fingerprint
    /// instead of the response's.
    #[test]
    fn an_encryption_key_is_filed_under_the_identity_the_delegate_named() {
        // An unrelated creation in flight, which is the value a consumer
        // reaching for the wrong fingerprint would most naturally pick up.
        let mut state = AppState {
            pending_store_creation: Some(PendingStoreCreation {
                ghostkey_fingerprint: "someone-else".to_string(),
                seller_verifying_key_bytes: [0u8; 32],
                certificate_pem: String::new(),
                store_name: String::new(),
                description: String::new(),
                payment_instructions: String::new(),
                rsa_public_key_der: None,
                encryption_public_key: None,
            }),
            ..AppState::default()
        };

        state.on_delegate_response(HarvestDelegateResponse::EncryptionKeyReady {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            x25519_public_key: vec![7u8; 32],
        });

        assert_eq!(
            state.encryption_public_keys.get(FINGERPRINT),
            Some(&[7u8; 32]),
            "the key must be filed under the identity the delegate answered about"
        );
        assert!(
            !state.encryption_public_keys.contains_key("someone-else"),
            "a key was filed under an identity the delegate said nothing about"
        );
        assert_eq!(
            state
                .pending_store_creation
                .as_ref()
                .and_then(|p| p.encryption_public_key),
            None,
            "a creation for a different identity must not adopt this key"
        );
    }

    /// A key of the wrong length is refused rather than truncated or padded
    /// into something the seller would publish and no buyer could use.
    #[test]
    fn a_wrong_length_encryption_key_is_refused() {
        let mut state = AppState::default();
        state.on_delegate_response(HarvestDelegateResponse::EncryptionKeyReady {
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            x25519_public_key: vec![7u8; 31],
        });
        assert!(state.encryption_public_keys.is_empty());
        assert!(
            state.notifications.iter().any(|n| n.contains("encryption")),
            "the seller must be told, or the key silently never appears: {:?}",
            state.notifications
        );
    }
}

/// The reply path: a buyer's thread with a store, and the seller's answer,
/// both carried by the seller's own mailbox.
///
/// Every one of these runs on the host. The only wasm-gated part is the
/// dispatch, which is why the decisions live here.
#[cfg(test)]
mod conversation_tests {
    use super::*;
    use crate::messaging::MessageContent;
    use harvest_common::mailbox::{conversation_key_from_dh, EncryptedMessage, MessageDirection};
    use harvest_common::ConversationKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    const STORE: &[u8] = &[1u8; 32];
    const FINGERPRINT: &str = "fp1";

    fn seller_secret() -> StaticSecret {
        StaticSecret::from([21u8; 32])
    }

    fn seller_public() -> [u8; 32] {
        *PublicKey::from(&seller_secret()).as_bytes()
    }

    /// A browser that is only browsing: it owns no store.
    fn buyer_state() -> AppState {
        let mut state = AppState::default();
        state.browsing_stores.entry(STORE.to_vec()).or_default();
        state
    }

    /// A browser whose connected identity owns the store, so the seller's
    /// half of the path is reachable.
    fn seller_state() -> AppState {
        let mut state = AppState::default();
        state.my_stores.insert(
            FINGERPRINT.to_string(),
            vec![StoreRegistration {
                store_contract_id: STORE.to_vec(),
                reputation_contract_id: vec![3u8; 32],
                mailbox_contract_id: vec![4u8; 32],
                store_contract_key: None,
            }],
        );
        state.browsing_stores.entry(STORE.to_vec()).or_default();
        state
    }

    /// The answer the delegate would give for one conversation tag.
    fn delegate_answer(tag: &[u8]) -> ConversationKey {
        let peer: [u8; 32] = tag.try_into().expect("32-byte tag");
        let shared = seller_secret()
            .diffie_hellman(&PublicKey::from(peer))
            .to_bytes();
        ConversationKey {
            peer_public_key: tag.to_vec(),
            buyer_to_seller: conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
            seller_to_buyer: conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
        }
    }

    /// Put a message into the store's mailbox as the network would.
    fn deliver(state: &mut AppState, message: EncryptedMessage) {
        state
            .browsing_stores
            .entry(STORE.to_vec())
            .or_default()
            .mailbox_messages
            .push(message);
    }

    fn text(content: &MessageContent) -> &str {
        match content {
            MessageContent::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        }
    }

    /// One conversation per store, reused.
    ///
    /// A second message that opened a NEW conversation would be readable by
    /// the seller, so nothing would look broken -- but the reply to the first
    /// message would become unreadable the moment the second was sent, and
    /// the buyer would see a thread that silently loses its own history.
    #[test]
    fn a_second_message_continues_the_same_conversation() {
        let mut state = buyer_state();

        let first = state
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        let second = state
            .compose_to_seller(STORE, &seller_public(), "still there?".into())
            .expect("compose");

        assert_eq!(
            first.sender_public_key, second.sender_public_key,
            "a second message must continue the conversation, not open a new one"
        );
        assert_ne!(first.nonce, second.nonce);
    }

    /// **The path the whole next phase rests on**, end to end through
    /// `AppState`: buyer writes, seller reads, seller replies into their own
    /// mailbox, buyer reads the reply. No buyer mailbox, no buyer identity.
    #[test]
    fn a_seller_replies_into_their_own_mailbox_and_the_buyer_reads_it() {
        // The buyer's browser.
        let mut buyer = buyer_state();
        let question = buyer
            .compose_to_seller(STORE, &seller_public(), "do you ship to Ireland?".into())
            .expect("compose");

        // The seller's browser: the same mailbox, and the delegate round
        // trip driven the way the real one is -- ask, then answer the id that
        // was asked. An answer to an id nothing asked for is ignored, which
        // is its own test.
        let mut seller = seller_state();
        deliver(&mut seller, question.clone());
        let asked = seller.conversation_keys_to_request(STORE).expect("asks");
        let request_id = match &asked {
            harvest_common::HarvestDelegateRequest::DeriveConversationKeys {
                request_id, ..
            } => *request_id,
            other => panic!("expected DeriveConversationKeys, got {other:?}"),
        };
        seller.on_delegate_response(HarvestDelegateResponse::ConversationKeys {
            request_id,
            ghostkey_fingerprint: FINGERPRINT.to_string(),
            result: Ok(vec![delegate_answer(&question.sender_public_key)]),
        });

        // The seller can read it, and can answer it.
        let inbox = seller.mailbox_entries(STORE);
        assert_eq!(inbox.len(), 1);
        let reply = seller
            .compose_reply(
                STORE,
                &question.sender_public_key,
                "yes, ten euro postage".into(),
            )
            .expect("the seller must be able to reply");

        // The reply reaches the buyer through the same mailbox.
        deliver(&mut buyer, question.clone());
        deliver(&mut buyer, reply);

        let thread = buyer.conversation_thread(STORE);
        assert_eq!(thread.len(), 2, "the buyer sees both halves");
        assert_eq!(thread[0].addressing, crate::messaging::Addressing::ToSeller);
        assert_eq!(
            thread[1].addressing,
            crate::messaging::Addressing::ToBuyer,
            "the reply is addressed to the buyer"
        );
        assert_eq!(text(&thread[1].content), "yes, ten euro postage");
    }

    /// A seller cannot reply to a conversation they have not read.
    ///
    /// The reply has to name the conversation id the buyer chose, and the
    /// only place that id exists is inside a message the seller decrypted --
    /// so "reply" without "read" is not a thing that can be done, and saying
    /// so is better than sending something the buyer silently discards.
    #[test]
    fn a_seller_cannot_reply_to_a_conversation_they_have_not_read() {
        let mut seller = seller_state();
        // The key is present, so this is not the "no key yet" refusal -- it
        // is the one about there being no conversation.
        let tag = {
            let buyer = crate::messaging::BuyerConversation::open(&seller_public()).expect("open");
            buyer.buyer_public_key.to_vec()
        };
        let answer = delegate_answer(&tag);
        seller.conversation_keys.insert(
            tag.clone(),
            crate::messaging::ConversationKeys {
                to_seller: answer.buyer_to_seller,
                from_seller: answer.seller_to_buyer,
            },
        );

        let error = seller
            .compose_reply(STORE, &tag, "hello?".into())
            .expect_err("must refuse");
        assert!(
            error.contains("no message"),
            "the refusal must say what is missing: {error}"
        );
    }

    /// The other refusal, kept separate because it is a different situation
    /// with a different fix: the delegate has not answered yet, so waiting
    /// helps.
    #[test]
    fn a_seller_without_the_key_is_told_to_wait_rather_than_told_there_is_no_conversation() {
        let seller = seller_state();
        let error = seller
            .compose_reply(STORE, &[9u8; 32], "hello?".into())
            .expect_err("must refuse");
        assert!(
            error.contains("delegate has not produced"),
            "a missing key must not be reported as a missing conversation: {error}"
        );
    }

    /// And a browser that does not own the store cannot reply into its
    /// mailbox at all -- it holds no key for the conversation and would be
    /// writing bytes nobody can read.
    #[test]
    fn a_buyer_cannot_reply_on_a_sellers_behalf() {
        let mut buyer = buyer_state();
        let question = buyer
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        deliver(&mut buyer, question.clone());

        let error = buyer
            .compose_reply(
                STORE,
                &question.sender_public_key,
                "not mine to send".into(),
            )
            .expect_err("must refuse");
        assert!(error.contains("not one of yours"), "got: {error}");
    }

    /// A message is unconfirmed until it turns up in the mailbox the buyer
    /// re-reads. That is the only delivery evidence Harvest has, and the
    /// distinction is what the UI shows instead of claiming delivery.
    #[test]
    fn a_sent_message_is_unconfirmed_until_it_appears_in_the_mailbox() {
        let mut buyer = buyer_state();
        let sent = buyer
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        buyer.record_sent_message(STORE, "hello".into(), &sent);

        assert_eq!(
            buyer.unconfirmed_sent(STORE).len(),
            1,
            "nothing has come back from the network yet"
        );

        deliver(&mut buyer, sent);
        assert!(
            buyer.unconfirmed_sent(STORE).is_empty(),
            "a message visible in the seller's mailbox has demonstrably landed"
        );
    }

    /// A store this browser has never written to has no thread, rather than
    /// a panic or an empty conversation that looks like one.
    #[test]
    fn a_store_with_no_conversation_has_no_thread() {
        let state = buyer_state();
        assert!(state.conversation_thread(STORE).is_empty());
        assert!(state.unconfirmed_sent(STORE).is_empty());
    }
}

/// The delegate/UI boundary: every answer is filed against the identity the
/// DELEGATE named, never against whatever this client had in flight.
///
/// # Why these are a group
///
/// Each of these responses carries an identity, and the consumer is the only
/// side that could file it under a different one. A delegate test proving it
/// answers about the right identity cannot say anything about that, because
/// the consumer is the side holding the local state a wrong answer would be
/// filed against. The same gap in `on_conversation_keys` passed all 216 tests
/// (`a_short_answer_does_not_hand_one_buyers_key_to_another`), so these are
/// the rest of the boundary rather than a hypothetical.
///
/// The Bitcoin surface already had its consumer-side test
/// (`invoice_tests::...` on `pending_invoices`), and its comment is worth
/// reading beside these: it records that with a `HashMap` instead of a
/// `BTreeMap` the positional shortcut passes "about half the time", which is
/// why a correlation test that happens to pass is not evidence of a
/// correlation.
#[cfg(test)]
mod delegate_correlation_tests {
    use super::*;

    const OURS: &str = "fp-ours";
    const THEIRS: &str = "fp-theirs";

    /// A creation in flight for a DIFFERENT identity -- the value a consumer
    /// reaching for the wrong fingerprint would most naturally pick up.
    fn with_another_creation_in_flight() -> AppState {
        AppState {
            pending_store_creation: Some(PendingStoreCreation {
                ghostkey_fingerprint: THEIRS.to_string(),
                seller_verifying_key_bytes: [0u8; 32],
                // Empty on purpose: `start_store_creation_if_ready` gates on
                // the certificate, so the creation cannot complete and be
                // taken out from under these tests. They are about where an
                // answer is FILED, not about the creation gate.
                certificate_pem: String::new(),
                store_name: "Theirs".to_string(),
                description: String::new(),
                payment_instructions: String::new(),
                rsa_public_key_der: None,
                encryption_public_key: None,
            }),
            ..AppState::default()
        }
    }

    /// **The RSA key decides where the reputation contract LIVES.**
    ///
    /// `ReputationParameters` carries the RSA public key, and a contract's
    /// address is `BLAKE3(code_hash || cbor(parameters))` -- so a key filed
    /// under the wrong identity puts that identity's reputation contract at an
    /// address derived from somebody else's key. The store then publishes a
    /// reputation link pointing at a contract nobody owns, inside a signed
    /// record, and every buyer follows it to nothing.
    ///
    /// Observed red by filing under `pending_store_creation`'s fingerprint.
    #[test]
    fn an_rsa_key_is_filed_under_the_identity_the_delegate_named() {
        let mut state = with_another_creation_in_flight();

        state.on_delegate_response(HarvestDelegateResponse::ReputationKeysInitialized {
            ghostkey_fingerprint: OURS.to_string(),
            rsa_public_key_der: vec![7u8; 16],
        });

        assert_eq!(
            state.rsa_public_keys.get(OURS),
            Some(&vec![7u8; 16]),
            "the key must be filed under the identity the delegate answered about"
        );
        assert!(
            !state.rsa_public_keys.contains_key(THEIRS),
            "a key was filed under an identity the delegate said nothing about"
        );
    }

    /// And the creation waiting on a DIFFERENT identity must not adopt it.
    ///
    /// This is the sharper half: adopting it would let the creation proceed
    /// (`start_store_creation_if_ready` gates on this field being `Some`) and
    /// publish a store whose reputation contract is addressed by another
    /// seller's key. The guard is the `pending.ghostkey_fingerprint ==
    /// ghostkey_fingerprint` check.
    ///
    /// Observed red by removing that check.
    #[test]
    fn a_creation_does_not_adopt_another_identitys_rsa_key() {
        let mut state = with_another_creation_in_flight();

        state.on_delegate_response(HarvestDelegateResponse::ReputationKeysInitialized {
            ghostkey_fingerprint: OURS.to_string(),
            rsa_public_key_der: vec![7u8; 16],
        });

        assert_eq!(
            state
                .pending_store_creation
                .as_ref()
                .and_then(|p| p.rsa_public_key_der.clone()),
            None,
            "a creation adopted an RSA key answered about a different identity"
        );

        // The matching answer IS adopted, so the assertion above is not
        // passing because the field is never filled.
        state.on_delegate_response(HarvestDelegateResponse::ReputationKeysInitialized {
            ghostkey_fingerprint: THEIRS.to_string(),
            rsa_public_key_der: vec![8u8; 16],
        });
        assert_eq!(
            state
                .pending_store_creation
                .as_ref()
                .and_then(|p| p.rsa_public_key_der.clone()),
            Some(vec![8u8; 16])
        );
    }

    /// `RsaPublicKey` is the other response carrying the same value, for an
    /// identity that already had keys, and files it the same way.
    #[test]
    fn a_recalled_rsa_key_is_filed_under_the_identity_the_delegate_named() {
        let mut state = with_another_creation_in_flight();

        state.on_delegate_response(HarvestDelegateResponse::RsaPublicKey {
            ghostkey_fingerprint: OURS.to_string(),
            rsa_public_key_der: vec![5u8; 16],
        });

        assert_eq!(state.rsa_public_keys.get(OURS), Some(&vec![5u8; 16]));
        assert!(!state.rsa_public_keys.contains_key(THEIRS));
    }

    /// **A store registry filed under the wrong identity makes somebody
    /// else's stores look like yours.**
    ///
    /// `my_stores` is what decides which stores this client will publish
    /// details for, issue invoices on, and treat as owned when reading a
    /// mailbox (`store_owner_fingerprint`). Filing another identity's
    /// registrations under this one offers the seller controls over contracts
    /// they cannot sign for.
    ///
    /// Observed red by filing under `pending_store_creation`'s fingerprint.
    #[test]
    fn a_store_list_is_filed_under_the_identity_the_delegate_named() {
        let mut state = with_another_creation_in_flight();

        state.on_delegate_response(HarvestDelegateResponse::StoreList {
            ghostkey_fingerprint: OURS.to_string(),
            stores: vec![StoreRegistration {
                store_contract_id: vec![1u8; 32],
                reputation_contract_id: vec![2u8; 32],
                mailbox_contract_id: vec![3u8; 32],
                store_contract_key: None,
            }],
        });

        assert_eq!(
            state.my_stores.get(OURS).map(|s| s.len()),
            Some(1),
            "the registry must be filed under the identity the delegate answered about"
        );
        assert!(
            !state.my_stores.contains_key(THEIRS),
            "another identity was given stores it does not own"
        );
    }
}

/// The buyer's conversation outliving the tab that opened it.
///
/// This is the half the whole mechanism exists for: the seller's reply is
/// readable after a reload, because the delegate kept the secret that reads
/// it. The delegate's own half is tested in `harvest-delegate`'s
/// `messaging::buyer_conversation_tests`; what these pin is what this browser
/// SENDS it and what it does with the answer.
#[cfg(test)]
mod buyer_persistence_tests {
    use super::*;
    use crate::messaging::MessageContent;
    use harvest_common::mailbox::{conversation_key_from_dh, EncryptedMessage, MessageDirection};
    use harvest_common::{HarvestDelegateRequest, RecalledConversation};
    use x25519_dalek::{PublicKey, StaticSecret};

    const STORE: &[u8] = &[1u8; 32];

    fn seller_secret() -> StaticSecret {
        StaticSecret::from([21u8; 32])
    }

    fn seller_public() -> [u8; 32] {
        *PublicKey::from(&seller_secret()).as_bytes()
    }

    /// A registered harvest delegate, which every request here needs
    /// somewhere to go.
    fn a_delegate_key() -> freenet_stdlib::prelude::DelegateKey {
        freenet_stdlib::prelude::DelegateKey::new(
            [0xA1; 32],
            freenet_stdlib::prelude::CodeHash::new([0xA1; 32]),
        )
    }

    /// The seller's Ed25519 identity, which is what the mailbox address is
    /// derived from.
    fn seller_identity() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes()
    }

    /// A browser that is only browsing, with the store's details in hand and
    /// the harvest delegate registered.
    fn buyer_state() -> AppState {
        let mut state = AppState {
            harvest_delegate_key: Some(a_delegate_key()),
            ..AppState::default()
        };
        let store = state.browsing_stores.entry(STORE.to_vec()).or_default();
        store.seller_verifying_key = Some(seller_identity());
        state
    }

    fn deliver(state: &mut AppState, message: EncryptedMessage) {
        state
            .browsing_stores
            .entry(STORE.to_vec())
            .or_default()
            .mailbox_messages
            .push(message);
    }

    /// Answer the recall this state actually issued.
    ///
    /// Driven as the round trip rather than by handing `AppState` a
    /// fabricated answer: an answer nothing asked for is ignored, so a test
    /// that skipped the question would be asserting against a path the app
    /// never takes.
    fn deliver_recall(state: &mut AppState, conversations: Vec<RecalledConversation>) {
        let request_id = match state.buyer_conversations_to_recall(STORE) {
            Some(HarvestDelegateRequest::ListBuyerConversations { request_id, .. }) => request_id,
            other => panic!("expected a recall to be asked for, got {other:?}"),
        };
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationList {
            request_id,
            store_contract_id: STORE.to_vec(),
            conversations,
        });
    }

    fn text(content: &MessageContent) -> &str {
        match content {
            MessageContent::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        }
    }

    /// What the delegate was asked to keep.
    fn kept(request: &HarvestDelegateRequest) -> ([u8; 32], [u8; 32], [u8; 32], i64) {
        match request {
            HarvestDelegateRequest::StoreBuyerConversation {
                store_contract_id,
                secret,
                seller_public_key,
                conversation_id,
                created_at,
                ..
            } => {
                assert_eq!(store_contract_id, STORE, "kept against the wrong store");
                (secret.0, *seller_public_key, *conversation_id, *created_at)
            }
            other => panic!("expected StoreBuyerConversation, got {other:?}"),
        }
    }

    /// **What the delegate answers on the next page load**, computed the way
    /// the delegate computes it -- from the secret it was given and the
    /// seller key it was given, with `harvest_common`'s own derivation, which
    /// is the one function both sides share.
    fn delegate_recalls(request: &HarvestDelegateRequest) -> RecalledConversation {
        let (secret, seller_public_key, conversation_id, created_at) = kept(request);
        let secret = StaticSecret::from(secret);
        let shared = secret
            .diffie_hellman(&PublicKey::from(seller_public_key))
            .to_bytes();
        RecalledConversation {
            buyer_public_key: *PublicKey::from(&secret).as_bytes(),
            conversation_id,
            buyer_to_seller: conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
            seller_to_buyer: conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
            order_binding: harvest_common::mailbox::order_binding_from_secret(&secret.to_bytes()),
            created_at,
            // A conversation just handed to the delegate has not been saved
            // anywhere by the buyer, and was opened here rather than
            // restored.
            imported: false,
            backed_up: false,
        }
    }

    /// **The reply survives the tab.**
    ///
    /// A buyer asks a question, closes the tab, and comes back. The seller's
    /// answer is in the mailbox and this browser has never seen the key that
    /// reads it -- only the delegate has. Without this the answer is
    /// ciphertext nobody can read, including the buyer who asked.
    #[test]
    fn a_reply_is_readable_after_the_tab_that_asked_is_gone() {
        // The tab that asks.
        let mut first_tab = buyer_state();
        let question = first_tab
            .compose_to_seller(STORE, &seller_public(), "do you ship to Ireland?".into())
            .expect("compose");
        let keep = first_tab
            .conversation_to_keep(STORE, &seller_public())
            .expect("the delegate must be asked to keep this conversation");

        // The seller answers, into their own mailbox, encrypted under the
        // conversation the buyer opened.
        let shared = seller_secret()
            .diffie_hellman(&PublicKey::from(
                <[u8; 32]>::try_from(question.sender_public_key.as_slice()).expect("32 bytes"),
            ))
            .to_bytes();
        let reply = crate::messaging::seal_reply(
            &crate::messaging::ConversationKeys::from_shared_secret(&shared),
            &question.sender_public_key,
            &question.conversation_id,
            "yes, ten euro postage".into(),
        )
        .expect("seal reply");

        // A new tab: nothing carried over but what the node kept.
        let mut second_tab = buyer_state();
        deliver(&mut second_tab, question.clone());
        deliver(&mut second_tab, reply);
        assert!(
            second_tab.conversation_thread(STORE).is_empty(),
            "precondition: a fresh tab holds no conversation of its own"
        );

        deliver_recall(&mut second_tab, vec![delegate_recalls(&keep)]);

        let thread = second_tab.conversation_thread(STORE);
        assert_eq!(
            thread.len(),
            2,
            "the recalled conversation reads its thread"
        );
        assert_eq!(text(&thread[0].content), "do you ship to Ireland?");
        assert_eq!(text(&thread[1].content), "yes, ten euro postage");
        assert_eq!(
            thread[1].addressing,
            crate::messaging::Addressing::ToBuyer,
            "the reply is addressed to the buyer"
        );
    }

    /// **Sending a message is what asks the node to keep the key.**
    ///
    /// The tests around this one call `conversation_to_keep` directly, so
    /// every one of them would still pass if the send path never asked. This
    /// is the one that pins the real path: a buyer who never opens a second
    /// tab must not have to do anything extra for the reply to survive.
    #[test]
    fn sending_a_message_asks_the_node_to_keep_the_conversation() {
        let mut state = buyer_state();
        state
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        let asked: Vec<&Vec<u8>> = state
            .pending_conversation_persists
            .values()
            .map(|(store_contract_id, _)| store_contract_id)
            .collect();
        assert_eq!(
            asked,
            vec![&STORE.to_vec()],
            "sending a message did not ask this node to keep the key that reads the reply"
        );
    }

    /// **The delegate files the conversation under the tag the mailbox
    /// carries.**
    ///
    /// This is the seam between the two crates. The delegate derives the
    /// routing tag from the secret it is sent rather than being told it, so
    /// what this browser sends decides the tag a later recall comes back
    /// under -- and if that were not the tag on the messages, recall would
    /// answer a conversation that reads an empty thread, with nothing
    /// anywhere reporting a fault.
    #[test]
    fn the_delegate_files_a_conversation_under_the_tag_the_mailbox_carries() {
        let mut state = buyer_state();
        let message = state
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        let keep = state
            .conversation_to_keep(STORE, &seller_public())
            .expect("must ask");
        let (secret, seller_public_key, conversation_id, _) = kept(&keep);

        assert_eq!(
            PublicKey::from(&StaticSecret::from(secret))
                .as_bytes()
                .to_vec(),
            message.sender_public_key,
            "the delegate would file this under a tag no message in the mailbox carries"
        );
        assert_eq!(
            seller_public_key,
            seller_public(),
            "recall derives against the stored seller key, so a wrong one is unreadable keys"
        );
        assert_eq!(conversation_id, message.conversation_id.0);
    }

    /// A recalled conversation is the one a new message continues, so a
    /// returning buyer writes into their existing thread rather than opening
    /// a second one beside it.
    #[test]
    fn a_new_message_continues_the_recalled_conversation() {
        let mut first_tab = buyer_state();
        let first = first_tab
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        let keep = first_tab
            .conversation_to_keep(STORE, &seller_public())
            .expect("must ask");

        let mut second_tab = buyer_state();
        deliver_recall(&mut second_tab, vec![delegate_recalls(&keep)]);
        let second = second_tab
            .compose_to_seller(STORE, &seller_public(), "still there?".into())
            .expect("compose");

        assert_eq!(
            first.sender_public_key, second.sender_public_key,
            "the returning buyer opened a new conversation instead of continuing theirs"
        );
        assert_eq!(first.conversation_id, second.conversation_id);
    }

    /// **Recall re-subscribes to the seller's mailbox.**
    ///
    /// Browsing a storefront deliberately does not subscribe -- that would
    /// advertise a standing interest in a seller's mailbox for a reader who
    /// never wrote to them. A non-empty recall is the evidence that this node
    /// HAS written, and without re-subscribing the buyer holds the key to a
    /// reply they never fetch.
    #[test]
    fn recalling_conversations_subscribes_to_the_sellers_mailbox() {
        let mut state = buyer_state();
        let keep = {
            let mut first_tab = buyer_state();
            first_tab
                .compose_to_seller(STORE, &seller_public(), "hello".into())
                .expect("compose");
            first_tab
                .conversation_to_keep(STORE, &seller_public())
                .expect("must ask")
        };
        assert!(
            state.browsing_stores[STORE].mailbox_contract_id.is_none(),
            "precondition: browsing alone subscribes to nothing"
        );

        deliver_recall(&mut state, vec![delegate_recalls(&keep)]);

        let mailbox = state.browsing_stores[STORE]
            .mailbox_contract_id
            .clone()
            .expect("the seller's mailbox must be subscribed to, or no reply is ever fetched");
        let expected = crate::gateway::mailbox_ops::mailbox_contract_key(
            &ed25519_dalek::VerifyingKey::from_bytes(&seller_identity()).expect("key"),
        )
        .expect("mailbox address");
        assert_eq!(mailbox, expected.id().as_bytes().to_vec());
    }

    /// An empty answer subscribes to nothing: a reader who has never written
    /// to this seller must not advertise an interest in their mailbox.
    #[test]
    fn recalling_nothing_subscribes_to_nothing() {
        let mut state = buyer_state();
        deliver_recall(&mut state, Vec::new());
        assert!(state.browsing_stores[STORE].mailbox_contract_id.is_none());
        assert!(state.mailbox_to_store.is_empty());
    }

    /// A store is asked once. Store state re-arrives on every update
    /// notification, and the answer cannot change between two of them.
    #[test]
    fn a_store_is_asked_for_its_kept_conversations_once() {
        let mut state = buyer_state();
        match state.buyer_conversations_to_recall(STORE) {
            Some(HarvestDelegateRequest::ListBuyerConversations {
                store_contract_id, ..
            }) => assert_eq!(store_contract_id, STORE),
            other => panic!("expected a recall, got {other:?}"),
        }
        assert!(
            state.buyer_conversations_to_recall(STORE).is_none(),
            "a second arrival of the same store state asked again"
        );
    }

    /// **Every conversation with the store is read, not just the newest.**
    ///
    /// A buyer who wrote last week and writes again today has two, and the
    /// older thread is where the reply they are waiting for is. Reading only
    /// the active one would lose it silently -- the messages stay visibly in
    /// the mailbox and simply never appear.
    #[test]
    fn every_conversation_with_a_store_is_read() {
        let mut old_tab = buyer_state();
        let old_question = old_tab
            .compose_to_seller(STORE, &seller_public(), "asked last week".into())
            .expect("compose");
        let kept_last_week = old_tab
            .conversation_to_keep(STORE, &seller_public())
            .expect("must ask");

        // Today: the buyer writes before the recall answer arrives, which is
        // the documented race -- so they open a SECOND conversation with the
        // same store. The older one must still be readable.
        let mut today = buyer_state();
        let new_question = today
            .compose_to_seller(STORE, &seller_public(), "asked today".into())
            .expect("compose");
        deliver_recall(
            &mut today,
            vec![RecalledConversation {
                // Older than anything opened in this tab, so it sorts first
                // and a further message still continues today's.
                created_at: 0,
                ..delegate_recalls(&kept_last_week)
            }],
        );
        assert_ne!(
            old_question.sender_public_key, new_question.sender_public_key,
            "precondition: these are two different conversations"
        );

        deliver(&mut today, old_question);
        deliver(&mut today, new_question);

        let thread = today.conversation_thread(STORE);
        let said: Vec<&str> = thread.iter().map(|m| text(&m.content)).collect();
        assert!(
            said.contains(&"asked last week") && said.contains(&"asked today"),
            "an older conversation with this store went unread: {said:?}"
        );
    }

    /// An answer nothing asked for contributes nothing.
    ///
    /// The same rule as the seller's `on_conversation_keys`: acting on an
    /// unrequested answer would let a stray or replayed message put
    /// conversations on screen that this browser never asked about.
    #[test]
    fn a_recall_answer_nothing_asked_for_is_ignored() {
        let mut state = buyer_state();
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationList {
            request_id: 9999,
            store_contract_id: STORE.to_vec(),
            conversations: vec![delegate_recalls(&{
                let mut tab = buyer_state();
                tab.compose_to_seller(STORE, &seller_public(), "hello".into())
                    .expect("compose");
                tab.conversation_to_keep(STORE, &seller_public())
                    .expect("must ask")
            })],
        });
        assert!(
            state.browsing_stores[STORE].conversations.is_empty(),
            "an answer nothing asked for put a conversation on screen"
        );
    }

    /// **Conversations are filed under the store this browser ASKED about,
    /// not the one the answer names.**
    ///
    /// The two can only disagree through a fault, and the consequence of
    /// trusting the echo is the sharp one: a buyer reading a thread, and
    /// composing into it, against the wrong seller's mailbox. Same lesson as
    /// the echoed conversation tag on the seller's side, where trusting
    /// position instead of the echo handed one buyer's key to another
    /// buyer's messages.
    #[test]
    fn conversations_are_filed_under_the_store_that_was_asked_about() {
        const ANOTHER_STORE: &[u8] = &[2u8; 32];
        let mut state = buyer_state();
        let keep = {
            let mut tab = buyer_state();
            tab.compose_to_seller(STORE, &seller_public(), "hello".into())
                .expect("compose");
            tab.conversation_to_keep(STORE, &seller_public())
                .expect("must ask")
        };

        let request_id = match state.buyer_conversations_to_recall(STORE) {
            Some(HarvestDelegateRequest::ListBuyerConversations { request_id, .. }) => request_id,
            other => panic!("expected a recall, got {other:?}"),
        };
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationList {
            request_id,
            // The delegate naming a store that was not asked about.
            store_contract_id: ANOTHER_STORE.to_vec(),
            conversations: vec![delegate_recalls(&keep)],
        });

        assert_eq!(
            state.browsing_stores[STORE].conversations.len(),
            1,
            "the conversation was not filed under the store that was asked about"
        );
        assert!(
            state
                .browsing_stores
                .get(ANOTHER_STORE)
                .is_none_or(|store| store.conversations.is_empty()),
            "a conversation was filed against a store this browser never asked about"
        );
    }

    /// **The NEWEST recalled conversation is the one a new message
    /// continues.**
    ///
    /// The sort that decides this had no test until it was reviewed:
    /// `a_new_message_continues_the_recalled_conversation` uses one recalled
    /// conversation, and `every_conversation_with_a_store_is_read` has two
    /// but only asserts both are readable. Deleting the sort left the suite
    /// green, and a returning buyer would then resume whichever the node
    /// happened to list last -- silently writing into an old thread while
    /// believing they had continued the current one.
    #[test]
    fn a_new_message_continues_the_newest_of_several_recalled_conversations() {
        let mut state = buyer_state();
        let keeps: Vec<HarvestDelegateRequest> = (0..2)
            .map(|_| {
                let mut tab = buyer_state();
                tab.compose_to_seller(STORE, &seller_public(), "hello".into())
                    .expect("compose");
                tab.conversation_to_keep(STORE, &seller_public())
                    .expect("must ask")
            })
            .collect();

        // Answered oldest-LAST, so a browser that kept the delegate's order
        // would continue the older one.
        let newer = RecalledConversation {
            created_at: 2_000,
            ..delegate_recalls(&keeps[0])
        };
        let older = RecalledConversation {
            created_at: 1_000,
            ..delegate_recalls(&keeps[1])
        };
        deliver_recall(&mut state, vec![newer.clone(), older.clone()]);

        let next = state
            .compose_to_seller(STORE, &seller_public(), "still there?".into())
            .expect("compose");
        assert_eq!(
            next.sender_public_key, newer.buyer_public_key,
            "a returning buyer resumed a thread that is not their most recent one"
        );
    }

    /// **A store is not marked as asked before there is anyone to ask.**
    ///
    /// `components::app` opens a store link BEFORE registering the harvest
    /// delegate, so a store's state routinely arrives first. Marking it asked
    /// on a request that was never sent would leave the buyer's kept
    /// conversations unrecalled for the life of the tab -- the reply sitting
    /// unread in the mailbox, with the key on the same machine, and nothing
    /// anywhere saying why.
    #[test]
    fn a_store_is_not_marked_asked_before_the_delegate_is_registered() {
        let mut state = buyer_state();
        state.harvest_delegate_key = None;
        assert!(
            state.buyer_conversations_to_recall(STORE).is_none(),
            "there is nobody to ask yet"
        );

        state.harvest_delegate_key = Some(a_delegate_key());
        assert!(
            state.buyer_conversations_to_recall(STORE).is_some(),
            "the store was marked as asked while the request could not be sent"
        );
    }

    /// And the sweep that covers that ordering asks for the stores already on
    /// screen.
    #[test]
    fn registering_the_delegate_asks_about_stores_already_on_screen() {
        let mut state = buyer_state();
        state.harvest_delegate_key = None;
        state.recall_conversations_for_known_stores();
        assert!(
            state.buyer_conversations_recalled.is_empty(),
            "precondition: nothing was asked, so nothing is marked"
        );

        state.harvest_delegate_key = Some(a_delegate_key());
        state.recall_conversations_for_known_stores();
        assert!(
            state.buyer_conversations_recalled.contains(STORE),
            "a store already on screen was never asked about"
        );
    }

    /// **A conversation the node could not keep is said out loud.**
    ///
    /// The buyer has already been told their message was sent. If the secret
    /// was not kept then the reply is unreadable after a reload -- which is
    /// exactly the failure this mechanism exists to prevent, so it must not
    /// happen quietly.
    #[test]
    fn a_conversation_the_node_could_not_keep_is_reported() {
        let mut state = buyer_state();
        state
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        let request_id = match state
            .conversation_to_keep(STORE, &seller_public())
            .expect("must ask")
        {
            HarvestDelegateRequest::StoreBuyerConversation { request_id, .. } => request_id,
            other => panic!("expected StoreBuyerConversation, got {other:?}"),
        };

        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationStored {
            request_id,
            result: Err("the node refused the write".to_string()),
            evicted: Vec::new(),
        });

        let notice = state
            .notifications
            .last()
            .expect("a refusal must reach the buyer");
        assert!(
            notice.contains("unreadable"),
            "the notice must say what the buyer loses: {notice}"
        );
    }

    /// **A conversation discarded to make room is said out loud.**
    ///
    /// The cap is global across every store, so keeping a new conversation
    /// can cost an old one -- and the design doc names silence here as the
    /// expensive direction: "the confession becomes unreadable and the buyer
    /// has no recourse, with no error at any layer".
    #[test]
    fn a_conversation_discarded_to_make_room_is_reported() {
        let mut state = buyer_state();
        let lost = [0x5Au8; 32];
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationStored {
            request_id: 1,
            result: Ok(()),
            evicted: vec![harvest_common::EvictedConversation {
                buyer_public_key: lost,
                was_backed_up: false,
            }],
        });

        let notice = state
            .notifications
            .last()
            .expect("a discarded conversation must reach the buyer")
            .clone();
        assert!(
            notice.contains(&crate::state::short_conversation_tag(&lost)),
            "the discarded conversation must be named: {notice}"
        );
        assert!(
            notice.contains("no longer be read"),
            "the buyer must be told it is gone for good, not merely tidied away: {notice}"
        );
    }

    /// One the buyer has a backup of is a different message: recoverable, so
    /// it must not read like the loss above.
    #[test]
    fn discarding_a_backed_up_conversation_says_it_can_be_restored() {
        let mut state = buyer_state();
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationStored {
            request_id: 1,
            result: Ok(()),
            evicted: vec![harvest_common::EvictedConversation {
                buyer_public_key: [0x77u8; 32],
                was_backed_up: true,
            }],
        });
        let notice = state.notifications.last().expect("must say something");
        assert!(notice.contains("restore"), "{notice}");
        assert!(
            !notice.contains("no longer be read"),
            "a recoverable loss must not be reported as a permanent one: {notice}"
        );
    }

    /// **A forgotten conversation leaves this browser only once the node says
    /// the record is gone.**
    ///
    /// Dropping it on the click would show a buyer a thread that had vanished
    /// while the record was still on their disk, which is the dishonesty the
    /// delete-rather-than-empty design exists to avoid.
    #[test]
    fn a_conversation_is_dropped_only_when_the_node_says_it_is_gone() {
        let mut state = buyer_state();
        let message = state
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        deliver(&mut state, message.clone());
        let tag: [u8; 32] = message
            .sender_public_key
            .clone()
            .try_into()
            .expect("32-byte tag");
        assert_eq!(state.conversation_thread(STORE).len(), 1, "precondition");

        // Refused: the record is still there, so the thread must be too.
        let request = state.conversation_to_forget(STORE, &tag);
        let request_id = match request {
            HarvestDelegateRequest::ForgetBuyerConversation { request_id, .. } => request_id,
            other => panic!("expected ForgetBuyerConversation, got {other:?}"),
        };
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationForgotten {
            request_id,
            result: Err("the node refused to remove it".to_string()),
        });
        assert_eq!(
            state.conversation_thread(STORE).len(),
            1,
            "a refused removal hid a conversation that is still stored"
        );
        assert!(state
            .notifications
            .last()
            .expect("a refusal must reach the buyer")
            .contains("still stored"));

        // Accepted: now it goes.
        let request_id = match state.conversation_to_forget(STORE, &tag) {
            HarvestDelegateRequest::ForgetBuyerConversation { request_id, .. } => request_id,
            other => panic!("expected ForgetBuyerConversation, got {other:?}"),
        };
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationForgotten {
            request_id,
            result: Ok(()),
        });
        assert!(
            state.conversation_thread(STORE).is_empty(),
            "a forgotten conversation was still on screen"
        );
    }

    /// An answer to a forget nothing asked for changes nothing.
    ///
    /// The same shape as `an_answer_to_an_unknown_request_is_ignored` on the
    /// seller's side: acting on it would drop a conversation this browser
    /// never asked to forget.
    #[test]
    fn an_unasked_forget_answer_drops_nothing() {
        let mut state = buyer_state();
        let message = state
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        deliver(&mut state, message);

        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationForgotten {
            request_id: 4321,
            result: Ok(()),
        });
        assert_eq!(
            state.conversation_thread(STORE).len(),
            1,
            "an answer nothing asked for dropped a conversation"
        );
    }
}

/// Backup: the buyer carrying ONE conversation to another machine, and being
/// told when it exists in only one place.
#[cfg(test)]
mod buyer_backup_tests {
    use super::*;
    use harvest_common::{HarvestDelegateRequest, ImportedConversation, RecalledConversation};
    use x25519_dalek::{PublicKey, StaticSecret};

    const STORE: &[u8] = &[1u8; 32];

    fn a_delegate_key() -> freenet_stdlib::prelude::DelegateKey {
        freenet_stdlib::prelude::DelegateKey::new(
            [0xA1; 32],
            freenet_stdlib::prelude::CodeHash::new([0xA1; 32]),
        )
    }

    fn buyer_state() -> AppState {
        let mut state = AppState {
            harvest_delegate_key: Some(a_delegate_key()),
            ..AppState::default()
        };
        state.browsing_stores.entry(STORE.to_vec()).or_default();
        state
    }

    /// One recalled conversation, as the delegate would answer it.
    fn recalled(seed: u8, backed_up: bool) -> RecalledConversation {
        let secret = StaticSecret::from([seed; 32]);
        RecalledConversation {
            buyer_public_key: *PublicKey::from(&secret).as_bytes(),
            conversation_id: [seed; 32],
            buyer_to_seller: [seed; 32],
            seller_to_buyer: [seed; 32],
            order_binding: harvest_common::mailbox::order_binding_from_secret(&[seed; 32]),
            created_at: 1_700_000_000 + seed as i64,
            imported: false,
            backed_up,
        }
    }

    /// The request id of a question this state actually asked.
    fn asked(request: &HarvestDelegateRequest) -> u64 {
        match request {
            HarvestDelegateRequest::ExportBuyerConversation { request_id, .. }
            | HarvestDelegateRequest::MarkConversationBackedUp { request_id, .. } => *request_id,
            other => panic!("expected a backup request, got {other:?}"),
        }
    }

    /// Answer the recall this state actually issued.
    fn deliver_recall(state: &mut AppState, conversations: Vec<RecalledConversation>) {
        match state.buyer_conversations_to_recall(STORE) {
            Some(HarvestDelegateRequest::ListBuyerConversations { .. }) => {}
            other => panic!("expected a recall to be asked for, got {other:?}"),
        }
        answer_outstanding_recall(state, conversations);
    }

    /// Answer whichever recall is in flight, whoever asked for it -- which is
    /// how a re-ask issued by the app itself gets answered.
    fn answer_outstanding_recall(state: &mut AppState, conversations: Vec<RecalledConversation>) {
        let request_id = *state
            .pending_conversation_recalls
            .keys()
            .next_back()
            .expect("a recall must be in flight");
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationList {
            request_id,
            store_contract_id: STORE.to_vec(),
            conversations,
        });
    }

    /// **A backup the buyer asked for reaches the screen, under the
    /// conversation they asked about.**
    ///
    /// It arrives from a delegate answer long after the click, so it has to
    /// be held somewhere the component can render from -- and one string
    /// covers ONE conversation, so it must not appear under another.
    #[test]
    fn an_exported_backup_reaches_the_screen_under_its_own_conversation() {
        let mut state = buyer_state();
        let tag = recalled(5, false).buyer_public_key;
        let request = state.conversation_to_export(STORE, &tag);
        match &request {
            HarvestDelegateRequest::ExportBuyerConversation {
                store_contract_id,
                buyer_public_key,
                ..
            } => {
                assert_eq!(store_contract_id, STORE);
                assert_eq!(buyer_public_key, &tag);
            }
            other => panic!("expected ExportBuyerConversation, got {other:?}"),
        }

        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationExported {
            request_id: asked(&request),
            store_contract_id: STORE.to_vec(),
            buyer_public_key: tag,
            result: Ok("harvest-conv-backup-v2:abc".to_string()),
        });

        let on_screen = state
            .conversation_backup_on_screen
            .as_ref()
            .expect("the backup must reach the screen, or the buyer cannot save it");
        assert_eq!(on_screen.text(), "harvest-conv-backup-v2:abc");
        assert_eq!(on_screen.store_contract_id, STORE);
        assert_eq!(
            on_screen.buyer_public_key, tag,
            "a backup shown under the wrong conversation invites the buyer to save it as that \
             conversation's"
        );
    }

    /// **A backup does not print itself.**
    ///
    /// It is a portable copy of one conversation. A `Debug` that printed it
    /// would put that into any console log a user pastes into a bug report.
    #[test]
    fn a_backup_on_screen_does_not_print_itself() {
        let mut state = buyer_state();
        let tag = recalled(6, false).buyer_public_key;
        let request_id = asked(&state.conversation_to_export(STORE, &tag));
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationExported {
            request_id,
            store_contract_id: STORE.to_vec(),
            buyer_public_key: tag,
            result: Ok("harvest-conv-backup-v2:SECRETMATERIAL".to_string()),
        });
        let printed = format!("{:?}", state.conversation_backup_on_screen);
        assert!(
            !printed.contains("SECRETMATERIAL"),
            "the backup printed itself: {printed}"
        );
    }

    /// A refused export is said out loud rather than leaving a button that
    /// appears to do nothing.
    #[test]
    fn a_refused_export_is_reported() {
        let mut state = buyer_state();
        let tag = recalled(7, false).buyer_public_key;
        let request_id = asked(&state.conversation_to_export(STORE, &tag));
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationExported {
            request_id,
            store_contract_id: STORE.to_vec(),
            buyer_public_key: tag,
            result: Err("this node does not hold that conversation".to_string()),
        });
        assert!(state.conversation_backup_on_screen.is_none());
        assert!(state
            .notifications
            .last()
            .expect("a refusal must reach the buyer")
            .contains("does not hold"));
    }

    /// **Marking names ONE conversation.**
    ///
    /// One saved string covers one conversation, so a request that named a
    /// set would clear the warning on conversations the string does not
    /// contain -- the granularity form of silencing a warning about a key
    /// nobody has a backup of.
    #[test]
    fn marking_names_only_the_conversation_that_was_saved() {
        let mut state = buyer_state();
        let saved = recalled(5, false);
        let other = recalled(6, false);
        deliver_recall(&mut state, vec![saved.clone(), other.clone()]);

        match state.conversation_to_mark_backed_up(STORE, &saved.buyer_public_key) {
            HarvestDelegateRequest::MarkConversationBackedUp {
                store_contract_id,
                buyer_public_key,
                ..
            } => {
                assert_eq!(store_contract_id, STORE);
                assert_eq!(buyer_public_key, saved.buyer_public_key);
                assert_ne!(buyer_public_key, other.buyer_public_key);
            }
            other => panic!("expected MarkConversationBackedUp, got {other:?}"),
        }
    }

    /// **A recall refreshes the warning on a conversation this browser
    /// already holds.**
    ///
    /// The delegate is the source of truth for whether a backup exists, and
    /// marking is confirmed by asking it again rather than by assuming
    /// locally. A recall that only ADDED conversations would leave the
    /// warning on screen after the buyer had cleared it.
    #[test]
    fn a_recall_refreshes_whether_a_held_conversation_is_backed_up() {
        let mut state = buyer_state();
        let conversation = recalled(7, false);
        deliver_recall(&mut state, vec![conversation.clone()]);
        assert!(!state.browsing_stores[STORE].conversations[0].backed_up);

        // The whole marking round trip: the buyer says they saved it, the
        // delegate confirms, and the app asks again rather than assuming.
        let request_id =
            asked(&state.conversation_to_mark_backed_up(STORE, &conversation.buyer_public_key));
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationMarkedBackedUp {
            request_id,
            store_contract_id: STORE.to_vec(),
            buyer_public_key: conversation.buyer_public_key,
            result: Ok(true),
        });
        answer_outstanding_recall(
            &mut state,
            vec![RecalledConversation {
                backed_up: true,
                ..conversation
            }],
        );

        assert_eq!(
            state.browsing_stores[STORE].conversations.len(),
            1,
            "a second recall duplicated a conversation"
        );
        assert!(
            state.browsing_stores[STORE].conversations[0].backed_up,
            "the warning stayed after the buyer said they had saved it"
        );
    }

    /// Marking asks the delegate again afterwards, rather than guessing what
    /// it did.
    #[test]
    fn marking_asks_the_delegate_again_rather_than_assuming() {
        let mut state = buyer_state();
        let conversation = recalled(8, false);
        deliver_recall(&mut state, vec![conversation.clone()]);
        assert!(
            state.buyer_conversations_recalled.contains(STORE),
            "precondition: this store has been asked about"
        );

        let request_id =
            asked(&state.conversation_to_mark_backed_up(STORE, &conversation.buyer_public_key));
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationMarkedBackedUp {
            request_id,
            store_contract_id: STORE.to_vec(),
            buyer_public_key: conversation.buyer_public_key,
            result: Ok(true),
        });
        assert!(
            !state.pending_conversation_recalls.is_empty(),
            "nothing re-asked the delegate, so the screen still shows what it showed before"
        );
    }

    /// **A restored conversation is asked for again, so it appears.**
    ///
    /// Import writes into the delegate, not into this browser. Without the
    /// re-ask the buyer pastes a backup, is told it worked, and sees nothing.
    #[test]
    fn an_import_asks_for_the_restored_conversation() {
        let mut state = buyer_state();
        deliver_recall(&mut state, Vec::new());
        assert!(
            state.pending_conversation_recalls.is_empty(),
            "precondition: nothing is in flight"
        );

        let tag = recalled(9, true).buyer_public_key;
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationImported {
            request_id: 1,
            result: Ok(ImportedConversation::Imported {
                store_contract_id: STORE.to_vec(),
                buyer_public_key: tag,
            }),
        });

        assert!(
            !state.pending_conversation_recalls.is_empty(),
            "a restored conversation was never asked for, so it never appears on screen"
        );
        let notice = state
            .notifications
            .last()
            .expect("the buyer must be told what the paste did");
        assert!(
            notice.contains(&crate::state::short_conversation_tag(&tag)),
            "the restored conversation must be named: {notice}"
        );
        assert!(
            notice.contains("whoever gave it to you"),
            "a restored conversation may be the one the next message continues, and its secret \
             may not be the buyer's alone: {notice}"
        );
    }

    /// **A refused conversation is NAMED with its reason.**
    ///
    /// A conversation that did not fit is one the buyer still cannot read,
    /// and the reason is what tells them what to do about it.
    #[test]
    fn a_refused_import_says_which_and_why() {
        let mut state = buyer_state();
        let refused = recalled(10, true).buyer_public_key;
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationImported {
            request_id: 1,
            result: Ok(ImportedConversation::Refused {
                store_contract_id: STORE.to_vec(),
                buyer_public_key: refused,
                why: "this node is full".to_string(),
            }),
        });

        let notice = state
            .notifications
            .last()
            .expect("the buyer must be told")
            .clone();
        assert!(
            notice.contains("this node is full"),
            "the reason must survive to the buyer: {notice}"
        );
        assert!(
            notice.contains(&crate::state::short_conversation_tag(&refused)),
            "the refused conversation must be named: {notice}"
        );
    }

    /// A backup that is not one is refused with something the buyer can act
    /// on, rather than silently.
    #[test]
    fn a_paste_that_could_not_be_read_is_reported() {
        let mut state = buyer_state();
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationImported {
            request_id: 1,
            result: Err("that does not look like a Harvest conversation backup".to_string()),
        });
        assert!(state
            .notifications
            .last()
            .expect("a refusal must reach the buyer")
            .contains("does not look like"));
    }

    /// Pasting a backup onto the node that made it must read as success, not
    /// as a problem.
    #[test]
    fn a_backup_pasted_onto_the_node_that_made_it_is_not_an_error() {
        let mut state = buyer_state();
        let held = recalled(12, true).buyer_public_key;
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationImported {
            request_id: 1,
            result: Ok(ImportedConversation::AlreadyHeld {
                store_contract_id: STORE.to_vec(),
                buyer_public_key: held,
            }),
        });
        let notice = state.notifications.last().expect("must say something");
        assert!(
            notice.contains("already"),
            "the buyer must be told nothing was wrong: {notice}"
        );
    }

    /// **A backup nothing asked for does not reach the screen.**
    ///
    /// Where it belongs is decided by the question this browser asked and not
    /// by what the answer says about itself.
    #[test]
    fn a_backup_nothing_asked_for_does_not_reach_the_screen() {
        let mut state = buyer_state();
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationExported {
            request_id: 4321,
            store_contract_id: STORE.to_vec(),
            buyer_public_key: [9u8; 32],
            result: Ok("harvest-conv-backup-v2:abc".to_string()),
        });
        assert!(
            state.conversation_backup_on_screen.is_none(),
            "a backup nothing asked for was put on screen"
        );
    }

    /// And it is filed under the conversation that was asked about, not the
    /// one the answer names.
    #[test]
    fn a_backup_is_filed_under_the_conversation_that_was_asked_about() {
        const ANOTHER_STORE: &[u8] = &[2u8; 32];
        let mut state = buyer_state();
        let asked_about = recalled(13, false).buyer_public_key;
        let request_id = asked(&state.conversation_to_export(STORE, &asked_about));
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationExported {
            request_id,
            store_contract_id: ANOTHER_STORE.to_vec(),
            buyer_public_key: [0xFF; 32],
            result: Ok("harvest-conv-backup-v2:abc".to_string()),
        });
        let on_screen = state
            .conversation_backup_on_screen
            .as_ref()
            .expect("on screen");
        assert_eq!(
            on_screen.store_contract_id, STORE,
            "a backup was filed under a store this browser never asked about"
        );
        assert_eq!(
            on_screen.buyer_public_key, asked_about,
            "a backup was filed under a conversation this browser never asked about"
        );
    }
}

/// What a counterparty can do with a nonce, and what the client may claim
/// afterwards.
///
/// The conversation key is symmetric -- the counterparty must hold it to read
/// replies at all -- so they can always produce anything the buyer could.
/// Authorship BETWEEN the two parties is therefore not attainable by
/// cryptography here, and `message_aad` does not help: it binds the nonce to
/// the ciphertext, and the counterparty can produce a valid binding for
/// content of their choosing.
///
/// What IS available is first-hand knowledge: this client knows the exact
/// bytes it sent. These tests pin that it uses that knowledge and nothing
/// weaker.
#[cfg(test)]
mod nonce_collision_tests {
    use super::*;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use harvest_common::mailbox::{
        conversation_key_from_dh, entry_digest, message_aad, pad_to_bucket, EncryptedMessage,
        MailboxStateV1, MessageDirection,
    };
    use x25519_dalek::{PublicKey, StaticSecret};

    const STORE: &[u8] = &[1u8; 32];

    fn seller_secret() -> StaticSecret {
        StaticSecret::from([21u8; 32])
    }

    fn seller_public() -> [u8; 32] {
        *PublicKey::from(&seller_secret()).as_bytes()
    }

    fn buyer_state() -> AppState {
        let mut state = AppState::default();
        state.browsing_stores.entry(STORE.to_vec()).or_default();
        state
    }

    /// The seller's side of one conversation.
    fn seller_keys(buyer_public_key: &[u8]) -> crate::messaging::ConversationKeys {
        let peer: [u8; 32] = buyer_public_key.try_into().expect("32-byte tag");
        let shared = seller_secret()
            .diffie_hellman(&PublicKey::from(peer))
            .to_bytes();
        crate::messaging::ConversationKeys::from_shared_secret(&shared)
    }

    /// **The attack.** Take a message the buyer sent, put different plaintext
    /// under the SAME nonce and the same conversation key, and date it one
    /// second later -- which is what the contract's dedup used to prefer,
    /// before identity moved to `entry_digest` and the two stopped colliding
    /// at all.
    ///
    /// Built here rather than through `messaging::seal`, which draws a fresh
    /// nonce -- that is exactly what an attacker declines to do. The attempt
    /// is still worth driving: it no longer displaces anything, and these
    /// tests are what say so.
    fn substitute(original: &EncryptedMessage, text: &str) -> EncryptedMessage {
        let keys = seller_keys(&original.sender_public_key);
        let plaintext = crate::messaging::PlaintextMessage {
            conversation_id: original.conversation_id.clone(),
            content: crate::messaging::MessageContent::Text(text.to_string()),
        };
        let padded = pad_to_bucket(&harvest_common::to_cbor(&plaintext).expect("cbor"));
        let timestamp = original.timestamp + chrono::Duration::seconds(1);
        let aad = message_aad(
            &original.conversation_id,
            &original.sender_public_key,
            &timestamp,
            &original.nonce,
        );
        let cipher = Aes256Gcm::new_from_slice(&keys.to_seller).expect("cipher");
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&original.nonce[..12]),
                Payload {
                    msg: padded.as_ref(),
                    aad: &aad,
                },
            )
            .expect("encrypt");
        EncryptedMessage {
            conversation_id: original.conversation_id.clone(),
            sender_public_key: original.sender_public_key.clone(),
            ciphertext,
            timestamp,
            nonce: original.nonce,
        }
    }

    /// Put messages through the REAL contract, so what the buyer sees is what
    /// the mailbox would actually hold -- including the dedup that resolves a
    /// nonce collision.
    fn mailbox_after(messages: Vec<EncryptedMessage>) -> Vec<EncryptedMessage> {
        let mut state = MailboxStateV1::default();
        state.apply_delta(&Some(messages)).expect("apply");
        state
            .verify()
            .expect("the contract must accept its own result");
        state.messages
    }

    fn text(content: &crate::messaging::MessageContent) -> &str {
        match content {
            crate::messaging::MessageContent::Text(text) => text,
            other => panic!("expected text, got {other:?}"),
        }
    }

    /// **A substituted message must not be shown as the buyer's own.**
    ///
    /// `683feb0` moved attribution off the channel and onto first-hand
    /// knowledge -- "the one thing a client can know is what it sent itself".
    /// Recognising that by NONCE puts it straight back onto something the
    /// counterparty controls: the nonce is public, and the counterparty can
    /// submit different plaintext under it. Losing a message you sent is bad;
    /// being shown a stranger's words as your own is worse.
    #[test]
    fn a_substituted_message_is_not_shown_as_the_buyers_own() {
        let mut buyer = buyer_state();
        let mine = buyer
            .compose_to_seller(STORE, &seller_public(), "please cancel my order".into())
            .expect("compose");
        // As `components::message_view::send` does once the send is
        // dispatched.
        buyer.record_sent_message(STORE, "please cancel my order".into(), &mine);

        // Precondition: my own message, in the mailbox, reads as mine.
        buyer
            .browsing_stores
            .get_mut(STORE)
            .expect("store")
            .mailbox_messages = mailbox_after(vec![mine.clone()]);
        let thread = buyer.conversation_thread(STORE);
        assert_eq!(thread.len(), 1);
        assert!(
            buyer.authored_here(STORE, &thread[0].digest),
            "precondition: a message this tab sent reads as its own"
        );

        // The seller submits different words under the same nonce.
        let theirs = substitute(&mine, "actually, never mind, cancel it");
        let mailbox = mailbox_after(vec![mine.clone(), theirs.clone()]);
        assert_eq!(
            mailbox.len(),
            2,
            "the substitute displaced the original, so a message can still be retracted"
        );
        buyer
            .browsing_stores
            .get_mut(STORE)
            .expect("store")
            .mailbox_messages = mailbox;

        let thread = buyer.conversation_thread(STORE);
        assert_eq!(
            thread.len(),
            2,
            "the buyer's own message is missing from their own thread"
        );

        let mine_shown = thread
            .iter()
            .find(|message| text(&message.content) == "please cancel my order")
            .expect("the buyer's own message must still be readable");
        assert!(
            buyer.authored_here(STORE, &mine_shown.digest),
            "the buyer's own message stopped being recognised as theirs"
        );

        let theirs_shown = thread
            .iter()
            .find(|message| text(&message.content) == "actually, never mind, cancel it")
            .expect("the substitute is in the mailbox and is shown");
        assert!(
            !buyer.authored_here(STORE, &theirs_shown.digest),
            "the buyer's own UI credited them with words the seller wrote"
        );
    }

    /// **A message someone submitted under is not reported as undelivered,
    /// because it was not displaced.**
    ///
    /// There used to be a `replaced_sent` here, reporting a message whose
    /// nonce was present under different bytes: it had arrived and then been
    /// displaced by the contract's dedup. That state can no longer arise, so
    /// it was deleted rather than left rendering a case that cannot happen.
    ///
    /// It was not repointed at "an entry shares your nonce" either, and the
    /// reason is worth keeping: that signal is FORGEABLE. The mailbox is
    /// open-write and the nonce is public, so any third party can plant an
    /// unreadable entry under it, and a "somebody tampered with your message"
    /// notice driven by that would be one an outsider could trigger against a
    /// seller they have never dealt with.
    #[test]
    fn a_message_someone_submitted_under_is_not_reported_as_undelivered() {
        let mut buyer = buyer_state();
        let mine = buyer
            .compose_to_seller(STORE, &seller_public(), "please cancel my order".into())
            .expect("compose");
        buyer.record_sent_message(STORE, "please cancel my order".into(), &mine);

        // Before anything lands, it is simply not seen yet.
        assert_eq!(buyer.unconfirmed_sent(STORE).len(), 1);

        let theirs = substitute(&mine, "actually, never mind, cancel it");
        buyer
            .browsing_stores
            .get_mut(STORE)
            .expect("store")
            .mailbox_messages = mailbox_after(vec![mine.clone(), theirs]);

        assert!(
            buyer.unconfirmed_sent(STORE).is_empty(),
            "the buyer's message is in the mailbox and was reported as not yet arrived"
        );
    }

    /// **A message that is NOT in the mailbox stays unconfirmed, even when
    /// something else holds its nonce.**
    ///
    /// The neighbouring test puts BOTH entries in the mailbox, so the nonce
    /// rule and the digest rule agree and it cannot see the difference --
    /// the same fixture shape that let the re-store guard go unpinned. This
    /// one puts only the substitute there.
    ///
    /// The failure it forbids is narrow and composes with the one retraction
    /// route still open: the buyer's message lands, a funded flood evicts it
    /// while a same-nonce entry planted earlier survives, and the UI reports
    /// the message as delivered when it is gone.
    #[test]
    fn a_message_absent_from_the_mailbox_is_unconfirmed_even_if_its_nonce_is_there() {
        let mut buyer = buyer_state();
        let mine = buyer
            .compose_to_seller(STORE, &seller_public(), "please cancel my order".into())
            .expect("compose");
        buyer.record_sent_message(STORE, "please cancel my order".into(), &mine);

        // Only THEIRS reaches the mailbox: same nonce, different bytes.
        let theirs = substitute(&mine, "actually, never mind, cancel it");
        buyer
            .browsing_stores
            .get_mut(STORE)
            .expect("store")
            .mailbox_messages = mailbox_after(vec![theirs]);

        assert_eq!(
            buyer.unconfirmed_sent(STORE).len(),
            1,
            "a message that is not in the mailbox was reported as delivered, because \
             something else holds its nonce"
        );
    }

    /// The ordinary case still works: a message that landed unaltered is not
    /// reported as unconfirmed.
    #[test]
    fn a_message_that_landed_is_not_reported_as_unconfirmed() {
        let mut buyer = buyer_state();
        let mine = buyer
            .compose_to_seller(STORE, &seller_public(), "hello".into())
            .expect("compose");
        buyer.record_sent_message(STORE, "hello".into(), &mine);
        buyer
            .browsing_stores
            .get_mut(STORE)
            .expect("store")
            .mailbox_messages = mailbox_after(vec![mine]);

        assert!(buyer.unconfirmed_sent(STORE).is_empty());
    }

    /// The seller's inbox is the same defect from the other side: their own
    /// replies are recorded by the same mechanism, so a buyer can substitute
    /// one and inherit the seller's "you wrote this" label.
    #[test]
    fn a_seller_is_not_credited_with_a_substituted_reply() {
        let mut seller = AppState::default();
        seller.my_stores.insert(
            "fp1".to_string(),
            vec![StoreRegistration {
                store_contract_id: STORE.to_vec(),
                reputation_contract_id: vec![3u8; 32],
                mailbox_contract_id: vec![4u8; 32],
                store_contract_key: None,
            }],
        );
        seller.browsing_stores.entry(STORE.to_vec()).or_default();

        // A buyer's conversation, and the seller's reply into it.
        let buyer = crate::messaging::BuyerConversation::open(&seller_public()).expect("open");
        let question = buyer.seal("do you ship?".into()).expect("seal");
        let keys = seller_keys(&question.sender_public_key);
        seller
            .conversation_keys
            .insert(question.sender_public_key.clone(), keys);
        let reply = crate::messaging::seal_reply(
            &keys,
            &question.sender_public_key,
            &question.conversation_id,
            "yes, ten euro".into(),
        )
        .expect("seal reply");
        seller.record_sent_message(STORE, "yes, ten euro".into(), &reply);

        // The buyer substitutes the seller's reply, under the seller's own
        // nonce, with something the seller never said.
        let forged = substitute(&reply, "I confess to everything");
        seller
            .browsing_stores
            .get_mut(STORE)
            .expect("store")
            .mailbox_messages = mailbox_after(vec![question, reply, forged]);

        let inbox = seller.mailbox_entries(STORE);
        let substituted = inbox
            .iter()
            .find(|entry| match entry {
                crate::messaging::MailboxEntry::Readable { content, .. } => {
                    matches!(content, crate::messaging::MessageContent::Text(t) if t == "I confess to everything")
                }
                _ => false,
            })
            .expect("the substitute is in the mailbox");
        assert!(
            !seller.authored_here(STORE, &substituted.digest()),
            "the seller's own inbox credited them with a confession they did not write"
        );
        // And their real reply is still there, which is the half the contract
        // now guarantees: the buyer could add words, never remove them.
        assert!(
            inbox.iter().any(|entry| match entry {
                crate::messaging::MailboxEntry::Readable { content, .. } => {
                    matches!(content, crate::messaging::MessageContent::Text(t) if t == "yes, ten euro")
                }
                _ => false,
            }),
            "the seller's own reply was removed from their own mailbox"
        );
        assert!(seller.unconfirmed_sent(STORE).is_empty());
    }
}

/// The buy flow, from the buyer's side: what has to be true before their
/// software will let them part with money.
///
/// `docs/design/incentive-mechanism.md` Part 5 steps 3 and 5, and the
/// ordering constraint recorded in `docs/buyer-conversation-persistence.md`:
/// the buyer persists what protects them, confirms the persistence, and only
/// then pays.
#[cfg(test)]
mod buy_flow_tests {
    use super::invoice_tests::{anchor, tip_at, TIP_HEIGHT};
    use super::*;
    use crate::messaging::{BuyerConversation, ConversationKeys};
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_bitcoin_common::BitcoinNetwork;
    use harvest_common::listing::ListingId;
    use harvest_common::mailbox::EncryptedMessage;
    use harvest_common::payment::{
        AuthorizedOrder, Order, OrderId, OrderStatus, MAX_ANCHOR_AGE_BLOCKS,
    };
    use x25519_dalek::{PublicKey, StaticSecret};

    const STORE: &[u8] = &[7u8; 32];

    /// A real signet address, the BIP-173 test vector this repository already
    /// uses in `components::bitcoin_view`.
    ///
    /// The fixture's `payment_script_pubkey` is DERIVED from it rather than
    /// written out, so the two cannot drift into the disagreement that
    /// `PaymentBlocker::DestinationDisagrees` exists to refuse -- which would
    /// otherwise make every fixture here unpayable for a reason unrelated to
    /// what the test is about.
    const PAYMENT_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    /// A different, equally valid signet address (the BIP-173 P2WSH vector),
    /// for the case where the two disagree.
    const ANOTHER_ADDRESS: &str = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";

    fn script_of(address: &str) -> Vec<u8> {
        crate::gateway::bitcoin_address::address_to_script_pubkey(address, BitcoinNetwork::Signet)
            .expect("a known-good signet address")
    }

    /// Re-stamp and re-sign a commitment whose terms a test has edited.
    ///
    /// Both halves are needed and forgetting either is a test that passes for
    /// the wrong reason: the id is derived from the terms, and the signature
    /// is over them.
    fn resigned(mut order: AuthorizedOrder, signing_key: &SigningKey) -> AuthorizedOrder {
        use freenet_stdlib::prelude::ContractInstanceId;

        order.order = order.order.with_derived_id();
        let message = harvest_common::to_cbor(&order.order).expect("serialize order");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        order.scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        order.signature = signing_key.sign(&order.scoped_payload).to_bytes().to_vec();
        order
    }

    fn seller_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[21u8; 32])
    }

    fn seller_encryption_secret() -> StaticSecret {
        StaticSecret::from([22u8; 32])
    }

    fn seller_encryption_key() -> [u8; 32] {
        *PublicKey::from(&seller_encryption_secret()).as_bytes()
    }

    /// The keys the seller's delegate would answer for one conversation tag.
    /// Built from the raw X25519 secret rather than from `BuyerConversation`,
    /// so a test cannot pass because the two halves drifted together.
    fn seller_keys_for(tag: &[u8; 32]) -> ConversationKeys {
        let shared = seller_encryption_secret()
            .diffie_hellman(&PublicKey::from(*tag))
            .to_bytes();
        ConversationKeys::from_shared_secret(&shared)
    }

    /// A published commitment, signed the way the invoice flow signs one.
    ///
    /// `what` varies the listing, and therefore the order id, so a test can
    /// hold two distinct commitments from one seller.
    fn commitment_for(
        what: &str,
        signing_key: &SigningKey,
        anchor_at: Option<freenet_bitcoin_common::BlockAnchor>,
        status: OrderStatus,
        order_binding: Option<[u8; 32]>,
    ) -> AuthorizedOrder {
        use freenet_stdlib::prelude::ContractInstanceId;

        let created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("timestamp");
        let listing_id = ListingId::from_label(what);
        let order = Order {
            id: OrderId([0u8; 32]),
            listing_id,
            // Empty, and that is the point: a buyer has no identity to name.
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller-fp".to_string(),
            amount_sats: 50_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: script_of(PAYMENT_ADDRESS),
            payment_address: PAYMENT_ADDRESS.to_string(),
            required_confirmations: 1,
            payment_hash: None,
            // The bridge this build actually trusts, derived rather than
            // invented: an invoice naming any other is refused
            // (`PaymentBlocker::BridgeNotRecognised`), so a made-up id here
            // would make every fixture unpayable.
            trusted_bridges: crate::gateway::bitcoin_config::default_trusted_bridges(
                BitcoinNetwork::Signet,
            )
            .expect("the build's own bridge constant must parse"),
            bitcoin_address_code_hash: Some([4u8; 32]),
            anchor: anchor_at,
            order_binding,
            created_at,
        }
        .with_derived_id();
        let message = harvest_common::to_cbor(&order).expect("serialize order");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        let signature = signing_key.sign(&scoped_payload).to_bytes().to_vec();
        AuthorizedOrder {
            order,
            scoped_payload,
            signature,
            status,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// [`commitment_for`] with a binding of the caller's choosing.
    fn commitment_bound_to(
        signing_key: &SigningKey,
        anchor_at: Option<freenet_bitcoin_common::BlockAnchor>,
        status: OrderStatus,
        order_binding: Option<[u8; 32]>,
    ) -> AuthorizedOrder {
        commitment_for("Widget", signing_key, anchor_at, status, order_binding)
    }

    /// The conversation every single-buyer test uses.
    ///
    /// Fixed rather than random so a commitment fixture can be bound to it
    /// without threading the conversation through every call.
    fn the_buyers_conversation() -> BuyerConversation {
        BuyerConversation::opened_from_secret_for_test(&[41u8; 32], &seller_encryption_key())
            .expect("open")
    }

    /// [`commitment_for`] with the listing every single-order test uses,
    /// bound to [`the_buyers_conversation`].
    fn commitment(
        signing_key: &SigningKey,
        anchor_at: Option<freenet_bitcoin_common::BlockAnchor>,
        status: OrderStatus,
    ) -> AuthorizedOrder {
        commitment_for(
            "Widget",
            signing_key,
            anchor_at,
            status,
            Some(the_buyers_conversation().order_binding()),
        )
    }

    /// An `AppState` browsing `STORE`, and a conversation with a fresh
    /// ephemeral secret. The state does not yet hold the conversation --
    /// [`buyer_holding`] is what puts them together.
    fn buyer_conversation() -> (AppState, BuyerConversation) {
        let mut state = AppState::default();
        state
            .bitcoin
            .tips
            .insert(BitcoinNetwork::Signet, tip_at(TIP_HEIGHT));
        state.begin_browsing(STORE.to_vec());
        (
            state,
            BuyerConversation::open(&seller_encryption_key()).expect("open"),
        )
    }

    /// Move a commitment to `Cancelled`, signed the way the contract demands
    /// -- over `(order id, status)`, not over the order terms.
    fn cancel(order: &mut AuthorizedOrder, signing_key: &SigningKey) {
        use freenet_stdlib::prelude::ContractInstanceId;

        order.status = OrderStatus::Cancelled;
        let message = harvest_common::to_cbor(&(order.order.id.clone(), order.status))
            .expect("serialize the status");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        order.status_signature = Some(signing_key.sign(&scoped_payload).to_bytes().to_vec());
        order.status_scoped_payload = Some(scoped_payload);
    }

    /// Put a buyer, their conversation and one published commitment together,
    /// with the seller's acceptance already in the mailbox.
    ///
    /// `kept` is whether this node's delegate has confirmed it is keeping the
    /// conversation. It is a parameter rather than something a test pokes
    /// afterwards, so `mark_kept` stays reachable only from the delegate's
    /// own answer.
    fn buyer_holding_with(
        mut state: AppState,
        mut conversation: BuyerConversation,
        published: &AuthorizedOrder,
        kept: bool,
    ) -> AppState {
        let tag = conversation.buyer_public_key;
        if kept {
            conversation.mark_kept();
        }
        let acceptance = crate::messaging::seal_order_accepted(
            &seller_keys_for(&tag),
            &tag,
            &conversation.conversation_id,
            &published.order.id,
        )
        .expect("the seller seals their acceptance");

        let store = state
            .browsing_stores
            .get_mut(STORE)
            .expect("begin_browsing creates it");
        store.seller_verifying_key = Some(seller_signing_key().verifying_key().to_bytes());
        store.orders = vec![published.clone()];
        store.conversations = vec![conversation];
        store.mailbox_messages = vec![acceptance];
        state
    }

    /// [`buyer_holding_with`] for the ordinary case: the node has confirmed
    /// it is keeping the conversation.
    fn buyer_holding(
        state: AppState,
        conversation: BuyerConversation,
        published: &AuthorizedOrder,
    ) -> AppState {
        buyer_holding_with(state, conversation, published, true)
    }

    /// A buyer who has asked to buy, been accepted, and whose node has
    /// confirmed it is keeping the conversation. Everything each test below
    /// does is to take one of those away.
    fn buyer_after_acceptance(commitment: &AuthorizedOrder) -> (AppState, [u8; 32]) {
        buyer_after_acceptance_with(commitment, true)
    }

    fn buyer_after_acceptance_with(
        commitment: &AuthorizedOrder,
        kept: bool,
    ) -> (AppState, [u8; 32]) {
        let (state, _) = buyer_conversation();
        let conversation = the_buyers_conversation();
        let tag = conversation.buyer_public_key;
        (
            buyer_holding_with(state, conversation, commitment, kept),
            tag,
        )
    }

    fn purchases(state: &AppState) -> Vec<BuyerPurchase> {
        state.buyer_purchases(STORE)
    }

    /// The seller's half: a store they own, a buyer's request already in
    /// their mailbox, and the conversation key their delegate answered.
    fn seller_holding_a_request() -> (AppState, [u8; 32], EncryptedMessage) {
        use crate::messaging::BuyerConversation;

        let mut state = AppState::default();
        state.my_stores.insert(
            "seller-fp".to_string(),
            vec![StoreRegistration {
                store_contract_id: STORE.to_vec(),
                reputation_contract_id: vec![10u8; 32],
                mailbox_contract_id: vec![11u8; 32],
                store_contract_key: None,
            }],
        );
        state.bitcoin.payment_xpub = Some(harvest_common::PaymentXpubStatus {
            xpub: "vpub-placeholder".to_string(),
            network: BitcoinNetwork::Signet,
            next_index: 0,
        });
        state.bitcoin.payment_xpub_loaded = true;
        state
            .bitcoin
            .tips
            .insert(BitcoinNetwork::Signet, tip_at(TIP_HEIGHT));

        let buyer = BuyerConversation::open(&seller_encryption_key()).expect("open");
        let tag = buyer.buyer_public_key;
        let request = buyer
            .request_order(
                &ListingId([3u8; 32]),
                2,
                "12 Example St".into(),
                String::new(),
            )
            .expect("seal the request");

        state.begin_browsing(STORE.to_vec());
        let store = state.browsing_stores.get_mut(STORE).expect("the store");
        store.mailbox_contract_id = Some(vec![11u8; 32]);
        store.mailbox_messages = vec![request.clone()];
        state
            .conversation_keys
            .insert(tag.to_vec(), seller_keys_for(&tag));
        (state, tag, request)
    }

    fn invoice_answering(tag: [u8; 32]) -> PendingInvoice {
        PendingInvoice {
            store_contract_id: STORE.to_vec(),
            seller_fingerprint: "seller-fp".to_string(),
            listing_id: ListingId([3u8; 32]),
            listing_title: "Widget".to_string(),
            buyer_fingerprint: String::new(),
            amount_sats: 50_000,
            required_confirmations: 1,
            reply_to: Some(tag),
            order_binding: Some(the_buyers_conversation().order_binding()),
        }
    }

    /// **Accepting a request tells the buyer which commitment is theirs.**
    ///
    /// The buyer cannot derive the order id -- it hashes a `created_at` the
    /// seller stamps -- so an acceptance that did not name it would leave the
    /// buyer looking at a public order book with no way to tell which entry
    /// they are supposed to pay.
    ///
    /// Read back through the BUYER's own conversation rather than by
    /// inspecting what the seller composed, because the buyer's side is the
    /// one that has to work.
    #[test]
    fn accepting_a_request_tells_the_buyer_which_commitment_is_theirs() {
        let (state, tag, _) = seller_holding_a_request();
        let buyer_keys = seller_keys_for(&tag);

        let published = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let sealed = state
            .acceptance_for(STORE, &tag, &published.order.id)
            .expect("the seller can answer a request they hold the key for");

        // The buyer, holding only their own conversation, reads it.
        let thread = decrypt_as_buyer(&buyer_keys, &tag, &sealed);
        assert_eq!(
            thread,
            Some(published.order.id.clone()),
            "the acceptance must name the published commitment"
        );
    }

    /// **A request whose key the seller no longer holds is refused, not
    /// silently skipped.**
    ///
    /// The alternative is a published commitment nobody was ever told about:
    /// the seller believes they accepted, and the buyer sees an order book
    /// entry they cannot recognise as their own.
    #[test]
    fn an_acceptance_with_no_conversation_key_is_an_error() {
        let (state, _, _) = seller_holding_a_request();
        let published = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );

        let refused = state.acceptance_for(STORE, &[0xcd; 32], &published.order.id);
        assert!(
            refused.is_err(),
            "a tag with no key must not produce a message"
        );
    }

    /// **The published invoice, and the acceptance, both come out of one
    /// click.**
    ///
    /// The whole seller path: request in hand, accept, and the acceptance is
    /// recorded as the seller's own outgoing message. Publishing the
    /// commitment itself needs a browser and is not exercised here; what this
    /// pins is that accepting produces the message that makes the commitment
    /// findable, rather than leaving that to a second manual step nobody
    /// takes.
    #[test]
    fn accepting_records_the_acceptance_as_the_sellers_own_message() {
        let (mut state, tag, _) = seller_holding_a_request();
        state
            .issue_invoice(invoice_answering(tag))
            .expect("the seller owns this store");
        let request_id = *state.pending_invoices.keys().next().expect("one entry");
        state.on_bitcoin_delegate_response(BitcoinDelegateResponse::OrderAddress {
            request_id,
            result: Ok(harvest_common::DerivedAddress {
                index: 0,
                network: BitcoinNetwork::Signet,
                script_pubkey: vec![0x00, 0x14, 0x01],
                address: "tb1qexample".to_string(),
            }),
        });
        let queued = match state.pending_signatures.front() {
            Some(PendingSignature::Order(order)) => order.clone(),
            other => panic!("expected an order awaiting signature, got {other:?}"),
        };
        assert_eq!(
            queued.reply_to,
            Some(tag),
            "the invoice must remember which request it answers"
        );

        state.on_ghostkey_response(order_sign_result(&queued));

        let sent = &state.browsing_stores[STORE].sent_messages;
        assert_eq!(sent.len(), 1, "accepting writes one message to the buyer");
        assert!(
            sent[0].text.contains(&queued.order.id.short()),
            "the seller's own record should name the order: {}",
            sent[0].text
        );
    }

    /// A `SignResult` shaped the way the ghostkey delegate answers.
    fn order_sign_result(pending: &PendingOrder) -> ghostkey_common::GhostkeyResponse {
        use freenet_stdlib::prelude::ContractInstanceId;

        let message = harvest_common::to_cbor(&pending.order).expect("serialize");
        let scoped = ghostkey_common::ScopedPayload {
            requestor: ghostkey_common::SignatureRequestor::WebApp(
                harvest_common::HARVEST_WEBAPP_CONTRACT_ID
                    .parse::<ContractInstanceId>()
                    .expect("canonical webapp id"),
            ),
            payload: message,
        };
        let scoped_payload = harvest_common::to_cbor(&scoped).expect("serialize scoped");
        let signature = seller_signing_key()
            .sign(&scoped_payload)
            .to_bytes()
            .to_vec();
        ghostkey_common::GhostkeyResponse::SignResult {
            scoped_payload,
            signature,
            certificate_pem: String::new(),
        }
    }

    /// What the buyer makes of one sealed message: the order id it names, or
    /// `None` if they cannot read it or it is not an acceptance.
    fn decrypt_as_buyer(
        keys: &ConversationKeys,
        tag: &[u8; 32],
        sealed: &EncryptedMessage,
    ) -> Option<OrderId> {
        let plaintext = crate::messaging::decrypt_message(sealed, &keys.from_seller).ok()?;
        let _ = tag;
        match plaintext.content {
            crate::messaging::MessageContent::OrderAccepted { order_id } => Some(order_id),
            _ => None,
        }
    }

    /// **Asking to buy opens a conversation and asks the node to keep it.**
    ///
    /// The request is the buyer's first message, so it is also the moment the
    /// key that reads the seller's answer comes into existence. Leaving the
    /// keep to a later message would mean the acceptance -- and, in Phase 2,
    /// the confession -- arriving against a key nothing durable holds.
    #[test]
    fn asking_to_buy_opens_a_conversation_and_asks_the_node_to_keep_it() {
        let mut state = AppState::default();
        state.begin_browsing(STORE.to_vec());
        state.harvest_delegate_key = Some(freenet_stdlib::prelude::DelegateKey::new(
            [0xA1; 32],
            freenet_stdlib::prelude::CodeHash::new([0xA1; 32]),
        ));

        let listing = ListingId([3u8; 32]);
        let sealed = state
            .request_order(
                STORE,
                &seller_encryption_key(),
                &listing,
                2,
                "12 Example St".to_string(),
                String::new(),
            )
            .expect("a request should be sealable");

        assert_eq!(
            state.browsing_stores[STORE].conversations.len(),
            1,
            "the request opens the conversation it will be answered in"
        );
        let tag = state.browsing_stores[STORE].conversations[0].buyer_public_key;
        assert_eq!(
            state
                .pending_conversation_persists
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            vec![(STORE.to_vec(), tag)],
            "the node must be asked to keep the key that reads the answer"
        );

        // And what was sealed is a request the seller can actually read.
        let seller_keys = seller_keys_for(&tag);
        let mut keys = std::collections::HashMap::new();
        keys.insert(tag.to_vec(), seller_keys);
        let inbox = crate::messaging::read_mailbox(&[sealed], &keys);
        match &inbox[0] {
            crate::messaging::MailboxEntry::Readable {
                content:
                    crate::messaging::MessageContent::OrderRequest {
                        listing_id,
                        quantity,
                        shipping,
                        ..
                    },
                ..
            } => {
                assert_eq!(listing_id, &listing);
                assert_eq!(*quantity, 2);
                assert_eq!(shipping, "12 Example St");
            }
            other => panic!("expected an order request, got {other:?}"),
        }
    }

    /// **A request continues the thread rather than forking a new one.**
    ///
    /// Same reasoning as an ordinary message: a seller who cannot connect the
    /// request to the question that preceded it is looking at two strangers.
    #[test]
    fn a_request_continues_the_conversation_already_open() {
        let mut state = AppState::default();
        state.begin_browsing(STORE.to_vec());
        state.harvest_delegate_key = Some(freenet_stdlib::prelude::DelegateKey::new(
            [0xA1; 32],
            freenet_stdlib::prelude::CodeHash::new([0xA1; 32]),
        ));
        state
            .compose_to_seller(STORE, &seller_encryption_key(), "is this in stock?".into())
            .expect("first message");
        let tag = state.browsing_stores[STORE].conversations[0].buyer_public_key;

        state
            .request_order(
                STORE,
                &seller_encryption_key(),
                &ListingId([3u8; 32]),
                1,
                "12 Example St".to_string(),
                String::new(),
            )
            .expect("request");

        assert_eq!(state.browsing_stores[STORE].conversations.len(), 1);
        assert_eq!(
            state.browsing_stores[STORE].conversations[0].buyer_public_key,
            tag
        );
    }

    /// **A request for nothing, or to nowhere, is refused before it is sent.**
    ///
    /// A zero quantity would have the seller invoicing for an amount the
    /// buyer never agreed to, and a request with no destination cannot be
    /// fulfilled at all -- both are better refused beside the box than
    /// discovered by a seller who has already published a commitment.
    #[test]
    fn an_empty_request_is_refused() {
        let mut state = AppState::default();
        state.begin_browsing(STORE.to_vec());

        let none = state.request_order(
            STORE,
            &seller_encryption_key(),
            &ListingId([3u8; 32]),
            0,
            "12 Example St".to_string(),
            String::new(),
        );
        assert!(none.is_err(), "a quantity of zero is not an order");

        let nowhere = state.request_order(
            STORE,
            &seller_encryption_key(),
            &ListingId([3u8; 32]),
            1,
            "   ".to_string(),
            String::new(),
        );
        assert!(nowhere.is_err(), "an order has to go somewhere");

        assert!(
            state.browsing_stores[STORE].conversations.is_empty(),
            "a refused request must not leave a conversation behind"
        );
    }

    /// **One published commitment is payable by exactly one buyer.**
    ///
    /// The hole this closes, found in review: nothing in the commitment named
    /// anything only one buyer could satisfy, so a seller could accept one
    /// order, publish one commitment, and send the same `OrderAccepted` down
    /// any number of conversations. Every buyer's software cleared every
    /// check and showed them the same payment address. One declared debt
    /// collected unbounded money -- which inverts the mechanism the
    /// commitment exists for, since a count that does not bound the money is
    /// not a count of anything.
    ///
    /// Alice and Bob are separate `AppState`s with separate conversations and
    /// separate ephemeral secrets, both pointed at the one commitment. The
    /// commitment is bound to Alice.
    #[test]
    fn one_commitment_is_payable_by_exactly_one_buyer() {
        let (alice, alice_conversation) = buyer_conversation();
        let published = commitment_bound_to(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
            Some(alice_conversation.order_binding()),
        );

        let alice = buyer_holding(alice, alice_conversation, &published);
        let (bob, bob_conversation) = buyer_conversation();
        let bob = buyer_holding(bob, bob_conversation, &published);

        assert_eq!(
            purchases(&alice)[0].blockers,
            Vec::new(),
            "the buyer it was issued to can pay it"
        );
        assert_eq!(
            purchases(&bob)[0].blockers,
            vec![PaymentBlocker::CommitmentNotForThisBuyer],
            "and nobody else can"
        );
    }

    /// **A commitment carrying no binding at all is refused.**
    ///
    /// Absence must not read as "matches". `Order::order_binding` is
    /// `Option` for the same wire-compatibility reason the anchor is, so the
    /// unbound case is reachable and has to fail closed.
    #[test]
    fn a_commitment_with_no_binding_is_refused() {
        let (state, conversation) = buyer_conversation();
        let published = commitment_bound_to(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
            None,
        );
        let state = buyer_holding(state, conversation, &published);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::CommitmentNotForThisBuyer]
        );
    }

    /// **The binding the buyer checks against is their own, not the one in
    /// the mailbox.**
    ///
    /// Direction is not authorship, so a seller can seal a request into the
    /// buyer's own thread -- the weakness `CommitmentNotRequested` already
    /// documents. If the check compared the commitment against the binding in
    /// that request, the seller would simply forge a request carrying the
    /// binding they published, and the check would pass for every buyer at
    /// once. It has to compare against the value this node derives from its
    /// own conversation secret, which no message can influence.
    #[test]
    fn a_forged_request_cannot_supply_the_binding_the_check_uses() {
        let (alice, alice_conversation) = buyer_conversation();
        let (_, other_conversation) = buyer_conversation();
        let published = commitment_bound_to(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
            // Bound to somebody else entirely.
            Some(other_conversation.order_binding()),
        );
        let tag = alice_conversation.buyer_public_key;
        let conversation_id = alice_conversation.conversation_id.clone();
        let mut alice = buyer_holding(alice, alice_conversation, &published);

        // The seller seals a request into Alice's thread, in the
        // buyer-to-seller direction, carrying the binding they published.
        let forged = crate::messaging::seal_for_test(
            &seller_keys_for(&tag).to_seller,
            &tag,
            &conversation_id,
            crate::messaging::MessageContent::OrderRequest {
                listing_id: published.order.listing_id.clone(),
                quantity: 1,
                shipping: "anywhere".into(),
                note: String::new(),
                order_binding: other_conversation.order_binding(),
            },
        )
        .expect("seal");
        alice
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .mailbox_messages
            .push(forged);

        assert_eq!(
            purchases(&alice)[0].blockers,
            vec![PaymentBlocker::CommitmentNotForThisBuyer],
            "a request the seller wrote must not decide what the buyer compares against"
        );
    }

    /// **The binding this browser computes is the shared derivation, applied
    /// to the secret it just generated.**
    ///
    /// The other half of the cross-crate seam lives in the delegate
    /// (`recall_answers_the_binding_the_shared_derivation_gives`). Neither
    /// side tests the other -- they cannot, they are different crates on
    /// different machines -- so each is pinned to
    /// `harvest_common::mailbox::order_binding_from_secret`, which has a
    /// known-answer test against `b3sum`. A drift on either side turns one of
    /// the three red.
    ///
    /// This matters because the failure is silent: the buyer computes the
    /// binding here from a secret it has just generated, and after a reload
    /// the delegate computes it from the copy it kept. If those disagree,
    /// nothing errors -- the buyer simply finds their own commitment
    /// unrecognisable and can never pay it.
    #[test]
    fn the_browsers_binding_is_the_shared_derivation() {
        let (_, conversation) = buyer_conversation();
        assert_eq!(
            conversation.order_binding(),
            harvest_common::mailbox::order_binding_from_secret(&conversation.secret_for_test()),
        );
    }

    /// **A conversation the delegate hands back keeps the binding it was
    /// given.**
    ///
    /// The UI's half of the recall path: whatever the delegate computed has
    /// to survive into the conversation the buyer's checks read.
    #[test]
    fn a_recalled_conversation_keeps_its_binding() {
        let recalled =
            crate::messaging::BuyerConversation::recalled(&harvest_common::RecalledConversation {
                buyer_public_key: [5u8; 32],
                conversation_id: [6u8; 32],
                buyer_to_seller: [7u8; 32],
                seller_to_buyer: [8u8; 32],
                order_binding: [9u8; 32],
                created_at: 1,
                imported: false,
                backed_up: false,
            });
        assert_eq!(recalled.order_binding(), [9u8; 32]);
    }

    /// **An invoice naming no Bitcoin bridge is refused, not footnoted.**
    ///
    /// Found in review. `verify_payment_proof` returns `NoTrustedBridges` for
    /// such an order permanently, so no payment to it can EVER be proven --
    /// and `trusted_bridges` is per-order and seller-chosen, so a malicious
    /// seller picks it. The card said so in smaller text underneath the
    /// sentence saying the order checked out, with the payment address shown
    /// above it. A condition that decides whether money can ever be recovered
    /// belongs in the same list as everything else that decides whether to
    /// pay.
    #[test]
    fn an_invoice_naming_no_bridge_is_refused() {
        let mut order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        order.order.trusted_bridges = Vec::new();
        let order = resigned(order, &seller_signing_key());
        let (state, _) = buyer_after_acceptance(&order);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::NoTrustedBridge]
        );
    }

    /// **An invoice settled by a bridge this build does not know is refused.**
    ///
    /// Its "Paid" verdict would rest on a signature the buyer has no reason
    /// to trust, and the seller chose it.
    #[test]
    fn an_invoice_naming_an_unknown_bridge_is_refused() {
        let mut order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        order.order.trusted_bridges = vec![freenet_bitcoin_common::BridgeId([0x77; 32])];
        let order = resigned(order, &seller_signing_key());
        let (state, _) = buyer_after_acceptance(&order);

        assert!(
            matches!(
                purchases(&state)[0].blockers.as_slice(),
                [PaymentBlocker::BridgeNotRecognised(_)]
            ),
            "got {:?}",
            purchases(&state)[0].blockers
        );
    }

    /// **An invoice whose displayed address is not the script that settles it
    /// is refused.**
    ///
    /// An `Order` carries both forms and the seller's signature covers both,
    /// so a signature proves the seller wrote them, not that they agree.
    /// Every verification path uses the script; the human pays the address.
    ///
    /// `OrderCard` already withheld the address for this, which is why it is
    /// the one case review found handled correctly -- but as a card-level
    /// special case rather than a blocker, so the top-line sentence still
    /// said the order checked out. Moving it here makes the pattern one
    /// pattern.
    #[test]
    fn an_invoice_whose_address_is_not_its_script_is_refused() {
        let mut order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        // A well-formed signet address that is not the order's script.
        order.order.payment_address = ANOTHER_ADDRESS.to_string();
        let order = resigned(order, &seller_signing_key());
        let (state, _) = buyer_after_acceptance(&order);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::DestinationDisagrees]
        );
    }

    /// **An address that cannot be read at all is refused too.**
    ///
    /// Nothing can be said about it, which is itself a reason not to pay it.
    #[test]
    fn an_invoice_with_an_unreadable_address_is_refused() {
        let mut order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        order.order.payment_address = "not an address".to_string();
        let order = resigned(order, &seller_signing_key());
        let (state, _) = buyer_after_acceptance(&order);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::DestinationUnreadable]
        );
    }

    /// **An expired order is not the seller's fault, and is not the end of
    /// the purchase.**
    ///
    /// The anchor is stamped when the seller signs and cannot be changed
    /// afterwards, so every honest order eventually ages past the tolerance.
    /// The buyer's screen used to accuse the seller of backdating and
    /// classify it as walk-away, which abandons a purchase one message would
    /// have rescued.
    #[test]
    fn an_expired_order_sends_the_buyer_back_to_the_seller() {
        use crate::components::buy_view::{remedy, Remedy};

        let expired = PaymentBlocker::AnchorStale {
            anchor_height: TIP_HEIGHT - MAX_ANCHOR_AGE_BLOCKS - 1,
            tip_height: TIP_HEIGHT,
        };
        assert_eq!(remedy(&expired), Remedy::AskTheSeller);

        let said = expired.describe();
        assert!(
            said.contains("expired"),
            "the buyer should be told what happened: {said}"
        );
        assert!(
            !said.contains("backdated"),
            "and not told the seller did something: {said}"
        );
    }

    /// **A seller is told when one of their own orders has aged out.**
    ///
    /// Without this the expiry is invisible on the side that can fix it: the
    /// buyer is asked to go back to a seller who has no idea anything
    /// happened, and nothing anywhere says the order stopped being payable.
    #[test]
    fn a_seller_is_told_which_of_their_orders_need_reissuing() {
        let fresh = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let expired = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT - MAX_ANCHOR_AGE_BLOCKS - 1)),
            OrderStatus::AwaitingPayment,
        );
        let unanchored = commitment(&seller_signing_key(), None, OrderStatus::AwaitingPayment);
        let mut settled = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT - MAX_ANCHOR_AGE_BLOCKS - 1)),
            OrderStatus::AwaitingPayment,
        );
        cancel(&mut settled, &seller_signing_key());

        let mut state = AppState::default();
        state
            .bitcoin
            .tips
            .insert(BitcoinNetwork::Signet, tip_at(TIP_HEIGHT));

        assert!(!state.needs_reissue(&fresh), "a fresh order is fine");
        assert!(state.needs_reissue(&expired), "an aged-out order is not");
        assert!(
            state.needs_reissue(&unanchored),
            "and neither is one that never had an anchor"
        );
        assert!(
            !state.needs_reissue(&settled),
            "an order nobody is waiting to pay needs nothing"
        );
    }

    /// **A seller who cannot see the chain is not told to reissue
    /// everything.**
    ///
    /// The judgement needs the reader's own clock. Without a tip there is no
    /// clock, and answering "yes" would have every seller reissuing every
    /// order every time their node was slow to load -- the same
    /// unknown-read-as-a-verdict mistake the buyer's side refuses to make in
    /// the other direction.
    #[test]
    fn a_seller_with_no_chain_view_is_told_to_reissue_nothing() {
        let expired = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT - MAX_ANCHOR_AGE_BLOCKS - 1)),
            OrderStatus::AwaitingPayment,
        );
        let state = AppState::default();
        assert!(!state.needs_reissue(&expired));
    }

    /// **A buyer's own purchase gets its payment address watched.**
    ///
    /// Without this, `bitcoin.addresses` never holds an entry for the order
    /// and the card reads "Awaiting payment" whatever has arrived. The
    /// blockers stop the wrong payment; this is the evidence a person can
    /// check them against -- and, in the one-commitment-many-buyers case the
    /// binding now refuses, it is what would have shown a buyer the money was
    /// already there.
    #[test]
    fn a_buyers_purchase_names_the_address_contract_to_watch() {
        let published = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let (state, _) = buyer_after_acceptance(&published);

        assert_eq!(
            state.address_contracts_to_watch(STORE),
            vec![published
                .order
                .bitcoin_address_instance_id()
                .expect("the fixture names a build")],
        );
    }

    /// **A seller's own issued invoice is watched too.**
    ///
    /// The same blindness on the other side: a seller who never added a
    /// manual watch could not see their own invoice being paid.
    #[test]
    fn a_sellers_own_invoice_names_the_address_contract_to_watch() {
        let published = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let mut state = AppState::default();
        state.begin_browsing(STORE.to_vec());
        state.my_stores.insert(
            "seller-fp".to_string(),
            vec![StoreRegistration {
                store_contract_id: STORE.to_vec(),
                reputation_contract_id: vec![10u8; 32],
                mailbox_contract_id: vec![11u8; 32],
                store_contract_key: None,
            }],
        );
        state
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .orders = vec![published.clone()];

        assert_eq!(
            state.address_contracts_to_watch(STORE),
            vec![published
                .order
                .bitcoin_address_instance_id()
                .expect("the fixture names a build")],
        );
    }

    /// **A stranger's order in a store this node is only browsing is not
    /// watched.**
    ///
    /// A store contract carries every order it has ever issued. Subscribing
    /// to all of them would advertise an interest in every one of a busy
    /// seller's payment addresses to the network, for orders this node has
    /// nothing to do with -- which is the private-watch-list-as-public-record
    /// shape `harvest_common::bitcoin_delegate` refuses to build.
    #[test]
    fn somebody_elses_order_is_not_watched() {
        let published = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let mut state = AppState::default();
        state.begin_browsing(STORE.to_vec());
        state
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .orders = vec![published];

        assert!(
            state.address_contracts_to_watch(STORE).is_empty(),
            "an order this node is neither buyer nor seller of is not ours to watch"
        );
    }

    /// **An order naming no contract build names nothing to watch.**
    #[test]
    fn an_order_with_no_build_names_no_contract_to_watch() {
        let mut published = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        published.order.bitcoin_address_code_hash = None;
        let published = resigned(published, &seller_signing_key());
        let (state, _) = buyer_after_acceptance(&published);

        assert!(state.address_contracts_to_watch(STORE).is_empty());
    }

    /// The bridge these settlement fixtures sign with.
    ///
    /// The order has to NAME it, because `verify_on_chain_proof` refuses a
    /// claim from a bridge the order does not trust -- so `a_paid_order`
    /// re-signs the commitment with this bridge in `trusted_bridges` rather
    /// than the build's own constant, whose private key nobody here has.
    fn settling_bridge() -> SigningKey {
        SigningKey::from_bytes(&[61u8; 32])
    }

    /// An order naming [`settling_bridge`], the claims that settle it, and a
    /// tip deep enough for its `required_confirmations`.
    fn a_paid_order() -> (
        AuthorizedOrder,
        Vec<freenet_bitcoin_common::SignedClaim>,
        freenet_bitcoin_common::SignedTipEntry,
    ) {
        use freenet_bitcoin_common::spv::testing::payment_proof;
        use freenet_bitcoin_common::{
            BlockHash, ClaimBody, SignedClaim, SignedTipEntry, TipEntryBody,
        };

        let mut order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        order.order.trusted_bridges = vec![freenet_bitcoin_common::BridgeId(
            settling_bridge().verifying_key().to_bytes(),
        )];
        let order = resigned(order, &seller_signing_key());

        let confirmed_at = TIP_HEIGHT - 1;
        let (spv, txid, block_hash) = payment_proof(
            &order.order.payment_script_pubkey,
            order.order.amount_sats,
            1,
            [7u8; 32],
        );
        let claim = SignedClaim::sign(
            &settling_bridge(),
            &ClaimBody {
                script_id: order.order.bitcoin_params().script_id(),
                network: order.order.network,
                // The bridge has scanned as far as the tip, which is what
                // lets the confirmation attest any depth at all -- see
                // `payment::proof_assembly_tests::confirmation`.
                as_of: freenet_bitcoin_common::BlockAnchor {
                    height: TIP_HEIGHT,
                    hash: BlockHash([5u8; 32]),
                },
                claim: freenet_bitcoin_common::Claim::ConfirmedOutput {
                    outpoint: freenet_bitcoin_common::OutPoint { txid, vout: 0 },
                    value_sats: order.order.amount_sats,
                    anchor: freenet_bitcoin_common::BlockAnchor {
                        height: confirmed_at,
                        hash: block_hash,
                    },
                    spv,
                },
            },
        )
        .expect("sign the claim");

        let tip = SignedTipEntry::sign(
            &settling_bridge(),
            &TipEntryBody {
                network: order.order.network,
                anchor: anchor(TIP_HEIGHT),
                prev_hash: BlockHash([8u8; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .expect("sign the tip");

        (order, vec![claim], tip)
    }

    /// The same claim shape as [`a_paid_order`], one satoshi short.
    ///
    /// A genuine, verifying, bridge-signed claim about this order's own
    /// script -- so it reaches the assembler's verify rather than being
    /// filtered out before it.
    fn an_underpayment(order: &AuthorizedOrder) -> Vec<freenet_bitcoin_common::SignedClaim> {
        use freenet_bitcoin_common::spv::testing::payment_proof;
        use freenet_bitcoin_common::{BlockHash, ClaimBody, SignedClaim};

        let short = order.order.amount_sats - 1;
        let (spv, txid, block_hash) =
            payment_proof(&order.order.payment_script_pubkey, short, 1, [7u8; 32]);
        vec![SignedClaim::sign(
            &settling_bridge(),
            &ClaimBody {
                script_id: order.order.bitcoin_params().script_id(),
                network: order.order.network,
                as_of: freenet_bitcoin_common::BlockAnchor {
                    height: TIP_HEIGHT,
                    hash: BlockHash([5u8; 32]),
                },
                claim: freenet_bitcoin_common::Claim::ConfirmedOutput {
                    outpoint: freenet_bitcoin_common::OutPoint { txid, vout: 0 },
                    value_sats: short,
                    anchor: freenet_bitcoin_common::BlockAnchor {
                        height: TIP_HEIGHT - 1,
                        hash: block_hash,
                    },
                    spv,
                },
            },
        )
        .expect("sign")]
    }

    /// Put the chain material where a subscription would have put it.
    fn give_the_node_the_chain(
        state: &mut AppState,
        order: &AuthorizedOrder,
        claims: Vec<freenet_bitcoin_common::SignedClaim>,
        tip: freenet_bitcoin_common::SignedTipEntry,
    ) {
        let mut view = tip_at(TIP_HEIGHT);
        view.signed_tip = Some(tip);
        state.bitcoin.tips.insert(BitcoinNetwork::Signet, view);
        state.bitcoin.addresses.insert(
            order
                .order
                .bitcoin_address_instance_id()
                .expect("the fixture names a build")
                .to_vec(),
            AddressView {
                network: BitcoinNetwork::Signet,
                claims,
                scanned_to: Some(TIP_HEIGHT),
                confirmed_sats: order.order.amount_sats,
                pending_sats: 0,
                txs: Vec::new(),
            },
        );
    }

    /// **A buyer whose payment has confirmed publishes the settled order.**
    ///
    /// The gap this closes: `verify_payment_proof`, the bridge claims and the
    /// address subscription all existed, and nothing constructed the proof --
    /// so an order sat `AwaitingPayment` forever however much had been paid,
    /// and the public record permanently misstated what happened. Every later
    /// mechanism reads that record; Phase 2's reversal argument is arithmetic
    /// over it.
    #[test]
    fn a_confirmed_payment_produces_a_paid_order_to_publish() {
        let (order, claims, tip) = a_paid_order();
        let (mut state, _) = buyer_after_acceptance(&order);
        give_the_node_the_chain(&mut state, &order, claims, tip);

        let settled = state
            .settled_orders(STORE)
            .pop()
            .expect("a confirmed payment settles the order");

        assert_eq!(settled.order.id, order.order.id);
        assert_eq!(settled.status, OrderStatus::Paid);
        assert!(settled.payment_proof.is_some());
        // And it is a record the network will actually accept.
        settled
            .verify(&seller_signing_key().verifying_key())
            .expect("a settled order must verify as Paid");
    }

    /// **An order whose payment has not confirmed is not settled.**
    ///
    /// Two cases, and the second is the one that would otherwise go
    /// untested here. Nothing seen at all takes the assembler's early
    /// refusal; a claim that exists but does not carry the transition takes
    /// the verify. An earlier version of this test covered only the first,
    /// so deleting the assembler's `verify_payment_proof` call left it green
    /// -- the guard is pinned in
    /// `harvest_common::payment::proof_assembly_tests`, and this is the same
    /// question asked through the state that actually publishes.
    ///
    /// Publishing `Paid` on evidence that does not carry it is a state every
    /// peer refuses, which on the buyer's screen looks like the payment
    /// never registering.
    #[test]
    fn an_unpaid_order_is_not_settled() {
        let (order, claims, tip) = a_paid_order();

        // Nothing seen at all.
        let (mut nothing_seen, _) = buyer_after_acceptance(&order);
        give_the_node_the_chain(&mut nothing_seen, &order, Vec::new(), tip.clone());
        assert!(nothing_seen.settled_orders(STORE).is_empty());

        // Seen, and short of the amount: the claims verify, and what they
        // attest is not this order being paid.
        let underpaid = an_underpayment(&order);
        assert_eq!(claims.len(), underpaid.len(), "the same shape of evidence");
        let (mut short, _) = buyer_after_acceptance(&order);
        give_the_node_the_chain(&mut short, &order, underpaid, tip);
        assert!(
            short.settled_orders(STORE).is_empty(),
            "an underpayment is not a payment"
        );
    }

    /// **An order already past `AwaitingPayment` is not settled again.**
    ///
    /// Status is a monotonic maximum under merge, so re-publishing is inert
    /// rather than harmful -- but it is an update per state arrival for an
    /// order that has already moved, which is exactly the churn the
    /// subscription path exists to avoid.
    #[test]
    fn an_order_that_has_already_moved_is_not_settled_again() {
        let (order, claims, tip) = a_paid_order();
        let (mut state, _) = buyer_after_acceptance(&order);
        give_the_node_the_chain(&mut state, &order, claims, tip);

        // Publish the settled form back into the store's state, as the
        // network would once the update lands.
        let settled = state.settled_orders(STORE).pop().expect("settles once");
        state
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .orders = vec![settled];

        assert!(
            state.settled_orders(STORE).is_empty(),
            "an order that is already Paid has nothing left to settle"
        );
    }

    /// **Settling an order does not stop the node keeping the conversation.**
    ///
    /// The ordering constraint from `docs/buyer-conversation-persistence.md`,
    /// checked at the moment it would be easiest to break: "paid" is exactly
    /// when a buyer's software might conclude the transaction is over and the
    /// conversation record no longer matters. In Phase 2 the confession lives
    /// in that record and has to be persisted BEFORE payment, so treating
    /// payment as a reason to stop caring about it inverts the whole
    /// argument.
    #[test]
    fn settling_leaves_the_conversation_record_alone() {
        let (order, claims, tip) = a_paid_order();
        let (mut state, tag) = buyer_after_acceptance(&order);
        give_the_node_the_chain(&mut state, &order, claims, tip);

        let settled = state.settled_orders(STORE).pop().expect("settles");
        state
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .orders = vec![settled];

        let store = &state.browsing_stores[STORE];
        assert_eq!(
            store.conversations.len(),
            1,
            "the conversation is still kept after payment"
        );
        assert_eq!(store.conversations[0].buyer_public_key, tag);
        assert!(
            store.conversations[0].is_kept(),
            "and the node has not forgotten it is keeping it"
        );
        // The purchase is still shown, now as one there is nothing to pay.
        assert_eq!(
            state.buyer_purchases(STORE)[0].blockers,
            vec![PaymentBlocker::NotAwaitingPayment(OrderStatus::Paid)]
        );
    }

    /// **A settlement is published once, not once per notification.**
    ///
    /// Between dispatching the update and the store's state coming back with
    /// it applied, `settled_orders` keeps answering the same order -- the
    /// state it reads has not changed yet. Without the guard that is one
    /// update per notification per paid order, against a contract, forever.
    #[test]
    fn a_settlement_is_published_once_per_tab() {
        let (order, claims, tip) = a_paid_order();
        let (mut state, _) = buyer_after_acceptance(&order);
        give_the_node_the_chain(&mut state, &order, claims, tip);

        assert_eq!(
            state.settled_orders(STORE).len(),
            1,
            "the order is settleable"
        );
        assert_eq!(
            state.publish_settled_orders(STORE).len(),
            1,
            "and was published once"
        );

        // The store's state has not come back yet, so it is still settleable
        // -- and must not be published again.
        assert_eq!(state.settled_orders(STORE).len(), 1);
        assert!(
            state.publish_settled_orders(STORE).is_empty(),
            "a second notification must not send a second update"
        );
    }

    /// **A conversation with no usable binding cannot pay anything.**
    ///
    /// Found in review. `RecalledConversation::order_binding` carries
    /// `#[serde(default)]` so a delegate answer produced before the field
    /// existed still decodes -- and it decodes to all-zeros, which
    /// `BuyerConversation::recalled` carried through verbatim. The commitment
    /// side of the comparison is a field the SELLER chooses and signs, so a
    /// seller signing `Some([0u8; 32])` matched every buyer in that state at
    /// once: H1 again, narrowed to a population rather than closed.
    ///
    /// Three comments asserted this could not happen, all reasoning about an
    /// *honest* commitment. The threat model here is a malicious seller, who
    /// is free to carry whatever value they like.
    ///
    /// Unreachable in a shipped build today -- the delegate WASM is
    /// `include_bytes!`d into the UI, so a new UI cannot reach an old
    /// delegate. That is the weakest kind of safe, and it is exactly why this
    /// is worth closing rather than deleting: the `serde(default)` exists FOR
    /// the skew case and got the skew case wrong.
    #[test]
    fn a_conversation_with_no_usable_binding_cannot_pay() {
        let (state, live) = buyer_conversation();
        let tag = live.buyer_public_key;
        let keys = seller_keys_for(&tag);
        // Exactly what `RecalledConversation` decodes to from a delegate
        // built before `order_binding` existed.
        let legacy =
            crate::messaging::BuyerConversation::recalled(&harvest_common::RecalledConversation {
                buyer_public_key: tag,
                conversation_id: live.conversation_id.0,
                buyer_to_seller: keys.to_seller,
                seller_to_buyer: keys.from_seller,
                order_binding: [0u8; 32],
                created_at: 0,
                imported: false,
                backed_up: false,
            });
        assert_eq!(legacy.order_binding(), [0u8; 32], "the premise");

        // The seller signs the matching value, which they are free to do.
        let published = commitment_bound_to(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
            Some([0u8; 32]),
        );
        let state = buyer_holding(state, legacy, &published);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::CommitmentNotForThisBuyer],
            "a binding that identifies nobody must not identify everybody"
        );
    }

    /// **Every input `payment_blockers` reads either yields a verdict or a
    /// blocker -- absence never reads as approval.**
    ///
    /// The generalisable half of the finding above. That function's entire
    /// contract is "empty means safe to pay", so a missing input that reads
    /// as a satisfied check is the one defect shape it cannot tolerate. The
    /// review found one; this enumerates the rest so the next one is a
    /// failing test rather than another review round.
    ///
    /// Each case removes exactly one input from an otherwise payable
    /// purchase and asserts SOME blocker comes back. It deliberately does not
    /// assert WHICH -- the individual blockers have their own tests, and
    /// pinning the identity here would make this test fail for reasons that
    /// are not the property it is about.
    ///
    /// The one deliberate exception is documented rather than tested as a
    /// blocker: an empty `requested_listings` does NOT block, because a
    /// conversation that never used the buy form is a real case (a seller
    /// invoicing against a plain question). It is safe only because the
    /// binding check above it already requires the seller to hold a value
    /// they can only have learned from a request -- so "no request" and "a
    /// matching binding" cannot both be true. If the binding check is ever
    /// weakened, that exception stops being safe.
    #[test]
    fn no_missing_input_reads_as_approval() {
        let order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );

        // The baseline: everything present, nothing standing in the way.
        let (state, _) = buyer_after_acceptance(&order);
        assert_eq!(
            purchases(&state)[0].blockers,
            Vec::new(),
            "the baseline must be payable, or the cases below prove nothing"
        );

        /// One input, and how to take it away.
        type MissingInput = (&'static str, Box<dyn Fn(&mut AppState)>);

        // Each case names an input and takes it away.
        let cases: Vec<MissingInput> = vec![
            (
                "the published commitment",
                Box::new(|s: &mut AppState| {
                    s.browsing_stores
                        .get_mut(STORE)
                        .expect("store")
                        .orders
                        .clear();
                }),
            ),
            (
                "the store's identity key",
                Box::new(|s: &mut AppState| {
                    s.browsing_stores
                        .get_mut(STORE)
                        .expect("store")
                        .seller_verifying_key = None;
                }),
            ),
            (
                "this node's view of the chain",
                Box::new(|s: &mut AppState| s.bitcoin.tips.clear()),
            ),
            (
                "the tip's height",
                Box::new(|s: &mut AppState| {
                    for tip in s.bitcoin.tips.values_mut() {
                        tip.tip_height = None;
                    }
                }),
            ),
            (
                "the blocks the anchor is checked against",
                Box::new(|s: &mut AppState| {
                    for tip in s.bitcoin.tips.values_mut() {
                        tip.recent_blocks.clear();
                    }
                }),
            ),
        ];

        // Safe means EITHER a blocker or no purchase shown at all -- a buyer
        // shown nothing is a buyer shown no payment address, which is the
        // property. Asserting a blocker specifically would fail for the cases
        // where the purchase becomes unreadable, which are safe by a
        // different route.
        let refuses = |state: &AppState| {
            let found = purchases(state);
            found.is_empty() || found.iter().all(|p| !p.blockers.is_empty())
        };

        for (what, remove) in cases {
            let (mut state, _) = buyer_after_acceptance(&order);
            remove(&mut state);
            assert!(
                refuses(&state),
                "without {what}, the buyer is told it is safe to pay"
            );
        }

        // The delegate's confirmation that it is keeping the conversation.
        // Built through the fixture rather than by swapping the conversation
        // out, because a fresh one carries a fresh `conversation_id` and the
        // acceptance then cannot be read at all -- safe, but for the wrong
        // reason, which would make this case prove nothing.
        let (not_kept, _) = buyer_after_acceptance_with(&order, false);
        assert!(
            refuses(&not_kept),
            "without the delegate's confirmation, the buyer is told it is safe to pay"
        );

        // The commitment's own optional fields, taken away one at a time.
        // These need re-signing, so they do not fit the closure shape above.
        for (what, mutate) in [
            (
                "the block anchor",
                Box::new(|o: &mut AuthorizedOrder| o.order.anchor = None)
                    as Box<dyn Fn(&mut AuthorizedOrder)>,
            ),
            (
                "the buyer binding",
                Box::new(|o: &mut AuthorizedOrder| o.order.order_binding = None),
            ),
            (
                "the trusted bridges",
                Box::new(|o: &mut AuthorizedOrder| o.order.trusted_bridges.clear()),
            ),
        ] {
            let mut stripped = order.clone();
            mutate(&mut stripped);
            let stripped = resigned(stripped, &seller_signing_key());
            let (state, _) = buyer_after_acceptance(&stripped);
            assert!(
                refuses(&state),
                "without {what}, the buyer is told it is safe to pay"
            );
        }
    }

    /// **A commitment for something this conversation never asked about is
    /// refused.**
    ///
    /// "Confirm your own order is present" is not satisfied by an order being
    /// present. A seller who accepted a request for a $5 listing by
    /// publishing a commitment against a $500 one would have a buyer paying
    /// the amount on a commitment for goods they never asked for -- and every
    /// other check in this list would pass, because the commitment is
    /// genuinely published, genuinely signed and genuinely fresh.
    ///
    /// What this rests on: the request is in the buyer's own thread, which
    /// only the two parties can write to. Direction is not authorship (see
    /// `messaging::Addressing`), so a seller CAN insert a request the buyer
    /// never sent -- but it then appears in the buyer's own thread as a
    /// request they do not recognise, which is a thing a person can see. The
    /// check is worth having for the case it does close and is not claimed to
    /// close more.
    #[test]
    fn a_commitment_for_a_listing_never_requested_is_refused() {
        let asked_for = ListingId([3u8; 32]);
        let published = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        assert_ne!(
            published.order.listing_id, asked_for,
            "the fixture must name a different listing, or this asserts nothing"
        );

        let (mut state, _) = buyer_after_acceptance(&published);
        // Put the buyer's own request into the thread, for a different
        // listing than the one the seller committed to.
        let conversation = state.browsing_stores[STORE].conversations[0].clone();
        let request = conversation
            .request_order(&asked_for, 1, "12 Example St".into(), String::new())
            .expect("seal the request");
        state
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .mailbox_messages
            .push(request);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::CommitmentNotRequested]
        );
    }

    /// **And the commitment for the listing that WAS asked about is fine.**
    ///
    /// The other half, so the rule above cannot pass by refusing everything.
    #[test]
    fn a_commitment_for_the_listing_that_was_requested_is_payable() {
        let published = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let (mut state, _) = buyer_after_acceptance(&published);
        let conversation = state.browsing_stores[STORE].conversations[0].clone();
        let request = conversation
            .request_order(
                &published.order.listing_id,
                1,
                "12 Example St".into(),
                String::new(),
            )
            .expect("seal the request");
        state
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .mailbox_messages
            .push(request);

        assert_eq!(purchases(&state)[0].blockers, Vec::new());
    }

    /// **A buyer who has been accepted has a purchase they can pay.**
    ///
    /// The whole flow, end to end, with nothing taken away. Every test below
    /// removes exactly one thing from this setup, so a failure here means the
    /// others are asserting about a state that never worked.
    #[test]
    fn an_accepted_request_becomes_a_payable_purchase() {
        let order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let (state, tag) = buyer_after_acceptance(&order);

        let found = purchases(&state);
        assert_eq!(found.len(), 1, "the acceptance names one purchase");
        assert_eq!(found[0].order_id, order.order.id);
        assert_eq!(found[0].conversation, tag);
        assert_eq!(
            found[0].blockers,
            Vec::new(),
            "nothing should stand between this buyer and paying"
        );
        assert_eq!(
            found[0].commitment.as_ref().map(|c| c.order.amount_sats),
            Some(50_000),
            "the buyer must see the amount they are about to pay"
        );
    }

    /// **The buyer will not pay until their own commitment is published.**
    ///
    /// This is the anti-exit-scam mechanism and the reason it works: an
    /// undeclared order collects no money, so a seller cannot take payment
    /// without first admitting publicly that they owe goods. The buyer is not
    /// policing anything -- they are refusing to be the order that was never
    /// declared.
    #[test]
    fn a_buyer_does_not_pay_a_commitment_that_was_never_published() {
        let order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let (mut state, _) = buyer_after_acceptance(&order);
        state
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .orders
            .clear();

        let found = purchases(&state);
        assert_eq!(found.len(), 1, "the acceptance is still in the thread");
        assert!(
            found[0].commitment.is_none(),
            "there is no commitment to show"
        );
        assert_eq!(
            found[0].blockers,
            vec![PaymentBlocker::CommitmentNotPublished]
        );
    }

    /// **A commitment somebody else signed is not the seller's.**
    ///
    /// The acceptance message carries no authority -- both parties hold both
    /// direction keys, so the buyer could have written it themselves. What
    /// makes a commitment binding is the ghostkey signature over its terms,
    /// checked against the identity whose store this is.
    #[test]
    fn a_commitment_signed_by_another_identity_is_refused() {
        let impostor = SigningKey::from_bytes(&[99u8; 32]);
        let order = commitment(
            &impostor,
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let (state, _) = buyer_after_acceptance(&order);

        let found = purchases(&state);
        assert!(
            matches!(
                found[0].blockers.as_slice(),
                [PaymentBlocker::CommitmentNotTheSellers(_)]
            ),
            "expected a signature refusal, got {:?}",
            found[0].blockers
        );
    }

    /// **A commitment with no block anchor is refused.**
    ///
    /// Without one there is nothing in the record a reader can date, and
    /// `created_at` is not a substitute: the seller stamps it, and the seller
    /// is the party with a motive to lie about when they took the order on.
    #[test]
    fn a_commitment_with_no_anchor_is_refused() {
        let order = commitment(&seller_signing_key(), None, OrderStatus::AwaitingPayment);
        let (state, _) = buyer_after_acceptance(&order);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::AnchorMissing]
        );
    }

    /// **A backdated commitment is refused, and the boundary is where the
    /// constant says it is.**
    ///
    /// Every past block hash is public, so a seller can anchor a fresh
    /// commitment to an old block and have readers count it as already
    /// closed -- reading as no outstanding exposure while taking money. The
    /// design document argues this is impossible; issue 8 records that it is
    /// wrong. This is the rule that neutralises it, and it lives in the
    /// reader because only a reader has a clock.
    ///
    /// Both sides of the boundary are asserted from the constant, so raising
    /// the tolerance moves the test with it rather than leaving it pinned to
    /// a number that no longer means anything.
    #[test]
    fn a_backdated_commitment_is_refused_and_a_fresh_one_is_not() {
        let oldest_allowed = TIP_HEIGHT - MAX_ANCHOR_AGE_BLOCKS;
        let order = commitment(
            &seller_signing_key(),
            Some(anchor(oldest_allowed)),
            OrderStatus::AwaitingPayment,
        );
        let (state, _) = buyer_after_acceptance(&order);
        assert_eq!(
            purchases(&state)[0].blockers,
            Vec::new(),
            "an anchor exactly at the tolerance is still fresh"
        );

        let order = commitment(
            &seller_signing_key(),
            Some(anchor(oldest_allowed - 1)),
            OrderStatus::AwaitingPayment,
        );
        let (state, _) = buyer_after_acceptance(&order);
        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::AnchorStale {
                anchor_height: oldest_allowed - 1,
                tip_height: TIP_HEIGHT,
            }],
            "one block past the tolerance is stale"
        );
    }

    /// **An anchor naming a block this reader does not have at that height is
    /// refused.**
    ///
    /// A height alone would accept an anchor from a chain the buyer is not
    /// on, which is exactly what the hash is in the anchor for.
    #[test]
    fn an_anchor_from_another_chain_is_refused() {
        let mut forged = anchor(TIP_HEIGHT);
        forged.hash = freenet_bitcoin_common::BlockHash([0xff; 32]);
        let order = commitment(
            &seller_signing_key(),
            Some(forged),
            OrderStatus::AwaitingPayment,
        );
        let (state, _) = buyer_after_acceptance(&order);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::AnchorOffChain]
        );
    }

    /// **A buyer who cannot see the chain does not judge the anchor -- and
    /// does not pay either.**
    ///
    /// Unknown is not the same answer as fresh, and the safe direction is to
    /// withhold. Saying which of the two it is matters because the fix is
    /// different: waiting versus walking away.
    #[test]
    fn a_buyer_who_cannot_see_the_chain_does_not_pay() {
        let order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let (mut state, _) = buyer_after_acceptance(&order);
        state.bitcoin.tips.clear();

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::ChainUnknown]
        );
    }

    /// **The buyer does not pay until their node has confirmed it is keeping
    /// the key that reads this conversation.**
    ///
    /// This is the ordering constraint from
    /// `docs/buyer-conversation-persistence.md`, applied to the thing that
    /// exists today. In Phase 2 the seller's reply carries a pre-signed
    /// confession, which is the buyer's only capability to file against the
    /// seller's bond, and it lands in the same delegate record as these keys.
    /// The doc's warning is aimed exactly here: "a Buy flow that pays first
    /// and stores after passes every test in this repository and defeats the
    /// entire mechanism".
    ///
    /// A conversation whose write the delegate refused, or has not answered,
    /// is one the buyer cannot read after a reload -- so paying against it
    /// buys goods and throws away the means of complaining about them.
    #[test]
    fn a_buyer_does_not_pay_before_the_node_confirms_it_kept_the_conversation() {
        let order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let (state, _) = buyer_after_acceptance_with(&order, false);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::ConversationNotKept]
        );
    }

    /// **The delegate's own answer is what clears that blocker.**
    ///
    /// Not the request having been sent, and not the UI's guess about what
    /// probably happened: the delegate is the only thing that knows whether a
    /// record was written, and a refused write must leave the buyer where
    /// they were.
    #[test]
    fn only_the_delegates_answer_marks_a_conversation_kept() {
        let mut state = AppState::default();
        state.begin_browsing(STORE.to_vec());
        let conversation =
            BuyerConversation::open(&seller_encryption_key()).expect("open a conversation");
        state
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .conversations = vec![conversation];

        let request = state
            .conversation_to_keep(STORE, &seller_encryption_key())
            .expect("a freshly opened conversation is one to keep");
        let request_id = match request {
            harvest_common::HarvestDelegateRequest::StoreBuyerConversation {
                request_id, ..
            } => request_id,
            other => panic!("expected a store request, got {other:?}"),
        };
        assert!(
            !state.browsing_stores[STORE].conversations[0].is_kept(),
            "sending the request is not the delegate answering it"
        );

        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationStored {
            request_id,
            result: Err("the node refused the write".to_string()),
            evicted: Vec::new(),
        });
        assert!(
            !state.browsing_stores[STORE].conversations[0].is_kept(),
            "a refused write must not count as kept"
        );

        let request = state
            .conversation_to_keep(STORE, &seller_encryption_key())
            .expect("asking again");
        let request_id = match request {
            harvest_common::HarvestDelegateRequest::StoreBuyerConversation {
                request_id, ..
            } => request_id,
            other => panic!("expected a store request, got {other:?}"),
        };
        state.on_delegate_response(HarvestDelegateResponse::BuyerConversationStored {
            request_id,
            result: Ok(()),
            evicted: Vec::new(),
        });
        assert!(
            state.browsing_stores[STORE].conversations[0].is_kept(),
            "the delegate said it kept it"
        );
    }

    /// **A conversation the delegate handed back is already kept.**
    ///
    /// It came out of the delegate's own store, so there is nothing to
    /// confirm -- and a returning buyer who had to send a message before they
    /// could pay would be a buyer told to do something pointless.
    #[test]
    fn a_recalled_conversation_is_already_kept() {
        let recalled = BuyerConversation::recalled(&harvest_common::RecalledConversation {
            buyer_public_key: [5u8; 32],
            conversation_id: [6u8; 32],
            buyer_to_seller: [7u8; 32],
            seller_to_buyer: [8u8; 32],
            order_binding: [9u8; 32],
            created_at: 1,
            imported: false,
            backed_up: false,
        });
        assert!(recalled.is_kept());
    }

    /// **An order the seller has cancelled is not offered for payment.**
    ///
    /// The cancellation is signed the way the contract requires, so this
    /// tests the status rule rather than tripping over an unsigned record --
    /// the first version of this test used a `Paid` status with no payment
    /// evidence and was refused by the signature check before it ever reached
    /// the status check, which would have made it a test of the wrong thing.
    #[test]
    fn an_order_that_is_not_awaiting_payment_is_not_payable() {
        let mut order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        cancel(&mut order, &seller_signing_key());
        let (state, _) = buyer_after_acceptance(&order);

        assert_eq!(
            purchases(&state)[0].blockers,
            vec![PaymentBlocker::NotAwaitingPayment(OrderStatus::Cancelled)]
        );
    }

    /// **An acceptance the buyer composed themselves is not an acceptance.**
    ///
    /// Both parties hold both direction keys, so a buyer's own message can be
    /// sealed in either direction. Reading one addressed to the seller as an
    /// acceptance would let anything the buyer typed point their own software
    /// at an order.
    #[test]
    fn an_acceptance_addressed_to_the_seller_is_not_one() {
        let order = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        let (mut state, tag) = buyer_after_acceptance(&order);

        // The same content, sealed the other way: buyer-to-seller.
        let keys = seller_keys_for(&tag);
        let conversation_id = state.browsing_stores[STORE].conversations[0]
            .conversation_id
            .clone();
        let wrong_way = crate::messaging::seal_for_test(
            &keys.to_seller,
            &tag,
            &conversation_id,
            crate::messaging::MessageContent::OrderAccepted {
                order_id: order.order.id.clone(),
            },
        )
        .expect("seal");
        state
            .browsing_stores
            .get_mut(STORE)
            .expect("the store")
            .mailbox_messages = vec![wrong_way];

        assert!(
            purchases(&state).is_empty(),
            "a message the buyer could have written is not the seller accepting"
        );
    }

    /// **Every acceptance in the thread is a purchase, and each is judged on
    /// its own.**
    ///
    /// A buyer can buy twice from one store. Collapsing to the newest would
    /// hide an earlier order the buyer still owes money on, and judging them
    /// together would let one fresh anchor carry a stale one.
    #[test]
    fn two_acceptances_are_two_purchases_judged_separately() {
        let fresh = commitment(
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT)),
            OrderStatus::AwaitingPayment,
        );
        // Signed with the stale anchor rather than edited afterwards: an
        // edited order fails its signature check first, and the test would
        // then pass without ever reaching the freshness rule it is about.
        let stale = commitment_for(
            "Second widget",
            &seller_signing_key(),
            Some(anchor(TIP_HEIGHT - MAX_ANCHOR_AGE_BLOCKS - 1)),
            OrderStatus::AwaitingPayment,
            Some(the_buyers_conversation().order_binding()),
        );
        assert_ne!(fresh.order.id, stale.order.id, "two distinct orders");

        let (mut state, tag) = buyer_after_acceptance(&fresh);
        let conversation_id = state.browsing_stores[STORE].conversations[0]
            .conversation_id
            .clone();
        let acceptance = crate::messaging::seal_order_accepted(
            &seller_keys_for(&tag),
            &tag,
            &conversation_id,
            &stale.order.id,
        )
        .expect("seal");
        {
            let store = state.browsing_stores.get_mut(STORE).expect("the store");
            store.mailbox_messages.push(acceptance);
            store.orders.push(stale.clone());
        }

        let found = purchases(&state);
        assert_eq!(found.len(), 2, "two acceptances, two purchases");
        let payable = found
            .iter()
            .find(|purchase| purchase.order_id == fresh.order.id)
            .expect("the fresh purchase");
        assert_eq!(payable.blockers, Vec::new());
        let refused = found
            .iter()
            .find(|purchase| purchase.order_id == stale.order.id)
            .expect("the stale purchase");
        assert_eq!(
            refused.blockers,
            vec![PaymentBlocker::AnchorStale {
                anchor_height: TIP_HEIGHT - MAX_ANCHOR_AGE_BLOCKS - 1,
                tip_height: TIP_HEIGHT,
            }]
        );
    }
}

#[cfg(test)]
mod payment_blocker_wording_tests {
    use super::*;
    use harvest_common::payment::OrderStatus;

    /// Every variant, once each.
    ///
    /// # Why the match is over the LIST rather than beside it
    ///
    /// The first version of this built a `vec!` and put an exhaustive `match`
    /// next to it, and its comment claimed that made a missing variant a
    /// compile error. It did not: the match forced itself to be updated and
    /// the list was independent, so a variant could be added to one and left
    /// out of the other and this test would silently stop covering it. Review
    /// found it.
    ///
    /// Matching on each element of the list is what actually ties them: a new
    /// variant does not compile until it is in the match, and the only way to
    /// reach the match is to be in the list. The `seen` count then fails if
    /// the list holds fewer distinct variants than the match has arms.
    fn every_blocker() -> Vec<PaymentBlocker> {
        let all = vec![
            PaymentBlocker::CommitmentNotPublished,
            PaymentBlocker::SellerIdentityUnknown,
            PaymentBlocker::CommitmentNotTheSellers("the signature is not theirs".to_string()),
            PaymentBlocker::CommitmentNotForThisBuyer,
            PaymentBlocker::NoTrustedBridge,
            PaymentBlocker::BridgeNotRecognised("7Kf2abcd".to_string()),
            PaymentBlocker::DestinationDisagrees,
            PaymentBlocker::DestinationUnreadable,
            PaymentBlocker::CommitmentNotRequested,
            PaymentBlocker::NotAwaitingPayment(OrderStatus::Cancelled),
            PaymentBlocker::AnchorMissing,
            PaymentBlocker::ChainUnknown,
            PaymentBlocker::AnchorOffChain,
            PaymentBlocker::AnchorUnverifiable,
            PaymentBlocker::AnchorAheadOfTip {
                anchor_height: 801_000,
                tip_height: 800_000,
            },
            PaymentBlocker::AnchorStale {
                anchor_height: 799_000,
                tip_height: 800_000,
            },
            PaymentBlocker::ConversationNotKept,
        ];

        // Exhaustive and wildcard-free, over the list itself. Each arm is
        // reached exactly once by a well-formed list; `discriminant` counts
        // distinct variants rather than entries, so duplicating one to pad
        // the list does not hide an omission.
        let mut seen = std::collections::HashSet::new();
        for blocker in &all {
            match blocker {
                PaymentBlocker::CommitmentNotPublished
                | PaymentBlocker::SellerIdentityUnknown
                | PaymentBlocker::CommitmentNotTheSellers(_)
                | PaymentBlocker::CommitmentNotForThisBuyer
                | PaymentBlocker::NoTrustedBridge
                | PaymentBlocker::BridgeNotRecognised(_)
                | PaymentBlocker::DestinationDisagrees
                | PaymentBlocker::DestinationUnreadable
                | PaymentBlocker::CommitmentNotRequested
                | PaymentBlocker::NotAwaitingPayment(_)
                | PaymentBlocker::AnchorMissing
                | PaymentBlocker::ChainUnknown
                | PaymentBlocker::AnchorOffChain
                | PaymentBlocker::AnchorUnverifiable
                | PaymentBlocker::AnchorAheadOfTip { .. }
                | PaymentBlocker::AnchorStale { .. }
                | PaymentBlocker::ConversationNotKept => {}
            }
            seen.insert(std::mem::discriminant(blocker));
        }
        assert_eq!(
            seen.len(),
            EVERY_BLOCKER,
            "the list must hold every variant exactly once; add the new one here as well as \
             to the match"
        );
        all
    }

    /// How many variants `PaymentBlocker` has.
    ///
    /// The one number a future edit has to change by hand, and the assertion
    /// above is what makes forgetting it fail rather than silently narrow the
    /// coverage.
    const EVERY_BLOCKER: usize = 17;

    /// **Every blocker says something, and says it as prose.**
    ///
    /// These sentences are the only thing a buyer has to decide on, and they
    /// are assembled from `\`-continued string literals -- a form where
    /// dropping the backslash leaves a run of spaces in the middle of the
    /// sentence and nothing complains. That happened once while this change
    /// was being written, in `components::buy_view`, and was caught by
    /// reading the file rather than by anything automatic. This is the
    /// automatic part.
    #[test]
    fn every_blocker_reads_as_a_sentence() {
        for blocker in every_blocker() {
            let said = blocker.describe();
            assert!(
                !said.trim().is_empty(),
                "{blocker:?} tells the buyer nothing"
            );
            assert!(
                !said.contains("  "),
                "{blocker:?} has a broken line continuation: {said}"
            );
            assert!(
                said.ends_with('.'),
                "{blocker:?} is not a finished sentence: {said}"
            );
        }
    }
}
