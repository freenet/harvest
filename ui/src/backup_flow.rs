//! One backup for all of a buyer's purchases (step 2).
//!
//! # The file
//!
//! `harvest-purchases-<date>.txt`: a few lines a person can read (what it is,
//! when it was made, how many purchases and conversations, which stores,
//! and to keep it private), then one line
//! `harvest-backup-v3:<base64 of the CBOR bundle>:<BLAKE3 of the CBOR, hex>`.
//! The bundle names each store by its code, which a store keeps across
//! re-keys, so a restore files each conversation under the store's address
//! today, and remembers the store, with no code typed. The id a store had
//! when the file was made rides along for a store whose code this device
//! did not know.
//!
//! The file is not encrypted. It holds every conversation's secret and
//! every purchase's receipt seed, so anyone with it can read the threads
//! and file complaints as the buyer; the page says so in those words.
//!
//! # Making it
//!
//! The delegate answers a page at a time (`ExportPurchasesBackup`, each
//! within one call's budget); this module asks for each page in turn and
//! assembles the file as soon as the Backup page opens. The buyer's click
//! saves it (a download needs the click), and only then are exactly the
//! items the file holds marked as backed up (`MarkBackedUp`), each purchase
//! by its digest, so a purchase made, paid or complained about later is
//! shown as not in a backup yet, and a file that was never saved marks
//! nothing.
//!
//! # Restoring it
//!
//! From a chosen file or pasted text. The bundle is sent in chunks of
//! `BACKUP_IMPORT_ITEMS` (`ImportPurchasesBackup`), each item kept by the
//! delegate's own rules: what this device already holds stays, a cap
//! refuses rather than evicts. The counts are reported at the end. An old
//! one-conversation string (`harvest-conv-backup-v2:`) is not a bundle; it
//! restores through the delegate's one-conversation import, as before.
//!
//! # An answer that never comes
//!
//! A request the delegate refused answers a bare `Error`, with no request
//! id, and a request can be lost on the way. An `Error` while a backup or a
//! restore is waiting ends it ([`AppState::backup_refused`]), and one that
//! has waited [`BACKUP_ANSWER_WAIT_MS`] for an answer no longer holds the
//! buttons ([`AppState::backup_busy_at`]).

use std::collections::VecDeque;

use harvest_common::delegate::{
    BackupConversation, BackupItemOutcome, KeptPurchase, PurchasesBackupPage, SellerKeptOrder,
    BACKUP_IMPORT_ITEMS, BACKUP_MARK_ITEMS, SELLER_ORDERS_PER_CALL,
};
use harvest_common::store::StoreParameters;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

/// The prefix of the bundle's line.
pub(crate) const BUNDLE_PREFIX: &str = "harvest-backup-v3:";

/// The prefix of an old one-conversation backup string.
pub(crate) const CONVERSATION_STRING_PREFIX: &str = "harvest-conv-backup-v2:";

/// How long a backup or restore waits for the delegate's answer before
/// its buttons work again.
pub(crate) const BACKUP_ANSWER_WAIT_MS: u64 = 60_000;

/// Said beside the button that makes the file.
pub(crate) const KEEP_IT_PRIVATE: &str = "Keep this file private, like a password: anyone with \
     it can read your messages and report problems as you.";

/// One store in a bundle.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BundleStore {
    /// The store's code, when this device knew it: what its address today
    /// is derived from.
    pub code: Option<String>,
    /// What the store was called, for the file's header and the restore
    /// report. An unsigned label: a wrong one only mislabels.
    pub name: String,
    /// The store's address when the file was made.
    pub contract_id_at_export: Vec<u8>,
}

/// One conversation in a bundle, and the store it is with.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BundleConversation {
    /// Index into [`Bundle::stores`].
    pub store: u32,
    pub conversation: BackupConversation,
}

/// One of the seller's own stores' books in a bundle (step 2): its orders,
/// each open one (not yet sent) with the buyer's request, each sent one
/// without (the overseer, 2026-10-09: a seller's file holding hundreds of
/// customers' home addresses is a different exposure from a buyer's own).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct BundleSellerBook {
    pub store_key: [u8; 32],
    pub orders: Vec<SellerKeptOrder>,
}

/// What a purchases backup holds.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Bundle {
    pub version: u32,
    pub made_at_ms: u64,
    pub stores: Vec<BundleStore>,
    pub conversations: Vec<BundleConversation>,
    pub purchases: Vec<KeptPurchase>,
    /// The seller's own stores' books, when this device sells.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seller_orders: Vec<BundleSellerBook>,
}

/// One delegate call of a restore.
#[derive(Clone, Debug, PartialEq)]
pub enum RestoreChunk {
    Purchases(Vec<BackupConversation>, Vec<KeptPurchase>),
    SellerOrders([u8; 32], Vec<SellerKeptOrder>),
}

/// The bundle's format version.
pub(crate) const BUNDLE_VERSION: u32 = 3;

// --- base64 (standard alphabet, padded) ------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub(crate) fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.as_bytes();
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| -> Option<u32> { B64.iter().position(|b| *b == c).map(|p| p as u32) };
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (i, chunk) in text.chunks(4).enumerate() {
        let last = i == text.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (j, c) in chunk.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { value(*c)? };
            n = (n << 6) | v;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// --- the file ---------------------------------------------------------------

/// The file's name for a bundle made at `made_at_ms`.
pub(crate) fn file_name(made_at_ms: u64) -> String {
    let date = chrono::DateTime::from_timestamp_millis(made_at_ms as i64)
        .unwrap_or_default()
        .format("%Y-%m-%d");
    format!("harvest-purchases-{date}.txt")
}

/// The file's text for `bundle`.
pub(crate) fn encode_file(bundle: &Bundle) -> Result<String, String> {
    let cbor = harvest_common::to_cbor(bundle).map_err(|e| format!("encode the backup: {e}"))?;
    let made = chrono::DateTime::from_timestamp_millis(bundle.made_at_ms as i64)
        .unwrap_or_default()
        .format("%-d %B %Y, %H:%M UTC");
    let mut names: Vec<&str> = bundle.stores.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut text = String::new();
    text.push_str("Harvest: a backup of your purchases\n");
    text.push_str(&format!("Made {made}.\n"));
    text.push_str(&format!(
        "{} purchase{} and {} conversation{}",
        bundle.purchases.len(),
        if bundle.purchases.len() == 1 { "" } else { "s" },
        bundle.conversations.len(),
        if bundle.conversations.len() == 1 {
            ""
        } else {
            "s"
        },
    ));
    if !names.is_empty() {
        text.push_str(&format!(", with {}", names.join(", ")));
    }
    text.push_str(".\n");
    text.push_str(KEEP_IT_PRIVATE);
    text.push_str("\nTo restore: open Harvest, go to Purchases, and choose Restore.\n\n");
    text.push_str(BUNDLE_PREFIX);
    text.push_str(&base64_encode(&cbor));
    text.push(':');
    text.push_str(&blake3::hash(&cbor).to_hex());
    text.push('\n');
    Ok(text)
}

/// The bundle a file's (or pasted) text holds.
pub(crate) fn decode_file(text: &str) -> Result<Bundle, String> {
    let line = text
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix(BUNDLE_PREFIX))
        .ok_or("This is not a Harvest purchases backup.")?;
    let (body, sum) = line
        .rsplit_once(':')
        .ok_or("This backup is damaged: its check is missing.")?;
    let cbor = base64_decode(body.trim()).ok_or("This backup is damaged: it does not decode.")?;
    if blake3::hash(&cbor).to_hex().as_str() != sum.trim() {
        return Err("This backup is damaged: it does not match its check.".into());
    }
    let bundle: Bundle = harvest_common::from_cbor(&cbor)
        .map_err(|e| format!("This backup could not be read: {e}"))?;
    if bundle.version != BUNDLE_VERSION {
        return Err(format!(
            "This backup is version {}, and this Harvest reads version {BUNDLE_VERSION}.",
            bundle.version
        ));
    }
    Ok(bundle)
}

// --- state ------------------------------------------------------------------

/// A backup being assembled from the delegate's pages.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BackupExport {
    pub request_id: u64,
    pub conversations: Vec<BackupConversation>,
    pub purchases: Vec<KeptPurchase>,
    /// When the last page was asked for.
    pub asked_at_ms: u64,
}

/// A restore being sent a chunk at a time.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BackupRestore {
    pub request_id: u64,
    pub chunks: VecDeque<RestoreChunk>,
    pub restored: usize,
    pub already: usize,
    pub refused: Vec<String>,
    /// When the last chunk was sent.
    pub asked_at_ms: u64,
    /// How many of the seller's orders the last chunk carried.
    pub seller_orders_sent: usize,
}

/// A finished backup, waiting for the buyer to save it. The file is made
/// from it as it is saved ([`AppState::ready_backup_file`]), with the
/// seller's books as this tab holds them then.
#[derive(Clone, Debug, PartialEq)]
pub struct ReadyBackup {
    pub name: String,
    pub bundle: Bundle,
    pub purchases: usize,
    pub conversations: usize,
    /// The marks for exactly what the file holds, sent once it is saved.
    pub marks: Outgoing,
}

/// What a request to the delegate this module wants sent.
pub(crate) type Outgoing = Vec<harvest_common::HarvestDelegateRequest>;

/// The buyer's X25519 public key for a conversation's secret: its routing
/// tag, which a conversation is marked by.
fn tag_of(secret: &harvest_common::ConversationSecret) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(secret.0);
    *x25519_dalek::PublicKey::from(&secret).as_bytes()
}

impl AppState {
    /// How many kept purchases are not in a backup the buyer holds.
    pub fn purchases_not_backed_up(&self) -> usize {
        self.kept_purchases.iter().filter(|k| !k.backed_up).count()
    }

    /// How many kept purchases, and how many of the conversations this
    /// device keeps with stores it does not own, are in no backup the
    /// buyer saved.
    pub fn not_backed_up(&self) -> (usize, usize) {
        let conversations = self
            .browsing_stores
            .iter()
            .filter(|(id, _)| self.store_owner_fingerprint(id).is_none())
            .map(|(_, store)| store.conversations.iter().filter(|c| !c.backed_up).count())
            .sum();
        (self.purchases_not_backed_up(), conversations)
    }

    /// Whether this order is in no backup the buyer saved: its kept copy
    /// as it is now is unmarked, or, with no kept copy, the conversation
    /// it was placed in is.
    pub(crate) fn order_not_backed_up(
        &self,
        store_contract_id: &[u8],
        order: &harvest_common::payment::OrderId,
        conversation: &[u8; 32],
    ) -> bool {
        match self
            .kept_purchases
            .iter()
            .find(|k| k.order.order.id == *order)
        {
            Some(kept) => !kept.backed_up,
            None => self
                .browsing_stores
                .get(store_contract_id)
                .and_then(|s| {
                    s.conversations
                        .iter()
                        .find(|c| c.buyer_public_key == *conversation)
                })
                .is_some_and(|c| !c.backed_up),
        }
    }

    /// Whether a backup or restore is waiting on the delegate, and has not
    /// waited past [`BACKUP_ANSWER_WAIT_MS`].
    pub(crate) fn backup_busy_at(&self, now_ms: u64) -> bool {
        let waiting = |asked: u64| now_ms.saturating_sub(asked) < BACKUP_ANSWER_WAIT_MS;
        self.backup_export
            .as_ref()
            .is_some_and(|e| waiting(e.asked_at_ms))
            || self
                .backup_restore
                .as_ref()
                .is_some_and(|r| waiting(r.asked_at_ms))
    }

    /// The delegate answered a bare `Error`: an export or restore waiting on
    /// it ends, saying why. Answers whether one was waiting.
    pub(crate) fn backup_refused(&mut self, why: &str) -> bool {
        if self.backup_export.take().is_some() {
            self.backup_message = Some(format!("The backup could not be made: {why}"));
            return true;
        }
        if let Some(done) = self.backup_restore.take() {
            self.backup_message = Some(format!(
                "The restore stopped: {why}. {} restored, {} already here before it stopped.",
                done.restored, done.already
            ));
            return true;
        }
        false
    }

    /// The file to save now, `(name, text)`: the backup made, with the
    /// seller's own books as this tab holds them.
    pub(crate) fn ready_backup_file(&self) -> Option<(String, String)> {
        let ready = self.backup_file_ready.as_ref()?;
        let mut bundle = ready.bundle.clone();
        bundle.seller_orders = self.seller_books_for_backup();
        encode_file(&bundle)
            .ok()
            .map(|text| (ready.name.clone(), text))
    }

    /// Each of our stores' books, open orders with their requests and sent
    /// ones without.
    pub(crate) fn seller_books_for_backup(&self) -> Vec<BundleSellerBook> {
        let mut books: Vec<BundleSellerBook> = self
            .seller_books
            .iter()
            .filter(|(_, b)| b.loaded && !b.orders.is_empty())
            .map(|(key, b)| BundleSellerBook {
                store_key: *key,
                orders: b
                    .orders
                    .iter()
                    .cloned()
                    .map(|mut r| {
                        if r.despatch.is_some()
                            || r.order.status
                                == harvest_common::payment::OrderStatus::PaymentReversed
                        {
                            r.request = None;
                        }
                        r
                    })
                    .collect(),
            })
            .collect();
        books.sort_by_key(|b| b.store_key);
        books
    }

    /// How many of our stores' books this tab has not read yet, so a backup
    /// made now would leave out: said on the Backup page.
    pub fn seller_books_unread(&self) -> usize {
        self.my_stores
            .values()
            .flatten()
            .filter_map(|r| r.store_verifying_key)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter(|key| self.seller_books.get(key).is_none_or(|b| !b.loaded))
            .count()
    }

    /// How many delivery addresses of orders not yet sent a backup made now
    /// would hold: said on the Backup page.
    pub fn unsent_addresses_in_backup(&self) -> usize {
        self.seller_books_for_backup()
            .iter()
            .flat_map(|b| b.orders.iter())
            .filter(|r| r.request.is_some())
            .count()
    }

    /// The buyer saved the file (or copied its text): mark exactly what it
    /// holds, and start the next one, so the button is ready again.
    pub(crate) fn backup_saved(&mut self) -> Outgoing {
        let Some(ready) = self.backup_file_ready.take() else {
            return Vec::new();
        };
        let orders: usize = self
            .seller_books_for_backup()
            .iter()
            .map(|b| b.orders.len())
            .sum();
        self.backup_message = Some(format!(
            "Saved {}. It holds {}{}. Keep it somewhere other than this computer.",
            ready.name,
            held_words(ready.purchases, ready.conversations),
            match orders {
                0 => String::new(),
                1 => ", and 1 of your store\u{2019}s orders".to_string(),
                n => format!(", and {n} of your store\u{2019}s orders"),
            },
        ));
        let mut out = ready.marks;
        out.extend(self.start_backup_export());
        out
    }

    /// The code of the store at `contract_id`, if this device knows it.
    fn code_of_store(&self, contract_id: &[u8]) -> Option<String> {
        if let Some(code) = self.store_codes.get(contract_id) {
            return Some(code.clone());
        }
        if let Some(code) = self.remembered_stores.iter().flatten().find_map(|s| {
            let id = StoreParameters::from_code(&s.store_code)
                .and_then(|p| crate::gateway::store_ops::store_instance_id(&p).ok())?;
            (id.as_bytes() == contract_id).then(|| s.store_code.clone())
        }) {
            return Some(code);
        }
        let owner = self.browsing_stores.get(contract_id)?.owner?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&owner).ok()?;
        Some(StoreParameters::new(key).code().to_string())
    }

    /// Start making a backup: ask for its first page. Nothing while one is
    /// being made or a restore runs (one that has waited past
    /// [`BACKUP_ANSWER_WAIT_MS`] is started again).
    pub(crate) fn start_backup_export(&mut self) -> Outgoing {
        let now = crate::state::now_ms();
        if self.backup_busy_at(now) {
            return Vec::new();
        }
        self.backup_restore = None;
        let request_id = self.next_messaging_request_id();
        self.backup_export = Some(BackupExport {
            request_id,
            asked_at_ms: now,
            ..Default::default()
        });
        vec![
            harvest_common::HarvestDelegateRequest::ExportPurchasesBackup {
                request_id,
                after: None,
            },
        ]
    }

    /// A page of the backup arrived: ask for the next, or, after the last,
    /// make the file and mark what it holds.
    pub(crate) fn on_purchases_backup(
        &mut self,
        request_id: u64,
        result: Result<PurchasesBackupPage, String>,
    ) -> Outgoing {
        let Some(export) = self.backup_export.as_mut() else {
            return Vec::new();
        };
        if export.request_id != request_id {
            return Vec::new();
        }
        let page = match result {
            Ok(page) => page,
            Err(why) => {
                self.backup_export = None;
                self.backup_message = Some(format!("The backup could not be made: {why}"));
                return Vec::new();
            }
        };
        export.conversations.extend(page.conversations);
        export.purchases.extend(page.purchases);
        if let Some(after) = page.next {
            export.asked_at_ms = crate::state::now_ms();
            return vec![
                harvest_common::HarvestDelegateRequest::ExportPurchasesBackup {
                    request_id,
                    after: Some(after),
                },
            ];
        }
        let export = self.backup_export.take().unwrap_or_default();
        let made_at_ms = crate::state::now_ms();
        let bundle = self.bundle_of(export, made_at_ms);
        match encode_file(&bundle) {
            Ok(_) => {
                self.backup_file_ready = Some(ReadyBackup {
                    name: file_name(made_at_ms),
                    purchases: bundle.purchases.len(),
                    conversations: bundle.conversations.len(),
                    marks: marks_for(&bundle, request_id),
                    bundle,
                });
            }
            Err(why) => {
                self.backup_message = Some(format!("The backup could not be made: {why}"));
            }
        }
        Vec::new()
    }

    /// The bundle for what the delegate exported, each conversation's store
    /// named by its code where this device knows it.
    pub(crate) fn bundle_of(&self, export: BackupExport, made_at_ms: u64) -> Bundle {
        let mut stores: Vec<BundleStore> = Vec::new();
        let index_of = |id: &[u8], stores: &mut Vec<BundleStore>| -> u32 {
            if let Some(at) = stores.iter().position(|s| s.contract_id_at_export == id) {
                return at as u32;
            }
            stores.push(BundleStore {
                code: self.code_of_store(id),
                name: self.store_name_of(id).label(),
                contract_id_at_export: id.to_vec(),
            });
            (stores.len() - 1) as u32
        };
        let conversations = export
            .conversations
            .into_iter()
            .map(|conversation| BundleConversation {
                store: index_of(&conversation.store_contract_id, &mut stores),
                conversation,
            })
            .collect();
        Bundle {
            version: BUNDLE_VERSION,
            made_at_ms,
            stores,
            conversations,
            purchases: export.purchases,
            seller_orders: Vec::new(),
        }
    }

    /// Restore from a file's or a pasted text. Answers what to send.
    pub(crate) fn start_restore(&mut self, text: &str) -> Outgoing {
        let now = crate::state::now_ms();
        if self
            .backup_restore
            .as_ref()
            .is_some_and(|r| now.saturating_sub(r.asked_at_ms) < BACKUP_ANSWER_WAIT_MS)
        {
            return Vec::new();
        }
        // An old one-conversation string goes through the delegate's own
        // import for it, which says what it did.
        let trimmed = text.trim();
        if trimmed.starts_with(CONVERSATION_STRING_PREFIX) {
            self.backup_message = Some("Restoring that conversation\u{2026}".into());
            return vec![self.conversation_to_import(trimmed.to_string())];
        }
        let bundle = match decode_file(text) {
            Ok(bundle) => bundle,
            Err(why) => {
                self.backup_message = Some(why);
                return Vec::new();
            }
        };
        // Each store at its address today, and remembered, so its page and
        // My purchases list it.
        let mut current: Vec<Vec<u8>> = Vec::with_capacity(bundle.stores.len());
        for store in &bundle.stores {
            let id = store
                .code
                .as_deref()
                .and_then(StoreParameters::from_code)
                .and_then(|p| crate::gateway::store_ops::store_instance_id(&p).ok())
                .map(|id| id.as_bytes().to_vec());
            if let Some(code) = &store.code {
                self.remember_store(code);
            }
            current.push(id.unwrap_or_else(|| store.contract_id_at_export.clone()));
        }
        let conversations: Vec<BackupConversation> = bundle
            .conversations
            .into_iter()
            .map(|c| {
                let mut conversation = c.conversation;
                if let Some(id) = current.get(c.store as usize) {
                    if let Ok(id) = <[u8; 32]>::try_from(id.as_slice()) {
                        conversation.store_contract_id = id;
                    }
                }
                conversation
            })
            .collect();
        let mut chunks: VecDeque<RestoreChunk> = VecDeque::new();
        for chunk in conversations.chunks(BACKUP_IMPORT_ITEMS) {
            chunks.push_back(RestoreChunk::Purchases(chunk.to_vec(), Vec::new()));
        }
        for chunk in bundle.purchases.chunks(BACKUP_IMPORT_ITEMS) {
            chunks.push_back(RestoreChunk::Purchases(Vec::new(), chunk.to_vec()));
        }
        for book in &bundle.seller_orders {
            for chunk in book.orders.chunks(SELLER_ORDERS_PER_CALL) {
                chunks.push_back(RestoreChunk::SellerOrders(book.store_key, chunk.to_vec()));
            }
        }
        let request_id = self.next_messaging_request_id();
        // The file made before this restore no longer holds everything.
        self.backup_file_ready = None;
        self.backup_export = None;
        self.backup_restore = Some(BackupRestore {
            request_id,
            chunks,
            asked_at_ms: now,
            ..Default::default()
        });
        self.backup_message = Some("Restoring your backup\u{2026}".into());
        self.next_restore_chunk()
    }

    fn next_restore_chunk(&mut self) -> Outgoing {
        let Some(restore) = self.backup_restore.as_mut() else {
            return Vec::new();
        };
        match restore.chunks.pop_front() {
            Some(RestoreChunk::Purchases(conversations, purchases)) => {
                restore.asked_at_ms = crate::state::now_ms();
                vec![
                    harvest_common::HarvestDelegateRequest::ImportPurchasesBackup {
                        request_id: restore.request_id,
                        conversations,
                        purchases,
                    },
                ]
            }
            Some(RestoreChunk::SellerOrders(store_key, orders)) => {
                restore.asked_at_ms = crate::state::now_ms();
                restore.seller_orders_sent = orders.len();
                vec![harvest_common::HarvestDelegateRequest::KeepSellerOrders {
                    request_id: restore.request_id,
                    store_key,
                    orders,
                }]
            }
            None => {
                let done = self.backup_restore.take().unwrap_or_default();
                let mut message =
                    format!("{} restored, {} already here.", done.restored, done.already);
                if !done.refused.is_empty() {
                    message.push_str(&format!(
                        " {} not restored: {}",
                        done.refused.len(),
                        done.refused.join("; ")
                    ));
                }
                self.backup_message = Some(message);
                // What the delegate now holds, shown: the purchases, and each
                // of our stores' books (one a full book could not take is
                // named there, and on the store's Home).
                let mut out = vec![harvest_common::HarvestDelegateRequest::ListKeptPurchases];
                let own: Vec<Vec<u8>> = self
                    .browsing_stores
                    .iter()
                    .filter(|(_, s)| s.owner.is_some_and(|k| self.seller_books.contains_key(&k)))
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in own {
                    out.extend(self.read_seller_book(&id));
                }
                out
            }
        }
    }

    /// A chunk of a restore was answered: count it, and send the next.
    pub(crate) fn on_purchases_backup_imported(
        &mut self,
        request_id: u64,
        result: Result<Vec<BackupItemOutcome>, String>,
    ) -> Outgoing {
        let Some(restore) = self.backup_restore.as_mut() else {
            return Vec::new();
        };
        if restore.request_id != request_id {
            return Vec::new();
        }
        match result {
            Ok(outcomes) => {
                for outcome in outcomes {
                    match outcome {
                        BackupItemOutcome::Imported => restore.restored += 1,
                        BackupItemOutcome::AlreadyHeld => restore.already += 1,
                        BackupItemOutcome::Refused(why) => restore.refused.push(why),
                    }
                }
            }
            Err(why) => restore.refused.push(why),
        }
        self.next_restore_chunk()
    }

    /// A restore's chunk of the seller's orders was answered, if it was
    /// one: count it, and send the next. Answers `None` for a keep that is
    /// not the restore's.
    pub(crate) fn on_restored_seller_orders(
        &mut self,
        request_id: u64,
        result: &Result<u32, String>,
    ) -> Option<Outgoing> {
        let restore = self
            .backup_restore
            .as_mut()
            .filter(|r| r.request_id == request_id)?;
        match result {
            Ok(kept) => {
                let kept = *kept as usize;
                restore.restored += kept;
                restore.already += restore.seller_orders_sent.saturating_sub(kept);
            }
            Err(why) => restore.refused.push(why.clone()),
        }
        Some(self.next_restore_chunk())
    }

    /// The marks were recorded: show what the delegate now holds.
    pub(crate) fn on_backed_up_marked(&mut self, result: Result<u32, String>) -> Outgoing {
        if let Err(why) = result {
            self.backup_message = Some(format!(
                "Your backup was made, but this device could not record it: {why}"
            ));
        }
        vec![harvest_common::HarvestDelegateRequest::ListKeptPurchases]
    }
}

/// What the Backup page says when a backup would hold buyers' delivery
/// addresses: the seller's orders not yet sent (step 2).
pub(crate) fn addresses_line(addresses: usize) -> Option<String> {
    match addresses {
        0 => None,
        1 => Some(
            "It also holds the delivery address of 1 of your store\u{2019}s orders not \
             yet sent: keep it as private as the buyer would want."
                .to_string(),
        ),
        n => Some(format!(
            "It also holds the delivery addresses of {n} of your store\u{2019}s orders not \
             yet sent: keep it as private as your buyers would want."
        )),
    }
}

/// "2 purchases and 1 conversation".
fn held_words(purchases: usize, conversations: usize) -> String {
    format!(
        "{purchases} purchase{} and {conversations} conversation{}",
        if purchases == 1 { "" } else { "s" },
        if conversations == 1 { "" } else { "s" },
    )
}

/// The `MarkBackedUp` requests for exactly what `bundle` holds: each
/// conversation by its store and tag, each purchase by its order and the
/// digest of the copy the file holds.
fn marks_for(bundle: &Bundle, request_id: u64) -> Outgoing {
    enum Mark {
        Conversation([u8; 32], [u8; 32]),
        Order(harvest_common::payment::OrderId, [u8; 32]),
    }
    let items: Vec<Mark> = bundle
        .conversations
        .iter()
        .map(|c| {
            Mark::Conversation(
                c.conversation.store_contract_id,
                tag_of(&c.conversation.secret),
            )
        })
        .chain(
            bundle
                .purchases
                .iter()
                .map(|p| Mark::Order(p.order.order.id.clone(), p.backup_digest())),
        )
        .collect();
    items
        .chunks(BACKUP_MARK_ITEMS)
        .map(
            |chunk| harvest_common::HarvestDelegateRequest::MarkBackedUp {
                request_id,
                conversations: chunk
                    .iter()
                    .filter_map(|m| match m {
                        Mark::Conversation(store, tag) => Some((*store, *tag)),
                        Mark::Order(..) => None,
                    })
                    .collect(),
                orders: chunk
                    .iter()
                    .filter_map(|m| match m {
                        Mark::Order(id, digest) => Some((id.clone(), *digest)),
                        Mark::Conversation(..) => None,
                    })
                    .collect(),
            },
        )
        .collect()
}

/// Send each of `requests` to the delegate.
pub(crate) fn send_all(requests: Outgoing) {
    #[cfg(target_arch = "wasm32")]
    for request in requests {
        crate::state::spawn_harvest_request(request, "a purchases backup request");
    }
    #[cfg(all(not(target_arch = "wasm32"), test))]
    SENT.with(|sent| sent.borrow_mut().extend(requests));
    #[cfg(all(not(target_arch = "wasm32"), not(test)))]
    let _ = requests;
}

#[cfg(test)]
thread_local! {
    /// What [`send_all`] was given, for a test to read.
    pub(crate) static SENT: std::cell::RefCell<Outgoing> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Base64 round-trips every length mod 3 and refuses what is not base64.
    #[test]
    fn base64_round_trips() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = base64_encode(&bytes);
            assert_eq!(base64_decode(&text), Some(bytes), "length {len}");
        }
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_decode("TWE"), None);
        assert_eq!(base64_decode("TW=u"), None);
        assert_eq!(base64_decode("T!Fu"), None);
    }

    fn conversation(seed: u8) -> BackupConversation {
        BackupConversation {
            store_contract_id: [seed; 32],
            secret: harvest_common::ConversationSecret([seed.wrapping_add(1); 32]),
            seller_public_key: [5; 32],
            conversation_id: [seed; 32],
            created_at: 1_700_000_000,
        }
    }

    fn kept_order(n: u8) -> harvest_common::payment::AuthorizedOrder {
        harvest_common::payment::AuthorizedOrder {
            order: harvest_common::payment::Order {
                request_id: None,
                id: harvest_common::payment::OrderId([n; 32]),
                buyer_fingerprint: String::new(),
                seller_fingerprint: String::new(),
                amount_sats: 1,
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                payment_script_pubkey: Vec::new(),
                payment_address: String::new(),
                required_confirmations: 1,
                payment_hash: None,
                trusted_bridges: Vec::new(),
                bitcoin_address_code_hash: None,
                anchor: None,
                order_binding: None,
                listing_tag: None,
                buyer_receipt_key: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status: harvest_common::payment::OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    fn bundle() -> Bundle {
        Bundle {
            version: BUNDLE_VERSION,
            made_at_ms: 1_760_000_000_000,
            stores: vec![BundleStore {
                code: Some("Abc123".into()),
                name: "Plum Jam Co".into(),
                contract_id_at_export: vec![3; 32],
            }],
            conversations: vec![BundleConversation {
                store: 0,
                conversation: conversation(3),
            }],
            purchases: Vec::new(),
            seller_orders: Vec::new(),
        }
    }

    /// The file says what it is in words, holds the bundle once, and reads
    /// back; a damaged line is refused with why. Mutated red by dropping the
    /// check.
    #[test]
    fn a_file_reads_back_and_a_damaged_one_is_refused() {
        let text = encode_file(&bundle()).unwrap();
        assert!(text.starts_with("Harvest: a backup of your purchases\n"));
        assert!(text.contains("0 purchases and 1 conversation, with Plum Jam Co."));
        assert!(text.contains(KEEP_IT_PRIVATE));
        assert_eq!(decode_file(&text), Ok(bundle()));
        let line = text.lines().find(|l| l.starts_with(BUNDLE_PREFIX)).unwrap();
        // One character of the body changed, still base64.
        let at = BUNDLE_PREFIX.len() + 4;
        let mut damaged = line.to_string();
        let swapped = if &damaged[at..at + 1] == "A" {
            "B"
        } else {
            "A"
        };
        damaged.replace_range(at..at + 1, swapped);
        assert!(decode_file(&damaged)
            .unwrap_err()
            .contains("does not match its check"));
        assert!(decode_file("hello").is_err());
        assert_eq!(
            file_name(1_760_000_000_000),
            "harvest-purchases-2025-10-09.txt"
        );
    }

    /// Making a backup: each page asks for the next, the last makes the
    /// file and marks nothing; saving it marks exactly what it holds (each
    /// conversation by its store and tag, each purchase by its order and
    /// the digest of the copy held) and starts the next file, and the file
    /// is offered once. Mutated red by marking at the last page, by marking
    /// a conversation by its secret, and by keeping the file after it is
    /// saved.
    #[test]
    fn a_backup_is_assembled_from_pages_and_marks_what_it_holds() {
        let mut state = AppState::default();
        let first = state.start_backup_export();
        let harvest_common::HarvestDelegateRequest::ExportPurchasesBackup {
            request_id,
            after: None,
        } = first[0]
        else {
            panic!("{first:?}");
        };
        assert!(state.start_backup_export().is_empty(), "one at a time");
        let next = state.on_purchases_backup(
            request_id,
            Ok(PurchasesBackupPage {
                conversations: vec![conversation(3)],
                purchases: Vec::new(),
                next: Some("harvest:buyer_conv:x".into()),
            }),
        );
        assert!(matches!(
            &next[..],
            [
                harvest_common::HarvestDelegateRequest::ExportPurchasesBackup {
                    after: Some(_),
                    ..
                }
            ]
        ));
        assert!(state.backup_file_ready.is_none());
        let last = state.on_purchases_backup(
            request_id,
            Ok(PurchasesBackupPage {
                conversations: vec![conversation(4)],
                purchases: Vec::new(),
                next: None,
            }),
        );
        assert!(
            last.is_empty(),
            "nothing is marked before the file is saved"
        );
        let (name, text) = state.ready_backup_file().expect("a file");
        assert!(name.starts_with("harvest-purchases-"));
        let held = decode_file(&text).unwrap();
        assert_eq!(held.conversations.len(), 2);
        assert_eq!(held.stores.len(), 2);
        let marks = state.backup_saved();
        assert!(state.backup_file_ready.is_none(), "offered once");
        assert!(state.backup_saved().is_empty(), "nothing to save twice");
        match &marks[..] {
            [harvest_common::HarvestDelegateRequest::MarkBackedUp {
                conversations,
                orders,
                ..
            }, harvest_common::HarvestDelegateRequest::ExportPurchasesBackup {
                after: None, ..
            }] => {
                assert_eq!(
                    conversations,
                    &vec![
                        ([3; 32], tag_of(&conversation(3).secret)),
                        ([4; 32], tag_of(&conversation(4).secret)),
                    ]
                );
                assert!(orders.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    /// Restoring: chunks of at most `BACKUP_IMPORT_ITEMS`, one at a time,
    /// each conversation filed under its store's address today (derived
    /// from its code), the counts reported at the end, and an old
    /// one-conversation string sent to the delegate's one-conversation
    /// import. Mutated red by
    /// keeping the address the file was made at when the code is known,
    /// and by sending every chunk at once.
    #[test]
    fn a_restore_goes_a_chunk_at_a_time_to_each_stores_address_today() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]).verifying_key();
        let code = StoreParameters::new(key).code().to_string();
        let today = crate::gateway::store_ops::store_instance_id(&StoreParameters::new(key))
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut file = bundle();
        file.stores[0].code = Some(code);
        file.conversations = (0..(BACKUP_IMPORT_ITEMS as u8 + 3))
            .map(|i| BundleConversation {
                store: 0,
                conversation: conversation(i),
            })
            .collect();
        let text = encode_file(&file).unwrap();

        let mut state = AppState::default();
        let first = state.start_restore(&text);
        let request_id = match &first[..] {
            [harvest_common::HarvestDelegateRequest::ImportPurchasesBackup {
                request_id,
                conversations,
                ..
            }] => {
                assert_eq!(conversations.len(), BACKUP_IMPORT_ITEMS);
                assert!(conversations
                    .iter()
                    .all(|c| c.store_contract_id.as_slice() == today.as_slice()));
                *request_id
            }
            other => panic!("{other:?}"),
        };
        let second = state.on_purchases_backup_imported(
            request_id,
            Ok(vec![BackupItemOutcome::Imported; BACKUP_IMPORT_ITEMS]),
        );
        assert!(matches!(
            &second[..],
            [harvest_common::HarvestDelegateRequest::ImportPurchasesBackup { conversations, .. }]
                if conversations.len() == 3
        ));
        let done = state.on_purchases_backup_imported(
            request_id,
            Ok(vec![
                BackupItemOutcome::AlreadyHeld,
                BackupItemOutcome::Imported,
                BackupItemOutcome::Refused("full".into()),
            ]),
        );
        assert!(matches!(
            &done[..],
            [harvest_common::HarvestDelegateRequest::ListKeptPurchases]
        ));
        assert_eq!(
            state.backup_message.as_deref(),
            Some("17 restored, 1 already here. 1 not restored: full")
        );

        let mut state = AppState::default();
        assert!(matches!(
            &state.start_restore("  harvest-conv-backup-v2:abcdef\n")[..],
            [harvest_common::HarvestDelegateRequest::ImportBuyerConversation { backup, .. }]
                if backup.0 == "harvest-conv-backup-v2:abcdef"
        ));
    }

    /// A backup with purchases and more items than one mark takes: the
    /// marks are split `BACKUP_MARK_ITEMS` at a time and together name every
    /// conversation and every purchase, each purchase with the digest of
    /// the copy the file holds. A page the delegate refuses ends the backup
    /// with why; a restore chunk it refuses is counted as not restored and
    /// the next goes on. Mutated red by dropping the purchases from the
    /// marks, and by an export that waits on after a refused page.
    #[test]
    fn marks_are_split_and_refusals_end_or_count() {
        let mut state = AppState::default();
        let first = state.start_backup_export();
        let harvest_common::HarvestDelegateRequest::ExportPurchasesBackup { request_id, .. } =
            first[0]
        else {
            panic!("{first:?}");
        };
        let kept = |n: u8| KeptPurchase {
            store_key: [3; 32],
            conversation: [9; 32],
            receipt_seed: [0; 32],
            order: harvest_common::payment::AuthorizedOrder {
                order: harvest_common::payment::Order {
                    request_id: None,
                    id: harvest_common::payment::OrderId([n; 32]),
                    buyer_fingerprint: String::new(),
                    seller_fingerprint: String::new(),
                    amount_sats: 1,
                    network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                    payment_script_pubkey: Vec::new(),
                    payment_address: String::new(),
                    required_confirmations: 1,
                    payment_hash: None,
                    trusted_bridges: Vec::new(),
                    bitcoin_address_code_hash: None,
                    anchor: None,
                    order_binding: None,
                    listing_tag: None,
                    buyer_receipt_key: None,
                    created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                },
                scoped_payload: Vec::new(),
                signature: Vec::new(),
                status: harvest_common::payment::OrderStatus::AwaitingPayment,
                payment_proof: None,
                status_scoped_payload: None,
                status_signature: None,
            },
            complaint: None,
            despatch: None,
            backed_up: false,
        };
        let purchases: Vec<KeptPurchase> = (0..2).map(kept).collect();
        assert!(state
            .on_purchases_backup(
                request_id,
                Ok(PurchasesBackupPage {
                    conversations: (0..50).map(conversation).collect(),
                    purchases: purchases.clone(),
                    next: None,
                }),
            )
            .is_empty());
        let marks = state.backup_saved();
        let (mut conversations, mut orders) = (0, Vec::new());
        let mut calls = 0;
        for request in &marks {
            if let harvest_common::HarvestDelegateRequest::MarkBackedUp {
                conversations: c,
                orders: o,
                ..
            } = request
            {
                calls += 1;
                assert!(c.len() + o.len() <= BACKUP_MARK_ITEMS);
                conversations += c.len();
                orders.extend(o.iter().cloned());
            }
        }
        assert_eq!(calls, 2);
        assert_eq!(conversations, 50);
        assert_eq!(
            orders,
            purchases
                .iter()
                .map(|p| (p.order.order.id.clone(), p.backup_digest()))
                .collect::<Vec<_>>()
        );

        // A refused page ends the export, saying why.
        let mut state = AppState::default();
        let first = state.start_backup_export();
        let harvest_common::HarvestDelegateRequest::ExportPurchasesBackup { request_id, .. } =
            first[0]
        else {
            panic!("{first:?}");
        };
        assert!(state
            .on_purchases_backup(request_id, Err("no".into()))
            .is_empty());
        assert!(state.backup_export.is_none());
        assert!(state.backup_file_ready.is_none());
        assert_eq!(
            state.backup_message.as_deref(),
            Some("The backup could not be made: no")
        );

        // A refused restore chunk is counted, and the next goes on.
        let mut file = bundle();
        file.conversations = (0..(BACKUP_IMPORT_ITEMS as u8 + 1))
            .map(|i| BundleConversation {
                store: 0,
                conversation: conversation(i),
            })
            .collect();
        let mut state = AppState::default();
        let first = state.start_restore(&encode_file(&file).unwrap());
        let harvest_common::HarvestDelegateRequest::ImportPurchasesBackup { request_id, .. } =
            first[0]
        else {
            panic!("{first:?}");
        };
        let next = state.on_purchases_backup_imported(request_id, Err("busy".into()));
        assert!(matches!(
            &next[..],
            [harvest_common::HarvestDelegateRequest::ImportPurchasesBackup { .. }]
        ));
        state.on_purchases_backup_imported(request_id, Ok(vec![BackupItemOutcome::Imported]));
        assert_eq!(
            state.backup_message.as_deref(),
            Some("1 restored, 0 already here. 1 not restored: busy")
        );
    }

    /// The seller's own books go into the file: an order not yet sent with
    /// the buyer's request, a sent one without (the overseer, 2026-10-09:
    /// no archive of customers' addresses), and the page counts the
    /// addresses it holds; a restore sends them back to the delegate a call
    /// at a time and counts them. Mutated red by exporting every request,
    /// and by leaving the seller's orders out of the restore.
    #[test]
    fn a_sellers_books_are_backed_up_with_only_unsent_addresses() {
        use harvest_common::delegate::{KeptRequest, SellerKeptOrder};
        let record = |n: u8, sent: bool| SellerKeptOrder {
            order: harvest_common::payment::AuthorizedOrder {
                status: harvest_common::payment::OrderStatus::Paid,
                ..kept_order(n)
            },
            request: Some(KeptRequest {
                listing_id: harvest_common::listing::ListingId([4; 32]),
                quantity: 1,
                shipping: format!("{n} Lane"),
                note: String::new(),
                region: None,
                choices: Vec::new(),
                conversation: [9; 32],
            }),
            despatch: sent.then(|| harvest_common::fulfilment::AuthorizedDespatch {
                despatch: harvest_common::fulfilment::Despatch {
                    order_id: harvest_common::payment::OrderId([n; 32]),
                    anchor: freenet_bitcoin_common::BlockAnchor {
                        height: 1,
                        hash: freenet_bitcoin_common::BlockHash([1; 32]),
                    },
                },
                scoped_payload: Vec::new(),
                signature: Vec::new(),
            }),
            paid_height: None,
            sent_off_store: false,
        };
        let mut state = AppState::default();
        state.seller_books.insert(
            [3; 32],
            crate::seller_book::SellerBook {
                orders: vec![record(1, false), record(2, true)],
                loaded: true,
                ..Default::default()
            },
        );
        let books = state.seller_books_for_backup();
        assert_eq!(books.len(), 1);
        assert!(books[0].orders[0].request.is_some(), "not yet sent");
        assert!(books[0].orders[1].request.is_none(), "sent: terms only");
        assert_eq!(state.unsent_addresses_in_backup(), 1);
        let mut reversed = record(5, false);
        reversed.order.status = harvest_common::payment::OrderStatus::PaymentReversed;
        let mut with_reversed = state.clone();
        with_reversed
            .seller_books
            .get_mut(&[3; 32])
            .unwrap()
            .orders
            .push(reversed);
        assert!(
            with_reversed.seller_books_for_backup()[0].orders[2]
                .request
                .is_none(),
            "reversed: terms only"
        );
        assert!(addresses_line(1).unwrap().contains("delivery address"));

        let mut file = bundle();
        file.seller_orders = books;
        let text = encode_file(&file).unwrap();
        assert_eq!(decode_file(&text).unwrap().seller_orders.len(), 1);
        let mut state = AppState::default();
        let first = state.start_restore(&text);
        let request_id = match &first[..] {
            [harvest_common::HarvestDelegateRequest::ImportPurchasesBackup {
                request_id, ..
            }] => *request_id,
            other => panic!("{other:?}"),
        };
        let next =
            state.on_purchases_backup_imported(request_id, Ok(vec![BackupItemOutcome::Imported]));
        match &next[..] {
            [harvest_common::HarvestDelegateRequest::KeepSellerOrders { orders, .. }] => {
                assert_eq!(orders.len(), 2)
            }
            other => panic!("{other:?}"),
        }
        let done = state
            .on_restored_seller_orders(request_id, &Ok(1))
            .expect("the restore's");
        assert!(matches!(
            &done[..],
            [harvest_common::HarvestDelegateRequest::ListKeptPurchases]
        ));
        assert_eq!(
            state.backup_message.as_deref(),
            Some("2 restored, 1 already here.")
        );
    }

    /// A book larger than one call takes is restored in calls of at most
    /// `SELLER_ORDERS_PER_CALL` (the delegate refuses a larger one whole).
    /// Mutated red by one call for the whole book.
    #[test]
    fn a_large_book_is_restored_a_call_at_a_time() {
        use harvest_common::delegate::{SellerKeptOrder, SELLER_ORDERS_PER_CALL};
        let mut file = bundle();
        file.purchases.clear();
        file.conversations.clear();
        file.seller_orders = vec![BundleSellerBook {
            store_key: [3; 32],
            orders: (0..100u8)
                .map(|n| SellerKeptOrder {
                    order: kept_order(n),
                    request: None,
                    despatch: None,
                    paid_height: None,
                    sent_off_store: false,
                })
                .collect(),
        }];
        let mut state = AppState::default();
        let mut sizes = Vec::new();
        let mut out = state.start_restore(&encode_file(&file).unwrap());
        while let [harvest_common::HarvestDelegateRequest::KeepSellerOrders {
            request_id,
            orders,
            ..
        }] = &out[..]
        {
            sizes.push(orders.len());
            let (id, n) = (*request_id, orders.len() as u32);
            out = state
                .on_restored_seller_orders(id, &Ok(n))
                .expect("the restore's");
        }
        assert_eq!(sizes.iter().sum::<usize>(), 100);
        assert!(
            sizes.iter().all(|n| *n <= SELLER_ORDERS_PER_CALL),
            "{sizes:?}"
        );
    }

    /// The order page's backup offer (step 2): an order whose kept copy, as
    /// it is now, is in no saved backup is offered one; once a backup holds
    /// it, not. An order with no kept copy follows its conversation's mark.
    /// Counted for Backup too. Mutated red by reading the store-wide flag,
    /// and by ignoring the kept copy's mark.
    #[test]
    fn an_order_is_offered_a_backup_until_one_holds_it() {
        let mut state = AppState::default();
        let order = harvest_common::payment::OrderId([7; 32]);
        let other = harvest_common::payment::OrderId([8; 32]);
        let kept = |id: &harvest_common::payment::OrderId, backed_up| KeptPurchase {
            store_key: [3; 32],
            conversation: [9; 32],
            receipt_seed: [0; 32],
            order: harvest_common::payment::AuthorizedOrder {
                order: harvest_common::payment::Order {
                    request_id: None,
                    id: id.clone(),
                    buyer_fingerprint: String::new(),
                    seller_fingerprint: String::new(),
                    amount_sats: 1,
                    network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                    payment_script_pubkey: Vec::new(),
                    payment_address: String::new(),
                    required_confirmations: 1,
                    payment_hash: None,
                    trusted_bridges: Vec::new(),
                    bitcoin_address_code_hash: None,
                    anchor: None,
                    order_binding: None,
                    listing_tag: None,
                    buyer_receipt_key: None,
                    created_at: chrono::Utc::now(),
                },
                scoped_payload: Vec::new(),
                signature: Vec::new(),
                status: harvest_common::payment::OrderStatus::Paid,
                payment_proof: None,
                status_scoped_payload: None,
                status_signature: None,
            },
            complaint: None,
            despatch: None,
            backed_up,
        };
        state.kept_purchases = vec![kept(&order, false), kept(&other, true)];
        assert!(state.order_not_backed_up(&[1; 32], &order, &[9; 32]));
        assert!(!state.order_not_backed_up(&[1; 32], &other, &[9; 32]));
        assert_eq!(state.not_backed_up(), (1, 0));
        // No kept copy: its conversation's mark decides.
        let none = harvest_common::payment::OrderId([6; 32]);
        let mut conversation = crate::messaging::BuyerConversation::open(&[5u8; 32]).expect("open");
        let tag = conversation.buyer_public_key;
        state
            .browsing_stores
            .entry(vec![1; 32])
            .or_default()
            .conversations
            .push(conversation.clone());
        assert!(state.order_not_backed_up(&[1; 32], &none, &tag));
        assert_eq!(state.not_backed_up(), (1, 1));
        conversation.backed_up = true;
        state
            .browsing_stores
            .get_mut(&vec![1u8; 32])
            .unwrap()
            .conversations = vec![conversation];
        assert!(!state.order_not_backed_up(&[1; 32], &none, &tag));
    }

    /// A delegate `Error` while a backup or a restore waits ends it, saying
    /// why; one whose answer never came stops holding the buttons after
    /// `BACKUP_ANSWER_WAIT_MS`. Mutated red by not ending on `Error`, and by
    /// holding the buttons for good.
    #[test]
    fn a_backup_whose_answer_never_comes_does_not_hold_the_page() {
        let mut state = AppState::default();
        assert!(!state.start_backup_export().is_empty());
        let now = crate::state::now_ms();
        assert!(state.backup_busy_at(now));
        assert!(state.start_backup_export().is_empty(), "one at a time");
        assert!(!state.backup_busy_at(now + BACKUP_ANSWER_WAIT_MS + 1));
        state.on_delegate_response(harvest_common::HarvestDelegateResponse::Error {
            message: "not allowed".into(),
        });
        assert!(state.backup_export.is_none());
        assert!(!state.backup_busy_at(now));
        assert!(state
            .backup_message
            .as_deref()
            .is_some_and(|m| m.contains("not allowed")));
        // A restore, likewise.
        let text = encode_file(&bundle()).unwrap();
        assert!(!state.start_restore(&text).is_empty());
        assert!(state.backup_busy_at(now));
        state.on_delegate_response(harvest_common::HarvestDelegateResponse::Error {
            message: "full".into(),
        });
        assert!(state.backup_restore.is_none());
        assert!(state
            .backup_message
            .as_deref()
            .is_some_and(|m| m.starts_with("The restore stopped: full")));
    }
}
