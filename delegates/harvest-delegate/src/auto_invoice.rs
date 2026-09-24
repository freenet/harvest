//! Instant checkout: answering a buyer's fixed-price request with an invoice
//! while the seller is away.
//!
//! A listing with fixed terms ([`harvest_common::listing::Listing::checkout`])
//! lets a buyer send a request that already names the total. The seller's UI
//! arms this delegate for the store ([`AutoInvoiceArm`]), the delegate
//! subscribes to the store's mailbox, and each mailbox change runs it with no
//! UI attached. It opens the new requests with the store's inbox key, reads
//! the store, and for each request that passes every check below publishes a
//! signed order and a sealed `OrderAccepted` pointing at it. Anything it
//! declines to answer stays in the mailbox for the seller, exactly as every
//! request did before this existed.
//!
//! # The invariants, and where each is kept
//!
//! - **I1, one order per request.** An order answering a request is
//!   identified by the request ([`harvest_common::payment::Order::request_id`]),
//!   so the store contract holds one per request whatever is published. On top
//!   of that this module skips a request whose order the store already holds,
//!   or which its own ledger records as answered, before it derives anything.
//! - **I2, no address reuse.** Addresses come only from
//!   [`crate::bitcoin::apply_derive_order_address`], after the counter has been
//!   raised past the store's published scripts, and only after every refusal
//!   check has passed, so a refused request burns nothing.
//! - **I3, the last item goes once.** Requests in one run are decided in one
//!   order against a running count that starts from the newer of the store's
//!   status and this delegate's own last-signed one.
//! - **I4, bounded exposure.** At most [`MAX_OPEN_PER_STORE`] open unpaid
//!   instant invoices per store, [`MAX_OPEN_PER_CONVERSATION`] per buyer
//!   conversation, [`MAX_PER_DAY`] a day, and none while the newest
//!   [`MAX_TRAILING_UNPAID`] addresses are all unpaid (a wallet stops looking
//!   after about 20 unused addresses in a row).
//! - **I5, fall back rather than guess.** Every missing or doubtful input ends
//!   in no invoice: see [`Refusal`].
//! - **I6, authority.** Only the Harvest web app can arm (the origin gate in
//!   `lib.rs`), and notifications are acted on only for contracts named in an
//!   arm.
//! - **I7, every address is watched.** The delegate invoices only on an
//!   address the seller's UI has had the bridge read a watch request for, and
//!   only until that watch lapses (see [`AutoInvoiceArm`]). Without this a
//!   payment made before the seller next opened Harvest would never be seen,
//!   because the bridge does not look back (freenet-bitcoin#7).
//!
//! # What this cannot do
//!
//! Run where the seller's secrets are not the node's own. A background run
//! reads this node's local secrets; on a hosted gateway such as
//! try.freenet.org the seller's arm lives in a per-user scope that run cannot
//! see, so nothing happens there and requests wait for the seller.
//! [`harvest_common::delegate::AutoInvoiceStatus::last_background_run_ms`]
//! is how the UI tells.

use std::collections::VecDeque;

use ed25519_dalek::{SigningKey, VerifyingKey};
use freenet_bitcoin_common::{BitcoinNetwork, BitcoinTipStateV1, BlockAnchor};
use freenet_migrate::SecretStore;
use freenet_stdlib::prelude::{
    ContractInstanceId, DelegateContext, GetContractRequest, OutboundDelegateMsg, StateDelta,
    SubscribeContractRequest, UpdateContractRequest, UpdateData,
};
use serde::{Deserialize, Serialize};

use harvest_common::delegate::{AutoInvoiceArm, AutoInvoiceStatus, HarvestDelegateResponse};
use harvest_common::listing::{
    AuthorizedListingStatus, Listing, ListingAvailability, ListingId, ListingStatus,
};
use harvest_common::mailbox::{
    conversation_key_from_dh, entry_digest, listing_tag, EncryptedMessage, MailboxStateV1,
    MessageDirection,
};
use harvest_common::payment::{
    request_id, AuthorizedOrder, Order, OrderId, OrderStatus, MAX_ANCHOR_AGE_BLOCKS,
};
use harvest_common::sealed::{decrypt_message, InstantSelection, MessageContent};
use harvest_common::store::{StoreStateV1, StoreStateV1Delta};
use harvest_common::{from_cbor, to_cbor};

/// Every secret this module writes starts with this. Under `harvest:` so the
/// migration tests hold it to the export prefix, but NOT exported
/// (`migration::is_not_exported`): an arm describes this node's subscriptions
/// and this delegate's own address counter, and the UI re-arms on every open.
pub(crate) const AUTO_PREFIX: &str = "harvest:auto:";

pub(crate) fn arm_key(store_contract_id: &[u8]) -> Vec<u8> {
    format!(
        "{AUTO_PREFIX}arm:{}",
        bs58::encode(store_contract_id).into_string()
    )
    .into_bytes()
}

pub(crate) fn ledger_key(store_contract_id: &[u8]) -> Vec<u8> {
    format!(
        "{AUTO_PREFIX}ledger:{}",
        bs58::encode(store_contract_id).into_string()
    )
    .into_bytes()
}

pub(crate) fn tip_key(network: BitcoinNetwork) -> Vec<u8> {
    format!("{AUTO_PREFIX}tip:{}", network.as_str()).into_bytes()
}

/// The most stores one delegate auto-invoices for. The arm key is sized by a
/// 32-byte id, so this bounds the bytes too.
pub(crate) const MAX_ARMS: usize = 16;
/// A request older (or newer) than this by its envelope time is left for the
/// seller. Bounds what an arm answers from a mailbox that filled while the
/// store was not armed.
pub(crate) const REQUEST_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;
/// The newest block must be at most this old for its hash to anchor an order.
/// A buyer refuses an order whose anchor is more than
/// [`MAX_ANCHOR_AGE_BLOCKS`] behind their tip, so an anchor from a stalled
/// feed would publish an invoice nobody can pay.
pub(crate) const TIP_MAX_AGE_MS: u64 = 3 * 60 * 60 * 1000;
pub(crate) const MAX_OPEN_PER_STORE: usize = 15;
pub(crate) const MAX_OPEN_PER_CONVERSATION: usize = 2;
pub(crate) const MAX_PER_DAY: usize = 30;
pub(crate) const MAX_TRAILING_UNPAID: u32 = 15;
/// Requests answered in one run; the rest wait for the next change.
pub(crate) const MAX_BATCH: usize = 16;
/// Every instant invoice asks one confirmation (harvest#155).
pub(crate) const REQUIRED_CONFIRMATIONS: u32 = 1;
/// How long the bridge must still be watching when an instant invoice goes
/// out: a buyer may start paying until the anchor is
/// [`MAX_ANCHOR_AGE_BLOCKS`] behind (about ten minutes a block), and the
/// payment then needs time to confirm. A payment the bridge was not watching
/// for when it was mined is never seen (freenet-bitcoin#7), so an invoice
/// whose watch could lapse inside this is not issued.
pub(crate) const WATCH_NEEDED_MS: u64 =
    MAX_ANCHOR_AGE_BLOCKS as u64 * 10 * 60 * 1000 + 2 * 60 * 60 * 1000;
/// A reservation whose order has not appeared in the store after this long
/// is taken to have never landed (a refused update), and released.
pub(crate) const NOT_LANDED_MS: u64 = 10 * 60 * 1000;
const SEEN_CAP: usize = 1024;
const ANSWERED_CAP: usize = 1024;
const STATUSES_CAP: usize = 64;
/// At most the open orders the store cap allows, twice over.
const RESERVATIONS_CAP: usize = 2 * MAX_OPEN_PER_STORE;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// An arm as stored.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct ArmRecord {
    pub arm: AutoInvoiceArm,
    /// When this store was first armed here, kept across re-arms.
    pub armed_at_ms: u64,
    /// When the watch on `arm.watched_scripts` lapses, by this node's clock:
    /// the time of the latest arm plus its `watch_left_ms`.
    pub watched_until_ms: u64,
}

/// What this delegate remembers about one store's instant checkout.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
pub(crate) struct Ledger {
    /// Digests of mailbox entries already looked at, oldest first.
    pub seen: VecDeque<[u8; 32]>,
    /// Request ids answered, oldest first.
    pub answered: VecDeque<[u8; 32]>,
    /// When each instant invoice of the last day was issued.
    pub issued_at_ms: Vec<u64>,
    /// The last status this delegate signed per listing, so a run that read
    /// the store before an earlier run's decrement landed still counts it.
    pub statuses: Vec<ListingStatus>,
    /// Stock held by instant invoices not yet paid. Published stock changes
    /// only when an order is PAID ([`settle`]); an unpaid invoice holds its
    /// quantity here until it is paid, cancelled, expires, or never lands.
    /// So nobody can empty a listing by asking for invoices they never pay.
    #[serde(default)]
    pub reservations: Vec<Reservation>,
}

/// Stock one unpaid instant invoice holds.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Reservation {
    pub order: OrderId,
    pub listing: ListingId,
    pub quantity: u32,
    pub issued_at_ms: u64,
}

impl Ledger {
    fn saw(&mut self, digest: [u8; 32]) {
        if !self.seen.contains(&digest) {
            self.seen.push_back(digest);
            while self.seen.len() > SEEN_CAP {
                self.seen.pop_front();
            }
        }
    }

    fn answer(&mut self, request: [u8; 32], now_ms: u64) {
        self.answered.push_back(request);
        while self.answered.len() > ANSWERED_CAP {
            self.answered.pop_front();
        }
        self.issued_at_ms
            .retain(|at| now_ms.saturating_sub(*at) < DAY_MS);
        self.issued_at_ms.push(now_ms);
    }

    fn reserved(&self, listing: &ListingId) -> u32 {
        self.reservations
            .iter()
            .filter(|r| r.listing == *listing)
            .map(|r| r.quantity)
            .sum()
    }

    fn issued_last_day(&self, now_ms: u64) -> usize {
        self.issued_at_ms
            .iter()
            .filter(|at| now_ms.saturating_sub(**at) < DAY_MS)
            .count()
    }

    fn signed(&mut self, status: ListingStatus) {
        self.statuses.retain(|s| s.listing != status.listing);
        self.statuses.push(status);
        while self.statuses.len() > STATUSES_CAP {
            self.statuses.remove(0);
        }
    }
}

/// The newest block this delegate has seen for a network, and when.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct TipCache {
    pub anchor: BlockAnchor,
    /// The block header's own time, in seconds.
    pub block_time: u32,
    /// When a background run last saw the tip contract, by the node's clock.
    pub seen_at_ms: u64,
}

/// Carried through the store GET, so the answer knows which entries to
/// decide. Ciphertext only: the plaintext, keys and the buyer's address never
/// leave this delegate.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct PendingBatch {
    magic: [u8; 8],
    store_contract_id: Vec<u8>,
    entries: Vec<EncryptedMessage>,
}

/// Carried through the store UPDATE: the replies to send once the store has
/// taken the orders, so a buyer is never pointed at an order that did not
/// land.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct PendingReplies {
    magic: [u8; 8],
    mailbox_contract_id: [u8; 32],
    replies: Vec<EncryptedMessage>,
}

const BATCH_MAGIC: [u8; 8] = *b"hvauto01";
const REPLIES_MAGIC: [u8; 8] = *b"hvrepl01";

fn load<S: SecretStore, T: for<'de> Deserialize<'de>>(secrets: &S, key: &[u8]) -> Option<T> {
    secrets.get_secret(key).and_then(|b| from_cbor(&b).ok())
}

fn save<S: SecretStore, T: Serialize>(secrets: &mut S, key: &[u8], value: &T) -> bool {
    to_cbor(value).is_ok_and(|bytes| secrets.set_secret(key, &bytes))
}

pub(crate) fn load_arm<S: SecretStore>(secrets: &S, store_contract_id: &[u8]) -> Option<ArmRecord> {
    load(secrets, &arm_key(store_contract_id))
}

fn arms<S: SecretStore>(secrets: &S) -> Vec<ArmRecord> {
    secrets
        .list_secrets(format!("{AUTO_PREFIX}arm:").as_bytes())
        .iter()
        .filter_map(|key| load(secrets, key))
        .collect()
}

fn load_ledger<S: SecretStore>(secrets: &S, store_contract_id: &[u8]) -> Ledger {
    load(secrets, &ledger_key(store_contract_id)).unwrap_or_default()
}

/// Arm (or re-arm) one store. Answers the status, and subscribes to the three
/// contracts a background run reads.
pub(crate) fn arm<S: SecretStore>(
    secrets: &mut S,
    arm: AutoInvoiceArm,
    now_ms: u64,
) -> (HarvestDelegateResponse, Vec<OutboundDelegateMsg>) {
    let store_contract_id = arm.store_contract_id.clone();
    let refuse = |why: String| {
        (
            HarvestDelegateResponse::AutoInvoice {
                store_contract_id: store_contract_id.clone(),
                result: Err(why),
            },
            Vec::new(),
        )
    };
    let Ok(store_id) = <[u8; 32]>::try_from(arm.store_contract_id.as_slice()) else {
        return refuse("a store contract id is 32 bytes".into());
    };
    if arm.watched_scripts.len() > harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES as usize
    {
        return refuse("too many watched addresses".into());
    }
    if store_key(secrets, &arm.store_verifying_key).is_none() {
        return refuse("this device does not hold that store's key".into());
    }
    let replacing = secrets.has_secret(&arm_key(&arm.store_contract_id));
    if !replacing && arms(secrets).len() >= MAX_ARMS {
        return refuse(format!(
            "instant checkout runs for at most {MAX_ARMS} stores on one device"
        ));
    }
    let record = ArmRecord {
        armed_at_ms: load_arm(secrets, &arm.store_contract_id)
            .map_or(now_ms, |held| held.armed_at_ms),
        watched_until_ms: now_ms.saturating_add(arm.watch_left_ms),
        arm: arm.clone(),
    };
    if !save(secrets, &arm_key(&arm.store_contract_id), &record) {
        return refuse("the node refused to store the arm".into());
    }
    let subscribe = [store_id, arm.mailbox_contract_id, arm.tip_contract_id]
        .into_iter()
        .map(|id| {
            OutboundDelegateMsg::SubscribeContractRequest(SubscribeContractRequest::new(
                ContractInstanceId::new(id),
            ))
        })
        .collect();
    (
        HarvestDelegateResponse::AutoInvoice {
            store_contract_id,
            result: Ok(status_of(secrets, &record, now_ms)),
        },
        subscribe,
    )
}

fn status_of<S: SecretStore>(secrets: &S, record: &ArmRecord, now_ms: u64) -> AutoInvoiceStatus {
    let tip: Option<TipCache> = load(secrets, &tip_key(record.arm.network));
    let ledger = load_ledger(secrets, &record.arm.store_contract_id);
    let remaining = remaining_watched(secrets, &record.arm);
    AutoInvoiceStatus {
        armed_at_ms: record.armed_at_ms,
        watched_remaining: remaining,
        invoicing_until_ms: record.watched_until_ms.saturating_sub(WATCH_NEEDED_MS),
        last_background_run_ms: tip.as_ref().map(|t| t.seen_at_ms),
        issued_last_day: ledger.issued_last_day(now_ms) as u32,
        paused: global_refusal(secrets, record, tip.as_ref(), now_ms)
            .err()
            .map(|r| r.explain()),
    }
}

/// Remove every arm, so no background run here invoices again until the UI
/// arms this delegate afresh. The ledgers stay: they only ever stop a
/// request being answered twice.
pub(crate) fn disarm_all<S: SecretStore + crate::secrets::RemovableSecrets>(secrets: &mut S) {
    for key in secrets.list_secrets(format!("{AUTO_PREFIX}arm:").as_bytes()) {
        secrets.remove_secret(&key);
    }
}

/// How many watched scripts are at or after the counter.
fn remaining_watched<S: SecretStore>(secrets: &S, arm: &AutoInvoiceArm) -> u32 {
    let Some(status) = crate::bitcoin::load_payment_xpub(secrets) else {
        return 0;
    };
    crate::bitcoin::upcoming_addresses(
        &status,
        harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES,
    )
    .map(|upcoming| {
        upcoming
            .iter()
            .filter(|a| arm.watched_scripts.contains(&a.script_pubkey))
            .count() as u32
    })
    .unwrap_or(0)
}

fn store_key<S: SecretStore>(secrets: &S, verifying: &[u8; 32]) -> Option<SigningKey> {
    VerifyingKey::from_bytes(verifying)
        .ok()
        .and_then(|vk| crate::store_keys::load(secrets, &vk))
}

/// Why a request was not answered with an invoice. Every one leaves the
/// request for the seller. (Not enough stock is answered, with a decline,
/// rather than refused.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    // Store-wide: nothing is answered, and the request is not marked seen, so
    // a later arm may still answer it within `REQUEST_MAX_AGE_MS`.
    WatchLapsed,
    NoStoreKey,
    NotOurStore,
    StoreClosed,
    NoPaymentKey,
    NetworkMismatch,
    NoFreshTip,
    NoWatchedAddress,
    CounterNotSaved,
    // Per request: the request is marked seen and left for the seller.
    NotInstant,
    AlreadyAnswered,
    NoBuyerKey,
    NoListing,
    Withdrawn,
    /// Enough is published, but not once unpaid instant invoices' holds are
    /// counted. Left for the seller rather than declined: those invoices may
    /// never be paid.
    Reserved,
    TotalMismatch,
    BindingElsewhere,
    StoreCap,
    ConversationCap,
    DailyCap,
    TrailingUnpaid,
    Signing(String),
}

impl Refusal {
    fn is_store_wide(&self) -> bool {
        matches!(
            self,
            Refusal::WatchLapsed
                | Refusal::NoStoreKey
                | Refusal::NotOurStore
                | Refusal::StoreClosed
                | Refusal::NoPaymentKey
                | Refusal::NetworkMismatch
                | Refusal::NoFreshTip
                | Refusal::NoWatchedAddress
                | Refusal::CounterNotSaved
        )
    }

    pub(crate) fn explain(&self) -> String {
        match self {
            Refusal::WatchLapsed => {
                "the watch on its payment addresses would lapse before a buyer could pay; open \
                 Harvest to renew it"
                    .into()
            }
            Refusal::NoStoreKey => "this device does not hold the store's key".into(),
            Refusal::NotOurStore => "the store is not signed by this store key".into(),
            Refusal::StoreClosed => "the store is closed".into(),
            Refusal::NoPaymentKey => "no payment key is set".into(),
            Refusal::NetworkMismatch => "the payment key is for another network".into(),
            Refusal::NoFreshTip => "no recent Bitcoin block has arrived".into(),
            Refusal::NoWatchedAddress => {
                "every watched payment address is used; open Harvest to watch more".into()
            }
            Refusal::CounterNotSaved => "the address counter could not be saved".into(),
            Refusal::StoreCap => {
                format!("{MAX_OPEN_PER_STORE} instant invoices are waiting for payment")
            }
            Refusal::DailyCap => format!("{MAX_PER_DAY} instant invoices went out today"),
            Refusal::TrailingUnpaid => {
                format!("the last {MAX_TRAILING_UNPAID} payment addresses are all unpaid")
            }
            other => format!("{other:?}"),
        }
    }
}

/// The checks that do not depend on the request. `Ok` carries the anchor.
fn global_refusal<S: SecretStore>(
    secrets: &S,
    record: &ArmRecord,
    tip: Option<&TipCache>,
    now_ms: u64,
) -> Result<BlockAnchor, Refusal> {
    let arm = &record.arm;
    if now_ms.saturating_add(WATCH_NEEDED_MS) >= record.watched_until_ms {
        return Err(Refusal::WatchLapsed);
    }
    if store_key(secrets, &arm.store_verifying_key).is_none() {
        return Err(Refusal::NoStoreKey);
    }
    let xpub = crate::bitcoin::load_payment_xpub(secrets).ok_or(Refusal::NoPaymentKey)?;
    if xpub.network != arm.network {
        return Err(Refusal::NetworkMismatch);
    }
    let tip = tip.ok_or(Refusal::NoFreshTip)?;
    if now_ms.saturating_sub(u64::from(tip.block_time) * 1000) > TIP_MAX_AGE_MS {
        return Err(Refusal::NoFreshTip);
    }
    Ok(tip.anchor)
}

/// A contract this delegate subscribed to changed. `None` when it is not one
/// an arm names, so the caller keeps its old behaviour for it.
pub(crate) fn on_notification<S: SecretStore>(
    secrets: &mut S,
    contract_id: &[u8; 32],
    state: &[u8],
    now_ms: u64,
) -> Option<Vec<OutboundDelegateMsg>> {
    let all = arms(secrets);
    if let Some(record) = all.iter().find(|r| r.arm.tip_contract_id == *contract_id) {
        note_tip(secrets, record.arm.network, state, now_ms);
        return Some(Vec::new());
    }
    if let Some(record) = all
        .iter()
        .find(|r| r.arm.mailbox_contract_id == *contract_id)
    {
        return Some(on_mailbox(secrets, record, state, now_ms));
    }
    if let Some(record) = all
        .iter()
        .find(|r| r.arm.store_contract_id.as_slice() == contract_id.as_slice())
    {
        // A store change may be a payment: release or settle what unpaid
        // instant invoices hold. Our own writes come back here too, and find
        // nothing left to do.
        return Some(on_store_change(secrets, record, state, now_ms));
    }
    None
}

fn on_store_change<S: SecretStore>(
    secrets: &mut S,
    record: &ArmRecord,
    state: &[u8],
    now_ms: u64,
) -> Vec<OutboundDelegateMsg> {
    let Some(store_sk) = store_key(secrets, &record.arm.store_verifying_key) else {
        return Vec::new();
    };
    let Ok(store) = from_cbor::<StoreStateV1>(state) else {
        return Vec::new();
    };
    if store.owner != Some(store_sk.verifying_key()) {
        return Vec::new();
    }
    let tip: Option<TipCache> = load(secrets, &tip_key(record.arm.network));
    let mut ledger = load_ledger(secrets, &record.arm.store_contract_id);
    if ledger.reservations.is_empty() {
        return Vec::new();
    }
    let statuses = settle(
        &mut ledger,
        &store,
        tip.map(|t| t.anchor.height),
        &store_sk,
        now_ms,
    );
    save(secrets, &ledger_key(&record.arm.store_contract_id), &ledger);
    Decided {
        statuses,
        owner: Some(store_sk.verifying_key()),
        ..Default::default()
    }
    .into_messages(&record.arm)
}

/// Settle the ledger's reservations against the store: a PAID order's
/// quantity comes off the published stock (a signed status returned for
/// publishing), and a reservation whose order was cancelled or reversed,
/// expired unpaid, or never landed is released. What is left holds stock.
pub(crate) fn settle(
    ledger: &mut Ledger,
    store: &StoreStateV1,
    tip_height: Option<u32>,
    store_sk: &SigningKey,
    now_ms: u64,
) -> Vec<AuthorizedListingStatus> {
    let mut statuses = Vec::new();
    let reservations = std::mem::take(&mut ledger.reservations);
    for reservation in reservations {
        let keep = match store.orders.orders.get(&reservation.order) {
            None => now_ms.saturating_sub(reservation.issued_at_ms) < NOT_LANDED_MS,
            Some(order) => match order.status {
                OrderStatus::Paid => {
                    let (revision, availability) =
                        effective_status(store, ledger, &reservation.listing);
                    if let ListingAvailability::Available {
                        quantity: Some(left),
                    } = availability
                    {
                        let remaining = left.saturating_sub(reservation.quantity);
                        let status = ListingStatus {
                            listing: reservation.listing.clone(),
                            revision: revision.saturating_add(1).max(now_ms),
                            availability: if remaining == 0 {
                                ListingAvailability::SoldOut
                            } else {
                                ListingAvailability::Available {
                                    quantity: Some(remaining),
                                }
                            },
                        };
                        if let Ok(signed) = sign_status(store_sk, status.clone()) {
                            ledger.signed(status);
                            statuses.retain(|s: &AuthorizedListingStatus| {
                                s.status.listing != reservation.listing
                            });
                            statuses.push(signed);
                        }
                    }
                    false
                }
                OrderStatus::AwaitingPayment => {
                    // Unpaid, and still payable while its anchor is young
                    // enough for a buyer to start paying. With no tip, keep.
                    match (tip_height, order.order.anchor) {
                        (Some(tip), Some(anchor)) => {
                            tip.saturating_sub(anchor.height) <= MAX_ANCHOR_AGE_BLOCKS
                        }
                        (None, _) => true,
                        (_, None) => false,
                    }
                }
                OrderStatus::Cancelled | OrderStatus::PaymentReversed => false,
            },
        };
        if keep {
            ledger.reservations.push(reservation);
        }
    }
    statuses
}

fn note_tip<S: SecretStore>(secrets: &mut S, network: BitcoinNetwork, state: &[u8], now_ms: u64) {
    let Ok(tip) = freenet_bitcoin_common::from_cbor::<BitcoinTipStateV1>(state) else {
        return;
    };
    let Some(newest) = tip.blocks.tip() else {
        return;
    };
    if newest.network != network {
        return;
    }
    let held: Option<TipCache> = load(secrets, &tip_key(network));
    // A copy that is behind never replaces a newer one (harvest#74), but it
    // still counts as a background run.
    let anchor = match &held {
        Some(held) if held.anchor.height > newest.anchor.height => held.clone(),
        _ => TipCache {
            anchor: newest.anchor,
            block_time: newest.block_time,
            seen_at_ms: now_ms,
        },
    };
    save(
        secrets,
        &tip_key(network),
        &TipCache {
            seen_at_ms: now_ms,
            ..anchor
        },
    );
}

/// The store's inbox secret and the conversation keys it shares with `tag`.
fn conversation_keys(store_sk: &SigningKey, tag: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
    let tag: [u8; 32] = tag.try_into().ok()?;
    let shared = harvest_common::custody::inbox_secret(store_sk)
        .diffie_hellman(&x25519_dalek::PublicKey::from(tag));
    // A low-order point gives a constant anyone can compute; see
    // `messaging::conversation_keys_from`.
    if !shared.was_contributory() {
        return None;
    }
    let shared = shared.to_bytes();
    Some((
        tag,
        conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
        conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
    ))
}

/// The instant request an entry carries, if it is one this store can open.
fn open_instant(
    store_sk: &SigningKey,
    message: &EncryptedMessage,
) -> Option<(
    [u8; 32],
    [u8; 32],
    harvest_common::mailbox::ConversationId,
    OpenedRequest,
)> {
    let (tag, to_seller, from_seller) = conversation_keys(store_sk, &message.sender_public_key)?;
    let plaintext = decrypt_message(message, &to_seller).ok()?;
    match plaintext.content {
        MessageContent::OrderRequest {
            listing_id,
            quantity,
            order_binding,
            buyer_receipt_key,
            instant: Some(instant),
            ..
        } => Some((
            tag,
            from_seller,
            plaintext.conversation_id,
            OpenedRequest {
                listing_id,
                quantity,
                order_binding,
                buyer_receipt_key,
                instant,
            },
        )),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct OpenedRequest {
    listing_id: ListingId,
    quantity: u32,
    order_binding: [u8; 32],
    buyer_receipt_key: Option<[u8; 32]>,
    instant: InstantSelection,
}

fn within_age(message: &EncryptedMessage, now_ms: u64) -> bool {
    let at = message.timestamp.timestamp_millis();
    at >= 0 && now_ms.abs_diff(at as u64) <= REQUEST_MAX_AGE_MS
}

fn on_mailbox<S: SecretStore>(
    secrets: &mut S,
    record: &ArmRecord,
    state: &[u8],
    now_ms: u64,
) -> Vec<OutboundDelegateMsg> {
    let tip: Option<TipCache> = load(secrets, &tip_key(record.arm.network));
    if global_refusal(secrets, record, tip.as_ref(), now_ms).is_err() {
        return Vec::new();
    }
    let Some(store_sk) = store_key(secrets, &record.arm.store_verifying_key) else {
        return Vec::new();
    };
    let Ok(mailbox) = from_cbor::<MailboxStateV1>(state) else {
        return Vec::new();
    };
    let mut ledger = load_ledger(secrets, &record.arm.store_contract_id);
    let mut batch: Vec<EncryptedMessage> = Vec::new();
    let mut entries: Vec<&EncryptedMessage> = mailbox.messages.iter().collect();
    entries.sort_by_key(|m| (m.timestamp, entry_digest(m)));
    let mut ledger_changed = false;
    // What the context can carry, less room for its own framing.
    let budget = DelegateContext::MAX_SIZE - 1024;
    let mut used = 0usize;
    for message in entries {
        let digest = entry_digest(message);
        if ledger.seen.contains(&digest) || !within_age(message, now_ms) {
            continue;
        }
        if open_instant(&store_sk, message).is_some() {
            let size = to_cbor(message).map_or(usize::MAX, |b| b.len());
            if size > budget {
                // Can never be carried; the seller answers it.
                ledger.saw(digest);
                ledger_changed = true;
            } else if batch.len() < MAX_BATCH && used + size <= budget {
                used += size;
                batch.push(message.clone());
            }
        } else {
            // Not an instant request this store can open: a reply, a text, a
            // quote request, or junk. Looked at once.
            ledger.saw(digest);
            ledger_changed = true;
        }
    }
    if ledger_changed {
        save(secrets, &ledger_key(&record.arm.store_contract_id), &ledger);
    }
    if batch.is_empty() {
        return Vec::new();
    }
    let Ok(store_id) = <[u8; 32]>::try_from(record.arm.store_contract_id.as_slice()) else {
        return Vec::new();
    };
    let Ok(context) = to_cbor(&PendingBatch {
        magic: BATCH_MAGIC,
        store_contract_id: record.arm.store_contract_id.clone(),
        entries: batch,
    }) else {
        return Vec::new();
    };
    if context.len() >= DelegateContext::MAX_SIZE {
        return Vec::new();
    }
    let mut get = GetContractRequest::new(ContractInstanceId::new(store_id));
    get.context = DelegateContext::new(context);
    vec![OutboundDelegateMsg::GetContractRequest(get)]
}

/// The store GET this module asked for has answered. `None` when the context
/// is not one of this module's, so the caller keeps its old behaviour.
pub(crate) fn on_store_state<S: SecretStore>(
    secrets: &mut S,
    state: Option<&[u8]>,
    context: &[u8],
    now_ms: u64,
) -> Option<Vec<OutboundDelegateMsg>> {
    let batch: PendingBatch = from_cbor(context).ok()?;
    if batch.magic != BATCH_MAGIC {
        return None;
    }
    let Some(record) = load_arm(secrets, &batch.store_contract_id) else {
        return Some(Vec::new());
    };
    let Some(store) = state.and_then(|s| from_cbor::<StoreStateV1>(s).ok()) else {
        return Some(Vec::new());
    };
    let decided = decide(secrets, &record, &store, &batch.entries, now_ms);
    Some(decided.into_messages(&record.arm))
}

/// A store UPDATE this module sent has been applied or refused. `None` when
/// the context is not one of this module's.
pub(crate) fn on_store_updated(
    result: &Result<(), String>,
    context: &[u8],
) -> Option<Vec<OutboundDelegateMsg>> {
    let pending: PendingReplies = from_cbor(context).ok()?;
    if pending.magic != REPLIES_MAGIC {
        return None;
    }
    if result.is_err() || pending.replies.is_empty() {
        // The orders did not land, so there is nothing to point at. The
        // requests stay in the mailbox, readable by the seller.
        return Some(Vec::new());
    }
    let Ok(delta) = to_cbor(&pending.replies) else {
        return Some(Vec::new());
    };
    Some(vec![OutboundDelegateMsg::UpdateContractRequest(
        UpdateContractRequest::new(
            ContractInstanceId::new(pending.mailbox_contract_id),
            UpdateData::Delta(StateDelta::from(delta)),
        ),
    )])
}

/// What one run decided to publish.
#[derive(Default, Debug)]
pub(crate) struct Decided {
    pub orders: Vec<AuthorizedOrder>,
    pub statuses: Vec<AuthorizedListingStatus>,
    pub replies: Vec<EncryptedMessage>,
    /// Why each request not answered with an invoice was not, by entry
    /// digest. For tests and the log.
    pub refused: Vec<([u8; 32], Refusal)>,
    pub owner: Option<VerifyingKey>,
}

impl Decided {
    fn into_messages(self, arm: &AutoInvoiceArm) -> Vec<OutboundDelegateMsg> {
        let Ok(store_id) = <[u8; 32]>::try_from(arm.store_contract_id.as_slice()) else {
            return Vec::new();
        };
        let Some(owner) = self.owner else {
            return Vec::new();
        };
        if self.orders.is_empty() && self.statuses.is_empty() {
            // Only declines: nothing for the store, straight to the mailbox.
            return on_store_updated(
                &Ok(()),
                &to_cbor(&PendingReplies {
                    magic: REPLIES_MAGIC,
                    mailbox_contract_id: arm.mailbox_contract_id,
                    replies: self.replies,
                })
                .unwrap_or_default(),
            )
            .unwrap_or_default();
        }
        let Ok(delta) = to_cbor(&StoreStateV1Delta {
            owner: Some(owner),
            orders: (!self.orders.is_empty()).then_some(self.orders),
            listing_statuses: (!self.statuses.is_empty()).then_some(self.statuses),
            ..Default::default()
        }) else {
            return Vec::new();
        };
        let mut update = UpdateContractRequest::new(
            ContractInstanceId::new(store_id),
            UpdateData::Delta(StateDelta::from(delta)),
        );
        if let Ok(context) = to_cbor(&PendingReplies {
            magic: REPLIES_MAGIC,
            mailbox_contract_id: arm.mailbox_contract_id,
            replies: self.replies,
        }) {
            if context.len() < DelegateContext::MAX_SIZE {
                update.context = DelegateContext::new(context);
            }
        }
        vec![OutboundDelegateMsg::UpdateContractRequest(update)]
    }
}

/// The listing's availability as this run should count it: the newer of the
/// store's status and the one this delegate last signed.
fn effective_status(
    store: &StoreStateV1,
    ledger: &Ledger,
    listing: &ListingId,
) -> (u64, ListingAvailability) {
    let held = store
        .listing_statuses
        .records
        .get(&harvest_common::store::Bytes32(listing.0))
        .map(|s| (s.status.revision, s.status.availability.clone()));
    let own = ledger
        .statuses
        .iter()
        .find(|s| s.listing == *listing)
        .map(|s| (s.revision, s.availability.clone()));
    match (held, own) {
        (Some(h), Some(o)) => {
            if o.0 > h.0 {
                o
            } else {
                h
            }
        }
        (Some(x), None) | (None, Some(x)) => x,
        (None, None) => (0, ListingAvailability::default()),
    }
}

/// Decide every request in `entries`, derive and sign for the ones that pass,
/// and record it all. The only function here that spends an address.
pub(crate) fn decide<S: SecretStore>(
    secrets: &mut S,
    record: &ArmRecord,
    store: &StoreStateV1,
    entries: &[EncryptedMessage],
    now_ms: u64,
) -> Decided {
    let arm = &record.arm;
    let mut decided = Decided::default();
    let tip: Option<TipCache> = load(secrets, &tip_key(arm.network));
    let refuse_all = |decided: &mut Decided, why: Refusal| {
        for e in entries {
            decided.refused.push((entry_digest(e), why.clone()));
        }
    };
    let anchor = match global_refusal(secrets, record, tip.as_ref(), now_ms) {
        Ok(anchor) => anchor,
        Err(why) => {
            refuse_all(&mut decided, why);
            return decided;
        }
    };
    let Some(store_sk) = store_key(secrets, &arm.store_verifying_key) else {
        refuse_all(&mut decided, Refusal::NoStoreKey);
        return decided;
    };
    let owner = store_sk.verifying_key();
    if store.owner != Some(owner) {
        refuse_all(&mut decided, Refusal::NotOurStore);
        return decided;
    }
    if !store.closed.is_empty() {
        refuse_all(&mut decided, Refusal::StoreClosed);
        return decided;
    }
    decided.owner = Some(owner);
    let Some(mut xpub) = crate::bitcoin::load_payment_xpub(secrets) else {
        refuse_all(&mut decided, Refusal::NoPaymentKey);
        return decided;
    };
    // Past every script this store has published (harvest#77), so a device
    // whose counter is behind does not hand one out again.
    let published: Vec<Vec<u8>> = store
        .orders
        .orders
        .values()
        .map(|o| o.order.payment_script_pubkey.clone())
        .filter(|s| !s.is_empty())
        .collect();
    if crate::bitcoin::published_floor_matches(&mut xpub, &published).is_err() {
        refuse_all(&mut decided, Refusal::NoPaymentKey);
        return decided;
    }

    let mut ledger = load_ledger(secrets, &arm.store_contract_id);
    decided.statuses = settle(&mut ledger, store, Some(anchor.height), &store_sk, now_ms);
    let mut issued_now: Vec<AuthorizedOrder> = Vec::new();
    let tip_height = anchor.height;

    let mut ordered: Vec<&EncryptedMessage> = entries.iter().collect();
    ordered.sort_by_key(|m| (m.timestamp, entry_digest(m)));
    for message in ordered {
        let digest = entry_digest(message);
        if ledger.seen.contains(&digest) {
            continue;
        }
        let outcome = decide_one(
            secrets,
            arm,
            store,
            &store_sk,
            &mut xpub,
            &anchor,
            tip_height,
            &mut ledger,
            &issued_now,
            message,
            now_ms,
        );
        match outcome {
            Ok(Answer::Invoice { order, reply }) => {
                issued_now.push((*order).clone());
                decided.orders.push(*order);
                decided.replies.push(reply);
                ledger.saw(digest);
            }
            Ok(Answer::Decline(reply)) => {
                decided.replies.push(reply);
                ledger.saw(digest);
            }
            Err(why) => {
                let store_wide = why.is_store_wide();
                decided.refused.push((digest, why));
                if store_wide {
                    // Everything after this waits too, unseen.
                    break;
                }
                ledger.saw(digest);
            }
        }
    }
    save(secrets, &ledger_key(&arm.store_contract_id), &ledger);
    decided
}

enum Answer {
    Invoice {
        order: Box<AuthorizedOrder>,
        reply: EncryptedMessage,
    },
    Decline(EncryptedMessage),
}

#[allow(clippy::too_many_arguments)]
fn decide_one<S: SecretStore>(
    secrets: &mut S,
    arm: &AutoInvoiceArm,
    store: &StoreStateV1,
    store_sk: &SigningKey,
    xpub: &mut harvest_common::PaymentXpubStatus,
    anchor: &BlockAnchor,
    tip_height: u32,
    ledger: &mut Ledger,
    issued_now: &[AuthorizedOrder],
    message: &EncryptedMessage,
    now_ms: u64,
) -> Result<Answer, Refusal> {
    let (tag, from_seller, conversation_id, request) =
        open_instant(store_sk, message).ok_or(Refusal::NotInstant)?;
    let seal = |content: MessageContent| {
        harvest_common::sealed::seal(
            &from_seller,
            &tag,
            &conversation_id,
            content,
            chrono::DateTime::from_timestamp_millis(now_ms as i64).unwrap_or_default(),
        )
        .map_err(Refusal::Signing)
    };

    // I1: one order per request, checked before anything is spent.
    let request_id = request_id(&tag, &request.instant.nonce);
    let order_id = OrderId::for_request(&request_id);
    if ledger.answered.contains(&request_id)
        || store.orders.orders.contains_key(&order_id)
        || issued_now.iter().any(|o| o.order.id == order_id)
    {
        return Err(Refusal::AlreadyAnswered);
    }
    let buyer_receipt_key = request.buyer_receipt_key.ok_or(Refusal::NoBuyerKey)?;

    let listing: &Listing = store
        .listings
        .listings
        .iter()
        .map(|l| &l.listing)
        .find(|l| l.id == request.listing_id)
        .ok_or(Refusal::NoListing)?;
    let total = listing
        .instant_total(
            request.quantity,
            request.instant.region.as_deref(),
            &request.instant.choices,
        )
        .map_err(|_| Refusal::TotalMismatch)?;
    if total != request.instant.expected_total_sats {
        return Err(Refusal::TotalMismatch);
    }

    // Stock (I3). Published stock is what the seller has; the ledger's
    // reservations are what unpaid instant invoices, this run's included,
    // hold of it.
    let (_, availability) = effective_status(store, ledger, &listing.id);
    let left = match &availability {
        ListingAvailability::Withdrawn => return Err(Refusal::Withdrawn),
        ListingAvailability::SoldOut => Some(0),
        ListingAvailability::Available { quantity } => *quantity,
    };
    if let Some(left) = left {
        if left < request.quantity {
            let reason = if left == 0 {
                "Sold out".to_string()
            } else {
                format!("Only {left} left")
            };
            return seal(MessageContent::Decline { reason }).map(Answer::Decline);
        }
        if left
            < ledger
                .reserved(&listing.id)
                .saturating_add(request.quantity)
        {
            return Err(Refusal::Reserved);
        }
    }

    // A binding already on an order for another conversation (I5): the
    // request copied someone else's, and answering would show that buyer a
    // second invoice as theirs.
    let ours: Vec<[u8; 32]> = store
        .listings
        .listings
        .iter()
        .map(|l| listing_tag(&from_seller, &l.listing.id))
        .collect();
    if store.orders.orders.values().any(|o| {
        o.order.order_binding == Some(request.order_binding)
            && !o.order.listing_tag.is_some_and(|t| ours.contains(&t))
    }) {
        return Err(Refusal::BindingElsewhere);
    }

    // I4.
    let open = |o: &&&AuthorizedOrder| {
        o.order.request_id.is_some()
            && o.status == OrderStatus::AwaitingPayment
            && o.order
                .anchor
                .is_some_and(|a| a.height.saturating_add(MAX_ANCHOR_AGE_BLOCKS) >= tip_height)
    };
    let all_orders: Vec<&AuthorizedOrder> = store
        .orders
        .orders
        .values()
        .chain(issued_now.iter())
        .collect();
    if all_orders.iter().filter(open).count() >= MAX_OPEN_PER_STORE {
        return Err(Refusal::StoreCap);
    }
    if all_orders
        .iter()
        .filter(open)
        .filter(|o| o.order.order_binding == Some(request.order_binding))
        .count()
        >= MAX_OPEN_PER_CONVERSATION
    {
        return Err(Refusal::ConversationCap);
    }
    if ledger.issued_last_day(now_ms) >= MAX_PER_DAY {
        return Err(Refusal::DailyCap);
    }
    // A reservation must be recordable, or the stock it holds would not be
    // counted: past this many held at once, the seller answers.
    if left.is_some() && ledger.reservations.len() >= RESERVATIONS_CAP {
        return Err(Refusal::StoreCap);
    }
    if trailing_unpaid(xpub, &all_orders) >= MAX_TRAILING_UNPAID {
        return Err(Refusal::TrailingUnpaid);
    }

    // I7 then I2: the next address must be one the bridge was asked to
    // watch; only then is it spent, and the counter saved before anything
    // names it.
    let mut next = xpub.clone();
    let derived = crate::bitcoin::apply_derive_order_address(&mut next)
        .map_err(|_| Refusal::NoWatchedAddress)?;
    if !arm.watched_scripts.contains(&derived.script_pubkey) {
        return Err(Refusal::NoWatchedAddress);
    }
    crate::bitcoin::save_payment_xpub(secrets, &next).map_err(|_| Refusal::CounterNotSaved)?;
    *xpub = next;

    let order = Order {
        id: OrderId([0u8; 32]),
        buyer_fingerprint: String::new(),
        seller_fingerprint: arm.seller_fingerprint.clone(),
        amount_sats: total,
        network: derived.network,
        payment_script_pubkey: derived.script_pubkey,
        payment_address: derived.address,
        required_confirmations: REQUIRED_CONFIRMATIONS,
        payment_hash: None,
        trusted_bridges: arm.trusted_bridges.clone(),
        bitcoin_address_code_hash: Some(arm.address_code_hash),
        anchor: Some(*anchor),
        order_binding: Some(request.order_binding),
        listing_tag: Some(listing_tag(&from_seller, &listing.id)),
        buyer_receipt_key: Some(buyer_receipt_key),
        request_id: Some(request_id),
        created_at: chrono::DateTime::from_timestamp_millis(now_ms as i64).unwrap_or_default(),
    }
    .with_derived_id();
    let signed = sign_order(store_sk, order)?;

    let reply = seal(MessageContent::OrderAccepted {
        order_id: signed.order.id.clone(),
    })?;
    if left.is_some() {
        ledger.reservations.push(Reservation {
            order: signed.order.id.clone(),
            listing: listing.id.clone(),
            quantity: request.quantity,
            issued_at_ms: now_ms,
        });
    }
    ledger.answer(request_id, now_ms);
    Ok(Answer::Invoice {
        order: Box::new(signed),
        reply,
    })
}

/// How many of the addresses just below the counter carry no paid order,
/// counting down until one does. A wallet stops scanning after a run of about
/// 20 unused addresses, so a payment past such a run is invisible to it.
fn trailing_unpaid(xpub: &harvest_common::PaymentXpubStatus, orders: &[&AuthorizedOrder]) -> u32 {
    let Ok(chain) = crate::bip32::AccountXpub::parse(&xpub.xpub).and_then(|a| a.external_chain())
    else {
        return MAX_TRAILING_UNPAID;
    };
    let paid: Vec<&[u8]> = orders
        .iter()
        .filter(|o| o.status == OrderStatus::Paid)
        .map(|o| o.order.payment_script_pubkey.as_slice())
        .collect();
    let mut run = 0;
    let mut index = xpub.next_index;
    while index > 0 && run < MAX_TRAILING_UNPAID {
        index -= 1;
        match chain.script_at(index) {
            Ok(script) if paid.contains(&script.as_slice()) => break,
            Ok(_) => run += 1,
            Err(_) => return MAX_TRAILING_UNPAID,
        }
    }
    run
}

fn sign_order(store_sk: &SigningKey, order: Order) -> Result<AuthorizedOrder, Refusal> {
    let payload = to_cbor(&order).map_err(|e| Refusal::Signing(e.to_string()))?;
    let (scoped_payload, signature) =
        harvest_common::backing::sign_with_store_key(store_sk, payload)
            .map_err(Refusal::Signing)?;
    let signed = AuthorizedOrder {
        order,
        scoped_payload,
        signature,
        status: OrderStatus::AwaitingPayment,
        payment_proof: None,
        status_scoped_payload: None,
        status_signature: None,
    };
    signed
        .verify_terms(&store_sk.verifying_key())
        .map_err(Refusal::Signing)?;
    Ok(signed)
}

fn sign_status(
    store_sk: &SigningKey,
    status: ListingStatus,
) -> Result<AuthorizedListingStatus, Refusal> {
    let payload = to_cbor(&status).map_err(|e| Refusal::Signing(e.to_string()))?;
    let (scoped_payload, signature) =
        harvest_common::backing::sign_with_store_key(store_sk, payload)
            .map_err(Refusal::Signing)?;
    Ok(AuthorizedListingStatus {
        status,
        scoped_payload,
        signature,
    })
}

#[cfg(test)]
mod tests {
    //! Each invariant in the module doc has a test here that drives the real
    //! decision against a real store state, a real sealed request and a real
    //! account key, and says which mutation it was seen to fail under.
    use super::*;
    use crate::secrets::MemSecrets;
    use harvest_common::listing::{
        AuthorizedListing, ChoiceGroup, DeliveryPrice, FixedCheckout, ListingKind, RegionPrice,
    };
    use harvest_common::mailbox::ConversationId;
    use harvest_common::PaymentXpubStatus;
    use x25519_dalek::{PublicKey, StaticSecret};

    const NOW: u64 = 1_800_000_000_000;

    fn store_sk() -> SigningKey {
        SigningKey::from_bytes(&[0x51; 32])
    }

    fn signet_vpub() -> String {
        let mut bytes = bs58::decode(
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        )
        .with_check(None)
        .into_vec()
        .expect("the BIP-84 vector must decode");
        bytes[..4].copy_from_slice(&0x045f_1cf6u32.to_be_bytes());
        bs58::encode(bytes).with_check().into_string()
    }

    fn xpub_at(next_index: u32) -> PaymentXpubStatus {
        PaymentXpubStatus {
            xpub: signet_vpub(),
            network: BitcoinNetwork::Signet,
            next_index,
        }
    }

    fn script_at(index: u32) -> Vec<u8> {
        crate::bip32::AccountXpub::parse(&signet_vpub())
            .unwrap()
            .external_chain()
            .unwrap()
            .script_at(index)
            .unwrap()
    }

    fn listing(quantity_terms: Option<FixedCheckout>) -> Listing {
        Listing {
            id: ListingId([0; 32]),
            title: "Jam".into(),
            description: String::new(),
            kind: ListingKind::Sale,
            price: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            checkout: quantity_terms,
            choices: vec![ChoiceGroup {
                name: "Flavour".into(),
                options: vec!["Plum".into(), "Fig".into()],
            }],
        }
        .with_derived_id()
    }

    /// The fixture store's instant-checkout listing.
    fn jam() -> Listing {
        listing(Some(terms()))
    }

    fn terms() -> FixedCheckout {
        FixedCheckout {
            unit_sats: 10_000,
            delivery: DeliveryPrice::ByRegion(vec![RegionPrice {
                region: "UK".into(),
                sats: 2_000,
            }]),
        }
    }

    /// Everything a test varies, with a working default.
    struct Fixture {
        secrets: MemSecrets,
        record: ArmRecord,
        store: StoreStateV1,
        listing: Listing,
    }

    fn fixture() -> Fixture {
        let mut secrets = MemSecrets::default();
        crate::store_keys::keep(&mut secrets, &store_sk());
        crate::bitcoin::save_payment_xpub(&mut secrets, &xpub_at(0)).unwrap();
        save(
            &mut secrets,
            &tip_key(BitcoinNetwork::Signet),
            &TipCache {
                anchor: BlockAnchor {
                    height: 1_000,
                    hash: freenet_bitcoin_common::BlockHash([7; 32]),
                },
                block_time: (NOW / 1000) as u32 - 600,
                seen_at_ms: NOW - 600_000,
            },
        );
        let listing = listing(Some(terms()));
        let store = StoreStateV1 {
            owner: Some(store_sk().verifying_key()),
            listings: harvest_common::store::ListingsV1 {
                listings: vec![AuthorizedListing {
                    listing: listing.clone(),
                    scoped_payload: Vec::new(),
                    signature: Vec::new(),
                    certificate_pem: String::new(),
                }],
            },
            ..Default::default()
        };
        let record = ArmRecord {
            arm: AutoInvoiceArm {
                store_contract_id: vec![1; 32],
                store_verifying_key: store_sk().verifying_key().to_bytes(),
                mailbox_contract_id: [2; 32],
                seller_fingerprint: "seller".into(),
                network: BitcoinNetwork::Signet,
                tip_contract_id: [3; 32],
                trusted_bridges: vec![freenet_bitcoin_common::BridgeId([4; 32])],
                address_code_hash: [5; 32],
                watched_scripts: (0..5).map(script_at).collect(),
                watch_left_ms: WATCH_NEEDED_MS + 3_600_000,
            },
            armed_at_ms: NOW - 1_000,
            watched_until_ms: NOW + WATCH_NEEDED_MS + 3_600_000,
        };
        save(
            &mut secrets,
            &arm_key(&record.arm.store_contract_id),
            &record,
        );
        Fixture {
            secrets,
            record,
            store,
            listing,
        }
    }

    /// A buyer's conversation with the fixture store.
    struct Buyer {
        secret: StaticSecret,
        conversation: ConversationId,
    }

    impl Buyer {
        fn new(seed: u8) -> Self {
            Buyer {
                secret: StaticSecret::from([seed; 32]),
                conversation: ConversationId([seed; 32]),
            }
        }

        fn tag(&self) -> [u8; 32] {
            *PublicKey::from(&self.secret).as_bytes()
        }

        fn keys(&self) -> ([u8; 32], [u8; 32]) {
            let inbox = PublicKey::from(&harvest_common::custody::inbox_secret(&store_sk()));
            let shared = self.secret.diffie_hellman(&inbox).to_bytes();
            (
                conversation_key_from_dh(&shared, MessageDirection::BuyerToSeller),
                conversation_key_from_dh(&shared, MessageDirection::SellerToBuyer),
            )
        }

        fn binding(&self) -> [u8; 32] {
            [self.secret.to_bytes()[0]; 32]
        }

        fn request(
            &self,
            listing: &Listing,
            quantity: u32,
            nonce: u8,
            total: u64,
        ) -> EncryptedMessage {
            self.request_at(listing, quantity, nonce, total, NOW - 5_000)
        }

        fn request_at(
            &self,
            listing: &Listing,
            quantity: u32,
            nonce: u8,
            total: u64,
            at_ms: u64,
        ) -> EncryptedMessage {
            harvest_common::sealed::seal(
                &self.keys().0,
                &self.tag(),
                &self.conversation,
                MessageContent::OrderRequest {
                    listing_id: listing.id.clone(),
                    quantity,
                    shipping: "1 Lane".into(),
                    note: String::new(),
                    order_binding: self.binding(),
                    buyer_receipt_key: Some([9; 32]),
                    instant: Some(InstantSelection {
                        nonce: [nonce; 16],
                        region: Some("UK".into()),
                        choices: vec!["Fig".into()],
                        expected_total_sats: total,
                    }),
                },
                chrono::DateTime::from_timestamp_millis(at_ms as i64).unwrap(),
            )
            .unwrap()
        }

        /// What the seller sent back down this conversation.
        fn read(&self, replies: &[EncryptedMessage]) -> Vec<MessageContent> {
            replies
                .iter()
                .filter(|m| m.sender_public_key == self.tag())
                .filter_map(|m| decrypt_message(m, &self.keys().1).ok())
                .map(|p| p.content)
                .collect()
        }
    }

    /// An unpaid order paying to `script`, as some earlier invoice was.
    fn order_on(script: Vec<u8>) -> Order {
        Order {
            id: OrderId([0; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller".into(),
            amount_sats: 5_000,
            network: BitcoinNetwork::Signet,
            payment_script_pubkey: script,
            payment_address: "tb1q".into(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: Vec::new(),
            bitcoin_address_code_hash: None,
            anchor: None,
            order_binding: None,
            listing_tag: None,
            buyer_receipt_key: None,
            request_id: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    fn run(f: &mut Fixture, entries: &[EncryptedMessage]) -> Decided {
        decide(&mut f.secrets, &f.record, &f.store, entries, NOW)
    }

    fn counter(f: &Fixture) -> u32 {
        crate::bitcoin::load_payment_xpub(&f.secrets)
            .unwrap()
            .next_index
    }

    fn publish(f: &mut Fixture, decided: &Decided) {
        for o in &decided.orders {
            f.store.orders.orders.insert(o.order.id.clone(), o.clone());
        }
        for s in &decided.statuses {
            f.store.listing_statuses.records.insert(
                harvest_common::store::Bytes32(s.status.listing.0),
                s.clone(),
            );
        }
    }

    fn counted(f: &mut Fixture, quantity: u32) {
        let status = ListingStatus {
            listing: f.listing.id.clone(),
            revision: 5,
            availability: ListingAvailability::Available {
                quantity: Some(quantity),
            },
        };
        let signed = sign_status(&store_sk(), status).unwrap();
        f.store
            .listing_statuses
            .records
            .insert(harvest_common::store::Bytes32(f.listing.id.0), signed);
    }

    #[test]
    fn a_fixed_price_request_is_invoiced_on_the_first_watched_address() {
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let decided = run(&mut f, &[buyer.request(&jam(), 2, 1, 22_000)]);
        assert_eq!(decided.refused, vec![]);
        assert_eq!(decided.orders.len(), 1);
        let order = &decided.orders[0];
        order
            .verify_terms(&store_sk().verifying_key())
            .expect("signed by the store key");
        assert_eq!(order.order.amount_sats, 22_000);
        assert_eq!(order.order.payment_script_pubkey, script_at(0));
        assert_eq!(
            order.order.request_id,
            Some(request_id(&buyer.tag(), &[1; 16]))
        );
        assert_eq!(order.order.order_binding, Some(buyer.binding()));
        assert_eq!(order.order.buyer_receipt_key, Some([9; 32]));
        assert_eq!(
            order.order.listing_tag,
            Some(listing_tag(&buyer.keys().1, &f.listing.id))
        );
        assert_eq!(order.order.anchor.unwrap().height, 1_000);
        assert_eq!(order.order.required_confirmations, 1);
        assert_eq!(counter(&f), 1);
        assert_eq!(
            buyer.read(&decided.replies),
            vec![MessageContent::OrderAccepted {
                order_id: order.order.id.clone()
            }]
        );
    }

    /// I1. The same entry again, the same request resent as a new entry, and
    /// a request whose order another device already published: none derives
    /// an address. Mutated red by removing the ledger/store check in
    /// `decide_one` (the resend then spends index 1).
    #[test]
    fn a_request_is_answered_at_most_once() {
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let first = buyer.request(&jam(), 1, 1, 12_000);
        let decided = run(&mut f, std::slice::from_ref(&first));
        assert_eq!(decided.orders.len(), 1);
        publish(&mut f, &decided);

        assert!(run(&mut f, &[first]).orders.is_empty());
        let resend = buyer.request_at(&jam(), 1, 1, 12_000, NOW - 1_000);
        let again = run(&mut f, &[resend]);
        assert!(again.orders.is_empty());
        assert_eq!(again.refused[0].1, Refusal::AlreadyAnswered);
        assert_eq!(counter(&f), 1);

        // Another device answered this one; this device's ledger never saw it.
        let mut g = fixture();
        let other = buyer.request(&jam(), 1, 7, 12_000);
        let elsewhere = run(&mut fixture(), std::slice::from_ref(&other));
        publish(&mut g, &elsewhere);
        let here = run(&mut g, &[other]);
        assert!(here.orders.is_empty());
        assert_eq!(here.refused[0].1, Refusal::AlreadyAnswered);
        assert_eq!(counter(&g), 0);
    }

    /// I1, the ledger alone: a resend before the first answer has reached the
    /// store, and one nonce twice in one run. Mutated red by dropping
    /// `ledger.answered.contains` (the resend) and the `issued_now` check (the
    /// same run).
    #[test]
    fn a_request_is_answered_once_before_the_store_shows_it() {
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let first = run(&mut f, &[buyer.request(&jam(), 1, 1, 12_000)]);
        assert_eq!(first.orders.len(), 1);
        // Not published: the store read is stale.
        let resend = buyer.request_at(&jam(), 1, 1, 12_000, NOW - 1_000);
        let again = run(&mut f, &[resend]);
        assert_eq!(again.refused[0].1, Refusal::AlreadyAnswered);
        assert_eq!(counter(&f), 1);

        let mut g = fixture();
        let twice = run(
            &mut g,
            &[
                buyer.request_at(&jam(), 1, 9, 12_000, NOW - 3_000),
                buyer.request_at(&jam(), 1, 9, 12_000, NOW - 2_000),
            ],
        );
        assert_eq!(twice.orders.len(), 1);
        assert_eq!(twice.refused[0].1, Refusal::AlreadyAnswered);
        assert_eq!(counter(&g), 1);
    }

    /// The daily count forgets what is over a day old, so the ledger stays
    /// small.
    #[test]
    fn the_daily_count_is_pruned() {
        let mut ledger = Ledger {
            issued_at_ms: vec![NOW - DAY_MS - 1; 500],
            ..Default::default()
        };
        ledger.answer([1; 32], NOW);
        assert_eq!(ledger.issued_at_ms, vec![NOW]);
    }

    /// Re-arming keeps the first arm time, so a device that never runs in the
    /// background is recognised however often the UI re-arms. Mutated red by
    /// stamping `now_ms` on every arm.
    #[test]
    fn re_arming_keeps_the_first_arm_time() {
        let mut secrets = MemSecrets::default();
        crate::store_keys::keep(&mut secrets, &store_sk());
        let f = fixture();
        arm(&mut secrets, f.record.arm.clone(), NOW);
        let (response, _) = arm(&mut secrets, f.record.arm.clone(), NOW + 3_600_000);
        let HarvestDelegateResponse::AutoInvoice {
            result: Ok(status), ..
        } = response
        else {
            panic!("{response:?}")
        };
        assert_eq!(status.armed_at_ms, NOW);
        assert_eq!(status.last_background_run_ms, None);
    }

    /// The newest block is kept, an older one never replaces it, a tip for
    /// another network is ignored, and every tip counts as a background run.
    /// Mutated red by dropping the height comparison.
    #[test]
    fn the_tip_cache_keeps_the_newest_block() {
        use freenet_bitcoin_common::{BlockHash, SignedTipEntry, TipEntryBody};
        let bridge = SigningKey::from_bytes(&[0x77; 32]);
        let tip_state = |network: BitcoinNetwork, height: u32| {
            let entry = SignedTipEntry::sign(
                &bridge,
                &TipEntryBody {
                    network,
                    anchor: BlockAnchor {
                        height,
                        hash: BlockHash([height as u8; 32]),
                    },
                    prev_hash: BlockHash([0; 32]),
                    block_time: 1_700_000_000 + height,
                    tx_count: 1,
                    median_time: 1_700_000_000,
                },
            )
            .unwrap();
            let mut state = BitcoinTipStateV1::default();
            state.blocks.blocks.insert(height, entry);
            freenet_bitcoin_common::to_cbor(&state).unwrap()
        };
        let mut f = fixture();
        crate::secrets::RemovableSecrets::remove_secret(
            &mut f.secrets,
            &tip_key(BitcoinNetwork::Signet),
        );
        let cached = |f: &Fixture| -> TipCache {
            load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap()
        };
        on_notification(
            &mut f.secrets,
            &[3; 32],
            &tip_state(BitcoinNetwork::Signet, 100),
            NOW,
        );
        assert_eq!(cached(&f).anchor.height, 100);
        on_notification(
            &mut f.secrets,
            &[3; 32],
            &tip_state(BitcoinNetwork::Signet, 99),
            NOW + 5,
        );
        assert_eq!(cached(&f).anchor.height, 100, "an older block never wins");
        assert_eq!(cached(&f).seen_at_ms, NOW + 5, "but it is a background run");
        on_notification(
            &mut f.secrets,
            &[3; 32],
            &tip_state(BitcoinNetwork::Bitcoin, 500),
            NOW + 9,
        );
        assert_eq!(
            cached(&f).anchor.height,
            100,
            "another network's tip is ignored"
        );
    }

    /// Entries are batched while the context can carry them; one that never
    /// could is left for the seller rather than stalling every later run.
    #[test]
    fn a_batch_never_outgrows_the_context() {
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let big = |nonce: u8| {
            harvest_common::sealed::seal(
                &buyer.keys().0,
                &buyer.tag(),
                &buyer.conversation,
                MessageContent::OrderRequest {
                    listing_id: jam().id,
                    quantity: 1,
                    shipping: "x".repeat(40_000),
                    note: String::new(),
                    order_binding: buyer.binding(),
                    buyer_receipt_key: Some([9; 32]),
                    instant: Some(InstantSelection {
                        nonce: [nonce; 16],
                        region: Some("UK".into()),
                        choices: vec!["Fig".into()],
                        expected_total_sats: 12_000,
                    }),
                },
                chrono::DateTime::from_timestamp_millis((NOW - 60_000 + u64::from(nonce)) as i64)
                    .unwrap(),
            )
            .unwrap()
        };
        let messages: Vec<EncryptedMessage> = (1..=12).map(big).collect();
        let state = to_cbor(&MailboxStateV1 { messages }).unwrap();
        let out = on_notification(&mut f.secrets, &[2; 32], &state, NOW).unwrap();
        let [OutboundDelegateMsg::GetContractRequest(get)] = out.as_slice() else {
            panic!("{out:?}")
        };
        assert!(get.context.as_ref().len() < DelegateContext::MAX_SIZE);
        let batch: PendingBatch = from_cbor(get.context.as_ref()).unwrap();
        assert!(!batch.entries.is_empty() && batch.entries.len() < 12);
    }

    /// I2 and I5. A request that fails any check spends no address. Mutated
    /// red by moving the derivation above the total check.
    #[test]
    fn a_refused_request_spends_no_address() {
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let cases = [
            (buyer.request(&jam(), 1, 1, 11_999), Refusal::TotalMismatch),
            (
                buyer.request(&jam(), 11, 2, 112_000),
                Refusal::TotalMismatch,
            ),
        ];
        for (entry, want) in cases {
            let decided = run(&mut f, &[entry]);
            assert!(decided.orders.is_empty());
            assert_eq!(decided.refused[0].1, want);
        }
        let mut quote_only = listing(None);
        quote_only.title = "Quote".into();
        let quote_only = quote_only.with_derived_id();
        f.store.listings.listings.push(AuthorizedListing {
            listing: quote_only.clone(),
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            certificate_pem: String::new(),
        });
        let decided = run(&mut f, &[buyer.request(&quote_only, 1, 3, 12_000)]);
        assert_eq!(decided.refused[0].1, Refusal::TotalMismatch);
        let decided = run(&mut f, &[buyer.request(&listing(None), 1, 4, 12_000)]);
        assert_eq!(decided.refused[0].1, Refusal::NoListing);
        assert_eq!(counter(&f), 0);
    }

    /// I2. The counter is raised past the store's published scripts before
    /// deriving, so a device whose counter is behind does not reuse one.
    /// Mutated red by removing the `published_floor_matches` call.
    #[test]
    fn the_counter_moves_past_published_addresses() {
        let mut f = fixture();
        let mut old = order_on(script_at(0));
        old.id = OrderId([0; 32]);
        let old = sign_order(&store_sk(), old.with_derived_id()).unwrap();
        f.store.orders.orders.insert(old.order.id.clone(), old);
        let decided = run(&mut f, &[Buyer::new(40).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(decided.orders[0].order.payment_script_pubkey, script_at(1));
    }

    /// I7. Only a watched address goes on an invoice, and only while the
    /// watch is live. Mutated red by removing the `watched_scripts` check.
    #[test]
    fn only_a_watched_address_is_used() {
        let mut f = fixture();
        f.record.arm.watched_scripts = vec![script_at(1)];
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        let decided = run(&mut f, std::slice::from_ref(&entry));
        assert!(decided.orders.is_empty());
        assert_eq!(decided.refused[0].1, Refusal::NoWatchedAddress);
        assert_eq!(counter(&f), 0, "nothing spent");

        let mut f = fixture();
        // A watch lapsing before a buyer invoiced now could finish paying.
        f.record.watched_until_ms = NOW + WATCH_NEEDED_MS;
        let decided = run(&mut f, std::slice::from_ref(&entry));
        assert_eq!(decided.refused[0].1, Refusal::WatchLapsed);

        // A store-wide refusal leaves the request unseen, so a later arm
        // can still answer it.
        let mut f = fixture();
        f.record.arm.watched_scripts.clear();
        run(&mut f, std::slice::from_ref(&entry));
        f.record.arm.watched_scripts = vec![script_at(0)];
        assert_eq!(run(&mut f, &[entry]).orders.len(), 1);
    }

    /// I3. Two requests for the last item in one run: one invoice, and the
    /// other left for the seller (the first may never be paid), with
    /// published stock untouched until a payment. Mutated red by dropping
    /// the reservation push.
    #[test]
    fn the_last_item_is_invoiced_once() {
        let mut f = fixture();
        counted(&mut f, 1);
        let (a, b) = (Buyer::new(40), Buyer::new(41));
        let decided = run(
            &mut f,
            &[
                a.request_at(&jam(), 1, 1, 12_000, NOW - 9_000),
                b.request_at(&jam(), 1, 1, 12_000, NOW - 8_000),
            ],
        );
        assert_eq!(decided.orders.len(), 1);
        assert_eq!(decided.orders[0].order.order_binding, Some(a.binding()));
        assert!(decided.statuses.is_empty(), "nothing published until paid");
        assert_eq!(decided.refused.len(), 1);
        assert_eq!(decided.refused[0].1, Refusal::Reserved);
        assert!(
            b.read(&decided.replies).is_empty(),
            "no decline: may free up"
        );
        assert_eq!(counter(&f), 1);

        // And in a later run that reads the same store.
        let later = run(&mut f, &[Buyer::new(42).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(later.refused[0].1, Refusal::Reserved);
        assert_eq!(counter(&f), 1);
    }

    /// Published stock that is genuinely short is declined, not left.
    #[test]
    fn a_real_shortage_is_declined() {
        let mut f = fixture();
        counted(&mut f, 1);
        let b = Buyer::new(41);
        let decided = run(&mut f, &[b.request(&jam(), 2, 1, 22_000)]);
        assert!(decided.orders.is_empty());
        assert_eq!(
            b.read(&decided.replies),
            vec![MessageContent::Decline {
                reason: "Only 1 left".into()
            }]
        );
        assert_eq!(counter(&f), 0);
    }

    /// Requests nobody pays cannot empty a listing: published stock does not
    /// move, and once their invoices expire the stock is offered again.
    /// Mutated red by keeping expired reservations in `settle`.
    #[test]
    fn unpaid_invoices_do_not_drain_stock() {
        let mut f = fixture();
        counted(&mut f, 2);
        f.record.arm.watched_scripts = (0..10).map(script_at).collect();
        for seed in 40..42 {
            let d = run(&mut f, &[Buyer::new(seed).request(&jam(), 1, 1, 12_000)]);
            assert_eq!(d.orders.len(), 1);
            publish(&mut f, &d);
        }
        let held = run(&mut f, &[Buyer::new(50).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(held.refused[0].1, Refusal::Reserved);
        assert_eq!(
            f.store.listing_availability(&jam().id),
            ListingAvailability::Available { quantity: Some(2) },
            "published stock untouched"
        );
        // The chain moves past the unpaid invoices' payable window.
        let mut tip: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
        tip.anchor.height += MAX_ANCHOR_AGE_BLOCKS + 1;
        save(&mut f.secrets, &tip_key(BitcoinNetwork::Signet), &tip);
        let again = run(&mut f, &[Buyer::new(51).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(again.orders.len(), 1, "{:?}", again.refused);
    }

    /// A paid instant order takes its quantity off the published stock,
    /// once, when the store shows it paid. Mutated red by not signing the
    /// decrement in `settle`.
    #[test]
    fn a_paid_order_takes_its_quantity_off_published_stock() {
        let mut f = fixture();
        counted(&mut f, 3);
        let d = run(&mut f, &[Buyer::new(40).request(&jam(), 2, 1, 22_000)]);
        let mut paid = d.orders[0].clone();
        paid.status = OrderStatus::Paid;
        f.store.orders.orders.insert(paid.order.id.clone(), paid);
        let state = to_cbor(&f.store).unwrap();
        let out = on_notification(&mut f.secrets, &[1; 32], &state, NOW).unwrap();
        let [OutboundDelegateMsg::UpdateContractRequest(update)] = out.as_slice() else {
            panic!("{out:?}")
        };
        let UpdateData::Delta(delta) = &update.update else {
            panic!("a delta")
        };
        let delta: StoreStateV1Delta = from_cbor(delta.as_ref()).unwrap();
        let statuses = delta.listing_statuses.unwrap();
        assert_eq!(
            statuses[0].status.availability,
            ListingAvailability::Available { quantity: Some(1) }
        );
        statuses[0]
            .verify(&store_sk().verifying_key())
            .expect("signed by the store key");
        // Settled once: the same state again changes nothing.
        assert!(on_notification(&mut f.secrets, &[1; 32], &state, NOW)
            .unwrap()
            .is_empty());
    }

    /// A store update that never landed releases its hold after a while.
    #[test]
    fn a_reservation_whose_order_never_landed_is_released() {
        let mut f = fixture();
        counted(&mut f, 1);
        let first = run(&mut f, &[Buyer::new(40).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(first.orders.len(), 1);
        let mut ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        let released = settle(
            &mut ledger,
            &f.store,
            Some(1_000),
            &store_sk(),
            NOW + NOT_LANDED_MS,
        );
        assert!(released.is_empty());
        assert!(ledger.reservations.is_empty());
    }

    /// I4. Past each cap the request is left for the seller. Mutated red by
    /// removing each cap's check in turn.
    #[test]
    fn exposure_is_capped() {
        // Per conversation.
        let mut f = fixture();
        f.record.arm.watched_scripts = (0..10).map(script_at).collect();
        let buyer = Buyer::new(40);
        for nonce in 1..=2 {
            let d = run(&mut f, &[buyer.request(&jam(), 1, nonce, 12_000)]);
            assert_eq!(d.orders.len(), 1);
            publish(&mut f, &d);
        }
        let third = run(&mut f, &[buyer.request(&jam(), 1, 3, 12_000)]);
        assert_eq!(third.refused[0].1, Refusal::ConversationCap);

        // Per store.
        let mut f = fixture();
        for n in 0..MAX_OPEN_PER_STORE as u8 {
            let mut o = order_on(vec![0x00, 0x14, n]);
            o.request_id = Some([n; 32]);
            o.anchor = Some(BlockAnchor {
                height: 1_000,
                hash: freenet_bitcoin_common::BlockHash([7; 32]),
            });
            let o = sign_order(&store_sk(), o.with_derived_id()).unwrap();
            f.store.orders.orders.insert(o.order.id.clone(), o);
        }
        let capped = run(&mut f, &[Buyer::new(50).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(capped.refused[0].1, Refusal::StoreCap);

        // Per day.
        let mut f = fixture();
        let ledger = Ledger {
            issued_at_ms: vec![NOW - 1_000; MAX_PER_DAY],
            ..Default::default()
        };
        save(
            &mut f.secrets,
            &ledger_key(&f.record.arm.store_contract_id),
            &ledger,
        );
        let capped = run(&mut f, &[Buyer::new(50).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(capped.refused[0].1, Refusal::DailyCap);

        // A run of unpaid addresses below the counter.
        let mut f = fixture();
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &xpub_at(MAX_TRAILING_UNPAID)).unwrap();
        f.record.arm.watched_scripts = vec![script_at(MAX_TRAILING_UNPAID)];
        let capped = run(&mut f, &[Buyer::new(50).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(capped.refused[0].1, Refusal::TrailingUnpaid);
        assert_eq!(counter(&f), MAX_TRAILING_UNPAID);
    }

    /// I5. Stale tip, a store this key does not own, a closed store and a
    /// binding already published for another conversation all fall back.
    #[test]
    fn doubtful_inputs_fall_back() {
        let entry = |_: &Fixture| Buyer::new(40).request(&jam(), 1, 1, 12_000);

        let mut f = fixture();
        let mut tip: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
        tip.block_time = ((NOW - TIP_MAX_AGE_MS) / 1000) as u32 - 1;
        save(&mut f.secrets, &tip_key(BitcoinNetwork::Signet), &tip);
        let e = entry(&f);
        assert_eq!(run(&mut f, &[e]).refused[0].1, Refusal::NoFreshTip);

        let mut f = fixture();
        f.store.owner = Some(SigningKey::from_bytes(&[1; 32]).verifying_key());
        let e = entry(&f);
        assert_eq!(run(&mut f, &[e]).refused[0].1, Refusal::NotOurStore);

        // The request copies a binding already on an order that no listing
        // tag of THIS conversation matches.
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let mut elsewhere = order_on(vec![0x00, 0x14, 0xee]);
        elsewhere.order_binding = Some(buyer.binding());
        elsewhere.listing_tag = Some([0xab; 32]);
        let elsewhere = sign_order(&store_sk(), elsewhere.with_derived_id()).unwrap();
        f.store
            .orders
            .orders
            .insert(elsewhere.order.id.clone(), elsewhere);
        let e = entry(&f);
        assert_eq!(run(&mut f, &[e]).refused[0].1, Refusal::BindingElsewhere);
        assert_eq!(counter(&f), 0);
    }

    /// I6. A notification for a contract no arm names is not handled here,
    /// and an arm needs the store's key.
    #[test]
    fn only_armed_contracts_are_acted_on() {
        let mut f = fixture();
        assert!(on_notification(&mut f.secrets, &[99; 32], b"", NOW).is_none());
        assert!(on_notification(&mut f.secrets, &[1; 32], b"", NOW).is_some());
        let mut other = f.record.arm.clone();
        other.store_verifying_key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let (response, subscriptions) = arm(&mut f.secrets, other, NOW);
        assert!(matches!(
            response,
            HarvestDelegateResponse::AutoInvoice { result: Err(_), .. }
        ));
        assert!(subscriptions.is_empty());
    }

    /// Arming stores the arm and subscribes to the three contracts.
    #[test]
    fn arming_subscribes_to_mailbox_store_and_tip() {
        let mut f = fixture();
        let (response, subscriptions) = arm(&mut f.secrets, f.record.arm.clone(), NOW);
        let HarvestDelegateResponse::AutoInvoice {
            result: Ok(status), ..
        } = response
        else {
            panic!("{response:?}")
        };
        assert_eq!(status.watched_remaining, 5);
        assert_eq!(status.paused, None);
        let ids: Vec<[u8; 32]> = subscriptions
            .iter()
            .map(|m| match m {
                OutboundDelegateMsg::SubscribeContractRequest(r) => {
                    r.contract_id.as_bytes().try_into().unwrap()
                }
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(ids, vec![[1; 32], [2; 32], [3; 32]]);
    }

    /// The mailbox run batches only unseen instant requests within a day,
    /// and marks everything else seen.
    #[test]
    fn the_mailbox_run_asks_for_the_store_with_only_new_instant_requests() {
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let fresh = buyer.request(&jam(), 1, 1, 12_000);
        let stale = buyer.request_at(&jam(), 1, 2, 12_000, NOW - REQUEST_MAX_AGE_MS - 1);
        let text = harvest_common::sealed::seal(
            &buyer.keys().0,
            &buyer.tag(),
            &buyer.conversation,
            MessageContent::Text("hello".into()),
            chrono::DateTime::from_timestamp_millis((NOW - 1) as i64).unwrap(),
        )
        .unwrap();
        let state = to_cbor(&MailboxStateV1 {
            messages: vec![fresh.clone(), stale, text.clone()],
        })
        .unwrap();
        let out = on_notification(&mut f.secrets, &[2; 32], &state, NOW).unwrap();
        let [OutboundDelegateMsg::GetContractRequest(get)] = out.as_slice() else {
            panic!("{out:?}")
        };
        let batch: PendingBatch = from_cbor(get.context.as_ref()).unwrap();
        assert_eq!(batch.entries, vec![fresh]);
        let ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        assert!(ledger.seen.contains(&entry_digest(&text)));
    }

    /// The pointer goes out only after the store took the order.
    #[test]
    fn replies_wait_for_the_store_update() {
        let context = to_cbor(&PendingReplies {
            magic: REPLIES_MAGIC,
            mailbox_contract_id: [2; 32],
            replies: vec![Buyer::new(40).request(&jam(), 1, 1, 1)],
        })
        .unwrap();
        assert_eq!(
            on_store_updated(&Err("refused".into()), &context)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(on_store_updated(&Ok(()), &context).unwrap().len(), 1);
        assert!(on_store_updated(&Ok(()), b"not ours").is_none());
    }
}
