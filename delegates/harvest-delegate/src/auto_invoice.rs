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
//!   [`crate::bitcoin::issue_next_address`], after the counter has been
//!   raised past the store's published scripts, and only after every refusal
//!   check has passed, so a refused request burns nothing.
//! - **I3, the last item goes once.** Requests in one run are decided in one
//!   order against a running count that starts from the newer of the store's
//!   status and this delegate's own last-signed one.
//! - **I4, bounded exposure.** At most [`MAX_OPEN_PER_STORE`] open unpaid
//!   instant invoices per store, [`MAX_OPEN_PER_CONVERSATION`] per buyer
//!   conversation, [`MAX_PER_DAY`] a day, and none while the newest
//!   [`MAX_TRAILING_UNPAID`] addresses are all unpaid. All generous and
//!   invisible (Ian, 2026-09-26): a genuine buyer never meets one.
//! - **I5, fall back rather than guess.** Every missing or doubtful input ends
//!   in no invoice: see [`Refusal`].
//! - **I6, authority.** Only the Harvest web app can arm (the origin gate in
//!   `lib.rs`), and notifications are acted on only for contracts named in an
//!   arm.
//! - **I7, every address is watched.** The delegate invoices only on an
//!   address the bridge has read a watch request for, and only while that
//!   watch outlasts the invoice's payment window: one the seller's UI had
//!   watched (see [`AutoInvoiceArm`]), or one this delegate asked for itself
//!   with the watch key the seller's Ghost Key delegated to it
//!   (`crate::watch_delegation`), and that only for a script the arm names
//!   (harvest#198: the tab arms only a window whose address contracts it
//!   read clear, so nothing is invoiced on an address nobody read); see
//!   [`WatchSet`]. Without this a payment
//!   made before the seller next opened Harvest would never be seen, because
//!   the bridge does not look back (freenet-bitcoin#7).
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
    ApplicationMessage, ContractInstanceId, DelegateContext, GetContractRequest,
    OutboundDelegateMsg, StateDelta, SubscribeContractRequest, UpdateContractRequest, UpdateData,
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

use crate::watch_delegation::Delegations;

/// Every secret this module writes starts with this, under `harvest:` so the
/// migration tests hold it to the export prefix. Only the ledgers are
/// exported ([`is_ledger_key`], `migration::is_store_key`): an arm describes
/// this node's subscriptions and the UI re-arms on every open, and the tip
/// cache and exported marker describe this node alone.
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

/// Whether a store's ledger has requests a refused update left undecided
/// (`Ledger::retry_pending`), kept beside the ledger as `b"1"` or `b"0"` so
/// the wake-up can find out without decoding every ledger (#206: decoding
/// sixteen full ledgers twice put the wake-up at 189% of a call's budget).
/// Node-local, like the arm: not exported.
pub(crate) fn retry_key(store_contract_id: &[u8]) -> Vec<u8> {
    format!(
        "{AUTO_PREFIX}retry:{}",
        bs58::encode(store_contract_id).into_string()
    )
    .into_bytes()
}

/// [`retry_key`] for the store a [`ledger_key`] names.
pub(crate) fn retry_key_for_ledger(ledger_key: &[u8]) -> Option<Vec<u8>> {
    let suffix = ledger_key.strip_prefix(format!("{AUTO_PREFIX}ledger:").as_bytes())?;
    let mut key = format!("{AUTO_PREFIX}retry:").into_bytes();
    key.extend_from_slice(suffix);
    Some(key)
}

/// Bring a [`retry_key`] in line with a ledger's flag, writing only when it
/// differs (each write is an fsync on a node). Whether it now says so.
pub(crate) fn sync_retry_flag<S: SecretStore>(secrets: &mut S, key: &[u8], pending: bool) -> bool {
    let want: &[u8] = if pending { b"1" } else { b"0" };
    secrets.get_secret(key).as_deref() == Some(want) || secrets.set_secret(key, want)
}

/// Save a store's ledger, and its [`retry_key`] beside it. Every ledger
/// write goes through here (`every_ledger_write_goes_through_save_ledger`).
///
/// The two writes are ordered so that a failure or a call stopped between
/// them errs toward a retry: a pending flag is written BEFORE the ledger
/// (left alone, it only costs a re-read), and a cleared one after it. Whether
/// the LEDGER was saved, which is what callers act on (`decide` publishes
/// only what it recorded). A flag that could not be written is not lost: a
/// missing one sends the wake-up to the ledger (`mailbox_retries`), and the
/// next mailbox run puts a wrong one right. (A host that refuses a "1" over a
/// "0" and then accepts the ledger leaves that retry to the next mailbox
/// change, as before the flag existed.)
fn save_ledger<S: SecretStore>(secrets: &mut S, store_contract_id: &[u8], ledger: &Ledger) -> bool {
    let flag = retry_key(store_contract_id);
    if ledger.retry_pending {
        sync_retry_flag(secrets, &flag, true);
    }
    let saved = save(secrets, &ledger_key(store_contract_id), ledger);
    if saved && !ledger.retry_pending {
        sync_retry_flag(secrets, &flag, false);
    }
    saved
}

/// Whether `key` is one of the ledgers ([`ledger_key`]): the one part of
/// instant checkout's state that moves to a successor generation.
pub(crate) fn is_ledger_key(key: &[u8]) -> bool {
    key.starts_with(format!("{AUTO_PREFIX}ledger:").as_bytes())
}

/// Fold a predecessor's encoded ledger into what `held` encodes (a
/// migration import). `Err` when the predecessor's does not decode.
pub(crate) fn merge_ledger_bytes(
    held: Option<&[u8]>,
    incoming: &[u8],
) -> Result<(Option<Vec<u8>>, bool), String> {
    let incoming: Ledger =
        from_cbor(incoming).map_err(|_| "the ledger did not decode".to_string())?;
    let mut ledger: Ledger = match held {
        None => Ledger::default(),
        Some(bytes) => {
            from_cbor(bytes).map_err(|_| "this delegate's own ledger did not decode".to_string())?
        }
    };
    if !merge_ledgers(&mut ledger, incoming) {
        return Ok((None, ledger.retry_pending));
    }
    to_cbor(&ledger)
        .map(|bytes| (Some(bytes), ledger.retry_pending))
        .map_err(|e| e.to_string())
}

/// What `decide` last found when it could not invoice for this store
/// because of the payment counter (harvest#206): CBOR of
/// `Option<CatchUpMark>`, `None` once a scan for it completed. While it
/// stands, the store's status and heartbeat say so rather than read as taking
/// orders ([`counter_refusal`]). Never a refusal `decide` checks: decide's own
/// scan is what catches up, so it must go on running. Node-local, like the
/// arm: not exported.
pub(crate) fn catchup_key(store_contract_id: &[u8]) -> Vec<u8> {
    format!(
        "{AUTO_PREFIX}catchup:{}",
        bs58::encode(store_contract_id).into_string()
    )
    .into_bytes()
}

/// What the store's state said the last time this delegate read it, for
/// the refusals only that state can give (`StoreClosed`, `NotOurStore`):
/// one byte, written by [`note_store_read`] from every read of the state
/// (`decide`, a store notification) when it differs. The wake-up reads this
/// instead of the store, which it does not fetch, so a heartbeat says "not
/// taking orders" for a store `decide` would refuse (harvest#198 lane, item
/// 2). Absent means no read has refused, which is how every store starts.
/// Node-local, like the arm: not exported.
pub(crate) fn store_read_key(store_contract_id: &[u8]) -> Vec<u8> {
    format!(
        "{AUTO_PREFIX}store:{}",
        bs58::encode(store_contract_id).into_string()
    )
    .into_bytes()
}

const STORE_READ_OPEN: &[u8] = b"o";
const STORE_READ_CLOSED: &[u8] = b"c";
const STORE_READ_NOT_OURS: &[u8] = b"n";

/// The refusal a store's state gives on its own, as `decide` checks it: not
/// signed by `owner` (including a store nobody has published to), then
/// closed.
fn store_refusal(store: &StoreStateV1, owner: &VerifyingKey) -> Option<Refusal> {
    if store.owner.as_ref() != Some(owner) {
        Some(Refusal::NotOurStore)
    } else if !store.closed.is_empty() {
        Some(Refusal::StoreClosed)
    } else {
        None
    }
}

/// Record what a read of the store's state said ([`store_read_key`]),
/// written only when it changed: a store notification arrives with every
/// order and status, and the answer almost never changes.
fn note_store_read<S: SecretStore>(
    secrets: &mut S,
    store_contract_id: &[u8],
    refusal: Option<&Refusal>,
) {
    let value = match refusal {
        Some(Refusal::NotOurStore) => STORE_READ_NOT_OURS,
        Some(Refusal::StoreClosed) => STORE_READ_CLOSED,
        _ => STORE_READ_OPEN,
    };
    let key = store_read_key(store_contract_id);
    if secrets.get_secret(&key).as_deref() != Some(value) {
        secrets.set_secret(&key, value);
    }
}

/// The refusal the last read of the store's state gave ([`store_read_key`]).
fn store_read_refusal<S: SecretStore>(secrets: &S, store_contract_id: &[u8]) -> Option<Refusal> {
    match secrets
        .get_secret(&store_read_key(store_contract_id))
        .as_deref()
    {
        Some(STORE_READ_NOT_OURS) => Some(Refusal::NotOurStore),
        Some(STORE_READ_CLOSED) => Some(Refusal::StoreClosed),
        _ => None,
    }
}

/// A [`catchup_key`] mark.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct CatchUpMark {
    /// When it was written; renewed by every run that finds the same.
    at_ms: u64,
    /// Which key it is about (`published_set::digest` of the key as
    /// stored): a mark for a key that is no longer active says nothing.
    key: [u8; 16],
    /// The count the scan raised could not be kept (`CounterNotSaved`),
    /// rather than the scan simply not being finished.
    not_saved: bool,
}

/// How long a [`catchup_key`] mark stands without being renewed. A store
/// that is catching up is re-run at each wake-up (every five minutes) while
/// its requests wait, and each such run writes the mark again; one not
/// renewed for this long belongs to a catch-up nothing is driving any more,
/// and the store's status goes back to what it was.
pub(crate) const CATCHING_UP_SHOWN_MS: u64 = 30 * 60 * 1000;

/// What the store's status and heartbeat say about the payment counter: a
/// recent [`catchup_key`] mark, for the key still active, whose catch-up is
/// not since known to be complete (by whichever path completed it: a tab's
/// request, another store's `decide`, a wake-up). `CounterNotSaved` when the
/// mark says the count could not be kept.
fn counter_refusal<S: SecretStore>(
    secrets: &S,
    store_contract_id: &[u8],
    now_ms: u64,
) -> Option<Refusal> {
    let mark = load::<_, Option<CatchUpMark>>(secrets, &catchup_key(store_contract_id))
        .flatten()
        .filter(|m| now_ms.saturating_sub(m.at_ms) < CATCHING_UP_SHOWN_MS)?;
    let active = crate::bitcoin::load_payment_xpub(secrets)?;
    if crate::published_set::digest(active.xpub.as_bytes()) != mark.key {
        return None;
    }
    if mark.not_saved {
        return Some(Refusal::CounterNotSaved);
    }
    (!crate::bitcoin::active_scan_known_complete(secrets)).then_some(Refusal::CatchingUp)
}

/// Write a [`catchup_key`] mark for `xpub`, or clear one once a scan
/// completed (written only when there is one).
fn mark_counter<S: SecretStore>(
    secrets: &mut S,
    store_contract_id: &[u8],
    mark: Option<(u64, &str, bool)>,
) {
    let key = catchup_key(store_contract_id);
    let value = mark.map(|(at_ms, xpub, not_saved)| CatchUpMark {
        at_ms,
        key: crate::published_set::digest(xpub.as_bytes()),
        not_saved,
    });
    if value.is_some()
        || load::<_, Option<CatchUpMark>>(secrets, &key)
            .flatten()
            .is_some()
    {
        save(secrets, &key, &value);
    }
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
// I4's caps are invisible and generous (Ian, 2026-09-26): no genuine buyer
// should reach one, and sellers are not told about them. The per-buyer one is
// shared with the buyer's app, which says so before sending
// (`harvest_common::delegate::MAX_UNPAID_INSTANT_PER_BUYER`).
pub(crate) const MAX_OPEN_PER_STORE: usize = 50;
pub(crate) const MAX_OPEN_PER_CONVERSATION: usize =
    harvest_common::delegate::MAX_UNPAID_INSTANT_PER_BUYER;
pub(crate) const MAX_PER_DAY: usize = 100;
/// A sanity bound, not a working limit (Ian, 2026-09-26): a store never
/// stops taking orders because buyers pressed Buy now and did not pay. A
/// wallet that stops looking after 20 unused addresses in a row may then miss
/// a payment past such a run, so the seller is told to raise its gap limit to
/// this when that has happened (`AutoInvoiceStatus::wallet_gap_paid_at_ms`,
/// `harvest-ui`'s `AppState::wallet_gap_note_due`), and the wallet guide says
/// so up front.
pub(crate) const MAX_TRAILING_UNPAID: u32 = 100;
/// How far the whole run of unused addresses below the counter, across
/// every store of the device (the payment key is shared), is counted: what
/// the wallet gap limit the seller is told can cover. Not a limit on
/// invoicing: a stop here would never heal on its own, and unpaid clicks
/// must never stop a store (review rounds 3 and 4 of harvest#177).
pub(crate) const MAX_ADDRESS_RUN: u32 = 1000;
/// Requests answered in one run; the rest wait for the next change.
pub(crate) const MAX_BATCH: usize = 16;
/// Every instant invoice asks one confirmation (harvest#155).
pub(crate) const REQUIRED_CONFIRMATIONS: u32 = 1;
/// How long the bridge must still be watching when an instant invoice goes
/// out: a buyer may start paying until the anchor is
/// [`MAX_ANCHOR_AGE_BLOCKS`] behind (about eight hours at ten minutes a
/// block, and longer about one time in twenty), and the payment then needs
/// time to confirm. A payment the bridge was not watching for when it was
/// mined is never seen (freenet-bitcoin#7), so an invoice whose watch could
/// lapse inside this is not issued. A payment that takes longer than this to
/// confirm can still be missed if the seller stays away: a residual.
pub(crate) const WATCH_NEEDED_MS: u64 =
    MAX_ANCHOR_AGE_BLOCKS as u64 * 10 * 60 * 1000 + 3 * 60 * 60 * 1000;
/// How far ahead of this node's clock a Buy now may be dated.
pub(crate) const MAX_CLOCK_AHEAD_MS: u64 = 10 * 60 * 1000;
/// [`WATCH_NEEDED_MS`] in blocks, for a watch that ends at a height
/// ([`AutoInvoiceArm::watched_until_height`]): the blocks a buyer may still
/// start paying in, three hours of blocks for the payment to confirm, and six
/// for the tip the UI read being behind the bridge's (a horizon is clamped
/// from the bridge's own tip, which a reorg can leave lower).
pub(crate) const WATCH_NEEDED_BLOCKS: u32 = MAX_ANCHOR_AGE_BLOCKS + 18 + 6;
/// A sale whose order has not appeared in the store after this long is
/// taken to have never landed (a refused update), and forgotten.
pub(crate) const NOT_LANDED_MS: u64 = 10 * 60 * 1000;
/// How long an unpaid instant order holds its stock (Ian, 2026-09-26: about
/// an hour, not the whole payment window). The invoice stays payable after
/// it; a payment that arrives once the item has sold to someone else goes
/// through the oversold path (`AutoInvoiceStatus::oversold`), which tells the
/// seller.
pub(crate) const HOLD_MS: u64 = 60 * 60 * 1000;
const SEEN_CAP: usize = 1024;
const ANSWERED_CAP: usize = 1024;
const STATUSES_CAP: usize = 64;
/// Sales are kept for a whole payment window (about two weeks), at most
/// [`MAX_PER_DAY`] a day. Past it no new instant invoice is issued, rather
/// than one whose sale could not be recorded.
const SALES_CAP: usize = 2048;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// Written when this generation's secrets are exported to a successor: from
/// then on it arms nothing, so an old tab cannot put it back to work beside
/// the successor, from a counter the successor has also copied.
pub(crate) const EXPORTED_KEY: &[u8] = b"harvest:auto:exported";

/// An arm as stored.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct ArmRecord {
    pub arm: AutoInvoiceArm,
    /// When this store was first armed here, kept across re-arms.
    pub armed_at_ms: u64,
    /// When the watch on `arm.watched_scripts` lapses, by this node's clock:
    /// the time of the latest arm plus its `watch_left_ms`.
    pub watched_until_ms: u64,
    /// When this arm last arrived, by this node's clock. Its scripts (both
    /// lists) count only within [`VETTED_FOR_MS`] of it. An open tab re-arms
    /// about every ten minutes and re-reads its window as often, so this is
    /// within minutes of when the window was last read clear. 0 for a record
    /// written before the field: it counts for nothing until re-armed.
    #[serde(default)]
    pub last_armed_ms: u64,
}

/// How long after an arm's last arrival its scripts still count, from
/// either source (harvest#198, review round 1 of batch 2). An armed address
/// read clear can still be paid after the read (by the seller's own wallet,
/// which shares the account key, or late), and the chance grows with time;
/// a week is just under the delegated request horizon
/// (`watch_delegation::REQUEST_AHEAD_BLOCKS`, nine days), so the delegation
/// renews about once in a read's life. The cost: a seller who has not opened
/// Harvest for a week stops taking orders until they do.
pub(crate) const VETTED_FOR_MS: u64 = 7 * 24 * 60 * 60 * 1000;

impl ArmRecord {
    /// Whether this arm's scripts may still count at `now_ms`
    /// ([`VETTED_FOR_MS`]).
    pub(crate) fn vetted_recently(&self, now_ms: u64) -> bool {
        now_ms < self.last_armed_ms.saturating_add(VETTED_FOR_MS)
    }
}

/// Empty every arm's script lists, keeping the arms: what the payment key's
/// change means (harvest#198, review round 1 of batch 2). A window read
/// clear under one key says nothing after the key changes, and changes back
/// (A to B to A) need not restore it: the seller's own wallet may have paid
/// one of its addresses meanwhile. Nothing is invoiced until the tab re-arms
/// under the active key, having read its window; the heartbeat says not
/// taking orders meanwhile. Called by `bitcoin::save_payment_xpub`, the one
/// writer of the active key.
pub(crate) fn forget_armed_scripts<S: SecretStore>(secrets: &mut S) {
    for mut record in arms(secrets) {
        if record.arm.watched_scripts.is_empty() && record.arm.vetted_scripts.is_empty() {
            continue;
        }
        record.arm.watched_scripts.clear();
        record.arm.vetted_scripts.clear();
        record.arm.watched_until_height = None;
        save(secrets, &arm_key(&record.arm.store_contract_id), &record);
    }
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
    /// The last status this delegate signed per listing, until the store
    /// shows it (or something newer): a run that read the store before it
    /// landed still counts it, and a store change re-sends one that has not
    /// landed.
    pub statuses: Vec<ListingStatus>,
    /// Every instant order this delegate issued for a counted listing, until
    /// its outcome is settled ([`settle`]). Published stock changes only when
    /// one is PAID, once; an unpaid one holds its quantity only for
    /// [`HOLD_MS`] ([`Sale::holds`]). Kept past that, for
    /// the whole payment window, because a payment may still confirm late,
    /// or after the buyer cancelled (Paid outranks Cancelled).
    #[serde(default)]
    pub sales: Vec<Sale>,
    /// Orders whose sale is settled and forgotten, so a predecessor's ledger
    /// merged in again cannot bring one back to be decremented twice.
    #[serde(default)]
    pub settled: VecDeque<OrderId>,
    /// Instant orders paid when published stock could not cover them (see
    /// `AutoInvoiceStatus::oversold`), and when that was found. Shown to the
    /// seller for [`OVERSOLD_SHOWN_MS`], then dropped.
    #[serde(default)]
    pub oversold: Vec<Oversold>,
    /// Instant orders issued at an address past a run of
    /// [`WALLET_GAP_LIMIT`] or more unpaid ones: a wallet with the usual gap
    /// limit does not look that far, so a payment to one may not show in it.
    /// Kept, with the length of that run, until one is seen paid (then
    /// [`Self::gap_paid`]) or it falls off the end.
    #[serde(default)]
    pub gap_orders: VecDeque<(OrderId, u32)>,
    /// When one of [`Self::gap_orders`] was last seen paid, and the longest
    /// run any of them sat past: the seller is told, for
    /// [`OVERSOLD_SHOWN_MS`], the gap limit their wallet needs
    /// (`AutoInvoiceStatus::wallet_gap_paid_at_ms`, `wallet_gap_limit`).
    #[serde(default)]
    pub gap_paid: Option<(u64, u32)>,
    /// When a Buy now was last turned away by a store limit, and which: the
    /// seller is told for [`CAPPED_SHOWN_MS`] (`AutoInvoiceStatus::capped`).
    #[serde(default)]
    pub capped: Option<(u64, String)>,
    /// Requests are waiting for a run to answer them: an update this
    /// delegate sent was refused, so some are undecided again, or the last
    /// mailbox run left messages unopened or unbatched (`OPEN_BUDGET`,
    /// `MAX_BATCH`). Mirrored by [`retry_key`], which the wake-up reads.
    #[serde(default)]
    pub retry_pending: bool,
}

/// How long the seller is told a store limit turned a buyer away.
pub(crate) const CAPPED_SHOWN_MS: u64 = 60 * 60 * 1000;

/// The gap limit most wallets start with: how many unused addresses in a
/// row they look past before they stop.
pub(crate) const WALLET_GAP_LIMIT: u32 = 20;

/// The gap limit a wallet needs to see a payment that sat past a run of
/// `run` unused addresses: 100 (the figure the wallet guide gives) unless
/// the run was that long or longer, then the next hundred above it. One to
/// spare, for wallets that count the limit one short.
///
/// A run counted to [`MAX_ADDRESS_RUN`] may be longer than that (the count
/// stops there): `u32::MAX`, which the seller's page words as "as high as it
/// goes" rather than a figure that may fall short.
pub(crate) fn wallet_gap_limit_for(run: u32) -> u32 {
    if run >= MAX_ADDRESS_RUN {
        return u32::MAX;
    }
    let needed = run.saturating_add(1);
    if needed < 100 {
        100
    } else {
        (needed / 100 + 1) * 100
    }
}
/// A payment window's worth at the daily cap (100 a day for about two
/// weeks), so no gap order still payable is dropped (codex on harvest#177).
const GAP_ORDERS_CAP: usize = 1500;

/// An instant order paid when published stock could not cover it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Oversold {
    pub order: OrderId,
    pub found_at_ms: u64,
}

/// How long an oversold order is shown to the seller: long enough to be seen
/// on some visit, short enough that one already dealt with goes away.
pub(crate) const OVERSOLD_SHOWN_MS: u64 = 14 * DAY_MS;

/// One instant order for a counted listing.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct Sale {
    pub order: OrderId,
    pub listing: ListingId,
    pub quantity: u32,
    pub issued_at_ms: u64,
    pub anchor_height: u32,
    /// The revision of the status that took this sale off published stock,
    /// once the order was seen Paid. Kept until the store shows it.
    #[serde(default)]
    pub decremented: Option<u64>,
}

impl Sale {
    /// Whether this sale still holds its quantity against new instant
    /// invoices, given the order as the store has it.
    ///
    /// An unpaid one holds for [`HOLD_MS`] from when it was issued, and no
    /// longer: its invoice stays payable for hours after that, and a payment
    /// arriving once the stock is gone is the oversold path's to report.
    fn holds(&self, order: Option<&AuthorizedOrder>, now_ms: u64) -> bool {
        if self.decremented.is_some() {
            // Already off published stock.
            return false;
        }
        let age = now_ms.saturating_sub(self.issued_at_ms);
        match order.map(|o| o.status) {
            // Paid and not yet decremented: the decrement is about to go out.
            Some(OrderStatus::Paid) => true,
            Some(OrderStatus::Cancelled) | Some(OrderStatus::PaymentReversed) => false,
            Some(OrderStatus::AwaitingPayment) => age < HOLD_MS,
            None => age < NOT_LANDED_MS,
        }
    }
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
        // One distinct time per invoice, so a migration merging these as a
        // set keeps every one (several are issued in one run).
        let mut at = now_ms;
        while self.issued_at_ms.contains(&at) {
            at += 1;
        }
        self.issued_at_ms.push(at);
    }

    /// Stock held for `listing` by unpaid instant orders ([`Sale::holds`]).
    fn held(&self, listing: &ListingId, store: &StoreStateV1, now_ms: u64) -> u32 {
        self.sales
            .iter()
            .filter(|s| s.listing == *listing)
            .filter(|s| s.holds(store.orders.orders.get(&s.order), now_ms))
            .map(|s| s.quantity)
            .sum()
    }

    fn settle(&mut self, order: OrderId) {
        if !self.settled.contains(&order) {
            self.settled.push_back(order);
            while self.settled.len() > ANSWERED_CAP {
                self.settled.pop_front();
            }
        }
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

/// The newest block this delegate has seen for a network.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct TipCache {
    pub anchor: BlockAnchor,
    /// The block header's own time, in seconds.
    pub block_time: u32,
}

/// When this delegate last acted on a notification for something an arm
/// names, by the node's clock: the evidence that it runs in the background
/// here, which a hosted gateway never gives (see the module docs). Any such
/// notification counts, a buyer's request as much as a block; a tip read on
/// arming does not, because the seller's own request caused it
/// (harvest#162).
pub(crate) const RAN_KEY: &[u8] = b"harvest:auto:ran";

/// Carried through the store GET, so the answer knows which entries to
/// decide. Ciphertext only: the plaintext, keys and the buyer's address never
/// leave this delegate.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct PendingBatch {
    magic: [u8; 8],
    store_contract_id: Vec<u8>,
    entries: Vec<EncryptedMessage>,
    /// The run that sent this left other messages for later.
    #[serde(default)]
    backlog: bool,
}

/// Carried through the store UPDATE: the replies to send once the store has
/// taken the orders, so a buyer is never pointed at an order that did not
/// land.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct PendingReplies {
    magic: [u8; 8],
    mailbox_contract_id: [u8; 32],
    replies: Vec<EncryptedMessage>,
    /// The store the orders went to, and each answered request's entry
    /// digest and request id: if the store refuses the update, they are
    /// forgotten as seen and answered, so the store's next run decides them
    /// again instead of leaving the buyer unanswered for good (codex on
    /// harvest#177).
    #[serde(default)]
    store_contract_id: Vec<u8>,
    #[serde(default)]
    retry: Vec<([u8; 32], [u8; 32])>,
    /// The orders the update carried (for the log and a later retry).
    #[serde(default)]
    orders: Vec<OrderId>,
}

const BATCH_MAGIC: [u8; 8] = *b"hvauto01";
const RETRY_MAGIC: [u8; 8] = *b"hvretry1";

/// Carried through a mailbox read a wake-up asks for when requests are
/// waiting (`Ledger::retry_pending`, read from its [`retry_key`]).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct MailboxRetry {
    magic: [u8; 8],
    store_contract_id: Vec<u8>,
}

/// A mailbox read for every armed store with requests left undecided by a
/// refused update: the wake-up's way to answer them without waiting for the
/// mailbox to change (codex on harvest#177).
pub(crate) fn mailbox_retries<S: SecretStore>(
    secrets: &S,
    now_ms: u64,
) -> Vec<OutboundDelegateMsg> {
    if secrets.has_secret(EXPORTED_KEY) {
        return Vec::new();
    }
    let delegations = Delegations::read(secrets);
    arms(secrets)
        .iter()
        // Every ledger write writes the flag (`save_ledger`, and the import
        // of a predecessor's ledger); one missing (a write the host refused)
        // is answered by the ledger itself.
        .filter(|record| {
            let id = &record.arm.store_contract_id;
            match secrets.get_secret(&retry_key(id)).as_deref() {
                Some(b"1") => true,
                Some(_) => false,
                None => ledger_retry_pending(secrets, id),
            }
        })
        // Only while the store can take orders: a run turned away (a lapsed
        // watch, a missing key, a tip too old) stops before reading anything,
        // and a wake-up neither lifts that nor fetches a tip. The flag is
        // kept, so the first wake-up after it lifts reads.
        .filter(|record| {
            let tip: Option<TipCache> = load(secrets, &tip_key(record.arm.network));
            let watched = watch_set_in(&delegations, record, tip.as_ref(), now_ms);
            refusal_given(secrets, record, tip.as_ref(), &watched, now_ms).is_ok()
        })
        .filter_map(|record| {
            let context = to_cbor(&MailboxRetry {
                magic: RETRY_MAGIC,
                store_contract_id: record.arm.store_contract_id.clone(),
            })
            .ok()?;
            let mut get =
                GetContractRequest::new(ContractInstanceId::new(record.arm.mailbox_contract_id));
            get.context = DelegateContext::new(context);
            Some(OutboundDelegateMsg::GetContractRequest(get))
        })
        .collect()
}

/// The mailbox read [`mailbox_retries`] asked for: the mailbox decided as
/// if it had just changed, which settles the retry flag.
fn on_mailbox_retry<S: SecretStore>(
    secrets: &mut S,
    store_contract_id: &[u8],
    state: Option<&[u8]>,
    now_ms: u64,
) -> Vec<OutboundDelegateMsg> {
    let Some(record) = load_arm(secrets, store_contract_id) else {
        return Vec::new();
    };
    let Some(state) = state else {
        return Vec::new();
    };
    // The run settles the flag once it has read the ledger (`on_mailbox`);
    // one turned away before that (no fresh tip yet, say) leaves it for the
    // next wake-up.
    on_mailbox(secrets, &record, state, now_ms)
}
const REPLIES_MAGIC: [u8; 8] = *b"hvrepl01";

pub(crate) fn load<S: SecretStore, T: for<'de> Deserialize<'de>>(
    secrets: &S,
    key: &[u8],
) -> Option<T> {
    secrets.get_secret(key).and_then(|b| from_cbor(&b).ok())
}

pub(crate) fn save<S: SecretStore, T: Serialize>(secrets: &mut S, key: &[u8], value: &T) -> bool {
    to_cbor(value).is_ok_and(|bytes| secrets.set_secret(key, &bytes))
}

pub(crate) fn load_arm<S: SecretStore>(secrets: &S, store_contract_id: &[u8]) -> Option<ArmRecord> {
    load(secrets, &arm_key(store_contract_id))
}

pub(crate) fn arms<S: SecretStore>(secrets: &S) -> Vec<ArmRecord> {
    secrets
        .list_secrets(format!("{AUTO_PREFIX}arm:").as_bytes())
        .iter()
        .filter_map(|key| load(secrets, key))
        .collect()
}

/// What a store's status shows of its ledger. Read without decoding the rest
/// ([`crate::fast_cbor::map_fields`]): a tip read sends the status of every
/// armed store, and decoding sixteen full ledgers for it took most of a
/// call's budget (#206).
#[derive(Default, PartialEq, Debug)]
struct LedgerShown {
    issued_at_ms: Vec<u64>,
    oversold: Vec<Oversold>,
    gap_paid: Option<(u64, u32)>,
    capped: Option<(u64, String)>,
}

impl LedgerShown {
    fn of(ledger: Ledger) -> Self {
        LedgerShown {
            issued_at_ms: ledger.issued_at_ms,
            oversold: ledger.oversold,
            gap_paid: ledger.gap_paid,
            capped: ledger.capped,
        }
    }

    fn issued_last_day(&self, now_ms: u64) -> usize {
        self.issued_at_ms
            .iter()
            .filter(|at| now_ms.saturating_sub(**at) < DAY_MS)
            .count()
    }
}

/// What a status shows of a store's ledger, or `None` when one is held that
/// does not decode (`load_ledger_kept` stops every run on it, which the
/// status must say).
fn load_ledger_shown<S: SecretStore>(secrets: &S, store_contract_id: &[u8]) -> Option<LedgerShown> {
    let Some(bytes) = secrets.get_secret(&ledger_key(store_contract_id)) else {
        return Some(LedgerShown::default());
    };
    ledger_shown(&bytes).or_else(|| from_cbor::<Ledger>(&bytes).ok().map(LedgerShown::of))
}

/// [`LedgerShown`] from a ledger's bytes, field by field, or `None` when any
/// of it does not read (the caller then decodes the whole ledger). The
/// fields skipped are checked only for their shape and for the presence of
/// those a ledger cannot lack, so a ledger this delegate wrote reads as the
/// whole decode reads it; one damaged inside a skipped field may show here
/// what the whole decode would refuse.
fn ledger_shown(bytes: &[u8]) -> Option<LedgerShown> {
    const FIELDS: [&str; 7] = [
        "issued_at_ms",
        "oversold",
        "gap_paid",
        "capped",
        // Without a `serde(default)`: present in every ledger.
        "seen",
        "answered",
        "statuses",
    ];
    let fields = crate::fast_cbor::map_fields(bytes, &FIELDS)?;
    let has = |i: usize| fields.iter().any(|(j, _)| *j == i);
    if !(has(0) && has(4) && has(5) && has(6)) {
        return None;
    }
    let mut shown = LedgerShown::default();
    for (i, value) in fields {
        match i {
            0 => shown.issued_at_ms = from_cbor(value).ok()?,
            1 => shown.oversold = from_cbor(value).ok()?,
            2 => shown.gap_paid = from_cbor(value).ok()?,
            3 => shown.capped = from_cbor(value).ok()?,
            _ => {}
        }
    }
    Some(shown)
}

/// A ledger's `retry_pending`, read without decoding the rest (as
/// [`ledger_shown`] reads its fields), for a wake-up that finds a flag
/// missing.
fn ledger_retry_pending<S: SecretStore>(secrets: &S, store_contract_id: &[u8]) -> bool {
    let Some(bytes) = secrets.get_secret(&ledger_key(store_contract_id)) else {
        return false;
    };
    match crate::fast_cbor::map_fields(&bytes, &["retry_pending"]) {
        Some(fields) => fields
            .first()
            .is_some_and(|(_, value)| from_cbor::<bool>(value).unwrap_or(true)),
        None => from_cbor::<Ledger>(&bytes).is_ok_and(|l| l.retry_pending),
    }
}

/// The ledger, for a run that will write it back: `None` when one is held
/// that does not decode, so the run stops rather than saving an empty ledger
/// over it, which would forget what was answered (a second invoice for a
/// request already invoiced), the stock its sales hold, and what is settled.
/// A store with no ledger yet starts from an empty one.
fn load_ledger_kept<S: SecretStore>(secrets: &S, store_contract_id: &[u8]) -> Option<Ledger> {
    match secrets.get_secret(&ledger_key(store_contract_id)) {
        None => Some(Ledger::default()),
        Some(bytes) => from_cbor(&bytes).ok(),
    }
}

#[cfg(test)]
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
    if secrets.has_secret(EXPORTED_KEY) {
        return refuse(
            "this generation of the Harvest delegate has handed its keys to a newer one; \
             reload Harvest to use it"
                .into(),
        );
    }
    let max = harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES as usize;
    if arm.watched_scripts.len() > max || arm.vetted_scripts.len() > max {
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
        last_armed_ms: now_ms,
        arm: arm.clone(),
    };
    if !save(secrets, &arm_key(&arm.store_contract_id), &record) {
        return refuse("the node refused to store the arm".into());
    }
    let mut subscribe: Vec<OutboundDelegateMsg> =
        [store_id, arm.mailbox_contract_id, arm.tip_contract_id]
            .into_iter()
            .map(|id| {
                OutboundDelegateMsg::SubscribeContractRequest(SubscribeContractRequest::new(
                    ContractInstanceId::new(id),
                ))
            })
            .collect();
    // And read the tip now (harvest#162). A subscription delivers the next
    // block, not the current one, so a node that had never seen the tip
    // waited up to a block (about ten minutes on signet) before its first
    // invoice. The answer is taken by `on_get_answer`. With the three
    // subscriptions this is four network operations, which is exactly the
    // node's per-request budget for a delegate.
    subscribe.push(OutboundDelegateMsg::GetContractRequest(
        GetContractRequest::new(ContractInstanceId::new(arm.tip_contract_id)),
    ));
    // Then the presence contract, last: the node refuses a delegate's
    // network operations past four per request (`MAX_NETWORK_CONTRACT_OPS_
    // PER_PARK`, counting only contracts it has never seen), and the four
    // above matter more. The seller's tab PUTs it anyway; this keeps the node
    // holding it once the tab is gone (see `resubscribe_all`).
    if let Some(presence) = arm.presence_contract_id {
        subscribe.extend(presence_ops(presence));
    }
    (
        HarvestDelegateResponse::AutoInvoice {
            store_contract_id,
            result: Ok(status_of(secrets, &record, now_ms)),
        },
        subscribe,
    )
}

fn status_of<S: SecretStore>(secrets: &S, record: &ArmRecord, now_ms: u64) -> AutoInvoiceStatus {
    status_in(secrets, &Delegations::read(secrets), record, now_ms)
}

/// [`status_of`], with the delegations already read.
fn status_in<S: SecretStore>(
    secrets: &S,
    delegations: &Delegations,
    record: &ArmRecord,
    now_ms: u64,
) -> AutoInvoiceStatus {
    let tip: Option<TipCache> = load(secrets, &tip_key(record.arm.network));
    let shown = load_ledger_shown(secrets, &record.arm.store_contract_id);
    let unreadable = shown.is_none();
    let ledger = shown.unwrap_or_default();
    let watched = watch_set_in(delegations, record, tip.as_ref(), now_ms);
    let (remaining, run_until_ms) =
        accepted_run_of(delegations.upcoming(), record, &watched, now_ms);
    AutoInvoiceStatus {
        armed_at_ms: record.armed_at_ms,
        watched_remaining: remaining,
        invoicing_until_ms: if remaining == 0 {
            record.watched_until_ms.saturating_sub(WATCH_NEEDED_MS)
        } else {
            run_until_ms
        },
        last_background_run_ms: load::<_, u64>(secrets, RAN_KEY),
        issued_last_day: ledger.issued_last_day(now_ms) as u32,
        oversold: ledger
            .oversold
            .iter()
            .filter(|o| now_ms.saturating_sub(o.found_at_ms) < OVERSOLD_SHOWN_MS)
            .map(|o| o.order.clone())
            .collect(),
        paused: not_taking_given(
            secrets,
            record,
            tip.as_ref(),
            &watched,
            || remaining,
            now_ms,
        )
        .or(unreadable.then_some(Refusal::LedgerUnreadable))
        .map(|r| r.explain()),
        wallet_gap_paid_at_ms: ledger
            .gap_paid
            .map(|(at, _)| at)
            .filter(|at| now_ms.saturating_sub(*at) < OVERSOLD_SHOWN_MS),
        wallet_gap_limit: ledger
            .gap_paid
            .filter(|(at, _)| now_ms.saturating_sub(*at) < OVERSOLD_SHOWN_MS)
            .map_or(0, |(_, run)| wallet_gap_limit_for(run)),
        capped: ledger
            .capped
            .as_ref()
            .filter(|(at, _)| now_ms.saturating_sub(*at) < CAPPED_SHOWN_MS)
            .map(|(_, why)| why.clone()),
        last_wakeup_ms: load::<_, u64>(secrets, WAKEUP_KEY),
        watch_delegation: delegations.status_for_arm(secrets, &record.arm, now_ms),
    }
}

/// When the node last woke this delegate on its schedule: what tells the
/// seller's tab that heartbeats go on without it (`AutoInvoiceStatus::
/// last_wakeup_ms`). Not exported: it describes this node.
pub(crate) const WAKEUP_KEY: &[u8] = b"harvest:auto:wakeup";

pub(crate) use harvest_common::presence::HEARTBEAT_MIN_GAP_MS;

fn beat_key(store_contract_id: &[u8]) -> Vec<u8> {
    format!(
        "{AUTO_PREFIX}beat:{}",
        bs58::encode(store_contract_id).into_string()
    )
    .into_bytes()
}

/// The last heartbeat this delegate sent for one store. Not exported.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
struct BeatRecord {
    at_ms: u64,
    taking_orders: bool,
    /// The reason it gave for not taking them (`Heartbeat::reason`), so a
    /// change of reason goes out at once as a change of `taking_orders`
    /// does.
    #[serde(default)]
    reason: Option<harvest_common::presence::NotTakingReason>,
    /// The `seq` it was signed with (`harvest_common::presence::Heartbeat`).
    #[serde(default)]
    seq: u64,
}

pub(crate) fn note_wakeup<S: SecretStore>(secrets: &mut S, now_ms: u64) {
    save(secrets, WAKEUP_KEY, &now_ms);
}

/// Whether the store can take an order now: it would issue payment details
/// for a Buy now (no store-wide refusal) and has a watched address left.
/// What a heartbeat carries as `taking_orders`.
///
/// It does not see the per-request caps, which need the store's state: a
/// store at its open-order or daily cap still reads as taking orders.
///
/// The same answer as [`status_of`]'s `paused` and `watched_remaining`,
/// without reading the ledger, which neither needs: the wake-up asks this for
/// every arm, and a full ledger is the costliest secret a store has (#206).
#[cfg(test)]
fn taking_orders<S: SecretStore>(
    secrets: &S,
    record: &ArmRecord,
    now_ms: u64,
    upcoming: &[harvest_common::DerivedAddress],
) -> bool {
    let delegations = Delegations::read(secrets);
    assert_eq!(delegations.upcoming(), upcoming, "the same addresses");
    taking_orders_in(secrets, &delegations, record, now_ms)
}

/// `taking_orders`, with the delegations already read.
#[cfg(test)]
fn taking_orders_in<S: SecretStore>(
    secrets: &S,
    delegations: &Delegations,
    record: &ArmRecord,
    now_ms: u64,
) -> bool {
    not_taking_in(secrets, delegations, record, now_ms).is_none()
}

/// Why a Buy now would be refused for the whole store now, if it would:
/// what a heartbeat's `taking_orders` and the status's `paused` both rest
/// on, so buyers never see a store open while the delegate refuses it. In
/// the order `decide` checks: [`refusal_given`], then what the last read of
/// the store's state said ([`store_read_refusal`]), then the payment
/// counter ([`counter_refusal`]), then no watched address left to issue
/// (`NoWatchedAddress`, the empty [`accepted_run_of`]).
///
/// Not the ledger: a heartbeat does not read it (#206), so
/// `LedgerUnreadable` is added by the status alone.
fn not_taking_in<S: SecretStore>(
    secrets: &S,
    delegations: &Delegations,
    record: &ArmRecord,
    now_ms: u64,
) -> Option<Refusal> {
    let tip: Option<TipCache> = load(secrets, &tip_key(record.arm.network));
    let watched = watch_set_in(delegations, record, tip.as_ref(), now_ms);
    let run = || accepted_run_of(delegations.upcoming(), record, &watched, now_ms).0;
    not_taking_given(secrets, record, tip.as_ref(), &watched, run, now_ms)
}

/// [`not_taking_in`], with the tip and the watch set worked out. `run` is
/// asked for last, and only when nothing else refuses: it derives the
/// upcoming addresses (ten BIP-32 derivations) the first time a run needs
/// them, which a forced heartbeat for a store refused anyway never did.
fn not_taking_given<S: SecretStore>(
    secrets: &S,
    record: &ArmRecord,
    tip: Option<&TipCache>,
    watched: &WatchSet,
    run: impl FnOnce() -> u32,
    now_ms: u64,
) -> Option<Refusal> {
    let id = &record.arm.store_contract_id;
    refusal_given(secrets, record, tip, watched, now_ms)
        .err()
        .or_else(|| store_read_refusal(secrets, id))
        .or_else(|| counter_refusal(secrets, id, now_ms))
        .or_else(|| (run() == 0).then_some(Refusal::NoWatchedAddress))
}

/// Sign a heartbeat for `record`'s store and send it to its presence
/// contract, unless one went out less than [`HEARTBEAT_MIN_GAP_MS`] ago
/// saying the same (or `force`). `None` when there is nothing to send: no
/// presence contract named (an older UI armed it), no store key, this
/// generation exported, or a heartbeat just sent.
pub(crate) fn heartbeat<S: SecretStore>(
    secrets: &mut S,
    record: &ArmRecord,
    now_ms: u64,
    force: bool,
) -> Option<(
    harvest_common::presence::SignedHeartbeat,
    OutboundDelegateMsg,
)> {
    let delegations = Delegations::read(secrets);
    heartbeat_with(secrets, record, now_ms, force, &delegations)
}

/// [`heartbeat`] with the upcoming addresses already derived.
fn heartbeat_with<S: SecretStore>(
    secrets: &mut S,
    record: &ArmRecord,
    now_ms: u64,
    force: bool,
    delegations: &Delegations,
) -> Option<(
    harvest_common::presence::SignedHeartbeat,
    OutboundDelegateMsg,
)> {
    use harvest_common::presence::{Heartbeat, SignedHeartbeat};
    let presence = record.arm.presence_contract_id?;
    if secrets.has_secret(EXPORTED_KEY) {
        return None;
    }
    let reason = not_taking_in(secrets, delegations, record, now_ms).map(|r| r.for_buyers());
    let taking = reason.is_none();
    let key = beat_key(&record.arm.store_contract_id);
    if !force {
        if let Some(last) = load::<_, BeatRecord>(secrets, &key) {
            if last.taking_orders == taking
                && last.reason == reason
                && now_ms >= last.at_ms
                && now_ms - last.at_ms < HEARTBEAT_MIN_GAP_MS
            {
                return None;
            }
        }
    }
    let store_sk = store_key(secrets, &record.arm.store_verifying_key)?;
    // Rising through a clock that jumps back (see `Heartbeat::seq`).
    let seq = load::<_, BeatRecord>(secrets, &key)
        .map_or(now_ms, |last| now_ms.max(last.seq.saturating_add(1)));
    let beat = match reason {
        None => Heartbeat::new(seq, now_ms, true),
        Some(reason) => Heartbeat::not_taking(seq, now_ms, reason),
    };
    let signed = SignedHeartbeat::sign(&store_sk, beat).ok()?;
    let delta = to_cbor(&signed).ok()?;
    save(
        secrets,
        &key,
        &BeatRecord {
            at_ms: now_ms,
            taking_orders: taking,
            reason,
            seq,
        },
    );
    Some((
        signed,
        OutboundDelegateMsg::UpdateContractRequest(UpdateContractRequest::new(
            ContractInstanceId::new(presence),
            UpdateData::Delta(StateDelta::from(delta)),
        )),
    ))
}

/// Learn the `seq` of the heartbeat the presence contract holds, so this
/// delegate's next one outranks it. What `BeatRecord::seq` alone cannot
/// cover: a heartbeat signed elsewhere with the same store key, by an
/// earlier generation of this delegate (the record is not exported) or on a
/// second device, possibly while its clock ran ahead. Without this, a new
/// generation numbers from `now` and loses to that one until real time
/// passes it, and the store reads closed all that while.
///
/// The state is the node's copy of a contract that checked every signature
/// in it, and only the store key signs one, so its `seq` is trusted as is.
fn note_presence_seen<S: SecretStore>(secrets: &mut S, record: &ArmRecord, state: &[u8]) {
    let Some(seen) = harvest_common::presence::decode_state(state)
        .ok()
        .and_then(|state| state.heartbeat)
        .map(|signed| signed.heartbeat.seq)
    else {
        return;
    };
    let key = beat_key(&record.arm.store_contract_id);
    let held = load::<_, BeatRecord>(secrets, &key);
    if held.is_some_and(|held| held.seq >= seen) {
        return;
    }
    // No record yet: one that sent nothing (`at_ms` 0), so the next
    // heartbeat is not held back by the gap.
    let mut next = held.unwrap_or(BeatRecord {
        at_ms: 0,
        taking_orders: false,
        reason: None,
        seq: 0,
    });
    next.seq = seen;
    save(secrets, &key, &next);
}

/// A heartbeat for every armed store that is due one: the wake-up's work.
pub(crate) fn heartbeats<S: SecretStore>(secrets: &mut S, now_ms: u64) -> Vec<OutboundDelegateMsg> {
    // Heartbeats change nothing the delegations, the arms or the payment key
    // read: read once (and the upcoming addresses derived once) for all.
    let delegations = Delegations::read(secrets);
    arms(secrets)
        .iter()
        .filter_map(|record| heartbeat_with(secrets, record, now_ms, false, &delegations))
        .map(|(_, message)| message)
        .collect()
}

/// The tab's heartbeat request
/// ([`harvest_common::delegate::HarvestDelegateRequest::Heartbeat`]): the
/// answer, and the update to send.
pub(crate) fn heartbeat_request<S: SecretStore>(
    secrets: &mut S,
    store_contract_id: &[u8],
    force: bool,
    now_ms: u64,
) -> (HarvestDelegateResponse, Vec<OutboundDelegateMsg>) {
    let answer = |result| HarvestDelegateResponse::Heartbeat {
        store_contract_id: store_contract_id.to_vec(),
        result,
    };
    let Some(record) = load_arm(secrets, store_contract_id) else {
        return (
            answer(Err("this store is not armed here".into())),
            Vec::new(),
        );
    };
    if record.arm.presence_contract_id.is_none() {
        return (
            answer(Err(
                "this store was armed without a presence contract".into()
            )),
            Vec::new(),
        );
    }
    let (heartbeat, out) = match heartbeat(secrets, &record, now_ms, force) {
        Some((signed, message)) => (Some(signed), vec![message]),
        None => (None, Vec::new()),
    };
    (
        answer(Ok(harvest_common::delegate::HeartbeatAnswer {
            heartbeat,
            last_wakeup_ms: load::<_, u64>(secrets, WAKEUP_KEY),
        })),
        out,
    )
}

/// Subscribe again to every armed store's contracts and read what the
/// delegate needs now: the node's start (or this delegate's install), after
/// which subscriptions may be gone and a notification missed.
///
/// In order of what matters, since a node refuses a delegate's network
/// operations past four per run (`MAX_NETWORK_CONTRACT_OPS_PER_PARK`,
/// counting only contracts it has never seen): each tip once (subscribed and
/// read), then every store and mailbox, then every presence contract
/// (subscribed, and read so this generation learns the `seq` to outrank:
/// [`note_presence_seen`]).
pub(crate) fn resubscribe_all<S: SecretStore>(secrets: &mut S) -> Vec<OutboundDelegateMsg> {
    if secrets.has_secret(EXPORTED_KEY) {
        return Vec::new();
    }
    let all = arms(secrets);
    let mut tips: Vec<[u8; 32]> = Vec::new();
    for record in &all {
        if !tips.contains(&record.arm.tip_contract_id) {
            tips.push(record.arm.tip_contract_id);
        }
    }
    // Each tip first, subscribed and read: without a fresh tip nothing is
    // invoiced (`NoFreshTip`) and every heartbeat says "not taking orders".
    // The node refuses a delegate's network operations past four per run
    // (`MAX_NETWORK_CONTRACT_OPS_PER_PARK`, counting only contracts it has
    // never seen), so what matters most goes where no cap reaches it.
    let mut out = Vec::new();
    for tip in &tips {
        out.push(OutboundDelegateMsg::SubscribeContractRequest(
            SubscribeContractRequest::new(ContractInstanceId::new(*tip)),
        ));
        out.push(OutboundDelegateMsg::GetContractRequest(
            GetContractRequest::new(ContractInstanceId::new(*tip)),
        ));
    }
    for record in &all {
        let Ok(store) = <[u8; 32]>::try_from(record.arm.store_contract_id.as_slice()) else {
            continue;
        };
        for id in [store, record.arm.mailbox_contract_id] {
            out.push(OutboundDelegateMsg::SubscribeContractRequest(
                SubscribeContractRequest::new(ContractInstanceId::new(id)),
            ));
        }
    }
    // The presence contracts last. A wake-up's heartbeat is an UPDATE, which
    // fails on a node that does not hold the contract (harvest#119; newer
    // nodes fetch it first), and only the seller's open tab ever PUTs it: a
    // subscription keeps this node holding it with no tab open.
    for presence in all.iter().filter_map(|r| r.arm.presence_contract_id) {
        out.extend(presence_ops(presence));
    }
    out
}

/// Subscribe to a presence contract and read it: the read is what
/// [`note_presence_seen`] learns a heartbeat signed elsewhere from, which a
/// notification alone never delivers once that signer has stopped (the
/// contract merges our lower heartbeats away, so nothing changes).
fn presence_ops(presence: [u8; 32]) -> [OutboundDelegateMsg; 2] {
    [
        OutboundDelegateMsg::SubscribeContractRequest(SubscribeContractRequest::new(
            ContractInstanceId::new(presence),
        )),
        OutboundDelegateMsg::GetContractRequest(GetContractRequest::new(ContractInstanceId::new(
            presence,
        ))),
    ]
}

/// Stop this generation for good: remove every arm, so no background run
/// here invoices again, and mark it exported, so no arm is taken again (an
/// old tab left open would otherwise put it back to work beside its
/// successor). The ledgers go to the successor with the export.
pub(crate) fn disarm_all<S: SecretStore + crate::secrets::RemovableSecrets>(secrets: &mut S) {
    secrets.set_secret(EXPORTED_KEY, b"1");
    for key in secrets.list_secrets(format!("{AUTO_PREFIX}arm:").as_bytes()) {
        secrets.remove_secret(&key);
    }
}

/// Fold a predecessor's ledger into this delegate's (a migration import):
/// the union of what each has seen, answered and issued, the newer of each
/// listing's status, and every sale once, preferring the record that has
/// already decremented. Both are lists this delegate only ever grows or
/// settles, so a union loses nothing either side knew.
pub(crate) fn merge_ledgers(held: &mut Ledger, incoming: Ledger) -> bool {
    // The same decisions as before #206, with every membership test against
    // a set instead of a scan: two full ledgers took about a hundred million
    // comparisons, most of a call's budget on the migration import. Each
    // set mirrors its list exactly, counting copies so a damaged ledger that
    // holds one twice still answers as the scan did.
    // `merge_ledgers_is_the_scanning_merge` pins the equality.
    use std::collections::{HashMap, HashSet};
    fn counts<T: std::hash::Hash + Eq + Clone>(
        items: impl Iterator<Item = T>,
    ) -> HashMap<T, usize> {
        let mut map = HashMap::new();
        for item in items {
            *map.entry(item).or_insert(0) += 1;
        }
        map
    }
    fn forget<T: std::hash::Hash + Eq>(map: &mut HashMap<T, usize>, item: &T) {
        if let Some(n) = map.get_mut(item) {
            *n -= 1;
            if *n == 0 {
                map.remove(item);
            }
        }
    }
    let before = held.clone();
    let mut seen = counts(held.seen.iter().copied());
    for digest in incoming.seen {
        if !seen.contains_key(&digest) {
            held.seen.push_back(digest);
            *seen.entry(digest).or_insert(0) += 1;
            while held.seen.len() > SEEN_CAP {
                if let Some(gone) = held.seen.pop_front() {
                    forget(&mut seen, &gone);
                }
            }
        }
    }
    let mut answered: HashSet<[u8; 32]> = held.answered.iter().copied().collect();
    for request in incoming.answered {
        if answered.insert(request) {
            held.answered.push_back(request);
        }
    }
    while held.answered.len() > ANSWERED_CAP {
        held.answered.pop_front();
    }
    // A set: the same ledger merged twice adds nothing.
    for at in incoming.issued_at_ms {
        if !held.issued_at_ms.contains(&at) {
            held.issued_at_ms.push(at);
        }
    }
    held.issued_at_ms.sort_unstable();
    let excess = held.issued_at_ms.len().saturating_sub(2 * MAX_PER_DAY);
    held.issued_at_ms.drain(..excess);
    let mut gaps: HashSet<OrderId> = held.gap_orders.iter().map(|(id, _)| id.clone()).collect();
    for gap in incoming.gap_orders {
        if gaps.insert(gap.0.clone()) {
            held.gap_orders.push_back(gap);
        }
    }
    while held.gap_orders.len() > GAP_ORDERS_CAP {
        held.gap_orders.pop_front();
    }
    held.gap_paid = match (held.gap_paid, incoming.gap_paid) {
        (Some((at, run)), Some((other_at, other_run))) => {
            Some((at.max(other_at), run.max(other_run)))
        }
        (held, incoming) => held.or(incoming),
    };
    if incoming.capped.as_ref().map(|(at, _)| *at) > held.capped.as_ref().map(|(at, _)| *at) {
        held.capped = incoming.capped;
    }
    held.retry_pending |= incoming.retry_pending;
    for oversold in incoming.oversold {
        if !held.oversold.iter().any(|o| o.order == oversold.order) {
            held.oversold.push(oversold);
        }
    }
    while held.oversold.len() > STATUSES_CAP {
        held.oversold.remove(0);
    }
    for status in incoming.statuses {
        match held.statuses.iter().find(|s| s.listing == status.listing) {
            Some(own) if own.revision >= status.revision => {}
            _ => held.signed(status),
        }
    }
    // Sales first, skipping any either side has settled, and only then the
    // tombstones: merged first, the incoming ones could push this
    // delegate's own out of the capped list and let a settled sale back in.
    let held_settled: HashSet<OrderId> = held.settled.iter().cloned().collect();
    let incoming_settled: HashSet<OrderId> = incoming.settled.iter().cloned().collect();
    // The FIRST sale held under each order, as `find` returned it.
    let mut sale_at: HashMap<OrderId, usize> = HashMap::new();
    for (i, s) in held.sales.iter().enumerate() {
        sale_at.entry(s.order.clone()).or_insert(i);
    }
    for sale in incoming.sales {
        if held_settled.contains(&sale.order) || incoming_settled.contains(&sale.order) {
            continue;
        }
        match sale_at.get(&sale.order) {
            Some(&i) => {
                let own = &mut held.sales[i];
                if own.decremented.is_none() {
                    own.decremented = sale.decremented;
                }
            }
            None => {
                sale_at.insert(sale.order.clone(), held.sales.len());
                held.sales.push(sale);
            }
        }
    }
    held.sales
        .retain(|s| !held_settled.contains(&s.order) && !incoming_settled.contains(&s.order));
    let mut settled = held_settled;
    for order in incoming.settled {
        if !settled.contains(&order) && held.settled.len() < ANSWERED_CAP {
            settled.insert(order.clone());
            held.settled.push_back(order);
        }
    }
    if held.sales.len() > SALES_CAP {
        // Keep the undecremented and the newest: a dropped sale is one whose
        // payment would never come off the stock. Dropped first: the
        // decremented, then the oldest.
        held.sales
            .sort_by_key(|s| (s.decremented.is_none(), s.issued_at_ms));
        let excess = held.sales.len() - SALES_CAP;
        held.sales.drain(..excess);
    }
    *held != before
}

/// The run of next addresses, from the counter, that I7 would accept now,
/// across both sources ([`WatchSet`]), and until when by this node's clock
/// the whole run stays usable (0 for an empty run).
///
/// A contiguous run, because I7 only ever invoices the NEXT address: a
/// watched address past an unwatched one cannot be reached until the
/// unwatched one is used, so counting it would show a store OPEN that answers
/// every Buy now with "no watched address" (review round 1 of
/// freenet/harvest#179). What a heartbeat's `taking_orders`, and the store
/// page, rest on.
///
/// Over the upcoming addresses, derived once per run, not once per store (all
/// stores share the payment key: `Delegations::upcoming`).
fn accepted_run_of(
    upcoming: &[harvest_common::DerivedAddress],
    record: &ArmRecord,
    watched: &WatchSet,
    now_ms: u64,
) -> (u32, u64) {
    let mut count = 0u32;
    let mut until = u64::MAX;
    for address in upcoming {
        let Some(this) = watched.usable_until_ms(&address.script_pubkey, record, now_ms) else {
            break;
        };
        count += 1;
        until = until.min(this);
    }
    (count, if count == 0 { 0 } else { until })
}

/// The addresses instant checkout would issue next, from the seller's
/// payment key, as `Delegations::upcoming` derives them.
#[cfg(test)]
pub(crate) fn upcoming<S: SecretStore>(secrets: &S) -> Vec<harvest_common::DerivedAddress> {
    crate::bitcoin::load_payment_xpub(secrets)
        .and_then(|status| {
            crate::bitcoin::upcoming_addresses(
                &status,
                harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES,
            )
            .ok()
        })
        .unwrap_or_default()
}

/// The payment scripts I7 accepts now, from its two sources.
///
/// - **The tab's** ([`AutoInvoiceArm::watched_scripts`]), while the watch the
///   tab had read still outlasts an invoice's window: by this node's clock
///   ([`ArmRecord::watched_until_ms`]), and by height when it named one.
/// - **The delegate's own** (`crate::watch_delegation`), each script while
///   the horizon its confirmed request asked for is at least
///   [`WATCH_NEEDED_BLOCKS`] past the tip, no probe has found it unscanned,
///   and its canary can still vouch for it (`watch_delegation::vouched`).
pub(crate) struct WatchSet {
    /// The arm's watch outlasts an invoice's window by the clock.
    arm_time_live: bool,
    /// ... and by height, when it names one and the tip is known.
    arm_live: bool,
    arm: Vec<Vec<u8>>,
    /// Each with the horizon asked.
    pub(crate) delegated: Vec<(Vec<u8>, u32)>,
    tip_height: Option<u32>,
}

impl WatchSet {
    fn accepts(&self, script: &[u8]) -> bool {
        (self.arm_live && self.arm.iter().any(|s| s == script))
            || self.delegated.iter().any(|(s, _)| s == script)
    }

    /// Until when, by this node's clock, an invoice on `script` may go out,
    /// or `None` if I7 refuses it now. A horizon is counted at the same
    /// pessimistic five minutes a block the tab counts one at.
    fn usable_until_ms(&self, script: &[u8], record: &ArmRecord, now_ms: u64) -> Option<u64> {
        let arm = (self.arm_live && self.arm.iter().any(|s| s == script))
            .then(|| record.watched_until_ms.saturating_sub(WATCH_NEEDED_MS));
        let delegated = self
            .delegated
            .iter()
            .filter(|(s, _)| s == script)
            .map(|(_, until)| {
                let tip = self.tip_height.unwrap_or(u32::MAX);
                now_ms.saturating_add(
                    u64::from(until.saturating_sub(tip.saturating_add(WATCH_NEEDED_BLOCKS)))
                        * 5
                        * 60
                        * 1000,
                )
            })
            .max();
        arm.max(delegated)
    }
}

pub(crate) fn watch_set<S: SecretStore>(
    secrets: &S,
    record: &ArmRecord,
    tip: Option<&TipCache>,
    now_ms: u64,
) -> WatchSet {
    watch_set_in(&Delegations::read(secrets), record, tip, now_ms)
}

/// [`watch_set`], with the delegations already read.
fn watch_set_in(
    delegations: &Delegations,
    record: &ArmRecord,
    tip: Option<&TipCache>,
    now_ms: u64,
) -> WatchSet {
    let arm = &record.arm;
    let vetted = record.vetted_recently(now_ms);
    let arm_time_live = vetted && now_ms.saturating_add(WATCH_NEEDED_MS) < record.watched_until_ms;
    let arm_height_live = match (arm.watched_until_height, tip) {
        (Some(until), Some(tip)) => tip.anchor.height.saturating_add(WATCH_NEEDED_BLOCKS) <= until,
        _ => true,
    };
    // The delegation renews, it does not extend (harvest#198): its watches
    // count only for a script the tab read clear and armed
    // (`vetted_scripts`), and only within `VETTED_FOR_MS` of that arm, so
    // nothing the delegate invoices on is an address nobody read recently;
    // with the tab closed the store stops at the end of that window
    // (`NoWatchedAddress`, and its heartbeat says so) rather than invoicing
    // addresses past it. A change of payment key empties the arms
    // (`forget_armed_scripts`).
    let delegated = tip.map_or_else(Vec::new, |tip| {
        delegations
            .watched(arm.network, &arm.trusted_bridges, tip.anchor.height)
            .into_iter()
            .filter(|(script, _)| vetted && arm.vetted_scripts.contains(script))
            .collect()
    });
    WatchSet {
        arm_time_live,
        arm_live: arm_time_live && arm_height_live,
        arm: arm.watched_scripts.clone(),
        delegated,
        tip_height: tip.map(|t| t.anchor.height),
    }
}

fn store_key<S: SecretStore>(secrets: &S, verifying: &[u8; 32]) -> Option<SigningKey> {
    VerifyingKey::from_bytes(verifying)
        .ok()
        .and_then(|vk| crate::store_keys::load(secrets, &vk))
}

/// Why a request was not answered with an invoice. A store-wide one leaves
/// the request unseen, to be decided again; a per-request one marks it seen
/// and, when it is about the buyer's request or a store limit, answers it
/// with a Decline naming why ([`Refusal::buyer_reason`]). (Not enough stock
/// is declined directly rather than refused.)
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
    /// The payment counter is still being raised past this store's published
    /// orders (`bitcoin::advance_scan`), over more runs than one.
    CatchingUp,
    /// The store's ledger is held but does not decode: nothing is invoiced
    /// rather than invoicing again what it records as answered.
    LedgerUnreadable,
    // Per request: the request is marked seen, and declined where
    // `buyer_reason` has words for it; the rest stay in the seller's inbox.
    NotInstant,
    /// Dated more than [`MAX_CLOCK_AHEAD_MS`] ahead of this node's clock.
    ClockAhead,
    AlreadyAnswered,
    NoBuyerKey,
    NoListing,
    Withdrawn,
    /// Enough is published, but not once unpaid instant invoices' holds are
    /// counted. Declined with "try again in about an hour": the holds end
    /// then, paid or not.
    Reserved,
    TotalMismatch,
    BindingElsewhere,
    StoreCap,
    DailyCap,
    TrailingUnpaid,
    Signing(String),
}

impl Refusal {
    /// What the buyer is told, in a sealed Decline, when this refusal is
    /// about their request or a store limit: every Buy now gets an answer,
    /// since a refused one is not retried and the seller is not asked to
    /// answer it by hand (review round 1 of harvest#177). `None` for a
    /// refusal that is not the buyer's to act on or not a Buy now at all
    /// (a quote request, an old client's, one already answered, or one that
    /// copies another conversation's binding).
    pub(crate) fn buyer_reason(&self) -> Option<&'static str> {
        match self {
            Refusal::Reserved => {
                Some("What is left is held for orders not yet paid. Try again in about an hour.")
            }
            Refusal::StoreCap | Refusal::DailyCap | Refusal::TrailingUnpaid => {
                Some("This store can't take more orders right now. Please try again later.")
            }
            Refusal::NoListing | Refusal::TotalMismatch => Some(
                "This listing has changed since you opened it. Reload the store to see it as \
                 it is now, then try again.",
            ),
            Refusal::Withdrawn => Some("This listing has been taken down."),
            Refusal::ClockAhead => Some(
                "Your computer's clock is ahead of the right time. Set it right, then try again.",
            ),
            _ => None,
        }
    }

    /// What a heartbeat tells buyers when this refusal stops the store
    /// taking orders (`harvest_common::presence::Heartbeat::reason`):
    /// coarse, since the buyer needs to know only whether to come back. The
    /// seller sees the detailed reason (`AutoInvoiceStatus::paused`).
    /// `Paused` is reserved for a whole-store pause, which nothing here
    /// gives yet.
    pub(crate) fn for_buyers(&self) -> harvest_common::presence::NotTakingReason {
        use harvest_common::presence::NotTakingReason as R;
        match self {
            Refusal::StoreClosed | Refusal::NotOurStore => R::ClosedForGood,
            Refusal::CatchingUp => R::CatchingUp,
            _ => R::Unavailable,
        }
    }

    /// A store limit the seller is told about (`AutoInvoiceStatus::capped`).
    fn is_store_cap(&self) -> bool {
        matches!(
            self,
            Refusal::StoreCap | Refusal::DailyCap | Refusal::TrailingUnpaid
        )
    }

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
                | Refusal::LedgerUnreadable
                | Refusal::CatchingUp
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
            Refusal::CatchingUp => {
                "the payment counter is still catching up with this store's published orders".into()
            }
            Refusal::LedgerUnreadable => {
                "this store's instant-checkout record could not be read".into()
            }
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
    let watched = watch_set(secrets, record, tip, now_ms);
    refusal_given(secrets, record, tip, &watched, now_ms)
}

/// [`global_refusal`], with the store's watch set already worked out.
fn refusal_given<S: SecretStore>(
    secrets: &S,
    record: &ArmRecord,
    tip: Option<&TipCache>,
    watched: &WatchSet,
    now_ms: u64,
) -> Result<BlockAnchor, Refusal> {
    let arm = &record.arm;
    // Lapsed only when neither source has anything: the delegate's own
    // watches keep a store taking orders after the tab's have lapsed. Not
    // judged without a tip, which the delegate's watches are measured
    // against: that is `NoFreshTip`, below.
    if !watched.arm_time_live && watched.delegated.is_empty() && tip.is_some() {
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
    // A watch that ends at a height (freenet-bitcoin#26) must outlast the
    // invoice's window in blocks too: the time above is the UI's estimate
    // of the same horizon, and blocks can come faster than it assumed.
    if !watched.arm_live && watched.delegated.is_empty() {
        return Err(Refusal::WatchLapsed);
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
    let names = |r: &&ArmRecord| {
        r.arm.tip_contract_id == *contract_id
            || r.arm.mailbox_contract_id == *contract_id
            || r.arm.store_contract_id.as_slice() == contract_id.as_slice()
    };
    if all.iter().any(|r| names(&r)) {
        // Evidence this node runs instant checkout in the background.
        save(secrets, RAN_KEY, &now_ms);
    }
    if let Some(record) = all.iter().find(|r| r.arm.tip_contract_id == *contract_id) {
        note_tip(secrets, record.arm.network, state);
        return Some(Vec::new());
    }
    if let Some(record) = all
        .iter()
        .find(|r| r.arm.presence_contract_id == Some(*contract_id))
    {
        // The subscription that keeps the presence contract here. Mostly
        // our own heartbeats coming back; nothing for a UI (a background run
        // has none).
        note_presence_seen(secrets, record, state);
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

/// What `decide` last fed of a store's published scripts
/// ([`feed_published`]): a digest of them and the published list's
/// generation after. Node-local, not exported.
pub(crate) fn fed_key(store_contract_id: &[u8]) -> Vec<u8> {
    format!(
        "{AUTO_PREFIX}fed:{}",
        bs58::encode(store_contract_id).into_string()
    )
    .into_bytes()
}

/// Add a store's published scripts to those the delegate holds
/// (`bitcoin::add_published`), unless exactly these were fed already and
/// the held list has not changed since (its generation, which rises with
/// every addition and so with every eviction). Then a run hashes the
/// scripts once, as one digest, rather than looking each up (#206).
fn feed_published<S: SecretStore>(
    secrets: &mut S,
    store_contract_id: &[u8],
    published: &[Vec<u8>],
) -> Result<(), String> {
    let mut hasher = blake3::Hasher::new();
    for script in published {
        hasher.update(&(script.len() as u32).to_le_bytes());
        hasher.update(script);
    }
    let digest = *hasher.finalize().as_bytes();
    let key = fed_key(store_contract_id);
    // The list's OWN generation, read from the list, not its separate count:
    // a count written while the list's write was refused names a
    // generation the list never had, and recorded as fed it would match a
    // later real one that evicted this store's scripts (#206 review).
    let marker = |secrets: &S| {
        crate::published_set::DigestList::load(secrets, crate::published_set::PUBLISHED_KEY)
            .map(|list| {
                let mut fed = digest.to_vec();
                fed.extend_from_slice(&list.generation().to_le_bytes());
                fed
            })
            .map_err(|_| crate::bitcoin::UNREADABLE_PUBLISHED.to_string())
    };
    if secrets.get_secret(&key).as_deref() == Some(&marker(secrets)?[..]) {
        return Ok(());
    }
    crate::bitcoin::add_published(secrets, published)?;
    let fed = marker(secrets)?;
    secrets.set_secret(&key, &fed);
    Ok(())
}

/// A store's state as instant checkout reads it: only what it uses
/// (`fast_cbor::decode_store_light`), or the whole state when that declines.
/// Decoding every order's payment proof was most of a run's cost at a few
/// thousand paid orders (#206).
fn read_store(state: &[u8]) -> Option<StoreStateV1> {
    crate::fast_cbor::decode_store_light(state).or_else(|| from_cbor(state).ok())
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
    let Some(store) = read_store(state) else {
        return Vec::new();
    };
    let read = store_refusal(&store, &store_sk.verifying_key());
    note_store_read(secrets, &record.arm.store_contract_id, read.as_ref());
    if read == Some(Refusal::NotOurStore) {
        return Vec::new();
    }
    note_paid_scripts(secrets, &store);
    let tip: Option<TipCache> = load(secrets, &tip_key(record.arm.network));
    let Some(mut ledger) = load_ledger_kept(secrets, &record.arm.store_contract_id) else {
        return Vec::new();
    };
    if ledger.sales.is_empty() && ledger.statuses.is_empty() && ledger.gap_orders.is_empty() {
        return Vec::new();
    }
    let statuses = settle(
        &mut ledger,
        &store,
        tip.map(|t| t.anchor.height),
        &store_sk,
        now_ms,
    );
    // Recorded before anything is published: a decrement sent but not
    // recorded would be sent again on the next change, twice off the stock.
    if !save_ledger(secrets, &record.arm.store_contract_id, &ledger) {
        return Vec::new();
    }
    Decided {
        statuses,
        owner: Some(store_sk.verifying_key()),
        ..Default::default()
    }
    .into_messages(&record.arm)
}

/// Settle the ledger's sales against the store, and return the statuses to
/// publish.
///
/// - A sale whose order is PAID comes off published stock once: a status
///   one revision above the one it is counted from, recorded as
///   `decremented` and in `ledger.statuses`.
/// - A status this delegate signed that the store does not show yet is
///   returned again (a lost update is re-sent on the next change), and one
///   the store shows, or has moved past, is forgotten.
/// - A sale is forgotten once its outcome cannot change any more: its
///   decrement landed, its payment was reversed, it never landed, or its
///   payment window closed. Until then a late payment still decrements.
pub(crate) fn settle(
    ledger: &mut Ledger,
    store: &StoreStateV1,
    tip_height: Option<u32>,
    store_sk: &SigningKey,
    now_ms: u64,
) -> Vec<AuthorizedListingStatus> {
    let held_revision = |listing: &ListingId| {
        store
            .listing_statuses
            .records
            .get(&harvest_common::store::Bytes32(listing.0))
            .map(|s| s.status.revision)
    };
    ledger
        .oversold
        .retain(|o| now_ms.saturating_sub(o.found_at_ms) < OVERSOLD_SHOWN_MS);
    // A payment to an address past the wallet's usual gap: the seller needs
    // to raise their wallet's gap limit to see it.
    let gap_paid = ledger
        .gap_orders
        .iter()
        .filter(|(id, _)| {
            store
                .orders
                .orders
                .get(id)
                .is_some_and(|o| o.status == OrderStatus::Paid)
        })
        .map(|(_, run)| *run)
        .max();
    if let Some(run) = gap_paid {
        let longest = ledger.gap_paid.map_or(run, |(_, held)| held.max(run));
        ledger.gap_paid = Some((now_ms, longest));
    }
    // Paid or reversed: nothing left to watch for. A cancelled one stays
    // (bounded by `GAP_ORDERS_CAP`): Paid outranks Cancelled, so it may yet
    // be paid.
    ledger.gap_orders.retain(|(id, _)| {
        store.orders.orders.get(id).is_none_or(|o| {
            matches!(
                o.status,
                OrderStatus::AwaitingPayment | OrderStatus::Cancelled
            )
        })
    });
    while ledger.oversold.len() > STATUSES_CAP {
        ledger.oversold.remove(0);
    }
    // Our own statuses the store now shows, or has moved past, are done.
    ledger
        .statuses
        .retain(|own| held_revision(&own.listing).is_none_or(|held| held < own.revision));

    let sales = std::mem::take(&mut ledger.sales);
    for mut sale in sales {
        let order = store.orders.orders.get(&sale.order);
        if let (Some(order), None) = (order, sale.decremented) {
            if order.status == OrderStatus::Paid {
                let (revision, availability) = effective_status(store, ledger, &sale.listing);
                // Paid when published stock could not cover it: its hold ended
                // (a cancel, or a buyer past the time to start paying) and the
                // unit went to someone else. Sold anyway; the seller is told.
                let covered = match &availability {
                    ListingAvailability::Available {
                        quantity: Some(left),
                    } => *left >= sale.quantity,
                    ListingAvailability::Available { quantity: None } => true,
                    ListingAvailability::SoldOut | ListingAvailability::Withdrawn => false,
                };
                if !covered && !ledger.oversold.iter().any(|o| o.order == sale.order) {
                    ledger.oversold.push(Oversold {
                        order: sale.order.clone(),
                        found_at_ms: now_ms,
                    });
                }
                sale.decremented = Some(match availability {
                    ListingAvailability::Available {
                        quantity: Some(left),
                    } => {
                        let status = ListingStatus {
                            listing: sale.listing.clone(),
                            revision: revision.saturating_add(1),
                            availability: match left.saturating_sub(sale.quantity) {
                                0 => ListingAvailability::SoldOut,
                                remaining => ListingAvailability::Available {
                                    quantity: Some(remaining),
                                },
                            },
                        };
                        let revision = status.revision;
                        ledger.signed(status);
                        revision
                    }
                    // Sold out, taken down or no longer counted: nothing to
                    // take off.
                    _ => 0,
                });
            }
        }
        let window_closed = tip_height.is_some_and(|tip| {
            tip.saturating_sub(sale.anchor_height) > harvest_common::payment::PAYMENT_WINDOW_BLOCKS
        });
        let done = match (order.map(|o| o.status), sale.decremented) {
            (_, Some(revision)) => {
                revision == 0 || held_revision(&sale.listing).is_some_and(|held| held >= revision)
            }
            (Some(OrderStatus::PaymentReversed), None) => true,
            (None, None) => now_ms.saturating_sub(sale.issued_at_ms) >= NOT_LANDED_MS,
            _ => window_closed,
        };
        if done {
            ledger.settle(sale.order);
        } else {
            ledger.sales.push(sale);
        }
    }

    // Every own status the store does not show yet goes out: the ones just
    // signed, and any whose earlier update was lost.
    ledger
        .statuses
        .iter()
        .filter(|own| held_revision(&own.listing).is_none_or(|held| held < own.revision))
        .filter_map(|own| sign_status(store_sk, own.clone()).ok())
        .collect()
}

/// A GET answer instant checkout asked for, if it is one: the tip read an
/// arm sends (harvest#162), which carries no context, or the store read a
/// mailbox run sends, which carries its batch. `None` for anything else.
pub(crate) fn on_get_answer<S: SecretStore>(
    secrets: &mut S,
    contract_id: &[u8; 32],
    state: Option<&[u8]>,
    context: &[u8],
    now_ms: u64,
) -> Option<Vec<OutboundDelegateMsg>> {
    if let Ok(retry) = from_cbor::<MailboxRetry>(context) {
        if retry.magic == RETRY_MAGIC {
            return Some(on_mailbox_retry(
                secrets,
                &retry.store_contract_id,
                state,
                now_ms,
            ));
        }
    }
    if context.is_empty() {
        if let Some(out) = on_tip_read(secrets, contract_id, state, now_ms) {
            return Some(out);
        }
        if let Some(record) = arms(secrets)
            .into_iter()
            .find(|r| r.arm.presence_contract_id == Some(*contract_id))
        {
            if let Some(state) = state {
                note_presence_seen(secrets, &record, state);
            }
            return Some(Vec::new());
        }
    }
    // The bridge inbox a wake-up read (`watch_delegation::on_wakeup`).
    if let Some(out) =
        crate::watch_delegation::on_inbox_read(secrets, contract_id, state, context, now_ms)
    {
        return Some(out);
    }
    on_store_state(secrets, state, context, now_ms)
}

/// The answer to the tip read an arm asks for, if `contract_id` is an armed
/// tip contract: kept like a notification's (newest block only), and each
/// arm naming it is told its status again, since the arm's own answer was
/// written before the read. A missing tip keeps nothing.
///
/// It is not a background run: the seller's own request caused it, and on a
/// hosted gateway it is answered in the seller's scope, where no background
/// run ever happens.
fn on_tip_read<S: SecretStore>(
    secrets: &mut S,
    contract_id: &[u8; 32],
    state: Option<&[u8]>,
    now_ms: u64,
) -> Option<Vec<OutboundDelegateMsg>> {
    let armed: Vec<ArmRecord> = arms(secrets)
        .into_iter()
        .filter(|r| r.arm.tip_contract_id == *contract_id)
        .collect();
    let first = armed.first()?;
    if let Some(state) = state {
        note_tip(secrets, first.arm.network, state);
    }
    let delegations = Delegations::read(secrets);
    Some(
        armed
            .iter()
            .filter_map(|record| {
                let status = HarvestDelegateResponse::AutoInvoice {
                    store_contract_id: record.arm.store_contract_id.clone(),
                    result: Ok(status_in(secrets, &delegations, record, now_ms)),
                };
                to_cbor(&status).ok().map(|bytes| {
                    OutboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(bytes))
                })
            })
            .collect(),
    )
}

fn note_tip<S: SecretStore>(secrets: &mut S, network: BitcoinNetwork, state: &[u8]) {
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
    // A copy that is behind never replaces a newer one (harvest#74).
    if held.is_some_and(|held| held.anchor.height > newest.anchor.height) {
        return;
    }
    save(
        secrets,
        &tip_key(network),
        &TipCache {
            anchor: newest.anchor,
            block_time: newest.block_time,
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
/// A sealed Decline answering the instant request in `message`, or `None`
/// when it does not open as one.
fn decline(
    store_sk: &SigningKey,
    message: &EncryptedMessage,
    reason: &str,
    now_ms: u64,
) -> Option<EncryptedMessage> {
    let (tag, from_seller, conversation_id, _) = open_instant(store_sk, message)?;
    harvest_common::sealed::seal(
        &from_seller,
        &tag,
        &conversation_id,
        MessageContent::Decline {
            reason: reason.to_string(),
        },
        chrono::DateTime::from_timestamp_millis(now_ms as i64).unwrap_or_default(),
    )
    .ok()
}

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
        // A twin of a buyer's tag opens with the buyer's own keys, so
        // whoever holds them could place a request under it: refused, as
        // `messaging::conversation_keys_from` refuses to derive its keys
        // (`messaging::is_canonical_tag`). Checked only for an instant
        // request that has opened, the one message this delegate acts on, so
        // the subgroup test's scalar multiplication is never paid for junk or
        // a chat message.
        MessageContent::OrderRequest {
            listing_id,
            quantity,
            order_binding,
            buyer_receipt_key,
            instant: Some(instant),
            ..
        } if crate::messaging::is_canonical_tag(&tag) => Some((
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

/// Whether a request made at `at_ms` (the buyer's clock) is within the day
/// `decide` answers.
fn within_request_age(at_ms: i64, now_ms: u64) -> bool {
    at_ms >= 0 && now_ms.abs_diff(at_ms as u64) <= REQUEST_MAX_AGE_MS
}

fn within_age(message: &EncryptedMessage, now_ms: u64) -> bool {
    let at = message.timestamp.timestamp_millis();
    at >= 0 && now_ms.abs_diff(at as u64) <= REQUEST_MAX_AGE_MS
}

/// How much opening one mailbox run may do, in bytes of ciphertext plus
/// [`OPEN_FIXED_COST`] per message (#206). Opening a message is an X25519
/// agreement, an AES-GCM pass over it and a decode of what it says; under
/// the node's fuel metering that is about 3.1 million units each plus about
/// 760 a byte for a text, and up to about 1,500 a byte for a plaintext built
/// to be slow to decode (a long list of one-byte integers), which anyone can
/// send. Sized so that a run over a mailbox at its byte cap of such messages
/// stays within half a call's budget (49%, `tests/delegate-budget`); a full
/// mailbox of short texts is about four runs, one at its byte cap about
/// seven.
pub(crate) const OPEN_BUDGET: usize = 851_968;

/// The X25519 agreement in [`OPEN_BUDGET`]'s units: about 4 KiB of AES-GCM.
pub(crate) const OPEN_FIXED_COST: usize = 4096;

/// Fresh randomness from the node, for [`open_within_budget`]'s order.
fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    // The source registered in `lib.rs` cannot fail. Were it to, the order
    // would be predictable, which is the starvation the random order is
    // there to prevent, though never a wrong answer.
    let _ = getrandom::getrandom(&mut seed);
    seed
}

/// One message a run opened: its digest, the message, and, when it is an
/// instant request this store can open, when the buyer says they asked.
type Opened<'a> = ([u8; 32], &'a EncryptedMessage, Option<i64>);

/// Open `candidates` in an order drawn from `seed` until [`OPEN_BUDGET`] is
/// spent, skipping any message that would not fit (so smaller ones behind it
/// still get their turn). Answers each opened message, with its digest and
/// whether it is an instant request this store can open, and whether any
/// candidate was left for the next run.
///
/// # Why a random order
///
/// Anyone can write to a store's mailbox, and opening is the expensive part,
/// so a bound on it is a bound an attacker can try to fill with junk ahead of
/// a real buyer's request. In any order the attacker can predict -- oldest
/// first, newest first, by digest -- they can place junk ahead of it, and with
/// a whole mailbox of junk per write a real request could wait as long as
/// they keep writing. Drawn from the node's randomness the order is one they
/// cannot see: each run opens every candidate with the same chance, about the
/// budget's share of what is waiting (about a seventh at the byte cap, more
/// for a buyer's short request, which also fits where a large message does
/// not). Junk opened once is never opened again (it is recorded as seen),
/// and so is an instant request outside the day `decide` answers, so the
/// backlog shrinks between the attacker's writes; the one exception is a
/// valid request held up by a condition of the whole store (no watched
/// address left, a counter not saved), which stays unseen and is opened again
/// each run until it clears, bounded like everything else. A real request is therefore
/// reached within a few runs whatever the attacker does, where before this
/// every run opened everything and a full mailbox could put the run past the
/// node's limit, which reached no one. The batch is then chosen in the same
/// order (`on_mailbox`), so an attacker's own valid requests, dated early,
/// cannot take its slots ahead of a buyer's either.
fn open_within_budget<'a>(
    store_sk: &SigningKey,
    mut candidates: Vec<([u8; 32], &'a EncryptedMessage)>,
    seed: [u8; 32],
) -> (Vec<Opened<'a>>, bool) {
    candidates.sort_by_cached_key(|(digest, _)| *blake3::keyed_hash(&seed, digest).as_bytes());
    let mut left = OPEN_BUDGET;
    let mut opened = Vec::new();
    let mut backlog = false;
    for (digest, message) in candidates {
        let cost = OPEN_FIXED_COST + message.ciphertext.len();
        if cost > left {
            backlog = true;
            continue;
        }
        left -= cost;
        let requested_at = open_instant(store_sk, message)
            .map(|(_, _, _, request)| request.instant.requested_at_ms);
        opened.push((digest, message, requested_at));
    }
    (opened, backlog)
}

fn on_mailbox<S: SecretStore>(
    secrets: &mut S,
    record: &ArmRecord,
    state: &[u8],
    now_ms: u64,
) -> Vec<OutboundDelegateMsg> {
    on_mailbox_ordered(secrets, record, state, now_ms, random_seed())
}

/// [`on_mailbox`], with the run's order drawn from `seed`.
fn on_mailbox_ordered<S: SecretStore>(
    secrets: &mut S,
    record: &ArmRecord,
    state: &[u8],
    now_ms: u64,
    seed: [u8; 32],
) -> Vec<OutboundDelegateMsg> {
    let tip: Option<TipCache> = load(secrets, &tip_key(record.arm.network));
    if global_refusal(secrets, record, tip.as_ref(), now_ms).is_err() {
        return Vec::new();
    }
    let Some(store_sk) = store_key(secrets, &record.arm.store_verifying_key) else {
        return Vec::new();
    };
    // Before the mailbox is decoded: a ledger that does not decode stops the
    // run (`load_ledger_kept`), and its flag is cleared so the wake-up does
    // not come back for it at every heartbeat; the status says why
    // (`Refusal::LedgerUnreadable`).
    let Some(mut ledger) = load_ledger_kept(secrets, &record.arm.store_contract_id) else {
        sync_retry_flag(secrets, &retry_key(&record.arm.store_contract_id), false);
        return Vec::new();
    };
    // The hand-written decoder first: same bytes, a fraction of the work
    // (`fast_cbor`); anything it does not recognise goes the generic way.
    let Some(mailbox) =
        crate::fast_cbor::decode_mailbox(state).or_else(|| from_cbor::<MailboxStateV1>(state).ok())
    else {
        return Vec::new();
    };
    let mut ledger_changed = false;
    // The messages not yet looked at, each digest computed once (a sort key
    // recomputed per comparison hashed every ciphertext about log2(n) times
    // over, #206).
    let candidates: Vec<([u8; 32], &EncryptedMessage)> = mailbox
        .messages
        .iter()
        .filter(|m| within_age(m, now_ms))
        .map(|m| (entry_digest(m), m))
        .filter(|(digest, _)| !ledger.seen.contains(digest))
        .collect();
    let (opened, mut backlog) = open_within_budget(&store_sk, candidates, seed);
    let mut batch: Vec<EncryptedMessage> = Vec::new();
    // What the context can carry, less room for its own framing.
    let budget = DelegateContext::MAX_SIZE - 1024;
    let mut used = 0usize;
    // In the order opened, which is the run's random order, NOT the order
    // the requests claim to have been made: a writer chooses the envelope
    // timestamp, so oldest-first would let a pile of their own valid
    // requests, dated early, take every slot ahead of a real buyer's.
    for (digest, message, requested_at) in &opened {
        match requested_at {
            // Not an instant request this store can open: a reply, a text, a
            // quote request, or junk. Looked at once.
            None => {
                ledger.saw(*digest);
                ledger_changed = true;
            }
            // Outside the day `decide` answers, it would refuse it unseen
            // forever: settled here, before it can hold a batch slot.
            Some(at) if !within_request_age(*at, now_ms) => {
                ledger.saw(*digest);
                ledger_changed = true;
            }
            Some(_) if batch.len() < MAX_BATCH => {
                let size = to_cbor(*message).map_or(usize::MAX, |b| b.len());
                if size > budget {
                    // Can never be carried; the seller answers it.
                    ledger.saw(*digest);
                    ledger_changed = true;
                } else if used + size <= budget {
                    used += size;
                    batch.push((*message).clone());
                } else {
                    backlog = true;
                }
            }
            // A request opened and left out of a full batch is still
            // waiting: the next run must come back for it.
            Some(_) => backlog = true,
        }
    }
    // The batch is decided oldest first (`decide` sorts it), as before this
    // module bounded its work.
    batch.sort_by_key(|m| (m.timestamp, entry_digest(m)));
    // What this run left -- unopened, or opened and not batched -- is looked
    // at by the next run: the next mailbox change, or the wake-up, which
    // re-reads a mailbox whose flag says so (`mailbox_retries`). So is a
    // batch until it is decided: the store GET it waits on can fail, and
    // only `on_store_state` knows it did not (`settle_batch_retry`). A run
    // that left nothing and sent nothing settles the flag here.
    let waiting = backlog || !batch.is_empty();
    if ledger.retry_pending != waiting {
        ledger.retry_pending = waiting;
        ledger_changed = true;
    }
    if ledger_changed {
        save_ledger(secrets, &record.arm.store_contract_id, &ledger);
    } else {
        // Nothing to write, but a flag left wrong by an earlier failure is
        // put right.
        sync_retry_flag(
            secrets,
            &retry_key(&record.arm.store_contract_id),
            ledger.retry_pending,
        );
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
        backlog,
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
    let Some(store) = state.and_then(read_store) else {
        return Some(Vec::new());
    };
    let decided = decide(secrets, &record, &store, &batch.entries, now_ms);
    settle_batch_retry(secrets, &batch, &decided);
    Some(decided.into_messages(&record.arm))
}

/// After a batch is decided: the retry flag its run set while it waited
/// (`on_mailbox_ordered`) is kept when anything still waits, that run's
/// backlog or an entry `decide` left undecided, and otherwise left for the
/// next mailbox run to settle, which reads the whole mailbox: this batch
/// cannot tell whether another (a refused UPDATE of an earlier one) set it
/// too. Cleared only when the store itself turns every request away for
/// good (closed, or not this seller's), which no wake-up can change; the
/// other whole-store refusals are the wake-up's to wait out
/// (`mailbox_retries`). A refused UPDATE sets it again
/// (`on_store_update_answer`).
fn settle_batch_retry<S: SecretStore>(secrets: &mut S, batch: &PendingBatch, decided: &Decided) {
    let id = &batch.store_contract_id;
    let for_good = decided
        .refused
        .iter()
        .any(|(_, why)| matches!(why, Refusal::NotOurStore | Refusal::StoreClosed));
    if for_good {
        let Some(mut ledger) = load_ledger_kept(secrets, id) else {
            return;
        };
        if ledger.retry_pending {
            ledger.retry_pending = false;
            save_ledger(secrets, id, &ledger);
        }
    } else if batch.backlog || decided.undecided {
        // The run that sent this batch set the ledger's flag; only the key
        // the wake-up reads may need writing again.
        sync_retry_flag(secrets, &retry_key(id), true);
    }
}

/// A store UPDATE this module sent has been applied or refused. `None` when
/// the context is not one of this module's.
/// [`on_store_updated`], and on a refused update, the requests it answered
/// made undecided again in the store's ledger.
pub(crate) fn on_store_update_answer<S: SecretStore>(
    secrets: &mut S,
    result: &Result<(), String>,
    context: &[u8],
) -> Option<Vec<OutboundDelegateMsg>> {
    if result.is_err() {
        if let Ok(pending) = from_cbor::<PendingReplies>(context) {
            if pending.magic == REPLIES_MAGIC
                && (!pending.retry.is_empty() || !pending.orders.is_empty())
            {
                if let Some(mut ledger) = load_ledger_kept(secrets, &pending.store_contract_id) {
                    ledger
                        .seen
                        .retain(|digest| !pending.retry.iter().any(|(d, _)| d == digest));
                    ledger
                        .answered
                        .retain(|request| !pending.retry.iter().any(|(_, r)| r == request));
                    // The sales stay: a refusal reported for an update that did
                    // land would otherwise lose the stock its order holds, and
                    // one that did not land is released after `NOT_LANDED_MS`
                    // anyway. A request made undecided here is answered at the
                    // store's next run, which the next mailbox change starts;
                    // `retry_pending` is what a run started some other way (the
                    // wake-up's `mailbox_retries`) looks at.
                    ledger.retry_pending = true;
                    save_ledger(secrets, &pending.store_contract_id, &ledger);
                }
            }
        }
    }
    on_store_updated(result, context)
}

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
    /// The replies that point a buyer at an order this run publishes: held
    /// back until the store takes the orders. Every other reply (a decline)
    /// goes to the mailbox at once, so a refused store update cannot drop a
    /// buyer's answer (review round 2 of harvest#177).
    pub held_back: Vec<EncryptedMessage>,
    /// Each invoiced request's entry digest and request id, to be decided
    /// again if the store refuses the update (`on_store_update_answer`).
    pub retry: Vec<([u8; 32], [u8; 32])>,
    /// The entry digests of the requests declined this run, to be decided
    /// again if the mailbox refuses the declines.
    pub declined: Vec<[u8; 32]>,
    /// Why each request not answered with an invoice was not, by entry
    /// digest. For tests and the log.
    pub refused: Vec<([u8; 32], Refusal)>,
    pub owner: Option<VerifyingKey>,
    /// Some of the entries were left undecided, unseen: the whole store
    /// turned away, a store-wide stop part way, or the ledger not saved.
    pub undecided: bool,
}

impl Decided {
    fn into_messages(self, arm: &AutoInvoiceArm) -> Vec<OutboundDelegateMsg> {
        let Ok(store_id) = <[u8; 32]>::try_from(arm.store_contract_id.as_slice()) else {
            return Vec::new();
        };
        let Some(owner) = self.owner else {
            return Vec::new();
        };
        let (held_back, now): (Vec<_>, Vec<_>) = self
            .replies
            .into_iter()
            .partition(|reply| self.held_back.contains(reply));
        // Declines: nothing for the store, straight to the mailbox, carrying
        // what to decide again if the mailbox refuses them.
        let mut out: Vec<OutboundDelegateMsg> = if now.is_empty() {
            Vec::new()
        } else {
            on_store_updated(
                &Ok(()),
                &to_cbor(&PendingReplies {
                    magic: REPLIES_MAGIC,
                    mailbox_contract_id: arm.mailbox_contract_id,
                    replies: now,
                    store_contract_id: Vec::new(),
                    retry: Vec::new(),
                    orders: Vec::new(),
                })
                .unwrap_or_default(),
            )
            .unwrap_or_default()
        };
        if let Ok(context) = to_cbor(&PendingReplies {
            magic: REPLIES_MAGIC,
            mailbox_contract_id: arm.mailbox_contract_id,
            replies: Vec::new(),
            store_contract_id: arm.store_contract_id.clone(),
            retry: self.declined.iter().map(|d| (*d, [0u8; 32])).collect(),
            orders: Vec::new(),
        }) {
            for message in &mut out {
                if let OutboundDelegateMsg::UpdateContractRequest(update) = message {
                    if context.len() < DelegateContext::MAX_SIZE {
                        update.context = DelegateContext::new(context.clone());
                    }
                }
            }
        }
        if self.orders.is_empty() && self.statuses.is_empty() {
            return out;
        }
        let order_ids: Vec<OrderId> = self.orders.iter().map(|o| o.order.id.clone()).collect();
        let Ok(delta) = to_cbor(&StoreStateV1Delta {
            owner: Some(owner),
            orders: (!self.orders.is_empty()).then_some(self.orders),
            listing_statuses: (!self.statuses.is_empty()).then_some(self.statuses),
            ..Default::default()
        }) else {
            return out;
        };
        let mut update = UpdateContractRequest::new(
            ContractInstanceId::new(store_id),
            UpdateData::Delta(StateDelta::from(delta)),
        );
        if let Ok(context) = to_cbor(&PendingReplies {
            magic: REPLIES_MAGIC,
            mailbox_contract_id: arm.mailbox_contract_id,
            replies: held_back,
            store_contract_id: arm.store_contract_id.clone(),
            retry: self.retry,
            orders: order_ids,
        }) {
            if context.len() < DelegateContext::MAX_SIZE {
                update.context = DelegateContext::new(context);
            }
        }
        out.push(OutboundDelegateMsg::UpdateContractRequest(update));
        out
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
        decided.undecided = !entries.is_empty();
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
    let read = store_refusal(store, &owner);
    note_store_read(secrets, &arm.store_contract_id, read.as_ref());
    if let Some(why) = read {
        refuse_all(&mut decided, why);
        return decided;
    }
    decided.owner = Some(owner);
    let Some(mut xpub) = crate::bitcoin::load_payment_xpub(secrets) else {
        refuse_all(&mut decided, Refusal::NoPaymentKey);
        return decided;
    };
    // This store's published scripts join those the delegate holds, and the
    // active key's scan moves on by a budget (harvest#77, #206). Until it is
    // complete nothing is invoiced: the requests wait (`CatchingUp`, store
    // wide, so the wake-up comes back for them), and the store is marked so
    // its status and heartbeat say why. The scan's progress is kept, so the
    // next run (and every wake-up) goes on from it.
    let published: Vec<Vec<u8>> = store
        .orders
        .orders
        .values()
        .map(|o| o.order.payment_script_pubkey.clone())
        .filter(|s| !s.is_empty())
        .collect();
    let scan = feed_published(secrets, &arm.store_contract_id, &published)
        .map_err(crate::bitcoin::ScanError::NotSaved)
        .and_then(|_| {
            crate::bitcoin::advance_scan(
                secrets,
                crate::bitcoin::Slot::Active,
                &mut xpub,
                crate::bitcoin::FLOOR_SCAN_BUDGET,
            )
        });
    match scan {
        Err(crate::bitcoin::ScanError::Key(_)) => {
            refuse_all(&mut decided, Refusal::NoPaymentKey);
            return decided;
        }
        // Said as it is: the status shows `CounterNotSaved`, not a catch-up
        // that would never move.
        Err(crate::bitcoin::ScanError::NotSaved(_)) => {
            mark_counter(
                secrets,
                &arm.store_contract_id,
                Some((now_ms, &xpub.xpub, true)),
            );
            refuse_all(&mut decided, Refusal::CounterNotSaved);
            return decided;
        }
        Ok(progress) if !progress.complete => {
            mark_counter(
                secrets,
                &arm.store_contract_id,
                Some((now_ms, &xpub.xpub, false)),
            );
            refuse_all(&mut decided, Refusal::CatchingUp);
            return decided;
        }
        Ok(_) => mark_counter(secrets, &arm.store_contract_id, None),
    }

    let Some(mut ledger) = load_ledger_kept(secrets, &arm.store_contract_id) else {
        refuse_all(&mut decided, Refusal::LedgerUnreadable);
        return decided;
    };
    decided.statuses = settle(&mut ledger, store, Some(anchor.height), &store_sk, now_ms);
    let mut issued_now: Vec<AuthorizedOrder> = Vec::new();
    // Counted once a run, not per request: up to MAX_ADDRESS_RUN
    // derivations each time. Every invoice this run adds one unpaid address
    // on top, and nothing else moves the counter.
    note_paid_scripts(secrets, store);
    let (gap_at_start, trailing_at_start) = {
        let orders: Vec<&AuthorizedOrder> = store.orders.orders.values().collect();
        let paid: Vec<Vec<u8>> = paid_scripts(secrets).into_iter().map(|(_, s)| s).collect();
        trailing_unpaid(&xpub, &orders, &paid, now_ms)
    };
    let tip_height = anchor.height;
    let watched = watch_set(secrets, record, tip.as_ref(), now_ms);

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
            &watched,
            &mut ledger,
            &issued_now,
            (
                gap_at_start.saturating_add(issued_now.len() as u32),
                trailing_at_start.saturating_add(issued_now.len() as u32),
            ),
            message,
            now_ms,
        );
        match outcome {
            Ok(Answer::Invoice { order, reply }) => {
                if let Some(request) = order.order.request_id {
                    decided.retry.push((digest, request));
                }
                issued_now.push((*order).clone());
                decided.orders.push(*order);
                decided.held_back.push(reply.clone());
                decided.replies.push(reply);
                ledger.saw(digest);
            }
            Ok(Answer::Decline(reply)) => {
                decided.replies.push(reply);
                decided.declined.push(digest);
                ledger.saw(digest);
            }
            Err(why) => {
                let store_wide = why.is_store_wide();
                if why.is_store_cap() {
                    ledger.capped = Some((now_ms, why.explain()));
                }
                // Answered, so the buyer is not left waiting on a request
                // that is never retried.
                if let Some(reply) = why
                    .buyer_reason()
                    .and_then(|reason| decline(&store_sk, message, reason, now_ms))
                {
                    decided.replies.push(reply);
                    decided.declined.push(digest);
                }
                decided.refused.push((digest, why));
                if store_wide {
                    // Everything after this waits too, unseen.
                    decided.undecided = true;
                    break;
                }
                ledger.saw(digest);
            }
        }
    }
    // Recorded before anything is published, as in `on_store_change`: an
    // order or decrement sent but not recorded would lose its hold, or be
    // decremented again.
    if !save_ledger(secrets, &arm.store_contract_id, &ledger) {
        return Decided {
            undecided: true,
            ..Decided::default()
        };
    }
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
    watched: &WatchSet,
    ledger: &mut Ledger,
    issued_now: &[AuthorizedOrder],
    (gap, trailing): (u32, u32),
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

    // The buyer's `requested_at` becomes the order's `created_at` and part
    // of its id; one far from this node's clock is left for the seller.
    let requested_at = chrono::DateTime::from_timestamp_millis(request.instant.requested_at_ms)
        .filter(|at| {
            at.timestamp_millis() >= 0
                && now_ms.abs_diff(at.timestamp_millis() as u64) <= REQUEST_MAX_AGE_MS
        })
        .ok_or(Refusal::NotInstant)?;
    // Dated ahead of this node's clock by more than a clock can drift: the
    // date becomes the order's, and the store's limits count an order's age
    // from it, so a buyer could keep one young for a day (codex on
    // harvest#177). Told, since it is theirs to fix.
    if requested_at.timestamp_millis() as u64 > now_ms.saturating_add(MAX_CLOCK_AHEAD_MS) {
        return Err(Refusal::ClockAhead);
    }

    // I1: one order per request, checked before anything is spent.
    let request_id = request_id(&tag, &request.instant.nonce);
    let order_id = OrderId::for_request(&request_id, &requested_at);
    // The ledger records a request as answered the moment its order is
    // built, so it covers a second entry for the same request later in this
    // run too.
    if ledger.answered.contains(&request_id) || store.orders.orders.contains_key(&order_id) {
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

    // Stock (I3). Published stock is what the seller has; the ledger's sales
    // are what unpaid instant invoices, this run's included, hold of it.
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
                .held(&listing.id, store, now_ms)
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
        // Declined in so many words rather than left unanswered: the buyer
        // can put this right themselves, by paying or cancelling one. Their
        // own app says the same before sending, so a genuine buyer normally
        // never gets here. Nothing is derived or spent before this point.
        return seal(MessageContent::Decline {
            reason: harvest_common::delegate::TOO_MANY_UNPAID.into(),
        })
        .map(Answer::Decline);
    }
    if ledger.issued_last_day(now_ms) >= MAX_PER_DAY {
        return Err(Refusal::DailyCap);
    }
    // A sale must be recordable, or the stock it takes would not be
    // counted: past this many kept at once, the seller answers.
    if left.is_some() && ledger.sales.len() >= SALES_CAP {
        return Err(Refusal::StoreCap);
    }
    if trailing >= MAX_TRAILING_UNPAID {
        return Err(Refusal::TrailingUnpaid);
    }

    // I7 then I2: the next address must be one the bridge was asked to
    // watch, by the tab or by this delegate ([`WatchSet`]); only then is it
    // spent, and the counter saved before anything names it.
    // Through the one way an address is handed out
    // (`bitcoin::issue_next_address`), which also refuses while the scan is
    // not complete.
    use crate::bitcoin::NotIssued;
    let derived =
        crate::bitcoin::issue_next_address(secrets, crate::bitcoin::FLOOR_SCAN_BUDGET, |derived| {
            watched.accepts(&derived.script_pubkey)
        })
        .map_err(|e| match e {
            NotIssued::NoKey => Refusal::NoPaymentKey,
            NotIssued::CatchingUp(_) => Refusal::CatchingUp,
            NotIssued::Declined | NotIssued::Failed(_) => Refusal::NoWatchedAddress,
            NotIssued::NotSaved(_) => Refusal::CounterNotSaved,
        })?;
    xpub.next_index = derived.index + 1;

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
        created_at: requested_at,
    }
    .with_derived_id();
    let signed = sign_order(store_sk, order)?;

    let reply = seal(MessageContent::OrderAccepted {
        order_id: signed.order.id.clone(),
    })?;
    if gap >= WALLET_GAP_LIMIT {
        ledger.gap_orders.push_back((signed.order.id.clone(), gap));
        while ledger.gap_orders.len() > GAP_ORDERS_CAP {
            ledger.gap_orders.pop_front();
        }
    }
    if left.is_some() {
        ledger.sales.push(Sale {
            order: signed.order.id.clone(),
            listing: listing.id.clone(),
            quantity: request.quantity,
            issued_at_ms: now_ms,
            anchor_height: anchor.height,
            decremented: None,
        });
    }
    ledger.answer(request_id, now_ms);
    Ok(Answer::Invoice {
        order: Box::new(signed),
        reply,
    })
}

/// The addresses just below the counter that carry no paid order, counting
/// down until one does: `(all, recent)`. `all` is the whole run, which is
/// what a wallet's gap limit is about: a wallet stops scanning after a run of
/// about 20 unused addresses, so a payment past such a run is invisible to
/// it. `recent` stops, in addition, at an address that is not one of this
/// store's orders from the last day: the store limit counts it, so the limit
/// turns buyers away for a day at most rather than for good, which unpaid
/// clicks alone would otherwise make permanent (review rounds 1 and 2 of
/// harvest#177).
///
/// Paid means paid at ANY store of this device: the payment key is shared
/// by every store (`paid_elsewhere`), so another store's paid address closes
/// the run as surely as this store's.
fn trailing_unpaid(
    xpub: &harvest_common::PaymentXpubStatus,
    orders: &[&AuthorizedOrder],
    paid_elsewhere: &[Vec<u8>],
    now_ms: u64,
) -> (u32, u32) {
    let Ok(chain) = crate::bip32::AccountXpub::parse(&xpub.xpub).and_then(|a| a.external_chain())
    else {
        return (MAX_ADDRESS_RUN, MAX_TRAILING_UNPAID);
    };
    // Built once: the walk looks each derived script up in them.
    let paid_set: std::collections::HashSet<&[u8]> = paid_elsewhere
        .iter()
        .map(Vec::as_slice)
        .chain(
            orders
                .iter()
                .filter(|o| o.status == OrderStatus::Paid)
                .map(|o| o.order.payment_script_pubkey.as_slice()),
        )
        .collect();
    let recent_set: std::collections::HashSet<&[u8]> = orders
        .iter()
        .filter(|o| {
            now_ms.saturating_sub(o.order.created_at.timestamp_millis().max(0) as u64) <= DAY_MS
        })
        .map(|o| o.order.payment_script_pubkey.as_slice())
        .collect();
    let paid = |script: &[u8]| paid_set.contains(script);
    // Only this store's own orders from the last day extend the limit's
    // run: an address with an older order, or none here (another store's,
    // or one spent and never published), ends it, so no other store's
    // clicks and nothing stranded can hold this one at its limit.
    let recent_here = |script: &[u8]| recent_set.contains(script);
    let (mut all, mut recent, mut recent_open) = (0, 0, true);
    let mut index = xpub.next_index;
    while index > 0 && all < MAX_ADDRESS_RUN {
        index -= 1;
        match chain.script_at(index) {
            Ok(script) if paid(&script) => break,
            Ok(script) => {
                all += 1;
                if recent_open && !recent_here(&script) {
                    recent_open = false;
                }
                if recent_open {
                    recent += 1;
                }
            }
            Err(_) => return (MAX_ADDRESS_RUN, MAX_TRAILING_UNPAID),
        }
    }
    (all, recent)
}

/// Every payment script this device has seen paid, at any of its stores,
/// newest last: [`trailing_unpaid`]'s `paid_elsewhere`. Not exported: a
/// successor relearns it from its stores.
pub(crate) const PAID_SCRIPTS_KEY: &[u8] = b"harvest:auto:paid";
const PAID_SCRIPTS_CAP: usize = 2048;

/// The paid scripts, each with its order's date: kept sorted by date, the
/// newest [`PAID_SCRIPTS_CAP`], so what the cap drops is the oldest payment
/// whichever store it was at.
fn paid_scripts<S: SecretStore>(secrets: &S) -> Vec<(i64, Vec<u8>)> {
    load(secrets, PAID_SCRIPTS_KEY).unwrap_or_default()
}

fn note_paid_scripts<S: SecretStore>(secrets: &mut S, store: &StoreStateV1) {
    let mut held = paid_scripts(secrets);
    let mut changed = false;
    // Looked up in a set: a scan of `held` per order, as `held` grows inside
    // the loop, was about n^2/2 comparisons (898M fuel at 4,096 paid orders,
    // measured by the #206 harness).
    let mut known: std::collections::HashSet<Vec<u8>> =
        held.iter().map(|(_, s)| s.clone()).collect();
    for order in store.orders.orders.values() {
        let script = &order.order.payment_script_pubkey;
        if order.status == OrderStatus::Paid && !script.is_empty() && known.insert(script.clone()) {
            held.push((order.order.created_at.timestamp_millis(), script.clone()));
            changed = true;
        }
    }
    if changed {
        held.sort();
        let excess = held.len().saturating_sub(PAID_SCRIPTS_CAP);
        // An old script dropped here and seen again later is added again
        // and dropped again: bounded churn, and never a newer one lost.
        held.drain(..excess);
        save(secrets, PAID_SCRIPTS_KEY, &held);
    }
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
                watched_until_height: None,
                presence_contract_id: Some([9; 32]),
                vetted_scripts: (0..5).map(script_at).collect(),
            },
            armed_at_ms: NOW - 1_000,
            watched_until_ms: NOW + WATCH_NEEDED_MS + 3_600_000,
            last_armed_ms: NOW - 1_000,
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
            self.request_dated(listing, quantity, nonce, total, at_ms, at_ms)
        }

        /// A request whose envelope says `sent_ms` and whose own date says
        /// `at_ms`: a writer chooses both.
        fn request_dated(
            &self,
            listing: &Listing,
            quantity: u32,
            nonce: u8,
            total: u64,
            at_ms: u64,
            sent_ms: u64,
        ) -> EncryptedMessage {
            self.request_under(&self.tag(), listing, quantity, nonce, total, at_ms, sent_ms)
        }

        /// [`Buyer::request_dated`], sent under `tag`, which need not be
        /// this buyer's own: a twin of it shares its keys.
        #[allow(clippy::too_many_arguments)]
        fn request_under(
            &self,
            tag: &[u8; 32],
            listing: &Listing,
            quantity: u32,
            nonce: u8,
            total: u64,
            at_ms: u64,
            sent_ms: u64,
        ) -> EncryptedMessage {
            harvest_common::sealed::seal(
                &self.keys().0,
                tag,
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
                        requested_at_ms: at_ms as i64,
                    }),
                },
                chrono::DateTime::from_timestamp_millis(sent_ms as i64).unwrap(),
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

    /// Unpaid orders of this store on the scripts at `indexes`, dated `at_ms`.
    fn unpaid_orders_on(f: &mut Fixture, indexes: std::ops::Range<u32>, at_ms: u64) {
        for i in indexes {
            let mut o = order_on(script_at(i));
            o.created_at = chrono::DateTime::from_timestamp_millis(at_ms as i64).unwrap();
            let o = sign_order(&store_sk(), o.with_derived_id()).unwrap();
            f.store.orders.orders.insert(o.order.id.clone(), o);
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

    /// `merge_ledgers` before #206, kept verbatim as the reference the set
    /// version must agree with.
    fn merge_ledgers_scanning(held: &mut Ledger, incoming: Ledger) -> bool {
        let before = held.clone();
        for digest in incoming.seen {
            held.saw(digest);
        }
        for request in incoming.answered {
            if !held.answered.contains(&request) {
                held.answered.push_back(request);
            }
        }
        while held.answered.len() > ANSWERED_CAP {
            held.answered.pop_front();
        }
        // A set: the same ledger merged twice adds nothing.
        for at in incoming.issued_at_ms {
            if !held.issued_at_ms.contains(&at) {
                held.issued_at_ms.push(at);
            }
        }
        held.issued_at_ms.sort_unstable();
        let excess = held.issued_at_ms.len().saturating_sub(2 * MAX_PER_DAY);
        held.issued_at_ms.drain(..excess);
        for gap in incoming.gap_orders {
            if !held.gap_orders.iter().any(|(id, _)| *id == gap.0) {
                held.gap_orders.push_back(gap);
            }
        }
        while held.gap_orders.len() > GAP_ORDERS_CAP {
            held.gap_orders.pop_front();
        }
        held.gap_paid = match (held.gap_paid, incoming.gap_paid) {
            (Some((at, run)), Some((other_at, other_run))) => {
                Some((at.max(other_at), run.max(other_run)))
            }
            (held, incoming) => held.or(incoming),
        };
        if incoming.capped.as_ref().map(|(at, _)| *at) > held.capped.as_ref().map(|(at, _)| *at) {
            held.capped = incoming.capped;
        }
        held.retry_pending |= incoming.retry_pending;
        for oversold in incoming.oversold {
            if !held.oversold.iter().any(|o| o.order == oversold.order) {
                held.oversold.push(oversold);
            }
        }
        while held.oversold.len() > STATUSES_CAP {
            held.oversold.remove(0);
        }
        for status in incoming.statuses {
            match held.statuses.iter().find(|s| s.listing == status.listing) {
                Some(own) if own.revision >= status.revision => {}
                _ => held.signed(status),
            }
        }
        // Sales first, skipping any either side has settled, and only then the
        // tombstones: merged first, the incoming ones could push this
        // delegate's own out of the capped list and let a settled sale back in.
        for sale in incoming.sales {
            if held.settled.contains(&sale.order) || incoming.settled.contains(&sale.order) {
                continue;
            }
            match held.sales.iter_mut().find(|s| s.order == sale.order) {
                Some(own) => {
                    if own.decremented.is_none() {
                        own.decremented = sale.decremented;
                    }
                }
                None => held.sales.push(sale),
            }
        }
        held.sales
            .retain(|s| !held.settled.contains(&s.order) && !incoming.settled.contains(&s.order));
        for order in incoming.settled {
            if !held.settled.contains(&order) && held.settled.len() < ANSWERED_CAP {
                held.settled.push_back(order);
            }
        }
        if held.sales.len() > SALES_CAP {
            // Keep the undecremented and the newest: a dropped sale is one whose
            // payment would never come off the stock. Dropped first: the
            // decremented, then the oldest.
            held.sales
                .sort_by_key(|s| (s.decremented.is_none(), s.issued_at_ms));
            let excess = held.sales.len() - SALES_CAP;
            held.sales.drain(..excess);
        }
        *held != before
    }

    /// #206: the set-based merge decides exactly what the scanning merge did,
    /// over ledgers that overlap, hold duplicates (a damaged ledger), sit at
    /// and past their caps, and settle each other's sales. Mutated red by
    /// dropping a settled check, by keeping the LAST held sale per order, and
    /// by forgetting a popped digest.
    #[test]
    fn merge_ledgers_is_the_scanning_merge() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = move |n: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % n
        };
        let mut id = |n: u64| {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&next(n).to_le_bytes());
            b
        };
        for round in 0..40 {
            let big = round % 4 == 0;
            let ledger = |id: &mut dyn FnMut(u64) -> [u8; 32]| {
                let space = if big { 3_000 } else { 40 };
                let count = |cap: usize| if big { cap + 20 } else { 30 };
                Ledger {
                    seen: (0..count(SEEN_CAP)).map(|_| id(space)).collect(),
                    answered: (0..count(ANSWERED_CAP)).map(|_| id(space)).collect(),
                    issued_at_ms: (0..30).map(|_| u64::from(id(500)[0])).collect(),
                    sales: (0..count(SALES_CAP))
                        .map(|_| {
                            let order = OrderId(id(space));
                            // Independent of the order, so two copies of one
                            // order can differ in it.
                            let decremented = (id(3)[0] == 0).then_some(u64::from(id(9)[0]));
                            Sale {
                                listing: ListingId(id(8)),
                                quantity: 1,
                                issued_at_ms: u64::from(id(1_000)[0]),
                                anchor_height: 1,
                                decremented,
                                order,
                            }
                        })
                        .collect(),
                    settled: (0..count(ANSWERED_CAP) / 3)
                        .map(|_| OrderId(id(space)))
                        .collect(),
                    gap_orders: (0..count(GAP_ORDERS_CAP))
                        .map(|_| (OrderId(id(space)), u32::from(id(50)[0])))
                        .collect(),
                    retry_pending: id(2)[0] == 1,
                    ..Default::default()
                }
            };
            let held = ledger(&mut id);
            let incoming = ledger(&mut id);
            let (mut fast, mut slow) = (held.clone(), held);
            let changed = merge_ledgers(&mut fast, incoming.clone());
            assert_eq!(
                changed,
                merge_ledgers_scanning(&mut slow, incoming),
                "round {round}"
            );
            assert_eq!(fast, slow, "round {round}");
        }
    }

    /// #206: what a status shows of a ledger, read field by field without
    /// decoding the rest, is what decoding the whole ledger shows: full and
    /// small ledgers, each of the four fields present or absent (an older
    /// ledger lacks some), statuses and long strings among the skipped
    /// fields; and so is its `retry_pending`, read the same way. Anything
    /// that is not a ledger map is declined and decoded whole. Mutated red
    /// by reading a field from the wrong slot.
    #[test]
    fn the_status_reads_a_ledger_as_the_whole_decode_does() {
        let full = |n: usize| Ledger {
            seen: (0..n).map(|i| [i as u8; 32]).collect(),
            answered: (0..n).map(|i| [i as u8 ^ 0x55; 32]).collect(),
            issued_at_ms: (0..n as u64).map(|i| NOW - i * 1_000).collect(),
            statuses: vec![ListingStatus {
                listing: ListingId([3; 32]),
                revision: 4,
                availability: ListingAvailability::default(),
            }],
            sales: Vec::new(),
            settled: (0..n).map(|i| OrderId([i as u8; 32])).collect(),
            oversold: (0..n.min(8))
                .map(|i| Oversold {
                    order: OrderId([i as u8 + 1; 32]),
                    found_at_ms: NOW - i as u64,
                })
                .collect(),
            gap_orders: (0..n).map(|i| (OrderId([7; 32]), i as u32)).collect(),
            gap_paid: Some((NOW - 5, 140)),
            capped: Some((NOW - 9, "x".repeat(300))),
            retry_pending: true,
        };
        let mut quiet = full(3);
        quiet.retry_pending = false;
        for ledger in [Ledger::default(), full(3), quiet, full(SEEN_CAP)] {
            let bytes = to_cbor(&ledger).unwrap();
            // And the wake-up's read of a flag gone missing.
            let mut secrets = MemSecrets::default();
            secrets.set_secret(&ledger_key(&[1; 32]), &bytes);
            assert_eq!(
                ledger_retry_pending(&secrets, &[1; 32]),
                ledger.retry_pending
            );
            assert_eq!(
                ledger_shown(&bytes),
                Some(LedgerShown::of(ledger.clone())),
                "{} seen",
                ledger.seen.len()
            );
        }
        // An older ledger, without the later fields: as serde defaults them.
        let mut value = ciborium::Value::serialized(&full(3)).unwrap();
        let ciborium::Value::Map(fields) = &mut value else {
            panic!()
        };
        fields.retain(|(k, _)| {
            !matches!(k, ciborium::Value::Text(t) if t == "oversold" || t == "gap_paid" || t == "capped")
        });
        let mut older = Vec::new();
        ciborium::into_writer(&value, &mut older).unwrap();
        assert_eq!(
            ledger_shown(&older),
            Some(LedgerShown::of(from_cbor::<Ledger>(&older).unwrap()))
        );
        // A ledger lacking a field every ledger has: declined.
        let mut value = ciborium::Value::serialized(&full(3)).unwrap();
        let ciborium::Value::Map(fields) = &mut value else {
            panic!()
        };
        fields.retain(|(k, _)| !matches!(k, ciborium::Value::Text(t) if t == "seen"));
        let mut lacking = Vec::new();
        ciborium::into_writer(&value, &mut lacking).unwrap();
        assert_eq!(ledger_shown(&lacking), None, "no seen");
        // Not a ledger map: declined, and the load falls back.
        assert_eq!(ledger_shown(b"\x80"), None);
        let mut secrets = MemSecrets::default();
        let mut indefinite = to_cbor(&full(3)).unwrap();
        indefinite[0] = 0xbf;
        indefinite.push(0xff);
        assert_eq!(ledger_shown(&indefinite), None);
        secrets.set_secret(&ledger_key(&[1; 32]), &indefinite);
        assert_eq!(
            load_ledger_shown(&secrets, &[1; 32]).unwrap(),
            LedgerShown::of(from_cbor::<Ledger>(&indefinite).unwrap())
        );
    }

    /// A text from the `i`th buyer, `len` characters long: what instant
    /// checkout opens and then never again.
    fn junk(i: usize, len: usize) -> EncryptedMessage {
        let mut seed = [0x77u8; 32];
        seed[1..9].copy_from_slice(&(i as u64).to_le_bytes());
        let secret = StaticSecret::from(seed);
        let tag = *PublicKey::from(&secret).as_bytes();
        let inbox = PublicKey::from(&harvest_common::custody::inbox_secret(&store_sk()));
        let key = conversation_key_from_dh(
            &secret.diffie_hellman(&inbox).to_bytes(),
            MessageDirection::BuyerToSeller,
        );
        harvest_common::sealed::seal(
            &key,
            &tag,
            &ConversationId([i as u8; 32]),
            MessageContent::Text("x".repeat(len)),
            chrono::DateTime::from_timestamp_millis((NOW - 60_000 - i as u64) as i64).unwrap(),
        )
        .unwrap()
    }

    fn seen(f: &Fixture) -> usize {
        load_ledger(&f.secrets, &f.record.arm.store_contract_id)
            .seen
            .len()
    }

    /// #206: one run opens no more than [`OPEN_BUDGET`] allows; what is left
    /// is flagged for the next run (the flag beside the ledger, which the
    /// wake-up's `mailbox_retries` turns into a re-read), and the runs drain
    /// it. The flag clears with the run that finishes. Mutated red by
    /// dropping the budget, by not flagging the backlog, and by not clearing
    /// the flag.
    #[test]
    fn opening_is_bounded_and_the_rest_waits_for_the_next_run() {
        let mut f = fixture();
        let messages: Vec<EncryptedMessage> = (0..400).map(|i| junk(i, 600)).collect();
        let per_message = OPEN_FIXED_COST + messages[0].ciphertext.len();
        let state = to_cbor(&MailboxStateV1 { messages }).unwrap();
        let mut runs = 0;
        let mut before = 0;
        loop {
            runs += 1;
            on_mailbox(&mut f.secrets, &f.record.clone(), &state, NOW);
            let now_seen = seen(&f);
            assert!(
                now_seen - before <= OPEN_BUDGET / per_message,
                "run {runs} over budget"
            );
            before = now_seen;
            let pending = load_ledger(&f.secrets, &f.record.arm.store_contract_id).retry_pending;
            assert_eq!(
                f.secrets
                    .get_secret(&retry_key(&f.record.arm.store_contract_id))
                    .as_deref()
                    == Some(b"1".as_slice()),
                pending,
                "the flag beside the ledger says what the ledger says"
            );
            assert_eq!(mailbox_retries(&f.secrets, NOW).len(), usize::from(pending));
            if !pending {
                break;
            }
            assert!(runs < 10, "no progress");
        }
        assert!(runs > 1, "400 messages did not fit one run's budget");
        assert_eq!(seen(&f), 400);
    }

    /// #206: a buyer's request behind a mailbox of junk is reached within a
    /// few runs, whichever order the junk is in, because the order of opening
    /// comes from the node's randomness and never from anything the writer
    /// chooses. Here the junk is all OLDER than the request (first in the old
    /// oldest-first order), the same size as it (so no gap in the budget lets
    /// it slip in), and a full mailbox of it, about 2.7 times what one run
    /// opens. Across 64 seeds the request is opened in the first run about a
    /// third of the time (at least 4 is asserted: the digests carry a random
    /// nonce, and fewer comes about once in a billion runs) and always by the
    /// time the junk is drained; oldest first would never open it in the
    /// first run. Mutated red by opening oldest first.
    #[test]
    fn a_request_behind_junk_is_reached_whatever_the_junk_order() {
        let buyer = Buyer::new(40);
        let request = buyer.request(&jam(), 1, 1, 12_000);
        let size = request.ciphertext.len();
        let junk: Vec<EncryptedMessage> = (0..511)
            .map(|i| junk(i, 1))
            .map(|mut m| {
                // The same cost as the request: only the order decides.
                m.ciphertext.resize(size, 0);
                m
            })
            .collect();
        let total: usize = junk
            .iter()
            .map(|m| OPEN_FIXED_COST + m.ciphertext.len())
            .sum();
        let drained_by = total.div_ceil(OPEN_BUDGET - OPEN_FIXED_COST - size) + 1;
        let mut first_run = 0;
        for seed in 0..64u8 {
            let mut waiting: Vec<&EncryptedMessage> = junk.iter().collect();
            waiting.push(&request);
            let mut runs = 0;
            loop {
                runs += 1;
                let candidates = waiting.iter().map(|m| (entry_digest(m), *m)).collect();
                let (opened, _) =
                    open_within_budget(&store_sk(), candidates, [seed.wrapping_add(runs); 32]);
                if opened.iter().any(|(_, _, at)| at.is_some()) {
                    break;
                }
                let done: Vec<[u8; 32]> = opened.iter().map(|(d, _, _)| *d).collect();
                waiting.retain(|m| !done.contains(&entry_digest(m)));
                assert!(
                    runs <= drained_by as u8,
                    "seed {seed}: not reached in {runs} runs"
                );
            }
            if runs == 1 {
                first_run += 1;
            }
        }
        assert!(
            first_run >= 4,
            "reached in the first run for only {first_run} of 64 seeds"
        );
    }

    /// #206: whether a store takes orders, as the wake-up's heartbeat asks
    /// it, is what the full status says, without reading the ledger. Checked
    /// taking, with the watch lapsed, with no payment key, and with no tip.
    /// Mutated red by ignoring the refusal, or the remaining run.
    #[test]
    fn taking_orders_is_what_the_status_says() {
        let agree = |f: &Fixture| {
            let status = status_of(&f.secrets, &f.record, NOW);
            assert_eq!(
                taking_orders(&f.secrets, &f.record, NOW, &upcoming(&f.secrets)),
                status.paused.is_none() && status.watched_remaining > 0,
                "{status:?}"
            );
        };
        let f = fixture();
        agree(&f);
        let mut lapsed = fixture();
        lapsed.record.watched_until_ms = NOW;
        agree(&lapsed);
        // No payment key and no tip: only the store key is held.
        let mut bare = fixture();
        bare.secrets = MemSecrets::default();
        crate::store_keys::keep(&mut bare.secrets, &store_sk());
        agree(&bare);
        let mut no_watch = fixture();
        no_watch.record.arm.watched_scripts.clear();
        agree(&no_watch);
        // Refused (a stale tip) while addresses are still watched: only the
        // refusal says no.
        let mut stale = fixture();
        save(
            &mut stale.secrets,
            &tip_key(BitcoinNetwork::Signet),
            &TipCache {
                anchor: BlockAnchor {
                    height: 1_000,
                    hash: freenet_bitcoin_common::BlockHash([7; 32]),
                },
                block_time: ((NOW - TIP_MAX_AGE_MS) / 1000) as u32 - 600,
            },
        );
        assert!(!taking_orders(
            &stale.secrets,
            &stale.record,
            NOW,
            &upcoming(&stale.secrets)
        ));
        agree(&stale);
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
        // Nothing issued; the counter is past the order published elsewhere
        // (its scan keeps what it raised, #206).
        assert_eq!(counter(&g), 1);
    }

    /// I1, the ledger alone: a resend before the first answer has reached the
    /// store, and one nonce twice in one run. Mutated red by dropping
    /// `ledger.answered.contains`, which covers both.
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

    /// A request dated more than a day from this node's clock is left for
    /// the seller: its date becomes the order's, and part of its id. Mutated
    /// red by dropping the bound.
    #[test]
    fn a_request_dated_far_from_now_is_left_for_the_seller() {
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let mut stale = buyer.request(&jam(), 1, 1, 12_000);
        // Re-seal with an envelope time of now but a requested_at two days
        // back.
        let (to_seller, _) = buyer.keys();
        let mut plaintext = decrypt_message(&stale, &to_seller).unwrap();
        if let MessageContent::OrderRequest {
            instant: Some(selection),
            ..
        } = &mut plaintext.content
        {
            selection.requested_at_ms = (NOW - 2 * DAY_MS) as i64;
        }
        stale = harvest_common::sealed::seal(
            &to_seller,
            &buyer.tag(),
            &buyer.conversation,
            plaintext.content,
            chrono::DateTime::from_timestamp_millis((NOW - 1_000) as i64).unwrap(),
        )
        .unwrap();
        let decided = run(&mut f, &[stale]);
        assert!(decided.orders.is_empty());
        assert_eq!(decided.refused[0].1, Refusal::NotInstant);
        assert_eq!(counter(&f), 0);

        // And two days ahead, which would otherwise rank the order newest of
        // all under the store's cap.
        let mut ahead = decrypt_message(
            &buyer.request_at(&jam(), 1, 2, 12_000, NOW - 1_000),
            &to_seller,
        )
        .unwrap();
        if let MessageContent::OrderRequest {
            instant: Some(selection),
            ..
        } = &mut ahead.content
        {
            selection.requested_at_ms = (NOW + 2 * DAY_MS) as i64;
        }
        let ahead = harvest_common::sealed::seal(
            &to_seller,
            &buyer.tag(),
            &buyer.conversation,
            ahead.content,
            chrono::DateTime::from_timestamp_millis((NOW - 1_000) as i64).unwrap(),
        )
        .unwrap();
        let decided = run(&mut f, &[ahead]);
        assert_eq!(decided.refused[0].1, Refusal::NotInstant);
        assert_eq!(counter(&f), 0);
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
    /// another network is ignored, and every notification counts as a
    /// background run.
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
        assert_eq!(
            load::<_, u64>(&f.secrets, RAN_KEY),
            Some(NOW + 5),
            "but it is a background run"
        );
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
                        requested_at_ms: (NOW - 60_000) as i64,
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
    /// Mutated red by removing the `add_published` call.
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

    /// harvest#183, the delegate's half. A counter lost at 0, with the arm
    /// still naming addresses 0 to 4 and nothing on this store naming 0 to
    /// 2 (they were paid through another store): the tab finds 0 to 2 paid
    /// in their address contracts and asks for one address with them as
    /// published (the raise, which names no key). That hands back index 3,
    /// which the tab drops, and the next instant invoice goes on index 4,
    /// not 0. Mutated red by dropping the floor from `DeriveOrderAddress`.
    #[test]
    fn a_raise_with_paid_addresses_moves_instant_checkout_past_them() {
        let mut f = fixture();
        assert_eq!(counter(&f), 0);
        let answer = crate::bitcoin::handle(
            &mut f.secrets,
            Some(&crate::origin::test_origins::harvest()),
            harvest_common::BitcoinDelegateRequest::DeriveOrderAddress {
                request_id: 1,
                published_scripts: (0..3).map(script_at).collect(),
            },
        )
        .expect("authorized");
        assert!(matches!(
            answer,
            harvest_common::BitcoinDelegateResponse::OrderAddress { result: Ok(ref d), .. }
                if d.index == 3
        ));
        let decided = run(&mut f, &[Buyer::new(40).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(decided.refused, vec![]);
        assert_eq!(decided.orders[0].order.payment_script_pubkey, script_at(4));
        assert_eq!(counter(&f), 5);
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

    /// S2. Two requests for the last item in one run: one invoice, and the
    /// other declined for now (the first may never be paid), with
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
        // Told, rather than left waiting on a request nothing retries
        // (review round 1 of harvest#177): the unit may free up within the
        // hour, and the buyer is told to come back then.
        assert_eq!(
            b.read(&decided.replies),
            vec![MessageContent::Decline {
                reason: Refusal::Reserved.buyer_reason().unwrap().into()
            }]
        );
        assert!(
            a.read(&decided.replies).len() == 1,
            "A's own acceptance only"
        );
        assert_eq!(counter(&f), 1);

        // And in a later run that reads the same store.
        let later = run(&mut f, &[Buyer::new(42).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(later.refused[0].1, Refusal::Reserved);
        assert_eq!(counter(&f), 1);
    }

    /// A decline goes to the mailbox at once; only the acceptance waits on
    /// the store taking its order, so a refused store update drops no
    /// buyer's decline (review round 2 of harvest#177). Mutated red by
    /// holding every reply back again.
    #[test]
    fn a_decline_does_not_wait_on_the_store_update() {
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
        let out = decided.into_messages(&f.record.arm);
        let mut mailbox = Vec::new();
        let mut held = Vec::new();
        for m in &out {
            let OutboundDelegateMsg::UpdateContractRequest(update) = m else {
                panic!("{m:?}")
            };
            if update.contract_id.as_bytes() == f.record.arm.mailbox_contract_id.as_slice() {
                let UpdateData::Delta(delta) = &update.update else {
                    panic!("a delta")
                };
                let delta: harvest_common::mailbox::MailboxDelta =
                    from_cbor(delta.as_ref()).unwrap();
                mailbox.extend(delta);
            } else {
                let pending: PendingReplies = from_cbor(update.context.as_ref()).unwrap();
                held.extend(pending.replies);
            }
        }
        assert_eq!(b.read(&mailbox).len(), 1, "B's decline, at once");
        assert!(a.read(&mailbox).is_empty());
        assert_eq!(a.read(&held).len(), 1, "A's acceptance, after the store");
        assert!(b.read(&held).is_empty());
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
    /// move, and an hour after each unpaid invoice went out its stock is
    /// offered again, though the invoice is still payable. Mutated red by
    /// holding for the whole payment window (the old rule) and by dropping
    /// the hold altogether.
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
        // The seller's tab keeps the watch renewed meanwhile.
        f.record.watched_until_ms += HOLD_MS;
        // Just short of the hour, still held.
        let still = decide(
            &mut f.secrets,
            &f.record,
            &f.store,
            &[Buyer::new(51).request(&jam(), 1, 1, 12_000)],
            NOW + HOLD_MS - 1,
        );
        assert_eq!(still.refused[0].1, Refusal::Reserved);
        // An hour on, with the chain where it was: the invoices are still
        // payable, and their stock is offered again.
        let again = decide(
            &mut f.secrets,
            &f.record,
            &f.store,
            &[Buyer::new(52).request(&jam(), 1, 1, 12_000)],
            NOW + HOLD_MS,
        );
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
        // Taken off once: the same state again (the update not landed yet)
        // sends the same status, not a second decrement.
        let again = on_notification(&mut f.secrets, &[1; 32], &state, NOW).unwrap();
        let [OutboundDelegateMsg::UpdateContractRequest(update)] = again.as_slice() else {
            panic!("{again:?}")
        };
        let UpdateData::Delta(delta) = &update.update else {
            panic!("a delta")
        };
        let delta: StoreStateV1Delta = from_cbor(delta.as_ref()).unwrap();
        assert_eq!(delta.listing_statuses.unwrap(), statuses);
    }

    /// The store as the delegate would see it after a store change, with
    /// one order's status set.
    fn with_status(f: &mut Fixture, id: &OrderId, status: OrderStatus) {
        f.store.orders.orders.get_mut(id).expect("published").status = status;
    }

    fn store_change(f: &mut Fixture) -> Vec<AuthorizedListingStatus> {
        store_change_at(f, NOW)
    }

    fn store_change_at(f: &mut Fixture, now_ms: u64) -> Vec<AuthorizedListingStatus> {
        let state = to_cbor(&f.store).unwrap();
        let out = on_notification(&mut f.secrets, &[1; 32], &state, now_ms).unwrap();
        out.iter()
            .flat_map(|m| match m {
                OutboundDelegateMsg::UpdateContractRequest(update) => {
                    let UpdateData::Delta(delta) = &update.update else {
                        panic!("a delta")
                    };
                    let delta: StoreStateV1Delta = from_cbor(delta.as_ref()).unwrap();
                    delta.listing_statuses.unwrap_or_default()
                }
                other => panic!("{other:?}"),
            })
            .collect()
    }

    /// S1: a payment that confirms after the hold ended, or after the buyer
    /// cancelled (Paid outranks Cancelled), still comes off the stock, once.
    /// Mutated red by forgetting a sale when its hold ends.
    #[test]
    fn a_late_or_post_cancel_payment_still_comes_off_the_stock() {
        for late in [OrderStatus::AwaitingPayment, OrderStatus::Cancelled] {
            let mut f = fixture();
            counted(&mut f, 1);
            let first = run(&mut f, &[Buyer::new(40).request(&jam(), 1, 1, 12_000)]);
            publish(&mut f, &first);
            let id = first.orders[0].order.id.clone();
            with_status(&mut f, &id, late);
            let after_hold = NOW + HOLD_MS + 1;
            assert!(
                store_change_at(&mut f, after_hold).is_empty(),
                "nothing paid yet"
            );
            with_status(&mut f, &id, OrderStatus::Paid);
            let statuses = store_change_at(&mut f, after_hold);
            assert_eq!(statuses.len(), 1, "{late:?}");
            assert_eq!(
                statuses[0].status.availability,
                ListingAvailability::SoldOut
            );
            assert_eq!(statuses[0].status.revision, 6, "one above the store's");
        }
    }

    /// A decrement whose update was lost goes out again on the next change,
    /// and stops once the store shows it. Mutated red by returning only the
    /// statuses signed in this call.
    #[test]
    fn a_lost_decrement_is_sent_again() {
        let mut f = fixture();
        counted(&mut f, 3);
        let first = run(&mut f, &[Buyer::new(40).request(&jam(), 1, 1, 12_000)]);
        publish(&mut f, &first);
        with_status(&mut f, &first.orders[0].order.id, OrderStatus::Paid);
        let sent = store_change(&mut f);
        assert_eq!(sent.len(), 1);
        // Lost: the store still shows the old count.
        let again = store_change(&mut f);
        assert_eq!(again, sent);
        // Landed.
        f.store
            .listing_statuses
            .records
            .insert(harvest_common::store::Bytes32(jam().id.0), sent[0].clone());
        assert!(store_change(&mut f).is_empty());
        assert!(load_ledger(&f.secrets, &f.record.arm.store_contract_id)
            .sales
            .is_empty());
    }

    /// A migration keeps every sale: the predecessor's ledger is folded
    /// into the successor's by order id. Mutated red by dropping incoming
    /// sales in `merge_ledgers`.
    #[test]
    fn a_migrated_ledger_keeps_its_sales() {
        let sale = |n: u8, decremented| Sale {
            order: OrderId([n; 32]),
            listing: jam().id,
            quantity: 1,
            issued_at_ms: NOW,
            anchor_height: 1_000,
            decremented,
        };
        let mut held = Ledger {
            sales: vec![sale(1, None)],
            ..Default::default()
        };
        let incoming = Ledger {
            sales: vec![sale(1, Some(9)), sale(2, None), sale(3, None)],
            answered: [[5; 32]].into(),
            issued_at_ms: vec![NOW - 5, NOW - 4],
            seen: [[6; 32]].into(),
            statuses: vec![ListingStatus {
                listing: jam().id,
                revision: 7,
                availability: ListingAvailability::SoldOut,
            }],
            settled: [OrderId([3; 32])].into(),
            oversold: vec![Oversold {
                order: OrderId([4; 32]),
                found_at_ms: NOW,
            }],
            gap_orders: [(OrderId([8; 32]), 25)].into(),
            gap_paid: Some((NOW - 1, 150)),
            capped: Some((NOW - 2, "a limit".into())),
            retry_pending: false,
        };
        assert!(merge_ledgers(&mut held, incoming.clone()));
        assert!(held.gap_orders.contains(&(OrderId([8; 32]), 25)));
        assert_eq!(held.gap_paid, Some((NOW - 1, 150)));
        assert_eq!(held.capped, Some((NOW - 2, "a limit".into())));
        assert_eq!(
            held.sales,
            vec![sale(1, Some(9)), sale(2, None)],
            "a sale the predecessor had settled does not come back"
        );
        assert!(held.answered.contains(&[5; 32]));
        // Idempotent with every field populated: the same ledger twice adds
        // nothing, and the daily count is not doubled.
        assert!(
            !merge_ledgers(&mut held, incoming),
            "nothing new the second time"
        );
        assert_eq!(held.issued_at_ms, vec![NOW - 5, NOW - 4]);
        assert_eq!(held.gap_orders.len(), 1);
    }

    /// A sale this delegate settled and forgot stays forgotten when the
    /// predecessor's frozen ledger is merged again. Mutated red by not
    /// skipping settled orders in `merge_ledgers`.
    #[test]
    fn a_settled_sale_is_not_revived_by_a_re_import() {
        let mut f = fixture();
        counted(&mut f, 3);
        let first = run(&mut f, &[Buyer::new(40).request(&jam(), 1, 1, 12_000)]);
        publish(&mut f, &first);
        let frozen = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        with_status(&mut f, &first.orders[0].order.id, OrderStatus::Paid);
        let sent = store_change(&mut f);
        f.store
            .listing_statuses
            .records
            .insert(harvest_common::store::Bytes32(jam().id.0), sent[0].clone());
        assert!(store_change(&mut f).is_empty(), "landed, forgotten");
        let mut ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        merge_ledgers(&mut ledger, frozen);
        save(
            &mut f.secrets,
            &ledger_key(&f.record.arm.store_contract_id),
            &ledger,
        );
        assert!(store_change(&mut f).is_empty(), "no second decrement");
    }

    /// Past the sales cap a merge drops what matters least: decremented
    /// sales, then the oldest; never a newer undecremented one.
    #[test]
    fn a_full_merge_keeps_undecremented_sales() {
        let sale = |n: u16, decremented: Option<u64>| Sale {
            order: OrderId({
                let mut id = [0; 32];
                id[..2].copy_from_slice(&n.to_le_bytes());
                id
            }),
            listing: jam().id,
            quantity: 1,
            issued_at_ms: NOW + u64::from(n),
            anchor_height: 1_000,
            decremented,
        };
        let mut held = Ledger {
            sales: (0..SALES_CAP as u16).map(|n| sale(n, Some(1))).collect(),
            ..Default::default()
        };
        let incoming = Ledger {
            sales: vec![sale(9_000, None)],
            ..Default::default()
        };
        merge_ledgers(&mut held, incoming);
        assert_eq!(held.sales.len(), SALES_CAP);
        assert!(held.sales.contains(&sale(9_000, None)));
    }

    /// S1 as the threat model now states it: a payment that arrives after
    /// its hold ended and the unit was resold is sold anyway, published stock
    /// ends at zero, and the seller is told. Mutated red by not recording it.
    #[test]
    fn a_sale_paid_after_its_unit_was_resold_is_reported() {
        let mut f = fixture();
        counted(&mut f, 1);
        let first = run(&mut f, &[Buyer::new(40).request(&jam(), 1, 1, 12_000)]);
        publish(&mut f, &first);
        let a = first.orders[0].order.id.clone();
        with_status(&mut f, &a, OrderStatus::Cancelled);
        let second = run(&mut f, &[Buyer::new(41).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(second.orders.len(), 1, "the unit was free again");
        publish(&mut f, &second);
        let b = second.orders[0].order.id.clone();
        with_status(&mut f, &b, OrderStatus::Paid);
        let sold = store_change(&mut f);
        f.store
            .listing_statuses
            .records
            .insert(harvest_common::store::Bytes32(jam().id.0), sold[0].clone());
        // The cancelled buyer pays anyway.
        with_status(&mut f, &a, OrderStatus::Paid);
        store_change(&mut f);
        let ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        assert_eq!(
            ledger
                .oversold
                .iter()
                .map(|o| o.order.clone())
                .collect::<Vec<_>>(),
            vec![a]
        );
        let (response, _) = arm(&mut f.secrets, f.record.arm.clone(), NOW);
        let HarvestDelegateResponse::AutoInvoice {
            result: Ok(status), ..
        } = response
        else {
            panic!("{response:?}")
        };
        assert_eq!(status.oversold.len(), 1);
        // Shown for two weeks, then gone.
        let (response, _) = arm(
            &mut f.secrets,
            f.record.arm.clone(),
            NOW + OVERSOLD_SHOWN_MS,
        );
        let HarvestDelegateResponse::AutoInvoice {
            result: Ok(status), ..
        } = response
        else {
            panic!("{response:?}")
        };
        assert!(status.oversold.is_empty());
    }

    /// Invoices issued in one run are each counted after a migration: they
    /// get distinct times, so the set-merge keeps every one. Mutated red by
    /// stamping every invoice of a run with the same time.
    #[test]
    fn a_runs_invoices_all_count_after_a_migration() {
        let mut f = fixture();
        f.record.arm.watched_scripts = (0..10).map(script_at).collect();
        let decided = run(
            &mut f,
            &[
                Buyer::new(40).request_at(&jam(), 1, 1, 12_000, NOW - 3_000),
                Buyer::new(41).request_at(&jam(), 1, 1, 12_000, NOW - 2_000),
                Buyer::new(42).request_at(&jam(), 1, 1, 12_000, NOW - 1_000),
            ],
        );
        assert_eq!(decided.orders.len(), 3);
        let old = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        let mut successor = Ledger::default();
        merge_ledgers(&mut successor, old);
        assert_eq!(successor.issued_last_day(NOW), 3);
    }

    /// A predecessor's full list of tombstones, merged again after this
    /// delegate settled more, does not push this delegate's own out and
    /// revive a sale. Mutated red by merging tombstones before sales.
    #[test]
    fn a_re_import_at_the_tombstone_cap_revives_nothing() {
        let sale = Sale {
            order: OrderId([0xee; 32]),
            listing: jam().id,
            quantity: 1,
            issued_at_ms: NOW,
            anchor_height: 1_000,
            decremented: None,
        };
        let predecessor = Ledger {
            settled: (0..ANSWERED_CAP as u32)
                .map(|n| {
                    let mut id = [0; 32];
                    id[..4].copy_from_slice(&n.to_le_bytes());
                    OrderId(id)
                })
                .collect(),
            sales: vec![sale.clone()],
            ..Default::default()
        };
        let mut held = Ledger::default();
        merge_ledgers(&mut held, predecessor.clone());
        // This delegate settles the carried sale.
        held.sales.clear();
        held.settle(sale.order.clone());
        merge_ledgers(&mut held, predecessor);
        assert!(held.sales.is_empty(), "the settled sale stays settled");
    }

    /// A sale is forgotten once its payment is reversed, or its payment
    /// window closes unpaid. Mutated red by keeping either.
    #[test]
    fn a_reversed_or_expired_sale_is_forgotten() {
        for (status, blocks) in [
            (OrderStatus::PaymentReversed, 0),
            (
                OrderStatus::AwaitingPayment,
                harvest_common::payment::PAYMENT_WINDOW_BLOCKS + 1,
            ),
        ] {
            let mut f = fixture();
            counted(&mut f, 2);
            let first = run(&mut f, &[Buyer::new(40).request(&jam(), 1, 1, 12_000)]);
            publish(&mut f, &first);
            with_status(&mut f, &first.orders[0].order.id, status);
            let mut tip: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
            tip.anchor.height += blocks;
            save(&mut f.secrets, &tip_key(BitcoinNetwork::Signet), &tip);
            store_change(&mut f);
            let ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
            assert!(ledger.sales.is_empty(), "{status:?}");
        }
    }

    /// S1 across a migration: a sale issued by the predecessor, carried in
    /// its ledger, comes off the stock when it is paid after the upgrade.
    #[test]
    fn a_sale_carried_by_a_migration_is_decremented_when_paid() {
        let mut old = fixture();
        counted(&mut old, 3);
        let first = run(&mut old, &[Buyer::new(40).request(&jam(), 2, 1, 22_000)]);
        let exported = to_cbor(&load_ledger(
            &old.secrets,
            &old.record.arm.store_contract_id,
        ))
        .unwrap();
        let mut new = fixture();
        counted(&mut new, 3);
        let key = ledger_key(&new.record.arm.store_contract_id);
        let merged = merge_ledger_bytes(None, &exported).unwrap().0.unwrap();
        new.secrets.set_secret(&key, &merged);
        publish(&mut new, &first);
        with_status(&mut new, &first.orders[0].order.id, OrderStatus::Paid);
        let sent = store_change(&mut new);
        assert_eq!(
            sent[0].status.availability,
            ListingAvailability::Available { quantity: Some(1) }
        );
    }

    /// Once exported, a generation takes no arm again. Mutated red by
    /// dropping the tombstone check in `arm`.
    #[test]
    fn an_exported_generation_takes_no_arm() {
        let mut f = fixture();
        disarm_all(&mut f.secrets);
        let (response, subscriptions) = arm(&mut f.secrets, f.record.arm.clone(), NOW);
        assert!(matches!(
            response,
            HarvestDelegateResponse::AutoInvoice { result: Err(_), .. }
        ));
        assert!(subscriptions.is_empty());
        assert!(load_arm(&f.secrets, &f.record.arm.store_contract_id).is_none());
    }

    /// The store read the mailbox run asked for comes back and is decided:
    /// the context carries the batch through, and the answer is one store
    /// update holding the replies for after it lands. Driven through
    /// `on_get_answer`, the dispatcher's one route. A mailbox run is a
    /// background run.
    #[test]
    fn the_store_read_is_decided_and_answered() {
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let state = to_cbor(&MailboxStateV1 {
            messages: vec![buyer.request(&jam(), 1, 1, 12_000)],
        })
        .unwrap();
        let out = on_notification(&mut f.secrets, &[2; 32], &state, NOW).unwrap();
        assert_eq!(
            load::<_, u64>(&f.secrets, RAN_KEY),
            Some(NOW),
            "a background run"
        );
        let [OutboundDelegateMsg::GetContractRequest(get)] = out.as_slice() else {
            panic!("{out:?}")
        };
        let store = to_cbor(&f.store).unwrap();
        let answer = on_get_answer(
            &mut f.secrets,
            &[1; 32],
            Some(&store),
            get.context.as_ref(),
            NOW,
        )
        .unwrap();
        let [OutboundDelegateMsg::UpdateContractRequest(update)] = answer.as_slice() else {
            panic!("{answer:?}")
        };
        let UpdateData::Delta(delta) = &update.update else {
            panic!("a delta")
        };
        let delta: StoreStateV1Delta = from_cbor(delta.as_ref()).unwrap();
        assert_eq!(delta.orders.unwrap().len(), 1);
        let replies: PendingReplies = from_cbor(update.context.as_ref()).unwrap();
        assert_eq!(buyer.read(&replies.replies).len(), 1);
        assert!(on_store_state(&mut f.secrets, Some(&store), b"not ours", NOW).is_none());
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
        assert!(ledger.sales.is_empty());
    }

    /// I4. Past the per-buyer cap the buyer is told, in the words their own
    /// app uses; past each other cap the buyer is told to try again later
    /// and the seller sees the limit for an hour.
    /// Mutated red by removing each cap's check in turn.
    #[test]
    fn exposure_is_capped() {
        // Per conversation: declined in so many words, nothing spent.
        let mut f = fixture();
        f.record.arm.watched_scripts = (0..10).map(script_at).collect();
        let buyer = Buyer::new(40);
        for nonce in 1..=MAX_OPEN_PER_CONVERSATION as u8 {
            let d = run(&mut f, &[buyer.request(&jam(), 1, nonce, 12_000)]);
            assert_eq!(d.orders.len(), 1);
            publish(&mut f, &d);
        }
        let spent = counter(&f);
        let over = run(
            &mut f,
            &[buyer.request(&jam(), 1, MAX_OPEN_PER_CONVERSATION as u8 + 1, 12_000)],
        );
        assert!(over.orders.is_empty());
        assert_eq!(
            buyer.read(&over.replies),
            vec![MessageContent::Decline {
                reason: harvest_common::delegate::TOO_MANY_UNPAID.into()
            }]
        );
        assert_eq!(counter(&f), spent, "no address spent on a decline");
        // Another buyer is not held to this one's orders.
        let other = run(&mut f, &[Buyer::new(41).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(other.orders.len(), 1, "{:?}", other.refused);

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
        let buyer = Buyer::new(50);
        let capped = run(&mut f, &[buyer.request(&jam(), 1, 1, 12_000)]);
        assert_eq!(capped.refused[0].1, Refusal::StoreCap);
        // The buyer is told, and so is the seller, for an hour.
        assert_eq!(
            buyer.read(&capped.replies),
            vec![MessageContent::Decline {
                reason: Refusal::StoreCap.buyer_reason().unwrap().into()
            }]
        );
        assert!(status_of(&f.secrets, &f.record, NOW).capped.is_some());
        assert!(status_of(&f.secrets, &f.record, NOW + CAPPED_SHOWN_MS)
            .capped
            .is_none());

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

        // A run of this store's unpaid orders from the last day below the
        // counter.
        let mut f = fixture();
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &xpub_at(MAX_TRAILING_UNPAID)).unwrap();
        f.record.arm.watched_scripts = vec![script_at(MAX_TRAILING_UNPAID)];
        unpaid_orders_on(&mut f, 0..MAX_TRAILING_UNPAID, NOW - 60_000);
        let capped = run(&mut f, &[Buyer::new(50).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(capped.refused[0].1, Refusal::TrailingUnpaid);
        assert_eq!(counter(&f), MAX_TRAILING_UNPAID);

        // The run is counted once and grows with each invoice in it: one
        // short of the cap, the first request is invoiced and the second,
        // in the same run, is not.
        let mut f = fixture();
        let start = MAX_TRAILING_UNPAID - 1;
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &xpub_at(start)).unwrap();
        f.record.arm.watched_scripts = vec![script_at(start), script_at(start + 1)];
        unpaid_orders_on(&mut f, 0..start, NOW - 60_000);
        let both = run(
            &mut f,
            &[
                Buyer::new(50).request(&jam(), 1, 1, 12_000),
                Buyer::new(51).request(&jam(), 1, 1, 12_000),
            ],
        );
        assert_eq!(both.orders.len(), 1, "{:?}", both.refused);
        assert_eq!(both.refused[0].1, Refusal::TrailingUnpaid);
        // Unpaid clicks do not stop the store for good: a run whose orders
        // are more than a day old no longer counts toward the limit (though
        // it still counts toward the wallet-gap note).
        let mut f = fixture();
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &xpub_at(MAX_TRAILING_UNPAID)).unwrap();
        f.record.arm.watched_scripts = vec![script_at(MAX_TRAILING_UNPAID)];
        unpaid_orders_on(&mut f, 0..MAX_TRAILING_UNPAID, NOW - DAY_MS - 1);
        let healed = run(&mut f, &[Buyer::new(52).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(healed.orders.len(), 1, "{:?}", healed.refused);
        assert_eq!(
            load_ledger(&f.secrets, &f.record.arm.store_contract_id)
                .gap_orders
                .len(),
            1,
            "past the wallet's gap all the same"
        );

        // Nor do addresses that are not this store's orders (another store's
        // of this device, or spent and never published).
        let mut f = fixture();
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &xpub_at(MAX_TRAILING_UNPAID)).unwrap();
        f.record.arm.watched_scripts = vec![script_at(MAX_TRAILING_UNPAID)];
        let foreign = run(&mut f, &[Buyer::new(54).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(foreign.orders.len(), 1, "{:?}", foreign.refused);

        // An address paid at ANOTHER store of this device closes the run:
        // the payment key is shared by every store.
        let mut f = fixture();
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &xpub_at(MAX_TRAILING_UNPAID)).unwrap();
        f.record.arm.watched_scripts = vec![script_at(MAX_TRAILING_UNPAID)];
        unpaid_orders_on(&mut f, 0..MAX_TRAILING_UNPAID, NOW - 60_000);
        let paid: Vec<(i64, Vec<u8>)> = vec![(0, script_at(MAX_TRAILING_UNPAID - 1))];
        save(&mut f.secrets, PAID_SCRIPTS_KEY, &paid);
        let elsewhere = run(&mut f, &[Buyer::new(53).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(elsewhere.orders.len(), 1, "{:?}", elsewhere.refused);

        // A run of other stores' or stranded addresses never stops this
        // store, however long: it only sets the gap limit the seller is told.
        let mut f = fixture();
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &xpub_at(MAX_ADDRESS_RUN)).unwrap();
        f.record.arm.watched_scripts = vec![script_at(MAX_ADDRESS_RUN)];
        let long = run(&mut f, &[Buyer::new(55).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(long.orders.len(), 1, "{:?}", long.refused);
        let ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        assert_eq!(ledger.gap_orders[0].1, MAX_ADDRESS_RUN);
    }

    /// The gap limit the seller is told: 100, or the next hundred above a
    /// longer run. Mutated red by always saying 100.
    #[test]
    fn the_wallet_gap_limit_covers_the_run() {
        assert_eq!(wallet_gap_limit_for(20), 100);
        assert_eq!(wallet_gap_limit_for(98), 100);
        assert_eq!(wallet_gap_limit_for(99), 200, "one to spare");
        assert_eq!(wallet_gap_limit_for(250), 300);
        assert_eq!(wallet_gap_limit_for(MAX_ADDRESS_RUN - 1), 1100);
        assert_eq!(
            wallet_gap_limit_for(MAX_ADDRESS_RUN),
            u32::MAX,
            "counted no further"
        );
    }

    /// A Buy now dated well ahead of this node's clock is declined with
    /// words the buyer can act on; one a few minutes ahead is fine. Mutated
    /// red by dropping the check.
    #[test]
    fn a_buy_now_from_a_clock_far_ahead_is_told_so() {
        let mut f = fixture();
        let buyer = Buyer::new(61);
        let ahead = run(
            &mut f,
            &[buyer.request_at(&jam(), 1, 1, 12_000, NOW + MAX_CLOCK_AHEAD_MS + 1)],
        );
        assert_eq!(ahead.refused[0].1, Refusal::ClockAhead);
        assert_eq!(
            buyer.read(&ahead.replies),
            vec![MessageContent::Decline {
                reason: Refusal::ClockAhead.buyer_reason().unwrap().into()
            }]
        );
        let ok = run(
            &mut f,
            &[Buyer::new(62).request_at(&jam(), 1, 1, 12_000, NOW + 60_000)],
        );
        assert_eq!(ok.orders.len(), 1, "{:?}", ok.refused);
    }

    /// A decline the mailbox refused leaves its request to be decided again,
    /// as does a refused store update; the sale stays (an update reported
    /// refused may have landed, and one that did not is released after
    /// `NOT_LANDED_MS`). Mutated red by not attaching the decline's retry.
    #[test]
    fn refused_answers_are_undone_so_the_retry_can_answer() {
        let mut f = fixture();
        counted(&mut f, 1);
        let (a, b) = (Buyer::new(40), Buyer::new(41));
        let (ea, eb) = (
            a.request_at(&jam(), 1, 1, 12_000, NOW - 9_000),
            b.request_at(&jam(), 1, 1, 12_000, NOW - 8_000),
        );
        let decided = run(&mut f, &[ea.clone(), eb.clone()]);
        let out = decided.into_messages(&f.record.arm);
        let contexts: Vec<Vec<u8>> = out
            .iter()
            .map(|m| match m {
                OutboundDelegateMsg::UpdateContractRequest(u) => u.context.as_ref().to_vec(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(contexts.len(), 2, "the decline and the store update");
        for context in &contexts {
            on_store_update_answer(&mut f.secrets, &Err("refused".into()), context);
        }
        let ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        assert!(!ledger.seen.contains(&entry_digest(&eb)), "decline undone");
        assert!(!ledger.seen.contains(&entry_digest(&ea)), "invoice undone");
        assert!(ledger.retry_pending);
        assert_eq!(ledger.sales.len(), 1, "the sale stays");
    }

    /// A Buy now for a listing that changed or went away is answered, not
    /// left waiting on a request nothing retries. Mutated red by dropping
    /// the decline.
    #[test]
    fn a_buy_now_for_a_changed_listing_is_told_so() {
        let mut f = fixture();
        let buyer = Buyer::new(60);
        let decided = run(&mut f, &[buyer.request(&jam(), 1, 1, 11_111)]);
        assert_eq!(decided.refused[0].1, Refusal::TotalMismatch);
        assert_eq!(
            buyer.read(&decided.replies),
            vec![MessageContent::Decline {
                reason: Refusal::TotalMismatch.buyer_reason().unwrap().into()
            }]
        );
        assert_eq!(counter(&f), 0, "nothing spent");
    }

    /// An invoice issued past a run of `WALLET_GAP_LIMIT` unpaid addresses
    /// is remembered, and once it is paid the seller is told (for two weeks)
    /// to raise their wallet's gap limit; one issued inside the gap is not.
    /// Mutated red by never recording, by recording every invoice, and by
    /// never noticing the payment.
    #[test]
    fn a_payment_past_the_wallet_gap_is_reported() {
        // Inside the gap: nothing to tell.
        let mut f = fixture();
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &xpub_at(WALLET_GAP_LIMIT - 1)).unwrap();
        f.record.arm.watched_scripts = vec![script_at(WALLET_GAP_LIMIT - 1)];
        let inside = run(&mut f, &[Buyer::new(50).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(inside.orders.len(), 1, "{:?}", inside.refused);
        let ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        assert!(ledger.gap_orders.is_empty());

        // Past it: remembered, and reported once paid.
        let mut f = fixture();
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &xpub_at(WALLET_GAP_LIMIT)).unwrap();
        f.record.arm.watched_scripts = vec![script_at(WALLET_GAP_LIMIT)];
        let past = run(&mut f, &[Buyer::new(50).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(past.orders.len(), 1, "{:?}", past.refused);
        publish(&mut f, &past);
        let ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        assert_eq!(ledger.gap_orders.len(), 1);
        assert_eq!(
            status_of(&f.secrets, &f.record, NOW).wallet_gap_paid_at_ms,
            None
        );
        with_status(&mut f, &past.orders[0].order.id, OrderStatus::Paid);
        store_change(&mut f);
        assert_eq!(
            status_of(&f.secrets, &f.record, NOW).wallet_gap_paid_at_ms,
            Some(NOW)
        );
        assert_eq!(status_of(&f.secrets, &f.record, NOW).wallet_gap_limit, 100);
        assert_eq!(
            status_of(&f.secrets, &f.record, NOW + OVERSOLD_SHOWN_MS).wallet_gap_paid_at_ms,
            None,
            "said for two weeks"
        );
        assert_eq!(
            status_of(&f.secrets, &f.record, NOW + OVERSOLD_SHOWN_MS).wallet_gap_limit,
            0
        );
    }

    fn heartbeat_of(out: &[OutboundDelegateMsg]) -> Vec<harvest_common::presence::SignedHeartbeat> {
        out.iter()
            .filter_map(|m| match m {
                OutboundDelegateMsg::UpdateContractRequest(u)
                    if u.contract_id.as_bytes() == [9; 32] =>
                {
                    let UpdateData::Delta(d) = &u.update else {
                        panic!("a delta")
                    };
                    Some(harvest_common::presence::decode_delta(d.as_ref()).unwrap())
                }
                _ => None,
            })
            .collect()
    }

    /// A wake-up sends each armed store's heartbeat to its presence
    /// contract, signed by the store key, saying whether it takes orders;
    /// a second one inside `HEARTBEAT_MIN_GAP_MS` saying the same is not
    /// sent; one after it is, with a larger `seq`. The wake-up is recorded
    /// for the tab. Mutated red by dropping the gap check, by never sending,
    /// and by not recording the wake-up.
    #[test]
    fn a_wake_up_sends_a_heartbeat_and_is_remembered() {
        use crate::node_glue::{BackgroundRun, HEARTBEAT_TAG};
        let mut f = fixture();
        let wake = BackgroundRun::Wakeup {
            tag: HEARTBEAT_TAG.to_vec(),
        };
        let out = crate::background::on_background(&mut f.secrets, &wake, NOW);
        let beats = heartbeat_of(&out);
        assert_eq!(beats.len(), 1, "{out:?}");
        beats[0]
            .verify(&store_sk().verifying_key())
            .expect("signed by the store key");
        assert!(beats[0].heartbeat.taking_orders);
        assert_eq!(beats[0].heartbeat.at_ms, NOW);
        assert_eq!(load::<_, u64>(&f.secrets, WAKEUP_KEY), Some(NOW));
        assert_eq!(
            status_of(&f.secrets, &f.record, NOW).last_wakeup_ms,
            Some(NOW)
        );

        let soon = crate::background::on_background(&mut f.secrets, &wake, NOW + 60_000);
        assert!(heartbeat_of(&soon).is_empty(), "one per interval");
        let later =
            crate::background::on_background(&mut f.secrets, &wake, NOW + HEARTBEAT_MIN_GAP_MS);
        let again = heartbeat_of(&later);
        assert_eq!(again.len(), 1);
        assert!(again[0].heartbeat.seq > beats[0].heartbeat.seq);

        // A tag this generation did not declare does nothing.
        let other = BackgroundRun::Wakeup { tag: b"x".to_vec() };
        assert!(crate::background::on_background(&mut f.secrets, &other, NOW + DAY_MS).is_empty());
    }

    /// A heartbeat says the store is not taking orders when it could not
    /// issue payment details (here, the watch lapsed), and a change of that
    /// goes out at once, inside the interval. Its `seq` keeps rising
    /// through a clock that jumped back. Mutated red by taking orders
    /// regardless, and by ordering on the clock.
    #[test]
    fn a_heartbeat_says_when_the_store_cannot_take_orders() {
        let mut f = fixture();
        let (first, _) = heartbeat(&mut f.secrets, &f.record.clone(), NOW, false).unwrap();
        assert!(first.heartbeat.taking_orders);
        let mut lapsed = f.record.clone();
        lapsed.watched_until_ms = NOW;
        let (closed, _) = heartbeat(&mut f.secrets, &lapsed, NOW + 1_000, false).expect("changed");
        assert!(!closed.heartbeat.taking_orders);
        // The clock jumps back an hour: still a later heartbeat.
        let (back, _) =
            heartbeat(&mut f.secrets, &f.record.clone(), NOW - 3_600_000, true).unwrap();
        assert!(back.heartbeat.seq > closed.heartbeat.seq);
        assert_eq!(back.heartbeat.at_ms, NOW - 3_600_000);
    }

    /// A generation that has handed on is still woken, and does nothing,
    /// not even note the wake-up. Mutated red by dropping the check.
    #[test]
    fn a_handed_on_generation_ignores_its_wake_ups() {
        use crate::node_glue::{BackgroundRun, HEARTBEAT_TAG};
        let mut f = fixture();
        f.secrets.set_secret(EXPORTED_KEY, b"1");
        let wake = BackgroundRun::Wakeup {
            tag: HEARTBEAT_TAG.to_vec(),
        };
        assert!(crate::background::on_background(&mut f.secrets, &wake, NOW).is_empty());
        assert_eq!(load::<_, u64>(&f.secrets, WAKEUP_KEY), None);
    }

    /// A heartbeat another signer left in the presence contract (an earlier
    /// generation, a second device, a clock that ran ahead) is learned from a
    /// read of it or the subscription, and the next one here outranks it at
    /// once. Mutated red by not learning it, by not routing the read, and by
    /// learning a lower one.
    #[test]
    fn a_heartbeat_signed_elsewhere_is_outranked() {
        use harvest_common::presence::{Heartbeat, PresenceStateV1, SignedHeartbeat};
        let mut f = fixture();
        let sk = store_key(&f.secrets, &f.record.arm.store_verifying_key).unwrap();
        let ahead = NOW + 365 * 24 * 3_600_000;
        let elsewhere = SignedHeartbeat::sign(&sk, Heartbeat::new(ahead, ahead, true)).unwrap();
        let state = to_cbor(&PresenceStateV1 {
            heartbeat: Some(elsewhere),
        })
        .unwrap();
        // Learned from a read (the node's start sends one; arming does too,
        // though a node may refuse it past its operation budget): a signer
        // that has stopped writing sends no notification.
        assert!(
            on_get_answer(&mut f.secrets, &[9; 32], Some(&state), &[], NOW)
                .is_some_and(|out| out.is_empty())
        );
        let (next, _) = heartbeat(&mut f.secrets, &f.record.clone(), NOW, false)
            .expect("nothing sent here yet, so not held back by the gap");
        assert_eq!(next.heartbeat.seq, ahead + 1);
        assert_eq!(next.heartbeat.at_ms, NOW);
        // An older one seen later lowers nothing.
        let older = SignedHeartbeat::sign(&sk, Heartbeat::new(NOW - 1, NOW - 1, true)).unwrap();
        let state = to_cbor(&PresenceStateV1 {
            heartbeat: Some(older),
        })
        .unwrap();
        on_notification(&mut f.secrets, &[9; 32], &state, NOW);
        let (again, _) = heartbeat(&mut f.secrets, &f.record.clone(), NOW + 1, true).unwrap();
        assert_eq!(again.heartbeat.seq, ahead + 2);
    }

    /// No heartbeat without a presence contract (an older UI armed it) or
    /// once this generation handed its keys on. Mutated red by dropping
    /// each check.
    #[test]
    fn no_heartbeat_without_a_presence_contract_or_after_export() {
        let mut f = fixture();
        let mut old_ui = f.record.clone();
        old_ui.arm.presence_contract_id = None;
        assert!(heartbeat(&mut f.secrets, &old_ui, NOW, true).is_none());
        f.secrets.set_secret(EXPORTED_KEY, b"1");
        assert!(heartbeat(&mut f.secrets, &f.record.clone(), NOW, true).is_none());
    }

    /// The tab's heartbeat request: answered with the heartbeat it sent and
    /// the last wake-up, or with why not. Mutated red by answering an
    /// unarmed store.
    #[test]
    fn the_tabs_heartbeat_request_is_answered() {
        let mut f = fixture();
        note_wakeup(&mut f.secrets, NOW - 5);
        let (answer, out) = heartbeat_request(&mut f.secrets, &[1; 32], true, NOW);
        let HarvestDelegateResponse::Heartbeat { result: Ok(a), .. } = answer else {
            panic!("{answer:?}")
        };
        assert!(a.heartbeat.is_some());
        assert_eq!(a.last_wakeup_ms, Some(NOW - 5));
        assert_eq!(heartbeat_of(&out).len(), 1);
        let (unarmed, out) = heartbeat_request(&mut f.secrets, &[8; 32], true, NOW);
        assert!(matches!(
            unarmed,
            HarvestDelegateResponse::Heartbeat { result: Err(_), .. }
        ));
        assert!(out.is_empty());
    }

    /// The node starting (or this delegate being installed) subscribes again
    /// to each tip once and reads it, then to every store and mailbox, then
    /// subscribes to and reads every presence contract: six operations for
    /// one store.
    /// Nothing after an export. Mutated red by dropping the tip read, the
    /// presence subscription, and the export check.
    #[test]
    fn the_node_starting_resubscribes_every_arm() {
        use crate::node_glue::BackgroundRun;
        let mut f = fixture();
        let out =
            crate::background::on_background(&mut f.secrets, &BackgroundRun::NodeStarted, NOW);
        let subscribed: Vec<[u8; 32]> = out
            .iter()
            .filter_map(|m| match m {
                OutboundDelegateMsg::SubscribeContractRequest(r) => {
                    Some(<[u8; 32]>::try_from(r.contract_id.as_bytes()).unwrap())
                }
                _ => None,
            })
            .collect();
        // The tip once, first, then every store and mailbox, then every
        // presence contract, subscribed and read.
        assert_eq!(subscribed, vec![[3; 32], [1; 32], [2; 32], [9; 32]]);
        let reads: Vec<(usize, [u8; 32])> = out
            .iter()
            .enumerate()
            .filter_map(|(i, m)| match m {
                OutboundDelegateMsg::GetContractRequest(r) => {
                    Some((i, <[u8; 32]>::try_from(r.contract_id.as_bytes()).unwrap()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(reads, vec![(1, [3; 32]), (5, [9; 32])]);
        assert_eq!(out.len(), 6);
        let installed =
            crate::background::on_background(&mut f.secrets, &BackgroundRun::Installed, NOW);
        assert_eq!(installed.len(), 6);
        // Our own heartbeat coming back through that subscription is taken
        // and dropped, not forwarded to a UI a background run does not have.
        assert!(on_notification(&mut f.secrets, &[9; 32], b"any", NOW)
            .is_some_and(|out| out.is_empty()));
        f.secrets.set_secret(EXPORTED_KEY, b"1");
        assert!(
            crate::background::on_background(&mut f.secrets, &BackgroundRun::NodeStarted, NOW)
                .is_empty()
        );
    }

    /// A wake-up re-reads the mailbox of a store whose update was refused,
    /// and the answer is decided as a mailbox change is: the undecided
    /// request goes to the store read again, and once it is decided the next
    /// read of the mailbox clears the flag. Mutated red by never asking, and
    /// by not clearing the flag.
    #[test]
    fn a_wake_up_retries_requests_a_refused_update_left_undecided() {
        use crate::node_glue::{BackgroundRun, HEARTBEAT_TAG};
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let entry = buyer.request(&jam(), 1, 1, 12_000);
        let decided = run(&mut f, std::slice::from_ref(&entry));
        let out = decided.into_messages(&f.record.arm);
        let [OutboundDelegateMsg::UpdateContractRequest(update)] = out.as_slice() else {
            panic!("{out:?}")
        };
        on_store_update_answer(
            &mut f.secrets,
            &Err("refused".into()),
            update.context.as_ref(),
        );
        let wake = BackgroundRun::Wakeup {
            tag: HEARTBEAT_TAG.to_vec(),
        };
        let out = crate::background::on_background(&mut f.secrets, &wake, NOW);
        let gets: Vec<&GetContractRequest> = out
            .iter()
            .filter_map(|m| match m {
                OutboundDelegateMsg::GetContractRequest(g) => Some(g),
                _ => None,
            })
            .collect();
        assert_eq!(gets.len(), 1, "{out:?}");
        assert_eq!(gets[0].contract_id.as_bytes(), [2; 32].as_slice());
        let mailbox = to_cbor(&MailboxStateV1 {
            messages: vec![entry.clone()],
        })
        .unwrap();
        let answered = on_get_answer(
            &mut f.secrets,
            &[2; 32],
            Some(&mailbox),
            gets[0].context.as_ref(),
            NOW,
        )
        .expect("ours");
        let [OutboundDelegateMsg::GetContractRequest(store_read)] = answered.as_slice() else {
            panic!("{answered:?}")
        };
        let batch: PendingBatch = from_cbor(store_read.context.as_ref()).unwrap();
        assert_eq!(batch.entries, vec![entry]);
        assert!(
            load_ledger(&f.secrets, &f.record.arm.store_contract_id).retry_pending,
            "kept while the batch waits on the store"
        );
        let store = to_cbor(&f.store).unwrap();
        on_store_state(
            &mut f.secrets,
            Some(&store),
            store_read.context.as_ref(),
            NOW,
        )
        .unwrap();
        // Decided; the next read of the whole mailbox settles the flag.
        let again = crate::background::on_background(&mut f.secrets, &wake, NOW + 1);
        let [read] = again
            .iter()
            .filter_map(|m| match m {
                OutboundDelegateMsg::GetContractRequest(g) => Some(g),
                _ => None,
            })
            .collect::<Vec<_>>()[..]
        else {
            panic!("{again:?}")
        };
        on_get_answer(
            &mut f.secrets,
            &[2; 32],
            Some(&mailbox),
            read.context.as_ref(),
            NOW,
        )
        .expect("ours");
        assert!(!load_ledger(&f.secrets, &f.record.arm.store_contract_id).retry_pending);
        // Nothing more to retry.
        let later =
            crate::background::on_background(&mut f.secrets, &wake, NOW + HEARTBEAT_MIN_GAP_MS);
        assert!(!later
            .iter()
            .any(|m| matches!(m, OutboundDelegateMsg::GetContractRequest(_))));
    }

    /// I7's second source, end to end: the tab's own watch of the window it
    /// armed (read clear) has lapsed, the delegate's own delegated Watch is
    /// sent, read by the bridge
    /// (a real removal in a real inbox), and the next Buy now is then invoiced
    /// on the first address it named. Before the removal, and once the tip
    /// nears the horizon asked for, the store waits for the seller instead.
    /// Mutated red by: dropping the delegated source from `WatchSet::accepts`
    /// (NoWatchedAddress), and from the `global_refusal` lapse checks
    /// (WatchLapsed).
    #[test]
    fn a_script_the_delegate_had_watched_is_invoiced_with_the_tab_gone() {
        use crate::watch_delegation::test_support as wd;
        let mut secrets = wd::delegated();
        let record: ArmRecord = load(&secrets, &arm_key(&[1; 32])).unwrap();
        assert!(
            record.watched_until_ms <= NOW,
            "the tab's own watch has lapsed"
        );
        assert_eq!(
            record.arm.watched_scripts,
            (0..harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES)
                .map(script_at)
                .collect::<Vec<_>>(),
            "the window the tab read clear"
        );
        let base = fixture();
        let mut f = Fixture {
            secrets: MemSecrets::default(),
            record,
            store: base.store,
            listing: base.listing,
        };
        let buyer = Buyer::new(80);

        // Sent, not yet read: nothing to rely on.
        let mut inbox = wd::open_inbox();
        let (delta, entry) = wd::submitted(&wd::wake_and_read(&mut secrets, &inbox, NOW));
        f.secrets = secrets;
        let waiting = run(&mut f, &[buyer.request(&jam(), 1, 1, 12_000)]);
        assert_eq!(waiting.refused[0].1, Refusal::WatchLapsed);
        assert_eq!(counter(&f), 0, "nothing spent");

        // Read by the bridge: still nothing, until the watermark shows.
        inbox.apply_delta(&wd::params(), &delta).unwrap();
        wd::bridge_reads(&mut inbox, &entry.entry.key(), entry.entry.mainnet_height);
        assert!(wd::wake_and_read(&mut f.secrets, &inbox, NOW + 300_000).is_empty());
        let read = run(&mut f, &[buyer.request(&jam(), 1, 4, 12_000)]);
        assert_eq!(read.refused[0].1, Refusal::WatchLapsed);
        assert!(!taking_orders(
            &f.secrets,
            &f.record,
            NOW,
            &upcoming(&f.secrets)
        ));
        let first_canary = harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES
            + crate::watch_delegation::CANARY_MARGIN;
        wd::wake_and_scan(
            &mut f.secrets,
            &script_at(first_canary),
            Some(wd::TIP),
            NOW + 600_000,
        );
        assert!(taking_orders(
            &f.secrets,
            &f.record,
            NOW,
            &upcoming(&f.secrets)
        ));
        let status = status_of(&f.secrets, &f.record, NOW);
        assert_eq!(status.paused, None);
        let pool = harvest_common::bitcoin_delegate::MAX_UPCOMING_ADDRESSES;
        assert_eq!(status.watched_remaining, pool);
        assert!(status.watch_delegation.is_some_and(|d| d.watched == pool));
        let ok = run(&mut f, &[buyer.request(&jam(), 1, 2, 12_000)]);
        assert_eq!(ok.orders.len(), 1, "{:?}", ok.refused);
        assert_eq!(ok.orders[0].order.payment_script_pubkey, script_at(0));

        // The tip within an invoice's window of the horizon asked for.
        let until = wd::TIP + crate::watch_delegation::REQUEST_AHEAD_BLOCKS;
        wd::set_tip(&mut f.secrets, until - WATCH_NEEDED_BLOCKS + 1);
        let near = run(&mut f, &[buyer.request(&jam(), 1, 3, 12_000)]);
        assert_eq!(near.refused[0].1, Refusal::WatchLapsed);
    }

    /// harvest#198: a delegated watch counts only for a script the store's
    /// arm names. The delegate has the next addresses watched, but the arm
    /// names another window (another key's, say, after an A to B to A key
    /// change, until the tab re-reads and re-arms), and the tab's own watch
    /// has lapsed: nothing is invoiced, the refusal is `WatchLapsed` (no
    /// watch counts for this store), and the heartbeat says not taking
    /// orders. Once the arm names the window, the delegate's watch of the
    /// next address is what invoices it. Mutated red by dropping the arm
    /// filter in `watch_set_in`, and the delegated source from
    /// `WatchSet::accepts`.
    #[test]
    fn a_delegated_watch_counts_only_for_a_script_the_arm_names() {
        use crate::watch_delegation::test_support as wd;
        let mut secrets = wd::delegated();
        wd::send_read_confirm(&mut secrets, wd::TIP, NOW);
        let mut f = fixture();
        f.secrets = secrets;
        f.record.arm.trusted_bridges = vec![wd::bridge()];
        f.record.watched_until_ms = NOW;
        f.record.arm.watched_scripts = (100..110).map(script_at).collect();
        f.record.arm.vetted_scripts = (100..110).map(script_at).collect();
        let entry = Buyer::new(81).request(&jam(), 1, 1, 12_000);
        let refused = run(&mut f, std::slice::from_ref(&entry));
        assert!(refused.orders.is_empty());
        assert_eq!(refused.refused[0].1, Refusal::WatchLapsed);
        assert_eq!(counter(&f), 0);
        assert_eq!(
            open_now(&f, NOW),
            (Some(Refusal::WatchLapsed.explain()), false)
        );
        f.record.arm.vetted_scripts = (0..10).map(script_at).collect();
        let decided = run(&mut f, &[entry]);
        assert_eq!(decided.orders.len(), 1, "{:?}", decided.refused);
        assert_eq!(decided.orders[0].order.payment_script_pubkey, script_at(0));
    }

    /// Review round 1 of batch 2 (#198 route 1): A to B to A. The tab had
    /// armed A's window and the delegation watches it; the seller switches
    /// to B and back to A without the tab re-reading A's window (an address
    /// of it may have been paid by the seller's own wallet meanwhile).
    /// Nothing is invoiced until the tab re-arms under A: every key change
    /// empties the arms. A write of the same key (a raised counter) does
    /// not. Mutated red by not forgetting on a key change, and by
    /// forgetting on every write.
    #[test]
    fn a_key_round_trip_invoices_only_what_the_current_arm_names() {
        use crate::watch_delegation::test_support as wd;
        let mut secrets = wd::delegated();
        wd::send_read_confirm(&mut secrets, wd::TIP, NOW);
        let mut f = fixture();
        f.secrets = secrets;
        f.record.arm.trusted_bridges = vec![wd::bridge()];
        f.record.arm.vetted_scripts = (0..10).map(script_at).collect();
        let id = f.record.arm.store_contract_id.clone();
        save(&mut f.secrets, &arm_key(&id), &f.record);
        let a = crate::bitcoin::load_payment_xpub(&f.secrets).unwrap();
        // The same key written again (a raised counter) keeps the window.
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &a).unwrap();
        assert_eq!(
            load_arm(&f.secrets, &id).unwrap().arm.vetted_scripts.len(),
            10
        );

        let mut b = a.clone();
        b.xpub = format!(" {}", a.xpub);
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &b).unwrap();
        crate::bitcoin::save_payment_xpub(&mut f.secrets, &a).unwrap();
        f.record = load_arm(&f.secrets, &id).unwrap();
        assert!(f.record.arm.vetted_scripts.is_empty() && f.record.arm.watched_scripts.is_empty());
        let entry = Buyer::new(83).request(&jam(), 1, 1, 12_000);
        let refused = run(&mut f, std::slice::from_ref(&entry));
        assert!(refused.orders.is_empty(), "nothing from A's old window");
        assert!(!taking_orders(
            &f.secrets,
            &f.record,
            NOW,
            &upcoming(&f.secrets)
        ));
        // The tab re-arms under A, having read the window again.
        f.record.arm.vetted_scripts = (0..10).map(script_at).collect();
        f.record.last_armed_ms = NOW;
        assert_eq!(run(&mut f, &[entry]).orders.len(), 1);
    }

    /// Review round 1 of batch 2: an arm's scripts count, from either
    /// source, only within `VETTED_FOR_MS` of its last arrival; past it the
    /// store waits for the seller (`WatchLapsed`), and its heartbeat says
    /// so. Mutated red by dropping the bound from the arm source, and from
    /// the delegated source.
    #[test]
    fn a_window_read_a_week_ago_counts_for_nothing() {
        use crate::watch_delegation::test_support as wd;
        let entry = Buyer::new(84).request(&jam(), 1, 1, 12_000);
        // The tab's own watch.
        let mut f = fixture();
        f.record.last_armed_ms = NOW - VETTED_FOR_MS;
        assert_eq!(
            run(&mut f, std::slice::from_ref(&entry)).refused[0].1,
            Refusal::WatchLapsed
        );
        f.record.last_armed_ms = NOW - VETTED_FOR_MS + 1;
        assert_eq!(run(&mut f, std::slice::from_ref(&entry)).orders.len(), 1);
        // The delegation's.
        let mut secrets = wd::delegated();
        wd::send_read_confirm(&mut secrets, wd::TIP, NOW);
        let mut f = fixture();
        f.secrets = secrets;
        f.record.arm.trusted_bridges = vec![wd::bridge()];
        f.record.watched_until_ms = NOW;
        f.record.arm.vetted_scripts = (0..10).map(script_at).collect();
        f.record.last_armed_ms = NOW - VETTED_FOR_MS;
        assert_eq!(
            run(&mut f, std::slice::from_ref(&entry)).refused[0].1,
            Refusal::WatchLapsed
        );
        assert!(!taking_orders(
            &f.secrets,
            &f.record,
            NOW,
            &upcoming(&f.secrets)
        ));
        f.record.last_armed_ms = NOW;
        assert_eq!(run(&mut f, &[entry]).orders.len(), 1);
    }

    /// harvest#183 / #198 with the tab closed: the counter was reset over a
    /// history whose paid address lies past the window the tab read clear.
    /// The tab armed the window (0..10); the delegate also holds credits for
    /// the addresses past it (from refills before the reset). Ten sales use
    /// the window; the eleventh is refused (`NoWatchedAddress`, and the
    /// heartbeat says so) and index 10 is never issued, however many
    /// wake-ups run, since the refill asks only for armed scripts. Mutated
    /// red by dropping either filter.
    #[test]
    fn the_183_scenario_with_the_tab_closed() {
        use crate::watch_delegation::test_support as wd;
        let mut secrets = wd::delegated();
        let until = wd::TIP + crate::watch_delegation::REQUEST_AHEAD_BLOCKS;
        wd::confirm_watched(
            &mut secrets,
            &(0..30).map(script_at).collect::<Vec<_>>(),
            until,
        );
        let mut f = fixture();
        f.secrets = secrets;
        f.record.arm.trusted_bridges = vec![wd::bridge()];
        f.record.watched_until_ms = NOW;
        f.record.arm.watched_scripts = (0..10).map(script_at).collect();
        f.record.arm.vetted_scripts = (0..10).map(script_at).collect();
        save(
            &mut f.secrets,
            &arm_key(&f.record.arm.store_contract_id),
            &f.record,
        );
        for i in 0..10u8 {
            let decided = run(&mut f, &[Buyer::new(100 + i).request(&jam(), 1, i, 12_000)]);
            assert_eq!(decided.orders.len(), 1, "sale {i}: {:?}", decided.refused);
            assert_eq!(
                decided.orders[0].order.payment_script_pubkey,
                script_at(u32::from(i))
            );
        }
        let eleventh = run(&mut f, &[Buyer::new(120).request(&jam(), 1, 1, 12_000)]);
        assert!(eleventh.orders.is_empty());
        assert_eq!(eleventh.refused[0].1, Refusal::NoWatchedAddress);
        assert_eq!(counter(&f), 10, "index 10 never issued");
        assert_eq!(
            open_now(&f, NOW),
            (Some(Refusal::NoWatchedAddress.explain()), false)
        );
        let h = wd::held(&f.secrets);
        assert!(
            crate::watch_delegation::refill_scripts_for_test(&f.secrets, &h, wd::TIP, NOW)
                .is_empty(),
            "nothing past the window is asked for"
        );
    }

    /// Without a tip the reason given is `NoFreshTip`, not a lapsed watch:
    /// the delegate's watches are measured against the tip (review round 2
    /// of #179). Mutated red by judging the lapse without a tip.
    #[test]
    fn without_a_tip_the_reason_is_the_tip() {
        let mut f = fixture();
        f.record.watched_until_ms = NOW;
        crate::secrets::RemovableSecrets::remove_secret(
            &mut f.secrets,
            &tip_key(BitcoinNetwork::Signet),
        );
        let decided = run(&mut f, &[Buyer::new(82).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(decided.refused[0].1, Refusal::NoFreshTip);
    }

    /// Review round 1 of #179, P1: what the store says (open, how many
    /// orders, until when) is the run of addresses from the counter I7 would
    /// actually accept, across both sources, not watched addresses anywhere.
    /// 6-9 watched through an older horizon, 10-15 through a newer one: once
    /// the older one is too near the tip, the next address is refused, so the
    /// store is closed although six watched addresses sit further on. The
    /// same at the tab-to-delegate handoff: the tab's 6-9 lapse, the
    /// delegate's 10-15 do not help. Mutated red by counting watched
    /// addresses anywhere in the pool (the old `remaining_watched`).
    #[test]
    fn the_store_is_open_only_while_the_next_address_is_watched() {
        use crate::watch_delegation::test_support as wd;
        let mut secrets = wd::delegated();
        let u1 = wd::TIP + 3_000;
        let u2 = wd::TIP + freenet_bitcoin_inbox::MAX_WATCH_AHEAD_BLOCKS;
        wd::confirm_watched(
            &mut secrets,
            &(6..10).map(script_at).collect::<Vec<_>>(),
            u1,
        );
        wd::confirm_watched(
            &mut secrets,
            &(10..16).map(script_at).collect::<Vec<_>>(),
            u2,
        );
        wd::set_counter(&mut secrets, 6);
        // The tab armed the window from the counter.
        wd::arm_window(&mut secrets, 6);
        let record: ArmRecord = load(&secrets, &arm_key(&[1; 32])).unwrap();
        let status = status_of(&secrets, &record, NOW);
        assert_eq!(status.watched_remaining, 10);
        assert!(taking_orders(&secrets, &record, NOW, &upcoming(&secrets)));
        // Too near U1: 6-9 no longer count, and nothing past them does.
        wd::set_tip(&mut secrets, u1 - WATCH_NEEDED_BLOCKS + 1);
        let status = status_of(&secrets, &record, NOW);
        assert_eq!(status.watched_remaining, 0);
        assert!(!taking_orders(&secrets, &record, NOW, &upcoming(&secrets)));

        // The handoff: the tab watched 6-9 and has lapsed; the delegate 10-15.
        let mut secrets = wd::delegated();
        wd::confirm_watched(
            &mut secrets,
            &(10..16).map(script_at).collect::<Vec<_>>(),
            u2,
        );
        wd::set_counter(&mut secrets, 6);
        let mut record: ArmRecord = load(&secrets, &arm_key(&[1; 32])).unwrap();
        record.arm.watched_scripts = (6..16).map(script_at).collect();
        record.watched_until_ms = NOW + WATCH_NEEDED_MS + 60_000;
        assert_eq!(status_of(&secrets, &record, NOW).watched_remaining, 10);
        record.watched_until_ms = NOW + WATCH_NEEDED_MS;
        assert_eq!(status_of(&secrets, &record, NOW).watched_remaining, 0);
        assert!(!taking_orders(&secrets, &record, NOW, &upcoming(&secrets)));
    }

    /// A watch that ends at a height must outlast an invoice's window in
    /// blocks: none is issued once the tip is within `WATCH_NEEDED_BLOCKS`
    /// of it. Mutated red by dropping the check and by an off-by-one.
    #[test]
    fn a_watch_horizon_near_the_tip_stops_invoicing() {
        let mut f = fixture();
        f.record.arm.watched_until_height = Some(1_000 + WATCH_NEEDED_BLOCKS);
        let ok = run(&mut f, &[Buyer::new(70).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(ok.orders.len(), 1, "{:?}", ok.refused);
        let mut f = fixture();
        f.record.arm.watched_until_height = Some(1_000 + WATCH_NEEDED_BLOCKS - 1);
        let near = run(&mut f, &[Buyer::new(71).request(&jam(), 1, 1, 12_000)]);
        assert_eq!(near.refused[0].1, Refusal::WatchLapsed);
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

    /// Arming stores the arm, subscribes to the three contracts, reads the
    /// tip once (harvest#162), and then subscribes to the presence contract.
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
        let ids: Vec<(&str, [u8; 32])> = subscriptions
            .iter()
            .map(|m| match m {
                OutboundDelegateMsg::SubscribeContractRequest(r) => {
                    ("subscribe", r.contract_id.as_bytes().try_into().unwrap())
                }
                OutboundDelegateMsg::GetContractRequest(r) => {
                    ("get", r.contract_id.as_bytes().try_into().unwrap())
                }
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            ids,
            vec![
                ("subscribe", [1; 32]),
                ("subscribe", [2; 32]),
                ("subscribe", [3; 32]),
                ("get", [3; 32]),
                ("subscribe", [9; 32]),
                ("get", [9; 32]),
            ]
        );
        // The node runs at most four network operations for one delegate
        // request (freenet-core's `MAX_NETWORK_CONTRACT_OPS_PER_PARK`,
        // counting only contracts it has never seen) and refuses the rest.
        // The four instant checkout needs come first, so what the node may
        // refuse is the presence contract's, which the seller's tab PUTs in
        // any case.
        assert!(
            subscriptions[..4].iter().all(|m| match m {
                OutboundDelegateMsg::SubscribeContractRequest(r) =>
                    r.contract_id.as_bytes() != [9; 32],
                OutboundDelegateMsg::GetContractRequest(r) => r.contract_id.as_bytes() != [9; 32],
                _ => true,
            }),
            "the presence contract goes last"
        );
    }

    /// **The tip read on arming turns instant checkout on at once
    /// (harvest#162)**, instead of waiting for the next block's notification:
    /// the answer is kept, and the arm is told its new status. It is not a
    /// background run, however many reads there are, so the hosted-gateway
    /// notice still rests on real ones. A missing tip keeps nothing but still
    /// answers; a read for a contract no arm names, or one carrying a store
    /// read's context, is not taken for the tip. Every arm reads, re-arms
    /// included. Mutated red by dropping the read from `arm`, by ignoring its
    /// answer, by counting it as a background run, and by not telling the arm.
    #[test]
    fn the_tip_read_on_arming_is_kept_but_is_not_a_background_run() {
        use freenet_bitcoin_common::{BlockHash, SignedTipEntry, TipEntryBody};
        let bridge = SigningKey::from_bytes(&[0x77; 32]);
        let entry = SignedTipEntry::sign(
            &bridge,
            &TipEntryBody {
                network: BitcoinNetwork::Signet,
                anchor: BlockAnchor {
                    height: 2_000,
                    hash: BlockHash([9; 32]),
                },
                prev_hash: BlockHash([0; 32]),
                block_time: (NOW / 1000) as u32 - 300,
                tx_count: 1,
                median_time: (NOW / 1000) as u32 - 900,
            },
        )
        .unwrap();
        let mut tip = BitcoinTipStateV1::default();
        tip.blocks.blocks.insert(2_000, entry);
        let tip = freenet_bitcoin_common::to_cbor(&tip).unwrap();

        let mut f = fixture();
        crate::secrets::RemovableSecrets::remove_secret(
            &mut f.secrets,
            &tip_key(BitcoinNetwork::Signet),
        );
        let arm_status = |f: &mut Fixture| {
            let (response, out) = arm(&mut f.secrets, f.record.arm.clone(), NOW);
            assert!(
                out.iter()
                    .any(|m| matches!(m, OutboundDelegateMsg::GetContractRequest(_))),
                "every arm reads the tip"
            );
            let HarvestDelegateResponse::AutoInvoice {
                result: Ok(status), ..
            } = response
            else {
                panic!("{response:?}")
            };
            status
        };
        let store_id = f.record.arm.store_contract_id.clone();
        let told = |out: Vec<OutboundDelegateMsg>| -> AutoInvoiceStatus {
            let [OutboundDelegateMsg::ApplicationMessage(m)] = out.as_slice() else {
                panic!("{out:?}")
            };
            let HarvestDelegateResponse::AutoInvoice {
                store_contract_id,
                result: Ok(status),
            } = from_cbor(&m.payload).unwrap()
            else {
                panic!()
            };
            assert_eq!(store_contract_id, store_id, "told for its own store");
            status
        };
        assert!(arm_status(&mut f).paused.is_some(), "no tip yet");

        assert!(on_get_answer(&mut f.secrets, &[0x44; 32], Some(&tip), &[], NOW).is_none());
        assert!(
            on_get_answer(&mut f.secrets, &[3; 32], Some(&tip), &[1, 2, 3], NOW).is_none(),
            "a context is not a tip read"
        );
        let missing = told(on_get_answer(&mut f.secrets, &[3; 32], None, &[], NOW).unwrap());
        assert!(missing.paused.is_some(), "a missing tip keeps nothing");

        let read = told(on_get_answer(&mut f.secrets, &[3; 32], Some(&tip), &[], NOW).unwrap());
        assert_eq!(read.paused, None, "on at once, and told");
        assert_eq!(read.last_background_run_ms, None, "not a background run");
        on_get_answer(&mut f.secrets, &[3; 32], Some(&tip), &[], NOW + 3).unwrap();
        assert_eq!(
            arm_status(&mut f).last_background_run_ms,
            None,
            "nor is a second"
        );

        on_notification(&mut f.secrets, &[3; 32], &tip, NOW + 5);
        assert_eq!(arm_status(&mut f).last_background_run_ms, Some(NOW + 5));
        // A later read keeps the background run it had.
        on_get_answer(&mut f.secrets, &[3; 32], Some(&tip), &[], NOW + 9).unwrap();
        assert_eq!(arm_status(&mut f).last_background_run_ms, Some(NOW + 5));

        // Every arm naming the tip is told.
        let mut other = f.record.arm.clone();
        other.store_contract_id = vec![9; 32];
        arm(&mut f.secrets, other, NOW);
        let both = on_get_answer(&mut f.secrets, &[3; 32], Some(&tip), &[], NOW + 11).unwrap();
        let mut stores: Vec<Vec<u8>> = both
            .iter()
            .map(|m| {
                let OutboundDelegateMsg::ApplicationMessage(m) = m else {
                    panic!("{m:?}")
                };
                let HarvestDelegateResponse::AutoInvoice {
                    store_contract_id, ..
                } = from_cbor(&m.payload).unwrap()
                else {
                    panic!()
                };
                store_contract_id
            })
            .collect();
        stores.sort();
        assert_eq!(
            stores,
            vec![vec![1; 32], vec![9; 32]],
            "each told for its own"
        );

        // A store change the delegate acts on is a background run too.
        crate::secrets::RemovableSecrets::remove_secret(&mut f.secrets, RAN_KEY);
        on_notification(
            &mut f.secrets,
            &[1; 32],
            &to_cbor(&f.store).unwrap(),
            NOW + 13,
        );
        assert_eq!(load::<_, u64>(&f.secrets, RAN_KEY), Some(NOW + 13));
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
            store_contract_id: Vec::new(),
            retry: Vec::new(),
            orders: Vec::new(),
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

    /// A store update the store refused leaves the requests it answered
    /// undecided again, so the next run answers them instead of leaving the
    /// buyers waiting for good; one that landed does not. Mutated red by
    /// dropping the forgetting.
    #[test]
    fn a_refused_store_update_leaves_its_requests_to_be_decided_again() {
        let mut f = fixture();
        let buyer = Buyer::new(40);
        let entry = buyer.request(&jam(), 1, 1, 12_000);
        let decided = run(&mut f, std::slice::from_ref(&entry));
        assert_eq!(decided.orders.len(), 1);
        let out = decided.into_messages(&f.record.arm);
        let [OutboundDelegateMsg::UpdateContractRequest(update)] = out.as_slice() else {
            panic!("{out:?}")
        };
        let context = update.context.as_ref().to_vec();
        let seen = |f: &Fixture| {
            load_ledger(&f.secrets, &f.record.arm.store_contract_id)
                .seen
                .contains(&entry_digest(&entry))
        };
        assert!(seen(&f));
        on_store_update_answer(&mut f.secrets, &Ok(()), &context);
        assert!(seen(&f), "landed: stays decided");
        on_store_update_answer(&mut f.secrets, &Err("refused".into()), &context);
        assert!(!seen(&f), "refused: decided again");
        let ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        assert!(ledger.retry_pending, "waits for a run");
        // And it is: the next run answers it.
        let again = run(&mut f, &[entry]);
        assert_eq!(again.orders.len(), 1, "{:?}", again.refused);
    }

    /// The requests a mailbox run put into its batch.
    fn batched(out: &[OutboundDelegateMsg]) -> Vec<EncryptedMessage> {
        match out {
            [] => Vec::new(),
            [OutboundDelegateMsg::GetContractRequest(get)] => {
                from_cbor::<PendingBatch>(get.context.as_ref())
                    .unwrap()
                    .entries
            }
            other => panic!("{other:?}"),
        }
    }

    fn flag(f: &Fixture) -> Option<Vec<u8>> {
        f.secrets
            .get_secret(&retry_key(&f.record.arm.store_contract_id))
    }

    /// #206: a buyer's request behind a pile of an attacker's own valid
    /// instant requests, all dated earlier and all opened in one run, still
    /// gets batch slots: the batch is chosen in the run's random order, not
    /// by the date the writer chose. 40 such requests against 16 slots, so
    /// about two seeds in five batch the buyer's (at least 4 of 64 is
    /// asserted: the digests carry a random nonce, and fewer comes about
    /// once in five billion runs); oldest first, none would. Mutated red by
    /// choosing the batch oldest first.
    #[test]
    fn a_request_behind_older_valid_requests_gets_a_batch_slot() {
        let attacker = Buyer::new(77);
        let buyer = Buyer::new(40);
        let real = buyer.request(&jam(), 1, 1, 12_000);
        let mut messages: Vec<EncryptedMessage> = (0..40u8)
            .map(|n| attacker.request_at(&jam(), 1, n, 12_000, NOW - 23 * 3_600_000))
            .collect();
        messages.push(real.clone());
        let state = to_cbor(&MailboxStateV1 { messages }).unwrap();
        let mut reached = 0;
        for seed in 0..64u8 {
            let mut f = fixture();
            let batch = batched(&on_mailbox_ordered(
                &mut f.secrets,
                &f.record.clone(),
                &state,
                NOW,
                [seed; 32],
            ));
            assert_eq!(batch.len(), MAX_BATCH, "seed {seed}");
            assert!(
                batch.windows(2).all(|w| w[0].timestamp <= w[1].timestamp),
                "decided oldest first"
            );
            reached += usize::from(batch.contains(&real));
        }
        assert!(
            reached >= 4,
            "the buyer's request reached {reached} of 64 batches"
        );
    }

    /// #206: the mailbox run takes its order from the node's randomness:
    /// two runs over the same backlog open different messages. Mutated red
    /// by a fixed seed.
    #[test]
    fn each_mailbox_run_draws_its_own_order() {
        assert_ne!(random_seed(), random_seed());
        let messages: Vec<EncryptedMessage> = (0..400).map(|i| junk(i, 600)).collect();
        let state = to_cbor(&MailboxStateV1 { messages }).unwrap();
        let opened = || {
            let mut f = fixture();
            on_mailbox(&mut f.secrets, &f.record.clone(), &state, NOW);
            load_ledger(&f.secrets, &f.record.arm.store_contract_id).seen
        };
        assert_ne!(opened(), opened());
    }

    /// #206: requests opened but left out of a full batch are still waiting,
    /// so the run keeps the retry flag, including one a refused update set
    /// before it. Mutated red by not counting the unbatched as backlog.
    #[test]
    fn requests_left_out_of_a_full_batch_keep_the_retry() {
        let mut f = fixture();
        let mut ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        ledger.retry_pending = true;
        save_ledger(&mut f.secrets, &f.record.arm.store_contract_id, &ledger);
        let messages: Vec<EncryptedMessage> = (0..20u8)
            .map(|n| Buyer::new(40).request(&jam(), 1, n, 12_000))
            .collect();
        let state = to_cbor(&MailboxStateV1 { messages }).unwrap();
        let batch = batched(&on_mailbox(&mut f.secrets, &f.record.clone(), &state, NOW));
        assert_eq!(batch.len(), MAX_BATCH);
        assert!(load_ledger(&f.secrets, &f.record.arm.store_contract_id).retry_pending);
        assert_eq!(flag(&f).as_deref(), Some(b"1".as_slice()));
        assert_eq!(mailbox_retries(&f.secrets, NOW).len(), 1);
    }

    /// #206: an instant request older than the day `decide` answers is
    /// settled as seen when opened, rather than reopened by every run and
    /// holding a batch slot. Mutated red by batching it.
    #[test]
    fn an_expired_request_is_seen_not_batched() {
        let mut f = fixture();
        let old = Buyer::new(40).request_dated(
            &jam(),
            1,
            1,
            12_000,
            NOW - REQUEST_MAX_AGE_MS - 1,
            NOW - 5_000,
        );
        let state = to_cbor(&MailboxStateV1 {
            messages: vec![old.clone()],
        })
        .unwrap();
        // Within the mailbox's own age, so the run looks at it at all.
        assert!(within_age(&old, NOW));
        assert!(batched(&on_mailbox(&mut f.secrets, &f.record.clone(), &state, NOW)).is_empty());
        assert!(load_ledger(&f.secrets, &f.record.arm.store_contract_id)
            .seen
            .contains(&entry_digest(&old)));
    }

    /// The wake-up reads a waiting mailbox only when the store can take
    /// orders: not with a tip too old, nor while it is turned away for a
    /// reason only the seller lifts; the flag is kept for when it can.
    /// Mutated red by dropping the refusal filter.
    #[test]
    fn the_wakeup_reads_a_waiting_mailbox_only_when_a_run_could_answer() {
        let mut f = fixture();
        let mut ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        ledger.retry_pending = true;
        save_ledger(&mut f.secrets, &f.record.arm.store_contract_id, &ledger);
        assert_eq!(mailbox_retries(&f.secrets, NOW).len(), 1, "taking orders");
        let tip: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
        let mut old = tip.clone();
        old.block_time = 1;
        save(&mut f.secrets, &tip_key(BitcoinNetwork::Signet), &old);
        assert!(mailbox_retries(&f.secrets, NOW).is_empty(), "a stale tip");
        save(&mut f.secrets, &tip_key(BitcoinNetwork::Signet), &tip);
        assert_eq!(
            mailbox_retries(&f.secrets, NOW).len(),
            1,
            "a fresh tip again"
        );
        let mut lapsed = f.record.clone();
        lapsed.watched_until_ms = 0;
        lapsed.arm.watch_left_ms = 0;
        lapsed.arm.watched_scripts.clear();
        save(
            &mut f.secrets,
            &arm_key(&lapsed.arm.store_contract_id),
            &lapsed,
        );
        assert!(
            global_refusal(&f.secrets, &lapsed, Some(&tip), NOW).is_err(),
            "the fixture is lapsed"
        );
        assert!(mailbox_retries(&f.secrets, NOW).is_empty(), "lapsed");
    }

    /// A refused store update reaches the wake-up through the flag; the run
    /// it starts keeps the flag while its batch waits on the store GET (a GET
    /// that fails leaves it set) and after (a batch cannot tell what else
    /// waits), and the next read of the whole mailbox settles it. Mutated
    /// red by saving that ledger without its flag, by clearing the flag when
    /// the batch is sent or decided, and by not settling it.
    #[test]
    fn a_refused_update_reaches_the_wakeup_and_its_run_clears_it() {
        let mut f = fixture();
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        let decided = run(&mut f, std::slice::from_ref(&entry));
        let out = decided.into_messages(&f.record.arm);
        let [OutboundDelegateMsg::UpdateContractRequest(update)] = out.as_slice() else {
            panic!("{out:?}")
        };
        let context = update.context.as_ref().to_vec();
        on_store_update_answer(&mut f.secrets, &Err("refused".into()), &context);
        let retries = mailbox_retries(&f.secrets, NOW);
        let [OutboundDelegateMsg::GetContractRequest(get)] = retries.as_slice() else {
            panic!("{retries:?}")
        };
        let state = to_cbor(&MailboxStateV1 {
            messages: vec![entry],
        })
        .unwrap();
        let context: MailboxRetry = from_cbor(get.context.as_ref()).unwrap();
        let out = on_mailbox_retry(
            &mut f.secrets,
            &context.store_contract_id,
            Some(&state),
            NOW,
        );
        assert_eq!(batched(&out).len(), 1, "the request is batched again");
        assert_eq!(
            flag(&f).as_deref(),
            Some(b"1".as_slice()),
            "while in flight"
        );
        let [OutboundDelegateMsg::GetContractRequest(store_get)] = out.as_slice() else {
            panic!("{out:?}")
        };
        let batch = store_get.context.as_ref().to_vec();
        // The store GET fails: still waiting.
        on_store_state(&mut f.secrets, None, &batch, NOW).unwrap();
        assert_eq!(flag(&f).as_deref(), Some(b"1".as_slice()), "a failed GET");
        assert_eq!(mailbox_retries(&f.secrets, NOW).len(), 1);
        // It answers: decided. The flag waits for a read of the whole
        // mailbox, which alone can tell nothing else waits.
        let store = to_cbor(&f.store).unwrap();
        let answered = on_store_state(&mut f.secrets, Some(&store), &batch, NOW).unwrap();
        assert!(!answered.is_empty(), "the request is decided");
        assert_eq!(flag(&f).as_deref(), Some(b"1".as_slice()));
        let out = on_mailbox_retry(
            &mut f.secrets,
            &context.store_contract_id,
            Some(&state),
            NOW,
        );
        assert!(out.is_empty(), "nothing left to batch");
        assert_eq!(flag(&f).as_deref(), Some(b"0".as_slice()));
        assert!(mailbox_retries(&f.secrets, NOW).is_empty());
    }

    /// A flag left saying "waiting" by an earlier failure is put right by
    /// the next run that reads the ledger, even one with nothing to write.
    /// Mutated red by syncing only on a write.
    #[test]
    fn a_wrong_flag_is_put_right_by_the_next_run() {
        let mut f = fixture();
        f.secrets
            .set_secret(&retry_key(&f.record.arm.store_contract_id), b"1");
        let state = to_cbor(&MailboxStateV1::default()).unwrap();
        on_mailbox(&mut f.secrets, &f.record.clone(), &state, NOW);
        assert_eq!(flag(&f).as_deref(), Some(b"0".as_slice()));
    }

    /// A pending flag is written before its ledger and a cleared one after,
    /// so a ledger write that fails (or a call stopped between the two)
    /// leaves the flag erring toward a retry. The save answers whether the
    /// LEDGER was saved, and a flag the host refused is answered by the
    /// ledger. Mutated red by writing a pending flag after the ledger, by
    /// clearing one before it, and by reading a missing flag as nothing
    /// waiting.
    #[test]
    fn a_pending_flag_is_written_before_its_ledger() {
        let pending = Ledger {
            retry_pending: true,
            ..Default::default()
        };
        let mut secrets = MemSecrets::default();
        assert!(save_ledger(&mut secrets, &[1; 32], &pending));
        assert_eq!(
            secrets.write_log,
            vec![retry_key(&[1; 32]), ledger_key(&[1; 32])]
        );
        let mut secrets = MemSecrets::default();
        secrets.set_secret(&retry_key(&[1; 32]), b"1");
        secrets.write_log.clear();
        assert!(save_ledger(&mut secrets, &[1; 32], &Ledger::default()));
        assert_eq!(
            secrets.write_log,
            vec![ledger_key(&[1; 32]), retry_key(&[1; 32])]
        );
        // The ledger refused: a pending flag stands, a cleared one is kept.
        let mut secrets = MemSecrets::refusing_writes_under(ledger_key(&[1; 32]));
        assert!(!save_ledger(&mut secrets, &[1; 32], &pending));
        assert_eq!(
            secrets.get_secret(&retry_key(&[1; 32])).as_deref(),
            Some(b"1".as_slice())
        );
        assert!(!save_ledger(&mut secrets, &[1; 32], &Ledger::default()));
        assert_eq!(
            secrets.get_secret(&retry_key(&[1; 32])).as_deref(),
            Some(b"1".as_slice())
        );
        // The flag refused: the ledger is saved, and the wake-up finds it.
        let mut f = fixture();
        let id = f.record.arm.store_contract_id.clone();
        let mut secrets = MemSecrets::refusing_writes_under(retry_key(&id));
        for (key, value) in f.secrets.list_secrets(b"").into_iter().map(|k| {
            let v = f.secrets.get_secret(&k).unwrap();
            (k, v)
        }) {
            secrets.set_secret(&key, &value);
        }
        f.secrets = secrets;
        assert!(save_ledger(&mut f.secrets, &id, &pending));
        assert!(f.secrets.get_secret(&retry_key(&id)).is_none());
        assert_eq!(mailbox_retries(&f.secrets, NOW).len(), 1);
    }

    /// A batch partly decided (a store-wide stop part way: no watched
    /// address left for the second request) keeps the flag, so the wake-up
    /// comes back for the rest; a key lost meanwhile is written again by
    /// the save `decide` makes. Mutated red by clearing the flag once a
    /// batch is decided.
    #[test]
    fn a_batch_decided_part_way_keeps_the_retry() {
        let mut f = fixture();
        f.record.arm.watched_scripts.truncate(1);
        save(
            &mut f.secrets,
            &arm_key(&f.record.arm.store_contract_id),
            &f.record,
        );
        let state = to_cbor(&MailboxStateV1 {
            messages: vec![
                Buyer::new(40).request(&jam(), 1, 1, 12_000),
                Buyer::new(41).request(&jam(), 1, 1, 12_000),
            ],
        })
        .unwrap();
        let out = on_mailbox(&mut f.secrets, &f.record.clone(), &state, NOW);
        let [OutboundDelegateMsg::GetContractRequest(get)] = out.as_slice() else {
            panic!("{out:?}")
        };
        let batch = get.context.as_ref().to_vec();
        // As a failed write would leave it: the key says nothing waits.
        f.secrets
            .set_secret(&retry_key(&f.record.arm.store_contract_id), b"0");
        let store = to_cbor(&f.store).unwrap();
        on_store_state(&mut f.secrets, Some(&store), &batch, NOW).unwrap();
        let ledger = load_ledger(&f.secrets, &f.record.arm.store_contract_id);
        assert_eq!(ledger.seen.len(), 1, "one decided, one left");
        assert_eq!(flag(&f).as_deref(), Some(b"1".as_slice()));
        assert_eq!(mailbox_retries(&f.secrets, NOW).len(), 1);
    }

    /// A ledger held that does not decode is never written over with an
    /// empty one: a mailbox run, a store change, a refused update and a
    /// batch all stop, and the batch is refused rather than invoiced again;
    /// the wake-up stops re-reading the mailbox and the status says why.
    /// Mutated red by reading it as empty.
    #[test]
    fn an_unreadable_ledger_is_never_written_over() {
        let mut f = fixture();
        let id = f.record.arm.store_contract_id.clone();
        f.secrets.set_secret(&ledger_key(&id), b"not a ledger");
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        let state = to_cbor(&MailboxStateV1 {
            messages: vec![entry.clone()],
        })
        .unwrap();
        assert!(on_mailbox(&mut f.secrets, &f.record.clone(), &state, NOW).is_empty());
        let decided = run(&mut f, std::slice::from_ref(&entry));
        assert!(decided.orders.is_empty());
        assert!(decided
            .refused
            .iter()
            .all(|(_, why)| *why == Refusal::LedgerUnreadable));
        assert!(decided.undecided);
        // A refused update of an earlier batch, and a store change.
        let context = to_cbor(&PendingReplies {
            magic: REPLIES_MAGIC,
            mailbox_contract_id: f.record.arm.mailbox_contract_id,
            store_contract_id: id.clone(),
            replies: Vec::new(),
            retry: vec![(entry_digest(&entry), [1; 32])],
            orders: Vec::new(),
        })
        .unwrap();
        on_store_update_answer(&mut f.secrets, &Err("refused".into()), &context);
        let store = to_cbor(&f.store).unwrap();
        on_notification(&mut f.secrets, &[1; 32], &store, NOW);
        assert_eq!(
            f.secrets.get_secret(&ledger_key(&id)).as_deref(),
            Some(b"not a ledger".as_slice())
        );
        // The wake-up does not come back for it, and the seller is told.
        f.secrets.set_secret(&retry_key(&id), b"1");
        on_mailbox(&mut f.secrets, &f.record.clone(), &state, NOW);
        assert_eq!(
            f.secrets.get_secret(&retry_key(&id)).as_deref(),
            Some(b"0".as_slice())
        );
        assert!(mailbox_retries(&f.secrets, NOW).is_empty());
        assert_eq!(
            status_of(&f.secrets, &f.record, NOW).paused,
            Some(Refusal::LedgerUnreadable.explain())
        );
    }

    /// #206: a store whose published orders are far past this device's
    /// counter is refused (`CatchingUp`) while the counter catches up, one
    /// bounded scan a run with the count kept, and the request waits; once
    /// caught up it is invoiced at an address past every published order.
    /// Mutated red by invoicing from a scan left short, and by not keeping
    /// the count.
    #[test]
    fn a_batch_waits_while_the_counter_catches_up() {
        use crate::bitcoin::FLOOR_SCAN_BUDGET;
        let mut f = fixture();
        let last = FLOOR_SCAN_BUDGET + 20;
        unpaid_orders_on(&mut f, 0..last, NOW - 1_000);
        // Paid, so no store limit turns the request away once caught up.
        for order in f.store.orders.orders.values_mut() {
            order.status = OrderStatus::Paid;
        }
        // As the seller's tab watches them: every published address and the
        // ten after.
        f.record.arm.watched_scripts = (0..last + 10).map(script_at).collect();
        save(
            &mut f.secrets,
            &arm_key(&f.record.arm.store_contract_id),
            &f.record,
        );
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        let first = run(&mut f, std::slice::from_ref(&entry));
        assert!(first.orders.is_empty());
        assert!(first
            .refused
            .iter()
            .all(|(_, why)| *why == Refusal::CatchingUp));
        assert!(first.undecided);
        assert_eq!(counter(&f), FLOOR_SCAN_BUDGET, "the count reached is kept");
        let second = run(&mut f, std::slice::from_ref(&entry));
        assert!(
            second
                .refused
                .iter()
                .all(|(_, why)| *why != Refusal::CatchingUp),
            "{:?}",
            second.refused
        );
        assert_eq!(second.orders.len(), 1, "{:?}", second.refused);
        assert_eq!(
            second.orders[0].order.payment_script_pubkey,
            script_at(last)
        );
    }

    /// A fixture whose store has published orders past one call's scan
    /// ([`crate::bitcoin::FLOOR_SCAN_BUDGET`]), all paid, with every
    /// published address and the ten after it watched; and the index the
    /// first invoice gets once caught up.
    fn far_behind_fixture() -> (Fixture, u32) {
        use crate::bitcoin::FLOOR_SCAN_BUDGET;
        let mut f = fixture();
        let last = FLOOR_SCAN_BUDGET + 20;
        unpaid_orders_on(&mut f, 0..last, NOW - 1_000);
        for order in f.store.orders.orders.values_mut() {
            order.status = OrderStatus::Paid;
        }
        f.record.arm.watched_scripts = (0..last + 10).map(script_at).collect();
        save(
            &mut f.secrets,
            &arm_key(&f.record.arm.store_contract_id),
            &f.record,
        );
        (f, last)
    }

    /// The store's status and heartbeat, as one pair.
    fn open_now(f: &Fixture, now: u64) -> (Option<String>, bool) {
        let status = status_of(&f.secrets, &f.record, now);
        (
            status.paused,
            taking_orders(&f.secrets, &f.record, now, &upcoming(&f.secrets)),
        )
    }

    /// #206: a scan whose raised count the node will not keep is refused
    /// `CounterNotSaved`, not `CatchingUp` (which promises the next run goes
    /// on from it), nothing is invoiced, and the store's status and
    /// heartbeat say that, not "catching up". Mutated red by answering
    /// `CatchingUp` whatever the save did, and by marking it as a catch-up.
    #[test]
    fn a_short_scan_whose_count_is_not_kept_says_so() {
        let (mut f, _) = far_behind_fixture();
        f.secrets.refused_prefix = Some(crate::bitcoin::BITCOIN_PAYMENT_XPUB_KEY.to_vec());
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        let decided = run(&mut f, std::slice::from_ref(&entry));
        assert!(decided.orders.is_empty());
        assert!(!decided.refused.is_empty());
        assert!(
            decided
                .refused
                .iter()
                .all(|(_, why)| *why == Refusal::CounterNotSaved),
            "{:?}",
            decided.refused
        );
        assert!(decided.undecided);
        assert_eq!(counter(&f), 0, "nothing was kept");
        assert_eq!(
            open_now(&f, NOW),
            (Some(Refusal::CounterNotSaved.explain()), false)
        );
    }

    /// #206: while `decide` is catching the counter up, the store's status
    /// says so (`paused`) and its heartbeat does not read as taking orders;
    /// once a scan completes, both go back. A mark nothing renews stops
    /// counting after `CATCHING_UP_SHOWN_MS`. And it is never a refusal that
    /// stops `decide` (the second run catches up and invoices). Mutated red
    /// by not reading the mark in `status_in`, in `taking_orders_in`, by not
    /// clearing it when the scan completes, by checking it in
    /// `refusal_given`, and by not letting it lapse.
    #[test]
    fn the_status_and_heartbeat_say_when_instant_checkout_is_catching_up() {
        let (mut f, last) = far_behind_fixture();
        assert_eq!(open_now(&f, NOW), (None, true), "taking orders before");
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        let first = run(&mut f, std::slice::from_ref(&entry));
        assert!(first.orders.is_empty());
        assert_eq!(
            open_now(&f, NOW),
            (Some(Refusal::CatchingUp.explain()), false),
            "catching up"
        );
        let mark = catchup_key(&f.record.arm.store_contract_id);
        let held: CatchUpMark = load::<_, Option<CatchUpMark>>(&f.secrets, &mark)
            .flatten()
            .expect("marked");
        save(
            &mut f.secrets,
            &mark,
            &Some(CatchUpMark {
                at_ms: NOW - CATCHING_UP_SHOWN_MS,
                ..held.clone()
            }),
        );
        assert_eq!(open_now(&f, NOW), (None, true), "a mark nothing renewed");
        save(&mut f.secrets, &mark, &Some(held));
        let second = run(&mut f, std::slice::from_ref(&entry));
        assert_eq!(second.orders.len(), 1, "{:?}", second.refused);
        assert_eq!(
            second.orders[0].order.payment_script_pubkey,
            script_at(last)
        );
        assert_eq!(open_now(&f, NOW).0, None, "caught up");
        assert_eq!(
            load::<_, Option<CatchUpMark>>(&f.secrets, &mark),
            Some(None),
            "cleared"
        );
    }

    /// #206 review: what `decide` records as fed is the held list's own
    /// generation. A count written while the list's write was refused names
    /// a generation the list never had; were that recorded, a later real
    /// one (an eviction taking this store's scripts) would match it and the
    /// store would not be fed again. Mutated red by recording the count's
    /// generation.
    #[test]
    fn what_was_fed_is_the_lists_own_generation() {
        use crate::published_set::{digest, DigestList, PUBLISHED_KEY};
        let mut f = fixture();
        unpaid_orders_on(&mut f, 0..3, NOW - 1_000);
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        run(&mut f, std::slice::from_ref(&entry));
        // A tab's addition whose list write the node refuses, after the
        // count was written: count G+1, list G.
        let held = DigestList::load(&f.secrets, PUBLISHED_KEY).unwrap();
        let generation = held.generation();
        f.secrets.refused_prefix = Some(PUBLISHED_KEY.to_vec());
        assert!(crate::bitcoin::add_published(&mut f.secrets, &[vec![0x51, 0x20, 7]]).is_err());
        assert_eq!(
            crate::published_set::published_meta(&f.secrets).map(|(g, _)| g),
            Some(generation + 1)
        );
        f.secrets.refused_prefix = None;
        run(&mut f, std::slice::from_ref(&entry));
        // A real G+1 that lost this store's scripts (an eviction).
        let mut list = DigestList::empty();
        let mut n = 0u32;
        while list.generation() < generation + 1 {
            list.insert(&[digest(&n.to_le_bytes())]);
            n += 1;
        }
        assert_eq!(list.generation(), generation + 1);
        crate::published_set::save_published(&mut f.secrets, &list);
        assert!(!DigestList::load(&f.secrets, PUBLISHED_KEY)
            .unwrap()
            .contains(&digest(&script_at(0))));
        run(&mut f, std::slice::from_ref(&entry));
        assert!(
            DigestList::load(&f.secrets, PUBLISHED_KEY)
                .unwrap()
                .contains(&digest(&script_at(0))),
            "fed again"
        );
    }

    /// #206 review: a held published list the node will not write, or one
    /// that does not read, refuses the batch `CounterNotSaved` and invoices
    /// nothing; the status says so. Mutated red by going on when the
    /// scripts are not held.
    #[test]
    fn scripts_that_cannot_be_held_refuse_the_batch() {
        for unreadable in [false, true] {
            let mut f = fixture();
            unpaid_orders_on(&mut f, 0..3, NOW - 1_000);
            if unreadable {
                f.secrets
                    .set_secret(crate::published_set::PUBLISHED_KEY, b"\x07garbage");
            } else {
                f.secrets.refused_prefix = Some(b"harvest:bitcoin:published".to_vec());
            }
            let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
            let decided = run(&mut f, std::slice::from_ref(&entry));
            assert!(decided.orders.is_empty(), "unreadable: {unreadable}");
            assert!(
                decided
                    .refused
                    .iter()
                    .all(|(_, why)| *why == Refusal::CounterNotSaved),
                "{:?}",
                decided.refused
            );
            assert_eq!(counter(&f), 0);
            assert_eq!(
                open_now(&f, NOW).0,
                Some(Refusal::CounterNotSaved.explain())
            );
        }
    }

    /// #206 (D3): a mark `decide` left is ignored once the catch-up it was
    /// about is over by another path: the active key's scan completed by a
    /// tab's request (or another store's `decide`, or a wake-up), or the
    /// active key changed. Mutated red by reading the mark alone.
    #[test]
    fn a_catch_up_mark_lapses_when_another_path_finishes_it() {
        let (mut f, _) = far_behind_fixture();
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        run(&mut f, std::slice::from_ref(&entry));
        assert_eq!(open_now(&f, NOW).0, Some(Refusal::CatchingUp.explain()));
        // Finished elsewhere, as a tab's address request would.
        let mut status = crate::bitcoin::load_payment_xpub(&f.secrets).unwrap();
        while !crate::bitcoin::advance_scan(
            &mut f.secrets,
            crate::bitcoin::Slot::Active,
            &mut status,
            crate::bitcoin::FLOOR_SCAN_BUDGET,
        )
        .unwrap()
        .complete
        {}
        assert_eq!(open_now(&f, NOW), (None, true), "completed elsewhere");

        // Another key made active: the mark is about a key no longer used.
        let (mut g, _) = far_behind_fixture();
        run(&mut g, std::slice::from_ref(&entry));
        assert_eq!(open_now(&g, NOW).0, Some(Refusal::CatchingUp.explain()));
        let mut other = crate::bitcoin::load_payment_xpub(&g.secrets).unwrap();
        other.xpub = format!(" {}", other.xpub);
        crate::bitcoin::save_payment_xpub(&mut g.secrets, &other).unwrap();
        assert_ne!(open_now(&g, NOW).0, Some(Refusal::CatchingUp.explain()));
    }

    /// A store's state with some paid orders carrying genuine SPV proofs
    /// and signatures, others awaiting payment or cancelled, listing
    /// statuses, a closing, and fields instant checkout does not read.
    fn a_full_store(f: &Fixture) -> StoreStateV1 {
        let mut store = f.store.clone();
        for n in 0..12u16 {
            let order = crate::kept_purchases::fixtures::order(n, 1);
            let mut signed = sign_order(&store_sk(), order).unwrap();
            match n % 3 {
                0 => {
                    signed.status = OrderStatus::Paid;
                    signed.payment_proof = Some(crate::kept_purchases::fixtures::proof(
                        &signed.order,
                        n as u8,
                    ));
                }
                1 => {
                    signed.status = OrderStatus::Cancelled;
                    signed.status_scoped_payload = Some(vec![7; 40]);
                    signed.status_signature = Some(vec![8; 64]);
                }
                _ => {}
            }
            store.orders.orders.insert(signed.order.id.clone(), signed);
        }
        store.info.scoped_payload = vec![1, 2, 3];
        store
    }

    /// What instant checkout reads of a store, from a whole decode: the
    /// fields it uses, each order's terms and status, nothing else.
    fn what_decide_reads(store: &StoreStateV1) -> StoreStateV1 {
        let mut orders = store.orders.clone();
        for o in orders.orders.values_mut() {
            o.scoped_payload.clear();
            o.signature.clear();
            o.payment_proof = None;
            o.status_scoped_payload = None;
            o.status_signature = None;
        }
        StoreStateV1 {
            owner: store.owner,
            listings: store.listings.clone(),
            orders,
            listing_statuses: store.listing_statuses.clone(),
            closed: store.closed.clone(),
            ..Default::default()
        }
    }

    /// #206: the light read of a store is exactly what a whole decode gives
    /// for every field instant checkout uses, over stores with genuine SPV
    /// proofs and signatures, and declines what is not a store (falling back
    /// to the whole decode). `decide` reaches the same outcome from it.
    /// Mutated red by reading an order's status from the wrong field, and
    /// by dropping a used field.
    #[test]
    fn the_light_store_read_is_what_decide_reads_of_the_whole() {
        let f = fixture();
        let store = a_full_store(&f);
        assert!(store
            .orders
            .orders
            .values()
            .any(|o| o.payment_proof.is_some()));
        let bytes = to_cbor(&store).unwrap();
        let light = crate::fast_cbor::decode_store_light(&bytes).expect("a store");
        let whole: StoreStateV1 = from_cbor(&bytes).unwrap();
        assert_eq!(light, what_decide_reads(&whole));
        assert_eq!(read_store(&bytes), Some(light.clone()));
        // An empty store, and one with no orders key.
        let empty = to_cbor(&StoreStateV1::default()).unwrap();
        assert_eq!(
            crate::fast_cbor::decode_store_light(&empty),
            Some(what_decide_reads(&StoreStateV1::default()))
        );
        // Not a store: declined, and the whole decode answers.
        assert_eq!(crate::fast_cbor::decode_store_light(b"\x01"), None);
        assert_eq!(read_store(b"\x01"), None);
        // decide from the light read and from the whole: the same.
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        let mut a = fixture();
        a.store = light;
        let mut b = fixture();
        b.store = whole;
        let (da, db) = (
            run(&mut a, std::slice::from_ref(&entry)),
            run(&mut b, std::slice::from_ref(&entry)),
        );
        assert_eq!(da.orders.len(), db.orders.len());
        assert_eq!(
            da.orders.iter().map(|o| &o.order).collect::<Vec<_>>(),
            db.orders.iter().map(|o| &o.order).collect::<Vec<_>>()
        );
        assert_eq!(da.refused, db.refused);
        assert_eq!(counter(&a), counter(&b));
    }

    /// The paid-scripts record as `note_paid_scripts` kept it before #206,
    /// kept verbatim as the reference: a scan of `held` per order.
    fn note_paid_scripts_scanning(held: &mut Vec<(i64, Vec<u8>)>, store: &StoreStateV1) -> bool {
        let mut changed = false;
        for order in store.orders.orders.values() {
            let script = &order.order.payment_script_pubkey;
            if order.status == OrderStatus::Paid
                && !script.is_empty()
                && !held.iter().any(|(_, s)| s == script)
            {
                held.push((order.order.created_at.timestamp_millis(), script.clone()));
                changed = true;
            }
        }
        if changed {
            held.sort();
            let excess = held.len().saturating_sub(PAID_SCRIPTS_CAP);
            held.drain(..excess);
        }
        changed
    }

    /// #206: `note_paid_scripts` with a set is the scanning one, over
    /// records with scripts already held, repeated scripts across orders,
    /// empty scripts, unpaid orders, and past the cap. Mutated red by
    /// counting a repeated script twice.
    #[test]
    fn note_paid_scripts_is_the_scanning_one() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for round in 0..20 {
            let mut f = fixture();
            let held: Vec<(i64, Vec<u8>)> = (0..next(40))
                .map(|i| (i as i64, vec![0x00, 0x14, (next(300) % 256) as u8, i as u8]))
                .collect();
            save(&mut f.secrets, PAID_SCRIPTS_KEY, &held);
            let count = if round % 5 == 0 {
                PAID_SCRIPTS_CAP + 50
            } else {
                1 + next(80) as usize
            };
            for i in 0..count {
                let script = match next(10) {
                    0 => Vec::new(),
                    1 => held.first().map_or(vec![1], |(_, s)| s.clone()),
                    2 => vec![0x00, 0x14, 0xee, (i % 3) as u8],
                    _ => vec![0x00, 0x14, (i >> 8) as u8, i as u8, 0xaa],
                };
                let mut o = order_on(script);
                o.created_at =
                    chrono::DateTime::from_timestamp_millis(1_700_000_000_000 + i as i64).unwrap();
                o.request_id = Some([(i % 251) as u8; 32]);
                let mut o = sign_order(&store_sk(), o.with_derived_id()).unwrap();
                o.status = if next(4) == 0 {
                    OrderStatus::AwaitingPayment
                } else {
                    OrderStatus::Paid
                };
                f.store.orders.orders.insert(o.order.id.clone(), o);
            }
            let mut want = held.clone();
            let changed = note_paid_scripts_scanning(&mut want, &f.store);
            note_paid_scripts(&mut f.secrets, &f.store);
            let got = paid_scripts(&f.secrets);
            if changed {
                assert_eq!(got, want, "round {round}");
            } else {
                assert_eq!(got, held, "round {round}");
            }
        }
    }

    /// #206: `decide` feeds a store's scripts to the held list once, and
    /// again only when they change or the held list does (an eviction
    /// changes its generation): a store whose held scripts were lost is fed
    /// again, not skipped. Mutated red by skipping on the scripts alone, and
    /// by feeding every run.
    #[test]
    fn a_store_is_fed_again_when_the_held_list_changed() {
        use crate::published_set::{digest, DigestList, PUBLISHED_KEY};
        let mut f = fixture();
        unpaid_orders_on(&mut f, 0..3, NOW - 1_000);
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        run(&mut f, std::slice::from_ref(&entry));
        let held = |f: &Fixture| DigestList::load(&f.secrets, PUBLISHED_KEY).unwrap();
        assert!(held(&f).contains(&digest(&script_at(0))));
        let writes = f.secrets.write_log.len();
        let looked_up = f.secrets.reads_under(PUBLISHED_KEY);
        run(&mut f, std::slice::from_ref(&entry));
        assert!(
            !f.secrets.write_log[writes..]
                .iter()
                .any(|k| k.as_slice() == PUBLISHED_KEY),
            "nothing new, nothing written"
        );
        assert_eq!(
            f.secrets.reads_under(PUBLISHED_KEY),
            looked_up + 2,
            "read twice (its generation, and the scan): the same scripts are not added again"
        );
        // The held list lost them (as an eviction would), at a later
        // generation.
        let mut emptied = DigestList::empty();
        emptied.insert(&[digest(b"elsewhere")]);
        emptied.insert(&[digest(b"elsewhere too")]);
        crate::published_set::save_published(&mut f.secrets, &emptied);
        run(&mut f, std::slice::from_ref(&entry));
        assert!(held(&f).contains(&digest(&script_at(0))), "fed again");
    }

    /// Each whole-store refusal, as `global_refusal` gives it: the exact
    /// reason, in the order checked. Mutated red by dropping or reordering a
    /// check.
    #[test]
    fn every_whole_store_refusal_is_the_one_it_says() {
        let refusal = |f: &Fixture| {
            let tip: Option<TipCache> = load(&f.secrets, &tip_key(BitcoinNetwork::Signet));
            global_refusal(&f.secrets, &f.record, tip.as_ref(), NOW)
        };
        assert!(refusal(&fixture()).is_ok());
        let mut f = fixture();
        f.record.arm.store_verifying_key = [0x42; 32];
        assert_eq!(refusal(&f), Err(Refusal::NoStoreKey));
        // Neither a store key nor a payment key: the store key is asked first.
        let mut f = fixture();
        f.record.arm.store_verifying_key = [0x42; 32];
        f.secrets = {
            let mut s = MemSecrets::default();
            let tip: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
            save(&mut s, &tip_key(BitcoinNetwork::Signet), &tip);
            s
        };
        assert_eq!(refusal(&f), Err(Refusal::NoStoreKey), "both missing");
        let mut f = fixture();
        f.secrets = {
            let mut s = MemSecrets::default();
            crate::store_keys::keep(&mut s, &store_sk());
            let tip: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
            save(&mut s, &tip_key(BitcoinNetwork::Signet), &tip);
            s
        };
        assert_eq!(refusal(&f), Err(Refusal::NoPaymentKey));
        let mut f = fixture();
        let mut other = f.record.clone();
        other.arm.network = BitcoinNetwork::Testnet4;
        let tip: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
        save(&mut f.secrets, &tip_key(BitcoinNetwork::Testnet4), &tip);
        f.record = other;
        assert_eq!(refusal(&f), Err(Refusal::NetworkMismatch));
        let mut f = fixture();
        let mut old: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
        old.block_time = 1;
        save(&mut f.secrets, &tip_key(BitcoinNetwork::Signet), &old);
        assert_eq!(refusal(&f), Err(Refusal::NoFreshTip));
        let mut f = fixture();
        f.record.watched_until_ms = 0;
        f.record.arm.watch_left_ms = 0;
        assert_eq!(refusal(&f), Err(Refusal::WatchLapsed));
        let f = fixture();
        assert_eq!(
            global_refusal(&f.secrets, &f.record, None, NOW),
            Err(Refusal::NoFreshTip),
            "no tip"
        );
    }

    /// A Buy now sent under a twin of the buyer's tag (bit 255 set, or the
    /// tag plus a small-torsion point) opens with the buyer's own keys, so
    /// whoever holds them could place it; it is not taken as a request, and nothing
    /// is invoiced to it (harvest#205 review, S1). The buyer's own tag still
    /// is. Mutated red by dropping the check in `open_instant`.
    #[test]
    fn a_request_under_a_twin_of_the_buyers_tag_is_not_opened() {
        let buyer = Buyer::new(40);
        let real = buyer.tag();
        let mut twins = Vec::new();
        let mut high = real;
        high[31] |= 0x80;
        twins.push(high);
        let point = curve25519_dalek::montgomery::MontgomeryPoint(real)
            .to_edwards(0)
            .unwrap();
        for torsion in curve25519_dalek::constants::EIGHT_TORSION.iter().skip(1) {
            twins.push((point + torsion).to_montgomery().to_bytes());
        }
        for (i, twin) in twins.iter().enumerate() {
            let mut f = fixture();
            let entry = buyer.request_under(twin, &jam(), 1, 1, 12_000, NOW - 5_000, NOW - 5_000);
            let decided = run(&mut f, &[entry]);
            assert!(decided.orders.is_empty(), "twin {i}: {:?}", decided.refused);
            assert!(decided.replies.is_empty(), "twin {i}: nothing sent to it");
            assert_eq!(counter(&f), 0, "twin {i}: no address spent");
        }
        let mut f = fixture();
        assert_eq!(
            run(&mut f, &[buyer.request(&jam(), 1, 1, 12_000)])
                .orders
                .len(),
            1
        );
    }

    /// harvest#198 lane, item 2: whenever `decide` would turn a Buy now away
    /// for the whole store, the status says why (`paused`, that refusal's
    /// words) and the heartbeat says not taking orders. Each refusal a
    /// heartbeat can see: a lapsed watch, no payment key, a payment key for
    /// another network, no fresh tip, every watched address used, and,
    /// from the last read of the store's state, closed and not this
    /// seller's (`CatchingUp` and `CounterNotSaved` have their own tests).
    /// Mutated red by dropping each of `not_taking_given`'s checks, by not
    /// noting the read in `decide` or in `on_store_change`, and by keeping
    /// the old reading after a store reads open.
    #[test]
    fn the_heartbeat_says_not_taking_orders_whenever_decide_refuses() {
        let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        let says = |f: &mut Fixture, why: Refusal, what: &str| {
            assert_eq!(
                run(f, std::slice::from_ref(&entry)).refused,
                vec![(entry_digest(&entry), why.clone())],
                "{what}: decide"
            );
            assert_eq!(
                open_now(f, NOW),
                (Some(why.explain()), false),
                "{what}: status and heartbeat"
            );
            let record = f.record.clone();
            let (beat, _) = heartbeat(&mut f.secrets, &record, NOW, true).unwrap();
            assert!(!beat.heartbeat.taking_orders, "{what}: the heartbeat sent");
            assert_eq!(
                beat.heartbeat.reason,
                Some(why.for_buyers()),
                "{what}: the buyers' reason"
            );
        };
        assert_eq!(open_now(&fixture(), NOW), (None, true), "taking orders");

        let mut f = fixture();
        f.record.watched_until_ms = NOW;
        says(&mut f, Refusal::WatchLapsed, "watch lapsed");

        let mut f = fixture();
        f.secrets = {
            let mut s = MemSecrets::default();
            crate::store_keys::keep(&mut s, &store_sk());
            let tip: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
            save(&mut s, &tip_key(BitcoinNetwork::Signet), &tip);
            s
        };
        says(&mut f, Refusal::NoPaymentKey, "no payment key");

        let mut f = fixture();
        let tip: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
        save(&mut f.secrets, &tip_key(BitcoinNetwork::Testnet4), &tip);
        f.record.arm.network = BitcoinNetwork::Testnet4;
        says(&mut f, Refusal::NetworkMismatch, "another network");

        let mut f = fixture();
        let mut old: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
        old.block_time = 1;
        save(&mut f.secrets, &tip_key(BitcoinNetwork::Signet), &old);
        says(&mut f, Refusal::NoFreshTip, "no fresh tip");

        let mut f = fixture();
        f.record.arm.watched_scripts = vec![script_at(7)];
        says(&mut f, Refusal::NoWatchedAddress, "no watched address");

        // The store's own refusals are what the last read of its state said:
        // decide's read, then a store notification's.
        let mut f = fixture();
        let owner = store_sk().verifying_key();
        let closure = harvest_common::backing::AuthorizedClosure {
            closure: harvest_common::backing::StoreClosure { store: owner },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
        };
        let open = f.store.clone();
        f.store
            .closed
            .records
            .insert(harvest_common::store::Bytes32(owner.to_bytes()), closure);
        let closed = f.store.clone();
        says(&mut f, Refusal::StoreClosed, "closed, read by decide");
        f.store = open.clone();
        assert_eq!(run(&mut f, std::slice::from_ref(&entry)).orders.len(), 1);
        assert_eq!(open_now(&f, NOW), (None, true), "decide read it open again");

        let id: [u8; 32] = f.record.arm.store_contract_id.clone().try_into().unwrap();
        let notify = |f: &mut Fixture, store: &StoreStateV1| {
            on_notification(&mut f.secrets, &id, &to_cbor(store).unwrap(), NOW).unwrap();
        };
        notify(&mut f, &closed);
        assert_eq!(
            open_now(&f, NOW),
            (Some(Refusal::StoreClosed.explain()), false),
            "closed, read from a notification"
        );
        let mut theirs = open.clone();
        theirs.owner = Some(SigningKey::from_bytes(&[0x66; 32]).verifying_key());
        notify(&mut f, &theirs);
        assert_eq!(
            open_now(&f, NOW),
            (Some(Refusal::NotOurStore.explain()), false),
            "not ours, read from a notification"
        );
        notify(&mut f, &open);
        assert_eq!(open_now(&f, NOW), (None, true), "read open again");
        f.store = theirs;
        says(&mut f, Refusal::NotOurStore, "not ours, read by decide");
    }

    /// What buyers are told for each refusal (harvest#219): closed and not
    /// ours are closed for good, catching up is back soon, and everything
    /// else is unavailable; a store taking orders sends no reason. A change
    /// of reason while still not taking orders goes out at once, inside the
    /// interval. Mutated red by mapping any refusal elsewhere, by sending a
    /// reason while taking orders, and by not comparing the reason.
    #[test]
    fn a_heartbeat_tells_buyers_why_in_a_word() {
        use harvest_common::presence::NotTakingReason as R;
        for (refusal, want) in [
            (Refusal::StoreClosed, R::ClosedForGood),
            (Refusal::NotOurStore, R::ClosedForGood),
            (Refusal::CatchingUp, R::CatchingUp),
            (Refusal::WatchLapsed, R::Unavailable),
            (Refusal::NoPaymentKey, R::Unavailable),
            (Refusal::NoFreshTip, R::Unavailable),
            (Refusal::NoWatchedAddress, R::Unavailable),
            (Refusal::NetworkMismatch, R::Unavailable),
            (Refusal::CounterNotSaved, R::Unavailable),
            (Refusal::NoStoreKey, R::Unavailable),
            (Refusal::LedgerUnreadable, R::Unavailable),
        ] {
            assert_eq!(refusal.for_buyers(), want, "{refusal:?}");
        }
        let mut f = fixture();
        let record = f.record.clone();
        let (open, _) = heartbeat(&mut f.secrets, &record, NOW, true).unwrap();
        assert!(open.heartbeat.taking_orders);
        assert_eq!(open.heartbeat.reason, None);
        open.verify(&store_sk().verifying_key()).unwrap();

        let mut lapsed = record.clone();
        lapsed.watched_until_ms = NOW;
        let (first, _) = heartbeat(&mut f.secrets, &lapsed, NOW + 1_000, false).unwrap();
        assert_eq!(first.heartbeat.reason, Some(R::Unavailable));
        first.verify(&store_sk().verifying_key()).unwrap();
        // Still not taking, now for another reason: sent at once.
        note_store_read(
            &mut f.secrets,
            &record.arm.store_contract_id,
            Some(&Refusal::StoreClosed),
        );
        let (second, _) = heartbeat(&mut f.secrets, &record, NOW + 2_000, false)
            .expect("a new reason goes out inside the interval");
        assert_eq!(second.heartbeat.reason, Some(R::ClosedForGood));
        assert!(heartbeat(&mut f.secrets, &record, NOW + 3_000, false).is_none());
    }

    /// A batch turned away for a reason only the seller lifts settles the
    /// flag rather than bringing the mailbox back at every wake-up; one held
    /// for a tip too old keeps it, writing it again if it had gone. Mutated
    /// red by keeping it for every refusal, by clearing it for a stale tip,
    /// and by not writing it for a batch left undecided.
    #[test]
    fn a_turned_away_batch_settles_the_flag_and_a_stale_tip_keeps_it() {
        let run = |f: &mut Fixture| {
            let entry = Buyer::new(40).request(&jam(), 1, 1, 12_000);
            let state = to_cbor(&MailboxStateV1 {
                messages: vec![entry],
            })
            .unwrap();
            let out = on_mailbox(&mut f.secrets, &f.record.clone(), &state, NOW);
            let [OutboundDelegateMsg::GetContractRequest(get)] = out.as_slice() else {
                panic!("{out:?}")
            };
            get.context.as_ref().to_vec()
        };
        let mut f = fixture();
        let batch = run(&mut f);
        assert_eq!(flag(&f).as_deref(), Some(b"1".as_slice()));
        let mut closed = f.store.clone();
        closed.owner = Some(SigningKey::from_bytes(&[0x66; 32]).verifying_key());
        let store = to_cbor(&closed).unwrap();
        on_store_state(&mut f.secrets, Some(&store), &batch, NOW).unwrap();
        assert_eq!(flag(&f).as_deref(), Some(b"0".as_slice()), "not our store");
        let mut f = fixture();
        let batch = run(&mut f);
        let mut old: TipCache = load(&f.secrets, &tip_key(BitcoinNetwork::Signet)).unwrap();
        old.block_time = 1;
        save(&mut f.secrets, &tip_key(BitcoinNetwork::Signet), &old);
        // As a failed write would leave it: decide saves nothing here, so
        // the settling is what puts it back.
        f.secrets
            .set_secret(&retry_key(&f.record.arm.store_contract_id), b"0");
        let store = to_cbor(&f.store).unwrap();
        on_store_state(&mut f.secrets, Some(&store), &batch, NOW).unwrap();
        assert_eq!(flag(&f).as_deref(), Some(b"1".as_slice()), "a stale tip");
    }

    /// Every ledger write in this module goes through `save_ledger`, so the
    /// flag the wake-up reads cannot fall behind the ledger (`import.rs`
    /// writes imported ledgers and syncs the flag itself, pinned by its own
    /// tests). Outside the tests, a ledger key is formed only in
    /// `save_ledger` and the loads, and no other `save(` or `set_secret(`
    /// call mentions a ledger. Mutated red by a bare `save` of a ledger.
    #[test]
    fn every_ledger_write_goes_through_save_ledger() {
        let src = include_str!("auto_invoice.rs");
        let code = &src[..src.find("\n#[cfg(test)]\nmod tests").unwrap()];
        let body = |name: &str| {
            let at = code.find(name).unwrap();
            &code[at..at + code[at..].find("\n}\n").unwrap()]
        };
        let outside = code
            .replace(body("fn save_ledger<"), "")
            .replace(body("fn load_ledger<"), "")
            .replace(body("fn load_ledger_shown<"), "")
            .replace(body("fn ledger_retry_pending<"), "")
            .replace(body("fn load_ledger_kept<"), "")
            .lines()
            // Doc comments name the key without forming one.
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
            .replace("pub(crate) fn ledger_key(", "")
            .replace("is_ledger_key(", "");
        assert!(
            !outside.contains("ledger_key("),
            "a ledger key formed outside save_ledger / load_ledger"
        );
        for call in ["save(", "set_secret("] {
            let mut rest = outside.as_str();
            while let Some(at) = rest.find(call) {
                let tail = &rest[at..];
                // The call's own arguments, to its matching parenthesis.
                let mut depth = 0;
                let close = tail
                    .char_indices()
                    .find(|&(_, c)| {
                        depth += match c {
                            '(' => 1,
                            ')' => -1,
                            _ => 0,
                        };
                        c == ')' && depth == 0
                    })
                    .map_or(tail.len(), |(i, _)| i);
                let args = &tail[..close];
                assert!(
                    !args.to_lowercase().contains("ledger"),
                    "a ledger written without its flag: {args}"
                );
                rest = &tail[call.len()..];
            }
        }
    }

    /// The hand decoder takes the mailboxes clients actually write (sealed
    /// requests and texts); anything else still reaches the run through the
    /// generic decoder. Mutated red by dropping the fallback.
    #[test]
    fn real_mailboxes_decode_fast_and_others_still_decode() {
        let request = Buyer::new(40).request(&jam(), 1, 1, 12_000);
        let mailbox = MailboxStateV1 {
            messages: vec![junk(1, 30), request, junk(2, 3000)],
        };
        let canonical = to_cbor(&mailbox).unwrap();
        assert_eq!(
            crate::fast_cbor::decode_mailbox(&canonical),
            Some(mailbox.clone())
        );
        // The same state with its message list as an indefinite-length array.
        let mut indefinite = canonical.clone();
        let at = indefinite.iter().position(|b| *b == 0x83).unwrap();
        indefinite[at] = 0x9f;
        indefinite.push(0xff);
        assert_eq!(crate::fast_cbor::decode_mailbox(&indefinite), None);
        assert_eq!(from_cbor::<MailboxStateV1>(&indefinite).unwrap(), mailbox);
        let mut f = fixture();
        let out = on_mailbox(&mut f.secrets, &f.record.clone(), &indefinite, NOW);
        assert_eq!(batched(&out).len(), 1);
    }
}
