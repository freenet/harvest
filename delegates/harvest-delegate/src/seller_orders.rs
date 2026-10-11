//! The seller's own copy of its orders (step 2): an order book per store
//! key, so an order that rolls off the store (its order cap, or Buy-now
//! spam) never silently vanishes from the seller's list of orders to send.
//!
//! Ian, 2026-10-09: the store holds an order until its complaint window
//! closes; history then lives in each side's delegate. The buyer's side is
//! `kept_purchases`; this is the seller's.
//!
//! # What a book holds
//!
//! Three secrets per store key (which, unlike the store's contract id,
//! survives re-keys), one per stage of an order, so each writer touches
//! only the stage it writes:
//!
//! * `unpaid`: orders awaiting payment, at most [`MAX_SELLER_UNPAID_KEPT`];
//!   past it the oldest unpaid one goes. Small: no proofs (a paid one that
//!   waits here for room drops its proof and keeps its paid height).
//!   Instant checkout appends here as it signs, and a store notification
//!   marks one paid or drops one cancelled here, so neither ever decodes
//!   the larger stages (the delegate budget's full-book row measured that
//!   at 91% of a call). An order marked paid here stays until the next tab
//!   call or wake-up moves it on (`Book::promote`); it is listed, and
//!   shown, as paid meanwhile, and marked ones are not counted against the
//!   cap until they move, so a wake-up that cannot move them (a stage that
//!   does not read) lets them grow as fast as orders are paid. An unpaid order that goes can still be paid later; it comes
//!   back only from the tab, while the store still shows it.
//! * `open`: paid orders not yet sent, at most [`MAX_SELLER_UNSENT_KEPT`],
//!   with the minimal proof once the tab supplies it. A paid order is never
//!   evicted: past the cap it waits in `unpaid`, marked paid, with its
//!   ship-to (up to [`MAX_SELLER_UNPAID_KEPT`] waiting so; past that only
//!   its id), is named in `paid_refused`, which the seller is shown, and
//!   moves on once there is room.
//! * `done`: sent (or reversed) orders, the newest
//!   [`MAX_SELLER_SENT_KEPT`] by `created_at`: history, which may decay,
//!   without the proof.
//!
//! Each record is the order's terms and signature, the buyer's request
//! (ship-to, choices, note; each text cut at [`MAX_KEPT_REQUEST_TEXT`]),
//! and the despatch once sent.
//!
//! # Who writes it
//!
//! * Instant checkout, as it signs an order (`auto_invoice::decide`): the
//!   order and the request it answers, into `unpaid`, with the tab closed.
//! * Every store notification for an armed store (`on_store_change`), on
//!   `unpaid` only: paid, or cancelled before payment.
//! * The seller's tab (`KeepSellerOrders`): orders the store shows that the
//!   book lacks or holds less of (a manual invoice and its request, a paid
//!   order's proof, a despatch), and a despatch for an order the store no
//!   longer holds, which is recorded here only (`sent_off_store`).
//! * A wake-up ([`sweep`], one book at a time): what `unpaid` holds as paid
//!   moves on, and unpaid orders past their payment window go.
//!
//! A sent order's request goes at the first tab call after its complaint
//! window has closed (the UI's `fulfilment::address_retained`), judged by
//! the chain tip instant checkout caches; with no tip cached (no store
//! armed for instant checkout on that network) it stays.

use freenet_migrate::SecretStore;
use harvest_common::delegate::{
    HarvestDelegateResponse, KeptRequest, RequestId, SellerKeptOrder, SellerOrdersPage,
    MAX_KEPT_REQUEST_TEXT, MAX_SELLER_BOOKS, MAX_SELLER_SENT_KEPT, MAX_SELLER_UNPAID_KEPT,
    MAX_SELLER_UNSENT_KEPT, SELLER_ORDERS_PAGE_BYTES, SELLER_ORDERS_PER_CALL,
};
use harvest_common::fulfilment::{COMPLAINT_WINDOW_BLOCKS, DESPATCH_WINDOW_BLOCKS};
use harvest_common::payment::{OrderId, OrderStatus};
use harvest_common::{from_cbor, to_cbor};
use serde::{Deserialize, Serialize};

/// The prefix every book secret starts with.
pub(crate) const SELLER_ORDERS_PREFIX: &str = "harvest:seller_orders:";

fn stage_key(stage: &str, store_key: &[u8; 32]) -> Vec<u8> {
    format!(
        "{SELLER_ORDERS_PREFIX}{stage}:{}",
        bs58::encode(store_key).into_string()
    )
    .into_bytes()
}

/// Where a book's unpaid orders are kept.
pub(crate) fn unpaid_key(store_key: &[u8; 32]) -> Vec<u8> {
    stage_key("unpaid", store_key)
}

/// Where a book's paid orders not yet sent are kept.
pub(crate) fn open_key(store_key: &[u8; 32]) -> Vec<u8> {
    stage_key("open", store_key)
}

/// Where a book's sent orders are kept.
pub(crate) fn done_key(store_key: &[u8; 32]) -> Vec<u8> {
    stage_key("done", store_key)
}

/// The wake-up sweep's place: the store key it swept last.
pub(crate) const SWEEP_CURSOR_KEY: &[u8] = b"harvest:seller_orders:cursor";

/// The paid, not yet sent, stage of a book.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub(crate) struct OpenBook {
    pub orders: Vec<SellerKeptOrder>,
    /// Paid orders not moved here because it already held
    /// [`MAX_SELLER_UNSENT_KEPT`]: shown to the seller until each is. At
    /// most [`MAX_SELLER_UNSENT_KEPT`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paid_refused: Vec<OrderId>,
}

/// One store's book, its three stages as read.
#[derive(Clone, Default, PartialEq, Debug)]
struct Book {
    unpaid: Vec<SellerKeptOrder>,
    open: OpenBook,
    done: Vec<SellerKeptOrder>,
}

fn is_awaiting(record: &SellerKeptOrder) -> bool {
    record.order.status == OrderStatus::AwaitingPayment
}

fn read<S: SecretStore, T: for<'de> Deserialize<'de> + Default>(
    secrets: &S,
    key: &[u8],
) -> Option<T> {
    match secrets.get_secret(key) {
        None => Some(T::default()),
        Some(bytes) => from_cbor(&bytes).ok(),
    }
}

impl Book {
    /// The book, or `None` if a stage is there and does not decode (then
    /// nothing is written over it). An order in two stages (a save refused
    /// part-way) is read from the later one.
    fn load<S: SecretStore>(secrets: &S, store_key: &[u8; 32]) -> Option<Book> {
        let mut book = Self::load_raw(secrets, store_key)?;
        book.dedupe();
        Some(book)
    }

    /// The three stages exactly as stored.
    fn load_raw<S: SecretStore>(secrets: &S, store_key: &[u8; 32]) -> Option<Book> {
        Some(Book {
            unpaid: read(secrets, &unpaid_key(store_key))?,
            open: read(secrets, &open_key(store_key))?,
            done: read(secrets, &done_key(store_key))?,
        })
    }

    /// Each order in its latest stage only, after a save refused part-way
    /// ([`Book::save`]). Over the stages read: a wake-up that read only
    /// `unpaid` leaves a copy there that the next tab call clears.
    fn dedupe(&mut self) {
        let later: std::collections::BTreeSet<[u8; 32]> =
            self.done.iter().map(|r| r.order.order.id.0).collect();
        self.open
            .orders
            .retain(|r| !later.contains(&r.order.order.id.0));
        let later: std::collections::BTreeSet<[u8; 32]> = later
            .into_iter()
            .chain(self.open.orders.iter().map(|r| r.order.order.id.0))
            .collect();
        self.unpaid.retain(|r| !later.contains(&r.order.order.id.0));
    }

    /// Write back each stage that differs from `before`, the later stages
    /// first: a record moves on, so if a write is refused part-way it is in
    /// two stages, never none, and [`Book::load`] keeps the later. Answers
    /// whether the node kept every write.
    fn save<S: SecretStore>(&self, secrets: &mut S, store_key: &[u8; 32], before: &Book) -> bool {
        let mut ok = true;
        if self.done != before.done {
            ok &= to_cbor(&self.done).is_ok_and(|b| secrets.set_secret(&done_key(store_key), &b));
        }
        if ok && self.open != before.open {
            ok &= to_cbor(&self.open).is_ok_and(|b| secrets.set_secret(&open_key(store_key), &b));
        }
        if ok && self.unpaid != before.unpaid {
            ok &=
                to_cbor(&self.unpaid).is_ok_and(|b| secrets.set_secret(&unpaid_key(store_key), &b));
        }
        ok
    }

    /// Every record, each once.
    fn all(self) -> Vec<SellerKeptOrder> {
        self.unpaid
            .into_iter()
            .chain(self.open.orders)
            .chain(self.done)
            .collect()
    }

    /// Move on what `unpaid` holds as paid (marked so by a store
    /// notification): into `open`, or, for a sent one, `done`.
    fn promote(&mut self) {
        let (mut moving, staying): (Vec<_>, Vec<_>) = std::mem::take(&mut self.unpaid)
            .into_iter()
            .partition(|r| !is_awaiting(r));
        self.unpaid = staying;
        // Those already waiting for room (named in `paid_refused`) first, so
        // one marked paid since never takes a waiting one's place, and its
        // ship-to with it.
        let waiting = &self.open.paid_refused;
        moving.sort_by_key(|r| !waiting.contains(&r.order.order.id));
        for record in moving {
            self.file(record);
        }
    }

    /// File `record` (checked) into its stage, under every cap.
    fn file(&mut self, record: SellerKeptOrder) -> Filed {
        let id = record.order.order.id.clone();
        let take = |stage: &mut Vec<SellerKeptOrder>| {
            stage
                .iter()
                .position(|r| r.order.order.id == id)
                .map(|at| stage.remove(at))
        };
        // Where it was: a paid order already in `open` keeps its place there.
        let mut was = Stage::None;
        let held = take(&mut self.unpaid)
            .inspect(|_| was = Stage::Unpaid)
            .or_else(|| take(&mut self.open.orders).inspect(|_| was = Stage::Open))
            .or_else(|| take(&mut self.done).inspect(|_| was = Stage::Done));
        let was_open = was == Stage::Open;
        let unchanged = held
            .as_ref()
            .is_some_and(|h| merged(h.clone(), record.clone()) == *h);
        let next = match held.clone() {
            Some(held) => merged(held, record),
            None => record,
        };
        // Nothing changed only if the record is as it was AND where it was.
        let filed = |f: Filed, to: Stage| {
            if unchanged && was == to {
                Filed::Unchanged
            } else {
                f
            }
        };
        match next.order.status {
            OrderStatus::Cancelled => {
                self.open.paid_refused.retain(|r| *r != id);
                Filed::Dropped
            }
            OrderStatus::AwaitingPayment => {
                self.unpaid.push(next);
                // Past the cap the oldest unpaid one goes; one marked paid
                // never does.
                while self.unpaid.iter().filter(|r| is_awaiting(r)).count() > MAX_SELLER_UNPAID_KEPT
                {
                    let oldest = self
                        .unpaid
                        .iter()
                        .enumerate()
                        .filter(|(_, r)| is_awaiting(r))
                        .min_by_key(|(_, r)| (r.order.order.created_at, r.order.order.id.0))
                        .map(|(at, _)| at)
                        .expect("over the cap, so one is there");
                    self.unpaid.remove(oldest);
                }
                self.unpaid
                    .sort_by_key(|r| (r.order.order.created_at, r.order.order.id.0));
                // Older than every unpaid one kept: it went at once.
                if !self.unpaid.iter().any(|r| r.order.order.id == id) {
                    return Filed::Dropped;
                }
                filed(Filed::Kept, Stage::Unpaid)
            }
            OrderStatus::Paid if next.despatch.is_none() => {
                if !was_open && self.open.orders.len() >= MAX_SELLER_UNSENT_KEPT {
                    // Never evicted, nor makes room: it waits in `unpaid`,
                    // marked paid, keeping its ship-to, up to
                    // `MAX_SELLER_UNPAID_KEPT` waiting so (which keeps the
                    // stage instant checkout reads small); past that only
                    // its id is kept. Every one is named, and the seller is
                    // shown it.
                    let waiting = self.unpaid.iter().filter(|r| !is_awaiting(r)).count();
                    if waiting < MAX_SELLER_UNPAID_KEPT {
                        // Without its proof, which keeps the stage small;
                        // the height it was paid at stands for it, and a
                        // tab that sees the store's paid copy supplies the
                        // proof again once it has moved on.
                        let mut next = next;
                        next.paid_height = next
                            .paid_height
                            .or_else(|| harvest_common::payment::paid_height(&next.order));
                        next.order.payment_proof = None;
                        self.unpaid.push(next);
                        self.unpaid
                            .sort_by_key(|r| (r.order.order.created_at, r.order.order.id.0));
                    }
                    if !self.open.paid_refused.contains(&id) {
                        self.open.paid_refused.push(id);
                        if self.open.paid_refused.len() > MAX_SELLER_UNSENT_KEPT {
                            self.open.paid_refused.remove(0);
                        }
                    }
                    return Filed::Refused;
                }
                self.open.paid_refused.retain(|r| *r != id);
                self.open.orders.push(next);
                self.open
                    .orders
                    .sort_by_key(|r| (r.order.order.created_at, r.order.order.id.0));
                filed(Filed::Kept, Stage::Open)
            }
            _ => {
                self.open.paid_refused.retain(|r| *r != id);
                // History: the terms, the despatch and the height it was
                // paid at, not the proof, which the store held while it
                // mattered and which would make a sent order as large as its
                // payment's transactions.
                let mut next = next;
                next.paid_height = next
                    .paid_height
                    .or_else(|| harvest_common::payment::paid_height(&next.order));
                next.order.payment_proof = None;
                self.done.push(next);
                self.done
                    .sort_by_key(|r| (r.order.order.created_at, r.order.order.id.0));
                if self.done.len() > MAX_SELLER_SENT_KEPT {
                    let excess = self.done.len() - MAX_SELLER_SENT_KEPT;
                    self.done.drain(..excess);
                }
                filed(Filed::Kept, Stage::Done)
            }
        }
    }
}

/// How many books this node keeps.
fn books<S: SecretStore>(secrets: &S) -> std::collections::BTreeSet<Vec<u8>> {
    secrets
        .list_secrets(SELLER_ORDERS_PREFIX.as_bytes())
        .into_iter()
        .filter_map(|key| {
            let rest = key.strip_prefix(SELLER_ORDERS_PREFIX.as_bytes())?;
            let rest = ["unpaid:", "open:", "done:"]
                .iter()
                .find_map(|stage| rest.strip_prefix(stage.as_bytes()))?;
            Some(rest.to_vec())
        })
        .collect()
}

/// `text` cut to at most `max` bytes, at a character boundary.
fn cut(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut at = max;
        while !text.is_char_boundary(at) {
            at -= 1;
        }
        text.truncate(at);
    }
    text
}

/// A request with every text cut to [`MAX_KEPT_REQUEST_TEXT`], and at most
/// as many choices as a listing may have groups.
pub(crate) fn bounded(request: KeptRequest) -> KeptRequest {
    KeptRequest {
        shipping: cut(request.shipping, MAX_KEPT_REQUEST_TEXT),
        note: cut(request.note, MAX_KEPT_REQUEST_TEXT),
        region: request.region.map(|r| cut(r, MAX_KEPT_REQUEST_TEXT)),
        choices: request
            .choices
            .into_iter()
            .take(harvest_common::listing::MAX_CHOICE_GROUPS)
            .map(|c| cut(c, MAX_KEPT_REQUEST_TEXT))
            .collect(),
        ..request
    }
}

/// Who a record comes from, which decides how much of it is checked.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Source {
    /// The seller's tab, or a restored backup file: anything in it may have
    /// been made up, so everything is checked as the store would keep it,
    /// except what the book's own seal vouches for ([`seal_of`], under this
    /// key).
    Tab { seal_key: [u8; 32] },
    /// A predecessor generation of this delegate (a re-key's migration),
    /// which filed every record after the same checks: kept as it was
    /// written, with only its shape held to this generation's bounds. A
    /// full book re-verified here would cost several calls' budget (1,536
    /// records, two or three signatures each). What this rests on: only the
    /// web app's migration walk sends `ImportMigratedSecret`
    /// (`ui/src/delegate_migrate.rs`), with what the predecessor exported;
    /// a tab that could forge it could already sign as the store.
    Predecessor,
}

/// The key a book seals its paid and reversed records with: derived from
/// the store key, so only a device that holds it can make or check one.
fn seal_key(store: &ed25519_dalek::SigningKey) -> [u8; 32] {
    blake3::derive_key("harvest seller book seal v1", store.as_bytes())
}

/// The book's seal on `record`: its order's terms and status (not the
/// proof, which the book drops once an order is sent or paid past the
/// store's byte bound) and its paid height.
fn seal_of(key: &[u8; 32], record: &SellerKeptOrder) -> Option<[u8; 32]> {
    let mut order = record.order.clone();
    order.payment_proof = None;
    let bytes = to_cbor(&(order, record.paid_height)).ok()?;
    Some(*blake3::keyed_hash(key, &bytes).as_bytes())
}

/// Check `incoming` as a record of the store `owner`, as the store would
/// keep it: the order verifies, a `Paid` on anything but the minimal proof
/// is its unpaid terms (`store::as_kept`), a despatch is the store key's and
/// names this order, and the request is cut to its bounds.
///
/// A `Paid` without its proof says nothing a tab can be held to (the status
/// is not signed, and every unpaid order's terms are public in the store),
/// so it is kept only as its unpaid terms unless the book sealed it (the
/// book's own listing, as a backup or the seller's tab sends it back):
/// filed into a book that already holds the order as paid, it changes
/// nothing there.
fn checked(
    owner: &ed25519_dalek::VerifyingKey,
    incoming: SellerKeptOrder,
    source: Source,
) -> Result<SellerKeptOrder, String> {
    let seal_key = match source {
        Source::Predecessor => return shaped(incoming),
        Source::Tab { seal_key } => seal_key,
    };
    // Compared as `blake3::Hash`, whose equality takes the same time
    // whatever the bytes.
    let sealed = incoming.seal.is_some_and(|seal| {
        seal_of(&seal_key, &incoming)
            .is_some_and(|ours| blake3::Hash::from(seal) == blake3::Hash::from(ours))
    });
    let mut order = incoming.order;
    let mut paid_height = incoming.paid_height;
    let id = order.order.id.clone();
    let terms = |order: &harvest_common::payment::AuthorizedOrder| {
        order
            .verify_terms(owner)
            .map_err(|e| format!("order {id} does not verify: {e}"))
    };
    if let Some(despatch) = &incoming.despatch {
        despatch.verify(owner)?;
        if despatch.despatch.order_id != id {
            return Err(format!("the despatch names another order than {id}"));
        }
    }
    if sealed
        && matches!(
            order.status,
            OrderStatus::Paid | OrderStatus::PaymentReversed
        )
    {
        // As the book had it, by its own seal (the seal does not cover the
        // proof): the status and paid height stand, and a proof is kept only
        // as the store would keep it, the minimal one within its byte bound.
        terms(&order)?;
        let kept_as_is = order.status == OrderStatus::Paid
            && order.payment_proof.is_some()
            && harvest_common::store::as_kept(order.clone()).status == OrderStatus::Paid
            && order.verify(owner).is_ok();
        if !kept_as_is {
            order.payment_proof = None;
        }
    } else if order.status == OrderStatus::Paid
        && !harvest_common::store::within_order_cap(&order)
        && order
            .payment_proof
            .as_ref()
            .is_some_and(|p| harvest_common::payment::verify_minimal_proof(&order.order, p).is_ok())
        && order.verify(owner).is_ok()
    {
        // Paid on the minimal proof, but past the store's byte bound
        // (`store::MAX_ORDER_BYTES`): the store keeps it unpaid, and the
        // seller's own book keeps it paid (the overseer, 2026-10-09: an
        // honest payment over the bound still reaches the seller as paid).
        // Without the proof, which would make the book as large as the
        // payment's transactions, and with the height it confirmed at.
        paid_height = paid_height.or_else(|| harvest_common::payment::paid_height(&order));
        order.payment_proof = None;
    } else {
        // Anything else as the store would keep it: a `Paid` without its
        // proof, or on another than the minimal one, is its unpaid terms
        // (the status is not signed, and every unpaid order's terms are
        // public in the store), and its paid height goes with it.
        let was = order.status;
        order = harvest_common::store::as_kept(order);
        if order.status != was {
            paid_height = None;
        }
        order
            .verify(owner)
            .map_err(|e| format!("order {} does not verify: {e}", order.order.id))?;
    }
    if !matches!(
        order.status,
        OrderStatus::AwaitingPayment | OrderStatus::Paid | OrderStatus::PaymentReversed
    ) {
        return Err(format!(
            "order {} is {:?}, and only an order unpaid, paid or reversed is kept",
            order.order.id, order.status
        ));
    }
    Ok(SellerKeptOrder {
        paid_height: paid_height.or_else(|| harvest_common::payment::paid_height(&order)),
        order,
        request: incoming.request.map(bounded),
        despatch: incoming.despatch,
        sent_off_store: incoming.sent_off_store,
        seal: None,
    })
}

/// A predecessor's record held to this generation's bounds (its despatch's
/// order, its request's texts and choices) without
/// re-checking its signatures or its proof ([`Source::Predecessor`]).
fn shaped(incoming: SellerKeptOrder) -> Result<SellerKeptOrder, String> {
    // (A cancelled one needs no check here: filing drops it.)
    let id = &incoming.order.order.id;
    if incoming
        .despatch
        .as_ref()
        .is_some_and(|d| d.despatch.order_id != *id)
    {
        return Err(format!("the despatch names another order than {id}"));
    }
    Ok(SellerKeptOrder {
        request: incoming.request.map(bounded),
        seal: None,
        ..incoming
    })
}

/// `held` with what `incoming` (the same order) adds: the higher status,
/// and at the same status a proof where the held has none; a request, a
/// despatch or a paid height the held lacks. Nothing held is ever lost.
pub(crate) fn merged(held: SellerKeptOrder, incoming: SellerKeptOrder) -> SellerKeptOrder {
    let order = if incoming.order.status.rank() > held.order.status.rank()
        || (incoming.order.status == held.order.status
            && held.order.payment_proof.is_none()
            && incoming.order.payment_proof.is_some())
    {
        incoming.order
    } else {
        held.order
    };
    SellerKeptOrder {
        paid_height: held
            .paid_height
            .or(incoming.paid_height)
            .or_else(|| harvest_common::payment::paid_height(&order)),
        order,
        request: held.request.or(incoming.request),
        despatch: held.despatch.or(incoming.despatch),
        sent_off_store: held.sent_off_store || incoming.sent_off_store,
        seal: None,
    }
}

/// Where a record was held before it was filed.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Stage {
    None,
    Unpaid,
    Open,
    Done,
}

/// What filing one record did.
#[derive(PartialEq, Debug)]
enum Filed {
    Kept,
    /// Already held as completely; nothing changed.
    Unchanged,
    /// A paid order past [`MAX_SELLER_UNSENT_KEPT`]: named in `paid_refused`.
    Refused,
    /// An unpaid order cancelled: there is nothing to send.
    Dropped,
}

/// Keep `orders` in `store_key`'s book: for a store whose key this node
/// holds, each checked as the store would keep it. Answers how many were
/// kept or changed; refused ones are named in the book's `paid_refused`.
/// Used by the tab, and by a restore.
pub(crate) fn keep<S: SecretStore>(
    secrets: &mut S,
    request_id: RequestId,
    store_key: [u8; 32],
    orders: Vec<SellerKeptOrder>,
) -> HarvestDelegateResponse {
    let answer = |result| HarvestDelegateResponse::SellerOrdersKept {
        request_id,
        store_key,
        result,
    };
    if orders.len() > SELLER_ORDERS_PER_CALL {
        return answer(Err(format!(
            "at most {SELLER_ORDERS_PER_CALL} orders are kept at a time"
        )));
    }
    let Ok(owner) = ed25519_dalek::VerifyingKey::from_bytes(&store_key) else {
        return answer(Err("that is not a store key".into()));
    };
    let Some(signing) = crate::store_keys::load(secrets, &owner) else {
        return answer(Err(
            "this device does not hold that store's key, so it keeps no orders for it".into(),
        ));
    };
    let source = Source::Tab {
        seal_key: seal_key(&signing),
    };
    match file_all(secrets, &store_key, orders, source) {
        Ok(kept) => answer(Ok(kept)),
        Err(why) => answer(Err(why)),
    }
}

/// Whether one more book may be kept for `store_key`.
fn book_room<S: SecretStore>(secrets: &S, store_key: &[u8; 32]) -> Result<(), String> {
    let encoded = bs58::encode(store_key).into_string().into_bytes();
    let held = books(secrets);
    if !held.contains(&encoded) && held.len() >= MAX_SELLER_BOOKS {
        return Err(format!(
            "this device already keeps the orders of {MAX_SELLER_BOOKS} stores, the most it keeps"
        ));
    }
    Ok(())
}

/// File every record into `store_key`'s book, after moving on what
/// `unpaid` holds as paid, and save the stages that changed. A record from
/// the tab that does not check refuses the whole call; a predecessor's is
/// skipped.
fn file_all<S: SecretStore>(
    secrets: &mut S,
    store_key: &[u8; 32],
    orders: Vec<SellerKeptOrder>,
    source: Source,
) -> Result<u32, String> {
    let owner = ed25519_dalek::VerifyingKey::from_bytes(store_key)
        .map_err(|_| "that is not a store key".to_string())?;
    // A record that does not check is left out, not the call: one bad
    // record in a restore or a tab's batch must not hold back the rest. The
    // answer counts what was kept.
    let checked_all: Vec<SellerKeptOrder> = orders
        .into_iter()
        .filter_map(|record| checked(&owner, record, source).ok())
        .collect();
    book_room(secrets, store_key)?;
    let Some(before) = Book::load_raw(secrets, store_key) else {
        return Err(
            "this store's kept orders do not read, so nothing was written over them".into(),
        );
    };
    // Compared with the stages as stored, so a copy `dedupe` drops is
    // written away too.
    let mut book = before.clone();
    book.dedupe();
    book.promote();
    book.drop_closed_requests(&cached_tips(secrets));
    let mut kept = 0u32;
    for record in checked_all {
        if book.file(record) == Filed::Kept {
            kept += 1;
        }
    }
    if !book.save(secrets, store_key, &before) {
        return Err("the node refused to save the kept orders".into());
    }
    Ok(kept)
}

/// Instant checkout's write: the orders it just signed, with the requests
/// they answer, into the book's `unpaid` stage only (never decoding the
/// others), at most [`MAX_SELLER_UNPAID_KEPT`] unpaid (the oldest go).
/// Answers whether it was written (or there was nothing to write).
pub(crate) fn keep_signed<S: SecretStore>(
    secrets: &mut S,
    store_key: &[u8; 32],
    orders: Vec<SellerKeptOrder>,
) -> bool {
    if orders.is_empty() {
        return true;
    }
    if book_room(secrets, store_key).is_err() {
        return false;
    }
    let Some(unpaid) = read::<_, Vec<SellerKeptOrder>>(secrets, &unpaid_key(store_key)) else {
        return false;
    };
    let mut book = Book {
        unpaid,
        ..Book::default()
    };
    for record in orders {
        // Only an order this stage does not hold: one held, perhaps marked
        // paid since, is not this stage's alone to file again.
        if book
            .unpaid
            .iter()
            .any(|r| r.order.order.id == record.order.order.id)
        {
            continue;
        }
        book.file(SellerKeptOrder {
            request: record.request.map(bounded),
            ..record
        });
    }
    to_cbor(&book.unpaid).is_ok_and(|bytes| secrets.set_secret(&unpaid_key(store_key), &bytes))
}

/// A store notification's write, on the `unpaid` stage only: an order the
/// store now shows paid is marked paid (the tab supplies the proof; the
/// next filing moves it on), and one it shows cancelled is dropped. Writes
/// only when something changed.
pub(crate) fn on_store_statuses<S: SecretStore>(
    secrets: &mut S,
    store_key: &[u8; 32],
    status_of: impl Fn(&OrderId) -> Option<OrderStatus>,
) {
    let key = unpaid_key(store_key);
    if !secrets.has_secret(&key) {
        return;
    }
    let Some(mut unpaid) = read::<_, Vec<SellerKeptOrder>>(secrets, &key) else {
        return;
    };
    let mut changed = false;
    unpaid.retain_mut(
        |record| match (record.order.status, status_of(&record.order.order.id)) {
            (OrderStatus::AwaitingPayment, Some(OrderStatus::Cancelled)) => {
                changed = true;
                false
            }
            (OrderStatus::AwaitingPayment, Some(OrderStatus::Paid)) => {
                record.order.status = OrderStatus::Paid;
                changed = true;
                true
            }
            _ => true,
        },
    );
    if changed {
        if let Ok(bytes) = to_cbor(&unpaid) {
            secrets.set_secret(&key, &bytes);
        }
    }
}

/// One page of `store_key`'s book: its orders, every stage, by order id
/// after `after`, about [`SELLER_ORDERS_PAGE_BYTES`] at a time.
pub(crate) fn list<S: SecretStore>(
    secrets: &S,
    request_id: RequestId,
    store_key: [u8; 32],
    after: Option<OrderId>,
) -> HarvestDelegateResponse {
    let answer = |result| HarvestDelegateResponse::SellerOrders {
        request_id,
        store_key,
        result,
    };
    let Some(book) = Book::load(secrets, &store_key) else {
        return answer(Err("this store's kept orders do not read".into()));
    };
    let paid_refused = book.open.paid_refused.clone();
    let mut all = book.all();
    all.sort_by(|a, b| a.order.order.id.0.cmp(&b.order.order.id.0));
    if let Some(after) = &after {
        all.retain(|r| r.order.order.id.0 > after.0);
    }
    let mut page = SellerOrdersPage {
        orders: Vec::new(),
        next: None,
        paid_refused: if after.is_none() {
            paid_refused
        } else {
            Vec::new()
        },
    };
    // Each paid or reversed record sealed, so a backup of this listing
    // restores it as the book has it (`checked`).
    let key = ed25519_dalek::VerifyingKey::from_bytes(&store_key)
        .ok()
        .and_then(|k| crate::store_keys::load(secrets, &k))
        .map(|k| seal_key(&k));
    let mut bytes = 0usize;
    for mut record in all {
        if !page.orders.is_empty() && bytes >= SELLER_ORDERS_PAGE_BYTES {
            page.next = page.orders.last().map(|r| r.order.order.id.clone());
            break;
        }
        if matches!(
            record.order.status,
            OrderStatus::Paid | OrderStatus::PaymentReversed
        ) {
            record.seal = key.as_ref().and_then(|k| seal_of(k, &record));
        }
        bytes += to_cbor(&record).map_or(0, |b| b.len());
        page.orders.push(record);
    }
    answer(Ok(page))
}

/// Whether a sent order's complaint window has closed by `tip`: the later
/// of the despatch deadline and the despatch's own anchor, plus the window
/// (the UI's `fulfilment::window_end_from`).
fn window_closed(record: &SellerKeptOrder, tip: u32) -> bool {
    let (Some(paid_at), Some(despatch)) = (record.paid_height, record.despatch.as_ref()) else {
        return false;
    };
    let end = paid_at
        .saturating_add(DESPATCH_WINDOW_BLOCKS)
        .max(despatch.despatch.anchor.height)
        .saturating_add(COMPLAINT_WINDOW_BLOCKS);
    tip > end
}

/// The tip instant checkout caches for each network.
fn cached_tips<S: SecretStore>(
    secrets: &S,
) -> impl Fn(freenet_bitcoin_common::BitcoinNetwork) -> Option<u32> {
    let tips: std::collections::BTreeMap<String, u32> = [
        freenet_bitcoin_common::BitcoinNetwork::Bitcoin,
        freenet_bitcoin_common::BitcoinNetwork::Testnet4,
        freenet_bitcoin_common::BitcoinNetwork::Signet,
        freenet_bitcoin_common::BitcoinNetwork::Regtest,
    ]
    .into_iter()
    .filter_map(|network| {
        let tip: crate::auto_invoice::TipCache =
            crate::auto_invoice::load(secrets, &crate::auto_invoice::tip_key(network))?;
        Some((format!("{network:?}"), tip.anchor.height))
    })
    .collect();
    move |network: freenet_bitcoin_common::BitcoinNetwork| {
        tips.get(&format!("{network:?}")).copied()
    }
}

impl Book {
    /// A sent order's request goes once its complaint window has closed
    /// (the UI's `fulfilment::address_retained`). Done on every tab call,
    /// which already decodes the sent stage: a seller opens Harvest at
    /// least weekly or the store stops taking orders, so an address is
    /// kept at most about a week past its window.
    fn drop_closed_requests(
        &mut self,
        tip_of: &impl Fn(freenet_bitcoin_common::BitcoinNetwork) -> Option<u32>,
    ) {
        for r in self.done.iter_mut() {
            if r.request.is_some()
                && tip_of(r.order.order.network).is_some_and(|tip| window_closed(r, tip))
            {
                r.request = None;
            }
        }
    }
}

/// A wake-up's sweep of one book (the next after the last one swept): what
/// `unpaid` holds as paid moves on, and an unpaid order whose payment can
/// no longer confirm goes, judged by the tips instant checkout caches.
/// Answers whether anything was written.
pub(crate) fn sweep<S: SecretStore>(secrets: &mut S) -> bool {
    let tip_of = cached_tips(secrets);
    let all: Vec<Vec<u8>> = books(secrets).into_iter().collect();
    if all.is_empty() {
        return false;
    }
    let last = secrets.get_secret(SWEEP_CURSOR_KEY);
    let next = all
        .iter()
        .find(|b| last.as_ref().is_none_or(|l| b.as_slice() > l.as_slice()))
        .unwrap_or(&all[0])
        .clone();
    if last.as_deref() != Some(next.as_slice()) {
        secrets.set_secret(SWEEP_CURSOR_KEY, &next);
    }
    let Some(store_key) = bs58::decode(&next)
        .into_vec()
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
    else {
        return false;
    };
    // The unpaid stage only, unless something there is to move on: the
    // larger stages are decoded only then (the delegate budget's wake-up
    // row measured a sweep of the whole book at 81% of a call).
    let Some(unpaid) = read::<_, Vec<SellerKeptOrder>>(secrets, &unpaid_key(&store_key)) else {
        return false;
    };
    let moving = unpaid.iter().any(|r| !is_awaiting(r));
    let sent = unpaid
        .iter()
        .any(|r| !is_awaiting(r) && r.despatch.is_some());
    let mut book = Book {
        unpaid,
        ..Book::default()
    };
    if moving {
        let Some(open) = read(secrets, &open_key(&store_key)) else {
            return false;
        };
        book.open = open;
        if sent {
            let Some(done) = read(secrets, &done_key(&store_key)) else {
                return false;
            };
            book.done = done;
        }
    }
    let before = book.clone();
    book.dedupe();
    book.promote();
    let lapse = harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS
        + harvest_common::payment::PAYMENT_CONFIRMATION_SLACK_BLOCKS;
    book.unpaid.retain(|r| {
        if !is_awaiting(r) {
            return true;
        }
        match (r.order.order.anchor.as_ref(), tip_of(r.order.order.network)) {
            (Some(anchor), Some(tip)) => tip.saturating_sub(anchor.height) <= lapse,
            _ => true,
        }
    });
    book != before && book.save(secrets, &store_key, &before)
}

/// A predecessor generation's book (a delegate re-key), merged into this
/// one's: each record taken as the predecessor wrote it
/// ([`Source::Predecessor`]), filed under the same caps, nothing held lost.
pub(crate) fn import<S: SecretStore>(
    secrets: &mut S,
    key: &[u8],
    value: &[u8],
) -> harvest_common::delegate::SecretImport {
    use harvest_common::delegate::SecretImport;
    let Some(rest) = key.strip_prefix(SELLER_ORDERS_PREFIX.as_bytes()) else {
        return SecretImport::Permanent("not a seller's order book".into());
    };
    let (records, name) = if let Some(name) = rest.strip_prefix(b"open:") {
        match from_cbor::<OpenBook>(value) {
            // Its refused names are not carried: a paid order the store
            // still holds is named again when the tab offers it.
            Ok(book) => (book.orders, name),
            Err(_) => {
                return SecretImport::Permanent("the predecessor's book did not decode".into())
            }
        }
    } else if let Some(name) = rest
        .strip_prefix(b"done:")
        .or_else(|| rest.strip_prefix(b"unpaid:"))
    {
        match from_cbor::<Vec<SellerKeptOrder>>(value) {
            Ok(orders) => (orders, name),
            Err(_) => {
                return SecretImport::Permanent("the predecessor's book did not decode".into())
            }
        }
    } else {
        // The sweep's place, rebuilt here.
        return SecretImport::AlreadyAuthoritative;
    };
    let Some(store_key) = bs58::decode(name)
        .into_vec()
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
    else {
        return SecretImport::Permanent("the predecessor's book names no store key".into());
    };
    match file_all(secrets, &store_key, records, Source::Predecessor) {
        Ok(0) => SecretImport::AlreadyAuthoritative,
        Ok(_) => SecretImport::Written,
        Err(why) => SecretImport::Retryable(why),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::kept_purchases::fixtures::{authorized, order, store_signing_key};
    use crate::secrets::MemSecrets;
    use harvest_common::fulfilment::{AuthorizedDespatch, Despatch};
    use harvest_common::listing::ListingId;
    use harvest_common::payment::AuthorizedOrder;

    pub(crate) fn store_key() -> [u8; 32] {
        store_signing_key().verifying_key().to_bytes()
    }

    /// A node holding the fixtures' store key.
    pub(crate) fn seller() -> MemSecrets {
        let mut secrets = MemSecrets::default();
        secrets.set_secret(
            &crate::store_keys::store_key_secret(&store_signing_key().verifying_key()),
            &store_signing_key().to_bytes(),
        );
        secrets
    }

    fn signed(n: u16, status: OrderStatus) -> AuthorizedOrder {
        authorized(&store_signing_key(), order(n, 1), status, 1)
    }

    fn request(shipping: &str) -> KeptRequest {
        KeptRequest {
            listing_id: ListingId([4; 32]),
            quantity: 1,
            shipping: shipping.into(),
            note: String::new(),
            region: None,
            choices: Vec::new(),
            conversation: [7; 32],
        }
    }

    pub(crate) fn record(n: u16, status: OrderStatus) -> SellerKeptOrder {
        SellerKeptOrder {
            order: signed(n, status),
            request: Some(request(&format!("{n} High Street"))),
            despatch: None,
            paid_height: None,
            sent_off_store: false,
            seal: None,
        }
    }

    pub(crate) fn despatch(order: &AuthorizedOrder, height: u32) -> AuthorizedDespatch {
        let despatch = Despatch {
            order_id: order.order.id.clone(),
            anchor: freenet_bitcoin_common::BlockAnchor {
                height,
                hash: freenet_bitcoin_common::BlockHash([3; 32]),
            },
        };
        let (scoped_payload, signature) = harvest_common::backing::sign_with_store_key(
            &store_signing_key(),
            to_cbor(&despatch).unwrap(),
        )
        .unwrap();
        AuthorizedDespatch {
            despatch,
            scoped_payload,
            signature,
        }
    }

    fn kept(secrets: &mut MemSecrets, orders: Vec<SellerKeptOrder>) -> Result<u32, String> {
        match keep(secrets, 1, store_key(), orders) {
            HarvestDelegateResponse::SellerOrdersKept { result, .. } => result,
            other => panic!("{other:?}"),
        }
    }

    pub(crate) fn whole(secrets: &MemSecrets) -> (Vec<SellerKeptOrder>, Vec<OrderId>) {
        let (mut all, mut refused, mut after) = (Vec::new(), Vec::new(), None);
        loop {
            match list(secrets, 2, store_key(), after) {
                HarvestDelegateResponse::SellerOrders {
                    result: Ok(page), ..
                } => {
                    all.extend(page.orders);
                    refused.extend(page.paid_refused);
                    match page.next {
                        Some(next) => after = Some(next),
                        None => return (all, refused),
                    }
                }
                other => panic!("{other:?}"),
            }
        }
    }

    fn held(secrets: &MemSecrets, n: u16) -> Option<SellerKeptOrder> {
        let id = signed(n, OrderStatus::AwaitingPayment).order.id;
        whole(secrets)
            .0
            .into_iter()
            .find(|r| r.order.order.id == id)
    }

    /// Kept only for a store whose key this node holds, and only records
    /// that check: a record another key signed refuses the call, a `Paid`
    /// on evidence that is not the minimal proof is kept as its unpaid
    /// terms, a request is cut to its bounds. Mutated red by keeping for a
    /// store whose key is not held, and by keeping a padded `Paid` as paid.
    #[test]
    fn only_checked_records_of_a_held_store_are_kept() {
        let mut stranger = MemSecrets::default();
        assert!(kept(&mut stranger, vec![record(1, OrderStatus::AwaitingPayment)]).is_err());

        let mut secrets = seller();
        let mut forged = record(2, OrderStatus::AwaitingPayment);
        forged.order = authorized(
            &crate::kept_purchases::fixtures::other_store_signing_key(),
            order(2, 1),
            OrderStatus::AwaitingPayment,
            1,
        );
        // Left out, not the call: one bad record must not hold back the
        // rest of a batch.
        assert_eq!(
            kept(
                &mut secrets,
                vec![forged, record(5, OrderStatus::AwaitingPayment)]
            ),
            Ok(1)
        );
        assert!(held(&secrets, 2).is_none());

        let mut padded = record(3, OrderStatus::Paid);
        if let Some(harvest_common::payment::OrderPaymentProof::OnChain(p)) =
            padded.order.payment_proof.as_mut()
        {
            let again = p.claims[0].clone();
            p.claims.push(again);
        }
        let mut long = record(4, OrderStatus::AwaitingPayment);
        long.request.as_mut().unwrap().shipping = "é".repeat(MAX_KEPT_REQUEST_TEXT);
        assert_eq!(kept(&mut secrets, vec![padded, long]), Ok(2));
        assert_eq!(
            held(&secrets, 3).unwrap().order.status,
            OrderStatus::AwaitingPayment
        );
        let shipping = held(&secrets, 4).unwrap().request.unwrap().shipping;
        assert!(
            shipping.len() <= MAX_KEPT_REQUEST_TEXT && shipping.len() >= MAX_KEPT_REQUEST_TEXT - 1
        );
    }

    /// Step 2 (the overseer, 2026-10-09): an honest payment past the
    /// store's byte bound still reaches the seller as paid. The store keeps
    /// such an order unpaid; the book keeps it paid, without the proof and
    /// with the height it confirmed at, and keeps it so when it comes back
    /// through an import. A padded proof is still kept unpaid. Mutated red by
    /// keeping it unpaid as the store does.
    #[test]
    fn an_honest_payment_past_the_byte_bound_is_kept_paid() {
        let mut secrets = seller();
        let terms = order(9, 1);
        let mut big = record(9, OrderStatus::Paid);
        big.order = authorized(&store_signing_key(), terms.clone(), OrderStatus::Paid, 1);
        big.order.payment_proof = Some(crate::kept_purchases::fixtures::big_proof(
            &terms,
            harvest_common::store::MAX_ORDER_BYTES,
        ));
        assert!(!harvest_common::store::within_order_cap(&big.order));
        assert_eq!(
            harvest_common::store::as_kept(big.order.clone()).status,
            OrderStatus::AwaitingPayment,
            "the store keeps it unpaid"
        );
        kept(&mut secrets, vec![big]).unwrap();
        let held = held(&secrets, 9).unwrap();
        assert_eq!(held.order.status, OrderStatus::Paid);
        assert!(held.order.payment_proof.is_none());
        assert_eq!(held.paid_height, Some(100));
        // Back through an import, it stays paid.
        let mut successor = seller();
        let key = open_key(&store_key());
        crate::import::import_secret(&mut successor, &key, &secrets.get_secret(&key).unwrap());
        assert_eq!(
            super::tests::held(&successor, 9).unwrap().order.status,
            OrderStatus::Paid
        );
    }

    /// Merging never loses what is held: a record seen again without its
    /// request keeps the request; paid replaces unpaid and gains the
    /// proof; a despatch moves it to the sent half; a cancellation of an
    /// unpaid order drops it. Mutated red by taking the incoming record
    /// whole, and by keeping a cancelled unpaid order.
    #[test]
    fn what_is_held_is_never_lost() {
        let mut secrets = seller();
        kept(&mut secrets, vec![record(1, OrderStatus::AwaitingPayment)]).unwrap();
        let mut bare = record(1, OrderStatus::Paid);
        bare.request = None;
        kept(&mut secrets, vec![bare]).unwrap();
        let now = held(&secrets, 1).unwrap();
        assert_eq!(now.order.status, OrderStatus::Paid);
        assert!(now.order.payment_proof.is_some());
        assert_eq!(now.request, Some(request("1 High Street")));
        assert_eq!(now.paid_height, Some(100), "from the proof");

        let mut sent = now.clone();
        sent.despatch = Some(despatch(&now.order, 120));
        sent.request = None;
        kept(&mut secrets, vec![sent]).unwrap();
        let open: OpenBook =
            from_cbor(&secrets.get_secret(&open_key(&store_key())).unwrap()).unwrap();
        assert!(open.orders.is_empty(), "sent: out of the open half");
        assert!(held(&secrets, 1).unwrap().despatch.is_some());
        assert!(held(&secrets, 1).unwrap().request.is_some());

        kept(&mut secrets, vec![record(2, OrderStatus::AwaitingPayment)]).unwrap();
        let mut cancelled = record(2, OrderStatus::AwaitingPayment);
        cancelled.order.status = OrderStatus::Cancelled;
        // A cancellation carries the seller's status signature; the book
        // drops the record whatever it carries, before any check of it.
        let mut book = Book::default();
        book.file(record(2, OrderStatus::AwaitingPayment));
        assert_eq!(book.file(cancelled), Filed::Dropped);
        assert!(book.unpaid.is_empty());
    }

    /// Caps: unpaid orders past `MAX_SELLER_UNPAID_KEPT` lose their oldest;
    /// a paid order not yet sent past `MAX_SELLER_UNSENT_KEPT` is never
    /// evicted for, nor evicts: it is named in `paid_refused` and kept once
    /// one is sent; the sent half keeps its newest `MAX_SELLER_SENT_KEPT`.
    /// Mutated red by evicting the oldest paid order to make room, and by
    /// refusing in silence.
    #[test]
    fn a_paid_order_is_never_evicted_and_one_past_the_cap_is_named() {
        let mut book = Book::default();
        for n in 0..(MAX_SELLER_UNPAID_KEPT as u16 + 3) {
            let mut r = record(n, OrderStatus::AwaitingPayment);
            r.request = None;
            book.file(r);
        }
        assert_eq!(book.unpaid.len(), MAX_SELLER_UNPAID_KEPT);
        let first_kept = signed(3, OrderStatus::AwaitingPayment).order.id;
        assert_eq!(book.unpaid[0].order.order.id, first_kept, "the oldest went");

        let mut book = Book::default();
        let paid = |n: u16| SellerKeptOrder {
            order: signed(n, OrderStatus::Paid),
            request: None,
            despatch: None,
            paid_height: Some(100),
            sent_off_store: false,
            seal: None,
        };
        for n in 0..MAX_SELLER_UNSENT_KEPT as u16 {
            assert_eq!(book.file(paid(n)), Filed::Kept);
        }
        let over = MAX_SELLER_UNSENT_KEPT as u16;
        assert_eq!(book.file(paid(over)), Filed::Refused);
        assert_eq!(book.open.orders.len(), MAX_SELLER_UNSENT_KEPT);
        assert!(book
            .open
            .orders
            .iter()
            .any(|r| r.order.order.id == paid(0).order.order.id));
        assert_eq!(book.open.paid_refused, vec![paid(over).order.order.id]);
        // One held unpaid that is then paid, with the stage full: it stays,
        // marked paid, its ship-to with it, and is named too.
        let held = record(
            MAX_SELLER_UNSENT_KEPT as u16 + 1,
            OrderStatus::AwaitingPayment,
        );
        book.file(held.clone());
        let mut now_paid = held.clone();
        now_paid.order = signed(MAX_SELLER_UNSENT_KEPT as u16 + 1, OrderStatus::Paid);
        now_paid.request = None;
        assert_eq!(book.file(now_paid), Filed::Refused);
        let stays = book
            .unpaid
            .iter()
            .find(|r| r.order.order.id == held.order.order.id)
            .expect("still held");
        assert_eq!(stays.order.status, OrderStatus::Paid);
        assert_eq!(stays.request, held.request);
        // One sent: room, and the refused one is kept when it comes again.
        let mut sent = paid(0);
        sent.despatch = Some(despatch(&sent.order, 120));
        book.file(sent);
        assert_eq!(book.file(paid(over)), Filed::Kept);
        assert!(!book.open.paid_refused.contains(&paid(over).order.order.id));

        let mut book = Book::default();
        for n in 0..(MAX_SELLER_SENT_KEPT as u16 + 2) {
            let mut r = paid(n);
            r.despatch = Some(despatch(&r.order, 120));
            book.file(r);
        }
        assert_eq!(book.done.len(), MAX_SELLER_SENT_KEPT);
        assert_eq!(book.done[0].order.order.id, paid(2).order.order.id);
        assert!(
            book.done[0].order.payment_proof.is_none(),
            "history keeps no proof"
        );
    }

    /// The store's statuses: an open order the store shows paid is marked
    /// paid, one it shows cancelled while unpaid goes, and nothing is
    /// written when nothing changed. Mutated red by not marking paid.
    #[test]
    fn a_store_notification_marks_paid_and_drops_cancelled() {
        let mut secrets = seller();
        // As instant checkout writes them: into the unpaid stage.
        keep_signed(
            &mut secrets,
            &store_key(),
            vec![
                record(1, OrderStatus::AwaitingPayment),
                record(2, OrderStatus::AwaitingPayment),
            ],
        )
        .then_some(())
        .unwrap();
        let one = signed(1, OrderStatus::AwaitingPayment).order.id;
        let two = signed(2, OrderStatus::AwaitingPayment).order.id;
        on_store_statuses(&mut secrets, &store_key(), |id| {
            if *id == one {
                Some(OrderStatus::Paid)
            } else if *id == two {
                Some(OrderStatus::Cancelled)
            } else {
                None
            }
        });
        let (all, _) = whole(&secrets);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].order.status, OrderStatus::Paid);
        assert!(all[0].request.is_some(), "with its ship-to");
        // A wake-up moves it on from the unpaid stage.
        assert!(sweep(&mut secrets));
        let unpaid: Vec<SellerKeptOrder> =
            from_cbor(&secrets.get_secret(&unpaid_key(&store_key())).unwrap()).unwrap();
        assert!(unpaid.is_empty(), "moved on");
        let open: OpenBook =
            from_cbor(&secrets.get_secret(&open_key(&store_key())).unwrap()).unwrap();
        assert_eq!(open.orders.len(), 1);
        assert_eq!(whole(&secrets).0, all);
    }

    /// The sweep drops an unpaid order past its payment window; the next
    /// tab call drops a sent order's request once its complaint window has
    /// closed, and not before; a paid order never sent keeps its request (as
    /// the app shows it). Mutated red by keeping the request past the
    /// window, and by dropping a never-sent order's.
    #[test]
    fn the_sweep_drops_lapsed_orders_and_closed_ship_tos() {
        let mut secrets = seller();
        let lapse = harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS
            + harvest_common::payment::PAYMENT_CONFIRMATION_SLACK_BLOCKS;
        let mut sent = record(2, OrderStatus::Paid);
        sent.despatch = Some(despatch(&sent.order, 120));
        kept(
            &mut secrets,
            vec![
                record(1, OrderStatus::AwaitingPayment),
                sent,
                record(3, OrderStatus::Paid),
            ],
        )
        .unwrap();
        let tip_at = |secrets: &mut MemSecrets, height: u32| {
            crate::auto_invoice::save(
                secrets,
                &crate::auto_invoice::tip_key(freenet_bitcoin_common::BitcoinNetwork::Signet),
                &crate::auto_invoice::TipCache {
                    anchor: freenet_bitcoin_common::BlockAnchor {
                        height,
                        hash: freenet_bitcoin_common::BlockHash([1; 32]),
                    },
                    block_time: 0,
                },
            );
        };
        // The unpaid one lapses past 99 + `lapse` (2163); the sent one's
        // window ends at max(100 + 1008, 120) + 2016 = 3124.
        tip_at(&mut secrets, 99 + lapse);
        sweep(&mut secrets);
        assert!(
            held(&secrets, 1).is_some(),
            "anchor 99 + {lapse} not passed"
        );
        assert!(
            held(&secrets, 2).unwrap().request.is_some(),
            "window still open"
        );
        tip_at(&mut secrets, 3125);
        sweep(&mut secrets);
        assert!(held(&secrets, 1).is_none(), "lapsed");
        // The sent stage is the tab's to clean: the next tab call.
        assert!(
            held(&secrets, 2).unwrap().request.is_some(),
            "not by the sweep, which leaves the sent stage alone"
        );
        kept(&mut secrets, Vec::new()).unwrap();
        assert!(
            held(&secrets, 2).unwrap().request.is_none(),
            "window closed"
        );
        assert!(held(&secrets, 3).unwrap().request.is_some(), "never sent");
    }

    /// Paged by order id, each page about `SELLER_ORDERS_PAGE_BYTES`, every
    /// order once. Mutated red by a cursor that does not move.
    #[test]
    fn the_book_is_listed_in_pages_every_order_once() {
        let mut secrets = seller();
        for chunk in 0..6u16 {
            let records = (0..40u16)
                .map(|i| {
                    let mut r = record(chunk * 40 + i, OrderStatus::AwaitingPayment);
                    r.request.as_mut().unwrap().note = "n".repeat(MAX_KEPT_REQUEST_TEXT);
                    r
                })
                .collect();
            // 240 unpaid: the 128 newest are kept.
            kept(&mut secrets, records).unwrap();
        }
        let (all, _) = whole(&secrets);
        assert_eq!(all.len(), MAX_SELLER_UNPAID_KEPT);
        let mut ids: Vec<_> = all.iter().map(|r| r.order.order.id.0).collect();
        ids.dedup();
        assert_eq!(ids.len(), MAX_SELLER_UNPAID_KEPT);
        assert!(matches!(
            list(&secrets, 1, store_key(), None),
            HarvestDelegateResponse::SellerOrders {
                result: Ok(SellerOrdersPage { next: Some(_), .. }),
                ..
            }
        ));
    }

    /// A delegate re-key carries the book: the predecessor's records merge
    /// into the successor's, nothing held lost. Mutated red by writing the
    /// predecessor's over the successor's.
    #[test]
    fn a_predecessors_book_is_merged() {
        let mut old = seller();
        kept(
            &mut old,
            vec![
                record(1, OrderStatus::Paid),
                record(2, OrderStatus::AwaitingPayment),
            ],
        )
        .unwrap();
        let mut new = seller();
        let mut bare = record(1, OrderStatus::AwaitingPayment);
        bare.request = None;
        kept(
            &mut new,
            vec![bare, record(3, OrderStatus::AwaitingPayment)],
        )
        .unwrap();
        for key in [open_key(&store_key()), unpaid_key(&store_key())] {
            let value = old.get_secret(&key).unwrap();
            assert!(matches!(
                crate::import::import_secret(&mut new, &key, &value),
                harvest_common::delegate::SecretImport::Written
            ));
        }
        let (all, _) = whole(&new);
        assert_eq!(all.len(), 3);
        let one = all
            .iter()
            .find(|r| r.order.order.id == signed(1, OrderStatus::Paid).order.id)
            .unwrap();
        assert_eq!(one.order.status, OrderStatus::Paid);
        assert!(one.request.is_some());
    }

    /// At most `MAX_SELLER_BOOKS` stores' books. Mutated red by no cap.
    #[test]
    fn books_are_capped() {
        let mut secrets = seller();
        for b in 0..MAX_SELLER_BOOKS as u8 {
            secrets.set_secret(&open_key(&[b; 32]), &to_cbor(&OpenBook::default()).unwrap());
        }
        assert!(
            kept(&mut secrets, vec![record(1, OrderStatus::AwaitingPayment)])
                .unwrap_err()
                .contains("the most it keeps")
        );
    }

    /// The stage `open` full of paid orders not yet sent.
    fn open_full(secrets: &mut MemSecrets) {
        let orders = (0..MAX_SELLER_UNSENT_KEPT as u16)
            .map(|n| SellerKeptOrder {
                order: signed(2000 + n, OrderStatus::Paid),
                request: None,
                despatch: None,
                paid_height: Some(100),
                sent_off_store: false,
                seal: None,
            })
            .collect();
        secrets.set_secret(
            &open_key(&store_key()),
            &to_cbor(&OpenBook {
                orders,
                paid_refused: Vec::new(),
            })
            .unwrap(),
        );
    }

    /// Review round 2 of step 2 (every lens): the 513th paid order, signed
    /// by instant checkout and marked paid by a store notification, waits in
    /// `unpaid` with its ship-to through the wake-up's move and the tab's
    /// next call, and is named. It was lost: the move took it out of
    /// `unpaid` before filing it, and a refusal kept only a record still
    /// held there. Mutated red by keeping only a record held before (the
    /// old condition), and by not keeping a waiting one at all.
    #[test]
    fn the_513th_paid_order_waits_with_its_ship_to_through_every_path() {
        let mut secrets = seller();
        open_full(&mut secrets);
        let late = record(600, OrderStatus::AwaitingPayment);
        assert!(keep_signed(&mut secrets, &store_key(), vec![late.clone()]));
        let id = late.order.order.id.clone();
        on_store_statuses(&mut secrets, &store_key(), |o| {
            (*o == id).then_some(OrderStatus::Paid)
        });
        sweep(&mut secrets);
        let check = |secrets: &MemSecrets, when: &str| {
            let (all, refused) = whole(secrets);
            let kept = all
                .iter()
                .find(|r| r.order.order.id == id)
                .unwrap_or_else(|| panic!("{when}: the 513th paid order is lost"));
            assert_eq!(kept.order.status, OrderStatus::Paid, "{when}");
            assert_eq!(kept.request, late.request, "{when}: its ship-to");
            assert!(refused.contains(&id), "{when}: named");
        };
        check(&secrets, "after the wake-up");
        assert_eq!(kept(&mut secrets, Vec::new()), Ok(0));
        check(&secrets, "after the tab's next call");
    }

    /// At most `MAX_SELLER_UNPAID_KEPT` paid orders wait in `unpaid` (which
    /// instant checkout and every store notification read); past that only
    /// the id is kept, and named. Mutated red by no bound on waiting ones.
    #[test]
    fn waiting_paid_orders_are_bounded_and_every_one_is_named() {
        let mut book = Book::default();
        for n in 0..MAX_SELLER_UNSENT_KEPT as u16 {
            book.open.orders.push(SellerKeptOrder {
                order: signed(n, OrderStatus::Paid),
                request: None,
                despatch: None,
                paid_height: Some(100),
                sent_off_store: false,
                seal: None,
            });
        }
        let waiting = MAX_SELLER_UNPAID_KEPT as u16;
        for n in 0..=waiting {
            let mut r = record(3000 + n, OrderStatus::AwaitingPayment);
            r.order = signed(3000 + n, OrderStatus::Paid);
            assert_eq!(book.file(r), Filed::Refused);
        }
        assert_eq!(book.unpaid.len(), MAX_SELLER_UNPAID_KEPT);
        assert!(book.unpaid.iter().all(|r| r.request.is_some()));
        let last = signed(3000 + waiting, OrderStatus::Paid).order.id;
        assert!(!book.unpaid.iter().any(|r| r.order.order.id == last));
        assert_eq!(book.open.paid_refused.len(), MAX_SELLER_UNPAID_KEPT + 1);
        assert!(book.open.paid_refused.contains(&last));
    }

    /// Review round 2 of step 2 (codex, skeptical, code-first): a `Paid`
    /// without its proof from the tab, or a restored file, says nothing the
    /// store key signed, so it is kept as its unpaid terms (unless the book
    /// sealed it: `a_restored_book_keeps_what_the_book_held_by_its_seal`);
    /// a forged despatch is left out; and into a book that holds the order
    /// paid already it changes nothing. Mutated red by keeping a proofless
    /// `Paid` as paid.
    #[test]
    fn a_tab_cannot_make_an_order_paid_without_its_proof() {
        let proofless = |n: u16| {
            let mut r = record(n, OrderStatus::AwaitingPayment);
            r.order.status = OrderStatus::Paid;
            r.order.payment_proof = None;
            r
        };
        let mut secrets = seller();
        assert_eq!(kept(&mut secrets, vec![proofless(1)]), Ok(1));
        assert_eq!(
            held(&secrets, 1).unwrap().order.status,
            OrderStatus::AwaitingPayment,
            "kept as its unpaid terms"
        );
        // Even with the store key's despatch (round 4: the seal is what
        // vouches for a book's own sent orders).
        let mut sent = proofless(2);
        sent.despatch = Some(despatch(&sent.order, 120));
        kept(&mut secrets, vec![sent]).unwrap();
        assert_eq!(
            held(&secrets, 2).unwrap().order.status,
            OrderStatus::AwaitingPayment
        );
        let mut forged = proofless(3);
        let mut other = despatch(&signed(4, OrderStatus::Paid), 120);
        other.despatch.order_id = forged.order.order.id.clone();
        forged.despatch = Some(other);
        assert_eq!(kept(&mut secrets, vec![forged]), Ok(0), "a forged despatch");
        assert!(held(&secrets, 3).is_none());
        // Marked paid by the store's own notification first: the tab's
        // proofless copy leaves it paid.
        assert!(keep_signed(
            &mut secrets,
            &store_key(),
            vec![record(5, OrderStatus::AwaitingPayment)]
        ));
        let five = signed(5, OrderStatus::AwaitingPayment).order.id;
        on_store_statuses(&mut secrets, &store_key(), |o| {
            (*o == five).then_some(OrderStatus::Paid)
        });
        kept(&mut secrets, vec![proofless(5)]).unwrap();
        assert_eq!(held(&secrets, 5).unwrap().order.status, OrderStatus::Paid);
    }

    /// Review round 2 of step 2 (codex, skeptical): a record moving on is
    /// written to its new stage before it leaves the old, so a host that
    /// refuses a write part-way leaves it in two stages, never none, and the
    /// book reads it from the later one. Mutated red by writing `unpaid`
    /// first, and by reading a record in two stages twice.
    #[test]
    fn a_save_refused_part_way_loses_no_order() {
        let mut secrets = seller();
        let r = record(1, OrderStatus::AwaitingPayment);
        assert!(keep_signed(&mut secrets, &store_key(), vec![r.clone()]));
        let id = r.order.order.id.clone();
        on_store_statuses(&mut secrets, &store_key(), |o| {
            (*o == id).then_some(OrderStatus::Paid)
        });
        // The move to `open` written, the `unpaid` write refused.
        secrets.refused_prefix = Some(unpaid_key(&store_key()));
        assert!(kept(&mut secrets, Vec::new()).is_err());
        secrets.refused_prefix = None;
        let (all, _) = whole(&secrets);
        assert_eq!(
            all.iter().filter(|o| o.order.order.id == id).count(),
            1,
            "held once"
        );
        assert_eq!(
            all.iter()
                .find(|o| o.order.order.id == id)
                .unwrap()
                .order
                .status,
            OrderStatus::Paid
        );
        // And the write that was refused goes through next time.
        assert_eq!(kept(&mut secrets, Vec::new()), Ok(0));
        let unpaid: Vec<SellerKeptOrder> =
            from_cbor(&secrets.get_secret(&unpaid_key(&store_key())).unwrap()).unwrap();
        assert!(unpaid.is_empty());

        // The move's destination refused: the order stays where it was.
        let mut secrets = seller();
        let r = record(2, OrderStatus::AwaitingPayment);
        assert!(keep_signed(&mut secrets, &store_key(), vec![r.clone()]));
        let id = r.order.order.id.clone();
        on_store_statuses(&mut secrets, &store_key(), |o| {
            (*o == id).then_some(OrderStatus::Paid)
        });
        secrets.refused_prefix = Some(open_key(&store_key()));
        assert!(kept(&mut secrets, Vec::new()).is_err());
        assert!(
            held(&secrets, 2).is_some_and(|o| o.request == r.request),
            "not lost with its ship-to"
        );
    }

    /// Review round 2 of step 2 (code-first): instant checkout files only an
    /// order its stage does not hold. One held and marked paid since, signed
    /// again, stays as it is (it was moved to a stage `keep_signed` never
    /// writes, and lost). Mutated red by filing it again.
    #[test]
    fn instant_checkout_never_refiles_an_order_it_holds() {
        let mut secrets = seller();
        let r = record(1, OrderStatus::AwaitingPayment);
        assert!(keep_signed(&mut secrets, &store_key(), vec![r.clone()]));
        let id = r.order.order.id.clone();
        on_store_statuses(&mut secrets, &store_key(), |o| {
            (*o == id).then_some(OrderStatus::Paid)
        });
        assert!(keep_signed(&mut secrets, &store_key(), vec![r]));
        assert_eq!(held(&secrets, 1).unwrap().order.status, OrderStatus::Paid);
    }

    /// A predecessor's book is taken as it was written (its signatures are
    /// not checked again, which a full book could not afford), held only to
    /// this generation's bounds; its refused names are not carried (a paid
    /// order the store still holds is named again when the tab offers it).
    /// Mutated red by checking a predecessor's records as the tab's (the
    /// record below would be kept unpaid).
    #[test]
    fn a_predecessors_book_is_taken_as_written() {
        let mut old = seller();
        let mut over = record(1, OrderStatus::Paid);
        // As the predecessor kept it past the store's byte bound: no proof.
        over.order.payment_proof = None;
        over.paid_height = Some(100);
        let named = signed(9, OrderStatus::Paid).order.id;
        old.set_secret(
            &open_key(&store_key()),
            &to_cbor(&OpenBook {
                orders: vec![over],
                paid_refused: vec![named.clone()],
            })
            .unwrap(),
        );
        let mut new = seller();
        let value = old.get_secret(&open_key(&store_key())).unwrap();
        assert!(matches!(
            crate::import::import_secret(&mut new, &open_key(&store_key()), &value),
            harvest_common::delegate::SecretImport::Written
        ));
        let (all, refused) = whole(&new);
        assert_eq!(all[0].order.status, OrderStatus::Paid, "kept paid");
        assert!(!refused.contains(&named));
    }

    /// Review round 2 of step 2 (testing lens): the wake-up sweeps each
    /// book in turn, not the first one every time. Mutated red by always
    /// sweeping the first.
    #[test]
    fn the_sweep_takes_each_book_in_turn() {
        let mut secrets = seller();
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x51; 32]);
        crate::store_keys::keep(&mut secrets, &other);
        let mut ids = Vec::new();
        for (key, signer) in [
            (store_key(), store_signing_key()),
            (other.verifying_key().to_bytes(), other.clone()),
        ] {
            let mut r = record(1, OrderStatus::AwaitingPayment);
            r.order = authorized(&signer, order(1, 1), OrderStatus::AwaitingPayment, 1);
            let id = r.order.order.id.clone();
            assert!(keep_signed(&mut secrets, &key, vec![r]));
            on_store_statuses(&mut secrets, &key, |o| {
                (*o == id).then_some(OrderStatus::Paid)
            });
            ids.push(key);
        }
        assert!(sweep(&mut secrets));
        assert!(sweep(&mut secrets));
        for key in ids {
            let unpaid: Vec<SellerKeptOrder> =
                from_cbor(&secrets.get_secret(&unpaid_key(&key)).unwrap()).unwrap();
            assert!(unpaid.is_empty(), "every book was swept");
        }
    }

    /// A request is held to its bounds: each text cut to
    /// `MAX_KEPT_REQUEST_TEXT` bytes at a character boundary, and no more
    /// choices than a listing may have groups. Mutated red by leaving the
    /// note, a choice or the choice count unbounded.
    #[test]
    fn a_request_is_held_to_its_bounds() {
        let long = "é".repeat(MAX_KEPT_REQUEST_TEXT);
        let r = bounded(KeptRequest {
            shipping: long.clone(),
            note: long.clone(),
            region: Some(long.clone()),
            choices: vec![long.clone(); harvest_common::listing::MAX_CHOICE_GROUPS + 3],
            ..request("x")
        });
        for text in [&r.shipping, &r.note, r.region.as_ref().unwrap()]
            .into_iter()
            .chain(&r.choices)
        {
            assert!(text.len() <= MAX_KEPT_REQUEST_TEXT && text.len() > MAX_KEPT_REQUEST_TEXT - 2);
            assert!(text.chars().all(|c| c == 'é'));
        }
        assert_eq!(r.choices.len(), harvest_common::listing::MAX_CHOICE_GROUPS);
    }

    /// Filing what the book already holds, where it holds it, changes
    /// nothing and is not counted; a store notification that changes
    /// nothing writes nothing. Mutated red by counting an unchanged record,
    /// and by writing on every notification.
    #[test]
    fn nothing_changed_is_neither_counted_nor_written() {
        let mut secrets = seller();
        let r = record(1, OrderStatus::AwaitingPayment);
        assert_eq!(kept(&mut secrets, vec![r.clone()]), Ok(1));
        assert_eq!(kept(&mut secrets, vec![r.clone()]), Ok(0));
        let writes = secrets.write_log.len();
        on_store_statuses(&mut secrets, &store_key(), |_| {
            Some(OrderStatus::AwaitingPayment)
        });
        assert_eq!(secrets.write_log.len(), writes);
    }

    /// The refused names are bounded too, the newest kept; and they come
    /// with the first page of a listing only, however many pages there are.
    /// Mutated red by no bound on the names, and by sending them on every
    /// page.
    #[test]
    fn refused_names_are_bounded_and_listed_once() {
        let mut book = Book::default();
        for n in 0..MAX_SELLER_UNSENT_KEPT as u16 {
            book.open.orders.push(SellerKeptOrder {
                order: signed(n, OrderStatus::Paid),
                request: Some(request(&"s".repeat(MAX_KEPT_REQUEST_TEXT))),
                despatch: None,
                paid_height: Some(100),
                sent_off_store: false,
                seal: None,
            });
        }
        let over = MAX_SELLER_UNSENT_KEPT as u16 + 40;
        for n in 0..over {
            let paid = signed(4000 + n, OrderStatus::Paid);
            book.file(SellerKeptOrder {
                order: paid,
                request: None,
                despatch: None,
                paid_height: Some(100),
                sent_off_store: false,
                seal: None,
            });
        }
        assert_eq!(book.open.paid_refused.len(), MAX_SELLER_UNSENT_KEPT);
        let newest = signed(4000 + over - 1, OrderStatus::Paid).order.id;
        assert!(book.open.paid_refused.contains(&newest));
        let mut secrets = seller();
        assert!(book.save(&mut secrets, &store_key(), &Book::default()));
        let mut pages = Vec::new();
        let mut after = None;
        loop {
            match list(&secrets, 1, store_key(), after) {
                HarvestDelegateResponse::SellerOrders {
                    result: Ok(page), ..
                } => {
                    after = page.next.clone();
                    pages.push(page);
                    if after.is_none() {
                        break;
                    }
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(pages.len() > 1, "several pages");
        assert_eq!(pages[0].paid_refused.len(), MAX_SELLER_UNSENT_KEPT);
        assert!(pages[1..].iter().all(|p| p.paid_refused.is_empty()));
    }

    /// Review round 3 of step 2 (skeptical, code-first, big-picture): a
    /// backup restored on another device that holds the store key keeps
    /// every paid or reversed order as the book had it, though the book
    /// keeps no proof for it: one past the store's byte bound, one marked
    /// paid by the store's notification, one sent, one reversed, by the
    /// book's own seal. Without the seal (or with one moved onto another
    /// record) a proofless `Paid` is its unpaid terms, as the tab's is.
    /// Mutated red by ignoring the seal, by not sealing a listing, and by
    /// sealing over the status alone.
    #[test]
    fn a_restored_book_keeps_what_the_book_held_by_its_seal() {
        let mut old = seller();
        let terms = order(9, 1);
        let mut big = record(9, OrderStatus::Paid);
        big.order = authorized(&store_signing_key(), terms.clone(), OrderStatus::Paid, 1);
        big.order.payment_proof = Some(crate::kept_purchases::fixtures::big_proof(
            &terms,
            harvest_common::store::MAX_ORDER_BYTES,
        ));
        kept(&mut old, vec![big]).unwrap();
        // Marked paid by a store notification: no proof ever.
        assert!(keep_signed(
            &mut old,
            &store_key(),
            vec![record(10, OrderStatus::AwaitingPayment)]
        ));
        let ten = signed(10, OrderStatus::AwaitingPayment).order.id;
        on_store_statuses(&mut old, &store_key(), |o| {
            (*o == ten).then_some(OrderStatus::Paid)
        });
        let mut sent = record(11, OrderStatus::Paid);
        sent.despatch = Some(despatch(&sent.order, 120));
        kept(&mut old, vec![sent]).unwrap();
        // Reversed, kept in history without its proof.
        let mut reversed = record(12, OrderStatus::Paid);
        reversed.despatch = Some(despatch(&reversed.order, 120));
        reversed.order.status = OrderStatus::PaymentReversed;
        reversed.order.payment_proof = None;
        let mut book = Book::load(&old, &store_key()).unwrap();
        let before = book.clone();
        book.file(reversed);
        assert!(book.save(&mut old, &store_key(), &before));
        assert_eq!(kept(&mut old, Vec::new()), Ok(0), "moved on");

        let (listed, _) = whole(&old);
        assert_eq!(listed.len(), 4);
        assert!(listed.iter().all(|r| r.seal.is_some()), "every one sealed");
        let mut new = seller();
        assert_eq!(kept(&mut new, listed.clone()), Ok(4));
        let (restored, _) = whole(&new);
        for r in &listed {
            let back = restored
                .iter()
                .find(|b| b.order.order.id == r.order.order.id)
                .expect("restored");
            assert_eq!(back.order.status, r.order.status, "{:?}", r.order.order.id);
            assert_eq!(back.paid_height, r.paid_height);
        }

        // Unsealed, or a seal moved onto another order: its unpaid terms.
        let mut other = seller();
        let mut unsealed = listed
            .iter()
            .find(|r| r.order.order.id == ten)
            .unwrap()
            .clone();
        let seal = unsealed.seal.take();
        kept(&mut other, vec![unsealed.clone()]).unwrap();
        let mut moved = record(13, OrderStatus::AwaitingPayment);
        moved.order.status = OrderStatus::Paid;
        moved.order.payment_proof = None;
        moved.seal = seal;
        kept(&mut other, vec![moved]).unwrap();
        let (got, _) = whole(&other);
        assert!(got
            .iter()
            .all(|r| r.order.status == OrderStatus::AwaitingPayment));
    }

    /// Review round 3 of step 2 (code-first): a move to the sent stage
    /// whose `done` write the host refuses leaves the order where it was.
    /// Mutated red by writing `open` after a refused `done`.
    #[test]
    fn a_refused_sent_stage_write_leaves_the_order_open() {
        let mut secrets = seller();
        kept(&mut secrets, vec![record(1, OrderStatus::Paid)]).unwrap();
        let mut sent = record(1, OrderStatus::Paid);
        sent.despatch = Some(despatch(&sent.order, 120));
        secrets.refused_prefix = Some(done_key(&store_key()));
        assert!(kept(&mut secrets, vec![sent]).is_err());
        secrets.refused_prefix = None;
        let open: OpenBook =
            from_cbor(&secrets.get_secret(&open_key(&store_key())).unwrap()).unwrap();
        assert_eq!(open.orders.len(), 1, "still in the paid stage");
    }

    /// A reversed order in the sent stage keeps no proof, as a sent one
    /// keeps none. Mutated red by stripping a paid one's only.
    #[test]
    fn history_keeps_no_proof_for_a_reversed_order_either() {
        let mut book = Book::default();
        let mut reversed = record(1, OrderStatus::Paid);
        reversed.despatch = Some(despatch(&reversed.order, 120));
        reversed.order.status = OrderStatus::PaymentReversed;
        assert!(reversed.order.payment_proof.is_some(), "precondition");
        book.file(reversed);
        assert_eq!(book.done.len(), 1);
        assert!(book.done[0].order.payment_proof.is_none());
    }

    /// A despatch the store key signed for another order is refused, not
    /// only one it did not sign. Mutated red by dropping the order check.
    #[test]
    fn a_despatch_for_another_order_is_refused() {
        let mut secrets = seller();
        let mut r = record(1, OrderStatus::Paid);
        r.despatch = Some(despatch(&signed(2, OrderStatus::Paid), 120));
        assert_eq!(kept(&mut secrets, vec![r]), Ok(0));
        assert!(held(&secrets, 1).is_none());
    }

    /// A predecessor's record is held to this generation's bounds: one
    /// cancelled, or with a despatch about another order, is skipped; a
    /// request is cut. Mutated red by dropping each.
    #[test]
    fn a_predecessors_book_is_held_to_this_generations_bounds() {
        let mut new = seller();
        let mut long = record(1, OrderStatus::Paid);
        long.request.as_mut().unwrap().note = "n".repeat(MAX_KEPT_REQUEST_TEXT + 10);
        let mut cancelled = record(2, OrderStatus::AwaitingPayment);
        cancelled.order.status = OrderStatus::Cancelled;
        let mut misfiled = record(3, OrderStatus::Paid);
        misfiled.despatch = Some(despatch(&signed(4, OrderStatus::Paid), 120));
        let value = to_cbor(&OpenBook {
            orders: vec![long, cancelled, misfiled],
            paid_refused: Vec::new(),
        })
        .unwrap();
        crate::import::import_secret(&mut new, &open_key(&store_key()), &value);
        let (all, _) = whole(&new);
        assert_eq!(all.len(), 1, "{all:?}");
        assert_eq!(
            all[0].request.as_ref().unwrap().note.len(),
            MAX_KEPT_REQUEST_TEXT
        );
    }

    /// Paid orders already waiting for room move on before one marked paid
    /// since, and a waiting one keeps its paid height and drops its proof.
    /// Mutated red by moving them in `created_at` order only, and by
    /// keeping the proof.
    #[test]
    fn those_waiting_longest_keep_their_place() {
        let mut book = Book::default();
        for n in 0..MAX_SELLER_UNSENT_KEPT as u16 {
            book.open.orders.push(SellerKeptOrder {
                order: signed(n, OrderStatus::Paid),
                request: None,
                despatch: None,
                paid_height: Some(100),
                sent_off_store: false,
                seal: None,
            });
        }
        for n in 0..MAX_SELLER_UNPAID_KEPT as u16 {
            let mut r = record(3000 + n, OrderStatus::Paid);
            r.order.order.created_at += chrono::Duration::days(1);
            book.file(r);
        }
        assert!(book.unpaid.iter().all(|r| r.order.payment_proof.is_none()
            && r.paid_height.is_some()
            && r.request.is_some()));
        // Marked paid since, and older: it does not push one out.
        // First in the stage, as its `created_at` would sort it.
        let mut marked = record(2999, OrderStatus::Paid);
        marked.order.payment_proof = None;
        book.unpaid.insert(0, marked);
        book.promote();
        assert_eq!(book.unpaid.len(), MAX_SELLER_UNPAID_KEPT);
        assert!(book
            .unpaid
            .iter()
            .all(|r| r.order.order.id != signed(2999, OrderStatus::Paid).order.id));
        assert!(book.unpaid.iter().all(|r| r.request.is_some()));
    }

    /// Review round 4 of step 2 (skeptical, codex): the seal vouches for a
    /// record's status and paid height, not its proof, so a sealed record
    /// restored with a proof the store would not keep (padded, or past the
    /// byte bound) is kept paid without it. Mutated red by keeping any proof
    /// that verifies.
    #[test]
    fn a_sealed_record_keeps_only_a_proof_the_store_would() {
        let mut old = seller();
        kept(&mut old, vec![record(1, OrderStatus::Paid)]).unwrap();
        let (listed, _) = whole(&old);
        let mut swapped = listed[0].clone();
        let terms = swapped.order.order.clone();
        swapped.order.payment_proof = Some(crate::kept_purchases::fixtures::big_proof(
            &terms,
            harvest_common::store::MAX_ORDER_BYTES,
        ));
        assert!(swapped
            .order
            .verify(&store_signing_key().verifying_key())
            .is_ok());
        let mut new = seller();
        assert_eq!(kept(&mut new, vec![swapped]), Ok(1));
        let back = held(&new, 1).unwrap();
        assert_eq!(back.order.status, OrderStatus::Paid, "by the seal");
        assert!(
            back.order.payment_proof.is_none(),
            "not the oversized proof"
        );
    }

    /// The seal is the store key's and covers the paid height: one made
    /// under another store key, or on a record whose paid height was moved,
    /// vouches for nothing. And it is pinned to its bytes, so a change to
    /// how an order encodes cannot silently void every seal in old backups.
    /// Mutated red by a key not derived from the store key, and by a seal
    /// over the order alone.
    #[test]
    fn the_seal_is_the_store_keys_and_covers_the_paid_height() {
        let mut old = seller();
        kept(&mut old, vec![record(1, OrderStatus::Paid)]).unwrap();
        let (listed, _) = whole(&old);
        let mut moved = listed[0].clone();
        moved.paid_height = moved.paid_height.map(|h| h + 1);
        moved.order.payment_proof = None;
        let mut new = seller();
        kept(&mut new, vec![moved]).unwrap();
        assert_eq!(
            held(&new, 1).unwrap().order.status,
            OrderStatus::AwaitingPayment
        );
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x31; 32]);
        let mut foreign = listed[0].clone();
        foreign.order.payment_proof = None;
        foreign.seal = seal_of(&seal_key(&other), &foreign);
        let mut new = seller();
        kept(&mut new, vec![foreign]).unwrap();
        assert_eq!(
            held(&new, 1).unwrap().order.status,
            OrderStatus::AwaitingPayment
        );
        // Golden: the seal of a fixed record under a fixed key.
        let fixed = SellerKeptOrder {
            order: signed(7, OrderStatus::Paid),
            request: None,
            despatch: None,
            paid_height: Some(100),
            sent_off_store: false,
            seal: None,
        };
        let seal = seal_of(&seal_key(&store_signing_key()), &fixed).unwrap();
        assert_eq!(
            bs58::encode(seal).into_string(),
            GOLDEN_SEAL,
            "the seal of a fixed record moved: every backup's seals would stop matching"
        );
    }

    /// The fixed record's seal in `the_seal_is_the_store_keys_and_covers_the_paid_height`.
    const GOLDEN_SEAL: &str = "9ud4tZUX77Xxr1qhPG2qP1pButMrsxqd2htFFVVBc94S";

    /// Review round 4 of step 2 (skeptical, simplicity): paid orders that
    /// wait for room move on before one marked paid since, judged by the
    /// book's own list of those waiting, not by whether a proof gave them a
    /// paid height (orders a store notification marked paid never had one).
    /// Mutated red by ordering on the paid height.
    #[test]
    fn orders_marked_paid_that_wait_keep_their_place() {
        let mut secrets = seller();
        open_full(&mut secrets);
        let waiting: Vec<_> = (0..MAX_SELLER_UNPAID_KEPT as u16)
            .map(|n| {
                let mut r = record(3000 + n, OrderStatus::AwaitingPayment);
                r.order.order.created_at += chrono::Duration::days(1);
                r.order = authorized(
                    &store_signing_key(),
                    r.order.order.clone(),
                    OrderStatus::AwaitingPayment,
                    1,
                );
                r
            })
            .collect();
        let ids: Vec<OrderId> = waiting.iter().map(|r| r.order.order.id.clone()).collect();
        assert!(keep_signed(&mut secrets, &store_key(), waiting));
        on_store_statuses(&mut secrets, &store_key(), |o| {
            ids.contains(o).then_some(OrderStatus::Paid)
        });
        sweep(&mut secrets);
        // One older, marked paid since.
        let late = record(2999, OrderStatus::AwaitingPayment);
        let late_id = late.order.order.id.clone();
        assert!(keep_signed(&mut secrets, &store_key(), vec![late]));
        on_store_statuses(&mut secrets, &store_key(), |o| {
            (*o == late_id).then_some(OrderStatus::Paid)
        });
        sweep(&mut secrets);
        let (all, _) = whole(&secrets);
        for id in &ids {
            assert!(
                all.iter()
                    .any(|r| r.order.order.id == *id && r.request.is_some()),
                "a waiting order kept its place and its ship-to"
            );
        }
    }

    /// Review round 4 of step 2 (skeptical, codex): an unpaid order older
    /// than every one the stage keeps goes at once, and is not counted as
    /// kept. Mutated red by counting it.
    #[test]
    fn an_unpaid_order_cut_on_arrival_is_not_counted_kept() {
        let mut secrets = seller();
        let newer: Vec<_> = (0..MAX_SELLER_UNPAID_KEPT as u16)
            .map(|n| {
                let mut r = record(100 + n, OrderStatus::AwaitingPayment);
                r.order.order.created_at += chrono::Duration::days(1);
                r.order = authorized(
                    &store_signing_key(),
                    r.order.order.clone(),
                    OrderStatus::AwaitingPayment,
                    1,
                );
                r
            })
            .collect();
        assert!(keep_signed(&mut secrets, &store_key(), newer));
        assert_eq!(
            kept(&mut secrets, vec![record(1, OrderStatus::AwaitingPayment)]),
            Ok(0)
        );
        assert!(held(&secrets, 1).is_none());
    }
}
