//! The seller's own copy of its orders (step 2): an order book per store
//! key, so an order that rolls off the store (its 500-order cap, or Buy-now
//! spam) never silently vanishes from the seller's list of orders to send.
//!
//! Ian, 2026-10-09: the store holds an order until its complaint window
//! closes; history then lives in each side's delegate. The buyer's side is
//! `kept_purchases`; this is the seller's.
//!
//! # What a book holds
//!
//! Two secrets per store key (which, unlike the store's contract id,
//! survives re-keys):
//!
//! * `open`: orders not yet sent. Unpaid orders still inside their payment
//!   window, at most [`MAX_SELLER_UNPAID_KEPT`] (the oldest go first: an
//!   unpaid order is not owed anything), and paid orders not yet sent, at
//!   most [`MAX_SELLER_UNSENT_KEPT`]. A paid order is never evicted: past
//!   that cap a new one is not kept, named in `paid_refused`, which the
//!   seller is shown, and kept once there is room.
//! * `done`: sent (or reversed) orders, the newest
//!   [`MAX_SELLER_SENT_KEPT`] by `created_at`: history, which may decay.
//!
//! Each record is the order's terms and signature, the minimal payment
//! proof once paid (the one the store keeps, `store::as_kept`), the buyer's
//! request (ship-to, choices, note; each text cut at
//! [`MAX_KEPT_REQUEST_TEXT`]), and the despatch once sent.
//!
//! # Who writes it
//!
//! * Instant checkout, as it signs an order (`auto_invoice::decide`): the
//!   order and the request it answers, with the tab closed.
//! * Every store notification for an armed store (`on_store_change`): an
//!   open order the store now shows paid is marked so, and one it shows
//!   cancelled before payment is dropped. The light store read carries no
//!   proof; the tab supplies it.
//! * The seller's tab (`KeepSellerOrders`): orders the store shows that the
//!   book lacks or holds less of (a manual invoice and its request, a paid
//!   order's proof, a despatch), and a despatch for an order the store no
//!   longer holds, which is recorded here only (`sent_off_store`).
//! * A wake-up ([`sweep`], one book at a time): unpaid orders past their
//!   payment window go, and a sent order's request goes once its complaint
//!   window has closed (the UI's `fulfilment::address_retained`).

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

/// Where a book's open orders are kept.
pub(crate) fn open_key(store_key: &[u8; 32]) -> Vec<u8> {
    format!(
        "{SELLER_ORDERS_PREFIX}open:{}",
        bs58::encode(store_key).into_string()
    )
    .into_bytes()
}

/// Where a book's sent orders are kept.
pub(crate) fn done_key(store_key: &[u8; 32]) -> Vec<u8> {
    format!(
        "{SELLER_ORDERS_PREFIX}done:{}",
        bs58::encode(store_key).into_string()
    )
    .into_bytes()
}

/// Where instant checkout puts the orders it signs (with their requests)
/// until they are filed into the book: a small secret, so a decision and a
/// store notification never decode the whole book (the delegate budget's
/// full-book row measured that at 91% of a call).
pub(crate) fn signed_key(store_key: &[u8; 32]) -> Vec<u8> {
    format!(
        "{SELLER_ORDERS_PREFIX}signed:{}",
        bs58::encode(store_key).into_string()
    )
    .into_bytes()
}

fn load_signed<S: SecretStore>(secrets: &S, store_key: &[u8; 32]) -> Vec<SellerKeptOrder> {
    secrets
        .get_secret(&signed_key(store_key))
        .and_then(|b| from_cbor(&b).ok())
        .unwrap_or_default()
}

/// The wake-up sweep's place: the store key it swept last.
pub(crate) const SWEEP_CURSOR_KEY: &[u8] = b"harvest:seller_orders:cursor";

/// The open half of a book.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub(crate) struct OpenBook {
    pub orders: Vec<SellerKeptOrder>,
    /// Paid orders not kept because the book already held
    /// [`MAX_SELLER_UNSENT_KEPT`] paid orders not yet sent: shown to the
    /// seller until each is kept. At most [`MAX_SELLER_UNSENT_KEPT`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paid_refused: Vec<OrderId>,
}

/// Whether a record belongs in the open half: unpaid, or paid and not sent.
fn is_open(record: &SellerKeptOrder) -> bool {
    match record.order.status {
        OrderStatus::AwaitingPayment => true,
        OrderStatus::Paid => record.despatch.is_none(),
        _ => false,
    }
}

fn is_paid_unsent(record: &SellerKeptOrder) -> bool {
    record.order.status == OrderStatus::Paid && record.despatch.is_none()
}

fn load_open<S: SecretStore>(secrets: &S, store_key: &[u8; 32]) -> Option<OpenBook> {
    match secrets.get_secret(&open_key(store_key)) {
        None => Some(OpenBook::default()),
        Some(bytes) => from_cbor(&bytes).ok(),
    }
}

fn load_done<S: SecretStore>(secrets: &S, store_key: &[u8; 32]) -> Option<Vec<SellerKeptOrder>> {
    match secrets.get_secret(&done_key(store_key)) {
        None => Some(Vec::new()),
        Some(bytes) => from_cbor(&bytes).ok(),
    }
}

/// How many books this node keeps.
fn books<S: SecretStore>(secrets: &S) -> std::collections::BTreeSet<Vec<u8>> {
    secrets
        .list_secrets(SELLER_ORDERS_PREFIX.as_bytes())
        .into_iter()
        .filter_map(|key| {
            let rest = key.strip_prefix(SELLER_ORDERS_PREFIX.as_bytes())?;
            let rest = rest
                .strip_prefix(b"open:")
                .or_else(|| rest.strip_prefix(b"done:"))
                .or_else(|| rest.strip_prefix(b"signed:"))?;
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

/// Check `incoming` as a record of the store `owner`, as the store would
/// keep it: the order verifies, a `Paid` on anything but the minimal proof
/// is its unpaid terms (`store::as_kept`), a despatch is the store key's and
/// names this order, and the request is cut to its bounds.
fn checked(
    owner: &ed25519_dalek::VerifyingKey,
    incoming: SellerKeptOrder,
) -> Result<SellerKeptOrder, String> {
    let mut order = incoming.order;
    let mut paid_height = incoming.paid_height;
    let id = order.order.id.clone();
    let terms = |order: &harvest_common::payment::AuthorizedOrder| {
        order
            .verify_terms(owner)
            .map_err(|e| format!("order {id} does not verify: {e}"))
    };
    if order.status == OrderStatus::Paid && order.payment_proof.is_none() {
        // Paid as a store notification showed it, or past the store's
        // byte bound (below), kept here before: the terms are the store
        // key's, and the payment was checked when it was first kept.
        terms(&order)?;
    } else if order.status == OrderStatus::Paid
        && !harvest_common::store::paid_within_cap(&order)
        && order
            .payment_proof
            .as_ref()
            .is_some_and(|p| harvest_common::payment::verify_minimal_proof(&order.order, p).is_ok())
        && order.verify(owner).is_ok()
    {
        // Paid on the minimal proof, but past the store's byte bound
        // (`store::MAX_PAID_ORDER_BYTES`): the store keeps it unpaid, and the
        // seller's own book keeps it paid (the overseer, 2026-10-09: an
        // honest payment over the bound still reaches the seller as paid).
        // Without the proof, which would make the book as large as the
        // payment's transactions, and with the height it confirmed at.
        paid_height = paid_height.or_else(|| harvest_common::payment::paid_height(&order));
        order.payment_proof = None;
    } else {
        order = harvest_common::store::as_kept(order);
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
    if let Some(despatch) = &incoming.despatch {
        despatch.verify(owner)?;
        if despatch.despatch.order_id != order.order.id {
            return Err(format!(
                "the despatch names another order than {}",
                order.order.id
            ));
        }
    }
    Ok(SellerKeptOrder {
        paid_height: paid_height.or_else(|| harvest_common::payment::paid_height(&order)),
        order,
        request: incoming.request.map(bounded),
        despatch: incoming.despatch,
        sent_off_store: incoming.sent_off_store,
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
    }
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

/// File `record` (checked) into `open` and `done`, under every cap.
fn file(open: &mut OpenBook, done: &mut Vec<SellerKeptOrder>, record: SellerKeptOrder) -> Filed {
    let id = record.order.order.id.clone();
    let held = if let Some(at) = open.orders.iter().position(|r| r.order.order.id == id) {
        Some(open.orders.remove(at))
    } else {
        done.iter()
            .position(|r| r.order.order.id == id)
            .map(|at| done.remove(at))
    };
    let unchanged = held
        .as_ref()
        .is_some_and(|h| merged(h.clone(), record.clone()) == *h);
    let next = match held.clone() {
        Some(held) => merged(held, record),
        None => record,
    };
    if next.order.status == OrderStatus::Cancelled {
        open.paid_refused.retain(|r| *r != id);
        return Filed::Dropped;
    }
    if is_open(&next) {
        // A paid order past the cap is never evicted, nor makes room by
        // evicting one: it is named, and the one held (unpaid) stays.
        let newly_paid_unsent = is_paid_unsent(&next) && !held.as_ref().is_some_and(is_paid_unsent);
        if newly_paid_unsent
            && open.orders.iter().filter(|r| is_paid_unsent(r)).count() >= MAX_SELLER_UNSENT_KEPT
        {
            if let Some(held) = held {
                open.orders.push(held);
            }
            if !open.paid_refused.contains(&id) {
                open.paid_refused.push(id);
                if open.paid_refused.len() > MAX_SELLER_UNSENT_KEPT {
                    open.paid_refused.remove(0);
                }
            }
            return Filed::Refused;
        }
        open.paid_refused.retain(|r| *r != id);
        open.orders.push(next);
        // Unpaid ones past their cap: the oldest go.
        let unpaid = |r: &SellerKeptOrder| r.order.status == OrderStatus::AwaitingPayment;
        while open.orders.iter().filter(|r| unpaid(r)).count() > MAX_SELLER_UNPAID_KEPT {
            let oldest = open
                .orders
                .iter()
                .enumerate()
                .filter(|(_, r)| unpaid(r))
                .min_by_key(|(_, r)| (r.order.order.created_at, r.order.order.id.0))
                .map(|(at, _)| at)
                .expect("over the cap, so one is there");
            open.orders.remove(oldest);
        }
        open.orders
            .sort_by_key(|r| (r.order.order.created_at, r.order.order.id.0));
    } else {
        open.paid_refused.retain(|r| *r != id);
        // History: the terms, the despatch and the height it was paid at,
        // not the proof, which the store held while it mattered and which
        // would make a sent order as large as its payment's transactions.
        let mut next = next;
        if next.order.status == OrderStatus::Paid {
            next.paid_height = next
                .paid_height
                .or_else(|| harvest_common::payment::paid_height(&next.order));
            next.order.payment_proof = None;
        }
        done.push(next);
        done.sort_by_key(|r| (r.order.order.created_at, r.order.order.id.0));
        if done.len() > MAX_SELLER_SENT_KEPT {
            let excess = done.len() - MAX_SELLER_SENT_KEPT;
            done.drain(..excess);
        }
    }
    if unchanged {
        Filed::Unchanged
    } else {
        Filed::Kept
    }
}

/// Write a book back. Answers whether the node kept it.
fn save<S: SecretStore>(
    secrets: &mut S,
    store_key: &[u8; 32],
    open: &OpenBook,
    done: &[SellerKeptOrder],
    write_done: bool,
) -> bool {
    let Ok(open_bytes) = to_cbor(open) else {
        return false;
    };
    if !secrets.set_secret(&open_key(store_key), &open_bytes) {
        return false;
    }
    if write_done {
        let Ok(done_bytes) = to_cbor(&done) else {
            return false;
        };
        return secrets.set_secret(&done_key(store_key), &done_bytes);
    }
    true
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
    if crate::store_keys::load(secrets, &owner).is_none() {
        return answer(Err(
            "this device does not hold that store's key, so it keeps no orders for it".into(),
        ));
    }
    match file_all(secrets, &store_key, orders, true) {
        Ok(kept) => answer(Ok(kept)),
        Err(why) => answer(Err(why)),
    }
}

/// File every record into `store_key`'s book and save it once. `strict`
/// refuses the whole call on a record that does not check (the tab's
/// call); otherwise such a record is skipped (instant checkout's own).
fn file_all<S: SecretStore>(
    secrets: &mut S,
    store_key: &[u8; 32],
    orders: Vec<SellerKeptOrder>,
    strict: bool,
) -> Result<u32, String> {
    let owner = ed25519_dalek::VerifyingKey::from_bytes(store_key)
        .map_err(|_| "that is not a store key".to_string())?;
    let mut checked_all = Vec::with_capacity(orders.len());
    for record in orders {
        match checked(&owner, record) {
            Ok(record) => checked_all.push(record),
            Err(why) if strict => return Err(why),
            Err(_) => {}
        }
    }
    let encoded = bs58::encode(store_key).into_string().into_bytes();
    if !books(secrets).contains(&encoded) && books(secrets).len() >= MAX_SELLER_BOOKS {
        return Err(format!(
            "this device already keeps the orders of {MAX_SELLER_BOOKS} stores, the most it keeps"
        ));
    }
    let (Some(mut open), Some(mut done)) =
        (load_open(secrets, store_key), load_done(secrets, store_key))
    else {
        return Err(
            "this store's kept orders do not read, so nothing was written over them".into(),
        );
    };
    let (open_before, done_before) = (open.clone(), done.clone());
    // What instant checkout signed since, filed first.
    let signed = load_signed(secrets, store_key);
    let had_signed = !signed.is_empty();
    for record in signed {
        file(&mut open, &mut done, record);
    }
    let mut kept = 0u32;
    for record in checked_all {
        if file(&mut open, &mut done, record) == Filed::Kept {
            kept += 1;
        }
    }
    if open == open_before && done == done_before && !had_signed {
        return Ok(kept);
    }
    if !save(secrets, store_key, &open, &done, done != done_before) {
        return Err("the node refused to save the kept orders".into());
    }
    if had_signed
        && !secrets.set_secret(
            &signed_key(store_key),
            &to_cbor(&Vec::<SellerKeptOrder>::new()).unwrap_or_default(),
        )
    {
        return Err("the node refused to save the kept orders".into());
    }
    Ok(kept)
}

/// Instant checkout's write: the orders it just signed, with the requests
/// they answer, into the small signed inbox ([`signed_key`]), at most
/// [`MAX_SELLER_UNPAID_KEPT`] (the oldest go: unpaid, nothing is owed on
/// them), filed into the book by the next tab call or wake-up. Answers
/// whether it was written (or there was nothing to write).
pub(crate) fn keep_signed<S: SecretStore>(
    secrets: &mut S,
    store_key: &[u8; 32],
    orders: Vec<SellerKeptOrder>,
) -> bool {
    if orders.is_empty() {
        return true;
    }
    let mut signed = load_signed(secrets, store_key);
    for record in orders {
        signed.retain(|r| r.order.order.id != record.order.order.id);
        signed.push(SellerKeptOrder {
            request: record.request.map(bounded),
            ..record
        });
    }
    signed.sort_by_key(|r| (r.order.order.created_at, r.order.order.id.0));
    if signed.len() > MAX_SELLER_UNPAID_KEPT {
        let excess = signed.len() - MAX_SELLER_UNPAID_KEPT;
        signed.drain(..excess);
    }
    to_cbor(&signed).is_ok_and(|bytes| secrets.set_secret(&signed_key(store_key), &bytes))
}

/// A store notification's write: an open order the store now shows paid is
/// marked so (the tab supplies the proof), and one it shows cancelled while
/// unpaid is dropped. `statuses` is the store's, by order id. Writes only
/// when something changed.
pub(crate) fn on_store_statuses<S: SecretStore>(
    secrets: &mut S,
    store_key: &[u8; 32],
    status_of: impl Fn(&OrderId) -> Option<OrderStatus>,
) {
    // The signed inbox only: what instant checkout signed and has not yet
    // been filed. The book itself is the tab's and the wake-up's to write.
    if !secrets.has_secret(&signed_key(store_key)) {
        return;
    }
    let mut signed = load_signed(secrets, store_key);
    let mut changed = false;
    signed.retain_mut(
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
        if let Ok(bytes) = to_cbor(&signed) {
            secrets.set_secret(&signed_key(store_key), &bytes);
        }
    }
}

/// One page of `store_key`'s book: its orders whose ids sort after `after`,
/// open ones first, about [`SELLER_ORDERS_PAGE_BYTES`] at a time.
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
    let (Some(open), Some(done)) = (
        load_open(secrets, &store_key),
        load_done(secrets, &store_key),
    ) else {
        return answer(Err("this store's kept orders do not read".into()));
    };
    let mut all: Vec<SellerKeptOrder> = open.orders.into_iter().chain(done).collect();
    // And what instant checkout signed since, as the book would file it.
    for record in load_signed(secrets, &store_key) {
        match all
            .iter_mut()
            .find(|r| r.order.order.id == record.order.order.id)
        {
            Some(held) => *held = merged(held.clone(), record),
            None => all.push(record),
        }
    }
    all.sort_by(|a, b| a.order.order.id.0.cmp(&b.order.order.id.0));
    if let Some(after) = &after {
        all.retain(|r| r.order.order.id.0 > after.0);
    }
    let mut page = SellerOrdersPage {
        orders: Vec::new(),
        next: None,
        paid_refused: if after.is_none() {
            open.paid_refused
        } else {
            Vec::new()
        },
    };
    let mut bytes = 0usize;
    for record in all {
        if !page.orders.is_empty() && bytes >= SELLER_ORDERS_PAGE_BYTES {
            page.next = page.orders.last().map(|r| r.order.order.id.clone());
            break;
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

/// A wake-up's sweep of one book (the next after the last one swept): an
/// unpaid order whose payment can no longer confirm goes, and a sent
/// order's request goes once its complaint window has closed, judged by
/// the tips instant checkout caches. Answers whether anything was written.
pub(crate) fn sweep<S: SecretStore>(secrets: &mut S) -> bool {
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
    let tip_of = |network: freenet_bitcoin_common::BitcoinNetwork| -> Option<u32> {
        tips.get(&format!("{network:?}")).copied()
    };
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
    secrets.set_secret(SWEEP_CURSOR_KEY, &next);
    let Some(store_key) = bs58::decode(&next)
        .into_vec()
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
    else {
        return false;
    };
    let (Some(mut open), Some(mut done)) = (
        load_open(secrets, &store_key),
        load_done(secrets, &store_key),
    ) else {
        return false;
    };
    // What instant checkout signed since, filed first.
    let signed = load_signed(secrets, &store_key);
    let had_signed = !signed.is_empty();
    let done_len = done.len();
    for record in signed {
        file(&mut open, &mut done, record);
    }
    let lapse = harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS
        + harvest_common::payment::PAYMENT_CONFIRMATION_SLACK_BLOCKS;
    let before = if had_signed {
        usize::MAX
    } else {
        open.orders.len()
    };
    open.orders.retain(|r| {
        if r.order.status != OrderStatus::AwaitingPayment {
            return true;
        }
        match (r.order.order.anchor.as_ref(), tip_of(r.order.order.network)) {
            (Some(anchor), Some(tip)) => tip.saturating_sub(anchor.height) <= lapse,
            _ => true,
        }
    });
    let mut changed_done = done.len() != done_len;
    for r in done.iter_mut() {
        if r.request.is_some()
            && tip_of(r.order.order.network).is_some_and(|tip| window_closed(r, tip))
        {
            r.request = None;
            changed_done = true;
        }
    }
    let changed_open = open.orders.len() != before;
    if !changed_open && !changed_done {
        return false;
    }
    if !save(secrets, &store_key, &open, &done, changed_done) {
        return false;
    }
    !had_signed
        || to_cbor(&Vec::<SellerKeptOrder>::new())
            .is_ok_and(|b| secrets.set_secret(&signed_key(&store_key), &b))
}

/// A predecessor generation's book (a delegate re-key), merged into this
/// one's as the tab's would be: every record re-checked against the store
/// key its secret names, filed under the same caps, nothing held lost.
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
            Ok(book) => (book.orders, name),
            Err(_) => {
                return SecretImport::Permanent("the predecessor's book did not decode".into())
            }
        }
    } else if let Some(name) = rest
        .strip_prefix(b"done:")
        .or_else(|| rest.strip_prefix(b"signed:"))
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
    match file_all(secrets, &store_key, records, false) {
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
        assert!(kept(&mut secrets, vec![forged]).is_err());

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
            harvest_common::store::MAX_PAID_ORDER_BYTES,
        ));
        assert!(!harvest_common::store::paid_within_cap(&big.order));
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
        let mut book = OpenBook::default();
        let mut done = Vec::new();
        file(
            &mut book,
            &mut done,
            record(2, OrderStatus::AwaitingPayment),
        );
        assert_eq!(file(&mut book, &mut done, cancelled), Filed::Dropped);
        assert!(book.orders.is_empty());
    }

    /// Caps: unpaid orders past `MAX_SELLER_UNPAID_KEPT` lose their oldest;
    /// a paid order not yet sent past `MAX_SELLER_UNSENT_KEPT` is never
    /// evicted for, nor evicts: it is named in `paid_refused` and kept once
    /// one is sent; the sent half keeps its newest `MAX_SELLER_SENT_KEPT`.
    /// Mutated red by evicting the oldest paid order to make room, and by
    /// refusing in silence.
    #[test]
    fn a_paid_order_is_never_evicted_and_one_past_the_cap_is_named() {
        let mut book = OpenBook::default();
        let mut done = Vec::new();
        for n in 0..(MAX_SELLER_UNPAID_KEPT as u16 + 3) {
            let mut r = record(n, OrderStatus::AwaitingPayment);
            r.request = None;
            file(&mut book, &mut done, r);
        }
        assert_eq!(book.orders.len(), MAX_SELLER_UNPAID_KEPT);
        let first_kept = signed(3, OrderStatus::AwaitingPayment).order.id;
        assert_eq!(book.orders[0].order.order.id, first_kept, "the oldest went");

        let mut book = OpenBook::default();
        let paid = |n: u16| SellerKeptOrder {
            order: signed(n, OrderStatus::Paid),
            request: None,
            despatch: None,
            paid_height: Some(100),
            sent_off_store: false,
        };
        for n in 0..MAX_SELLER_UNSENT_KEPT as u16 {
            assert_eq!(file(&mut book, &mut done, paid(n)), Filed::Kept);
        }
        let over = MAX_SELLER_UNSENT_KEPT as u16;
        assert_eq!(file(&mut book, &mut done, paid(over)), Filed::Refused);
        assert_eq!(book.orders.len(), MAX_SELLER_UNSENT_KEPT);
        assert!(book
            .orders
            .iter()
            .any(|r| r.order.order.id == paid(0).order.order.id));
        assert_eq!(book.paid_refused, vec![paid(over).order.order.id]);
        // One sent: room, and the refused one is kept when it comes again.
        let mut sent = paid(0);
        sent.despatch = Some(despatch(&sent.order, 120));
        file(&mut book, &mut done, sent);
        assert_eq!(file(&mut book, &mut done, paid(over)), Filed::Kept);
        assert!(book.paid_refused.is_empty());

        let mut done = Vec::new();
        let mut book = OpenBook::default();
        for n in 0..(MAX_SELLER_SENT_KEPT as u16 + 2) {
            let mut r = paid(n);
            r.despatch = Some(despatch(&r.order, 120));
            file(&mut book, &mut done, r);
        }
        assert_eq!(done.len(), MAX_SELLER_SENT_KEPT);
        assert_eq!(done[0].order.order.id, paid(2).order.order.id);
    }

    /// The store's statuses: an open order the store shows paid is marked
    /// paid, one it shows cancelled while unpaid goes, and nothing is
    /// written when nothing changed. Mutated red by not marking paid.
    #[test]
    fn a_store_notification_marks_paid_and_drops_cancelled() {
        let mut secrets = seller();
        // As instant checkout writes them: into the signed inbox.
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
        // A wake-up files it into the book and empties the inbox.
        assert!(sweep(&mut secrets));
        assert!(load_signed(&secrets, &store_key()).is_empty());
        let open: OpenBook =
            from_cbor(&secrets.get_secret(&open_key(&store_key())).unwrap()).unwrap();
        assert_eq!(open.orders.len(), 1);
        assert_eq!(whole(&secrets).0, all);
    }

    /// The sweep: an unpaid order past its payment window goes; a sent
    /// order's request goes once its complaint window has closed, and not
    /// before; a paid order never sent keeps its request (as the app shows
    /// it). Mutated red by keeping the request past the window, and by
    /// dropping a never-sent order's.
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
        let key = open_key(&store_key());
        let value = old.get_secret(&key).unwrap();
        assert!(matches!(
            crate::import::import_secret(&mut new, &key, &value),
            harvest_common::delegate::SecretImport::Written
        ));
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
}
