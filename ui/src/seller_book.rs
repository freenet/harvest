//! The seller's own copy of its orders, as this tab reads and fills it
//! (step 2; the delegate's `seller_orders`).
//!
//! The store keeps its newest 256 orders and the mailbox its newest 512
//! messages, so a paid order not yet sent, or the request with its ship-to,
//! can roll off either. The seller's delegate keeps a book per store key:
//! instant checkout writes each order it signs with its request; this tab
//! writes what the store shows that the book lacks or holds less of (a
//! manual invoice and its request, a paid order's proof, a despatch); and a
//! despatch for an order the store no longer holds goes only to the book.
//!
//! Readers take the store's orders and, after them, the book's orders the
//! store no longer holds ([`AppState::book_only_orders`]); the store's copy
//! wins where both have one. A request gone from the mailbox is the book's
//! ([`AppState::book_request`]), and a despatch gone from the store too
//! (`AppState::despatch_of`).

use std::collections::HashMap;

use harvest_common::delegate::{
    SellerKeptOrder, SellerOrdersPage, MAX_SELLER_UNSENT_KEPT, SELLER_ORDERS_PER_CALL,
};
use harvest_common::payment::{AuthorizedOrder, OrderId, OrderStatus};

use crate::state::{AppState, BrowsingStore, SellerOrderRequest};

/// One store's book, as this tab last read it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SellerBook {
    pub orders: Vec<SellerKeptOrder>,
    /// Paid orders not yet sent the book could not keep, being full.
    pub paid_refused: Vec<OrderId>,
    /// Read at least once.
    pub loaded: bool,
    /// A read under way: its request id, and the pages so far.
    pub reading: Option<(u64, SellerOrdersPage)>,
    /// A keep under way: its request id and when it went.
    pub keeping: Option<(u64, u64)>,
    /// Every note this tab has sent this session, by order id and the
    /// note's digest: one is never sent twice. What the book keeps can
    /// differ from what it was sent (it keeps no proof once an order is
    /// sent, drops a request once its window closes, or refuses a note), so
    /// comparing the two again would offer the same note for ever.
    pub noted: std::collections::HashSet<([u8; 32], [u8; 32])>,
}

/// A note's identity for [`SellerBook::noted`].
fn note_digest(note: &SellerKeptOrder) -> ([u8; 32], [u8; 32]) {
    let bytes = harvest_common::to_cbor(note).unwrap_or_default();
    (note.order.order.id.0, *blake3::hash(&bytes).as_bytes())
}

/// How long a keep waits for its answer before another may go.
const KEEP_ANSWER_WAIT_MS: u64 = 60_000;

/// What a request this module wants sent.
pub(crate) type Outgoing = Vec<harvest_common::HarvestDelegateRequest>;

/// Whether `note` adds to `held` (the same order): what the delegate's
/// merge would take from it and keep. A proof adds only to a paid order not
/// yet sent that has none: a sent one is kept without it.
fn adds_to(held: &SellerKeptOrder, note: &SellerKeptOrder) -> bool {
    note.order.status.rank() > held.order.status.rank()
        || (note.order.status == held.order.status
            && held.order.payment_proof.is_none()
            && held.despatch.is_none()
            && note.order.payment_proof.is_some())
        || (held.request.is_none() && note.request.is_some())
        || (held.despatch.is_none() && note.despatch.is_some())
}

impl AppState {
    /// The store key of one of our own stores.
    fn own_store_key(&self, store_contract_id: &[u8]) -> Option<[u8; 32]> {
        self.store_owner_fingerprint(store_contract_id)?;
        self.browsing_stores.get(store_contract_id)?.owner
    }

    /// The book of one of our own stores, once read.
    pub(crate) fn seller_book(&self, store_contract_id: &[u8]) -> Option<&SellerBook> {
        let key = self.own_store_key(store_contract_id)?;
        self.seller_books.get(&key).filter(|b| b.loaded)
    }

    /// The paid orders this store's book keeps that the store no longer
    /// holds, newest first: what the seller would otherwise lose sight of.
    /// Not an unpaid one: the store has dropped it (or never held it, if
    /// its publish failed), and there is nothing to send for it.
    pub(crate) fn book_only_orders(&self, store_contract_id: &[u8]) -> Vec<AuthorizedOrder> {
        let Some(book) = self.seller_book(store_contract_id) else {
            return Vec::new();
        };
        let held = self.browsing_stores.get(store_contract_id);
        let mut orders: Vec<AuthorizedOrder> = book
            .orders
            .iter()
            .filter(|r| r.order.status != OrderStatus::AwaitingPayment)
            .filter(|r| {
                held.is_none_or(|s| !s.orders.iter().any(|o| o.order.id == r.order.order.id))
            })
            .map(|r| r.order.clone())
            .collect();
        orders.sort_by_key(|o| std::cmp::Reverse(o.order.created_at));
        orders
    }

    /// Whether this order is shown from the book alone.
    pub(crate) fn order_only_in_book(&self, store_contract_id: &[u8], order: &OrderId) -> bool {
        self.book_only_orders(store_contract_id)
            .iter()
            .any(|o| o.order.id == *order)
    }

    /// The book's copy of the request `order` answers, as the seller's card
    /// shows a request, with the address hidden once the app hides it.
    pub(crate) fn book_request(
        &self,
        store_contract_id: &[u8],
        store: &BrowsingStore,
        order: &AuthorizedOrder,
    ) -> Option<SellerOrderRequest> {
        let request = self
            .seller_book(store_contract_id)?
            .orders
            .iter()
            .find(|r| r.order.order.id == order.order.id)?
            .request
            .clone()?;
        let listing = store
            .listings
            .iter()
            .find(|l| l.listing.id == request.listing_id)
            .map(|l| &l.listing);
        let retained = self.address_retained_for(order);
        Some(SellerOrderRequest {
            listing_id: Some(request.listing_id.clone()),
            title: listing.map(|l| l.title.clone()),
            quantity: request.quantity,
            shipping: if retained {
                request.shipping
            } else {
                crate::fulfilment::ADDRESS_HIDDEN.to_string()
            },
            note: if retained {
                request.note
            } else {
                String::new()
            },
            region: request.region,
            choices: crate::state::labelled_choices(
                listing.map(|l| l.choices.as_slice()).unwrap_or_default(),
                &request.choices,
            ),
        })
    }

    /// The despatch the seller's books hold for `order`, the store key's.
    pub(crate) fn book_despatch(
        &self,
        order: &AuthorizedOrder,
    ) -> Option<harvest_common::fulfilment::AuthorizedDespatch> {
        let mut keys: Vec<&[u8; 32]> = self.seller_books.keys().collect();
        keys.sort_unstable();
        keys.into_iter().find_map(|key| {
            let despatch = self.seller_books[key]
                .orders
                .iter()
                .find(|r| r.order.order.id == order.order.id)?
                .despatch
                .clone()?;
            let owner = ed25519_dalek::VerifyingKey::from_bytes(key).ok()?;
            order.verify_terms(&owner).ok()?;
            despatch.verify(&owner).ok()?;
            Some(despatch)
        })
    }

    /// Whether this tab is reading one of our stores' books for the first
    /// time: what it holds is not known yet.
    pub(crate) fn seller_book_unread(&self, store_contract_id: &[u8]) -> bool {
        self.own_store_key(store_contract_id)
            .and_then(|key| self.seller_books.get(&key))
            .is_some_and(|b| !b.loaded && b.reading.is_some())
    }

    /// Paid orders not yet sent that this store's book could not keep.
    pub(crate) fn book_refused(&self, store_contract_id: &[u8]) -> usize {
        self.seller_book(store_contract_id)
            .map_or(0, |b| b.paid_refused.len())
    }

    /// Read one of our stores' books, unless a read is under way.
    pub(crate) fn read_seller_book(&mut self, store_contract_id: &[u8]) -> Outgoing {
        let Some(key) = self.own_store_key(store_contract_id) else {
            return Vec::new();
        };
        if self
            .seller_books
            .get(&key)
            .is_some_and(|b| b.reading.is_some())
        {
            return Vec::new();
        }
        let request_id = self.next_messaging_request_id();
        self.seller_books.entry(key).or_default().reading = Some((
            request_id,
            SellerOrdersPage {
                orders: Vec::new(),
                next: None,
                paid_refused: Vec::new(),
            },
        ));
        vec![harvest_common::HarvestDelegateRequest::ListSellerOrders {
            request_id,
            store_key: key,
            after: None,
        }]
    }

    /// A page of a book: ask for the next, or after the last, hold it.
    pub(crate) fn on_seller_orders(
        &mut self,
        request_id: u64,
        store_key: [u8; 32],
        result: Result<SellerOrdersPage, String>,
    ) -> Outgoing {
        let Some(book) = self.seller_books.get_mut(&store_key) else {
            return Vec::new();
        };
        let Some((asked, so_far)) = book.reading.as_mut() else {
            return Vec::new();
        };
        if *asked != request_id {
            return Vec::new();
        }
        let page = match result {
            Ok(page) => page,
            Err(why) => {
                book.reading = None;
                dioxus::logger::tracing::warn!("The seller's kept orders could not be read: {why}");
                return Vec::new();
            }
        };
        so_far.orders.extend(page.orders);
        so_far.paid_refused.extend(page.paid_refused);
        if let Some(after) = page.next {
            return vec![harvest_common::HarvestDelegateRequest::ListSellerOrders {
                request_id,
                store_key,
                after: Some(after),
            }];
        }
        let (_, done) = book.reading.take().expect("held above");
        book.orders = done.orders;
        book.paid_refused = done.paid_refused;
        book.loaded = true;
        // The book read, what the store shows it lacks goes in.
        let ids: Vec<Vec<u8>> = self
            .browsing_stores
            .iter()
            .filter(|(_, s)| s.owner == Some(store_key))
            .map(|(id, _)| id.clone())
            .collect();
        ids.iter()
            .flat_map(|id| self.sync_seller_book_requests(id))
            .collect()
    }

    /// A keep was answered: read the book again, so this tab shows it. A
    /// refusal is not read again for: nothing changed.
    pub(crate) fn on_seller_orders_kept(
        &mut self,
        request_id: u64,
        store_key: [u8; 32],
        result: Result<u32, String>,
    ) -> Outgoing {
        let Some(book) = self.seller_books.get_mut(&store_key) else {
            return Vec::new();
        };
        if book.keeping.is_some_and(|(id, _)| id == request_id) {
            book.keeping = None;
        }
        if let Err(why) = &result {
            dioxus::logger::tracing::warn!("The seller's orders were not kept: {why}");
            return Vec::new();
        }
        let ids: Vec<Vec<u8>> = self
            .browsing_stores
            .iter()
            .filter(|(_, s)| s.owner == Some(store_key))
            .map(|(id, _)| id.clone())
            .collect();
        ids.first()
            .map(|id| self.read_seller_book(id))
            .unwrap_or_default()
    }

    /// What this store shows that its book lacks or holds less of: each
    /// paid or reversed order (with its proof, and despatch when sent), and
    /// each unpaid one whose request this tab can read, with the request.
    pub(crate) fn seller_book_notes(&self, store_contract_id: &[u8]) -> Vec<SellerKeptOrder> {
        let (Some(store), Some(book)) = (
            self.browsing_stores.get(store_contract_id),
            self.seller_book(store_contract_id),
        ) else {
            return Vec::new();
        };
        let requests = self.seller_kept_requests(store_contract_id);
        let held: HashMap<&OrderId, &SellerKeptOrder> =
            book.orders.iter().map(|r| (&r.order.order.id, r)).collect();
        let full = book
            .orders
            .iter()
            .filter(|r| r.order.status == OrderStatus::Paid && r.despatch.is_none())
            .count()
            >= MAX_SELLER_UNSENT_KEPT;
        store
            .orders
            .iter()
            .filter(|o| {
                matches!(
                    o.status,
                    OrderStatus::AwaitingPayment | OrderStatus::Paid | OrderStatus::PaymentReversed
                )
            })
            .filter_map(|o| {
                // Not a ship-to the app would no longer show: the book drops
                // a sent order's once its complaint window has closed.
                let request = requests
                    .get(&o.order.id)
                    .filter(|_| self.address_retained_for(o))
                    .cloned();
                if o.status == OrderStatus::AwaitingPayment && request.is_none() {
                    return None;
                }
                // A full book refused it: it goes again once there is room.
                if full && book.paid_refused.contains(&o.order.id) {
                    return None;
                }
                let note = SellerKeptOrder {
                    order: o.clone(),
                    request,
                    despatch: store.despatches.get(&o.order.id).cloned(),
                    paid_height: None,
                    sent_off_store: false,
                };
                match held.get(&o.order.id) {
                    Some(held) if !adds_to(held, &note) => None,
                    _ if book.noted.contains(&note_digest(&note)) => None,
                    _ => Some(note),
                }
            })
            .collect()
    }

    /// Send what [`Self::seller_book_notes`] finds, one call at a time.
    pub(crate) fn sync_seller_book_requests(&mut self, store_contract_id: &[u8]) -> Outgoing {
        let Some(key) = self.own_store_key(store_contract_id) else {
            return Vec::new();
        };
        let now = crate::state::now_ms();
        let busy = self.seller_books.get(&key).is_some_and(|b| {
            b.reading.is_some()
                || b.keeping
                    .is_some_and(|(_, at)| now.saturating_sub(at) < KEEP_ANSWER_WAIT_MS)
        });
        if busy {
            return Vec::new();
        }
        let mut notes = self.seller_book_notes(store_contract_id);
        if notes.is_empty() {
            return Vec::new();
        }
        notes.truncate(SELLER_ORDERS_PER_CALL);
        let request_id = self.next_messaging_request_id();
        if let Some(book) = self.seller_books.get_mut(&key) {
            book.keeping = Some((request_id, now));
            book.noted.extend(notes.iter().map(note_digest));
        }
        vec![harvest_common::HarvestDelegateRequest::KeepSellerOrders {
            request_id,
            store_key: key,
            orders: notes,
        }]
    }

    /// One of our stores' state arrived: read its book the first time, and
    /// after that keep in it what the store shows that it lacks.
    pub(crate) fn sync_seller_book(&mut self, store_contract_id: &[u8]) {
        let Some(key) = self.own_store_key(store_contract_id) else {
            return;
        };
        let out = if self.seller_books.get(&key).is_some_and(|b| b.loaded) {
            self.sync_seller_book_requests(store_contract_id)
        } else {
            self.read_seller_book(store_contract_id)
        };
        crate::backup_flow::send_all(out);
    }

    /// A despatch for an order the store no longer holds: kept in the book
    /// only (the store drops a despatch whose order it does not hold).
    pub(crate) fn keep_despatch_off_store(
        &mut self,
        store_contract_id: &[u8],
        order: AuthorizedOrder,
        despatch: harvest_common::fulfilment::AuthorizedDespatch,
    ) -> Outgoing {
        let Some(key) = self.own_store_key(store_contract_id) else {
            return Vec::new();
        };
        let request_id = self.next_messaging_request_id();
        let held = self
            .seller_books
            .get(&key)
            .and_then(|b| b.orders.iter().find(|r| r.order.order.id == order.order.id))
            .cloned();
        // Shown at once; the book's answer replaces it.
        if let Some(book) = self.seller_books.get_mut(&key) {
            if let Some(r) = book
                .orders
                .iter_mut()
                .find(|r| r.order.order.id == order.order.id)
            {
                r.despatch = Some(despatch.clone());
                r.sent_off_store = true;
            }
        }
        vec![harvest_common::HarvestDelegateRequest::KeepSellerOrders {
            request_id,
            store_key: key,
            orders: vec![SellerKeptOrder {
                order,
                request: held.and_then(|h| h.request),
                despatch: Some(despatch),
                paid_height: None,
                sent_off_store: true,
            }],
        }]
    }

    /// The orders the seller's to-send list and order pages read: the
    /// store's, then the book's that the store no longer holds. An order the
    /// store keeps unpaid (or cancelled) that is paid as this tab proved it
    /// past the store's byte bound, or as the book holds it, reads as that
    /// paid copy (step 2): the book's survives a reload, the tab's proof
    /// does not.
    pub(crate) fn seller_orders_with_book(&self, store_contract_id: &[u8]) -> Vec<AuthorizedOrder> {
        let book = self.seller_book(store_contract_id);
        let mut orders: Vec<AuthorizedOrder> = self
            .browsing_stores
            .get(store_contract_id)
            .map(|s| s.orders.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|o| {
                if !matches!(
                    o.status,
                    OrderStatus::AwaitingPayment | OrderStatus::Cancelled
                ) {
                    return o;
                }
                if let Some(paid) = self.paid_past_store_bound.get(&o.order.id) {
                    return paid.clone();
                }
                book.and_then(|b| b.orders.iter().find(|r| r.order.order.id == o.order.id))
                    .filter(|r| r.order.status.rank() > o.status.rank())
                    .map_or(o, |r| r.order.clone())
            })
            .collect();
        orders.extend(self.book_only_orders(store_contract_id));
        orders
    }

    /// A paid order past the store's byte bound, into the seller's own book
    /// for one of our stores, which keeps it paid (step 2).
    pub(crate) fn keep_paid_past_bound(
        &mut self,
        store_contract_id: &[u8],
        paid: AuthorizedOrder,
    ) -> Outgoing {
        let Some(key) = self.own_store_key(store_contract_id) else {
            return Vec::new();
        };
        let held = self
            .seller_books
            .get(&key)
            .and_then(|b| b.orders.iter().find(|r| r.order.order.id == paid.order.id))
            .cloned();
        if held
            .as_ref()
            .is_some_and(|r| r.order.status == OrderStatus::Paid)
        {
            return Vec::new();
        }
        let request_id = self.next_messaging_request_id();
        vec![harvest_common::HarvestDelegateRequest::KeepSellerOrders {
            request_id,
            store_key: key,
            orders: vec![SellerKeptOrder {
                order: paid,
                request: held.and_then(|h| h.request),
                despatch: None,
                paid_height: None,
                sent_off_store: false,
            }],
        }]
    }
}
