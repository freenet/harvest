//! Which conversation an order belongs to, and when a paid order opens that
//! conversation to plain text from its buyer.
//!
//! # Why this exists
//!
//! Buyer-to-seller messages need a Ghost Key (anti-spam); buying does not.
//! A buyer whose order is PAID may write in that order's conversation without
//! one (Ian, 2026-09-27, confirmed 2026-09-30): money has been spent, which
//! is no cheaper for a spammer than a Ghost Key, and a worried buyer's only
//! other frictionless move is a permanent complaint. Before payment a Ghost
//! Key is still required.
//!
//! The rule has two halves, and they must agree:
//!
//! * **The seller's half** ([`conversation_has_paid_order`]) decides whether
//!   the seller's inbox shows a buyer's plain text in a conversation
//!   (`components::message_view::shown_to_seller`). It is the one that
//!   enforces anything: the mailbox is open-write, so a gate in the buyer's
//!   compose box stops only a buyer using this UI.
//! * **The buyer's half** (`AppState::paid_conversation`) decides whether the
//!   buyer is offered a compose box without a Ghost Key. It must be a STRICT
//!   SUBSET of the seller's half, or a buyer would be invited to send text the
//!   seller never sees. It is built from the same predicate
//!   ([`order_in_conversation`]) over the same kind of evidence, plus
//!   conditions of its own, so it cannot say yes where the seller says no.
//!
//! # What counts as the evidence
//!
//! Only the seller's own published store state. An order `O` of the store
//! opens conversation `T` when `O` is `Paid` or `PaymentReversed` (money was
//! spent to reach that status, which is the bar; the store contract accepts
//! `Paid` only with a payment proof) and `O` belongs to `T` by one of:
//!
//! 1. **Its request.** `O` answers an instant request (`O.request_id` is
//!    set), and a Buy now request read in `T` gives that request id and that
//!    order id under `T`'s own tag (`InstantSelection::answered_request`).
//!    The request id hashes the tag, so a request copied into another
//!    conversation names another id.
//! 2. **Its listing tag.** `O.listing_tag` is `T`'s keyed tag for a listing
//!    named by a request in `T`, or for one the store lists now. Only the two
//!    holders of `T`'s keys can compute that tag, and only the seller can
//!    publish an order, so an order carrying it was issued to `T`. This is
//!    what opens a conversation for a paid invoice answering a QUOTE request
//!    (no request id), and for a Buy now whose request has since left the
//!    bounded mailbox.
//!
//! **Never** evidence, because a buyer can produce it for any order:
//!
//! * the order's `order_binding` alone: it is published on the order, so
//!   anyone can copy it into a request in their own conversation;
//! * an `OrderAccepted` message naming a paid order: both parties hold both
//!   direction keys, so the buyer can write one naming any order id;
//! * anything else the buyer sends. Nothing in a message is read as a
//!   statement that something was paid.

use std::collections::HashSet;

use harvest_common::listing::ListingId;
use harvest_common::payment::{AuthorizedOrder, OrderId, OrderStatus};

use crate::messaging::InstantSelection;

/// Whether an order in `status` can open its conversation: money was spent
/// to reach it. `PaymentReversed` counts (a reorg took the payment back, but
/// it was made); `AwaitingPayment` and `Cancelled` never do.
pub(crate) fn status_opens(status: OrderStatus) -> bool {
    match status {
        OrderStatus::Paid | OrderStatus::PaymentReversed => true,
        OrderStatus::AwaitingPayment | OrderStatus::Cancelled => false,
    }
}

/// What one conversation's requests to buy, and the store's listings, let a
/// reader match an order against: worked out once per conversation, so
/// matching every order in a store costs one lookup each rather than a keyed
/// hash per listing per order.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ConversationClaims {
    /// `(request id, order id)` for each Buy now request read in the
    /// conversation, computed under the conversation's own tag.
    answered: Vec<([u8; 32], OrderId)>,
    /// The conversation's keyed tag for every listing its requests name and
    /// every listing the store lists now. Empty when the reader holds no keys
    /// for the conversation.
    listing_tags: HashSet<[u8; 32]>,
}

impl ConversationClaims {
    /// The claims of the conversation tagged `tag`, from the requests read in
    /// it (`(listing, Buy now selection)` pairs), the store's current
    /// listings, and the conversation's keyed listing tag (`None` when the
    /// reader has no keys for it).
    pub(crate) fn of<'a>(
        tag: &[u8; 32],
        requests: impl IntoIterator<Item = (&'a ListingId, Option<&'a InstantSelection>)>,
        listings: impl IntoIterator<Item = &'a ListingId>,
        listing_tag: impl Fn(&ListingId) -> Option<[u8; 32]>,
    ) -> Self {
        let mut claims = ConversationClaims::default();
        let mut named: Vec<&ListingId> = Vec::new();
        for (listing, selection) in requests {
            named.push(listing);
            if let Some(request) = selection.and_then(|s| s.answered_request(tag)) {
                claims
                    .answered
                    .push((request.request_id, request.order_id()));
            }
        }
        claims.listing_tags = named
            .into_iter()
            .chain(listings)
            .filter_map(&listing_tag)
            .collect();
        claims
    }
}

/// Whether `order` was issued to the conversation `claims` describes, by its
/// request (rule 1 of the module docs) or its listing tag (rule 2). Nothing
/// else is read: not its binding, not any message naming it.
pub(crate) fn order_in_conversation(order: &AuthorizedOrder, claims: &ConversationClaims) -> bool {
    #[cfg(test)]
    FULL_MATCHES.with(|n| n.set(n.get() + 1));
    let by_listing_tag = order
        .order
        .listing_tag
        .is_some_and(|tag| claims.listing_tags.contains(&tag));
    order_by_request(order, claims) || by_listing_tag
}

/// Whether `order` belongs to the conversation `claims` describes by rule 1
/// alone: a Buy now request read there gives the order's request id and id.
/// The request id hashes the conversation's own tag, so no other tag,
/// however it shares the conversation's keys, can make this true: the
/// strongest evidence of which conversation an order is in.
pub(crate) fn order_by_request(order: &AuthorizedOrder, claims: &ConversationClaims) -> bool {
    order.order.request_id.is_some_and(|request_id| {
        claims
            .answered
            .iter()
            .any(|(asked, id)| *asked == request_id && *id == order.order.id)
    })
}

// How many times `order_in_conversation` has run on this thread: lets a
// test prove the seller's inbox matches orders through `OrderLookup` and
// never order by order (review after 1bd9bcd).
#[cfg(test)]
thread_local! {
    pub(crate) static FULL_MATCHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A store's orders indexed by what a conversation's claims match on
/// (review after 1bd9bcd): by listing tag and by request id. Matching every
/// conversation against every order was claims × orders on each read of the
/// seller's inbox, and anyone can make conversations; with this, matching
/// one conversation costs what its own claims hold.
pub(crate) struct OrderLookup<'a> {
    by_listing_tag: std::collections::HashMap<[u8; 32], Vec<&'a AuthorizedOrder>>,
    by_request_id: std::collections::HashMap<[u8; 32], Vec<&'a AuthorizedOrder>>,
}

impl<'a> OrderLookup<'a> {
    pub(crate) fn new(orders: &'a [AuthorizedOrder]) -> Self {
        let mut by_listing_tag: std::collections::HashMap<[u8; 32], Vec<&'a AuthorizedOrder>> =
            std::collections::HashMap::new();
        let mut by_request_id: std::collections::HashMap<[u8; 32], Vec<&'a AuthorizedOrder>> =
            std::collections::HashMap::new();
        for order in orders {
            if let Some(tag) = order.order.listing_tag {
                by_listing_tag.entry(tag).or_default().push(order);
            }
            if let Some(request_id) = order.order.request_id {
                by_request_id.entry(request_id).or_default().push(order);
            }
        }
        OrderLookup {
            by_listing_tag,
            by_request_id,
        }
    }

    /// The orders belonging to the conversation `claims` describes, each
    /// once, with whether by its request (rule 1, [`order_by_request`]):
    /// exactly what [`order_in_conversation`] over every order gives, in no
    /// particular order.
    pub(crate) fn in_conversation(
        &self,
        claims: &ConversationClaims,
    ) -> Vec<(&'a AuthorizedOrder, bool)> {
        let mut found: Vec<(&'a AuthorizedOrder, bool)> = Vec::new();
        for (request_id, order_id) in &claims.answered {
            for order in self.by_request_id.get(request_id).into_iter().flatten() {
                if order.order.id == *order_id
                    && !found.iter().any(|(o, _)| o.order.id == order.order.id)
                {
                    found.push((order, true));
                }
            }
        }
        for tag in &claims.listing_tags {
            for order in self.by_listing_tag.get(tag).into_iter().flatten() {
                if !found.iter().any(|(o, _)| o.order.id == order.order.id) {
                    found.push((order, false));
                }
            }
        }
        found
    }
}

/// The seller's half of the rule: whether one of `orders` is paid (or was,
/// [`status_opens`]) and belongs to the conversation `claims` describes.
pub(crate) fn conversation_has_paid_order(
    orders: &[AuthorizedOrder],
    claims: &ConversationClaims,
) -> bool {
    orders
        .iter()
        .any(|order| status_opens(order.status) && order_in_conversation(order, claims))
}

impl crate::state::AppState {
    /// The buyer's half of the rule: whether this buyer may write in their
    /// conversation `tag` with `store_contract_id` without a Ghost Key.
    ///
    /// A STRICT subset of the seller's half ([`conversation_has_paid_order`]),
    /// evaluated over the same store state and the same conversation. Every
    /// one of these must hold:
    ///
    /// * the conversation is one this node still holds, so it can seal into
    ///   it;
    /// * one of this buyer's purchases filed under it is paid by this node's
    ///   own judgement (`BuyerPurchase::paid`: the kept `Paid` copy, or a
    ///   store copy that passes every check the buyer's own would);
    /// * the store's own copy of that order is `Paid` (the seller also counts
    ///   `PaymentReversed`; the buyer does not);
    /// * that order belongs to the conversation by [`order_in_conversation`],
    ///   over the requests the BUYER wrote in it (the seller counts requests
    ///   in either direction) and the store's current listings.
    ///
    /// Nothing the buyer holds is sent as evidence: the seller decides from
    /// their own store state. What this guards is only that the buyer is not
    /// offered a box whose text the seller would hide.
    pub fn paid_conversation(&self, store_contract_id: &[u8], tag: &[u8; 32]) -> bool {
        use crate::messaging::{Addressing, MessageContent};
        let Some(store) = self.browsing_stores.get(store_contract_id) else {
            return false;
        };
        let Some(conversation) = store
            .conversations
            .iter()
            .find(|conversation| conversation.buyer_public_key == *tag)
        else {
            return false;
        };
        let requests: Vec<(ListingId, Option<InstantSelection>)> = conversation
            .read(&store.mailbox_messages)
            .into_iter()
            .filter_map(|message| match message.content {
                MessageContent::OrderRequest {
                    listing_id,
                    instant,
                    ..
                } if message.addressing == Addressing::ToSeller => Some((listing_id, instant)),
                _ => None,
            })
            .collect();
        let claims = ConversationClaims::of(
            tag,
            requests
                .iter()
                .map(|(listing, selection)| (listing, selection.as_ref())),
            store.listings.iter().map(|listing| &listing.listing.id),
            |listing| Some(conversation.listing_tag(listing)),
        );
        self.buyer_purchases(store_contract_id)
            .iter()
            .filter(|purchase| purchase.conversation == *tag && purchase.paid.is_some())
            .any(|purchase| {
                store.orders.iter().any(|order| {
                    order.order.id == purchase.order_id
                        && order.status == OrderStatus::Paid
                        && order_in_conversation(order, &claims)
                })
            })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::messaging::ConversationKeys;

    pub(crate) const TAG: [u8; 32] = [1; 32];
    pub(crate) const OTHER: [u8; 32] = [2; 32];

    pub(crate) fn keys(tag: &[u8; 32]) -> ConversationKeys {
        ConversationKeys::from_shared_secret(tag)
    }

    pub(crate) fn selection(nonce: u8) -> InstantSelection {
        InstantSelection {
            requested_at_ms: 1_700_000_000_000,
            nonce: [nonce; 16],
            region: None,
            choices: vec![],
            expected_total_sats: 12_000,
        }
    }

    /// An order with only the fields this rule reads set; unsigned, since
    /// the rule reads terms and status, never the signature (the store
    /// contract checked it).
    pub(crate) fn order(status: OrderStatus) -> AuthorizedOrder {
        AuthorizedOrder {
            order: harvest_common::payment::Order {
                request_id: None,
                id: OrderId([7; 32]),
                buyer_fingerprint: String::new(),
                seller_fingerprint: "seller-fp".to_string(),
                amount_sats: 12_000,
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                payment_script_pubkey: Vec::new(),
                payment_address: String::new(),
                required_confirmations: 1,
                payment_hash: None,
                trusted_bridges: Vec::new(),
                bitcoin_address_code_hash: None,
                anchor: None,
                order_binding: Some([5; 32]),
                listing_tag: None,
                buyer_receipt_key: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// The Buy now order answering `selection` in `tag`.
    pub(crate) fn buy_now_order(
        tag: &[u8; 32],
        selection: &InstantSelection,
        status: OrderStatus,
    ) -> AuthorizedOrder {
        let request = selection.answered_request(tag).expect("dated");
        let mut o = order(status);
        o.order.id = request.order_id();
        o.order.request_id = Some(request.request_id);
        o
    }

    /// A quote order for `listing` issued to `tag`: no request id, the
    /// conversation's listing tag.
    pub(crate) fn quote_order(
        tag: &[u8; 32],
        listing: &ListingId,
        status: OrderStatus,
    ) -> AuthorizedOrder {
        let mut o = order(status);
        o.order.listing_tag = Some(keys(tag).listing_tag(listing));
        o
    }

    fn claims(
        tag: &[u8; 32],
        requests: &[(ListingId, Option<InstantSelection>)],
        listings: &[ListingId],
        with_keys: bool,
    ) -> ConversationClaims {
        let k = keys(tag);
        ConversationClaims::of(
            tag,
            requests.iter().map(|(l, s)| (l, s.as_ref())),
            listings.iter(),
            |l| with_keys.then(|| k.listing_tag(l)),
        )
    }

    const L: ListingId = ListingId([9; 32]);

    /// **The order lookup gives exactly what scanning every order does**
    /// (review after 1bd9bcd): for each set of claims below, the orders it
    /// finds, and which by request, equal `order_in_conversation` and
    /// `order_by_request` over all orders. Red with either index dropped.
    #[test]
    fn the_order_lookup_matches_the_full_scan() {
        let orders = vec![
            quote_order(&TAG, &L, OrderStatus::Paid),
            {
                let mut o = buy_now_order(&TAG, &selection(4), OrderStatus::Paid);
                o.order.listing_tag = Some(keys(&TAG).listing_tag(&L));
                o
            },
            buy_now_order(&TAG, &selection(5), OrderStatus::AwaitingPayment),
            quote_order(&OTHER, &L, OrderStatus::Paid),
            quote_order(&TAG, &ListingId([8; 32]), OrderStatus::Cancelled),
        ];
        // Distinct ids, as a store's are (the quote fixture reuses one).
        let orders: Vec<AuthorizedOrder> = orders
            .into_iter()
            .enumerate()
            .map(|(i, mut o)| {
                if o.order.request_id.is_none() {
                    o.order.id = OrderId([0x40 + i as u8; 32]);
                }
                o
            })
            .collect();
        let lookup = OrderLookup::new(&orders);
        for c in [
            claims(&TAG, &[(L, Some(selection(4)))], &[], true),
            claims(&TAG, &[(L, None)], &[ListingId([8; 32])], true),
            claims(&TAG, &[(L, Some(selection(5)))], &[], false),
            claims(&OTHER, &[(L, None)], &[], true),
            claims(&TAG, &[], &[], false),
        ] {
            let mut found: Vec<([u8; 32], bool)> = lookup
                .in_conversation(&c)
                .iter()
                .map(|(o, by_request)| (o.order.id.0, *by_request))
                .collect();
            found.sort();
            let mut scanned: Vec<([u8; 32], bool)> = orders
                .iter()
                .filter(|o| order_in_conversation(o, &c))
                .map(|o| (o.order.id.0, order_by_request(o, &c)))
                .collect();
            scanned.sort();
            assert_eq!(found, scanned);
        }
    }

    /// **A paid invoice answering a QUOTE request opens its conversation.**
    /// Only a paid Buy now did before (extortion second opinion, section 4).
    /// Unpaid or cancelled, it opens nothing; reversed, it does. Red with
    /// the listing-tag rule dropped, and with the status check dropped.
    #[test]
    fn a_paid_quote_invoice_opens_its_conversation() {
        let asked = claims(&TAG, &[(L, None)], &[], true);
        for (status, opens) in [
            (OrderStatus::Paid, true),
            (OrderStatus::PaymentReversed, true),
            (OrderStatus::AwaitingPayment, false),
            (OrderStatus::Cancelled, false),
        ] {
            assert_eq!(
                conversation_has_paid_order(&[quote_order(&TAG, &L, status)], &asked),
                opens,
                "{status:?}"
            );
        }
    }

    /// Only its OWN conversation: the same listing's tag under another
    /// conversation's keys matches nothing, and without the keys nothing can
    /// be matched by tag at all.
    #[test]
    fn a_paid_order_opens_only_its_own_conversation() {
        let paid = quote_order(&TAG, &L, OrderStatus::Paid);
        assert!(!conversation_has_paid_order(
            std::slice::from_ref(&paid),
            &claims(&OTHER, &[(L, None)], &[], true)
        ));
        assert!(!conversation_has_paid_order(
            std::slice::from_ref(&paid),
            &claims(&TAG, &[(L, None)], &[], false)
        ));
        let buy_now = buy_now_order(&TAG, &selection(4), OrderStatus::Paid);
        assert!(conversation_has_paid_order(
            std::slice::from_ref(&buy_now),
            &claims(&TAG, &[(L, Some(selection(4)))], &[], false)
        ));
        // The same selection read under another tag names another id.
        assert!(!conversation_has_paid_order(
            &[buy_now],
            &claims(&OTHER, &[(L, Some(selection(4)))], &[], false)
        ));
    }

    /// A paid Buy now opens by its request; an unpaid or cancelled one does
    /// not, nor one whose request id differs from the order's. Red with the
    /// request-id check dropped.
    #[test]
    fn a_buy_now_opens_by_its_own_request_only_once_paid() {
        let asked = claims(&TAG, &[(L, Some(selection(4)))], &[], false);
        for (status, opens) in [
            (OrderStatus::Paid, true),
            (OrderStatus::PaymentReversed, true),
            (OrderStatus::AwaitingPayment, false),
            (OrderStatus::Cancelled, false),
        ] {
            assert_eq!(
                conversation_has_paid_order(&[buy_now_order(&TAG, &selection(4), status)], &asked),
                opens,
                "{status:?}"
            );
        }
        let mut stray = buy_now_order(&TAG, &selection(4), OrderStatus::Paid);
        stray.order.request_id = Some([3; 32]);
        assert!(!conversation_has_paid_order(&[stray], &asked));
        // Another request in the conversation names another order.
        assert!(!conversation_has_paid_order(
            &[buy_now_order(&TAG, &selection(5), OrderStatus::Paid)],
            &asked
        ));
    }

    /// **A copied order binding opens nothing.** The binding is published on
    /// the order, so anyone can put it in a request of their own; a request
    /// in OTHER naming the paid order's listing and carrying its binding
    /// still opens nothing there. The claims never read the binding at all:
    /// the request pairs carry only the listing and selection.
    #[test]
    fn a_copied_order_binding_opens_nothing() {
        let paid = quote_order(&TAG, &L, OrderStatus::Paid);
        assert_eq!(paid.order.order_binding, Some([5; 32]));
        assert!(!conversation_has_paid_order(
            &[paid],
            &claims(&OTHER, &[(L, None)], &[L], true)
        ));
    }

    /// **An OrderAccepted message naming a paid order opens nothing.** The
    /// buyer can write one naming any id, so the claims are built from
    /// requests and listings only; a conversation holding nothing but such a
    /// message has no claims that match a paid order issued elsewhere.
    #[test]
    fn an_order_accepted_naming_a_paid_order_opens_nothing() {
        let elsewhere = buy_now_order(&OTHER, &selection(4), OrderStatus::Paid);
        // What TAG's claims are when all it holds is an acceptance naming
        // `elsewhere.order.id`: no request, and TAG's own listing tags.
        assert!(!conversation_has_paid_order(
            std::slice::from_ref(&elsewhere),
            &claims(&TAG, &[], &[L], true)
        ));
        let mut quote_elsewhere = quote_order(&OTHER, &L, OrderStatus::Paid);
        quote_elsewhere.order.id = elsewhere.order.id;
        assert!(!conversation_has_paid_order(
            &[quote_elsewhere],
            &claims(&TAG, &[], &[L], true)
        ));
    }

    /// A request that has left the bounded mailbox does not close the
    /// conversation again: the store's current listings still give the tag.
    /// A listing neither named in the conversation nor listed any more gives
    /// nothing. Red with the current listings left out of the claims.
    #[test]
    fn a_request_that_left_the_mailbox_still_opens_by_the_listing() {
        let paid = quote_order(&TAG, &L, OrderStatus::Paid);
        assert!(conversation_has_paid_order(
            std::slice::from_ref(&paid),
            &claims(&TAG, &[], &[L], true)
        ));
        assert!(!conversation_has_paid_order(
            &[paid],
            &claims(&TAG, &[], &[ListingId([8; 32])], true)
        ));
    }
}
