//! The one set of order statuses both sides read (page structure, rule 6):
//! Waiting for payment, Paid, Sent, Complete, Expired, Cancelled, Reported.
//! The seller's "To send" filter and "Send by 4 Oct" pill are Paid seen from
//! their side. Worked out from the same reader-side stage the order cards
//! already use (`fulfilment::order_stage`), never decided here.

use harvest_common::payment::{AuthorizedOrder, OrderStatus};

use crate::fulfilment::OrderStage;
use crate::state::{AppState, BuyerPurchase};

/// Where an order stands, in the words both sides use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Status {
    WaitingForPayment,
    Paid,
    Sent,
    Complete,
    Expired,
    Cancelled,
    Reported,
    /// The payment that settled it was reversed on the chain.
    Reversed,
    /// The buyer's order the store has not published yet, or one this app
    /// will not pay (a blocker waiting does not clear): said on its page.
    CantBePaid,
    /// Placed, and the store has not answered with payment details yet.
    Placed,
}

impl Status {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Status::WaitingForPayment => "Waiting for payment",
            Status::Paid => "Paid",
            Status::Sent => "Sent",
            Status::Complete => "Complete",
            Status::Expired => "Expired",
            Status::Cancelled => "Cancelled",
            Status::Reported => "Reported",
            Status::Reversed => "Payment reversed",
            Status::CantBePaid => "Can\u{2019}t be paid",
            Status::Placed => "Placed",
        }
    }

    /// An order that ended unpaid: folded at the foot of a list.
    pub(crate) fn ended(self) -> bool {
        matches!(
            self,
            Status::Expired | Status::Cancelled | Status::CantBePaid
        )
    }

    /// The pill's class: amber where the reader has something to do is
    /// decided by the caller; this is the quiet one.
    pub(crate) fn pill_class(self) -> &'static str {
        match self {
            Status::Reported | Status::Reversed => "pill pill-warn",
            Status::Paid | Status::Sent | Status::Complete => "pill pill-open",
            _ => "pill",
        }
    }

    /// Which of the progress line's four steps (Ordered, Paid, Sent,
    /// Complete) this status has reached, or `None` for one off the line.
    pub(crate) fn step(self) -> Option<usize> {
        match self {
            Status::Placed | Status::WaitingForPayment => Some(0),
            Status::Paid => Some(1),
            Status::Sent | Status::Reported => Some(2),
            Status::Complete => Some(3),
            _ => None,
        }
    }
}

/// The status a reader-side `stage` reads as, for an order whose published
/// status is `status`.
pub(crate) fn from_stage(stage: OrderStage, status: OrderStatus) -> Status {
    match stage {
        OrderStage::AwaitingPayment { .. } => Status::WaitingForPayment,
        OrderStage::Lapsed { .. } => Status::Expired,
        // A payment made in time outranks a cancel: once it is recorded the
        // order is paid, and its page says so meanwhile.
        OrderStage::Cancelled { .. } => Status::Cancelled,
        OrderStage::AwaitingDespatch { .. } | OrderStage::DespatchWindowClosed { .. } => {
            Status::Paid
        }
        OrderStage::Despatched { .. } => Status::Sent,
        OrderStage::Closed { .. } => Status::Complete,
        OrderStage::Reversed => Status::Reversed,
        OrderStage::Unknown => match status {
            OrderStatus::Paid => Status::Paid,
            OrderStatus::Cancelled => Status::Cancelled,
            OrderStatus::PaymentReversed => Status::Reversed,
            OrderStatus::AwaitingPayment => Status::WaitingForPayment,
        },
    }
}

/// `order`'s stage as this node reads it.
pub(crate) fn stage_of(state: &AppState, order: &AuthorizedOrder) -> OrderStage {
    let tip = state.tip_height(order.order.network);
    crate::fulfilment::order_stage(
        order,
        state.despatch_of(order).as_ref(),
        tip,
        state.payment_sight(order),
    )
}

/// Where one of the seller's orders stands. Reported when a complaint about
/// it is on the store's record.
pub(crate) fn seller_status(
    state: &AppState,
    store_contract_id: &[u8],
    order: &AuthorizedOrder,
) -> Status {
    let status = from_stage(stage_of(state, order), order.status);
    if state
        .complaint_on_record(store_contract_id, &order.order.id)
        .is_some()
    {
        return Status::Reported;
    }
    status
}

/// Where one of the buyer's purchases stands, from the same facts its card
/// shows: the paid copy when there is one, the published order otherwise,
/// and the blockers that decide whether it can be paid.
pub(crate) fn buyer_status(
    state: &AppState,
    store_contract_id: &[u8],
    purchase: &BuyerPurchase,
) -> Status {
    use crate::state::PaymentBlocker;
    if let Some(paid) = purchase.paid.as_ref() {
        if state
            .complaint_on_record(store_contract_id, &purchase.order_id)
            .is_some()
        {
            return Status::Reported;
        }
        return from_stage(stage_of(state, paid), paid.status);
    }
    if let Some(settled) = purchase.settled() {
        return from_stage(stage_of(state, settled), settled.status);
    }
    if purchase.unconfirmed_paid() {
        return Status::CantBePaid;
    }
    let Some(order) = purchase.commitment.as_ref() else {
        return Status::Placed;
    };
    if purchase
        .blockers
        .iter()
        .any(|b| matches!(b, PaymentBlocker::AnchorStale { .. }))
    {
        return Status::Expired;
    }
    match order.status {
        OrderStatus::Cancelled => return Status::Cancelled,
        OrderStatus::Paid | OrderStatus::PaymentReversed => return Status::CantBePaid,
        OrderStatus::AwaitingPayment => {}
    }
    if matches!(stage_of(state, order), OrderStage::Lapsed { .. }) {
        return Status::Expired;
    }
    // Waiting only where nothing stands in the way that waiting will not
    // clear (`buy_view::remedy`).
    let stuck = purchase
        .blockers
        .iter()
        .any(|b| !matches!(super::buy_view::remedy(b), super::buy_view::Remedy::Wait));
    if stuck {
        Status::CantBePaid
    } else {
        Status::WaitingForPayment
    }
}

/// Whether the buyer can pay this purchase now: what its row's "Pay now"
/// and the header's count say (`store_view::orders_here`'s "to pay").
pub(crate) fn buyer_can_pay(purchase: &BuyerPurchase, status: Status) -> bool {
    status == Status::WaitingForPayment
        && (purchase.blockers.is_empty() || purchase.ready_to_keep())
}

/// The seller's pill for a paid order still to send: "Send by 4 Oct", or
/// "Send now" once that date has passed. `None` for any other order.
pub(crate) fn send_by_pill(state: &AppState, order: &AuthorizedOrder) -> Option<String> {
    let tip = state.tip_height(order.order.network);
    match (stage_of(state, order), tip) {
        (OrderStage::AwaitingDespatch { despatch_by, .. }, Some(tip)) => Some(format!(
            "Send by {}",
            crate::fulfilment::approx_date(despatch_by, tip, crate::state::now_ms())
        )),
        (OrderStage::DespatchWindowClosed { .. }, _) => Some("Send now".to_string()),
        (OrderStage::AwaitingDespatch { .. }, None) => Some("To send".to_string()),
        (OrderStage::Unknown, _) if order.status == OrderStatus::Paid => {
            Some("To send".to_string())
        }
        _ => None,
    }
}

/// A short local date for a row, "1 Oct", from a signed timestamp.
pub(crate) fn short_date(at: chrono::DateTime<chrono::Utc>) -> String {
    at.with_timezone(&chrono::Local)
        .format("%-d %b")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both sides read one set of statuses off the same stage.
    #[test]
    fn each_stage_reads_as_one_status() {
        let paid = OrderStatus::Paid;
        assert_eq!(
            from_stage(
                OrderStage::AwaitingPayment { settle_until: 9 },
                OrderStatus::AwaitingPayment
            ),
            Status::WaitingForPayment
        );
        assert_eq!(
            from_stage(
                OrderStage::Lapsed { closed_at: 9 },
                OrderStatus::AwaitingPayment
            ),
            Status::Expired
        );
        assert_eq!(
            from_stage(
                OrderStage::AwaitingDespatch {
                    paid_at: 1,
                    despatch_by: 9
                },
                paid
            ),
            Status::Paid
        );
        assert_eq!(
            from_stage(
                OrderStage::DespatchWindowClosed {
                    despatch_by: 1,
                    complaint_until: 9
                },
                paid
            ),
            Status::Paid
        );
        assert_eq!(
            from_stage(
                OrderStage::Despatched {
                    despatched_at: 1,
                    complaint_until: 9
                },
                paid
            ),
            Status::Sent
        );
        assert_eq!(
            from_stage(OrderStage::Closed { closed_at: 9 }, paid),
            Status::Complete
        );
        assert_eq!(from_stage(OrderStage::Unknown, paid), Status::Paid);
        assert_eq!(from_stage(OrderStage::Reversed, paid), Status::Reversed);
    }

    /// The progress line has four steps, and only orders on their way are
    /// placed on it.
    #[test]
    fn only_orders_on_their_way_are_on_the_progress_line() {
        assert_eq!(Status::WaitingForPayment.step(), Some(0));
        assert_eq!(Status::Paid.step(), Some(1));
        assert_eq!(Status::Sent.step(), Some(2));
        assert_eq!(Status::Complete.step(), Some(3));
        assert_eq!(Status::Expired.step(), None);
        assert_eq!(Status::Cancelled.step(), None);
        assert!(Status::Expired.ended() && Status::Cancelled.ended());
        assert!(!Status::Paid.ended());
    }

    fn order(status: OrderStatus) -> AuthorizedOrder {
        AuthorizedOrder {
            order: harvest_common::payment::Order {
                request_id: Some([4; 32]),
                id: harvest_common::payment::OrderId([1; 32]),
                buyer_fingerprint: String::new(),
                seller_fingerprint: String::new(),
                amount_sats: 2,
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
                created_at: chrono::DateTime::UNIX_EPOCH,
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// **A purchase reads "Waiting for payment" only when the buyer can
    /// wait it out**: an order a blocker makes unpayable reads "Can't be
    /// paid", never waiting above a line saying not to pay it (round 3 of
    /// harvest#187); a stale one reads expired, a cancelled one cancelled,
    /// and a paid copy paid. Red with the remedy check dropped.
    #[test]
    fn a_purchase_waits_only_when_waiting_can_clear_it() {
        use crate::state::PaymentBlocker;
        let state = AppState::default();
        let purchase =
            |commitment: Option<AuthorizedOrder>, blockers: Vec<PaymentBlocker>| BuyerPurchase {
                order_id: harvest_common::payment::OrderId([1; 32]),
                conversation: [2; 32],
                commitment,
                blockers,
                paid: None,
            };
        let store = [3u8; 32];
        let waiting = purchase(Some(order(OrderStatus::AwaitingPayment)), vec![]);
        assert_eq!(
            buyer_status(&state, &store, &waiting),
            Status::WaitingForPayment
        );
        assert!(buyer_can_pay(&waiting, Status::WaitingForPayment));
        let wrong_amount = purchase(
            Some(order(OrderStatus::AwaitingPayment)),
            vec![PaymentBlocker::AmountNotAsked {
                asked_sats: 1,
                order_sats: 2,
            }],
        );
        assert_eq!(
            buyer_status(&state, &store, &wrong_amount),
            Status::CantBePaid
        );
        let not_yet = purchase(
            Some(order(OrderStatus::AwaitingPayment)),
            vec![PaymentBlocker::ChainUnknown],
        );
        assert_eq!(
            buyer_status(&state, &store, &not_yet),
            Status::WaitingForPayment
        );
        assert!(
            !buyer_can_pay(&not_yet, Status::WaitingForPayment),
            "not yet"
        );
        let stale = purchase(
            Some(order(OrderStatus::AwaitingPayment)),
            vec![PaymentBlocker::AnchorStale {
                anchor_height: 1,
                tip_height: 100,
            }],
        );
        assert_eq!(buyer_status(&state, &store, &stale), Status::Expired);
        let cancelled = purchase(
            Some(order(OrderStatus::Cancelled)),
            vec![PaymentBlocker::NotAwaitingPayment(OrderStatus::Cancelled)],
        );
        assert_eq!(buyer_status(&state, &store, &cancelled), Status::Cancelled);
        let mut paid = purchase(
            Some(order(OrderStatus::Paid)),
            vec![PaymentBlocker::NotAwaitingPayment(OrderStatus::Paid)],
        );
        assert_eq!(
            buyer_status(&state, &store, &paid),
            Status::CantBePaid,
            "a Paid record this app can't confirm as the buyer's"
        );
        paid.paid = Some(order(OrderStatus::Paid));
        assert_eq!(buyer_status(&state, &store, &paid), Status::Paid);
        assert_eq!(
            buyer_status(
                &state,
                &store,
                &purchase(None, vec![PaymentBlocker::CommitmentNotPublished])
            ),
            Status::Placed
        );
    }
}
