//! Where an order stands after the payment question: the reader-side windows
//! that take a purchase from `Paid` to finished (harvest#53).
//!
//! # No clock, no arbitrator, no terminal write
//!
//! A contract cannot read a clock, and freenet-core is removing host clock
//! access. So no deadline here is enforced by any contract, and nothing has
//! to be written for an order to finish. Every window is a judgement each
//! reader forms for themselves, in Bitcoin blocks, against the chain tip they
//! can see -- the same pattern [`harvest_common::payment::MAX_ANCHOR_AGE_BLOCKS`]
//! and [`harvest_common::payment::Order::payment_window`] already use.
//!
//! Silence is success and writes nothing. An order whose windows have all
//! passed with no complaint reads as finished to everyone, whether or not
//! either party ever opens Harvest again. Only what a STRANGER has to be able
//! to read gets written: the payment, and (in later phases) the despatch and
//! a complaint.
//!
//! # Why these live in the UI crate and not in `harvest-common`
//!
//! `harvest-common` compiles into every contract, and even reordering impl
//! blocks there has moved a contract's address before (harvest#96). The
//! windows are read by clients only, so keeping them here means tuning a
//! window can never re-key anything.

use harvest_common::payment::{AuthorizedOrder, OrderPaymentProof, OrderStatus};

/// How long after the payment confirmed the seller has to despatch: about a
/// week of blocks.
///
/// Decided in the harvest#53 design (section 7, decision 4) as a starting
/// point to revisit with real seller data. Reader-side, so changing it moves
/// no contract.
pub const DESPATCH_WINDOW_BLOCKS: u32 = 1008;

/// How long after the despatch deadline the buyer may still complain: about
/// two further weeks of blocks. Past it, the order counts as finished.
///
/// Same provenance and the same freedom to change as
/// [`DESPATCH_WINDOW_BLOCKS`].
pub const COMPLAINT_WINDOW_BLOCKS: u32 = 2016;

/// Whether a payment could still settle an order in this status: unpaid, or
/// CANCELLED.
///
/// Cancelled is included because `Paid` outranks `Cancelled` in the store's
/// merge, so a buyer who pays a cancelled invoice settles it and the seller
/// owes the goods. That is only true if somebody PUBLISHES the `Paid`, so
/// every place that decides what to settle, what to watch and what to compare
/// against a payment has to keep treating a cancelled order as open until its
/// payment window closes (harvest#53 review, which found the app settling
/// only `AwaitingPayment` and so stranding exactly that buyer).
pub fn payment_could_still_settle(status: OrderStatus) -> bool {
    match status {
        OrderStatus::AwaitingPayment | OrderStatus::Cancelled => true,
        OrderStatus::Paid | OrderStatus::PaymentReversed => false,
    }
}

/// What this reader can see at an order's address that bears on whether it
/// will be paid (harvest#53 review round 2).
///
/// Only payments that would SETTLE the order count. A partial payment or dust
/// settles nothing, and anyone who can read the public address can send
/// dust, so letting either hold an order open would let a stranger keep any
/// invoice from ever lapsing and any cancel from ever being allowed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PaymentSight {
    /// Value confirmed inside the order's payment window covers the amount:
    /// the order will settle once that payment is deep enough and somebody
    /// publishes it. There is no deadline on publishing, so this holds after
    /// the window closes too.
    pub covered: bool,
    /// Unconfirmed value that, with what is already confirmed in the window,
    /// would cover the amount -- while the window is still open for it to
    /// confirm in.
    pub in_flight: bool,
}

impl PaymentSight {
    /// Whether what is in sight would settle the order.
    pub fn settles(self) -> bool {
        self.covered || self.in_flight
    }
}

/// Where one order stands, as this reader judges it against their own view
/// of the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderStage {
    /// Unpaid, and a payment could still settle it: one confirming inside
    /// the order's payment window can be proven until `settle_until`.
    AwaitingPayment { settle_until: u32 },
    /// Unpaid, no payment is in sight, and the last block at which one could
    /// still have been proven, `closed_at`, has passed.
    Lapsed { closed_at: u32 },
    /// Cancelled by the seller. `settle_until` is `Some` while a payment made
    /// in time could still settle it anyway -- `Paid` outranks `Cancelled` --
    /// and `payment_seen` says this reader can see one that would, at the
    /// address ([`PaymentSight::settles`]).
    Cancelled {
        settle_until: Option<u32>,
        payment_seen: bool,
    },
    /// Paid, counting from `paid_at`; the seller is expected to despatch by
    /// `despatch_by`.
    AwaitingDespatch { paid_at: u32, despatch_by: u32 },
    /// Paid, and the despatch window closed at `despatch_by`. The complaint
    /// window runs until `complaint_until`.
    DespatchWindowClosed {
        despatch_by: u32,
        complaint_until: u32,
    },
    /// Every window has passed: the order is finished, by silence.
    Closed { closed_at: u32 },
    /// The payment that settled it was reorged out of the chain.
    Reversed,
    /// This reader cannot place the order: no chain tip yet, an order with
    /// no anchor, or a payment record whose confirmation height cannot be
    /// read. Deliberately not a guess -- an unknown deadline shown as a known
    /// one is how a buyer is told their window closed when it did not.
    Unknown,
}

/// The block from which `order` counts as paid: the height at which value
/// confirmed inside its payment window first covered the amount, plus the
/// confirmations the order requires beyond that one.
///
/// The confirmations matter (external review of harvest#53): a record cannot
/// be `Paid` until the payment is `required_confirmations` deep, and that is
/// a per-invoice number the seller chooses. Counting the despatch window
/// from the first confirmation would let an invoice demanding a thousand
/// confirmations spend the seller's whole despatch window, and more, before
/// the order could even read as paid.
///
/// Read out of the `Paid` record's own evidence, so every reader holding the
/// same published record measures from the same block. `None` when the order
/// is not `Paid`, carries no on-chain proof, or its evidence does not show it
/// covered.
///
/// # What the evidence does and does not pin
///
/// Per RECORD, this is deterministic. It is not per ORDER: `Paid` is signed
/// by nobody, the submitter chooses which claims to present, and the store's
/// merge keeps the smaller encoding of two equal-rank records. So where
/// several outputs could cover an order, whoever publishes the smallest
/// valid subset chooses which one the window counts from -- a later one
/// moves `paid_at` later, by at most the payment window. That is the
/// selective-omission gap `OnChainPaymentProof` already documents, seen from
/// the reader's side; it shifts a reader-side deadline and nothing else.
///
/// # Why the claims are decoded without checking their signatures
///
/// This decides what a card SAYS, not whether a record is accepted. Every
/// record reaching it has already been verified: by the store contract,
/// which refuses a `Paid` whose proof does not verify, and on the buyer's
/// side by `AuthorizedOrder::verify` in `payment_blockers`. Verifying every
/// claim again on each render would cost an Ed25519 check and an SPV proof
/// per claim, per card, per frame.
pub fn paid_height(order: &AuthorizedOrder) -> Option<u32> {
    if order.status != OrderStatus::Paid {
        return None;
    }
    let OrderPaymentProof::OnChain(proof) = order.payment_proof.as_ref()? else {
        // A Lightning payment has no confirmation height at all. No
        // Lightning order is issued by this build.
        return None;
    };
    let window = order.order.payment_window()?;
    let bodies: Vec<freenet_bitcoin_common::ClaimBody> = proof
        .claims
        .iter()
        .filter_map(|claim| claim.body().ok())
        .collect();
    // The same fold the verifier runs, so the height read here is the one the
    // winning confirmation of each outpoint names.
    let mut confirmed: Vec<(u32, u64)> = freenet_bitcoin_common::fold_claims_by_outpoint(&bodies)
        .into_values()
        .filter_map(|status| match status {
            freenet_bitcoin_common::OutpointStatus::Confirmed {
                value_sats,
                anchor,
                attested_depth: _,
            } if window.contains(&anchor.height) => Some((anchor.height, value_sats)),
            _ => None,
        })
        .collect();
    confirmed.sort_unstable();
    let mut total: u64 = 0;
    for (height, value) in confirmed {
        total = total.saturating_add(value);
        if total >= order.order.amount_sats {
            return Some(height.saturating_add(extra_confirmations(order)));
        }
    }
    None
}

/// Confirmations the order needs beyond the one that puts the payment in a
/// block. A seller-chosen zero is treated as one, which is what the verifier
/// makes of it too: a confirmation is at least the block it is in.
fn extra_confirmations(order: &AuthorizedOrder) -> u32 {
    order.order.required_confirmations.saturating_sub(1)
}

/// The last block at which a payment that confirmed inside `order`'s payment
/// window could first become provable: the window's last block plus the
/// confirmations the order requires beyond it. `None` for an order with no
/// anchor, which no on-chain payment can settle.
fn last_settling_block(order: &AuthorizedOrder) -> Option<u32> {
    let window = order.order.payment_window()?;
    Some(window.end().saturating_add(extra_confirmations(order)))
}

/// Where `order` stands against a chain tip at `tip_height`.
///
/// `tip_height` is `None` when this reader has no tip for the order's
/// network, and every window then reads [`OrderStage::Unknown`] rather than
/// open: a window cannot be said to be open by a reader who cannot see the
/// chain.
///
/// `sight` is what this reader's own view of the order's address shows (see
/// `components::bitcoin_view::AddressReading::sight`). While it shows a
/// payment covering the order inside its window, an unpaid order is not
/// called lapsed: a payment the chain holds but nobody has published yet is
/// still a payment, and saying "no payment" over it would contradict the
/// address reading on the same card.
pub fn order_stage(
    order: &AuthorizedOrder,
    tip_height: Option<u32>,
    sight: PaymentSight,
) -> OrderStage {
    match order.status {
        OrderStatus::PaymentReversed => OrderStage::Reversed,
        OrderStatus::Cancelled => {
            let settle_until = match (last_settling_block(order), tip_height) {
                (Some(last), Some(tip)) if tip <= last => Some(last),
                // Past it: a payment can no longer count. With no tip, the
                // honest reading is that it still might.
                (Some(_), Some(_)) => None,
                (Some(last), None) => Some(last),
                (None, _) => None,
            };
            OrderStage::Cancelled {
                settle_until,
                payment_seen: sight.settles(),
            }
        }
        OrderStatus::AwaitingPayment => {
            let (Some(last), Some(tip)) = (last_settling_block(order), tip_height) else {
                return OrderStage::Unknown;
            };
            if tip > last && !sight.covered {
                OrderStage::Lapsed { closed_at: last }
            } else {
                OrderStage::AwaitingPayment { settle_until: last }
            }
        }
        OrderStatus::Paid => {
            let (Some(paid_at), Some(tip)) = (paid_height(order), tip_height) else {
                return OrderStage::Unknown;
            };
            let despatch_by = paid_at.saturating_add(DESPATCH_WINDOW_BLOCKS);
            let complaint_until = despatch_by.saturating_add(COMPLAINT_WINDOW_BLOCKS);
            if tip <= despatch_by {
                OrderStage::AwaitingDespatch {
                    paid_at,
                    despatch_by,
                }
            } else if tip <= complaint_until {
                OrderStage::DespatchWindowClosed {
                    despatch_by,
                    complaint_until,
                }
            } else {
                OrderStage::Closed {
                    closed_at: complaint_until,
                }
            }
        }
    }
}

/// "about 3 days" for a span of blocks, at Bitcoin's ten-minute target.
///
/// Rough on purpose: blocks are not a clock, and a precise-looking duration
/// would promise a deadline to the minute that the chain does not keep.
pub fn approx_duration(blocks: u32) -> String {
    let minutes = u64::from(blocks) * 10;
    let hours = minutes / 60;
    let days = (hours + 12) / 24;
    if hours < 1 {
        "under an hour".to_string()
    } else if hours < 36 {
        format!("about {hours} hour{}", if hours == 1 { "" } else { "s" })
    } else {
        format!("about {days} days")
    }
}

impl OrderStage {
    /// What an order card says about where the order stands, or `None` when
    /// the card's existing payment status already says it all.
    ///
    /// Worded for BOTH parties, because the card is shared between the
    /// seller's panel and the buyer's view (see `OrderCard`), so it names
    /// "the seller" and "the buyer" rather than "you".
    ///
    /// `status` is the order's published status, which [`OrderStage::Unknown`]
    /// needs to say anything true: a paid order whose deadline cannot be
    /// placed is still paid.
    ///
    /// # What this build can and cannot record, said plainly
    ///
    /// Nothing in this build records a despatch or takes a complaint, so no
    /// sentence here claims either exists. The despatch window closing is
    /// reported as a fact about the calendar, not as a seller's failure: a
    /// seller who shipped on day one reads exactly the same, and styling it
    /// as a warning would accuse every honest seller after a week.
    pub fn describe(self, tip_height: Option<u32>, status: OrderStatus) -> Option<String> {
        // " (about 3 days)", or nothing when this reader has no tip to count
        // from: a duration made up without one is a made-up number.
        let left = |until: u32| {
            tip_height
                .map(|tip| format!(" ({})", approx_duration(until.saturating_sub(tip))))
                .unwrap_or_default()
        };
        match self {
            // The payment pill and the notes beside it already cover an open
            // invoice.
            OrderStage::AwaitingPayment { .. } => None,
            OrderStage::Unknown => (status == OrderStatus::Paid).then(|| {
                "Paid. This node cannot yet place the order against the Bitcoin chain, so its \
                 despatch deadline is not shown."
                    .to_string()
            }),
            OrderStage::Lapsed { closed_at } => Some(format!(
                "No payment was recorded for this invoice before its payment window closed at \
                 block {closed_at}, so it can no longer be paid."
            )),
            OrderStage::Cancelled {
                payment_seen: true, ..
            } => Some(
                "The seller cancelled this invoice, but a payment that settles it has been seen \
                 at its address. A cancellation does not undo a payment: once it is recorded the \
                 order is paid, and the seller owes the goods."
                    .to_string(),
            ),
            OrderStage::Cancelled {
                settle_until: Some(until),
                payment_seen: false,
            } => Some(format!(
                "The seller cancelled this invoice. A payment made in time still counts until \
                 block {until}{}, and the seller would then owe the goods.",
                left(until),
            )),
            OrderStage::Cancelled {
                settle_until: None, ..
            } => Some(
                "The seller cancelled this invoice, and no payment was recorded for it in time."
                    .to_string(),
            ),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by,
            } => Some(format!(
                "Paid, counting from block {paid_at}. The seller is expected to despatch by \
                 block {despatch_by}{}.",
                left(despatch_by)
            )),
            OrderStage::DespatchWindowClosed {
                despatch_by,
                complaint_until,
            } => Some(format!(
                "Paid. The despatch window closed at block {despatch_by}, and this order counts \
                 as complete from block {complaint_until}{}.",
                left(complaint_until)
            )),
            OrderStage::Closed { closed_at } => Some(format!(
                "Paid and complete: every window on this order closed by block {closed_at}."
            )),
            OrderStage::Reversed => Some(
                "The payment that settled this order was reversed on the Bitcoin chain, so it no \
                 longer counts as paid."
                    .to_string(),
            ),
        }
    }

    /// Whether the note should read as a warning: something a party ought to
    /// act on, rather than a status.
    ///
    /// Not the despatch window closing, deliberately -- see [`Self::describe`].
    pub fn needs_attention(self) -> bool {
        matches!(
            self,
            OrderStage::Reversed
                | OrderStage::Cancelled {
                    payment_seen: true,
                    ..
                }
        )
    }
}

/// Whether anybody should be shown `order`'s payment address.
///
/// Only an unpaid invoice, and only while a payment sent now could still
/// confirm inside its payment window. Showing the address of a cancelled or
/// already-paid order invites a payment it will either never recognise or
/// does not need. (A cancelled invoice paid anyway does still settle, but it
/// is not one to invite payment to.)
///
/// Judged against the window's last block, NOT against the order's stage
/// (harvest#53 review round 2). The stage stays "awaiting payment" past the
/// window while a payment made in time is still gathering confirmations or
/// waiting to be published, and a second payment sent in that time can only
/// confirm outside the window and never settle anything.
///
/// A reader with no tip still sees an open invoice's address as before:
/// withholding it on "unknown" would blank every seller's panel while the
/// chain loads. The buyer's own purchase card refuses to show payment details
/// without a tip anyway (`PaymentBlocker::ChainUnknown`). An order with no
/// anchor keeps the address and its existing note saying it can never settle.
pub fn offers_payment_address(order: &AuthorizedOrder, tip_height: Option<u32>) -> bool {
    if order.status != OrderStatus::AwaitingPayment {
        return false;
    }
    match (order.order.payment_window(), tip_height) {
        (Some(window), Some(tip)) => tip <= *window.end(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use freenet_bitcoin_common::spv::testing::payment_proof;
    use freenet_bitcoin_common::{
        BlockAnchor, BlockHash, BridgeId, Claim, ClaimBody, OutPoint, SignedClaim, SignedTipEntry,
        TipEntryBody,
    };
    use harvest_common::payment::{Order, OrderId, PAYMENT_WINDOW_BLOCKS};

    const ANCHOR: u32 = 800_000;

    /// A payment covering the order, confirmed inside its window.
    const COVERED: PaymentSight = PaymentSight {
        covered: true,
        in_flight: false,
    };

    fn bridge() -> SigningKey {
        SigningKey::from_bytes(&[61u8; 32])
    }

    fn anchor(height: u32) -> BlockAnchor {
        BlockAnchor {
            height,
            hash: BlockHash([height as u8; 32]),
        }
    }

    fn order(status: OrderStatus, amount_sats: u64) -> AuthorizedOrder {
        let order = Order {
            id: OrderId([0u8; 32]),
            buyer_fingerprint: String::new(),
            seller_fingerprint: "seller".into(),
            amount_sats,
            network: freenet_bitcoin_common::BitcoinNetwork::Signet,
            payment_script_pubkey: vec![0x00, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
            payment_address: String::new(),
            required_confirmations: 1,
            payment_hash: None,
            trusted_bridges: vec![BridgeId(bridge().verifying_key().to_bytes())],
            bitcoin_address_code_hash: None,
            anchor: Some(anchor(ANCHOR)),
            order_binding: None,
            listing_tag: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
        .with_derived_id();
        AuthorizedOrder {
            order,
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// A bridge-signed confirmation of `value_sats` to the order's script at
    /// `height`, one outpoint per `seed`.
    fn confirmed(order: &AuthorizedOrder, value_sats: u64, height: u32, seed: u8) -> SignedClaim {
        let (spv, txid, block_hash) = payment_proof(
            &order.order.payment_script_pubkey,
            value_sats,
            1,
            [seed; 32],
        );
        SignedClaim::sign(
            &bridge(),
            &ClaimBody {
                script_id: order.order.bitcoin_params().script_id(),
                network: order.order.network,
                as_of: anchor(height + 10),
                claim: Claim::ConfirmedOutput {
                    outpoint: OutPoint { txid, vout: 0 },
                    value_sats,
                    anchor: BlockAnchor {
                        height,
                        hash: block_hash,
                    },
                    spv,
                },
            },
        )
        .expect("sign the claim")
    }

    fn tip() -> SignedTipEntry {
        SignedTipEntry::sign(
            &bridge(),
            &TipEntryBody {
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                anchor: anchor(ANCHOR + 20),
                prev_hash: BlockHash([8u8; 32]),
                block_time: 1_700_000_000,
                tx_count: 1,
                median_time: 1_700_000_000,
            },
        )
        .expect("sign the tip")
    }

    fn paid_with(claims: impl FnOnce(&AuthorizedOrder) -> Vec<SignedClaim>) -> AuthorizedOrder {
        let mut paid = order(OrderStatus::Paid, 10_000);
        let claims = claims(&paid);
        paid.payment_proof = Some(OrderPaymentProof::on_chain(claims, tip()));
        paid
    }

    #[test]
    fn the_paid_height_is_where_the_payment_first_covered_the_order() {
        // Two part-payments: the order is covered only once the second lands.
        let paid = paid_with(|o| {
            vec![
                confirmed(o, 4_000, ANCHOR + 3, 1),
                confirmed(o, 6_000, ANCHOR + 9, 2),
            ]
        });
        assert_eq!(paid_height(&paid), Some(ANCHOR + 9));
    }

    #[test]
    fn a_later_overpayment_does_not_move_the_paid_height() {
        let paid = paid_with(|o| {
            vec![
                confirmed(o, 10_000, ANCHOR + 3, 1),
                confirmed(o, 5_000, ANCHOR + 40, 2),
            ]
        });
        assert_eq!(paid_height(&paid), Some(ANCHOR + 3));
    }

    #[test]
    fn value_outside_the_payment_window_is_not_the_orders_payment() {
        // Confirmed AT the anchor: before the order existed (harvest#77).
        let paid = paid_with(|o| {
            vec![
                confirmed(o, 10_000, ANCHOR, 1),
                confirmed(o, 10_000, ANCHOR + 5, 2),
            ]
        });
        assert_eq!(paid_height(&paid), Some(ANCHOR + 5));

        let only_before = paid_with(|o| vec![confirmed(o, 10_000, ANCHOR, 1)]);
        assert_eq!(paid_height(&only_before), None);
    }

    #[test]
    fn only_a_paid_record_has_a_paid_height() {
        let mut not_paid = paid_with(|o| vec![confirmed(o, 10_000, ANCHOR + 3, 1)]);
        not_paid.status = OrderStatus::AwaitingPayment;
        assert_eq!(paid_height(&not_paid), None);
    }

    #[test]
    fn a_paid_order_moves_through_despatch_complaint_and_closed_by_the_tip_alone() {
        let paid_at = ANCHOR + 3;
        let paid = paid_with(|o| vec![confirmed(o, 10_000, paid_at, 1)]);
        let despatch_by = paid_at + DESPATCH_WINDOW_BLOCKS;
        let complaint_until = despatch_by + COMPLAINT_WINDOW_BLOCKS;

        assert_eq!(
            order_stage(&paid, Some(paid_at + 6), PaymentSight::default()),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by
            }
        );
        // The deadline block itself is still inside the window.
        assert_eq!(
            order_stage(&paid, Some(despatch_by), PaymentSight::default()),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by
            }
        );
        assert_eq!(
            order_stage(&paid, Some(despatch_by + 1), PaymentSight::default()),
            OrderStage::DespatchWindowClosed {
                despatch_by,
                complaint_until
            }
        );
        assert_eq!(
            order_stage(&paid, Some(complaint_until), PaymentSight::default()),
            OrderStage::DespatchWindowClosed {
                despatch_by,
                complaint_until
            }
        );
        assert_eq!(
            order_stage(&paid, Some(complaint_until + 1), PaymentSight::default()),
            OrderStage::Closed {
                closed_at: complaint_until
            }
        );
    }

    #[test]
    fn an_unpaid_order_lapses_when_its_payment_window_closes() {
        let open = order(OrderStatus::AwaitingPayment, 10_000);
        let settle_until = ANCHOR + PAYMENT_WINDOW_BLOCKS;
        assert_eq!(
            order_stage(&open, Some(settle_until), PaymentSight::default()),
            OrderStage::AwaitingPayment { settle_until }
        );
        assert_eq!(
            order_stage(&open, Some(settle_until + 1), PaymentSight::default()),
            OrderStage::Lapsed {
                closed_at: settle_until
            }
        );
    }

    #[test]
    fn no_window_is_judged_without_a_tip_or_a_paid_height() {
        let open = order(OrderStatus::AwaitingPayment, 10_000);
        assert_eq!(
            order_stage(&open, None, PaymentSight::default()),
            OrderStage::Unknown
        );

        let paid = paid_with(|o| vec![confirmed(o, 10_000, ANCHOR + 3, 1)]);
        assert_eq!(
            order_stage(&paid, None, PaymentSight::default()),
            OrderStage::Unknown
        );

        // Paid, but the evidence does not show it covered: unknown, NOT an
        // open despatch window measured from some default.
        let short = paid_with(|o| vec![confirmed(o, 9_999, ANCHOR + 3, 1)]);
        assert_eq!(
            order_stage(&short, Some(ANCHOR + 10), PaymentSight::default()),
            OrderStage::Unknown
        );

        let mut unanchored = order(OrderStatus::AwaitingPayment, 10_000);
        unanchored.order.anchor = None;
        assert_eq!(
            order_stage(&unanchored, Some(ANCHOR), PaymentSight::default()),
            OrderStage::Unknown
        );
    }

    #[test]
    fn only_an_open_invoice_offers_its_address_and_only_inside_its_window() {
        let window_end = ANCHOR + PAYMENT_WINDOW_BLOCKS;
        let mut open = order(OrderStatus::AwaitingPayment, 10_000);
        assert!(offers_payment_address(&open, Some(window_end)));
        // No tip yet: an open invoice still shows its address.
        assert!(offers_payment_address(&open, None));
        assert!(!offers_payment_address(&open, Some(window_end + 1)));
        // Review round 2: past the window the STAGE can still read as
        // awaiting payment (a payment made in time gathering confirmations),
        // and the address must not come back with it.
        open.order.required_confirmations = 6;
        assert_eq!(
            order_stage(&open, Some(window_end + 3), COVERED),
            OrderStage::AwaitingPayment {
                settle_until: window_end + 5
            }
        );
        assert!(!offers_payment_address(&open, Some(window_end + 3)));
        for status in [
            OrderStatus::Cancelled,
            OrderStatus::Paid,
            OrderStatus::PaymentReversed,
        ] {
            let settled = order(status, 10_000);
            assert!(
                !offers_payment_address(&settled, Some(ANCHOR + 1)),
                "{status:?} must not show an address"
            );
        }
    }

    #[test]
    fn the_despatch_window_counts_from_the_required_depth() {
        // External review of harvest#53: an invoice demanding many
        // confirmations must not spend the despatch window before it can
        // even read as paid.
        let mut paid = paid_with(|o| vec![confirmed(o, 10_000, ANCHOR + 3, 1)]);
        paid.order.required_confirmations = 1_500;
        assert_eq!(paid_height(&paid), Some(ANCHOR + 3 + 1_499));
        let paid_at = ANCHOR + 3 + 1_499;
        assert_eq!(
            order_stage(&paid, Some(paid_at), PaymentSight::default()),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by: paid_at + DESPATCH_WINDOW_BLOCKS
            }
        );
        // A seller-chosen zero is treated as one, as the verifier treats it.
        paid.order.required_confirmations = 0;
        assert_eq!(paid_height(&paid), Some(ANCHOR + 3));
    }

    #[test]
    fn an_unpaid_order_does_not_lapse_while_a_payment_in_time_could_still_be_proven() {
        let mut open = order(OrderStatus::AwaitingPayment, 10_000);
        open.order.required_confirmations = 6;
        let last = ANCHOR + PAYMENT_WINDOW_BLOCKS + 5;
        assert_eq!(
            order_stage(&open, Some(last), PaymentSight::default()),
            OrderStage::AwaitingPayment { settle_until: last }
        );
        assert_eq!(
            order_stage(&open, Some(last + 1), PaymentSight::default()),
            OrderStage::Lapsed { closed_at: last }
        );
        // A covering payment this reader can see is never called lapsed.
        assert_eq!(
            order_stage(&open, Some(last + 1), COVERED),
            OrderStage::AwaitingPayment { settle_until: last }
        );
        // But a partial payment, dust, or something still in flight after
        // the window is not a payment that settles it (review round 2).
        assert_eq!(
            order_stage(&open, Some(last + 1), PaymentSight::default()),
            OrderStage::Lapsed { closed_at: last }
        );
    }

    #[test]
    fn a_cancelled_order_can_still_be_paid_until_its_window_closes() {
        let cancelled = order(OrderStatus::Cancelled, 10_000);
        let last = ANCHOR + PAYMENT_WINDOW_BLOCKS;
        assert_eq!(
            order_stage(&cancelled, Some(last), COVERED),
            OrderStage::Cancelled {
                settle_until: Some(last),
                payment_seen: true
            }
        );
        assert_eq!(
            order_stage(&cancelled, Some(last + 1), PaymentSight::default()),
            OrderStage::Cancelled {
                settle_until: None,
                payment_seen: false
            }
        );
        // No tip: it still might.
        assert_eq!(
            order_stage(&cancelled, None, PaymentSight::default()),
            OrderStage::Cancelled {
                settle_until: Some(last),
                payment_seen: false
            }
        );
        // Review round 2: a covering payment past the cutoff is still seen,
        // and still reads as a warning, because publishing it has no
        // deadline and it will turn the order Paid.
        let stage = order_stage(&cancelled, Some(last + 1), COVERED);
        assert_eq!(
            stage,
            OrderStage::Cancelled {
                settle_until: None,
                payment_seen: true
            }
        );
        assert!(stage.needs_attention());
        assert!(stage
            .describe(Some(last + 1), OrderStatus::Cancelled)
            .expect("said")
            .contains("owes the goods"));
    }

    #[test]
    fn a_payment_can_still_settle_an_unpaid_or_cancelled_order_only() {
        assert!(payment_could_still_settle(OrderStatus::AwaitingPayment));
        assert!(payment_could_still_settle(OrderStatus::Cancelled));
        assert!(!payment_could_still_settle(OrderStatus::Paid));
        assert!(!payment_could_still_settle(OrderStatus::PaymentReversed));
    }

    /// The card's sentences: each names the block it is about, and none
    /// promises a despatch record or a complaint this build cannot make.
    #[test]
    fn each_stage_says_what_is_true_and_nothing_this_build_cannot_do() {
        let tip = Some(1_000);
        let say = |stage: OrderStage, status| stage.describe(tip, status);
        assert_eq!(
            say(
                OrderStage::AwaitingPayment {
                    settle_until: 2_000
                },
                OrderStatus::AwaitingPayment
            ),
            None
        );
        assert_eq!(say(OrderStage::Unknown, OrderStatus::AwaitingPayment), None);
        assert!(say(OrderStage::Unknown, OrderStatus::Paid)
            .expect("a paid order says it is paid")
            .starts_with("Paid."));
        let lapsed = say(
            OrderStage::Lapsed { closed_at: 900 },
            OrderStatus::AwaitingPayment,
        )
        .expect("lapsed");
        assert!(lapsed.contains("block 900"), "{lapsed}");
        let open_cancel = say(
            OrderStage::Cancelled {
                settle_until: Some(1_144),
                payment_seen: false,
            },
            OrderStatus::Cancelled,
        )
        .expect("cancelled");
        assert!(open_cancel.contains("block 1144"), "{open_cancel}");
        assert!(open_cancel.contains("about 24 hours"), "{open_cancel}");
        assert!(!open_cancel.contains("seen"), "{open_cancel}");
        let seen = say(
            OrderStage::Cancelled {
                settle_until: Some(1_144),
                payment_seen: true,
            },
            OrderStatus::Cancelled,
        )
        .expect("cancelled");
        assert!(seen.contains("has been seen"), "{seen}");
        // No tip: the block, but no duration counted from nowhere (codex,
        // review round 2).
        let no_tip = OrderStage::Cancelled {
            settle_until: Some(1_144),
            payment_seen: false,
        }
        .describe(None, OrderStatus::Cancelled)
        .expect("cancelled");
        assert!(no_tip.contains("block 1144"), "{no_tip}");
        assert!(
            !no_tip.contains("about") && !no_tip.contains("under"),
            "{no_tip}"
        );
        let despatch = say(
            OrderStage::AwaitingDespatch {
                paid_at: 990,
                despatch_by: 1_998,
            },
            OrderStatus::Paid,
        )
        .expect("despatch");
        assert!(despatch.contains("block 990"), "{despatch}");
        assert!(despatch.contains("block 1998"), "{despatch}");
        assert!(despatch.contains("about 7 days"), "{despatch}");
        let closed_window = say(
            OrderStage::DespatchWindowClosed {
                despatch_by: 900,
                complaint_until: 2_916,
            },
            OrderStatus::Paid,
        )
        .expect("window closed");
        for stage_text in [&despatch, &closed_window] {
            for promise in ["complain", "overdue", "recorded"] {
                assert!(
                    !stage_text.contains(promise),
                    "{stage_text:?} promises something this build cannot do ({promise})"
                );
            }
        }
        // A tip past the deadline does not underflow into a huge duration.
        let late = OrderStage::AwaitingDespatch {
            paid_at: 1,
            despatch_by: 10,
        }
        .describe(Some(5_000), OrderStatus::Paid)
        .expect("despatch");
        assert!(late.contains("under an hour"), "{late}");
    }

    #[test]
    fn only_a_reversal_or_a_payment_on_a_cancelled_invoice_is_a_warning() {
        assert!(OrderStage::Reversed.needs_attention());
        for settle_until in [Some(1), None] {
            assert!(OrderStage::Cancelled {
                settle_until,
                payment_seen: true
            }
            .needs_attention());
        }
        for calm in [
            OrderStage::AwaitingPayment { settle_until: 1 },
            OrderStage::Lapsed { closed_at: 1 },
            OrderStage::Cancelled {
                settle_until: Some(1),
                payment_seen: false,
            },
            OrderStage::AwaitingDespatch {
                paid_at: 1,
                despatch_by: 2,
            },
            OrderStage::DespatchWindowClosed {
                despatch_by: 1,
                complaint_until: 2,
            },
            OrderStage::Closed { closed_at: 1 },
            OrderStage::Unknown,
        ] {
            assert!(!calm.needs_attention(), "{calm:?} is not a warning");
        }
    }

    #[test]
    fn durations_are_rough_and_never_claim_precision() {
        assert_eq!(approx_duration(0), "under an hour");
        assert_eq!(approx_duration(6), "about 1 hour");
        assert_eq!(approx_duration(144), "about 24 hours");
        assert_eq!(approx_duration(DESPATCH_WINDOW_BLOCKS), "about 7 days");
        assert_eq!(approx_duration(COMPLAINT_WINDOW_BLOCKS), "about 14 days");
    }
}
