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

/// Where one order stands, as this reader judges it against their own view
/// of the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderStage {
    /// Unpaid, and a payment could still settle it: a confirmation up to
    /// `settle_until` is inside the order's payment window.
    AwaitingPayment { settle_until: u32 },
    /// Unpaid, and the payment window closed at `closed_at`: nothing can
    /// settle it now, so nothing is owed either way.
    Lapsed { closed_at: u32 },
    /// Cancelled before payment.
    Cancelled,
    /// Paid at `paid_at`; the seller has until `despatch_by` to despatch.
    AwaitingDespatch { paid_at: u32, despatch_by: u32 },
    /// Paid, and the despatch window closed at `despatch_by` with no
    /// despatch on record. The buyer may complain until `complaint_until`.
    DespatchOverdue {
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

/// The block at which `order`'s payment covered it: the height at which the
/// value confirmed inside its payment window first reached the amount owed.
///
/// Read out of the `Paid` record's own evidence, so every reader holding the
/// published record measures the despatch window from the same block,
/// whoever published it and whenever they read it. `None` when the order is
/// not `Paid`, carries no on-chain proof, or its evidence does not show it
/// covered.
///
/// # Why the claims are decoded without checking their signatures
///
/// This decides what a card SAYS, not whether a record is accepted. The
/// record reaching this function has already been verified: by the store
/// contract, which refuses a `Paid` whose proof does not verify, and on the
/// buyer's side by `AuthorizedOrder::verify` in `payment_blockers`. Verifying
/// every claim again on each render would cost an Ed25519 check and an SPV
/// proof per claim, per card, per frame.
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
            return Some(height);
        }
    }
    None
}

/// Where `order` stands against a chain tip at `tip_height`.
///
/// `tip_height` is `None` when this reader has no tip for the order's
/// network, and every window then reads [`OrderStage::Unknown`] rather than
/// open: a window cannot be said to be open by a reader who cannot see the
/// chain.
pub fn order_stage(order: &AuthorizedOrder, tip_height: Option<u32>) -> OrderStage {
    match order.status {
        OrderStatus::Cancelled => OrderStage::Cancelled,
        OrderStatus::PaymentReversed => OrderStage::Reversed,
        OrderStatus::AwaitingPayment => {
            let (Some(window), Some(tip)) = (order.order.payment_window(), tip_height) else {
                return OrderStage::Unknown;
            };
            let settle_until = *window.end();
            if tip > settle_until {
                OrderStage::Lapsed {
                    closed_at: settle_until,
                }
            } else {
                OrderStage::AwaitingPayment { settle_until }
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
                OrderStage::DespatchOverdue {
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
    /// What the order card says about where the order stands, or `None` when
    /// the card's existing payment status already says it all.
    ///
    /// Worded for BOTH parties, because the card is shared between the
    /// seller's panel and the buyer's view (see `OrderCard`), so it names
    /// "the seller" and "the buyer" rather than "you".
    pub fn describe(self, tip_height: Option<u32>) -> Option<String> {
        let left = |until: u32| approx_duration(until.saturating_sub(tip_height.unwrap_or(until)));
        match self {
            // The payment pill and the notes beside it already cover an open
            // invoice.
            OrderStage::AwaitingPayment { .. } | OrderStage::Unknown => None,
            OrderStage::Lapsed { closed_at } => Some(format!(
                "No payment confirmed by block {closed_at}, when this invoice's payment window \
                 closed. It can no longer be paid, and nothing is owed on either side."
            )),
            OrderStage::Cancelled => Some(
                "The seller cancelled this invoice before it was paid. Nothing is owed on either \
                 side."
                    .to_string(),
            ),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by,
            } => Some(format!(
                "Paid in block {paid_at}. The seller has until block {despatch_by} ({}) to \
                 despatch.",
                left(despatch_by)
            )),
            OrderStage::DespatchOverdue {
                despatch_by,
                complaint_until,
            } => Some(format!(
                "Despatch is overdue: the window closed at block {despatch_by} with no \
                 despatch recorded. The buyer can complain until block {complaint_until} ({}).",
                left(complaint_until)
            )),
            OrderStage::Closed { closed_at } => Some(format!(
                "Complete. Every window on this order closed by block {closed_at} with no \
                 complaint."
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
    pub fn needs_attention(self) -> bool {
        matches!(
            self,
            OrderStage::DespatchOverdue { .. } | OrderStage::Reversed
        )
    }
}

/// Whether anybody should be shown `order`'s payment address.
///
/// Only while a payment could still settle it. Showing the address of a
/// cancelled, lapsed or already-paid order invites a payment the order will
/// either never recognise or does not need.
///
/// Decided on the STATUS first and the stage second, so that a reader who
/// cannot yet see the chain ([`OrderStage::Unknown`]) still sees an open
/// invoice's address as before: withholding it on "unknown" would blank every
/// seller's panel while the tip loads. The buyer's own purchase card refuses
/// to show payment details without a tip anyway (`PaymentBlocker::ChainUnknown`).
pub fn offers_payment_address(order: &AuthorizedOrder, stage: OrderStage) -> bool {
    order.status == OrderStatus::AwaitingPayment && !matches!(stage, OrderStage::Lapsed { .. })
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
            order_stage(&paid, Some(paid_at + 6)),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by
            }
        );
        // The deadline block itself is still inside the window.
        assert_eq!(
            order_stage(&paid, Some(despatch_by)),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by
            }
        );
        assert_eq!(
            order_stage(&paid, Some(despatch_by + 1)),
            OrderStage::DespatchOverdue {
                despatch_by,
                complaint_until
            }
        );
        assert_eq!(
            order_stage(&paid, Some(complaint_until)),
            OrderStage::DespatchOverdue {
                despatch_by,
                complaint_until
            }
        );
        assert_eq!(
            order_stage(&paid, Some(complaint_until + 1)),
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
            order_stage(&open, Some(settle_until)),
            OrderStage::AwaitingPayment { settle_until }
        );
        assert_eq!(
            order_stage(&open, Some(settle_until + 1)),
            OrderStage::Lapsed {
                closed_at: settle_until
            }
        );
    }

    #[test]
    fn no_window_is_judged_without_a_tip_or_a_paid_height() {
        let open = order(OrderStatus::AwaitingPayment, 10_000);
        assert_eq!(order_stage(&open, None), OrderStage::Unknown);

        let paid = paid_with(|o| vec![confirmed(o, 10_000, ANCHOR + 3, 1)]);
        assert_eq!(order_stage(&paid, None), OrderStage::Unknown);

        // Paid, but the evidence does not show it covered: unknown, NOT an
        // open despatch window measured from some default.
        let short = paid_with(|o| vec![confirmed(o, 9_999, ANCHOR + 3, 1)]);
        assert_eq!(order_stage(&short, Some(ANCHOR + 10)), OrderStage::Unknown);

        let mut unanchored = order(OrderStatus::AwaitingPayment, 10_000);
        unanchored.order.anchor = None;
        assert_eq!(order_stage(&unanchored, Some(ANCHOR)), OrderStage::Unknown);
    }

    #[test]
    fn only_an_open_invoice_offers_its_address() {
        let settle_until = ANCHOR + PAYMENT_WINDOW_BLOCKS;
        let open = order(OrderStatus::AwaitingPayment, 10_000);
        assert!(offers_payment_address(
            &open,
            OrderStage::AwaitingPayment { settle_until }
        ));
        // No tip yet: an open invoice still shows its address.
        assert!(offers_payment_address(&open, OrderStage::Unknown));
        assert!(!offers_payment_address(
            &open,
            OrderStage::Lapsed {
                closed_at: settle_until
            }
        ));
        for status in [
            OrderStatus::Cancelled,
            OrderStatus::Paid,
            OrderStatus::PaymentReversed,
        ] {
            let settled = order(status, 10_000);
            assert!(
                !offers_payment_address(&settled, OrderStage::Unknown),
                "{status:?} must not show an address"
            );
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
