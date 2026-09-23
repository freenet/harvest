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
//! to read gets written: the payment, the seller's despatch (Phase B), and the
//! buyer's complaint (Phase C).
//!
//! # Why these live in the UI crate and not in `harvest-common`
//!
//! `harvest-common` compiles into every contract, and even reordering impl
//! blocks there has moved a contract's address before (harvest#96). The
//! windows are read by clients only, so keeping them here means tuning a
//! window can never re-key anything.

use harvest_common::fulfilment::AuthorizedDespatch;
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
    /// A payment covering the order is in sight, but it also falls inside
    /// another order's window on the same (reused) address, so it may be that
    /// order's. Not counted as settling this one -- `settlement_hold` leaves
    /// that to the seller -- and not ignored either: while it stands the
    /// order is neither lapsed nor "no payment recorded", because the seller
    /// may yet confirm it (review round 4).
    pub ambiguous: bool,
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
    /// Cancelled, by the seller or (harvest#53 Phase B) the buyer. `settle_until` is `Some` while a payment made
    /// in time could still settle it anyway -- `Paid` outranks `Cancelled` --
    /// and `payment_seen` says this reader can see one that would, at the
    /// address ([`PaymentSight::settles`]).
    Cancelled {
        settle_until: Option<u32>,
        payment_seen: bool,
        /// A covering payment is in sight that may be another order's
        /// ([`PaymentSight::ambiguous`]).
        payment_maybe: bool,
    },
    /// Paid, counting from `paid_at`; the seller is expected to despatch by
    /// `despatch_by`.
    AwaitingDespatch { paid_at: u32, despatch_by: u32 },
    /// Paid, and the seller recorded a despatch anchored at block
    /// `despatched_at` (harvest#53 Phase B). The order counts as complete from
    /// `complaint_until`.
    Despatched {
        despatched_at: u32,
        complaint_until: u32,
    },
    /// Paid, no despatch recorded, and the despatch window closed at
    /// `despatch_by`. The complaint window runs until `complaint_until`.
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
    // One function, in `harvest-common`, because the reputation contract
    // checks a complaint's signed paid height against it
    // (`docs/complaint-threat-model.md` section 5.2): a reader measuring
    // from any other height would disagree with what the buyer signed.
    harvest_common::payment::paid_height(order)
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
pub(crate) fn last_settling_block(order: &AuthorizedOrder) -> Option<u32> {
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
/// `despatch` is the seller's despatch of this order, if the store holds one
/// (`AppState::despatch_of`). It counts only on a PAID order: the contract does
/// not check status (see `harvest_common::fulfilment`), so a despatch on an
/// unpaid, cancelled or reversed order is ignored here.
///
/// # A despatch never shortens the buyer's window
///
/// The complaint window closes [`COMPLAINT_WINDOW_BLOCKS`] after the LATER of
/// the despatch deadline and the despatch's own anchor. A despatch's anchor is
/// a lower bound the seller chooses, so a seller could backdate a late one;
/// measuring from the deadline at least means that gains them nothing. A
/// despatch recorded after the deadline moves the end later, which is the
/// buyer's side.
///
/// A despatch anchored before the block the order counts as paid from still
/// reads as a despatch, deliberately (round 4 of harvest#136). It is the
/// seller's claim that the goods went, and hiding it would be worse than
/// showing it: `paid_height` is per RECORD and can move later when a smaller
/// valid `Paid` record wins the merge, the store keeps one despatch per order
/// (the lower anchor wins), so a filter on it could hide an honest despatch
/// for good and show the order as missed. The window is unaffected either
/// way.
///
/// The guarantee is against the NO-DESPATCH baseline, not against a despatch
/// this reader saw earlier: a store keeps the smaller encoding of two
/// despatches for one order, so a seller who signed a late despatch and then
/// a backdated one can pull the end back to `despatch_by +
/// COMPLAINT_WINDOW_BLOCKS` -- never earlier. The app normally signs one
/// despatch per order (a second only after a send it believed failed).
///
/// `sight` is what this reader's own view of the order's address shows (see
/// `components::bitcoin_view::AddressReading::sight`). While it shows a
/// payment covering the order inside its window, an unpaid order is not
/// called lapsed: a payment the chain holds but nobody has published yet is
/// still a payment, and saying "no payment" over it would contradict the
/// address reading on the same card.
pub fn order_stage(
    order: &AuthorizedOrder,
    despatch: Option<&AuthorizedDespatch>,
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
                payment_maybe: sight.ambiguous,
            }
        }
        OrderStatus::AwaitingPayment => {
            let (Some(last), Some(tip)) = (last_settling_block(order), tip_height) else {
                return OrderStage::Unknown;
            };
            if tip > last && !sight.covered && !sight.ambiguous {
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
            // Only a despatch of THIS order; the store already guarantees it,
            // and checking again costs nothing.
            let despatched_at = despatch
                .filter(|d| d.despatch.order_id == order.order.id)
                .map(|d| d.despatch.anchor.height);
            // The one computation of the window's end, shared with how a
            // reader counts a complaint (`complaint_standing`), so the card
            // and the record cannot disagree about when it closed.
            let complaint_until = complaint_window_end(order, despatch).unwrap_or(despatch_by);
            if let Some(despatched_at) = despatched_at {
                return if tip <= complaint_until {
                    OrderStage::Despatched {
                        despatched_at,
                        complaint_until,
                    }
                } else {
                    OrderStage::Closed {
                        closed_at: complaint_until,
                    }
                };
            }
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

/// Whether a complaint against a payment the store later records as
/// reversed still counts against the seller.
///
/// **The one place this decision lives** (harvest#53 design, section 8).
/// Resolved for now as a reader-side rule: the contract accepts a complaint
/// only against a `Paid` order, and if that payment is later reversed on the
/// chain, readers show the complaint as "payment reversed" and do not count
/// it -- the buyer's money did not stay with the seller, so the complaint no
/// longer carries the cost that gives it weight. It is Ian's call to revisit;
/// change this and every reader follows, with no re-key.
pub fn complaint_against_reversed_payment_counts() -> bool {
    false
}

/// How a reader counts one complaint on a seller's record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ComplaintStanding {
    /// Counts against the seller.
    Counts,
    /// Signed after the complaint window closed at `closed_at`, by its own
    /// block reference. Shown, not counted.
    Late { closed_at: u32 },
    /// The store records the order's payment as reversed. Shown as such, and
    /// counted only if [`complaint_against_reversed_payment_counts`] says so.
    PaymentReversed,
}

impl ComplaintStanding {
    pub fn counts(self) -> bool {
        match self {
            ComplaintStanding::Counts => true,
            ComplaintStanding::Late { .. } => false,
            ComplaintStanding::PaymentReversed => complaint_against_reversed_payment_counts(),
        }
    }
}

/// The last block at which the buyer of `order` may complain: the despatch
/// deadline or the despatch's own anchor, whichever is later, plus
/// [`COMPLAINT_WINDOW_BLOCKS`] -- the same end [`order_stage`] reads.
/// `None` when the order's paid height cannot be read.
pub fn complaint_window_end(
    order: &AuthorizedOrder,
    despatch: Option<&AuthorizedDespatch>,
) -> Option<u32> {
    Some(window_end_from(
        paid_height(order)?,
        &order.order.id,
        despatch,
    ))
}

/// [`complaint_window_end`] for an order paid at `paid_at`.
fn window_end_from(
    paid_at: u32,
    order_id: &harvest_common::payment::OrderId,
    despatch: Option<&AuthorizedDespatch>,
) -> u32 {
    let despatch_by = paid_at.saturating_add(DESPATCH_WINDOW_BLOCKS);
    let despatched_at = despatch
        .filter(|d| &d.despatch.order_id == order_id)
        .map(|d| d.despatch.anchor.height)
        .unwrap_or(0);
    despatch_by
        .max(despatched_at)
        .saturating_add(COMPLAINT_WINDOW_BLOCKS)
}

/// How a reader counts `complaint` (harvest#53 Phase C,
/// `docs/complaint-threat-model.md` section 6).
///
/// `store_order` is the store's current record of the complained-about
/// order, if the reader has the store loaded and it still holds the order
/// (`enforce_order_cap` prunes old ones); `despatch` is the store's despatch
/// of it, if any. Neither is needed: the complaint carries its own paid
/// order, which the contract verified.
///
/// # The window is the complaint's own
///
/// It counts from the complaint's SIGNED `paid_height`, which the contract
/// checked against the complaint's own proof, so nothing the store holds can
/// move its start. A despatch can only extend it (`max`).
///
/// # What the block height can and cannot show
///
/// It is the buyer's statement, a lower bound at best: a buyer can name any
/// in-window height after the window closed, so a window's close is not
/// enforceable against a buyer who does. What it does show is a complaint
/// honestly signed late, which is not counted.
///
/// # A reversal counts only on the union of the evidence
///
/// A store `PaymentReversed` record is built from claims its submitter chose,
/// and a submitter can build a genuine one by withholding the later
/// re-confirmation of a reorged payment. So the reversal discounts the
/// complaint only if the reversal's claims TOGETHER WITH the complaint's
/// still fold to `Reversed` ([`reversal_stands`]).
///
/// # Nothing about the store's status
///
/// Closure, retirement and backing are never read. A seller can backdate a
/// closure anchor, so no rule of the form "discount complaints after
/// closure" is safe; complaints are counted on the store key's record
/// whatever the store's status.
pub fn complaint_standing(
    complaint: &harvest_common::reputation::Complaint,
    store_order: Option<&AuthorizedOrder>,
    despatch: Option<&AuthorizedDespatch>,
) -> ComplaintStanding {
    let reversal = store_order.filter(|held| {
        held.order.id == complaint.order.order.id && held.status == OrderStatus::PaymentReversed
    });
    if reversal.is_some_and(|reversal| reversal_stands(complaint, reversal)) {
        return ComplaintStanding::PaymentReversed;
    }
    let closed_at = window_end_from(complaint.paid_height, complaint.order_id(), despatch);
    if complaint.block_height > closed_at {
        ComplaintStanding::Late { closed_at }
    } else {
        ComplaintStanding::Counts
    }
}

/// Whether a store's `PaymentReversed` record of the complained-about order
/// still shows the payment reversed once the complaint's own evidence is
/// added to it (`docs/complaint-threat-model.md` section 6).
///
/// The union of both claim sets, deduplicated by digest, with whichever of
/// the two tips is higher, verified against the complaint's order: a
/// reversal counts only if that verification answers
/// [`harvest_common::payment::ProofError::Reversed`] itself. Anything else
/// -- the union shows the payment confirmed again, or the evidence cannot be
/// read -- leaves the complaint standing, since the complaint is what the
/// contract verified.
///
/// # Only when every bridge the order names is recognised
///
/// A retraction is the one claim SPV cannot check, so it is trusted from the
/// bridge that signed it. An order naming a bridge the SELLER runs can
/// therefore be "reversed" at will: the seller's bridge signs a retraction of
/// its own confirmation. Honoured, that let a seller fill its record, up to
/// the cap, with sockpuppet complaints dated at their paid height (nearest of
/// all, so kept first) that no reader counted, pushing every honest
/// complaint out (review round 6 of #143). A buyer pays only orders whose
/// bridges are all recognised (`PaymentBlocker::BridgeNotRecognised`), so an
/// honest buyer's complaint loses nothing here: only a reversal a recognised
/// bridge attested discounts it. A bridge recognised once and dropped later
/// makes its reversals count for nothing, which errs toward the buyer.
pub fn reversal_stands(
    complaint: &harvest_common::reputation::Complaint,
    reversal: &AuthorizedOrder,
) -> bool {
    use harvest_common::payment::{verify_payment_proof, ProofError};
    let bridges = &complaint.order.order.trusted_bridges;
    if bridges.is_empty()
        || !crate::components::bitcoin_view::unrecognised_bridges(&complaint.order.order).is_empty()
    {
        return false;
    }
    let (Some(OrderPaymentProof::OnChain(theirs)), Some(OrderPaymentProof::OnChain(ours))) = (
        reversal.payment_proof.as_ref(),
        complaint.order.payment_proof.as_ref(),
    ) else {
        return false;
    };
    let mut seen = std::collections::BTreeSet::new();
    let claims: Vec<freenet_bitcoin_common::SignedClaim> = theirs
        .claims
        .iter()
        .chain(ours.claims.iter())
        .filter(|claim| seen.insert(claim.digest()))
        .cloned()
        .collect();
    let height = |tip: &freenet_bitcoin_common::SignedTipEntry| {
        tip.body().map(|body| body.anchor.height).unwrap_or(0)
    };
    let tip = if height(&theirs.tip) >= height(&ours.tip) {
        theirs.tip.clone()
    } else {
        ours.tip.clone()
    };
    let union = OrderPaymentProof::on_chain(claims, tip);
    verify_payment_proof(&complaint.order.order, &union) == Err(ProofError::Reversed)
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
    /// A seller can record a despatch (harvest#53 Phase B), so a despatch
    /// window that closes with none recorded is now a fact about the SELLER,
    /// and is said and styled as one. The buyer's complaint (Phase C) is
    /// offered by the buyer's own card, not here: this card is shared with
    /// the seller.
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
                "This invoice was cancelled, but a payment that settles it has been seen \
                 at its address. A cancellation does not undo a payment: once it is recorded the \
                 order is paid, and the seller owes the goods."
                    .to_string(),
            ),
            OrderStage::Cancelled {
                payment_maybe: true,
                ..
            } => Some(
                "This invoice was cancelled. A payment at its address may be for this \
                 invoice or for another one sharing the address; the seller has to confirm which. \
                 If it is this invoice's, the order is paid and the seller owes the goods."
                    .to_string(),
            ),
            OrderStage::Cancelled {
                settle_until: Some(until),
                payment_seen: false,
                payment_maybe: false,
            } => Some(format!(
                "This invoice was cancelled. A payment made in time still counts until \
                 block {until}{}, and the seller would then owe the goods.",
                left(until),
            )),
            OrderStage::Cancelled {
                settle_until: None, ..
            } => Some(
                "This invoice was cancelled, and no payment was recorded for it in time."
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
            OrderStage::Despatched {
                despatched_at,
                complaint_until,
            } => Some(format!(
                "Paid, and the seller says it was despatched (anchored at block \
                 {despatched_at}). This order counts as complete from block \
                 {complaint_until}{}.",
                left(complaint_until)
            )),
            OrderStage::DespatchWindowClosed {
                despatch_by,
                complaint_until,
            } => Some(format!(
                "Paid, but the seller has not recorded a despatch, and the despatch window \
                 closed at block {despatch_by}. This order counts as complete from block \
                 {complaint_until}{}.",
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
    /// Including a despatch window that closed with no despatch recorded: a
    /// seller can record one since harvest#53 Phase B, so its absence is
    /// something the seller should act on and the buyer should know.
    pub fn needs_attention(self) -> bool {
        matches!(
            self,
            OrderStage::Reversed
                | OrderStage::DespatchWindowClosed { .. }
                | OrderStage::Cancelled {
                    payment_seen: true,
                    ..
                }
                | OrderStage::Cancelled {
                    payment_maybe: true,
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
    order.status == OrderStatus::AwaitingPayment && accepts_new_payment(&order.order, tip_height)
}

/// Whether a payment sent NOW could still confirm inside `order`'s payment
/// window: the tip is strictly below the window's last block, since a
/// transaction confirms in the next block at the earliest (review round 3).
/// With no tip, or no window, the answer is yes -- see
/// [`offers_payment_address`] for why "unknown" does not withhold.
pub fn accepts_new_payment(
    order: &harvest_common::payment::Order,
    tip_height: Option<u32>,
) -> bool {
    match (order.payment_window(), tip_height) {
        (Some(window), Some(tip)) => tip < *window.end(),
        _ => true,
    }
}

/// What an unpaid invoice's card says once its window has closed to new
/// payments but a payment made in time could still be recorded -- the
/// stretch where the address is withdrawn and the order has not lapsed. The
/// card would otherwise hide the address with no reason given (review
/// round 3).
pub fn closed_window_note(
    order: &AuthorizedOrder,
    tip_height: Option<u32>,
    sight: PaymentSight,
) -> Option<String> {
    if order.status != OrderStatus::AwaitingPayment || accepts_new_payment(&order.order, tip_height)
    {
        return None;
    }
    let last = last_settling_block(order)?;
    // A payment made in time is in sight; publishing it has no deadline, so
    // naming a block here would soon name one already passed (review round
    // 4). The pill and the notes beside it say what was seen.
    if sight.covered {
        return Some(
            "This invoice's payment window has closed, so a new payment would not count. A \
             payment made in time is in sight and still counts."
                .to_string(),
        );
    }
    if sight.ambiguous {
        // Not "still counts": it may be another invoice's (review round 5).
        return Some(
            "This invoice's payment window has closed, so a new payment would not count. A \
             payment made in time is in sight, but it may be for another invoice on this \
             address."
                .to_string(),
        );
    }
    // Past `last` with nothing in sight the stage is Lapsed and says so.
    tip_height.is_some_and(|tip| tip <= last).then(|| {
        format!(
            "This invoice's payment window has closed, so a new payment would not count. A \
             payment made in time can still be recorded until block {last}."
        )
    })
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
        ambiguous: false,
    };

    /// A covering payment that may be a twin's.
    const AMBIGUOUS: PaymentSight = PaymentSight {
        covered: false,
        in_flight: false,
        ambiguous: true,
    };

    fn bridge() -> SigningKey {
        SigningKey::from_bytes(&[61u8; 32])
    }

    /// The fixture's bridge, recognised on this thread while the guard lives.
    fn recognise_fixture_bridge() -> crate::components::bitcoin_view::RecognisedForTest {
        crate::components::bitcoin_view::recognise_for_test(freenet_bitcoin_common::BridgeId(
            bridge().verifying_key().to_bytes(),
        ))
    }

    /// **A reversal counts only when every bridge the order names is
    /// recognised** (review round 6 of #143). A seller names its own bridge in
    /// a sockpuppet order, pays it, complains about it at its paid height, and
    /// has its bridge retract the payment: with the bridge unrecognised the
    /// reversal discounts nothing, so the complaint counts against the seller,
    /// and a full record of them cannot push out honest complaints for free.
    /// The same evidence under a recognised bridge still discounts it. Red if
    /// `reversal_stands` stops checking the bridges.
    #[test]
    fn a_reversal_by_a_bridge_nobody_recognises_discounts_nothing() {
        let paid_at = ANCHOR + 3;
        let paid = paid_with(|o| vec![confirmed(o, 10_000, paid_at, 1)]);
        let complaint = complaint_at(&paid, paid_at);
        let mut reversed = paid.clone();
        reversed.status = OrderStatus::PaymentReversed;
        reversed.payment_proof = Some(OrderPaymentProof::on_chain(
            vec![
                confirmed(&paid, 10_000, paid_at, 1),
                retracted(&paid, 10_000, 1, paid_at + 15),
            ],
            tip(),
        ));
        assert!(
            !crate::components::bitcoin_view::unrecognised_bridges(&paid.order).is_empty(),
            "precondition: the fixture's bridge is not the build's"
        );
        assert_eq!(
            complaint_standing(&complaint, Some(&reversed), None),
            ComplaintStanding::Counts
        );
        let _recognised = recognise_fixture_bridge();
        assert_eq!(
            complaint_standing(&complaint, Some(&reversed), None),
            ComplaintStanding::PaymentReversed,
            "the same reversal from a recognised bridge still discounts it"
        );
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
            buyer_receipt_key: None,
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
            order_stage(&paid, None, Some(paid_at + 6), PaymentSight::default()),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by
            }
        );
        // The deadline block itself is still inside the window.
        assert_eq!(
            order_stage(&paid, None, Some(despatch_by), PaymentSight::default()),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by
            }
        );
        assert_eq!(
            order_stage(&paid, None, Some(despatch_by + 1), PaymentSight::default()),
            OrderStage::DespatchWindowClosed {
                despatch_by,
                complaint_until
            }
        );
        assert_eq!(
            order_stage(&paid, None, Some(complaint_until), PaymentSight::default()),
            OrderStage::DespatchWindowClosed {
                despatch_by,
                complaint_until
            }
        );
        assert_eq!(
            order_stage(
                &paid,
                None,
                Some(complaint_until + 1),
                PaymentSight::default()
            ),
            OrderStage::Closed {
                closed_at: complaint_until
            }
        );
    }

    /// A despatch of `order` anchored at `height`. Unsigned: the stage reads
    /// only the record the store contract already accepted.
    fn despatch_at(order: &AuthorizedOrder, height: u32) -> AuthorizedDespatch {
        AuthorizedDespatch {
            despatch: harvest_common::fulfilment::Despatch {
                order_id: order.order.id.clone(),
                anchor: anchor(height),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
        }
    }

    /// harvest#53 Phase B: a recorded despatch reads as despatched until the
    /// complaint window closes, then closed; and it never SHORTENS the
    /// buyer's window, however early its anchor says it was.
    #[test]
    fn a_despatch_is_read_on_a_paid_order_and_never_shortens_the_window() {
        let paid_at = ANCHOR + 3;
        let paid = paid_with(|o| vec![confirmed(o, 10_000, paid_at, 1)]);
        let despatch_by = paid_at + DESPATCH_WINDOW_BLOCKS;
        let complaint_until = despatch_by + COMPLAINT_WINDOW_BLOCKS;

        // On time, or backdated to before the payment: the window still runs
        // from the despatch deadline.
        for anchored in [paid_at + 10, paid_at - 50, 0] {
            let d = despatch_at(&paid, anchored);
            assert_eq!(
                order_stage(&paid, Some(&d), Some(paid_at + 20), PaymentSight::default()),
                OrderStage::Despatched {
                    despatched_at: anchored,
                    complaint_until
                },
                "anchored at {anchored}"
            );
            assert_eq!(
                order_stage(
                    &paid,
                    Some(&d),
                    Some(complaint_until),
                    PaymentSight::default()
                ),
                OrderStage::Despatched {
                    despatched_at: anchored,
                    complaint_until
                }
            );
            assert_eq!(
                order_stage(
                    &paid,
                    Some(&d),
                    Some(complaint_until + 1),
                    PaymentSight::default()
                ),
                OrderStage::Closed {
                    closed_at: complaint_until
                }
            );
        }

        // Late: recorded after the deadline, so the buyer's window runs from
        // the despatch instead, and a late despatch reads as despatched.
        let late_at = despatch_by + 500;
        let late = despatch_at(&paid, late_at);
        assert_eq!(
            order_stage(
                &paid,
                Some(&late),
                Some(late_at + 1),
                PaymentSight::default()
            ),
            OrderStage::Despatched {
                despatched_at: late_at,
                complaint_until: late_at + COMPLAINT_WINDOW_BLOCKS
            }
        );
    }

    /// The contract accepts a despatch on any order it holds (a status check
    /// there would break convergence), so the READER ignores one on an order
    /// that is not paid, and one naming a different order.
    #[test]
    fn a_despatch_on_an_unpaid_order_or_another_order_is_ignored() {
        let open = order(OrderStatus::AwaitingPayment, 10_000);
        let d = despatch_at(&open, ANCHOR + 2);
        let settle_until = ANCHOR + PAYMENT_WINDOW_BLOCKS;
        assert_eq!(
            order_stage(&open, Some(&d), Some(ANCHOR + 5), PaymentSight::default()),
            OrderStage::AwaitingPayment { settle_until }
        );
        let mut cancelled = open.clone();
        cancelled.status = OrderStatus::Cancelled;
        assert!(matches!(
            order_stage(
                &cancelled,
                Some(&d),
                Some(ANCHOR + 5),
                PaymentSight::default()
            ),
            OrderStage::Cancelled { .. }
        ));

        let paid_at = ANCHOR + 3;
        let paid = paid_with(|o| vec![confirmed(o, 10_000, paid_at, 1)]);
        let mut other = despatch_at(&paid, paid_at + 10);
        other.despatch.order_id = harvest_common::payment::OrderId([0xee; 32]);
        assert_eq!(
            order_stage(
                &paid,
                Some(&other),
                Some(paid_at + 20),
                PaymentSight::default()
            ),
            OrderStage::AwaitingDespatch {
                paid_at,
                despatch_by: paid_at + DESPATCH_WINDOW_BLOCKS
            }
        );
    }

    #[test]
    fn an_unpaid_order_lapses_when_its_payment_window_closes() {
        let open = order(OrderStatus::AwaitingPayment, 10_000);
        let settle_until = ANCHOR + PAYMENT_WINDOW_BLOCKS;
        assert_eq!(
            order_stage(&open, None, Some(settle_until), PaymentSight::default()),
            OrderStage::AwaitingPayment { settle_until }
        );
        assert_eq!(
            order_stage(&open, None, Some(settle_until + 1), PaymentSight::default()),
            OrderStage::Lapsed {
                closed_at: settle_until
            }
        );
    }

    #[test]
    fn no_window_is_judged_without_a_tip_or_a_paid_height() {
        let open = order(OrderStatus::AwaitingPayment, 10_000);
        assert_eq!(
            order_stage(&open, None, None, PaymentSight::default()),
            OrderStage::Unknown
        );

        let paid = paid_with(|o| vec![confirmed(o, 10_000, ANCHOR + 3, 1)]);
        assert_eq!(
            order_stage(&paid, None, None, PaymentSight::default()),
            OrderStage::Unknown
        );

        // Paid, but the evidence does not show it covered: unknown, NOT an
        // open despatch window measured from some default.
        let short = paid_with(|o| vec![confirmed(o, 9_999, ANCHOR + 3, 1)]);
        assert_eq!(
            order_stage(&short, None, Some(ANCHOR + 10), PaymentSight::default()),
            OrderStage::Unknown
        );

        let mut unanchored = order(OrderStatus::AwaitingPayment, 10_000);
        unanchored.order.anchor = None;
        assert_eq!(
            order_stage(&unanchored, None, Some(ANCHOR), PaymentSight::default()),
            OrderStage::Unknown
        );
    }

    #[test]
    fn only_an_open_invoice_offers_its_address_and_only_inside_its_window() {
        let window_end = ANCHOR + PAYMENT_WINDOW_BLOCKS;
        let mut open = order(OrderStatus::AwaitingPayment, 10_000);
        assert!(offers_payment_address(&open, Some(window_end - 1)));
        // At the window's last block a payment sent now confirms in the next
        // block at the earliest, outside the window (review round 3).
        assert!(!offers_payment_address(&open, Some(window_end)));
        // No tip yet: an open invoice still shows its address.
        assert!(offers_payment_address(&open, None));
        assert!(closed_window_note(&open, Some(window_end - 1), PaymentSight::default()).is_none());
        let note =
            closed_window_note(&open, Some(window_end), PaymentSight::default()).expect("said why");
        assert!(note.contains(&format!("block {window_end}")), "{note}");
        // Review round 2: past the window the STAGE can still read as
        // awaiting payment (a payment made in time gathering confirmations),
        // and the address must not come back with it.
        open.order.required_confirmations = 6;
        assert_eq!(
            order_stage(&open, None, Some(window_end + 3), COVERED),
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
            order_stage(&paid, None, Some(paid_at), PaymentSight::default()),
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
            order_stage(&open, None, Some(last), PaymentSight::default()),
            OrderStage::AwaitingPayment { settle_until: last }
        );
        assert_eq!(
            order_stage(&open, None, Some(last + 1), PaymentSight::default()),
            OrderStage::Lapsed { closed_at: last }
        );
        // A covering payment this reader can see is never called lapsed.
        assert_eq!(
            order_stage(&open, None, Some(last + 1), COVERED),
            OrderStage::AwaitingPayment { settle_until: last }
        );
        // But a partial payment, dust, or something still in flight after
        // the window is not a payment that settles it (review round 2).
        assert_eq!(
            order_stage(&open, None, Some(last + 1), PaymentSight::default()),
            OrderStage::Lapsed { closed_at: last }
        );
    }

    #[test]
    fn a_cancelled_order_can_still_be_paid_until_its_window_closes() {
        let cancelled = order(OrderStatus::Cancelled, 10_000);
        let last = ANCHOR + PAYMENT_WINDOW_BLOCKS;
        assert_eq!(
            order_stage(&cancelled, None, Some(last), COVERED),
            OrderStage::Cancelled {
                settle_until: Some(last),
                payment_seen: true,
                payment_maybe: false
            }
        );
        assert_eq!(
            order_stage(&cancelled, None, Some(last + 1), PaymentSight::default()),
            OrderStage::Cancelled {
                settle_until: None,
                payment_seen: false,
                payment_maybe: false
            }
        );
        // No tip: it still might.
        assert_eq!(
            order_stage(&cancelled, None, None, PaymentSight::default()),
            OrderStage::Cancelled {
                settle_until: Some(last),
                payment_seen: false,
                payment_maybe: false
            }
        );
        // Review round 2: a covering payment past the cutoff is still seen,
        // and still reads as a warning, because publishing it has no
        // deadline and it will turn the order Paid.
        let stage = order_stage(&cancelled, None, Some(last + 1), COVERED);
        assert_eq!(
            stage,
            OrderStage::Cancelled {
                settle_until: None,
                payment_seen: true,
                payment_maybe: false
            }
        );
        assert!(stage.needs_attention());
        assert!(stage
            .describe(Some(last + 1), OrderStatus::Cancelled)
            .expect("said")
            .contains("owes the goods"));
    }

    /// Review round 4: a covering payment that may be a twin's keeps the
    /// order from reading lapsed (the seller may yet confirm it) without
    /// counting as settling it, and a cancelled one says the seller has to
    /// decide rather than that the goods are owed.
    #[test]
    fn a_payment_that_may_be_a_twins_holds_the_order_open_without_settling_it() {
        let open = order(OrderStatus::AwaitingPayment, 10_000);
        let last = ANCHOR + PAYMENT_WINDOW_BLOCKS;
        assert_eq!(
            order_stage(&open, None, Some(last + 500), AMBIGUOUS),
            OrderStage::AwaitingPayment { settle_until: last }
        );
        assert!(!AMBIGUOUS.settles());
        let cancelled = order(OrderStatus::Cancelled, 10_000);
        let stage = order_stage(&cancelled, None, Some(last + 500), AMBIGUOUS);
        assert!(stage.needs_attention());
        let said = stage
            .describe(Some(last + 500), OrderStatus::Cancelled)
            .expect("said");
        assert!(said.contains("confirm which"), "{said}");
        assert!(!said.contains("no payment was recorded"), "{said}");
        // Past the cutoff, the closed-window note never names a block that
        // has already gone by.
        let note = closed_window_note(&open, Some(last + 500), AMBIGUOUS).expect("said");
        assert!(!note.contains("block"), "{note}");
        assert!(!note.contains("still counts"), "{note}");
        assert!(note.contains("may be for another invoice"), "{note}");
        let covered = closed_window_note(&open, Some(last + 500), COVERED).expect("said");
        assert!(covered.contains("still counts"), "{covered}");
        assert!(!covered.contains("block"), "{covered}");
        assert!(closed_window_note(&open, Some(last + 1), PaymentSight::default()).is_none());
    }

    #[test]
    fn a_payment_can_still_settle_an_unpaid_or_cancelled_order_only() {
        assert!(payment_could_still_settle(OrderStatus::AwaitingPayment));
        assert!(payment_could_still_settle(OrderStatus::Cancelled));
        assert!(!payment_could_still_settle(OrderStatus::Paid));
        assert!(!payment_could_still_settle(OrderStatus::PaymentReversed));
    }

    /// The card's sentences: each names the block it is about, and none
    /// offers a complaint this build cannot take (Phase C adds it).
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
                payment_maybe: false,
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
                payment_maybe: false,
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
            payment_maybe: false,
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
        assert!(closed_window.contains("block 900"), "{closed_window}");
        assert!(
            closed_window.contains("not recorded a despatch"),
            "a closed window with no despatch says so, now a seller can record one: \
             {closed_window}"
        );
        let despatched = say(
            OrderStage::Despatched {
                despatched_at: 995,
                complaint_until: 3_014,
            },
            OrderStatus::Paid,
        )
        .expect("despatched");
        assert!(despatched.contains("despatched"), "{despatched}");
        assert!(despatched.contains("block 995"), "{despatched}");
        assert!(despatched.contains("block 3014"), "{despatched}");
        // "The seller says": a despatch is the seller's own statement, and
        // the card must not present it as proof the goods arrived.
        assert!(despatched.contains("seller says"), "{despatched}");
        for stage_text in [&despatch, &closed_window, &despatched] {
            for promise in ["complain", "delivered", "received"] {
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
    fn only_a_reversal_a_missed_despatch_or_a_payment_on_a_cancelled_invoice_is_a_warning() {
        assert!(OrderStage::Reversed.needs_attention());
        assert!(OrderStage::DespatchWindowClosed {
            despatch_by: 1,
            complaint_until: 2,
        }
        .needs_attention());
        for settle_until in [Some(1), None] {
            assert!(OrderStage::Cancelled {
                settle_until,
                payment_seen: true,
                payment_maybe: false
            }
            .needs_attention());
        }
        for calm in [
            OrderStage::AwaitingPayment { settle_until: 1 },
            OrderStage::Lapsed { closed_at: 1 },
            OrderStage::Cancelled {
                settle_until: Some(1),
                payment_seen: false,
                payment_maybe: false,
            },
            OrderStage::AwaitingDespatch {
                paid_at: 1,
                despatch_by: 2,
            },
            OrderStage::Despatched {
                despatched_at: 1,
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

    /// A complaint about `order` made at `block`, in the shape the record
    /// holds. Its signatures are not what `complaint_standing` judges: the
    /// contract verified them before any reader sees it.
    fn complaint_at(order: &AuthorizedOrder, block: u32) -> harvest_common::reputation::Complaint {
        harvest_common::reputation::Complaint {
            order: order.clone(),
            category: harvest_common::feedback::FeedbackCategory::NonDelivery,
            block_height: block,
            paid_height: paid_height(order).expect("a paid order"),
            scoped_payload: Vec::new(),
            buyer_signature: Vec::new(),
        }
    }

    /// [`confirmed`], with the bridge's `as_of` of the caller's choosing, so
    /// a test can order a confirmation against a retraction.
    fn confirmed_as_of(
        order: &AuthorizedOrder,
        value_sats: u64,
        height: u32,
        seed: u8,
        as_of: u32,
    ) -> SignedClaim {
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
                as_of: anchor(as_of),
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

    /// The bridge's retraction, as of `as_of`, of the outpoint
    /// [`confirmed`] makes for `value_sats` and `seed`.
    fn retracted(order: &AuthorizedOrder, value_sats: u64, seed: u8, as_of: u32) -> SignedClaim {
        let (_, txid, _) = payment_proof(
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
                as_of: anchor(as_of),
                claim: Claim::Retracted {
                    outpoint: OutPoint { txid, vout: 0 },
                },
            },
        )
        .expect("sign the retraction")
    }

    /// harvest#53 Phase C: a complaint counts when it was made inside the
    /// window the order's own card shows, and not when it was honestly made
    /// after; a recorded despatch moves the window's end later, never
    /// earlier. Red if `complaint_standing` stops comparing the block to the
    /// window, or measures it from anything but `complaint_window_end`.
    #[test]
    fn a_complaint_counts_inside_the_window_and_not_after() {
        let paid_at = ANCHOR + 3;
        let paid = paid_with(|o| vec![confirmed(o, 10_000, paid_at, 1)]);
        let end = paid_at + DESPATCH_WINDOW_BLOCKS + COMPLAINT_WINDOW_BLOCKS;
        assert_eq!(complaint_window_end(&paid, None), Some(end));

        for block in [paid_at + 1, end] {
            assert_eq!(
                complaint_standing(&complaint_at(&paid, block), Some(&paid), None),
                ComplaintStanding::Counts,
                "made at {block}, inside the window"
            );
        }
        let late = complaint_standing(&complaint_at(&paid, end + 1), Some(&paid), None);
        assert_eq!(late, ComplaintStanding::Late { closed_at: end });
        assert!(!late.counts());

        // A despatch anchored late extends the window to its own anchor plus
        // the complaint window.
        let despatched = end + 500;
        let despatch = despatch_at(&paid, despatched);
        assert_eq!(
            complaint_standing(&complaint_at(&paid, end + 1), Some(&paid), Some(&despatch)),
            ComplaintStanding::Counts
        );
        // And the card agrees about where that window ends.
        assert_eq!(
            order_stage(
                &paid,
                Some(&despatch),
                Some(end + 1),
                PaymentSight::default()
            ),
            OrderStage::Despatched {
                despatched_at: despatched,
                complaint_until: despatched + COMPLAINT_WINDOW_BLOCKS,
            }
        );

        // Without the store's copy (pruned, or not loaded), the complaint's
        // own paid order places the window.
        assert_eq!(
            complaint_standing(&complaint_at(&paid, end + 1), None, None),
            ComplaintStanding::Late { closed_at: end }
        );
    }

    /// **A complaint against a payment the store later records as reversed
    /// is shown as such and not counted** (design section 8, resolved as a
    /// reader-side rule). Red if the reversal check is removed, or if
    /// `complaint_against_reversed_payment_counts` is flipped without meaning
    /// to.
    #[test]
    fn a_complaint_against_a_reversed_payment_does_not_count() {
        let _recognised = recognise_fixture_bridge();
        let paid_at = ANCHOR + 3;
        let paid = paid_with(|o| vec![confirmed(o, 10_000, paid_at, 1)]);
        let complaint = complaint_at(&paid, paid_at + 10);
        // A genuine reversal: the payment the complaint shows, retracted
        // later, and nothing since.
        let mut reversed = paid.clone();
        reversed.status = OrderStatus::PaymentReversed;
        reversed.payment_proof = Some(OrderPaymentProof::on_chain(
            vec![
                confirmed(&paid, 10_000, paid_at, 1),
                retracted(&paid, 10_000, 1, paid_at + 15),
            ],
            tip(),
        ));
        assert_eq!(
            harvest_common::payment::verify_payment_proof(
                &paid.order,
                reversed.payment_proof.as_ref().unwrap()
            ),
            Err(harvest_common::payment::ProofError::Reversed),
            "precondition: the reversal's own evidence shows it reversed"
        );

        let standing = complaint_standing(&complaint, Some(&reversed), None);
        assert_eq!(standing, ComplaintStanding::PaymentReversed);
        assert!(!complaint_against_reversed_payment_counts());
        assert!(!standing.counts());

        // A reversal of a DIFFERENT order does not touch this complaint.
        let mut other = order(OrderStatus::PaymentReversed, 20_000);
        other.order.amount_sats = 20_000;
        let other = AuthorizedOrder {
            order: other.order.with_derived_id(),
            ..other
        };
        assert_ne!(other.order.id, paid.order.id);
        assert_eq!(
            complaint_standing(&complaint, Some(&other), None),
            ComplaintStanding::Counts
        );
    }

    /// **A reversal built by withholding a re-confirmation does not erase
    /// the complaint** (`docs/complaint-threat-model.md` section 6). The
    /// buyer's payment was reorged out and confirmed again; the seller
    /// publishes `PaymentReversed` from the genuine confirmation and
    /// retraction, leaving out the later re-confirmation the complaint
    /// carries. On the union of both, the payment stands. Red if
    /// `complaint_standing` goes back to trusting the store's status alone.
    #[test]
    fn a_reversal_withholding_a_reconfirmation_does_not_erase_the_complaint() {
        let _recognised = recognise_fixture_bridge();
        let paid_at = ANCHOR + 3;
        let order_paid =
            paid_with(|o| vec![confirmed_as_of(o, 10_000, paid_at + 1, 1, paid_at + 18)]);
        let complaint = complaint_at(&order_paid, paid_at + 20);

        let mut reversed = order_paid.clone();
        reversed.status = OrderStatus::PaymentReversed;
        reversed.payment_proof = Some(OrderPaymentProof::on_chain(
            vec![
                confirmed(&order_paid, 10_000, paid_at, 1),
                retracted(&order_paid, 10_000, 1, paid_at + 15),
            ],
            tip(),
        ));
        assert_eq!(
            harvest_common::payment::verify_payment_proof(
                &order_paid.order,
                reversed.payment_proof.as_ref().unwrap()
            ),
            Err(harvest_common::payment::ProofError::Reversed),
            "precondition: on its own, the reversal's evidence verifies as a reversal"
        );
        assert!(!reversal_stands(&complaint, &reversed));
        assert_eq!(
            complaint_standing(&complaint, Some(&reversed), None),
            ComplaintStanding::Counts
        );
    }

    /// **The window counts from the complaint's signed paid height** (model
    /// section 6): the contract checked it against the complaint's own
    /// proof, so it is what every reader measures from. Red if the standing
    /// re-reads the height from anything else.
    #[test]
    fn the_window_counts_from_the_complaints_own_paid_height() {
        let paid_at = ANCHOR + 3;
        let paid = paid_with(|o| vec![confirmed(o, 10_000, paid_at, 1)]);
        let end = paid_at + DESPATCH_WINDOW_BLOCKS + COMPLAINT_WINDOW_BLOCKS;
        let mut complaint = complaint_at(&paid, end + 1);
        assert_eq!(
            complaint_standing(&complaint, None, None),
            ComplaintStanding::Late { closed_at: end }
        );
        // The signed paid height, not a height re-read from anything else.
        complaint.paid_height = paid_at + 1;
        assert_eq!(
            complaint_standing(&complaint, None, None),
            ComplaintStanding::Counts
        );
    }
}
