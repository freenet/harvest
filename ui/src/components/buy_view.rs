//! Buying: the buyer's request, and what has to be true before they pay.
//!
//! Three surfaces, and they are here together because they are one exchange
//! seen from two sides -- the form a buyer fills in, the panel that says
//! whether their order is safe to pay, and the control a seller uses to
//! accept. Splitting them across the store and message views would put the
//! two halves of one protocol in two files that nothing keeps in step.
//!
//! # What this may and may not claim
//!
//! * **The request is encrypted to the seller.** True, and it is the most
//!   identifying thing a buyer ever sends: a shipping address. It travels
//!   inside the AEAD and is never part of what the seller publishes.
//! * **The seller publishing the order is what protects the buyer.** True,
//!   and it is checked rather than asserted -- see
//!   [`crate::state::AppState::payment_blockers`]. The buyer's software
//!   refuses to show a payment address until the commitment is published,
//!   signed by this store's seller, and anchored to a recent block their own
//!   node agrees with.
//! * **It does NOT say the seller is good for it.** Nothing here counts a
//!   bond, because there is no bond yet. A published commitment says the
//!   seller has admitted the debt in public; it does not say they can cover
//!   it. Phase 2 is what adds the second half, and this screen does not
//!   pretend to it.
//! * **The commitment is not private, and the accept control says so.** The
//!   design document describes a commitment carrying "the amount and a recent
//!   Bitcoin block hash" and nothing else. What is actually published is an
//!   `AuthorizedOrder`, which also carries the payment address, linking the
//!   order to a chain transaction. It names the listing only as a tag the
//!   two parties can read (harvest#57), so WHO bought is not published and
//!   WHAT is not published directly, though an amount that is a multiple
//!   of a uniquely priced listing can still give the listing away.
//!   Separating the countable commitment from the payable invoice is the
//!   ledger contract in issue 8. Until then the
//!   seller is told what they are publishing rather than reassured about it.
//!   Recorded in `docs/untested-invariants.md`.

use dioxus::prelude::*;
use harvest_common::listing::ListingId;

use crate::gateway::APP_STATE;
use crate::state::{BuyerPurchase, PaymentBlocker};

/// The form a buyer fills in to ask for a listing.
///
/// Quantity and destination and nothing else. There is no price arithmetic
/// here on purpose: a listing's price is free text in a currency of the
/// seller's choosing (`harvest_common::listing::PriceInfo`), so any number
/// this form computed would be a guess presented as a total. The seller names
/// the amount when they accept, and the buyer sees THAT amount, from the
/// published commitment, before paying.
#[component]
pub fn BuyForm(
    store_contract_id: Vec<u8>,
    listing_id: ListingId,
    listing_title: String,
    seller_encryption_key: [u8; 32],
    seller_verifying_key: [u8; 32],
) -> Element {
    let mut quantity = use_signal(|| "1".to_string());
    let mut shipping = use_signal(String::new);
    let mut note = use_signal(String::new);
    let mut problem = use_signal(|| Option::<String>::None);
    let mut asked = use_signal(|| false);

    let parsed_quantity = quantity().trim().parse::<u32>().ok().filter(|n| *n > 0);
    let ready = parsed_quantity.is_some() && !shipping().trim().is_empty();

    if asked() {
        return rsx! {
            p { class: "text-muted",
                "Your request for {listing_title} has been handed to your Freenet node. "
                "Harvest checks that it shows up in the seller's mailbox, and says so under "
                "\"Your conversation\" if it does not. "
                "The seller has to publish the order publicly before you can pay for it, and "
                "it will appear under \"Your purchases\" below when they do."
            }
        };
    }

    rsx! {
        div { style: "margin-top: 0.75rem;",
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "Your address is encrypted to this seller before it leaves your browser and is "
                "not part of anything they publish. Sending this commits you to nothing: the "
                "seller decides whether to accept, and you decide whether to pay."
            }
            div { class: "form-group",
                label { class: "form-label", "How many" }
                input {
                    class: "form-input",
                    r#type: "number",
                    min: "1",
                    value: "{quantity}",
                    oninput: move |event| quantity.set(event.value()),
                }
            }
            div { class: "form-group",
                label { class: "form-label", "Where to send it" }
                textarea {
                    class: "form-textarea",
                    value: "{shipping}",
                    placeholder: "Name and postal address, or whatever this seller needs.",
                    oninput: move |event| shipping.set(event.value()),
                }
            }
            div { class: "form-group",
                label { class: "form-label", "Anything else (optional)" }
                textarea {
                    class: "form-textarea",
                    value: "{note}",
                    placeholder: "Size, colour, delivery date...",
                    oninput: move |event| note.set(event.value()),
                }
            }
            if let Some(message) = problem() {
                p { class: "text-warning", "{message}" }
            }
            button {
                class: "btn btn-primary",
                disabled: !ready,
                onclick: move |_| {
                    let Some(quantity_wanted) = parsed_quantity else {
                        return;
                    };
                    match request(
                        &store_contract_id,
                        &seller_encryption_key,
                        &seller_verifying_key,
                        &listing_id,
                        quantity_wanted,
                        shipping().trim().to_string(),
                        note().trim().to_string(),
                    ) {
                        Ok(()) => {
                            problem.set(None);
                            asked.set(true);
                        }
                        Err(e) => problem.set(Some(e)),
                    }
                },
                "Send this request"
            }
        }
    }
}

/// Seal a buyer's request and hand it to the local node.
///
/// Errors are returned rather than notified, so the form can say what went
/// wrong beside the box the buyer just filled in.
fn request(
    store_contract_id: &[u8],
    seller_encryption_key: &[u8; 32],
    seller_verifying_key: &[u8; 32],
    listing_id: &ListingId,
    quantity: u32,
    shipping: String,
    note: String,
) -> Result<(), String> {
    let seller = ed25519_dalek::VerifyingKey::from_bytes(seller_verifying_key)
        .map_err(|e| format!("this store's identity key is unusable: {e}"))?;

    let sealed = APP_STATE.write().request_order(
        store_contract_id,
        seller_encryption_key,
        listing_id,
        quantity,
        shipping,
        note,
    )?;

    super::message_view::deliver_to_seller(
        store_contract_id,
        seller,
        format!("Asked to buy {quantity}."),
        sealed,
    )
}

/// What this buyer has been accepted for at one store, and whether each is
/// safe to pay.
#[component]
pub fn Purchases(store_contract_id: Vec<u8>) -> Element {
    let app_state = APP_STATE.read();
    let purchases = app_state.buyer_purchases(&store_contract_id);
    if purchases.is_empty() {
        return rsx! {};
    }
    let bitcoin = app_state.bitcoin.clone();
    drop(app_state);

    rsx! {
        div { style: "margin-top: 24px;",
            h4 { "Your purchases" }
            p { class: "text-muted",
                "A seller has to publish an order publicly before you can pay for it, and "
                "your software checks that yours is there rather than taking anyone's word. "
                "What that buys you today is that the seller cannot take your money without "
                "first admitting in public that they owe you goods. It does not yet tell you "
                "they can cover it: there is nothing staked behind these orders, and nothing "
                "here counts one."
            }
            for purchase in purchases.iter() {
                PurchaseCard {
                    key: "{purchase.order_id}",
                    store_contract_id: store_contract_id.clone(),
                    purchase: purchase.clone(),
                    bitcoin: bitcoin.clone(),
                }
            }
        }
    }
}

#[component]
fn PurchaseCard(
    store_contract_id: Vec<u8>,
    purchase: BuyerPurchase,
    bitcoin: crate::state::BitcoinState,
) -> Element {
    let short = purchase.order_id.short();
    let cancellable = purchase.cancellable();
    rsx! {
        div { class: "card", style: "margin-top: 0.5rem;",
            p { class: "text-muted", style: "font-size: 0.8rem;",
                "Order {short}, from conversation {crate::state::short_conversation_tag(&purchase.conversation)}"
            }
            if cancellable {
                CancelPurchase {
                    store_contract_id: store_contract_id.clone(),
                    purchase: purchase.clone(),
                }
            }
            // A paid order of this buyer's is shown as paid, and offered the
            // complaint, whatever the payment checks now say: those are about
            // whether to PAY, and the seller can trip them after payment by
            // closing the store or retiring its backing (review round 1 of
            // #143, P1-1).
            if let Some(paid) = purchase.paid.as_ref() {
                SettledPurchase { order: paid.clone(), bitcoin: bitcoin.clone() }
                FileComplaint {
                    store_contract_id: store_contract_id.clone(),
                    purchase: purchase.clone(),
                }
            } else if let Some(settled) = purchase.settled() {
                SettledPurchase { order: settled.clone(), bitcoin: bitcoin.clone() }
            } else {
            match (purchase.blockers.is_empty(), purchase.commitment.as_ref()) {
                // Everything checks out, so the payment details are shown --
                // through the same `OrderCard` the seller's own panel uses,
                // which carries the per-invoice bridge check with it.
                (true, Some(commitment)) => rsx! {
                    p { class: "text-muted",
                        "This order is published, signed by this store's seller, and anchored "
                        "to a recent block your node agrees with."
                    }
                    super::bitcoin_view::OrderCard {
                        order: commitment.clone(),
                        live: super::bitcoin_view::live_address_for_order(&bitcoin, &commitment.order),
                    }
                },
                // Deliberately no payment address while anything is
                // outstanding. A greyed-out button next to a visible address
                // is an invitation to pay it by hand.
                _ => rsx! {
                    for blocker in purchase.blockers.iter() {
                        p { class: "text-warning", "{blocker.describe()}" }
                    }
                    p { class: "text-muted", style: "font-size: 0.85rem;",
                        // The worst remedy among the blockers, because the
                        // buyer has to do the hardest of them: one thing that
                        // waiting will not fix means waiting is not the
                        // answer.
                        match purchase.blockers.iter().map(remedy).max_by_key(|r| match r {
                            Remedy::Wait => 0,
                            Remedy::AskTheSeller => 1,
                            // Above asking the seller: a new request gets a
                            // new order, which puts right whatever else the
                            // seller got wrong in this one.
                            Remedy::AskAgain => 2,
                            Remedy::WalkAway => 3,
                        }) {
                            Some(Remedy::WalkAway) => "No payment details are shown while that is true, and this is not something either of you can put right.",
                            Some(Remedy::AskTheSeller) => "No payment details are shown while that is true. The seller can fix it by issuing the order again.",
                            Some(Remedy::AskAgain) => "No payment details are shown while that is true. Send your request to buy again from this device: a request from this version of Harvest carries your key, and the seller can answer it with an order you can pay.",
                            _ => "No payment details are shown while that is true. Look again in a moment.",
                        }
                    }
                },
            }
            }
        }
    }
}

/// The buyer's control to cancel one of their own unpaid purchases
/// (harvest#53 Phase B). Two steps, because the record is public and
/// permanent, and the confirmation says what a buyer might not expect: a
/// payment already sent still counts.
#[component]
fn CancelPurchase(store_contract_id: Vec<u8>, purchase: BuyerPurchase) -> Element {
    let order_id = purchase.order_id.clone();
    let mut confirming = use_signal(|| false);
    let mut problem = use_signal(|| Option::<String>::None);
    let (sent, refusal) = {
        let state = APP_STATE.read();
        (
            state.buyer_cancellation_sent(&store_contract_id, &order_id),
            state.buyer_cancel_refusal(&store_contract_id, &purchase),
        )
    };
    let short = order_id.short();
    if sent {
        return rsx! {
            p { class: "text-muted",
                "Cancellation of order {short} sent. It shows here once the store has it."
            }
        };
    }
    // Said instead of a button that would refuse when pressed -- most often
    // a payment already on its way, which settles the order anyway.
    if let Some(why) = refusal {
        return rsx! {
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "Order {short} cannot be cancelled right now: {why}"
            }
        };
    }
    rsx! {
        if let Some(why) = problem() {
            p { class: "text-warning", "{why}" }
        }
        if confirming() {
            p { class: "text-warning",
                "Cancel order {short}? This is public and cannot be undone. If you have already "
                "paid, your payment still counts and the seller owes you the goods."
            }
            button {
                class: "btn btn-sm btn-primary",
                onclick: {
                    let store_contract_id = store_contract_id.clone();
                    let order_id = order_id.clone();
                    move |_| {
                        confirming.set(false);
                        let result = APP_STATE
                            .write()
                            .buyer_cancel_order(&store_contract_id, &order_id);
                        problem.set(result.err());
                    }
                },
                "Yes, cancel it"
            }
            button {
                class: "btn btn-sm btn-outline",
                onclick: move |_| confirming.set(false),
                "Keep it"
            }
        } else {
            button {
                class: "btn btn-sm btn-outline",
                onclick: move |_| {
                    problem.set(None);
                    confirming.set(true);
                },
                "Cancel order"
            }
        }
    }
}

/// The buyer's control to complain about one of their PAID purchases
/// (harvest#53 Phase C).
///
/// A category, never free text: the complaint lands on a public, permanent
/// record nobody can moderate. Two steps, because it cannot be withdrawn.
/// Shown only when a complaint could be made; otherwise the reason, or the
/// complaint already on record.
#[component]
fn FileComplaint(store_contract_id: Vec<u8>, purchase: BuyerPurchase) -> Element {
    use harvest_common::feedback::FeedbackCategory;
    let order_id = purchase.order_id.clone();
    let mut chosen = use_signal(|| Option::<FeedbackCategory>::None);
    let mut problem = use_signal(|| Option::<String>::None);
    let (on_record, sent, refusal) = {
        let state = APP_STATE.read();
        (
            state.complaint_on_record(&store_contract_id, &order_id),
            state.complaint_sent(&store_contract_id, &order_id),
            state.complaint_refusal(&store_contract_id, &purchase),
        )
    };
    let short = order_id.short();
    if let Some(complaint) = on_record {
        return rsx! {
            p { class: "text-muted",
                "Your complaint about order {short} ({super::reputation_view::category_label(&complaint.category)}) \
                 is on the seller's public record."
            }
        };
    }
    if sent {
        return rsx! {
            p { class: "text-muted",
                "Complaint about order {short} sent. It shows on the seller's record once the \
                 network has it."
            }
        };
    }
    if let Some(why) = refusal {
        return rsx! {
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "No complaint can be made about order {short} right now: {why}."
            }
        };
    }
    rsx! {
        if let Some(why) = problem() {
            p { class: "text-warning", "{why}" }
        }
        match chosen() {
            Some(category) => rsx! {
                p { class: "text-warning",
                    "Complain that order {short} was \"{super::reputation_view::category_label(&category)}\"? \
                     This goes on the seller's public record permanently, cannot be withdrawn, \
                     and is one per order."
                }
                button {
                    class: "btn btn-sm btn-primary",
                    onclick: {
                        let store_contract_id = store_contract_id.clone();
                        let order_id = order_id.clone();
                        move |_| {
                            chosen.set(None);
                            let result = APP_STATE.write().file_complaint(
                                &store_contract_id,
                                &order_id,
                                category.clone(),
                            );
                            problem.set(result.err());
                        }
                    },
                    "Yes, complain"
                }
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| chosen.set(None),
                    "Go back"
                }
            },
            None => rsx! {
                p { class: "text-muted", style: "font-size: 0.85rem;",
                    "Something wrong with order {short}? You can put one complaint on the \
                     seller's public record:"
                }
                for category in FeedbackCategory::ALL {
                    {
                        let label = super::reputation_view::category_label(&category);
                        rsx! {
                            button {
                                class: "btn btn-sm btn-outline",
                                onclick: move |_| {
                                    problem.set(None);
                                    chosen.set(Some(category.clone()));
                                },
                                "{label}"
                            }
                        }
                    }
                }
            },
        }
    }
}

/// A purchase that has moved past payment, as its buyer sees it: where it
/// stands against the reader-side windows (harvest#53), and no payment
/// address, since there is nothing left to pay.
#[component]
fn SettledPurchase(
    order: harvest_common::payment::AuthorizedOrder,
    bitcoin: crate::state::BitcoinState,
) -> Element {
    let tip_height = bitcoin
        .tips
        .get(&order.order.network)
        .and_then(|tip| tip.tip_height);
    let (sight, despatch) = {
        let state = APP_STATE.read();
        (state.payment_sight(&order), state.despatch_of(&order))
    };
    let stage = crate::fulfilment::order_stage(&order, despatch.as_ref(), tip_height, sight);
    // Every status that reaches here is past AwaitingPayment, and `describe`
    // has a sentence for each of those; the fallback is for safety only.
    let note = stage
        .describe(tip_height, order.status)
        .unwrap_or_else(|| "This order is no longer awaiting payment.".to_string());
    let amount = super::bitcoin_view::format_sats(order.order.amount_sats);
    rsx! {
        p { class: if stage.needs_attention() { "text-warning" } else { "" },
            "{amount} \u{00b7} {note}"
        }
    }
}

/// The seller's side: accept one buyer's request by issuing an invoice
/// against it.
///
/// The amount is typed here rather than derived from the listing, for the
/// same reason the buy form does no arithmetic: the listing's price is free
/// text in whatever currency the seller wrote, and only the seller can turn
/// it into satoshis.
#[component]
pub fn AcceptRequest(
    store_contract_id: Vec<u8>,
    tag: Vec<u8>,
    listing_id: ListingId,
    /// The listing's title as this seller's own store publishes it, or empty
    /// when the store's listings have not arrived. Empty is shown as a
    /// refusal rather than as a blank: a seller pricing an item the screen
    /// cannot name is signing for something they cannot see.
    listing_title: String,
    order_binding: [u8; 32],
    buyer_receipt_key: Option<[u8; 32]>,
    quantity: u32,
) -> Element {
    let mut amount = use_signal(String::new);
    let mut confirmations = use_signal(|| "1".to_string());
    let mut problem = use_signal(|| Option::<String>::None);
    let mut accepted = use_signal(|| false);

    let parsed_amount = amount().trim().parse::<u64>().ok().filter(|n| *n > 0);
    let parsed_confirmations = confirmations()
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|n| *n > 0);
    let ready = parsed_amount.is_some() && parsed_confirmations.is_some();

    if accepted() {
        return rsx! {
            p { class: "text-muted",
                "Accepted. The order is being published and the buyer is being told which "
                "one is theirs; they cannot pay until the published entry reaches them."
            }
        };
    }

    // No title means this store's listings have not arrived, so the screen
    // cannot say what is being priced. Withhold the control rather than
    // showing one whose only label is a quantity: signing an amount against a
    // listing id nobody has read is exactly the thing this says it is not.
    if listing_title.trim().is_empty() {
        return rsx! {
            p { class: "text-warning",
                "A buyer has asked to buy {quantity} of a listing this page cannot name yet. "
                "Wait for your store's listings to load before pricing it."
            }
        };
    }

    rsx! {
        div { style: "margin-top: 0.75rem;",
            h5 { style: "margin-bottom: 0.25rem;", "{quantity} x {listing_title}" }
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "Accepting publishes this order on your store, where anyone can see it. It "
                "carries the amount, the payment address, a recent block, the confirmations you "
                "require and the bridges you trust. It does NOT say which listing it is for "
                "(though an amount matching a unique price can give that away), who asked, or "
                "where they want it sent -- those stay in this conversation."
            }
            div { class: "form-group",
                label { class: "form-label",
                    "Amount for {quantity} x {listing_title} (satoshis)"
                }
                input {
                    class: "form-input",
                    r#type: "number",
                    min: "1",
                    value: "{amount}",
                    oninput: move |event| amount.set(event.value()),
                }
            }
            div { class: "form-group",
                label { class: "form-label", "Confirmations required" }
                input {
                    class: "form-input",
                    r#type: "number",
                    min: "1",
                    value: "{confirmations}",
                    oninput: move |event| confirmations.set(event.value()),
                }
            }
            if let Some(message) = problem() {
                p { class: "text-warning", "{message}" }
            }
            button {
                class: "btn btn-primary",
                disabled: !ready,
                onclick: move |_| {
                    let (Some(amount_sats), Some(required_confirmations)) =
                        (parsed_amount, parsed_confirmations)
                    else {
                        return;
                    };
                    match accept(
                        &store_contract_id,
                        &tag,
                        &listing_id,
                        listing_title.clone(),
                        BuyerValues {
                            order_binding,
                            buyer_receipt_key,
                        },
                        amount_sats,
                        required_confirmations,
                    ) {
                        Ok(()) => {
                            problem.set(None);
                            accepted.set(true);
                        }
                        Err(e) => problem.set(Some(e)),
                    }
                },
                "Accept and publish this order"
            }
        }
    }
}

/// Issue an invoice that answers one request.
///
/// The tag travels on the invoice as `PendingInvoice::reply_to`, so the
/// acceptance is sent from the same place the commitment is published rather
/// than being a second thing the seller has to remember.
fn accept(
    store_contract_id: &[u8],
    tag: &[u8],
    listing_id: &ListingId,
    listing_title: String,
    buyer: BuyerValues,
    amount_sats: u64,
    required_confirmations: u32,
) -> Result<(), String> {
    let reply_to: [u8; 32] = tag
        .try_into()
        .map_err(|_| format!("this conversation's tag is {} bytes, not 32", tag.len()))?;

    let mut state = APP_STATE.write();
    let seller_fingerprint = state
        .store_owner_fingerprint(store_contract_id)
        .ok_or("this store is not one of yours")?;
    state.issue_invoice(crate::state::PendingInvoice {
        store_contract_id: store_contract_id.to_vec(),
        seller_fingerprint,
        listing_id: listing_id.clone(),
        listing_title,
        // A buyer has no ghostkey, so there is no fingerprint to name. See
        // `PendingInvoice::buyer_fingerprint`: naming one restricts nothing
        // anyway, since Bitcoin cannot say who sent a payment.
        buyer_fingerprint: String::new(),
        amount_sats,
        required_confirmations,
        reply_to: Some(reply_to),
        // The buyer's own value, carried from their request. Without it the
        // commitment matches nobody's check and the buyer will not pay it.
        order_binding: Some(buyer.order_binding),
        // Likewise the buyer's receipt key (harvest#53 Phase B): without it
        // the buyer can neither cancel nor complain, and will not pay.
        buyer_receipt_key: buyer.buyer_receipt_key,
    })
}

/// The two values a buyer's request asks the seller to sign into the
/// commitment: they travel together from the request to the terms, so they
/// are one argument rather than two a positional call could swap.
struct BuyerValues {
    order_binding: [u8; 32],
    buyer_receipt_key: Option<[u8; 32]>,
}

/// What a buyer can actually DO about one blocker.
///
/// # Why three and not a bool
///
/// It was a bool -- wait, or walk away -- and review found the case that
/// breaks it: an order whose anchor has aged out is neither. Waiting does not
/// fix it, and there is nothing wrong with the seller; the remedy is to ask
/// for the order again. Told to walk away, a buyer abandons a purchase that
/// one message would have rescued, and does it while being told the seller
/// backdated something.
///
/// Several other blockers were being classified as walk-away for the same
/// wrong reason -- an unbridgeable invoice, an address that disagrees with
/// its script, a missing anchor -- all of which are a seller's mistake that a
/// seller can undo.
///
/// The match is exhaustive, with no wildcard, and that is the Phase 2 seam:
/// adding a blocker does not compile until somebody has said which of these
/// three a buyer should be told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// Nothing is wrong; this node is not ready yet. Look again shortly.
    Wait,
    /// The seller can put this right by issuing the order again.
    AskTheSeller,
    /// Only a new request can put this right: the order answers a request
    /// that did not carry what it lacks, and a seller reissuing it would copy
    /// the same gap from the same request. Sending the request again from
    /// this build carries it (round-3 review of harvest#136).
    AskAgain,
    /// Nothing either party can do makes this order safe to pay.
    WalkAway,
}

/// What can be done about one blocker.
pub fn remedy(blocker: &PaymentBlocker) -> Remedy {
    match blocker {
        // Not ready yet, on this side of the wire.
        PaymentBlocker::CommitmentNotPublished
        | PaymentBlocker::ChainUnknown
        | PaymentBlocker::AnchorUnverifiable
        | PaymentBlocker::AnchorAheadOfTip { .. }
        | PaymentBlocker::ConversationNotKept => Remedy::Wait,
        // The seller issued something that cannot be acted on, and issuing it
        // again fixes every one of these.
        PaymentBlocker::NoTrustedBridge
        | PaymentBlocker::BridgeNotRecognised(_)
        | PaymentBlocker::DestinationDisagrees
        | PaymentBlocker::DestinationUnreadable
        | PaymentBlocker::AnchorMissing
        | PaymentBlocker::AnchorStale { .. } => Remedy::AskTheSeller,
        // The order carries no key for this buyer because the REQUEST it
        // answers carried none (an earlier build), or carried another; the
        // seller copies the key from the request, so only a new request
        // fixes it. The seller's inbox offers a keyed request afresh even
        // beside an unkeyed order (`message_view::unanswered_requests`).
        PaymentBlocker::CommitmentLacksBuyerKey => Remedy::AskAgain,
        // The order is not this buyer's, not this seller's, or not payable at
        // all. None of these is a mistake anybody can undo.
        PaymentBlocker::SellerIdentityUnknown
        | PaymentBlocker::StoreClosed
        | PaymentBlocker::CommitmentNotTheSellers(_)
        | PaymentBlocker::CommitmentNotForThisBuyer
        | PaymentBlocker::CommitmentNotRequested
        | PaymentBlocker::NotAwaitingPayment(_)
        | PaymentBlocker::AnchorOffChain => Remedy::WalkAway,
    }
}
