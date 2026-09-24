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
use harvest_common::listing::{
    DeliveryPrice, FixedCheckout, Listing, ListingId, MAX_INSTANT_QUANTITY,
};

use crate::messaging::{Addressing, InstantSelection, MessageContent};

use crate::gateway::APP_STATE;
use crate::state::{BuyerPurchase, PaymentBlocker};

/// The form a buyer fills in to ask for a listing.
///
/// For a quote-only listing: quantity, destination and a note, and no price
/// arithmetic. A listing's price is free text in a currency of the seller's
/// choosing (`harvest_common::listing::PriceInfo`), so any number this form
/// computed would be a guess presented as a total. The seller names the
/// amount when they accept, and the buyer sees THAT amount, from the
/// published commitment, before paying.
///
/// For a listing with instant checkout ([`Listing::offers_instant_checkout`])
/// the total is not a guess: it comes from the listing's fixed terms through
/// [`Listing::instant_total`], the same function the seller's delegate uses
/// to check it. The buyer still pays only against the published commitment,
/// exactly as for a quote.
#[component]
pub fn BuyForm(
    store_contract_id: Vec<u8>,
    listing: Listing,
    seller_encryption_key: [u8; 32],
    seller_verifying_key: [u8; 32],
) -> Element {
    let mut quantity = use_signal(|| "1".to_string());
    let mut shipping = use_signal(String::new);
    let mut note = use_signal(String::new);
    let mut region = use_signal(String::new);
    let choice_count = listing.choices.len();
    let mut picks = use_signal(move || vec![String::new(); choice_count]);
    let mut problem = use_signal(|| Option::<String>::None);
    let mut quote_instead = use_signal(|| false);
    // When an instant request was sent, and how many seller answers the
    // thread already held then; `None` for a quote request or none yet.
    let mut sent = use_signal(|| Option::<Sent>::None);
    let mut asked = use_signal(|| false);
    // Bumped by the 30-second timer so the form re-renders when it fires.
    let now_ms = use_signal(unix_millis);

    let instant = listing.offers_instant_checkout() && !quote_instead();
    let listing_title = listing.title.clone();
    let by_region = match &listing.checkout {
        Some(FixedCheckout {
            delivery: DeliveryPrice::ByRegion(rows),
            ..
        }) => rows.iter().map(|row| row.region.clone()).collect(),
        _ => Vec::<String>::new(),
    };

    let parsed_quantity = quantity().trim().parse::<u32>().ok().filter(|n| *n > 0);
    let picked_all = picks().iter().all(|p| !p.is_empty());
    let total = if instant {
        parsed_quantity.and_then(|q| {
            let region = region();
            let region = (!region.is_empty()).then_some(region);
            listing.instant_total(q, region.as_deref(), &picks()).ok()
        })
    } else {
        None
    };
    let ready = parsed_quantity.is_some()
        && !shipping().trim().is_empty()
        && picked_all
        && (!instant || total.is_some());

    if asked() {
        if let Some(sent) = sent() {
            let answers = seller_answers(&APP_STATE.read().conversation_thread(&store_contract_id));
            let _ = now_ms();
            return match instant_wait(sent.at_ms, unix_millis(), answers > sent.answers_before) {
                InstantWait::Answered => rsx! {
                    p { class: "text-muted",
                        "The seller's store has answered. Their reply is under \"Your conversation\", "
                        "and an accepted order appears under \"Your purchases\" below."
                    }
                },
                InstantWait::Waiting => rsx! {
                    p { class: "text-muted",
                        "Your order for {listing_title} has been sent. Waiting for the seller's store "
                        "to answer; this usually takes a few seconds."
                    }
                },
                InstantWait::NotResponding => rsx! {
                    p { class: "text-muted",
                        "The seller's store isn't responding right now. Your request is saved and they'll see it when they're back."
                    }
                },
            };
        }
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
                if instant {
                    "Your address is encrypted to this seller before it leaves your browser and is "
                    "not part of anything they publish. Buying commits you to nothing until you pay: "
                    "the seller's store issues the order, and you decide whether to pay it."
                } else {
                    "Your address is encrypted to this seller before it leaves your browser and is "
                    "not part of anything they publish. Sending this commits you to nothing: the "
                    "seller decides whether to accept, and you decide whether to pay."
                }
            }
            if instant && !by_region.is_empty() {
                div { class: "form-group",
                    label { class: "form-label", "Deliver to" }
                    select {
                        class: "form-select",
                        value: "{region}",
                        onchange: move |event| region.set(event.value()),
                        option { value: "", "Choose a region" }
                        for name in by_region.iter() {
                            option { key: "{name}", value: "{name}", "{name}" }
                        }
                    }
                }
            }
            for (i, group) in listing.choices.iter().enumerate() {
                div { key: "{group.name}", class: "form-group",
                    label { class: "form-label", "{group.name}" }
                    select {
                        class: "form-select",
                        value: "{picks()[i]}",
                        onchange: move |event| picks.with_mut(|p| p[i] = event.value()),
                        option { value: "", "Choose one" }
                        for option_name in group.options.iter() {
                            option { key: "{option_name}", value: "{option_name}", "{option_name}" }
                        }
                    }
                }
            }
            div { class: "form-group",
                label { class: "form-label", "How many" }
                if instant {
                    select {
                        class: "form-select",
                        value: "{quantity}",
                        onchange: move |event| quantity.set(event.value()),
                        for n in 1..=MAX_INSTANT_QUANTITY {
                            option { key: "{n}", value: "{n}", "{n}" }
                        }
                    }
                } else {
                    input {
                        class: "form-input",
                        r#type: "number",
                        min: "1",
                        value: "{quantity}",
                        oninput: move |event| quantity.set(event.value()),
                    }
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
                    placeholder: "Delivery date, gift message...",
                    oninput: move |event| note.set(event.value()),
                }
            }
            if let Some(total) = total {
                p { class: "listing-price",
                    "Total: {total} sats ({super::bitcoin_view::format_sats(total)})"
                }
            }
            if let Some(message) = problem() {
                p { class: "text-warning", "{message}" }
            }
            button {
                class: "btn btn-primary",
                disabled: !ready,
                onclick: {
                    let listing = listing.clone();
                    let store_contract_id = store_contract_id.clone();
                    move |_| {
                        let Some(quantity_wanted) = parsed_quantity else {
                            return;
                        };
                        let picked = picks();
                        let selection = if instant {
                            let Some(total) = total else {
                                return;
                            };
                            let region = region();
                            Some(InstantSelection {
                                nonce: fresh_nonce(),
                                region: (!region.is_empty()).then_some(region),
                                choices: picked.clone(),
                                expected_total_sats: total,
                                requested_at_ms: unix_millis() as i64,
                            })
                        } else {
                            None
                        };
                        // A quote request carries the picks in its note: the
                        // seller reads the note, and the request has no other
                        // place for them.
                        let note_text = if instant {
                            note().trim().to_string()
                        } else {
                            note_with_picks(&listing, &picked, note().trim())
                        };
                        let answers_before = seller_answers(
                            &APP_STATE.read().conversation_thread(&store_contract_id),
                        );
                        let was_instant = selection.is_some();
                        match request(
                            &store_contract_id,
                            &seller_encryption_key,
                            &seller_verifying_key,
                            &listing.id,
                            quantity_wanted,
                            shipping().trim().to_string(),
                            note_text,
                            selection,
                        ) {
                            Ok(()) => {
                                problem.set(None);
                                if was_instant {
                                    sent.set(Some(Sent {
                                        at_ms: unix_millis(),
                                        answers_before,
                                    }));
                                    wake_after_wait(now_ms);
                                }
                                asked.set(true);
                            }
                            Err(e) => problem.set(Some(e)),
                        }
                    }
                },
                if instant { "Buy now" } else { "Send this request" }
            }
            if instant {
                p { class: "text-muted small",
                    "Another region, or more than {MAX_INSTANT_QUANTITY}? "
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: move |_| quote_instead.set(true),
                        "Ask the seller for a total instead"
                    }
                }
            }
        }
    }
}

/// An instant request that was sent: when, and how many seller answers the
/// thread held at that moment.
#[derive(Clone, Copy, PartialEq, Debug)]
struct Sent {
    at_ms: u64,
    answers_before: usize,
}

/// How long a buyer waits for the seller's store before being told it is
/// not answering. The seller's delegate answers within seconds when their
/// node is running, so this is long enough to cover a slow network and short
/// enough that a buyer is not left looking at a spinner.
const INSTANT_WAIT_MS: u64 = 30_000;

/// Where an instant request stands, as the buyer is told.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum InstantWait {
    Waiting,
    Answered,
    /// Nothing yet after [`INSTANT_WAIT_MS`]. The request is still valid and
    /// an answer arriving later is still shown: `Answered` wins whenever it
    /// comes.
    NotResponding,
}

fn instant_wait(sent_at_ms: u64, now_ms: u64, answered: bool) -> InstantWait {
    if answered {
        InstantWait::Answered
    } else if now_ms.saturating_sub(sent_at_ms) >= INSTANT_WAIT_MS {
        InstantWait::NotResponding
    } else {
        InstantWait::Waiting
    }
}

/// How many answers from the seller (an accepted order or a decline) the
/// buyer's thread with this store holds. Compared before and after a
/// request, so it does not depend on the seller's clock.
fn seller_answers(thread: &[crate::messaging::ConversationMessage]) -> usize {
    thread
        .iter()
        .filter(|message| message.addressing == Addressing::ToBuyer)
        .filter(|message| {
            matches!(
                message.content,
                MessageContent::OrderAccepted { .. } | MessageContent::Decline { .. }
            )
        })
        .count()
}

/// The buyer's note, with the choices they picked in front of it, one per
/// line ("Flavour: Fig").
fn note_with_picks(listing: &Listing, picks: &[String], note: &str) -> String {
    let mut lines: Vec<String> = listing
        .choices
        .iter()
        .zip(picks)
        .map(|(group, pick)| format!("{}: {pick}", group.name))
        .collect();
    if !note.is_empty() {
        lines.push(note.to_string());
    }
    lines.join("\n")
}

/// A fresh request nonce. Only the buyer's own resends reuse one, and this
/// form never resends.
fn fresh_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).expect("the browser's random source");
    nonce
}

#[cfg(target_arch = "wasm32")]
fn unix_millis() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn unix_millis() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

/// Re-render the form once the wait is over, so "not responding" appears
/// without the buyer touching anything.
#[cfg(target_arch = "wasm32")]
fn wake_after_wait(mut now_ms: Signal<u64>) {
    spawn(async move {
        gloo_timers::future::TimeoutFuture::new(INSTANT_WAIT_MS as u32).await;
        now_ms.set(unix_millis());
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn wake_after_wait(_now_ms: Signal<u64>) {}

/// Seal a buyer's request and hand it to the local node.
///
/// Errors are returned rather than notified, so the form can say what went
/// wrong beside the box the buyer just filled in.
#[allow(clippy::too_many_arguments)]
fn request(
    store_contract_id: &[u8],
    seller_encryption_key: &[u8; 32],
    seller_verifying_key: &[u8; 32],
    listing_id: &ListingId,
    quantity: u32,
    shipping: String,
    note: String,
    instant: Option<InstantSelection>,
) -> Result<(), String> {
    let seller = ed25519_dalek::VerifyingKey::from_bytes(seller_verifying_key)
        .map_err(|e| format!("this store's identity key is unusable: {e}"))?;

    let record_as = match &instant {
        Some(selection) => format!(
            "Asked to buy {quantity} with instant checkout, {} sats.",
            selection.expected_total_sats
        ),
        None => format!("Asked to buy {quantity}."),
    };
    let sealed = APP_STATE.write().request_order(
        store_contract_id,
        seller_encryption_key,
        listing_id,
        quantity,
        shipping,
        note,
        instant,
    )?;

    super::message_view::deliver_to_seller(store_contract_id, seller, record_as, sealed)
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
                    target: ComplaintTarget::AtStore {
                        store_contract_id: store_contract_id.clone(),
                        purchase: Box::new(purchase.clone()),
                    },
                }
            } else if let Some(settled) = purchase.settled() {
                SettledPurchase { order: settled.clone(), bitcoin: bitcoin.clone() }
            } else if purchase.unconfirmed_paid() {
                // A `Paid` record the fallback checks refuse: a bridge this app
                // does not recognise, or an order no complaint could be made
                // about. Not shown as paid (review round 3, P2-C).
                p { class: "text-warning",
                    "The seller's record says this order is paid, but it is not a purchase this \
                     app can confirm as yours."
                }
            } else if purchase.ready_to_keep() {
                // Everything checks out but this node does not keep its own
                // copy yet: the press keeps it, and the payment details
                // appear once the delegate says it holds it
                // (`docs/complaint-threat-model.md` section 3.1). No address
                // here, for the reason the blocker arm below gives.
                PayThisOrder {
                    store_contract_id: store_contract_id.clone(),
                    purchase: purchase.clone(),
                }
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

/// "Pay this order": ask this node's delegate to keep the seller-signed terms
/// before any payment details are shown (`docs/complaint-threat-model.md`
/// section 3.1). Shown only when keeping them is the one thing left
/// ([`BuyerPurchase::ready_to_keep`]).
#[component]
fn PayThisOrder(store_contract_id: Vec<u8>, purchase: BuyerPurchase) -> Element {
    let order_id = purchase.order_id.clone();
    let mut problem = use_signal(|| Option::<String>::None);
    let (sent, refusal) = {
        let state = APP_STATE.read();
        (
            state.keep_sent(&order_id),
            state.keep_refusal(&order_id).map(str::to_string),
        )
    };
    if let Some(why) = refusal {
        // A refusal may be transient (the node would not save it); the press
        // asks again (review round 3, P3).
        return rsx! {
            p { class: "text-warning",
                "Your node would not keep a copy of this order, so no payment details are \
                 shown: {why}"
            }
            if let Some(why) = problem() {
                p { class: "text-warning", "{why}" }
            }
            button {
                class: "btn btn-sm btn-outline",
                onclick: move |_| {
                    let result = APP_STATE.write().keep_purchase(&store_contract_id, &order_id);
                    problem.set(result.err());
                },
                "Try again"
            }
        };
    }
    if sent {
        return rsx! {
            p { class: "text-muted",
                "Keeping your copy of this order. The payment details appear here once your \
                 node has it."
            }
        };
    }
    rsx! {
        p { class: "text-muted",
            "This order is published, signed by this store's seller, and anchored to a recent \
             block your node agrees with. Before you pay, your node keeps its own copy of it, \
             so a complaint about it never depends on what the seller keeps."
        }
        if let Some(why) = problem() {
            p { class: "text-warning", "{why}" }
        }
        button {
            class: "btn btn-sm btn-primary",
            onclick: move |_| {
                let result = APP_STATE.write().keep_purchase(&store_contract_id, &order_id);
                problem.set(result.err());
            },
            "Pay this order"
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
fn FileComplaint(target: ComplaintTarget) -> Element {
    use harvest_common::feedback::FeedbackCategory;
    let order_id = target.order_id();
    let mut chosen = use_signal(|| Option::<FeedbackCategory>::None);
    let mut problem = use_signal(|| Option::<String>::None);
    // The refusal is read only when there is no complaint on record: it ends
    // in a full verification of the complaint (memoised, review round 3
    // P2-D), which a card with nothing to offer does not need.
    let (on_record, sent, refusal) = {
        let state = APP_STATE.read();
        let on_record = target.on_record(&state);
        let sent = state.complaint_sent(&order_id);
        let refusal = (on_record.is_none() && !sent)
            .then(|| target.refusal(&state))
            .flatten();
        (on_record, sent, refusal)
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
                "Complaint about order {short} is being kept on your node. It goes to the \
                 seller's record once it is kept, and shows there once the network has it."
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
                        let target = target.clone();
                        move |_| {
                            chosen.set(None);
                            let result = target.file(&mut APP_STATE.write(), category.clone());
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

/// What a complaint control is about: a purchase on a loaded store's page,
/// or a purchase this node keeps, judged from the kept record alone (review
/// round 5 of #143, R5-B).
#[derive(Clone, PartialEq)]
enum ComplaintTarget {
    AtStore {
        store_contract_id: Vec<u8>,
        purchase: Box<BuyerPurchase>,
    },
    Kept {
        store_key: [u8; 32],
        order_id: harvest_common::payment::OrderId,
    },
}

impl ComplaintTarget {
    fn order_id(&self) -> harvest_common::payment::OrderId {
        match self {
            Self::AtStore { purchase, .. } => purchase.order_id.clone(),
            Self::Kept { order_id, .. } => order_id.clone(),
        }
    }

    fn on_record(
        &self,
        state: &crate::state::AppState,
    ) -> Option<harvest_common::reputation::Complaint> {
        match self {
            Self::AtStore {
                store_contract_id,
                purchase,
            } => state.complaint_on_record(store_contract_id, &purchase.order_id),
            Self::Kept {
                store_key,
                order_id,
            } => state.complaint_on_record_by_key(store_key, order_id),
        }
    }

    fn refusal(&self, state: &crate::state::AppState) -> Option<String> {
        match self {
            Self::AtStore {
                store_contract_id,
                purchase,
            } => state.complaint_refusal(store_contract_id, purchase),
            Self::Kept {
                store_key,
                order_id,
            } => state.kept_complaint_refusal(store_key, order_id),
        }
    }

    fn file(
        &self,
        state: &mut crate::state::AppState,
        category: harvest_common::feedback::FeedbackCategory,
    ) -> Result<(), String> {
        match self {
            Self::AtStore {
                store_contract_id,
                purchase,
            } => state.file_complaint(store_contract_id, &purchase.order_id, category),
            Self::Kept {
                store_key,
                order_id,
            } => state.file_kept_complaint(store_key, order_id, category),
        }
    }
}

/// The kept purchases to list, newest first: every one this node keeps except
/// those in `shown`, `(store key, order id)` pairs a store's purchase card on
/// the same page already shows from the same kept copy, so a paid order does
/// not appear twice with two complaint controls (harvest#125 review). Matched
/// on the pair, never the order id alone: another store's card naming the
/// same id must not hide this one.
pub(crate) fn kept_purchases_to_list(
    kept: &[harvest_common::delegate::KeptPurchase],
    shown: &[([u8; 32], harvest_common::payment::OrderId)],
) -> Vec<harvest_common::delegate::KeptPurchase> {
    let mut kept: Vec<_> = kept
        .iter()
        .filter(|k| {
            !shown
                .iter()
                .any(|(store_key, id)| *store_key == k.store_key && *id == k.order.order.id)
        })
        .cloned()
        .collect();
    kept.sort_by_key(|k| std::cmp::Reverse(k.order.order.created_at));
    kept
}

/// Every purchase this node keeps, from the kept records alone, with no
/// store loaded (review round 5 of #143, R5-B). A store re-keyed while its
/// seller stays away, or one nobody hosts, still leaves the buyer the paid
/// copy and the complaint control here. Shown on My purchases, below the
/// loaded stores' purchase cards; `shown` names the kept purchases those
/// cards already carry (`AppState::kept_purchases_shown_at`).
///
/// No payment address, ever: the purchase card is the one component that
/// shows a buyer one (`docs/complaint-threat-model.md` section 3.1). An
/// unpaid kept order is listed so the buyer knows it is held, and is paid
/// from its purchase card once its store is loaded.
#[component]
pub fn KeptPurchases(shown: Vec<([u8; 32], harvest_common::payment::OrderId)>) -> Element {
    let app_state = APP_STATE.read();
    let kept = kept_purchases_to_list(&app_state.kept_purchases, &shown);
    if kept.is_empty() {
        return rsx! {};
    }
    let bitcoin = app_state.bitcoin.clone();
    drop(app_state);
    let seen_paid: Vec<bool> = {
        let state = APP_STATE.read();
        kept.iter().map(|k| state.kept_seen_paid(k)).collect()
    };
    let heading = if shown.is_empty() {
        "Your purchases"
    } else {
        "Other purchases your node keeps"
    };
    rsx! {
        div { class: "card", style: "margin-top: 1rem;",
            h3 { "{heading}" }
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "Every order your node keeps its own copy of. A complaint about a paid one "
                "is made from that copy, so it does not need the seller's store to be "
                "online or unchanged."
            }
            for (purchase, seen_paid) in kept.into_iter().zip(seen_paid) {
                KeptPurchaseRow {
                    // A kept purchase is one per order id on this node, but
                    // its identity is the pair.
                    key: "{hex::encode(purchase.store_key)}-{purchase.order.order.id}",
                    purchase,
                    seen_paid,
                    bitcoin: bitcoin.clone(),
                }
            }
        }
    }
}

#[component]
fn KeptPurchaseRow(
    purchase: harvest_common::delegate::KeptPurchase,
    /// Claims this node holds prove the unpaid copy paid, and its upgrade
    /// is on its way.
    seen_paid: bool,
    bitcoin: crate::state::BitcoinState,
) -> Element {
    use harvest_common::payment::OrderStatus;
    let short = purchase.order.order.id.short();
    let paid = purchase.order.status == OrderStatus::Paid;
    let amount = super::bitcoin_view::format_sats(purchase.order.order.amount_sats);
    rsx! {
        div { style: "margin-top: 0.5rem; border-top: 1px solid var(--border, #ddd); padding-top: 0.5rem;",
            p { class: "text-muted", style: "font-size: 0.8rem;", "Order {short}" }
            if paid {
                SettledPurchase { order: purchase.order.clone(), bitcoin }
                FileComplaint {
                    target: ComplaintTarget::Kept {
                        store_key: purchase.store_key,
                        order_id: purchase.order.order.id.clone(),
                    },
                }
            } else if seen_paid {
                p { class: "text-muted",
                    "{amount} \u{00b7} Payment seen. Your node is keeping its proof of payment, \
                     and a complaint can be made once it has."
                }
            } else {
                // No "pay it here" (review round 6): a buyer who paid while
                // the payment went unobserved (model 7.4) would read it as a
                // prompt to pay again.
                p { class: "text-muted",
                    "{amount} \u{00b7} No payment seen yet. Your node keeps this order and \
                     follows what the bridge reports for its address. If you have not paid, \
                     the seller's store page is where to."
                }
            }
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
    /// Set for an instant-checkout request: the amount starts at the total
    /// the buyer was shown, and the order carries the request id.
    #[props(default)]
    instant: Option<super::message_view::InstantAnswer>,
) -> Element {
    let mut amount = use_signal(|| {
        instant
            .map(|i| i.total_sats.to_string())
            .unwrap_or_default()
    });
    let mut confirmations = use_signal(|| "1".to_string());
    let mut problem = use_signal(|| Option::<String>::None);
    let mut accepted = use_signal(|| false);

    let parsed_amount = amount().trim().parse::<u64>().ok().filter(|n| *n > 0);
    // The invoice form's own rule, so the two seller controls refuse the
    // same values (`docs/complaint-threat-model.md` section 4).
    let confirmations_read = super::invoice_form::parse_required_confirmations(&confirmations());
    let parsed_confirmations = confirmations_read.as_ref().ok().copied();
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
            if instant.is_some() {
                p { class: "text-muted", style: "font-size: 0.85rem;",
                    "The buyer used instant checkout. Your device's instant checkout does not "
                    "count an order you answer here: if you count this listing, lower the count "
                    "yourself once it is paid."
                }
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
                if let Err(why) = confirmations_read {
                    p { class: "text-warning", "{why}" }
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
                            request: instant.map(|i| i.request),
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
    if let Some(request) = buyer.request {
        let published = state
            .browsing_stores
            .get(store_contract_id)
            .map(|store| store.orders.as_slice())
            .unwrap_or_default();
        if let Some(why) = manual_answer_refusal(published, &request, crate::state::now_ms()) {
            return Err(why);
        }
    }
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
        answers_request: buyer.request,
    })
}

/// Why a seller may not answer instant request `request` by hand, if they
/// may not:
/// - it is answered already (by this device's delegate, or another of the
///   seller's devices): a second answer would be the same order id with a
///   different address, and the buyer could pay the one the store drops;
/// - the buyer's clock put it more than a day from this one: the order is
///   dated at the request, and a date far off would rank it wrongly among
///   the store's orders for good. The delegate refuses the same.
fn manual_answer_refusal(
    published: &[harvest_common::payment::AuthorizedOrder],
    request: &harvest_common::payment::AnsweredRequest,
    now_ms: u64,
) -> Option<String> {
    let id = request.order_id();
    if published.iter().any(|order| order.order.id == id) {
        return Some(
            "this request has already been answered with an order; it is under Orders".into(),
        );
    }
    let at = request.requested_at.timestamp_millis();
    if at < 0 || now_ms.abs_diff(at as u64) > 24 * 60 * 60 * 1000 {
        return Some(
            "this request is dated more than a day from now by the buyer's clock; ask them to \
             send it again"
                .into(),
        );
    }
    None
}

/// The two values a buyer's request asks the seller to sign into the
/// commitment: they travel together from the request to the terms, so they
/// are one argument rather than two a positional call could swap.
struct BuyerValues {
    order_binding: [u8; 32],
    buyer_receipt_key: Option<[u8; 32]>,
    /// The instant-checkout request this answers, if it was one.
    request: Option<harvest_common::payment::AnsweredRequest>,
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
        | PaymentBlocker::AddressContractNotCurrent {
            generation_known: false,
        }
        | PaymentBlocker::ConversationNotKept
        // The buyer's own press clears it; when it is the only blocker the
        // card offers the press instead of this text.
        | PaymentBlocker::PurchaseNotKept => Remedy::Wait,
        // The seller issued something that cannot be acted on, and issuing it
        // again fixes every one of these.
        PaymentBlocker::NoTrustedBridge
        | PaymentBlocker::BridgeNotRecognised(_)
        | PaymentBlocker::DestinationDisagrees
        | PaymentBlocker::DestinationUnreadable
        | PaymentBlocker::AnchorMissing
        | PaymentBlocker::AnchorStale { .. }
        | PaymentBlocker::UnfitForComplaint(_)
        | PaymentBlocker::AddressContractNotCurrent {
            generation_known: true,
        } => Remedy::AskTheSeller,
        // The order carries no key for this buyer because the REQUEST it
        // answers carried none (an earlier build), or carried another; the
        // seller copies the key from the request, so only a new request
        // fixes it. The seller's inbox offers a keyed request afresh even
        // beside an unkeyed order (`message_view::unanswered_requests`).
        PaymentBlocker::CommitmentLacksBuyerKey => Remedy::AskAgain,
        // The thread the order was agreed in is gone; a new request starts a
        // new one.
        PaymentBlocker::ConversationForgotten => Remedy::AskAgain,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A seller answers an instant request by hand only when no order for it
    /// is published and the buyer dated it within a day of now. Mutated red
    /// by dropping each check.
    #[test]
    fn a_manual_answer_is_refused_when_answered_or_far_dated() {
        let now = 1_800_000_000_000u64;
        let request = |at: i64| harvest_common::payment::AnsweredRequest {
            request_id: [4; 32],
            requested_at: chrono::DateTime::from_timestamp_millis(at).unwrap(),
        };
        let fresh = request(now as i64 - 60_000);
        assert_eq!(manual_answer_refusal(&[], &fresh, now), None);
        let answered = harvest_common::payment::AuthorizedOrder {
            order: harvest_common::payment::Order {
                request_id: Some([4; 32]),
                id: fresh.order_id(),
                buyer_fingerprint: String::new(),
                seller_fingerprint: String::new(),
                amount_sats: 1,
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
                created_at: fresh.requested_at,
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status: harvest_common::payment::OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        };
        assert!(manual_answer_refusal(&[answered], &fresh, now).is_some());
        let day = 24 * 60 * 60 * 1000;
        assert!(manual_answer_refusal(&[], &request(now as i64 - 2 * day), now).is_some());
        assert!(manual_answer_refusal(&[], &request(now as i64 + 2 * day), now).is_some());
    }

    /// Waiting until the limit, "not responding" after it, and an answer
    /// shown whenever it comes, including after the limit.
    #[test]
    fn an_instant_request_waits_thirty_seconds_and_an_answer_always_wins() {
        let sent = 1_000_000;
        assert_eq!(instant_wait(sent, sent, false), InstantWait::Waiting);
        assert_eq!(
            instant_wait(sent, sent + INSTANT_WAIT_MS - 1, false),
            InstantWait::Waiting
        );
        assert_eq!(
            instant_wait(sent, sent + INSTANT_WAIT_MS, false),
            InstantWait::NotResponding
        );
        assert_eq!(instant_wait(sent, sent + 5, true), InstantWait::Answered);
        assert_eq!(
            instant_wait(sent, sent + 10 * INSTANT_WAIT_MS, true),
            InstantWait::Answered
        );
        // A clock that went backwards is still waiting, not a panic.
        assert_eq!(instant_wait(sent, sent - 1, false), InstantWait::Waiting);
    }

    fn message(
        addressing: Addressing,
        content: MessageContent,
    ) -> crate::messaging::ConversationMessage {
        crate::messaging::ConversationMessage {
            addressing,
            timestamp: chrono::Utc::now(),
            nonce: [0u8; 24],
            digest: [0u8; 32],
            content,
        }
    }

    /// Only an acceptance or a decline addressed to the buyer is an answer:
    /// the buyer's own messages, and plain text from the seller, are not.
    #[test]
    fn only_the_sellers_acceptance_or_decline_counts_as_an_answer() {
        let accepted = MessageContent::OrderAccepted {
            order_id: harvest_common::payment::OrderId([1u8; 32]),
        };
        let thread = vec![
            message(Addressing::ToBuyer, accepted.clone()),
            message(
                Addressing::ToBuyer,
                MessageContent::Decline {
                    reason: "Sold out".into(),
                },
            ),
            message(Addressing::ToBuyer, MessageContent::Text("Hello".into())),
            message(Addressing::ToSeller, accepted),
        ];
        assert_eq!(seller_answers(&thread), 2);
    }

    #[test]
    fn a_quote_request_carries_the_picks_in_its_note() {
        let listing = Listing {
            id: ListingId([0u8; 32]),
            title: "Jam".into(),
            description: String::new(),
            kind: harvest_common::listing::ListingKind::Sale,
            price: None,
            created_at: chrono::DateTime::UNIX_EPOCH,
            checkout: None,
            choices: vec![
                harvest_common::listing::ChoiceGroup {
                    name: "Flavour".into(),
                    options: vec!["Fig".into(), "Plum".into()],
                },
                harvest_common::listing::ChoiceGroup {
                    name: "Size".into(),
                    options: vec!["Small".into()],
                },
            ],
        };
        let picks = vec!["Fig".to_string(), "Small".to_string()];
        assert_eq!(
            note_with_picks(&listing, &picks, "By Friday"),
            "Flavour: Fig\nSize: Small\nBy Friday"
        );
        assert_eq!(
            note_with_picks(&listing, &picks, ""),
            "Flavour: Fig\nSize: Small"
        );
    }
}
