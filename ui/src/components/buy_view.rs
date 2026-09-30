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

/// The form a buyer fills in to buy a listing.
///
/// Every listing it is offered for has a sats price and fixed delivery
/// ([`Listing::offers_instant_checkout`]), so the total is not a guess: it
/// comes from the listing's fixed terms through [`Listing::instant_total`],
/// the same function the seller's delegate uses to check it. There is no
/// "ask the seller for a total" any more (Ian, 2026-09-26). The buyer still
/// pays only against the order the seller's store publishes.
#[component]
pub fn BuyForm(
    store_contract_id: Vec<u8>,
    listing: Listing,
    seller_encryption_key: [u8; 32],
    seller_verifying_key: [u8; 32],
    /// The store closed while this form was open: an order already sent
    /// keeps its pay card, and no new one is sent.
    #[props(default)]
    closed: bool,
) -> Element {
    let mut quantity = use_signal(|| "1".to_string());
    let mut shipping = use_signal(String::new);
    let mut note = use_signal(String::new);
    let mut region = use_signal(String::new);
    let choice_count = listing.choices.len();
    let mut picks = use_signal(move || vec![String::new(); choice_count]);
    let mut problem = use_signal(|| Option::<String>::None);
    // When the order was sent, and how many seller answers the thread
    // already held then.
    let mut sent = use_signal(|| Option::<Sent>::None);
    // Bumped by the 30-second timer so the form re-renders when it fires.
    let now_ms = use_signal(unix_millis);

    let listing_title = listing.title.clone();
    let counted = matches!(
        APP_STATE
            .read()
            .listing_availability(&store_contract_id, &listing.id),
        harvest_common::listing::ListingAvailability::Available { quantity: Some(_) }
    );
    let by_region = match &listing.checkout {
        Some(FixedCheckout {
            delivery: DeliveryPrice::ByRegion(rows),
            ..
        }) => rows.iter().map(|row| row.region.clone()).collect(),
        _ => Vec::<String>::new(),
    };

    let parsed_quantity = quantity().trim().parse::<u32>().ok().filter(|n| *n > 0);
    let total = parsed_quantity.and_then(|q| {
        let region = region();
        let region = (!region.is_empty()).then_some(region);
        listing.instant_total(q, region.as_deref(), &picks()).ok()
    });
    // The buyer's own unpaid orders here, counted the way the seller's store
    // counts them. Said before sending rather than after a wait.
    // Only the conversation this Buy now goes out in (`conversation_with`
    // continues the last one), which is what the store counts per.
    let too_many_unpaid = {
        let state = APP_STATE.read();
        let current = state
            .browsing_stores
            .get(&store_contract_id)
            .and_then(|s| s.conversations.last())
            .map(|c| c.buyer_public_key);
        unpaid_in_conversation(&state.buyer_purchases(&store_contract_id), current)
            >= harvest_common::delegate::MAX_UNPAID_INSTANT_PER_BUYER
    };
    let ready = total.is_some() && !shipping().trim().is_empty() && !too_many_unpaid && !closed;

    if let Some(sent) = sent() {
        let thread = APP_STATE.read().conversation_thread(&store_contract_id);
        let answer = latest_answer(&thread, &sent.answers_before, sent.expected.as_ref());
        let _ = now_ms();
        return match instant_wait(sent.at_ms, unix_millis(), answer.is_some()) {
            InstantWait::Answered => match answer {
                Some(Answer::Declined(reason)) => rsx! {
                    p { class: "text-warning", "The seller\u{2019}s store couldn\u{2019}t take this order: {reason}" }
                    p { class: "text-muted small", "You haven\u{2019}t been charged anything." }
                },
                _ => {
                    // The order's own card, here under the listing where the
                    // buyer pressed Buy now, rather than a pointer to a list
                    // further down the page (the 2026-09-27 friction report).
                    let purchase = sent.expected.as_ref().and_then(|expected| {
                        APP_STATE
                            .read()
                            .buyer_purchases(&store_contract_id)
                            .into_iter()
                            .find(|p| &p.order_id == expected)
                    });
                    let bitcoin = APP_STATE.read().bitcoin.clone();
                    // Said only while there is something to pay.
                    let payable = purchase.as_ref().is_some_and(|p| {
                        (p.blockers.is_empty() || p.ready_to_keep())
                            && p.commitment
                                .as_ref()
                                .is_some_and(|c| c.order.amount_sats == sent.asked_sats)
                    });
                    rsx! {
                        // Only a counted listing holds stock (the delegate's
                        // `Sale::holds`), and only for the hour: a payment
                        // after that still counts, but the item may have gone.
                        if counted && payable {
                            p { class: "text-muted",
                                "Pay soon: this item is kept for you for about an hour. If it sells out "
                                "before your payment is confirmed, the seller either sends it anyway or refunds you."
                            }
                        }
                        match purchase {
                            Some(purchase) => rsx! {
                                InlinePurchase { order_id: purchase.order_id.clone() }
                                PurchaseCard {
                                    store_contract_id: store_contract_id.clone(),
                                    purchase,
                                    bitcoin,
                                    just_bought: true,
                                    asked_sats: Some(sent.asked_sats),
                                }
                            },
                            None => rsx! {
                                p { strong { "Order placed." } }
                                p { class: "text-muted", "Getting the payment details ready\u{2026}" }
                            },
                        }
                    }
                }
            },
            InstantWait::Waiting => rsx! {
                p { strong { "Order placed." } }
                p { class: "text-muted",
                    "Getting the payment details for {listing_title} from the seller\u{2019}s store. "
                    "This usually takes a few seconds."
                }
            },
            InstantWait::NotResponding => rsx! {
                p { class: "text-muted",
                    "The seller\u{2019}s store hasn\u{2019}t answered yet. You haven\u{2019}t been charged "
                    "anything. If it answers later, your order appears under \u{201c}Your purchases\u{201d} below."
                }
            },
        };
    }

    rsx! {
        div { style: "margin-top: 0.75rem;",
            if !by_region.is_empty() {
                div { class: "form-group",
                    label { class: "form-label", "Deliver to" }
                    select {
                        class: "form-select field-fit",
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
                        class: "form-select field-fit",
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
                select {
                    class: "form-select field-fit",
                    value: "{quantity}",
                    onchange: move |event| quantity.set(event.value()),
                    for n in 1..=MAX_INSTANT_QUANTITY {
                        option { key: "{n}", value: "{n}", "{n}" }
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
                p { class: "text-muted small",
                    "Only this seller can read it. It is locked to them before it leaves your "
                    "browser, and it is never published."
                }
            }
            div { class: "form-group",
                label { class: "form-label", "Note for the seller (optional)" }
                // One line, growing as the buyer types (Ian, 2026-09-29):
                // most notes are a line.
                textarea {
                    class: "form-textarea grow-textarea",
                    rows: 1,
                    value: "{note}",
                    placeholder: "Delivery date, gift message...",
                    oninput: move |event| {
                        note.set(event.value());
                        super::grow_focused_textarea();
                    },
                }
            }
            if let Some(total) = total {
                p { class: "listing-price",
                    "Total: {super::store_view::sats_text(total)} ({super::bitcoin_view::format_sats(total)})"
                }
            }
            if too_many_unpaid {
                p { class: "text-warning", "{harvest_common::delegate::TOO_MANY_UNPAID}" }
            }
            if closed {
                p { class: "text-warning",
                    "This store has just closed, so this order can\u{2019}t be sent now."
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
                        let (Some(quantity_wanted), Some(total)) = (parsed_quantity, total) else {
                            return;
                        };
                        if too_many_unpaid {
                            return;
                        }
                        let region = region();
                        let selection = InstantSelection {
                            nonce: fresh_nonce(),
                            region: (!region.is_empty()).then_some(region),
                            choices: picks(),
                            expected_total_sats: total,
                            requested_at_ms: unix_millis() as i64,
                        };
                        let answering = selection.clone();
                        let answers_before = seller_answers(
                            &APP_STATE.read().conversation_thread(&store_contract_id),
                        );
                        match request(
                            &store_contract_id,
                            &seller_encryption_key,
                            &seller_verifying_key,
                            &listing.id,
                            quantity_wanted,
                            shipping().trim().to_string(),
                            note().trim().to_string(),
                            selection,
                        ) {
                            Ok(tag) => {
                                problem.set(None);
                                sent.set(Some(Sent {
                                    at_ms: unix_millis(),
                                    asked_sats: total,
                                    answers_before,
                                    expected: answering
                                        .answered_request(&tag)
                                        .map(|request| request.order_id()),
                                }));
                                wake_after_wait(now_ms);
                            }
                            Err(e) => problem.set(Some(e)),
                        }
                    }
                },
                "Buy now"
            }
            p { class: "text-muted small",
                "Nothing is charged when you press Buy now. The seller\u{2019}s store sends the "
                "payment details, and you pay from your own wallet."
            }
        }
    }
}

/// The orders Buy now forms are showing in place, one entry per mounted
/// card, which the store page's "Your purchases" list then leaves out rather
/// than showing twice. Several forms (one per listing) can each show one.
static SHOWN_IN_BUY_FORM: GlobalSignal<Vec<harvest_common::payment::OrderId>> =
    GlobalSignal::new(Vec::new);

/// Marks `order_id` as shown by a Buy now form for as long as this is
/// mounted beside its card.
#[component]
fn InlinePurchase(order_id: harvest_common::payment::OrderId) -> Element {
    let mine = order_id.clone();
    use_hook(move || {
        // Deferred to a task: a signal is not written while a component
        // renders. The task belongs to this component, so it never runs
        // after the drop below.
        spawn(async move {
            SHOWN_IN_BUY_FORM.write().push(order_id);
        });
    });
    use_drop(move || {
        let mut shown = SHOWN_IN_BUY_FORM.write();
        if let Some(at) = shown.iter().position(|id| *id == mine) {
            shown.remove(at);
        }
    });
    rsx! {}
}

/// The purchases "Your purchases" lists: all but those a Buy now form on the
/// page is already showing (`shown_above`).
fn purchases_to_list<'a>(
    purchases: &'a [BuyerPurchase],
    shown_above: &[harvest_common::payment::OrderId],
) -> Vec<&'a BuyerPurchase> {
    purchases
        .iter()
        .filter(|p| !shown_above.contains(&p.order_id))
        .collect()
}

/// [`open_unpaid_orders`] in the conversation tagged `current` alone: the
/// one a Buy now goes out in, and what the store counts per. None before a
/// conversation exists.
fn unpaid_in_conversation(purchases: &[BuyerPurchase], current: Option<[u8; 32]>) -> usize {
    let here: Vec<BuyerPurchase> = purchases
        .iter()
        .filter(|p| Some(p.conversation) == current)
        .cloned()
        .collect();
    open_unpaid_orders(&here)
}

/// How many of this buyer's orders at a store are Buy now orders still
/// waiting for payment: published, unpaid, and not yet too old to pay. The
/// same count the seller's store caps at
/// [`harvest_common::delegate::MAX_UNPAID_INSTANT_PER_BUYER`], so a buyer at
/// the cap is told before sending rather than left waiting.
fn open_unpaid_orders(purchases: &[BuyerPurchase]) -> usize {
    purchases
        .iter()
        .filter(|p| p.paid.is_none())
        .filter(|p| {
            p.commitment.as_ref().is_some_and(|c| {
                c.order.request_id.is_some()
                    && c.status == harvest_common::payment::OrderStatus::AwaitingPayment
            })
        })
        .filter(|p| {
            !p.blockers
                .iter()
                .any(|b| matches!(b, PaymentBlocker::AnchorStale { .. }))
        })
        .count()
}

/// An instant request that was sent: when, and how many seller answers the
/// thread held at that moment.
#[derive(Clone, PartialEq, Debug)]
struct Sent {
    at_ms: u64,
    /// The total the form showed when Buy now was pressed: what the order
    /// must ask, checked on its card even if the request itself is not in
    /// this device's thread (round 2 of harvest#187).
    asked_sats: u64,
    answers_before: Vec<[u8; 32]>,
    /// The order the store would issue for this request
    /// (`OrderId::for_request`), so an acceptance of another request is
    /// never read as this one's.
    expected: Option<harvest_common::payment::OrderId>,
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

/// The seller's answers (an accepted order or a decline) the buyer's thread
/// with this store holds, by entry digest. Taken when a Buy now goes out, so
/// an answer that arrives later is told apart by what it is, not by where a
/// seller's clock sorts it (codex on harvest#177).
fn seller_answers(thread: &[crate::messaging::ConversationMessage]) -> Vec<[u8; 32]> {
    thread
        .iter()
        .filter(|message| message.addressing == Addressing::ToBuyer)
        .filter(|message| {
            matches!(
                message.content,
                MessageContent::OrderAccepted { .. } | MessageContent::Decline { .. }
            )
        })
        .map(|message| message.digest)
        .collect()
}

/// The seller's store's answer to an order: an acceptance (the order is
/// published and can be paid) or a decline, with its reason.
#[derive(Clone, PartialEq, Debug)]
enum Answer {
    Accepted,
    Declined(String),
}

/// This order's answer: the acceptance of the order it `expected`, found
/// anywhere in the thread (the id is unique to this request), else the
/// newest decline that was not already there when it went out (`before`,
/// from [`seller_answers`]), or `None` when there is neither yet. Neither
/// depends on where a seller's clock sorts a reply. An acceptance of another
/// request is never taken for this one's; a decline names no order, so one
/// sent to another request of the same buyer at the same moment can still
/// be shown here.
fn latest_answer(
    thread: &[crate::messaging::ConversationMessage],
    before: &[[u8; 32]],
    expected: Option<&harvest_common::payment::OrderId>,
) -> Option<Answer> {
    let to_buyer = thread
        .iter()
        .filter(|message| message.addressing == Addressing::ToBuyer);
    if to_buyer.clone().any(|message| {
        matches!(&message.content, MessageContent::OrderAccepted { order_id } if Some(order_id) == expected)
    }) {
        return Some(Answer::Accepted);
    }
    to_buyer
        .rev()
        .filter(|message| !before.contains(&message.digest))
        .find_map(|message| match &message.content {
            MessageContent::Decline { reason } => Some(Answer::Declined(reason.clone())),
            _ => None,
        })
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
    instant: InstantSelection,
) -> Result<[u8; 32], String> {
    let seller = ed25519_dalek::VerifyingKey::from_bytes(seller_verifying_key)
        .map_err(|e| format!("this store's identity key is unusable: {e}"))?;

    let record_as = format!(
        "Ordered {quantity}, {} in all.",
        super::store_view::sats_text(instant.expected_total_sats)
    );
    let sealed = APP_STATE.write().request_order(
        store_contract_id,
        seller_encryption_key,
        listing_id,
        quantity,
        shipping,
        note,
        Some(instant),
    )?;

    let tag: [u8; 32] = sealed
        .sender_public_key
        .as_slice()
        .try_into()
        .map_err(|_| "the conversation's key is not 32 bytes".to_string())?;
    super::message_view::deliver_to_seller(store_contract_id, seller, record_as, sealed)?;
    Ok(tag)
}

/// A buyer's purchases from one store on Purchases, each conversation's
/// messages under the orders it holds, and any conversation with no order (a
/// question) on its own (mockup `scrPurchase`, `scrPurchases`; round-6
/// critique: messages move into each order's screen). One Messages button
/// per conversation rather than per order: a buyer's next Buy now continues
/// the same conversation, so two orders can share one thread.
#[component]
pub fn Purchases(store_contract_id: Vec<u8>) -> Element {
    // Which of this store's conversations is open, shared with the
    // complaint step (msg1 critique MSG-13). A hook, so before any return.
    use_context_provider(|| super::message_view::BuyerOpenThread(Signal::new(None)));
    // The order a Buy now form on this page is already showing, in place,
    // right under the listing: not listed a second time here.
    let shown_above = SHOWN_IN_BUY_FORM();
    let app_state = APP_STATE.read();
    let purchases = app_state.buyer_purchases(&store_contract_id);
    let held: Vec<[u8; 32]> = app_state
        .browsing_stores
        .get(&store_contract_id)
        .map(|store| {
            store
                .conversations
                .iter()
                .map(|conversation| conversation.buyer_public_key)
                .collect()
        })
        .unwrap_or_default();
    // Grouped over EVERY purchase, the one the Buy now form shows included,
    // so its conversation keeps its thread here and is never taken for a
    // question (codex on #205 round 2); only its card is left out.
    let groups = purchase_groups(&purchases, &shown_above);
    let questions: Vec<[u8; 32]> = held
        .iter()
        .filter(|tag| !groups.iter().any(|(held, _)| held == *tag))
        .filter(|tag| {
            super::message_view::buyer_thread_has_messages(
                &app_state,
                &store_contract_id,
                Some(**tag),
            )
        })
        .copied()
        .collect();
    if groups.is_empty() && questions.is_empty() {
        return rsx! {};
    }
    let bitcoin = app_state.bitcoin.clone();
    let store_name = app_state.store_name_of(&store_contract_id).label();
    // The orders in each conversation, newest first, for its header (msg1
    // critique MSG-14): every purchase, the one the form shows included.
    let refs: Vec<([u8; 32], Vec<String>)> = by_conversation(&purchases)
        .into_iter()
        .map(|(tag, mut group)| {
            group.sort_by_key(|p| {
                std::cmp::Reverse(p.commitment.as_ref().map(|c| c.order.created_at))
            });
            (tag, group.iter().map(|p| p.order_id.short()).collect())
        })
        .collect();
    drop(app_state);

    rsx! {
        div { style: "margin-top: 24px;",
            if !groups.is_empty() {
                h4 { "Your purchases" }
            }
            for (tag , group) in groups.iter() {
                div { key: "{bs58::encode(tag).into_string()}",
                    // The conversation first, headed, then its orders: after
                    // the orders it read as belonging to the last one, often
                    // an expired order (msg1 critique MSG-6).
                    // A conversation this node no longer holds cannot be read
                    // or written: nothing to open.
                    if held.contains(tag) {
                        p { class: "order-label", "Messages with {store_name}" }
                        // Its only order is the one the Buy now form on this
                        // page shows (round 3 of #205).
                        if group.is_empty() {
                            p { class: "text-muted small", "About the order you just placed" }
                        }
                        super::message_view::BuyerThread {
                            store_contract_id: store_contract_id.clone(),
                            tag: *tag,
                            orders: refs
                                .iter()
                                .find(|(t, _)| t == tag)
                                .map(|(_, r)| r.clone())
                                .unwrap_or_default(),
                        }
                    }
                    for purchase in group.iter() {
                        PurchaseCard {
                            key: "{purchase.order_id}",
                            store_contract_id: store_contract_id.clone(),
                            purchase: purchase.clone(),
                            bitcoin: bitcoin.clone(),
                        }
                    }
                }
            }
            for tag in questions.iter() {
                div { key: "{bs58::encode(tag).into_string()}", class: "card",
                    p { class: "text-muted small", "Your question" }
                    super::message_view::BuyerThread {
                        store_contract_id: store_contract_id.clone(),
                        tag: *tag,
                        open: true,
                    }
                }
            }
        }
    }
}

/// Every conversation `purchases` are filed under, in the order the first of
/// each appears, with the purchases to show a card for: all but those a Buy
/// now form on the page already shows (`shown_above`). A conversation whose
/// every purchase is shown above is still here, with no cards, so its thread
/// stays with its orders.
fn purchase_groups(
    purchases: &[BuyerPurchase],
    shown_above: &[harvest_common::payment::OrderId],
) -> Vec<([u8; 32], Vec<BuyerPurchase>)> {
    by_conversation(purchases)
        .into_iter()
        .map(|(tag, group)| {
            let cards = purchases_to_list(&group, shown_above)
                .into_iter()
                .cloned()
                .collect();
            (tag, cards)
        })
        .collect()
}

/// `purchases` grouped by the conversation each is filed under, in the order
/// the first of each appears.
fn by_conversation(purchases: &[BuyerPurchase]) -> Vec<([u8; 32], Vec<BuyerPurchase>)> {
    let mut groups: Vec<([u8; 32], Vec<BuyerPurchase>)> = Vec::new();
    for purchase in purchases {
        match groups
            .iter_mut()
            .find(|(tag, _)| *tag == purchase.conversation)
        {
            Some((_, group)) => group.push(purchase.clone()),
            None => groups.push((purchase.conversation, vec![purchase.clone()])),
        }
    }
    groups
}

#[component]
pub(crate) fn PurchaseCard(
    store_contract_id: Vec<u8>,
    purchase: BuyerPurchase,
    bitcoin: crate::state::BitcoinState,
    /// Set only by the Buy now form, for the one order its own press just
    /// created: that press is the buyer's, so the order is kept with nothing
    /// more to press (see [`KeepBeforePaying`]).
    #[props(default)]
    just_bought: bool,
    /// The total the Buy now form showed, when this card is under it.
    #[props(default)]
    asked_sats: Option<u64>,
) -> Element {
    let short = purchase.order_id.short();
    // The order must ask what the form showed. `AmountNotAsked` checks the
    // same against the request in the thread; this covers a thread that
    // does not hold it.
    let not_asked = asked_sats
        .zip(purchase.commitment.as_ref())
        .and_then(|(asked, c)| {
            (c.status == harvest_common::payment::OrderStatus::AwaitingPayment
                && c.order.amount_sats != asked)
                .then_some(PaymentBlocker::AmountNotAsked {
                    asked_sats: asked,
                    order_sats: c.order.amount_sats,
                })
        });
    let cancellable = purchase.cancellable();
    let item = APP_STATE
        .read()
        .purchase_item(&store_contract_id, &purchase);
    let what = match item {
        Some((Some(title), quantity)) => {
            format!("{title} \u{00d7} {quantity} \u{00b7} order {short}")
        }
        Some((None, quantity)) => {
            format!("{quantity} \u{00d7} an item no longer listed \u{00b7} order {short}")
        }
        None => format!("Order {short}"),
    };
    rsx! {
        div { class: "card", style: "margin-top: 0.5rem;",
            if let Some(headline) = purchase_headline(&purchase).filter(|_| not_asked.is_none()) {
                p { strong { "{headline}" } }
            }
            p { class: "text-muted small", "{what}" }
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
            } else if let Some(blocker) = not_asked {
                p { class: "text-warning", "{blocker.describe()}" }
                p { class: "text-muted", style: "font-size: 0.85rem;",
                    "No payment details are shown while that is true. Buy it again to get an order you can pay."
                }
            } else if purchase.ready_to_keep() {
                // Everything checks out but this node does not keep its own
                // copy yet. The payment details appear once the delegate says
                // it holds it (`docs/complaint-threat-model.md` section 3.1).
                // No address here, for the reason the blocker arm below gives.
                KeepBeforePaying {
                    store_contract_id: store_contract_id.clone(),
                    purchase: purchase.clone(),
                    just_bought,
                }
            } else {
            match (purchase.blockers.is_empty(), purchase.commitment.as_ref()) {
                // Everything checks out, so the payment details are shown --
                // through the same `OrderCard` the seller's own panel uses,
                // which carries the per-invoice bridge check with it, laid
                // out as the buyer's pay steps.
                (true, Some(commitment)) => rsx! {
                    super::bitcoin_view::OrderCard {
                        order: commitment.clone(),
                        live: super::bitcoin_view::live_address_for_order(&bitcoin, &commitment.order),
                        buyer: true,
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
                            Remedy::AskAgain | Remedy::BuyAgain => 2,
                            Remedy::WalkAway => 3,
                        }) {
                            Some(Remedy::WalkAway) => "No payment details are shown while that is true, and this is not something either of you can put right.",
                            Some(Remedy::AskTheSeller) => "No payment details are shown while that is true. Buy it again to get an order you can pay, or ask the seller.",
                            Some(Remedy::AskAgain) => "No payment details are shown while that is true. Send your request to buy again from this device: a request from this version of Harvest carries your key, and the seller can answer it with an order you can pay.",
                            Some(Remedy::BuyAgain) => "No payment details are shown while that is true. Buy it again to get an order you can pay.",
                            _ => "No payment details are shown while that is true. Look again in a moment.",
                        }
                    }
                },
            }
            }
        }
    }
}

/// The one line a buyer reads first about a purchase: placed and waiting
/// for their payment, or paid (Ian, 2026-09-26). `None` for anything else
/// (settled otherwise, or a record the app cannot confirm), whose card says
/// what happened in its own words.
fn purchase_headline(purchase: &BuyerPurchase) -> Option<&'static str> {
    use harvest_common::payment::OrderStatus;
    if purchase.paid.is_some() {
        return Some("Paid.");
    }
    if purchase.settled().is_some() || purchase.unconfirmed_paid() {
        return None;
    }
    // Not "waiting for your payment" above a line saying not to pay it:
    // only a blocker that waiting clears leaves the order waiting.
    if purchase
        .blockers
        .iter()
        .any(|b| !matches!(remedy(b), Remedy::Wait))
    {
        return None;
    }
    purchase
        .commitment
        .as_ref()
        .filter(|c| c.status == OrderStatus::AwaitingPayment)
        .map(|_| "Order placed, waiting for your payment.")
}

/// Before any payment details: this node keeps its own copy of the
/// seller-signed terms (`docs/complaint-threat-model.md` section 3.1), so a
/// complaint about the order never depends on what the seller keeps.
///
/// Only the buyer's own press takes one of the node's kept-purchase slots
/// (section 5.1), so nothing a seller mints can fill them. Buy now is such a
/// press: the order it creates is named by the nonce that form just chose
/// (`OrderId::for_request`), so a seller cannot make another order that
/// passes for it. For that one order (`just_bought`, set only by the form)
/// the copy is asked for by itself and the pay steps follow Buy now with no
/// second press (the 2026-09-27 friction report). Anywhere else, such as an
/// order found after a reload, whose request this tab did not send, the
/// buyer still presses "Pay this order". A refusal is shown with "Try
/// again", and only that press asks again for the same copy.
#[component]
fn KeepBeforePaying(
    store_contract_id: Vec<u8>,
    purchase: BuyerPurchase,
    just_bought: bool,
) -> Element {
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
    if !just_bought && !sent {
        return rsx! {
            p { class: "text-muted",
                "Before you pay, Harvest keeps its own copy of this order, so a complaint about \
                 it never depends on what the seller keeps."
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
        };
    }
    rsx! {
        if !sent {
            AskToKeep {
                store_contract_id: store_contract_id.clone(),
                order_id: order_id.clone(),
                problem,
            }
        }
        if let Some(why) = problem() {
            // Said, with the press to ask again now rather than at the next
            // automatic try.
            p { class: "text-warning", "{why}" }
            button {
                class: "btn btn-sm btn-outline",
                onclick: move |_| {
                    let result = APP_STATE.write().keep_purchase(&store_contract_id, &order_id);
                    problem.set(result.err());
                },
                "Try again"
            }
        } else {
            p { class: "text-muted", "Getting the payment details ready\u{2026}" }
        }
    }
}

/// Mounted while an order waits to be kept and nothing is on its way: asks
/// the delegate at once, then every `AUTO_KEEP_RETRY_MS` for as long as it
/// stays mounted (`AppState::keep_when_ready` enforces the spacing, so a
/// remount after a failed send does not ask again early). It unmounts while
/// an ask is in flight.
#[component]
fn AskToKeep(
    store_contract_id: Vec<u8>,
    order_id: harvest_common::payment::OrderId,
    problem: Signal<Option<String>>,
) -> Element {
    // A task of this component: it ends when the component unmounts.
    use_future(move || {
        let store_contract_id = store_contract_id.clone();
        let order_id = order_id.clone();
        async move {
            let mut ask = move || {
                let result = APP_STATE
                    .write()
                    .keep_when_ready(&store_contract_id, &order_id);
                problem.set(result.err());
            };
            ask();
            #[cfg(target_arch = "wasm32")]
            loop {
                gloo_timers::future::TimeoutFuture::new(crate::state::AUTO_KEEP_RETRY_MS as u32)
                    .await;
                ask();
            }
        }
    });
    rsx! {}
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
    // One "Report a problem" first, then the step with the choices and the
    // decided line (round-6 critique 06-5, mockup D4): three permanent-record
    // buttons inline were the loudest thing on a delivered order.
    let mut reporting = use_signal(|| false);
    let mut messaging = use_signal(|| false);
    // The store's shared open conversation, when this card is on Purchases:
    // "Message the seller" opens that one rather than a second copy of it
    // (msg1 critique MSG-13).
    let shared = try_use_context::<super::message_view::BuyerOpenThread>();
    // The refusal is read only when there is no complaint on record: it ends
    // in a full verification of the complaint (memoised, review round 3
    // P2-D), which a card with nothing to offer does not need.
    let (on_record, sent, refusal, message_to, store_page, paid_there) = {
        let state = APP_STATE.read();
        let on_record = target.on_record(&state);
        let sent = state.complaint_sent(&order_id);
        let refusal = (on_record.is_none() && !sent)
            .then(|| target.refusal(&state))
            .flatten();
        (
            on_record,
            sent,
            refusal,
            target.conversation(&state),
            target.store_page(&state),
            // Whether a message from the store page would go into a paid
            // conversation, needing no Ghost Key (`compose_tag` continues
            // the last conversation).
            target.store_page(&state).is_some_and(|id| {
                matches!(
                    state.compose_gate_in(&id, None),
                    crate::voucher_flow::ComposeGate::PaidOrder { .. }
                )
            }),
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
    if !reporting() {
        return rsx! {
            div { class: "form-actions",
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| {
                        problem.set(None);
                        reporting.set(true);
                    },
                    "Report a problem"
                }
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
                    "Report order {short} as {super::reputation_view::category_label(&category)}? \
                     It goes on the seller's public record for good, showing that choice, the \
                     order's reference and the month, with no names or messages. You can't \
                     withdraw it, and there's one per order."
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
                    "Report it"
                }
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| chosen.set(None),
                    "Go back"
                }
            },
            None => rsx! {
                p { strong { "{COMPLAINT_LINE}" } }
                // The way to message the seller, right here: the line asks for
                // it, and a buyer with a paid order needs no Ghost Key for it.
                match (message_to.clone(), shared) {
                    // On Purchases: open the store's one conversation, above
                    // the orders, and go to it.
                    (Some((_, tag)), Some(super::message_view::BuyerOpenThread(mut open))) => rsx! {
                        div { class: "form-actions",
                            button {
                                class: "btn btn-sm btn-primary",
                                onclick: move |_| {
                                    open.set(Some(tag));
                                    super::scroll_to_id(super::message_view::buyer_thread_dom_id(&tag));
                                },
                                "Message the seller"
                            }
                        }
                    },
                    // Elsewhere (a kept purchase's row): inline, with the
                    // thread, so what was just sent shows here (U6).
                    (Some((store_contract_id, tag)), None) => rsx! {
                        if messaging() {
                            super::message_view::OrderThreadInline { store_contract_id, tag }
                        } else {
                            div { class: "form-actions",
                                button {
                                    class: "btn btn-sm btn-primary",
                                    onclick: move |_| messaging.set(true),
                                    "Message the seller"
                                }
                            }
                        }
                    },
                    // No conversation held here: the line still says to
                    // message the seller first, so say where (msg1 critique
                    // MSG-11).
                    // Said as it is: this order's conversation is not on this
                    // device, so a question from the store page starts a new
                    // one, which needs a Ghost Key (review after b9c727f).
                    (None, _) => rsx! {
                        p { class: "text-muted small",
                            if paid_there {
                                "This order's messages aren't on this device. You can message the \
                                 seller from their store page, in your conversation about another \
                                 order there."
                            } else {
                                "This order's messages aren't on this device. You can ask the \
                                 seller a new question from their store page; that needs a Ghost Key."
                            }
                        }
                        if let Some(id) = store_page.clone().filter(|_| {
                            super::app::ROUTE() != super::app::Route::Store
                        }) {
                            div { class: "form-actions",
                                button {
                                    class: "btn btn-sm btn-primary",
                                    onclick: move |_| super::app::open_store_page(id.clone()),
                                    "Open their store"
                                }
                            }
                        }
                    },
                }
                h4 { class: "complaint-question", "What went wrong?" }
                div { class: "form-actions",
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
                    button {
                        class: "link-btn",
                        onclick: move |_| {
                            reporting.set(false);
                            messaging.set(false);
                        },
                        "Not now"
                    }
                }
                // Mockup D4's answer to what a new buyer actually asks.
                p { class: "text-muted small",
                    "Harvest can't refund you: the payment went straight to the seller. The \
                     record warns future buyers."
                }
            },
        }
    }
}

/// Said on the complaint step before any category (Ian, 2026-09-30).
pub(crate) const COMPLAINT_LINE: &str =
    "Complaints are permanent and can't be withdrawn. Message the seller first.";

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

    /// The store page to send the buyer to when no conversation is held here
    /// (msg1 critique MSG-11): the purchase's store, or for a kept purchase
    /// a loaded store under its key.
    fn store_page(&self, state: &crate::state::AppState) -> Option<Vec<u8>> {
        match self {
            Self::AtStore {
                store_contract_id, ..
            } => Some(store_contract_id.clone()),
            Self::Kept { store_key, .. } => state
                .browsing_stores
                .iter()
                .filter(|(_, store)| store.owner == Some(*store_key))
                .map(|(id, _)| id.clone())
                .min(),
        }
    }

    /// Where the buyer can message the seller about this purchase: its store
    /// (loaded on this page) and the conversation it is filed under, when this
    /// node still holds that conversation. For a kept purchase, the loaded
    /// store whose key it is kept under, if any; otherwise nowhere to offer.
    fn conversation(&self, state: &crate::state::AppState) -> Option<(Vec<u8>, [u8; 32])> {
        let (store_contract_id, tag) = match self {
            Self::AtStore {
                store_contract_id,
                purchase,
            } => (store_contract_id.clone(), purchase.conversation),
            Self::Kept {
                store_key,
                order_id,
            } => {
                let kept = state
                    .kept_purchases
                    .iter()
                    .find(|k| k.store_key == *store_key && k.order.order.id == *order_id)?;
                // The loaded store under this key that holds the kept
                // conversation, not merely the first under the key: a store
                // migrated to a new generation has more than one entry.
                let (id, _) = state.browsing_stores.iter().find(|(_, store)| {
                    store.owner == Some(*store_key)
                        && store
                            .conversations
                            .iter()
                            .any(|conversation| conversation.buyer_public_key == kept.conversation)
                })?;
                (id.clone(), kept.conversation)
            }
        };
        state
            .browsing_stores
            .get(&store_contract_id)?
            .conversations
            .iter()
            .any(|conversation| conversation.buyer_public_key == tag)
            .then_some((store_contract_id, tag))
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
        .describe(
            tip_height,
            order.status,
            crate::state::now_ms(),
            crate::fulfilment::Reader::Buyer,
        )
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
                    "The buyer pressed Buy now while your store couldn't answer. An order you answer "
                    "here shows under your orders once it is paid, and is not taken off your count "
                    "for you: if you count this listing, lower the count yourself once it is paid."
                }
            }
            div { class: "form-group",
                label { class: "form-label",
                    "Amount for {quantity} x {listing_title} (satoshis)"
                }
                // Fixed for a Buy now answer: the buyer's app pays only the
                // total they agreed to (`PaymentBlocker::AmountNotAsked`), so
                // any other amount would publish an order nobody can pay.
                input {
                    class: "form-input field-num",
                    // Text with a numeric keyboard, as every other number
                    // field: a number input's spinner eats the width.
                    r#type: "text",
                    inputmode: "numeric",
                    readonly: instant.is_some(),
                    value: "{amount}",
                    oninput: move |event| amount.set(event.value()),
                }
                if instant.is_some() {
                    p { class: "text-muted small",
                        "The total the buyer agreed to when they pressed Buy now. Their app pays no "
                        "other amount."
                    }
                }
            }
            div { class: "form-group",
                label { class: "form-label", "Confirmations required" }
                input {
                    class: "form-input field-count",
                    r#type: "text",
                    inputmode: "numeric",
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
    /// The seller got this order wrong; a new order (the buyer buys again,
    /// or asks the seller) puts it right.
    AskTheSeller,
    /// Only a new request can put this right: the order answers a request
    /// that did not carry what it lacks, and a seller reissuing it would copy
    /// the same gap from the same request. Sending the request again from
    /// this build carries it (round-3 review of harvest#136).
    AskAgain,
    /// Only a new Buy now can put this right: this order's terms are not
    /// what was agreed, and its id cannot take other terms.
    BuyAgain,
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
        // A Buy now order's id comes from its request, and the store merges
        // only upwards, so the seller cannot put these right under this id:
        // a new Buy now gets a new order.
        PaymentBlocker::AmountNotAsked { .. } => Remedy::BuyAgain,
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

    /// **A purchase the Buy now form shows keeps its conversation with its
    /// orders** (codex, round 2 of #205): its card is left out, not its
    /// conversation, so the thread is not lost or taken for a question.
    /// Red grouping only the purchases listed.
    #[test]
    fn a_purchase_shown_in_the_buy_form_keeps_its_conversation() {
        let purchase = |n: u8, conversation: u8| BuyerPurchase {
            order_id: harvest_common::payment::OrderId([n; 32]),
            conversation: [conversation; 32],
            commitment: None,
            blockers: Vec::new(),
            paid: None,
        };
        let all = [purchase(1, 5), purchase(2, 6), purchase(3, 6)];
        let above = [harvest_common::payment::OrderId([1; 32])];
        let groups = purchase_groups(&all, &above);
        assert_eq!(
            groups
                .iter()
                .map(|(tag, cards)| (tag[0], cards.len()))
                .collect::<Vec<_>>(),
            vec![(5, 0), (6, 2)]
        );
    }

    /// **The complaint step's "Message the seller" goes to the purchase's
    /// own conversation**, and only where this node holds it: at a loaded
    /// store, and for a kept purchase, at the store under its key that holds
    /// the kept conversation (not merely the first under that key). Red with
    /// `conversation` returning None, and with the kept lookup picking the
    /// first store under the key.
    #[test]
    fn the_complaint_step_messages_the_purchases_own_conversation() {
        let key = [4u8; 32];
        let held = crate::messaging::BuyerConversation::open(&[9u8; 32]).expect("open");
        let tag = held.buyer_public_key;
        let mut state = crate::state::AppState::default();
        // An older generation of the store under the same key, without the
        // conversation, and the current one with it.
        let old_generation = crate::state::BrowsingStore {
            owner: Some(key),
            ..Default::default()
        };
        let current = crate::state::BrowsingStore {
            owner: Some(key),
            conversations: vec![held],
            ..Default::default()
        };
        // Several, so a lookup taking the first store under the key (in
        // hash order) almost never lands on the right one by luck.
        for generation in 10u8..20 {
            state
                .browsing_stores
                .insert(vec![generation; 32], old_generation.clone());
        }
        state.browsing_stores.insert(vec![2u8; 32], current);
        let purchase = |conversation: [u8; 32]| BuyerPurchase {
            order_id: harvest_common::payment::OrderId([7; 32]),
            conversation,
            commitment: None,
            blockers: Vec::new(),
            paid: None,
        };
        let at_store = |conversation| ComplaintTarget::AtStore {
            store_contract_id: vec![2u8; 32],
            purchase: Box::new(purchase(conversation)),
        };
        assert_eq!(
            at_store(tag).conversation(&state),
            Some((vec![2u8; 32], tag))
        );
        assert_eq!(
            at_store([3u8; 32]).conversation(&state),
            None,
            "not held here"
        );

        let kept_order = harvest_common::payment::AuthorizedOrder {
            order: harvest_common::payment::Order {
                request_id: None,
                id: harvest_common::payment::OrderId([7; 32]),
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
                created_at: chrono::Utc::now(),
            },
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status: harvest_common::payment::OrderStatus::Paid,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        };
        state
            .kept_purchases
            .push(harvest_common::delegate::KeptPurchase {
                store_key: key,
                conversation: tag,
                receipt_seed: [0; 32],
                order: kept_order,
                complaint: None,
            });
        let kept = ComplaintTarget::Kept {
            store_key: key,
            order_id: harvest_common::payment::OrderId([7; 32]),
        };
        assert_eq!(kept.conversation(&state), Some((vec![2u8; 32], tag)));
    }

    /// No "waiting for your payment" above a line saying not to pay it
    /// (round 3 of harvest#187). Red without the check.
    #[test]
    fn a_purchase_not_to_pay_has_no_waiting_headline() {
        let order = harvest_common::payment::AuthorizedOrder {
            order: harvest_common::payment::Order {
                request_id: None,
                id: harvest_common::payment::OrderId([0u8; 32]),
                buyer_fingerprint: String::new(),
                seller_fingerprint: "me".into(),
                amount_sats: 2,
                network: freenet_bitcoin_common::BitcoinNetwork::Signet,
                payment_script_pubkey: vec![0x00, 0x14, 1],
                payment_address: "tb1qtest".into(),
                required_confirmations: 1,
                payment_hash: None,
                trusted_bridges: Vec::new(),
                bitcoin_address_code_hash: None,
                anchor: None,
                order_binding: None,
                listing_tag: None,
                buyer_receipt_key: None,
                created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            }
            .with_derived_id(),
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status: harvest_common::payment::OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        };
        let mut purchase = BuyerPurchase {
            order_id: order.order.id.clone(),
            conversation: [0; 32],
            commitment: Some(order),
            blockers: Vec::new(),
            paid: None,
        };
        assert_eq!(
            purchase_headline(&purchase),
            Some("Order placed, waiting for your payment.")
        );
        purchase.blockers = vec![PaymentBlocker::AmountNotAsked {
            asked_sats: 1,
            order_sats: 2,
        }];
        assert_eq!(purchase_headline(&purchase), None);
    }

    /// "Your purchases" leaves out every order a Buy now form is showing, and
    /// only those: two forms open on two listings each hide their own
    /// (codex and review round 1 of harvest#187). Red with a single slot.
    #[test]
    fn purchases_shown_under_a_form_are_not_listed_again() {
        let purchase = |seed: u8| BuyerPurchase {
            order_id: harvest_common::payment::OrderId([seed; 32]),
            conversation: [0; 32],
            commitment: None,
            blockers: Vec::new(),
            paid: None,
        };
        let all = vec![purchase(1), purchase(2), purchase(3)];
        let ids = |list: Vec<&BuyerPurchase>| -> Vec<u8> {
            list.iter().map(|p| p.order_id.0[0]).collect()
        };
        assert_eq!(ids(purchases_to_list(&all, &[])), vec![1, 2, 3]);
        let two_forms = [all[0].order_id.clone(), all[2].order_id.clone()];
        assert_eq!(ids(purchases_to_list(&all, &two_forms)), vec![2]);
        let elsewhere = [harvest_common::payment::OrderId([9; 32])];
        assert_eq!(ids(purchases_to_list(&all, &elsewhere)), vec![1, 2, 3]);
    }

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

    /// A message with a digest of its own, as every real entry has.
    fn message(
        addressing: Addressing,
        content: MessageContent,
    ) -> crate::messaging::ConversationMessage {
        use std::sync::atomic::{AtomicU8, Ordering};
        static NEXT: AtomicU8 = AtomicU8::new(1);
        crate::messaging::ConversationMessage {
            addressing,
            timestamp: chrono::Utc::now(),
            nonce: [0u8; 24],
            digest: [NEXT.fetch_add(1, Ordering::Relaxed); 32],
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
        assert_eq!(seller_answers(&thread).len(), 2);
    }

    fn order(
        status: harvest_common::payment::OrderStatus,
        buy_now: bool,
    ) -> harvest_common::payment::AuthorizedOrder {
        harvest_common::payment::AuthorizedOrder {
            order: harvest_common::payment::Order {
                request_id: buy_now.then_some([4; 32]),
                id: harvest_common::payment::OrderId([1; 32]),
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

    fn purchase(
        commitment: Option<harvest_common::payment::AuthorizedOrder>,
        blockers: Vec<PaymentBlocker>,
    ) -> BuyerPurchase {
        BuyerPurchase {
            order_id: harvest_common::payment::OrderId([1; 32]),
            conversation: [2; 32],
            commitment,
            blockers,
            paid: None,
        }
    }

    /// The buyer's cap is counted the way the seller's store counts it:
    /// unpaid Buy now orders still open. Paid, cancelled, too old to pay, and
    /// orders the seller issued by hand do not count. Mutated red by dropping
    /// each filter in turn.
    #[test]
    fn a_buyers_unpaid_orders_are_counted_like_the_stores_cap() {
        use harvest_common::payment::OrderStatus;
        let open = purchase(Some(order(OrderStatus::AwaitingPayment, true)), vec![]);
        // Paid by what this node holds, while the store still reads unpaid.
        let mut paid = purchase(Some(order(OrderStatus::AwaitingPayment, true)), vec![]);
        paid.paid = Some(order(OrderStatus::Paid, true));
        let cancelled = purchase(
            Some(order(OrderStatus::Cancelled, true)),
            vec![PaymentBlocker::NotAwaitingPayment(OrderStatus::Cancelled)],
        );
        let stale = purchase(
            Some(order(OrderStatus::AwaitingPayment, true)),
            vec![PaymentBlocker::AnchorStale {
                anchor_height: 1,
                tip_height: 100,
            }],
        );
        let by_hand = purchase(Some(order(OrderStatus::AwaitingPayment, false)), vec![]);
        let unpublished = purchase(None, vec![PaymentBlocker::CommitmentNotPublished]);
        assert_eq!(open_unpaid_orders(std::slice::from_ref(&open)), 1);
        assert_eq!(
            open_unpaid_orders(&[paid, cancelled, stale, by_hand, unpublished]),
            0
        );
        // Only the conversation the Buy now goes out in counts. Mutated red
        // by counting every conversation.
        let mut elsewhere = open.clone();
        elsewhere.conversation = [9; 32];
        assert_eq!(
            unpaid_in_conversation(&[open.clone(), elsewhere], Some([2; 32])),
            1
        );
        assert_eq!(unpaid_in_conversation(std::slice::from_ref(&open), None), 0);
        let at_cap = vec![open; harvest_common::delegate::MAX_UNPAID_INSTANT_PER_BUYER];
        assert_eq!(
            open_unpaid_orders(&at_cap),
            harvest_common::delegate::MAX_UNPAID_INSTANT_PER_BUYER
        );
    }

    /// Placed and waiting, then paid; nothing for a settled order, whose card
    /// says what happened. Mutated red by swapping the two lines.
    #[test]
    fn a_purchase_reads_placed_then_paid() {
        use harvest_common::payment::OrderStatus;
        let waiting = purchase(Some(order(OrderStatus::AwaitingPayment, true)), vec![]);
        assert_eq!(
            purchase_headline(&waiting),
            Some("Order placed, waiting for your payment.")
        );
        let mut paid = purchase(
            Some(order(OrderStatus::Paid, true)),
            vec![PaymentBlocker::NotAwaitingPayment(OrderStatus::Paid)],
        );
        paid.paid = Some(order(OrderStatus::Paid, true));
        assert_eq!(purchase_headline(&paid), Some("Paid."));
        let cancelled = purchase(
            Some(order(OrderStatus::Cancelled, true)),
            vec![PaymentBlocker::NotAwaitingPayment(OrderStatus::Cancelled)],
        );
        assert_eq!(purchase_headline(&cancelled), None);
    }

    /// The newest answer after the ones already there when the order went
    /// out: nothing yet, then a decline with its reason, or an acceptance.
    /// An answer that was already in the thread is not mistaken for this
    /// order's. Mutated red by dropping the `skip`.
    #[test]
    fn the_answer_shown_is_the_newest_one_after_the_order_went_out() {
        let accepted = MessageContent::OrderAccepted {
            order_id: harvest_common::payment::OrderId([1u8; 32]),
        };
        let ours = harvest_common::payment::OrderId([1u8; 32]);
        // An earlier order's acceptance, already in the thread.
        let earlier = MessageContent::OrderAccepted {
            order_id: harvest_common::payment::OrderId([3u8; 32]),
        };
        let mut thread = vec![message(Addressing::ToBuyer, earlier)];
        let before = seller_answers(&thread);
        assert_eq!(latest_answer(&thread, &before, Some(&ours)), None);
        thread.push(message(Addressing::ToSeller, accepted.clone()));
        thread.push(message(
            Addressing::ToBuyer,
            MessageContent::Text("Hi".into()),
        ));
        assert_eq!(latest_answer(&thread, &before, Some(&ours)), None);
        thread.push(message(
            Addressing::ToBuyer,
            MessageContent::Decline {
                reason: harvest_common::delegate::TOO_MANY_UNPAID.into(),
            },
        ));
        assert_eq!(
            latest_answer(&thread, &before, Some(&ours)),
            Some(Answer::Declined(
                harvest_common::delegate::TOO_MANY_UNPAID.into()
            ))
        );
        // Another request's acceptance is not this one's.
        let theirs = MessageContent::OrderAccepted {
            order_id: harvest_common::payment::OrderId([2u8; 32]),
        };
        thread.push(message(Addressing::ToBuyer, theirs));
        assert_eq!(
            latest_answer(&thread, &before, Some(&ours)),
            Some(Answer::Declined(
                harvest_common::delegate::TOO_MANY_UNPAID.into()
            )),
            "not taken for ours"
        );
        thread.push(message(Addressing::ToBuyer, accepted.clone()));
        assert_eq!(
            latest_answer(&thread, &before, Some(&ours)),
            Some(Answer::Accepted)
        );
        // Found wherever it sorts: a reply dated by a slower seller clock
        // lands before the answers there at send. Mutated red by skipping by
        // position again.
        let old = message(
            Addressing::ToBuyer,
            MessageContent::OrderAccepted {
                order_id: harvest_common::payment::OrderId([3u8; 32]),
            },
        );
        let at_send = seller_answers(std::slice::from_ref(&old));
        let early = vec![message(Addressing::ToBuyer, accepted), old.clone()];
        assert_eq!(
            latest_answer(&early, &at_send, Some(&ours)),
            Some(Answer::Accepted)
        );
        let declined_early = vec![
            message(
                Addressing::ToBuyer,
                MessageContent::Decline {
                    reason: "Sold out".into(),
                },
            ),
            old,
        ];
        assert_eq!(
            latest_answer(&declined_early, &at_send, Some(&ours)),
            Some(Answer::Declined("Sold out".into()))
        );
        // A decline that was already there when this order went out is not
        // this order's. Mutated red by dropping the digest filter.
        let old_decline = message(
            Addressing::ToBuyer,
            MessageContent::Decline {
                reason: "Only 1 left".into(),
            },
        );
        let at_send = seller_answers(std::slice::from_ref(&old_decline));
        assert_eq!(latest_answer(&[old_decline], &at_send, Some(&ours)), None);
    }
}
