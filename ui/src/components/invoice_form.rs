//! Issuing invoices: the seller's payment key, and the form that turns a
//! listing into a signed order on their store contract.
//!
//! # Why the seller issues the invoice
//!
//! `AuthorizedOrder::verify_terms` checks a ghostkey-scoped SELLER signature
//! over the whole `Order`, so a buyer cannot create one -- "buyer clicks Buy"
//! needs buyer-to-seller messaging, which is a separate decision. A seller
//! handing over an invoice needs nothing that does not already exist, and it
//! is how a small seller works anyway: here is what you owe, here is where to
//! pay it.
//!
//! # What the seller has to be told, and is
//!
//! **An invoice reaches Paid only while a bridge is watching its address, and
//! that watch has to be kept alive.** Harvest asks the bridge through its
//! request inbox when the invoice is issued, and renews the request while the
//! seller has Harvest open (`AppState::queue_due_watch_requests`). The bridge
//! drops a watch about a day after the request that last asked for it, and it
//! does not look back over blocks it scanned while not watching
//! (freenet-bitcoin#7), so a payment made during a lapse is never picked up.
//! [`PaymentWatchNote`] says that, because otherwise an invoice stuck at
//! "Awaiting payment" would read as a payment that never came.

use dioxus::prelude::*;
use freenet_bitcoin_common::BitcoinNetwork;
use harvest_common::listing::{AuthorizedListing, ListingId};

use crate::gateway::{bitcoin_config, bitcoin_ops, APP_STATE};
use crate::state::PendingInvoice;

/// The networks the picker offers.
///
/// Exactly the ones this build can settle a payment on
/// ([`bitcoin_config::settleable_networks`]), not every network Bitcoin has.
/// Offering the others would let a seller file a mainnet key and issue
/// real-money invoices naming a bridge that watches signet: they would look
/// entirely normal and could never be shown to have been paid, which is the
/// failure mode `bitcoin_config`'s own header exists to prevent.
///
/// `order_for_invoice` refuses such a network too, so this is the second of
/// two gates rather than the only one -- but a choice that always fails at
/// submit is a worse way to learn than one that is not offered.
fn offered_networks() -> &'static [BitcoinNetwork] {
    bitcoin_config::settleable_networks()
}

/// The seller-side payments panel for one store: the payment key, the form
/// that issues an invoice against a listing, and the invoices already issued.
#[component]
pub fn StorePayments(store_contract_id: Vec<u8>, seller_fingerprint: String) -> Element {
    let mut show_form = use_signal(|| false);

    let (xpub, xpub_loaded, store_loaded, listings, orders, live, needs_reissue) = {
        let state = APP_STATE.read();
        let store = state.browsing_stores.get(&store_contract_id);
        let mine = invoices_issued_by(
            store.map(|s| s.orders.as_slice()).unwrap_or_default(),
            &seller_fingerprint,
        );
        // Decided once, here, against this node's own view of the chain --
        // the same read `payment_blockers` makes on the buyer's side, so the
        // two cannot disagree about whether an order has aged out.
        let needs_reissue: std::collections::HashSet<harvest_common::payment::OrderId> = mine
            .iter()
            .filter(|order| state.needs_reissue(order))
            .map(|order| order.order.id.clone())
            .collect();
        (
            state.bitcoin.payment_xpub.clone(),
            state.bitcoin.payment_xpub_loaded,
            // "No listings" and "this store's state has not arrived" look
            // identical through an `unwrap_or_default`, and telling a seller to
            // add a listing they already have -- while hiding the button that
            // would let them invoice it -- is the same trap `publish_store_details`
            // documents at length for the store's version number.
            state.store_details_are_resolved(&store_contract_id),
            store.map(|s| s.listings.clone()).unwrap_or_default(),
            mine,
            // Cloned once outside the render loop below; taking a fresh read
            // guard per order would be a borrow per row for no gain.
            state.bitcoin.clone(),
            needs_reissue,
        )
    };

    rsx! {
        div { class: "card",
            h4 { "Payments" }

            PaymentKeyPanel { xpub: xpub.clone(), xpub_loaded }

            if xpub.is_some() {
                if !store_loaded {
                    p { class: "text-muted text-italic",
                        "Loading this store's listings\u{2026}"
                    }
                } else if listings.is_empty() {
                    p { class: "text-muted text-italic",
                        "Add a listing first \u{2014} an invoice is issued against one, so a \
                         buyer can see what they are paying for."
                    }
                } else {
                    button {
                        class: if show_form() { "btn btn-sm btn-outline" } else { "btn btn-sm btn-primary" },
                        onclick: move |_| show_form.toggle(),
                        if show_form() { "Cancel" } else { "Issue an invoice" }
                    }
                    if show_form() {
                        InvoiceForm {
                            store_contract_id: store_contract_id.clone(),
                            seller_fingerprint: seller_fingerprint.clone(),
                            listings: listings.clone(),
                            on_submitted: move |_| show_form.set(false),
                        }
                    }
                }
            }

            if !orders.is_empty() {
                p { class: "section-count", "{orders.len()} invoice(s) issued" }
                PaymentWatchNote {}
                for order in orders.iter() {
                    // One keyed node per invoice, wrapping both, because a
                    // `key` is only honoured on the first node of a block.
                    div { key: "{order.order.id}",
                        // Said above the card rather than inside it, because
                        // it is about what the SELLER should do and
                        // `OrderCard` is shared with the buyer's view. An
                        // order's anchor is fixed at signing, so an unpaid
                        // one eventually stops being payable -- and without
                        // this the only party who can fix that never learns
                        // of it.
                        if needs_reissue.contains(&order.order.id) {
                            p { class: "text-warning",
                                "Invoice {order.order.id.short()} has expired: it is anchored "
                                "to a Bitcoin block too old for a buyer's software to accept, "
                                "so nobody can pay it now. Issue it again if the buyer still "
                                "wants it."
                            }
                        }
                        super::bitcoin_view::OrderCard {
                            order: order.clone(),
                            live: super::bitcoin_view::live_address_for_order(&live, &order.order),
                        }
                        if order.status == harvest_common::payment::OrderStatus::AwaitingPayment {
                            CancelInvoice {
                                store_contract_id: store_contract_id.clone(),
                                order_id: order.order.id.clone(),
                            }
                        }
                        if order.status == harvest_common::payment::OrderStatus::Paid {
                            MarkDespatched {
                                store_contract_id: store_contract_id.clone(),
                                order_id: order.order.id.clone(),
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The seller's control to cancel one unpaid invoice (harvest#53).
///
/// Two steps, because the second one is permanent: a cancellation cannot be
/// withdrawn, and the confirmation says the one thing a seller might not
/// expect -- that a payment already on its way still counts.
///
/// Offered for an unpaid invoice whether or not its payment window has
/// closed. A lapsed invoice needs no cancelling, but saying so in public
/// costs nothing and is what a stranger reading the store can see without
/// a chain tip of their own.
#[component]
fn CancelInvoice(
    store_contract_id: Vec<u8>,
    order_id: harvest_common::payment::OrderId,
) -> Element {
    let mut confirming = use_signal(|| false);
    let mut problem = use_signal(|| Option::<String>::None);
    let (pending, sent, unsignable) = {
        let state = APP_STATE.read();
        (
            state.cancellation_pending(&store_contract_id, &order_id),
            state.cancellation_sent(&store_contract_id, &order_id),
            state.store_key_refusal(&store_contract_id),
        )
    };
    let short = order_id.short();

    if pending {
        return rsx! {
            p { class: "text-muted", "Cancelling invoice {short}\u{2026}" }
        };
    }
    // Said instead of a button the delegate would refuse: this device holds
    // no key that can sign for the store, as `MarkDespatched` does (#136
    // review, round 5).
    if let Some(why) = unsignable {
        return rsx! {
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "Invoice {short} cannot be cancelled from this device yet: {why}"
            }
        };
    }
    if sent {
        return rsx! {
            p { class: "text-muted",
                "Cancellation of invoice {short} sent. It shows here once the store has it."
            }
        };
    }
    rsx! {
        if let Some(why) = problem() {
            p { class: "text-warning", "{why}" }
        }
        if confirming() {
            p { class: "text-warning",
                "Cancel invoice {short}? This is public and cannot be undone. If the buyer "
                "has already paid, or pays anyway, their payment still counts and you owe "
                "them the goods."
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
                            .cancel_invoice(&store_contract_id, &order_id);
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
                "Cancel invoice"
            }
        }
    }
}

/// The seller's control to record that a paid order has been sent
/// (harvest#53 Phase B).
///
/// Two steps, like the cancel, because the record is public and permanent.
/// Hidden once a despatch of the order is on record
/// (`AppState::despatch_recorded`), read from the same source as the
/// card's stage line, which then says so.
#[component]
fn MarkDespatched(
    store_contract_id: Vec<u8>,
    order_id: harvest_common::payment::OrderId,
) -> Element {
    let mut confirming = use_signal(|| false);
    let mut problem = use_signal(|| Option::<String>::None);
    let (recorded, pending, sent, refusal) = {
        let state = APP_STATE.read();
        (
            state.despatch_recorded(&store_contract_id, &order_id),
            state.despatch_pending(&store_contract_id, &order_id),
            state.despatch_sent(&store_contract_id, &order_id),
            state.despatch_refusal(&store_contract_id, &order_id),
        )
    };
    let short = order_id.short();

    if recorded {
        return rsx! {};
    }
    if pending {
        return rsx! {
            p { class: "text-muted", "Recording the despatch of order {short}\u{2026}" }
        };
    }
    if sent {
        return rsx! {
            p { class: "text-muted",
                "Despatch of order {short} sent. It shows here once the store has it."
            }
        };
    }
    // Said instead of a button that would refuse when pressed: no store key
    // on this device, or no chain data recent enough to anchor it.
    if let Some(why) = refusal {
        return rsx! {
            p { class: "text-muted", style: "font-size: 0.85rem;",
                "Order {short} cannot be marked despatched yet: {why}"
            }
        };
    }
    rsx! {
        if let Some(why) = problem() {
            p { class: "text-warning", "{why}" }
        }
        if confirming() {
            p { class: "text-warning",
                "Mark order {short} as despatched? This is public and cannot be undone. Only "
                "do it once the goods are on their way."
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
                            .despatch_order(&store_contract_id, &order_id);
                        problem.set(result.err());
                    }
                },
                "Yes, it has been sent"
            }
            button {
                class: "btn btn-sm btn-outline",
                onclick: move |_| confirming.set(false),
                "Not yet"
            }
        } else {
            button {
                class: "btn btn-sm btn-primary",
                onclick: move |_| {
                    problem.set(None);
                    confirming.set(true);
                },
                "Mark despatched"
            }
        }
    }
}

/// The invoices on a store that THIS seller issued, newest first.
///
/// A store contract carries every order, and the seller's panel is about
/// their own. The filter is on `seller_fingerprint` rather than on ownership
/// of the store because the two can differ in exactly the case that matters:
/// a seller with more than one connected Ghost Key sees one panel per
/// identity, and showing another identity's invoices under this one would
/// invite them to act on an invoice they cannot cancel.
fn invoices_issued_by(
    orders: &[harvest_common::payment::AuthorizedOrder],
    seller_fingerprint: &str,
) -> Vec<harvest_common::payment::AuthorizedOrder> {
    let mut mine: Vec<_> = orders
        .iter()
        .filter(|o| o.order.seller_fingerprint == seller_fingerprint)
        .cloned()
        .collect();
    mine.sort_by_key(|o| std::cmp::Reverse(o.order.created_at));
    mine
}

/// What keeps an invoice's status honest, said wherever invoices are listed.
///
/// Shown to buyers too: a buyer about to pay is the one who loses out if the
/// seller has not opened Harvest in days.
#[component]
pub fn PaymentWatchNote() -> Element {
    rsx! {
        p { class: "text-warning",
            "Harvest asks a Bitcoin bridge to watch each invoice\u{2019}s address, and the "
            "invoice shows Paid once the bridge sees the payment confirmed. The seller\u{2019}s Harvest "
            "renews that request while it is open, and the bridge stops watching about a "
            "day after the last renewal. A payment made while it is not watching is not "
            "picked up later, so a seller waiting to be paid should open Harvest more than "
            "once a day."
        }
    }
}

/// Show the configured payment key, or take one.
#[component]
fn PaymentKeyPanel(xpub: Option<harvest_common::PaymentXpubStatus>, xpub_loaded: bool) -> Element {
    let mut editing = use_signal(|| false);

    // Not "no key configured" -- we have not asked yet. Prompting here would
    // tell a seller who already has one that they do not.
    if !xpub_loaded {
        return rsx! {
            p { class: "text-muted text-italic", "Checking your payment key\u{2026}" }
        };
    }

    rsx! {
        match xpub {
            Some(status) if !editing() => rsx! {
                p { class: "text-muted",
                    "Paying into your "
                    strong { "{status.network.as_str()}" }
                    " wallet. "
                    "{status.next_index} address(es) from this key are already taken, \
                     counting the orders your stores have published, so the next invoice \
                     gets a new one. "
                    "This key is shared by every store and every Ghost Key in this app."
                }
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| editing.set(true),
                    "Change payment key"
                }
            },
            _ => rsx! {
                PaymentKeyForm {
                    // Replacing a key restarts the address count, which is
                    // correct but worth saying out loud.
                    replacing: xpub.is_some(),
                    on_done: move |_| editing.set(false),
                }
            },
        }
    }
}

#[component]
fn PaymentKeyForm(replacing: bool, on_done: EventHandler<()>) -> Element {
    let mut xpub = use_signal(String::new);
    let mut network = use_signal(bitcoin_config::default_network);

    rsx! {
        div { class: "form-group",
            p {
                "Paste your wallet's "
                strong { "native SegWit (BIP-84) account public key" }
                ". It starts with "
                code { "zpub" }
                " on mainnet or "
                code { "vpub" }
                " on signet and testnet. Harvest derives a fresh receiving "
                "address from it for each invoice, so no address is ever reused."
            }
            p { class: "text-muted",
                "This is a "
                strong { "public" }
                " key: it can produce addresses and nothing else. Harvest never holds "
                "anything that could spend your coins: the key that can spend stays in "
                "your wallet, which is also what lets you spend what buyers send."
            }
            if replacing {
                p { class: "text-warning",
                    "Entering a DIFFERENT key starts its addresses from the beginning, which "
                    "is correct: addresses only mean anything relative to the key they come "
                    "from. Entering a key you have used before, here or on another device, "
                    "does not reuse its addresses: Harvest skips past every address your "
                    "stores' published orders already name. Either way, invoices you have "
                    "already issued are unaffected: they name an address, not a key."
                }
            }

            label { class: "form-label", "Account public key" }
            input {
                class: "form-input",
                r#type: "text",
                placeholder: "vpub…",
                value: "{xpub}",
                oninput: move |e| xpub.set(e.value()),
            }

            label { class: "form-label", "Network" }
            select {
                class: "form-input",
                value: "{network().as_str()}",
                onchange: move |e| {
                    if let Some(picked) =
                        offered_networks().iter().find(|n| n.as_str() == e.value())
                    {
                        network.set(*picked);
                    }
                },
                for option in offered_networks() {
                    option { value: "{option.as_str()}", "{option.as_str()}" }
                }
            }

            button {
                class: "btn btn-primary",
                disabled: xpub().trim().is_empty(),
                onclick: move |_| {
                    save_payment_key(xpub().trim().to_string(), network());
                    xpub.set(String::new());
                    on_done.call(());
                },
                "Save payment key"
            }
        }
    }
}

/// The invoice form proper: which listing, how much, and who for.
#[component]
fn InvoiceForm(
    store_contract_id: Vec<u8>,
    seller_fingerprint: String,
    listings: Vec<AuthorizedListing>,
    on_submitted: EventHandler<()>,
) -> Element {
    // Which listing, by its display id. `ListingId` is not a form value, so
    // the select carries its `Display` form and the submit looks it back up --
    // rather than carrying an index, which goes wrong the moment the listing
    // list changes under an open form.
    let first = listings
        .first()
        .map(|l| l.listing.id.to_string())
        .unwrap_or_default();
    let mut chosen = use_signal(|| first);
    let mut amount = use_signal(String::new);
    let mut buyer = use_signal(String::new);
    let mut confirmations = use_signal(|| "1".to_string());

    let parsed_amount = amount().trim().parse::<u64>().ok().filter(|n| *n > 0);
    let confirmations_read = parse_required_confirmations(&confirmations());
    let parsed_confirmations = confirmations_read.as_ref().ok().copied();
    let ready = parsed_amount.is_some() && parsed_confirmations.is_some();

    rsx! {
        div { class: "form-group",
            label { class: "form-label", "Listing" }
            select {
                class: "form-input",
                value: "{chosen}",
                onchange: move |e| chosen.set(e.value()),
                for listing in listings.iter() {
                    option {
                        value: "{listing.listing.id}",
                        "{listing.listing.title}"
                    }
                }
            }

            label { class: "form-label", "Amount (satoshis)" }
            input {
                class: "form-input",
                r#type: "text",
                placeholder: "50000",
                value: "{amount}",
                oninput: move |e| amount.set(e.value()),
            }
            if !amount().trim().is_empty() && parsed_amount.is_none() {
                p { class: "text-warning",
                    "Enter the amount as a whole number of satoshis, greater than zero."
                }
            }

            label { class: "form-label", "Buyer's Ghost Key fingerprint (optional)" }
            input {
                class: "form-input",
                r#type: "text",
                placeholder: "leave blank for an invoice anyone with the link may pay",
                value: "{buyer}",
                oninput: move |e| buyer.set(e.value()),
            }
            p { class: "text-muted",
                "Naming a buyer records who the invoice was issued to. It does not stop "
                "somebody else paying it \u{2014} Bitcoin has no way to tell who sent a "
                "payment \u{2014} so treat it as a label, not a restriction."
            }

            label { class: "form-label", "Confirmations required" }
            input {
                class: "form-input",
                r#type: "text",
                value: "{confirmations}",
                oninput: move |e| confirmations.set(e.value()),
            }
            if let Err(why) = confirmations_read {
                p { class: "text-warning", "{why}" }
            }

            PaymentWatchNote {}

            button {
                class: "btn btn-primary",
                disabled: !ready,
                onclick: {
                    let store_contract_id = store_contract_id.clone();
                    let seller_fingerprint = seller_fingerprint.clone();
                    let listings = listings.clone();
                    move |_| {
                        let Some(listing) = listings
                            .iter()
                            .find(|l| l.listing.id.to_string() == chosen())
                        else {
                            APP_STATE.write().notifications.push(
                                "That listing is no longer on this store \u{2014} pick another."
                                    .to_string(),
                            );
                            return;
                        };
                        // Both parse successfully or the button is disabled;
                        // re-checked rather than unwrapped so a future change
                        // to `ready` cannot turn into a panic.
                        let (Some(amount_sats), Some(required_confirmations)) =
                            (parsed_amount, parsed_confirmations)
                        else {
                            return;
                        };
                        issue_invoice(PendingInvoice {
                            store_contract_id: store_contract_id.clone(),
                            seller_fingerprint: seller_fingerprint.clone(),
                            listing_id: listing.listing.id.clone(),
                            listing_title: listing.listing.title.clone(),
                            buyer_fingerprint: buyer().trim().to_string(),
                            amount_sats,
                            required_confirmations,
                            // This form writes an invoice from scratch. One
                            // answering a buyer's request is issued from the
                            // inbox, which is where the conversation to reply
                            // into is known -- and where the buyer's binding
                            // is. An invoice with no binding matches no
                            // buyer's check, so it is payable only by
                            // somebody following the address by hand, which
                            // is what this form is for.
                            reply_to: None,
                            order_binding: None,
                            // Nor a buyer's receipt key (harvest#53 Phase B):
                            // no buyer asked, so nobody can cancel it but the
                            // seller or complain about it.
                            buyer_receipt_key: None,
                        });
                        amount.set(String::new());
                        buyer.set(String::new());
                        on_submitted.call(());
                    }
                },
                "Issue invoice"
            }
        }
    }
}

fn save_payment_key(xpub: String, network: BitcoinNetwork) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = bitcoin_ops::set_payment_xpub(xpub, network).await {
            dioxus::logger::tracing::error!("Failed to send the payment key: {e}");
            APP_STATE
                .write()
                .notifications
                .push(format!("Could not save your payment key: {e}"));
        }
    });
    #[cfg(not(target_arch = "wasm32"))]
    let _ = (xpub, network, bitcoin_ops::set_payment_xpub);
}

/// Start issuing an invoice, and say why if nothing happens.
///
/// `AppState::issue_invoice` owns every check -- the store has to be one of
/// ours, signed by the identity that owns it, for a real amount, with a
/// payment key set -- so this is only the reporting.
fn issue_invoice(invoice: PendingInvoice) {
    let title = invoice.listing_title.clone();
    let outcome = APP_STATE.write().issue_invoice(invoice);
    match outcome {
        Ok(()) => APP_STATE
            .write()
            .notifications
            .push(format!("Issuing an invoice for '{title}'\u{2026}")),
        Err(e) => {
            dioxus::logger::tracing::error!("Could not issue an invoice: {e}");
            APP_STATE
                .write()
                .notifications
                .push(format!("Could not issue an invoice: {e}"));
        }
    }
}

/// The confirmations a seller typed, or why an order may not require that
/// many. Shared by this form and the accept control in `buy_view`, so both
/// refuse the same values.
///
/// At least one: accepting zero would count a payment as settled while it is
/// still only in the mempool. At most
/// [`harvest_common::payment::MAX_REQUIRED_CONFIRMATIONS`]: an order needing
/// more could not read as paid in time for a complaint about it, so buyers'
/// software refuses to pay it (`docs/complaint-threat-model.md` section 4).
pub(crate) fn parse_required_confirmations(input: &str) -> Result<u32, String> {
    use harvest_common::payment::MAX_REQUIRED_CONFIRMATIONS;
    match input.trim().parse::<u32>() {
        Ok(n) if n > MAX_REQUIRED_CONFIRMATIONS => Err(format!(
            "At most {MAX_REQUIRED_CONFIRMATIONS} confirmations, about a day of blocks. An \
             order needing more could not count as paid in time for a buyer to complain about \
             it, so buyers will not pay it."
        )),
        Ok(n) if n > 0 => Ok(n),
        _ => Err(
            "At least one confirmation. Accepting zero would count a payment as settled \
             while it is still only in the mempool, where it can still be replaced."
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use harvest_common::payment::{AuthorizedOrder, Order, OrderId, OrderStatus};

    fn order(seller: &str, minutes: i64) -> AuthorizedOrder {
        let created_at =
            chrono::DateTime::from_timestamp(1_700_000_000 + minutes * 60, 0).expect("timestamp");
        AuthorizedOrder {
            order: Order {
                request_id: None,
                derivation: None,
                id: OrderId([0u8; 32]),
                buyer_fingerprint: "buyer".to_string(),
                seller_fingerprint: seller.to_string(),
                amount_sats: 1_000,
                network: BitcoinNetwork::Signet,
                payment_script_pubkey: vec![0x00, 0x14, minutes as u8],
                payment_address: format!("tb1qexample{minutes}"),
                required_confirmations: 1,
                payment_hash: None,
                trusted_bridges: Vec::new(),
                bitcoin_address_code_hash: None,
                anchor: None,
                order_binding: None,
                listing_tag: None,
                buyer_receipt_key: None,
                created_at,
            }
            .with_derived_id(),
            scoped_payload: Vec::new(),
            signature: Vec::new(),
            status: OrderStatus::AwaitingPayment,
            payment_proof: None,
            status_scoped_payload: None,
            status_signature: None,
        }
    }

    /// A store contract carries every order it has ever seen. A seller's panel
    /// showing another identity's invoices would offer them actions on an
    /// invoice they cannot sign for.
    #[test]
    fn a_sellers_panel_shows_only_their_own_invoices() {
        let orders = vec![order("me", 1), order("someone-else", 2), order("me", 3)];

        let mine = invoices_issued_by(&orders, "me");

        assert_eq!(mine.len(), 2);
        assert!(mine.iter().all(|o| o.order.seller_fingerprint == "me"));
    }

    /// Newest first: the invoice a seller just issued is the one they are
    /// looking for.
    #[test]
    fn invoices_are_listed_newest_first() {
        let orders = vec![order("me", 1), order("me", 3), order("me", 2)];

        let mine = invoices_issued_by(&orders, "me");

        let addresses: Vec<&str> = mine
            .iter()
            .map(|o| o.order.payment_address.as_str())
            .collect();
        assert_eq!(
            addresses,
            vec!["tb1qexample3", "tb1qexample2", "tb1qexample1"]
        );
    }

    #[test]
    fn a_seller_with_no_invoices_gets_an_empty_list() {
        assert!(invoices_issued_by(&[], "me").is_empty());
        assert!(invoices_issued_by(&[order("someone-else", 1)], "me").is_empty());
    }

    /// **The seller's forms refuse what a buyer would refuse to pay**
    /// (`docs/complaint-threat-model.md` section 4, TM-C): zero, and more
    /// than `MAX_REQUIRED_CONFIRMATIONS`, each with a reason. Red if either
    /// bound is dropped.
    #[test]
    fn the_confirmations_input_refuses_zero_and_more_than_the_cap() {
        use harvest_common::payment::MAX_REQUIRED_CONFIRMATIONS;
        assert_eq!(parse_required_confirmations(" 1 "), Ok(1));
        assert_eq!(
            parse_required_confirmations(&MAX_REQUIRED_CONFIRMATIONS.to_string()),
            Ok(MAX_REQUIRED_CONFIRMATIONS)
        );
        let too_many = parse_required_confirmations(&(MAX_REQUIRED_CONFIRMATIONS + 1).to_string())
            .expect_err("over the cap");
        assert!(too_many.contains("At most 144"), "{too_many}");
        for refused in ["0", "", "two", "-1"] {
            let why = parse_required_confirmations(refused).expect_err(refused);
            assert!(why.contains("At least one"), "{refused}: {why}");
        }
    }
}
