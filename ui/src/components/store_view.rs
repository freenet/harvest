use dioxus::prelude::*;
use harvest_common::listing::{AuthorizedListing, ListingKind, PriceInfo};

use crate::gateway::APP_STATE;

#[component]
pub fn StoreView() -> Element {
    let app_state = APP_STATE.read();

    // `AppState::displayed_store` owns this choice, so the document title
    // (see `components::App`) cannot answer it differently.
    let store_entry = app_state
        .displayed_store()
        .map(|(id, store)| (id.clone(), store.clone()));

    // A link was followed but the store's state hasn't come back yet. Once
    // `store_link_error` is set the wait is over and the message changes --
    // otherwise this reads "Loading store..." for the rest of the session.
    let link_error = app_state.store_link_error.clone();
    let awaiting_link =
        store_entry.is_none() && app_state.active_store_id.is_some() && link_error.is_none();

    rsx! {
        div {
            h2 { "Store" }

            match store_entry {
                Some((contract_id, store)) => {
                    rsx! { LoadedStore { store: store, contract_id: contract_id } }
                }
                None if awaiting_link => {
                    rsx! {
                        p { class: "text-muted text-italic", "Loading store..." }
                    }
                }
                None if link_error.is_some() => {
                    let message = link_error.clone().unwrap_or_default();
                    rsx! {
                        p { class: "text-warning", "{message}" }
                    }
                }
                None => {
                    rsx! {
                        p { class: "text-muted text-italic",
                            "No store loaded. Share a store link to browse listings."
                        }
                        {example_listings_section()}
                    }
                }
            }
        }
    }
}

#[component]
fn LoadedStore(store: crate::state::BrowsingStore, contract_id: Vec<u8>) -> Element {
    let info = store.info.as_ref().unwrap();
    let mut show_messages = use_signal(|| false);
    // Read once, here, rather than inside the per-listing helper: this
    // component re-renders on every keystroke in the boxes below it, and the
    // answer cannot change between two listings of the same store.
    let owned = APP_STATE
        .read()
        .store_owner_fingerprint(&contract_id)
        .is_some();

    rsx! {
        div {
            div { class: "store-header",
                div { class: "store-header-inner",
                    div {
                        h3 { class: "store-name", "{info.store_name}" }
                        crate::markdown::Markdown {
                            source: info.description.clone(),
                            class: "store-desc",
                        }
                    }
                    div { class: "store-meta",
                        if store.feedback.is_empty() {
                            span { class: "reputation-clean", "Clean record" }
                        } else {
                            span { class: "reputation-negative",
                                "{store.feedback.len()} negative"
                            }
                        }
                        p { class: "seller-id",
                            "Seller: {truncate_fingerprint(&info.seller_fingerprint)}"
                        }
                        p {
                            class: if store.certificate_status.is_verified() { "cert-verified" } else { "cert-unverified" },
                            "{store.certificate_status.label()}"
                        }
                    }
                }

                // The verdict, spelled out. A badge alone tells a buyer that
                // something is wrong without telling them what it costs them,
                // and this is the one line on the page that decides whether
                // the seller has anything at stake.
                if !store.certificate_status.is_verified() {
                    p { class: "text-warning",
                        "{certificate_warning(&store.certificate_status)}"
                    }
                }

            }

            // Contact seller button
            div {
                style: "margin-bottom: 1.5rem;",
                button {
                    class: if show_messages() { "btn btn-sm btn-outline" } else { "btn btn-primary" },
                    onclick: move |_| show_messages.toggle(),
                    if show_messages() { "Hide Messages" } else { "Contact Seller" }
                }
            }

            if show_messages() {
                super::message_view::MessageView { store_contract_id: contract_id.clone() }
            }

            if store.listings.is_empty() {
                p { class: "text-muted text-italic", "No listings yet." }
            } else {
                p { class: "section-count", "{store.listings.len()} listing(s)" }
                for listing in &store.listings {
                    ListingCard {
                        listing: listing.clone(),
                        // Only when it adds something. If the store's own
                        // certificate failed, the warning above already
                        // covers everything under it, and repeating it on
                        // every card is the kind of noise that teaches a
                        // reader to skip warnings.
                        certificate_mismatch: store.certificate_status.is_verified()
                            && store.unverified_listings.contains(&listing.listing.id),
                        // `None` disables the Buy control rather than hiding
                        // the listing. A store whose certificate does not
                        // verify, or which publishes no encryption key, can
                        // still be READ -- what it cannot be is bought from,
                        // because there is no key to encrypt an address to
                        // and no identity to hold to the order. See
                        // `BuyControl`.
                        // `None` for a listing whose OWN certificate did
                        // not verify, as well as for a store that cannot be
                        // bought from at all. The store-level check cannot
                        // see this: `buyable` is computed once per store,
                        // and a mismatched listing is a per-listing fact.
                        buyable: buyable(&store, &contract_id, owned)
                            .filter(|_| !store.unverified_listings.contains(&listing.listing.id)),
                    }
                }
            }

            super::buy_view::Purchases { store_contract_id: contract_id.clone() }

            StoreInvoices { orders: store.orders.clone() }
        }
    }
}

/// The invoices a store has issued, as a buyer sees them.
///
/// They are on the store contract and public, which is not an oversight:
/// decentralized payment verification is impossible unless everyone can see
/// what was owed and where it was to be paid. That is application semantics
/// requiring publication, and quite different from publishing a user's private
/// list of addresses they happen to be interested in -- which Harvest refuses
/// to do anywhere (see `harvest_common::bitcoin_delegate`).
///
/// Every invoice goes through the SAME `OrderCard` the seller's own payments
/// panel uses, so the per-invoice bridge check travels with it. That check is
/// the one a buyer most needs and is easiest to leave out of a second copy:
/// the trusted-bridge set moved onto the order to make rotation possible, so
/// two invoices from one store may name different observers, and an invoice
/// whose "Paid" verdict would rest on a stranger's signature has to say so
/// before the buyer sends anything.
#[component]
fn StoreInvoices(orders: Vec<harvest_common::payment::AuthorizedOrder>) -> Element {
    if orders.is_empty() {
        return rsx! {};
    }
    let mut sorted = orders;
    sorted.sort_by_key(|o| std::cmp::Reverse(o.order.created_at));
    let bitcoin = crate::gateway::APP_STATE.read().bitcoin.clone();

    rsx! {
        div { style: "margin-top: 24px;",
            h4 { "Invoices" }
            p { class: "text-muted",
                "Pay the address shown on an invoice for the exact amount. Anyone can "
                "check the evidence that settles it, so neither you nor the seller has to "
                "be taken at their word about the payment."
            }
            super::invoice_form::PaymentWatchNote {}
            for order in sorted.iter() {
                super::bitcoin_view::OrderCard {
                    key: "{order.order.id}",
                    order: order.clone(),
                    live: super::bitcoin_view::live_address_for_order(&bitcoin, &order.order),
                }
            }
        }
    }
}

/// What an unverified certificate means for the person reading the page.
///
/// The two cases are genuinely different and must not be collapsed. A store
/// with no certificate is claiming nothing; a store whose certificate fails
/// is claiming a bond it does not have, which is worse than claiming none.
fn certificate_warning(status: &crate::ghostkey_cert::CertificateStatus) -> String {
    use crate::ghostkey_cert::CertificateStatus;
    match status {
        CertificateStatus::Verified => String::new(),
        CertificateStatus::Absent => "This store publishes no ghostkey certificate, so nothing \
             here shows that the seller's identity cost anything to create. They can abandon it \
             and start again for free."
            .to_string(),
        CertificateStatus::Invalid(why) => format!(
            "This store's ghostkey certificate does not check out ({why}). Treat the seller as \
             anonymous: nothing here shows they have staked anything they would lose."
        ),
    }
}

/// What a buy form needs, or `None` when this store cannot be bought from.
///
/// The three values travel together because they are useless apart: the
/// contract id says where, the encryption key is what the buyer's address is
/// sealed to, and the verifying key is the identity a published commitment
/// has to be signed by. A card holding two of the three could render a Buy
/// button that cannot complete.
#[derive(Clone, PartialEq)]
pub struct Buyable {
    store_contract_id: Vec<u8>,
    seller_encryption_key: [u8; 32],
    seller_verifying_key: [u8; 32],
}

/// Whether this store can be bought from, and with what.
///
/// The same two conditions that decide whether it can be MESSAGED, and
/// necessarily so: a purchase is a conversation. A store with no published
/// encryption key has nothing to seal a shipping address to, and one whose
/// certificate does not verify has no identity whose signature on a
/// commitment would mean anything.
///
/// **Per-store only.** A listing whose OWN certificate does not verify is a
/// per-listing fact this cannot see, and the caller filters on it -- review
/// found the Buy control being offered on exactly those listings while the
/// module comment read as though signature failure disabled buying. The
/// consequence was contained (a commitment for a listing id the seller never
/// signed) but the screen was claiming something it did not do.
fn buyable(
    store: &crate::state::BrowsingStore,
    contract_id: &[u8],
    owned: bool,
) -> Option<Buyable> {
    // A store the connected identity owns is not one to buy from: a seller
    // does not open a conversation with themselves. Passed in rather than
    // read from `APP_STATE` here, so this is a pure function of what it is
    // handed and can be asserted without a Dioxus runtime.
    if owned {
        return None;
    }
    Some(Buyable {
        store_contract_id: contract_id.to_vec(),
        seller_encryption_key: store.info.as_ref()?.encryption_public_key?,
        seller_verifying_key: store.seller_verifying_key?,
    })
}

#[component]
fn ListingCard(
    listing: AuthorizedListing,
    certificate_mismatch: bool,
    buyable: Option<Buyable>,
) -> Element {
    let l = &listing.listing;

    rsx! {
        div { class: "listing-card",
            div { class: "listing-header",
                h4 { "{l.title}" }
                span { class: "badge {kind_badge_class(&l.kind)}",
                    "{kind_label(&l.kind)}"
                }
            }
            // The store verified, and this listing did not: it carries a
            // certificate that is not the seller's. Worth saying loudly,
            // precisely because everything around it checks out.
            if certificate_mismatch {
                p { class: "text-warning",
                    "This listing's ghostkey certificate is not this seller's."
                }
            }
            p { class: "listing-desc", "{l.description}" }
            div { class: "listing-footer",
                if let Some(ref price) = l.price {
                    span { class: "listing-price", "{price.amount} {price.currency}" }
                }
                {
                    let date = l.created_at.format("%Y-%m-%d").to_string();
                    rsx! {
                        span { class: "listing-date", "Listed {date}" }
                    }
                }
            }
            match buyable {
                Some(buyable) => rsx! {
                    BuyControl {
                        listing_id: l.id.clone(),
                        listing_title: l.title.clone(),
                        buyable: buyable,
                    }
                },
                // Silence rather than a disabled button: a control that can
                // never work is worse than none, and the reason is already on
                // the page above -- the certificate warning, or the notice
                // that this store publishes no key to write to.
                None => rsx! {},
            }
        }
    }
}

/// The Buy button, and the form it opens.
///
/// Collapsed by default. A storefront is something people read, and a form
/// under every listing would turn a page of things to look at into a page of
/// things to fill in.
#[component]
fn BuyControl(
    listing_id: harvest_common::listing::ListingId,
    listing_title: String,
    buyable: Buyable,
) -> Element {
    let mut open = use_signal(|| false);

    rsx! {
        div { style: "margin-top: 0.75rem;",
            button {
                class: if open() { "btn btn-sm btn-outline" } else { "btn btn-primary btn-sm" },
                onclick: move |_| open.toggle(),
                if open() { "Cancel" } else { "Buy this" }
            }
            if open() {
                super::buy_view::BuyForm {
                    store_contract_id: buyable.store_contract_id.clone(),
                    listing_id: listing_id.clone(),
                    listing_title: listing_title.clone(),
                    seller_encryption_key: buyable.seller_encryption_key,
                    seller_verifying_key: buyable.seller_verifying_key,
                }
            }
        }
    }
}

fn truncate_fingerprint(fp: &str) -> String {
    if fp.len() > 12 {
        format!("{}...", &fp[..12])
    } else {
        fp.to_string()
    }
}

fn kind_badge_class(kind: &ListingKind) -> &'static str {
    match kind {
        ListingKind::Sale => "badge-sale",
        ListingKind::Gift => "badge-gift",
        ListingKind::Request => "badge-request",
    }
}

fn kind_label(kind: &ListingKind) -> &'static str {
    match kind {
        ListingKind::Sale => "Sale",
        ListingKind::Gift => "Gift",
        ListingKind::Request => "Request",
    }
}

fn example_listings_section() -> Element {
    #[cfg(not(feature = "example-data"))]
    {
        rsx! {}
    }

    #[cfg(feature = "example-data")]
    {
        let examples = vec![
            (
                "Handmade Ceramic Mug",
                "Beautiful hand-thrown stoneware mug, holds 12oz.",
                ListingKind::Sale,
                Some(PriceInfo {
                    amount: "0.001".into(),
                    currency: "BTC".into(),
                }),
            ),
            (
                "Sourdough Starter",
                "Active 3-year-old starter, ready to bake.",
                ListingKind::Gift,
                None,
            ),
            (
                "Looking for: Bicycle Parts",
                "Need a rear derailleur, Shimano compatible.",
                ListingKind::Request,
                None,
            ),
        ];

        rsx! {
            div {
                h3 { "Example Listings" }
                for (title, desc, kind, price) in examples {
                    div { class: "listing-card",
                        div { class: "listing-header",
                            h4 { "{title}" }
                            span { class: "badge {kind_badge_class(&kind)}", "{kind_label(&kind)}" }
                        }
                        p { class: "listing-desc", "{desc}" }
                        if let Some(ref p) = price {
                            p { class: "listing-price", "{p.amount} {p.currency}" }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod buy_control_tests {
    use super::*;
    use harvest_common::store::StoreInfoV1;

    const STORE: &[u8] = &[4u8; 32];

    fn store_with(
        encryption_key: Option<[u8; 32]>,
        identity: Option<[u8; 32]>,
    ) -> crate::state::BrowsingStore {
        crate::state::BrowsingStore {
            info: Some(StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: "seller-fp".to_string(),
                reputation_contract_id: [0u8; 32],
                store_name: "Hot sauce".to_string(),
                description: String::new(),
                encryption_public_key: encryption_key,
            }),
            seller_verifying_key: identity,
            ..Default::default()
        }
    }

    /// **A store with no published encryption key cannot be bought from.**
    ///
    /// A purchase begins with a shipping address, and there is nothing to
    /// seal it to. Offering the button anyway would put the buyer's address
    /// one click from a failure they cannot fix.
    #[test]
    fn a_store_with_no_encryption_key_cannot_be_bought_from() {
        let store = store_with(None, Some([2u8; 32]));
        assert!(buyable(&store, STORE, false).is_none());
    }

    /// **A store whose identity did not verify cannot be bought from.**
    ///
    /// `seller_verifying_key` is `None` when the certificate does not check
    /// out, and it is the key a published commitment has to be signed by. A
    /// buyer who could reach the Buy button here would be sending an address
    /// to somebody whose order could never be tied to anyone.
    #[test]
    fn a_store_whose_identity_did_not_verify_cannot_be_bought_from() {
        let store = store_with(Some([1u8; 32]), None);
        assert!(buyable(&store, STORE, false).is_none());
    }

    /// **Your own store is not one you buy from.**
    #[test]
    fn your_own_store_is_not_one_you_buy_from() {
        let store = store_with(Some([1u8; 32]), Some([2u8; 32]));
        assert!(buyable(&store, STORE, true).is_none());
        assert!(
            buyable(&store, STORE, false).is_some(),
            "and the same store IS buyable when it is somebody else's"
        );
    }
}

#[cfg(test)]
mod listing_buy_gate_tests {
    use super::*;
    use harvest_common::listing::ListingId;

    const STORE: &[u8] = &[4u8; 32];

    /// **A listing whose own certificate did not verify cannot be bought.**
    ///
    /// The store may check out perfectly while one listing on it does not --
    /// that is exactly what `unverified_listings` records, and the card
    /// already warns about it. Offering Buy underneath that warning invites a
    /// purchase of something this seller never signed for.
    ///
    /// Written against the expression the component actually renders, since
    /// the store-level `buyable` cannot see a per-listing fact and a test of
    /// `buyable` alone would pass while the screen was wrong.
    #[test]
    fn a_listing_whose_certificate_did_not_verify_is_not_buyable() {
        let good = ListingId([1u8; 32]);
        let bad = ListingId([2u8; 32]);
        let mut store = crate::state::BrowsingStore {
            info: Some(harvest_common::store::StoreInfoV1 {
                version: 1,
                certificate_pem: String::new(),
                seller_fingerprint: "seller-fp".to_string(),
                reputation_contract_id: [0u8; 32],
                store_name: "Hot sauce".to_string(),
                description: String::new(),
                encryption_public_key: Some([1u8; 32]),
            }),
            seller_verifying_key: Some([2u8; 32]),
            ..Default::default()
        };
        store.unverified_listings.insert(bad.clone());

        let for_listing = |id: &ListingId| {
            buyable(&store, STORE, false).filter(|_| !store.unverified_listings.contains(id))
        };
        assert!(
            for_listing(&good).is_some(),
            "a listing that verifies is buyable"
        );
        assert!(
            for_listing(&bad).is_none(),
            "and one whose certificate is not this seller's is not"
        );
    }
}
