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
        StoreList {}
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
                            "No store open. Follow a seller's link, or enter their store code above."
                        }
                        {example_listings_section()}
                    }
                }
            }
        }
    }
}

/// Whether a pasted link names a store the old way, from its fragment or
/// query string: the same check a followed link gets.
fn typed_is_old_format_link(typed: &str) -> bool {
    let typed = typed.trim();
    let fragment = typed.split_once('#').map(|(_, f)| f);
    let query = typed
        .split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or(q));
    fragment.is_some_and(crate::store_link::is_old_format_link)
        || query.is_some_and(crate::store_link::is_old_format_link)
}

/// The stores this node has visited, a way to open one by its code, and
/// archiving (harvest#52).
///
/// # Archive, and why it says what it does not do
///
/// Archiving hides a row and deletes nothing: a buyer's history with a store
/// IS its conversations, so a "remove" that removed would take them with it.
/// Deleting a conversation is `ForgetBuyerConversation`, inside the thread.
/// And archiving a store you own is a view preference, not closing the shop,
/// so the text beside the control says both.
#[component]
fn StoreList() -> Element {
    let mut show_archived = use_signal(|| false);
    let mut typed = use_signal(String::new);
    let mut typed_error = use_signal(|| Option::<String>::None);

    let app_state = APP_STATE.read();
    let remembered = app_state.remembered_stores.is_some();
    let (rows, hidden) = app_state.store_list_rows(show_archived());
    let any_archived = hidden > 0 || rows.iter().any(|row| row.archived);
    drop(app_state);

    let mut open_typed = move || match crate::store_link::parse_typed_store_code(&typed()) {
        Some(params) => {
            typed_error.set(None);
            typed.set(String::new());
            crate::store_link::open_store(params);
        }
        None => typed_error.set(Some(if typed_is_old_format_link(&typed()) {
            crate::store_link::OLD_FORMAT_LINK_MESSAGE.to_string()
        } else {
            "That is not a store code. A store code is 16 letters and digits, the part of a \
             store link after \"store=\"."
                .to_string()
        })),
    };

    rsx! {
        div { class: "store-list",
            h2 { "Stores" }
            div { class: "store-share-row",
                input {
                    class: "form-input",
                    r#type: "text",
                    spellcheck: false,
                    aria_label: "Store code or link",
                    placeholder: "Store code or link",
                    value: "{typed}",
                    oninput: move |e| typed.set(e.value()),
                    onkeydown: move |e| {
                        if e.key() == Key::Enter {
                            open_typed();
                        }
                    },
                }
                button {
                    class: "btn btn-sm btn-primary",
                    onclick: move |_| open_typed(),
                    "Open"
                }
            }
            if let Some(ref why) = typed_error() {
                p { class: "text-warning", "{why}" }
            }

            if remembered && rows.is_empty() && hidden == 0 {
                p { class: "text-muted text-italic", "Stores you open are listed here." }
            }
            for row in rows {
                div { class: "store-share-row", key: "{row.code}",
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: {
                            let code = row.code.clone();
                            move |_| {
                                if let Some(params) = harvest_common::StoreParameters::from_code(&code) {
                                    crate::store_link::open_store(params);
                                }
                            }
                        },
                        "{row.label}"
                    }
                    span { class: "text-muted", " {row.code} " }
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: {
                            let code = row.code.clone();
                            let archive = !row.archived;
                            move |_| APP_STATE.write().set_store_archived(&code, archive)
                        },
                        if row.archived { "Unarchive" } else { "Archive" }
                    }
                }
            }
            if hidden > 0 {
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| show_archived.set(true),
                    "Show {hidden} archived store(s)"
                }
            } else if show_archived() && any_archived {
                button {
                    class: "btn btn-sm btn-outline",
                    onclick: move |_| show_archived.set(false),
                    "Hide archived stores"
                }
            }
            if any_archived || show_archived() {
                p { class: "text-muted",
                    "Archiving only hides a store from this list. Its conversations are kept, and "
                    "archiving a store of your own does not close it: buyers can still open it "
                    "and order."
                }
            }
        }
    }
}

#[component]
fn LoadedStore(store: crate::state::BrowsingStore, contract_id: Vec<u8>) -> Element {
    let info = store.info.as_ref().unwrap();
    // Counted the way the Reputation page counts them (`complaint_standing`),
    // so the badge and the record agree.
    let counted_complaints = store
        .complaints
        .iter()
        .filter(|c| {
            crate::fulfilment::complaint_standing(
                c,
                store.orders.iter().find(|o| o.order.id == *c.order_id()),
                store.despatches.get(c.order_id()),
            )
            .counts()
        })
        .count();
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
                        if counted_complaints == 0 {
                            span { class: "reputation-clean", "Clean record" }
                        } else {
                            span { class: "reputation-negative",
                                "{counted_complaints} complaint(s)"
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

                // Said first and plainly: a closed store's key may be in
                // someone else's hands, so nothing on this page can be
                // bought, and the record stays visible (harvest#93, 6.4).
                if store.closed {
                    p { class: "text-warning",
                        "This store has closed. Its seller closed it because its key may be \
                         in someone else's hands, so nothing here can be bought. Its record \
                         stays visible."
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

            // No payment address on a store buyers must not pay: closed, or
            // backed by nothing a reader can believe in (Must Fix 2).
            if store.payable() {
                StoreInvoices { orders: store.orders.clone() }
            } else if !store.orders.is_empty() {
                p { class: "text-muted",
                    "This store's invoices are not shown: it has closed, or nothing vouches \
                     for the key that signs them, so none of them should be paid."
                }
            }
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
    // A closed store's key may be in someone else's hands (harvest#93): an
    // order from it could be anybody's, so nothing here is bought.
    if store.closed {
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
            crate::markdown::Markdown {
                source: l.description.clone(),
                class: "listing-desc",
            }
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
                        crate::markdown::Markdown {
                            source: desc,
                            class: "listing-desc",
                        }
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
                record_public_key: None,
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

    /// **A closed store cannot be bought from**, however well its identity
    /// checks out: the key that signs its orders may be someone else's.
    #[test]
    fn a_closed_store_cannot_be_bought_from() {
        let mut store = store_with(Some([1u8; 32]), Some([2u8; 32]));
        assert!(buyable(&store, STORE, false).is_some());
        store.closed = true;
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
                record_public_key: None,
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

#[cfg(test)]
mod typed_link_tests {
    use super::typed_is_old_format_link;

    /// A pasted pre-#52 link gets the old-format notice, like a followed one.
    #[test]
    fn a_pasted_old_link_is_recognised() {
        let old = bs58::encode([5u8; 32]).into_string();
        assert!(typed_is_old_format_link(&format!(
            "http://127.0.0.1:7509/v1/contract/web/x/#store={old}"
        )));
        assert!(typed_is_old_format_link(&format!(" ?store={old}\n")));
        assert!(!typed_is_old_format_link("3Bn8xWqLd6Tz9Kf"));
        assert!(!typed_is_old_format_link(&old), "a bare id is not a link");
    }
}
