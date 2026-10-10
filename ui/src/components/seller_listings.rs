//! The seller's Listings: what the seller has listed, and the controls to change
//! it (harvest#69, #70).
//!
//! Every change is a store-key-signed status or a new listing; see
//! `crate::listing_status_flow`. Nothing on this page claims a change has
//! happened until the store's own state says so: while a change waits for
//! the store key the row says "Saving", and after that it shows whatever the
//! network holds.

use dioxus::prelude::*;
use harvest_common::listing::{AuthorizedListing, Listing, ListingAvailability, ListingId};

use super::listing_form::ListingForm;

use crate::gateway::APP_STATE;

/// What the seller sees about one listing's availability.
pub(crate) fn availability_label(availability: &ListingAvailability) -> String {
    match availability {
        ListingAvailability::Available { quantity: None } => "On sale".to_string(),
        ListingAvailability::Available { quantity: Some(0) } => "Sold out".to_string(),
        ListingAvailability::Available { quantity: Some(n) } => format!("On sale · {n} left"),
        ListingAvailability::SoldOut => "Sold out".to_string(),
        ListingAvailability::Withdrawn => "Taken down".to_string(),
    }
}

/// The availability after one more is sold, for a counted listing: one fewer,
/// and sold out at none.
pub(crate) fn after_one_sold(availability: &ListingAvailability) -> Option<ListingAvailability> {
    match availability {
        ListingAvailability::Available { quantity: Some(n) } if *n > 1 => {
            Some(ListingAvailability::Available {
                quantity: Some(n - 1),
            })
        }
        ListingAvailability::Available { quantity: Some(1) } => Some(ListingAvailability::SoldOut),
        _ => None,
    }
}

fn change_status(
    store_contract_id: Vec<u8>,
    listing: ListingId,
    availability: ListingAvailability,
) {
    let mut state = APP_STATE.write();
    // Two clicks can land before the row re-renders as "Saving" (#80); the
    // second is dropped rather than queued on top of the first.
    if state.listing_status_pending(&store_contract_id, &listing) {
        return;
    }
    if let Err(e) = state.queue_listing_status(store_contract_id, listing, availability) {
        state
            .notifications
            .push(format!("Could not update the listing: {e}"));
    }
}

/// S7: what the store offers. Each row has its quick actions; adding or
/// editing a listing is its own page ([`ListingFormPage`]).
#[component]
pub fn SellerListings(store_contract_id: Vec<u8>, fingerprint: String) -> Element {
    let _ = &fingerprint;
    let mut show_taken_down = use_signal(|| false);
    // "Saving" is judged against the clock (`listing_status_pending_at`),
    // which is read only when this renders. Re-render every few seconds, so a
    // row whose echo never came leaves "Saving" when its window ends, not at
    // the next unrelated change (harvest#125 review).
    #[allow(unused_mut)]
    let mut clock = use_signal(|| 0u32);
    #[cfg(target_arch = "wasm32")]
    use_future(move || async move {
        loop {
            gloo_timers::future::TimeoutFuture::new(5_000).await;
            clock += 1;
        }
    });
    let _ = clock();

    let (resolved, mut rows) = {
        let state = APP_STATE.read();
        let store = state.browsing_stores.get(&store_contract_id);
        let rows: Vec<(AuthorizedListing, ListingAvailability, bool)> = store
            .map(|store| {
                store
                    .listings
                    .iter()
                    .map(|listing| {
                        (
                            listing.clone(),
                            store.availability(&listing.listing.id),
                            state.listing_status_pending(&store_contract_id, &listing.listing.id),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        (state.store_details_are_resolved(&store_contract_id), rows)
    };
    // Newest first, sold out last, as the store page lists them.
    rows.sort_by(|a, b| b.0.listing.created_at.cmp(&a.0.listing.created_at));
    rows.sort_by_key(|(_, availability, _)| !availability.is_buyable());
    let (taken_down, shown): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|(_, availability, _)| *availability == ListingAvailability::Withdrawn);
    let sold_out = shown.iter().filter(|(_, a, _)| !a.is_buyable()).count();
    let add = {
        let id = store_contract_id.clone();
        move |_| {
            super::router::go(super::seller_pages::seller_page(
                &id,
                super::router::SellerView::AddListing,
            ))
        }
    };

    rsx! {
        div { class: "seller-listings",
            div { class: "row-between list-head",
                p { class: "section-count",
                    match (shown.len(), sold_out) {
                        (0, _) => "Nothing on sale".to_string(),
                        (n, 0) => super::needs::plural(n, "listing", "listings"),
                        (n, s) => format!("{} \u{00b7} {s} sold out", super::needs::plural(n, "listing", "listings")),
                    }
                }
                button { class: "btn btn-primary", onclick: add.clone(), "Add a listing" }
            }

            if !resolved {
                p { class: "text-muted text-italic", "Loading your listings\u{2026}" }
            } else if shown.is_empty() && taken_down.is_empty() {
                div { class: "empty-block",
                    p { "You have not listed anything yet." }
                    p { class: "text-muted small", "A listing is what buyers see and buy. You can change it or take it down later." }
                }
            }

            for (listing, availability, pending) in shown {
                SellerListingRow {
                    key: "{listing.listing.id}",
                    store_contract_id: store_contract_id.clone(),
                    listing: listing.clone(),
                    availability: availability.clone(),
                    pending,
                }
            }

            if !taken_down.is_empty() {
                button {
                    class: "link-btn",
                    onclick: move |_| show_taken_down.toggle(),
                    if show_taken_down() {
                        "Hide taken down ({taken_down.len()})"
                    } else {
                        "Show taken down ({taken_down.len()})"
                    }
                }
                if show_taken_down() {
                    for (listing, availability, pending) in taken_down {
                        SellerListingRow {
                            key: "{listing.listing.id}",
                            store_contract_id: store_contract_id.clone(),
                            listing: listing.clone(),
                            availability: availability.clone(),
                            pending,
                        }
                    }
                }
            }
        }
    }
}

/// Where a listing from [`ListingFormPage`]'s form goes: the store it is
/// published to, and the listing it replaces when editing.
///
/// Plain data, not a callback: when a listing has photos to upload first,
/// the publish runs after the upload, which outlives the form (the seller
/// may leave the page meanwhile), while a Dioxus callback dies with the
/// component that made it.
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct ListingTarget {
    pub store: Vec<u8>,
    pub fingerprint: String,
    /// The listing being edited; `None` for a new one.
    pub replaces: Option<ListingId>,
}

impl ListingTarget {
    /// Publish `listing`: a new one, or in place of [`Self::replaces`]. An
    /// error is said as a sentence for the seller; nothing is pushed to the
    /// notices here, since where it is said depends on whether the form is
    /// still on screen.
    pub(crate) fn apply(
        &self,
        state: &mut crate::state::AppState,
        listing: Listing,
        quantity: Option<u32>,
    ) -> Result<(), String> {
        match &self.replaces {
            Some(old) => state
                .replace_listing(
                    self.store.clone(),
                    self.fingerprint.clone(),
                    old.clone(),
                    listing,
                    quantity,
                )
                .map_err(|e| format!("Could not save the listing: {e}")),
            None => state
                .publish_new_listing(
                    self.store.clone(),
                    self.fingerprint.clone(),
                    listing,
                    quantity,
                )
                .map_err(|e| format!("Cannot add the listing: {e}")),
        }
    }

    /// Where the seller goes once the listing is handed on.
    pub(crate) fn listings_page(&self) -> super::router::Page {
        super::seller_pages::seller_page(&self.store, super::router::SellerView::Listings)
    }

    /// Said when the photos for `title` did not upload and the seller has
    /// left the form, so its own error line is not there to say it.
    pub(crate) fn upload_failed_notice(&self, title: &str, problem: &str) -> String {
        match self.replaces {
            Some(_) => format!(
                "The photos for your edit of \u{201c}{title}\u{201d} did not upload, so the \
                 listing is unchanged. {problem}"
            ),
            None => format!(
                "The photos for \u{201c}{title}\u{201d} did not upload, so it was not listed. \
                 {problem}"
            ),
        }
    }
}

/// S8: describe one item and its price. `editing`: the listing to change,
/// else a new one. Back to Listings when it is published or cancelled.
#[component]
pub(crate) fn ListingFormPage(
    store_contract_id: Vec<u8>,
    fingerprint: String,
    editing: Option<ListingId>,
) -> Element {
    let listings_page =
        super::seller_pages::seller_page(&store_contract_id, super::router::SellerView::Listings);
    let found = editing.as_ref().map(|id| {
        let state = APP_STATE.read();
        state
            .browsing_stores
            .get(&store_contract_id)
            .and_then(|store| {
                store
                    .listings
                    .iter()
                    .find(|l| l.listing.id == *id)
                    .map(|l| (l.listing.clone(), store.availability(id)))
            })
    });
    let back = rsx! {
        super::seller_pages::BackTo { label: "Listings".to_string(), page: listings_page.clone() }
    };
    let add_key = format!("add-{}", listings_page.fragment());
    let on_cancel = {
        let page = listings_page.clone();
        move |_| super::router::go(page.clone())
    };
    match found {
        Some(None) => rsx! {
            {back}
            p { class: "text-muted text-italic", "That listing isn\u{2019}t here, or hasn\u{2019}t loaded yet." }
        },
        // Keyed: a jump straight from one listing's Edit page to another's
        // (or from one store's Add page to another's) must get a new form,
        // not carry the first one's fields over. Dioxus reads a key only in
        // a list, hence the list of one.
        Some(Some((listing, availability))) => rsx! {
            // In a one-item list: a key counts only there.
            for form_key in std::iter::once(listing.id.to_string()) {
            Fragment { key: "{form_key}",
            {back.clone()}
            h2 { class: "page-h", "Edit {listing.title}" }
            ListingForm {
                initial: Some(listing.clone()),
                initial_quantity: match &availability {
                    ListingAvailability::Available { quantity } => *quantity,
                    _ => None,
                },
                sold_out: !availability.is_buyable(),
                on_cancel: on_cancel.clone(),
                target: ListingTarget {
                    store: store_contract_id.clone(),
                    fingerprint: fingerprint.clone(),
                    replaces: Some(listing.id.clone()),
                },
            }
            }
            }
        },
        None => rsx! {
            for form_key in std::iter::once(add_key.clone()) {
            Fragment { key: "{form_key}",
            {back.clone()}
            h2 { class: "page-h", "Add a listing" }
            ListingForm {
                initial: None,
                initial_quantity: None,
                on_cancel: on_cancel.clone(),
                target: ListingTarget {
                    store: store_contract_id.clone(),
                    fingerprint: fingerprint.clone(),
                    replaces: None,
                },
            }
            }
            }
        },
    }
}

/// Every image contract a listing names: each photo, and the cover's
/// thumbnail.
pub(crate) fn photo_hashes(listing: &harvest_common::listing::Listing) -> Vec<[u8; 32]> {
    listing
        .images
        .iter()
        .flat_map(|i| std::iter::once(i.full.hash.0).chain(i.thumb.iter().map(|t| t.hash.0)))
        .collect()
}

/// "Photo missing" under a listing whose photos the network no longer has.
#[component]
fn MissingPhotos(hashes: Vec<[u8; 32]>) -> Element {
    #[cfg(target_arch = "wasm32")]
    let missing = use_resource(move || {
        let hashes = hashes.clone();
        async move {
            use crate::gateway::image_ops::{fetch_image, Fetched};
            // All at once, and an absent photo asked again before it is
            // reported: a GET that dead-ends answers "not found" for a
            // contract that exists, and one such answer is not worth
            // telling the seller their photo is gone.
            let first =
                futures::future::join_all(hashes.iter().map(|h| fetch_image(*h, true))).await;
            let absent: Vec<[u8; 32]> = hashes
                .iter()
                .zip(first)
                .filter(|(_, f)| *f == Fetched::Absent)
                .map(|(h, _)| *h)
                .collect();
            if absent.is_empty() {
                return 0usize;
            }
            gloo_timers::future::TimeoutFuture::new(5_000).await;
            futures::future::join_all(absent.iter().map(|h| fetch_image(*h, false)))
                .await
                .into_iter()
                .filter(|f| *f == Fetched::Absent)
                .count()
        }
    });
    #[cfg(target_arch = "wasm32")]
    let missing = missing.read().unwrap_or(0);
    #[cfg(not(target_arch = "wasm32"))]
    let missing = {
        let _ = hashes;
        0usize
    };
    rsx! {
        if missing > 0 {
            p { class: "text-warning small",
                "A photo is missing from Freenet, so buyers don't see it. Open Edit, remove that photo and add it again."
            }
        }
    }
}

/// One listing: its picture when it has one, its title, price, delivery and
/// stock, Edit, and the quick actions under "More".
#[component]
fn SellerListingRow(
    store_contract_id: Vec<u8>,
    listing: AuthorizedListing,
    availability: ListingAvailability,
    pending: bool,
) -> Element {
    let l = &listing.listing;
    let id = l.id.clone();
    let taken_down = availability == ListingAvailability::Withdrawn;
    let buyable = availability.is_buyable();
    let unpriced = !taken_down && !l.offers_instant_checkout();
    let row_class = if buyable && !unpriced {
        "seller-listing"
    } else {
        "seller-listing seller-listing-off"
    };
    let thumb = super::item_image::listing_image(&l.id, &l.title);
    let meta = match super::store_view::price_lines(l) {
        Some((price, delivery)) => format!("{price} \u{00b7} {delivery}"),
        None => "No price yet: buyers can\u{2019}t buy it".to_string(),
    };
    let stock = match &availability {
        ListingAvailability::Available { quantity: Some(n) } if *n > 0 => Some(format!("{n} left")),
        _ => None,
    };
    let pill = if unpriced {
        Some(("Needs a price", "pill pill-needs"))
    } else if taken_down {
        Some(("Taken down", "pill"))
    } else if !buyable {
        Some(("Sold out", "pill"))
    } else {
        None
    };
    let edit = {
        let store = store_contract_id.clone();
        let id = id.clone();
        move |_| {
            super::router::go(super::seller_pages::seller_page(
                &store,
                super::router::SellerView::EditListing(id.clone()),
            ))
        }
    };

    rsx! {
        div { class: "{row_class}",
            super::item_image::RowThumb { src: thumb }
            div { class: "seller-listing-main",
                h4 { class: "seller-listing-title", "{l.title}" }
                p { class: "seller-listing-meta",
                    "{meta}"
                    if let Some(stock) = stock {
                        " \u{00b7} {stock}"
                    }
                }
                // Each photo of a listing still on show, looked up (and
                // subscribed to, which keeps it on this node while the page
                // is open). One the network no longer has is said here: only
                // the seller can put it back.
                if !taken_down && !l.images.is_empty() {
                    MissingPhotos { hashes: photo_hashes(l) }
                }
            }
            div { class: "seller-listing-actions",
                if let Some((pill, class)) = pill {
                    span { class: "{class}", "{pill}" }
                }
                if pending {
                    span { class: "text-muted text-italic small", "Saving\u{2026}" }
                } else if taken_down {
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: {
                            let store = store_contract_id.clone();
                            let id = id.clone();
                            move |_| change_status(store.clone(), id.clone(), ListingAvailability::Available { quantity: None })
                        },
                        "Put back on sale"
                    }
                } else {
                    button { class: "btn btn-sm btn-outline", onclick: edit, "Edit" }
                    details { class: "row-more",
                        summary { class: "btn btn-sm btn-outline", aria_label: "More for {l.title}", "More" }
                        div { class: "row-more-menu",
                            if after_one_sold(&availability).is_some() {
                                button {
                                    class: "row-more-item",
                                    onclick: {
                                        let store = store_contract_id.clone();
                                        let id = id.clone();
                                        // Counted down from the store's state at
                                        // click time, not from this render's.
                                        move |_| {
                                            let now = APP_STATE.read().listing_availability(&store, &id);
                                            if let Some(next) = after_one_sold(&now) {
                                                change_status(store.clone(), id.clone(), next);
                                            }
                                        }
                                    },
                                    "One sold"
                                }
                            }
                            if buyable {
                                button {
                                    class: "row-more-item",
                                    onclick: {
                                        let store = store_contract_id.clone();
                                        let id = id.clone();
                                        move |_| change_status(store.clone(), id.clone(), ListingAvailability::SoldOut)
                                    },
                                    "Mark sold out"
                                }
                            } else {
                                button {
                                    class: "row-more-item",
                                    onclick: {
                                        let store = store_contract_id.clone();
                                        let id = id.clone();
                                        move |_| change_status(store.clone(), id.clone(), ListingAvailability::Available { quantity: None })
                                    },
                                    "Back on sale"
                                }
                            }
                            button {
                                class: "row-more-item",
                                onclick: {
                                    let store = store_contract_id.clone();
                                    let id = id.clone();
                                    move |_| change_status(store.clone(), id.clone(), ListingAvailability::Withdrawn)
                                },
                                "Take down"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The missing-photo check looks up every image contract the listing
    /// names, the cover's thumbnail included, and no other.
    #[test]
    fn photo_hashes_are_each_photo_and_the_covers_thumbnail() {
        use harvest_common::listing_image::{ImageBlob, ListingImage};
        use harvest_common::store::Bytes32;
        let blob = |s: u8| ImageBlob {
            hash: Bytes32([s; 32]),
            len: 10,
            width: 4,
            height: 3,
        };
        let listing = harvest_common::listing::Listing {
            images: vec![
                ListingImage {
                    full: blob(1),
                    thumb: Some(blob(9)),
                    colour: [0; 3],
                    alt: String::new(),
                },
                ListingImage {
                    full: blob(2),
                    thumb: None,
                    colour: [0; 3],
                    alt: String::new(),
                },
            ],
            id: ListingId([0; 32]),
            title: "Jam".into(),
            description: String::new(),
            kind: harvest_common::listing::ListingKind::Sale,
            price: None,
            created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            checkout: None,
            choices: Vec::new(),
        };
        assert_eq!(photo_hashes(&listing), vec![[1; 32], [9; 32], [2; 32]]);
    }

    #[test]
    fn labels_say_what_a_buyer_can_do() {
        use ListingAvailability::*;
        assert_eq!(availability_label(&Available { quantity: None }), "On sale");
        assert_eq!(
            availability_label(&Available { quantity: Some(3) }),
            "On sale · 3 left"
        );
        assert_eq!(
            availability_label(&Available { quantity: Some(0) }),
            "Sold out"
        );
        assert_eq!(availability_label(&SoldOut), "Sold out");
        assert_eq!(availability_label(&Withdrawn), "Taken down");
    }

    /// Selling the last one marks the listing sold out; an uncounted or sold
    /// out listing has no "one sold".
    #[test]
    fn one_sold_counts_down_to_sold_out() {
        use ListingAvailability::*;
        assert_eq!(
            after_one_sold(&Available { quantity: Some(3) }),
            Some(Available { quantity: Some(2) })
        );
        assert_eq!(
            after_one_sold(&Available { quantity: Some(1) }),
            Some(SoldOut)
        );
        assert_eq!(after_one_sold(&Available { quantity: Some(0) }), None);
        assert_eq!(after_one_sold(&Available { quantity: None }), None);
        assert_eq!(after_one_sold(&SoldOut), None);
        assert_eq!(after_one_sold(&Withdrawn), None);
    }
}
