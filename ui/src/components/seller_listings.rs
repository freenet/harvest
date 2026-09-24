//! My store > Listings: what the seller has listed, and the controls to change
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

#[component]
pub fn SellerListings(store_contract_id: Vec<u8>, fingerprint: String) -> Element {
    let mut adding = use_signal(|| false);
    let mut editing = use_signal(|| Option::<ListingId>::None);
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
    rows.sort_by(|a, b| b.0.listing.created_at.cmp(&a.0.listing.created_at));
    let (taken_down, shown): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|(_, availability, _)| *availability == ListingAvailability::Withdrawn);

    rsx! {
        div { class: "seller-listings",
            div { class: "row-between",
                p { class: "section-count",
                    match shown.len() {
                        0 => "Nothing on sale".to_string(),
                        1 => "1 listing".to_string(),
                        n => format!("{n} listings"),
                    }
                }
                if !adding() {
                    button {
                        class: "btn btn-sm btn-primary",
                        onclick: move |_| {
                            editing.set(None);
                            adding.set(true);
                        },
                        "Add a listing"
                    }
                }
            }

            if adding() {
                ListingForm {
                    initial: None,
                    initial_quantity: None,
                    on_cancel: move |_| adding.set(false),
                    on_submit: {
                        let store = store_contract_id.clone();
                        let fp = fingerprint.clone();
                        move |(listing, quantity): (Listing, Option<u32>)| {
                            adding.set(false);
                            let mut state = APP_STATE.write();
                            if let Err(e) = state.publish_new_listing(store.clone(), fp.clone(), listing, quantity) {
                                state.notifications.push(format!("Cannot add the listing: {e}"));
                            }
                        }
                    },
                }
            }

            if !resolved {
                p { class: "text-muted text-italic", "Loading your listings\u{2026}" }
            } else if shown.is_empty() && taken_down.is_empty() && !adding() {
                div { class: "card empty-state",
                    p { "You have not listed anything yet." }
                    p { "A listing is what buyers see and ask to buy. You can change or take it down later." }
                }
            }

            for (listing, availability, pending) in shown {
                // Keyed on the loop's first node, where dioxus reads a list
                // key, so an open edit form keeps what was typed when a new
                // listing arrives above it.
                div { key: "{listing.listing.id}",
                    if editing() == Some(listing.listing.id.clone()) {
                        ListingForm {
                            initial: Some(listing.listing.clone()),
                            initial_quantity: match &availability {
                                ListingAvailability::Available { quantity } => *quantity,
                                _ => None,
                            },
                            sold_out: !availability.is_buyable(),
                            on_cancel: move |_| editing.set(None),
                            on_submit: {
                                let store = store_contract_id.clone();
                                let fp = fingerprint.clone();
                                let old = listing.listing.id.clone();
                                move |(edited, quantity): (Listing, Option<u32>)| {
                                    editing.set(None);
                                    let mut state = APP_STATE.write();
                                    if let Err(e) = state.replace_listing(store.clone(), fp.clone(), old.clone(), edited, quantity) {
                                        state.notifications.push(format!("Could not save the listing: {e}"));
                                    }
                                }
                            },
                        }
                    } else {
                        SellerListingRow {
                            store_contract_id: store_contract_id.clone(),
                            listing: listing.clone(),
                            availability: availability.clone(),
                            pending,
                            on_edit: move |id: ListingId| {
                                adding.set(false);
                                editing.set(Some(id));
                            },
                        }
                    }
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
                            on_edit: move |_| {},
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn SellerListingRow(
    store_contract_id: Vec<u8>,
    listing: AuthorizedListing,
    availability: ListingAvailability,
    pending: bool,
    on_edit: EventHandler<ListingId>,
) -> Element {
    let l = &listing.listing;
    let id = l.id.clone();
    let taken_down = availability == ListingAvailability::Withdrawn;
    let buyable = availability.is_buyable();
    let date = l.created_at.format("%-d %b %Y").to_string();
    let row_class = if buyable {
        "seller-listing"
    } else {
        "seller-listing seller-listing-off"
    };

    rsx! {
        div { class: "{row_class}",
            div { class: "seller-listing-main",
                h4 { class: "seller-listing-title", "{l.title}" }
                p { class: "seller-listing-meta",
                    if let Some(ref price) = l.price {
                        span { class: "listing-price", "{price.amount} {price.currency}" }
                        span { class: "sep", " · " }
                    }
                    span { class: if buyable { "status-on" } else { "status-off" },
                        "{availability_label(&availability)}"
                    }
                    span { class: "sep", " · " }
                    span { "Listed {date}" }
                }
            }
            div { class: "seller-listing-actions",
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
                    button {
                        class: "btn btn-sm btn-outline",
                        onclick: {
                            let id = id.clone();
                            move |_| on_edit.call(id.clone())
                        },
                        "Edit"
                    }
                    if after_one_sold(&availability).is_some() {
                        button {
                            class: "btn btn-sm btn-outline",
                            onclick: {
                                let store = store_contract_id.clone();
                                let id = id.clone();
                                // Counted down from the store's state at click
                            // time, not from the value this row rendered with.
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
                            class: "btn btn-sm btn-outline",
                            onclick: {
                                let store = store_contract_id.clone();
                                let id = id.clone();
                                move |_| change_status(store.clone(), id.clone(), ListingAvailability::SoldOut)
                            },
                            "Mark sold out"
                        }
                    } else {
                        button {
                            class: "btn btn-sm btn-outline",
                            onclick: {
                                let store = store_contract_id.clone();
                                let id = id.clone();
                                move |_| change_status(store.clone(), id.clone(), ListingAvailability::Available { quantity: None })
                            },
                            "Back on sale"
                        }
                    }
                    button {
                        class: "btn btn-sm btn-outline",
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

#[cfg(test)]
mod tests {
    use super::*;

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
