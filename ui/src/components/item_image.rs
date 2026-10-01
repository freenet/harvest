//! An item's picture, where one exists.
//!
//! Listings carry no picture today: the store contract has no field for one.
//! Every layout that shows an item is built to look finished without one
//! (no grey box, no empty frame) and to take one without changing shape:
//! a card puts it above its words, a row puts a small square before its
//! text. [`listing_image`] is the one place a picture would come from.
//!
//! The `image-preview` feature is a test fixture, not shipped behaviour: it
//! draws a stand-in picture for some listings so the layouts can be looked
//! at with pictures. Release builds and CI never enable it.

use dioxus::prelude::*;
use harvest_common::listing::ListingId;

/// The picture for a listing, if it has one. Always `None` in a real build.
pub(crate) fn listing_image(listing: &ListingId, title: &str) -> Option<String> {
    #[cfg(feature = "image-preview")]
    {
        // About half the listings, so a page shows both cases side by side.
        if listing.0[0] % 2 == 0 {
            return Some(preview_picture(listing, title));
        }
        None
    }
    #[cfg(not(feature = "image-preview"))]
    {
        let _ = (listing, title);
        None
    }
}

/// A stand-in picture: a soft field of an earth colour picked by the
/// listing's id, with the item's initial in the middle. Test fixture only.
#[cfg(feature = "image-preview")]
fn preview_picture(listing: &ListingId, title: &str) -> String {
    const FIELDS: [(&str, &str); 5] = [
        ("#d9c9a8", "#b89f72"),
        ("#c8d2bb", "#8fa17b"),
        ("#e2c4ad", "#c08a63"),
        ("#cfc6b8", "#9d917e"),
        ("#d6cfa6", "#a99e5f"),
    ];
    let (light, dark) = FIELDS[listing.0[1] as usize % FIELDS.len()];
    let initial = title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_default();
    let svg = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 400 300'>\
         <defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>\
         <stop offset='0' stop-color='{light}'/><stop offset='1' stop-color='{dark}'/>\
         </linearGradient></defs>\
         <rect width='400' height='300' fill='url(#g)'/>\
         <circle cx='200' cy='150' r='78' fill='#ffffff' fill-opacity='0.28'/>\
         <text x='200' y='176' text-anchor='middle' font-family='Georgia,serif' \
         font-size='84' fill='#2c2416' fill-opacity='0.55'>{initial}</text></svg>"
    );
    format!(
        "data:image/svg+xml,{}",
        svg.replace('#', "%23")
            .replace('<', "%3C")
            .replace('>', "%3E")
            .replace(' ', "%20")
    )
}

/// A small square picture at the start of a row, or nothing.
#[component]
pub(crate) fn RowThumb(src: Option<String>) -> Element {
    match src {
        Some(src) => rsx! {
            img { class: "row-thumb", src: "{src}", alt: "" }
        },
        None => rsx! {},
    }
}
