//! An item's picture, where one exists.
//!
//! No picture is shown today: listings can name their photos
//! (`Listing::images`, #215), but nothing fetches the image contracts yet.
//! Every layout that shows an item is built to look finished without one
//! (no grey box, no empty frame) and to take one without changing shape:
//! a card puts it above its words, a row puts a small square before its
//! text. [`listing_image`] is the one place a picture would come from.
//!
//! The `image-preview` feature is a test fixture, not shipped behaviour: it
//! draws a stand-in photo for some listings so the layouts can be looked
//! at with pictures. Release builds and CI never enable it.

use dioxus::prelude::*;
use harvest_common::listing::ListingId;

/// The picture for a listing, if it has one. Always `None` in a real build.
pub(crate) fn listing_image(listing: &ListingId, title: &str) -> Option<String> {
    #[cfg(feature = "image-preview")]
    {
        // About half the listings, so a page shows both cases side by side.
        if listing.0[0].is_multiple_of(2) {
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

/// A stand-in photo, picked by the words in the item's name. Test fixture
/// only. The photos are 600x600 JPEGs in `ui/assets/preview/`, all from
/// Wikimedia Commons under CC0 or public domain:
///
/// - mug.jpg: "Meissen Porcelain Factory (German) - Small Mug - 1989.178",
///   Cleveland Museum of Art, CC0
/// - towel.jpg: "Viskestykke.jpg", Nillerdk, public domain
/// - vase.jpg: "Small bottle-vase MET SLP1747-1.jpg", The Metropolitan
///   Museum of Art, CC0
/// - teapot.jpg: "Worcester Porcelain Factory (British) - Teapot -
///   2009.108.a", Cleveland Museum of Art, CC0
/// - bowl.jpg: "Unknown artist - Yellow Glazed Bowl - 2020.180", Cleveland
///   Museum of Art, CC0
/// - candle.jpg: "Wax candle.jpg", Paolo Neo, public domain
#[cfg(feature = "image-preview")]
fn preview_picture(_listing: &ListingId, title: &str) -> String {
    const PHOTOS: [(&str, &[u8]); 5] = [
        ("mug", include_bytes!("../../assets/preview/mug.jpg")),
        ("towel", include_bytes!("../../assets/preview/towel.jpg")),
        ("vase", include_bytes!("../../assets/preview/vase.jpg")),
        ("teapot", include_bytes!("../../assets/preview/teapot.jpg")),
        ("bowl", include_bytes!("../../assets/preview/bowl.jpg")),
    ];
    const OTHER: &[u8] = include_bytes!("../../assets/preview/candle.jpg");
    let title = title.to_lowercase();
    let photo = PHOTOS
        .iter()
        .find(|(word, _)| title.contains(word))
        .map_or(OTHER, |(_, bytes)| *bytes);
    format!("data:image/jpeg;base64,{}", base64(photo))
}

/// Standard base64, for the fixture's data URIs (the UI has no base64
/// dependency, and the fixture is not worth one).
#[cfg(feature = "image-preview")]
fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ABC[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
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

#[cfg(all(test, feature = "image-preview"))]
mod tests {
    /// The fixture's encoder pads as standard base64 does.
    #[test]
    fn base64_pads_like_the_standard() {
        assert_eq!(super::base64(b"Man"), "TWFu");
        assert_eq!(super::base64(b"Ma"), "TWE=");
        assert_eq!(super::base64(b"M"), "TQ==");
        assert_eq!(super::base64(b""), "");
    }
}
