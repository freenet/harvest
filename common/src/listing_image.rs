//! A listing's photos: what a listing says about each one, and the store
//! contract's bounds on it.
//!
//! The photo itself is an image contract whose parameters are the BLAKE3 hash
//! of its bytes (`harvest_image`, harvest#212). A listing names each photo by
//! that hash inside its signed terms, so the store key's signature and the
//! [`crate::listing::ListingId`] cover the photos like any other term: nobody
//! can attach a photo to someone else's listing, and a listing's photos never
//! change after it is published. Changing photos is an edit, which publishes a
//! new listing and takes the old one down, as any change of terms does.
//!
//! # Why the store contract bounds these, when it bounds no other term
//!
//! The contract caps nothing else about a listing, on the grounds that an
//! oversized listing costs only its seller (see the note above
//! [`crate::listing::MAX_CHOICE_GROUPS`]). A photo reference is different: it
//! costs every BUYER who opens the listing a network fetch. So the contract
//! refuses a listing naming more than [`MAX_IMAGES_HARD`] photos, or a photo
//! whose declared size or dimensions no image contract would accept. The UI's
//! own limit, [`MAX_IMAGES_UI`], is lower (the upload path applies it), so it
//! can be raised to the hard cap later without a re-key.
//!
//! # These bound what a listing DECLARES, not the bytes behind it
//!
//! `len`, `width` and `height` are the seller's own statements about the image
//! a hash names; the store cannot fetch it. So a dishonest seller can point a
//! thumbnail reference at any image contract, which is bounded only by that
//! contract's own caps (256 KiB, 2048 px). The reader (the buyer's display
//! path) is what holds a reference to its bytes: it checks the BLAKE3 hash,
//! the length and the dimensions it decodes against the reference, and shows
//! the colour block instead when they disagree.
//!
//! # `harvest_image`'s limits are copied, not imported
//!
//! `harvest-common` does not depend on `harvest-image`, so no change to the
//! image rules can reach the store contract, the delegate, or any other
//! artifact this crate is compiled into. The two limits a listing needs are
//! copied here instead, and a test (with `harvest-image` as a dev-dependency,
//! which never reaches the WASM) fails if they ever disagree.

use serde::{Deserialize, Serialize};

use crate::store::Bytes32;

/// The largest image a listing may name, in bytes: `harvest_image`'s cap,
/// copied (see the module docs for why it is not imported); a test checks the
/// two agree.
pub const MAX_IMAGE_BYTES: usize = 256 * 1024;

/// The longest edge a listing's full photo may declare: `harvest_image`'s cap,
/// copied likewise.
pub const MAX_IMAGE_EDGE: u16 = 2048;

/// The most photos a listing may name, as the store contract enforces it.
pub const MAX_IMAGES_HARD: usize = 8;

/// The most photos the UI offers (Ian, 2026-10-01). Raising it up to
/// [`MAX_IMAGES_HARD`] is a UI change only.
pub const MAX_IMAGES_UI: usize = 4;

/// The longest description a photo may carry, in characters.
pub const MAX_ALT_CHARS: usize = 200;

/// The longest edge, in pixels, of the cover's thumbnail.
pub const MAX_THUMB_EDGE: u16 = 400;

/// The largest thumbnail a listing may declare, in bytes. The upload path aims
/// at about 30 KiB; this leaves room for a busy photo.
pub const MAX_THUMB_BYTES: usize = 64 * 1024;

const _: () = assert!(MAX_IMAGES_UI <= MAX_IMAGES_HARD);
const _: () = assert!(MAX_THUMB_BYTES <= MAX_IMAGE_BYTES);

/// One photo on a listing.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ListingImage {
    /// The photo. The upload path makes it at most 1600 px on its long edge;
    /// the store allows up to [`MAX_IMAGE_EDGE`].
    pub full: ImageBlob,
    /// A small copy for grids and rows (at most [`MAX_THUMB_EDGE`] px and
    /// [`MAX_THUMB_BYTES`]). On the cover (the first photo) only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumb: Option<ImageBlob>,
    /// The photo's average colour, shown while it loads or if it never does.
    pub colour: [u8; 3],
    /// What the photo shows, for screen readers. Optional; at most
    /// [`MAX_ALT_CHARS`] characters, none of them a control, a direction
    /// override or an invisible format character (see `is_hidden_char`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alt: String,
}

/// One image contract a listing names. There is no format field: every image
/// is a baseline JPEG (harvest#212).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ImageBlob {
    /// BLAKE3 of the exact bytes, which is the image contract's parameters.
    pub hash: Bytes32,
    /// The bytes' length, as the seller declares it; a reader checks it against
    /// what it fetched (see the module docs).
    pub len: u32,
    pub width: u16,
    pub height: u16,
}

impl ImageBlob {
    fn problem(&self, max_edge: u16, max_bytes: usize) -> Option<String> {
        if self.len == 0 || self.len as usize > max_bytes {
            return Some(format!(
                "a photo must be 1 to {max_bytes} bytes, not {}",
                self.len
            ));
        }
        if self.width == 0 || self.height == 0 || self.width > max_edge || self.height > max_edge {
            return Some(format!(
                "a photo must be 1 to {max_edge} pixels on each edge, not {}x{}",
                self.width, self.height
            ));
        }
        None
    }
}

/// What is wrong with a listing's photos, as the store contract judges it, or
/// `None`.
pub fn images_problem(images: &[ListingImage]) -> Option<String> {
    if images.len() > MAX_IMAGES_HARD {
        return Some(format!(
            "at most {MAX_IMAGES_HARD} photos, not {}",
            images.len()
        ));
    }
    for (i, image) in images.iter().enumerate() {
        if let Some(problem) = image.full.problem(MAX_IMAGE_EDGE, MAX_IMAGE_BYTES) {
            return Some(problem);
        }
        match (&image.thumb, i) {
            (Some(thumb), 0) => {
                if let Some(problem) = thumb.problem(MAX_THUMB_EDGE, MAX_THUMB_BYTES) {
                    return Some(format!("the cover's thumbnail: {problem}"));
                }
            }
            (None, 0) => return Some("the cover photo needs a thumbnail".into()),
            (Some(_), _) => return Some("only the cover photo has a thumbnail".into()),
            (None, _) => {}
        }
        if image.alt.chars().count() > MAX_ALT_CHARS {
            return Some(format!(
                "a photo's description is at most {MAX_ALT_CHARS} characters"
            ));
        }
        if image.alt.chars().any(is_hidden_char) {
            return Some("a photo's description has a control or invisible character".into());
        }
        // Full photos only: the cover's thumbnail is a different image
        // contract, and may even share bytes with a full photo.
        if images[..i]
            .iter()
            .any(|earlier| earlier.full.hash == image.full.hash)
        {
            return Some("the same photo appears twice".into());
        }
    }
    None
}

/// A character that hides or rewrites what a description says: a control
/// (newlines included), a direction override or isolate (which reorder the
/// text around them), or an invisible character with no job in ordinary
/// writing (soft hyphen, combining grapheme joiner, zero-width space, word joiner and invisible operators, BOM, the
/// Mongolian vowel separator, the deprecated format characters, Hangul
/// fillers, interlinear annotation marks). Each lets a description display,
/// or be read aloud, as something other than what it says.
///
/// Deliberately ALLOWED, because real writing needs them: the zero-width
/// joiner and non-joiner (emoji sequences such as families and the rainbow
/// flag; Persian and several Indic scripts), the left-to-right, right-to-left
/// and Arabic letter marks (mixed-direction text), variation selectors, and
/// tag characters (subdivision flags). Changing this set changes what the
/// store contract accepts, so it is a re-key.
fn is_hidden_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{180E}'
                | '\u{200B}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
        )
}

/// [`images_problem`] for one listing, as the error the store's merge
/// returns. Called wherever the store accepts a listing: on the whole state
/// (`ListingsV1::verify`) and on each listing a delta adds
/// (`ListingsV1::apply_delta`), since a contract may merge without
/// re-verifying the whole state.
pub fn check_listing_images(listing: &crate::listing::Listing) -> Result<(), String> {
    match images_problem(&listing.images) {
        Some(problem) => Err(format!("listing {}: {problem}", listing.id)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
