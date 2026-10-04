//! A seller's photo, from the file they picked to the bytes a listing names.
//!
//! The browser decodes the file, scales it, and re-encodes it as a baseline
//! JPEG on a canvas: a full photo (long edge at most [`FULL_EDGE`]) and a
//! thumbnail (at most [`THUMB_EDGE`]). Re-encoding drops every metadata block
//! the camera wrote, location included. The result then goes through
//! `harvest_image::strip` and `sniff`, the same rules the image contract
//! applies, and is named by the hash of the STRIPPED bytes, so what the
//! listing signs is exactly what is uploaded.
//!
//! Only [`encode_file`] needs a browser. Everything it hands on is checked by
//! [`prepare`], which is plain Rust and tested on the host.

use harvest_common::listing_image::{ImageBlob, MAX_IMAGE_BYTES, MAX_THUMB_BYTES, MAX_THUMB_EDGE};
use harvest_common::store::Bytes32;

/// The longest edge of a full photo, in pixels.
pub const FULL_EDGE: u32 = 1600;
/// The longest edge of a thumbnail, in pixels.
pub const THUMB_EDGE: u32 = MAX_THUMB_EDGE as u32;
/// The size a full photo is squeezed under: below the contract's 256 KiB.
pub const FULL_TARGET_BYTES: usize = 240 * 1024;
/// The size a thumbnail is squeezed under: well below the store's 64 KiB.
pub const THUMB_TARGET_BYTES: usize = 30 * 1024;
/// Files larger than this are refused before decoding.
pub const MAX_INPUT_BYTES: f64 = 30.0 * 1024.0 * 1024.0;
/// Images with more pixels than this are refused before drawing: a phone's
/// 48-megapixel photo fits, a decompression bomb does not, and iOS limits a
/// canvas's area.
pub const MAX_INPUT_PIXELS: u64 = 50_000_000;
/// The JPEG qualities tried, best first.
pub const QUALITIES: [f64; 5] = [0.85, 0.75, 0.65, 0.55, 0.5];
/// What transparent areas are filled with before encoding (JPEG has no
/// transparency, and an unfilled canvas turns them black): the card colour.
pub const BACKGROUND: &str = "#f3ede2";

/// The seller-facing message for a photo this browser produced that the
/// image rules refuse. The detail goes to the log.
pub const UNUSABLE: &str =
    "This photo could not be used. Try another photo, or a JPEG or PNG copy of it.";

/// One encoded image, as the browser produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    pub bytes: Vec<u8>,
}

/// A photo ready to upload: the bytes of each image contract and the
/// reference each one gets in the listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPhoto {
    pub full: Vec<u8>,
    pub full_blob: ImageBlob,
    pub thumb: Vec<u8>,
    pub thumb_blob: ImageBlob,
    /// The photo's average colour, shown while it loads.
    pub colour: [u8; 3],
}

/// Check what the browser produced and name it.
///
/// Each image is stripped of any metadata block a browser might have written
/// (no engine tested writes one, but `strip` costs nothing when it does not),
/// then must pass `sniff` and the store's size and edge limits. The reference
/// carries the hash of the stripped bytes, which are the bytes uploaded.
pub fn prepare(full: &[u8], thumb: &[u8], colour: [u8; 3]) -> Result<PreparedPhoto, String> {
    let (full, full_blob) = named(
        full,
        MAX_IMAGE_BYTES,
        harvest_common::listing_image::MAX_IMAGE_EDGE,
    )?;
    let (thumb, thumb_blob) = named(thumb, MAX_THUMB_BYTES, MAX_THUMB_EDGE)?;
    Ok(PreparedPhoto {
        full,
        full_blob,
        thumb,
        thumb_blob,
        colour,
    })
}

fn named(bytes: &[u8], max_bytes: usize, max_edge: u16) -> Result<(Vec<u8>, ImageBlob), String> {
    let stripped = harvest_image::strip(bytes).map_err(|e| {
        dioxus::logger::tracing::warn!("photo refused by strip: {e}");
        UNUSABLE.to_string()
    })?;
    let info = harvest_image::sniff(&stripped).map_err(|e| {
        dioxus::logger::tracing::warn!("photo refused by sniff: {e}");
        UNUSABLE.to_string()
    })?;
    if stripped.len() > max_bytes {
        return Err(format!(
            "This photo is still {} KB after shrinking; the most is {} KB.",
            stripped.len() / 1024,
            max_bytes / 1024
        ));
    }
    if info.width > max_edge || info.height > max_edge {
        return Err(format!(
            "This photo is {}x{} pixels; the most is {max_edge}.",
            info.width, info.height
        ));
    }
    let blob = ImageBlob {
        hash: Bytes32(harvest_image::image_hash(&stripped)),
        len: stripped.len() as u32,
        width: info.width,
        height: info.height,
    };
    Ok((stripped, blob))
}

/// The size to draw an image of `width` x `height` at so its long edge is at
/// most `edge`. Never enlarges.
pub fn fit(width: u32, height: u32, edge: u32) -> (u32, u32) {
    let long = width.max(height).max(1);
    if long <= edge {
        return (width.max(1), height.max(1));
    }
    let scale = edge as f64 / long as f64;
    (
        ((width as f64 * scale).round() as u32).max(1),
        ((height as f64 * scale).round() as u32).max(1),
    )
}

/// The mean colour of RGBA pixels.
pub fn mean_colour(rgba: &[u8]) -> [u8; 3] {
    let n = (rgba.len() / 4).max(1) as u64;
    let mut sum = [0u64; 3];
    for px in rgba.chunks_exact(4) {
        for c in 0..3 {
            sum[c] += u64::from(px[c]);
        }
    }
    [(sum[0] / n) as u8, (sum[1] / n) as u8, (sum[2] / n) as u8]
}

/// Why a file the seller picked was refused before it was decoded.
pub fn input_problem(size_bytes: f64, mime: &str) -> Option<String> {
    if size_bytes > MAX_INPUT_BYTES {
        return Some("This file is over 30 MB. Try a smaller photo.".into());
    }
    if mime == "image/svg+xml" {
        return Some("Drawings in SVG format can't be used. Try a JPEG or PNG.".into());
    }
    if !mime.is_empty() && !mime.starts_with("image/") {
        return Some("This file isn't a photo.".into());
    }
    None
}

/// Decode, scale and re-encode a picked file, then [`prepare`] it.
#[cfg(target_arch = "wasm32")]
pub async fn encode_file(file: web_sys::File) -> Result<PreparedPhoto, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    if let Some(problem) = input_problem(file.size(), &file.type_()) {
        return Err(problem);
    }
    let window = web_sys::window().ok_or("no window")?;
    let unsupported = "This photo's format isn't supported in this browser. Try a JPEG or PNG.";
    let options = web_sys::ImageBitmapOptions::new();
    options.set_image_orientation(web_sys::ImageOrientation::FromImage);
    let promise = window
        .create_image_bitmap_with_blob_and_image_bitmap_options(&file, &options)
        .map_err(|_| unsupported.to_string())?;
    let bitmap: web_sys::ImageBitmap = JsFuture::from(promise)
        .await
        .map_err(|_| unsupported.to_string())?
        .dyn_into()
        .map_err(|_| unsupported.to_string())?;
    let result = encode_bitmap(&bitmap).await;
    // Released on every path: a decoded photo is tens of megabytes.
    bitmap.close();
    let (full, thumb, colour) = result?;
    prepare(&full, &thumb, colour)
}

/// The full photo, the thumbnail and its mean colour. The pixel limit is
/// checked here, after decoding: a browser exposes no size before it
/// decodes, so it bounds the canvas work and memory that follow, not the
/// decode itself (the browser's own decoder bounds that).
#[cfg(target_arch = "wasm32")]
async fn encode_bitmap(
    bitmap: &web_sys::ImageBitmap,
) -> Result<(Vec<u8>, Vec<u8>, [u8; 3]), String> {
    let (w, h) = (bitmap.width(), bitmap.height());
    if u64::from(w) * u64::from(h) > MAX_INPUT_PIXELS {
        return Err("This photo has too many pixels. Try a smaller one.".into());
    }
    let full = encode_at(bitmap, FULL_EDGE, FULL_TARGET_BYTES, false)
        .await?
        .0;
    let (thumb, colour) = encode_at(bitmap, THUMB_EDGE, THUMB_TARGET_BYTES, true).await?;
    Ok((full, thumb, colour))
}

/// Draw `bitmap` with its long edge at most `edge`, and encode it as JPEG at
/// the best quality that fits `target`, shrinking further if none does.
/// Also returns the drawn image's mean colour.
#[cfg(target_arch = "wasm32")]
async fn encode_at(
    bitmap: &web_sys::ImageBitmap,
    edge: u32,
    target: usize,
    with_colour: bool,
) -> Result<(Vec<u8>, [u8; 3]), String> {
    use wasm_bindgen::JsCast;

    let document = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("no document")?;
    // Start no larger than the photo itself, so a small photo that does not
    // fit the size target shrinks at once instead of redrawing at one size.
    let mut limit = edge.min(bitmap.width().max(bitmap.height()).max(1));
    loop {
        let (dw, dh) = fit(bitmap.width(), bitmap.height(), limit);
        let canvas: web_sys::HtmlCanvasElement = document
            .create_element("canvas")
            .map_err(|_| "no canvas")?
            .dyn_into()
            .map_err(|_| "no canvas")?;
        canvas.set_width(dw);
        canvas.set_height(dh);
        let ctx: web_sys::CanvasRenderingContext2d = canvas
            .get_context("2d")
            .ok()
            .flatten()
            .ok_or("no canvas context")?
            .dyn_into()
            .map_err(|_| "no canvas context")?;
        ctx.set_fill_style_str(BACKGROUND);
        ctx.fill_rect(0.0, 0.0, dw as f64, dh as f64);
        ctx.draw_image_with_image_bitmap_and_dw_and_dh(bitmap, 0.0, 0.0, dw as f64, dh as f64)
            .map_err(|_| "This photo could not be drawn.")?;
        // Only for the thumbnail: copying a full photo's pixels out to
        // average them is megabytes of work for one colour.
        let colour = if with_colour {
            ctx.get_image_data(0.0, 0.0, dw as f64, dh as f64)
                .map(|d| mean_colour(&d.data()))
                .unwrap_or([200, 190, 170])
        } else {
            [0, 0, 0]
        };
        for q in QUALITIES {
            let bytes = to_jpeg(&canvas, q).await?;
            if bytes.len() <= target {
                return Ok((bytes, colour));
            }
        }
        // Still too large at the lowest quality: a smaller picture.
        if limit <= 64 {
            return Err("This photo could not be made small enough.".into());
        }
        limit = limit * 85 / 100;
    }
}

#[cfg(target_arch = "wasm32")]
async fn to_jpeg(canvas: &web_sys::HtmlCanvasElement, quality: f64) -> Result<Vec<u8>, String> {
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        let reject_later = reject.clone();
        let done = Closure::once_into_js(move |blob: wasm_bindgen::JsValue| {
            if blob.is_null() {
                let _ = reject_later.call0(&wasm_bindgen::JsValue::NULL);
            } else {
                let _ = resolve.call1(&wasm_bindgen::JsValue::NULL, &blob);
            }
        });
        if canvas
            .to_blob_with_type_and_encoder_options(
                done.unchecked_ref(),
                "image/jpeg",
                &wasm_bindgen::JsValue::from_f64(quality),
            )
            .is_err()
        {
            let _ = reject.call0(&wasm_bindgen::JsValue::NULL);
        }
    });
    let blob: web_sys::Blob = JsFuture::from(promise)
        .await
        .map_err(|_| "This photo could not be encoded.".to_string())?
        .dyn_into()
        .map_err(|_| "This photo could not be encoded.".to_string())?;
    if blob.type_() != "image/jpeg" {
        return Err("This browser could not save the photo as JPEG.".into());
    }
    let buffer = JsFuture::from(blob.array_buffer())
        .await
        .map_err(|_| "This photo could not be read back.".to_string())?;
    Ok(js_sys::Uint8Array::new(&buffer).to_vec())
}

/// A `blob:` URL showing `jpeg`, for a preview. The caller revokes it.
#[cfg(target_arch = "wasm32")]
pub fn preview_url(jpeg: &[u8]) -> Option<String> {
    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(jpeg));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type("image/jpeg");
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &options).ok()?;
    web_sys::Url::create_object_url_with_blob(&blob).ok()
}

#[cfg(target_arch = "wasm32")]
pub fn revoke_preview(url: &str) {
    let _ = web_sys::Url::revoke_object_url(url);
}

#[cfg(test)]
mod tests;
