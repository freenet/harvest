//! The "Photos (optional)" part of the listing form: add photos from the
//! device, put them in order (the first is the cover), describe them, remove
//! them.
//!
//! What a photo becomes in the listing, and what has to be uploaded before
//! the listing may be signed, are worked out by plain functions here
//! ([`listing_images`], [`uploads`]) so they are tested on the host; the
//! component only edits a list of [`PhotoDraft`]s.

use dioxus::prelude::*;
use harvest_common::listing::Listing;
use harvest_common::listing_image::{ImageBlob, ListingImage, MAX_ALT_CHARS, MAX_IMAGES_UI};

/// One photo on the form.
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct PhotoDraft {
    /// Stable across reordering, for rendering.
    pub key: u64,
    pub full: ImageBlob,
    /// The thumbnail, if one is known: every photo added here has one; of a
    /// published listing's photos, only the cover does.
    pub thumb: Option<ImageBlob>,
    pub colour: [u8; 3],
    pub alt: String,
    /// The bytes to upload, for a photo added here. A published photo's are
    /// already on the network.
    pub full_bytes: Option<Vec<u8>>,
    pub thumb_bytes: Option<Vec<u8>>,
    /// A `blob:` URL showing the photo, once one has been made.
    pub preview: Option<String>,
}

/// The photos of a listing being edited, in order.
pub(crate) fn drafts_from_listing(listing: Option<&Listing>) -> Vec<PhotoDraft> {
    listing
        .map(|l| {
            l.images
                .iter()
                .enumerate()
                .map(|(i, image)| PhotoDraft {
                    key: i as u64,
                    full: image.full.clone(),
                    thumb: image.thumb.clone(),
                    colour: image.colour,
                    alt: image.alt.clone(),
                    full_bytes: None,
                    thumb_bytes: None,
                    preview: None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// What the listing will name: the photos in order, the first carrying its
/// thumbnail and no other. Fails when the photo in first place has no known
/// thumbnail (a published photo moved to the front), or when a description
/// breaks the store's rules, so nothing is signed that the store refuses.
pub(crate) fn listing_images(drafts: &[PhotoDraft]) -> Result<Vec<ListingImage>, String> {
    // The UI's limit applies when a photo is ADDED (`add_photo`), not here:
    // a listing another client gave more photos (up to the store's 8) must
    // still be editable, a count change included. The store's own rules
    // decide below.
    let mut images = Vec::with_capacity(drafts.len());
    for (i, d) in drafts.iter().enumerate() {
        let thumb = if i == 0 {
            Some(d.thumb.clone().ok_or(
                "To make this photo the cover, add it again from your device.".to_string(),
            )?)
        } else {
            None
        };
        images.push(ListingImage {
            full: d.full.clone(),
            thumb,
            colour: d.colour,
            alt: d.alt.trim().to_string(),
        });
    }
    if let Some(problem) = harvest_common::listing_image::images_problem(&images) {
        return Err(format!("Photos: {problem}."));
    }
    Ok(images)
}

/// The image contracts to upload before the listing is signed, as (hash,
/// bytes): every photo added here, and the cover's thumbnail if it was
/// added here. Thumbnails of photos that are not the cover are not named by
/// the listing and are not uploaded.
pub(crate) fn uploads(drafts: &[PhotoDraft]) -> Vec<([u8; 32], Vec<u8>)> {
    let mut out = Vec::new();
    for (i, d) in drafts.iter().enumerate() {
        if i == 0 {
            if let (Some(thumb), Some(bytes)) = (&d.thumb, &d.thumb_bytes) {
                out.push((thumb.hash.0, bytes.clone()));
            }
        }
        if let Some(bytes) = &d.full_bytes {
            out.push((d.full.hash.0, bytes.clone()));
        }
    }
    out
}

/// Move the photo at `i` one place earlier (towards the cover).
pub(crate) fn move_earlier(drafts: &mut [PhotoDraft], i: usize) {
    if i > 0 && i < drafts.len() {
        drafts.swap(i - 1, i);
    }
}

/// Move the photo at `i` one place later.
pub(crate) fn move_later(drafts: &mut [PhotoDraft], i: usize) {
    if i + 1 < drafts.len() {
        drafts.swap(i, i + 1);
    }
}

/// What adding a photo did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Added {
    /// A new photo, at the end.
    New,
    /// The same photo was already on the form without its bytes (a
    /// published photo, perhaps one the network lost): its bytes are now
    /// attached, so saving uploads it again.
    Restored,
    /// Already on the form, with its bytes.
    Duplicate,
    /// The form already has [`MAX_IMAGES_UI`] photos.
    Full,
}

/// Add a freshly encoded photo, or give a photo already on the form back
/// its bytes. A browser re-encodes the same file to the same bytes, so
/// adding a published photo again is how a missing one is put back.
pub(crate) fn add_photo(drafts: &mut Vec<PhotoDraft>, new: PhotoDraft) -> Added {
    if let Some(existing) = drafts.iter_mut().find(|d| d.full.hash == new.full.hash) {
        if existing.full_bytes.is_some() {
            return Added::Duplicate;
        }
        existing.full_bytes = new.full_bytes;
        existing.thumb = new.thumb;
        existing.thumb_bytes = new.thumb_bytes;
        if existing.preview.is_none() {
            existing.preview = new.preview;
        }
        return Added::Restored;
    }
    if drafts.len() >= MAX_IMAGES_UI {
        return Added::Full;
    }
    drafts.push(new);
    Added::New
}

/// Where the photo with `key` is now, if it is still on the form. Every
/// tile action goes through this rather than a captured position, so two
/// clicks landing before a re-render act on the photo clicked, or on
/// nothing, never on whatever slid into its place.
pub(crate) fn position(drafts: &[PhotoDraft], key: u64) -> Option<usize> {
    drafts.iter().position(|d| d.key == key)
}

/// Upload every pending photo, all at once, and call `finish` (which signs
/// and publishes the listing) only if EVERY upload was acknowledged. A
/// failure is returned and `finish` is not called, so a listing never names
/// a photo its seller's node did not take.
pub(crate) async fn publish_after_uploads<P, Fut, F>(
    pending: Vec<([u8; 32], Vec<u8>)>,
    put: P,
    finish: F,
) -> Result<(), String>
where
    P: Fn([u8; 32], Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
    F: FnOnce(),
{
    let results =
        futures::future::join_all(pending.into_iter().map(|(hash, bytes)| put(hash, bytes))).await;
    for r in results {
        r?;
    }
    finish();
    Ok(())
}

#[component]
pub(crate) fn PhotoEditor(
    photos: Signal<Vec<PhotoDraft>>,
    /// Photos still being prepared; the form will not publish while any are.
    busy: Signal<usize>,
    /// The form is publishing: nothing here may change.
    #[props(default)]
    disabled: bool,
) -> Element {
    let message = use_signal(|| None::<String>);
    let next_key = use_signal(|| 1_000u64);
    let count = photos.read().len();
    let room = MAX_IMAGES_UI.saturating_sub(count);
    // Previews of photos still on the form when it goes (Cancel, or opening
    // another listing). Saving and Remove revoke theirs as they go.
    use_drop(move || {
        #[cfg(target_arch = "wasm32")]
        for d in photos.peek().iter() {
            if let Some(url) = &d.preview {
                crate::image_pipeline::revoke_preview(url);
            }
        }
    });

    rsx! {
        div { class: "form-group photo-editor",
            if room > 0 && !disabled {
                label { class: "form-label", r#for: "listing-photo-input", "Photos (optional)" }
            } else {
                p { class: "form-label", "Photos (optional)" }
            }
            p { class: "text-muted small",
                "Up to {MAX_IMAGES_UI}. The first is the cover. Photos are made smaller on this device and saved without location or camera details."
            }
            if count > 0 {
                ol { class: "photo-grid",
                    for (i, draft) in photos.read().iter().enumerate() {
                        PhotoTile {
                            key: "{draft.key}",
                            photos,
                            photo_key: draft.key,
                            index: i,
                            count,
                            hash: draft.full.hash.0,
                            preview: draft.preview.clone(),
                            colour: draft.colour,
                            width: draft.full.width,
                            height: draft.full.height,
                            alt: draft.alt.clone(),
                            local: draft.full_bytes.is_some(),
                            disabled,
                        }
                    }
                }
            }
            if room > 0 && !disabled {
                input {
                    id: "listing-photo-input",
                    class: "photo-input",
                    r#type: "file",
                    accept: "image/*",
                    multiple: true,
                    onchange: move |_| {
                        #[cfg(target_arch = "wasm32")]
                        add_picked_files(photos, message, busy, next_key);
                        #[cfg(not(target_arch = "wasm32"))]
                        let _ = (message, busy, next_key);
                    },
                }
            } else if room == 0 {
                p { class: "text-muted small", "That's the most photos a listing can have." }
            }
            div { role: "status", aria_live: "polite",
                if busy() > 0 {
                    p { class: "text-muted small", "Preparing photos\u{2026}" }
                }
                if let Some(m) = message() {
                    p { class: "text-warning", "{m}" }
                }
            }
        }
    }
}

#[component]
fn PhotoTile(
    photos: Signal<Vec<PhotoDraft>>,
    photo_key: u64,
    index: usize,
    count: usize,
    hash: [u8; 32],
    preview: Option<String>,
    colour: [u8; 3],
    width: u16,
    height: u16,
    alt: String,
    /// The photo's bytes are on this device (added or added again here).
    local: bool,
    disabled: bool,
) -> Element {
    let n = index + 1;
    rsx! {
        li { class: "photo-tile",
            PhotoPreview { hash, preview, colour, width, height, alt: alt.clone(), local }
            if index == 0 {
                span { class: "photo-cover", "Cover" }
            }
            input {
                class: "form-input photo-alt",
                r#type: "text",
                maxlength: "{MAX_ALT_CHARS}",
                placeholder: "Describe this photo (optional)",
                aria_label: "Describe photo {n}",
                disabled,
                value: "{alt}",
                oninput: move |e| {
                    photos.with_mut(|p| {
                        if let Some(i) = position(p, photo_key) {
                            p[i].alt = e.value();
                        }
                    })
                },
            }
            div { class: "photo-actions",
                button {
                    class: "btn btn-sm btn-outline",
                    disabled: disabled || index == 0,
                    aria_label: "Move photo {n} earlier",
                    onclick: move |_| {
                        photos.with_mut(|p| {
                            if let Some(i) = position(p, photo_key) {
                                move_earlier(p, i);
                            }
                        })
                    },
                    "Move earlier"
                }
                button {
                    class: "btn btn-sm btn-outline",
                    disabled: disabled || index + 1 >= count,
                    aria_label: "Move photo {n} later",
                    onclick: move |_| {
                        photos.with_mut(|p| {
                            if let Some(i) = position(p, photo_key) {
                                move_later(p, i);
                            }
                        })
                    },
                    "Move later"
                }
                button {
                    class: "btn btn-sm btn-outline",
                    disabled,
                    aria_label: "Remove photo {n}",
                    onclick: move |_| {
                        photos.with_mut(|p| {
                            if let Some(i) = position(p, photo_key) {
                                let removed = p.remove(i);
                                #[cfg(target_arch = "wasm32")]
                                if let Some(url) = removed.preview {
                                    crate::image_pipeline::revoke_preview(&url);
                                }
                                #[cfg(not(target_arch = "wasm32"))]
                                let _ = removed;
                            }
                        })
                    },
                    "Remove"
                }
            }
        }
    }
}

/// A photo's picture: its local preview, or for a published photo, fetched
/// from the network (the seller's own node holds it); its colour until then.
/// A published photo the network no longer has says so, since adding it
/// again is the seller's to do.
#[component]
fn PhotoPreview(
    hash: [u8; 32],
    preview: Option<String>,
    colour: [u8; 3],
    width: u16,
    height: u16,
    alt: String,
    /// Its bytes are on this device, so it is uploaded when the form saves.
    local: bool,
) -> Element {
    let [r, g, b] = colour;
    let ratio = format!("{} / {}", width.max(1), height.max(1));
    #[cfg(target_arch = "wasm32")]
    let (src, missing) = {
        let has_preview = preview.is_some();
        // Ok(url) once fetched; Err(true) when the network has no copy.
        let fetched = use_resource(move || async move {
            if has_preview {
                return None;
            }
            Some(
                match crate::gateway::image_ops::fetch_image(hash, true).await {
                    crate::gateway::image_ops::Fetched::Bytes(bytes)
                        if harvest_image::validate(&hash, &bytes).is_ok() =>
                    {
                        crate::image_pipeline::preview_url(&bytes).ok_or(false)
                    }
                    crate::gateway::image_ops::Fetched::Absent => Err(true),
                    _ => Err(false),
                },
            )
        });
        // A fetched preview is this component's to revoke.
        use_drop(move || {
            if let Some(Some(Ok(url))) = fetched.peek().as_ref() {
                crate::image_pipeline::revoke_preview(url);
            }
        });
        let result = fetched.read().clone().flatten();
        match (&preview, result) {
            (Some(p), _) => (Some(p.clone()), false),
            (None, Some(Ok(url))) => (Some(url), false),
            (None, Some(Err(absent))) => (None, absent),
            (None, None) => (None, false),
        }
    };
    #[cfg(not(target_arch = "wasm32"))]
    let (src, missing) = {
        let _ = hash;
        (preview.clone(), false)
    };
    rsx! {
        div {
            class: "photo-frame",
            style: "background-color: rgb({r}, {g}, {b}); aspect-ratio: {ratio};",
            if let Some(src) = src {
                img { class: "photo-img", src: "{src}", alt: "{alt}" }
            } else if missing && !local {
                p { class: "photo-missing", "Missing from Freenet. Add this photo again to put it back." }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn add_picked_files(
    mut photos: Signal<Vec<PhotoDraft>>,
    mut message: Signal<Option<String>>,
    mut busy: Signal<usize>,
    mut next_key: Signal<u64>,
) {
    use wasm_bindgen::JsCast;
    let Some(input) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id("listing-photo-input"))
        .and_then(|e| e.dyn_into::<web_sys::HtmlInputElement>().ok())
    else {
        return;
    };
    let Some(list) = input.files() else {
        return;
    };
    let mut files = Vec::new();
    for i in 0..list.length() {
        if let Some(f) = list.get(i) {
            files.push(f);
        }
    }
    // Let the same file be picked again after it is removed.
    input.set_value("");
    message.set(None);
    // One task, in the order picked: the first file picked becomes the
    // cover, whichever would have finished encoding first. Encoding one at
    // a time also holds one decoded camera photo in memory, not several.
    busy += files.len();
    spawn(async move {
        for file in files {
            let result = crate::image_pipeline::encode_file(file).await;
            busy -= 1;
            let p = match result {
                Ok(p) => p,
                Err(e) => {
                    message.set(Some(e));
                    continue;
                }
            };
            let key = next_key();
            next_key += 1;
            let preview = crate::image_pipeline::preview_url(&p.full);
            let draft = PhotoDraft {
                key,
                full: p.full_blob,
                thumb: Some(p.thumb_blob),
                colour: p.colour,
                alt: String::new(),
                full_bytes: Some(p.full),
                thumb_bytes: Some(p.thumb),
                preview: preview.clone(),
            };
            let outcome = photos.with_mut(|list| add_photo(list, draft));
            let kept = matches!(outcome, Added::New)
                || (outcome == Added::Restored
                    && photos
                        .peek()
                        .iter()
                        .any(|d| d.preview.is_some() && d.preview == preview));
            if !kept {
                if let Some(url) = preview {
                    crate::image_pipeline::revoke_preview(&url);
                }
            }
            match outcome {
                Added::New => {}
                Added::Restored => message.set(Some(
                    "Added again. It will be uploaded when you save.".into(),
                )),
                Added::Duplicate => {
                    message.set(Some("That photo is already on this listing.".into()))
                }
                Added::Full => message.set(Some(format!(
                    "A listing can have {MAX_IMAGES_UI} photos, so that one was not added."
                ))),
            }
        }
    });
}

#[cfg(test)]
mod tests;
