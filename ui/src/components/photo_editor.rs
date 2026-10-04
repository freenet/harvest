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
    if drafts.len() > MAX_IMAGES_UI {
        return Err(format!(
            "A listing can have at most {MAX_IMAGES_UI} photos."
        ));
    }
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

/// Whether a photo with these bytes is already on the form.
pub(crate) fn already_added(drafts: &[PhotoDraft], full: &ImageBlob) -> bool {
    drafts.iter().any(|d| d.full.hash == full.hash)
}

#[component]
pub(crate) fn PhotoEditor(photos: Signal<Vec<PhotoDraft>>) -> Element {
    let message = use_signal(|| None::<String>);
    let busy = use_signal(|| 0usize);
    let next_key = use_signal(|| 1_000u64);
    let count = photos.read().len();
    let room = MAX_IMAGES_UI.saturating_sub(count);

    rsx! {
        div { class: "form-group photo-editor",
            label { class: "form-label", r#for: "listing-photo-input", "Photos (optional)" }
            p { class: "text-muted small",
                "Up to {MAX_IMAGES_UI}. The first is the cover. Photos are shrunk on this device and saved without location or camera details."
            }
            if count > 0 {
                ol { class: "photo-grid",
                    for (i, draft) in photos.read().iter().enumerate() {
                        li { key: "{draft.key}", class: "photo-tile",
                            PhotoPreview { draft: draft.clone() }
                            if i == 0 {
                                span { class: "photo-cover", "Cover" }
                            }
                            input {
                                class: "form-input photo-alt",
                                r#type: "text",
                                maxlength: "{MAX_ALT_CHARS}",
                                placeholder: "Describe this photo (optional)",
                                aria_label: "Describe photo {i + 1}",
                                value: "{draft.alt}",
                                oninput: move |e| photos.with_mut(|p| p[i].alt = e.value()),
                            }
                            div { class: "photo-actions",
                                button {
                                    class: "btn btn-sm btn-outline",
                                    disabled: i == 0,
                                    aria_label: "Move photo {i + 1} earlier",
                                    onclick: move |_| photos.with_mut(|p| move_earlier(p, i)),
                                    "Move earlier"
                                }
                                button {
                                    class: "btn btn-sm btn-outline",
                                    disabled: i + 1 >= count,
                                    aria_label: "Move photo {i + 1} later",
                                    onclick: move |_| photos.with_mut(|p| move_later(p, i)),
                                    "Move later"
                                }
                                button {
                                    class: "btn btn-sm btn-outline",
                                    aria_label: "Remove photo {i + 1}",
                                    onclick: move |_| {
                                        photos.with_mut(|p| {
                                            let removed = p.remove(i);
                                            #[cfg(target_arch = "wasm32")]
                                            if let Some(url) = removed.preview {
                                                crate::image_pipeline::revoke_preview(&url);
                                            }
                                            #[cfg(not(target_arch = "wasm32"))]
                                            let _ = removed;
                                        });
                                    },
                                    "Remove"
                                }
                            }
                        }
                    }
                }
            }
            if room > 0 {
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
            } else {
                p { class: "text-muted small", "That's the most photos a listing can have." }
            }
            if busy() > 0 {
                p { class: "text-muted small", "Preparing photos\u{2026}" }
            }
            if let Some(m) = message() {
                p { class: "text-warning", "{m}" }
            }
        }
    }
}

/// A photo's picture: its local preview, or for a published photo, fetched
/// from the network (the seller's own node holds it); its colour until then.
#[component]
fn PhotoPreview(draft: PhotoDraft) -> Element {
    let [r, g, b] = draft.colour;
    let ratio = format!("{} / {}", draft.full.width.max(1), draft.full.height.max(1));
    #[cfg(target_arch = "wasm32")]
    let fetched = {
        let hash = draft.full.hash.0;
        let has_preview = draft.preview.is_some();
        use_resource(move || async move {
            if has_preview {
                return None;
            }
            match crate::gateway::image_ops::fetch_image(hash, true).await {
                crate::gateway::image_ops::Fetched::Bytes(bytes)
                    if harvest_image::validate(&hash, &bytes).is_ok() =>
                {
                    crate::image_pipeline::preview_url(&bytes)
                }
                _ => None,
            }
        })
    };
    #[cfg(target_arch = "wasm32")]
    let src = draft
        .preview
        .clone()
        .or_else(|| fetched.read().clone().flatten());
    #[cfg(not(target_arch = "wasm32"))]
    let src = draft.preview.clone();
    rsx! {
        div {
            class: "photo-frame",
            style: "background-color: rgb({r}, {g}, {b}); aspect-ratio: {ratio};",
            if let Some(src) = src {
                img { class: "photo-img", src: "{src}", alt: "{draft.alt}" }
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
    let room = MAX_IMAGES_UI.saturating_sub(photos.read().len() + busy());
    if files.len() > room {
        message.set(Some(format!(
            "Only {room} more photo{} can be added.",
            if room == 1 { "" } else { "s" }
        )));
        files.truncate(room);
    }
    for file in files {
        busy += 1;
        spawn(async move {
            let result = crate::image_pipeline::encode_file(file).await;
            busy -= 1;
            match result {
                Ok(p) => {
                    if already_added(&photos.read(), &p.full_blob) {
                        message.set(Some("That photo is already on this listing.".into()));
                        return;
                    }
                    if photos.read().len() >= MAX_IMAGES_UI {
                        return;
                    }
                    let key = next_key();
                    next_key += 1;
                    let preview = crate::image_pipeline::preview_url(&p.full);
                    photos.with_mut(|list| {
                        list.push(PhotoDraft {
                            key,
                            full: p.full_blob,
                            thumb: Some(p.thumb_blob),
                            colour: p.colour,
                            alt: String::new(),
                            full_bytes: Some(p.full),
                            thumb_bytes: Some(p.thumb),
                            preview,
                        })
                    });
                }
                Err(e) => message.set(Some(e)),
            }
        });
    }
}

#[cfg(test)]
mod tests;
