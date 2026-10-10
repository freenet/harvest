use super::*;
use harvest_common::store::Bytes32;

fn blob(seed: u8, edge: u16) -> ImageBlob {
    ImageBlob {
        hash: Bytes32([seed; 32]),
        len: 10_000,
        width: edge,
        height: edge * 3 / 4,
    }
}

/// A photo added on this device: bytes for both images.
fn added(seed: u8) -> PhotoDraft {
    PhotoDraft {
        key: seed as u64,
        full: blob(seed, 1600),
        thumb: Some(blob(seed + 100, 400)),
        colour: [seed, 0, 0],
        alt: String::new(),
        full_bytes: Some(vec![seed; 3]),
        thumb_bytes: Some(vec![seed + 100; 3]),
        preview: None,
    }
}

/// A published photo: no bytes, and a thumbnail only if it was the cover.
fn published(seed: u8, cover: bool) -> PhotoDraft {
    PhotoDraft {
        full_bytes: None,
        thumb_bytes: None,
        thumb: cover.then(|| blob(seed + 100, 400)),
        ..added(seed)
    }
}

#[test]
fn only_the_cover_carries_its_thumbnail() {
    let images = listing_images(&[added(1), added(2), added(3)]).unwrap();
    assert_eq!(images.len(), 3);
    assert_eq!(images[0].thumb, Some(blob(101, 400)));
    assert!(images[1].thumb.is_none() && images[2].thumb.is_none());
    assert_eq!(images[1].full, blob(2, 1600));
}

#[test]
fn reordering_moves_the_cover_and_its_thumbnail() {
    let mut drafts = vec![added(1), added(2)];
    move_later(&mut drafts, 0);
    let images = listing_images(&drafts).unwrap();
    assert_eq!(images[0].full, blob(2, 1600));
    assert_eq!(
        images[0].thumb,
        Some(blob(102, 400)),
        "the new cover's own thumbnail"
    );
    assert!(images[1].thumb.is_none());
    move_earlier(&mut drafts, 1);
    assert_eq!(drafts[0].full, blob(1, 1600));
    // Out of range does nothing.
    move_earlier(&mut drafts, 0);
    move_later(&mut drafts, 1);
    move_later(&mut drafts, 9);
    assert_eq!(drafts[0].full, blob(1, 1600));
}

#[test]
fn a_published_photo_without_a_thumbnail_cannot_be_the_cover() {
    let drafts = vec![published(2, false), published(1, true)];
    assert!(listing_images(&drafts).is_err());
    let drafts = vec![published(1, true), published(2, false)];
    assert!(listing_images(&drafts).is_ok());
}

#[test]
fn descriptions_are_trimmed_and_checked_by_the_stores_rules() {
    let mut d = added(1);
    d.alt = "  Jar, front  ".into();
    assert_eq!(listing_images(&[d.clone()]).unwrap()[0].alt, "Jar, front");
    d.alt = "line\nbreak".into();
    assert!(
        listing_images(&[d]).is_err(),
        "refused here, never signed and then refused"
    );
}

#[test]
fn uploads_are_the_added_photos_and_the_covers_thumbnail() {
    let drafts = vec![added(1), added(2), published(3, false)];
    let up = uploads(&drafts);
    let hashes: Vec<[u8; 32]> = up.iter().map(|(h, _)| *h).collect();
    assert_eq!(hashes, vec![[101; 32], [1; 32], [2; 32]]);
    assert_eq!(up[0].1, vec![101; 3]);
    // A published cover uploads nothing.
    assert!(uploads(&[published(1, true)]).is_empty());
}

#[test]
fn every_uploaded_hash_is_one_the_listing_names_and_every_new_one_named_is_uploaded() {
    let drafts = vec![added(2), published(1, false), added(3)];
    // What the listings page looks up, so the two cannot drift apart.
    let named =
        crate::components::seller_listings::photo_hashes(&jam(listing_images(&drafts).unwrap()));
    let uploaded: Vec<[u8; 32]> = uploads(&drafts).into_iter().map(|(h, _)| h).collect();
    for h in &uploaded {
        assert!(named.contains(h), "uploaded but not named");
    }
    for (i, d) in drafts.iter().enumerate() {
        if d.full_bytes.is_some() {
            assert!(uploaded.contains(&d.full.hash.0));
        }
        if i == 0 && d.thumb_bytes.is_some() {
            assert!(uploaded.contains(&d.thumb.as_ref().unwrap().hash.0));
        }
    }
}

/// A listing carrying `images`.
fn jam(images: Vec<ListingImage>) -> harvest_common::listing::Listing {
    harvest_common::listing::Listing {
        images,
        id: harvest_common::listing::ListingId([0; 32]),
        title: "Jam".into(),
        description: String::new(),
        kind: harvest_common::listing::ListingKind::Sale,
        price: None,
        created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        checkout: None,
        choices: Vec::new(),
    }
}

#[test]
fn a_listings_photos_come_back_as_drafts_in_order() {
    let listing = jam(listing_images(&[added(1), added(2)]).unwrap());
    let drafts = drafts_from_listing(Some(&listing));
    assert_eq!(drafts.len(), 2);
    assert!(drafts.iter().all(|d| d.full_bytes.is_none()));
    assert_eq!(
        listing_images(&drafts).unwrap(),
        listing.images,
        "unchanged photos round-trip"
    );
    assert!(
        uploads(&drafts).is_empty(),
        "nothing to upload for an unchanged edit"
    );
    assert!(drafts_from_listing(None).is_empty());
}

#[test]
fn adding_a_photo_already_on_the_form() {
    let mut drafts = vec![added(1)];
    assert_eq!(add_photo(&mut drafts, added(1)), Added::Duplicate);
    assert_eq!(drafts.len(), 1);
    assert_eq!(add_photo(&mut drafts, added(2)), Added::New);
    assert_eq!(drafts.len(), 2);
}

/// The recovery the seller's Listings page asks for: a published photo the
/// network lost is added again from the device. The same file re-encodes to
/// the same bytes, so it lands on the existing photo, which then uploads.
#[test]
fn adding_a_published_photo_again_restores_its_bytes_in_place() {
    let mut drafts = vec![published(1, false), published(2, true)];
    drafts.swap(0, 1);
    drafts[1].alt = "Jar, front".into();
    drafts[1].colour = [9, 9, 9];
    assert!(uploads(&drafts).is_empty());
    let mut again = added(1);
    again.key = 77;
    assert_eq!(add_photo(&mut drafts, again), Added::Restored);
    assert_eq!(drafts.len(), 2, "no second copy");
    assert_eq!(drafts[1].key, 1, "it keeps its place and key");
    assert_eq!(drafts[1].alt, "Jar, front", "and its description");
    assert_eq!(drafts[1].colour, [9, 9, 9], "and its colour");
    let up: Vec<[u8; 32]> = uploads(&drafts).into_iter().map(|(h, _)| h).collect();
    assert_eq!(up, vec![[1; 32]], "and is uploaded when the form saves");
    // A published photo added again can now be the cover: it has its
    // thumbnail.
    move_earlier(&mut drafts, 1);
    let images = listing_images(&drafts).unwrap();
    assert_eq!(images[0].thumb, Some(blob(101, 400)));
    let up: Vec<[u8; 32]> = uploads(&drafts).into_iter().map(|(h, _)| h).collect();
    assert_eq!(up, vec![[101; 32], [1; 32]]);
}

#[test]
fn the_ui_stops_at_four_photos_but_the_form_saves_more_from_elsewhere() {
    let mut drafts: Vec<PhotoDraft> = (1..=4).map(added).collect();
    assert_eq!(add_photo(&mut drafts, added(5)), Added::Full);
    assert_eq!(drafts.len(), 4);
    // A listing another client gave six photos still saves (a count
    // change, say): the store allows up to eight.
    let mut six: Vec<PhotoDraft> = (1..=6).map(|s| published(s, s == 1)).collect();
    assert!(listing_images(&six).is_ok());
    six.extend((7..=9).map(|s| published(s, false)));
    assert!(
        listing_images(&six).is_err(),
        "nine is over the store's limit"
    );
}

#[test]
fn tile_actions_find_their_photo_by_key() {
    let mut drafts = vec![added(1), added(2), added(3)];
    assert_eq!(position(&drafts, 2), Some(1));
    drafts.remove(0);
    assert_eq!(position(&drafts, 2), Some(0), "found where it now is");
    assert_eq!(
        position(&drafts, 1),
        None,
        "a removed photo is gone, not replaced"
    );
}

/// The publish order: `finish` (sign and publish) runs only after every
/// upload succeeded, and never after a failure.
#[test]
fn the_listing_is_published_only_after_every_upload() {
    use futures::executor::block_on;
    use std::cell::RefCell;
    let calls = RefCell::new(Vec::new());
    let published = RefCell::new(0u32);
    let ok = block_on(publish_after_uploads(
        vec![([1; 32], vec![1]), ([2; 32], vec![2])],
        |h, _| {
            calls.borrow_mut().push(h);
            // Each upload, when it runs, finds nothing published yet.
            let published = &published;
            async move {
                assert_eq!(*published.borrow(), 0, "published before an upload ran");
                Ok(())
            }
        },
        || *published.borrow_mut() += 1,
    ));
    assert_eq!(ok, Ok(()));
    assert_eq!(calls.borrow().len(), 2);
    assert_eq!(*published.borrow(), 1, "published once");

    let calls = RefCell::new(Vec::new());
    let published = RefCell::new(0u32);
    let failed = block_on(publish_after_uploads(
        vec![([1; 32], vec![1]), ([2; 32], vec![2])],
        |h, _| {
            calls.borrow_mut().push(h);
            // The FIRST fails, so an upload loop that stops at a failure
            // is caught by the count below.
            async move {
                if h == [1; 32] {
                    Err("refused".to_string())
                } else {
                    Ok(())
                }
            }
        },
        || *published.borrow_mut() += 1,
    ));
    assert_eq!(failed, Err("refused".to_string()));
    assert_eq!(calls.borrow().len(), 2, "every upload was tried");
    assert_eq!(
        *published.borrow(),
        0,
        "nothing is published after a failed upload"
    );

    // Nothing to upload: published at once.
    let published = RefCell::new(0u32);
    block_on(publish_after_uploads(
        Vec::new(),
        |_, _| async { Ok(()) },
        || *published.borrow_mut() += 1,
    ))
    .unwrap();
    assert_eq!(*published.borrow(), 1);
}

/// What List it hands on. An edit that changes no term (a photo the network
/// lost, added again) keeps the ORIGINAL listing, and its id, yet still
/// uploads that photo: the uploads are worked out apart from the
/// count-only check.
#[test]
fn a_restored_photo_keeps_the_listing_and_is_still_uploaded() {
    use crate::components::listing_form::{plan_submission, Submission};
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let original =
        jam(listing_images(&[published(1, true), published(2, false)]).unwrap()).with_derived_id();
    let mut drafts = drafts_from_listing(Some(&original));
    let mut again = added(2);
    again.thumb = None;
    again.thumb_bytes = None;
    assert_eq!(add_photo(&mut drafts, again), Added::Restored);
    let Submission { listing, pending } = plan_submission(
        Some(&original),
        &original.title,
        &original.description,
        original.checkout.clone(),
        original.choices.clone(),
        &drafts,
        now,
    )
    .unwrap();
    assert_eq!(listing.id, original.id, "no term changed");
    assert_eq!(listing.created_at, original.created_at);
    let up: Vec<[u8; 32]> = pending.into_iter().map(|(h, _)| h).collect();
    assert_eq!(up, vec![[2; 32]], "the restored photo still goes up");
}

/// A photo-only change is a new listing, stamped now, with the new photo
/// uploaded; a new listing is identified from its own terms.
#[test]
fn a_photo_change_is_a_new_listing() {
    use crate::components::listing_form::{plan_submission, Submission};
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let original = jam(listing_images(&[published(1, true)]).unwrap()).with_derived_id();
    let mut drafts = drafts_from_listing(Some(&original));
    assert_eq!(add_photo(&mut drafts, added(3)), Added::New);
    let Submission { listing, pending } = plan_submission(
        Some(&original),
        " Jam ",
        " Sweet ",
        None,
        Vec::new(),
        &drafts,
        now,
    )
    .unwrap();
    assert_ne!(listing.id, original.id);
    assert_eq!(listing.title, "Jam", "trimmed");
    assert_eq!(listing.description, "Sweet", "trimmed");
    assert_eq!(listing.created_at, now);
    assert_eq!(listing.id, listing.clone().with_derived_id().id);
    assert_eq!(listing.images.len(), 2);
    let up: Vec<[u8; 32]> = pending.into_iter().map(|(h, _)| h).collect();
    assert_eq!(up, vec![[3; 32]]);

    // Photos the store would refuse stop it before anything is planned.
    let bad = vec![published(2, false), published(1, true)];
    assert!(plan_submission(None, "Jam", "", None, Vec::new(), &bad, now).is_err());
}
