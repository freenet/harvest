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
    let mut drafts = drafts;
    drafts[1].thumb = None;
    let images = listing_images(&drafts).unwrap();
    let named: Vec<[u8; 32]> = images
        .iter()
        .flat_map(|i| std::iter::once(i.full.hash.0).chain(i.thumb.iter().map(|t| t.hash.0)))
        .collect();
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

#[test]
fn a_listings_photos_come_back_as_drafts_in_order() {
    let listing = harvest_common::listing::Listing {
        images: listing_images(&[added(1), added(2)]).unwrap(),
        id: harvest_common::listing::ListingId([0; 32]),
        title: "Jam".into(),
        description: String::new(),
        kind: harvest_common::listing::ListingKind::Sale,
        price: None,
        created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        checkout: None,
        choices: Vec::new(),
    };
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
    assert!(uploads(&drafts).is_empty());
    let mut again = added(1);
    again.key = 77;
    assert_eq!(add_photo(&mut drafts, again), Added::Restored);
    assert_eq!(drafts.len(), 2, "no second copy");
    assert_eq!(drafts[1].key, 1, "it keeps its place and key");
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
    let published = RefCell::new(false);
    let ok = block_on(publish_after_uploads(
        vec![([1; 32], vec![1]), ([2; 32], vec![2])],
        |h, _| {
            calls.borrow_mut().push(h);
            async { Ok(()) }
        },
        || *published.borrow_mut() = true,
    ));
    assert_eq!(ok, Ok(()));
    assert_eq!(calls.borrow().len(), 2);
    assert!(*published.borrow());

    let published = RefCell::new(false);
    let failed = block_on(publish_after_uploads(
        vec![([1; 32], vec![1]), ([2; 32], vec![2])],
        |h, _| async move {
            if h == [2; 32] {
                Err("refused".to_string())
            } else {
                Ok(())
            }
        },
        || *published.borrow_mut() = true,
    ));
    assert_eq!(failed, Err("refused".to_string()));
    assert!(
        !*published.borrow(),
        "nothing is published after a failed upload"
    );

    // Nothing to upload: published at once.
    let published = RefCell::new(false);
    block_on(publish_after_uploads(
        Vec::new(),
        |_, _| async { Ok(()) },
        || *published.borrow_mut() = true,
    ))
    .unwrap();
    assert!(*published.borrow());
}
