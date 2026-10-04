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
fn at_most_four_photos() {
    assert!(listing_images(&(1..=4).map(added).collect::<Vec<_>>()).is_ok());
    assert!(listing_images(&(1..=5).map(added).collect::<Vec<_>>()).is_err());
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
fn the_same_photo_is_noticed() {
    let drafts = vec![added(1)];
    assert!(already_added(&drafts, &blob(1, 1600)));
    assert!(!already_added(&drafts, &blob(2, 1600)));
}
