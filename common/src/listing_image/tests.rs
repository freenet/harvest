use super::*;
use crate::listing::{
    ChoiceGroup, DeliveryPrice, FixedCheckout, Listing, ListingId, ListingKind, RegionPrice,
};

fn blob(seed: u8, width: u16, height: u16) -> ImageBlob {
    ImageBlob {
        hash: Bytes32([seed; 32]),
        len: 100_000,
        width,
        height,
    }
}

fn photo(seed: u8, thumb: bool) -> ListingImage {
    ListingImage {
        full: blob(seed, 1600, 1200),
        thumb: thumb.then(|| blob(seed.wrapping_add(100), 400, 300)),
        colour: [120, 90, 60],
        alt: String::new(),
    }
}

/// A cover and `n - 1` more, all valid.
fn photos(n: usize) -> Vec<ListingImage> {
    (0..n).map(|i| photo(i as u8 + 1, i == 0)).collect()
}

#[test]
fn up_to_eight_valid_photos_pass() {
    for n in 0..=MAX_IMAGES_HARD {
        assert_eq!(images_problem(&photos(n)), None, "{n} photos");
    }
}

#[test]
fn more_than_eight_photos_are_refused() {
    assert!(images_problem(&photos(MAX_IMAGES_HARD + 1)).is_some());
}

#[test]
fn the_cover_needs_a_thumbnail_and_no_other_photo_has_one() {
    let mut no_cover_thumb = photos(2);
    no_cover_thumb[0].thumb = None;
    assert!(images_problem(&no_cover_thumb).is_some());
    let mut second_thumb = photos(2);
    second_thumb[1].thumb = Some(blob(77, 400, 300));
    assert!(images_problem(&second_thumb).is_some());
}

#[test]
fn byte_lengths_are_bounded_on_both_ends() {
    let max = MAX_IMAGE_BYTES as u32;
    let with_full_len = |len: u32| {
        let mut p = photos(1);
        p[0].full.len = len;
        images_problem(&p)
    };
    assert!(with_full_len(0).is_some());
    assert!(with_full_len(max + 1).is_some());
    assert_eq!(with_full_len(max), None);
    assert_eq!(with_full_len(1), None);
    let mut big_thumb = photos(1);
    big_thumb[0].thumb.as_mut().unwrap().len = max + 1;
    assert!(images_problem(&big_thumb).is_some());
}

#[test]
fn full_image_edges_are_bounded() {
    let edge = MAX_IMAGE_EDGE;
    let with = |w: u16, h: u16| {
        let mut p = photos(1);
        p[0].full.width = w;
        p[0].full.height = h;
        images_problem(&p)
    };
    assert_eq!(with(edge, edge), None);
    assert!(with(edge + 1, 100).is_some());
    assert!(with(100, edge + 1).is_some());
    assert!(with(0, 100).is_some());
    assert!(with(100, 0).is_some());
}

#[test]
fn thumbnail_edges_are_bounded_tighter() {
    let with = |w: u16, h: u16| {
        let mut p = photos(1);
        let t = p[0].thumb.as_mut().unwrap();
        t.width = w;
        t.height = h;
        images_problem(&p)
    };
    assert_eq!(with(MAX_THUMB_EDGE, MAX_THUMB_EDGE), None);
    assert!(with(MAX_THUMB_EDGE + 1, 10).is_some());
    assert!(with(10, MAX_THUMB_EDGE + 1).is_some());
    assert!(with(0, 10).is_some());
}

#[test]
fn a_description_is_at_most_200_characters_not_bytes() {
    let with_alt = |alt: String| {
        let mut p = photos(2);
        p[1].alt = alt;
        images_problem(&p)
    };
    // 200 two-byte characters: 400 bytes, still within the limit.
    assert_eq!(with_alt("é".repeat(MAX_ALT_CHARS)), None);
    assert!(with_alt("é".repeat(MAX_ALT_CHARS + 1)).is_some());
    let mut on_cover = photos(1);
    on_cover[0].alt = "a".repeat(MAX_ALT_CHARS + 1);
    assert!(images_problem(&on_cover).is_some());
}

#[test]
fn the_same_photo_twice_is_refused() {
    let mut p = photos(3);
    p[2].full.hash = p[0].full.hash;
    assert!(images_problem(&p).is_some());
    // The same bytes as the cover's THUMBNAIL is a different image contract
    // and is not a repeat of a full photo.
    let mut q = photos(2);
    q[1].full.hash = q[0].thumb.as_ref().unwrap().hash;
    assert_eq!(images_problem(&q), None);
}

fn pinned() -> Listing {
    Listing {
        id: ListingId([0; 32]),
        title: "Pinned jar of honey".into(),
        description: "Pre-photo listing, its id must never move.".into(),
        kind: ListingKind::Sale,
        price: None,
        created_at: chrono::DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
        checkout: Some(FixedCheckout {
            unit_sats: 21_000,
            delivery: DeliveryPrice::ByRegion(vec![RegionPrice {
                region: "US".into(),
                sats: 3_000,
            }]),
        }),
        choices: vec![ChoiceGroup {
            name: "Size".into(),
            options: vec!["Small".into(), "Large".into()],
        }],
        images: Vec::new(),
    }
    .with_derived_id()
}

/// A listing published before photos existed must encode, and so be
/// identified and signed, exactly as it was: otherwise every live listing's
/// id moves and its signature stops verifying, and the store migration
/// discards it. The expected bytes and id were computed by the code on
/// `main` before `images` existed (b658341), not by this code.
#[test]
fn a_listing_without_photos_encodes_and_is_identified_as_before() {
    const BEFORE_CBOR: &str = "a8626964982018ac185c186a18751864111858186e184c18601118e718ba1831188618770a18fc18d20b090a0a183c1849184118f218a6183e188d188118ed657469746c657350696e6e6564206a6172206f6620686f6e65796b6465736372697074696f6e782a5072652d70686f746f206c697374696e672c20697473206964206d757374206e65766572206d6f76652e646b696e646453616c65657072696365f66a637265617465645f617474323032362d30392d32315431343a31333a32305a68636865636b6f7574a269756e69745f736174731952086864656c6976657279a1684279526567696f6e81a266726567696f6e6255536473617473190bb86763686f6963657381a2646e616d656453697a65676f7074696f6e738265536d616c6c654c61726765";
    const BEFORE_ID: &str = "CbpriAZiP7toKDwcaUvKtC7DdWRk2nZbnqPTHgnN2z7v";
    let listing = pinned();
    assert_eq!(hex::encode(crate::to_cbor(&listing).unwrap()), BEFORE_CBOR);
    assert_eq!(listing.id.to_string(), BEFORE_ID);
    // And a listing from before decodes into this struct with no photos.
    let decoded: Listing = crate::from_cbor(&hex::decode(BEFORE_CBOR).unwrap()).unwrap();
    assert_eq!(decoded, listing);
}

#[test]
fn photos_are_part_of_a_listings_identity() {
    let plain = pinned();
    let mut with_photo = plain.clone();
    with_photo.images = photos(1);
    let with_photo = with_photo.with_derived_id();
    assert_ne!(with_photo.id, plain.id);
    let mut other_photo = with_photo.clone();
    other_photo.images[0].full.hash = Bytes32([200; 32]);
    assert_ne!(other_photo.with_derived_id().id, with_photo.id);
    let mut reordered = with_photo.clone();
    reordered.images = vec![photo(2, true), photo(1, false)];
    assert_ne!(reordered.with_derived_id().id, with_photo.id);
}

#[test]
fn a_photo_reference_encodes_its_hashes_as_byte_strings() {
    let bytes = crate::to_cbor(&blob(7, 10, 10)).unwrap();
    // A 32-byte CBOR byte string: major type 2, one-byte length, 0x20.
    let marker = [0x58, 0x20];
    assert!(
        bytes.windows(2).any(|w| w == marker),
        "{}",
        hex::encode(&bytes)
    );
    let image: ListingImage = crate::from_cbor(&crate::to_cbor(&photo(3, true)).unwrap()).unwrap();
    assert_eq!(image, photo(3, true));
    // About 60 bytes per blob, so a four-photo listing stays well under 1 KB.
    assert!(bytes.len() < 70, "{} bytes", bytes.len());
}

#[test]
fn check_listing_images_names_the_listing() {
    let mut listing = pinned();
    listing.images = photos(MAX_IMAGES_HARD + 1);
    let err = check_listing_images(&listing).unwrap_err();
    assert!(err.contains(&listing.id.to_string()), "{err}");
    listing.images = photos(2);
    assert_eq!(check_listing_images(&listing), Ok(()));
}

#[test]
fn the_copied_limits_agree_with_the_image_contracts() {
    assert_eq!(MAX_IMAGE_BYTES, harvest_image::MAX_IMAGE_BYTES);
    assert_eq!(MAX_IMAGE_EDGE, harvest_image::MAX_IMAGE_EDGE);
}
