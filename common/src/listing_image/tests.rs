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
        thumb: thumb.then(|| ImageBlob {
            len: 20_000,
            ..blob(seed.wrapping_add(100), 400, 300)
        }),
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

/// The limits Ian chose and the store enforces, written out, so a change to
/// one is a change to this test too (every other test is written in terms of
/// the constant and would follow it silently).
#[test]
fn the_limits_are_the_chosen_ones() {
    assert_eq!(MAX_IMAGES_HARD, 8);
    assert_eq!(MAX_IMAGES_UI, 4);
    assert_eq!(MAX_ALT_CHARS, 200);
    assert_eq!(MAX_THUMB_EDGE, 400);
    assert_eq!(MAX_THUMB_BYTES, 64 * 1024);
    assert_eq!(MAX_IMAGE_BYTES, 256 * 1024);
    assert_eq!(MAX_IMAGE_EDGE, 2048);
}

#[test]
fn a_thumbnail_is_bounded_in_bytes_tighter_than_a_photo() {
    let with_thumb_len = |len: u32| {
        let mut p = photos(1);
        p[0].thumb.as_mut().unwrap().len = len;
        images_problem(&p)
    };
    assert_eq!(with_thumb_len(MAX_THUMB_BYTES as u32), None);
    assert!(with_thumb_len(MAX_THUMB_BYTES as u32 + 1).is_some());
}

#[test]
fn a_description_may_not_hide_characters() {
    let with_alt = |alt: &str| {
        let mut p = photos(2);
        p[1].alt = alt.to_string();
        images_problem(&p)
    };
    // Real writing that needs joiners, marks, selectors or tags.
    for fine in [
        "Jar of honey, lid off, côte view",
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} family picnic",
        "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308} flag",
        "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}",
        "\u{05D3}\u{05D1}\u{05E9} 500g\u{200F}",
        "\u{8702}\u{871C}\u{7F50}",
        "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}",
        "\u{2764}\u{FE0F}",
        "abc\u{200E}123 left-to-right mark",
        "\u{0639}\u{0633}\u{0644}\u{061C} 500",
        "1\u{FE0F}\u{20E3} keycap",
        "\u{1F44B}\u{1F3FD} skin tone",
        "\u{1F1F3}\u{1F1F1} regional indicators",
        "\u{0E19}\u{0E49}\u{0E33}\u{0E1C}\u{0E36}\u{0E49}\u{0E07}",
        "e\u{0301} combining accent",
    ] {
        assert_eq!(with_alt(fine), None, "{fine:?} must be accepted");
    }
    for hidden in [
        "line\nbreak",
        "tab\there",
        "nul\0",
        "\u{202E}esrever",
        "\u{2066}isolate\u{2069}",
        "zero\u{200B}width",
        "word\u{2060}joiner",
        "invisible\u{2062}times",
        "bom\u{FEFF}",
        "mongolian\u{180E}vs",
        "deprecated\u{206A}format",
        "nominal\u{206F}digits",
        "hangul\u{3164}filler",
        "choseong\u{115F}filler",
        "jungseong\u{1160}filler",
        "soft\u{00AD}hyphen",
        "grapheme\u{034F}joiner",
        "half\u{FFA0}width",
        "a\u{202A}b",
        "a\u{202B}b",
        "a\u{202C}b",
        "a\u{202D}b",
        "a\u{2061}b",
        "a\u{2063}b",
        "a\u{2064}b",
        "a\u{2065}b",
        "a\u{FFF9}b",
        "a\u{FFFA}b",
        "a\u{FFFB}b",
        "line\u{2028}sep",
        "para\u{2029}sep",
    ] {
        assert!(with_alt(hidden).is_some(), "{hidden:?} must be refused");
    }
}

/// A listing WITH photos, pinned. Unlike the pin above, these bytes were
/// computed by this code (the field is new, so no earlier code could), and
/// the hashes' byte-string form (`5820`) was checked by hand. It catches a
/// later drift, not a wrong encoding today. Its encoding is the preimage of
/// its id and its signature, so once photographed listings exist, a change to
/// how a photo reference encodes (field order, a dropped `skip_serializing_if`,
/// the hash's byte-string form) would move their ids and the store migration
/// would discard them. Covers a cover with thumbnail and description, and a
/// second photo with neither.
#[test]
fn a_listing_with_photos_encodes_as_pinned() {
    const PINNED_CBOR: &str = "a96269649820187b181f184818ce18601832188e1882189818e218b518ee186f18d218aa185b18e218dc182718961887184218bd186718491618fa185018f4186a187b182c657469746c657350696e6e6564206a6172206f6620686f6e65796b6465736372697074696f6e782a5072652d70686f746f206c697374696e672c20697473206964206d757374206e65766572206d6f76652e646b696e646453616c65657072696365f66a637265617465645f617474323032362d30392d32315431343a31333a32305a68636865636b6f7574a269756e69745f736174731952086864656c6976657279a1684279526567696f6e81a266726567696f6e6255536473617473190bb86763686f6963657381a2646e616d656453697a65676f7074696f6e738265536d616c6c654c6172676566696d6167657382a46466756c6ca4646861736858200101010101010101010101010101010101010101010101010101010101010101636c656e1a000186a0657769647468190640666865696768741904b0657468756d62a4646861736858206565656565656565656565656565656565656565656565656565656565656565636c656e194e206577696474681901906668656967687419012c66636f6c6f7572831878185a183c63616c747046726f6e74206f6620746865206a6172a26466756c6ca4646861736858200202020202020202020202020202020202020202020202020202020202020202636c656e1a000186a0657769647468190640666865696768741904b066636f6c6f7572831878185a183c";
    const PINNED_ID: &str = "9HcpGLtZJZgF3CPRsyMjnw864khPpNCZgKxVdc2DZYS7";
    let mut listing = pinned();
    listing.images = vec![
        ListingImage {
            alt: "Front of the jar".into(),
            ..photo(1, true)
        },
        photo(2, false),
    ];
    let listing = listing.with_derived_id();
    assert_eq!(hex::encode(crate::to_cbor(&listing).unwrap()), PINNED_CBOR);
    assert_eq!(listing.id.to_string(), PINNED_ID);
    let decoded: Listing = crate::from_cbor(&hex::decode(PINNED_CBOR).unwrap()).unwrap();
    assert_eq!(decoded, listing);
}
