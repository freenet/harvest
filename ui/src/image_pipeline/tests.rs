use super::*;

/// Real `canvas.toBlob("image/jpeg")` output, 160 x 120 (harvest#212).
const CANVAS_JPEG: &[u8] =
    include_bytes!("../../../harvest-image/tests/fixtures/chromium-canvas.jpg");
const FIREFOX_JPEG: &[u8] =
    include_bytes!("../../../harvest-image/tests/fixtures/firefox-canvas.jpg");
const WEBP: &[u8] = include_bytes!("../../../harvest-image/tests/fixtures/chromium-canvas.webp");

/// `jpeg` with `extra` inserted straight after start-of-image.
fn after_soi(jpeg: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut v = jpeg[..2].to_vec();
    v.extend_from_slice(extra);
    v.extend_from_slice(&jpeg[2..]);
    v
}

fn app1_exif_with_gps() -> Vec<u8> {
    let body = b"Exif\0\0MM\0\x2A\0\0\0\x08\0\x01\x88\x25\0\x04\0\0\0\x01\0\0\0\x1aGPS 51.5N 0.1W";
    let mut seg = vec![0xFF, 0xE1];
    seg.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
    seg.extend_from_slice(body);
    seg
}

/// Offset of the first byte after the scan header.
fn scan_data_start(jpeg: &[u8]) -> usize {
    let mut i = 2;
    loop {
        let len = usize::from(u16::from_be_bytes([jpeg[i + 2], jpeg[i + 3]]));
        if jpeg[i + 1] == 0xDA {
            return i + 2 + len;
        }
        i += 2 + len;
    }
}

fn with_dimensions(jpeg: &[u8], width: u16, height: u16) -> Vec<u8> {
    let mut v = jpeg.to_vec();
    let mut i = 2;
    loop {
        let len = usize::from(u16::from_be_bytes([v[i + 2], v[i + 3]]));
        if v[i + 1] == 0xC0 {
            v[i + 5..i + 7].copy_from_slice(&height.to_be_bytes());
            v[i + 7..i + 9].copy_from_slice(&width.to_be_bytes());
            return v;
        }
        i += 2 + len;
    }
}

#[test]
fn canvas_output_is_named_by_its_own_hash() {
    let p = prepare(CANVAS_JPEG, FIREFOX_JPEG, [1, 2, 3]).unwrap();
    assert_eq!(p.full, CANVAS_JPEG);
    assert_eq!(p.full_blob.hash.0, harvest_image::image_hash(CANVAS_JPEG));
    assert_eq!(p.full_blob.len as usize, CANVAS_JPEG.len());
    assert_eq!((p.full_blob.width, p.full_blob.height), (160, 120));
    assert_eq!(p.thumb_blob.hash.0, harvest_image::image_hash(FIREFOX_JPEG));
    assert_eq!(p.colour, [1, 2, 3]);
}

/// What the listing signs is the hash of what is uploaded: if a browser ever
/// left a metadata block in, the uploaded bytes are the stripped ones and the
/// hash is theirs, not the browser output's.
#[test]
fn metadata_is_stripped_before_the_hash_is_taken() {
    let with_exif = after_soi(CANVAS_JPEG, &app1_exif_with_gps());
    let p = prepare(&with_exif, FIREFOX_JPEG, [0, 0, 0]).unwrap();
    assert_eq!(p.full, CANVAS_JPEG, "the location block is gone");
    assert_eq!(p.full_blob.hash.0, harvest_image::image_hash(CANVAS_JPEG));
    assert_ne!(p.full_blob.hash.0, harvest_image::image_hash(&with_exif));
    assert_eq!(p.full_blob.len as usize, CANVAS_JPEG.len());
    assert!(harvest_image::validate(&p.full_blob.hash.0, &p.full).is_ok());
}

#[test]
fn only_baseline_jpeg_is_accepted() {
    assert!(prepare(WEBP, FIREFOX_JPEG, [0; 3]).is_err());
    assert!(prepare(CANVAS_JPEG, WEBP, [0; 3]).is_err());
}

#[test]
fn a_thumbnail_over_its_byte_limit_is_refused() {
    // Padding inside the compressed data keeps the file well formed.
    let mut big = FIREFOX_JPEG.to_vec();
    let at = scan_data_start(&big);
    big.splice(at..at, std::iter::repeat_n(0u8, MAX_THUMB_BYTES));
    assert!(harvest_image::sniff(&big).is_ok());
    assert!(prepare(CANVAS_JPEG, &big, [0; 3]).is_err());
    assert!(
        prepare(&big, FIREFOX_JPEG, [0; 3]).is_ok(),
        "fine as a full photo"
    );
}

#[test]
fn a_thumbnail_over_its_edge_is_refused() {
    let wide = with_dimensions(FIREFOX_JPEG, 401, 120);
    assert!(prepare(CANVAS_JPEG, &wide, [0; 3]).is_err());
    let at_edge = with_dimensions(FIREFOX_JPEG, 400, 120);
    assert!(prepare(CANVAS_JPEG, &at_edge, [0; 3]).is_ok());
}

#[test]
fn fit_keeps_the_aspect_and_never_enlarges() {
    assert_eq!(fit(4000, 3000, 1600), (1600, 1200));
    assert_eq!(fit(3000, 4000, 1600), (1200, 1600));
    assert_eq!(fit(800, 600, 1600), (800, 600));
    assert_eq!(fit(5000, 10, 400), (400, 1));
    assert_eq!(fit(0, 0, 400), (1, 1));
}

#[test]
fn the_mean_colour_ignores_alpha() {
    assert_eq!(mean_colour(&[10, 20, 30, 0, 30, 40, 50, 255]), [20, 30, 40]);
    assert_eq!(mean_colour(&[]), [0, 0, 0]);
}

#[test]
fn some_files_are_refused_before_decoding() {
    assert!(input_problem(31.0 * 1024.0 * 1024.0, "image/jpeg").is_some());
    assert!(input_problem(1024.0, "image/svg+xml").is_some());
    assert!(input_problem(1024.0, "application/pdf").is_some());
    assert_eq!(
        input_problem(1024.0, "image/heic"),
        None,
        "the browser decides whether it can decode it"
    );
    assert_eq!(input_problem(1024.0, ""), None, "some systems give no type");
}
