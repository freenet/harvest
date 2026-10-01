use super::*;

/// Real `canvas.toBlob("image/jpeg")` output, 160 x 120, from each engine
/// (generated with Playwright on 2026-10-01). Chromium and WebKit write
/// JFIF + ICC; Firefox writes JFIF only. All are baseline with one scan.
const CHROMIUM: &[u8] = include_bytes!("../tests/fixtures/chromium-canvas.jpg");
const FIREFOX: &[u8] = include_bytes!("../tests/fixtures/firefox-canvas.jpg");
const WEBKIT: &[u8] = include_bytes!("../tests/fixtures/webkit-canvas.jpg");
/// A one-component (grey) baseline JPEG from Pillow (libjpeg): no canvas
/// writes one, but a grey frame is legal baseline and must stay accepted.
const GREY: &[u8] = include_bytes!("../tests/fixtures/pillow-gray.jpg");
/// Chromium's `toBlob("image/webp")`: the format this crate refuses.
const WEBP: &[u8] = include_bytes!("../tests/fixtures/chromium-canvas.webp");

const ALL: [&[u8]; 3] = [CHROMIUM, FIREFOX, WEBKIT];

fn segment(marker: u8, body: &[u8]) -> Vec<u8> {
    let mut s = vec![0xFF, marker];
    s.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
    s.extend_from_slice(body);
    s
}

/// `jpeg` with `extra` inserted straight after start-of-image.
fn after_soi(jpeg: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut v = jpeg[..2].to_vec();
    v.extend_from_slice(extra);
    v.extend_from_slice(&jpeg[2..]);
    v
}

/// Offset of the first `FF <marker>` in the header (before the scan).
fn find(jpeg: &[u8], marker: u8) -> usize {
    let mut i = 2;
    loop {
        assert_eq!(jpeg[i], 0xFF);
        if jpeg[i + 1] == marker {
            return i;
        }
        let len = usize::from(u16::from_be_bytes([jpeg[i + 2], jpeg[i + 3]]));
        i += 2 + len;
    }
}

/// `jpeg` with `extra` inserted immediately before the scan header.
fn before_sos(jpeg: &[u8], extra: &[u8]) -> Vec<u8> {
    let at = find(jpeg, SOS);
    let mut v = jpeg[..at].to_vec();
    v.extend_from_slice(extra);
    v.extend_from_slice(&jpeg[at..]);
    v
}

/// A minimal TIFF-in-Exif body carrying a GPS IFD pointer: what a phone
/// writes for location. The structure is valid TIFF, so a decoder that read
/// Exif would find the GPS tag (0x8825).
fn exif_with_gps() -> Vec<u8> {
    let mut b = b"Exif\0\0".to_vec();
    b.extend_from_slice(b"MM\0\x2A\0\0\0\x08"); // big-endian TIFF, IFD0 at 8
    b.extend_from_slice(&[0, 1]); // one entry
    b.extend_from_slice(&[0x88, 0x25, 0, 4, 0, 0, 0, 1, 0, 0, 0, 26]); // GPSInfo -> 26
    b.extend_from_slice(&[0, 0, 0, 0]); // no next IFD
    b.extend_from_slice(&[0, 1]); // GPS IFD: one entry
    b.extend_from_slice(&[0, 2, 0, 5, 0, 0, 0, 3, 0, 0, 0, 0]); // GPSLatitude
    b.extend_from_slice(&[0, 0, 0, 0]);
    b
}

fn set_dimensions(jpeg: &[u8], width: u16, height: u16) -> Vec<u8> {
    let mut v = jpeg.to_vec();
    let at = find(&v, SOF0) + 4; // body start
    v[at + 1..at + 3].copy_from_slice(&height.to_be_bytes());
    v[at + 3..at + 5].copy_from_slice(&width.to_be_bytes());
    v
}

#[test]
fn every_engines_canvas_output_is_accepted() {
    for jpeg in ALL {
        assert_eq!(
            sniff(jpeg),
            Ok(ImageInfo {
                width: 160,
                height: 120
            })
        );
        assert_eq!(
            validate(&image_hash(jpeg), jpeg),
            Ok(ImageInfo {
                width: 160,
                height: 120
            })
        );
    }
}

#[test]
fn validate_refuses_parameters_that_are_not_one_hash() {
    for len in [0, 31, 33, 64] {
        assert_eq!(
            validate(&vec![0; len], CHROMIUM),
            Err(ImageError::ParamsLength(len))
        );
    }
}

#[test]
fn validate_refuses_an_empty_state_even_under_its_own_hash() {
    // The hash of nothing is a perfectly good 32-byte parameter. Were an
    // empty state valid anywhere, it would be valid under every image's key.
    assert_eq!(validate(&image_hash(&[]), &[]), Err(ImageError::Empty));
    assert_eq!(validate(&image_hash(CHROMIUM), &[]), Err(ImageError::Empty));
}

#[test]
fn validate_refuses_an_oversized_state_before_hashing() {
    let big = vec![0u8; MAX_IMAGE_BYTES + 1];
    // Under its own hash, so the only thing wrong is the size.
    assert_eq!(
        validate(&image_hash(&big), &big),
        Err(ImageError::TooLarge(MAX_IMAGE_BYTES + 1))
    );
}

#[test]
fn validate_refuses_bytes_that_do_not_hash_to_the_parameters() {
    assert_eq!(
        validate(&image_hash(FIREFOX), CHROMIUM),
        Err(ImageError::HashMismatch)
    );
    let mut flipped = image_hash(CHROMIUM);
    flipped[31] ^= 1;
    assert_eq!(validate(&flipped, CHROMIUM), Err(ImageError::HashMismatch));
}

#[test]
fn validate_runs_the_format_check_after_the_hash() {
    // Valid hash, not a JPEG: refused by the format check, which the hash
    // must not short-circuit.
    assert_eq!(validate(&image_hash(WEBP), WEBP), Err(ImageError::NotJpeg));
}

#[test]
fn other_formats_are_refused() {
    assert_eq!(sniff(WEBP), Err(ImageError::NotJpeg));
    assert_eq!(sniff(b"\x89PNG\r\n\x1a\n"), Err(ImageError::NotJpeg));
    assert_eq!(sniff(b"GIF89a"), Err(ImageError::NotJpeg));
    assert_eq!(
        sniff(b"<svg xmlns='http://www.w3.org/2000/svg'/>"),
        Err(ImageError::NotJpeg)
    );
    assert_eq!(sniff(&[0xFF]), Err(ImageError::NotJpeg));
}

#[test]
fn exif_with_location_is_refused() {
    let bad = after_soi(CHROMIUM, &segment(0xE1, &exif_with_gps()));
    assert_eq!(sniff(&bad), Err(ImageError::Metadata { marker: 0xE1 }));
}

#[test]
fn metadata_anywhere_before_the_scan_is_refused() {
    let xmp = segment(0xE1, b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta/>");
    let iptc = segment(0xED, b"Photoshop 3.0\0");
    let com = segment(COM, b"taken at 51.5N 0.1W");
    let other_app = segment(0xE5, b"anything");
    for seg in [xmp, iptc, com, other_app] {
        let marker = seg[1];
        for jpeg in ALL {
            // Before the frame, and after it (between the tables and the
            // scan, where a header-only check would never look).
            assert_eq!(
                sniff(&after_soi(jpeg, &seg)),
                Err(ImageError::Metadata { marker })
            );
            assert_eq!(
                sniff(&before_sos(jpeg, &seg)),
                Err(ImageError::Metadata { marker })
            );
        }
    }
}

#[test]
fn an_app2_that_is_not_an_icc_profile_is_refused() {
    // MPF: how a phone announces the second picture after end-of-image.
    let mpf = segment(APP2, b"MPF\0MM\0\x2A\0\0\0\x08");
    assert_eq!(
        sniff(&after_soi(FIREFOX, &mpf)),
        Err(ImageError::Metadata { marker: APP2 })
    );
}

#[test]
fn anything_after_end_of_image_is_refused() {
    let mut mpf_second_picture = CHROMIUM.to_vec();
    mpf_second_picture.extend_from_slice(&after_soi(FIREFOX, &segment(0xE1, &exif_with_gps())));
    assert_eq!(sniff(&mpf_second_picture), Err(ImageError::TrailingBytes));
    let mut one_byte = CHROMIUM.to_vec();
    one_byte.push(0);
    assert_eq!(sniff(&one_byte), Err(ImageError::TrailingBytes));
}

#[test]
fn a_jfif_header_must_be_plain() {
    let jfif = &CHROMIUM[find(CHROMIUM, APP0)..][..2 + JFIF_LEN];
    // With a 1 x 1 thumbnail (three bytes of RGB after the header).
    let mut thumb = jfif[4..].to_vec();
    thumb[12] = 1;
    thumb[13] = 1;
    thumb.extend_from_slice(&[0, 0, 0]);
    let without = strip_app0(CHROMIUM);
    assert_eq!(
        sniff(&after_soi(&without, &segment(APP0, &thumb))),
        Err(ImageError::BadJfif)
    );
    // Not JFIF at all (JFXX extension thumbnail).
    assert_eq!(
        sniff(&after_soi(&without, &segment(APP0, b"JFXX\0\x10abc"))),
        Err(ImageError::BadJfif)
    );
    // Twice.
    assert_eq!(
        sniff(&after_soi(CHROMIUM, &segment(APP0, &jfif[4..]))),
        Err(ImageError::Duplicate { marker: APP0 })
    );
}

fn strip_app0(jpeg: &[u8]) -> Vec<u8> {
    let at = find(jpeg, APP0);
    let len = usize::from(u16::from_be_bytes([jpeg[at + 2], jpeg[at + 3]]));
    let mut v = jpeg[..at].to_vec();
    v.extend_from_slice(&jpeg[at + 2 + len..]);
    v
}

#[test]
fn a_jfif_header_is_optional() {
    assert!(sniff(&strip_app0(FIREFOX)).is_ok());
}

#[test]
fn only_baseline_frames_are_accepted() {
    for marker in [0xC1, 0xC2, 0xC3, 0xC5, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF] {
        let mut v = CHROMIUM.to_vec();
        let at = find(&v, SOF0);
        v[at + 1] = marker;
        assert_eq!(
            sniff(&v),
            Err(ImageError::UnsupportedCoding { marker }),
            "{marker:02X}"
        );
    }
}

#[test]
fn a_frame_header_must_be_baseline_shaped() {
    let at = find(CHROMIUM, SOF0) + 4;
    // 12-bit samples.
    let mut v = CHROMIUM.to_vec();
    v[at] = 12;
    assert_eq!(sniff(&v), Err(ImageError::BadFrame));
    // Four components (CMYK).
    let mut v = CHROMIUM.to_vec();
    v[at + 5] = 4;
    assert_eq!(sniff(&v), Err(ImageError::BadFrame));
    // A second frame header.
    let sof = &CHROMIUM[at - 4..][..4 + 15];
    assert_eq!(
        sniff(&before_sos(CHROMIUM, sof)),
        Err(ImageError::Duplicate { marker: SOF0 })
    );
}

#[test]
fn dimensions_are_bounded() {
    for (w, h) in [
        (0, 120),
        (160, 0),
        (MAX_IMAGE_EDGE + 1, 120),
        (160, MAX_IMAGE_EDGE + 1),
        (65535, 65535),
    ] {
        assert_eq!(
            sniff(&set_dimensions(FIREFOX, w, h)),
            Err(ImageError::Dimensions {
                width: w,
                height: h
            })
        );
    }
    let edge = MAX_IMAGE_EDGE;
    assert_eq!(
        sniff(&set_dimensions(FIREFOX, edge, edge)),
        Ok(ImageInfo {
            width: edge,
            height: edge
        })
    );
}

#[test]
fn the_scan_must_cover_every_component() {
    let at = find(CHROMIUM, SOS) + 4;
    let mut v = CHROMIUM.to_vec();
    v[at] = 1; // claims one component in a three-component frame
    assert_eq!(sniff(&v), Err(ImageError::BadScan));
}

#[test]
fn a_scan_before_any_frame_is_refused() {
    let at = find(CHROMIUM, SOF0);
    let len = 2 + 17;
    let mut v = CHROMIUM[..at].to_vec();
    v.extend_from_slice(&CHROMIUM[at + len..]);
    assert_eq!(sniff(&v), Err(ImageError::NoFrame));
}

#[test]
fn a_second_scan_is_refused() {
    // Replace end-of-image with a second scan header, then end-of-image.
    let sos_at = find(CHROMIUM, SOS);
    let sos_len = usize::from(u16::from_be_bytes([
        CHROMIUM[sos_at + 2],
        CHROMIUM[sos_at + 3],
    ]));
    let mut v = CHROMIUM[..CHROMIUM.len() - 2].to_vec();
    v.extend_from_slice(&CHROMIUM[sos_at..sos_at + 2 + sos_len]);
    v.extend_from_slice(&[0x12, 0x34, 0xFF, EOI]);
    assert_eq!(sniff(&v), Err(ImageError::MultipleScans));
}

#[test]
fn a_restart_interval_is_accepted_once() {
    let dri = segment(DRI, &[0, 16]);
    assert!(sniff(&before_sos(FIREFOX, &dri)).is_ok());
    let twice = before_sos(&before_sos(FIREFOX, &dri), &dri);
    assert_eq!(sniff(&twice), Err(ImageError::Duplicate { marker: DRI }));
    assert_eq!(
        sniff(&before_sos(FIREFOX, &segment(DRI, &[0, 16, 0]))),
        Err(ImageError::BadLength { marker: DRI })
    );
}

#[test]
fn an_adobe_marker_is_accepted_once() {
    let adobe = segment(APP14, b"Adobe\0\x64\0\0\0\0\x01");
    assert!(sniff(&after_soi(FIREFOX, &adobe)).is_ok());
    let twice = after_soi(&after_soi(FIREFOX, &adobe), &adobe);
    assert_eq!(sniff(&twice), Err(ImageError::Duplicate { marker: APP14 }));
    // An APP14 that is not Adobe's is metadata.
    assert_eq!(
        sniff(&after_soi(FIREFOX, &segment(APP14, b"Ducky"))),
        Err(ImageError::Metadata { marker: APP14 })
    );
}

#[test]
fn unknown_and_misplaced_markers_are_refused() {
    // A start-of-image inside the header.
    assert_eq!(
        sniff(&after_soi(FIREFOX, &[0xFF, SOI])),
        Err(ImageError::UnexpectedMarker { marker: SOI })
    );
    // A fill byte before a marker.
    assert_eq!(
        sniff(&after_soi(FIREFOX, &[0xFF])),
        Err(ImageError::UnexpectedMarker { marker: 0xFF })
    );
    // DNL, DHP and other non-frame, non-table markers.
    for marker in [0xDC, 0xDE, 0xDF, 0xF0, 0xF7] {
        assert_eq!(
            sniff(&after_soi(FIREFOX, &segment(marker, &[0]))),
            Err(ImageError::UnexpectedMarker { marker })
        );
    }
    // Not a marker at all where one belongs.
    assert_eq!(
        sniff(&after_soi(FIREFOX, &[0x00])),
        Err(ImageError::UnexpectedMarker { marker: 0x00 })
    );
}

#[test]
fn lying_lengths_are_refused() {
    // A length of 0 or 1 cannot even cover its own field.
    for len in [0u16, 1] {
        let mut seg = vec![0xFF, DQT];
        seg.extend_from_slice(&len.to_be_bytes());
        assert_eq!(
            sniff(&after_soi(FIREFOX, &seg)),
            Err(ImageError::BadLength { marker: DQT })
        );
    }
    // A length running past the end of the file.
    let mut v = FIREFOX[..20].to_vec();
    v.extend_from_slice(&[0xFF, DQT, 0xFF, 0xFF]);
    assert_eq!(sniff(&v), Err(ImageError::Truncated));
}

#[test]
fn every_truncation_is_refused_without_panicking() {
    for jpeg in ALL {
        for len in 0..jpeg.len() {
            assert!(
                sniff(&jpeg[..len]).is_err(),
                "a {len}-byte prefix was accepted"
            );
        }
    }
}

/// A deterministic corruption sweep: flip, overwrite and splice bytes all
/// over the real fixtures. The property is that `sniff` and `strip` never
/// panic (a panic in the contract is a refusal with no reason, and in the UI
/// a crashed tab), and that anything `strip` returns either passes `sniff` or
/// is refused by it with an ordinary error.
#[test]
fn corrupted_files_never_panic() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for jpeg in ALL {
        for _ in 0..4000 {
            let mut v = jpeg.to_vec();
            for _ in 0..(1 + next() % 4) {
                let at = (next() as usize) % v.len();
                match next() % 4 {
                    0 => v[at] ^= 1 << (next() % 8),
                    1 => v[at] = 0xFF,
                    2 => v[at] = next() as u8,
                    _ => {
                        let n = (next() % 8) as usize;
                        v.splice(at..at, std::iter::repeat_n(next() as u8, n));
                    }
                }
            }
            let _ = sniff(&v);
            if let Ok(stripped) = strip(&v) {
                let _ = sniff(&stripped);
            }
        }
    }
}

#[test]
fn strip_leaves_canvas_output_byte_identical() {
    // So the seller's path can always strip: on the engines we know, it is a
    // no-op, and the hash the seller signs is the hash of what the canvas
    // wrote.
    for jpeg in ALL {
        assert_eq!(strip(jpeg).as_deref(), Ok(jpeg));
    }
}

#[test]
fn strip_removes_every_kind_of_metadata_and_the_result_passes() {
    let mut v = after_soi(CHROMIUM, &segment(0xE1, &exif_with_gps()));
    v = before_sos(&v, &segment(COM, b"comment"));
    v = before_sos(&v, &segment(0xED, b"Photoshop 3.0\0"));
    v = after_soi(&v, &segment(APP2, b"MPF\0data"));
    v.extend_from_slice(&after_soi(FIREFOX, &segment(0xE1, &exif_with_gps())));
    assert!(sniff(&v).is_err());
    let stripped = strip(&v).unwrap();
    assert_eq!(
        stripped, CHROMIUM,
        "stripping should give back exactly the canvas output"
    );
    assert!(sniff(&stripped).is_ok());
}

#[test]
fn strip_drops_a_jfif_thumbnail_and_keeps_one_plain_header() {
    let jfif = CHROMIUM[find(CHROMIUM, APP0)..][4..2 + JFIF_LEN].to_vec();
    let mut thumb = jfif.clone();
    thumb[12] = 1;
    thumb[13] = 1;
    thumb.extend_from_slice(&[0, 0, 0]);
    let with_thumb = after_soi(&strip_app0(CHROMIUM), &segment(APP0, &thumb));
    let stripped = strip(&with_thumb).unwrap();
    assert!(sniff(&stripped).is_ok());
    assert_eq!(stripped, strip_app0(CHROMIUM));
    // Two plain headers: the second goes.
    let twice = after_soi(CHROMIUM, &segment(APP0, &jfif));
    assert_eq!(strip(&twice).unwrap(), CHROMIUM);
}

#[test]
fn strip_does_not_repair_structure() {
    let mut progressive = CHROMIUM.to_vec();
    let at = find(&progressive, SOF0);
    progressive[at + 1] = 0xC2;
    let stripped = strip(&progressive).unwrap();
    assert_eq!(
        sniff(&stripped),
        Err(ImageError::UnsupportedCoding { marker: 0xC2 })
    );
    assert_eq!(strip(&CHROMIUM[..100]), Err(ImageError::Truncated));
}

/// `jpeg` with the segment at `marker` replaced by one with `body`.
fn replace_segment(jpeg: &[u8], marker: u8, body: &[u8]) -> Vec<u8> {
    let at = find(jpeg, marker);
    let len = usize::from(u16::from_be_bytes([jpeg[at + 2], jpeg[at + 3]]));
    let mut v = jpeg[..at].to_vec();
    v.extend_from_slice(&segment(marker, body));
    v.extend_from_slice(&jpeg[at + 2 + len..]);
    v
}

fn jfif_body() -> Vec<u8> {
    let at = find(FIREFOX, APP0);
    FIREFOX[at + 4..at + 2 + JFIF_LEN].to_vec()
}

#[test]
fn a_jfif_header_declaring_a_thumbnail_is_refused_even_at_the_plain_length() {
    // Length exactly that of a plain header, but the thumbnail size fields
    // are not zero: only the thumbnail check sees it.
    let mut body = jfif_body();
    body[12] = 4;
    assert_eq!(
        sniff(&replace_segment(FIREFOX, APP0, &body)),
        Err(ImageError::BadJfif)
    );
    let mut body = jfif_body();
    body[13] = 4;
    assert_eq!(
        sniff(&replace_segment(FIREFOX, APP0, &body)),
        Err(ImageError::BadJfif)
    );
}

#[test]
fn a_jfif_header_with_extra_bytes_is_refused() {
    // Zero-size thumbnail declared, and bytes after it anyway: room to carry
    // anything, so only the length check sees it.
    let mut body = jfif_body();
    body.extend_from_slice(b"51.5N");
    assert_eq!(
        sniff(&replace_segment(FIREFOX, APP0, &body)),
        Err(ImageError::BadJfif)
    );
}

/// A frame body for `components` components, each with a well-formed spec.
fn frame_body(components: u8) -> Vec<u8> {
    let mut body = vec![8, 0, 120, 0, 160, components];
    for id in 1..=components {
        body.extend_from_slice(&[id, 0x11, 0]);
    }
    body
}

#[test]
fn a_frame_with_a_consistent_length_but_two_or_four_components_is_refused() {
    for components in [0, 2, 4] {
        let v = replace_segment(FIREFOX, SOF0, &frame_body(components));
        assert_eq!(
            sniff(&v),
            Err(ImageError::BadFrame),
            "{components} components"
        );
    }
}

#[test]
fn a_frame_whose_length_does_not_match_its_components_is_refused() {
    let mut body = frame_body(3);
    body.push(0);
    assert_eq!(
        sniff(&replace_segment(FIREFOX, SOF0, &body)),
        Err(ImageError::BadFrame)
    );
    let mut body = frame_body(3);
    body.pop();
    assert_eq!(
        sniff(&replace_segment(FIREFOX, SOF0, &body)),
        Err(ImageError::BadFrame)
    );
}

#[test]
fn a_well_formed_scan_of_fewer_components_than_the_frame_is_refused() {
    // One component, with the length one component gives: only the
    // components-must-match rule sees it.
    let scan = [1, 1, 0x00, 0, 63, 0];
    assert_eq!(
        sniff(&replace_segment(FIREFOX, SOS, &scan)),
        Err(ImageError::BadScan)
    );
}

/// `jpeg` with every segment of `marker` before the scan removed.
fn without(jpeg: &[u8], marker: u8) -> Vec<u8> {
    let mut v = jpeg.to_vec();
    loop {
        let mut i = 2;
        let mut found = None;
        while v[i + 1] != SOS {
            let len = usize::from(u16::from_be_bytes([v[i + 2], v[i + 3]]));
            if v[i + 1] == marker {
                found = Some((i, 2 + len));
                break;
            }
            i += 2 + len;
        }
        match found {
            Some((at, n)) => {
                v.drain(at..at + n);
            }
            None => return v,
        }
    }
}

fn body_of(jpeg: &[u8], marker: u8) -> Vec<u8> {
    let at = find(jpeg, marker);
    let len = usize::from(u16::from_be_bytes([jpeg[at + 2], jpeg[at + 3]]));
    jpeg[at + 4..at + 2 + len].to_vec()
}

#[test]
fn a_grey_baseline_jpeg_is_accepted() {
    assert_eq!(
        sniff(GREY),
        Ok(ImageInfo {
            width: 160,
            height: 120
        })
    );
    assert_eq!(strip(GREY).as_deref(), Ok(GREY));
}

#[test]
fn an_app0_of_the_plain_length_that_is_not_jfif_is_refused() {
    let mut body = jfif_body();
    body[..5].copy_from_slice(b"JFXX\0");
    assert_eq!(
        sniff(&replace_segment(FIREFOX, APP0, &body)),
        Err(ImageError::BadJfif)
    );
}

#[test]
fn a_second_byte_that_is_not_start_of_image_is_refused() {
    let mut v = FIREFOX.to_vec();
    v[1] = 0xD9;
    assert_eq!(sniff(&v), Err(ImageError::NotJpeg));
}

#[test]
fn the_size_cap_runs_before_the_hash() {
    // Wrong hash AND oversized: the size is what is reported, so the
    // oversized bytes were never hashed.
    let big = vec![0u8; MAX_IMAGE_BYTES + 1];
    assert_eq!(
        validate(&[0; 32], &big),
        Err(ImageError::TooLarge(MAX_IMAGE_BYTES + 1))
    );
    // Exactly at the cap is not "too large" (it fails later, as a non-JPEG).
    let at_cap = vec![0u8; MAX_IMAGE_BYTES];
    assert_eq!(
        validate(&image_hash(&at_cap), &at_cap),
        Err(ImageError::NotJpeg)
    );
}

#[test]
fn short_frame_and_scan_headers_are_refused_without_panicking() {
    for len in 0..6 {
        let body = &frame_body(3)[..len];
        assert_eq!(
            sniff(&replace_segment(FIREFOX, SOF0, body)),
            Err(ImageError::BadFrame)
        );
    }
    assert_eq!(
        sniff(&replace_segment(FIREFOX, SOS, &[])),
        Err(ImageError::BadScan)
    );
}

#[test]
fn a_scan_header_with_extra_bytes_is_refused() {
    // Extra bytes that still END in the baseline spectral values, so only
    // the length rule can see them.
    let mut scan = body_of(FIREFOX, SOS);
    scan.extend_from_slice(&[0, 63, 0]);
    assert_eq!(
        sniff(&replace_segment(FIREFOX, SOS, &scan)),
        Err(ImageError::BadScan)
    );
}

/// One way to spoil a header, for a table of cases.
type Change = fn(&mut Vec<u8>);

#[test]
fn a_scan_must_name_the_frame_components_in_order_with_baseline_values() {
    let good = body_of(FIREFOX, SOS);
    assert!(sniff(&replace_segment(FIREFOX, SOS, &good)).is_ok());
    let cases: [(&str, Change); 7] = [
        ("unknown id", |s| s[1] = 0x99),
        ("ids out of order", |s| s.swap(1, 3)),
        ("DC table slot 2", |s| s[2] = 0x20 | (s[2] & 0x0F)),
        ("AC table slot 2", |s| s[2] = (s[2] & 0xF0) | 2),
        ("spectral start", |s| {
            *s.iter_mut().rev().nth(2).unwrap() = 1
        }),
        ("spectral end", |s| *s.iter_mut().rev().nth(1).unwrap() = 5),
        ("approximation", |s| *s.last_mut().unwrap() = 0x10),
    ];
    for (what, change) in cases {
        let mut scan = good.clone();
        change(&mut scan);
        assert_eq!(
            sniff(&replace_segment(FIREFOX, SOS, &scan)),
            Err(ImageError::BadScan),
            "{what}"
        );
    }
}

#[test]
fn frame_components_must_be_distinct_with_baseline_sampling_and_slots() {
    let cases: [(&str, Change); 5] = [
        ("repeated id", |f| f[9] = f[6]),
        ("zero horizontal sampling", |f| f[7] = 0x01),
        ("zero vertical sampling", |f| f[7] = 0x10),
        ("sampling of five", |f| f[7] = 0x51),
        ("quantisation slot 4", |f| f[8] = 4),
    ];
    for (what, change) in cases {
        let mut frame = frame_body(3);
        change(&mut frame);
        assert_eq!(
            sniff(&replace_segment(FIREFOX, SOF0, &frame)),
            Err(ImageError::BadFrame),
            "{what}"
        );
    }
    // The unchanged form is accepted, so each case above is refused for its
    // own reason. (Firefox's scan names ids 1, 2, 3, as `frame_body` does.)
    assert!(sniff(&replace_segment(FIREFOX, SOF0, &frame_body(3))).is_ok());
}

#[test]
fn restart_markers_inside_the_scan_are_accepted() {
    let mut v = before_sos(FIREFOX, &segment(DRI, &[0, 4]));
    let scan_data = find(&v, SOS) + 2 + body_of(&v, SOS).len() + 2;
    for (k, rst) in (0xD0..=0xD7).enumerate() {
        let at = scan_data + 20 + 10 * k;
        v.splice(at..at, [0xFF, rst]);
    }
    assert!(sniff(&v).is_ok());
}

#[test]
fn a_segment_between_the_scan_and_the_end_is_refused() {
    let mut v = FIREFOX[..FIREFOX.len() - 2].to_vec();
    v.extend_from_slice(&segment(0xE1, &exif_with_gps()));
    v.extend_from_slice(&[0xFF, EOI]);
    assert_eq!(
        sniff(&v),
        Err(ImageError::UnexpectedMarker { marker: 0xE1 })
    );
}

#[test]
fn an_empty_scan_is_refused() {
    let sos = find(FIREFOX, SOS);
    let mut v = FIREFOX[..sos + 2 + 2 + body_of(FIREFOX, SOS).len()].to_vec();
    v.extend_from_slice(&[0xFF, EOI]);
    assert_eq!(sniff(&v), Err(ImageError::EmptyScan));
}

#[test]
fn both_kinds_of_table_are_required() {
    assert_eq!(sniff(&without(FIREFOX, DQT)), Err(ImageError::NoTables));
    assert_eq!(sniff(&without(FIREFOX, DHT)), Err(ImageError::NoTables));
}

#[test]
fn quantisation_tables_must_be_baseline_and_exact() {
    let good = body_of(FIREFOX, DQT);
    assert_eq!(good.len(), 65);
    let bad = |body: &[u8]| sniff(&replace_segment(FIREFOX, DQT, body));
    let mut sixteen_bit = good.clone();
    sixteen_bit[0] |= 0x10;
    assert_eq!(bad(&sixteen_bit), Err(ImageError::BadTable { marker: DQT }));
    let mut slot_four = good.clone();
    slot_four[0] = 4;
    assert_eq!(bad(&slot_four), Err(ImageError::BadTable { marker: DQT }));
    let mut long = good.clone();
    long.push(0);
    assert_eq!(bad(&long), Err(ImageError::BadTable { marker: DQT }));
    assert_eq!(bad(&[]), Err(ImageError::BadTable { marker: DQT }));
    // Five tables: one more than a baseline decoder has slots for.
    let mut five = Vec::new();
    for _ in 0..4 {
        five.extend_from_slice(&good);
    }
    assert_eq!(
        bad(&five),
        Err(ImageError::BadTable { marker: DQT }),
        "4 here + 1 more = 5"
    );
}

#[test]
fn huffman_tables_must_be_baseline_and_exact() {
    let good = body_of(FIREFOX, DHT);
    let bad = |body: &[u8]| sniff(&replace_segment(FIREFOX, DHT, body));
    let refused = Err(ImageError::BadTable { marker: DHT });
    let mut class_two = good.clone();
    class_two[0] = 0x20;
    assert_eq!(bad(&class_two), refused);
    let mut slot_two = good.clone();
    slot_two[0] = 0x02;
    assert_eq!(bad(&slot_two), refused);
    let mut extra = good.clone();
    extra.push(0);
    assert_eq!(bad(&extra), refused, "a byte after the last table");
    assert_eq!(bad(&good[..good.len() - 1]), refused, "one symbol short");
    let mut no_codes = good[..17].to_vec();
    no_codes[1..17].fill(0);
    assert_eq!(bad(&no_codes), refused);
    assert_eq!(bad(&[]), refused);
    // A fifth table, beyond the four baseline slots.
    assert_eq!(sniff(&before_sos(FIREFOX, &segment(DHT, &good))), refused);
}

/// An ICC APP2 body holding `profile`, as chunk 1 of 1.
fn icc_body(profile: &[u8]) -> Vec<u8> {
    let mut body = b"ICC_PROFILE\0\x01\x01".to_vec();
    body.extend_from_slice(profile);
    body
}

/// Chromium's real profile, resized to `len` bytes with its size field
/// updated to match.
fn profile_of_len(len: usize) -> Vec<u8> {
    let mut profile = body_of(CHROMIUM, APP2)[14..].to_vec();
    profile.resize(len, 0);
    profile[..4].copy_from_slice(&(len as u32).to_be_bytes());
    profile
}

#[test]
fn the_icc_profile_is_one_bounded_chunk() {
    let icc = body_of(CHROMIUM, APP2);
    let bad = |v: Vec<u8>| sniff(&v);
    assert_eq!(
        bad(after_soi(CHROMIUM, &segment(APP2, &icc))),
        Err(ImageError::Duplicate { marker: APP2 })
    );
    let mut one_of_two = icc.clone();
    one_of_two[13] = 2;
    assert_eq!(
        bad(replace_segment(CHROMIUM, APP2, &one_of_two)),
        Err(ImageError::BadIcc)
    );
    let mut second = icc.clone();
    second[12] = 2;
    assert_eq!(
        bad(replace_segment(CHROMIUM, APP2, &second)),
        Err(ImageError::BadIcc)
    );
    let over = icc_body(&profile_of_len(MAX_ICC_PROFILE_BYTES + 1));
    assert_eq!(
        bad(replace_segment(CHROMIUM, APP2, &over)),
        Err(ImageError::BadIcc)
    );
    let at_cap = icc_body(&profile_of_len(MAX_ICC_PROFILE_BYTES));
    assert!(
        bad(replace_segment(CHROMIUM, APP2, &at_cap)).is_ok(),
        "exactly at the cap"
    );
    assert_eq!(
        bad(replace_segment(CHROMIUM, APP2, &icc[..14])),
        Err(ImageError::BadIcc),
        "no profile"
    );
}

#[test]
fn the_icc_chunk_must_hold_a_whole_profile() {
    let bad = |profile: &[u8]| sniff(&replace_segment(CHROMIUM, APP2, &icc_body(profile)));
    // Shorter than an ICC header, even with a matching size field.
    let short = profile_of_len(ICC_PROFILE_HEADER_LEN - 1);
    assert_eq!(bad(&short), Err(ImageError::BadIcc));
    // Exactly a header is a well-formed (if empty) profile.
    assert!(bad(&profile_of_len(ICC_PROFILE_HEADER_LEN)).is_ok());
    // A size field that does not match the bytes present.
    let mut lying = profile_of_len(600);
    lying[3] ^= 1;
    assert_eq!(bad(&lying), Err(ImageError::BadIcc));
    // No profile signature: an arbitrary blob with an ICC label on it.
    let mut unsigned = profile_of_len(600);
    unsigned[36..40].copy_from_slice(b"GPS ");
    assert_eq!(bad(&unsigned), Err(ImageError::BadIcc));
}

#[test]
fn an_adobe_transform_must_be_a_known_one() {
    let mut adobe = b"Adobe\0\x64\0\0\0\0\x02".to_vec();
    assert!(sniff(&after_soi(FIREFOX, &segment(APP14, &adobe))).is_ok());
    adobe[11] = 3;
    assert_eq!(
        sniff(&after_soi(FIREFOX, &segment(APP14, &adobe))),
        Err(ImageError::BadAdobe)
    );
}

#[test]
fn sampling_must_stay_within_what_a_decoder_takes() {
    // Each factor 1 or 2: three components at 2x2 is 12 blocks, over 10.
    let mut frame = frame_body(3);
    for k in 0..3 {
        frame[7 + 3 * k] = 0x22;
    }
    assert_eq!(
        sniff(&replace_segment(FIREFOX, SOF0, &frame)),
        Err(ImageError::BadFrame)
    );
    // 2x2 + 2x1 + 2x1 is 8 blocks: accepted.
    let mut frame = frame_body(3);
    frame[7] = 0x22;
    frame[10] = 0x21;
    frame[13] = 0x21;
    assert!(sniff(&replace_segment(FIREFOX, SOF0, &frame)).is_ok());
    // A factor of 3 or 4 is refused even within the block budget.
    for sampling in [0x31, 0x13, 0x41] {
        let mut frame = frame_body(1);
        frame[7] = sampling;
        assert_eq!(
            sniff(&replace_segment(GREY, SOF0, &frame)),
            Err(ImageError::BadFrame),
            "{sampling:02X}"
        );
    }
}

#[test]
fn every_table_named_must_be_defined() {
    // Grey has one quantisation table (slot 0) and Huffman tables in DC
    // slot 0 and AC slot 0 only.
    let mut frame = frame_body(1);
    frame[8] = 1;
    assert_eq!(
        sniff(&replace_segment(GREY, SOF0, &frame)),
        Err(ImageError::BadFrame),
        "quant slot 1"
    );
    let scan = body_of(GREY, SOS);
    let mut dc_one = scan.clone();
    dc_one[2] = 0x10;
    assert_eq!(
        sniff(&replace_segment(GREY, SOS, &dc_one)),
        Err(ImageError::BadScan),
        "DC slot 1"
    );
    let mut ac_one = scan.clone();
    ac_one[2] = 0x01;
    assert_eq!(
        sniff(&replace_segment(GREY, SOS, &ac_one)),
        Err(ImageError::BadScan),
        "AC slot 1"
    );
    // Slots past any a baseline file can define: refused, and the slot
    // number is never used as a shift count (it would overflow).
    for spec in [0xF0, 0x0F, 0x90, 0x09] {
        let mut wild = scan.clone();
        wild[2] = spec;
        assert_eq!(
            sniff(&replace_segment(GREY, SOS, &wild)),
            Err(ImageError::BadScan),
            "{spec:02X}"
        );
    }
}

#[test]
fn a_huffman_table_holds_at_most_256_symbols() {
    // One AC table in slot 1: 16 code counts summing to `n`, then n symbols.
    let table = |n: usize| {
        let mut t = vec![0x11];
        let mut counts = [0u8; 16];
        let mut left = n;
        for c in counts.iter_mut().rev() {
            let take = left.min(255);
            *c = take as u8;
            left -= take;
        }
        t.extend_from_slice(&counts);
        t.extend(std::iter::repeat_n(0u8, n));
        t
    };
    // The grey file has two tables, so a third and fourth fit under the cap.
    assert!(sniff(&before_sos(GREY, &segment(DHT, &table(256)))).is_ok());
    assert_eq!(
        sniff(&before_sos(GREY, &segment(DHT, &table(257)))),
        Err(ImageError::BadTable { marker: DHT })
    );
}

#[test]
fn an_adobe_segment_must_be_its_fixed_form() {
    let mut long = b"Adobe\0\x64\0\0\0\0\x01".to_vec();
    long.push(0);
    assert_eq!(
        sniff(&after_soi(FIREFOX, &segment(APP14, &long))),
        Err(ImageError::BadAdobe)
    );
    assert_eq!(
        sniff(&after_soi(FIREFOX, &segment(APP14, b"Adobe"))),
        Err(ImageError::BadAdobe)
    );
}

#[test]
fn strip_keeps_an_adobe_segment_and_drops_another_app14() {
    let adobe = segment(APP14, b"Adobe\0\x64\0\0\0\0\x01");
    let with_adobe = after_soi(FIREFOX, &adobe);
    assert_eq!(strip(&with_adobe).as_deref(), Ok(&with_adobe[..]));
    let ducky = after_soi(FIREFOX, &segment(APP14, b"Ducky\0\x01"));
    assert_eq!(strip(&ducky).as_deref(), Ok(FIREFOX));
}

/// A Huffman table for `class_slot` with `counts` and the given symbols.
fn huffman(class_slot: u8, counts: [u8; 16], symbols: &[u8]) -> Vec<u8> {
    let mut t = vec![class_slot];
    t.extend_from_slice(&counts);
    t.extend_from_slice(symbols);
    t
}

#[test]
fn a_huffman_table_must_be_a_code_a_decoder_can_build() {
    let extra = |table: Vec<u8>| sniff(&before_sos(GREY, &segment(DHT, &table)));
    let refused = Err(ImageError::BadTable { marker: DHT });
    // Three one-bit codes: there are only two.
    let mut counts = [0; 16];
    counts[0] = 3;
    assert_eq!(extra(huffman(0x11, counts, &[1, 2, 3])), refused);
    // Two one-bit codes: fits, but uses the all-ones code, which is reserved.
    counts[0] = 2;
    assert_eq!(extra(huffman(0x11, counts, &[1, 2])), refused);
    // One one-bit code and two two-bit codes: the second two-bit code is
    // all ones again.
    counts[0] = 1;
    counts[1] = 2;
    assert_eq!(extra(huffman(0x11, counts, &[1, 2, 3])), refused);
    // One of each: a proper code.
    counts[1] = 1;
    assert!(extra(huffman(0x11, counts, &[1, 2])).is_ok());
    // Twelve one-bit codes, which codex found the earlier check accepted.
    let mut counts = [0; 16];
    counts[0] = 12;
    assert_eq!(extra(huffman(0x11, counts, &[0; 12])), refused);
}

#[test]
fn a_dc_symbol_is_a_magnitude_category_of_at_most_15() {
    let extra = |table: Vec<u8>| sniff(&before_sos(GREY, &segment(DHT, &table)));
    let mut counts = [0; 16];
    counts[1] = 2;
    assert!(extra(huffman(0x01, counts, &[0, 15])).is_ok());
    assert_eq!(
        extra(huffman(0x01, counts, &[0, 16])),
        Err(ImageError::BadTable { marker: DHT })
    );
    // The same symbol is fine in an AC table, where it means something else.
    assert!(extra(huffman(0x11, counts, &[0, 16])).is_ok());
}
