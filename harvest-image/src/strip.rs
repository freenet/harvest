//! [`strip`]: the seller's upload path's metadata remover. In a file of its
//! own because the image contract never calls it: changing it must not move
//! a line of `lib.rs`, whose line numbers are part of every image's address
//! (see the crate README).

use super::{
    check_jfif, parse, ImageError, ADOBE_TAG, APP0, APP14, APP2, COM, EOI, ICC_TAG, SOI, SOS,
};

/// The JPEG with every segment [`sniff`](crate::sniff) would refuse as metadata removed,
/// and anything after end-of-image dropped. For the seller's upload path: a
/// browser that ever writes metadata into its canvas output (an engine not in
/// `tests/fixtures/`) still produces a publishable image, and the result is
/// then checked with [`sniff`](crate::sniff) like any other.
///
/// It removes only what carries no picture: APPn segments other than a
/// thumbnail-free JFIF header, an ICC profile and an Adobe colour marker;
/// comments; and trailing data, which is where a second (MPF) picture sits.
/// It does not convert progressive files, add or remove scans, or repair a
/// truncated file; those are refused with the same errors as [`sniff`](crate::sniff).
pub fn strip(bytes: &[u8]) -> Result<Vec<u8>, ImageError> {
    let parsed = parse(bytes)?;
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&[0xFF, SOI]);
    let mut kept_jfif = false;
    for seg in &parsed.head {
        let keep = match seg.marker {
            APP0 => !kept_jfif && check_jfif(seg.body).is_ok(),
            APP2 => seg.body.starts_with(ICC_TAG),
            APP14 => seg.body.starts_with(ADOBE_TAG),
            0xE0..=0xEF | COM => false,
            _ => true,
        };
        if !keep {
            continue;
        }
        if seg.marker == APP0 {
            kept_jfif = true;
        }
        write_segment(&mut out, seg.marker, seg.body);
    }
    write_segment(&mut out, SOS, parsed.scan_header);
    out.extend_from_slice(parsed.entropy);
    out.extend_from_slice(&[0xFF, EOI]);
    Ok(out)
}

fn write_segment(out: &mut Vec<u8>, marker: u8, body: &[u8]) {
    // `parse` read this length from a u16 field, so it fits back into one.
    let len = (body.len() + 2) as u16;
    out.extend_from_slice(&[0xFF, marker]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
}
