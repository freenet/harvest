#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::fmt;

/// Length of the parameters: one BLAKE3 hash.
pub const HASH_LEN: usize = 32;

/// The largest state the contract accepts. The browser aims below this
/// (about 240 KiB for a full image, 30 KiB for a thumbnail).
pub const MAX_IMAGE_BYTES: usize = 256 * 1024;

/// The longest edge, in pixels, an image may declare. Bounds what a buyer's
/// browser is asked to decode: a 200 KB file may otherwise declare
/// 65535 x 65535 and exhaust the tab's memory.
pub const MAX_IMAGE_EDGE: u16 = 2048;

/// The largest ICC profile accepted, in one segment. Canvas encoders write a
/// fixed profile for their colour space (Chromium's and WebKit's are 456
/// bytes); the cap bounds what a buyer's browser is asked to parse.
pub const MAX_ICC_PROFILE_BYTES: usize = 8 * 1024;

/// What a valid image is, as far as its header says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageInfo {
    pub width: u16,
    pub height: u16,
}

/// Why bytes are not a Harvest image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// Parameters that are not one BLAKE3 hash.
    ParamsLength(usize),
    /// An empty state. Never valid: an empty copy must not stand in for an
    /// image, or anyone could blank one by publishing nothing under its key.
    Empty,
    /// Over [`MAX_IMAGE_BYTES`].
    TooLarge(usize),
    /// The bytes do not hash to the parameters.
    HashMismatch,
    /// Does not start with a JPEG start-of-image marker.
    NotJpeg,
    /// The file ends inside a segment or a scan.
    Truncated,
    /// A segment length shorter than its own length field.
    BadLength { marker: u8 },
    /// A metadata segment (APPn other than the allowed three, or COM).
    Metadata { marker: u8 },
    /// A frame type other than baseline (SOF0): progressive, lossless,
    /// arithmetic or hierarchical.
    UnsupportedCoding { marker: u8 },
    /// A marker that has no place in a baseline JPEG here.
    UnexpectedMarker { marker: u8 },
    /// A segment that may appear once appeared twice.
    Duplicate { marker: u8 },
    /// An APP0 that is not exactly a JFIF header with no thumbnail.
    BadJfif,
    /// A frame header this module does not accept.
    BadFrame,
    /// A scan header this module does not accept, or one before the frame.
    BadScan,
    /// More than one scan. A canvas writes one; a second is room to hide in.
    MultipleScans,
    /// No frame header, so no dimensions.
    NoFrame,
    /// A quantisation or Huffman table segment that does not parse as
    /// baseline tables, or more tables than a baseline file can use.
    BadTable { marker: u8 },
    /// No quantisation table, or no Huffman table.
    NoTables,
    /// An ICC profile that is not exactly one chunk, or over
    /// [`MAX_ICC_PROFILE_BYTES`].
    BadIcc,
    /// An Adobe APP14 segment that is not the fixed 12-byte form.
    BadAdobe,
    /// A scan with no entropy-coded data.
    EmptyScan,
    /// Bytes after the end-of-image marker.
    TrailingBytes,
    /// A dimension of zero or over [`MAX_IMAGE_EDGE`].
    Dimensions { width: u16, height: u16 },
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParamsLength(n) => write!(
                f,
                "image parameters must be the {HASH_LEN}-byte BLAKE3 hash of the image, got {n} bytes"
            ),
            Self::Empty => write!(f, "an image cannot be empty"),
            Self::TooLarge(n) => write!(f, "image is {n} bytes, over the {MAX_IMAGE_BYTES}-byte cap"),
            Self::HashMismatch => write!(f, "image bytes do not hash to the contract parameters"),
            Self::NotJpeg => write!(f, "not a JPEG"),
            Self::Truncated => write!(f, "JPEG is truncated"),
            Self::BadLength { marker } => write!(f, "JPEG segment FF{marker:02X} has an impossible length"),
            Self::Metadata { marker } => write!(f, "JPEG carries a metadata segment (FF{marker:02X})"),
            Self::UnsupportedCoding { marker } => {
                write!(f, "only baseline JPEG is accepted, found frame type FF{marker:02X}")
            }
            Self::UnexpectedMarker { marker } => write!(f, "unexpected JPEG marker FF{marker:02X}"),
            Self::Duplicate { marker } => write!(f, "JPEG segment FF{marker:02X} appears twice"),
            Self::BadJfif => write!(f, "JPEG APP0 is not a plain JFIF header without a thumbnail"),
            Self::BadFrame => write!(f, "JPEG frame header is not an accepted baseline frame"),
            Self::BadScan => write!(f, "JPEG scan header is not accepted"),
            Self::MultipleScans => write!(f, "JPEG has more than one scan"),
            Self::NoFrame => write!(f, "JPEG has no frame header"),
            Self::BadTable { marker } => write!(f, "JPEG table segment FF{marker:02X} is not baseline"),
            Self::NoTables => write!(f, "JPEG lacks a quantisation or Huffman table"),
            Self::BadIcc => write!(
                f,
                "JPEG ICC profile must be one chunk of at most {MAX_ICC_PROFILE_BYTES} bytes"
            ),
            Self::BadAdobe => write!(f, "JPEG Adobe segment is not the fixed 12-byte form"),
            Self::EmptyScan => write!(f, "JPEG scan has no image data"),
            Self::TrailingBytes => write!(f, "bytes after the end of the JPEG"),
            Self::Dimensions { width, height } => write!(
                f,
                "image is {width}x{height}; each edge must be 1 to {MAX_IMAGE_EDGE} pixels"
            ),
        }
    }
}

impl std::error::Error for ImageError {}

/// The BLAKE3 hash that names an image: its contract parameters.
pub fn image_hash(bytes: &[u8]) -> [u8; HASH_LEN] {
    *blake3::hash(bytes).as_bytes()
}

/// Whether `state` is a valid image for an image contract with these
/// `parameters`. The checks run cheapest first, and the size cap runs before
/// hashing so an oversized state costs nothing to refuse.
pub fn validate(parameters: &[u8], state: &[u8]) -> Result<ImageInfo, ImageError> {
    if parameters.len() != HASH_LEN {
        return Err(ImageError::ParamsLength(parameters.len()));
    }
    if state.is_empty() {
        return Err(ImageError::Empty);
    }
    if state.len() > MAX_IMAGE_BYTES {
        return Err(ImageError::TooLarge(state.len()));
    }
    if image_hash(state) != parameters {
        return Err(ImageError::HashMismatch);
    }
    sniff(state)
}

const SOI: u8 = 0xD8;
const EOI: u8 = 0xD9;
const SOS: u8 = 0xDA;
const DQT: u8 = 0xDB;
const DHT: u8 = 0xC4;
const DRI: u8 = 0xDD;
const SOF0: u8 = 0xC0;
const APP0: u8 = 0xE0;
const APP2: u8 = 0xE2;
const APP14: u8 = 0xEE;
const COM: u8 = 0xFE;

/// The length field of a plain JFIF APP0 segment (which counts itself):
/// `JFIF\0`, a version, a unit, two densities and a 0 x 0 thumbnail, so a
/// 14-byte body.
const JFIF_LEN: usize = 16;

/// One marker segment: its marker and the body after the two length bytes.
struct Segment<'a> {
    marker: u8,
    body: &'a [u8],
}

/// A JPEG split into its parts. Structural only: every length is in bounds,
/// there is exactly one scan, and it is followed by end-of-image. No policy
/// about WHICH segments appear; that is [`sniff`]'s job and [`strip()`]'s.
struct Parsed<'a> {
    /// The segments before the scan, in order.
    head: Vec<Segment<'a>>,
    /// The scan header's body.
    scan_header: &'a [u8],
    /// The entropy-coded data, up to but not including end-of-image.
    entropy: &'a [u8],
    /// Anything after end-of-image.
    trailing: &'a [u8],
}

fn parse(bytes: &[u8]) -> Result<Parsed<'_>, ImageError> {
    if bytes.len() < 2 || bytes[0] != 0xFF || bytes[1] != SOI {
        return Err(ImageError::NotJpeg);
    }
    let mut i = 2;
    let mut head = Vec::new();
    loop {
        // Every segment starts with exactly one 0xFF. The standard lets an
        // encoder pad with extra 0xFF fill bytes; no canvas does, and
        // refusing them keeps one layout per file.
        if i + 2 > bytes.len() {
            return Err(ImageError::Truncated);
        }
        if bytes[i] != 0xFF {
            return Err(ImageError::UnexpectedMarker { marker: bytes[i] });
        }
        let marker = bytes[i + 1];
        match marker {
            // Markers with no length field.
            SOI | EOI | 0x01 | 0xD0..=0xD7 | 0xFF => {
                return Err(ImageError::UnexpectedMarker { marker });
            }
            _ => {}
        }
        if i + 4 > bytes.len() {
            return Err(ImageError::Truncated);
        }
        let len = usize::from(u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]));
        if len < 2 {
            return Err(ImageError::BadLength { marker });
        }
        let end = i + 2 + len;
        if end > bytes.len() {
            return Err(ImageError::Truncated);
        }
        let body = &bytes[i + 4..end];
        i = end;
        if marker != SOS {
            head.push(Segment { marker, body });
            continue;
        }
        // The scan. Entropy-coded data runs until a 0xFF that is neither a
        // stuffed zero (FF00) nor a restart marker (FFD0-FFD7).
        let start = i;
        loop {
            if i >= bytes.len() {
                return Err(ImageError::Truncated);
            }
            if bytes[i] != 0xFF {
                i += 1;
                continue;
            }
            match bytes.get(i + 1) {
                None => return Err(ImageError::Truncated),
                Some(0x00) | Some(0xD0..=0xD7) => i += 2,
                Some(&EOI) => {
                    return Ok(Parsed {
                        head,
                        scan_header: body,
                        entropy: &bytes[start..i],
                        trailing: &bytes[i + 2..],
                    });
                }
                // A second scan, or tables for one. A canvas writes a single
                // interleaved scan.
                Some(&SOS) | Some(&DHT) | Some(&DQT) | Some(&DRI) => {
                    return Err(ImageError::MultipleScans)
                }
                // Anything else after the scan: a fill byte, DNL, or a
                // segment (an APPn would be metadata after the picture).
                Some(&marker) => return Err(ImageError::UnexpectedMarker { marker }),
            }
        }
    }
}

/// Whether `bytes` is a baseline JPEG in the layout a canvas writes, with no
/// metadata, at accepted dimensions. See the module docs for what is allowed
/// and why.
///
/// Every allowed segment's body is checked too, not only its marker: the
/// quantisation and Huffman tables parse as baseline tables and are consumed
/// exactly; the frame and scan headers carry only baseline values and use
/// only table slots that were defined; the ICC profile is one chunk with a
/// valid ICC header, at most [`MAX_ICC_PROFILE_BYTES`]; the Adobe segment is
/// its 12-byte form. The ICC profile's contents and the Adobe flag bytes are
/// bounded, not fixed: those are the containers a canvas fills with its own
/// colour data, and nothing a camera writes reaches them.
///
/// **What remains, stated plainly:** table VALUES and the entropy-coded data
/// can still be chosen to carry bytes. That cannot be closed by any check
/// short of re-encoding, and it does not need to be: the threat here is a
/// seller's own browser leaking a photo's location by accident, through the
/// metadata containers a camera fills in. A seller who sets out to hide data
/// in their own photo can always do so.
pub fn sniff(bytes: &[u8]) -> Result<ImageInfo, ImageError> {
    let parsed = parse(bytes)?;
    if !parsed.trailing.is_empty() {
        return Err(ImageError::TrailingBytes);
    }
    let mut frame: Option<Frame> = None;
    let (mut seen_jfif, mut seen_dri, mut seen_adobe, mut seen_icc) = (false, false, false, false);
    let (mut quant_tables, mut huffman_tables) = (0usize, 0usize);
    let mut defined = Slots::default();
    for seg in &parsed.head {
        match seg.marker {
            DQT => quant_tables += check_quant_tables(seg.body, &mut defined)?,
            DHT => huffman_tables += check_huffman_tables(seg.body, &mut defined)?,
            DRI => {
                if seg.body.len() != 2 {
                    return Err(ImageError::BadLength { marker: DRI });
                }
                once(&mut seen_dri, DRI)?;
            }
            APP0 => {
                once(&mut seen_jfif, APP0)?;
                check_jfif(seg.body)?;
            }
            APP2 if seg.body.starts_with(ICC_TAG) => {
                once(&mut seen_icc, APP2)?;
                check_icc(seg.body)?;
            }
            APP14 if seg.body.starts_with(ADOBE_TAG) => {
                once(&mut seen_adobe, APP14)?;
                // The last byte is the colour transform: 0 (none), 1
                // (YCbCr) or 2 (YCCK).
                if seg.body.len() != ADOBE_BODY_LEN || seg.body[ADOBE_BODY_LEN - 1] > 2 {
                    return Err(ImageError::BadAdobe);
                }
            }
            SOF0 => {
                if frame.is_some() {
                    return Err(ImageError::Duplicate { marker: SOF0 });
                }
                frame = Some(check_frame(seg.body)?);
            }
            // Every other APPn, including APP1 (Exif, XMP), APP2 that is not
            // an ICC profile (MPF), APP13 (IPTC), and comments.
            0xE0..=0xEF | COM => return Err(ImageError::Metadata { marker: seg.marker }),
            // Every other frame type: extended, progressive, lossless,
            // hierarchical, arithmetic. (C4 is DHT, handled above; C8 and CC
            // are JPG and DAC, which no baseline file has.)
            0xC1..=0xCF => return Err(ImageError::UnsupportedCoding { marker: seg.marker }),
            marker => return Err(ImageError::UnexpectedMarker { marker }),
        }
        // A baseline decoder has four quantisation slots and four Huffman
        // slots (two classes of two). Redefining them is legal JPEG, and
        // also unbounded room; no canvas does it.
        if quant_tables > 4 {
            return Err(ImageError::BadTable { marker: DQT });
        }
        if huffman_tables > 4 {
            return Err(ImageError::BadTable { marker: DHT });
        }
    }
    let frame = frame.ok_or(ImageError::NoFrame)?;
    if quant_tables == 0 || huffman_tables == 0 {
        return Err(ImageError::NoTables);
    }
    // Every table the frame and scan name must exist. A decoder refuses a
    // file that names an undefined one.
    if frame
        .quant_slots
        .iter()
        .any(|&s| defined.quant & (1 << s) == 0)
    {
        return Err(ImageError::BadFrame);
    }
    check_scan(parsed.scan_header, &frame.ids, &defined)?;
    if parsed.entropy.is_empty() {
        return Err(ImageError::EmptyScan);
    }
    Ok(frame.info)
}

fn once(seen: &mut bool, marker: u8) -> Result<(), ImageError> {
    if std::mem::replace(seen, true) {
        return Err(ImageError::Duplicate { marker });
    }
    Ok(())
}

const ICC_TAG: &[u8] = b"ICC_PROFILE\0";
const ADOBE_TAG: &[u8] = b"Adobe";
/// `Adobe`, a version, two flag words and a colour transform byte.
const ADOBE_BODY_LEN: usize = 12;

/// `JFIF\0`, version, units, X and Y density, and a 0 x 0 thumbnail: the
/// header and nothing else. A JFIF thumbnail is a second picture, and may be
/// a different one.
fn check_jfif(body: &[u8]) -> Result<(), ImageError> {
    if body.len() != JFIF_LEN - 2 || !body.starts_with(b"JFIF\0") || body[12] != 0 || body[13] != 0
    {
        return Err(ImageError::BadJfif);
    }
    Ok(())
}

/// The length of an ICC profile's own header (ICC.1, section 7.2).
const ICC_PROFILE_HEADER_LEN: usize = 128;

/// One ICC chunk, numbered 1 of 1, holding a whole profile of at most
/// [`MAX_ICC_PROFILE_BYTES`]: its header's size field equals the bytes
/// present, and it carries the `acsp` signature. So the segment is a profile,
/// not an arbitrary blob with an ICC label on it.
fn check_icc(body: &[u8]) -> Result<(), ImageError> {
    let header = ICC_TAG.len() + 2;
    if body.len() < header + ICC_PROFILE_HEADER_LEN
        || body.len() - header > MAX_ICC_PROFILE_BYTES
        || body[ICC_TAG.len()] != 1
        || body[ICC_TAG.len() + 1] != 1
    {
        return Err(ImageError::BadIcc);
    }
    let profile = &body[header..];
    let declared = u32::from_be_bytes([profile[0], profile[1], profile[2], profile[3]]);
    if declared as usize != profile.len() || &profile[36..40] != b"acsp" {
        return Err(ImageError::BadIcc);
    }
    Ok(())
}

/// Which table slots the file defines, one bit per slot.
#[derive(Default)]
struct Slots {
    quant: u8,
    dc: u8,
    ac: u8,
}

/// The quantisation tables in one DQT segment, each `Pq|Tq` then 64 bytes,
/// with 8-bit precision (`Pq` = 0, as baseline requires) and a slot of 0-3,
/// consuming the body exactly. Records the slots it defines and returns how
/// many tables it held.
fn check_quant_tables(body: &[u8], defined: &mut Slots) -> Result<usize, ImageError> {
    let bad = ImageError::BadTable { marker: DQT };
    if body.is_empty() || !body.len().is_multiple_of(65) {
        return Err(bad);
    }
    for table in body.chunks_exact(65) {
        if table[0] >> 4 != 0 || table[0] & 0x0F > 3 {
            return Err(bad);
        }
        defined.quant |= 1 << (table[0] & 0x0F);
    }
    Ok(body.len() / 65)
}

/// The Huffman tables in one DHT segment, each `Tc|Th`, sixteen code counts
/// and that many symbols, with class and slot each 0 or 1 (baseline),
/// consuming the body exactly. Records the slots it defines and returns how
/// many tables it held.
fn check_huffman_tables(body: &[u8], defined: &mut Slots) -> Result<usize, ImageError> {
    let bad = ImageError::BadTable { marker: DHT };
    let mut rest = body;
    let mut tables = 0;
    while !rest.is_empty() {
        if rest.len() < 17 || rest[0] >> 4 > 1 || rest[0] & 0x0F > 1 {
            return Err(bad);
        }
        let symbols: usize = rest[1..17].iter().map(|&n| usize::from(n)).sum();
        // 162 symbols cover every 8-bit AC code; 256 is the hard ceiling.
        if symbols == 0 || symbols > 256 || rest.len() < 17 + symbols {
            return Err(bad);
        }
        if !is_prefix_code(&rest[1..17]) {
            return Err(bad);
        }
        let slot = 1 << (rest[0] & 0x0F);
        if rest[0] >> 4 == 0 {
            // A DC symbol is a magnitude category, at most 11 for 8-bit
            // samples; libjpeg refuses anything over 15, and so does this.
            if rest[17..17 + symbols].iter().any(|&s| s > 15) {
                return Err(bad);
            }
            defined.dc |= slot;
        } else {
            defined.ac |= slot;
        }
        rest = &rest[17 + symbols..];
        tables += 1;
    }
    if tables == 0 {
        return Err(bad);
    }
    Ok(tables)
}

/// Whether sixteen code-length counts describe a Huffman code a decoder will
/// build: at each length, the codes assigned so far must leave room, and the
/// all-ones code is reserved. This is libjpeg's own check
/// (`jpeg_make_d_derived_tbl`), so a table it would refuse is refused here,
/// rather than published as an image no browser shows.
fn is_prefix_code(counts: &[u8]) -> bool {
    let mut code: u32 = 0;
    for (length, &count) in counts.iter().enumerate() {
        code += u32::from(count);
        if code >= 1 << (length + 1) {
            return false;
        }
        code <<= 1;
    }
    true
}

/// What a frame header says, for the scan to be checked against.
struct Frame {
    info: ImageInfo,
    /// Component ids, in frame order.
    ids: Vec<u8>,
    /// The quantisation slot each component uses.
    quant_slots: Vec<u8>,
}

/// A baseline frame: 8-bit samples, one (grey) or three (colour) components
/// with distinct ids, sampling factors of 1 or 2 totalling at most 10 blocks
/// per unit (libjpeg's block limit), a quantisation slot of 0-3, a length
/// that matches, and dimensions inside the cap. libjpeg itself allows
/// factors up to 4, so this refuses some files a browser would show (4:1:1);
/// every canvas writes 1 or 2, which is all an upload ever is.
fn check_frame(body: &[u8]) -> Result<Frame, ImageError> {
    if body.len() < 6 {
        return Err(ImageError::BadFrame);
    }
    let precision = body[0];
    let height = u16::from_be_bytes([body[1], body[2]]);
    let width = u16::from_be_bytes([body[3], body[4]]);
    let components = body[5];
    if precision != 8 || !(components == 1 || components == 3) {
        return Err(ImageError::BadFrame);
    }
    if body.len() != 6 + 3 * usize::from(components) {
        return Err(ImageError::BadFrame);
    }
    let mut ids = Vec::with_capacity(usize::from(components));
    let mut quant_slots = Vec::with_capacity(usize::from(components));
    let mut blocks = 0u8;
    for spec in body[6..].chunks_exact(3) {
        let (id, sampling, slot) = (spec[0], spec[1], spec[2]);
        let (h, v) = (sampling >> 4, sampling & 0x0F);
        if ids.contains(&id) || !(1..=2).contains(&h) || !(1..=2).contains(&v) || slot > 3 {
            return Err(ImageError::BadFrame);
        }
        blocks += h * v;
        ids.push(id);
        quant_slots.push(slot);
    }
    if blocks > 10 {
        return Err(ImageError::BadFrame);
    }
    if width == 0 || height == 0 || width > MAX_IMAGE_EDGE || height > MAX_IMAGE_EDGE {
        return Err(ImageError::Dimensions { width, height });
    }
    Ok(Frame {
        info: ImageInfo { width, height },
        ids,
        quant_slots,
    })
}

/// The one scan must cover every component, in frame order, since there is
/// no other scan to carry the rest, with baseline Huffman slots (0 or 1)
/// that were defined, and the baseline spectral values (0, 63, 0, 0).
fn check_scan(body: &[u8], ids: &[u8], defined: &Slots) -> Result<(), ImageError> {
    let Some(&count) = body.first() else {
        return Err(ImageError::BadScan);
    };
    if usize::from(count) != ids.len() || body.len() != 4 + 2 * usize::from(count) {
        return Err(ImageError::BadScan);
    }
    for (spec, id) in body[1..1 + 2 * ids.len()].chunks_exact(2).zip(ids) {
        let (dc, ac) = (spec[1] >> 4, spec[1] & 0x0F);
        if spec[0] != *id || dc > 1 || ac > 1 {
            return Err(ImageError::BadScan);
        }
        if defined.dc & (1 << dc) == 0 || defined.ac & (1 << ac) == 0 {
            return Err(ImageError::BadScan);
        }
    }
    if body[body.len() - 3..] != [0, 63, 0] {
        return Err(ImageError::BadScan);
    }
    Ok(())
}

mod strip;
pub use strip::strip;

#[cfg(test)]
mod tests;
