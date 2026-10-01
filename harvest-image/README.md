# harvest-image

The rules for a Harvest listing image, shared by the image contract, the
seller's upload path and the buyer's display path.

## The shape (Ian, 2026-10-01)

An image is a contract whose parameters are the BLAKE3 hash of its state.
The state is the image file itself, nothing else: no wrapper, no type
field. A listing names an image by that hash, and anyone can derive the
contract key from it.

## One format, so no MIME type

Every upload is re-encoded in the browser, so the stored format is ours to
fix, and it is fixed at **baseline JPEG**. Nothing declares a type, so
nothing can declare a wrong one; a reader always builds an `image/jpeg`
blob. JPEG rather than WebP because every browser's canvas encodes JPEG,
while Safari's canvas cannot encode WebP at all (it silently returns PNG).

## Why an allowlist over the whole file

A JPEG can carry a seller's location in places a header check never
reaches: an APP1 Exif or XMP segment anywhere before the scan, a second
picture with its own Exif after the first end-of-image marker (MPF, which
phone cameras write), or a JFIF thumbnail. So [`sniff`] walks every
segment to the end of the file, accepts only the segments a canvas
encoder writes, checks each one's body against its fixed form, and
refuses everything else, including any byte after the end-of-image
marker. Real output from Chromium, Firefox and WebKit is in
`tests/fixtures/` and must keep passing.

The threat this answers is a seller's own browser leaking a photo's
location by ACCIDENT, through the containers cameras fill in. A seller
who means to hide bytes in their own photo can still do it in table
values or the compressed data; no check short of re-encoding closes
that, and nothing here claims to.

**What this does not prove**: that the entropy-coded data decodes to a
sensible picture. Only a full decode could, and the buyer's browser does
that decode, in its sandbox, at dimensions this module has bounded.

## One crate for all three checks

The contract, the seller's pre-publish check and the buyer's pre-display
check all call this crate at one commit, so they cannot disagree. It
depends on `blake3` alone and nothing in `harvest-common`, so ordinary
Harvest changes never move the image contract's code hash, and with it
every image's address.

## Where the decodability checks stop, and why

`sniff` refuses a header that libjpeg (which every browser's decoder is,
or behaves like) refuses while READING THE HEADER:
- an undefined table slot;
- a Huffman table that is not a prefix code;
- a DC symbol over 15;
- sampling beyond the block limit.

It does not check values that only matter once the compressed data uses
them. Those are:
- AC symbol values;
- quantiser values (a zero divides nothing; it only scales);
- the compressed data itself.

Those belong to the same class as the compressed data, which `sniff` cannot
check without decoding. A seller whose file passes `sniff` and still does
not render has published a broken picture of their own. No one else is
affected, and the buyer sees the colour block. Reviews of #212 found more
such values each round; this is the line, so it is not re-litigated one
value at a time.

## Line numbers are part of every image's address

This crate is compiled into the image contract, and a release build bakes the
`file:line:col` of every possible panic into the WASM. So ANY edit to
`src/lib.rs` that moves a line, a comment included, changes the image
contract's code hash and with it every image's address. The drift guard
(`contract-drift.yml`) reports it as a re-key. Measured on #212: adding four
comment lines to a doc comment moved the hash.

Two things keep that from happening by accident:

- This prose lives here, not in `src/lib.rs`, so editing the docs moves
  nothing. (`src/lib.rs` includes it with `#![doc = include_str!(...)]`.)
- [`strip`], which only the seller's upload path calls, lives in
  `src/strip.rs`. The contract never links it, so changing it moves nothing.

A deliberate change to `src/lib.rs` is a re-key of the image contract: record
the outgoing hash in `legacy/image_contract.toml` first, as for any contract.
