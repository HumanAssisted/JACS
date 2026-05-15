//! Issue 016 / PRD §5.1: PNG signature survives `oxipng` lossless
//! optimisation when safe-to-copy chunks are preserved.
//!
//! The user-facing claim "JACS iTXt signatures survive PNG optimisers" needs a
//! load-bearing test. We run a freshly-signed PNG through `oxipng` with default
//! settings (which keep iTXt chunks marked safe-to-copy) and assert the
//! signature is still extractable. We also lock the negative case
//! (`StripChunks::All` strips iTXt) so future contributors notice if oxipng's
//! defaults change.

use jacs_media::{embed_signature, extract_signature};
use std::io::Cursor;

fn fresh_png_bytes() -> Vec<u8> {
    // Build a tiny PNG via the `image` crate so the test is hermetic.
    let img = image::RgbaImage::from_pixel(8, 8, image::Rgba([10, 20, 30, 255]));
    let mut buf = Vec::new();
    let mut cur = Cursor::new(&mut buf);
    img.write_to(&mut cur, image::ImageFormat::Png)
        .expect("png encode");
    buf
}

#[test]
fn png_signature_survives_oxipng_default_optimisation() {
    let png = fresh_png_bytes();
    let payload = "test-signature-payload-survives-oxipng";
    let signed = embed_signature(&png, payload, false, false).expect("embed");

    // Confirm the JACS iTXt chunk is present pre-optimisation.
    let pre = extract_signature(&signed, false)
        .expect("extract pre-oxipng")
        .expect("payload pre-oxipng");
    assert_eq!(pre, payload);

    // Run through oxipng with defaults (no chunk stripping). PRD §5.1: this
    // is the "expected to survive" case — oxipng leaves safe-to-copy chunks
    // (iTXt) alone.
    let opts = oxipng::Options {
        strip: oxipng::StripChunks::None,
        idat_recoding: false,
        ..Default::default()
    };

    let optimised = oxipng::optimize_from_memory(&signed, &opts).expect("oxipng optimize");

    let extracted = extract_signature(&optimised, false)
        .expect("extract post-oxipng")
        .expect("payload survived oxipng default optimisation");
    assert_eq!(
        extracted, payload,
        "PNG signature must survive oxipng default optimisation (safe-to-copy chunks preserved)"
    );
}

#[test]
fn png_signature_lost_through_oxipng_strip_all() {
    // Negative case: `StripChunks::All` removes safe-to-copy ancillary chunks
    // including iTXt — the JACS signature is gone post-optimisation. Locking
    // this lets future contributors notice if oxipng's strip-all semantics
    // change in a way that affects us.
    let png = fresh_png_bytes();
    let payload = "lost-through-strip-all";
    let signed = embed_signature(&png, payload, false, false).expect("embed");

    let opts = oxipng::Options {
        strip: oxipng::StripChunks::All,
        idat_recoding: false,
        ..Default::default()
    };

    let stripped = oxipng::optimize_from_memory(&signed, &opts).expect("oxipng optimize");

    // Metadata channel is stripped — extract returns None (no payload found).
    // The robust LSB fallback path is tested separately in jacs/tests/.
    let extracted = extract_signature(&stripped, false).expect("extract post-strip-all");
    assert!(
        extracted.is_none(),
        "StripChunks::All MUST drop the iTXt JACS chunk (got {:?})",
        extracted
    );
}
