//! `jacs-media` — embed base64url-encoded JACS signed-document JSON in
//! PNG (iTXt), JPEG (APP11), or WebP (XMP) images.
//!
//! Design: `docs/prds/PROVENANCE_EXPANSION_PRD.md` §4.2.
//! Clean-room guardrails: `LICENSE-NOTICE` in this crate root. No ST3GG code.
//!
//! Public API:
//! - [`MediaFormat`] — PNG / JPEG / WebP discriminator.
//! - [`MediaError`] — error taxonomy with `PayloadTooLarge`, `Unsupported`,
//!   `Parse`, `Encode`, `UnsupportedFormat`.
//! - [`detect_format`] — magic-byte dispatch.
//! - [`embed_signature`] — write `signature_json` (base64url JACS JSON) into
//!   the format-appropriate metadata chunk; optionally also LSB (`robust: true`).
//! - [`extract_signature`] — read back the payload.
//! - [`canonical_hash`] / [`canonical_hash_robust`] — deterministic content
//!   hashing that excludes the JACS chunk (and, for the robust variant, zeroes
//!   the target-channel LSB so pre-embed and post-embed hashes match).
//!
//! # Asymmetry with markdown (intentional)
//!
//! The markdown inline-text signature block uses YAML as its on-disk format
//! (C3). The image-embedded payload uses base64url-encoded JSON. The asymmetry
//! is intentional: images are binary containers; human-readability of the
//! embedded payload has no user value, and JSON is what the rest of the JACS
//! stack already speaks.

pub mod format;
pub mod jpeg;
pub mod png;
pub mod robust;
pub mod webp;

pub use format::{MediaFormat, detect_format};

use sha2::{Digest, Sha256};

/// PNG iTXt chunk: 64 KiB JSON payload cap.
pub const MAX_PAYLOAD_BYTES_PNG: usize = 64 * 1024;

/// JPEG APP11 segment body (post-identifier) cap. 65533 - 5 (for `JACS\0`
/// identifier) = 65528. An earlier draft used 65533 which forgot the identifier;
/// see PRD §4.2.2 boundary tests.
pub const MAX_PAYLOAD_BYTES_JPEG: usize = 65_528;

/// WebP XMP chunk JSON payload cap.
pub const MAX_PAYLOAD_BYTES_WEBP: usize = 64 * 1024;

/// The keyword used for the PNG iTXt chunk.
pub const PNG_KEYWORD: &str = "JACS-Signature";

/// The JPEG APP11 identifier (5 bytes incl. trailing NUL).
pub const JPEG_IDENTIFIER: &[u8] = b"JACS\0";

/// The XMP key used in WebP payloads.
pub const WEBP_XMP_KEY: &str = "JACS:Signature";

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("unsupported format")]
    UnsupportedFormat,
    #[error("parse error: {0}")]
    Parse(String),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("payload too large: {actual} bytes > {limit} limit")]
    PayloadTooLarge { limit: usize, actual: usize },
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Embed the JACS signature payload (base64url JSON) into the format-specific
/// metadata chunk. `robust: true` additionally writes the same payload into
/// the visual-channel LSB stream (PNG/JPEG only; WebP + robust returns
/// `MediaError::Unsupported("webp robust mode deferred")`).
///
/// `refuse_overwrite: true` returns `MediaError::Parse("input already carries
/// JACS signature")` if a JACS chunk is already present — useful for
/// first-signer-wins workflows. Default (false) OVERWRITES any prior JACS
/// chunk, which is the expected behaviour for `sign-image foo.png --out foo.png`
/// idempotency.
///
/// Payload format reminder: the `signature_json` argument is the base64url-
/// encoded JACS signed-document JSON, NOT YAML. See PRD §4.2.2 C3.
pub fn embed_signature(
    bytes: &[u8],
    signature_json: &str,
    robust: bool,
    refuse_overwrite: bool,
) -> Result<Vec<u8>, MediaError> {
    let fmt = detect_format(bytes)?;
    match fmt {
        MediaFormat::Png => png::embed(bytes, signature_json, robust, refuse_overwrite),
        MediaFormat::Jpeg => jpeg::embed(bytes, signature_json, robust, refuse_overwrite),
        MediaFormat::WebP => {
            if robust {
                return Err(MediaError::Unsupported(
                    "webp robust mode deferred".to_string(),
                ));
            }
            webp::embed(bytes, signature_json, refuse_overwrite)
        }
    }
}

/// Extract the embedded signature payload. Returns `Ok(None)` if no JACS
/// chunk is present. `scan_robust: true` additionally scans the LSB channel
/// for the `"JACS"` magic preamble when the metadata channel is empty
/// (cost: full pixel decode; default off).
///
/// Returns `Err(MediaError::Parse("duplicate JACS-Signature chunk"))` if the
/// file contains more than one JACS chunk of the relevant type — we never
/// silently pick one.
pub fn extract_signature(bytes: &[u8], scan_robust: bool) -> Result<Option<String>, MediaError> {
    let fmt = detect_format(bytes)?;
    match fmt {
        MediaFormat::Png => png::extract(bytes, scan_robust),
        MediaFormat::Jpeg => jpeg::extract(bytes, scan_robust),
        MediaFormat::WebP => webp::extract(bytes),
    }
}

/// Non-robust canonicalisation: metadata-stripped image bytes. Matches claims
/// tagged `"jacs-media-v1"`. Verifiers MUST pick between this and
/// [`canonical_hash_robust`] by reading the claim's `canonicalization` tag.
pub fn canonical_hash(bytes: &[u8]) -> Result<[u8; 32], MediaError> {
    let fmt = detect_format(bytes)?;
    let stripped = match fmt {
        MediaFormat::Png => png::bytes_without_jacs_chunk(bytes)?,
        MediaFormat::Jpeg => jpeg::bytes_without_jacs_segment(bytes)?,
        MediaFormat::WebP => webp::bytes_without_jacs_chunk(bytes)?,
    };
    let mut hasher = Sha256::new();
    hasher.update(&stripped);
    let out: [u8; 32] = hasher.finalize().into();
    Ok(out)
}

/// Robust canonicalisation: metadata-stripped AND target-channel LSB-zeroed.
/// Matches claims tagged `"jacs-media-v1-robust"`. Invariant: robust
/// `canonical_hash` is the same before and after robust LSB embedding on the
/// same logical image. Calling on WebP returns
/// `MediaError::Unsupported("webp robust mode deferred")`.
pub fn canonical_hash_robust(bytes: &[u8]) -> Result<[u8; 32], MediaError> {
    let fmt = detect_format(bytes)?;
    match fmt {
        MediaFormat::Png => robust::canonical_hash_robust_png(bytes),
        MediaFormat::Jpeg => robust::canonical_hash_robust_jpeg(bytes),
        MediaFormat::WebP => Err(MediaError::Unsupported(
            "webp robust mode deferred".to_string(),
        )),
    }
}

/// Convenience: sha256 a buffer.
pub(crate) fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
