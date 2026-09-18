//! Image / media signing and verification tools (PRD §3.2, §4.2).
//!
//! These tools embed JACS signatures into image metadata (PNG iTXt, JPEG APP11,
//! WebP XMP) so the signature travels with the image. Robust mode (PNG/JPEG)
//! additionally encodes the signature into the LSB channel for survivability.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::schema_map;

// =============================================================================
// Request / Response Types
// =============================================================================

/// Parameters for `jacs_sign_image`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignImageParams {
    /// Input image file path.
    #[schemars(description = "Path to the input image (PNG, JPEG, or WebP)")]
    pub input_path: String,

    /// Output image file path. May be the same as `input_path` for in-place
    /// signing — a `.bak` is then created by default.
    #[schemars(description = "Path to write the signed output image")]
    pub output_path: String,

    /// PRD §4.2.3: enable LSB channel embedding alongside metadata.
    /// Default false (metadata-only).
    #[schemars(
        description = "Embed signature into the LSB channel as well as metadata for re-encode survivability (default: false)"
    )]
    pub robust: Option<bool>,

    /// Optional explicit format override ("png" | "jpeg" | "webp").
    /// Default: detect from input bytes.
    #[schemars(
        description = "Explicit format hint: 'png' | 'jpeg' | 'webp' (default: auto-detect)"
    )]
    pub format: Option<String>,

    /// PRD §4.2.2: refuse if the input image already carries a JACS signature.
    /// Default false (overwrite existing signature).
    #[schemars(
        description = "Refuse to overwrite an input that already carries a JACS signature (PRD §4.2.2 single-signer; default: false)"
    )]
    pub refuse_overwrite: Option<bool>,
}

/// Result of `jacs_sign_image`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignImageResult {
    pub success: bool,
    pub out_path: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,

    /// Detected (or hinted) image format: "png" | "jpeg" | "webp".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Whether robust LSB embedding was applied.
    pub robust: bool,

    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for `jacs_verify_image` (PRD §4.1.5, §4.2.4, C1).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyImageParams {
    #[schemars(description = "Path to the signed image to verify")]
    pub file_path: String,

    /// C1: missing signature -> hard error when true. Default false.
    #[schemars(
        description = "Treat 'no signature found' as a real error instead of a typed status (default: false)"
    )]
    pub strict: Option<bool>,

    /// PRD §4.1.5: directory containing `<signer_id>.public.pem` files.
    #[schemars(
        description = "Optional path to a directory containing public-key PEM files (PRD §4.1.5)"
    )]
    pub key_dir: Option<String>,

    /// PRD §4.2.4: scan LSB channel for robust-mode payload when metadata is absent.
    /// Default false.
    #[schemars(
        description = "Scan LSB channel for robust-mode payload when metadata is absent (default: false)"
    )]
    pub robust: Option<bool>,
}

/// Result of `jacs_verify_image`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyImageResult {
    pub success: bool,

    /// "valid" | "invalid_signature" | "hash_mismatch" | "missing_signature"
    /// | "key_not_found" | "unsupported_format" | "malformed".
    pub status: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// "metadata" | "metadata+lsb" — populated when status is `valid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding_channels: Option<String>,

    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for `jacs_extract_media_signature` (PRD §3.2).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractMediaSignatureParams {
    #[schemars(description = "Path to a signed image to extract the embedded JACS payload from")]
    pub file_path: String,

    /// PRD §3.2: when true, return the raw base64url wire form instead of the
    /// decoded JACS signed-document JSON.
    #[schemars(
        description = "Return the raw base64url wire form instead of the decoded JACS signed-document JSON (default: false)"
    )]
    pub raw_payload: Option<bool>,

    /// R-011 / PRD §4.2.4: when true, fall back to LSB scan if the metadata
    /// channel has no payload. Mirrors `verify_image --robust`.
    #[schemars(
        description = "Scan the LSB channel as a fallback if the metadata channel has no payload (default: false; cost: full pixel decode)"
    )]
    pub robust: Option<bool>,
}

/// Result of `jacs_extract_media_signature`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExtractMediaSignatureResult {
    pub success: bool,

    /// True iff a JACS signature payload was found in the image.
    pub present: bool,

    /// The payload (decoded JSON string by default; base64url wire form
    /// when `raw_payload: true`). `null` if not present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,

    pub message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the media family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_sign_image",
            "Sign a PNG, JPEG, or WebP image by embedding a JACS signature into format-native \
             metadata (PNG iTXt, JPEG APP11, WebP XMP). Default mode is metadata-only and does \
             NOT modify pixel data. Robust mode (PNG/JPEG only) additionally embeds into the LSB \
             channel for re-encode survivability — pass `robust: true` to enable. \
             Use `refuse_overwrite: true` to refuse an input that already carries a JACS signature \
             (PRD §4.2.2 single-signer guard).",
            schema_map::<SignImageParams>(),
        ),
        Tool::new(
            "jacs_verify_image",
            "Verify a JACS signature embedded in a PNG, JPEG, or WebP image. Permissive by default \
             (C1): missing signature returns `status: \"missing_signature\"` with `success: true`. \
             With `strict: true`, missing signatures cause `success: false`. Pass `key_dir` for \
             offline verification (PRD §4.1.5). Pass `robust: true` to also scan the LSB channel \
             for a robust-mode payload (PRD §4.2.4) when no metadata payload is found.",
            schema_map::<VerifyImageParams>(),
        ),
        Tool::new(
            "jacs_extract_media_signature",
            "Extract the JACS signature payload embedded in a PNG, JPEG, or WebP image. \
             By default returns the decoded JACS signed-document JSON string. Pass \
             `raw_payload: true` to return the base64url wire form instead (useful for \
             byte-for-byte relay or fuzz fixtures). Pass `robust: true` to fall back to \
             LSB scan when the metadata channel has no payload (R-011; mirrors \
             verify_image --robust). Returns `present: false` if no payload is found.",
            schema_map::<ExtractMediaSignatureParams>(),
        ),
    ]
}
