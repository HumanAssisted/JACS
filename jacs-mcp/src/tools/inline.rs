//! Inline text signing/verification tools (PRD §3.1).
//!
//! These tools sign and verify in-line markdown / text files using the JACS
//! signature block format (PRD §4.1). The signature is appended after the
//! original content, so signed files remain valid markdown / text.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::schema_map;

// =============================================================================
// Request / Response Types
// =============================================================================

/// Parameters for `jacs_sign_text` (PRD §4.1.1).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignTextParams {
    /// Path to the text/markdown file to sign in place.
    #[schemars(description = "Path to the text/markdown file to sign in place")]
    pub file_path: String,

    /// Skip the automatic .bak backup. Default: false (backup enabled).
    #[schemars(description = "Skip the automatic .bak backup (default: false)")]
    pub no_backup: Option<bool>,
}

/// Result of `jacs_sign_text`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignTextResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The path that was signed.
    pub file_path: String,

    /// Number of new signature blocks appended (0 if file already signed).
    pub signers_added: u32,

    /// Path to the .bak file if backup was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if signing failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for `jacs_verify_text` (PRD §4.1.5, C1).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyTextParams {
    /// Path to the file to verify.
    #[schemars(description = "Path to the signed text/markdown file to verify")]
    pub file_path: String,

    /// C1: When true, missing signature is reported as a hard error
    /// (`success: false`). Default false (permissive): missing signature
    /// is reported as `status: "missing_signature"` with `success: true`.
    #[schemars(
        description = "Treat 'no signature found' as a real error instead of a typed status (default: false)"
    )]
    pub strict: Option<bool>,

    /// PRD §4.1.5: optional path to a directory containing
    /// `<signer_id>.public.pem` files for offline verification.
    #[schemars(
        description = "Optional path to a directory containing public-key PEM files for offline verification"
    )]
    pub key_dir: Option<String>,
}

/// One signature entry from a verify-text result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignatureEntry {
    pub signer_id: String,
    pub algorithm: String,
    pub timestamp: String,
    /// "valid" | "invalid_signature" | "hash_mismatch" | "key_not_found" |
    /// "unsupported_algorithm" | "malformed".
    pub status: String,
}

/// Result of `jacs_verify_text`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyTextResult {
    /// Whether the operation completed without a hard error.
    /// In strict mode, missing signature flips this to `false`.
    pub success: bool,

    /// "signed" | "missing_signature" | "malformed".
    pub status: String,

    /// One entry per signature block found in the file.
    pub signatures: Vec<SignatureEntry>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if a hard error occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the inline-text family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_sign_text",
            "Sign a text/markdown file in place by appending an inline JACS signature block. \
             Content bytes are preserved exactly; the signature block is appended at the end \
             of the file (PRD §4.1, C2). A `<path>.bak` is created by default before signing. \
             Use this for signing markdown documents, agent prompts, or any plaintext file \
             where the signature should be embedded in the file itself.",
            schema_map::<SignTextParams>(),
        ),
        Tool::new(
            "jacs_verify_text",
            "Verify inline JACS signatures embedded in a text/markdown file. By default \
             (permissive mode, C1), a file with no signature returns `status: \"missing_signature\"` \
             with `success: true`. With `strict: true`, missing signatures cause `success: false` \
             with an explicit error. Pass `key_dir` (PRD §4.1.5) for offline verification using \
             pre-shared `<signer_id>.public.pem` files.",
            schema_map::<VerifyTextParams>(),
        ),
    ]
}
