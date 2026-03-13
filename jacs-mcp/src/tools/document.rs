//! Document signing and verification tools.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn schema_map<T: JsonSchema>() -> serde_json::Map<String, serde_json::Value> {
    let schema = schemars::schema_for!(T);
    match serde_json::to_value(schema) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    }
}

// =============================================================================
// Request/Response Types
// =============================================================================

/// Parameters for signing arbitrary content as a JACS document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignDocumentParams {
    /// The JSON content string to sign.
    #[schemars(description = "The JSON content to sign as a JACS document")]
    pub content: String,

    /// Optional MIME type of the content (default: "application/json").
    #[schemars(description = "MIME type of the content (default: 'application/json')")]
    pub content_type: Option<String>,
}

/// Result of signing a document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SignDocumentResult {
    /// Whether the operation succeeded.
    pub success: bool,

    /// The full signed JACS document as a JSON string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_document: Option<String>,

    /// SHA-256 hash of the signed document content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,

    /// The JACS document ID assigned to the signed document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jacs_document_id: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if signing failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Parameters for verifying a raw signed JACS document string.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyDocumentParams {
    /// The full JACS signed document as a JSON string.
    #[schemars(description = "The full signed JACS document JSON string to verify")]
    pub document: String,
}

/// Result of verifying a signed document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VerifyDocumentResult {
    /// Whether the operation completed without error.
    pub success: bool,

    /// Whether the document's hash and signature are valid.
    pub valid: bool,

    /// The signer's agent ID, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,

    /// Human-readable status message.
    pub message: String,

    /// Error message if verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the document family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_sign_document",
            "Sign arbitrary JSON content to create a cryptographically signed JACS document. \
             Use this for attestation -- when you want to prove that content was signed by \
             this agent. Returns the signed envelope with hash and document ID.",
            schema_map::<SignDocumentParams>(),
        ),
        Tool::new(
            "jacs_verify_document",
            "Verify a signed JACS document given its full JSON string. Checks both the \
             content hash and cryptographic signature. Use this when you have a signed \
             document in memory (e.g. from an approval context or message payload) and \
             need to confirm its integrity and authenticity.",
            schema_map::<VerifyDocumentParams>(),
        ),
    ]
}
