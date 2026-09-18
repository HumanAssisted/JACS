//! W3C AI Agent Protocol interop tools.

use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::schema_map;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct W3cOriginParams {
    /// Controlling HTTPS origin for did:wba and discovery URLs.
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct W3cDidResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct W3cJsonDocumentResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<Value>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct W3cWellKnownResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Value>,
    pub count: usize,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct W3cSignRequestParams {
    pub method: String,
    pub url: String,
    pub body: Option<String>,
    pub nonce: Option<String>,
    pub created: Option<String>,
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct W3cRequestProofResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct W3cVerifyRequestParams {
    pub proof_json: String,
    pub did_document_json: String,
    pub body: Option<String>,
    pub max_age_seconds: Option<u64>,
    /// Actual HTTP method to compare against the proof.
    pub method: Option<String>,
    /// Actual HTTP target URI to compare against the proof.
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct W3cVerifyRequestResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<Value>,
    /// SECURITY: whether the DID document used to verify was independently
    /// resolved/trust-pinned by the server. Always `false` here because the
    /// DID document is supplied as an untrusted tool argument — a successful
    /// result proves the proof was signed by the key IN that document
    /// (proof-of-possession), NOT that the signer owns the claimed DID.
    #[serde(default)]
    pub did_document_trusted: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_w3c_export_did",
            "Export this agent's did:wba identifier for W3C AI Agent Protocol interop.",
            schema_map::<W3cOriginParams>(),
        ),
        Tool::new(
            "jacs_w3c_export_did_document",
            "Export this agent's W3C did:wba DID document.",
            schema_map::<W3cOriginParams>(),
        ),
        Tool::new(
            "jacs_w3c_export_agent_description",
            "Export this agent's W3C agent description document.",
            schema_map::<W3cOriginParams>(),
        ),
        Tool::new(
            "jacs_w3c_generate_well_known",
            "Generate W3C well-known discovery documents keyed by path.",
            schema_map::<W3cOriginParams>(),
        ),
        Tool::new(
            "jacs_w3c_sign_request",
            "Create a request-bound DID authentication proof for a concrete HTTP request.",
            schema_map::<W3cSignRequestParams>(),
        ),
        Tool::new(
            "jacs_w3c_verify_request",
            "Verify a request-bound DID authentication proof against a resolved DID document and optional actual request method/URL.",
            schema_map::<W3cVerifyRequestParams>(),
        ),
    ]
}
