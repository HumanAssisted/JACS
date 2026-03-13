//! Attestation tools: create, verify, lift, export DSSE.

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

/// Parameters for creating an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttestCreateParams {
    /// JSON string with subject, claims, and optional evidence/derivation/policyContext.
    #[schemars(
        description = "JSON string containing attestation parameters: { subject: { type, id, digests }, claims: [{ name, value, confidence?, assuranceLevel? }], evidence?: [...], derivation?: {...}, policyContext?: {...} }"
    )]
    pub params_json: String,
}

/// Parameters for verifying an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttestVerifyParams {
    /// The document key in "jacsId:jacsVersion" format.
    #[schemars(description = "Document key in 'jacsId:jacsVersion' format")]
    pub document_key: String,

    /// Whether to perform full verification (including evidence and chain).
    #[serde(default)]
    #[schemars(description = "Set to true for full-tier verification (evidence + chain checks)")]
    pub full: bool,
}

/// Parameters for lifting a signed document to an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttestLiftParams {
    /// The signed document JSON string.
    #[schemars(description = "JSON string of the existing signed JACS document to lift")]
    pub signed_doc_json: String,

    /// Claims JSON string (array of claim objects).
    #[schemars(
        description = "JSON array of claim objects: [{ name, value, confidence?, assuranceLevel? }]"
    )]
    pub claims_json: String,
}

/// Parameters for exporting an attestation as a DSSE envelope.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttestExportDsseParams {
    /// The signed attestation document JSON string.
    #[schemars(description = "JSON string of the signed attestation document to export as DSSE")]
    pub attestation_json: String,
}

// =============================================================================
// Tool Definitions
// =============================================================================

/// Return the `Tool` definitions for the attestation family.
pub fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "jacs_attest_create",
            "Create a signed attestation document. Provide a JSON string with: subject \
             (type, id, digests), claims (name, value, confidence, assuranceLevel), and \
             optional evidence, derivation, and policyContext. Requires the attestation \
             feature.",
            schema_map::<AttestCreateParams>(),
        ),
        Tool::new(
            "jacs_attest_verify",
            "Verify an attestation document. Provide a document_key in 'jacsId:jacsVersion' \
             format. Set full=true for full-tier verification including evidence and \
             derivation chain checks. Requires the attestation feature.",
            schema_map::<AttestVerifyParams>(),
        ),
        Tool::new(
            "jacs_attest_lift",
            "Lift an existing signed JACS document into an attestation. Provide the signed \
             document JSON and a JSON array of claims to attach. Requires the attestation \
             feature.",
            schema_map::<AttestLiftParams>(),
        ),
        Tool::new(
            "jacs_attest_export_dsse",
            "Export an attestation as a DSSE envelope for in-toto/SLSA compatibility. \
             Provide the signed attestation document JSON. Returns a DSSE envelope with \
             payloadType, payload, and signatures. Requires the attestation feature.",
            schema_map::<AttestExportDsseParams>(),
        ),
    ]
}
