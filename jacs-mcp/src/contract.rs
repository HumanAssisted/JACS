//! Closed tool contract, shared by discovery and its checked-in snapshot.

use rmcp::model::{Tool, ToolAnnotations};
use serde_json::{Value, json};
use std::sync::Arc;

pub const TOOL_NAMES: &[&str] = &[
    "jacs_create_agent",
    "jacs_sign_document",
    "jacs_verify_document",
    "jacs_rotate_keys",
    "jacs_reencrypt_key",
    "jacs_import_encrypted_agent",
    "jacs_export_encrypted_agent",
];

pub fn tools() -> Vec<Tool> {
    let text = json!({"type":"string", "maxLength": crate::vault::MAX_MATERIAL_BYTES});
    let empty = json!({"type":"object", "properties":{}, "additionalProperties":false});
    let specs = [
        (
            TOOL_NAMES[0],
            "Create a new ML-DSA-87 identity in the configured empty encrypted vault.",
            empty.clone(),
            false,
            false,
        ),
        (
            TOOL_NAMES[1],
            "Sign a JSON object with the configured identity, preserving its algorithm.",
            json!({"type":"object", "properties":{"document":text}, "required":["document"], "additionalProperties":false}),
            true,
            false,
        ),
        (
            TOOL_NAMES[2],
            "Verify a signed JSON document against an explicitly supplied public key and algorithm. This verifies cryptography, not registry trust.",
            json!({"type":"object", "properties":{"document":text,"public_key":{"type":"string","maxLength":16384,"description":"Canonical standard-base64 raw public key, independently pinned by the caller"},"algorithm":{"type":"string","enum":["pq2025","ed25519","es256"]}}, "required":["document","public_key","algorithm"], "additionalProperties":false}),
            true,
            false,
        ),
        (
            TOOL_NAMES[3],
            "Rotate to a new ML-DSA-87 key with an old-key-authorized transition proof, atomically replacing the configured vault.",
            empty.clone(),
            false,
            true,
        ),
        (
            TOOL_NAMES[4],
            "Re-encrypt the configured vault using the new password supplied by the host at startup. Passwords are never tool arguments.",
            empty.clone(),
            false,
            true,
        ),
        (
            TOOL_NAMES[5],
            "Authenticate and import encrypted AgentMaterial into the configured empty vault; plaintext keys and overwrites are rejected.",
            json!({"type":"object", "properties":{"material_json":text}, "required":["material_json"], "additionalProperties":false}),
            false,
            false,
        ),
        (
            TOOL_NAMES[6],
            "Export authenticated encrypted AgentMaterial from the configured vault. Never exports plaintext key bytes.",
            empty,
            true,
            false,
        ),
    ];
    specs
        .into_iter()
        .map(|(name, description, schema, read_only, destructive)| {
            let mut tool = Tool::default();
            tool.name = name.into();
            tool.description = Some(description.into());
            tool.input_schema = Arc::new(schema.as_object().expect("object schema").clone());
            tool.annotations = Some(
                ToolAnnotations::new()
                    .read_only(read_only)
                    .destructive(destructive)
                    .open_world(false),
            );
            tool
        })
        .collect()
}

pub fn canonical_contract_snapshot() -> Value {
    json!({
        "server": {"name":"jacs-mcp", "version":env!("CARGO_PKG_VERSION"), "transport":"stdio"},
        "default_profile":"verify-only",
        "profiles": {"verify-only":["jacs_verify_document"], "local-sign":TOOL_NAMES},
        "tools": tools(),
    })
}
