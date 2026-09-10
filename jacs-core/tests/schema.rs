//! Wave 2 / Task 006: jacs-core embedded schemas + portable resolver tests.

use jacs_core::CoreError;
use jacs_core::schema::{
    CONFIG_SCHEMA_STRING, DEFAULT_SCHEMA_STRINGS, EmbeddedSchemaResolver, SCHEMA_SHORT_NAME,
    V2_SCHEMA_ID,
};

const EXPECTED_KEYS: &[&str] = &[
    "schemas/agent/v1/agent.schema.json",
    "schemas/header/v1/header.schema.json",
    "schemas/components/signature/v1/signature.schema.json",
    "schemas/components/files/v1/files.schema.json",
    "schemas/components/agreement/v1/agreement.schema.json",
    "schemas/agreement/v2/agreement.schema.json",
    "schemas/attestation/v1/attestation.schema.json",
    "schemas/conflict/v1/conflict.schema.json",
    "schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json",
];

#[test]
fn default_schema_strings_present() {
    assert_eq!(
        DEFAULT_SCHEMA_STRINGS.len(),
        EXPECTED_KEYS.len(),
        "DEFAULT_SCHEMA_STRINGS cardinality drifted",
    );
    for key in EXPECTED_KEYS {
        let body = DEFAULT_SCHEMA_STRINGS
            .get(key)
            .copied()
            .unwrap_or_else(|| panic!("missing embedded schema for {key}"));
        assert!(!body.is_empty(), "schema {key} body was empty");
        let parsed: serde_json::Value = serde_json::from_str(body)
            .unwrap_or_else(|e| panic!("schema {key} did not parse as JSON: {e}"));
        assert!(parsed.is_object(), "schema {key} was not a JSON object");
    }
}

#[test]
fn config_schema_string_parses_as_json_object() {
    let v: serde_json::Value =
        serde_json::from_str(CONFIG_SCHEMA_STRING).expect("config schema parses");
    assert!(v.is_object());
}

#[test]
fn schema_short_name_returns_expected_slot_for_known_id() {
    // Keep the portable schema short-name table aligned with the native
    // consolidated schema set from v0.10.2.
    let cases: &[(&str, &str)] = &[
        ("https://hai.ai/schemas/agent/v1/agent.schema.json", "agent"),
        (
            "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json",
            "agreement",
        ),
        (V2_SCHEMA_ID, "agreement"),
        (
            "https://hai.ai/schemas/header/v1/header.schema.json",
            "header",
        ),
        (
            "https://hai.ai/schemas/attestation/v1/attestation.schema.json",
            "attestation",
        ),
        (
            "https://hai.ai/schemas/conflict/v1/conflict.schema.json",
            "conflict",
        ),
        ("document", "document"),
    ];
    for (id, expected) in cases {
        let got = SCHEMA_SHORT_NAME
            .get(id)
            .unwrap_or_else(|| panic!("SCHEMA_SHORT_NAME missing $id {id}"));
        assert_eq!(*got, *expected, "wrong short name for {id}");
    }
}

#[test]
fn v2_schema_id_constant_matches_embedded_schema() {
    let schema = EmbeddedSchemaResolver::resolve("schemas/agreement/v2/agreement.schema.json")
        .expect("agreement v2 schema resolves");
    assert_eq!(
        schema.get("$id").and_then(serde_json::Value::as_str),
        Some(V2_SCHEMA_ID)
    );
}

#[test]
fn embedded_resolver_returns_known_schema() {
    // EmbeddedSchemaResolver::resolve accepts both the bare key and the
    // leading-slash variant that jsonschema::Uri::path() would emit.
    let v = EmbeddedSchemaResolver::resolve("schemas/agent/v1/agent.schema.json")
        .expect("known schema resolves");
    assert!(v.is_object());

    let v_slash = EmbeddedSchemaResolver::resolve("/schemas/agent/v1/agent.schema.json")
        .expect("leading-slash variant resolves");
    assert_eq!(v, v_slash);
}

#[test]
fn embedded_resolver_unknown_ref_errors() {
    let err =
        EmbeddedSchemaResolver::resolve("/schemas/does-not-exist/v1/does-not-exist.schema.json")
            .expect_err("unknown ref errors");
    assert!(matches!(err, CoreError::SchemaInvalid(_)));
    let msg = err.to_string();
    assert!(
        msg.contains("does-not-exist"),
        "error message includes the missing path: {msg}"
    );
}

#[test]
fn embedded_resolver_implements_retrieve_trait() {
    // This exercises the path through `jsonschema::Retrieve` — the same
    // shape used by validator construction. Build a fake URI by going
    // through the jsonschema::Uri parser.
    use jsonschema::Retrieve;
    let resolver = EmbeddedSchemaResolver::new();
    // jsonschema::Uri::from_str via the referencing crate would normally
    // be how a URI is constructed; the simplest portable path is to use
    // referencing::Uri directly via the re-export.
    let uri: jsonschema::Uri<String> = "https://hai.ai/schemas/agent/v1/agent.schema.json"
        .parse()
        .expect("uri parses");
    let v = resolver
        .retrieve(&uri)
        .expect("retrieve resolves known schema");
    assert!(v.is_object());
}

// =========================================================================
// P2 Task 001 — the native algorithm schema wall.
//
// The `signingAlgorithm` enum is the crypto-level guard that keeps
// ecosystem algorithms (ES256) out of native `jacsSignature` objects. It
// must stay exactly `ring-Ed25519 | pq2025`, and it must stay OPTIONAL so
// legacy documents that omit it still validate.
// =========================================================================

#[test]
fn signature_schema_enum_stays_ring_ed25519_and_pq2025() {
    let body = DEFAULT_SCHEMA_STRINGS
        .get("schemas/components/signature/v1/signature.schema.json")
        .copied()
        .expect("signature schema embedded");
    let schema: serde_json::Value = serde_json::from_str(body).expect("schema parses");

    let enum_vals: Vec<&str> = schema["properties"]["signingAlgorithm"]["enum"]
        .as_array()
        .expect("signingAlgorithm must have an enum")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        enum_vals,
        vec!["ring-Ed25519", "pq2025"],
        "native signingAlgorithm enum is the PQ wall — it must stay exactly \
         ring-Ed25519|pq2025; ecosystem algorithms (ES256) are never valid here"
    );

    let required: Vec<&str> = schema["required"]
        .as_array()
        .expect("required array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        !required.contains(&"signingAlgorithm"),
        "signingAlgorithm stays OPTIONAL so legacy documents without it still validate"
    );

    assert_eq!(
        schema["additionalProperties"],
        serde_json::json!(false),
        "signature schema must keep additionalProperties:false"
    );
}

// =========================================================================
// P2 Task 003 — compatibility-key-binding schema tests (portable copy).
//
// The jacs-core copy is the one the runtime validator is actually built
// from (the jacs crate re-exports these embedded strings), so the Task
// 003 schema contract is pinned here: valid bindings validate, scope is
// required and closed, content scopes are schema-valid (grant is a
// policy question), and the native `jacsSignature` is REQUIRED. Both supported
// native roots (`pq2025` and explicitly selected `ring-Ed25519`) may sign
// bindings until rotation; ES256 never can.
// =========================================================================

use serde_json::json;

fn compat_binding_validator() -> jsonschema::Validator {
    let body = DEFAULT_SCHEMA_STRINGS
        .get("schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json")
        .copied()
        .expect("binding schema embedded");
    let schema: serde_json::Value = serde_json::from_str(body).expect("binding schema parses");
    jsonschema::Validator::options()
        .with_draft(jsonschema::Draft::Draft7)
        .with_retriever(EmbeddedSchemaResolver::new())
        .build(&schema)
        .expect("binding schema compiles")
}

fn valid_binding_document() -> serde_json::Value {
    json!({
        "$schema": "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json",
        "jacsId": "8c8a1b90-0000-4000-8000-000000000001",
        "jacsVersion": "8c8a1b90-0000-4000-8000-000000000002",
        "jacsVersionDate": "2026-06-28T00:00:00Z",
        "jacsOriginalVersion": "8c8a1b90-0000-4000-8000-000000000002",
        "jacsOriginalDate": "2026-06-28T00:00:00Z",
        "jacsType": "compatibilityKeyBinding",
        "jacsLevel": "config",
        "compatibilityKeyBinding": {
            "agentId": "8c8a1b90-0000-4000-8000-000000000003",
            "rootKey": { "algorithm": "pq2025", "kid": "roothash" },
            "compatibilityKey": {
                "algorithm": "ES256",
                "kid": "thumbprintthumbprintthumbprintthumbprintxyz",
                "publicJwk": { "kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ" }
            },
            "scope": ["jwks"],
            "issuedAt": "2026-06-28T00:00:00Z",
            "expiresAt": null
        },
        "jacsSignature": {
            "agentID": "8c8a1b90-0000-4000-8000-000000000003",
            "agentVersion": "8c8a1b90-0000-4000-8000-000000000004",
            "date": "2026-06-28T00:00:00Z",
            "iat": 1782604800,
            "jti": "binding-fixture-nonce-0001",
            "signature": "c2lnbmF0dXJl",
            "publicKeyHash": "roothash",
            "signingAlgorithm": "pq2025",
            "fields": ["$schema", "compatibilityKeyBinding", "jacsId"]
        }
    })
}

#[test]
fn compatibility_key_binding_schema_accepts_valid_document() {
    let validator = compat_binding_validator();
    assert!(
        validator.is_valid(&valid_binding_document()),
        "a valid signed binding must validate"
    );

    // The type discriminator is pinned: any other jacsType is rejected.
    let mut wrong_type = valid_binding_document();
    wrong_type["jacsType"] = json!("agent");
    assert!(
        !validator.is_valid(&wrong_type),
        "a wrong jacsType must fail the binding schema"
    );
}

#[test]
fn compatibility_key_binding_schema_rejects_missing_scope() {
    let validator = compat_binding_validator();

    let mut missing = valid_binding_document();
    missing["compatibilityKeyBinding"]
        .as_object_mut()
        .unwrap()
        .remove("scope");
    assert!(!validator.is_valid(&missing), "scope is required");

    let mut empty = valid_binding_document();
    empty["compatibilityKeyBinding"]["scope"] = json!([]);
    assert!(!validator.is_valid(&empty), "scope must be non-empty");

    let mut unknown = valid_binding_document();
    unknown["compatibilityKeyBinding"]["scope"] = json!(["native-signing"]);
    assert!(
        !validator.is_valid(&unknown),
        "unknown scopes are rejected (closed enum)"
    );
}

#[test]
fn compatibility_key_binding_schema_requires_signature() {
    let validator = compat_binding_validator();

    // No jacsSignature at all: the trust bridge is unsigned — reject.
    let mut unsigned = valid_binding_document();
    unsigned.as_object_mut().unwrap().remove("jacsSignature");
    assert!(
        !validator.is_valid(&unsigned),
        "a binding without the native jacsSignature must fail schema validation"
    );

    // ES256 is never a NATIVE signing algorithm — not even on the binding.
    let mut es256 = valid_binding_document();
    es256["jacsSignature"]["signingAlgorithm"] = json!("ES256");
    assert!(
        !validator.is_valid(&es256),
        "ES256 must be rejected as the binding's native signingAlgorithm"
    );

    // pq2025 and explicitly selected ring-Ed25519 native roots both validate.
    let mut ed25519 = valid_binding_document();
    ed25519["jacsSignature"]["signingAlgorithm"] = json!("ring-Ed25519");
    ed25519["compatibilityKeyBinding"]["rootKey"]["algorithm"] = json!("ring-Ed25519");
    assert!(
        validator.is_valid(&ed25519),
        "supported Ed25519 native roots may sign bindings until rotation"
    );
}

#[test]
fn compatibility_key_binding_schema_accepts_ap2_and_agreement_vc_scopes() {
    let validator = compat_binding_validator();
    let mut doc = valid_binding_document();
    doc["compatibilityKeyBinding"]["scope"] = json!(["ap2-mandate", "agreement-vc"]);
    assert!(
        validator.is_valid(&doc),
        "content scopes are schema-valid (the grant is a policy question)"
    );
}
