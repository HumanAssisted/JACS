#![cfg(feature = "attestation")]

//! Tests for the attestation JSON schema file.
//! These tests validate the schema itself is well-formed and has the correct structure.

use jacs::schema::utils::DEFAULT_SCHEMA_STRINGS;
use serde_json::Value;

const ATTESTATION_SCHEMA: &str = include_str!("../schemas/attestation/v1/attestation.schema.json");

#[test]
fn schema_is_valid_json() {
    let result: Result<Value, _> = serde_json::from_str(ATTESTATION_SCHEMA);
    assert!(
        result.is_ok(),
        "Schema must be valid JSON: {:?}",
        result.err()
    );
}

#[test]
fn schema_has_required_fields() {
    let schema: Value = serde_json::from_str(ATTESTATION_SCHEMA).unwrap();

    // "attestation" must be in the root "required" array
    let root_required = schema["required"]
        .as_array()
        .expect("root required must be an array");
    assert!(
        root_required.iter().any(|v| v == "attestation"),
        "Root required must include 'attestation'"
    );

    // "subject" and "claims" must be required within attestation.properties
    let attestation_required = schema["properties"]["attestation"]["required"]
        .as_array()
        .expect("attestation required must be an array");
    assert!(
        attestation_required.iter().any(|v| v == "subject"),
        "Attestation required must include 'subject'"
    );
    assert!(
        attestation_required.iter().any(|v| v == "claims"),
        "Attestation required must include 'claims'"
    );
}

#[test]
fn schema_subject_type_enum() {
    let schema: Value = serde_json::from_str(ATTESTATION_SCHEMA).unwrap();
    let type_enum =
        schema["properties"]["attestation"]["properties"]["subject"]["properties"]["type"]["enum"]
            .as_array()
            .expect("subject.type.enum must be an array");

    let expected = vec!["agent", "artifact", "workflow", "identity"];
    let actual: Vec<&str> = type_enum.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(actual, expected, "Subject type enum must match exactly");
}

#[test]
fn schema_evidence_kind_enum() {
    let schema: Value = serde_json::from_str(ATTESTATION_SCHEMA).unwrap();
    let kind_enum = schema["properties"]["attestation"]["properties"]["evidence"]["items"]["properties"]["kind"]["enum"]
        .as_array()
        .expect("evidence.kind.enum must be an array");

    let expected = vec!["a2a", "email", "jwt", "tlsnotary", "custom"];
    let actual: Vec<&str> = kind_enum.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(actual, expected, "Evidence kind enum must match exactly");
}

#[test]
fn schema_id_matches_convention() {
    let schema: Value = serde_json::from_str(ATTESTATION_SCHEMA).unwrap();
    assert_eq!(
        schema["$id"].as_str().unwrap(),
        "https://hai.ai/schemas/attestation/v1/attestation.schema.json"
    );
}

#[test]
fn schema_uses_allof_with_header() {
    let schema: Value = serde_json::from_str(ATTESTATION_SCHEMA).unwrap();
    let all_of = schema["allOf"].as_array().expect("allOf must be an array");
    assert!(
        all_of
            .iter()
            .any(|v| v["$ref"] == "https://hai.ai/schemas/header/v1/header.schema.json"),
        "allOf must reference header.schema.json"
    );
}

#[test]
fn schema_digest_set_requires_sha256() {
    let schema: Value = serde_json::from_str(ATTESTATION_SCHEMA).unwrap();

    // Check subject.digests requires sha256
    let subject_digest_required = schema["properties"]["attestation"]["properties"]["subject"]["properties"]["digests"]["required"]
        .as_array()
        .expect("subject.digests.required must be an array");
    assert!(
        subject_digest_required.iter().any(|v| v == "sha256"),
        "Subject digests must require sha256"
    );

    // Check evidence.digests requires sha256
    let evidence_digest_required = schema["properties"]["attestation"]["properties"]["evidence"]["items"]["properties"]["digests"]["required"]
        .as_array()
        .expect("evidence.digests.required must be an array");
    assert!(
        evidence_digest_required.iter().any(|v| v == "sha256"),
        "Evidence digests must require sha256"
    );
}

#[test]
fn attestation_schema_registered_in_defaults() {
    assert!(
        DEFAULT_SCHEMA_STRINGS.contains_key("schemas/attestation/v1/attestation.schema.json"),
        "Attestation schema must be registered in DEFAULT_SCHEMA_STRINGS"
    );
}

#[test]
fn attestation_schema_validator_exists() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    // Validate a minimal valid attestation JSON document
    let minimal_attestation = serde_json::json!({
        "$schema": "https://hai.ai/schemas/attestation/v1/attestation.schema.json",
        "jacsId": "00000000-0000-0000-0000-000000000001",
        "jacsVersion": "00000000-0000-0000-0000-000000000002",
        "jacsVersionDate": "2026-01-01T00:00:00Z",
        "jacsOriginalVersion": "00000000-0000-0000-0000-000000000002",
        "jacsOriginalDate": "2026-01-01T00:00:00Z",
        "jacsType": "attestation",
        "jacsLevel": "raw",
        "attestation": {
            "subject": {
                "type": "agent",
                "id": "test-agent-id",
                "digests": {
                    "sha256": "abc123"
                }
            },
            "claims": [
                {
                    "name": "test",
                    "value": "ok"
                }
            ]
        }
    });
    let result = schema.validate_attestation(&minimal_attestation.to_string());
    assert!(
        result.is_ok(),
        "Minimal attestation should validate: {:?}",
        result.err()
    );
}

// ---- Tests for jacsType and jacsLevel enum constraints ----

/// Helper: build a minimal valid attestation JSON document, allowing overrides
/// for jacsType and jacsLevel.
fn minimal_attestation_doc(jacs_type: &str, jacs_level: &str) -> Value {
    serde_json::json!({
        "$schema": "https://hai.ai/schemas/attestation/v1/attestation.schema.json",
        "jacsId": "00000000-0000-0000-0000-000000000001",
        "jacsVersion": "00000000-0000-0000-0000-000000000002",
        "jacsVersionDate": "2026-01-01T00:00:00Z",
        "jacsOriginalVersion": "00000000-0000-0000-0000-000000000002",
        "jacsOriginalDate": "2026-01-01T00:00:00Z",
        "jacsType": jacs_type,
        "jacsLevel": jacs_level,
        "attestation": {
            "subject": {
                "type": "agent",
                "id": "test-agent-id",
                "digests": {
                    "sha256": "abc123"
                }
            },
            "claims": [
                {
                    "name": "test",
                    "value": "ok"
                }
            ]
        }
    })
}

#[test]
fn schema_accepts_jacs_level_raw() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    let doc = minimal_attestation_doc("attestation", "raw");
    let result = schema.validate_attestation(&doc.to_string());
    assert!(
        result.is_ok(),
        "jacsLevel='raw' should be accepted: {:?}",
        result.err()
    );
}

#[test]
fn schema_accepts_jacs_level_derived() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    let doc = minimal_attestation_doc("attestation-transform-receipt", "derived");
    let result = schema.validate_attestation(&doc.to_string());
    assert!(
        result.is_ok(),
        "jacsLevel='derived' should be accepted: {:?}",
        result.err()
    );
}

#[test]
fn schema_rejects_jacs_level_verified() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    let doc = minimal_attestation_doc("attestation", "verified");
    let result = schema.validate_attestation(&doc.to_string());
    assert!(
        result.is_err(),
        "jacsLevel='verified' must be rejected by attestation schema"
    );
}

#[test]
fn schema_rejects_jacs_level_config() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    let doc = minimal_attestation_doc("attestation", "config");
    let result = schema.validate_attestation(&doc.to_string());
    assert!(
        result.is_err(),
        "jacsLevel='config' must be rejected by attestation schema"
    );
}

#[test]
fn schema_rejects_jacs_level_artifact() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    let doc = minimal_attestation_doc("attestation", "artifact");
    let result = schema.validate_attestation(&doc.to_string());
    assert!(
        result.is_err(),
        "jacsLevel='artifact' must be rejected by attestation schema"
    );
}

#[test]
fn schema_accepts_jacs_type_attestation() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    let doc = minimal_attestation_doc("attestation", "raw");
    let result = schema.validate_attestation(&doc.to_string());
    assert!(
        result.is_ok(),
        "jacsType='attestation' should be accepted: {:?}",
        result.err()
    );
}

#[test]
fn schema_accepts_jacs_type_transform_receipt() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    let doc = minimal_attestation_doc("attestation-transform-receipt", "derived");
    let result = schema.validate_attestation(&doc.to_string());
    assert!(
        result.is_ok(),
        "jacsType='attestation-transform-receipt' should be accepted: {:?}",
        result.err()
    );
}

#[test]
fn schema_rejects_jacs_type_unknown() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    let doc = minimal_attestation_doc("unknown", "raw");
    let result = schema.validate_attestation(&doc.to_string());
    assert!(
        result.is_err(),
        "jacsType='unknown' must be rejected by attestation schema"
    );
}

#[test]
fn schema_rejects_jacs_type_agent() {
    let schema = jacs::schema::Schema::new("v1", "v1", "v1").unwrap();
    let doc = minimal_attestation_doc("agent", "raw");
    let result = schema.validate_attestation(&doc.to_string());
    assert!(
        result.is_err(),
        "jacsType='agent' must be rejected by attestation schema"
    );
}

// ---- Schema structure tests for the enum definitions themselves ----

#[test]
fn schema_jacs_type_has_enum() {
    let schema: Value = serde_json::from_str(ATTESTATION_SCHEMA).unwrap();
    let jacs_type_enum = schema["properties"]["jacsType"]["enum"]
        .as_array()
        .expect("jacsType must have an enum constraint in the attestation schema");

    let actual: Vec<&str> = jacs_type_enum.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        actual,
        vec!["attestation", "attestation-transform-receipt"],
        "jacsType enum must be exactly ['attestation', 'attestation-transform-receipt']"
    );
}

#[test]
fn schema_jacs_level_has_enum() {
    let schema: Value = serde_json::from_str(ATTESTATION_SCHEMA).unwrap();
    let jacs_level_enum = schema["properties"]["jacsLevel"]["enum"]
        .as_array()
        .expect("jacsLevel must have an enum constraint in the attestation schema");

    let actual: Vec<&str> = jacs_level_enum
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        actual,
        vec!["raw", "derived"],
        "jacsLevel enum must be exactly ['raw', 'derived']"
    );
}
