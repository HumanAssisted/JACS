#![cfg(feature = "a2a")]
//! A2A verification result contract tests (Task 001).
//!
//! These tests validate that fixture files in `tests/fixtures/a2a_contract/`
//! deserialize correctly into the Rust `VerificationResult` type, ensuring
//! cross-language schema compatibility per TR-3 of the ATTESTATION_A2A_RESOLUTION PRD.

use jacs::a2a::provenance::{VerificationResult, VerificationStatus};
use std::path::PathBuf;

/// Resolve fixture directory path relative to the crate root.
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/a2a_contract")
}

/// Load and parse a fixture file into a VerificationResult.
fn load_fixture(name: &str) -> VerificationResult {
    let path = fixture_dir().join(name);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path.display(), e));
    serde_json::from_str(&content).unwrap_or_else(|e| {
        panic!(
            "Failed to parse fixture {} as VerificationResult: {}",
            name, e
        )
    })
}

// =========================================================================
// Fixture deserialization tests
// =========================================================================

#[test]
fn test_load_self_signed_verified_fixture() {
    let result = load_fixture("self_signed_verified.json");
    assert!(result.valid, "self-signed verified should be valid");
    assert!(
        matches!(result.status, VerificationStatus::SelfSigned),
        "status should be SelfSigned, got {:?}",
        result.status
    );
    assert!(!result.signer_id.is_empty(), "signer_id must be populated");
    assert!(
        !result.signer_version.is_empty(),
        "signer_version must be populated"
    );
    assert!(
        !result.artifact_type.is_empty(),
        "artifact_type must be populated"
    );
    assert!(!result.timestamp.is_empty(), "timestamp must be populated");
    assert!(result.parent_signatures_valid, "no parents means valid");
    assert!(
        result.parent_verification_results.is_empty(),
        "self-signed should have no parent results"
    );
}

#[test]
fn test_load_foreign_verified_fixture() {
    let result = load_fixture("foreign_verified.json");
    assert!(result.valid, "foreign verified should be valid");
    assert!(
        matches!(result.status, VerificationStatus::Verified),
        "status should be Verified, got {:?}",
        result.status
    );
    assert!(!result.signer_id.is_empty(), "signer_id must be populated");
}

#[test]
fn test_load_foreign_unverified_fixture() {
    let result = load_fixture("foreign_unverified.json");
    assert!(!result.valid, "unverified should not be valid");
    assert!(
        matches!(result.status, VerificationStatus::Unverified { .. }),
        "status should be Unverified, got {:?}",
        result.status
    );
    if let VerificationStatus::Unverified { reason } = &result.status {
        assert!(!reason.is_empty(), "unverified reason must not be empty");
    }
}

#[test]
fn test_load_invalid_signature_fixture() {
    let result = load_fixture("invalid_signature.json");
    assert!(!result.valid, "invalid signature should not be valid");
    assert!(
        matches!(result.status, VerificationStatus::Invalid { .. }),
        "status should be Invalid, got {:?}",
        result.status
    );
    if let VerificationStatus::Invalid { reason } = &result.status {
        assert!(!reason.is_empty(), "invalid reason must not be empty");
    }
}

#[test]
fn test_load_trust_blocked_fixture() {
    let result = load_fixture("trust_blocked.json");
    assert!(!result.valid, "trust-blocked should not be valid");
    assert!(
        result.trust_assessment.is_some(),
        "trust_blocked fixture must include trust assessment"
    );
    let assessment = result.trust_assessment.as_ref().unwrap();
    assert!(
        !assessment.allowed,
        "trust assessment should have allowed=false"
    );
    assert!(
        !assessment.reason.is_empty(),
        "trust assessment reason must not be empty"
    );
}

// =========================================================================
// Fixture camelCase field name validation
// =========================================================================

/// Ensure all fixture files use camelCase field names (no snake_case leakage).
#[test]
fn test_all_fixtures_use_camel_case_keys() {
    let snake_case_keys = [
        "signer_id",
        "signer_version",
        "artifact_type",
        "parent_signatures_valid",
        "parent_verification_results",
        "original_artifact",
        "trust_level",
        "trust_assessment",
        "jacs_registered",
        "agent_id",
        "artifact_id",
    ];

    let fixture_names = [
        "self_signed_verified.json",
        "foreign_verified.json",
        "foreign_unverified.json",
        "invalid_signature.json",
        "trust_blocked.json",
    ];

    for name in &fixture_names {
        let path = fixture_dir().join(name);
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", name, e));

        for key in &snake_case_keys {
            assert!(
                !content.contains(&format!("\"{}\"", key)),
                "Fixture {} contains snake_case key '{}' -- should be camelCase",
                name,
                key
            );
        }
    }
}

/// Verify all fixture files can round-trip through serde.
#[test]
fn test_all_fixtures_round_trip() {
    let fixture_names = [
        "self_signed_verified.json",
        "foreign_verified.json",
        "foreign_unverified.json",
        "invalid_signature.json",
        "trust_blocked.json",
    ];

    for name in &fixture_names {
        let result = load_fixture(name);
        let serialized = serde_json::to_string_pretty(&result)
            .unwrap_or_else(|e| panic!("Failed to re-serialize {}: {}", name, e));
        let _re_deserialized: VerificationResult = serde_json::from_str(&serialized)
            .unwrap_or_else(|e| panic!("Failed to re-deserialize {}: {}", name, e));
    }
}
