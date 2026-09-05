use base64::Engine as _;
use jacs_core::identity::{digest_bytes, digest_json};
use jacs_core::signing::{SigningOperation, SigningPurpose};
use jacs_core::verification::{VerificationIntent, VerificationPolicy};
use jacs_core::verification_registry::*;
use serde_json::json;

fn entry() -> SecurityProfileEntry {
    SecurityProfileEntry {
        profile_id: "jacs-document-v2".into(),
        profile_kind: ProfileKind::BuiltIn,
        operation: SigningOperation::SignDocument,
        purpose: SigningPurpose::Document,
        signature_family_id: SignatureFamilyId::SignatureV2,
        wire_rule_id: WireRuleId::DocumentV2,
        context_rule_id: ContextRuleId::NoneV1,
        allowed_algorithms: vec!["ed25519".into(), "pq2025".into()],
        schema_id: None,
        schema_bundle_digest: None,
        conformance_fixture_digest: format!("sha256:{}", "0".repeat(64)),
    }
}

#[test]
fn registry_catalog_rejects_wrong_pairs_and_missing_nullable_members() {
    let mut row = entry();
    assert!(row.validate().is_ok());
    row.operation = SigningOperation::SignEmail;
    assert!(row.validate().is_err());
    let mut value = serde_json::to_value(entry()).unwrap();
    value.as_object_mut().unwrap().remove("schemaId");
    assert!(serde_json::from_value::<SecurityProfileEntry>(value).is_err());
}

#[test]
fn policy_pinned_registry_requires_complete_matching_fixture_bytes() {
    let mut signer = jacs_core::CoreAgent::ephemeral(jacs_core::SigningAlgorithm::Ed25519).unwrap();
    let raw = signer
        .sign_message(&json!({"result":"ordinary"}))
        .unwrap()
        .to_string();
    let mut row = entry();
    let derived = match_builtin_wire(&raw, &row, None).unwrap().unwrap();
    let expected = ConformanceExpected {
        status: ConformanceStatus::Match,
        derived: Some(derived),
        error_code: None,
    };
    let fixture = ConformanceFixture {
        fixture_id: "document-positive".into(),
        wire_bytes: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes()),
        registry_entry_projection: row.projection().unwrap(),
        intent: VerificationIntent::document_integrity(),
        input_digest: digest_bytes("JACS-CONFORMANCE-FIXTURE-INPUT-V1", raw.as_bytes()),
        expected_result_digest: digest_json(
            "JACS-CONFORMANCE-FIXTURE-RESULT-V1",
            &serde_json::to_value(&expected).unwrap(),
        )
        .unwrap(),
        expected,
    };
    let bundle = ConformanceFixtureBundle {
        wire_rule_id: WireRuleId::DocumentV2,
        signature_family_id: SignatureFamilyId::SignatureV2,
        fixtures: vec![fixture],
    };
    row.conformance_fixture_digest = bundle.digest().unwrap();
    let registry = SecurityProfileRegistry {
        profile: "jacs-security-profile-registry-v1".into(),
        policy_name: "jacs-integrity-only-v1".into(),
        policy_version: 1,
        entries: vec![row],
    };
    let policy =
        VerificationPolicy::integrity_only("fixture-verifier".into(), registry.digest().unwrap())
            .unwrap();
    let intent = VerificationIntent::document_integrity();
    assert!(registry.select(&raw, &intent, &policy, &[], None).is_err());
    let selected = registry
        .select(&raw, &intent, &policy, &[bundle], None)
        .unwrap();
    assert_eq!(selected.entry().operation, SigningOperation::SignDocument);
    assert_eq!(
        selected.derived().operation_context,
        json!({"type":"none_v1"})
    );
}

#[test]
fn schema_aliases_cannot_conflict_across_authenticated_entries() {
    let registry = SchemaRegistry {
        profile: "jacs-schema-registry-v1".into(),
        registry_id: "local-schemas".into(),
        version: 1,
        entries: vec![
            SchemaRegistryEntry {
                schema_id: "urn:example:a".into(),
                schema_bundle_digest: format!("sha256:{}", "0".repeat(64)),
                legacy_signed_schema_aliases: vec!["urn:example:b".into()],
            },
            SchemaRegistryEntry {
                schema_id: "urn:example:b".into(),
                schema_bundle_digest: format!("sha256:{}", "1".repeat(64)),
                legacy_signed_schema_aliases: vec![],
            },
        ],
    };
    assert!(registry.validate().is_err());
}
