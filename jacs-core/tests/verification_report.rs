use jacs_core::sign::DetachedSigner;
use jacs_core::verification::{
    DocumentIntegrityChecks, FieldStatus, REPORT_FIELDS, ReportField, VerificationIntent,
    VerificationPolicy, document_integrity_report,
};
use serde_json::{Value, json};

fn policy() -> VerificationPolicy {
    VerificationPolicy::integrity_only("test-verifier".into(), format!("sha256:{}", "0".repeat(64)))
        .unwrap()
}

#[test]
fn canonical_intent_requires_closed_variants_and_explicit_nulls() {
    let intent = VerificationIntent::document_integrity();
    let encoded = serde_json::to_string(&intent).unwrap();
    assert_eq!(VerificationIntent::from_json(&encoded).unwrap(), intent);
    let mut value: Value = serde_json::from_str(&encoded).unwrap();
    value["expectedIdentity"]["unexpected"] = json!(true);
    assert!(VerificationIntent::from_json(&value.to_string()).is_err());
    value = serde_json::from_str(&encoded).unwrap();
    value["expectedIdentity"]
        .as_object_mut()
        .unwrap()
        .remove("value");
    assert!(VerificationIntent::from_json(&value.to_string()).is_err());
}

#[test]
fn integrity_policy_cannot_be_relabelled_as_authorizing() {
    let mut selected = policy();
    selected.policy_acceptance_enabled = true;
    assert!(selected.validate().is_err());
    selected = policy();
    selected.allowed_algorithms.push("ed25519".into());
    assert!(selected.validate().is_err());
}

#[test]
fn canonical_policy_requires_explicit_nullable_members() {
    let encoded = serde_json::to_value(policy()).unwrap();
    assert!(VerificationPolicy::from_json(&encoded.to_string()).is_ok());
    for member in [
        "trustSourceAnchor",
        "schemaRegistryDigest",
        "defaultCheckpointAgeSeconds",
        "maximumCheckpointAgeSeconds",
        "defaultRevocationHorizonAgeSeconds",
        "maximumRevocationHorizonAgeSeconds",
        "compatibilityCutoff",
    ] {
        let mut omitted = encoded.clone();
        omitted.as_object_mut().unwrap().remove(member);
        assert!(
            VerificationPolicy::from_json(&omitted.to_string()).is_err(),
            "{member}"
        );
    }
}

#[test]
fn report_records_selected_numeric_profile_without_exact_to_compatible_fallback() {
    let signer = jacs_core::ed25519_signer_for_tests();
    let raw = r#"{"ordinary":333333333.33333329}"#;
    let checks = DocumentIntegrityChecks {
        header_valid: false,
        content_hash_valid: false,
        public_key_hash_valid: false,
        referenced_content_valid: None,
    };
    let mut selected = policy();
    let compatible = document_integrity_report(
        raw,
        signer.public_key(),
        "ed25519",
        &VerificationIntent::document_integrity(),
        &selected,
        checks,
    )
    .unwrap();
    assert_eq!(
        compatible.field(ReportField::ParseValid).status,
        FieldStatus::Valid
    );
    assert_eq!(
        compatible.field(ReportField::CanonicalizationProfile).value,
        "jacs-json-rfc8785-binary64-v1"
    );
    selected.numeric_profile = jacs_core::verification::NumericProfile::SafeBinary64V1;
    let exact = document_integrity_report(
        raw,
        signer.public_key(),
        "ed25519",
        &VerificationIntent::document_integrity(),
        &selected,
        checks,
    )
    .unwrap();
    assert_eq!(
        exact.field(ReportField::ParseValid).status,
        FieldStatus::Invalid
    );
    assert!(!exact.policy_accepted());
}

#[test]
fn parse_failure_has_complete_report_and_exact_artifact_digest() {
    let signer = jacs_core::ed25519_signer_for_tests();
    let report = document_integrity_report(
        "not JSON",
        signer.public_key(),
        "ed25519",
        &VerificationIntent::document_integrity(),
        &policy(),
        DocumentIntegrityChecks {
            header_valid: false,
            content_hash_valid: false,
            public_key_hash_valid: false,
            referenced_content_valid: None,
        },
    )
    .unwrap();
    let value = serde_json::to_value(&report).unwrap();
    assert_eq!(value.as_object().unwrap().len(), REPORT_FIELDS.len() + 2);
    assert_eq!(value["profile"], "jacs-verification-report-v1");
    assert_eq!(
        report.field(ReportField::SubmittedArtifactDigest).status,
        FieldStatus::Present
    );
    assert_eq!(
        report.field(ReportField::ParseValid).status,
        FieldStatus::Invalid
    );
    assert_eq!(
        report.field(ReportField::SignatureInputDigest).status,
        FieldStatus::NotComputed
    );
    assert!(!report.policy_accepted());
    assert_eq!(value["policy_accepted"]["value"], false);
    assert_eq!(report.digest().unwrap(), report.digest().unwrap());
}
