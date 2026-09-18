//! Defensive contract tests for explicit-key document integrity verification.

use jacs::agent::document::DocumentTraits;
use jacs::simple::SimpleAgent;
use jacs::verification::{ExpectedSigner, NonSigningVerifier};
use serde_json::json;

#[test]
fn explicit_verifier_uses_public_key_without_a_signing_identity() {
    let (signer, info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let signed = signer
        .sign_message(&json!({"message": "public verification"}))
        .unwrap();
    let public_key = signer.get_public_key().unwrap();
    drop(signer);

    let report = NonSigningVerifier::new()
        .unwrap()
        .verify_with_key(
            &signed.raw,
            &public_key,
            "ed25519",
            Some(ExpectedSigner {
                agent_id: &info.agent_id,
                agent_version: &info.version,
            }),
        )
        .unwrap();

    assert!(report.integrity_valid, "{:?}", report.errors);
    assert!(report.signature_valid);
    assert_eq!(report.signer_claims_match, Some(true));
    assert!(!report.identity_bound);
    assert_eq!(report.verified_algorithm.as_deref(), Some("ed25519"));
    assert!(report.canonical_key_id.starts_with("jacs-key-v1:ed25519:"));
    assert_eq!(
        report.verified_fields.as_ref().unwrap()["content"]["message"],
        "public verification"
    );
    assert!(
        report
            .verified_fields
            .as_ref()
            .unwrap()
            .get("jacsSha256")
            .is_none()
    );
}

#[test]
fn incorrect_expected_signer_claims_do_not_release_fields() {
    let (signer, _) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let (_, other) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let signed = signer
        .sign_message(&json!({"message": "claim comparison"}))
        .unwrap();
    let report = NonSigningVerifier::new()
        .unwrap()
        .verify_with_key(
            &signed.raw,
            &signer.get_public_key().unwrap(),
            "ed25519",
            Some(ExpectedSigner {
                agent_id: &other.agent_id,
                agent_version: &other.version,
            }),
        )
        .unwrap();
    assert!(report.signature_valid);
    assert_eq!(report.signer_claims_match, Some(false));
    assert!(!report.integrity_valid);
    assert!(!report.identity_bound);
    assert!(report.verified_fields.is_none());
}

#[test]
fn wrong_key_and_malformed_input_never_release_fields() {
    let (signer, _) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let (other, _) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let signed = signer
        .sign_message(&json!({"message": "verify first"}))
        .unwrap();
    let verifier = NonSigningVerifier::new().unwrap();
    for input in [&signed.raw, "not JSON"] {
        let report = verifier
            .verify_with_key(input, &other.get_public_key().unwrap(), "ed25519", None)
            .unwrap();
        assert!(!report.integrity_valid);
        assert!(report.verified_fields.is_none());
        assert!(!report.errors.is_empty());
        assert!(report.input_sha256.starts_with("sha256:"));
    }
}

#[test]
fn mismatched_explicit_algorithm_is_rejected() {
    let (signer, _) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let signed = signer
        .sign_message(&json!({"message": "algorithm expectation"}))
        .unwrap();
    assert!(
        NonSigningVerifier::new()
            .unwrap()
            .verify_with_key(
                &signed.raw,
                &signer.get_public_key().unwrap(),
                "pq2025",
                None,
            )
            .is_err()
    );
}

#[test]
fn native_verification_checks_expected_algorithm_before_dispatch() {
    let (signer, _) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let signed = signer
        .sign_message(&json!({"message": "native algorithm expectation"}))
        .unwrap();
    let value = serde_json::from_str(&signed.raw).unwrap();
    let mut verifier = jacs::agent::Agent::ephemeral("ed25519").unwrap();
    let result = verifier.verify_document_signature_value(
        &value,
        None,
        None,
        Some(signer.get_public_key().unwrap()),
        Some("pq2025".to_string()),
    );
    assert!(result.unwrap_err().to_string().contains("does not match"));
}

#[test]
fn full_report_separates_integrity_from_authorization_and_exact_bytes() {
    use jacs::verification::{ReportField, VerificationIntent, VerificationPolicy};
    let (signer, _) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let signed = signer
        .sign_message(&json!({"message": "complete integrity report"}))
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&signed.raw).unwrap();
    let reformatted = serde_json::to_string_pretty(&value).unwrap();
    let policy = VerificationPolicy::integrity_only(
        "public-verifier".into(),
        format!("sha256:{}", "0".repeat(64)),
    )
    .unwrap();
    let verifier = NonSigningVerifier::new().unwrap();
    let public_key = signer.get_public_key().unwrap();
    let first = verifier
        .verify_for(
            &signed.raw,
            &public_key,
            "ed25519",
            &VerificationIntent::document_integrity(),
            &policy,
        )
        .unwrap();
    let second = verifier
        .verify_for(
            &reformatted,
            &public_key,
            "ed25519",
            &VerificationIntent::document_integrity(),
            &policy,
        )
        .unwrap();
    assert_eq!(
        first
            .field(ReportField::LegacyIntegrityValidOrNotApplicable)
            .value,
        true
    );
    assert_eq!(first.field(ReportField::IdentityBound).value, false);
    assert!(!first.policy_accepted());
    assert_ne!(
        first.field(ReportField::SubmittedArtifactDigest).value,
        second.field(ReportField::SubmittedArtifactDigest).value
    );
    assert_eq!(
        first
            .field(ReportField::CanonicalEnvelopeDigestOrNotApplicable)
            .value,
        second
            .field(ReportField::CanonicalEnvelopeDigestOrNotApplicable)
            .value
    );
}

#[test]
fn response_report_binds_exact_context_without_identity_authorization() {
    use jacs::response_context::{RequestBinding, ResponseData, ResponseOperation};
    use jacs::verification::{
        ContextExpectation, ExactExpectation, ReportField, VerificationIntent, VerificationPolicy,
    };
    let (signer, _) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
    let data = ResponseData::DirectResponse {
        request_id: "request-1".into(),
        request_binding: RequestBinding::RequestNonce("nonce-1".into()),
        audience: "recipient-1".into(),
        response_type: "result".into(),
        payload: json!({"ok":true}),
    };
    let envelope = signer
        .sign_response_with_context(&data, ResponseOperation::SignBoundResponse)
        .unwrap();
    let mut intent = VerificationIntent::document_integrity();
    intent.operation = jacs_core::signing::SigningOperation::SignBoundResponse;
    intent.signature_profile = "jacs-response-v2/direct-response".into();
    intent.audience = ExactExpectation::exact("recipient-1");
    intent.context = ContextExpectation::ExactFields {
        value: json!({"type":"response_context_v2","value":data.operation_context().unwrap()}),
    };
    let policy = VerificationPolicy::integrity_only(
        "public-verifier".into(),
        format!("sha256:{}", "0".repeat(64)),
    )
    .unwrap();
    let report = NonSigningVerifier::new()
        .unwrap()
        .verify_for(
            &envelope.to_string(),
            &signer.get_public_key().unwrap(),
            "ed25519",
            &intent,
            &policy,
        )
        .unwrap();
    assert_eq!(report.field(ReportField::SignatureValid).value, true);
    assert_eq!(report.field(ReportField::OperationProfileBound).value, true);
    assert_eq!(
        report
            .field(ReportField::AudienceContextBoundOrNotApplicable)
            .value,
        true
    );
    assert!(!report.policy_accepted());
}
