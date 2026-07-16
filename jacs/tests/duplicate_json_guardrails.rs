//! Regression coverage for strict I-JSON ingress at signing and verification
//! boundaries. RFC 8785 requires unique decoded object names; accepting
//! duplicates before canonicalization permits parser-confused artifacts.

use jacs_binding_core::{ErrorKind, SimpleAgentWrapper, verify_document_standalone};

const SIGNED_FIXTURE: &str = include_str!("fixtures/cross-language/pq2025_signed.json");

fn prepend_root_member(document: &str, member: &str) -> String {
    let rest = document
        .strip_prefix('{')
        .expect("committed signed fixture is a JSON object");
    format!("{{{member},{rest}")
}

#[test]
fn standalone_verification_rejects_duplicates_around_protected_fields() {
    let attacks = [
        prepend_root_member(SIGNED_FIXTURE, r#""content":{"decision":"deny"}"#),
        prepend_root_member(SIGNED_FIXTURE, r#""jacsId":"attacker-document""#),
        prepend_root_member(SIGNED_FIXTURE, r#""jacsSha256":"attacker-hash""#),
        prepend_root_member(SIGNED_FIXTURE, r#""jacsSignature":{"agentID":"attacker"}"#),
        SIGNED_FIXTURE.replacen(
            r#""jacsSignature":{"agentID":"#,
            r#""jacsSignature":{"agent\u0049D":"attacker","agentID":"#,
            1,
        ),
        SIGNED_FIXTURE.replacen(
            r#""signingAlgorithm":"pq2025""#,
            r#""signingAlgorithm":"ring-Ed25519","signingAlgorithm":"pq2025""#,
            1,
        ),
    ];

    for attack in attacks {
        let error = verify_document_standalone(&attack, Some("local"), None, None)
            .expect_err("ambiguous signed bytes must be rejected before key resolution");
        assert_eq!(error.kind, ErrorKind::SerializationFailed);
        assert!(
            error.message.contains("duplicate JSON object key"),
            "unexpected verification error: {}",
            error.message
        );
    }
}

#[test]
fn binding_sign_message_rejects_duplicate_payload_keys() {
    let (inner, _) = jacs::simple::SimpleAgent::ephemeral_legacy_ed25519_for_fixtures()
        .expect("create grandfathered Ed25519 fixture");
    let agent = SimpleAgentWrapper::from_agent(inner);
    let error = agent
        .sign_message_json(r#"{"decision":"deny","decision":"allow"}"#)
        .expect_err("ambiguous payload must not be signed");
    assert_eq!(error.kind, ErrorKind::InvalidArgument);
    assert!(error.message.contains("duplicate JSON object key"));
}

#[test]
fn binding_signing_and_verification_reject_unsafe_json_integers() {
    let (inner, _) = jacs::simple::SimpleAgent::ephemeral_legacy_ed25519_for_fixtures()
        .expect("create grandfathered Ed25519 fixture");
    let agent = SimpleAgentWrapper::from_agent(inner);
    let signing_error = agent
        .sign_message_json(r#"{"amount":9007199254740993}"#)
        .expect_err("non-interoperable integer must not be signed");
    assert_eq!(signing_error.kind, ErrorKind::InvalidArgument);
    assert!(signing_error.message.contains("safe integer range"));

    let attacked = prepend_root_member(SIGNED_FIXTURE, r#""amount":9007199254740993"#);
    let verification_error = verify_document_standalone(&attacked, Some("local"), None, None)
        .expect_err("non-interoperable integer must fail before verification");
    assert_eq!(verification_error.kind, ErrorKind::SerializationFailed);
    assert!(verification_error.message.contains("safe integer range"));
}

#[cfg(feature = "a2a")]
#[test]
fn a2a_artifact_signing_rejects_duplicate_payload_keys() {
    let (agent, _) = jacs::simple::SimpleAgent::ephemeral_legacy_ed25519_for_fixtures()
        .expect("create grandfathered Ed25519 fixture");
    let error = jacs::a2a::simple::sign_artifact(
        &agent,
        r#"{"task":"safe","task":"attacker"}"#,
        "artifact",
        None,
    )
    .expect_err("ambiguous A2A artifact must not be signed");
    assert!(error.to_string().contains("duplicate JSON object key"));
}
