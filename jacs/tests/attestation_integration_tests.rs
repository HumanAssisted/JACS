#![cfg(feature = "attestation-tests")]

//! Integration tests for the attestation feature.
//!
//! These tests exercise the full attestation pipeline end-to-end:
//! create, verify (both tiers), adapters, migration, derivation chains,
//! schema validation, tampering detection, and DSSE export.

use jacs::agent::Agent;
use jacs::agent::document::DocumentTraits;
use jacs::attestation::AttestationTraits;
use jacs::attestation::adapters::EvidenceAdapter;
use jacs::attestation::dsse::{
    DSSE_PAYLOAD_TYPE, INTOTO_STATEMENT_TYPE, JACS_PREDICATE_TYPE, export_dsse,
};
use jacs::attestation::types::*;
use jacs::simple::SimpleAgent;
use serde_json::{Value, json};
use std::collections::HashMap;

fn ephemeral_agent() -> Agent {
    let algo = "ring-Ed25519";
    let mut agent = Agent::ephemeral(algo).expect("create ephemeral agent");
    let agent_json = jacs::create_minimal_blank_agent("ai".to_string(), None, None, None)
        .expect("create agent template");
    agent
        .create_agent_and_load(&agent_json, true, Some(algo))
        .expect("load ephemeral agent");
    agent
}

fn ephemeral_simple_agent() -> SimpleAgent {
    let (agent, _info) = SimpleAgent::ephemeral(Some("ring-Ed25519")).unwrap();
    agent
}

fn test_subject() -> AttestationSubject {
    AttestationSubject {
        subject_type: SubjectType::Artifact,
        id: "test-artifact-001".into(),
        digests: DigestSet {
            sha256: "abc123def456".into(),
            sha512: None,
            additional: HashMap::new(),
        },
    }
}

fn test_claim() -> Claim {
    Claim {
        name: "reviewed".into(),
        value: json!(true),
        confidence: Some(0.95),
        assurance_level: Some(AssuranceLevel::Verified),
        issuer: None,
        issued_at: None,
    }
}

// ---------------------------------------------------------------------------
// 1. Round-trip create/verify
// ---------------------------------------------------------------------------

#[test]
fn attestation_create_verify_round_trip() {
    let agent = ephemeral_simple_agent();
    let subject = test_subject();
    let signed =
        jacs::attestation::simple::create(&agent, &subject, &[test_claim()], &[], None, None)
            .expect("create attestation");

    let doc: Value = serde_json::from_str(&signed.raw).unwrap();
    let key = format!(
        "{}:{}",
        doc["jacsId"].as_str().unwrap(),
        doc["jacsVersion"].as_str().unwrap()
    );

    let result = jacs::attestation::simple::verify(&agent, &key).expect("verify attestation");
    assert!(
        result.valid,
        "round-trip attestation should verify: {:?}",
        result.errors
    );
    assert!(result.crypto.signature_valid);
    assert!(result.crypto.hash_valid);
}

// ---------------------------------------------------------------------------
// 2. A2A evidence adapter integration
// ---------------------------------------------------------------------------

#[test]
fn attestation_create_with_a2a_evidence_verify() {
    let mut agent = ephemeral_agent();
    let adapter = jacs::attestation::adapters::a2a::A2aAdapter;

    let a2a_msg = json!({"jsonrpc": "2.0", "method": "test", "id": 1});
    let raw = serde_json::to_vec(&a2a_msg).unwrap();
    let (claims, evidence) = adapter.normalize(&raw, &json!({})).unwrap();

    let subject = test_subject();
    let all_claims = vec![test_claim(), claims[0].clone()];
    let doc = agent
        .create_attestation(&subject, &all_claims, &[evidence], None, None)
        .expect("create with A2A evidence");

    let key = format!("{}:{}", doc.id, doc.version);
    let result = agent
        .verify_attestation_full_impl(&key)
        .expect("full verify");
    assert!(
        result.valid,
        "A2A evidence attestation should verify: {:?}",
        result.errors
    );
    assert!(!result.evidence.is_empty(), "should have evidence results");
}

// ---------------------------------------------------------------------------
// 3. Email evidence adapter integration
// ---------------------------------------------------------------------------

#[test]
fn attestation_create_with_email_evidence_verify() {
    let mut agent = ephemeral_agent();
    let adapter = jacs::attestation::adapters::email::EmailAdapter;

    let email_data = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody";
    let (claims, evidence) = adapter.normalize(email_data, &json!({})).unwrap();

    let subject = test_subject();
    let all_claims = vec![test_claim(), claims[0].clone()];
    let doc = agent
        .create_attestation(&subject, &all_claims, &[evidence], None, None)
        .expect("create with email evidence");

    let key = format!("{}:{}", doc.id, doc.version);
    let result = agent
        .verify_attestation_full_impl(&key)
        .expect("full verify");
    assert!(
        result.valid,
        "email evidence attestation should verify: {:?}",
        result.errors
    );
}

// ---------------------------------------------------------------------------
// 4. Lift existing document to attestation
// ---------------------------------------------------------------------------

#[test]
fn attestation_lift_existing_document_verify() {
    let agent = ephemeral_simple_agent();

    // Sign a regular message
    let msg = json!({"title": "Original Document", "content": "Test content"});
    let signed_msg = agent.sign_message(&msg).unwrap();
    let original_id = signed_msg.document_id.clone();

    // Lift to attestation
    let attestation = jacs::attestation::simple::lift(&agent, &signed_msg.raw, &[test_claim()])
        .expect("lift to attestation");

    let att_doc: Value = serde_json::from_str(&attestation.raw).unwrap();

    // Subject should reference the original document
    assert_eq!(
        att_doc["attestation"]["subject"]["id"].as_str().unwrap(),
        original_id,
        "subject ID should match original document"
    );

    // Verify the lifted attestation
    let att_key = format!(
        "{}:{}",
        att_doc["jacsId"].as_str().unwrap(),
        att_doc["jacsVersion"].as_str().unwrap()
    );
    let result = jacs::attestation::simple::verify(&agent, &att_key).expect("verify lifted");
    assert!(
        result.valid,
        "lifted attestation should verify: {:?}",
        result.errors
    );
}

// ---------------------------------------------------------------------------
// 5. Schema validation rejects invalid documents
// ---------------------------------------------------------------------------

#[test]
fn attestation_schema_validation_rejects_invalid() {
    let mut agent = ephemeral_agent();

    // Try to create attestation with empty claims (should fail schema validation)
    let subject = test_subject();
    let result = agent.create_attestation(&subject, &[], &[], None, None);
    assert!(
        result.is_err(),
        "empty claims should be rejected by schema validation"
    );
}

// ---------------------------------------------------------------------------
// 6. Tampered body detection
// ---------------------------------------------------------------------------

#[test]
fn attestation_tampered_body_verify_fails() {
    let mut agent = ephemeral_agent();
    let subject = test_subject();
    let doc = agent
        .create_attestation(&subject, &[test_claim()], &[], None, None)
        .expect("create attestation");

    // Tamper with the attestation body
    let mut tampered = doc.value.clone();
    tampered["attestation"]["claims"][0]["value"] = json!(false);

    // Store the tampered document
    let tampered_doc = jacs::agent::document::JACSDocument {
        id: doc.id.clone(),
        version: doc.version.clone(),
        value: tampered,
        jacs_type: doc.jacs_type.clone(),
    };
    agent.store_jacs_document(&tampered_doc.value).unwrap();

    let key = format!("{}:{}", doc.id, doc.version);
    let result = agent
        .verify_attestation_local_impl(&key)
        .expect("verify should not error");
    assert!(!result.valid, "tampered body should fail verification");
}

// ---------------------------------------------------------------------------
// 7. Tampered signature detection
// ---------------------------------------------------------------------------

#[test]
fn attestation_tampered_signature_verify_fails() {
    let mut agent = ephemeral_agent();
    let subject = test_subject();
    let doc = agent
        .create_attestation(&subject, &[test_claim()], &[], None, None)
        .expect("create attestation");

    // Tamper with the signature
    let mut tampered = doc.value.clone();
    if let Some(sig) = tampered.get_mut("jacsSignature") {
        sig["signature"] = json!("TAMPERED_SIGNATURE_VALUE");
    }

    let tampered_doc = jacs::agent::document::JACSDocument {
        id: doc.id.clone(),
        version: doc.version.clone(),
        value: tampered,
        jacs_type: doc.jacs_type.clone(),
    };
    agent.store_jacs_document(&tampered_doc.value).unwrap();

    let key = format!("{}:{}", doc.id, doc.version);
    let result = agent
        .verify_attestation_local_impl(&key)
        .expect("verify should not error");
    assert!(!result.valid, "tampered signature should fail verification");
}

// ---------------------------------------------------------------------------
// 8. Multiple evidence items
// ---------------------------------------------------------------------------

#[test]
fn attestation_multiple_evidence_items() {
    let mut agent = ephemeral_agent();
    let a2a_adapter = jacs::attestation::adapters::a2a::A2aAdapter;
    let email_adapter = jacs::attestation::adapters::email::EmailAdapter;

    let (_, ev1) = a2a_adapter.normalize(b"a2a msg 1", &json!({})).unwrap();
    let (_, ev2) = email_adapter.normalize(b"email data", &json!({})).unwrap();
    let (_, ev3) = a2a_adapter.normalize(b"a2a msg 2", &json!({})).unwrap();

    let doc = agent
        .create_attestation(
            &test_subject(),
            &[test_claim()],
            &[ev1, ev2, ev3],
            None,
            None,
        )
        .expect("create with 3 evidence items");

    let key = format!("{}:{}", doc.id, doc.version);
    let result = agent
        .verify_attestation_full_impl(&key)
        .expect("full verify");
    assert_eq!(
        result.evidence.len(),
        3,
        "should have 3 evidence verification results"
    );
}

// ---------------------------------------------------------------------------
// 9. Transform receipt sets jacsLevel = "derived"
// ---------------------------------------------------------------------------

#[test]
fn attestation_transform_receipt_jacs_level() {
    let mut agent = ephemeral_agent();
    let derivation = Derivation {
        inputs: vec![DerivationInput {
            digests: DigestSet {
                sha256: "input_hash".into(),
                sha512: None,
                additional: HashMap::new(),
            },
            id: Some("source-doc".into()),
        }],
        transform: TransformRef {
            name: "summarize-v2".into(),
            hash: "transform_hash_abc".into(),
            reproducible: false,
            environment: None,
        },
        output_digests: DigestSet {
            sha256: "output_hash".into(),
            sha512: None,
            additional: HashMap::new(),
        },
    };

    let doc = agent
        .create_attestation(
            &test_subject(),
            &[test_claim()],
            &[],
            Some(&derivation),
            None,
        )
        .expect("create transform receipt");

    assert_eq!(
        doc.value["jacsLevel"].as_str().unwrap(),
        "derived",
        "transform receipt should have jacsLevel = derived"
    );
    assert_eq!(
        doc.value["jacsType"].as_str().unwrap(),
        "attestation-transform-receipt",
        "should have type attestation-transform-receipt"
    );
}

// ---------------------------------------------------------------------------
// 10. Basic attestation has jacsLevel = "raw"
// ---------------------------------------------------------------------------

#[test]
fn attestation_basic_jacs_level() {
    let mut agent = ephemeral_agent();
    let doc = agent
        .create_attestation(&test_subject(), &[test_claim()], &[], None, None)
        .expect("create basic attestation");

    assert_eq!(
        doc.value["jacsLevel"].as_str().unwrap(),
        "raw",
        "basic attestation should have jacsLevel = raw"
    );
    assert_eq!(
        doc.value["jacsType"].as_str().unwrap(),
        "attestation",
        "basic attestation should have jacsType = attestation"
    );
}

// ---------------------------------------------------------------------------
// 11. DSSE export
// ---------------------------------------------------------------------------

#[test]
fn attestation_dsse_export() {
    let mut agent = ephemeral_agent();
    let doc = agent
        .create_attestation(&test_subject(), &[test_claim()], &[], None, None)
        .expect("create attestation");

    let envelope = export_dsse(&doc.value).expect("export DSSE");

    assert_eq!(envelope["payloadType"].as_str().unwrap(), DSSE_PAYLOAD_TYPE);

    // Decode and verify the payload
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let payload_b64 = envelope["payload"].as_str().unwrap();
    let payload_bytes = STANDARD.decode(payload_b64).expect("valid base64");
    let statement: Value = serde_json::from_slice(&payload_bytes).expect("valid JSON");

    assert_eq!(statement["_type"].as_str().unwrap(), INTOTO_STATEMENT_TYPE);
    assert_eq!(
        statement["predicateType"].as_str().unwrap(),
        JACS_PREDICATE_TYPE
    );

    // Verify subject mapping
    let subjects = statement["subject"].as_array().unwrap();
    assert_eq!(subjects[0]["name"].as_str().unwrap(), "test-artifact-001");
    assert_eq!(
        subjects[0]["digest"]["sha256"].as_str().unwrap(),
        "abc123def456"
    );

    // Verify signatures
    let sigs = envelope["signatures"].as_array().unwrap();
    assert!(!sigs.is_empty());
    assert!(!sigs[0]["keyid"].as_str().unwrap().is_empty());
    assert!(!sigs[0]["sig"].as_str().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// 12. SimpleAgent API round-trip with DSSE
// ---------------------------------------------------------------------------

#[test]
fn attestation_simple_agent_full_pipeline() {
    let agent = ephemeral_simple_agent();

    // Create attestation
    let signed = jacs::attestation::simple::create(
        &agent,
        &test_subject(),
        &[test_claim()],
        &[],
        None,
        None,
    )
    .expect("create attestation");

    // Local verify
    let doc: Value = serde_json::from_str(&signed.raw).unwrap();
    let key = format!(
        "{}:{}",
        doc["jacsId"].as_str().unwrap(),
        doc["jacsVersion"].as_str().unwrap()
    );
    let local_result = jacs::attestation::simple::verify(&agent, &key).expect("local verify");
    assert!(local_result.valid);

    // Full verify
    let full_result = jacs::attestation::simple::verify_full(&agent, &key).expect("full verify");
    assert!(full_result.valid);

    // DSSE export
    let dsse_json = jacs::attestation::simple::export_dsse(&signed.raw).expect("DSSE export");
    let envelope: Value = serde_json::from_str(&dsse_json).unwrap();
    assert_eq!(
        envelope["payloadType"].as_str().unwrap(),
        "application/vnd.in-toto+json"
    );
}

// ---------------------------------------------------------------------------
// 13. Full verify returns evidence results even when empty
// ---------------------------------------------------------------------------

#[test]
fn attestation_full_verify_empty_evidence() {
    let mut agent = ephemeral_agent();
    let doc = agent
        .create_attestation(&test_subject(), &[test_claim()], &[], None, None)
        .expect("create with no evidence");

    let key = format!("{}:{}", doc.id, doc.version);
    let result = agent
        .verify_attestation_full_impl(&key)
        .expect("full verify");
    assert!(result.valid);
    assert!(
        result.evidence.is_empty(),
        "no evidence means empty evidence results"
    );
}

// ---------------------------------------------------------------------------
// 14. Attestation with policy context
// ---------------------------------------------------------------------------

#[test]
fn attestation_with_policy_context() {
    let mut agent = ephemeral_agent();
    let policy = PolicyContext {
        policy_id: Some("policy-001".into()),
        required_trust_level: Some("verified".into()),
        max_evidence_age: Some("P30D".into()),
    };

    let doc = agent
        .create_attestation(&test_subject(), &[test_claim()], &[], None, Some(&policy))
        .expect("create with policy context");

    let att = &doc.value["attestation"];
    assert_eq!(
        att["policyContext"]["policyId"].as_str().unwrap(),
        "policy-001"
    );
    assert_eq!(
        att["policyContext"]["requiredTrustLevel"].as_str().unwrap(),
        "verified"
    );
    assert_eq!(
        att["policyContext"]["maxEvidenceAge"].as_str().unwrap(),
        "P30D"
    );

    // Should still verify
    let key = format!("{}:{}", doc.id, doc.version);
    let result = agent.verify_attestation_local_impl(&key).expect("verify");
    assert!(result.valid);
}

// ---------------------------------------------------------------------------
// 15. Verify crypto result contains signer info
// ---------------------------------------------------------------------------

#[test]
fn attestation_verify_contains_signer_info() {
    let mut agent = ephemeral_agent();
    let doc = agent
        .create_attestation(&test_subject(), &[test_claim()], &[], None, None)
        .expect("create attestation");

    let key = format!("{}:{}", doc.id, doc.version);
    let result = agent.verify_attestation_local_impl(&key).expect("verify");
    assert!(result.valid);
    assert!(
        !result.crypto.signer_id.is_empty(),
        "signer_id should be set"
    );
    assert!(
        !result.crypto.algorithm.is_empty(),
        "algorithm should be set"
    );
}
