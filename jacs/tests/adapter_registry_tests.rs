#![cfg(feature = "attestation-tests")]

//! Tests for evidence adapter registry wiring.
//!
//! Verifies that:
//! - Agent is constructed with default adapters populated
//! - `register_adapter()` adds a custom adapter
//! - Full verification dispatches to adapter's `verify_evidence()` based on evidence kind
//! - Custom adapter receives evidence for its registered kind

use jacs::agent::Agent;
use jacs::attestation::adapters::EvidenceAdapter;
use jacs::attestation::digest::compute_digest_set_bytes;
use jacs::attestation::types::*;
use jacs::attestation::AttestationTraits;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
        name: "test-claim".into(),
        value: json!("ok"),
        confidence: Some(0.9),
        assurance_level: None,
        issuer: None,
        issued_at: None,
    }
}

// ---------------------------------------------------------------------------
// 1. Agent constructed with default_adapters() populated
// ---------------------------------------------------------------------------

#[test]
fn agent_has_default_adapters_on_construction() {
    let agent = ephemeral_agent();
    // Default adapters include "a2a" and "email"
    assert!(
        agent.adapters.len() >= 2,
        "Agent should have at least 2 default adapters, got {}",
        agent.adapters.len()
    );

    let kinds: Vec<&str> = agent.adapters.iter().map(|a| a.kind()).collect();
    assert!(
        kinds.contains(&"a2a"),
        "Default adapters should include 'a2a', got: {:?}",
        kinds
    );
    assert!(
        kinds.contains(&"email"),
        "Default adapters should include 'email', got: {:?}",
        kinds
    );
}

// ---------------------------------------------------------------------------
// 2. register_adapter() adds a custom adapter to the list
// ---------------------------------------------------------------------------

/// A mock adapter for testing custom adapter registration.
#[derive(Debug)]
struct MockAdapter {
    kind_str: String,
    was_called: Arc<AtomicBool>,
}

impl EvidenceAdapter for MockAdapter {
    fn kind(&self) -> &str {
        &self.kind_str
    }

    fn normalize(
        &self,
        raw: &[u8],
        _metadata: &Value,
    ) -> Result<(Vec<Claim>, EvidenceRef), Box<dyn Error>> {
        let digests = compute_digest_set_bytes(raw);
        let claims = vec![Claim {
            name: format!("{}-claim", self.kind_str),
            value: json!(true),
            confidence: Some(1.0),
            assurance_level: None,
            issuer: None,
            issued_at: None,
        }];
        let evidence = EvidenceRef {
            kind: EvidenceKind::Custom,
            digests,
            uri: None,
            embedded: true,
            embedded_data: Some(Value::String(
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw),
            )),
            collected_at: jacs::time_utils::now_rfc3339(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::Public,
            verifier: VerifierInfo {
                name: format!("mock-{}-adapter", self.kind_str),
                version: "0.1.0".into(),
            },
        };
        Ok((claims, evidence))
    }

    fn verify_evidence(
        &self,
        evidence: &EvidenceRef,
    ) -> Result<EvidenceVerificationResult, Box<dyn Error>> {
        self.was_called.store(true, Ordering::SeqCst);
        let digest_valid = if let Some(ref data) = evidence.embedded_data {
            let raw = match data {
                Value::String(s) => {
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
                        .unwrap_or_else(|_| s.as_bytes().to_vec())
                }
                other => serde_json::to_vec(other).unwrap_or_default(),
            };
            let recomputed = compute_digest_set_bytes(&raw);
            recomputed.sha256 == evidence.digests.sha256
        } else {
            false
        };
        Ok(EvidenceVerificationResult {
            kind: self.kind_str.clone(),
            digest_valid,
            freshness_valid: true,
            detail: format!("Mock {} adapter verified", self.kind_str),
        })
    }
}

#[test]
fn register_adapter_adds_custom_adapter() {
    let mut agent = ephemeral_agent();
    let initial_count = agent.adapters.len();

    let was_called = Arc::new(AtomicBool::new(false));
    let adapter = MockAdapter {
        kind_str: "custom-test".into(),
        was_called: was_called.clone(),
    };
    agent.register_adapter(Box::new(adapter));

    assert_eq!(
        agent.adapters.len(),
        initial_count + 1,
        "Adapter count should increase by 1"
    );

    let kinds: Vec<&str> = agent.adapters.iter().map(|a| a.kind()).collect();
    assert!(
        kinds.contains(&"custom-test"),
        "Custom adapter should be in the registry: {:?}",
        kinds
    );
}

// ---------------------------------------------------------------------------
// 3. Full verification dispatches to adapter's verify_evidence() for matching kind
// ---------------------------------------------------------------------------

#[test]
fn full_verify_dispatches_to_a2a_adapter() {
    let mut agent = ephemeral_agent();
    let subject = test_subject();
    let claims = vec![test_claim()];

    // Create evidence with A2A kind
    let data = b"evidence-data-for-a2a";
    let evidence = vec![EvidenceRef {
        kind: EvidenceKind::A2a,
        digests: compute_digest_set_bytes(data),
        uri: None,
        embedded: true,
        embedded_data: Some(json!(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data
        ))),
        collected_at: jacs::time_utils::now_rfc3339(),
        resolved_at: None,
        sensitivity: EvidenceSensitivity::Public,
        verifier: VerifierInfo {
            name: "test-verifier".into(),
            version: "1.0".into(),
        },
    }];

    let doc = agent
        .create_attestation(&subject, &claims, &evidence, None, None)
        .unwrap();
    let key = format!("{}:{}", doc.id, doc.version);

    let result = agent.verify_attestation_full_impl(&key).unwrap();
    assert_eq!(result.evidence.len(), 1);
    assert!(
        result.evidence[0].digest_valid,
        "A2A adapter should verify digest: {}",
        result.evidence[0].detail
    );
    // The A2A adapter returns kind = "a2a"
    assert_eq!(result.evidence[0].kind, "a2a");
}

#[test]
fn full_verify_dispatches_to_email_adapter() {
    let mut agent = ephemeral_agent();
    let subject = test_subject();
    let claims = vec![test_claim()];

    // Create evidence with Email kind
    let data = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody";
    let evidence = vec![EvidenceRef {
        kind: EvidenceKind::Email,
        digests: compute_digest_set_bytes(data),
        uri: None,
        embedded: true,
        embedded_data: Some(Value::String(
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data),
        )),
        collected_at: jacs::time_utils::now_rfc3339(),
        resolved_at: None,
        sensitivity: EvidenceSensitivity::Public,
        verifier: VerifierInfo {
            name: "test-verifier".into(),
            version: "1.0".into(),
        },
    }];

    let doc = agent
        .create_attestation(&subject, &claims, &evidence, None, None)
        .unwrap();
    let key = format!("{}:{}", doc.id, doc.version);

    let result = agent.verify_attestation_full_impl(&key).unwrap();
    assert_eq!(result.evidence.len(), 1);
    assert!(
        result.evidence[0].digest_valid,
        "Email adapter should verify digest: {}",
        result.evidence[0].detail
    );
    assert_eq!(result.evidence[0].kind, "email");
}

// ---------------------------------------------------------------------------
// 4. Custom adapter receives evidence for its registered kind
// ---------------------------------------------------------------------------

#[test]
fn custom_adapter_receives_evidence_for_its_kind() {
    let mut agent = ephemeral_agent();

    let was_called = Arc::new(AtomicBool::new(false));
    let adapter = MockAdapter {
        kind_str: "custom".into(),
        was_called: was_called.clone(),
    };
    agent.register_adapter(Box::new(adapter));

    let subject = test_subject();
    let claims = vec![test_claim()];

    // Create evidence with Custom kind (matches our mock adapter's kind "custom")
    let data = b"custom-evidence-payload";
    let evidence = vec![EvidenceRef {
        kind: EvidenceKind::Custom,
        digests: compute_digest_set_bytes(data),
        uri: None,
        embedded: true,
        embedded_data: Some(Value::String(
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data),
        )),
        collected_at: jacs::time_utils::now_rfc3339(),
        resolved_at: None,
        sensitivity: EvidenceSensitivity::Public,
        verifier: VerifierInfo {
            name: "test-verifier".into(),
            version: "1.0".into(),
        },
    }];

    let doc = agent
        .create_attestation(&subject, &claims, &evidence, None, None)
        .unwrap();
    let key = format!("{}:{}", doc.id, doc.version);

    let result = agent.verify_attestation_full_impl(&key).unwrap();
    assert_eq!(result.evidence.len(), 1);
    assert!(
        was_called.load(Ordering::SeqCst),
        "Custom adapter's verify_evidence() should have been called"
    );
    assert!(
        result.evidence[0].digest_valid,
        "Custom adapter should verify digest: {}",
        result.evidence[0].detail
    );
    assert_eq!(result.evidence[0].kind, "custom");
}

// ---------------------------------------------------------------------------
// 5. Fallback: evidence with no matching adapter uses verify_evidence_ref
// ---------------------------------------------------------------------------

#[test]
fn unmatched_evidence_kind_falls_back_to_verify_evidence_ref() {
    let mut agent = ephemeral_agent();
    let subject = test_subject();
    let claims = vec![test_claim()];

    // JWT evidence but no JWT adapter registered (only a2a and email by default)
    let data = b"jwt-evidence-data";
    let evidence = vec![EvidenceRef {
        kind: EvidenceKind::Jwt,
        digests: compute_digest_set_bytes(data),
        uri: None,
        embedded: true,
        embedded_data: Some(json!(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data
        ))),
        collected_at: jacs::time_utils::now_rfc3339(),
        resolved_at: None,
        sensitivity: EvidenceSensitivity::Public,
        verifier: VerifierInfo {
            name: "test-verifier".into(),
            version: "1.0".into(),
        },
    }];

    let doc = agent
        .create_attestation(&subject, &claims, &evidence, None, None)
        .unwrap();
    let key = format!("{}:{}", doc.id, doc.version);

    let result = agent.verify_attestation_full_impl(&key).unwrap();
    assert_eq!(result.evidence.len(), 1);
    // Fallback verify_evidence_ref should still verify the digest
    assert!(
        result.evidence[0].digest_valid,
        "Fallback should still verify embedded evidence digest: {}",
        result.evidence[0].detail
    );
}
