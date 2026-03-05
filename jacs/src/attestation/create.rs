//! Implementation of create_attestation() on Agent.
//!
//! Constructs an attestation JSON document, validates it against the attestation
//! schema, signs it, and stores it. Reuses existing document creation/signing
//! infrastructure (schema.create + signing_procedure + hash_doc + store).

use crate::agent::document::{DocumentTraits, JACSDocument};
use crate::agent::{Agent, DOCUMENT_AGENT_SIGNATURE_FIELDNAME, SHA256_FIELDNAME};
use crate::attestation::types::*;
use serde_json::{json, Value};
use std::error::Error;
use tracing::info;

/// Build the attestation JSON body from typed parameters.
/// This produces the inner `{"attestation": {...}}` envelope without any JACS header fields,
/// which are added by `schema.create()`.
fn build_attestation_json(
    subject: &AttestationSubject,
    claims: &[Claim],
    evidence: &[EvidenceRef],
    derivation: Option<&Derivation>,
    policy_context: Option<&PolicyContext>,
) -> Result<Value, Box<dyn Error>> {
    let mut attestation_body = json!({
        "subject": serde_json::to_value(subject)?,
        "claims": serde_json::to_value(claims)?,
    });

    // Optional evidence array
    if !evidence.is_empty() {
        attestation_body["evidence"] = serde_json::to_value(evidence)?;
    }

    // Optional derivation (transform receipt)
    if let Some(d) = derivation {
        attestation_body["derivation"] = serde_json::to_value(d)?;
    }

    // Optional policy context
    if let Some(pc) = policy_context {
        let pc_value = serde_json::to_value(pc)?;
        // Only include if it has at least one field set
        if pc_value.as_object().is_some_and(|o| !o.is_empty()) {
            attestation_body["policyContext"] = pc_value;
        }
    }

    // Determine jacsLevel and jacsType based on TRD decision 12:
    // - attestation (no derivation) -> jacsLevel = "raw"
    // - transform receipt (with derivation) -> jacsLevel = "derived"
    let jacs_level = if derivation.is_some() {
        "derived"
    } else {
        "raw"
    };

    let jacs_type = if derivation.is_some() {
        "attestation-transform-receipt"
    } else {
        "attestation"
    };

    let envelope = json!({
        "$schema": "https://hai.ai/schemas/attestation/v1/attestation.schema.json",
        "jacsType": jacs_type,
        "jacsLevel": jacs_level,
        "attestation": attestation_body,
    });

    Ok(envelope)
}

/// Create a signed attestation document.
/// Called by the AttestationTraits impl (in verify.rs) to separate concerns.
#[tracing::instrument(
    name = "jacs.attestation.create",
    skip_all,
)]
pub fn create_attestation_impl(
    agent: &mut Agent,
    subject: &AttestationSubject,
    claims: &[Claim],
    evidence: &[EvidenceRef],
    derivation: Option<&Derivation>,
    policy_context: Option<&PolicyContext>,
) -> Result<JACSDocument, Box<dyn Error>> {
    // 1. Build the attestation JSON envelope (no JACS header fields yet)
    let envelope = build_attestation_json(subject, claims, evidence, derivation, policy_context)?;
    let envelope_str = serde_json::to_string(&envelope)?;

    // 2. schema.create() adds jacsId, jacsVersion, etc. and validates against header schema.
    let mut instance = agent.schema.create(&envelope_str)?;

    // 3. Validate against the attestation schema (now header fields are present).
    let instance_str = serde_json::to_string(&instance)?;
    agent.schema.validate_attestation(&instance_str)?;

    // 4. Sign the document
    instance[DOCUMENT_AGENT_SIGNATURE_FIELDNAME] =
        agent.signing_procedure(&instance, None, DOCUMENT_AGENT_SIGNATURE_FIELDNAME)?;

    // 5. Hash the document
    let document_hash = agent.hash_doc(&instance)?;
    instance[SHA256_FIELDNAME] = json!(format!("{}", document_hash));

    // 6. Store and return
    let doc = agent.store_jacs_document(&instance)?;

    info!(
        target: "jacs::attestation::create",
        event = "attestation_created",
        jacs_id = %doc.id,
        jacs_type = %doc.jacs_type,
        subject_type = ?subject.subject_type,
        subject_id = %subject.id,
        claims_count = claims.len(),
        evidence_count = evidence.len(),
        has_derivation = derivation.is_some(),
    );

    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::attestation::digest::compute_digest_set_string;
    use crate::attestation::AttestationTraits;
    use std::collections::HashMap;

    /// Helper: create a loaded ephemeral Agent for testing.
    fn test_agent() -> Agent {
        let algo = "ring-Ed25519";
        let mut agent = Agent::ephemeral(algo).expect("create ephemeral agent");
        let agent_json = crate::create_minimal_blank_agent(
            "ai".to_string(),
            None,
            None,
            None,
        )
        .expect("create agent template");
        agent
            .create_agent_and_load(&agent_json, true, Some(algo))
            .expect("load ephemeral agent");
        agent
    }

    /// Helper: build a minimal AttestationSubject.
    fn test_subject() -> AttestationSubject {
        AttestationSubject {
            subject_type: SubjectType::Agent,
            id: "test-agent-123".into(),
            digests: DigestSet {
                sha256: compute_digest_set_string("test-content").sha256,
                sha512: None,
                additional: HashMap::new(),
            },
        }
    }

    /// Helper: build a minimal Claim.
    fn test_claim() -> Claim {
        Claim {
            name: "test-claim".into(),
            value: json!("ok"),
            confidence: None,
            assurance_level: None,
            issuer: None,
            issued_at: None,
        }
    }

    /// Helper: build a minimal EvidenceRef.
    fn test_evidence() -> EvidenceRef {
        EvidenceRef {
            kind: EvidenceKind::A2a,
            digests: compute_digest_set_string("evidence-data"),
            uri: None,
            embedded: true,
            embedded_data: Some(json!("evidence-data")),
            collected_at: crate::time_utils::now_rfc3339(),
            resolved_at: None,
            sensitivity: EvidenceSensitivity::Public,
            verifier: VerifierInfo {
                name: "test-verifier".into(),
                version: "1.0".into(),
            },
        }
    }

    #[test]
    fn create_attestation_minimal() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];

        let doc = agent
            .create_attestation(&subject, &claims, &[], None, None)
            .expect("create_attestation should succeed");

        assert_eq!(doc.jacs_type, "attestation");
        let attestation = &doc.value["attestation"];
        assert_eq!(attestation["subject"]["type"], "agent");
        assert_eq!(attestation["subject"]["id"], "test-agent-123");
        assert_eq!(attestation["claims"][0]["name"], "test-claim");
    }

    #[test]
    fn create_attestation_with_evidence() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let evidence = vec![test_evidence()];

        let doc = agent
            .create_attestation(&subject, &claims, &evidence, None, None)
            .expect("create_attestation with evidence should succeed");

        let evidence_arr = doc.value["attestation"]["evidence"]
            .as_array()
            .expect("evidence should be an array");
        assert_eq!(evidence_arr.len(), 1);
        assert_eq!(evidence_arr[0]["kind"], "a2a");
    }

    #[test]
    fn create_attestation_with_derivation() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let derivation = Derivation {
            inputs: vec![DerivationInput {
                digests: compute_digest_set_string("input-content"),
                id: Some("input-doc-id".into()),
            }],
            transform: TransformRef {
                name: "summarize-v2".into(),
                hash: "transform-hash-abc".into(),
                reproducible: false,
                environment: None,
            },
            output_digests: compute_digest_set_string("output-content"),
        };

        let doc = agent
            .create_attestation(&subject, &claims, &[], Some(&derivation), None)
            .expect("create_attestation with derivation should succeed");

        assert_eq!(doc.jacs_type, "attestation-transform-receipt");
        let deriv = &doc.value["attestation"]["derivation"];
        assert!(!deriv.is_null(), "derivation should be present");
        assert_eq!(deriv["transform"]["name"], "summarize-v2");
        assert!(
            deriv["outputDigests"]["sha256"].is_string(),
            "outputDigests.sha256 should be present"
        );
    }

    #[test]
    fn create_attestation_validates_schema() {
        let mut agent = test_agent();
        // Subject missing sha256 in digests -- should fail schema validation
        let bad_subject = AttestationSubject {
            subject_type: SubjectType::Agent,
            id: "bad-agent".into(),
            digests: DigestSet {
                sha256: "".into(), // empty, but present -- schema won't reject this
                sha512: None,
                additional: HashMap::new(),
            },
        };
        // No claims at all -- schema requires minItems: 1
        let result = agent.create_attestation(&bad_subject, &[], &[], None, None);
        assert!(
            result.is_err(),
            "Should fail: schema requires at least 1 claim"
        );
    }

    #[test]
    fn create_attestation_is_signed() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];

        let doc = agent
            .create_attestation(&subject, &claims, &[], None, None)
            .expect("create_attestation should succeed");

        // Document must have a signature and hash
        assert!(
            doc.value.get("jacsSignature").is_some(),
            "Document must have jacsSignature"
        );
        assert!(
            doc.value.get("jacsSha256").is_some(),
            "Document must have jacsSha256"
        );
    }

    #[test]
    fn create_attestation_jacs_level_raw() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];

        let doc = agent
            .create_attestation(&subject, &claims, &[], None, None)
            .expect("attestation without derivation");

        assert_eq!(
            doc.value["jacsLevel"].as_str().unwrap(),
            "raw",
            "attestation without derivation should have jacsLevel='raw'"
        );
    }

    #[test]
    fn create_attestation_jacs_level_derived() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let derivation = Derivation {
            inputs: vec![DerivationInput {
                digests: compute_digest_set_string("input"),
                id: None,
            }],
            transform: TransformRef {
                name: "transform".into(),
                hash: "hash".into(),
                reproducible: true,
                environment: None,
            },
            output_digests: compute_digest_set_string("output"),
        };

        let doc = agent
            .create_attestation(&subject, &claims, &[], Some(&derivation), None)
            .expect("attestation with derivation");

        assert_eq!(
            doc.value["jacsLevel"].as_str().unwrap(),
            "derived",
            "attestation with derivation should have jacsLevel='derived'"
        );
    }

    #[test]
    fn create_attestation_stored_and_retrievable() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];

        let doc = agent
            .create_attestation(&subject, &claims, &[], None, None)
            .expect("create_attestation should succeed");

        let key = format!("{}:{}", doc.id, doc.version);
        let retrieved = agent.get_document(&key).expect("document should be retrievable");
        assert_eq!(retrieved.id, doc.id);
        assert_eq!(retrieved.version, doc.version);
    }

    #[test]
    fn create_attestation_with_policy_context() {
        let mut agent = test_agent();
        let subject = test_subject();
        let claims = vec![test_claim()];
        let policy = PolicyContext {
            policy_id: Some("policy-hash-123".into()),
            required_trust_level: Some("verified".into()),
            max_evidence_age: Some("PT5M".into()),
        };

        let doc = agent
            .create_attestation(&subject, &claims, &[], None, Some(&policy))
            .expect("create_attestation with policy should succeed");

        let pc = &doc.value["attestation"]["policyContext"];
        assert!(!pc.is_null(), "policyContext should be present");
        assert_eq!(pc["policyId"], "policy-hash-123");
    }

    #[test]
    fn build_attestation_json_minimal() {
        let subject = test_subject();
        let claims = vec![test_claim()];
        let result = build_attestation_json(&subject, &claims, &[], None, None).unwrap();

        assert_eq!(
            result["$schema"],
            "https://hai.ai/schemas/attestation/v1/attestation.schema.json"
        );
        assert_eq!(result["jacsType"], "attestation");
        assert_eq!(result["jacsLevel"], "raw");
        assert!(result["attestation"]["derivation"].is_null());
    }

    #[test]
    fn build_attestation_json_empty_policy_omitted() {
        let subject = test_subject();
        let claims = vec![test_claim()];
        let empty_policy = PolicyContext::default();
        let result =
            build_attestation_json(&subject, &claims, &[], None, Some(&empty_policy)).unwrap();

        // Empty policy context (all fields None) should not appear in the JSON
        assert!(
            result["attestation"]["policyContext"].is_null(),
            "Empty policy context should be omitted"
        );
    }
}
