//! Migration helper: lift existing signed documents into attestations.
//!
//! Provides lift_to_attestation() to convert an existing signed JACS document
//! into an attestation document that references the original.

use crate::agent::Agent;
use crate::agent::document::JACSDocument;
use crate::attestation::AttestationTraits;
use crate::attestation::digest::compute_digest_set;
use crate::attestation::types::*;
use serde_json::Value;
use std::error::Error;

/// Lift an existing signed JACS document into an attestation.
///
/// The original document's ID becomes the attestation subject ID,
/// and its canonical content hash becomes the subject digest.
///
/// # Arguments
/// * `agent` - The agent performing the attestation
/// * `signed_document_json` - JSON string of the existing signed document
/// * `claims` - Claims to include in the attestation
///
/// # Returns
/// A new signed attestation JACSDocument referencing the original.
pub fn lift_to_attestation(
    agent: &mut Agent,
    signed_document_json: &str,
    claims: &[Claim],
) -> Result<JACSDocument, Box<dyn Error>> {
    // 1. Parse the signed document
    let doc_value: Value = serde_json::from_str(signed_document_json).map_err(|e| {
        format!(
            "lift_to_attestation: invalid JSON input: {}. \
             Provide a valid signed JACS document JSON string.",
            e
        )
    })?;

    // 2. Verify it has a signature (must be a signed document)
    if doc_value.get("jacsSignature").is_none() {
        return Err(
            "lift_to_attestation: document is missing 'jacsSignature' field. \
             Only signed JACS documents can be lifted to attestations. \
             Sign the document first using create_document_and_load() or sign_message()."
                .into(),
        );
    }

    // 3. Extract document ID (use jacsId if present, else generate a description)
    let doc_id = doc_value
        .get("jacsId")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown-document")
        .to_string();

    // 4. Compute the digest of the original document's content
    let digests = compute_digest_set(&doc_value)?;

    // 5. Construct the attestation subject
    let subject = AttestationSubject {
        subject_type: SubjectType::Artifact,
        id: doc_id,
        digests,
    };

    // 6. Ensure at least one claim is provided
    if claims.is_empty() {
        return Err("lift_to_attestation: at least one claim is required. \
             Provide claims describing what is being attested about the document."
            .into());
    }

    // 7. Create the attestation using the existing infrastructure
    agent.create_attestation(&subject, claims, &[], None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::document::DocumentTraits;
    use crate::attestation::digest::compute_digest_set;
    use serde_json::json;

    fn test_agent() -> Agent {
        let algo = "ring-Ed25519";
        let mut agent = Agent::ephemeral(algo).expect("create ephemeral agent");
        let agent_json = crate::create_minimal_blank_agent("ai".to_string(), None, None, None)
            .expect("create agent template");
        agent
            .create_agent_and_load(&agent_json, true, Some(algo))
            .expect("load ephemeral agent");
        agent
    }

    /// Create a signed document for testing.
    fn create_signed_doc(agent: &mut Agent) -> JACSDocument {
        let doc_json = json!({
            "title": "Test Document",
            "content": "This is a test document for migration."
        });
        agent
            .create_document_and_load(&doc_json.to_string(), None, None)
            .expect("create signed document")
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

    #[test]
    fn lift_creates_attestation_from_signed_doc() {
        let mut agent = test_agent();
        let signed_doc = create_signed_doc(&mut agent);
        let signed_json = serde_json::to_string(&signed_doc.value).unwrap();

        let attestation = lift_to_attestation(&mut agent, &signed_json, &[test_claim()]).unwrap();

        let att = &attestation.value["attestation"];
        assert_eq!(att["subject"]["type"], "artifact");
        assert_eq!(
            att["subject"]["id"].as_str().unwrap(),
            signed_doc.id,
            "Subject ID should match original document ID"
        );
    }

    #[test]
    fn lift_computes_subject_digest() {
        let mut agent = test_agent();
        let signed_doc = create_signed_doc(&mut agent);
        let signed_json = serde_json::to_string(&signed_doc.value).unwrap();
        let expected_digests = compute_digest_set(&signed_doc.value).unwrap();

        let attestation = lift_to_attestation(&mut agent, &signed_json, &[test_claim()]).unwrap();

        let att = &attestation.value["attestation"];
        assert_eq!(
            att["subject"]["digests"]["sha256"].as_str().unwrap(),
            expected_digests.sha256,
            "Subject digest should match SHA-256 of original canonical content"
        );
    }

    #[test]
    fn lift_preserves_claims() {
        let mut agent = test_agent();
        let signed_doc = create_signed_doc(&mut agent);
        let signed_json = serde_json::to_string(&signed_doc.value).unwrap();

        let claims = vec![
            Claim {
                name: "reviewed".into(),
                value: json!(true),
                confidence: None,
                assurance_level: None,
                issuer: None,
                issued_at: None,
            },
            Claim {
                name: "approved".into(),
                value: json!("yes"),
                confidence: Some(1.0),
                assurance_level: None,
                issuer: None,
                issued_at: None,
            },
        ];

        let attestation = lift_to_attestation(&mut agent, &signed_json, &claims).unwrap();

        let att_claims = attestation.value["attestation"]["claims"]
            .as_array()
            .expect("claims should be array");
        assert_eq!(att_claims.len(), 2);
        assert_eq!(att_claims[0]["name"], "reviewed");
        assert_eq!(att_claims[1]["name"], "approved");
    }

    #[test]
    fn lift_signed_document_is_valid() {
        let mut agent = test_agent();
        let signed_doc = create_signed_doc(&mut agent);
        let signed_json = serde_json::to_string(&signed_doc.value).unwrap();

        let attestation = lift_to_attestation(&mut agent, &signed_json, &[test_claim()]).unwrap();
        let key = format!("{}:{}", attestation.id, attestation.version);

        let result = agent.verify_attestation_local_impl(&key).unwrap();
        assert!(
            result.valid,
            "Lifted attestation should verify: {:?}",
            result.errors
        );
    }

    #[test]
    fn lift_invalid_json_errors() {
        let mut agent = test_agent();
        let result = lift_to_attestation(&mut agent, "not json {{{", &[test_claim()]);
        assert!(result.is_err(), "Invalid JSON should error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid JSON"),
            "Error should mention invalid JSON: {}",
            err
        );
    }

    #[test]
    fn lift_unsigned_document_errors() {
        let mut agent = test_agent();
        let unsigned = json!({"title": "unsigned", "content": "no signature"});
        let result = lift_to_attestation(&mut agent, &unsigned.to_string(), &[test_claim()]);
        assert!(result.is_err(), "Unsigned document should error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("jacsSignature"),
            "Error should mention missing signature: {}",
            err
        );
    }
}
