//! in-toto DSSE (Dead Simple Signing Envelope) export.
//!
//! Wraps a JACS attestation as an in-toto Statement in a DSSE envelope.
//! Export-only for v0.9.0 (no import).
//!
//! See:
//! - in-toto Statement spec: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
//! - DSSE spec: <https://github.com/secure-systems-lab/dsse/blob/master/envelope.md>

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::error::Error;

/// The `_type` field for in-toto Statements.
pub const INTOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// The `predicateType` for JACS attestations.
pub const JACS_PREDICATE_TYPE: &str = "https://jacs.dev/attestation/v1";

/// The `payloadType` for DSSE envelopes carrying in-toto Statements.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Export a signed JACS attestation document as a DSSE envelope.
///
/// Takes the full attestation JSON value (already signed with jacsSignature)
/// and produces a DSSE envelope wrapping an in-toto Statement.
///
/// # Arguments
/// * `attestation_value` - The signed attestation document JSON (must contain
///   `attestation` and `jacsSignature` fields)
///
/// # Returns
/// A DSSE envelope as a JSON `Value` with structure:
/// ```json
/// {
///   "payloadType": "application/vnd.in-toto+json",
///   "payload": "<base64-encoded in-toto Statement>",
///   "signatures": [{ "keyid": "...", "sig": "..." }]
/// }
/// ```
pub fn export_dsse(attestation_value: &Value) -> Result<Value, Box<dyn Error>> {
    // 1. Extract the attestation content
    let attestation = attestation_value
        .get("attestation")
        .ok_or("export_dsse: document missing 'attestation' field. Provide a valid JACS attestation document.")?;

    // 2. Extract subject information for in-toto subject[]
    let subject = attestation
        .get("subject")
        .ok_or("export_dsse: attestation missing 'subject' field.")?;

    let subject_id = subject
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Build the in-toto digest map from subject.digests
    let mut digest_map = json!({});
    if let Some(digests) = subject.get("digests") {
        if let Some(sha256) = digests.get("sha256").and_then(|v| v.as_str()) {
            digest_map["sha256"] = json!(sha256);
        }
        if let Some(sha512) = digests.get("sha512").and_then(|v| v.as_str()) {
            digest_map["sha512"] = json!(sha512);
        }
    }

    // 3. Build the in-toto Statement
    let statement = json!({
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [{
            "name": subject_id,
            "digest": digest_map,
        }],
        "predicateType": JACS_PREDICATE_TYPE,
        "predicate": {
            "attestation": attestation,
        },
    });

    // 4. Serialize the statement to canonical JSON and base64-encode
    let statement_json = serde_json::to_string(&statement)?;
    let payload_b64 = STANDARD.encode(statement_json.as_bytes());

    // 5. Extract JACS signature info and map to DSSE signatures[]
    let signatures = build_dsse_signatures(attestation_value)?;

    // 6. Assemble DSSE envelope
    let envelope = json!({
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": payload_b64,
        "signatures": signatures,
    });

    Ok(envelope)
}

/// Build the DSSE `signatures[]` array from a JACS signature.
fn build_dsse_signatures(doc: &Value) -> Result<Vec<Value>, Box<dyn Error>> {
    let jacs_sig = doc
        .get("jacsSignature")
        .ok_or("export_dsse: document missing 'jacsSignature'. Sign the attestation first.")?;

    let keyid = jacs_sig
        .get("publicKeyHash")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let sig = jacs_sig
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    Ok(vec![json!({
        "keyid": keyid,
        "sig": sig,
    })])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::document::DocumentTraits;
    use crate::agent::Agent;
    use crate::attestation::types::*;
    use crate::attestation::AttestationTraits;
    use serde_json::json;
    use std::collections::HashMap;

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

    fn create_test_attestation(agent: &mut Agent) -> Value {
        let subject = AttestationSubject {
            subject_type: SubjectType::Artifact,
            id: "artifact-001".into(),
            digests: DigestSet {
                sha256: "abc123def456".into(),
                sha512: Some("sha512hash".into()),
                additional: HashMap::new(),
            },
        };
        let claims = vec![Claim {
            name: "reviewed".into(),
            value: json!(true),
            confidence: Some(0.95),
            assurance_level: Some(AssuranceLevel::Verified),
            issuer: None,
            issued_at: None,
        }];
        let doc = agent
            .create_attestation(&subject, &claims, &[], None, None)
            .expect("create attestation");
        doc.value
    }

    #[test]
    fn export_dsse_valid_envelope() {
        let mut agent = test_agent();
        let att_value = create_test_attestation(&mut agent);
        let envelope = export_dsse(&att_value).expect("export_dsse should succeed");

        assert_eq!(
            envelope["payloadType"].as_str().unwrap(),
            DSSE_PAYLOAD_TYPE,
            "payloadType must be application/vnd.in-toto+json"
        );
        assert!(envelope.get("payload").is_some(), "must have payload field");
        assert!(
            envelope.get("signatures").is_some(),
            "must have signatures field"
        );
    }

    #[test]
    fn export_dsse_statement_type() {
        let mut agent = test_agent();
        let att_value = create_test_attestation(&mut agent);
        let envelope = export_dsse(&att_value).unwrap();

        let payload_b64 = envelope["payload"].as_str().unwrap();
        let payload_bytes = STANDARD.decode(payload_b64).expect("payload should be valid base64");
        let statement: Value =
            serde_json::from_slice(&payload_bytes).expect("payload should be valid JSON");

        assert_eq!(
            statement["_type"].as_str().unwrap(),
            INTOTO_STATEMENT_TYPE,
            "_type must be the in-toto Statement v1 type"
        );
    }

    #[test]
    fn export_dsse_predicate_type() {
        let mut agent = test_agent();
        let att_value = create_test_attestation(&mut agent);
        let envelope = export_dsse(&att_value).unwrap();

        let payload_b64 = envelope["payload"].as_str().unwrap();
        let payload_bytes = STANDARD.decode(payload_b64).unwrap();
        let statement: Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(
            statement["predicateType"].as_str().unwrap(),
            JACS_PREDICATE_TYPE,
            "predicateType must be https://jacs.dev/attestation/v1"
        );
    }

    #[test]
    fn export_dsse_subject_mapping() {
        let mut agent = test_agent();
        let att_value = create_test_attestation(&mut agent);
        let envelope = export_dsse(&att_value).unwrap();

        let payload_b64 = envelope["payload"].as_str().unwrap();
        let payload_bytes = STANDARD.decode(payload_b64).unwrap();
        let statement: Value = serde_json::from_slice(&payload_bytes).unwrap();

        let subjects = statement["subject"].as_array().expect("subject should be array");
        assert_eq!(subjects.len(), 1, "should have exactly one subject");

        assert_eq!(
            subjects[0]["name"].as_str().unwrap(),
            "artifact-001",
            "subject name should match attestation subject ID"
        );
        assert_eq!(
            subjects[0]["digest"]["sha256"].as_str().unwrap(),
            "abc123def456",
            "digest sha256 should match"
        );
        assert_eq!(
            subjects[0]["digest"]["sha512"].as_str().unwrap(),
            "sha512hash",
            "digest sha512 should match when present"
        );
    }

    #[test]
    fn export_dsse_predicate_contains_attestation() {
        let mut agent = test_agent();
        let att_value = create_test_attestation(&mut agent);
        let original_attestation = att_value["attestation"].clone();

        let envelope = export_dsse(&att_value).unwrap();

        let payload_b64 = envelope["payload"].as_str().unwrap();
        let payload_bytes = STANDARD.decode(payload_b64).unwrap();
        let statement: Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(
            statement["predicate"]["attestation"], original_attestation,
            "predicate.attestation should contain the original attestation content"
        );
    }

    #[test]
    fn export_dsse_signatures() {
        let mut agent = test_agent();
        let att_value = create_test_attestation(&mut agent);
        let envelope = export_dsse(&att_value).unwrap();

        let sigs = envelope["signatures"]
            .as_array()
            .expect("signatures should be array");
        assert!(sigs.len() >= 1, "should have at least one signature");
        assert!(
            sigs[0].get("keyid").is_some(),
            "signature should have keyid field"
        );
        assert!(
            sigs[0].get("sig").is_some(),
            "signature should have sig field"
        );

        // keyid should be non-empty (it's the publicKeyHash)
        let keyid = sigs[0]["keyid"].as_str().unwrap();
        assert!(!keyid.is_empty(), "keyid should not be empty");

        // sig should be non-empty (it's the actual signature)
        let sig = sigs[0]["sig"].as_str().unwrap();
        assert!(!sig.is_empty(), "sig should not be empty");
    }

    #[test]
    fn export_dsse_payload_is_base64() {
        let mut agent = test_agent();
        let att_value = create_test_attestation(&mut agent);
        let envelope = export_dsse(&att_value).unwrap();

        let payload_b64 = envelope["payload"].as_str().unwrap();

        // Verify it's valid base64
        let decoded = STANDARD.decode(payload_b64);
        assert!(
            decoded.is_ok(),
            "payload should be valid base64: {:?}",
            decoded.err()
        );

        // Verify the decoded content is valid JSON
        let json_result = serde_json::from_slice::<Value>(&decoded.unwrap());
        assert!(
            json_result.is_ok(),
            "decoded payload should be valid JSON: {:?}",
            json_result.err()
        );
    }

    #[test]
    fn export_dsse_missing_attestation_field_errors() {
        let doc = json!({"jacsSignature": {"signature": "abc", "publicKeyHash": "xyz"}});
        let result = export_dsse(&doc);
        assert!(result.is_err(), "missing attestation field should error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("attestation"),
            "error should mention missing attestation: {}",
            err
        );
    }

    #[test]
    fn export_dsse_missing_signature_errors() {
        let doc = json!({
            "attestation": {
                "subject": {"type": "artifact", "id": "test", "digests": {"sha256": "abc"}},
                "claims": [{"name": "test", "value": true}]
            }
        });
        let result = export_dsse(&doc);
        assert!(result.is_err(), "missing jacsSignature should error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("jacsSignature"),
            "error should mention missing signature: {}",
            err
        );
    }
}
