use crate::agent::Agent;
use crate::crypt::{KeyManager, base64_decode};
use crate::error::JacsError;
use crate::protocol::canonicalize_json_try;
use crate::replay::check_and_store_nonce_with_ttl;
use crate::time_utils::{
    now_rfc3339, validate_timestamp_not_expired, validate_timestamp_not_future,
};
use crate::w3c::did_wba::{W3cDidOptions, export_did_document};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3cRequestProofParams {
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

pub fn build_request_proof(
    agent: &mut Agent,
    params: W3cRequestProofParams,
) -> Result<Value, JacsError> {
    let did_doc = export_did_document(
        agent,
        W3cDidOptions {
            origin: params.origin.clone(),
        },
    )?;
    let did = did_doc["id"]
        .as_str()
        .ok_or("Generated DID document is missing id")?
        .to_string();
    let verification_method = did_doc["authentication"][0]
        .as_str()
        .ok_or("Generated DID document is missing authentication method")?
        .to_string();
    let created = params.created.unwrap_or_else(now_rfc3339);
    let nonce = params
        .nonce
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let request = canonical_request_value(
        &params.method,
        &params.url,
        &created,
        &nonce,
        &did,
        &verification_method,
        params.body.as_deref().map(str::as_bytes),
    )?;
    let canonical = canonicalize_json_try(&request).map_err(JacsError::from)?;
    let signing_algorithm =
        crate::protocol::configured_agent_signing_algorithm(agent, "W3C request proof")?;
    let signature = agent.sign_string(&canonical)?;

    Ok(json!({
        "type": "JacsW3cRequestProof",
        "scheme": "DIDWba",
        "did": did,
        "verificationMethod": verification_method,
        "created": created,
        "nonce": nonce,
        "method": crate::protocol::normalize_http_method(&params.method)?,
        "url": params.url,
        "contentDigest": request.get("contentDigest").cloned(),
        "signingInput": request,
        "signingAlgorithm": signing_algorithm,
        "signature": signature
    }))
}

pub fn verify_request_proof(
    verifier: &Agent,
    proof_json: &str,
    did_document_json: &str,
    body: Option<&str>,
    max_age_seconds: u64,
) -> Result<Value, JacsError> {
    verify_request_proof_for_request(
        verifier,
        proof_json,
        did_document_json,
        body,
        max_age_seconds,
        None,
        None,
    )
}

pub fn verify_request_proof_for_request(
    verifier: &Agent,
    proof_json: &str,
    did_document_json: &str,
    body: Option<&str>,
    max_age_seconds: u64,
    expected_method: Option<&str>,
    expected_url: Option<&str>,
) -> Result<Value, JacsError> {
    let proof: Value = jacs_core::strict_json::parse_strict_json(proof_json).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "proof_json".to_string(),
            reason: e.to_string(),
        }
    })?;
    let did_document: Value = jacs_core::strict_json::parse_strict_json(did_document_json)
        .map_err(|e| JacsError::DocumentMalformed {
            field: "did_document_json".to_string(),
            reason: e.to_string(),
        })?;
    verify_request_proof_value_for_request(
        verifier,
        &proof,
        &did_document,
        body,
        max_age_seconds,
        expected_method,
        expected_url,
    )
}

pub fn verify_request_proof_value(
    verifier: &Agent,
    proof: &Value,
    did_document: &Value,
    body: Option<&str>,
    max_age_seconds: u64,
) -> Result<Value, JacsError> {
    verify_request_proof_value_for_request(
        verifier,
        proof,
        did_document,
        body,
        max_age_seconds,
        None,
        None,
    )
}

pub fn verify_request_proof_value_for_request(
    verifier: &Agent,
    proof: &Value,
    did_document: &Value,
    body: Option<&str>,
    max_age_seconds: u64,
    expected_method: Option<&str>,
    expected_url: Option<&str>,
) -> Result<Value, JacsError> {
    let did = required_str(proof, "did")?;
    let verification_method = required_str(proof, "verificationMethod")?;
    let created = required_str(proof, "created")?;
    let nonce = required_str(proof, "nonce")?;
    let method = required_str(proof, "method")?;
    let url = required_str(proof, "url")?;
    let signature = required_str(proof, "signature")?;

    if did_document["id"].as_str() != Some(did) {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "DID document id does not match request proof did".to_string(),
        });
    }

    let max_age_seconds_i64 = i64::try_from(max_age_seconds).map_err(|_| {
        JacsError::ValidationError("max_age_seconds exceeds supported timestamp range".to_string())
    })?;
    validate_timestamp_not_future(created)?;
    validate_timestamp_not_expired(created, max_age_seconds_i64)?;
    let request = canonical_request_value(
        method,
        url,
        created,
        nonce,
        did,
        verification_method,
        body.map(str::as_bytes),
    )?;
    ensure_expected_request_binding(&request, expected_method, expected_url)?;
    let proof_digest = proof.get("contentDigest").and_then(Value::as_str);
    if body.is_some() && proof_digest.is_none() {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "Body-carrying request proof is missing contentDigest".to_string(),
        });
    }
    if let Some(expected) = proof_digest
        && request.get("contentDigest").and_then(Value::as_str) != Some(expected)
    {
        return Err(JacsError::SignatureVerificationFailed {
            reason: "Request body digest does not match proof contentDigest".to_string(),
        });
    }
    let canonical = canonicalize_json_try(&request).map_err(JacsError::from)?;
    let (public_key, algorithm) = public_key_for_method(did_document, verification_method)?;
    verifier.verify_string(&canonical, signature, public_key, Some(algorithm.clone()))?;
    let replay_ttl =
        crate::protocol::replay_ttl_from_rfc3339(created, max_age_seconds, "W3C request proof")?;
    check_and_store_nonce_with_ttl(verification_method, nonce, replay_ttl)?;

    Ok(json!({
        "valid": true,
        "did": did,
        "verificationMethod": verification_method,
        "method": crate::protocol::normalize_http_method(method)?,
        "url": url,
        "signingAlgorithm": algorithm,
        "created": created,
        "nonce": nonce,
        "expectedRequestChecked": expected_method.is_some() || expected_url.is_some()
    }))
}

fn canonical_request_value(
    method: &str,
    url: &str,
    created: &str,
    nonce: &str,
    did: &str,
    verification_method: &str,
    body: Option<&[u8]>,
) -> Result<Value, JacsError> {
    let (scheme, authority, target) = crate::protocol::canonical_request_url_components(url)?;

    let mut request = json!({
        "method": crate::protocol::normalize_http_method(method)?,
        "scheme": scheme,
        "authority": authority,
        "target": target,
        "created": created,
        "nonce": nonce,
        "did": did,
        "verificationMethod": verification_method
    });
    if let Some(body) = body {
        request["contentDigest"] = json!(crate::protocol::request_content_digest(body));
    }
    Ok(request)
}

fn ensure_expected_request_binding(
    request: &Value,
    expected_method: Option<&str>,
    expected_url: Option<&str>,
) -> Result<(), JacsError> {
    if let Some(expected_method) = expected_method {
        let proof_method = request["method"].as_str().unwrap_or_default();
        if crate::protocol::normalize_http_method(expected_method)? != proof_method {
            return Err(JacsError::SignatureVerificationFailed {
                reason: "Request proof method does not match actual request method".to_string(),
            });
        }
    }

    if let Some(expected_url) = expected_url {
        let (scheme, authority, target) =
            crate::protocol::canonical_request_url_components(expected_url)?;
        if request["scheme"].as_str() != Some(scheme.as_str())
            || request["authority"].as_str() != Some(authority.as_str())
            || request["target"].as_str() != Some(target.as_str())
        {
            return Err(JacsError::SignatureVerificationFailed {
                reason: "Request proof target URI does not match actual request URI".to_string(),
            });
        }
    }

    Ok(())
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, JacsError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: field.to_string(),
            reason: "Missing or non-string field".to_string(),
        })
}

fn public_key_for_method(
    did_document: &Value,
    verification_method: &str,
) -> Result<(Vec<u8>, String), JacsError> {
    let methods = did_document["verificationMethod"]
        .as_array()
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "verificationMethod".to_string(),
            reason: "DID document verificationMethod must be an array".to_string(),
        })?;
    let method = methods
        .iter()
        .find(|method| method["id"].as_str() == Some(verification_method))
        .ok_or_else(|| JacsError::KeyNotFound {
            path: format!("verification method '{}'", verification_method),
        })?;
    let algorithm = method["jacsSigningAlgorithm"]
        .as_str()
        .filter(|algorithm| !algorithm.trim().is_empty())
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "verificationMethod.jacsSigningAlgorithm".to_string(),
            reason: "DID verification method must declare its signing algorithm".to_string(),
        })?
        .to_string();
    if let Some(jwk) = method.get("publicKeyJwk") {
        let x = jwk["x"]
            .as_str()
            .ok_or_else(|| JacsError::DocumentMalformed {
                field: "publicKeyJwk.x".to_string(),
                reason: "Missing Ed25519 JWK x coordinate".to_string(),
            })?;
        let public_key = general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|e| JacsError::CryptoError(format!("Invalid JWK public key: {}", e)))?;
        Ok((public_key, algorithm))
    } else {
        let public_key_b64 =
            method["publicKeyBase64"]
                .as_str()
                .ok_or_else(|| JacsError::DocumentMalformed {
                    field: "publicKeyBase64".to_string(),
                    reason: "Missing public key bytes".to_string(),
                })?;
        Ok((base64_decode(public_key_b64)?, algorithm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use serde_json::json;

    fn test_agent() -> Agent {
        // Fixture path keeps request proofs on the Ed25519 OKP JWK branch
        // in the DID document.
        let mut agent = Agent::ephemeral_legacy_ed25519_for_fixtures().expect("ephemeral agent");
        let doc = json!({
            "jacsAgentType": "ai",
            "name": "auth-test",
            "description": "W3C auth test agent"
        });
        agent
            .create_agent_and_load(&doc.to_string(), true, Some("ring-Ed25519"))
            .expect("agent created");
        agent
    }

    #[test]
    fn verification_method_without_algorithm_fails_closed() {
        let method_id = "did:wba:example.com:agent#key-1";
        let did_document = json!({
            "verificationMethod": [{
                "id": method_id,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32])
                }
            }]
        });
        let error = public_key_for_method(&did_document, method_id)
            .expect_err("missing algorithm must not silently become Ed25519");
        assert!(matches!(error, JacsError::DocumentMalformed { .. }));
        assert!(error.to_string().contains("signing algorithm"));
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn request_proof_round_trips() {
        let mut agent = test_agent();
        let did_document = export_did_document(
            &agent,
            W3cDidOptions {
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("did doc");
        let proof = build_request_proof(
            &mut agent,
            W3cRequestProofParams {
                method: "POST".to_string(),
                url: "https://service.example/tasks?debug=true".to_string(),
                body: Some("{\"hello\":\"world\"}".to_string()),
                nonce: Some(format!("nonce-{}", uuid::Uuid::new_v4())),
                created: Some(now_rfc3339()),
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("proof");

        let result = verify_request_proof_value(
            &agent,
            &proof,
            &did_document,
            Some("{\"hello\":\"world\"}"),
            300,
        )
        .expect("verified");

        assert_eq!(result["valid"], true);
    }

    #[derive(Default)]
    struct RecordingReplayStore {
        ttls: std::sync::Mutex<Vec<std::time::Duration>>,
    }

    impl crate::replay::ReplayStore for RecordingReplayStore {
        fn consume(&self, _key: &str, ttl: std::time::Duration) -> Result<bool, JacsError> {
            self.ttls.lock().expect("TTL recording lock").push(ttl);
            Ok(true)
        }

        fn name(&self) -> &'static str {
            "w3c-ttl-recording-test"
        }

        fn scope(&self) -> crate::replay::ReplayStoreScope {
            crate::replay::ReplayStoreScope::Shared
        }
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn request_proof_replay_retention_matches_max_age() {
        let recording = std::sync::Arc::new(RecordingReplayStore::default());
        let mut agent = test_agent();
        let did_document = export_did_document(
            &agent,
            W3cDidOptions {
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("did doc");
        let proof = build_request_proof(
            &mut agent,
            W3cRequestProofParams {
                method: "POST".to_string(),
                url: "https://service.example/tasks".to_string(),
                body: Some("payload".to_string()),
                nonce: Some(format!("ttl-{}", uuid::Uuid::new_v4())),
                created: Some(now_rfc3339()),
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("proof");

        let previous = crate::replay::install_replay_store(recording.clone())
            .expect("install recording replay store");
        let result =
            verify_request_proof_value(&agent, &proof, &did_document, Some("payload"), 937);
        crate::replay::install_replay_store(previous).expect("restore replay store");
        result.expect("request proof should verify");

        let ttls = recording.ttls.lock().expect("TTL recording lock");
        assert_eq!(ttls.len(), 1);
        assert!((937..=938).contains(&ttls[0].as_secs()));
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn request_proof_replay_retention_covers_accepted_future_clock_skew() {
        let recording = std::sync::Arc::new(RecordingReplayStore::default());
        let mut agent = test_agent();
        let did_document = export_did_document(
            &agent,
            W3cDidOptions {
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("did doc");
        let proof = build_request_proof(
            &mut agent,
            W3cRequestProofParams {
                method: "POST".to_string(),
                url: "https://service.example/tasks".to_string(),
                body: Some("payload".to_string()),
                nonce: Some(format!("future-ttl-{}", uuid::Uuid::new_v4())),
                created: Some((chrono::Utc::now() + chrono::Duration::seconds(120)).to_rfc3339()),
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("proof");
        let max_age = 60;

        let previous = crate::replay::install_replay_store(recording.clone())
            .expect("install recording replay store");
        let result =
            verify_request_proof_value(&agent, &proof, &did_document, Some("payload"), max_age);
        crate::replay::install_replay_store(previous).expect("restore replay store");
        result.expect("proof within accepted future skew should verify");

        let ttls = recording.ttls.lock().expect("TTL recording lock");
        assert_eq!(ttls.len(), 1);
        assert!(ttls[0] > std::time::Duration::from_secs(max_age));
        assert!(ttls[0] <= std::time::Duration::from_secs(max_age + 121));
    }

    #[test]
    fn request_proof_rejects_body_substitution() {
        let mut agent = test_agent();
        let did_document = export_did_document(
            &agent,
            W3cDidOptions {
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("did doc");
        let proof = build_request_proof(
            &mut agent,
            W3cRequestProofParams {
                method: "POST".to_string(),
                url: "https://service.example/tasks".to_string(),
                body: Some("original".to_string()),
                nonce: Some(format!("nonce-{}", uuid::Uuid::new_v4())),
                created: Some(now_rfc3339()),
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("proof");

        let result =
            verify_request_proof_value(&agent, &proof, &did_document, Some("tampered"), 300);
        assert!(result.is_err());
    }

    #[test]
    #[serial_test::serial(replay_store)]
    fn invalid_signature_does_not_consume_nonce() {
        let mut agent = test_agent();
        let did_document = export_did_document(
            &agent,
            W3cDidOptions {
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("did doc");
        let proof = build_request_proof(
            &mut agent,
            W3cRequestProofParams {
                method: "GET".to_string(),
                url: "https://service.example/tasks".to_string(),
                body: None,
                nonce: Some(format!("nonce-{}", uuid::Uuid::new_v4())),
                created: Some(now_rfc3339()),
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("proof");
        let mut tampered = proof.clone();
        tampered["signature"] = json!("not-a-valid-signature");

        let bad_result = verify_request_proof_value(&agent, &tampered, &did_document, None, 300);
        assert!(bad_result.is_err());

        let good_result = verify_request_proof_value(&agent, &proof, &did_document, None, 300);
        assert!(good_result.is_ok());
    }

    #[test]
    fn request_proof_rejects_mismatched_actual_request() {
        let mut agent = test_agent();
        let did_document = export_did_document(
            &agent,
            W3cDidOptions {
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("did doc");
        let proof = build_request_proof(
            &mut agent,
            W3cRequestProofParams {
                method: "POST".to_string(),
                url: "https://service.example/tasks".to_string(),
                body: Some("payload".to_string()),
                nonce: Some(format!("nonce-{}", uuid::Uuid::new_v4())),
                created: Some(now_rfc3339()),
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("proof");

        let result = verify_request_proof_value_for_request(
            &agent,
            &proof,
            &did_document,
            Some("payload"),
            300,
            Some("POST"),
            Some("https://service.example/other"),
        );
        assert!(result.is_err());
    }
}
