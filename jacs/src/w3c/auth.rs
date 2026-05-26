use crate::agent::Agent;
use crate::crypt::{KeyManager, base64_decode};
use crate::error::JacsError;
use crate::protocol::canonicalize_json;
use crate::replay::check_and_store_nonce;
use crate::time_utils::{
    now_rfc3339, validate_timestamp_not_expired, validate_timestamp_not_future,
};
use crate::w3c::did_wba::{W3cDidOptions, export_did_document};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
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
    let canonical = canonicalize_json(&request);
    let signature = agent.sign_string(&canonical)?;

    Ok(json!({
        "type": "JacsW3cRequestProof",
        "scheme": "DIDWba",
        "did": did,
        "verificationMethod": verification_method,
        "created": created,
        "nonce": nonce,
        "method": normalize_method(&params.method),
        "url": params.url,
        "contentDigest": request.get("contentDigest").cloned(),
        "signingInput": request,
        "signingAlgorithm": agent.get_key_algorithm().cloned().unwrap_or_else(|| "unknown".to_string()),
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
    let proof: Value =
        serde_json::from_str(proof_json).map_err(|e| JacsError::DocumentMalformed {
            field: "proof_json".to_string(),
            reason: e.to_string(),
        })?;
    let did_document: Value =
        serde_json::from_str(did_document_json).map_err(|e| JacsError::DocumentMalformed {
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
        && request.get("contentDigest").and_then(Value::as_str) != Some(expected) {
            return Err(JacsError::SignatureVerificationFailed {
                reason: "Request body digest does not match proof contentDigest".to_string(),
            });
        }
    let canonical = canonicalize_json(&request);
    let (public_key, algorithm) = public_key_for_method(did_document, verification_method)?;
    verifier.verify_string(&canonical, signature, public_key, Some(algorithm.clone()))?;
    check_and_store_nonce(verification_method, nonce)?;

    Ok(json!({
        "valid": true,
        "did": did,
        "verificationMethod": verification_method,
        "method": normalize_method(method),
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
    let (scheme, authority, target) = request_url_components(url)?;

    let mut request = json!({
        "method": normalize_method(method),
        "scheme": scheme,
        "authority": authority,
        "target": target,
        "created": created,
        "nonce": nonce,
        "did": did,
        "verificationMethod": verification_method
    });
    if let Some(body) = body {
        request["contentDigest"] = json!(content_digest(body));
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
        if normalize_method(expected_method) != proof_method {
            return Err(JacsError::SignatureVerificationFailed {
                reason: "Request proof method does not match actual request method".to_string(),
            });
        }
    }

    if let Some(expected_url) = expected_url {
        let (scheme, authority, target) = request_url_components(expected_url)?;
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

fn request_url_components(url: &str) -> Result<(String, String, String), JacsError> {
    let parsed = Url::parse(url)
        .map_err(|e| JacsError::ValidationError(format!("Invalid request URL '{}': {}", url, e)))?;
    let authority = parsed
        .host_str()
        .map(|host| match parsed.port() {
            Some(port) => format!("{}:{}", host, port),
            None => host.to_string(),
        })
        .ok_or_else(|| {
            JacsError::ValidationError("Request URL must include authority".to_string())
        })?;
    let mut target = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        target.push('?');
        target.push_str(query);
    }
    Ok((parsed.scheme().to_string(), authority, target))
}

fn content_digest(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("sha-256=:{}:", general_purpose::STANDARD.encode(digest))
}

fn normalize_method(method: &str) -> String {
    method.trim().to_ascii_uppercase()
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
        .unwrap_or("ring-Ed25519")
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
        let mut agent = Agent::ephemeral("ring-Ed25519").expect("ephemeral agent");
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
