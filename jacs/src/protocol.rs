//! JACS protocol helpers shared across SDKs.
//!
//! This module provides building blocks that every JACS-aware client needs:
//!
//! * [`canonicalize_json`] -- deterministic JSON serialization (RFC 8785) via
//!   `serde_json_canonicalizer`.
//! * [`build_auth_header`] -- construct the `Authorization: JACS ...` header
//!   value used by all HAI SDK language implementations.
//! * [`sign_response`] -- build and sign a JACS response envelope.
//! * [`encode_verify_payload`] / [`decode_verify_payload`] -- URL-safe base64
//!   encoding/decoding for verification payloads.
//! * [`extract_document_id`] -- extract document ID for hosted verification.

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::crypt::KeyManager;
use crate::time_utils::now_rfc3339;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Deterministically serialize a [`serde_json::Value`] per RFC 8785 (JCS).
///
/// Returns `"null"` if canonicalization fails (should not happen for valid
/// `Value` inputs).
pub fn canonicalize_json(value: &serde_json::Value) -> String {
    serde_json_canonicalizer::to_string(value).unwrap_or_else(|_| "null".to_string())
}

/// Build the JACS `Authorization` header value.
///
/// Format: `"JACS {jacs_id}:{unix_timestamp}:{base64_signature}"`
///
/// The signed message is `"{jacs_id}:{unix_timestamp}"` where `jacs_id` is the
/// agent's lookup ID (`{id}:{version}`) and the timestamp is seconds since the
/// Unix epoch.
///
/// This matches the format used by all four HAI SDK language implementations
/// (Rust, Python, Node, Go).
pub fn build_auth_header(agent: &mut Agent) -> Result<String, Box<dyn Error>> {
    let jacs_id = agent.get_lookup_id()?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("build_auth_header: system clock error: {}", e))?
        .as_secs();
    let message = format!("{jacs_id}:{ts}");
    let signature = agent.sign_string(&message)?;
    Ok(format!("JACS {jacs_id}:{ts}:{signature}"))
}

/// Build and sign a JACS response envelope.
///
/// The envelope format matches the HAI SDK `sign_response` contract:
///
/// ```json
/// {
///   "version": "1.0.0",
///   "document_type": "job_response",
///   "data": <canonicalized payload>,
///   "metadata": {
///     "issuer": "<jacs_id>",
///     "document_id": "<uuid-v4>",
///     "created_at": "<rfc3339>",
///     "hash": "<sha256-hex>"
///   },
///   "jacsSignature": {
///     "agentID": "<jacs_id>",
///     "date": "<rfc3339>",
///     "signature": "<base64-signature>"
///   }
/// }
/// ```
pub fn sign_response(agent: &mut Agent, payload: &Value) -> Result<Value, Box<dyn Error>> {
    let jacs_id = agent.get_lookup_id()?;
    let now = now_rfc3339();
    let canonical = canonicalize_json(payload);

    // SHA-256 hex digest of the canonical bytes
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    };

    let signature = agent.sign_string(&canonical)?;

    let data: Value = serde_json::from_str(&canonical)
        .map_err(|e| format!("sign_response: failed to re-parse canonical JSON: {e}"))?;

    let envelope = serde_json::json!({
        "version": "1.0.0",
        "document_type": "job_response",
        "data": data,
        "metadata": {
            "issuer": jacs_id,
            "document_id": Uuid::new_v4().to_string(),
            "created_at": now,
            "hash": hash,
        },
        "jacsSignature": {
            "agentID": jacs_id,
            "date": now,
            "signature": signature,
        },
    });

    Ok(envelope)
}

/// Encode a document as URL-safe base64 (no padding) for use in verification
/// links.
///
/// This is the JACS-level primitive. SDK clients are responsible for
/// constructing the full URL (e.g. `https://hai.ai/jacs/verify?s={encoded}`).
pub fn encode_verify_payload(document: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(document.as_bytes())
}

/// Decode a URL-safe base64 (no padding) verification payload back to the
/// original document string.
pub fn decode_verify_payload(encoded: &str) -> Result<String, Box<dyn Error>> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| format!("decode_verify_payload: invalid base64url: {e}"))?;
    String::from_utf8(bytes)
        .map_err(|e| format!("decode_verify_payload: invalid UTF-8: {e}").into())
}

/// Extract the document ID from a JACS-signed document.
///
/// Checks fields in priority order: `jacsDocumentId`, `document_id`, `id`.
///
/// SDK clients use this to build hosted verification URLs
/// (e.g. `https://hai.ai/verify/{id}`).
pub fn extract_document_id(document: &str) -> Result<String, Box<dyn Error>> {
    let value: Value = serde_json::from_str(document)
        .map_err(|e| format!("extract_document_id: invalid JSON: {e}"))?;

    let doc_id = value
        .get("jacsDocumentId")
        .and_then(Value::as_str)
        .or_else(|| value.get("document_id").and_then(Value::as_str))
        .or_else(|| value.get("id").and_then(Value::as_str));

    doc_id.map(String::from).ok_or_else(|| {
        "extract_document_id: no ID field found (expected jacsDocumentId, document_id, or id)"
            .into()
    })
}

/// Unwrap a JACS-signed event, verifying the signature when the signer's
/// public key is known.
///
/// This matches the behaviour of `unwrapSignedEvent` (Node) and
/// `unwrap_signed_event` (Python) in the HAI SDK.
///
/// # Formats recognised
///
/// 1. **Canonical JacsDocument** -- `{data, jacsSignature, ...}`.
///    The `jacsSignature.agentID` is looked up in `server_public_keys`.
///    * **Known key**: the signature over `canonicalize_json(data)` is
///      verified. Returns `(data, true)` on success, or an error on failure.
///    * **Unknown key**: returns `(data, false)` -- unverified but not an
///      error.
///
/// 2. **Legacy format** -- `{payload, ...}`.
///    Returns `(payload, false)`.
///
/// 3. **Unrecognised** -- returns `(event.clone(), false)`.
///
/// # Arguments
///
/// * `agent`              -- an initialised JACS agent used for verification.
/// * `event`              -- the parsed JSON event to unwrap.
/// * `server_public_keys` -- map of `agent_id -> public_key_bytes`
///   (raw bytes, the same encoding that `KeyManager::verify_string` expects).
pub fn unwrap_signed_event(
    agent: &Agent,
    event: &Value,
    server_public_keys: &HashMap<String, Vec<u8>>,
) -> Result<(Value, bool), Box<dyn Error>> {
    // --- Format 1: Canonical JacsDocument {data, jacsSignature} ---
    if let (Some(data), Some(jacs_sig)) = (event.get("data"), event.get("jacsSignature")) {
        let agent_id = jacs_sig
            .get("agentID")
            .and_then(Value::as_str)
            .unwrap_or("");

        if let Some(public_key) = server_public_keys.get(agent_id) {
            // Known key -- verify signature
            let signature = jacs_sig
                .get("signature")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "unwrap_signed_event: jacsSignature for agentID=\"{}\" is missing \"signature\" field",
                        agent_id
                    )
                })?;

            let signing_algorithm = jacs_sig
                .get("signingAlgorithm")
                .and_then(Value::as_str)
                .map(String::from);

            let canonical = canonicalize_json(data);

            agent
                .verify_string(&canonical, signature, public_key.clone(), signing_algorithm)
                .map_err(|e| {
                    format!(
                        "JACS signature verification failed for agentID=\"{}\": {}",
                        agent_id, e
                    )
                })?;

            return Ok((data.clone(), true));
        }

        // Unknown key -- return data unverified
        return Ok((data.clone(), false));
    }

    // --- Format 2: Legacy {payload} ---
    if let Some(payload) = event.get("payload") {
        return Ok((payload.clone(), false));
    }

    // --- Format 3: Unrecognised ---
    Ok((event.clone(), false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- canonicalize_json tests ----

    #[test]
    fn canonicalize_sorts_keys() {
        let input = json!({"b": 2, "a": 1});
        let result = canonicalize_json(&input);
        assert_eq!(result, r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonicalize_nested_objects() {
        let input = json!({"z": {"b": 2, "a": 1}, "a": 0});
        let result = canonicalize_json(&input);
        assert_eq!(result, r#"{"a":0,"z":{"a":1,"b":2}}"#);
    }

    #[test]
    fn canonicalize_null() {
        let input = json!(null);
        let result = canonicalize_json(&input);
        assert_eq!(result, "null");
    }

    #[test]
    fn canonicalize_empty_object() {
        let input = json!({});
        let result = canonicalize_json(&input);
        assert_eq!(result, "{}");
    }

    #[test]
    fn canonicalize_empty_array() {
        let input = json!([]);
        let result = canonicalize_json(&input);
        assert_eq!(result, "[]");
    }

    // ---- build_auth_header tests ----
    //
    // These tests require a fully initialized agent with keys, so they use
    // the same test harness pattern as the rest of the JACS crate. We test
    // the output format only (not the cryptographic validity -- that is
    // covered by the crypt module tests).

    /// Helper: create an ephemeral agent with keys for testing.
    fn make_test_agent() -> Agent {
        let mut agent = Agent::ephemeral("ring-Ed25519").expect("Failed to create ephemeral agent");

        let agent_string = crate::create_minimal_blank_agent("ai".to_string(), None, None, None)
            .expect("Failed to create minimal agent JSON");

        agent
            .create_agent_and_load(&agent_string, true, Some("ring-Ed25519"))
            .expect("Failed to create and load agent");

        agent
    }

    #[test]
    fn auth_header_starts_with_jacs_prefix() {
        let mut agent = make_test_agent();
        let header = build_auth_header(&mut agent).expect("build_auth_header failed");
        assert!(
            header.starts_with("JACS "),
            "Header must start with 'JACS ', got: {header}"
        );
    }

    #[test]
    fn auth_header_has_three_colon_separated_parts() {
        let mut agent = make_test_agent();
        let header = build_auth_header(&mut agent).expect("build_auth_header failed");
        // Strip the "JACS " prefix
        let payload = header
            .strip_prefix("JACS ")
            .expect("Missing 'JACS ' prefix");
        // The payload is {id}:{version}:{timestamp}:{signature}
        // where jacs_id = {id}:{version}, so there are 3 colons total.
        let parts: Vec<&str> = payload.splitn(4, ':').collect();
        assert_eq!(
            parts.len(),
            4,
            "Expected 4 colon-separated parts (id:version:timestamp:sig), got {}: {:?}",
            parts.len(),
            parts
        );
    }

    #[test]
    fn auth_header_timestamp_is_recent() {
        let mut agent = make_test_agent();
        let header = build_auth_header(&mut agent).expect("build_auth_header failed");
        let payload = header
            .strip_prefix("JACS ")
            .expect("Missing 'JACS ' prefix");
        // jacs_id is "uuid:version", so third part is the timestamp
        let parts: Vec<&str> = payload.splitn(4, ':').collect();
        let ts: u64 = parts[2].parse().expect("Timestamp should be a u64");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            now.abs_diff(ts) < 5,
            "Timestamp should be within 5 seconds of now"
        );
    }

    #[test]
    fn auth_header_signature_is_nonempty_base64() {
        let mut agent = make_test_agent();
        let header = build_auth_header(&mut agent).expect("build_auth_header failed");
        let payload = header
            .strip_prefix("JACS ")
            .expect("Missing 'JACS ' prefix");
        let parts: Vec<&str> = payload.splitn(4, ':').collect();
        let sig = parts[3];
        assert!(!sig.is_empty(), "Signature must not be empty");
        // Verify it is valid base64
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        STANDARD
            .decode(sig)
            .expect("Signature should be valid base64");
    }

    // ---- sign_response tests ----

    #[test]
    fn sign_response_has_required_top_level_keys() {
        let mut agent = make_test_agent();
        let payload = json!({"answer": 42});
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");

        for key in &[
            "version",
            "document_type",
            "data",
            "metadata",
            "jacsSignature",
        ] {
            assert!(
                envelope.get(key).is_some(),
                "Envelope missing required key: {key}"
            );
        }
    }

    #[test]
    fn sign_response_version_and_document_type() {
        let mut agent = make_test_agent();
        let payload = json!({"foo": "bar"});
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");

        assert_eq!(envelope["version"], "1.0.0");
        assert_eq!(envelope["document_type"], "job_response");
    }

    #[test]
    fn sign_response_metadata_has_required_fields() {
        let mut agent = make_test_agent();
        let payload = json!({"x": 1});
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");
        let metadata = &envelope["metadata"];

        for key in &["issuer", "document_id", "created_at", "hash"] {
            assert!(
                metadata.get(key).is_some(),
                "metadata missing required field: {key}"
            );
        }

        // hash should be a non-empty hex string (64 hex chars for SHA-256)
        let hash = metadata["hash"].as_str().expect("hash should be string");
        assert_eq!(hash.len(), 64, "SHA-256 hex hash should be 64 chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash should be valid hex"
        );
    }

    #[test]
    fn sign_response_jacs_signature_has_required_fields() {
        let mut agent = make_test_agent();
        let payload = json!({"y": 2});
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");
        let sig = &envelope["jacsSignature"];

        for key in &["agentID", "date", "signature"] {
            assert!(
                sig.get(key).is_some(),
                "jacsSignature missing required field: {key}"
            );
        }

        let signature = sig["signature"]
            .as_str()
            .expect("signature should be string");
        assert!(!signature.is_empty(), "signature must not be empty");
    }

    // ---- encode/decode verify payload tests ----

    #[test]
    fn encode_verify_payload_uses_url_safe_base64_no_padding() {
        let encoded = encode_verify_payload(r#"{"k":">>>>"}"#);
        assert!(!encoded.contains('+'), "URL-safe base64 must not contain +");
        assert!(!encoded.contains('/'), "URL-safe base64 must not contain /");
        assert!(
            !encoded.contains('='),
            "URL-safe base64 must not contain = (no padding)"
        );
    }

    #[test]
    fn encode_decode_round_trips() {
        let original = r#"{"hello":"world","num":123}"#;
        let encoded = encode_verify_payload(original);
        let decoded = decode_verify_payload(&encoded).expect("should decode");
        assert_eq!(decoded, original);
    }

    // ---- extract_document_id tests ----

    #[test]
    fn extract_id_prefers_jacs_document_id() {
        let doc = r#"{"jacsDocumentId":"preferred","document_id":"fallback","id":"last"}"#;
        let id = extract_document_id(doc).expect("should succeed");
        assert_eq!(id, "preferred");
    }

    #[test]
    fn extract_id_falls_back_to_document_id() {
        let doc = r#"{"document_id":"def-456"}"#;
        let id = extract_document_id(doc).expect("should succeed");
        assert_eq!(id, "def-456");
    }

    #[test]
    fn extract_id_falls_back_to_id() {
        let doc = r#"{"id":"ghi-789"}"#;
        let id = extract_document_id(doc).expect("should succeed");
        assert_eq!(id, "ghi-789");
    }

    #[test]
    fn extract_id_errors_when_no_id_field() {
        let doc = r#"{"name":"no-id-here"}"#;
        let result = extract_document_id(doc);
        assert!(result.is_err(), "Should error when no ID field is present");
    }

    #[test]
    fn extract_id_errors_on_invalid_json() {
        let result = extract_document_id("not json");
        assert!(result.is_err(), "Should error on invalid JSON input");
    }

    // ---- unwrap_signed_event tests ----

    #[test]
    fn unwrap_canonical_with_unknown_agent_returns_data_unverified() {
        let agent = make_test_agent();
        let data = json!({"result": "hello"});
        let event = json!({
            "version": "1.0.0",
            "document_type": "job_response",
            "data": data,
            "metadata": {
                "issuer": "unknown-agent:v1",
                "document_id": "doc-1",
                "created_at": "2026-01-01T00:00:00Z",
                "hash": "abc123",
            },
            "jacsSignature": {
                "agentID": "unknown-agent:v1",
                "date": "2026-01-01T00:00:00Z",
                "signature": "fakesig",
            },
        });

        let keys: HashMap<String, Vec<u8>> = HashMap::new();
        let (result_data, verified) =
            unwrap_signed_event(&agent, &event, &keys).expect("should not error");
        assert_eq!(result_data, data);
        assert!(!verified, "Unknown agent should return verified=false");
    }

    #[test]
    fn unwrap_legacy_payload_returns_payload_unverified() {
        let agent = make_test_agent();
        let payload = json!({"status": "ok", "items": [1, 2, 3]});
        let event = json!({
            "payload": payload,
            "signature": {
                "key_id": "some-key",
                "signature": "irrelevant",
            },
            "metadata": {
                "timestamp": "2026-01-01T00:00:00Z",
            },
        });

        let keys: HashMap<String, Vec<u8>> = HashMap::new();
        let (result_data, verified) =
            unwrap_signed_event(&agent, &event, &keys).expect("should not error");
        assert_eq!(result_data, payload);
        assert!(!verified, "Legacy format should return verified=false");
    }

    #[test]
    fn unwrap_plain_event_returns_event_unverified() {
        let agent = make_test_agent();
        let event = json!({"type": "heartbeat", "ts": 12345});

        let keys: HashMap<String, Vec<u8>> = HashMap::new();
        let (result_data, verified) =
            unwrap_signed_event(&agent, &event, &keys).expect("should not error");
        assert_eq!(result_data, event);
        assert!(!verified, "Plain event should return verified=false");
    }

    #[test]
    fn unwrap_canonical_with_known_key_verifies_signature() {
        // Create a test agent, sign a payload, then verify it via unwrap_signed_event
        let mut agent = make_test_agent();
        let payload = json!({"answer": 42});

        // Use sign_response to create a properly signed envelope
        let envelope = sign_response(&mut agent, &payload).expect("sign_response failed");

        // Extract the agentID from the signed envelope
        let agent_id = envelope["jacsSignature"]["agentID"]
            .as_str()
            .expect("agentID should be a string")
            .to_string();

        // Get the agent's public key (raw bytes)
        let public_key = agent
            .get_public_key()
            .expect("should be able to get public key");

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert(agent_id, public_key);

        let (result_data, verified) =
            unwrap_signed_event(&agent, &envelope, &keys).expect("should not error");

        // The data should be the canonicalized payload
        assert_eq!(result_data["answer"], 42);
        assert!(
            verified,
            "Known key with valid signature should return verified=true"
        );
    }

    #[test]
    fn unwrap_canonical_with_known_key_and_bad_signature_errors() {
        let agent = make_test_agent();
        let data = json!({"result": "tampered"});
        let agent_id = "known-agent:v1".to_string();

        // Use the agent's real public key but a bogus signature
        let public_key = agent
            .get_public_key()
            .expect("should be able to get public key");

        let event = json!({
            "version": "1.0.0",
            "document_type": "job_response",
            "data": data,
            "metadata": {
                "issuer": agent_id,
                "document_id": "doc-bad",
                "created_at": "2026-01-01T00:00:00Z",
                "hash": "000",
            },
            "jacsSignature": {
                "agentID": agent_id,
                "date": "2026-01-01T00:00:00Z",
                "signature": "dGhpcyBpcyBub3QgYSB2YWxpZCBzaWduYXR1cmU=",
            },
        });

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert(agent_id, public_key);

        let result = unwrap_signed_event(&agent, &event, &keys);
        assert!(
            result.is_err(),
            "Known key with bad signature must return an error, not silent false"
        );
    }
}
