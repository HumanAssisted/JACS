use crate::agent::Agent;
use crate::error::JacsError;
use crate::public_agent::PublicAgentProjection;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::info;
use url::Url;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct W3cDidOptions {
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct W3cDidParts {
    pub did: String,
    pub origin: String,
    pub agent_path_segment: String,
    pub verification_method: String,
    pub did_document_path: String,
    pub agent_description_path: String,
}

pub fn export_did_identifier(agent: &Agent) -> Result<String, JacsError> {
    export_did_identifier_with_options(agent, W3cDidOptions::default())
}

pub fn export_did_identifier_with_options(
    agent: &Agent,
    options: W3cDidOptions,
) -> Result<String, JacsError> {
    let projection = PublicAgentProjection::from_agent(agent)?;
    Ok(parts_for_projection(&projection, &options)?.did)
}

pub fn export_did_document(agent: &Agent, options: W3cDidOptions) -> Result<Value, JacsError> {
    let projection = PublicAgentProjection::from_agent(agent)?;
    let parts = parts_for_projection(&projection, &options)?;
    let verification_method = verification_method_for_projection(&projection, &parts);

    let mut verification_methods = vec![verification_method];
    let mut authentication = vec![json!(parts.verification_method)];
    let mut assertion_method = vec![json!(parts.verification_method)];
    let mut jacs_block = json!({
        "jacsId": projection.jacs_id,
        "jacsVersion": projection.jacs_version,
        "jacsLookupId": projection.jacs_lookup_id,
        "publicKeyHash": projection.public_key_hash,
        "keyAlgorithm": projection.key_algorithm
    });

    // P2 Task 004-B: when the agent has an ES256 compatibility key AND a
    // valid PQ-root-signed binding granting the `did` scope, the DID
    // document additionally lists the compat key TWICE for the same key:
    // a `JsonWebKey` entry (publicKeyJwk, JOSE consumers — not the legacy
    // JsonWebKey2020) and a `Multikey` entry (publicKeyMultibase — the
    // type `ecdsa-jcs-2019` Data Integrity verifiers require). The `jacs`
    // block carries the binding reference AS A CONTENT HASH — never a
    // URL; P2 defines no resolution protocol (NG8).
    if let Some(compat_entries) = es256_entries_if_authorized(agent, &parts)? {
        let (jwk_entry, multikey_entry, kid, binding_hash) = compat_entries;
        info!(
            event = "ecosystem_export_generated",
            format = "did",
            jacs_id = %projection.jacs_id,
            kid = %kid,
            binding_hash = %binding_hash,
            "DID document exported with ES256 compatibility verification methods"
        );
        crate::compatibility::record_export_generated("did");
        let jwk_id = jwk_entry["id"].as_str().unwrap_or("").to_string();
        let mk_id = multikey_entry["id"].as_str().unwrap_or("").to_string();
        verification_methods.push(jwk_entry);
        verification_methods.push(multikey_entry);
        authentication.push(json!(jwk_id));
        assertion_method.push(json!(jwk_id));
        assertion_method.push(json!(mk_id));
        jacs_block["compatKid"] = json!(kid);
        jacs_block["compatBindingHash"] = json!(binding_hash);
    }

    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1"
        ],
        "id": parts.did,
        "verificationMethod": verification_methods,
        "authentication": authentication,
        "assertionMethod": assertion_method,
        "service": [
            {
                "id": format!("{}#agent-desc", parts.did),
                "type": "AgentDescription",
                "serviceEndpoint": format!("{}{}", parts.origin, parts.agent_description_path)
            }
        ],
        "jacs": jacs_block
    }))
}

/// Build the two ES256 verification-method entries when (and only when)
/// a valid binding grants the `did` scope. Returns None when the agent
/// has no compat key, no binding, an invalid binding, or no `did` scope —
/// the DID document then keeps its pre-P2 (native-only) shape.
fn es256_entries_if_authorized(
    agent: &Agent,
    parts: &W3cDidParts,
) -> Result<Option<(Value, Value, String, String)>, JacsError> {
    let (compat, binding) =
        match crate::compatibility::binding::compat_enrichment_if_authorized(agent, "did")? {
            Some(pair) => pair,
            None => return Ok(None),
        };

    let public_pem = std::fs::read_to_string(&compat.public_key_path).map_err(|e| {
        JacsError::FileReadFailed {
            path: compat.public_key_path.clone(),
            reason: e.to_string(),
        }
    })?;
    let (x, y) = crate::crypt::es256::jwk_xy_from_spki_pem(&public_pem)?;
    let multibase = crate::crypt::es256::multikey_from_spki_pem(&public_pem)?;
    let binding_hash = binding["jacsSha256"].as_str().unwrap_or("").to_string();

    let jwk_id = format!("{}#{}", parts.did, compat.kid);
    let mk_id = format!("{}#{}-multikey", parts.did, compat.kid);

    let jwk_entry = json!({
        "id": jwk_id,
        "type": "JsonWebKey",
        "controller": parts.did,
        "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "alg": "ES256",
            "kid": compat.kid
        }
    });
    let multikey_entry = json!({
        "id": mk_id,
        "type": "Multikey",
        "controller": parts.did,
        "publicKeyMultibase": multibase
    });

    Ok(Some((jwk_entry, multikey_entry, compat.kid, binding_hash)))
}

pub(crate) fn parts_for_projection(
    projection: &PublicAgentProjection,
    options: &W3cDidOptions,
) -> Result<W3cDidParts, JacsError> {
    let origin = resolve_origin(projection, options)?;
    let url = Url::parse(&origin).map_err(|e| {
        JacsError::ValidationError(format!("Invalid W3C origin '{}': {}", origin, e))
    })?;
    let authority = url.host_str().ok_or_else(|| {
        JacsError::ValidationError(format!("W3C origin '{}' must include a host", origin))
    })?;
    let authority = match url.port() {
        Some(port) => format!("{}%3A{}", authority, port),
        None => authority.to_string(),
    };
    let agent_segment = method_segment(&projection.jacs_id);
    let did = format!("did:wba:{}:agent:{}", authority, agent_segment);
    let key_fragment = projection
        .public_key_hash
        .chars()
        .take(16)
        .collect::<String>();
    let verification_method = format!("{}#jacs-key-{}", did, key_fragment);

    Ok(W3cDidParts {
        did,
        origin,
        agent_path_segment: agent_segment.clone(),
        verification_method,
        did_document_path: did_document_path(&agent_segment),
        agent_description_path: default_agent_description_path(&agent_segment),
    })
}

pub fn did_document_path(agent_path_segment: &str) -> String {
    format!("/agent/{}/did.json", agent_path_segment)
}

pub fn default_agent_description_path(agent_path_segment: &str) -> String {
    format!("/agent/{}/description.json", agent_path_segment)
}

pub(crate) fn resolve_origin(
    projection: &PublicAgentProjection,
    options: &W3cDidOptions,
) -> Result<String, JacsError> {
    let candidate = options
        .origin
        .as_deref()
        .or(projection.origin.as_deref())
        .unwrap_or("https://jacs.localhost");
    let trimmed = candidate.trim().trim_end_matches('/');
    let origin = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };
    let parsed = Url::parse(&origin).map_err(|e| {
        JacsError::ValidationError(format!("Invalid W3C origin '{}': {}", origin, e))
    })?;
    if parsed.host_str().is_none() {
        return Err(JacsError::ValidationError(format!(
            "W3C origin '{}' must include a host",
            origin
        )));
    }
    Ok(origin)
}

fn verification_method_for_projection(
    projection: &PublicAgentProjection,
    parts: &W3cDidParts,
) -> Value {
    if projection.key_algorithm == "ring-Ed25519" && projection.public_key.len() == 32 {
        json!({
            "id": parts.verification_method,
            "type": "JsonWebKey2020",
            "controller": parts.did,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": general_purpose::URL_SAFE_NO_PAD.encode(&projection.public_key),
                "alg": "EdDSA",
                "kid": parts.verification_method
            },
            "jacsSigningAlgorithm": projection.key_algorithm
        })
    } else {
        json!({
            "id": parts.verification_method,
            "type": "JacsVerificationKey2026",
            "controller": parts.did,
            "publicKeyBase64": projection.public_key_base64,
            "jacsSigningAlgorithm": projection.key_algorithm
        })
    }
}

fn method_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use serde_json::json;

    fn test_agent() -> Agent {
        // Fixture hatch: these tests exercise the Ed25519 OKP JWK path
        // (32-byte keys); public ephemeral creation is PQ-only.
        let mut agent = Agent::ephemeral_legacy_ed25519_for_fixtures().expect("ephemeral agent");
        let doc = json!({
            "jacsAgentType": "ai",
            "name": "w3c-test",
            "description": "W3C test agent"
        });
        agent
            .create_agent_and_load(&doc.to_string(), true, Some("ring-Ed25519"))
            .expect("agent created");
        agent
    }

    #[test]
    fn did_identifier_is_stable_for_agent_version_changes() {
        let agent = test_agent();
        let mut projection = PublicAgentProjection::from_agent(&agent).expect("projection");
        let parts_v1 = parts_for_projection(
            &projection,
            &W3cDidOptions {
                origin: Some("https://example.com".into()),
            },
        )
        .expect("parts");

        projection.jacs_version = "rotated-version".to_string();
        projection.jacs_lookup_id = format!("{}:{}", projection.jacs_id, projection.jacs_version);
        let parts_v2 = parts_for_projection(
            &projection,
            &W3cDidOptions {
                origin: Some("https://example.com".into()),
            },
        )
        .expect("parts");

        assert_eq!(parts_v1.did, parts_v2.did);
        assert_eq!(parts_v1.verification_method, parts_v2.verification_method);
    }

    #[test]
    fn did_document_exposes_current_key_material() {
        let agent = test_agent();
        let doc = export_did_document(
            &agent,
            W3cDidOptions {
                origin: Some("https://example.com".to_string()),
            },
        )
        .expect("did doc");

        assert_eq!(
            doc["id"].as_str().unwrap(),
            "did:wba:example.com:agent:".to_string() + doc["jacs"]["jacsId"].as_str().unwrap()
        );
        assert!(doc["verificationMethod"][0]["publicKeyJwk"].is_object());
        assert_eq!(
            doc["authentication"][0].as_str().unwrap(),
            doc["verificationMethod"][0]["id"].as_str().unwrap()
        );
    }
}
