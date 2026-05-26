use crate::agent::Agent;
use crate::error::JacsError;
use crate::public_agent::PublicAgentProjection;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1"
        ],
        "id": parts.did,
        "verificationMethod": [
            verification_method
        ],
        "authentication": [
            parts.verification_method
        ],
        "assertionMethod": [
            parts.verification_method
        ],
        "service": [
            {
                "id": format!("{}#agent-desc", parts.did),
                "type": "AgentDescription",
                "serviceEndpoint": format!("{}{}", parts.origin, parts.agent_description_path)
            }
        ],
        "jacs": {
            "jacsId": projection.jacs_id,
            "jacsVersion": projection.jacs_version,
            "jacsLookupId": projection.jacs_lookup_id,
            "publicKeyHash": projection.public_key_hash,
            "keyAlgorithm": projection.key_algorithm
        }
    }))
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
        let mut agent = Agent::ephemeral("ring-Ed25519").expect("ephemeral agent");
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
