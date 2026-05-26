//! Protocol-neutral public agent metadata projection.
//!
//! This module is intentionally free of A2A, DID, JSON-LD, and W3C-specific
//! types. Protocol exporters consume this one normalized view so they do not
//! each scrape raw JACS agent JSON differently.

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::crypt::{base64_encode, hash::hash_public_key, supported_verification_algorithms};
use crate::error::JacsError;
use crate::schema::utils::ValueExt;
use serde::{Deserialize, Serialize};

/// Public, protocol-neutral metadata about a loaded JACS agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicAgentProjection {
    pub jacs_id: String,
    pub jacs_version: String,
    pub jacs_lookup_id: String,
    pub agent_type: Option<String>,
    pub name: String,
    pub description: String,
    pub domain: Option<String>,
    pub origin: Option<String>,
    pub default_endpoint: String,
    pub public_key: Vec<u8>,
    pub public_key_base64: String,
    pub public_key_hash: String,
    pub key_algorithm: String,
    pub verification_algorithms: Vec<String>,
}

impl PublicAgentProjection {
    /// Build a protocol-neutral projection from the currently loaded agent.
    pub fn from_agent(agent: &Agent) -> Result<Self, JacsError> {
        let value = agent.get_value().ok_or("Agent value not loaded")?;
        let jacs_id = agent.get_id()?;
        let jacs_version = agent.get_version()?;
        let jacs_lookup_id = agent.get_lookup_id()?;
        let public_key = agent.get_public_key()?;
        let public_key_base64 = base64_encode(&public_key);
        let public_key_hash = hash_public_key(&public_key);
        let key_algorithm = agent
            .get_key_algorithm()
            .cloned()
            .or_else(|| {
                agent
                    .config
                    .as_ref()
                    .and_then(|config| config.jacs_agent_key_algorithm().clone())
            })
            .unwrap_or_else(|| "unknown".to_string());

        let name = value
            .get_str("jacsName")
            .or_else(|| value.get_str("name"))
            .unwrap_or_else(|| "Unnamed Agent".to_string());
        let description = value
            .get_str("jacsDescription")
            .or_else(|| value.get_str("description"))
            .unwrap_or_else(|| "JACS-enabled agent".to_string());
        let domain = value
            .get_str("jacsAgentDomain")
            .or_else(|| value.get_str("domain"))
            .or_else(|| {
                agent
                    .config
                    .as_ref()
                    .and_then(|config| config.jacs_agent_domain().clone())
            });
        let origin = domain.as_deref().map(domain_to_origin);
        let default_endpoint = match &origin {
            Some(origin) => format!("{}/agent/{}", origin.trim_end_matches('/'), jacs_id),
            None => format!("https://agent-{}.jacs.localhost", jacs_id),
        };

        Ok(Self {
            jacs_id,
            jacs_version,
            jacs_lookup_id,
            agent_type: value.get_str("jacsAgentType"),
            name,
            description,
            domain,
            origin,
            default_endpoint,
            public_key,
            public_key_base64,
            public_key_hash,
            key_algorithm,
            verification_algorithms: supported_verification_algorithms()
                .into_iter()
                .map(str::to_string)
                .collect(),
        })
    }
}

fn domain_to_origin(domain: &str) -> String {
    let trimmed = domain.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use serde_json::json;

    #[test]
    fn projection_extracts_public_agent_metadata() {
        let mut agent = Agent::ephemeral("ring-Ed25519").expect("ephemeral agent");
        let agent_doc = json!({
            "jacsAgentType": "ai",
            "name": "projection-test",
            "description": "public projection test"
        });
        agent
            .create_agent_and_load(&agent_doc.to_string(), true, Some("ring-Ed25519"))
            .expect("agent created");

        let projection = PublicAgentProjection::from_agent(&agent).expect("projection");

        assert_eq!(projection.name, "projection-test");
        assert_eq!(projection.description, "public projection test");
        assert_eq!(projection.agent_type.as_deref(), Some("ai"));
        assert_eq!(projection.domain, None);
        assert_eq!(projection.origin, None);
        assert_eq!(
            projection.default_endpoint,
            format!("https://agent-{}.jacs.localhost", projection.jacs_id)
        );
        assert_eq!(projection.key_algorithm, "ring-Ed25519");
        assert!(!projection.public_key.is_empty());
        assert!(!projection.public_key_base64.is_empty());
        assert!(!projection.public_key_hash.is_empty());
        assert!(
            projection
                .verification_algorithms
                .contains(&"ring-Ed25519".to_string())
        );
    }

    #[test]
    fn domain_to_origin_adds_https_for_plain_domains() {
        assert_eq!(domain_to_origin("example.com"), "https://example.com");
        assert_eq!(
            domain_to_origin("https://example.com/"),
            "https://example.com"
        );
    }
}
