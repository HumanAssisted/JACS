//! Agent Card export functionality for A2A integration (v0.4.0)

use crate::a2a::{
    A2A_PROTOCOL_VERSION, AgentCapabilities, AgentCard, AgentExtension, AgentInterface, AgentSkill,
    JACS_EXTENSION_URI, SecurityScheme,
};
use crate::agent::Agent;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::error::Error;

/// Export a JACS agent as an A2A Agent Card (v0.4.0)
pub fn export_agent_card(agent: &Agent) -> Result<AgentCard, Box<dyn Error>> {
    let agent_value = agent.get_value().ok_or("Agent value not loaded")?;

    // Extract basic agent information
    let name = agent_value
        .get("jacsName")
        .and_then(|v| v.as_str())
        .unwrap_or("Unnamed Agent");

    let description = agent_value
        .get("jacsDescription")
        .and_then(|v| v.as_str())
        .unwrap_or("JACS-enabled agent");

    let agent_id = agent_value
        .get("jacsId")
        .and_then(|v| v.as_str())
        .ok_or("Agent ID not found")?;

    let agent_version = agent_value
        .get("jacsVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("1");

    // Build supported interfaces from jacsAgentDomain or agent ID
    let base_url = if let Some(domain) = agent_value.get("jacsAgentDomain").and_then(|d| d.as_str())
    {
        format!("https://{}/agent/{}", domain, agent_id)
    } else {
        format!("https://agent-{}.jacs.localhost", agent_id)
    };

    let supported_interfaces = vec![AgentInterface {
        url: base_url.clone(),
        protocol_binding: "jsonrpc".to_string(),
        tenant: None,
    }];

    // Convert JACS services to A2A skills
    let skills = convert_services_to_skills(agent_value)?;

    // Define security schemes as a keyed map
    let mut security_schemes = HashMap::new();
    security_schemes.insert(
        "bearer-jwt".to_string(),
        SecurityScheme::Http {
            scheme: "Bearer".to_string(),
            bearer_format: Some("JWT".to_string()),
        },
    );
    security_schemes.insert(
        "api-key".to_string(),
        SecurityScheme::ApiKey {
            location: "header".to_string(),
            name: "X-API-Key".to_string(),
        },
    );

    // Create JACS extension
    let jacs_extension = create_jacs_extension(agent)?;

    let capabilities = AgentCapabilities {
        streaming: None,
        push_notifications: None,
        extended_agent_card: None,
        extensions: Some(vec![jacs_extension]),
    };

    // Create metadata with agent type and additional info
    let metadata = json!({
        "jacsAgentType": agent_value.get("jacsAgentType"),
        "jacsId": agent_id,
        "jacsVersion": agent_value.get("jacsVersion"),
    });

    Ok(AgentCard {
        name: name.to_string(),
        description: description.to_string(),
        version: agent_version.to_string(),
        protocol_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
        supported_interfaces,
        default_input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
        default_output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
        capabilities,
        skills,
        provider: None,
        documentation_url: None,
        icon_url: None,
        security_schemes: Some(security_schemes),
        security: None,
        signatures: None,
        metadata: Some(metadata),
    })
}

/// Convert JACS services to A2A skills (v0.4.0)
fn convert_services_to_skills(agent_value: &Value) -> Result<Vec<AgentSkill>, Box<dyn Error>> {
    let mut skills = Vec::new();

    if let Some(services) = agent_value.get("jacsServices").and_then(|v| v.as_array()) {
        for service in services {
            // Extract service name and description
            let service_name = service
                .get("name")
                .or_else(|| service.get("serviceDescription"))
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed_service");

            let service_desc = service
                .get("serviceDescription")
                .and_then(|v| v.as_str())
                .unwrap_or("No description available");

            // Convert tools to skills
            if let Some(tools) = service.get("tools").and_then(|v| v.as_array()) {
                for tool in tools {
                    if let Some(function) = tool.get("function") {
                        let fn_name = function
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or(service_name);

                        let fn_desc = function
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or(service_desc);

                        let skill = AgentSkill {
                            id: slugify(fn_name),
                            name: fn_name.to_string(),
                            description: fn_desc.to_string(),
                            tags: derive_tags(service_name, fn_name),
                            examples: None,
                            input_modes: None,
                            output_modes: None,
                            security: None,
                        };
                        skills.push(skill);
                    }
                }
            } else {
                // Create a skill for the service itself if no tools are defined
                let skill = AgentSkill {
                    id: slugify(service_name),
                    name: service_name.to_string(),
                    description: service_desc.to_string(),
                    tags: derive_tags(service_name, service_name),
                    examples: None,
                    input_modes: None,
                    output_modes: None,
                    security: None,
                };
                skills.push(skill);
            }
        }
    }

    // If no services/skills found, add a default verification skill
    if skills.is_empty() {
        skills.push(AgentSkill {
            id: "verify-signature".to_string(),
            name: "verify_signature".to_string(),
            description: "Verify JACS document signatures".to_string(),
            tags: vec![
                "jacs".to_string(),
                "verification".to_string(),
                "cryptography".to_string(),
            ],
            examples: Some(vec![
                "Verify a signed JACS document".to_string(),
                "Check document signature integrity".to_string(),
            ]),
            input_modes: Some(vec!["application/json".to_string()]),
            output_modes: Some(vec!["application/json".to_string()]),
            security: None,
        });
    }

    Ok(skills)
}

/// Create JACS extension for A2A capabilities (v0.4.0)
fn create_jacs_extension(agent: &Agent) -> Result<AgentExtension, Box<dyn Error>> {
    let key_algorithm = agent.get_key_algorithm().ok_or("Key algorithm not set")?;

    let is_pqc = key_algorithm.contains("dilithium")
        || key_algorithm.contains("falcon")
        || key_algorithm.contains("sphincs");

    let desc = if is_pqc {
        "JACS cryptographic document signing and verification with post-quantum support"
    } else {
        "JACS cryptographic document signing and verification"
    };

    Ok(AgentExtension {
        uri: JACS_EXTENSION_URI.to_string(),
        description: Some(desc.to_string()),
        required: Some(false),
    })
}

/// Create an extension descriptor for JACS provenance.
///
/// This is a JACS-specific document served at the extension descriptor URL;
/// it is separate from the AgentExtension declaration in the AgentCard.
pub fn create_extension_descriptor() -> Value {
    json!({
        "uri": JACS_EXTENSION_URI,
        "name": "JACS Document Provenance",
        "version": "1.0",
        "a2aProtocolVersion": A2A_PROTOCOL_VERSION,
        "description": "Provides cryptographic document signing and verification with post-quantum support",
        "specification": "https://hai.ai/jacs/specs/a2a-extension",
        "capabilities": {
            "documentSigning": {
                "description": "Sign documents with JACS signatures",
                "algorithms": ["dilithium", "falcon", "sphincs+", "rsa", "ecdsa"],
                "formats": ["jacs-v1", "jws-detached"]
            },
            "documentVerification": {
                "description": "Verify JACS signatures on documents",
                "offlineCapable": true,
                "chainOfCustody": true
            },
            "postQuantumCrypto": {
                "description": "Support for quantum-resistant signatures",
                "algorithms": ["dilithium", "falcon", "sphincs+"]
            }
        },
        "endpoints": {
            "sign": {
                "path": "/jacs/sign",
                "method": "POST",
                "description": "Sign a document with JACS"
            },
            "verify": {
                "path": "/jacs/verify",
                "method": "POST",
                "description": "Verify a JACS signature"
            },
            "publicKey": {
                "path": "/.well-known/jacs-pubkey.json",
                "method": "GET",
                "description": "Retrieve agent's public key"
            }
        }
    })
}

/// Convert a name to a URL-friendly slug for skill IDs.
fn slugify(name: &str) -> String {
    name.to_lowercase()
        .replace([' ', '_'], "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .collect()
}

/// Derive tags from service/function context.
fn derive_tags(service_name: &str, fn_name: &str) -> Vec<String> {
    let mut tags = vec!["jacs".to_string()];

    // Add service name as a tag if different from function name
    let service_slug = slugify(service_name);
    let fn_slug = slugify(fn_name);
    if service_slug != fn_slug {
        tags.push(service_slug);
    }
    tags.push(fn_slug);

    tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a::JACS_EXTENSION_URI;

    #[test]
    fn test_create_extension_descriptor() {
        let descriptor = create_extension_descriptor();
        assert_eq!(descriptor["uri"], JACS_EXTENSION_URI);
        assert!(descriptor["capabilities"]["postQuantumCrypto"].is_object());
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("Hello World"), "hello-world");
        assert_eq!(slugify("analyze_text"), "analyze-text");
        assert_eq!(slugify("MyFunction123"), "myfunction123");
    }

    #[test]
    fn test_derive_tags() {
        let tags = derive_tags("Text Analysis", "analyze_text");
        assert!(tags.contains(&"jacs".to_string()));
        assert!(tags.contains(&"text-analysis".to_string()));
        assert!(tags.contains(&"analyze-text".to_string()));
    }
}
