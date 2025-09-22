//! Agent Card export functionality for A2A integration

use crate::a2a::{
    A2A_PROTOCOL_VERSION, AgentCard, Capabilities, Extension, JACS_EXTENSION_URI, SecurityScheme,
    Skill,
};
use crate::agent::Agent;
use serde_json::{Value, json};
use std::error::Error;

/// Export a JACS agent as an A2A Agent Card
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

    // Determine agent URL from config or use a default
    let url = format!("https://agent-{}.example.com", agent_id);

    // Convert JACS services to A2A skills
    let skills = convert_services_to_skills(agent_value)?;

    // Define security schemes
    let security_schemes = vec![
        SecurityScheme {
            r#type: "http".to_string(),
            scheme: "bearer".to_string(),
            bearer_format: Some("JWT".to_string()),
        },
        SecurityScheme {
            r#type: "apiKey".to_string(),
            scheme: "X-API-Key".to_string(),
            bearer_format: None,
        },
    ];

    // Create JACS extension
    let jacs_extension = create_jacs_extension(agent, &url)?;

    let capabilities = Capabilities {
        extensions: Some(vec![jacs_extension]),
    };

    // Create metadata with agent type and additional info
    let metadata = json!({
        "jacsAgentType": agent_value.get("jacsAgentType"),
        "jacsId": agent_id,
        "jacsVersion": agent_value.get("jacsVersion"),
    });

    Ok(AgentCard {
        protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        url,
        name: name.to_string(),
        description: description.to_string(),
        skills,
        security_schemes,
        capabilities,
        metadata: Some(metadata),
    })
}

/// Convert JACS services to A2A skills
fn convert_services_to_skills(agent_value: &Value) -> Result<Vec<Skill>, Box<dyn Error>> {
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
                        let skill = Skill {
                            name: function
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or(service_name)
                                .to_string(),
                            description: function
                                .get("description")
                                .and_then(|v| v.as_str())
                                .unwrap_or(service_desc)
                                .to_string(),
                            endpoint: tool
                                .get("url")
                                .and_then(|v| v.as_str())
                                .unwrap_or("/api/tool")
                                .to_string(),
                            input_schema: function.get("parameters").cloned(),
                            output_schema: None, // JACS doesn't define output schemas
                        };
                        skills.push(skill);
                    }
                }
            } else {
                // Create a skill for the service itself if no tools are defined
                let skill = Skill {
                    name: service_name.to_string(),
                    description: service_desc.to_string(),
                    endpoint: format!(
                        "/api/service/{}",
                        service_name.to_lowercase().replace(" ", "_")
                    ),
                    input_schema: None,
                    output_schema: None,
                };
                skills.push(skill);
            }
        }
    }

    // If no services/skills found, add a default verification skill
    if skills.is_empty() {
        skills.push(Skill {
            name: "verify_signature".to_string(),
            description: "Verify JACS document signatures".to_string(),
            endpoint: "/jacs/verify".to_string(),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "document": {
                        "type": "object",
                        "description": "The JACS document to verify"
                    }
                },
                "required": ["document"]
            })),
            output_schema: Some(json!({
                "type": "object",
                "properties": {
                    "valid": {
                        "type": "boolean",
                        "description": "Whether the signature is valid"
                    },
                    "signerInfo": {
                        "type": "object",
                        "description": "Information about the signer"
                    }
                }
            })),
        });
    }

    Ok(skills)
}

/// Create JACS extension for A2A capabilities
fn create_jacs_extension(agent: &Agent, base_url: &str) -> Result<Extension, Box<dyn Error>> {
    let key_algorithm = agent.get_key_algorithm().ok_or("Key algorithm not set")?;

    // Determine supported algorithms based on JACS config
    let mut supported_algorithms = vec![];

    // Add the current algorithm
    match key_algorithm.as_str() {
        "dilithium" | "falcon" | "sphincs+" => {
            supported_algorithms.push(key_algorithm.clone());
            // Also support traditional algorithms for compatibility
            supported_algorithms.push("rsa".to_string());
            supported_algorithms.push("ecdsa".to_string());
        }
        "rsa" | "ecdsa" | "eddsa" => {
            supported_algorithms.push(key_algorithm.clone());
        }
        _ => {
            supported_algorithms.push("rsa".to_string());
        }
    }

    let extension = Extension {
        uri: JACS_EXTENSION_URI.to_string(),
        description: "JACS cryptographic document signing and verification".to_string(),
        required: false,
        params: json!({
            "jacsDescriptorUrl": format!("{}/.well-known/jacs-agent.json", base_url),
            "signatureType": if key_algorithm.contains("dilithium") || key_algorithm.contains("falcon") || key_algorithm.contains("sphincs") {
                "JACS_PQC"
            } else {
                "JACS_STANDARD"
            },
            "supportedAlgorithms": supported_algorithms,
            "verificationEndpoint": "/jacs/verify",
            "signatureEndpoint": "/jacs/sign",
            "publicKeyEndpoint": "/.well-known/jacs-pubkey.json"
        }),
    };

    Ok(extension)
}

/// Create an extension descriptor for JACS provenance
pub fn create_extension_descriptor() -> Value {
    json!({
        "uri": JACS_EXTENSION_URI,
        "name": "JACS Document Provenance",
        "version": "1.0",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_extension_descriptor() {
        let descriptor = create_extension_descriptor();
        assert_eq!(descriptor["uri"], JACS_EXTENSION_URI);
        assert!(descriptor["capabilities"]["postQuantumCrypto"].is_object());
    }
}
