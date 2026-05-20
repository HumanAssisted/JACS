//! Agent Card export functionality for A2A integration (v0.4.0)

use crate::a2a::{
    A2A_PROTOCOL_VERSION, AgentCapabilities, AgentCard, AgentExtension, AgentInterface, AgentSkill,
    JACS_EXTENSION_URI, SecurityScheme,
};
use crate::agent::Agent;
use crate::crypt::{supported_pq_algorithms, supported_verification_algorithms};
use crate::error::JacsError;
use crate::schema::utils::ValueExt;
use serde_json::{Value, json};
use std::collections::HashMap;

/// Export a JACS agent as an A2A Agent Card (v0.4.0)
pub fn export_agent_card(agent: &Agent) -> Result<AgentCard, JacsError> {
    let agent_value = agent.get_value().ok_or("Agent value not loaded")?;

    // Extract basic agent information
    let name = agent_value.get_str_or("jacsName", "Unnamed Agent");
    let description = agent_value.get_str_or("jacsDescription", "JACS-enabled agent");
    let agent_id = agent_value.get_str("jacsId").ok_or("Agent ID not found")?;
    let agent_version = agent_value.get_str_or("jacsVersion", "1");

    // Build supported interfaces from jacsAgentDomain or agent ID
    let base_url = if let Some(domain) = agent_value.get_str("jacsAgentDomain") {
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
    let skills = default_jacs_skills();

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

fn default_jacs_skills() -> Vec<AgentSkill> {
    vec![AgentSkill {
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
    }]
}

/// Create JACS extension for A2A capabilities (v0.4.0)
fn create_jacs_extension(agent: &Agent) -> Result<AgentExtension, JacsError> {
    let key_algorithm = agent.get_key_algorithm().ok_or("Key algorithm not set")?;

    let is_pqc = key_algorithm.contains("pq2025");

    let desc = if is_pqc {
        "JACS cryptographic document signing and verification with post-quantum support. Signing creates permanent, non-repudiable proof."
    } else {
        "JACS cryptographic document signing and verification. Signing creates permanent, non-repudiable proof."
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
///
/// `signing_algorithm` is the agent's own signing algorithm (e.g. "pq2025").
pub fn create_extension_descriptor(signing_algorithm: &str) -> Value {
    let verification_algorithms = supported_verification_algorithms();
    let pq_algorithms = supported_pq_algorithms();

    json!({
        "uri": JACS_EXTENSION_URI,
        "name": "JACS Document Provenance",
        "version": "1.0",
        "a2aProtocolVersion": A2A_PROTOCOL_VERSION,
        "description": "Provides cryptographic document signing and verification with post-quantum support",
        "specification": "https://jacs.sh/specs/a2a-extension",
        "signingGuidance": {
            "importance": "CRITICAL",
            "message": "Signing a document is a sacred, irreversible act. A signature creates permanent cryptographic proof that binds the signer to the document content. Once signed, the signature cannot be undone. The signer is accountable forever for what they sign. Only sign after careful review and full understanding of the document contents.",
            "nonRepudiation": "Signatures provide non-repudiation: the signer cannot later deny having signed the document.",
            "beforeSigning": [
                "Read and understand the complete document content",
                "Verify the document represents your intent",
                "Confirm you have authority to sign this document",
                "Understand this creates a permanent, verifiable record"
            ]
        },
        "capabilities": {
            "documentSigning": {
                "description": "SACRED OPERATION: Sign documents with JACS signatures. Creates permanent, non-repudiable cryptographic proof of commitment. The signer is forever accountable for signed content. Do not sign without fully understanding the document.",
                "signingAlgorithm": signing_algorithm,
                "formats": ["jacs-v1", "jws-detached"],
                "warning": "Signing is irreversible. Review document carefully before signing."
            },
            "documentVerification": {
                "description": "Verify JACS signatures on documents. Confirms document integrity and signer identity.",
                "algorithms": verification_algorithms,
                "offlineCapable": true,
                "chainOfCustody": true
            },
            "postQuantumCrypto": {
                "description": "Support for quantum-resistant signatures",
                "algorithms": pq_algorithms
            }
        },
        "endpoints": {
            "sign": {
                "path": "/jacs/sign",
                "method": "POST",
                "description": "SACRED OPERATION: Sign a document with JACS. Creates permanent cryptographic commitment. Review document carefully before calling.",
                "warning": "This operation is irreversible and creates non-repudiable proof of commitment."
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
    use crate::a2a::JACS_EXTENSION_URI;

    #[test]
    fn test_create_extension_descriptor() {
        let descriptor = create_extension_descriptor("pq2025");
        assert_eq!(descriptor["uri"], JACS_EXTENSION_URI);
        assert!(descriptor["capabilities"]["postQuantumCrypto"].is_object());
        assert_eq!(
            descriptor["capabilities"]["documentSigning"]["signingAlgorithm"],
            "pq2025"
        );
    }

    #[test]
    fn test_extension_descriptor_no_fake_algorithms() {
        let descriptor = create_extension_descriptor("ring-Ed25519");
        let descriptor_str = serde_json::to_string(&descriptor).unwrap();

        // These fake algorithms must never appear
        assert!(
            !descriptor_str.contains("\"falcon\""),
            "falcon is not a JACS algorithm"
        );
        assert!(
            !descriptor_str.contains("\"sphincs+\""),
            "sphincs+ is not a JACS algorithm"
        );
        assert!(
            !descriptor_str.contains("\"ecdsa\""),
            "ecdsa is not a JACS algorithm"
        );

        // Only real algorithms should appear in verification
        let verification_algs = descriptor["capabilities"]["documentVerification"]["algorithms"]
            .as_array()
            .expect("verification algorithms should be an array");
        let alg_strings: Vec<&str> = verification_algs
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(alg_strings.contains(&"ring-Ed25519"));
        assert!(alg_strings.contains(&"pq2025"));
    }

    #[test]
    fn test_extension_descriptor_only_real_pq_algorithms() {
        let descriptor = create_extension_descriptor("pq2025");
        let pq_algs = descriptor["capabilities"]["postQuantumCrypto"]["algorithms"]
            .as_array()
            .expect("PQ algorithms should be an array");
        let pq_strings: Vec<&str> = pq_algs.iter().map(|v| v.as_str().unwrap()).collect();

        assert!(pq_strings.contains(&"pq2025"));
        assert!(!pq_strings.contains(&"falcon"));
        assert!(!pq_strings.contains(&"sphincs+"));
        assert_eq!(pq_strings.len(), 1);
    }
}
