//! Simple example demonstrating A2A integration without full agent setup
//!
//! This example shows how to:
//! 1. Create an A2A Agent Card manually (v0.4.0)
//! 2. Export JACS extension descriptor
//! 3. Sign with JWS for A2A compatibility

use jacs::a2a::{agent_card::*, extension::*, keys::*, *};
use serde_json::json;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== JACS A2A Simple Integration Example (v0.4.0) ===\n");

    // Step 1: Create an A2A Agent Card manually
    println!("1. Creating A2A Agent Card...");

    let mut security_schemes = HashMap::new();
    security_schemes.insert(
        "bearer-jwt".to_string(),
        SecurityScheme::Http {
            scheme: "Bearer".to_string(),
            bearer_format: Some("JWT".to_string()),
        },
    );

    let agent_card = AgentCard {
        name: "Example JACS Agent".to_string(),
        description: "A JACS-enabled agent demonstrating A2A integration".to_string(),
        version: "1.0.0".to_string(),
        protocol_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
        supported_interfaces: vec![AgentInterface {
            url: "https://example-agent.com".to_string(),
            protocol_binding: "jsonrpc".to_string(),
            tenant: None,
        }],
        default_input_modes: vec!["text/plain".to_string(), "application/json".to_string()],
        default_output_modes: vec!["text/plain".to_string(), "application/json".to_string()],
        skills: vec![
            AgentSkill {
                id: "verify-document".to_string(),
                name: "verify_document".to_string(),
                description: "Verify JACS document signatures".to_string(),
                tags: vec![
                    "jacs".to_string(),
                    "verification".to_string(),
                    "cryptography".to_string(),
                ],
                examples: Some(vec!["Verify a signed JACS document".to_string()]),
                input_modes: Some(vec!["application/json".to_string()]),
                output_modes: Some(vec!["application/json".to_string()]),
                security: None,
            },
            AgentSkill {
                id: "sign-document".to_string(),
                name: "sign_document".to_string(),
                description: "Sign documents with JACS provenance".to_string(),
                tags: vec!["jacs".to_string(), "signing".to_string()],
                examples: None,
                input_modes: Some(vec!["application/json".to_string()]),
                output_modes: Some(vec!["application/json".to_string()]),
                security: None,
            },
        ],
        security_schemes: Some(security_schemes),
        capabilities: AgentCapabilities {
            streaming: None,
            push_notifications: None,
            extended_agent_card: None,
            extensions: Some(vec![AgentExtension {
                uri: JACS_EXTENSION_URI.to_string(),
                description: Some(
                    "JACS cryptographic document signing and verification".to_string(),
                ),
                required: Some(false),
            }]),
        },
        provider: None,
        documentation_url: None,
        icon_url: None,
        security: None,
        signatures: None,
        metadata: Some(json!({
            "author": "JACS Example",
            "license": "Apache-2.0",
        })),
    };

    println!("   Agent Card created");
    println!("   - Name: {}", agent_card.name);
    println!("   - Protocol: {:?}", agent_card.protocol_versions);
    println!("   - Skills: {} defined", agent_card.skills.len());
    println!("   - Extensions: JACS provenance enabled");

    // Step 2: Display the Agent Card as JSON
    println!("\n2. Agent Card JSON:");
    let agent_card_json = serde_json::to_string_pretty(&agent_card)?;
    println!("{}", agent_card_json);

    // Step 3: Create JACS extension descriptor
    println!("\n3. JACS Extension Descriptor:");
    let descriptor = create_extension_descriptor();
    println!("{}", serde_json::to_string_pretty(&descriptor)?);

    // Step 4: Show how the Agent Card would be served
    println!("\n4. Well-known endpoints (v0.4.0):");
    println!("   - /.well-known/agent-card.json - The A2A Agent Card (with embedded signatures)");
    println!("   - /.well-known/jwks.json - JWK Set for signature verification");
    println!("   - /.well-known/jacs-agent.json - JACS agent descriptor");
    println!("   - /.well-known/jacs-pubkey.json - JACS public key");

    // Step 5: Example A2A artifact wrapped with JACS provenance
    println!("\n5. Example JACS-wrapped A2A artifact:");

    let a2a_task = json!({
        "taskId": "task-789",
        "type": "document-analysis",
        "input": {
            "documentUrl": "https://example.com/document.pdf",
            "operations": ["extract-text", "analyze-sentiment"]
        },
        "requestedBy": "client-agent-456",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let wrapped_artifact = json!({
        "jacsId": uuid::Uuid::new_v4().to_string(),
        "jacsVersion": uuid::Uuid::new_v4().to_string(),
        "jacsType": "a2a-task",
        "jacsLevel": "artifact",
        "jacsVersionDate": chrono::Utc::now().to_rfc3339(),
        "$schema": "https://hai.ai/schemas/header/v1/header.schema.json",
        "a2aArtifact": a2a_task,
        "jacsSignature": {
            "agentID": "example-agent-123",
            "agentVersion": "v1.0.0",
            "date": chrono::Utc::now().to_rfc3339(),
            "signature": "base64-encoded-signature-would-go-here",
            "signingAlgorithm": "dilithium",
            "publicKeyHash": "sha256-hash-of-public-key",
            "fields": ["jacsId", "jacsVersion", "jacsType", "a2aArtifact"]
        },
        "jacsSha256": "sha256-hash-of-document"
    });

    println!("{}", serde_json::to_string_pretty(&wrapped_artifact)?);

    println!("\n=== Example completed successfully! ===");
    println!("\nKey Takeaways:");
    println!("1. JACS extends A2A with cryptographic document provenance");
    println!("2. Agent Cards declare JACS capabilities via extensions");
    println!("3. All A2A artifacts can be wrapped with JACS signatures");
    println!("4. JACS provides post-quantum cryptography support");
    println!("5. Documents are self-verifying with complete audit trails");

    Ok(())
}
