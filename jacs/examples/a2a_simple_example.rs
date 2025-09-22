//! Simple example demonstrating A2A integration without full agent setup
//! 
//! This example shows how to:
//! 1. Create an A2A Agent Card manually
//! 2. Export JACS extension descriptor
//! 3. Sign with JWS for A2A compatibility

use jacs::a2a::{*, agent_card::*, keys::*, extension::*};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== JACS A2A Simple Integration Example ===\n");

    // Step 1: Create an A2A Agent Card manually
    println!("1. Creating A2A Agent Card...");
    
    let agent_card = AgentCard {
        protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        url: "https://example-agent.com".to_string(),
        name: "Example JACS Agent".to_string(),
        description: "A JACS-enabled agent demonstrating A2A integration".to_string(),
        skills: vec![
            Skill {
                name: "verify_document".to_string(),
                description: "Verify JACS document signatures".to_string(),
                endpoint: "/api/verify".to_string(),
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
                        "valid": {"type": "boolean"},
                        "signerInfo": {"type": "object"}
                    }
                })),
            },
            Skill {
                name: "sign_document".to_string(),
                description: "Sign documents with JACS provenance".to_string(),
                endpoint: "/api/sign".to_string(),
                input_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "document": {
                            "type": "object",
                            "description": "The document to sign"
                        }
                    },
                    "required": ["document"]
                })),
                output_schema: None,
            },
        ],
        security_schemes: vec![
            SecurityScheme {
                r#type: "http".to_string(),
                scheme: "bearer".to_string(),
                bearer_format: Some("JWT".to_string()),
            },
        ],
        capabilities: Capabilities {
            extensions: Some(vec![
                Extension {
                    uri: JACS_EXTENSION_URI.to_string(),
                    description: "JACS cryptographic document signing and verification".to_string(),
                    required: false,
                    params: json!({
                        "jacsDescriptorUrl": "https://example-agent.com/.well-known/jacs-agent.json",
                        "signatureType": "JACS_PQC",
                        "supportedAlgorithms": ["dilithium", "rsa", "ecdsa"],
                        "verificationEndpoint": "/jacs/verify",
                        "signatureEndpoint": "/jacs/sign",
                    }),
                },
            ]),
        },
        metadata: Some(json!({
            "version": "1.0.0",
            "author": "JACS Example",
            "license": "Apache-2.0",
        })),
    };

    println!("   ✓ Agent Card created");
    println!("   - Name: {}", agent_card.name);
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
    println!("\n4. Well-known endpoints:");
    println!("   - /.well-known/agent.json - The A2A Agent Card");
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
