//! Complete example: JACS agent with A2A protocol integration (v0.4.0)
//!
//! This example demonstrates:
//! 1. Loading a JACS agent from configuration
//! 2. Exporting to A2A Agent Card format (v0.4.0)
//! 3. Generating dual keys (PQC + traditional)
//! 4. Signing Agent Cards with JWS (embedded signatures)
//! 5. Wrapping A2A artifacts with JACS provenance

use jacs::a2a::{agent_card::*, extension::*, keys::*, provenance::*, *};
use jacs::agent::{Agent, boilerplate::BoilerPlate};
use serde_json::json;
use std::env;
use std::fs;
use std::path::Path;

// Example configuration for a JACS agent
const EXAMPLE_CONFIG: &str = r#"{
    "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
    "jacs_use_filesystem": "true",
    "jacs_use_security": "true",
    "jacs_data_directory": "./example_data",
    "jacs_key_directory": "./example_keys",
    "jacs_agent_private_key_filename": "example.private.pem.enc",
    "jacs_agent_public_key_filename": "example.public.pem",
    "jacs_agent_key_algorithm": "RSA-PSS",
    "jacs_agent_schema_version": "v1",
    "jacs_header_schema_version": "v1",
    "jacs_signature_schema_version": "v1",
    "jacs_private_key_password": "example_password",
    "jacs_default_storage": "fs"
}"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== JACS + A2A Complete Integration Example (v0.4.0) ===\n");

    // Initialize JACS with default observability
    jacs::init_default_observability()?;

    // Step 1: Set up example environment
    println!("1. Setting up example environment...");
    setup_example_environment()?;

    // Step 2: Create or load a JACS agent
    println!("\n2. Creating JACS agent...");
    let mut agent = create_example_agent()?;
    println!("   Agent created with ID: {}", agent.get_id()?);
    println!(
        "   Using algorithm: {}",
        agent.get_key_algorithm().unwrap_or(&"unknown".to_string())
    );

    // Step 3: Export agent as A2A Agent Card (v0.4.0)
    println!("\n3. Exporting to A2A Agent Card...");
    let agent_card = export_agent_card(&agent)?;
    display_agent_card_info(&agent_card);

    // Step 4: Generate dual keys for A2A compatibility
    println!("\n4. Generating dual keys for A2A...");
    setup_key_env_vars();
    let dual_keys = create_jwk_keys(Some("rsa"), Some("rsa"))?;
    println!(
        "   JACS key generated: {} ({} bytes)",
        dual_keys.jacs_algorithm,
        dual_keys.jacs_private_key.len()
    );
    println!(
        "   A2A key generated: {} ({} bytes)",
        dual_keys.a2a_algorithm,
        dual_keys.a2a_private_key.len()
    );
    cleanup_key_env_vars();

    // Step 5: Sign Agent Card with JWS
    println!("\n5. Signing Agent Card with JWS...");
    let agent_id = agent.get_id()?;
    let jws_signature = sign_agent_card_jws(
        &agent_card,
        &dual_keys.a2a_private_key,
        &dual_keys.a2a_algorithm,
        &agent_id,
    )?;
    println!("   JWS signature created");
    println!("   - Format: header.payload.signature");
    println!("   - Length: {} characters", jws_signature.len());

    // Step 5b: Embed signature in Agent Card (v0.4.0)
    let signed_card = embed_signature_in_agent_card(&agent_card, &jws_signature, Some(&agent_id));
    println!(
        "   Signature embedded in AgentCard.signatures (count: {})",
        signed_card.signatures.as_ref().map_or(0, |s| s.len())
    );

    // Step 6: Generate well-known documents
    println!("\n6. Generating .well-known documents...");
    let well_known_docs = generate_well_known_documents(
        &agent,
        &agent_card,
        &dual_keys.a2a_public_key,
        &dual_keys.a2a_algorithm,
        &jws_signature,
    )?;

    // Save well-known documents
    let well_known_dir = Path::new("example_output/.well-known");
    fs::create_dir_all(well_known_dir)?;

    for (path, content) in &well_known_docs {
        let file_path = format!("example_output{}", path);
        let parent = Path::new(&file_path).parent().unwrap();
        fs::create_dir_all(parent)?;
        fs::write(&file_path, serde_json::to_string_pretty(&content)?)?;
        println!("   Created: {}", file_path);
    }

    // Step 7: Demonstrate wrapping A2A artifacts
    println!("\n7. Wrapping A2A artifacts with JACS provenance...");

    let a2a_task = json!({
        "taskId": "analyze-doc-001",
        "type": "document-analysis",
        "input": {
            "documentUrl": "https://example.com/important-doc.pdf",
            "operations": ["ocr", "entity-extraction", "classification"],
            "requestor": "client-agent-789",
            "priority": "high"
        },
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let wrapped_task = wrap_artifact_with_provenance(&mut agent, a2a_task.clone(), "task", None)?;

    println!("   Task wrapped with JACS signature");
    println!("   - JACS ID: {}", wrapped_task["jacsId"]);
    println!("   - Type: {}", wrapped_task["jacsType"]);

    fs::write(
        "example_output/wrapped-task.json",
        serde_json::to_string_pretty(&wrapped_task)?,
    )?;

    // Step 8: Demonstrate verification
    println!("\n8. Verifying wrapped artifact...");
    let verification = verify_wrapped_artifact(&agent, &wrapped_task)?;
    println!(
        "   Verification: {}",
        if verification.valid {
            "PASSED"
        } else {
            "FAILED"
        }
    );
    println!("   - Signer: {}", verification.signer_id);
    println!("   - Timestamp: {}", verification.timestamp);

    // Step 9: Create a workflow with chain of custody
    println!("\n9. Creating multi-step workflow with chain of custody...");
    let workflow = create_example_workflow(&mut agent)?;

    fs::write(
        "example_output/workflow-chain.json",
        serde_json::to_string_pretty(&workflow)?,
    )?;

    println!(
        "   Workflow created with {} steps",
        workflow["totalArtifacts"]
    );

    println!("\n=== Example completed successfully! ===");
    println!("\nOutputs saved to: example_output/");
    println!("\nKey Integration Points:");
    println!("- JACS provides document-level cryptographic provenance");
    println!("- A2A handles agent discovery and communication");
    println!("- JWS ensures compatibility with web standards");
    println!("- Post-quantum support future-proofs the system");
    println!("\nTo serve as an A2A agent:");
    println!("1. Host the .well-known files on your web server");
    println!("2. Implement the JACS endpoints (/jacs/sign, /jacs/verify)");
    println!("3. Register your agent with A2A discovery services");

    // Cleanup
    cleanup_example_environment()?;

    Ok(())
}

fn setup_example_environment() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("example_data/agent")?;
    fs::create_dir_all("example_keys")?;
    fs::create_dir_all("example_output")?;
    fs::write("example_jacs.config.json", EXAMPLE_CONFIG)?;

    unsafe {
        env::set_var("JACS_PRIVATE_KEY_PASSWORD", "example_password");
    }

    Ok(())
}

fn create_example_agent() -> Result<Agent, Box<dyn std::error::Error>> {
    let mut agent = jacs::get_empty_agent();

    let agent_json = json!({
        "jacsName": "Example A2A Agent",
        "jacsDescription": "A JACS agent demonstrating A2A protocol integration",
        "jacsAgentType": "ai",
        "jacsServices": [{
            "name": "Document Analysis Service",
            "serviceDescription": "Analyzes documents using advanced AI techniques",
            "successDescription": "Document successfully analyzed with extracted entities and insights",
            "failureDescription": "Document analysis failed due to format or processing errors",
            "tools": [{
                "url": "https://example-agent.com/api/analyze",
                "function": {
                    "name": "analyze_document",
                    "description": "Analyze a document and extract structured information",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "document_url": {
                                "type": "string",
                                "description": "URL of the document to analyze"
                            },
                            "operations": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of operations to perform"
                            }
                        },
                        "required": ["document_url", "operations"]
                    }
                }
            }]
        }],
        "jacsContacts": [{
            "type": "email",
            "value": "admin@example-agent.com",
            "description": "Administrator contact"
        }]
    });

    agent.create_agent_and_load(&agent_json.to_string(), true, None)?;
    agent.save()?;

    Ok(agent)
}

fn display_agent_card_info(agent_card: &AgentCard) {
    println!("   Agent Card created");
    println!("   - Name: {}", agent_card.name);
    println!("   - Version: {}", agent_card.version);
    println!("   - Protocol: {:?}", agent_card.protocol_versions);
    println!(
        "   - Interfaces: {} ({})",
        agent_card.supported_interfaces[0].url, agent_card.supported_interfaces[0].protocol_binding
    );
    println!("   - Skills: {} defined", agent_card.skills.len());

    for skill in &agent_card.skills {
        println!(
            "     - {} (id: {}): {}",
            skill.name, skill.id, skill.description
        );
    }

    if let Some(extensions) = &agent_card.capabilities.extensions {
        println!("   - Extensions: {} configured", extensions.len());
        for ext in extensions {
            println!(
                "     - {}: {}",
                ext.uri,
                ext.description.as_deref().unwrap_or("(no description)")
            );
        }
    }
}

fn create_example_workflow(
    agent: &mut Agent,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut artifacts = Vec::new();

    let receipt = json!({
        "step": "document-receipt",
        "documentId": "doc-123",
        "receivedFrom": "client-456",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let wrapped_receipt = wrap_artifact_with_provenance(agent, receipt, "workflow-step", None)?;
    artifacts.push(wrapped_receipt);

    let ocr = json!({
        "step": "ocr-processing",
        "documentId": "doc-123",
        "extractedText": "Sample text extracted from document...",
        "confidence": 0.98,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let wrapped_ocr = wrap_artifact_with_provenance(
        agent,
        ocr,
        "workflow-step",
        Some(vec![artifacts.last().unwrap().clone()]),
    )?;
    artifacts.push(wrapped_ocr);

    let entities = json!({
        "step": "entity-extraction",
        "documentId": "doc-123",
        "entities": [
            {"type": "PERSON", "value": "John Doe", "confidence": 0.95},
            {"type": "ORG", "value": "ACME Corp", "confidence": 0.92},
            {"type": "DATE", "value": "2024-01-15", "confidence": 0.99}
        ],
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let wrapped_entities = wrap_artifact_with_provenance(
        agent,
        entities,
        "workflow-step",
        Some(vec![artifacts.last().unwrap().clone()]),
    )?;
    artifacts.push(wrapped_entities);

    create_chain_of_custody(artifacts)
}

fn setup_key_env_vars() {
    unsafe {
        env::set_var("JACS_KEY_DIRECTORY", "example_keys");
        env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "a2a.private.pem");
        env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "a2a.public.pem");
    }
}

fn cleanup_key_env_vars() {
    unsafe {
        env::remove_var("JACS_KEY_DIRECTORY");
        env::remove_var("JACS_AGENT_PRIVATE_KEY_FILENAME");
        env::remove_var("JACS_AGENT_PUBLIC_KEY_FILENAME");
    }
}

fn cleanup_example_environment() -> Result<(), Box<dyn std::error::Error>> {
    if Path::new("example_jacs.config.json").exists() {
        fs::remove_file("example_jacs.config.json")?;
    }

    unsafe {
        env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
    }

    Ok(())
}
