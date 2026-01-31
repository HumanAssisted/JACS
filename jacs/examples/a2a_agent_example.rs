//! Example: Creating a JACS agent with A2A protocol support (v0.4.0)
//!
//! This example demonstrates:
//! 1. Creating a JACS agent with post-quantum cryptography
//! 2. Exporting the agent as an A2A Agent Card
//! 3. Signing the Agent Card with JWS for A2A compatibility
//! 4. Wrapping A2A artifacts with JACS provenance

use jacs::a2a::{agent_card::*, extension::*, keys::*, provenance::*};
use jacs::agent::boilerplate::BoilerPlate;
use jacs::{create_minimal_blank_agent, get_empty_agent};
use serde_json::json;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== JACS + A2A Integration Example (v0.4.0) ===\n");

    // Initialize JACS with default observability
    jacs::init_default_observability()?;

    // Step 1: Create a JACS agent
    println!("1. Creating JACS agent...");
    let mut agent = get_empty_agent();

    let agent_json = create_minimal_blank_agent(
        "ai".to_string(),
        Some("Advanced Document Processing Service".to_string()),
        Some("Documents processed and verified successfully".to_string()),
        Some("Document processing failed - invalid format or signature".to_string()),
    )?;

    let agent_value = agent.create_agent_and_load(&agent_json, true, None)?;
    println!("   Agent created with ID: {}", agent.get_id()?);
    println!(
        "   Using algorithm: {}",
        agent.get_key_algorithm().unwrap_or(&"unknown".to_string())
    );

    // Step 2: Generate dual keys for JACS and A2A
    println!("\n2. Generating dual keys...");
    let dual_keys = create_jwk_keys(Some("dilithium"), Some("rsa"))?;
    println!("   JACS key: {} (post-quantum)", dual_keys.jacs_algorithm);
    println!("   A2A key: {} (traditional)", dual_keys.a2a_algorithm);

    // Step 3: Export agent as A2A Agent Card (v0.4.0)
    println!("\n3. Exporting to A2A Agent Card...");
    let agent_card = export_agent_card(&agent)?;
    println!("   Agent Card created");
    println!("   - Protocol versions: {:?}", agent_card.protocol_versions);
    println!(
        "   - Interfaces: {} ({})",
        agent_card.supported_interfaces[0].url, agent_card.supported_interfaces[0].protocol_binding
    );
    println!("   - Skills: {} defined", agent_card.skills.len());
    println!("   - Extensions: JACS provenance enabled");

    // Step 4: Sign Agent Card with JWS
    println!("\n4. Signing Agent Card with JWS...");
    let jws_signature = sign_agent_card_jws(
        &agent_card,
        &dual_keys.a2a_private_key,
        &dual_keys.a2a_algorithm,
        &agent.get_id()?,
    )?;
    println!("   Agent Card signed (JWS format)");
    println!("   - Signature: {}...", &jws_signature[..50]);

    // Step 5: Embed signature in Agent Card (v0.4.0)
    println!("\n5. Embedding signature in Agent Card...");
    let signed_card = embed_signature_in_agent_card(&agent_card, &jws_signature, None);
    println!(
        "   Signatures: {}",
        signed_card.signatures.as_ref().map_or(0, |s| s.len())
    );

    // Step 6: Generate .well-known documents
    println!("\n6. Generating .well-known endpoints...");
    let well_known_docs = generate_well_known_documents(
        &agent,
        &agent_card,
        &dual_keys.a2a_public_key,
        &dual_keys.a2a_algorithm,
        &jws_signature,
    )?;

    for (path, _) in &well_known_docs {
        println!("   {}", path);
    }

    // Step 7: Demonstrate wrapping A2A artifacts
    println!("\n7. Wrapping A2A artifacts with JACS provenance...");

    let a2a_task = json!({
        "taskId": "extract-entities-001",
        "type": "document-processing",
        "input": {
            "documentUrl": "https://example.com/doc.pdf",
            "operations": ["ocr", "entity-extraction", "sentiment-analysis"]
        },
        "requestedBy": "client-agent-123",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let wrapped_task = wrap_artifact_with_provenance(&mut agent, a2a_task, "task", None)?;
    println!("   Task wrapped with JACS signature");
    println!("   - JACS ID: {}", wrapped_task["jacsId"]);
    println!("   - Type: {}", wrapped_task["jacsType"]);

    // Step 8: Verify the wrapped artifact
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
    println!("   - Type: {}", verification.artifact_type);
    println!("   - Timestamp: {}", verification.timestamp);

    // Step 9: Create a multi-step workflow with chain of custody
    println!("\n9. Creating workflow with chain of custody...");
    let mut workflow_artifacts = Vec::new();

    let ocr_result = json!({
        "step": "ocr",
        "status": "completed",
        "output": { "text": "Sample extracted text...", "confidence": 0.98 }
    });
    let wrapped_ocr = wrap_artifact_with_provenance(&mut agent, ocr_result, "workflow-step", None)?;
    workflow_artifacts.push(wrapped_ocr);

    let entity_result = json!({
        "step": "entity-extraction",
        "status": "completed",
        "entities": [
            {"type": "PERSON", "value": "John Doe"},
            {"type": "ORG", "value": "ACME Corp"}
        ]
    });
    let wrapped_entities = wrap_artifact_with_provenance(
        &mut agent,
        entity_result,
        "workflow-step",
        Some(vec![workflow_artifacts.last().unwrap().clone()]),
    )?;
    workflow_artifacts.push(wrapped_entities);

    let chain = create_chain_of_custody(workflow_artifacts)?;
    println!("   Chain of custody created");
    println!("   - Total steps: {}", chain["totalArtifacts"]);

    // Display the JACS extension descriptor
    println!("\n10. JACS Extension Descriptor:");
    let descriptor = create_extension_descriptor();
    println!("{}", serde_json::to_string_pretty(&descriptor)?);

    println!("\n=== Example completed successfully! ===");

    // Save example outputs
    let output_dir = Path::new("a2a_example_output");
    fs::create_dir_all(output_dir)?;

    fs::write(
        output_dir.join("agent-card.json"),
        serde_json::to_string_pretty(&signed_card)?,
    )?;
    fs::write(output_dir.join("agent-card-signed.jws"), &jws_signature)?;
    fs::write(
        output_dir.join("wrapped-task.json"),
        serde_json::to_string_pretty(&wrapped_task)?,
    )?;
    fs::write(
        output_dir.join("chain-of-custody.json"),
        serde_json::to_string_pretty(&chain)?,
    )?;

    println!("\nOutputs saved to: a2a_example_output/");

    Ok(())
}
