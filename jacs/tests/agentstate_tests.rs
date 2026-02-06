use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::schema::agentstate_crud::{
    create_agentstate_with_content, create_agentstate_with_file, create_minimal_agentstate,
    set_agentstate_framework, set_agentstate_origin, set_agentstate_tags,
    verify_agentstate_file_hash,
};
use serde_json::Value;
use std::fs;
use std::io::Write;

mod utils;
use utils::load_test_agent_one;

// =============================================================================
// Phase 0A: Schema and CRUD Tests (Steps 0.1 - 0.15)
// =============================================================================

/// Step 0.1: Test creating a minimal signed agent state document.
#[test]
fn test_create_minimal_agentstate() {
    let doc = create_minimal_agentstate("memory", "Project Memory", Some("JACS project context"))
        .expect("Should create valid agentstate");

    assert_eq!(doc["jacsAgentStateType"], "memory");
    assert_eq!(doc["jacsAgentStateName"], "Project Memory");
    assert_eq!(doc["jacsAgentStateDescription"], "JACS project context");
    assert_eq!(doc["jacsType"], "agentstate");
    assert_eq!(doc["jacsLevel"], "config");
    assert_eq!(
        doc["$schema"],
        "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json"
    );
}

/// Step 0.2: Test that every valid state type is accepted.
#[test]
fn test_agentstate_all_valid_types() {
    let valid_types = ["memory", "skill", "plan", "config", "hook"];
    for state_type in &valid_types {
        let doc = create_minimal_agentstate(state_type, &format!("Test {}", state_type), None)
            .unwrap_or_else(|e| panic!("Failed for type '{}': {}", state_type, e));
        assert_eq!(doc["jacsAgentStateType"], *state_type);
    }
}

/// Step 0.3: Test that an invalid state type is rejected.
#[test]
fn test_agentstate_invalid_type() {
    let result = create_minimal_agentstate("invalid", "Bad Type", None);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Invalid agent state type"));
}

/// Step 0.4: Test creating an agentstate that references an external file.
#[test]
fn test_agentstate_with_file_reference() {
    // Create a temporary test file
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("MEMORY.md");
    fs::write(&file_path, "# Project Memory\n\nThis is test content.")
        .expect("Failed to write test file");

    let doc = create_agentstate_with_file(
        "memory",
        "Test Memory",
        file_path.to_str().unwrap(),
        false,
    )
    .expect("Should create agentstate with file");

    assert_eq!(doc["jacsAgentStateType"], "memory");
    assert_eq!(doc["jacsAgentStateName"], "Test Memory");

    // Should have jacsFiles array with one entry
    let files = doc["jacsFiles"].as_array().expect("Should have jacsFiles");
    assert_eq!(files.len(), 1);
    assert!(files[0]["sha256"].as_str().is_some());
    assert_eq!(files[0]["embed"], false);
    // Non-embedded files should not have inline content
    assert!(doc.get("jacsAgentStateContent").is_none() || doc["jacsAgentStateContent"].is_null());
}

/// Step 0.5: Test creating an agentstate with embedded content (hooks).
#[test]
fn test_agentstate_with_embedded_content() {
    let hook_content = r#"{"event":"PreToolUse","matcher":{"tool_name":"Bash"},"command":"npm run lint"}"#;
    let doc = create_agentstate_with_content(
        "hook",
        "pre-commit-lint",
        hook_content,
        "application/json",
    )
    .expect("Should create agentstate with content");

    assert_eq!(doc["jacsAgentStateType"], "hook");
    assert_eq!(doc["jacsAgentStateContent"], hook_content);
    assert_eq!(doc["jacsAgentStateContentType"], "application/json");
}

/// Step 0.6: Test SHA-256 hash verification of referenced file.
#[test]
fn test_agentstate_file_hash_verification() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("SKILL.md");
    let original_content = "# My Skill\n\nDoes something useful.";
    fs::write(&file_path, original_content).expect("Failed to write test file");

    let doc = create_agentstate_with_file(
        "skill",
        "Test Skill",
        file_path.to_str().unwrap(),
        false,
    )
    .expect("Should create agentstate");

    // Hash should match original content
    assert!(verify_agentstate_file_hash(&doc).expect("Verify should succeed"));

    // Modify the file
    fs::write(&file_path, "# Modified Skill\n\nContent changed.").expect("Failed to modify file");

    // Hash should no longer match
    assert!(!verify_agentstate_file_hash(&doc).expect("Verify should succeed but mismatch"));
}

/// Step 0.7: Test that every valid origin type is accepted.
#[test]
fn test_agentstate_all_valid_origins() {
    let valid_origins = ["authored", "adopted", "generated", "imported"];
    for origin in &valid_origins {
        let mut doc = create_minimal_agentstate("memory", "Test", None).unwrap();
        set_agentstate_origin(&mut doc, origin, None)
            .unwrap_or_else(|e| panic!("Failed for origin '{}': {}", origin, e));
        assert_eq!(doc["jacsAgentStateOrigin"], *origin);
    }
}

/// Step 0.8: Test agentstate with source URL for adopted skills.
#[test]
fn test_agentstate_with_source_url() {
    let mut doc = create_minimal_agentstate("skill", "Adopted Skill", None).unwrap();
    set_agentstate_origin(
        &mut doc,
        "adopted",
        Some("https://agentskills.io/skills/jacs-signing"),
    )
    .unwrap();

    assert_eq!(doc["jacsAgentStateOrigin"], "adopted");
    assert_eq!(
        doc["jacsAgentStateSourceUrl"],
        "https://agentskills.io/skills/jacs-signing"
    );
}

/// Step 0.9: Test agentstate with tags.
#[test]
fn test_agentstate_with_tags() {
    let mut doc = create_minimal_agentstate("skill", "Crypto Skill", None).unwrap();
    set_agentstate_tags(&mut doc, vec!["crypto", "signing", "security"]).unwrap();

    let tags = doc["jacsAgentStateTags"]
        .as_array()
        .expect("Should have tags");
    assert_eq!(tags.len(), 3);
    assert_eq!(tags[0], "crypto");
    assert_eq!(tags[1], "signing");
    assert_eq!(tags[2], "security");
}

/// Step 0.10: Test that missing required name is rejected by schema validation.
#[test]
fn test_agentstate_missing_required_name() {
    let mut agent = load_test_agent_one();
    // Create a doc without jacsAgentStateName
    let raw = serde_json::json!({
        "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
        "jacsAgentStateType": "memory",
        "jacsType": "agentstate",
        "jacsLevel": "config",
    });

    let result = agent.schema.validate_agentstate(&raw.to_string());
    assert!(result.is_err(), "Should reject missing jacsAgentStateName");
}

/// Step 0.11: Test that missing required state type is rejected by schema validation.
#[test]
fn test_agentstate_missing_required_type() {
    let mut agent = load_test_agent_one();
    // Create a doc without jacsAgentStateType
    let raw = serde_json::json!({
        "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
        "jacsAgentStateName": "Test Memory",
        "jacsType": "agentstate",
        "jacsLevel": "config",
    });

    let result = agent.schema.validate_agentstate(&raw.to_string());
    assert!(result.is_err(), "Should reject missing jacsAgentStateType");
}

/// Test that framework field can be set correctly.
#[test]
fn test_agentstate_with_framework() {
    let mut doc = create_minimal_agentstate("memory", "Claude Memory", None).unwrap();
    set_agentstate_framework(&mut doc, "claude-code").unwrap();
    assert_eq!(doc["jacsAgentStateFramework"], "claude-code");
}

/// Test hook files always embed content (Decision P0-3).
#[test]
fn test_agentstate_hook_always_embeds() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("hook.sh");
    fs::write(&file_path, "#!/bin/bash\necho 'hello'").expect("Failed to write test file");

    // Even with embed=false, hooks should embed
    let doc = create_agentstate_with_file(
        "hook",
        "test-hook",
        file_path.to_str().unwrap(),
        false, // requesting no embed, but hooks override this
    )
    .expect("Should create hook agentstate");

    // Hook should have embedded content
    assert!(
        doc.get("jacsAgentStateContent").is_some()
            && !doc["jacsAgentStateContent"].is_null(),
        "Hook should always embed content"
    );
    let files = doc["jacsFiles"].as_array().unwrap();
    assert_eq!(files[0]["embed"], true, "Hook file entry should have embed=true");
}

/// Test creating and loading an agentstate document through the full agent pipeline.
#[test]
fn test_agentstate_create_document_and_load() {
    let mut agent = load_test_agent_one();

    let doc = create_minimal_agentstate("memory", "Project Memory", Some("Test memory"))
        .expect("Should create valid agentstate");

    let loaded = agent
        .create_document_and_load(&doc.to_string(), None, None)
        .expect("Should load agentstate as JACS document");

    let value = loaded.getvalue();
    assert_eq!(value["jacsAgentStateType"], "memory");
    assert_eq!(value["jacsAgentStateName"], "Project Memory");
    assert!(value.get("jacsId").is_some(), "Should have jacsId");
    assert!(value.get("jacsVersion").is_some(), "Should have jacsVersion");
}

/// Test agentstate schema validation through the Schema validator.
#[test]
fn test_agentstate_schema_validation_valid() {
    let agent = load_test_agent_one();

    let doc = create_minimal_agentstate("skill", "JACS Signing", Some("Crypto signing skill"))
        .expect("Should create valid agentstate");

    // Add header fields that schema validation requires
    let mut full_doc = doc.clone();
    full_doc["jacsId"] = serde_json::json!("test-id");
    full_doc["jacsVersion"] = serde_json::json!("test-version");
    full_doc["jacsVersionDate"] = serde_json::json!("2026-02-05T00:00:00Z");
    full_doc["jacsOriginalVersion"] = serde_json::json!("test-version");
    full_doc["jacsOriginalDate"] = serde_json::json!("2026-02-05T00:00:00Z");

    let result = agent.schema.validate_agentstate(&full_doc.to_string());
    assert!(result.is_ok(), "Valid agentstate should pass validation: {:?}", result.err());
}

/// Test invalid agentstate type is rejected by schema validation.
#[test]
fn test_agentstate_schema_rejects_invalid_type() {
    let agent = load_test_agent_one();

    let raw = serde_json::json!({
        "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
        "jacsAgentStateType": "bogus",
        "jacsAgentStateName": "Bad Type",
        "jacsType": "agentstate",
        "jacsLevel": "config",
        "jacsId": "test-id",
        "jacsVersion": "test-version",
        "jacsVersionDate": "2026-02-05T00:00:00Z",
        "jacsOriginalVersion": "test-version",
        "jacsOriginalDate": "2026-02-05T00:00:00Z",
    });

    let result = agent.schema.validate_agentstate(&raw.to_string());
    assert!(result.is_err(), "Invalid type should fail validation");
}

/// Test various MIME content types work correctly.
#[test]
fn test_agentstate_different_content_types() {
    let content_types = [
        ("memory", "text/markdown", "# Memory\n\nContent here."),
        ("config", "application/json", r#"{"key": "value"}"#),
        ("config", "application/yaml", "key: value\nlist:\n  - item1"),
        ("hook", "text/x-shellscript", "#!/bin/bash\necho hello"),
    ];

    for (state_type, content_type, content) in &content_types {
        let doc = create_agentstate_with_content(state_type, "Test", content, content_type)
            .unwrap_or_else(|e| panic!("Failed for {}/{}: {}", state_type, content_type, e));
        assert_eq!(doc["jacsAgentStateContentType"], *content_type);
        assert_eq!(doc["jacsAgentStateContent"], *content);
    }
}

// =============================================================================
// Phase 0B: Signing and Verification Pipeline Tests (Steps 0.16 - 0.25)
// =============================================================================

/// Step 0.16: Test that creating and loading an agentstate via the agent produces
/// a signed document with jacsSignature, jacsId, and jacsVersion.
#[test]
fn test_agentstate_signing_and_verification() {
    let mut agent = load_test_agent_one();

    let doc = create_minimal_agentstate("memory", "Signed Memory", Some("Testing signing"))
        .expect("Should create valid agentstate");

    let loaded = agent
        .create_document_and_load(&doc.to_string(), None, None)
        .expect("Should load and sign agentstate document");

    let value = loaded.getvalue();

    // The signed document must have a jacsSignature field
    assert!(
        value.get("jacsSignature").is_some(),
        "Signed agentstate must have jacsSignature"
    );
    assert!(
        value["jacsSignature"].is_object(),
        "jacsSignature must be a JSON object"
    );

    // Must have jacsId and jacsVersion assigned by the signing pipeline
    assert!(
        value.get("jacsId").is_some() && value["jacsId"].as_str().is_some(),
        "Signed agentstate must have jacsId"
    );
    assert!(
        value.get("jacsVersion").is_some() && value["jacsVersion"].as_str().is_some(),
        "Signed agentstate must have jacsVersion"
    );
}

/// Step 0.17: Test that updating an agentstate document produces a new version
/// with a different jacsVersion and jacsPreviousVersion pointing to the original.
#[test]
fn test_agentstate_resign_on_content_change() {
    let mut agent = load_test_agent_one();

    let doc = create_minimal_agentstate("memory", "Versioned Memory", Some("version 1"))
        .expect("Should create valid agentstate");

    let loaded = agent
        .create_document_and_load(&doc.to_string(), None, None)
        .expect("Should load agentstate");

    let doc_key = loaded.getkey();
    let original_value = loaded.getvalue().clone();
    let original_version = original_value["jacsVersion"]
        .as_str()
        .expect("Should have jacsVersion")
        .to_string();

    // Modify the document content while keeping jacsId and jacsVersion the same
    let mut updated_value = original_value.clone();
    updated_value["jacsAgentStateDescription"] =
        serde_json::json!("updated description for version 2");

    let updated_doc = agent
        .update_document(&doc_key, &updated_value.to_string(), None, None)
        .expect("Should update agentstate document");

    let updated_val = updated_doc.getvalue();

    // New version must differ from original
    let new_version = updated_val["jacsVersion"]
        .as_str()
        .expect("Updated doc should have jacsVersion");
    assert_ne!(
        new_version, original_version,
        "Updated document must have a different jacsVersion"
    );

    // jacsPreviousVersion must point to the original version
    let prev_version = updated_val["jacsPreviousVersion"]
        .as_str()
        .expect("Updated doc should have jacsPreviousVersion");
    assert_eq!(
        prev_version, original_version,
        "jacsPreviousVersion must equal the original jacsVersion"
    );
}

/// Step 0.18: Test a version chain of three document versions.
/// Version 3's jacsPreviousVersion must equal version 2's jacsVersion.
#[test]
fn test_agentstate_version_chain() {
    let mut agent = load_test_agent_one();

    // Version 1
    let doc = create_minimal_agentstate("skill", "Chained Skill", Some("v1"))
        .expect("Should create agentstate");

    let v1 = agent
        .create_document_and_load(&doc.to_string(), None, None)
        .expect("Should load v1");

    let v1_key = v1.getkey();
    let v1_value = v1.getvalue().clone();
    let v1_version = v1_value["jacsVersion"]
        .as_str()
        .expect("v1 should have jacsVersion")
        .to_string();

    // Version 2
    let mut v2_input = v1_value.clone();
    v2_input["jacsAgentStateDescription"] = serde_json::json!("v2");
    let v2 = agent
        .update_document(&v1_key, &v2_input.to_string(), None, None)
        .expect("Should create v2");

    let v2_key = v2.getkey();
    let v2_value = v2.getvalue().clone();
    let v2_version = v2_value["jacsVersion"]
        .as_str()
        .expect("v2 should have jacsVersion")
        .to_string();

    // Verify v2 previous points to v1
    assert_eq!(
        v2_value["jacsPreviousVersion"].as_str().unwrap(),
        v1_version,
        "v2's jacsPreviousVersion must equal v1's jacsVersion"
    );

    // Version 3
    let mut v3_input = v2_value.clone();
    v3_input["jacsAgentStateDescription"] = serde_json::json!("v3");
    let v3 = agent
        .update_document(&v2_key, &v3_input.to_string(), None, None)
        .expect("Should create v3");

    let v3_value = v3.getvalue();

    // Verify v3 previous points to v2
    assert_eq!(
        v3_value["jacsPreviousVersion"].as_str().unwrap(),
        v2_version,
        "v3's jacsPreviousVersion must equal v2's jacsVersion"
    );

    // Verify all three versions are distinct
    let v3_version = v3_value["jacsVersion"].as_str().unwrap();
    assert_ne!(v1_version, v2_version);
    assert_ne!(v2_version, v3_version);
    assert_ne!(v1_version, v3_version);
}

/// Step 0.19: Test the adoption workflow: create a skill from an external file,
/// set origin to "adopted" with a source URL, load via agent, and verify.
#[test]
fn test_agentstate_adoption_workflow() {
    let mut agent = load_test_agent_one();

    // Create a temp file representing an unsigned external skill
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("SKILL.md");
    let skill_content = "# External Skill\n\nAdopted from a community repository.";
    fs::write(&file_path, skill_content).expect("Failed to write skill file");

    // Create agentstate with file, set origin to adopted
    let mut doc = create_agentstate_with_file(
        "skill",
        "Adopted Community Skill",
        file_path.to_str().unwrap(),
        false,
    )
    .expect("Should create agentstate with file");

    set_agentstate_origin(
        &mut doc,
        "adopted",
        Some("https://agentskills.io/skills/community-skill"),
    )
    .expect("Should set origin");

    // Load through agent signing pipeline
    let loaded = agent
        .create_document_and_load(&doc.to_string(), None, None)
        .expect("Should load adopted agentstate");

    let value = loaded.getvalue();

    // Verify origin is "adopted"
    assert_eq!(
        value["jacsAgentStateOrigin"], "adopted",
        "Origin should be adopted"
    );

    // Verify source URL is present
    assert_eq!(
        value["jacsAgentStateSourceUrl"],
        "https://agentskills.io/skills/community-skill"
    );

    // Verify file hash is present in jacsFiles
    let files = value["jacsFiles"]
        .as_array()
        .expect("Should have jacsFiles");
    assert!(!files.is_empty(), "jacsFiles should not be empty");
    assert!(
        files[0].get("sha256").is_some(),
        "File entry should have sha256 hash"
    );

    // Verify the agent signed the document
    assert!(
        value.get("jacsSignature").is_some(),
        "Adopted agentstate must be signed by the agent"
    );
}

/// Step 0.20: Test that hook-type agentstates always embed content in the signed
/// document, even when embed=false is requested.
#[test]
fn test_agentstate_hook_always_embeds_signing() {
    let mut agent = load_test_agent_one();

    // Create a temp hook file
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("pre-commit.sh");
    fs::write(&file_path, "#!/bin/bash\nnpm run lint && npm test")
        .expect("Failed to write hook file");

    // Create agentstate with embed=false, but hooks should override to embed=true
    let doc = create_agentstate_with_file(
        "hook",
        "pre-commit-lint-hook",
        file_path.to_str().unwrap(),
        false,
    )
    .expect("Should create hook agentstate");

    // Load via agent to sign
    let loaded = agent
        .create_document_and_load(&doc.to_string(), None, None)
        .expect("Should load hook agentstate");

    let value = loaded.getvalue();

    // Hooks must always have embedded content in the signed document
    assert!(
        value.get("jacsAgentStateContent").is_some()
            && !value["jacsAgentStateContent"].is_null(),
        "Hook content must be embedded in the signed document"
    );

    // Verify the file entry has embed=true
    let files = value["jacsFiles"]
        .as_array()
        .expect("Should have jacsFiles");
    assert_eq!(
        files[0]["embed"], true,
        "Hook file entry must have embed=true in signed document"
    );

    // Verify signing
    assert!(
        value.get("jacsSignature").is_some(),
        "Hook agentstate must be signed"
    );
}

/// Step 0.21: Test creating an agentstate with multiple file references.
#[test]
fn test_agentstate_multi_file_skill() {
    let mut agent = load_test_agent_one();

    let dir = tempfile::tempdir().expect("Failed to create temp dir");

    // Create 3 temp files
    let skill_path = dir.path().join("SKILL.md");
    fs::write(&skill_path, "# Multi-file Skill\n\nMain skill description.")
        .expect("Failed to write skill file");

    let script_path = dir.path().join("script.sh");
    fs::write(&script_path, "#!/bin/bash\necho 'executing skill'")
        .expect("Failed to write script file");

    let ref_path = dir.path().join("reference.md");
    fs::write(&ref_path, "# References\n\n- https://example.com")
        .expect("Failed to write reference file");

    // Build the agentstate manually with multiple jacsFiles entries
    let mut doc = create_minimal_agentstate("skill", "Multi-File Skill", Some("Skill with 3 files"))
        .expect("Should create agentstate");

    // Compute hashes for each file
    let file_paths = [&skill_path, &script_path, &ref_path];
    let mut files_array = Vec::new();
    for path in &file_paths {
        let content = fs::read_to_string(path).expect("Failed to read file");
        let hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        let mimetype = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();
        files_array.push(serde_json::json!({
            "mimetype": mimetype,
            "path": path.to_str().unwrap(),
            "embed": false,
            "sha256": hash,
        }));
    }
    doc["jacsFiles"] = serde_json::json!(files_array);

    // Load via agent
    let loaded = agent
        .create_document_and_load(&doc.to_string(), None, None)
        .expect("Should load multi-file agentstate");

    let value = loaded.getvalue();

    // Verify all 3 files are in jacsFiles
    let files = value["jacsFiles"]
        .as_array()
        .expect("Should have jacsFiles");
    assert_eq!(
        files.len(),
        3,
        "Should have 3 file entries in jacsFiles"
    );

    // Verify each entry has required fields
    for (i, file_entry) in files.iter().enumerate() {
        assert!(
            file_entry.get("sha256").is_some(),
            "File entry {} should have sha256",
            i
        );
        assert!(
            file_entry.get("path").is_some(),
            "File entry {} should have path",
            i
        );
    }

    // Verify signing
    assert!(
        value.get("jacsSignature").is_some(),
        "Multi-file agentstate must be signed"
    );
}

/// Step 0.22: Test that tampering with a referenced file is detected via hash mismatch.
#[test]
fn test_agentstate_detect_tampered_file() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let file_path = dir.path().join("SKILL.md");
    let original_content = "# Original Skill Content\n\nThis content is signed.";
    fs::write(&file_path, original_content).expect("Failed to write test file");

    // Create agentstate with file reference
    let doc = create_agentstate_with_file(
        "skill",
        "Tamper Test Skill",
        file_path.to_str().unwrap(),
        false,
    )
    .expect("Should create agentstate with file");

    // Verify hash matches before tampering
    assert!(
        verify_agentstate_file_hash(&doc).expect("Initial verify should succeed"),
        "Hash should match for unmodified file"
    );

    // Tamper with the file on disk without re-signing
    fs::write(&file_path, "# TAMPERED Content\n\nThis was modified by an attacker.")
        .expect("Failed to modify file");

    // Hash verification should detect the tampering
    assert!(
        !verify_agentstate_file_hash(&doc).expect("Verify should succeed but detect mismatch"),
        "Hash must not match for tampered file"
    );
}

/// Step 0.23: Test that all required JACS header fields are present after signing.
#[test]
fn test_agentstate_header_fields_present() {
    let mut agent = load_test_agent_one();

    let doc = create_minimal_agentstate("config", "Header Test Config", Some("Testing headers"))
        .expect("Should create agentstate");

    let loaded = agent
        .create_document_and_load(&doc.to_string(), None, None)
        .expect("Should load agentstate");

    let value = loaded.getvalue();

    // All required header fields must be present
    let required_fields = [
        "jacsId",
        "jacsVersion",
        "jacsVersionDate",
        "jacsOriginalVersion",
        "jacsOriginalDate",
        "jacsType",
        "jacsLevel",
    ];

    for field in &required_fields {
        assert!(
            value.get(*field).is_some() && !value[*field].is_null(),
            "Header field '{}' must be present and non-null in signed agentstate",
            field
        );
    }

    // jacsType should be "agentstate"
    assert_eq!(
        value["jacsType"], "agentstate",
        "jacsType must be 'agentstate'"
    );

    // jacsLevel should be "config" (set by create_minimal_agentstate)
    assert_eq!(
        value["jacsLevel"], "config",
        "jacsLevel must be 'config'"
    );

    // jacsOriginalVersion should equal jacsVersion for a newly created document
    assert_eq!(
        value["jacsOriginalVersion"], value["jacsVersion"],
        "For a new document, jacsOriginalVersion must equal jacsVersion"
    );
}

/// Step 0.24: Test that different content types all sign correctly through the agent.
#[test]
fn test_agentstate_different_content_types_signing() {
    let mut agent = load_test_agent_one();

    let content_cases = [
        ("memory", "text/markdown", "# Memory\n\nSome markdown content."),
        ("config", "application/json", r#"{"setting": "value", "debug": true}"#),
        ("hook", "text/x-shellscript", "#!/bin/bash\nset -e\nnpm test"),
    ];

    for (state_type, content_type, content) in &content_cases {
        let doc = create_agentstate_with_content(state_type, "Content Sign Test", content, content_type)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to create agentstate for {}/{}: {}",
                    state_type, content_type, e
                )
            });

        let loaded = agent
            .create_document_and_load(&doc.to_string(), None, None)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to load and sign agentstate for {}/{}: {}",
                    state_type, content_type, e
                )
            });

        let value = loaded.getvalue();

        // Each must have jacsSignature
        assert!(
            value.get("jacsSignature").is_some(),
            "Agentstate with content type '{}' must have jacsSignature",
            content_type
        );

        // Verify content is preserved
        assert_eq!(
            value["jacsAgentStateContent"], *content,
            "Content must be preserved for type '{}'",
            content_type
        );

        // Verify content type is preserved
        assert_eq!(
            value["jacsAgentStateContentType"], *content_type,
            "Content type must be preserved for '{}'",
            content_type
        );
    }
}
