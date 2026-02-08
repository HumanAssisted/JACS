use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use uuid::Uuid;

/// Creates a minimal agent state document with required fields.
///
/// # Arguments
///
/// * `state_type` - The type of agent state (memory, skill, plan, config, hook, other).
/// * `name` - Human-readable name for this state document.
/// * `description` - Optional description of what this state document contains.
///
/// # Returns
///
/// A `serde_json::Value` representing the created agent state document.
///
/// # Errors
///
/// Returns an error if `state_type` is not one of the allowed values.
pub fn create_minimal_agentstate(
    state_type: &str,
    name: &str,
    description: Option<&str>,
) -> Result<Value, String> {
    let allowed_types = ["memory", "skill", "plan", "config", "hook", "other"];
    if !allowed_types.contains(&state_type) {
        return Err(format!(
            "Invalid agent state type: '{}'. Must be one of: {:?}",
            state_type, allowed_types
        ));
    }

    let mut doc = json!({
        "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
        "jacsAgentStateType": state_type,
        "jacsAgentStateName": name,
    });

    if let Some(desc) = description {
        doc["jacsAgentStateDescription"] = json!(desc);
    }

    doc["id"] = json!(Uuid::new_v4().to_string());
    doc["jacsType"] = json!("agentstate");
    doc["jacsLevel"] = json!("config");
    Ok(doc)
}

/// Creates an agent state document that references an external file.
///
/// Reads the file, computes its SHA-256 hash, and creates a document with
/// a `jacsFiles` reference. For hook-type documents, the content is always
/// embedded regardless of the `embed` parameter.
///
/// # Arguments
///
/// * `state_type` - The type of agent state.
/// * `name` - Human-readable name for this state document.
/// * `file_path` - Path to the original file to reference.
/// * `embed` - Whether to embed the file content inline. Always true for hooks.
///
/// # Returns
///
/// A `serde_json::Value` representing the agent state document with file reference.
pub fn create_agentstate_with_file(
    state_type: &str,
    name: &str,
    file_path: &str,
    embed: bool,
) -> Result<Value, String> {
    let mut doc = create_minimal_agentstate(state_type, name, None)?;

    let content = fs::read_to_string(file_path)
        .map_err(|e| format!("Failed to read file '{}': {}", file_path, e))?;

    let hash = compute_sha256(&content);

    let mimetype = mime_guess::from_path(file_path)
        .first_or_octet_stream()
        .to_string();

    // Hooks always embed content (Decision P0-3)
    let should_embed = embed || state_type == "hook";

    let mut file_entry = json!({
        "mimetype": mimetype,
        "path": file_path,
        "embed": should_embed,
        "sha256": hash,
    });

    if should_embed {
        file_entry["contents"] = json!(content);
        doc["jacsAgentStateContent"] = json!(content);
    }

    doc["jacsAgentStateContentType"] = json!(mimetype);
    doc["jacsFiles"] = json!([file_entry]);

    Ok(doc)
}

/// Creates an agent state document with inline content.
///
/// # Arguments
///
/// * `state_type` - The type of agent state.
/// * `name` - Human-readable name for this state document.
/// * `content` - The content to embed in the document.
/// * `content_type` - MIME type of the content.
///
/// # Returns
///
/// A `serde_json::Value` representing the agent state document with inline content.
pub fn create_agentstate_with_content(
    state_type: &str,
    name: &str,
    content: &str,
    content_type: &str,
) -> Result<Value, String> {
    let mut doc = create_minimal_agentstate(state_type, name, None)?;

    doc["jacsAgentStateContent"] = json!(content);
    doc["jacsAgentStateContentType"] = json!(content_type);

    Ok(doc)
}

/// Sets the framework field on an agent state document.
///
/// # Arguments
///
/// * `doc` - A mutable reference to the agent state document.
/// * `framework` - The framework identifier (e.g., "claude-code", "openclaw").
pub fn set_agentstate_framework(doc: &mut Value, framework: &str) -> Result<(), String> {
    doc["jacsAgentStateFramework"] = json!(framework);
    Ok(())
}

/// Sets the origin and optional source URL on an agent state document.
///
/// # Arguments
///
/// * `doc` - A mutable reference to the agent state document.
/// * `origin` - Origin type: "authored", "adopted", "generated", or "imported".
/// * `source_url` - Optional URL where the content was obtained from.
///
/// # Errors
///
/// Returns an error if `origin` is not one of the allowed values.
pub fn set_agentstate_origin(
    doc: &mut Value,
    origin: &str,
    source_url: Option<&str>,
) -> Result<(), String> {
    let allowed_origins = ["authored", "adopted", "generated", "imported"];
    if !allowed_origins.contains(&origin) {
        return Err(format!(
            "Invalid origin: '{}'. Must be one of: {:?}",
            origin, allowed_origins
        ));
    }

    doc["jacsAgentStateOrigin"] = json!(origin);

    if let Some(url) = source_url {
        doc["jacsAgentStateSourceUrl"] = json!(url);
    }

    Ok(())
}

/// Sets tags on an agent state document.
///
/// # Arguments
///
/// * `doc` - A mutable reference to the agent state document.
/// * `tags` - Vector of tag strings.
pub fn set_agentstate_tags(doc: &mut Value, tags: Vec<&str>) -> Result<(), String> {
    doc["jacsAgentStateTags"] = json!(tags);
    Ok(())
}

/// Verifies that the SHA-256 hash in `jacsFiles` matches the current file content.
///
/// # Arguments
///
/// * `doc` - The agent state document to verify.
///
/// # Returns
///
/// * `Ok(true)` if all file hashes match.
/// * `Ok(false)` if any file hash does not match.
/// * `Err` if the document has no file references or files cannot be read.
pub fn verify_agentstate_file_hash(doc: &Value) -> Result<bool, String> {
    let files = doc
        .get("jacsFiles")
        .and_then(|f| f.as_array())
        .ok_or_else(|| "No jacsFiles array in document".to_string())?;

    if files.is_empty() {
        return Err("jacsFiles array is empty".to_string());
    }

    for file_entry in files {
        let path = file_entry
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| "File entry missing 'path' field".to_string())?;

        let expected_hash = file_entry
            .get("sha256")
            .and_then(|h| h.as_str())
            .ok_or_else(|| "File entry missing 'sha256' field".to_string())?;

        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;

        let actual_hash = compute_sha256(&content);

        if actual_hash != expected_hash {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Sets the content version on an agent state document.
///
/// # Arguments
///
/// * `doc` - A mutable reference to the agent state document.
/// * `version` - Version string for the content.
pub fn set_agentstate_version(doc: &mut Value, version: &str) -> Result<(), String> {
    doc["jacsAgentStateVersion"] = json!(version);
    Ok(())
}

/// Computes the SHA-256 hash of a string, returning hex-encoded result.
fn compute_sha256(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sha256() {
        let hash = compute_sha256("hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_create_minimal_agentstate_valid() {
        let doc = create_minimal_agentstate("memory", "Test Memory", Some("A test memory"))
            .expect("Should create valid agentstate");
        assert_eq!(doc["jacsAgentStateType"], "memory");
        assert_eq!(doc["jacsAgentStateName"], "Test Memory");
        assert_eq!(doc["jacsAgentStateDescription"], "A test memory");
        assert_eq!(doc["jacsType"], "agentstate");
        assert_eq!(doc["jacsLevel"], "config");
    }

    #[test]
    fn test_create_minimal_agentstate_invalid_type() {
        let result = create_minimal_agentstate("invalid", "Test", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid agent state type"));
    }

    #[test]
    fn test_set_agentstate_origin_valid() {
        let mut doc = create_minimal_agentstate("skill", "Test Skill", None).unwrap();
        set_agentstate_origin(&mut doc, "adopted", Some("https://example.com/skill")).unwrap();
        assert_eq!(doc["jacsAgentStateOrigin"], "adopted");
        assert_eq!(doc["jacsAgentStateSourceUrl"], "https://example.com/skill");
    }

    #[test]
    fn test_set_agentstate_origin_invalid() {
        let mut doc = create_minimal_agentstate("skill", "Test Skill", None).unwrap();
        let result = set_agentstate_origin(&mut doc, "bogus", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_agentstate_tags() {
        let mut doc = create_minimal_agentstate("memory", "Test", None).unwrap();
        set_agentstate_tags(&mut doc, vec!["crypto", "signing"]).unwrap();
        let tags = doc["jacsAgentStateTags"].as_array().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0], "crypto");
    }
}
