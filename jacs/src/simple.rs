//! Simplified JACS API for common operations.
//!
//! This module provides a clean, developer-friendly API for the most common
//! JACS operations: creating agents, signing messages/files, and verification.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use jacs::simple::{create, sign_message, verify};
//!
//! // Create a new agent identity
//! let info = create("my-agent", None, None)?;
//!
//! // Sign a message
//! let signed = sign_message(&serde_json::json!({"hello": "world"}))?;
//!
//! // Verify the signed document
//! let result = verify(&signed.raw)?;
//! assert!(result.valid);
//! ```
//!
//! # Design Philosophy
//!
//! This API is a facade over the existing JACS functionality, designed for:
//! - **Simplicity**: 6 core operations cover 90% of use cases
//! - **Safety**: Errors include actionable guidance
//! - **Consistency**: Same API shape across Rust, Python, Go, and NPM

use crate::agent::document::DocumentTraits;
use crate::agent::Agent;
use crate::error::JacsError;
use crate::mime::mime_from_extension;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

// =============================================================================
// Types
// =============================================================================

/// Information about a created or loaded agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Unique identifier for the agent (UUID).
    pub agent_id: String,
    /// Human-readable name of the agent.
    pub name: String,
    /// Path to the public key file.
    pub public_key_path: String,
    /// Path to the configuration file.
    pub config_path: String,
}

/// A signed JACS document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDocument {
    /// The full JSON string of the signed JACS document.
    pub raw: String,
    /// Unique identifier for this document (UUID).
    pub document_id: String,
    /// ID of the agent that signed this document.
    pub agent_id: String,
    /// ISO 8601 timestamp of when the document was signed.
    pub timestamp: String,
}

/// Result of verifying a signed document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the signature is valid.
    pub valid: bool,
    /// The original data that was signed (extracted from the document).
    pub data: Value,
    /// ID of the agent that signed the document.
    pub signer_id: String,
    /// Name of the signer (if available in trust store).
    pub signer_name: Option<String>,
    /// ISO 8601 timestamp of when the document was signed.
    pub timestamp: String,
    /// Any file attachments included in the document.
    pub attachments: Vec<Attachment>,
    /// Error messages if verification failed.
    pub errors: Vec<String>,
}

/// A file attachment in a signed document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Original filename.
    pub filename: String,
    /// MIME type of the file.
    pub mime_type: String,
    /// File content (decoded if it was embedded).
    #[serde(with = "base64_bytes")]
    pub content: Vec<u8>,
    /// SHA-256 hash of the original file.
    pub hash: String,
    /// Whether the file was embedded (true) or referenced (false).
    pub embedded: bool,
}

// Custom serialization for Vec<u8> as base64
mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

// =============================================================================
// Global Agent State
// =============================================================================

lazy_static::lazy_static! {
    /// Global agent instance for module-level convenience functions.
    static ref GLOBAL_AGENT: Arc<Mutex<Option<Agent>>> = Arc::new(Mutex::new(None));
}

/// Ensures an agent is loaded, returning an error if not.
fn ensure_loaded() -> Result<(), JacsError> {
    let guard = GLOBAL_AGENT.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    if guard.is_none() {
        return Err(JacsError::AgentNotLoaded);
    }
    Ok(())
}

/// Executes a function with the global agent.
fn with_agent<F, T>(f: F) -> Result<T, JacsError>
where
    F: FnOnce(&mut Agent) -> Result<T, JacsError>,
{
    let mut guard = GLOBAL_AGENT.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    let agent = guard.as_mut().ok_or(JacsError::AgentNotLoaded)?;
    f(agent)
}

// =============================================================================
// Core Operations
// =============================================================================

/// Creates a new JACS agent with persistent identity.
///
/// This generates cryptographic keys, creates configuration files, and saves
/// them to the current working directory.
///
/// # Arguments
///
/// * `name` - Human-readable name for the agent
/// * `purpose` - Optional description of the agent's purpose
/// * `key_algorithm` - Signing algorithm: "ed25519" (default), "rsa-pss", or "pq2025"
///
/// # Returns
///
/// `AgentInfo` containing the agent ID, name, and file paths.
///
/// # Files Created
///
/// * `./jacs.config.json` - Configuration file
/// * `./jacs.agent.json` - Signed agent identity (in jacs_data/agent/)
/// * `./jacs_keys/` - Directory containing public and private keys
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::create;
///
/// let info = create("my-agent", Some("Signing documents"), None)?;
/// println!("Agent created: {}", info.agent_id);
/// ```
pub fn create(
    name: &str,
    purpose: Option<&str>,
    key_algorithm: Option<&str>,
) -> Result<AgentInfo, JacsError> {
    let algorithm = key_algorithm.unwrap_or("ed25519");

    info!("Creating new agent '{}' with algorithm '{}'", name, algorithm);

    // Create directories if they don't exist
    let keys_dir = Path::new("./jacs_keys");
    let data_dir = Path::new("./jacs_data");

    fs::create_dir_all(keys_dir).map_err(|e| JacsError::Internal {
        message: format!("Failed to create keys directory: {}", e),
    })?;
    fs::create_dir_all(data_dir).map_err(|e| JacsError::Internal {
        message: format!("Failed to create data directory: {}", e),
    })?;

    // Create a minimal agent JSON
    let agent_type = "ai";
    let description = purpose.unwrap_or("JACS agent");

    let agent_json = json!({
        "jacsAgentType": agent_type,
        "name": name,
        "description": description,
    });

    // Create the agent
    let mut agent = crate::get_empty_agent();

    // Note: algorithm is passed to create_agent_and_load below

    // Create agent with keys
    let instance = agent
        .create_agent_and_load(&agent_json.to_string(), true, Some(algorithm))
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to create agent: {}", e),
        })?;

    // Extract agent info
    let agent_id = instance["jacsId"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let version = instance["jacsVersion"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    // Save the agent
    let lookup_id = format!("{}:{}", agent_id, version);
    agent.save().map_err(|e| JacsError::Internal {
        message: format!("Failed to save agent: {}", e),
    })?;

    // Create config file
    let config_json = json!({
        "$schema": "https://hai.ai/schemas/jacs.config.schema.json",
        "jacs_agent_id_and_version": lookup_id,
        "jacs_data_directory": "./jacs_data",
        "jacs_key_directory": "./jacs_keys",
        "jacs_agent_key_algorithm": algorithm,
        "jacs_default_storage": "fs"
    });

    let config_path = "./jacs.config.json";
    let config_str = serde_json::to_string_pretty(&config_json).map_err(|e| JacsError::Internal {
        message: format!("Failed to serialize config: {}", e),
    })?;
    fs::write(config_path, config_str).map_err(|e| JacsError::Internal {
        message: format!("Failed to write config: {}", e),
    })?;

    // Store agent globally
    {
        let mut guard = GLOBAL_AGENT.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire lock: {}", e),
        })?;
        *guard = Some(agent);
    }

    info!("Agent '{}' created successfully with ID {}", name, agent_id);

    Ok(AgentInfo {
        agent_id,
        name: name.to_string(),
        public_key_path: format!("./jacs_keys/jacs.public.pem"),
        config_path: config_path.to_string(),
    })
}

/// Loads an existing agent from a configuration file.
///
/// # Arguments
///
/// * `config_path` - Path to the configuration file (default: "./jacs.config.json")
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::load;
///
/// load(None)?;  // Load from ./jacs.config.json
/// // or
/// load(Some("./my-agent/jacs.config.json"))?;
/// ```
pub fn load(config_path: Option<&str>) -> Result<(), JacsError> {
    let path = config_path.unwrap_or("./jacs.config.json");

    debug!("Loading agent from config: {}", path);

    if !Path::new(path).exists() {
        return Err(JacsError::ConfigNotFound {
            path: path.to_string(),
        });
    }

    let mut agent = crate::get_empty_agent();
    agent.load_by_config(path.to_string()).map_err(|e| {
        JacsError::ConfigInvalid {
            field: "config".to_string(),
            reason: e.to_string(),
        }
    })?;

    // Store agent globally
    {
        let mut guard = GLOBAL_AGENT.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire lock: {}", e),
        })?;
        *guard = Some(agent);
    }

    info!("Agent loaded successfully from {}", path);
    Ok(())
}

/// Verifies the loaded agent's own identity.
///
/// This checks:
/// 1. Self-signature validity
/// 2. Document hash integrity
/// 3. DNS TXT record (if domain is configured)
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::{load, verify_self};
///
/// load(None)?;
/// let result = verify_self()?;
/// assert!(result.valid);
/// ```
pub fn verify_self() -> Result<VerificationResult, JacsError> {
    ensure_loaded()?;

    with_agent(|agent| {
        // Verify self-signature
        let sig_result = agent.verify_self_signature();
        let hash_result = agent.verify_self_hash();

        let mut errors = Vec::new();

        if let Err(e) = sig_result {
            errors.push(format!("Signature verification failed: {}", e));
        }

        if let Err(e) = hash_result {
            errors.push(format!("Hash verification failed: {}", e));
        }

        let valid = errors.is_empty();

        // Extract agent info
        let agent_value = agent.get_value().cloned().unwrap_or(json!({}));
        let agent_id = agent_value["jacsId"].as_str().unwrap_or("").to_string();
        let agent_name = agent_value["name"].as_str().map(|s| s.to_string());
        let timestamp = agent_value["jacsVersionDate"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(VerificationResult {
            valid,
            data: agent_value,
            signer_id: agent_id.clone(),
            signer_name: agent_name,
            timestamp,
            attachments: vec![],
            errors,
        })
    })
}

/// Signs arbitrary data as a JACS message.
///
/// The data can be a JSON object, string, or any serializable value.
///
/// # Arguments
///
/// * `data` - The data to sign (will be JSON-serialized)
///
/// # Returns
///
/// A `SignedDocument` containing the full signed document.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::{load, sign_message};
/// use serde_json::json;
///
/// load(None)?;
/// let signed = sign_message(&json!({"action": "approve", "amount": 100}))?;
/// println!("Document ID: {}", signed.document_id);
/// ```
pub fn sign_message(data: &Value) -> Result<SignedDocument, JacsError> {
    ensure_loaded()?;

    with_agent(|agent| {
        // Wrap the data in a minimal document structure
        let doc_content = json!({
            "jacsType": "message",
            "jacsLevel": "raw",
            "content": data
        });

        let jacs_doc = agent
            .create_document_and_load(&doc_content.to_string(), None, None)
            .map_err(|e| JacsError::SigningFailed {
                reason: e.to_string(),
            })?;

        let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize document: {}", e),
        })?;

        let timestamp = jacs_doc.value["jacsSignature"]["date"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let agent_id = jacs_doc.value["jacsSignature"]["agentID"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(SignedDocument {
            raw,
            document_id: jacs_doc.id,
            agent_id,
            timestamp,
        })
    })
}

/// Signs a file with optional content embedding.
///
/// # Arguments
///
/// * `file_path` - Path to the file to sign
/// * `embed` - If true, embed file content; if false, store only hash reference
///
/// # Returns
///
/// A `SignedDocument` containing the signed file reference or embedded content.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::{load, sign_file};
///
/// load(None)?;
///
/// // Embed the file content
/// let signed = sign_file("contract.pdf", true)?;
///
/// // Or just reference it by hash
/// let signed = sign_file("large-video.mp4", false)?;
/// ```
pub fn sign_file(file_path: &str, embed: bool) -> Result<SignedDocument, JacsError> {
    ensure_loaded()?;

    // Check file exists
    if !Path::new(file_path).exists() {
        return Err(JacsError::FileNotFound {
            path: file_path.to_string(),
        });
    }

    let mime_type = mime_from_extension(file_path);
    let filename = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");

    with_agent(|agent| {
        // Create document with file attachment
        let doc_content = json!({
            "jacsType": "file",
            "jacsLevel": "raw",
            "filename": filename,
            "mimetype": mime_type
        });

        let attachment = vec![file_path.to_string()];

        let jacs_doc = agent
            .create_document_and_load(&doc_content.to_string(), Some(attachment), Some(embed))
            .map_err(|e| JacsError::SigningFailed {
                reason: e.to_string(),
            })?;

        let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize document: {}", e),
        })?;

        let timestamp = jacs_doc.value["jacsSignature"]["date"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let agent_id = jacs_doc.value["jacsSignature"]["agentID"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(SignedDocument {
            raw,
            document_id: jacs_doc.id,
            agent_id,
            timestamp,
        })
    })
}

/// Verifies a signed document and extracts its content.
///
/// This function auto-detects whether the document contains a message or file.
///
/// # Arguments
///
/// * `signed_document` - The JSON string of the signed document
///
/// # Returns
///
/// A `VerificationResult` with the verification status and extracted content.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::{load, verify};
///
/// load(None)?;
/// let result = verify(&signed_json)?;
/// if result.valid {
///     println!("Content: {}", result.data);
/// } else {
///     println!("Verification failed: {:?}", result.errors);
/// }
/// ```
pub fn verify(signed_document: &str) -> Result<VerificationResult, JacsError> {
    ensure_loaded()?;

    // Parse the document to validate JSON
    let _: Value = serde_json::from_str(signed_document).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "json".to_string(),
            reason: e.to_string(),
        }
    })?;

    with_agent(|agent| {
        // Load the document
        let jacs_doc = agent.load_document(signed_document).map_err(|e| {
            JacsError::DocumentMalformed {
                field: "document".to_string(),
                reason: e.to_string(),
            }
        })?;

        let document_key = jacs_doc.getkey();

        // Verify the signature
        let verification_result = agent.verify_document_signature(&document_key, None, None, None, None);

        let mut errors = Vec::new();
        if let Err(e) = verification_result {
            errors.push(e.to_string());
        }

        // Verify hash
        if let Err(e) = agent.verify_hash(&jacs_doc.value) {
            errors.push(format!("Hash verification failed: {}", e));
        }

        let valid = errors.is_empty();

        // Extract signer info
        let signer_id = jacs_doc.value["jacsSignature"]["agentID"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let timestamp = jacs_doc.value["jacsSignature"]["date"]
            .as_str()
            .unwrap_or("")
            .to_string();

        // Extract original content
        let data = if let Some(content) = jacs_doc.value.get("content") {
            content.clone()
        } else {
            jacs_doc.value.clone()
        };

        // Extract attachments
        let attachments = extract_attachments(&jacs_doc.value);

        Ok(VerificationResult {
            valid,
            data,
            signer_id,
            signer_name: None, // TODO: Look up in trust store
            timestamp,
            attachments,
            errors,
        })
    })
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Extracts file attachments from a JACS document.
fn extract_attachments(doc: &Value) -> Vec<Attachment> {
    let mut attachments = Vec::new();

    if let Some(files) = doc.get("jacsFiles").and_then(|f| f.as_array()) {
        for file in files {
            let filename = file["path"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let mime_type = file["mimetype"]
                .as_str()
                .unwrap_or("application/octet-stream")
                .to_string();
            let hash = file["sha256"].as_str().unwrap_or("").to_string();
            let embedded = file["embed"].as_bool().unwrap_or(false);

            let content = if embedded {
                if let Some(contents_b64) = file["contents"].as_str() {
                    use base64::{Engine as _, engine::general_purpose::STANDARD};
                    STANDARD.decode(contents_b64).unwrap_or_default()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            attachments.push(Attachment {
                filename,
                mime_type,
                content,
                hash,
                embedded,
            });
        }
    }

    attachments
}

/// Exports the current agent's identity JSON for P2P exchange.
pub fn export_agent() -> Result<String, JacsError> {
    ensure_loaded()?;

    with_agent(|agent| {
        let value = agent.get_value().cloned().ok_or(JacsError::AgentNotLoaded)?;
        serde_json::to_string_pretty(&value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize agent: {}", e),
        })
    })
}

/// Returns the current agent's public key in PEM format.
pub fn get_public_key_pem() -> Result<String, JacsError> {
    ensure_loaded()?;

    // Read from the standard key file location
    let key_path = "./jacs_keys/jacs.public.pem";
    fs::read_to_string(key_path).map_err(|_| JacsError::KeyNotFound {
        path: key_path.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::env;

    #[test]
    fn test_agent_info_serialization() {
        let info = AgentInfo {
            agent_id: "test-id".to_string(),
            name: "Test Agent".to_string(),
            public_key_path: "./keys/public.pem".to_string(),
            config_path: "./config.json".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test-id"));
        assert!(json.contains("Test Agent"));
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult {
            valid: true,
            data: json!({"test": "data"}),
            signer_id: "agent-123".to_string(),
            signer_name: Some("Test Agent".to_string()),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            attachments: vec![],
            errors: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("agent-123"));
    }

    #[test]
    fn test_signed_document_serialization() {
        let doc = SignedDocument {
            raw: r#"{"test":"doc"}"#.to_string(),
            document_id: "doc-456".to_string(),
            agent_id: "agent-789".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("doc-456"));
        assert!(json.contains("agent-789"));
    }

    #[test]
    fn test_attachment_serialization() {
        let att = Attachment {
            filename: "test.txt".to_string(),
            mime_type: "text/plain".to_string(),
            content: b"hello world".to_vec(),
            hash: "abc123".to_string(),
            embedded: true,
        };

        let json = serde_json::to_string(&att).unwrap();
        assert!(json.contains("test.txt"));
        assert!(json.contains("text/plain"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_ensure_loaded_fails_when_no_agent() {
        // Reset global agent
        {
            let mut guard = GLOBAL_AGENT.lock().unwrap();
            *guard = None;
        }

        let result = ensure_loaded();
        assert!(result.is_err());

        match result {
            Err(JacsError::AgentNotLoaded) => (),
            _ => panic!("Expected AgentNotLoaded error"),
        }
    }

    #[test]
    fn test_load_missing_config() {
        let result = load(Some("/nonexistent/path/config.json"));
        assert!(result.is_err());

        match result {
            Err(JacsError::ConfigNotFound { path }) => {
                assert!(path.contains("nonexistent"));
            }
            _ => panic!("Expected ConfigNotFound error"),
        }
    }

    #[test]
    fn test_sign_file_missing_file() {
        // First we need a loaded agent for this test
        // Since no agent is loaded, it should fail with AgentNotLoaded first
        let result = sign_file("/nonexistent/file.txt", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_result_with_errors() {
        let result = VerificationResult {
            valid: false,
            data: json!(null),
            signer_id: "".to_string(),
            signer_name: None,
            timestamp: "".to_string(),
            attachments: vec![],
            errors: vec![
                "Signature invalid".to_string(),
                "Hash mismatch".to_string(),
            ],
        };

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 2);
        assert!(result.errors[0].contains("Signature"));
        assert!(result.errors[1].contains("Hash"));
    }

    #[test]
    fn test_extract_attachments_empty() {
        let doc = json!({});
        let attachments = extract_attachments(&doc);
        assert!(attachments.is_empty());
    }

    #[test]
    fn test_extract_attachments_with_files() {
        let doc = json!({
            "jacsFiles": [
                {
                    "path": "document.pdf",
                    "mimetype": "application/pdf",
                    "sha256": "abcdef123456",
                    "embed": false
                },
                {
                    "path": "image.png",
                    "mimetype": "image/png",
                    "sha256": "fedcba654321",
                    "embed": true,
                    "contents": "SGVsbG8gV29ybGQ="
                }
            ]
        });

        let attachments = extract_attachments(&doc);
        assert_eq!(attachments.len(), 2);

        assert_eq!(attachments[0].filename, "document.pdf");
        assert_eq!(attachments[0].mime_type, "application/pdf");
        assert!(!attachments[0].embedded);
        assert!(attachments[0].content.is_empty());

        assert_eq!(attachments[1].filename, "image.png");
        assert_eq!(attachments[1].mime_type, "image/png");
        assert!(attachments[1].embedded);
        assert!(!attachments[1].content.is_empty());
    }

    #[test]
    fn test_get_public_key_pem_not_found() {
        // Reset global agent and set a dummy
        {
            let mut guard = GLOBAL_AGENT.lock().unwrap();
            *guard = Some(crate::get_empty_agent());
        }

        // This should fail because the key file doesn't exist
        let result = get_public_key_pem();
        assert!(result.is_err());
    }
}
