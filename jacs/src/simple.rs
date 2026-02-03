//! Simplified JACS API for common operations.
//!
//! This module provides a clean, developer-friendly API for the most common
//! JACS operations: creating agents, signing messages/files, and verification.
//!
//! # IMPORTANT: Signing is Sacred
//!
//! **Signing a document is a permanent, irreversible cryptographic commitment.**
//!
//! When an agent signs a document:
//! - The signature creates proof that binds the signer to the content forever
//! - The signer cannot deny having signed (non-repudiation)
//! - Anyone can verify the signature at any time
//! - The signer is accountable for what they signed
//!
//! **Always review documents carefully before signing.** Do not sign:
//! - Content you haven't read or don't understand
//! - Documents whose implications you haven't considered
//! - Anything you wouldn't want permanently associated with your identity
//!
//! # Quick Start (Instance-based API - Recommended)
//!
//! ```rust,ignore
//! use jacs::simple::SimpleAgent;
//!
//! // Create a new agent identity
//! let agent = SimpleAgent::create("my-agent", None, None)?;
//!
//! // Sign a message (REVIEW CONTENT FIRST!)
//! let signed = agent.sign_message(&serde_json::json!({"hello": "world"}))?;
//!
//! // Verify the signed document
//! let result = agent.verify(&signed.raw)?;
//! assert!(result.valid);
//! ```
//!
//! # Loading an Existing Agent
//!
//! ```rust,ignore
//! use jacs::simple::SimpleAgent;
//!
//! // Load from default config path
//! let agent = SimpleAgent::load(None)?;
//!
//! // Or from a specific config
//! let agent = SimpleAgent::load(Some("./my-agent/jacs.config.json"))?;
//! ```
//!
//! # Design Philosophy
//!
//! This API is a facade over the existing JACS functionality, designed for:
//! - **Simplicity**: 6 core operations cover 90% of use cases
//! - **Safety**: Errors include actionable guidance
//! - **Consistency**: Same API shape across Rust, Python, Go, and NPM
//! - **Thread Safety**: Instance-based design avoids global mutable state
//! - **Signing Gravity**: Documentation emphasizes the sacred nature of signing

use crate::agent::document::DocumentTraits;
use crate::agent::Agent;
use crate::error::JacsError;
use crate::mime::mime_from_extension;
use crate::schema::utils::{check_document_size, ValueExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
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

impl VerificationResult {
    /// Creates a failed verification result with the given error message.
    ///
    /// This is a convenience constructor for creating a `VerificationResult`
    /// that represents a failed verification.
    ///
    /// # Arguments
    ///
    /// * `error` - The error message describing why verification failed
    ///
    /// # Returns
    ///
    /// A `VerificationResult` with `valid: false` and the error in the `errors` field.
    #[must_use]
    pub fn failure(error: String) -> Self {
        Self {
            valid: false,
            data: json!(null),
            signer_id: String::new(),
            signer_name: None,
            timestamp: String::new(),
            attachments: vec![],
            errors: vec![error],
        }
    }

    /// Creates a successful verification result.
    ///
    /// # Arguments
    ///
    /// * `data` - The verified data/content
    /// * `signer_id` - The ID of the agent that signed the document
    /// * `timestamp` - The timestamp when the document was signed
    ///
    /// # Returns
    ///
    /// A `VerificationResult` with `valid: true` and no errors.
    #[must_use]
    pub fn success(data: Value, signer_id: String, timestamp: String) -> Self {
        Self {
            valid: true,
            data,
            signer_id,
            signer_name: None,
            timestamp,
            attachments: vec![],
            errors: vec![],
        }
    }
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

/// Status of a single signer in a multi-party agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerStatus {
    /// Unique identifier of the signing agent.
    pub agent_id: String,
    /// Whether this agent has signed the agreement.
    pub signed: bool,
    /// ISO 8601 timestamp when the agent signed (if signed).
    pub signed_at: Option<String>,
}

/// Status of a multi-party agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgreementStatus {
    /// Whether all required parties have signed.
    pub complete: bool,
    /// List of signers and their status.
    pub signers: Vec<SignerStatus>,
    /// List of agent IDs that haven't signed yet.
    pub pending: Vec<String>,
}

// =============================================================================
// SimpleAgent - Instance-based API (Recommended)
// =============================================================================

/// A wrapper around the JACS Agent that provides a simplified, instance-based API.
///
/// This struct owns an Agent instance and provides methods for common operations
/// like signing and verification. Unlike the deprecated module-level functions,
/// `SimpleAgent` does not use global mutable state, making it thread-safe when
/// used with appropriate synchronization.
///
/// # Thread Safety
///
/// `SimpleAgent` uses interior mutability via `Mutex` to allow safe concurrent
/// access to the underlying Agent. Multiple threads can share a `SimpleAgent`
/// wrapped in an `Arc`.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use std::sync::Arc;
///
/// // Create and share across threads
/// let agent = Arc::new(SimpleAgent::create("my-agent", None, None)?);
///
/// let agent_clone = Arc::clone(&agent);
/// std::thread::spawn(move || {
///     let signed = agent_clone.sign_message(&serde_json::json!({"thread": 1})).unwrap();
/// });
/// ```
pub struct SimpleAgent {
    agent: Mutex<Agent>,
    config_path: Option<String>,
}

impl SimpleAgent {
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
    /// A `SimpleAgent` instance ready for use, along with `AgentInfo` containing
    /// the agent ID, name, and file paths.
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
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::create("my-agent", Some("Signing documents"), None)?;
    /// println!("Agent created successfully");
    /// ```
    #[must_use = "agent creation result must be checked for errors"]
    pub fn create(
        name: &str,
        purpose: Option<&str>,
        key_algorithm: Option<&str>,
    ) -> Result<(Self, AgentInfo), JacsError> {
        let algorithm = key_algorithm.unwrap_or("ed25519");

        info!("Creating new agent '{}' with algorithm '{}'", name, algorithm);

        // Create directories if they don't exist
        let keys_dir = Path::new("./jacs_keys");
        let data_dir = Path::new("./jacs_data");

        fs::create_dir_all(keys_dir).map_err(|e| JacsError::DirectoryCreateFailed {
            path: keys_dir.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
        fs::create_dir_all(data_dir).map_err(|e| JacsError::DirectoryCreateFailed {
            path: data_dir.to_string_lossy().to_string(),
            reason: e.to_string(),
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

        info!("Agent '{}' created successfully with ID {}", name, agent_id);

        let info = AgentInfo {
            agent_id,
            name: name.to_string(),
            public_key_path: "./jacs_keys/jacs.public.pem".to_string(),
            config_path: config_path.to_string(),
        };

        Ok((
            Self {
                agent: Mutex::new(agent),
                config_path: Some(config_path.to_string()),
            },
            info,
        ))
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
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;  // Load from ./jacs.config.json
    /// // or
    /// let agent = SimpleAgent::load(Some("./my-agent/jacs.config.json"))?;
    /// ```
    #[must_use = "agent loading result must be checked for errors"]
    pub fn load(config_path: Option<&str>) -> Result<Self, JacsError> {
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

        info!("Agent loaded successfully from {}", path);

        Ok(Self {
            agent: Mutex::new(agent),
            config_path: Some(path.to_string()),
        })
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
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let result = agent.verify_self()?;
    /// assert!(result.valid);
    /// ```
    #[must_use = "self-verification result must be checked"]
    pub fn verify_self(&self) -> Result<VerificationResult, JacsError> {
        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

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
        let agent_id = agent_value.get_str_or("jacsId", "");
        let agent_name = agent_value.get_str("name");
        let timestamp = agent_value.get_str_or("jacsVersionDate", "");

        Ok(VerificationResult {
            valid,
            data: agent_value,
            signer_id: agent_id.clone(),
            signer_name: agent_name,
            timestamp,
            attachments: vec![],
            errors,
        })
    }

    /// Updates the current agent with new data and re-signs it.
    ///
    /// This function expects a complete agent document (not partial updates).
    /// Use `export_agent()` to get the current document, modify it, then pass it here.
    /// The function will create a new version, re-sign, and re-hash the document.
    ///
    /// # Arguments
    ///
    /// * `new_agent_data` - Complete agent document as a JSON string
    ///
    /// # Returns
    ///
    /// The updated and re-signed agent document as a JSON string.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Get current agent, modify, and update
    /// let agent_doc: serde_json::Value = serde_json::from_str(&agent.export_agent()?)?;
    /// let mut modified = agent_doc.clone();
    /// modified["jacsAgentType"] = json!("updated-service");
    /// let updated = agent.update_agent(&modified.to_string())?;
    /// println!("Agent updated with new version");
    /// ```
    #[must_use = "updated agent JSON must be used or stored"]
    pub fn update_agent(&self, new_agent_data: &str) -> Result<String, JacsError> {
        // Check document size before processing
        check_document_size(new_agent_data)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        agent.update_self(new_agent_data).map_err(|e| JacsError::Internal {
            message: format!("Failed to update agent: {}", e),
        })
    }

    /// Updates an existing document with new data and re-signs it.
    ///
    /// Use `sign_message()` to create a document first, then use this to update it.
    /// The function will create a new version, re-sign, and re-hash the document.
    ///
    /// # Arguments
    ///
    /// * `document_id` - The document ID (jacsId) to update
    /// * `new_data` - The updated document as a JSON string
    /// * `attachments` - Optional list of file paths to attach
    /// * `embed` - If true, embed attachment contents
    ///
    /// # Returns
    ///
    /// A `SignedDocument` with the updated document.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Create a document first
    /// let signed = agent.sign_message(&json!({"status": "pending"}))?;
    ///
    /// // Later, update it
    /// let doc: serde_json::Value = serde_json::from_str(&signed.raw)?;
    /// let mut modified = doc.clone();
    /// modified["content"]["status"] = json!("approved");
    /// let updated = agent.update_document(
    ///     &signed.document_id,
    ///     &modified.to_string(),
    ///     None,
    ///     None
    /// )?;
    /// println!("Document updated with new version");
    /// ```
    #[must_use = "updated document must be used or stored"]
    pub fn update_document(
        &self,
        document_id: &str,
        new_data: &str,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> Result<SignedDocument, JacsError> {
        // Check document size before processing
        check_document_size(new_data)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let jacs_doc = agent
            .update_document(document_id, new_data, attachments, embed)
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to update document: {}", e),
            })?;

        let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize document: {}", e),
        })?;

        let timestamp = jacs_doc.value.get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = jacs_doc.value.get_path_str_or(&["jacsSignature", "agentID"], "");

        Ok(SignedDocument {
            raw,
            document_id: jacs_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Signs arbitrary data as a JACS message.
    ///
    /// # IMPORTANT: Signing is Sacred
    ///
    /// **Signing a document is an irreversible, permanent commitment.** Once signed:
    /// - The signature creates cryptographic proof binding you to the content
    /// - You cannot deny having signed (non-repudiation)
    /// - The signed document can be verified by anyone forever
    /// - You are accountable for the content you signed
    ///
    /// **Before signing, always:**
    /// - Read and understand the complete document content
    /// - Verify the data represents your actual intent
    /// - Confirm you have authority to make this commitment
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
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// // Review data carefully before signing!
    /// let signed = agent.sign_message(&json!({"action": "approve", "amount": 100}))?;
    /// println!("Document ID: {}", signed.document_id);
    /// ```
    #[must_use = "signed document must be used or stored"]
    pub fn sign_message(&self, data: &Value) -> Result<SignedDocument, JacsError> {
        debug!("sign_message() called");

        // Wrap the data in a minimal document structure
        let doc_content = json!({
            "jacsType": "message",
            "jacsLevel": "raw",
            "content": data
        });

        // Check document size before processing
        let doc_string = doc_content.to_string();
        check_document_size(&doc_string)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let jacs_doc = agent
            .create_document_and_load(&doc_string, None, None)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!(
                    "{}. Ensure the agent is properly initialized with load() or create() and has valid keys.",
                    e
                ),
            })?;

        let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize document: {}", e),
        })?;

        let timestamp = jacs_doc.value.get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = jacs_doc.value.get_path_str_or(&["jacsSignature", "agentID"], "");

        info!("Message signed: document_id={}", jacs_doc.id);

        Ok(SignedDocument {
            raw,
            document_id: jacs_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Signs a file with optional content embedding.
    ///
    /// # IMPORTANT: Signing is Sacred
    ///
    /// **Signing a file is an irreversible, permanent commitment.** Your signature:
    /// - Cryptographically binds you to the file's exact contents
    /// - Cannot be revoked or denied (non-repudiation)
    /// - Creates permanent proof that you attested to this file
    /// - Makes you accountable for the file content forever
    ///
    /// **Before signing any file:**
    /// - Review the complete file contents
    /// - Verify the file has not been tampered with
    /// - Confirm you intend to attest to this specific file
    /// - Understand your signature is permanent and verifiable
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
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Review file before signing! Embed the file content
    /// let signed = agent.sign_file("contract.pdf", true)?;
    ///
    /// // Or just reference it by hash
    /// let signed = agent.sign_file("large-video.mp4", false)?;
    /// ```
    #[must_use = "signed document must be used or stored"]
    pub fn sign_file(&self, file_path: &str, embed: bool) -> Result<SignedDocument, JacsError> {
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

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

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
                reason: format!(
                    "File signing failed for '{}': {}. Verify the file exists and the agent has valid keys.",
                    file_path, e
                ),
            })?;

        let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize document: {}", e),
        })?;

        let timestamp = jacs_doc.value.get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = jacs_doc.value.get_path_str_or(&["jacsSignature", "agentID"], "");

        Ok(SignedDocument {
            raw,
            document_id: jacs_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Signs multiple messages in a batch operation.
    ///
    /// # IMPORTANT: Each Signature is Sacred
    ///
    /// **Every signature in the batch is an irreversible, permanent commitment.**
    /// Batch signing is convenient, but each document is independently signed with
    /// full cryptographic weight. Before batch signing:
    /// - Review ALL messages in the batch
    /// - Verify each message represents your intent
    /// - Understand you are making multiple permanent commitments
    ///
    /// This is more efficient than calling `sign_message` repeatedly because it
    /// amortizes the overhead of acquiring locks and key operations across all
    /// messages.
    ///
    /// # Arguments
    ///
    /// * `messages` - A slice of JSON values to sign
    ///
    /// # Returns
    ///
    /// A vector of `SignedDocument` objects, one for each input message, in the
    /// same order as the input slice.
    ///
    /// # Errors
    ///
    /// Returns an error if signing any message fails. In case of failure,
    /// documents created before the failure are still stored but the partial
    /// results are not returned (all-or-nothing return semantics).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Review ALL messages before batch signing!
    /// let messages = vec![
    ///     json!({"action": "approve", "item": 1}),
    ///     json!({"action": "approve", "item": 2}),
    ///     json!({"action": "reject", "item": 3}),
    /// ];
    ///
    /// let refs: Vec<&serde_json::Value> = messages.iter().collect();
    /// let signed_docs = agent.sign_messages_batch(&refs)?;
    ///
    /// for doc in &signed_docs {
    ///     println!("Signed document: {}", doc.document_id);
    /// }
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - The agent lock is acquired once for the entire batch
    /// - Key decryption overhead is amortized across all messages
    /// - For very large batches, consider splitting into smaller chunks
    pub fn sign_messages_batch(&self, messages: &[&Value]) -> Result<Vec<SignedDocument>, JacsError> {
        use crate::agent::document::DocumentTraits;
        use tracing::info;

        if messages.is_empty() {
            return Ok(Vec::new());
        }

        info!(
            batch_size = messages.len(),
            "Signing batch of messages"
        );

        // Prepare all document JSON strings
        let doc_strings: Vec<String> = messages
            .iter()
            .map(|data| {
                let doc_content = json!({
                    "jacsType": "message",
                    "jacsLevel": "raw",
                    "content": data
                });
                doc_content.to_string()
            })
            .collect();

        // Check size of each document before processing
        for doc_str in &doc_strings {
            check_document_size(doc_str)?;
        }

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Convert to slice of &str for the batch API
        let doc_refs: Vec<&str> = doc_strings.iter().map(|s| s.as_str()).collect();

        // Use the batch document creation API
        let jacs_docs = agent
            .create_documents_batch(&doc_refs)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!(
                    "Batch signing failed: {}. Ensure the agent is properly initialized with load() or create() and has valid keys.",
                    e
                ),
            })?;

        // Convert to SignedDocument results
        let mut results = Vec::with_capacity(jacs_docs.len());
        for jacs_doc in jacs_docs {
            let raw = serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
                message: format!("Failed to serialize document: {}", e),
            })?;

            let timestamp = jacs_doc.value.get_path_str_or(&["jacsSignature", "date"], "");
            let agent_id = jacs_doc.value.get_path_str_or(&["jacsSignature", "agentID"], "");

            results.push(SignedDocument {
                raw,
                document_id: jacs_doc.id,
                agent_id,
                timestamp,
            });
        }

        info!(
            batch_size = results.len(),
            "Batch message signing completed successfully"
        );

        Ok(results)
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
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let result = agent.verify(&signed_json)?;
    /// if result.valid {
    ///     println!("Content: {}", result.data);
    /// } else {
    ///     println!("Verification failed: {:?}", result.errors);
    /// }
    /// ```
    #[must_use = "verification result must be checked"]
    pub fn verify(&self, signed_document: &str) -> Result<VerificationResult, JacsError> {
        debug!("verify() called");

        // Check document size before processing
        check_document_size(signed_document)?;

        // Parse the document to validate JSON
        let _: Value = serde_json::from_str(signed_document).map_err(|e| {
            JacsError::DocumentMalformed {
                field: "json".to_string(),
                reason: e.to_string(),
            }
        })?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

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
        let signer_id = jacs_doc.value.get_path_str_or(&["jacsSignature", "agentID"], "");
        let timestamp = jacs_doc.value.get_path_str_or(&["jacsSignature", "date"], "");

        info!("Document verified: valid={}, signer={}", valid, signer_id);

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
    }

    /// Exports the agent's identity JSON for P2P exchange.
    #[must_use = "exported agent data must be used"]
    pub fn export_agent(&self) -> Result<String, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let value = agent.get_value().cloned().ok_or(JacsError::AgentNotLoaded)?;
        serde_json::to_string_pretty(&value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize agent: {}", e),
        })
    }

    /// Returns the agent's public key in PEM format.
    #[must_use = "public key data must be used"]
    pub fn get_public_key_pem(&self) -> Result<String, JacsError> {
        // Read from the standard key file location
        let key_path = "./jacs_keys/jacs.public.pem";
        fs::read_to_string(key_path).map_err(|e| {
            let reason = match e.kind() {
                std::io::ErrorKind::NotFound => {
                    "file does not exist. Run agent creation to generate keys first.".to_string()
                }
                std::io::ErrorKind::PermissionDenied => {
                    "permission denied. Check that the key file is readable.".to_string()
                }
                _ => e.to_string(),
            };
            JacsError::FileReadFailed {
                path: key_path.to_string(),
                reason,
            }
        })
    }

    /// Returns the path to the configuration file, if available.
    pub fn config_path(&self) -> Option<&str> {
        self.config_path.as_deref()
    }

    /// Verifies multiple signed documents in a batch operation.
    ///
    /// This method processes each document sequentially, verifying signatures
    /// and hashes for each. All documents are processed regardless of individual
    /// failures, and results are returned for each input document.
    ///
    /// # Arguments
    ///
    /// * `documents` - A slice of JSON strings, each representing a signed JACS document
    ///
    /// # Returns
    ///
    /// A vector of `VerificationResult` in the same order as the input documents.
    /// Each result contains:
    /// - `valid`: Whether the signature and hash are valid
    /// - `data`: The extracted content from the document
    /// - `signer_id`: The ID of the signing agent
    /// - `errors`: Any error messages if verification failed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// let documents = vec![
    ///     signed_doc1.as_str(),
    ///     signed_doc2.as_str(),
    ///     signed_doc3.as_str(),
    /// ];
    ///
    /// let results = agent.verify_batch(&documents);
    /// for (i, result) in results.iter().enumerate() {
    ///     if result.valid {
    ///         println!("Document {} verified successfully", i);
    ///     } else {
    ///         println!("Document {} failed: {:?}", i, result.errors);
    ///     }
    /// }
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - Verification is sequential; for parallel verification, consider using
    ///   rayon's `par_iter()` externally or spawning threads
    /// - Each verification is independent and does not short-circuit on failure
    /// - The method acquires the agent lock once per document verification
    #[must_use]
    pub fn verify_batch(&self, documents: &[&str]) -> Vec<VerificationResult> {
        documents
            .iter()
            .map(|doc| {
                match self.verify(doc) {
                    Ok(result) => result,
                    Err(e) => VerificationResult::failure(e.to_string()),
                }
            })
            .collect()
    }

    // =========================================================================
    // Agreement Methods
    // =========================================================================

    /// Creates a multi-party agreement requiring signatures from specified agents.
    ///
    /// This creates an agreement on a document that must be signed by all specified
    /// agents before it is considered complete. Use this for scenarios requiring
    /// multi-party approval, such as contract signing or governance decisions.
    ///
    /// # Arguments
    ///
    /// * `document` - The document to create an agreement on (JSON string)
    /// * `agent_ids` - List of agent IDs required to sign the agreement
    /// * `question` - Optional question or purpose of the agreement
    /// * `context` - Optional additional context for signers
    ///
    /// # Returns
    ///
    /// A `SignedDocument` containing the agreement document.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let proposal = json!({"proposal": "Merge codebases A and B"});
    ///
    /// let agreement = agent.create_agreement(
    ///     &proposal.to_string(),
    ///     &["agent-1-uuid".to_string(), "agent-2-uuid".to_string()],
    ///     Some("Do you approve this merge?"),
    ///     Some("This will combine repositories A and B"),
    /// )?;
    /// println!("Agreement created: {}", agreement.document_id);
    /// ```
    #[must_use = "agreement document must be used or stored"]
    pub fn create_agreement(
        &self,
        document: &str,
        agent_ids: &[String],
        question: Option<&str>,
        context: Option<&str>,
    ) -> Result<SignedDocument, JacsError> {
        use crate::agent::agreement::Agreement;

        debug!("create_agreement() called with {} signers", agent_ids.len());

        // Check document size before processing
        check_document_size(document)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // First create the document
        let jacs_doc = agent
            .create_document_and_load(document, None, None)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!("Failed to create base document: {}", e),
            })?;

        // Then create the agreement on it
        let agreement_doc = agent
            .create_agreement(&jacs_doc.getkey(), agent_ids, question, context, None)
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to create agreement: {}", e),
            })?;

        let raw = serde_json::to_string(&agreement_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize agreement: {}", e),
        })?;

        let timestamp = agreement_doc.value.get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = agreement_doc.value.get_path_str_or(&["jacsSignature", "agentID"], "");

        info!("Agreement created: document_id={}", agreement_doc.id);

        Ok(SignedDocument {
            raw,
            document_id: agreement_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Signs an existing multi-party agreement as the current agent.
    ///
    /// # IMPORTANT: Signing Agreements is Sacred
    ///
    /// **Signing an agreement is a binding, irreversible commitment.** When you sign:
    /// - You cryptographically commit to the agreement terms
    /// - Your signature is permanent and cannot be revoked
    /// - All parties can verify your commitment forever
    /// - You are legally and ethically bound to the agreement content
    ///
    /// **Multi-party agreements are especially significant** because:
    /// - Your signature joins a binding consensus
    /// - Other parties rely on your commitment
    /// - Breaking the agreement may harm other signers
    ///
    /// **Before signing any agreement:**
    /// - Read the complete agreement document carefully
    /// - Verify all terms are acceptable to you
    /// - Confirm you have authority to bind yourself/your organization
    /// - Understand the obligations you are accepting
    ///
    /// When an agreement is created, each required signer must call this function
    /// to add their signature. The agreement is complete when all signers have signed.
    ///
    /// # Arguments
    ///
    /// * `document` - The agreement document to sign (JSON string)
    ///
    /// # Returns
    ///
    /// A `SignedDocument` with this agent's signature added.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Receive agreement from coordinator
    /// let agreement_json = receive_agreement_from_coordinator();
    ///
    /// // REVIEW CAREFULLY before signing!
    /// let signed = agent.sign_agreement(&agreement_json)?;
    ///
    /// // Send back to coordinator or pass to next signer
    /// send_to_coordinator(&signed.raw);
    /// ```
    #[must_use = "signed agreement must be used or stored"]
    pub fn sign_agreement(&self, document: &str) -> Result<SignedDocument, JacsError> {
        use crate::agent::agreement::Agreement;

        // Check document size before processing
        check_document_size(document)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Load the document
        let jacs_doc = agent.load_document(document).map_err(|e| {
            JacsError::DocumentMalformed {
                field: "document".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Sign the agreement
        let signed_doc = agent
            .sign_agreement(&jacs_doc.getkey(), None)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!("Failed to sign agreement: {}", e),
            })?;

        let raw = serde_json::to_string(&signed_doc.value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize signed agreement: {}", e),
        })?;

        let timestamp = signed_doc.value.get_path_str_or(&["jacsSignature", "date"], "");
        let agent_id = signed_doc.value.get_path_str_or(&["jacsSignature", "agentID"], "");

        Ok(SignedDocument {
            raw,
            document_id: signed_doc.id,
            agent_id,
            timestamp,
        })
    }

    /// Checks the status of a multi-party agreement.
    ///
    /// Use this to determine which agents have signed and whether the agreement
    /// is complete (all required signatures collected).
    ///
    /// # Arguments
    ///
    /// * `document` - The agreement document to check (JSON string)
    ///
    /// # Returns
    ///
    /// An `AgreementStatus` with completion status and signer details.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// let status = agent.check_agreement(&agreement_json)?;
    /// if status.complete {
    ///     println!("All parties have signed!");
    /// } else {
    ///     println!("Waiting for signatures from: {:?}", status.pending);
    ///     for signer in &status.signers {
    ///         if signer.signed {
    ///             println!("  {}: signed at {:?}", signer.agent_id, signer.signed_at);
    ///         } else {
    ///             println!("  {}: pending", signer.agent_id);
    ///         }
    ///     }
    /// }
    /// ```
    #[must_use = "agreement status must be checked"]
    pub fn check_agreement(&self, document: &str) -> Result<AgreementStatus, JacsError> {
        // Check document size before processing
        check_document_size(document)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Load the document
        let jacs_doc = agent.load_document(document).map_err(|e| {
            JacsError::DocumentMalformed {
                field: "document".to_string(),
                reason: e.to_string(),
            }
        })?;

        // Get the unsigned agents
        let unsigned = jacs_doc.agreement_unsigned_agents(None).map_err(|e| {
            JacsError::Internal {
                message: format!("Failed to check unsigned agents: {}", e),
            }
        })?;

        // Get all requested agents from the agreement
        let all_agents = jacs_doc.agreement_requested_agents(None).map_err(|e| {
            JacsError::Internal {
                message: format!("Failed to get agreement agents: {}", e),
            }
        })?;

        // Build signer status list
        let mut signers = Vec::new();
        let unsigned_set: std::collections::HashSet<&String> = unsigned.iter().collect();

        for agent_id in &all_agents {
            let signed = !unsigned_set.contains(agent_id);
            signers.push(SignerStatus {
                agent_id: agent_id.clone(),
                signed,
                signed_at: if signed {
                    // Try to get the signature timestamp from the document
                    // For simplicity, we use the document timestamp
                    Some(jacs_doc.value.get_path_str_or(&["jacsSignature", "date"], "").to_string())
                } else {
                    None
                },
            });
        }

        Ok(AgreementStatus {
            complete: unsigned.is_empty(),
            signers,
            pending: unsigned,
        })
    }
}

// =============================================================================
// Deprecated Module-Level Functions (for backward compatibility)
// =============================================================================
//
// These functions use thread-local storage to maintain compatibility with
// existing code that uses the module-level API. New code should use
// `SimpleAgent` directly.

use std::cell::RefCell;

thread_local! {
    /// Thread-local agent instance for deprecated module-level functions.
    /// This replaces the previous global `lazy_static!` singleton with thread-local
    /// storage, which is safer for concurrent use.
    static THREAD_AGENT: RefCell<Option<SimpleAgent>> = const { RefCell::new(None) };
}

/// Creates a new JACS agent with persistent identity.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::create()` instead.
///
/// # Example
///
/// ```rust,ignore
/// // Old way (deprecated)
/// use jacs::simple::create;
/// let info = create("my-agent", None, None)?;
///
/// // New way (recommended)
/// use jacs::simple::SimpleAgent;
/// let (agent, info) = SimpleAgent::create("my-agent", None, None)?;
/// ```
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::create() instead")]
pub fn create(
    name: &str,
    purpose: Option<&str>,
    key_algorithm: Option<&str>,
) -> Result<AgentInfo, JacsError> {
    let (agent, info) = SimpleAgent::create(name, purpose, key_algorithm)?;
    THREAD_AGENT.with(|cell| {
        *cell.borrow_mut() = Some(agent);
    });
    Ok(info)
}

/// Loads an existing agent from a configuration file.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::load()` instead.
///
/// # Example
///
/// ```rust,ignore
/// // Old way (deprecated)
/// use jacs::simple::load;
/// load(None)?;
///
/// // New way (recommended)
/// use jacs::simple::SimpleAgent;
/// let agent = SimpleAgent::load(None)?;
/// ```
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::load() instead")]
pub fn load(config_path: Option<&str>) -> Result<(), JacsError> {
    let agent = SimpleAgent::load(config_path)?;
    THREAD_AGENT.with(|cell| {
        *cell.borrow_mut() = Some(agent);
    });
    Ok(())
}

/// Helper to execute a function with the thread-local agent.
fn with_thread_agent<F, T>(f: F) -> Result<T, JacsError>
where
    F: FnOnce(&SimpleAgent) -> Result<T, JacsError>,
{
    THREAD_AGENT.with(|cell| {
        let borrow = cell.borrow();
        let agent = borrow.as_ref().ok_or(JacsError::AgentNotLoaded)?;
        f(agent)
    })
}

/// Verifies the loaded agent's own identity.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::verify_self()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::verify_self() instead")]
pub fn verify_self() -> Result<VerificationResult, JacsError> {
    with_thread_agent(|agent| agent.verify_self())
}

/// Updates the current agent with new data and re-signs it.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::update_agent()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::update_agent() instead")]
pub fn update_agent(new_agent_data: &str) -> Result<String, JacsError> {
    with_thread_agent(|agent| agent.update_agent(new_agent_data))
}

/// Updates an existing document with new data and re-signs it.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::update_document()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::update_document() instead")]
pub fn update_document(
    document_id: &str,
    new_data: &str,
    attachments: Option<Vec<String>>,
    embed: Option<bool>,
) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.update_document(document_id, new_data, attachments, embed))
}

/// Signs arbitrary data as a JACS message.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::sign_message()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::sign_message() instead")]
pub fn sign_message(data: &Value) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.sign_message(data))
}

/// Signs a file with optional content embedding.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::sign_file()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::sign_file() instead")]
pub fn sign_file(file_path: &str, embed: bool) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.sign_file(file_path, embed))
}

/// Verifies a signed document and extracts its content.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::verify()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::verify() instead")]
pub fn verify(signed_document: &str) -> Result<VerificationResult, JacsError> {
    with_thread_agent(|agent| agent.verify(signed_document))
}

/// Exports the current agent's identity JSON for P2P exchange.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::export_agent()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::export_agent() instead")]
pub fn export_agent() -> Result<String, JacsError> {
    with_thread_agent(|agent| agent.export_agent())
}

/// Returns the current agent's public key in PEM format.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::get_public_key_pem()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::get_public_key_pem() instead")]
pub fn get_public_key_pem() -> Result<String, JacsError> {
    with_thread_agent(|agent| agent.get_public_key_pem())
}

/// Creates a multi-party agreement requiring signatures from specified agents.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::create_agreement()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::create_agreement() instead")]
pub fn create_agreement(
    document: &str,
    agent_ids: &[String],
    question: Option<&str>,
    context: Option<&str>,
) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.create_agreement(document, agent_ids, question, context))
}

/// Signs an existing agreement as the current agent.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::sign_agreement()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::sign_agreement() instead")]
pub fn sign_agreement(document: &str) -> Result<SignedDocument, JacsError> {
    with_thread_agent(|agent| agent.sign_agreement(document))
}

/// Checks the status of a multi-party agreement.
///
/// # Deprecated
///
/// This function uses thread-local global state. Prefer `SimpleAgent::check_agreement()` instead.
#[deprecated(since = "0.3.0", note = "Use SimpleAgent::check_agreement() instead")]
pub fn check_agreement(document: &str) -> Result<AgreementStatus, JacsError> {
    with_thread_agent(|agent| agent.check_agreement(document))
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_thread_agent_not_loaded() {
        // Clear the thread-local agent
        THREAD_AGENT.with(|cell| {
            *cell.borrow_mut() = None;
        });

        // Trying to use deprecated functions without loading should fail
        #[allow(deprecated)]
        let result = verify_self();
        assert!(result.is_err());

        match result {
            Err(JacsError::AgentNotLoaded) => (),
            _ => panic!("Expected AgentNotLoaded error"),
        }
    }

    #[test]
    fn test_simple_agent_load_missing_config() {
        let result = SimpleAgent::load(Some("/nonexistent/path/config.json"));
        assert!(result.is_err());

        match result {
            Err(JacsError::ConfigNotFound { path }) => {
                assert!(path.contains("nonexistent"));
            }
            _ => panic!("Expected ConfigNotFound error"),
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_deprecated_load_missing_config() {
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
    #[allow(deprecated)]
    fn test_sign_file_missing_file() {
        // Without a loaded agent, this should fail with AgentNotLoaded
        THREAD_AGENT.with(|cell| {
            *cell.borrow_mut() = None;
        });
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
    #[allow(deprecated)]
    fn test_get_public_key_pem_not_found() {
        // Without a loaded agent, this should fail with AgentNotLoaded
        THREAD_AGENT.with(|cell| {
            *cell.borrow_mut() = None;
        });

        // This should fail because no agent is loaded
        let result = get_public_key_pem();
        assert!(result.is_err());
    }

    #[test]
    fn test_simple_agent_struct_has_config_path() {
        // Test that SimpleAgent can store and return config path
        // Note: We can't fully test create/load without a valid config,
        // but we can verify the struct design
        let result = SimpleAgent::load(Some("./nonexistent.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_verification_result_failure_constructor() {
        // Test that VerificationResult::failure creates a valid failure result
        let result = VerificationResult::failure("Test error message".to_string());
        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("Test error message"));
        assert_eq!(result.signer_id, "");
        assert!(result.signer_name.is_none());
    }

    #[test]
    fn test_verification_result_success_constructor() {
        let data = json!({"message": "hello"});
        let signer_id = "agent-123".to_string();
        let timestamp = "2024-01-15T10:30:00Z".to_string();

        let result = VerificationResult::success(data.clone(), signer_id.clone(), timestamp.clone());

        assert!(result.valid);
        assert_eq!(result.data, data);
        assert_eq!(result.signer_id, signer_id);
        assert!(result.signer_name.is_none());
        assert_eq!(result.timestamp, timestamp);
        assert!(result.attachments.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_verification_result_failure_has_null_data() {
        let result = VerificationResult::failure("error".to_string());
        assert_eq!(result.data, json!(null));
        assert!(result.timestamp.is_empty());
        assert!(result.attachments.is_empty());
    }
}
