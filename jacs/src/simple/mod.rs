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


pub mod core;
pub mod diagnostics;
pub mod types;
pub use core::SimpleAgent;
pub use diagnostics::diagnostics;
pub use types::*;

use crate::agent::SHA256_FIELDNAME;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::DocumentTraits;
use crate::crypt::hash::hash_string;
use crate::error::JacsError;
use crate::protocol::canonicalize_json;
use crate::schema::utils::{ValueExt, check_document_size};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use tracing::{debug, info};

// Re-import helpers from core.rs that advanced methods still need
use core::DEFAULT_PRIVATE_KEY_FILENAME;
use core::DEFAULT_PUBLIC_KEY_FILENAME;
// The following imports are used by tests via `use super::*`
#[allow(unused_imports)]
use core::resolve_strict;
#[allow(unused_imports)]
use std::sync::Mutex;
#[allow(unused_imports)]
pub(crate) use core::extract_attachments;

// Standalone diagnostics() is defined in diagnostics.rs and re-exported above.
// Constants, build_agent_document, resolve_strict, CREATE_MUTEX, and
// extract_attachments are defined in core.rs and imported above.

// =============================================================================
// SimpleAgent - Advanced methods (instance-based)
// =============================================================================
// The SimpleAgent struct and narrow contract methods (is_strict, key_id, create,
// create_with_params, load, ephemeral, verify_self, sign_message, sign_raw_bytes,
// get_agent_id, sign_file, verify, verify_with_key, verify_by_id, export_agent,
// get_public_key, get_public_key_pem, diagnostics, config_path) are defined in
// core.rs and re-exported above.

impl SimpleAgent {






    /// Zero-config persistent agent creation.
    ///
    /// If a config file already exists at `config_path` (default: `./jacs.config.json`),
    /// loads the existing agent. Otherwise, creates a new persistent agent with keys
    /// on disk and a minimal config file.
    ///
    /// `JACS_PRIVATE_KEY_PASSWORD` must be set (or provided by caller wrappers).
    /// Quickstart fails hard if no password is available.
    ///
    /// # Arguments
    ///
    /// * `name` - Agent name to use when creating a new config/identity
    /// * `domain` - Agent domain to use for DNS/public-key verification workflows
    /// * `description` - Optional human-readable description for a newly created agent
    /// * `algorithm` - Signing algorithm (default: "pq2025"). Also: "ed25519", "rsa-pss"
    /// * `config_path` - Config file path (default: "./jacs.config.json")
    ///
    /// # Returns
    ///
    /// A `SimpleAgent` with persistent keys on disk, along with `AgentInfo`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let (agent, info) = SimpleAgent::quickstart(
    ///     "my-agent",
    ///     "agent.example.com",
    ///     Some("My JACS agent"),
    ///     None,
    ///     None,
    /// )?;
    /// let signed = agent.sign_message(&serde_json::json!({"hello": "world"}))?;
    /// // Keys and config are saved to disk -- the same agent is loaded next time.
    /// ```
    #[must_use = "quickstart result must be checked for errors"]
    pub fn quickstart(
        name: &str,
        domain: &str,
        description: Option<&str>,
        algorithm: Option<&str>,
        config_path: Option<&str>,
    ) -> Result<(Self, AgentInfo), JacsError> {
        let config = config_path.unwrap_or("./jacs.config.json");

        // If config already exists, load the existing agent
        if Path::new(config).exists() {
            info!(
                "quickstart: found existing config at {}, loading agent",
                config
            );
            let agent = Self::load(Some(config), None)?;

            // Build AgentInfo from the loaded agent
            let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
                message: format!("Failed to acquire agent lock: {}", e),
            })?;
            let agent_value = inner
                .get_value()
                .cloned()
                .ok_or(JacsError::AgentNotLoaded)?;
            let agent_id = agent_value["jacsId"].as_str().unwrap_or("").to_string();
            let version = agent_value["jacsVersion"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let loaded_name = agent_value
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(name)
                .to_string();
            let loaded_domain = agent_value
                .get("jacsAgentDomain")
                .and_then(|v| v.as_str())
                .or_else(|| agent_value.get("domain").and_then(|v| v.as_str()))
                .unwrap_or(domain)
                .to_string();
            let (algo, key_dir, data_dir, private_key_filename, public_key_filename) =
                if let Some(ref cfg) = inner.config {
                    let a = cfg
                        .jacs_agent_key_algorithm()
                        .as_deref()
                        .unwrap_or("")
                        .to_string();
                    let k = cfg
                        .jacs_key_directory()
                        .as_deref()
                        .unwrap_or("./jacs_keys")
                        .to_string();
                    let d = cfg
                        .jacs_data_directory()
                        .as_deref()
                        .unwrap_or("./jacs_data")
                        .to_string();
                    let priv_name = cfg
                        .jacs_agent_private_key_filename()
                        .as_deref()
                        .unwrap_or(DEFAULT_PRIVATE_KEY_FILENAME)
                        .to_string();
                    let pub_name = cfg
                        .jacs_agent_public_key_filename()
                        .as_deref()
                        .unwrap_or(DEFAULT_PUBLIC_KEY_FILENAME)
                        .to_string();
                    (a, k, d, priv_name, pub_name)
                } else {
                    (
                        String::new(),
                        "./jacs_keys".to_string(),
                        "./jacs_data".to_string(),
                        DEFAULT_PRIVATE_KEY_FILENAME.to_string(),
                        DEFAULT_PUBLIC_KEY_FILENAME.to_string(),
                    )
                };
            drop(inner);

            let info = AgentInfo {
                agent_id,
                name: loaded_name,
                public_key_path: format!("{}/{}", key_dir, public_key_filename),
                config_path: config.to_string(),
                version,
                algorithm: algo,
                private_key_path: format!("{}/{}", key_dir, private_key_filename),
                data_directory: data_dir,
                key_directory: key_dir,
                domain: loaded_domain,
                dns_record: String::new(),
            };

            return Ok((agent, info));
        }

        // No existing config -- create a new persistent agent
        info!(
            "quickstart: no config at {}, creating new persistent agent",
            config
        );

        if name.trim().is_empty() {
            return Err(JacsError::ConfigError(
                "Quickstart requires a non-empty agent name.".to_string(),
            ));
        }
        if domain.trim().is_empty() {
            return Err(JacsError::ConfigError(
                "Quickstart requires a non-empty domain.".to_string(),
            ));
        }

        // Fail hard if no password is available.
        let password = std::env::var("JACS_PRIVATE_KEY_PASSWORD")
            .ok()
            .filter(|pw| !pw.trim().is_empty())
            .ok_or_else(|| {
                JacsError::ConfigError(
                    "Missing private key password. Set JACS_PRIVATE_KEY_PASSWORD \
                    from your environment or secret manager before calling quickstart()."
                        .to_string(),
                )
            })?;

        // Use create_with_params for full control
        let algo = match algorithm.unwrap_or("pq2025") {
            "ed25519" => "ring-Ed25519",
            "rsa-pss" => "RSA-PSS",
            "pq2025" => "pq2025",
            other => other,
        };

        let params = CreateAgentParams {
            name: name.to_string(),
            password,
            algorithm: algo.to_string(),
            config_path: config.to_string(),
            description: description.unwrap_or("").to_string(),
            domain: domain.to_string(),
            ..Default::default()
        };

        Self::create_with_params(params)
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

        agent
            .update_self(new_agent_data)
            .map_err(|e| JacsError::Internal {
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

        SignedDocument::from_jacs_document(jacs_doc, "document")
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
    pub fn sign_messages_batch(
        &self,
        messages: &[&Value],
    ) -> Result<Vec<SignedDocument>, JacsError> {
        use crate::agent::document::DocumentTraits;
        use tracing::info;

        if messages.is_empty() {
            return Ok(Vec::new());
        }

        info!(batch_size = messages.len(), "Signing batch of messages");

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
            results.push(SignedDocument::from_jacs_document(jacs_doc, "document")?);
        }

        info!(
            batch_size = results.len(),
            "Batch message signing completed successfully"
        );

        Ok(results)
    }



    /// Re-encrypts the agent's private key from one password to another.
    ///
    /// This reads the encrypted private key file, decrypts with the old password,
    /// validates the new password, re-encrypts, and writes the updated file.
    ///
    /// # Arguments
    ///
    /// * `old_password` - The current password protecting the private key
    /// * `new_password` - The new password (must meet password requirements)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// agent.reencrypt_key("OldP@ss123!", "NewStr0ng!Pass#2025")?;
    /// println!("Key re-encrypted successfully");
    /// ```
    pub fn reencrypt_key(&self, old_password: &str, new_password: &str) -> Result<(), JacsError> {
        use crate::crypt::aes_encrypt::reencrypt_private_key;

        // Find the private key file
        let key_path = if let Some(ref config_path) = self.config_path {
            // Try to read config to find key directory
            let config_str =
                fs::read_to_string(config_path).map_err(|e| JacsError::FileReadFailed {
                    path: config_path.clone(),
                    reason: e.to_string(),
                })?;
            let config: Value =
                serde_json::from_str(&config_str).map_err(|e| JacsError::ConfigInvalid {
                    field: "json".to_string(),
                    reason: e.to_string(),
                })?;
            let key_dir = config["jacs_key_directory"]
                .as_str()
                .unwrap_or("./jacs_keys");
            let key_filename = config["jacs_agent_private_key_filename"]
                .as_str()
                .unwrap_or("jacs.private.pem.enc");
            format!("{}/{}", key_dir, key_filename)
        } else {
            "./jacs_keys/jacs.private.pem.enc".to_string()
        };

        info!("Re-encrypting private key at: {}", key_path);

        // Read encrypted key
        let encrypted_data = fs::read(&key_path).map_err(|e| JacsError::FileReadFailed {
            path: key_path.clone(),
            reason: e.to_string(),
        })?;

        // Re-encrypt
        let re_encrypted = reencrypt_private_key(&encrypted_data, old_password, new_password)
            .map_err(|e| JacsError::CryptoError(format!("Re-encryption failed: {}", e)))?;

        // Write back
        fs::write(&key_path, &re_encrypted).map_err(|e| JacsError::Internal {
            message: format!("Failed to write re-encrypted key to '{}': {}", key_path, e),
        })?;

        info!("Private key re-encrypted successfully");
        Ok(())
    }







    /// Returns setup instructions for publishing the agent's DNS record
    /// and enabling DNSSEC.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to publish the DNS TXT record under
    /// * `ttl` - TTL in seconds for the DNS record (e.g. 3600)
    pub fn get_setup_instructions(
        &self,
        domain: &str,
        ttl: u32,
    ) -> Result<SetupInstructions, JacsError> {
        use crate::dns::bootstrap::{
            DigestEncoding, build_dns_record, dnssec_guidance, emit_azure_cli,
            emit_cloudflare_curl, emit_gcloud_dns, emit_plain_bind, emit_route53_change_batch,
            tld_requirement_text,
        };

        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to lock agent: {}", e),
        })?;

        let agent_value = agent.get_value().cloned().unwrap_or(json!({}));
        let agent_id = agent_value.get_str_or("jacsId", "");
        if agent_id.is_empty() {
            return Err(JacsError::AgentNotLoaded);
        }

        let pk = agent.get_public_key().map_err(|e| JacsError::Internal {
            message: format!("Failed to get public key: {}", e),
        })?;
        let digest = crate::dns::bootstrap::pubkey_digest_b64(&pk);
        let rr = build_dns_record(domain, ttl, &agent_id, &digest, DigestEncoding::Base64);

        let dns_record_bind = emit_plain_bind(&rr);
        let dns_record_value = rr.txt.clone();
        let dns_owner = rr.owner.clone();

        // Provider commands
        let mut provider_commands = std::collections::HashMap::new();
        provider_commands.insert("bind".to_string(), dns_record_bind.clone());
        provider_commands.insert("route53".to_string(), emit_route53_change_batch(&rr));
        provider_commands.insert("gcloud".to_string(), emit_gcloud_dns(&rr, "YOUR_ZONE_NAME"));
        provider_commands.insert(
            "azure".to_string(),
            emit_azure_cli(&rr, "YOUR_RG", domain, "_v1.agent.jacs"),
        );
        provider_commands.insert(
            "cloudflare".to_string(),
            emit_cloudflare_curl(&rr, "YOUR_ZONE_ID"),
        );

        // DNSSEC guidance per provider
        let mut dnssec_instructions = std::collections::HashMap::new();
        for name in &["aws", "cloudflare", "azure", "gcloud"] {
            dnssec_instructions.insert(name.to_string(), dnssec_guidance(name).to_string());
        }

        let tld_requirement = tld_requirement_text().to_string();

        // .well-known JSON
        let well_known = json!({
            "jacs_agent_id": agent_id,
            "jacs_public_key_hash": digest,
            "jacs_dns_record": dns_owner,
        });
        let well_known_json = serde_json::to_string_pretty(&well_known).unwrap_or_default();

        // Build summary
        let summary = format!(
            "Setup instructions for agent {agent_id} on domain {domain}:\n\
             \n\
             1. DNS: Publish the following TXT record:\n\
             {bind}\n\
             \n\
             2. DNSSEC: {dnssec}\n\
             \n\
             3. Domain requirement: {tld}\n\
             \n\
             4. .well-known: Serve the well-known JSON at /.well-known/jacs-agent.json",
            agent_id = agent_id,
            domain = domain,
            bind = dns_record_bind,
            dnssec = dnssec_guidance("aws"),
            tld = tld_requirement,
        );

        Ok(SetupInstructions {
            dns_record_bind,
            dns_record_value,
            dns_owner,
            provider_commands,
            dnssec_instructions,
            tld_requirement,
            well_known_json,
            summary,
        })
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
            .map(|doc| match self.verify(doc) {
                Ok(result) => result,
                Err(e) => VerificationResult::failure(e.to_string()),
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
        self.create_agreement_with_options(document, agent_ids, question, context, None)
    }

    /// Creates a multi-party agreement with extended options.
    ///
    /// Like `create_agreement`, but accepts `AgreementOptions` for timeout,
    /// quorum (M-of-N), and algorithm constraints.
    ///
    /// # Arguments
    ///
    /// * `document` - The document to create an agreement on (JSON string)
    /// * `agent_ids` - List of agent IDs required to sign
    /// * `question` - Optional prompt describing what agents are agreeing to
    /// * `context` - Optional context for the agreement
    /// * `options` - Optional `AgreementOptions` (timeout, quorum, algorithm constraints)
    pub fn create_agreement_with_options(
        &self,
        document: &str,
        agent_ids: &[String],
        question: Option<&str>,
        context: Option<&str>,
        options: Option<&crate::agent::agreement::AgreementOptions>,
    ) -> Result<SignedDocument, JacsError> {
        use crate::agent::agreement::{Agreement, AgreementOptions};

        debug!(
            "create_agreement_with_options() called with {} signers",
            agent_ids.len()
        );

        // Check document size before processing
        check_document_size(document)?;

        let default_opts = AgreementOptions::default();
        let opts = options.unwrap_or(&default_opts);

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
            .create_agreement_with_options(
                &jacs_doc.getkey(),
                agent_ids,
                question,
                context,
                None,
                opts,
            )
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to create agreement: {}", e),
            })?;

        info!("Agreement created: document_id={}", agreement_doc.id);

        SignedDocument::from_jacs_document(agreement_doc, "agreement")
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
        let jacs_doc = agent
            .load_document(document)
            .map_err(|e| JacsError::DocumentMalformed {
                field: "document".to_string(),
                reason: e.to_string(),
            })?;

        // Sign the agreement
        let signed_doc = agent
            .sign_agreement(&jacs_doc.getkey(), None)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!("Failed to sign agreement: {}", e),
            })?;

        SignedDocument::from_jacs_document(signed_doc, "signed agreement")
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
        let jacs_doc = agent
            .load_document(document)
            .map_err(|e| JacsError::DocumentMalformed {
                field: "document".to_string(),
                reason: e.to_string(),
            })?;

        // Get the unsigned agents
        let unsigned =
            jacs_doc
                .agreement_unsigned_agents(None)
                .map_err(|e| JacsError::Internal {
                    message: format!("Failed to check unsigned agents: {}", e),
                })?;

        // Get all requested agents from the agreement
        let all_agents =
            jacs_doc
                .agreement_requested_agents(None)
                .map_err(|e| JacsError::Internal {
                    message: format!("Failed to get agreement agents: {}", e),
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
                    Some(
                        jacs_doc
                            .value
                            .get_path_str_or(&["jacsSignature", "date"], "")
                            .to_string(),
                    )
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

    // =========================================================================
    // A2A Protocol Methods
    // =========================================================================

    /// Export this agent as an A2A Agent Card (v0.4.0).
    ///
    /// The Agent Card describes the agent's capabilities, skills, and
    /// cryptographic configuration for zero-config A2A discovery.
    pub fn export_agent_card(&self) -> Result<crate::a2a::AgentCard, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        crate::a2a::agent_card::export_agent_card(&agent).map_err(|e| JacsError::Internal {
            message: format!("Failed to export agent card: {}", e),
        })
    }

    /// Generate .well-known documents for A2A discovery.
    ///
    /// Creates all well-known endpoint documents including the signed Agent Card,
    /// JWKS, JACS descriptor, public key document, and extension descriptor.
    ///
    /// Returns a vector of (path, JSON value) tuples suitable for serving.
    pub fn generate_well_known_documents(
        &self,
        a2a_algorithm: Option<&str>,
    ) -> Result<Vec<(String, serde_json::Value)>, JacsError> {
        let agent_card = self.export_agent_card()?;

        let a2a_alg = a2a_algorithm.unwrap_or("ring-Ed25519");
        let dual_keys = crate::a2a::keys::create_jwk_keys(None, Some(a2a_alg)).map_err(|e| {
            JacsError::Internal {
                message: format!("Failed to generate A2A keys: {}", e),
            }
        })?;

        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let agent_id = agent.get_id().map_err(|e| JacsError::Internal {
            message: format!("Failed to get agent ID: {}", e),
        })?;

        let jws = crate::a2a::extension::sign_agent_card_jws(
            &agent_card,
            &dual_keys.a2a_private_key,
            &dual_keys.a2a_algorithm,
            &agent_id,
        )
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to sign Agent Card: {}", e),
        })?;

        crate::a2a::extension::generate_well_known_documents(
            &agent,
            &agent_card,
            &dual_keys.a2a_public_key,
            &dual_keys.a2a_algorithm,
            &jws,
        )
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to generate well-known documents: {}", e),
        })
    }

    /// Wrap an A2A artifact with JACS provenance signature.
    ///
    /// This creates a signed envelope around arbitrary JSON content,
    /// binding the signer's identity to the artifact.
    ///
    /// # Arguments
    ///
    /// * `artifact_json` - JSON string of the artifact to wrap
    /// * `artifact_type` - Type label (e.g., "artifact", "message", "task")
    /// * `parent_signatures_json` - Optional JSON array of parent signatures for chain-of-custody
    ///
    /// # Returns
    ///
    /// JSON string of the wrapped, signed artifact.
    #[deprecated(since = "0.9.0", note = "Use sign_artifact() instead")]
    pub fn wrap_a2a_artifact(
        &self,
        artifact_json: &str,
        artifact_type: &str,
        parent_signatures_json: Option<&str>,
    ) -> Result<String, JacsError> {
        if std::env::var("JACS_SHOW_DEPRECATIONS").is_ok() {
            tracing::warn!("wrap_a2a_artifact is deprecated, use sign_artifact instead");
        }

        let artifact: Value =
            serde_json::from_str(artifact_json).map_err(|e| JacsError::DocumentMalformed {
                field: "artifact_json".to_string(),
                reason: format!("Invalid JSON: {}", e),
            })?;

        let parent_signatures: Option<Vec<Value>> = match parent_signatures_json {
            Some(json_str) => {
                let parsed: Vec<Value> =
                    serde_json::from_str(json_str).map_err(|e| JacsError::DocumentMalformed {
                        field: "parent_signatures_json".to_string(),
                        reason: format!("Invalid JSON array: {}", e),
                    })?;
                Some(parsed)
            }
            None => None,
        };

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let wrapped = crate::a2a::provenance::wrap_artifact_with_provenance(
            &mut agent,
            artifact,
            artifact_type,
            parent_signatures,
        )
        .map_err(|e| JacsError::SigningFailed {
            reason: format!("Failed to wrap artifact: {}", e),
        })?;

        serde_json::to_string_pretty(&wrapped).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize wrapped artifact: {}", e),
        })
    }

    /// Sign an A2A artifact with JACS provenance.
    ///
    /// This is the recommended primary API, replacing the deprecated
    /// [`wrap_a2a_artifact`](Self::wrap_a2a_artifact).
    pub fn sign_artifact(
        &self,
        artifact_json: &str,
        artifact_type: &str,
        parent_signatures_json: Option<&str>,
    ) -> Result<String, JacsError> {
        #[allow(deprecated)]
        self.wrap_a2a_artifact(artifact_json, artifact_type, parent_signatures_json)
    }

    /// Verify a JACS-wrapped A2A artifact.
    ///
    /// Returns a JSON string containing the verification result, including
    /// the verification status, signer identity, and the original artifact.
    ///
    /// # Arguments
    ///
    /// * `wrapped_json` - JSON string of the wrapped artifact to verify
    pub fn verify_a2a_artifact(&self, wrapped_json: &str) -> Result<String, JacsError> {
        let wrapped: Value =
            serde_json::from_str(wrapped_json).map_err(|e| JacsError::DocumentMalformed {
                field: "wrapped_json".to_string(),
                reason: format!("Invalid JSON: {}", e),
            })?;

        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let result =
            crate::a2a::provenance::verify_wrapped_artifact(&agent, &wrapped).map_err(|e| {
                JacsError::SignatureVerificationFailed {
                    reason: format!("A2A artifact verification error: {}", e),
                }
            })?;

        serde_json::to_string_pretty(&result).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize verification result: {}", e),
        })
    }

    // =========================================================================
    // Key Rotation
    // =========================================================================

    /// Rotates the agent's cryptographic keys.
    ///
    /// This generates a new keypair, archives the old keys (for filesystem-backed
    /// agents), creates a new agent version with the new public key, self-signs it,
    /// and updates the config file.
    ///
    /// The old keys remain on disk (archived with a version suffix) so that
    /// documents signed with the old key can still be verified.
    ///
    /// # Returns
    ///
    /// A [`RotationResult`] containing the old and new version strings, the new
    /// public key in PEM format, and the complete self-signed agent JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The agent is not loaded (no `jacsId`)
    /// - Key generation fails
    /// - Signing fails
    /// - Config file cannot be updated
    ///
    /// On failure after key archival, the old keys are restored (rollback).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let (agent, _info) = SimpleAgent::create("my-agent", None, None)?;
    /// let rotation = agent.rotate()?;
    /// println!("Rotated from {} to {}", rotation.old_version, rotation.new_version);
    /// ```
    pub fn rotate(&self) -> Result<RotationResult, JacsError> {
        use crate::crypt::hash::hash_public_key;

        info!("Starting key rotation");

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // 1. Capture pre-rotation state
        let agent_value = agent
            .get_value()
            .cloned()
            .ok_or(JacsError::AgentNotLoaded)?;
        let jacs_id = agent_value["jacsId"]
            .as_str()
            .ok_or(JacsError::AgentNotLoaded)?
            .to_string();
        let old_version = agent_value["jacsVersion"]
            .as_str()
            .ok_or_else(|| JacsError::Internal {
                message: "Agent has no jacsVersion".to_string(),
            })?
            .to_string();

        // 2. Delegate to Agent::rotate_self() (archives keys, generates new, signs, verifies)
        let (new_version, new_public_key, new_doc) =
            agent.rotate_self().map_err(|e| JacsError::Internal {
                message: format!("Key rotation failed: {}", e),
            })?;

        // 3. Save agent document to disk (non-ephemeral only)
        if !agent.is_ephemeral() {
            agent.save().map_err(|e| JacsError::Internal {
                message: format!("Failed to save rotated agent: {}", e),
            })?;
        }

        // 4. Update config file with the new version
        if let Some(ref config_path) = self.config_path {
            let config_path_p = Path::new(config_path);
            if config_path_p.exists() {
                let config_str =
                    fs::read_to_string(config_path_p).map_err(|e| JacsError::Internal {
                        message: format!("Failed to read config for rotation update: {}", e),
                    })?;
                let mut config_value: Value =
                    serde_json::from_str(&config_str).map_err(|e| JacsError::Internal {
                        message: format!("Failed to parse config: {}", e),
                    })?;

                let new_lookup = format!("{}:{}", jacs_id, new_version);
                if let Some(obj) = config_value.as_object_mut() {
                    obj.insert("jacs_agent_id_and_version".to_string(), json!(new_lookup));
                }

                let updated_str = serde_json::to_string_pretty(&config_value).map_err(|e| {
                    JacsError::Internal {
                        message: format!("Failed to serialize updated config: {}", e),
                    }
                })?;
                fs::write(config_path_p, updated_str).map_err(|e| JacsError::Internal {
                    message: format!("Failed to write updated config: {}", e),
                })?;

                info!(
                    "Config updated with new version: {}:{}",
                    jacs_id, new_version
                );
            }
        }

        // 5. Build the PEM string for the new public key
        // We always encode from the raw bytes since the on-disk public key may
        // be raw bytes (ring Ed25519) rather than actual PEM text.
        let new_public_key_pem = crate::crypt::normalize_public_key_pem(&new_public_key);
        drop(agent); // Release lock — no longer needed

        let new_public_key_hash = hash_public_key(&new_public_key);
        let signed_agent_json =
            serde_json::to_string_pretty(&new_doc).map_err(|e| JacsError::Internal {
                message: format!("Failed to serialize rotated agent: {}", e),
            })?;

        info!(
            "Key rotation complete: {} -> {} (id={})",
            old_version, new_version, jacs_id
        );

        Ok(RotationResult {
            jacs_id,
            old_version,
            new_version,
            new_public_key_pem,
            new_public_key_hash,
            signed_agent_json,
        })
    }

    // =========================================================================
    // Migration API
    // =========================================================================

    /// Migrates a legacy agent document that predates a schema change.
    ///
    /// Agents created before the `iat` (issued-at timestamp) and `jti` (unique
    /// nonce) fields were added to the `jacsSignature` schema will fail
    /// validation on load. This method works around that by:
    ///
    /// 1. Reading the raw agent JSON from disk (bypassing schema validation)
    /// 2. Patching in temporary `iat` and `jti` values if they are missing
    /// 3. Writing the patched JSON back to disk
    /// 4. Loading the agent normally (now passes schema validation)
    /// 5. Calling `update_agent()` to produce a properly re-signed new version
    /// 6. Saving the new version and updating the config file
    ///
    /// This is a static method because the agent cannot be loaded yet (that is
    /// the whole point of migration).
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the JACS config file (default: `./jacs.config.json`)
    ///
    /// # Returns
    ///
    /// A [`MigrateResult`] describing what was patched and the new version.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let result = SimpleAgent::migrate_agent(None)?;
    /// println!("Migrated {} -> {}", result.old_version, result.new_version);
    /// println!("Patched fields: {:?}", result.patched_fields);
    /// ```
    pub fn migrate_agent(config_path: Option<&str>) -> Result<MigrateResult, JacsError> {
        let path = config_path.unwrap_or("./jacs.config.json");

        info!("Starting agent migration from config: {}", path);

        if !Path::new(path).exists() {
            return Err(JacsError::ConfigNotFound {
                path: path.to_string(),
            });
        }

        // Step 1: Load config to find the agent file
        let config = crate::config::load_config_12factor(Some(path)).map_err(|e| {
            JacsError::ConfigInvalid {
                field: "config".to_string(),
                reason: format!("Could not load configuration from '{}': {}", path, e),
            }
        })?;

        let id_and_version = config
            .jacs_agent_id_and_version()
            .as_deref()
            .unwrap_or("")
            .to_string();
        if id_and_version.is_empty() {
            return Err(JacsError::ConfigInvalid {
                field: "jacs_agent_id_and_version".to_string(),
                reason: "Agent ID and version not set in config".to_string(),
            });
        }

        let data_dir = config
            .jacs_data_directory()
            .as_deref()
            .unwrap_or("jacs_data")
            .to_string();

        // Step 2: Construct the agent file path (same logic as fs_agent_load)
        // The path is relative to the config file's parent directory.
        let config_dir = Path::new(path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        let agent_file = if Path::new(&data_dir).is_absolute() {
            Path::new(&data_dir)
                .join("agent")
                .join(format!("{}.json", id_and_version))
        } else {
            config_dir
                .join(&data_dir)
                .join("agent")
                .join(format!("{}.json", id_and_version))
        };

        info!("Migration: reading agent file at {:?}", agent_file);

        if !agent_file.exists() {
            return Err(JacsError::Internal {
                message: format!(
                    "Agent file not found at '{}'. Check jacs_data_directory and jacs_agent_id_and_version in config.",
                    agent_file.display()
                ),
            });
        }

        // Step 3: Read and parse the raw JSON
        let raw_json = fs::read_to_string(&agent_file).map_err(|e| JacsError::Internal {
            message: format!(
                "Failed to read agent file '{}': {}",
                agent_file.display(),
                e
            ),
        })?;

        let mut agent_value: Value =
            serde_json::from_str(&raw_json).map_err(|e| JacsError::Internal {
                message: format!(
                    "Failed to parse agent JSON from '{}': {}",
                    agent_file.display(),
                    e
                ),
            })?;

        // Capture pre-migration version info
        let jacs_id = agent_value["jacsId"].as_str().unwrap_or("").to_string();
        let old_version = agent_value["jacsVersion"]
            .as_str()
            .unwrap_or("")
            .to_string();

        if jacs_id.is_empty() || old_version.is_empty() {
            return Err(JacsError::Internal {
                message: "Agent document is missing jacsId or jacsVersion".to_string(),
            });
        }

        // Step 4: Patch jacsSignature if iat/jti are missing
        let mut patched_fields: Vec<String> = Vec::new();

        if let Some(sig) = agent_value.get_mut("jacsSignature") {
            if sig.get("iat").is_none() {
                let iat = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                sig["iat"] = json!(iat);
                patched_fields.push("iat".to_string());
                info!("Migration: patched missing 'iat' field with {}", iat);
            }

            if sig.get("jti").is_none() {
                let jti = uuid::Uuid::now_v7().to_string();
                sig["jti"] = json!(jti);
                patched_fields.push("jti".to_string());
                info!("Migration: patched missing 'jti' field with {}", jti);
            }
        } else {
            return Err(JacsError::Internal {
                message: "Agent document is missing jacsSignature object".to_string(),
            });
        }

        // Step 5: Recompute hash and write patched JSON back to disk (only if changes were made)
        if !patched_fields.is_empty() {
            // Recompute jacsSha256: clone doc, remove the hash field, canonicalize, SHA-256.
            // This mirrors Agent::hash_doc() so the hash gate passes during load.
            let mut hash_copy = agent_value.clone();
            if let Some(obj) = hash_copy.as_object_mut() {
                obj.remove(SHA256_FIELDNAME);
            }
            let canonical = canonicalize_json(&hash_copy);
            let new_hash = hash_string(&canonical);
            agent_value[SHA256_FIELDNAME] = json!(new_hash);
            patched_fields.push(SHA256_FIELDNAME.to_string());
            info!("Migration: recomputed {} after patching", SHA256_FIELDNAME);

            let patched_json =
                serde_json::to_string_pretty(&agent_value).map_err(|e| JacsError::Internal {
                    message: format!("Failed to serialize patched agent: {}", e),
                })?;
            fs::write(&agent_file, &patched_json).map_err(|e| JacsError::Internal {
                message: format!(
                    "Failed to write patched agent to '{}': {}",
                    agent_file.display(),
                    e
                ),
            })?;
            info!(
                "Migration: wrote patched agent to {} (fields: {:?})",
                agent_file.display(),
                patched_fields
            );
        } else {
            info!("Migration: no fields needed patching, agent already has iat and jti");
        }

        // Step 6: Load the agent normally (should now pass schema validation)
        let simple_agent = Self::load(Some(path), None)?;

        // Step 7: Export current agent doc, then call update_agent to re-sign
        let agent_doc = simple_agent.export_agent()?;
        let updated_json = simple_agent.update_agent(&agent_doc)?;

        // Step 8: Parse new version from the updated document
        let updated_value: Value =
            serde_json::from_str(&updated_json).map_err(|e| JacsError::Internal {
                message: format!("Failed to parse updated agent JSON: {}", e),
            })?;
        let new_version = updated_value["jacsVersion"]
            .as_str()
            .unwrap_or("")
            .to_string();

        // Step 9: Save the updated agent to disk
        {
            let agent = simple_agent.agent.lock().map_err(|e| JacsError::Internal {
                message: format!("Failed to acquire agent lock: {}", e),
            })?;
            agent.save().map_err(|e| JacsError::Internal {
                message: format!("Failed to save migrated agent: {}", e),
            })?;
        }

        // Step 10: Update config file with the new version (same pattern as rotate())
        let config_path_p = Path::new(path);
        if config_path_p.exists() {
            let config_str =
                fs::read_to_string(config_path_p).map_err(|e| JacsError::Internal {
                    message: format!("Failed to read config for migration update: {}", e),
                })?;
            let mut config_value: Value =
                serde_json::from_str(&config_str).map_err(|e| JacsError::Internal {
                    message: format!("Failed to parse config: {}", e),
                })?;

            let new_lookup = format!("{}:{}", jacs_id, new_version);
            if let Some(obj) = config_value.as_object_mut() {
                obj.insert("jacs_agent_id_and_version".to_string(), json!(new_lookup));
            }

            let updated_str =
                serde_json::to_string_pretty(&config_value).map_err(|e| JacsError::Internal {
                    message: format!("Failed to serialize updated config: {}", e),
                })?;
            fs::write(config_path_p, updated_str).map_err(|e| JacsError::Internal {
                message: format!("Failed to write updated config: {}", e),
            })?;

            info!(
                "Migration: config updated with new version {}:{}",
                jacs_id, new_version
            );
        }

        info!(
            "Agent migration complete: {} -> {} (id={}), patched: {:?}",
            old_version, new_version, jacs_id, patched_fields
        );

        Ok(MigrateResult {
            jacs_id,
            old_version,
            new_version,
            patched_fields,
        })
    }

    // =========================================================================
    // Attestation API (gated behind `attestation` feature)
    // =========================================================================

    /// Create a signed attestation document.
    ///
    /// Wraps `Agent::create_attestation()` with SimpleAgent's mutex + error handling.
    ///
    /// # Arguments
    /// * `subject` - The attestation subject (who/what is being attested)
    /// * `claims` - Claims about the subject (minimum 1 required by schema)
    /// * `evidence` - Optional evidence references supporting the claims
    /// * `derivation` - Optional derivation/transform receipt
    /// * `policy_context` - Optional policy evaluation context
    #[cfg(feature = "attestation")]
    pub fn create_attestation(
        &self,
        subject: &crate::attestation::types::AttestationSubject,
        claims: &[crate::attestation::types::Claim],
        evidence: &[crate::attestation::types::EvidenceRef],
        derivation: Option<&crate::attestation::types::Derivation>,
        policy_context: Option<&crate::attestation::types::PolicyContext>,
    ) -> Result<SignedDocument, JacsError> {
        use crate::attestation::AttestationTraits;
        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        let jacs_doc = agent
            .create_attestation(subject, claims, evidence, derivation, policy_context)
            .map_err(|e| JacsError::AttestationFailed {
                message: format!("Failed to create attestation: {}", e),
            })?;
        SignedDocument::from_jacs_document(jacs_doc, "attestation")
    }

    /// Verify an attestation using local (crypto-only) verification.
    ///
    /// Fast path: checks signature + hash only. No network calls, no evidence checks.
    ///
    /// # Arguments
    /// * `document_key` - The document key in "id:version" format
    #[cfg(feature = "attestation")]
    pub fn verify_attestation(
        &self,
        document_key: &str,
    ) -> Result<crate::attestation::types::AttestationVerificationResult, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        agent
            .verify_attestation_local_impl(document_key)
            .map_err(|e| JacsError::VerificationFailed {
                message: format!("Attestation local verification failed: {}", e),
            })
    }

    /// Verify an attestation using full verification.
    ///
    /// Full path: checks signature + hash + evidence digests + freshness + derivation chain.
    ///
    /// # Arguments
    /// * `document_key` - The document key in "id:version" format
    #[cfg(feature = "attestation")]
    pub fn verify_attestation_full(
        &self,
        document_key: &str,
    ) -> Result<crate::attestation::types::AttestationVerificationResult, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        agent
            .verify_attestation_full_impl(document_key)
            .map_err(|e| JacsError::VerificationFailed {
                message: format!("Attestation full verification failed: {}", e),
            })
    }

    /// Lift an existing signed document into an attestation.
    ///
    /// Convenience wrapper that takes a signed JACS document JSON string
    /// and produces a new attestation document referencing the original.
    ///
    /// # Arguments
    /// * `signed_document_json` - JSON string of the existing signed document
    /// * `claims` - Claims about the document (minimum 1 required)
    #[cfg(feature = "attestation")]
    pub fn lift_to_attestation(
        &self,
        signed_document_json: &str,
        claims: &[crate::attestation::types::Claim],
    ) -> Result<SignedDocument, JacsError> {
        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        let jacs_doc = crate::attestation::migration::lift_to_attestation(
            &mut agent,
            signed_document_json,
            claims,
        )
        .map_err(|e| JacsError::AttestationFailed {
            message: format!("Failed to lift document to attestation: {}", e),
        })?;
        SignedDocument::from_jacs_document(jacs_doc, "attestation")
    }

    /// Create a signed attestation from a JSON params string.
    ///
    /// Convenience method that accepts a JSON string with `subject`, `claims`,
    /// `evidence` (optional), `derivation` (optional), and `policyContext` (optional).
    #[cfg(feature = "attestation")]
    pub fn create_attestation_from_json(
        &self,
        params_json: &str,
    ) -> Result<SignedDocument, JacsError> {
        use crate::attestation::types::*;

        let params: serde_json::Value =
            serde_json::from_str(params_json).map_err(|e| JacsError::Internal {
                message: format!("Invalid JSON params: {}", e),
            })?;

        let subject: AttestationSubject =
            serde_json::from_value(params.get("subject").cloned().ok_or_else(|| {
                JacsError::Internal {
                    message: "Missing required 'subject' field".into(),
                }
            })?)
            .map_err(|e| JacsError::Internal {
                message: format!("Invalid subject: {}", e),
            })?;

        let claims: Vec<Claim> =
            serde_json::from_value(params.get("claims").cloned().ok_or_else(|| {
                JacsError::Internal {
                    message: "Missing required 'claims' field".into(),
                }
            })?)
            .map_err(|e| JacsError::Internal {
                message: format!("Invalid claims: {}", e),
            })?;

        let evidence: Vec<EvidenceRef> = match params.get("evidence") {
            Some(v) if !v.is_null() => {
                serde_json::from_value(v.clone()).map_err(|e| JacsError::Internal {
                    message: format!("Invalid evidence: {}", e),
                })?
            }
            _ => vec![],
        };

        let derivation: Option<Derivation> =
            match params.get("derivation") {
                Some(v) if !v.is_null() => Some(serde_json::from_value(v.clone()).map_err(
                    |e| JacsError::Internal {
                        message: format!("Invalid derivation: {}", e),
                    },
                )?),
                _ => None,
            };

        let policy_context: Option<PolicyContext> =
            match params.get("policyContext") {
                Some(v) if !v.is_null() => Some(serde_json::from_value(v.clone()).map_err(
                    |e| JacsError::Internal {
                        message: format!("Invalid policyContext: {}", e),
                    },
                )?),
                _ => None,
            };

        self.create_attestation(
            &subject,
            &claims,
            &evidence,
            derivation.as_ref(),
            policy_context.as_ref(),
        )
    }

    /// Lift a signed document into an attestation from a JSON claims string.
    ///
    /// Convenience method that accepts claims as a JSON string.
    #[cfg(feature = "attestation")]
    pub fn lift_to_attestation_from_json(
        &self,
        signed_doc_json: &str,
        claims_json: &str,
    ) -> Result<SignedDocument, JacsError> {
        use crate::attestation::types::Claim;

        let claims: Vec<Claim> =
            serde_json::from_str(claims_json).map_err(|e| JacsError::Internal {
                message: format!("Invalid claims JSON: {}", e),
            })?;

        self.lift_to_attestation(signed_doc_json, &claims)
    }

    /// Export a signed attestation as a DSSE (Dead Simple Signing Envelope).
    ///
    /// Produces an in-toto Statement wrapped in a DSSE envelope.
    /// Export-only for v0.9.0 (no import).
    ///
    /// # Arguments
    /// * `attestation_json` - JSON string of the signed attestation document
    ///
    /// # Returns
    /// A DSSE envelope JSON string containing the in-toto Statement.
    #[cfg(feature = "attestation")]
    pub fn export_dsse(&self, attestation_json: &str) -> Result<String, JacsError> {
        let att_value: serde_json::Value =
            serde_json::from_str(attestation_json).map_err(|e| JacsError::AttestationFailed {
                message: format!("Invalid attestation JSON: {}", e),
            })?;
        let envelope = crate::attestation::dsse::export_dsse(&att_value).map_err(|e| {
            JacsError::AttestationFailed {
                message: format!("Failed to export DSSE envelope: {}", e),
            }
        })?;
        serde_json::to_string(&envelope).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize DSSE envelope: {}", e),
        })
    }
}

/// Migrates a legacy agent that predates a schema change.
///
/// Convenience wrapper around [`SimpleAgent::migrate_agent()`].
/// This is a standalone function (no thread-local state needed) because
/// the agent cannot be loaded before migration.
pub fn migrate_agent(config_path: Option<&str>) -> Result<MigrateResult, JacsError> {
    SimpleAgent::migrate_agent(config_path)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::document::JACSDocument;
    use serial_test::serial;

    #[test]
    fn test_diagnostics_returns_version() {
        let info = diagnostics();
        let version = info["jacs_version"].as_str().unwrap();
        assert!(!version.is_empty(), "jacs_version should not be empty");
        assert_eq!(info["agent_loaded"], false);
        assert!(info["os"].as_str().is_some());
        assert!(info["arch"].as_str().is_some());
    }

    #[test]
    fn test_agent_info_serialization() {
        let info = AgentInfo {
            agent_id: "test-id".to_string(),
            name: "Test Agent".to_string(),
            public_key_path: "./keys/public.pem".to_string(),
            config_path: "./config.json".to_string(),
            version: "v1".to_string(),
            algorithm: "pq2025".to_string(),
            private_key_path: "./keys/private.pem.enc".to_string(),
            data_directory: "./data".to_string(),
            key_directory: "./keys".to_string(),
            domain: String::new(),
            dns_record: String::new(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test-id"));
        assert!(json.contains("Test Agent"));
        assert!(json.contains("pq2025"));
    }

    #[test]
    fn test_create_agent_params_defaults() {
        let params = CreateAgentParams::default();
        assert_eq!(params.algorithm, "pq2025");
        assert_eq!(params.data_directory, "./jacs_data");
        assert_eq!(params.key_directory, "./jacs_keys");
        assert_eq!(params.config_path, "./jacs.config.json");
        assert_eq!(params.agent_type, "ai");
        assert_eq!(params.default_storage, "fs");
    }

    #[test]
    fn test_create_agent_params_builder() {
        let params = CreateAgentParams::builder()
            .name("test-agent")
            .password("test-pass")
            .algorithm("ring-Ed25519")
            .data_directory("/tmp/data")
            .key_directory("/tmp/keys")
            .build();

        assert_eq!(params.name, "test-agent");
        assert_eq!(params.password, "test-pass");
        assert_eq!(params.algorithm, "ring-Ed25519");
        assert_eq!(params.data_directory, "/tmp/data");
        assert_eq!(params.key_directory, "/tmp/keys");
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
    fn test_signed_document_from_jacs_document_extracts_signature_fields() {
        let jacs_doc = JACSDocument {
            id: "doc-123".to_string(),
            version: "ver-1".to_string(),
            value: json!({
                "content": {"k": "v"},
                "jacsSignature": {
                    "agentID": "agent-abc",
                    "date": "2026-02-17T00:00:00Z"
                }
            }),
            jacs_type: "message".to_string(),
        };

        let signed = SignedDocument::from_jacs_document(jacs_doc, "document")
            .expect("conversion should succeed");

        assert_eq!(signed.document_id, "doc-123");
        assert_eq!(signed.agent_id, "agent-abc");
        assert_eq!(signed.timestamp, "2026-02-17T00:00:00Z");
        assert!(signed.raw.contains("\"content\""));
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
    fn test_simple_agent_load_missing_config() {
        let result = SimpleAgent::load(Some("/nonexistent/path/config.json"), None);
        assert!(result.is_err());

        match result {
            Err(JacsError::ConfigNotFound { path }) => {
                assert!(path.contains("nonexistent"));
            }
            _ => panic!("Expected ConfigNotFound error"),
        }
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
            errors: vec!["Signature invalid".to_string(), "Hash mismatch".to_string()],
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
    fn test_simple_agent_get_public_key_pem_wraps_raw_bytes() {
        let mut agent = crate::get_empty_agent();
        agent.set_keys_raw(
            vec![1, 2, 3],
            vec![0x34, 0x9e, 0x74, 0xd9, 0xd1, 0x60],
            "pq2025",
        );
        let simple = SimpleAgent {
            agent: Mutex::new(agent),
            config_path: None,
            strict: false,
        };

        let pem = simple
            .get_public_key_pem()
            .expect("raw public key bytes should export as PEM");
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    fn assert_public_key_pem_for_algorithm(requested_algorithm: &str, expected_algorithm: &str) {
        let (agent, info) =
            SimpleAgent::ephemeral(Some(requested_algorithm)).expect("create ephemeral agent");
        assert_eq!(info.algorithm, expected_algorithm);

        let pem = agent
            .get_public_key_pem()
            .expect("public key should export as canonical PEM");
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[test]
    fn test_simple_agent_get_public_key_pem_for_pq2025() {
        assert_public_key_pem_for_algorithm("pq2025", "pq2025");
    }

    #[test]
    fn test_simple_agent_get_public_key_pem_for_ed25519() {
        assert_public_key_pem_for_algorithm("ed25519", "ring-Ed25519");
    }

    #[test]
    fn test_simple_agent_get_public_key_pem_for_rsa_pss() {
        assert_public_key_pem_for_algorithm("rsa-pss", "RSA-PSS");
    }

    #[test]
    fn test_simple_agent_struct_has_config_path() {
        // Test that SimpleAgent can store and return config path
        // Note: We can't fully test create/load without a valid config,
        // but we can verify the struct design
        let result = SimpleAgent::load(Some("./nonexistent.json"), None);
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

        let result =
            VerificationResult::success(data.clone(), signer_id.clone(), timestamp.clone());

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

    #[test]
    fn test_verify_non_json_returns_helpful_error() {
        // Create a dummy SimpleAgent for testing verify() pre-check
        // The pre-check happens before agent lock, so we need a valid agent struct
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };

        // Plain text that's not JSON
        let result = agent.verify("not-json-at-all");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("verify_by_id"),
            "Error should suggest verify_by_id(): {}",
            err_str
        );
    }

    #[test]
    fn test_verify_uuid_like_input_returns_helpful_error() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };

        // A document ID like "uuid:version"
        let result = agent.verify("550e8400-e29b-41d4-a716-446655440000:1");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("verify_by_id"),
            "Error for UUID-like input should suggest verify_by_id(): {}",
            err_str
        );
    }

    #[test]
    fn test_verify_empty_string_returns_error() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };

        // Empty string should fail at JSON parse, not at pre-check
        let result = agent.verify("");
        assert!(result.is_err());
    }

    #[test]
    fn test_setup_instructions_serialization() {
        let instr = SetupInstructions {
            dns_record_bind: "example.com. 3600 IN TXT \"test\"".to_string(),
            dns_record_value: "test".to_string(),
            dns_owner: "_v1.agent.jacs.example.com.".to_string(),
            provider_commands: std::collections::HashMap::new(),
            dnssec_instructions: std::collections::HashMap::new(),
            tld_requirement: "You must own a domain".to_string(),
            well_known_json: "{}".to_string(),
            summary: "Setup summary".to_string(),
        };

        let json = serde_json::to_string(&instr).unwrap();
        assert!(json.contains("dns_record_bind"));
        assert!(json.contains("_v1.agent.jacs.example.com."));
    }

    #[test]
    fn test_get_setup_instructions_requires_loaded_agent() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };

        let result = agent.get_setup_instructions("example.com", 3600);
        assert!(result.is_err(), "should fail without a loaded agent");
    }

    #[test]
    fn test_resolve_strict_defaults_to_false() {
        // With no explicit param and no env var, strict should be false
        assert!(!resolve_strict(None));
    }

    #[test]
    fn test_resolve_strict_explicit_overrides() {
        assert!(resolve_strict(Some(true)));
        assert!(!resolve_strict(Some(false)));
    }

    #[test]
    fn test_resolve_strict_env_var() {
        // SAFETY: Tests run single-threaded (serial_test or #[test] default)
        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "true");
        }
        assert!(resolve_strict(None));

        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "1");
        }
        assert!(resolve_strict(None));

        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "false");
        }
        assert!(!resolve_strict(None));

        // Explicit overrides env var
        unsafe {
            std::env::set_var("JACS_STRICT_MODE", "true");
        }
        assert!(!resolve_strict(Some(false)));

        unsafe {
            std::env::remove_var("JACS_STRICT_MODE");
        }
    }

    #[test]
    fn test_simple_agent_is_strict_accessor() {
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: true,
        };
        assert!(agent.is_strict());

        let agent2 = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: false,
        };
        assert!(!agent2.is_strict());
    }

    #[test]
    fn test_verify_non_json_strict_still_returns_err() {
        // Strict mode shouldn't change behavior for malformed input — it should
        // still return Err(DocumentMalformed), not SignatureVerificationFailed
        let agent = SimpleAgent {
            agent: Mutex::new(crate::get_empty_agent()),
            config_path: None,

            strict: true,
        };

        let result = agent.verify("not-json-at-all");
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { .. }) => {} // expected
            other => panic!("Expected DocumentMalformed, got {:?}", other),
        }
    }

    #[test]
    fn test_simple_ephemeral_default_pq2025() {
        let (agent, info) = SimpleAgent::ephemeral(None).unwrap();
        assert!(!info.agent_id.is_empty());
        assert_eq!(info.algorithm, "pq2025");
        assert_eq!(info.name, "ephemeral");
        assert!(info.config_path.is_empty());
        assert!(info.public_key_path.is_empty());
        // Verify self works
        let result = agent.verify_self().unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_simple_ephemeral_pq2025() {
        let (agent, info) = SimpleAgent::ephemeral(Some("pq2025")).unwrap();
        assert_eq!(info.algorithm, "pq2025");
        let result = agent.verify_self().unwrap();
        assert!(result.valid);
    }

    #[test]
    fn test_simple_ephemeral_sign_and_verify() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let msg = serde_json::json!({"hello": "world"});
        let signed = agent.sign_message(&msg).unwrap();
        assert!(!signed.raw.is_empty());
        // Verify the signed document
        let result = agent.verify(&signed.raw).unwrap();
        assert!(
            result.valid,
            "Signed message should verify: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_verify_by_id_uses_loaded_agent_storage_backend() {
        let (agent, _info) =
            SimpleAgent::ephemeral(Some("ed25519")).expect("create ephemeral agent");
        let signed = agent
            .sign_message(&json!({"hello": "verify-by-id"}))
            .expect("sign message");
        let signed_value: Value = serde_json::from_str(&signed.raw).expect("parse signed document");
        let document_key = format!(
            "{}:{}",
            signed_value["jacsId"].as_str().expect("jacsId"),
            signed_value["jacsVersion"].as_str().expect("jacsVersion")
        );

        let result = agent
            .verify_by_id(&document_key)
            .expect("verify_by_id should read from the agent's configured storage");
        assert!(
            result.valid,
            "verify_by_id should succeed for a document stored in memory: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_simple_ephemeral_no_files() {
        let temp = std::env::temp_dir().join("jacs_simple_ephemeral_no_files");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let (_agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let entries: Vec<_> = std::fs::read_dir(&temp).unwrap().collect();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir_all(&temp);
    }

    // =========================================================================
    // A2A Protocol Method Tests
    // =========================================================================

    #[test]
    fn test_export_agent_card() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let card = agent.export_agent_card().unwrap();
        assert!(!card.name.is_empty());
        assert!(!card.protocol_versions.is_empty());
        assert_eq!(card.protocol_versions[0], "0.4.0");
        assert!(!card.supported_interfaces.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn test_wrap_and_verify_a2a_artifact() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let artifact = r#"{"text": "hello from A2A"}"#;

        let wrapped = agent.wrap_a2a_artifact(artifact, "message", None).unwrap();

        // Wrapped should be valid JSON with JACS fields
        let wrapped_value: Value = serde_json::from_str(&wrapped).unwrap();
        assert!(wrapped_value.get("jacsId").is_some());
        assert!(wrapped_value.get("jacsSignature").is_some());
        assert_eq!(wrapped_value["jacsType"], "a2a-message");

        // Verify the wrapped artifact
        let result_json = agent.verify_a2a_artifact(&wrapped).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
        assert_eq!(result["status"], "SelfSigned");
    }

    #[test]
    fn test_sign_artifact_alias() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let artifact = r#"{"data": "test"}"#;

        // sign_artifact should produce the same structure as wrap_a2a_artifact
        let signed = agent.sign_artifact(artifact, "artifact", None).unwrap();
        let value: Value = serde_json::from_str(&signed).unwrap();
        assert!(value.get("jacsId").is_some());
        assert_eq!(value["jacsType"], "a2a-artifact");

        // And it should verify
        let result_json = agent.verify_a2a_artifact(&signed).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
    }

    #[test]
    #[allow(deprecated)]
    fn test_wrap_a2a_artifact_with_parent_signatures() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();

        // Create a first artifact
        let first = agent
            .wrap_a2a_artifact(r#"{"step": 1}"#, "task", None)
            .unwrap();

        // Use the first as a parent signature for a second
        let parents = format!("[{}]", first);
        let second = agent
            .wrap_a2a_artifact(r#"{"step": 2}"#, "task", Some(&parents))
            .unwrap();

        let second_value: Value = serde_json::from_str(&second).unwrap();
        assert!(second_value.get("jacsParentSignatures").is_some());
        let parent_sigs = second_value["jacsParentSignatures"].as_array().unwrap();
        assert_eq!(parent_sigs.len(), 1);
    }

    #[test]
    #[allow(deprecated)]
    fn test_wrap_a2a_artifact_invalid_json() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let result = agent.wrap_a2a_artifact("not json", "artifact", None);
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { field, .. }) => {
                assert_eq!(field, "artifact_json");
            }
            other => panic!("Expected DocumentMalformed, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_a2a_artifact_invalid_json() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let result = agent.verify_a2a_artifact("not json");
        assert!(result.is_err());
        match result {
            Err(JacsError::DocumentMalformed { field, .. }) => {
                assert_eq!(field, "wrapped_json");
            }
            other => panic!("Expected DocumentMalformed, got {:?}", other),
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_wrap_a2a_artifact_pq2025() {
        let (agent, _info) = SimpleAgent::ephemeral(Some("pq2025")).unwrap();
        let artifact = r#"{"quantum": "safe"}"#;

        let wrapped = agent.wrap_a2a_artifact(artifact, "artifact", None).unwrap();
        let result_json = agent.verify_a2a_artifact(&wrapped).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
    }

    #[test]
    fn test_export_agent_card_has_jacs_extension() {
        let (agent, _info) = SimpleAgent::ephemeral(None).unwrap();
        let card = agent.export_agent_card().unwrap();

        let extensions = card.capabilities.extensions.unwrap();
        assert!(!extensions.is_empty());
        assert_eq!(extensions[0].uri, crate::a2a::JACS_EXTENSION_URI);
    }

    /// Shared mutex for verify_with_key tests that set global env vars.
    static VERIFY_WITH_KEY_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Create a test SimpleAgent with its own temp directory.
    /// MUST be called while holding `VERIFY_WITH_KEY_MUTEX`.
    fn create_test_agent_for_verify(name: &str) -> (SimpleAgent, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let tmp_path = tmp.path().to_string_lossy().to_string();

        let params = CreateAgentParams::builder()
            .name(name)
            .password("TestVerify!2026")
            .algorithm("ring-Ed25519")
            .domain("test.example.com")
            .description("Test agent for verify_with_key")
            .data_directory(&format!("{}/jacs_data", tmp_path))
            .key_directory(&format!("{}/jacs_keys", tmp_path))
            .config_path(&format!("{}/jacs.config.json", tmp_path))
            .build();

        let (agent, _info) = SimpleAgent::create_with_params(params).expect("create test agent");

        unsafe {
            std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "TestVerify!2026");
            std::env::set_var("JACS_KEY_DIRECTORY", format!("{}/jacs_keys", tmp_path));
            std::env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "jacs.private.pem.enc");
            std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "jacs.public.pem");
        }

        (agent, tmp)
    }

    #[test]
    #[serial]
    fn verify_with_key_cross_agent_succeeds() {
        let _lock = VERIFY_WITH_KEY_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // agent_a signs a message
        let (agent_a, _tmp_a) = create_test_agent_for_verify("agent-a-vwk");
        let signed = agent_a
            .sign_message(&json!({"msg": "hello from A"}))
            .expect("sign_message should succeed");

        let agent_a_pubkey = agent_a
            .get_public_key()
            .expect("get_public_key should succeed");

        // agent_b verifies using agent_a's public key
        let (agent_b, _tmp_b) = create_test_agent_for_verify("agent-b-vwk");
        let result = agent_b
            .verify_with_key(&signed.raw, agent_a_pubkey)
            .expect("verify_with_key should succeed");

        assert!(
            result.valid,
            "cross-agent verification should pass: {:?}",
            result.errors
        );
        assert!(!result.signer_id.is_empty());
    }

    #[test]
    #[serial]
    fn verify_with_key_wrong_key_fails() {
        let _lock = VERIFY_WITH_KEY_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // agent_a signs a message
        let (agent_a, _tmp_a) = create_test_agent_for_verify("agent-a-wrong");
        let signed = agent_a
            .sign_message(&json!({"msg": "hello from A"}))
            .expect("sign_message should succeed");

        // agent_b tries to verify with its OWN key (wrong key)
        let (agent_b, _tmp_b) = create_test_agent_for_verify("agent-b-wrong");
        let agent_b_pubkey = agent_b
            .get_public_key()
            .expect("get_public_key should succeed");

        let result = agent_b
            .verify_with_key(&signed.raw, agent_b_pubkey)
            .expect("verify_with_key should return Ok with errors, not Err");

        assert!(!result.valid, "verification with wrong key should fail");
        assert!(!result.errors.is_empty(), "should have verification errors");
    }

    // =========================================================================
    // Key Rotation Tests
    // =========================================================================

    /// Shared mutex for rotation tests that manipulate env vars / filesystem.
    static ROTATION_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that restores the working directory when dropped (even on panic).
    struct CwdGuard {
        saved: std::path::PathBuf,
    }
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.saved);
        }
    }

    /// Helper: create a persistent test agent in a temp directory.
    /// Returns (SimpleAgent, AgentInfo, TempDir, CwdGuard). Caller MUST hold ROTATION_TEST_MUTEX.
    ///
    /// This changes CWD to the temp dir so that the MultiStorage (which saves
    /// public keys relative to CWD) and the FsEncryptedStore key_paths (which
    /// computes paths from the env var) agree on file locations.
    /// The CwdGuard restores CWD automatically when dropped, even on panic.
    fn create_persistent_test_agent(
        name: &str,
    ) -> (SimpleAgent, AgentInfo, tempfile::TempDir, CwdGuard) {
        let saved_cwd = std::env::current_dir().expect("get cwd");
        let tmp = tempfile::tempdir().expect("create temp dir");

        // Change CWD to temp dir so relative paths work
        std::env::set_current_dir(tmp.path()).expect("cd to temp dir");
        let guard = CwdGuard { saved: saved_cwd };

        let params = CreateAgentParams::builder()
            .name(name)
            .password("RotateTest!2026")
            .algorithm("ring-Ed25519")
            .description("Test agent for key rotation")
            .data_directory("./jacs_data")
            .key_directory("./jacs_keys")
            .config_path("./jacs.config.json")
            .build();

        let (agent, info) = SimpleAgent::create_with_params(params).expect("create test agent");

        // Set env vars so key operations work
        unsafe {
            std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "RotateTest!2026");
            std::env::set_var("JACS_KEY_DIRECTORY", "./jacs_keys");
            std::env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "jacs.private.pem.enc");
            std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "jacs.public.pem");
        }

        (agent, info, tmp, guard)
    }

    #[test]
    #[serial]
    fn test_load_roots_relative_paths_to_config_directory() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, tmp, guard) = create_persistent_test_agent("load-relative-root-test");
        let config_path = tmp.path().join("jacs.config.json");
        drop(guard);

        let signed = agent
            .sign_message(&json!({"load": "relative"}))
            .expect("signing should succeed");
        drop(agent);

        let loaded = SimpleAgent::load(Some(config_path.to_string_lossy().as_ref()), Some(true))
            .expect("loading should succeed from any CWD when config uses relative paths");
        let result = loaded.verify(&signed.raw).expect("verify should succeed");
        assert!(
            result.valid,
            "loaded agent should verify documents after CWD change: {:?}",
            result.errors
        );
    }

    #[test]
    #[serial]
    fn test_embedded_export_writes_to_data_directory_only() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, tmp, guard) = create_persistent_test_agent("embedded-export-root-test");
        let source_name = "source-embed.bin";
        let source_path = tmp.path().join(source_name);
        std::fs::write(&source_path, b"embedded payload").expect("write source file");
        drop(guard);

        {
            let mut inner = agent.agent.lock().expect("lock agent");
            let content = json!({
                "jacsType": "file",
                "jacsLevel": "raw",
                "filename": source_name,
                "mimetype": "application/octet-stream"
            });
            let doc = inner
                .create_document_and_load(
                    &content.to_string(),
                    Some(vec![source_name.to_string()]),
                    Some(true),
                )
                .expect("create embedded document");
            std::fs::remove_file(&source_path).expect("remove original source file");
            inner
                .save_document(&doc.getkey(), None, Some(true), Some(true))
                .expect("save_document export should succeed");
        }

        let extracted_in_data_dir = tmp.path().join("jacs_data").join(source_name);
        assert!(
            extracted_in_data_dir.exists(),
            "embedded export should be written under jacs_data"
        );
        assert!(
            !tmp.path().join(source_name).exists(),
            "embedded export must not be written to repository root paths"
        );
    }

    #[test]
    #[serial]
    fn test_load_handles_mixed_relative_data_and_absolute_key_directories() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, tmp, guard) = create_persistent_test_agent("mixed-dir-root-test");
        let config_path = tmp.path().join("jacs.config.json");

        // Make key directory absolute while keeping data directory relative.
        let mut config_value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config"))
                .expect("parse config json");
        config_value["jacs_key_directory"] =
            serde_json::Value::String(tmp.path().join("jacs_keys").to_string_lossy().to_string());
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&config_value).expect("serialize config"),
        )
        .expect("write updated config");

        let signed = agent
            .sign_message(&json!({"mixed": "dirs"}))
            .expect("signing should succeed");
        drop(agent);
        drop(guard);

        // Ensure file config is honored (do not let helper env vars override it).
        unsafe {
            std::env::remove_var("JACS_DATA_DIRECTORY");
            std::env::remove_var("JACS_KEY_DIRECTORY");
            std::env::remove_var("JACS_AGENT_PRIVATE_KEY_FILENAME");
            std::env::remove_var("JACS_AGENT_PUBLIC_KEY_FILENAME");
            std::env::remove_var("JACS_DEFAULT_STORAGE");
            std::env::remove_var("JACS_AGENT_ID_AND_VERSION");
        }

        let loaded = SimpleAgent::load(Some(config_path.to_string_lossy().as_ref()), Some(true))
            .expect("loading should succeed with mixed absolute/relative config directories");
        let result = loaded.verify(&signed.raw).expect("verify should succeed");
        assert!(
            result.valid,
            "loaded agent should verify when key dir is absolute and data dir is relative: {:?}",
            result.errors
        );
    }

    #[test]
    #[serial]
    fn test_load_rejects_parent_directory_segments_in_storage_dirs() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (_agent, _info, tmp, guard) = create_persistent_test_agent("reject-parent-dir-test");
        let config_path = tmp.path().join("jacs.config.json");

        let mut config_value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).expect("read config"))
                .expect("parse config json");
        config_value["jacs_data_directory"] =
            serde_json::Value::String("../outside-data".to_string());
        std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&config_value).expect("serialize config"),
        )
        .expect("write updated config");
        drop(guard);

        unsafe {
            std::env::remove_var("JACS_DATA_DIRECTORY");
            std::env::remove_var("JACS_KEY_DIRECTORY");
            std::env::remove_var("JACS_AGENT_PRIVATE_KEY_FILENAME");
            std::env::remove_var("JACS_AGENT_PUBLIC_KEY_FILENAME");
            std::env::remove_var("JACS_DEFAULT_STORAGE");
            std::env::remove_var("JACS_AGENT_ID_AND_VERSION");
        }

        let load_result =
            SimpleAgent::load(Some(config_path.to_string_lossy().as_ref()), Some(true));
        assert!(
            load_result.is_err(),
            "loading should reject parent-directory segments in configured storage directories"
        );
        let err_text = load_result.err().unwrap().to_string();
        assert!(
            err_text.contains("parent-directory segment"),
            "error should mention parent-directory segment rejection, got: {}",
            err_text
        );
    }

    #[test]
    #[serial]
    fn test_rotate_preserves_jacs_id() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, info, _tmp, _guard) = create_persistent_test_agent("rotate-id-test");
        let original_id = info.agent_id.clone();
        let original_version = info.version.clone();

        let result = agent.rotate().expect("rotation should succeed");

        assert_eq!(
            result.jacs_id, original_id,
            "jacsId must not change after rotation"
        );
        assert_ne!(
            result.new_version, original_version,
            "jacsVersion must change after rotation"
        );
        assert_eq!(result.old_version, original_version);
    }

    #[test]
    #[serial]
    fn test_rotate_new_key_signs_correctly() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, _tmp, _guard) = create_persistent_test_agent("rotate-sign-test");

        let _result = agent.rotate().expect("rotation should succeed");

        // Sign a message with the rotated agent's new key
        let signed = agent
            .sign_message(&json!({"after": "rotation"}))
            .expect("signing with new key should succeed");

        // Verify the message
        let verification = agent.verify(&signed.raw).expect("verify should succeed");

        assert!(
            verification.valid,
            "Message signed with new key should verify: {:?}",
            verification.errors
        );
    }

    #[test]
    #[serial]
    fn test_rotate_returns_rotation_result() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, _tmp, _guard) = create_persistent_test_agent("rotate-result-test");

        let result = agent.rotate().expect("rotation should succeed");

        // All fields should be non-empty
        assert!(!result.jacs_id.is_empty(), "jacs_id should not be empty");
        assert!(
            !result.old_version.is_empty(),
            "old_version should not be empty"
        );
        assert!(
            !result.new_version.is_empty(),
            "new_version should not be empty"
        );
        assert!(
            !result.new_public_key_pem.is_empty(),
            "new_public_key_pem should not be empty"
        );
        assert!(
            !result.new_public_key_hash.is_empty(),
            "new_public_key_hash should not be empty"
        );
        assert!(
            !result.signed_agent_json.is_empty(),
            "signed_agent_json should not be empty"
        );

        // signed_agent_json should be valid JSON containing the new version
        let doc: Value =
            serde_json::from_str(&result.signed_agent_json).expect("should be valid JSON");
        assert_eq!(
            doc["jacsVersion"].as_str().unwrap(),
            result.new_version,
            "signed doc should contain new version"
        );
        assert_eq!(
            doc["jacsId"].as_str().unwrap(),
            result.jacs_id,
            "signed doc should contain same jacsId"
        );
    }

    #[test]
    #[serial]
    fn test_rotate_config_updated() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, info, _tmp, _guard) = create_persistent_test_agent("rotate-config-test");

        let result = agent.rotate().expect("rotation should succeed");

        // Read the config (CWD is still temp dir, so relative path works)
        let config_str = std::fs::read_to_string("./jacs.config.json").expect("read config");

        let config: Value = serde_json::from_str(&config_str).expect("parse config");
        let expected_lookup = format!("{}:{}", info.agent_id, result.new_version);
        assert_eq!(
            config["jacs_agent_id_and_version"].as_str().unwrap(),
            expected_lookup,
            "Config should be updated with new version"
        );
    }

    #[test]
    fn test_rotate_ephemeral_agent() {
        // Ephemeral agents should support rotation (no filesystem involved)
        let (agent, info) = SimpleAgent::ephemeral(Some("ed25519")).unwrap();
        let original_version = info.version.clone();

        let result = agent.rotate().expect("ephemeral rotation should succeed");

        assert_eq!(result.jacs_id, info.agent_id);
        assert_ne!(result.new_version, original_version);
        assert!(!result.new_public_key_pem.is_empty());
        assert!(!result.signed_agent_json.is_empty());

        // Agent should still be functional after rotation
        let signed = agent
            .sign_message(&json!({"ephemeral": "after rotate"}))
            .expect("signing after ephemeral rotation should work");
        let verification = agent.verify(&signed.raw).expect("verify should work");
        assert!(
            verification.valid,
            "ephemeral post-rotation verify failed: {:?}",
            verification.errors
        );
    }

    #[test]
    #[serial]
    fn test_rotate_old_key_still_verifies_old_doc() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, _tmp, _guard) = create_persistent_test_agent("rotate-old-key-test");

        // Sign a document with the original key
        let signed_before = agent
            .sign_message(&json!({"pre_rotation": true}))
            .expect("signing before rotation should succeed");

        // Save the old public key bytes
        let old_public_key = agent.get_public_key().expect("get old public key");

        // Rotate
        let _result = agent.rotate().expect("rotation should succeed");

        // Verify the pre-rotation doc using the old public key
        let verification = agent
            .verify_with_key(&signed_before.raw, old_public_key)
            .expect("verify_with_key should return a result");

        assert!(
            verification.valid,
            "Old doc should still verify with old key: {:?}",
            verification.errors
        );
    }

    #[test]
    #[serial]
    fn test_rotate_full_cycle() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, _tmp, _guard) = create_persistent_test_agent("rotate-full-cycle");

        // Phase 1: Sign with original key
        let old_public_key = agent.get_public_key().expect("get old key");
        let signed_v1 = agent.sign_message(&json!({"version": 1})).expect("sign v1");

        // Phase 2: Rotate
        let result = agent.rotate().expect("rotation should succeed");

        // Phase 3: Sign with new key
        let signed_v2 = agent.sign_message(&json!({"version": 2})).expect("sign v2");

        // Phase 4: Verify both documents
        // v1 doc with old key
        let v1_check = agent
            .verify_with_key(&signed_v1.raw, old_public_key)
            .expect("verify v1 with old key");
        assert!(
            v1_check.valid,
            "v1 should verify with old key: {:?}",
            v1_check.errors
        );

        // v2 doc with current agent (new key)
        let v2_check = agent.verify(&signed_v2.raw).expect("verify v2");
        assert!(
            v2_check.valid,
            "v2 should verify with new key: {:?}",
            v2_check.errors
        );

        // Version chain is correct
        let doc: Value =
            serde_json::from_str(&result.signed_agent_json).expect("parse signed agent");
        assert_eq!(
            doc["jacsPreviousVersion"].as_str().unwrap(),
            result.old_version,
            "jacsPreviousVersion should reference old version"
        );
    }

    // =========================================================================
    // Agent Update Lifecycle Tests
    //
    // These test the core contract:
    //   - Key rotation creates a new version, preserves jacsId, agent is valid
    //   - Metadata update creates a new version, preserves jacsId, agent is valid
    //   - jacsId MUST NOT change across any update operation
    // =========================================================================

    #[test]
    #[serial]
    fn test_update_lifecycle_rotate_preserves_id_and_creates_new_version() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, info, _tmp, _guard) = create_persistent_test_agent("lifecycle-rotate-test");
        let original_id = info.agent_id.clone();
        let original_version = info.version.clone();

        // Step 2: rotate keys
        let rot = agent.rotate().expect("key rotation should succeed");

        // jacsId MUST NOT change
        assert_eq!(
            rot.jacs_id, original_id,
            "jacsId MUST NOT change after key rotation"
        );
        // version MUST change
        assert_ne!(
            rot.new_version, original_version,
            "jacsVersion must change after key rotation"
        );
        assert_eq!(rot.old_version, original_version);

        // Verify the rotated agent is valid: can sign and verify
        let signed = agent
            .sign_message(&json!({"after": "rotation"}))
            .expect("signing with new key should succeed");
        let verification = agent.verify(&signed.raw).expect("verify should succeed");
        assert!(
            verification.valid,
            "message signed after rotation should verify: {:?}",
            verification.errors
        );

        // Verify agent doc itself has correct fields
        let exported = agent.export_agent().expect("export should succeed");
        let doc: Value = serde_json::from_str(&exported).expect("parse agent");
        assert_eq!(doc["jacsId"].as_str().unwrap(), original_id);
        assert_eq!(doc["jacsVersion"].as_str().unwrap(), rot.new_version);

        let sig = doc.get("jacsSignature").expect("should have jacsSignature");
        assert!(sig.get("iat").is_some(), "rotated doc should have iat");
        assert!(sig.get("jti").is_some(), "rotated doc should have jti");
    }

    #[test]
    #[serial]
    fn test_update_lifecycle_metadata_update_preserves_id_and_creates_new_version() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, info, _tmp, _guard) = create_persistent_test_agent("lifecycle-metadata-test");
        let original_id = info.agent_id.clone();
        let original_version = info.version.clone();

        // Step 3: update metadata (change description via jacsServices)
        let exported = agent.export_agent().expect("export original agent");
        let mut doc: Value = serde_json::from_str(&exported).expect("parse agent");
        doc["jacsServices"] = json!([{
            "serviceDescription": "Updated service description",
            "successDescription": "Updated success",
            "failureDescription": "Updated failure"
        }]);

        let updated_json = agent
            .update_agent(&doc.to_string())
            .expect("metadata update should succeed");

        // Parse the updated doc
        let updated_doc: Value = serde_json::from_str(&updated_json).expect("parse updated agent");

        // jacsId MUST NOT change
        assert_eq!(
            updated_doc["jacsId"].as_str().unwrap(),
            original_id,
            "jacsId MUST NOT change after metadata update"
        );
        // version MUST change
        assert_ne!(
            updated_doc["jacsVersion"].as_str().unwrap(),
            original_version,
            "jacsVersion must change after metadata update"
        );
        // metadata should be updated
        assert_eq!(
            updated_doc["jacsServices"][0]["serviceDescription"]
                .as_str()
                .unwrap(),
            "Updated service description"
        );

        // Verify the updated agent is valid: can sign and verify
        let signed = agent
            .sign_message(&json!({"after": "metadata-update"}))
            .expect("signing after metadata update should succeed");
        let verification = agent.verify(&signed.raw).expect("verify should succeed");
        assert!(
            verification.valid,
            "message signed after metadata update should verify: {:?}",
            verification.errors
        );

        // Verify signature fields
        let sig = updated_doc
            .get("jacsSignature")
            .expect("should have jacsSignature");
        assert!(sig.get("iat").is_some(), "updated doc should have iat");
        assert!(sig.get("jti").is_some(), "updated doc should have jti");
    }

    #[test]
    #[serial]
    fn test_update_lifecycle_rotate_then_metadata_update() {
        // Full lifecycle: create → rotate keys → update metadata
        // Each step must preserve jacsId and produce a new valid version.
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, info, _tmp, _guard) = create_persistent_test_agent("lifecycle-full-test");
        let original_id = info.agent_id.clone();
        let v1 = info.version.clone();

        // Step 2: rotate keys
        let rot = agent.rotate().expect("key rotation should succeed");
        let v2 = rot.new_version.clone();
        assert_eq!(
            rot.jacs_id, original_id,
            "jacsId MUST NOT change after rotation"
        );
        assert_ne!(v2, v1, "version must change after rotation");

        // Verify agent is valid after rotation
        let signed_after_rotate = agent
            .sign_message(&json!({"phase": "after-rotation"}))
            .expect("signing after rotation should succeed");
        let check_rotate = agent.verify(&signed_after_rotate.raw).expect("verify");
        assert!(
            check_rotate.valid,
            "valid after rotation: {:?}",
            check_rotate.errors
        );

        // Step 3: update metadata
        let exported = agent.export_agent().expect("export after rotation");
        let mut doc: Value = serde_json::from_str(&exported).expect("parse");
        doc["jacsServices"] = json!([{
            "serviceDescription": "Post-rotation service",
            "successDescription": "Works",
            "failureDescription": "Fails"
        }]);

        let updated_json = agent
            .update_agent(&doc.to_string())
            .expect("metadata update after rotation should succeed");
        let updated_doc: Value = serde_json::from_str(&updated_json).expect("parse updated");
        let v3 = updated_doc["jacsVersion"].as_str().unwrap().to_string();

        // jacsId still the same
        assert_eq!(
            updated_doc["jacsId"].as_str().unwrap(),
            original_id,
            "jacsId MUST NOT change after metadata update post-rotation"
        );
        // version progressed
        assert_ne!(v3, v2, "version must change after metadata update");
        assert_ne!(v3, v1, "version must differ from original");

        // Verify the agent is still valid after both operations
        let signed_after_meta = agent
            .sign_message(&json!({"phase": "after-metadata-update"}))
            .expect("signing after metadata update should succeed");
        let check_meta = agent.verify(&signed_after_meta.raw).expect("verify");
        assert!(
            check_meta.valid,
            "valid after metadata update: {:?}",
            check_meta.errors
        );

        // Metadata persisted
        assert_eq!(
            updated_doc["jacsServices"][0]["serviceDescription"]
                .as_str()
                .unwrap(),
            "Post-rotation service"
        );
    }

    #[test]
    #[serial]
    fn test_update_agent_must_not_change_jacs_id() {
        // Attempting to change jacsId in an update MUST fail.
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (agent, _info, _tmp, _guard) = create_persistent_test_agent("lifecycle-id-guard-test");

        let exported = agent.export_agent().expect("export");
        let mut doc: Value = serde_json::from_str(&exported).expect("parse");
        // Try to change jacsId
        doc["jacsId"] = json!("00000000-0000-0000-0000-000000000000");

        let result = agent.update_agent(&doc.to_string());
        assert!(
            result.is_err(),
            "updating with a different jacsId MUST fail"
        );
    }

    // =========================================================================
    // migrate_agent Tests (legacy schema migration)
    // =========================================================================

    #[test]
    #[serial]
    fn test_migrate_already_current_agent_still_works() {
        // An agent that already has iat/jti should still migrate (no-op patch,
        // but still creates a new version).
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (_agent, info, _tmp, _guard) = create_persistent_test_agent("migrate-current-test");
        let config_path = "./jacs.config.json";

        let result = SimpleAgent::migrate_agent(Some(config_path))
            .expect("migration of current agent should succeed");

        assert_eq!(result.jacs_id, info.agent_id);
        assert!(
            result.patched_fields.is_empty(),
            "current agent should need no patches, got: {:?}",
            result.patched_fields
        );
        // Still creates a new version (re-signed)
        assert_ne!(result.new_version, info.version);
    }

    #[test]
    #[serial]
    fn test_migrate_missing_config_returns_error() {
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let result = SimpleAgent::migrate_agent(Some("/nonexistent/path/jacs.config.json"));
        assert!(result.is_err(), "migrating with missing config should fail");
    }

    #[test]
    #[serial]
    fn test_migrate_legacy_agent_missing_iat_jti() {
        // Simulate a truly legacy agent by creating an agent then stripping iat/jti
        // from the on-disk jacsSignature. Migration should recompute the hash,
        // re-sign, and produce a valid new version.
        let _lock = ROTATION_TEST_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let (_agent, info, _tmp, _guard) = create_persistent_test_agent("migrate-legacy-test");
        let config_path = "./jacs.config.json";

        // Read config to find the agent file
        let config_str = std::fs::read_to_string(config_path).expect("read config");
        let config_val: Value = serde_json::from_str(&config_str).expect("parse config");
        let id_and_version = config_val["jacs_agent_id_and_version"]
            .as_str()
            .expect("id_and_version in config");
        let data_dir = config_val["jacs_data_directory"]
            .as_str()
            .unwrap_or("jacs_data");
        let agent_file = std::path::PathBuf::from(data_dir)
            .join("agent")
            .join(format!("{}.json", id_and_version));

        // Strip iat and jti from jacsSignature to simulate a legacy agent
        let raw = std::fs::read_to_string(&agent_file).expect("read agent file");
        let mut agent_val: Value = serde_json::from_str(&raw).expect("parse agent");
        let sig = agent_val
            .get_mut("jacsSignature")
            .expect("jacsSignature exists")
            .as_object_mut()
            .expect("jacsSignature is object");
        assert!(sig.remove("iat").is_some(), "iat should have existed");
        assert!(sig.remove("jti").is_some(), "jti should have existed");
        let stripped = serde_json::to_string_pretty(&agent_val).expect("serialize");
        std::fs::write(&agent_file, &stripped).expect("write stripped agent");

        // Verify that loading normally would fail (hash mismatch)
        let load_result = SimpleAgent::load(Some(config_path), None);
        assert!(
            load_result.is_err(),
            "loading a stripped legacy agent without migration should fail"
        );

        // Now migrate — should patch iat/jti, recompute hash, re-sign
        let result = SimpleAgent::migrate_agent(Some(config_path))
            .expect("migration of legacy agent should succeed");

        assert_eq!(result.jacs_id, info.agent_id, "jacsId must not change");
        assert_ne!(
            result.new_version, info.version,
            "migration must produce a new version"
        );
        assert!(
            result.patched_fields.contains(&"iat".to_string()),
            "iat should be patched: {:?}",
            result.patched_fields
        );
        assert!(
            result.patched_fields.contains(&"jti".to_string()),
            "jti should be patched: {:?}",
            result.patched_fields
        );
        assert!(
            result.patched_fields.contains(&"jacsSha256".to_string()),
            "jacsSha256 should be recomputed: {:?}",
            result.patched_fields
        );

        // Verify the migrated agent can be loaded and used
        let migrated =
            SimpleAgent::load(Some(config_path), None).expect("migrated agent should load");
        let signed = migrated
            .sign_message(&json!({"test": "post-migration"}))
            .expect("signing after migration should work");
        let verified = migrated
            .verify(&signed.raw)
            .expect("verification after migration should work");
        assert!(
            verified.valid,
            "migrated agent should produce valid signatures: {:?}",
            verified.errors
        );
    }

    // =========================================================================
    // Attestation API Tests (gated behind `attestation` feature)
    // =========================================================================

    #[cfg(feature = "attestation")]
    mod attestation_tests {
        use super::*;
        use crate::attestation::types::*;

        fn ephemeral_agent() -> SimpleAgent {
            let (agent, _info) = SimpleAgent::ephemeral(Some("ring-Ed25519")).unwrap();
            agent
        }

        fn test_subject() -> AttestationSubject {
            AttestationSubject {
                subject_type: SubjectType::Artifact,
                id: "test-artifact-001".into(),
                digests: DigestSet {
                    sha256: "abc123".into(),
                    sha512: None,
                    additional: std::collections::HashMap::new(),
                },
            }
        }

        fn test_claim() -> Claim {
            Claim {
                name: "reviewed".into(),
                value: json!(true),
                confidence: Some(0.95),
                assurance_level: Some(AssuranceLevel::Verified),
                issuer: None,
                issued_at: None,
            }
        }

        #[test]
        fn simple_create_attestation_returns_signed_document() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let result = agent.create_attestation(&subject, &[test_claim()], &[], None, None);
            assert!(
                result.is_ok(),
                "create_attestation should succeed: {:?}",
                result.err()
            );

            let signed = result.unwrap();
            assert!(!signed.raw.is_empty(), "raw JSON should not be empty");
            assert!(!signed.document_id.is_empty(), "document_id should be set");
            assert!(!signed.agent_id.is_empty(), "agent_id should be set");
            assert!(!signed.timestamp.is_empty(), "timestamp should be set");
        }

        #[test]
        fn simple_create_attestation_raw_contains_attestation_fields() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = agent
                .create_attestation(&subject, &[test_claim()], &[], None, None)
                .unwrap();

            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            assert!(
                doc.get("attestation").is_some(),
                "should contain attestation field"
            );
            assert!(doc.get("jacsSignature").is_some(), "should be signed");
            assert_eq!(
                doc["attestation"]["subject"]["id"].as_str().unwrap(),
                "test-artifact-001"
            );
        }

        #[test]
        fn simple_verify_attestation_local_valid() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = agent
                .create_attestation(&subject, &[test_claim()], &[], None, None)
                .unwrap();

            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            let key = format!(
                "{}:{}",
                doc["jacsId"].as_str().unwrap(),
                doc["jacsVersion"].as_str().unwrap()
            );

            let result = agent.verify_attestation(&key);
            assert!(
                result.is_ok(),
                "verify_attestation should succeed: {:?}",
                result.err()
            );

            let verification = result.unwrap();
            assert!(
                verification.valid,
                "attestation should verify: {:?}",
                verification.errors
            );
        }

        #[test]
        fn simple_verify_attestation_full_valid() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = agent
                .create_attestation(&subject, &[test_claim()], &[], None, None)
                .unwrap();

            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            let key = format!(
                "{}:{}",
                doc["jacsId"].as_str().unwrap(),
                doc["jacsVersion"].as_str().unwrap()
            );

            let result = agent.verify_attestation_full(&key);
            assert!(
                result.is_ok(),
                "verify_attestation_full should succeed: {:?}",
                result.err()
            );

            let verification = result.unwrap();
            assert!(
                verification.valid,
                "full attestation should verify: {:?}",
                verification.errors
            );
        }

        #[test]
        fn simple_verify_attestation_returns_signer_info() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = agent
                .create_attestation(&subject, &[test_claim()], &[], None, None)
                .unwrap();

            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            let key = format!(
                "{}:{}",
                doc["jacsId"].as_str().unwrap(),
                doc["jacsVersion"].as_str().unwrap()
            );

            let verification = agent.verify_attestation(&key).unwrap();
            assert!(
                !verification.crypto.signer_id.is_empty(),
                "should include signer info in crypto result"
            );
        }

        #[test]
        fn simple_lift_to_attestation_from_signed_document() {
            let agent = ephemeral_agent();

            // First sign a regular message
            let msg = json!({"title": "Test Document", "content": "Some content"});
            let signed_msg = agent.sign_message(&msg).unwrap();

            // Lift it to an attestation
            let claims = vec![test_claim()];
            let result = agent.lift_to_attestation(&signed_msg.raw, &claims);
            assert!(
                result.is_ok(),
                "lift_to_attestation should succeed: {:?}",
                result.err()
            );

            let attestation = result.unwrap();
            assert!(!attestation.raw.is_empty());
            assert!(!attestation.document_id.is_empty());

            // Verify the lifted attestation
            let att_doc: Value = serde_json::from_str(&attestation.raw).unwrap();
            let att_key = format!(
                "{}:{}",
                att_doc["jacsId"].as_str().unwrap(),
                att_doc["jacsVersion"].as_str().unwrap()
            );

            let verification = agent.verify_attestation(&att_key).unwrap();
            assert!(
                verification.valid,
                "lifted attestation should verify: {:?}",
                verification.errors
            );
        }

        #[test]
        fn simple_lift_to_attestation_subject_references_original() {
            let agent = ephemeral_agent();

            let msg = json!({"title": "Original Document"});
            let signed_msg = agent.sign_message(&msg).unwrap();
            let original_id = signed_msg.document_id.clone();

            let attestation = agent
                .lift_to_attestation(&signed_msg.raw, &[test_claim()])
                .unwrap();

            let att_doc: Value = serde_json::from_str(&attestation.raw).unwrap();
            assert_eq!(
                att_doc["attestation"]["subject"]["id"].as_str().unwrap(),
                original_id,
                "attestation subject ID should reference the original document ID"
            );
        }

        #[test]
        fn simple_lift_unsigned_document_fails() {
            let agent = ephemeral_agent();
            let unsigned = json!({"title": "Not Signed"}).to_string();
            let result = agent.lift_to_attestation(&unsigned, &[test_claim()]);
            assert!(result.is_err(), "lifting unsigned document should fail");
        }

        #[test]
        fn simple_create_attestation_with_evidence() {
            let agent = ephemeral_agent();
            let subject = test_subject();

            let evidence = vec![EvidenceRef {
                kind: EvidenceKind::Custom,
                digests: DigestSet {
                    sha256: "ev_hash_123".into(),
                    sha512: None,
                    additional: std::collections::HashMap::new(),
                },
                uri: Some("https://example.com/evidence.pdf".into()),
                embedded: false,
                embedded_data: None,
                collected_at: crate::time_utils::now_rfc3339(),
                resolved_at: None,
                sensitivity: EvidenceSensitivity::Public,
                verifier: VerifierInfo {
                    name: "test-verifier".into(),
                    version: "1.0".into(),
                },
            }];

            let result = agent.create_attestation(&subject, &[test_claim()], &evidence, None, None);
            assert!(
                result.is_ok(),
                "attestation with evidence should succeed: {:?}",
                result.err()
            );

            let signed = result.unwrap();
            let doc: Value = serde_json::from_str(&signed.raw).unwrap();
            let ev_arr = doc["attestation"]["evidence"]
                .as_array()
                .expect("evidence should be array");
            assert_eq!(ev_arr.len(), 1);
            assert_eq!(ev_arr[0]["kind"], "custom");
        }

        #[test]
        fn simple_verify_attestation_nonexistent_key_returns_error() {
            let agent = ephemeral_agent();
            let result = agent.verify_attestation("nonexistent-id:v1");
            assert!(
                result.is_err(),
                "verifying nonexistent attestation should fail"
            );
        }

        #[test]
        fn simple_export_dsse_produces_valid_envelope() {
            let agent = ephemeral_agent();
            let subject = test_subject();
            let signed = agent
                .create_attestation(&subject, &[test_claim()], &[], None, None)
                .unwrap();

            let dsse_json = agent.export_dsse(&signed.raw).unwrap();
            let envelope: Value = serde_json::from_str(&dsse_json).unwrap();

            assert_eq!(
                envelope["payloadType"].as_str().unwrap(),
                "application/vnd.in-toto+json"
            );
            assert!(envelope.get("payload").is_some());
            assert!(envelope.get("signatures").is_some());

            let sigs = envelope["signatures"].as_array().unwrap();
            assert!(!sigs.is_empty(), "should have at least one signature");
        }
    }
}
