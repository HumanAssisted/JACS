//! # jacs-binding-core
//!
//! Shared core logic for JACS language bindings (Python, Node.js, etc.).
//!
//! This crate provides the binding-agnostic business logic that can be used
//! by any language binding. Each binding implements the `BindingError` trait
//! to convert errors to their native format.

use jacs::agent::document::DocumentTraits;
use jacs::agent::payloads::PayloadTraits;
use jacs::agent::{Agent, AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME};
use jacs::config::Config;
use jacs::crypt::hash::hash_string as jacs_hash_string;
use jacs::crypt::KeyManager;
use serde_json::Value;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

pub mod conversion;

/// Error type for binding core operations.
///
/// This is the internal error type that binding implementations convert
/// to their native error types (PyErr, napi::Error, etc.).
#[derive(Debug)]
pub struct BindingCoreError {
    pub message: String,
    pub kind: ErrorKind,
}

/// Categories of errors for better handling by bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Failed to acquire a mutex lock
    LockFailed,
    /// Agent loading or configuration failed
    AgentLoad,
    /// Validation failed (agent or document)
    Validation,
    /// Signature operation failed
    SigningFailed,
    /// Verification operation failed
    VerificationFailed,
    /// Document operation failed
    DocumentFailed,
    /// Agreement operation failed
    AgreementFailed,
    /// Serialization/deserialization failed
    SerializationFailed,
    /// Invalid argument provided
    InvalidArgument,
    /// Trust store operation failed
    TrustFailed,
    /// Generic failure
    Generic,
}

impl BindingCoreError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind,
        }
    }

    pub fn lock_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::LockFailed, message)
    }

    pub fn agent_load(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::AgentLoad, message)
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Validation, message)
    }

    pub fn signing_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::SigningFailed, message)
    }

    pub fn verification_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::VerificationFailed, message)
    }

    pub fn document_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::DocumentFailed, message)
    }

    pub fn agreement_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::AgreementFailed, message)
    }

    pub fn serialization_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::SerializationFailed, message)
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidArgument, message)
    }

    pub fn trust_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::TrustFailed, message)
    }

    pub fn generic(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Generic, message)
    }
}

impl std::fmt::Display for BindingCoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BindingCoreError {}

impl<T> From<PoisonError<T>> for BindingCoreError {
    fn from(e: PoisonError<T>) -> Self {
        Self::lock_failed(format!("Failed to acquire lock: {}", e))
    }
}

/// Result type for binding core operations.
pub type BindingResult<T> = Result<T, BindingCoreError>;

// =============================================================================
// Wrapper Type for Agent with Arc<Mutex<Agent>>
// =============================================================================

/// Thread-safe wrapper around a JACS Agent.
///
/// This provides the core agent functionality that all bindings share.
/// Bindings wrap this in their own types and convert errors appropriately.
#[derive(Clone)]
pub struct AgentWrapper {
    inner: Arc<Mutex<Agent>>,
}

impl Default for AgentWrapper {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentWrapper {
    /// Create a new empty agent wrapper.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(jacs::get_empty_agent())),
        }
    }

    /// Get a locked reference to the inner agent.
    fn lock(&self) -> BindingResult<MutexGuard<'_, Agent>> {
        self.inner.lock().map_err(BindingCoreError::from)
    }

    /// Load agent configuration from a file path.
    pub fn load(&self, config_path: String) -> BindingResult<String> {
        let mut agent = self.lock()?;
        agent
            .load_by_config(config_path)
            .map_err(|e| BindingCoreError::agent_load(format!("Failed to load agent: {}", e)))?;
        Ok("Agent loaded".to_string())
    }

    /// Sign an external agent's document with this agent's registration signature.
    pub fn sign_agent(
        &self,
        agent_string: &str,
        public_key: Vec<u8>,
        public_key_enc_type: String,
    ) -> BindingResult<String> {
        let mut agent = self.lock()?;

        let mut external_agent: Value = agent
            .validate_agent(agent_string)
            .map_err(|e| BindingCoreError::validation(format!("Agent validation failed: {}", e)))?;

        agent
            .signature_verification_procedure(
                &external_agent,
                None,
                &AGENT_SIGNATURE_FIELDNAME.to_string(),
                public_key,
                Some(public_key_enc_type),
                None,
                None,
            )
            .map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Signature verification failed: {}",
                    e
                ))
            })?;

        let registration_signature = agent
            .signing_procedure(
                &external_agent,
                None,
                &AGENT_REGISTRATION_SIGNATURE_FIELDNAME.to_string(),
            )
            .map_err(|e| {
                BindingCoreError::signing_failed(format!("Signing procedure failed: {}", e))
            })?;

        external_agent[AGENT_REGISTRATION_SIGNATURE_FIELDNAME] = registration_signature;
        Ok(external_agent.to_string())
    }

    /// Verify a signature on arbitrary string data.
    pub fn verify_string(
        &self,
        data: &str,
        signature_base64: &str,
        public_key: Vec<u8>,
        public_key_enc_type: String,
    ) -> BindingResult<bool> {
        let agent = self.lock()?;

        if data.is_empty()
            || signature_base64.is_empty()
            || public_key.is_empty()
            || public_key_enc_type.is_empty()
        {
            return Err(BindingCoreError::invalid_argument(format!(
                "One parameter is empty: data={}, signature_base64={}, public_key_enc_type={}",
                data.is_empty(),
                signature_base64.is_empty(),
                public_key_enc_type
            )));
        }

        agent
            .verify_string(
                &data.to_string(),
                &signature_base64.to_string(),
                public_key,
                Some(public_key_enc_type),
            )
            .map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Signature verification failed: {}",
                    e
                ))
            })?;

        Ok(true)
    }

    /// Sign arbitrary string data with this agent's private key.
    pub fn sign_string(&self, data: &str) -> BindingResult<String> {
        let mut agent = self.lock()?;

        agent
            .sign_string(&data.to_string())
            .map_err(|e| BindingCoreError::signing_failed(format!("Failed to sign string: {}", e)))
    }

    /// Verify this agent's signature and hash.
    pub fn verify_agent(&self, agentfile: Option<String>) -> BindingResult<bool> {
        let mut agent = self.lock()?;

        if let Some(file) = agentfile {
            let loaded_agent = jacs::load_agent(Some(file))
                .map_err(|e| BindingCoreError::agent_load(format!("Failed to load agent: {}", e)))?;
            *agent = loaded_agent;
        }

        agent.verify_self_signature().map_err(|e| {
            BindingCoreError::verification_failed(format!("Failed to verify agent signature: {}", e))
        })?;

        agent.verify_self_hash().map_err(|e| {
            BindingCoreError::verification_failed(format!("Failed to verify agent hash: {}", e))
        })?;

        Ok(true)
    }

    /// Update the agent document with new data.
    pub fn update_agent(&self, new_agent_string: &str) -> BindingResult<String> {
        let mut agent = self.lock()?;

        agent
            .update_self(new_agent_string)
            .map_err(|e| BindingCoreError::agent_load(format!("Failed to update agent: {}", e)))
    }

    /// Verify a document's signature and hash.
    pub fn verify_document(&self, document_string: &str) -> BindingResult<bool> {
        let mut agent = self.lock()?;

        let doc = agent.load_document(document_string).map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to load document: {}", e))
        })?;

        let document_key = doc.getkey();
        let value = doc.getvalue();

        agent.verify_hash(value).map_err(|e| {
            BindingCoreError::verification_failed(format!("Failed to verify document hash: {}", e))
        })?;

        agent
            .verify_external_document_signature(&document_key)
            .map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Failed to verify document signature: {}",
                    e
                ))
            })?;

        Ok(true)
    }

    /// Update an existing document.
    pub fn update_document(
        &self,
        document_key: &str,
        new_document_string: &str,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> BindingResult<String> {
        let mut agent = self.lock()?;

        let doc = agent
            .update_document(document_key, new_document_string, attachments, embed)
            .map_err(|e| {
                BindingCoreError::document_failed(format!("Failed to update document: {}", e))
            })?;

        Ok(doc.to_string())
    }

    /// Verify a document's signature with an optional custom signature field.
    pub fn verify_signature(
        &self,
        document_string: &str,
        signature_field: Option<String>,
    ) -> BindingResult<bool> {
        let mut agent = self.lock()?;

        let doc = agent.load_document(document_string).map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to load document: {}", e))
        })?;

        let document_key = doc.getkey();
        let sig_field_ref = signature_field.as_ref();

        agent
            .verify_document_signature(
                &document_key,
                sig_field_ref.map(|s| s.as_str()),
                None,
                None,
                None,
            )
            .map_err(|e| {
                BindingCoreError::verification_failed(format!("Failed to verify signature: {}", e))
            })?;

        Ok(true)
    }

    /// Create an agreement on a document.
    pub fn create_agreement(
        &self,
        document_string: &str,
        agentids: Vec<String>,
        question: Option<String>,
        context: Option<String>,
        agreement_fieldname: Option<String>,
    ) -> BindingResult<String> {
        let mut agent = self.lock()?;

        jacs::shared::document_add_agreement(
            &mut agent,
            document_string,
            agentids,
            None,
            None,
            question,
            context,
            None,
            None,
            false,
            agreement_fieldname,
        )
        .map_err(|e| {
            BindingCoreError::agreement_failed(format!("Failed to create agreement: {}", e))
        })
    }

    /// Sign an agreement on a document.
    pub fn sign_agreement(
        &self,
        document_string: &str,
        agreement_fieldname: Option<String>,
    ) -> BindingResult<String> {
        let mut agent = self.lock()?;

        jacs::shared::document_sign_agreement(
            &mut agent,
            document_string,
            None,
            None,
            None,
            None,
            false,
            agreement_fieldname,
        )
        .map_err(|e| {
            BindingCoreError::agreement_failed(format!("Failed to sign agreement: {}", e))
        })
    }

    /// Create a new JACS document.
    pub fn create_document(
        &self,
        document_string: &str,
        custom_schema: Option<String>,
        outputfilename: Option<String>,
        no_save: bool,
        attachments: Option<&str>,
        embed: Option<bool>,
    ) -> BindingResult<String> {
        let mut agent = self.lock()?;

        jacs::shared::document_create(
            &mut agent,
            document_string,
            custom_schema,
            outputfilename,
            no_save,
            attachments,
            embed,
        )
        .map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to create document: {}", e))
        })
    }

    /// Check an agreement on a document.
    pub fn check_agreement(
        &self,
        document_string: &str,
        agreement_fieldname: Option<String>,
    ) -> BindingResult<String> {
        let mut agent = self.lock()?;

        jacs::shared::document_check_agreement(&mut agent, document_string, None, agreement_fieldname)
            .map_err(|e| {
                BindingCoreError::agreement_failed(format!("Failed to check agreement: {}", e))
            })
    }

    /// Sign a request payload (wraps in a JACS document).
    pub fn sign_request(&self, payload_value: Value) -> BindingResult<String> {
        let mut agent = self.lock()?;

        let wrapper_value = serde_json::json!({
            "jacs_payload": payload_value
        });

        let wrapper_string = serde_json::to_string(&wrapper_value).map_err(|e| {
            BindingCoreError::serialization_failed(format!("Failed to serialize wrapper JSON: {}", e))
        })?;

        jacs::shared::document_create(
            &mut agent,
            &wrapper_string,
            None,
            None,
            true, // no_save
            None,
            Some(false),
        )
        .map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to create document: {}", e))
        })
    }

    /// Verify a response payload and return the payload value.
    pub fn verify_response(&self, document_string: String) -> BindingResult<Value> {
        let mut agent = self.lock()?;

        agent
            .verify_payload(document_string, None)
            .map_err(|e| BindingCoreError::verification_failed(e.to_string()))
    }

    /// Verify a response payload and return (payload, agent_id).
    pub fn verify_response_with_agent_id(
        &self,
        document_string: String,
    ) -> BindingResult<(Value, String)> {
        let mut agent = self.lock()?;

        agent
            .verify_payload_with_agent_id(document_string, None)
            .map_err(|e| BindingCoreError::verification_failed(e.to_string()))
    }
}

// =============================================================================
// Stateless Utility Functions
// =============================================================================

/// Hash a string using the JACS hash function (SHA-256).
pub fn hash_string(data: &str) -> String {
    jacs_hash_string(&data.to_string())
}

/// Create a JACS configuration JSON string.
pub fn create_config(
    jacs_use_security: Option<String>,
    jacs_data_directory: Option<String>,
    jacs_key_directory: Option<String>,
    jacs_agent_private_key_filename: Option<String>,
    jacs_agent_public_key_filename: Option<String>,
    jacs_agent_key_algorithm: Option<String>,
    jacs_private_key_password: Option<String>,
    jacs_agent_id_and_version: Option<String>,
    jacs_default_storage: Option<String>,
) -> BindingResult<String> {
    let config = Config::new(
        jacs_use_security,
        jacs_data_directory,
        jacs_key_directory,
        jacs_agent_private_key_filename,
        jacs_agent_public_key_filename,
        jacs_agent_key_algorithm,
        jacs_private_key_password,
        jacs_agent_id_and_version,
        jacs_default_storage,
    );

    serde_json::to_string_pretty(&config).map_err(|e| {
        BindingCoreError::serialization_failed(format!("Failed to serialize config: {}", e))
    })
}

// =============================================================================
// Trust Store Functions
// =============================================================================

/// Add an agent to the local trust store.
pub fn trust_agent(agent_json: &str) -> BindingResult<String> {
    jacs::trust::trust_agent(agent_json)
        .map_err(|e| BindingCoreError::trust_failed(format!("Failed to trust agent: {}", e)))
}

/// List all trusted agent IDs.
pub fn list_trusted_agents() -> BindingResult<Vec<String>> {
    jacs::trust::list_trusted_agents()
        .map_err(|e| BindingCoreError::trust_failed(format!("Failed to list trusted agents: {}", e)))
}

/// Remove an agent from the trust store.
pub fn untrust_agent(agent_id: &str) -> BindingResult<()> {
    jacs::trust::untrust_agent(agent_id)
        .map_err(|e| BindingCoreError::trust_failed(format!("Failed to untrust agent: {}", e)))
}

/// Check if an agent is in the trust store.
pub fn is_trusted(agent_id: &str) -> bool {
    jacs::trust::is_trusted(agent_id)
}

/// Get a trusted agent's JSON document.
pub fn get_trusted_agent(agent_id: &str) -> BindingResult<String> {
    jacs::trust::get_trusted_agent(agent_id)
        .map_err(|e| BindingCoreError::trust_failed(format!("Failed to get trusted agent: {}", e)))
}

// =============================================================================
// CLI Utility Functions
// =============================================================================

/// Create agent and config files interactively.
pub fn handle_agent_create(filename: Option<&String>, create_keys: bool) -> BindingResult<()> {
    jacs::cli_utils::create::handle_agent_create(filename, create_keys)
        .map_err(|e| BindingCoreError::generic(e.to_string()))
}

/// Create a jacs.config.json file interactively.
pub fn handle_config_create() -> BindingResult<()> {
    jacs::cli_utils::create::handle_config_create()
        .map_err(|e| BindingCoreError::generic(e.to_string()))
}

// =============================================================================
// Re-exports for convenience
// =============================================================================

pub use jacs;
