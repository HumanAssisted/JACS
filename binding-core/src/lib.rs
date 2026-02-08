//! # jacs-binding-core
//!
//! Shared core logic for JACS language bindings (Python, Node.js, etc.).
//!
//! This crate provides the binding-agnostic business logic that can be used
//! by any language binding. Each binding implements the `BindingError` trait
//! to convert errors to their native format.

use jacs::agent::agreement::Agreement;
use jacs::agent::document::{DocumentTraits, JACSDocument};
use jacs::agent::payloads::PayloadTraits;
use jacs::agent::{
    AGENT_AGREEMENT_FIELDNAME, AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME,
    Agent,
};
use jacs::config::Config;
use jacs::crypt::KeyManager;
use jacs::crypt::hash::hash_string as jacs_hash_string;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

pub mod conversion;

#[cfg(feature = "hai")]
pub mod hai;

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
    /// Network operation failed
    NetworkFailed,
    /// Key not found
    KeyNotFound,
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

    pub fn network_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NetworkFailed, message)
    }

    pub fn key_not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::KeyNotFound, message)
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

fn is_editable_level(level: &str) -> bool {
    matches!(level, "artifact" | "config")
}

fn normalize_agent_id_for_compare(agent_id: &str) -> &str {
    agent_id.split(':').next().unwrap_or(agent_id)
}

fn extract_agreement_payload(value: &Value) -> Value {
    if let Some(payload) = value.get("jacsDocument") {
        return payload.clone();
    }
    if let Some(payload) = value.get("content") {
        return payload.clone();
    }
    if let Some(obj) = value.as_object() {
        let mut filtered = serde_json::Map::new();
        for (k, v) in obj {
            if !k.starts_with("jacs") && k != "$schema" {
                filtered.insert(k.clone(), v.clone());
            }
        }
        if !filtered.is_empty() {
            return Value::Object(filtered);
        }
    }
    Value::Null
}

fn create_editable_agreement_document(agent: &mut Agent, payload: Value) -> BindingResult<JACSDocument> {
    let wrapped = json!({
        "jacsType": "artifact",
        "jacsLevel": "artifact",
        "content": payload
    });
    agent
        .create_document_and_load(&wrapped.to_string(), None, None)
        .map_err(|e| {
            BindingCoreError::document_failed(format!(
                "Failed to create editable agreement document: {}",
                e
            ))
        })
}

fn ensure_editable_agreement_document(
    agent: &mut Agent,
    document_string: &str,
) -> BindingResult<JACSDocument> {
    match agent.load_document(document_string) {
        Ok(doc) => {
            let level = doc.value.get("jacsLevel").and_then(|v| v.as_str()).unwrap_or("");
            if is_editable_level(level) {
                Ok(doc)
            } else {
                let payload = extract_agreement_payload(doc.getvalue());
                create_editable_agreement_document(agent, payload)
            }
        }
        Err(load_err) => {
            if let Ok(parsed) = serde_json::from_str::<Value>(document_string)
                && (parsed.get("jacsId").is_some() || parsed.get("jacsVersion").is_some())
            {
                return Err(BindingCoreError::document_failed(format!(
                    "Failed to load document: {}",
                    load_err
                )));
            }
            let payload = serde_json::from_str::<Value>(document_string)
                .unwrap_or_else(|_| Value::String(document_string.to_string()));
            create_editable_agreement_document(agent, payload)
        }
    }
}

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
            let loaded_agent = jacs::load_agent(Some(file)).map_err(|e| {
                BindingCoreError::agent_load(format!("Failed to load agent: {}", e))
            })?;
            *agent = loaded_agent;
        }

        agent.verify_self_signature().map_err(|e| {
            BindingCoreError::verification_failed(format!(
                "Failed to verify agent signature: {}",
                e
            ))
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
        let base_doc = ensure_editable_agreement_document(&mut agent, document_string)?;
        let document_key = base_doc.getkey();
        let agreement_doc = agent
            .create_agreement(
                &document_key,
                agentids.as_slice(),
                question.as_deref(),
                context.as_deref(),
                agreement_fieldname,
            )
            .map_err(|e| {
                BindingCoreError::agreement_failed(format!("Failed to create agreement: {}", e))
            })?;

        Ok(agreement_doc.value.to_string())
    }

    /// Sign an agreement on a document.
    pub fn sign_agreement(
        &self,
        document_string: &str,
        agreement_fieldname: Option<String>,
    ) -> BindingResult<String> {
        let mut agent = self.lock()?;
        let doc = agent.load_document(document_string).map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to load document: {}", e))
        })?;
        let document_key = doc.getkey();
        let signed_doc = agent
            .sign_agreement(&document_key, agreement_fieldname)
            .map_err(|e| {
                BindingCoreError::agreement_failed(format!("Failed to sign agreement: {}", e))
            })?;

        Ok(signed_doc.value.to_string())
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
        .map_err(|e| BindingCoreError::document_failed(format!("Failed to create document: {}", e)))
    }

    /// Check an agreement on a document.
    pub fn check_agreement(
        &self,
        document_string: &str,
        agreement_fieldname: Option<String>,
    ) -> BindingResult<String> {
        let mut agent = self.lock()?;
        let doc = agent.load_document(document_string).map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to load document: {}", e))
        })?;
        let document_key = doc.getkey();
        let agreement_fieldname_key = agreement_fieldname
            .clone()
            .unwrap_or_else(|| AGENT_AGREEMENT_FIELDNAME.to_string());

        agent
            .check_agreement(&document_key, Some(agreement_fieldname_key.clone()))
            .map_err(|e| {
                BindingCoreError::agreement_failed(format!("Failed to check agreement: {}", e))
            })?;

        let requested = doc
            .agreement_requested_agents(Some(agreement_fieldname_key.clone()))
            .map_err(|e| {
                BindingCoreError::agreement_failed(format!(
                    "Failed to read requested signers: {}",
                    e
                ))
            })?;

        let pending = doc
            .agreement_unsigned_agents(Some(agreement_fieldname_key.clone()))
            .map_err(|e| {
                BindingCoreError::agreement_failed(format!(
                    "Failed to read pending signers: {}",
                    e
                ))
            })?;

        let signatures = doc
            .value
            .get(&agreement_fieldname_key)
            .and_then(|agreement| agreement.get("signatures"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut signed_at_by_agent: HashMap<String, String> = HashMap::new();
        for signature in signatures {
            if let Some(agent_id) = signature.get("agentID").and_then(|v| v.as_str()) {
                let normalized = normalize_agent_id_for_compare(agent_id).to_string();
                let signed_at = signature
                    .get("date")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                signed_at_by_agent.insert(normalized, signed_at);
            }
        }

        let signers = requested
            .iter()
            .map(|agent_id| {
                let normalized = normalize_agent_id_for_compare(agent_id).to_string();
                let signed_at = signed_at_by_agent
                    .get(&normalized)
                    .filter(|ts| !ts.is_empty())
                    .cloned();
                let signed = signed_at.is_some();
                let mut signer = json!({
                    "agentId": agent_id,
                    "agent_id": agent_id,
                    "signed": signed
                });
                if let Some(ts) = signed_at {
                    signer["signedAt"] = json!(ts.clone());
                    signer["signed_at"] = json!(ts);
                }
                signer
            })
            .collect::<Vec<Value>>();

        let result = json!({
            "complete": pending.is_empty(),
            "signers": signers,
            "pending": pending
        });

        Ok(result.to_string())
    }

    /// Sign a request payload (wraps in a JACS document).
    pub fn sign_request(&self, payload_value: Value) -> BindingResult<String> {
        let mut agent = self.lock()?;

        let wrapper_value = serde_json::json!({
            "jacs_payload": payload_value
        });

        let wrapper_string = serde_json::to_string(&wrapper_value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize wrapper JSON: {}",
                e
            ))
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
        .map_err(|e| BindingCoreError::document_failed(format!("Failed to create document: {}", e)))
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

    /// Verify a document looked up by its ID from storage.
    ///
    /// This is a convenience method for when you have a document ID rather than
    /// the full JSON string. The document ID should be in "uuid:version" format.
    pub fn verify_document_by_id(&self, document_id: &str) -> BindingResult<bool> {
        use jacs::storage::StorageDocumentTraits;

        // Validate format
        if !document_id.contains(':') {
            return Err(BindingCoreError::invalid_argument(format!(
                "Document ID must be in 'uuid:version' format, got '{}'. \
                Use verify_document() with the full JSON string instead.",
                document_id
            )));
        }

        let storage = jacs::storage::MultiStorage::default_new().map_err(|e| {
            BindingCoreError::generic(format!("Failed to initialize storage: {}", e))
        })?;

        let doc = storage.get_document(document_id).map_err(|e| {
            BindingCoreError::document_failed(format!(
                "Failed to load document '{}' from storage: {}",
                document_id, e
            ))
        })?;

        let doc_str = serde_json::to_string(&doc.value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize document '{}': {}",
                document_id, e
            ))
        })?;

        self.verify_document(&doc_str)
    }

    /// Re-encrypt the agent's private key with a new password.
    ///
    /// Reads the encrypted private key file, decrypts with old_password,
    /// validates new_password, re-encrypts, and writes the updated file.
    pub fn reencrypt_key(&self, old_password: &str, new_password: &str) -> BindingResult<()> {
        use jacs::crypt::aes_encrypt::reencrypt_private_key;

        // Find key path from config
        let agent = self.lock()?;
        let key_path = if let Some(config) = &agent.config {
            let key_dir = config
                .jacs_key_directory()
                .as_deref()
                .unwrap_or("./jacs_keys");
            let key_file = config
                .jacs_agent_private_key_filename()
                .as_deref()
                .unwrap_or("jacs.private.pem.enc");
            format!("{}/{}", key_dir, key_file)
        } else {
            "./jacs_keys/jacs.private.pem.enc".to_string()
        };
        drop(agent);

        let encrypted_data = std::fs::read(&key_path).map_err(|e| {
            BindingCoreError::generic(format!(
                "Failed to read private key file '{}': {}",
                key_path, e
            ))
        })?;

        let re_encrypted = reencrypt_private_key(&encrypted_data, old_password, new_password)
            .map_err(|e| BindingCoreError::generic(format!("Re-encryption failed: {}", e)))?;

        std::fs::write(&key_path, &re_encrypted).map_err(|e| {
            BindingCoreError::generic(format!(
                "Failed to write re-encrypted key to '{}': {}",
                key_path, e
            ))
        })?;

        Ok(())
    }

    /// Get the agent's JSON representation as a string.
    ///
    /// Returns the agent's full JSON document, suitable for registration
    /// with external services like HAI.
    pub fn get_agent_json(&self) -> BindingResult<String> {
        let agent = self.lock()?;
        match agent.get_value() {
            Some(value) => Ok(value.to_string()),
            None => Err(BindingCoreError::agent_load(
                "Agent not loaded. Call load() first.",
            )),
        }
    }
}

// =============================================================================
// Standalone verification (no agent required)
// =============================================================================

/// Result of verifying a signed JACS document (used by verify_document_standalone).
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the document's signature and hash are valid.
    pub valid: bool,
    /// The signer's agent ID from the document's jacsSignature.agentID (empty if unparseable).
    pub signer_id: String,
}

/// Verify a signed JACS document without loading an agent.
///
/// Creates a minimal verifier context (config with data/key directories and optional
/// key resolution), runs verification, and returns a result with valid flag and signer_id.
/// Does not persist any state.
///
/// # Arguments
///
/// * `signed_document` - Full signed JACS document JSON string.
/// * `key_resolution` - Optional key resolution order, e.g. "local" or "local,hai" (default "local").
/// * `data_directory` - Optional path for data/trust store (defaults to temp/cwd).
/// * `key_directory` - Optional path for public keys (defaults to temp/cwd).
///
/// # Returns
///
/// * `Ok(VerificationResult { valid: true, signer_id })` when signature and hash are valid.
/// * `Ok(VerificationResult { valid: false, signer_id })` when document parses but verification fails.
/// * `Err` when setup fails (e.g. missing key directory when using local resolution).
pub fn verify_document_standalone(
    signed_document: &str,
    key_resolution: Option<&str>,
    data_directory: Option<&str>,
    key_directory: Option<&str>,
) -> BindingResult<VerificationResult> {
    fn signer_id_from_doc(doc: &str) -> String {
        serde_json::from_str::<Value>(doc)
            .ok()
            .and_then(|v| {
                v.get("jacsSignature")
                    .and_then(|s| s.get("agentID"))
                    .and_then(|id| id.as_str())
                    .map(String::from)
            })
            .unwrap_or_default()
    }

    let signer_id = signer_id_from_doc(signed_document);

    let data_dir = data_directory
        .map(String::from)
        .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().to_string());
    let key_dir = key_directory
        .map(String::from)
        .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().to_string());

    let config = Config::new(
        Some("false".to_string()),
        Some(data_dir.clone()),
        Some(key_dir.clone()),
        Some("jacs.private.pem.enc".to_string()),
        Some("jacs.public.pem".to_string()),
        Some("pq2025".to_string()),
        None,
        Some("".to_string()),
        Some("fs".to_string()),
    );
    let config_json = serde_json::to_string_pretty(&config).map_err(|e| {
        BindingCoreError::serialization_failed(format!("Failed to serialize config: {}", e))
    })?;

    let config_path = std::env::temp_dir().join("jacs_standalone_verify_config.json");
    std::fs::write(&config_path, &config_json)
        .map_err(|e| BindingCoreError::generic(format!("Failed to write temp config: {}", e)))?;

    struct EnvGuard(std::option::Option<std::ffi::OsString>);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(ref prev) = self.0 {
                // SAFETY: single-threaded test/standalone use; restore of previous value
                unsafe { std::env::set_var("JACS_KEY_RESOLUTION", prev) }
            } else {
                unsafe { std::env::remove_var("JACS_KEY_RESOLUTION") }
            }
        }
    }
    let _env_guard = if let Some(kr) = key_resolution {
        let prev = std::env::var_os("JACS_KEY_RESOLUTION");
        unsafe { std::env::set_var("JACS_KEY_RESOLUTION", kr) }
        Some(EnvGuard(prev))
    } else {
        None
    };

    let result: BindingResult<VerificationResult> = (|| {
        let wrapper = AgentWrapper::new();
        wrapper.load(config_path.to_string_lossy().to_string())?;
        let valid = wrapper.verify_document(signed_document)?;
        Ok(VerificationResult {
            valid,
            signer_id: signer_id.clone(),
        })
    })();

    match result {
        Ok(r) => Ok(r),
        Err(e) => {
            if e.kind == ErrorKind::VerificationFailed
                || e.kind == ErrorKind::DocumentFailed
                || e.kind == ErrorKind::InvalidArgument
            {
                Ok(VerificationResult {
                    valid: false,
                    signer_id,
                })
            } else {
                Err(e)
            }
        }
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
    jacs::trust::list_trusted_agents().map_err(|e| {
        BindingCoreError::trust_failed(format!("Failed to list trusted agents: {}", e))
    })
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
// Audit (security audit and health checks)
// =============================================================================

/// Run a read-only security audit and health checks.
///
/// Returns the audit result as a JSON string (risks, health_checks, summary).
/// Does not modify state. Optional config path and recent document re-verification count.
pub fn audit(config_path: Option<&str>, recent_n: Option<u32>) -> BindingResult<String> {
    use jacs::audit::{AuditOptions, audit as jacs_audit};

    let mut opts = AuditOptions::default();
    opts.config_path = config_path.map(String::from);
    if let Some(n) = recent_n {
        opts.recent_verify_count = Some(n);
    }
    let result =
        jacs_audit(opts).map_err(|e| BindingCoreError::generic(format!("Audit failed: {}", e)))?;
    serde_json::to_string_pretty(&result).map_err(|e| {
        BindingCoreError::serialization_failed(format!("Failed to serialize audit result: {}", e))
    })
}

// =============================================================================
// CLI Utility Functions
// =============================================================================

/// Create a JACS agent programmatically (non-interactive).
///
/// Accepts all creation parameters and returns a JSON string containing agent info.
pub fn create_agent_programmatic(
    name: &str,
    password: &str,
    algorithm: Option<&str>,
    data_directory: Option<&str>,
    key_directory: Option<&str>,
    config_path: Option<&str>,
    agent_type: Option<&str>,
    description: Option<&str>,
    domain: Option<&str>,
    default_storage: Option<&str>,
) -> BindingResult<String> {
    use jacs::simple::{CreateAgentParams, SimpleAgent};

    let params = CreateAgentParams {
        name: name.to_string(),
        password: password.to_string(),
        algorithm: algorithm.unwrap_or("pq2025").to_string(),
        data_directory: data_directory.unwrap_or("./jacs_data").to_string(),
        key_directory: key_directory.unwrap_or("./jacs_keys").to_string(),
        config_path: config_path.unwrap_or("./jacs.config.json").to_string(),
        agent_type: agent_type.unwrap_or("ai").to_string(),
        description: description.unwrap_or("").to_string(),
        domain: domain.unwrap_or("").to_string(),
        default_storage: default_storage.unwrap_or("fs").to_string(),
        hai_api_key: String::new(),
        hai_endpoint: String::new(),
    };

    let (_agent, info) = SimpleAgent::create_with_params(params)
        .map_err(|e| BindingCoreError::agent_load(format!("Failed to create agent: {}", e)))?;

    serde_json::to_string_pretty(&info).map_err(|e| {
        BindingCoreError::serialization_failed(format!("Failed to serialize agent info: {}", e))
    })
}

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
// Remote Key Fetch Functions
// =============================================================================

/// Information about a public key fetched from HAI key service.
///
/// This struct contains the public key data and metadata returned by
/// the HAI key distribution service.
#[derive(Debug, Clone)]
pub struct RemotePublicKeyInfo {
    /// The raw public key bytes (DER encoded).
    pub public_key: Vec<u8>,
    /// The cryptographic algorithm (e.g., "ed25519", "rsa-pss-sha256").
    pub algorithm: String,
    /// The hash of the public key (SHA-256).
    pub public_key_hash: String,
    /// The agent ID the key belongs to.
    pub agent_id: String,
    /// The version of the key.
    pub version: String,
}

/// Fetch a public key from HAI's key distribution service.
///
/// This function retrieves the public key for a specific agent and version
/// from the HAI key distribution service. It is used to obtain trusted public
/// keys for verifying agent signatures without requiring local key storage.
///
/// # Arguments
///
/// * `agent_id` - The unique identifier of the agent whose key to fetch.
/// * `version` - The version of the agent's key to fetch. Use "latest" for
///   the most recent version.
///
/// # Returns
///
/// Returns `Ok(RemotePublicKeyInfo)` containing the public key, algorithm, and hash
/// on success.
///
/// # Errors
///
/// * `ErrorKind::KeyNotFound` - The agent or key version was not found (404).
/// * `ErrorKind::NetworkFailed` - Connection, timeout, or other HTTP errors.
/// * `ErrorKind::Generic` - The returned key has invalid encoding.
///
/// # Environment Variables
///
/// * `HAI_KEYS_BASE_URL` - Base URL for the key service. Defaults to `https://keys.hai.ai`.
/// * `JACS_KEY_RESOLUTION` - Controls key resolution order. Options:
///   - "hai-only" - Only use HAI key service (default when set)
///   - "local-first" - Try local trust store, fall back to HAI
///   - "hai-first" - Try HAI first, fall back to local trust store
///
/// # Example
///
/// ```rust,ignore
/// use jacs_binding_core::fetch_remote_key;
///
/// let key_info = fetch_remote_key(
///     "550e8400-e29b-41d4-a716-446655440000",
///     "latest"
/// )?;
///
/// println!("Algorithm: {}", key_info.algorithm);
/// println!("Hash: {}", key_info.public_key_hash);
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn fetch_remote_key(agent_id: &str, version: &str) -> BindingResult<RemotePublicKeyInfo> {
    use jacs::agent::loaders::fetch_public_key_from_hai;

    let key_info = fetch_public_key_from_hai(agent_id, version).map_err(|e| {
        // Map JacsError to appropriate BindingCoreError
        let error_str = e.to_string();
        if error_str.contains("not found") || error_str.contains("404") {
            BindingCoreError::key_not_found(format!(
                "Public key not found for agent '{}' version '{}': {}",
                agent_id, version, e
            ))
        } else if error_str.contains("network")
            || error_str.contains("connect")
            || error_str.contains("timeout")
        {
            BindingCoreError::network_failed(format!("Failed to fetch public key from HAI: {}", e))
        } else {
            BindingCoreError::generic(format!("Failed to fetch public key: {}", e))
        }
    })?;

    Ok(RemotePublicKeyInfo {
        public_key: key_info.public_key,
        algorithm: key_info.algorithm,
        public_key_hash: key_info.hash,
        agent_id: agent_id.to_string(),
        version: version.to_string(),
    })
}

// =============================================================================
// Re-exports for convenience
// =============================================================================

pub use jacs;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_standalone_invalid_json_returns_valid_false() {
        let result = verify_document_standalone("not json", Some("local"), None, None).unwrap();
        assert!(!result.valid);
        assert_eq!(result.signer_id, "");
    }

    #[test]
    fn verify_standalone_tampered_document_returns_valid_false_with_signer_id() {
        let tampered = r#"{"jacsSignature":{"agentID":"golden-test-agent","agentVersion":"v1"},"jacsSha256":"x"}"#;
        let result = verify_document_standalone(tampered, Some("local"), None, None).unwrap();
        assert!(!result.valid);
        assert_eq!(result.signer_id, "golden-test-agent");
    }

    #[test]
    fn verify_standalone_golden_invalid_signature_returns_valid_false() {
        let invalid_sig =
            std::fs::read_to_string("../jacs/tests/fixtures/golden/invalid_signature.json")
                .unwrap_or_else(|_| {
                    r#"{"jacsSignature":{"agentID":"golden-test-agent"},"jacsSha256":"x"}"#
                        .to_string()
                });
        let result = verify_document_standalone(
            &invalid_sig,
            Some("local"),
            Some("../jacs/tests/fixtures"),
            Some("../jacs/tests/fixtures/keys"),
        )
        .unwrap();
        assert!(!result.valid);
        assert_eq!(result.signer_id, "golden-test-agent");
    }

    #[test]
    fn verify_standalone_nonexistent_key_directory_returns_valid_false() {
        let doc = r#"{"jacsSignature":{"agentID":"some-agent"},"jacsSha256":"x"}"#;
        let result = verify_document_standalone(
            doc,
            Some("local"),
            Some("/nonexistent_data"),
            Some("/nonexistent_keys"),
        )
        .unwrap();
        assert!(!result.valid);
        assert_eq!(result.signer_id, "some-agent");
    }

    #[test]
    fn audit_default_returns_ok_json_has_risks_and_health_checks() {
        let json = audit(None, None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("risks").is_some(), "audit JSON should have risks");
        assert!(
            v.get("health_checks").is_some(),
            "audit JSON should have health_checks"
        );
    }
}
