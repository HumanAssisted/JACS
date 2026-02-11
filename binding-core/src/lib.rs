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

    /// Re-root the internal file storage at `root`.
    ///
    /// By default `load_by_config` roots the FS backend at the current
    /// working directory.  `verify_document_standalone` uses this to
    /// re-root at `/` so that absolute data/key directory paths work
    /// regardless of CWD.
    pub fn set_storage_root(&self, root: std::path::PathBuf) -> BindingResult<()> {
        let mut agent = self.lock()?;
        agent
            .set_storage_root(root)
            .map_err(|e| BindingCoreError::generic(format!("Failed to set storage root: {}", e)))?;
        Ok(())
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

    /// Sign multiple messages in a single batch, decrypting the private key only once.
    pub fn sign_batch(&self, messages: Vec<String>) -> BindingResult<Vec<String>> {
        let mut agent = self.lock()?;
        let refs: Vec<&str> = messages.iter().map(|s| s.as_str()).collect();
        agent
            .sign_batch(&refs)
            .map_err(|e| BindingCoreError::signing_failed(format!("Batch sign failed: {}", e)))
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
        self.create_agreement_with_options(
            document_string,
            agentids,
            question,
            context,
            agreement_fieldname,
            None,
            None,
            None,
            None,
        )
    }

    /// Create an agreement with extended options (timeout, quorum, algorithm constraints).
    ///
    /// All option parameters are optional:
    /// - `timeout`: ISO 8601 deadline after which the agreement expires
    /// - `quorum`: minimum number of signatures required (M-of-N)
    /// - `required_algorithms`: only accept signatures from these algorithms
    /// - `minimum_strength`: "classical" or "post-quantum"
    pub fn create_agreement_with_options(
        &self,
        document_string: &str,
        agentids: Vec<String>,
        question: Option<String>,
        context: Option<String>,
        agreement_fieldname: Option<String>,
        timeout: Option<String>,
        quorum: Option<u32>,
        required_algorithms: Option<Vec<String>>,
        minimum_strength: Option<String>,
    ) -> BindingResult<String> {
        use jacs::agent::agreement::{Agreement, AgreementOptions};

        let mut agent = self.lock()?;
        let base_doc = ensure_editable_agreement_document(&mut agent, document_string)?;
        let document_key = base_doc.getkey();

        let options = AgreementOptions {
            timeout,
            quorum,
            required_algorithms,
            minimum_strength,
        };

        let agreement_doc = agent
            .create_agreement_with_options(
                &document_key,
                agentids.as_slice(),
                question.as_deref(),
                context.as_deref(),
                agreement_fieldname,
                &options,
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

    /// Create an ephemeral in-memory agent. No config, no files, no env vars needed.
    ///
    /// Replaces the inner agent with a freshly created ephemeral agent that
    /// lives entirely in memory. Returns a JSON string with agent info
    /// (agent_id, name, version, algorithm).
    pub fn ephemeral(&self, algorithm: Option<&str>) -> BindingResult<String> {
        // Map user-friendly names to internal algorithm strings
        let algo = match algorithm.unwrap_or("ed25519") {
            "ed25519" => "ring-Ed25519",
            "rsa-pss" => "RSA-PSS",
            "pq2025" => "pq2025",
            other => other,
        };

        let mut agent = Agent::ephemeral(algo).map_err(|e| {
            BindingCoreError::agent_load(format!("Failed to create ephemeral agent: {}", e))
        })?;

        let template = jacs::create_minimal_blank_agent("ai".to_string(), None, None, None)
            .map_err(|e| {
                BindingCoreError::agent_load(format!(
                    "Failed to create minimal agent template: {}",
                    e
                ))
            })?;
        let mut agent_json: Value = serde_json::from_str(&template).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to parse agent template JSON: {}",
                e
            ))
        })?;
        if let Some(obj) = agent_json.as_object_mut() {
            obj.insert("name".to_string(), json!("ephemeral"));
            obj.insert(
                "description".to_string(),
                json!("Ephemeral JACS agent"),
            );
        }

        let instance = agent
            .create_agent_and_load(&agent_json.to_string(), true, Some(algo))
            .map_err(|e| {
                BindingCoreError::agent_load(format!(
                    "Failed to initialize ephemeral agent: {}",
                    e
                ))
            })?;

        let agent_id = instance["jacsId"].as_str().unwrap_or("").to_string();
        let version = instance["jacsVersion"].as_str().unwrap_or("").to_string();

        // Replace the inner agent with the ephemeral one
        let mut inner = self.lock()?;
        *inner = agent;

        let info = json!({
            "agent_id": agent_id,
            "name": "ephemeral",
            "version": version,
            "algorithm": algo,
        });

        serde_json::to_string_pretty(&info).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize ephemeral agent info: {}",
                e
            ))
        })
    }

    /// Returns diagnostic information including loaded agent details as a JSON string.
    pub fn diagnostics(&self) -> String {
        let mut info = jacs::simple::diagnostics();

        if let Ok(agent) = self.inner.lock() {
            if agent.ready() {
                info["agent_loaded"] = json!(true);
                if let Some(value) = agent.get_value() {
                    info["agent_id"] =
                        json!(value.get("jacsId").and_then(|v| v.as_str()));
                    info["agent_version"] =
                        json!(value.get("jacsVersion").and_then(|v| v.as_str()));
                }
            }
            if let Some(config) = &agent.config {
                if let Some(dir) = config.jacs_data_directory().as_ref() {
                    info["data_directory"] = json!(dir);
                }
                if let Some(dir) = config.jacs_key_directory().as_ref() {
                    info["key_directory"] = json!(dir);
                }
                if let Some(storage) = config.jacs_default_storage().as_ref() {
                    info["default_storage"] = json!(storage);
                }
                if let Some(algo) = config.jacs_agent_key_algorithm().as_ref() {
                    info["key_algorithm"] = json!(algo);
                }
            }
        }

        serde_json::to_string_pretty(&info).unwrap_or_default()
    }

    /// Returns setup instructions for publishing DNS records, enabling DNSSEC,
    /// and registering with HAI.ai.
    ///
    /// Requires a loaded agent (call `load()` first).
    pub fn get_setup_instructions(
        &self,
        domain: &str,
        ttl: u32,
    ) -> BindingResult<String> {
        use jacs::agent::boilerplate::BoilerPlate;
        use jacs::dns::bootstrap::{
            DigestEncoding, build_dns_record, dnssec_guidance, emit_azure_cli,
            emit_cloudflare_curl, emit_gcloud_dns, emit_plain_bind,
            emit_route53_change_batch, tld_requirement_text,
        };

        let agent = self.lock()?;
        let agent_value = agent.get_value().cloned().unwrap_or(json!({}));
        let agent_id = agent_value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if agent_id.is_empty() {
            return Err(BindingCoreError::agent_load(
                "Agent not loaded or has no jacsId. Call load() first.",
            ));
        }

        let pk = agent.get_public_key().map_err(|e| {
            BindingCoreError::generic(format!("Failed to get public key: {}", e))
        })?;
        let digest = jacs::dns::bootstrap::pubkey_digest_b64(&pk);
        let rr = build_dns_record(domain, ttl, agent_id, &digest, DigestEncoding::Base64);

        let dns_record_bind = emit_plain_bind(&rr);
        let dns_owner = rr.owner.clone();
        let dns_record_value = rr.txt.clone();

        let mut provider_commands = std::collections::HashMap::new();
        provider_commands.insert("bind".to_string(), dns_record_bind.clone());
        provider_commands.insert("route53".to_string(), emit_route53_change_batch(&rr));
        provider_commands.insert("gcloud".to_string(), emit_gcloud_dns(&rr, "YOUR_ZONE_NAME"));
        provider_commands.insert("azure".to_string(), emit_azure_cli(&rr, "YOUR_RG", domain, "_v1.agent.jacs"));
        provider_commands.insert("cloudflare".to_string(), emit_cloudflare_curl(&rr, "YOUR_ZONE_ID"));

        let mut dnssec_instructions = std::collections::HashMap::new();
        for name in &["aws", "cloudflare", "azure", "gcloud"] {
            dnssec_instructions.insert(name.to_string(), dnssec_guidance(name).to_string());
        }

        let tld_requirement = tld_requirement_text().to_string();

        let well_known = json!({
            "jacs_agent_id": agent_id,
            "jacs_public_key_hash": digest,
            "jacs_dns_record": dns_owner,
        });
        let well_known_json = serde_json::to_string_pretty(&well_known).unwrap_or_default();

        let hai_url = std::env::var("HAI_API_URL")
            .unwrap_or_else(|_| "https://api.hai.ai".to_string());
        let hai_registration_url = format!("{}/v1/agents", hai_url.trim_end_matches('/'));
        let hai_payload = json!({
            "agent_id": agent_id,
            "public_key_hash": digest,
            "domain": domain,
        });
        let hai_registration_payload = serde_json::to_string_pretty(&hai_payload).unwrap_or_default();
        let hai_registration_instructions = format!(
            "POST the payload to {} with your HAI API key in the Authorization header.",
            hai_registration_url
        );

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
             4. .well-known: Serve the well-known JSON at /.well-known/jacs-agent.json\n\
             \n\
             5. HAI registration: {hai_instr}",
            agent_id = agent_id,
            domain = domain,
            bind = dns_record_bind,
            dnssec = dnssec_guidance("aws"),
            tld = tld_requirement,
            hai_instr = hai_registration_instructions,
        );

        let result = json!({
            "dns_record_bind": dns_record_bind,
            "dns_record_value": dns_record_value,
            "dns_owner": dns_owner,
            "provider_commands": provider_commands,
            "dnssec_instructions": dnssec_instructions,
            "tld_requirement": tld_requirement,
            "well_known_json": well_known_json,
            "hai_registration_url": hai_registration_url,
            "hai_registration_payload": hai_registration_payload,
            "hai_registration_instructions": hai_registration_instructions,
            "summary": summary,
        });

        serde_json::to_string_pretty(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize setup instructions: {}", e
            ))
        })
    }

    /// Register this agent with HAI.ai.
    ///
    /// If `preview` is true, returns a preview without actually registering.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn register_with_hai(
        &self,
        api_key: Option<&str>,
        hai_url: &str,
        preview: bool,
    ) -> BindingResult<String> {
        if preview {
            let result = json!({
                "hai_registered": false,
                "hai_error": "preview mode",
                "dns_record": "",
                "dns_route53": "",
            });
            return serde_json::to_string_pretty(&result).map_err(|e| {
                BindingCoreError::serialization_failed(format!("Failed to serialize: {}", e))
            });
        }

        let key = match api_key {
            Some(k) => k.to_string(),
            None => std::env::var("HAI_API_KEY").map_err(|_| {
                BindingCoreError::invalid_argument(
                    "No API key provided and HAI_API_KEY environment variable not set",
                )
            })?,
        };

        let agent_json = self.get_agent_json()?;
        let url = format!("{}/api/v1/agents/register", hai_url.trim_end_matches('/'));

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| BindingCoreError::network_failed(format!("Failed to build HTTP client: {}", e)))?;

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", key))
            .header("Content-Type", "application/json")
            .json(&json!({ "agent_json": agent_json }))
            .send()
            .map_err(|e| BindingCoreError::network_failed(format!("HAI registration request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            let result = json!({
                "hai_registered": false,
                "hai_error": format!("HTTP {}: {}", status, body),
                "dns_record": "",
                "dns_route53": "",
            });
            return serde_json::to_string_pretty(&result).map_err(|e| {
                BindingCoreError::serialization_failed(format!("Failed to serialize: {}", e))
            });
        }

        let body: Value = response.json().map_err(|e| {
            BindingCoreError::network_failed(format!("Failed to parse HAI response: {}", e))
        })?;

        let result = json!({
            "hai_registered": true,
            "hai_error": "",
            "dns_record": body.get("dns_record").and_then(|v| v.as_str()).unwrap_or_default(),
            "dns_route53": body.get("dns_route53").and_then(|v| v.as_str()).unwrap_or_default(),
        });

        serde_json::to_string_pretty(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!("Failed to serialize: {}", e))
        })
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
// Standalone diagnostics (no agent required)
// =============================================================================

/// Returns basic JACS diagnostic info as a pretty-printed JSON string.
/// Does not require a loaded agent.
pub fn diagnostics_standalone() -> String {
    serde_json::to_string_pretty(&jacs::simple::diagnostics()).unwrap_or_default()
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
    /// The signing timestamp from jacsSignature.date (empty if unparseable).
    pub timestamp: String,
    /// The signer's agent version from jacsSignature.agentVersion (empty if unparseable).
    pub agent_version: String,
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
    fn absolutize_dir(raw: &str) -> String {
        let p = std::path::PathBuf::from(raw);
        if p.is_absolute() {
            p.to_string_lossy().to_string()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join(p)
                .to_string_lossy()
                .to_string()
        }
    }

    fn sig_field(doc: &str, field: &str) -> String {
        serde_json::from_str::<Value>(doc)
            .ok()
            .and_then(|v| {
                v.get("jacsSignature")
                    .and_then(|s| s.get(field))
                    .and_then(|f| f.as_str())
                    .map(String::from)
            })
            .unwrap_or_default()
    }

    let signer_id = sig_field(signed_document, "agentID");
    let timestamp = sig_field(signed_document, "date");
    let agent_version = sig_field(signed_document, "agentVersion");

    // Always resolve caller-provided directories to absolute paths so relative
    // inputs like "../fixtures" work regardless of process CWD.
    let temp_dir = std::env::temp_dir().to_string_lossy().to_string();
    let raw_data_dir = data_directory
        .map(String::from)
        .unwrap_or_else(|| temp_dir.clone());
    let raw_key_dir = key_directory
        .map(String::from)
        .unwrap_or_else(|| raw_data_dir.clone());

    let absolute_data_dir = absolutize_dir(&raw_data_dir);
    let absolute_key_dir = absolutize_dir(&raw_key_dir);

    // Verification loads public keys from {data_directory}/public_keys.
    // If only key_directory is supplied, use it as the storage root fallback.
    let storage_root = if data_directory.is_some() {
        absolute_data_dir.clone()
    } else if key_directory.is_some() {
        absolute_key_dir.clone()
    } else {
        absolute_data_dir.clone()
    };

    // Re-root storage and keep config dirs empty so path construction remains
    // relative to storage_root (e.g., "public_keys/<hash>.pem").
    let data_dir = String::new();
    let key_dir = String::new();

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

    let thread_id = format!("{:?}", std::thread::current().id())
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let config_path = std::env::temp_dir().join(format!(
        "jacs_standalone_verify_config_{}_{}_{}.json",
        std::process::id(),
        thread_id,
        nonce
    ));
    std::fs::write(&config_path, &config_json)
        .map_err(|e| BindingCoreError::generic(format!("Failed to write temp config: {}", e)))?;

    struct EnvGuard {
        saved: Vec<(&'static str, std::option::Option<std::ffi::OsString>)>,
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, prev) in &self.saved {
                if let Some(val) = prev {
                    // SAFETY: test/standalone path restores process env to prior values.
                    unsafe { std::env::set_var(key, val) }
                } else {
                    // SAFETY: removing a missing key is a no-op.
                    unsafe { std::env::remove_var(key) }
                }
            }
        }
    }

    // Isolate standalone verification from ambient env var pollution.
    // Several test suites set JACS_* vars globally; load_config_12factor would
    // otherwise override our temp config and silently point key lookups elsewhere.
    let isolated_keys: [&'static str; 16] = [
        "JACS_USE_SECURITY",
        "JACS_DATA_DIRECTORY",
        "JACS_KEY_DIRECTORY",
        "JACS_AGENT_PRIVATE_KEY_FILENAME",
        "JACS_AGENT_PUBLIC_KEY_FILENAME",
        "JACS_AGENT_KEY_ALGORITHM",
        "JACS_AGENT_ID_AND_VERSION",
        "JACS_DEFAULT_STORAGE",
        "JACS_AGENT_DOMAIN",
        "JACS_DNS_VALIDATE",
        "JACS_DNS_STRICT",
        "JACS_DNS_REQUIRED",
        "JACS_DATABASE_URL",
        "JACS_DATABASE_MAX_CONNECTIONS",
        "JACS_DATABASE_MIN_CONNECTIONS",
        "JACS_DATABASE_CONNECT_TIMEOUT_SECS",
    ];
    let mut saved: Vec<(&'static str, std::option::Option<std::ffi::OsString>)> = Vec::new();
    for key in isolated_keys {
        saved.push((key, std::env::var_os(key)));
        // SAFETY: intentionally clearing process env vars for isolated verification.
        unsafe { std::env::remove_var(key) }
    }
    saved.push(("JACS_KEY_RESOLUTION", std::env::var_os("JACS_KEY_RESOLUTION")));
    if let Some(kr) = key_resolution {
        // SAFETY: set explicit key resolution only for this call.
        unsafe { std::env::set_var("JACS_KEY_RESOLUTION", kr) }
    } else {
        // SAFETY: ensure no inherited override leaks in.
        unsafe { std::env::remove_var("JACS_KEY_RESOLUTION") }
    }
    let _env_guard = EnvGuard { saved };

    let result: BindingResult<VerificationResult> = (|| {
        let wrapper = AgentWrapper::new();
        wrapper.load(config_path.to_string_lossy().to_string())?;
        // If re-rooting fails (e.g. directory doesn't exist), fall through to
        // return valid=false from the verification step.
        let _ = wrapper.set_storage_root(std::path::PathBuf::from(&storage_root));
        let valid = wrapper.verify_document(signed_document)?;
        Ok(VerificationResult {
            valid,
            signer_id: signer_id.clone(),
            timestamp: timestamp.clone(),
            agent_version: agent_version.clone(),
        })
    })();

    // Clean up temp config file
    let _ = std::fs::remove_file(&config_path);

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
                    timestamp,
                    agent_version,
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
// DNS Verification
// =============================================================================

/// Re-export DNS verification result for bindings.
pub use jacs::dns::bootstrap::DnsVerificationResult;

/// Verify an agent's DNS TXT record matches its public key hash.
///
/// Parses the agent JSON and looks up `_v1.agent.jacs.{domain}` to compare hashes.
/// Returns a structured result — never errors for DNS failures (those are `verified: false`).
pub fn verify_agent_dns(agent_json: &str, domain: &str) -> BindingResult<DnsVerificationResult> {
    jacs::dns::bootstrap::verify_agent_dns(agent_json, domain).map_err(|e| {
        BindingCoreError::invalid_argument(format!("DNS verification setup failed: {}", e))
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
    use std::path::PathBuf;

    fn cross_language_fixtures_dir() -> Option<PathBuf> {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent()?.to_path_buf();
        let dir = workspace.join("jacs/tests/fixtures/cross-language");
        if dir.exists() { Some(dir) } else { None }
    }

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
    fn verify_standalone_accepts_relative_parent_paths_from_subdir() {
        let Some(fixtures_dir) = cross_language_fixtures_dir() else {
            eprintln!("Skipping: cross-language fixtures directory not found");
            return;
        };
        let signed_path = fixtures_dir.join("python_ed25519_signed.json");
        if !signed_path.exists() {
            eprintln!(
                "Skipping: fixture '{}' not found",
                signed_path.to_string_lossy()
            );
            return;
        }
        let signed = std::fs::read_to_string(&signed_path).expect("read python fixture");

        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let jacsnpm_dir = workspace.join("jacsnpm");
        if !jacsnpm_dir.exists() {
            eprintln!("Skipping: jacsnpm directory not found");
            return;
        }

        struct CwdGuard(PathBuf);
        impl Drop for CwdGuard {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.0);
            }
        }

        let original_cwd = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(&jacsnpm_dir).expect("chdir to jacsnpm");
        let _guard = CwdGuard(original_cwd);

        let rel = "../jacs/tests/fixtures/cross-language";
        let result = verify_document_standalone(&signed, Some("local"), Some(rel), Some(rel))
            .expect("standalone verify should not error");
        assert!(result.valid, "relative parent-path fixture should verify");
    }

    #[test]
    fn verify_standalone_accepts_absolute_fixture_paths() {
        let Some(fixtures_dir) = cross_language_fixtures_dir() else {
            eprintln!("Skipping: cross-language fixtures directory not found");
            return;
        };
        let signed_path = fixtures_dir.join("python_ed25519_signed.json");
        if !signed_path.exists() {
            eprintln!(
                "Skipping: fixture '{}' not found",
                signed_path.to_string_lossy()
            );
            return;
        }
        let signed = std::fs::read_to_string(&signed_path).expect("read python fixture");
        let fixtures_abs = fixtures_dir
            .canonicalize()
            .unwrap_or_else(|_| fixtures_dir.clone());
        let fixtures_abs_str = fixtures_abs.to_string_lossy().to_string();

        let result = verify_document_standalone(
            &signed,
            Some("local"),
            Some(&fixtures_abs_str),
            Some(&fixtures_abs_str),
        )
        .expect("standalone verify should not error");
        assert!(result.valid, "absolute-path fixture should verify");
    }

    #[test]
    fn verify_standalone_uses_key_directory_when_data_directory_missing() {
        let Some(fixtures_dir) = cross_language_fixtures_dir() else {
            eprintln!("Skipping: cross-language fixtures directory not found");
            return;
        };
        let signed_path = fixtures_dir.join("python_ed25519_signed.json");
        if !signed_path.exists() {
            eprintln!(
                "Skipping: fixture '{}' not found",
                signed_path.to_string_lossy()
            );
            return;
        }
        let signed = std::fs::read_to_string(&signed_path).expect("read python fixture");
        let fixtures_abs = fixtures_dir
            .canonicalize()
            .unwrap_or_else(|_| fixtures_dir.clone());
        let fixtures_abs_str = fixtures_abs.to_string_lossy().to_string();

        let result =
            verify_document_standalone(&signed, Some("local"), None, Some(&fixtures_abs_str))
                .expect("standalone verify should not error");
        assert!(
            result.valid,
            "key_directory should be usable as standalone storage root when data_directory is omitted"
        );
    }

    #[test]
    fn verify_standalone_ignores_polluting_env_overrides() {
        let Some(fixtures_dir) = cross_language_fixtures_dir() else {
            eprintln!("Skipping: cross-language fixtures directory not found");
            return;
        };
        let signed_path = fixtures_dir.join("python_ed25519_signed.json");
        if !signed_path.exists() {
            eprintln!(
                "Skipping: fixture '{}' not found",
                signed_path.to_string_lossy()
            );
            return;
        }
        let signed = std::fs::read_to_string(&signed_path).expect("read python fixture");
        let fixtures_abs = fixtures_dir
            .canonicalize()
            .unwrap_or_else(|_| fixtures_dir.clone());
        let fixtures_abs_str = fixtures_abs.to_string_lossy().to_string();

        struct EnvRestore(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for EnvRestore {
            fn drop(&mut self) {
                for (k, v) in &self.0 {
                    if let Some(val) = v {
                        // SAFETY: test-only env restoration.
                        unsafe { std::env::set_var(k, val) }
                    } else {
                        // SAFETY: removing missing env vars is safe.
                        unsafe { std::env::remove_var(k) }
                    }
                }
            }
        }

        let keys = [
            "JACS_DATA_DIRECTORY",
            "JACS_KEY_DIRECTORY",
            "JACS_DEFAULT_STORAGE",
            "JACS_KEY_RESOLUTION",
        ];
        let mut prev = Vec::new();
        for k in keys {
            prev.push((k, std::env::var_os(k)));
        }
        let _restore = EnvRestore(prev);

        // Simulate pollution from earlier tests in the same process.
        // SAFETY: test-only env manipulation.
        unsafe {
            std::env::set_var("JACS_DATA_DIRECTORY", "/tmp/does-not-exist");
            std::env::set_var("JACS_KEY_DIRECTORY", "/tmp/does-not-exist");
            std::env::set_var("JACS_DEFAULT_STORAGE", "memory");
            std::env::set_var("JACS_KEY_RESOLUTION", "hai");
        }

        let result = verify_document_standalone(
            &signed,
            Some("local"),
            Some(&fixtures_abs_str),
            Some(&fixtures_abs_str),
        )
        .expect("standalone verify should not error");

        assert!(
            result.valid,
            "verification should ignore ambient JACS_* env pollution"
        );
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
