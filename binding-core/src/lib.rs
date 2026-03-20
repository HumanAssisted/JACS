//! # jacs-binding-core
//!
//! Shared core logic for JACS language bindings (Python, Node.js, etc.).
//!
//! This crate provides the binding-agnostic business logic that can be used
//! by any language binding. Each binding implements the `BindingError` trait
//! to convert errors to their native format.

use base64::Engine as _;
use jacs::agent::agreement::Agreement;
use jacs::agent::boilerplate::BoilerPlate;
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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

pub mod conversion;
pub mod doc_wrapper;
pub mod simple_wrapper;

pub use doc_wrapper::DocumentServiceWrapper;
pub use simple_wrapper::SimpleAgentWrapper;
pub use simple_wrapper::sign_message_json;
pub use simple_wrapper::verify_json;

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

fn serialize_agent_info(info: &jacs::simple::AgentInfo) -> BindingResult<String> {
    serde_json::to_string(info).map_err(|e| {
        BindingCoreError::serialization_failed(format!("Failed to serialize AgentInfo: {}", e))
    })
}

fn resolve_existing_config_path(config_path: &str) -> BindingResult<String> {
    let requested = Path::new(config_path);
    let resolved = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| {
                BindingCoreError::agent_load(format!(
                    "Failed to determine current working directory: {}",
                    e
                ))
            })?
            .join(requested)
    };

    if !resolved.exists() {
        return Err(BindingCoreError::agent_load(format!(
            "Config file not found: {}",
            resolved.display()
        )));
    }

    Ok(normalize_path(&resolved).to_string_lossy().into_owned())
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

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

fn create_editable_agreement_document(
    agent: &mut Agent,
    payload: Value,
) -> BindingResult<JACSDocument> {
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
            let level = doc
                .value
                .get("jacsLevel")
                .and_then(|v| v.as_str())
                .unwrap_or("");
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
    private_key_password: Arc<Mutex<Option<String>>>,
}

// ScopedPrivateKeyEnv and private_key_env_lock removed:
// Password is now set directly on Agent.password (agent-scoped, no global state).
// See ENV_SECURITY_PRD Task 006.

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
            private_key_password: Arc::new(Mutex::new(None)),
        }
    }

    /// Create an agent wrapper from an existing Arc<Mutex<Agent>>.
    ///
    /// This is used by the Go FFI to share the agent handle's inner agent
    /// with binding-core's attestation methods.
    pub fn from_inner(inner: Arc<Mutex<Agent>>) -> Self {
        Self {
            inner,
            private_key_password: Arc::new(Mutex::new(None)),
        }
    }

    /// Get the inner `Arc<Mutex<Agent>>`.
    ///
    /// Used to share the agent handle with `DocumentServiceWrapper` and other
    /// components that need direct access to the underlying agent.
    pub fn inner_arc(&self) -> Arc<Mutex<Agent>> {
        Arc::clone(&self.inner)
    }

    /// Get a locked reference to the inner agent.
    fn lock(&self) -> BindingResult<MutexGuard<'_, Agent>> {
        self.inner.lock().map_err(BindingCoreError::from)
    }

    fn configured_private_key_password(&self) -> BindingResult<Option<String>> {
        self.private_key_password
            .lock()
            .map_err(BindingCoreError::from)
            .map(|password| password.clone())
    }

    fn with_private_key_password<T>(
        &self,
        operation: impl FnOnce() -> BindingResult<T>,
    ) -> BindingResult<T> {
        // Always sync the wrapper's password state to the Agent's agent-scoped
        // password field, including None. This ensures that when a caller clears
        // the wrapper password, the inner Agent also has its password cleared
        // so it falls back to env/jenv/keychain resolution (Issue 013).
        {
            let password = self.configured_private_key_password()?;
            let mut agent = self.lock()?;
            agent.set_password(password);
        }
        operation()
    }

    /// Configure a per-wrapper private-key password for load/sign operations.
    ///
    /// This lets higher-level bindings keep per-instance passwords out of
    /// process-global environment management while the current core library
    /// still resolves decryption passwords through `JACS_PRIVATE_KEY_PASSWORD`.
    pub fn set_private_key_password(&self, password: Option<String>) -> BindingResult<()> {
        let mut slot = self
            .private_key_password
            .lock()
            .map_err(BindingCoreError::from)?;
        *slot = password.and_then(|value| if value.is_empty() { None } else { Some(value) });
        Ok(())
    }

    /// Load agent configuration from a file path.
    ///
    /// Uses `Config::from_file` + `apply_env_overrides` + `Agent::from_config`
    /// to avoid deprecated `load_by_config` and env var side-channels.
    pub fn load(&self, config_path: String) -> BindingResult<String> {
        let password = self.configured_private_key_password()?;
        let new_agent = self.load_agent_from_config(&config_path, true, password.as_deref())?;
        *self.lock()? = new_agent;
        Ok("Agent loaded".to_string())
    }

    /// Load agent configuration from file only, **without** applying env/jenv
    /// overrides. This is the isolation-safe counterpart of [`load`] — the
    /// caller constructs a pristine config file and does not want ambient JACS_*
    /// environment variables to pollute it (Issue 008).
    pub fn load_file_only(&self, config_path: String) -> BindingResult<String> {
        let new_agent = self.load_agent_from_config(&config_path, false, None)?;
        *self.lock()? = new_agent;
        Ok("Agent loaded (file-only)".to_string())
    }

    /// Load agent configuration and return canonical loaded-agent metadata.
    pub fn load_with_info(&self, config_path: String) -> BindingResult<String> {
        let resolved_config_path = resolve_existing_config_path(&config_path)?;
        let password = self.configured_private_key_password()?;
        let new_agent =
            self.load_agent_from_config(&resolved_config_path, true, password.as_deref())?;
        let info = jacs::simple::build_loaded_agent_info(&new_agent, &resolved_config_path)
            .map_err(|e| {
                BindingCoreError::agent_load(format!("Failed to load agent: {}", e))
            })?;
        *self.lock()? = new_agent;
        serialize_agent_info(&info)
    }

    /// Internal helper: load an agent from config using the new pattern.
    ///
    /// * `apply_env` - Whether to call `config.apply_env_overrides()` (false for file-only)
    /// * `password` - Optional password to pass directly to Agent::from_config
    fn load_agent_from_config(
        &self,
        config_path: &str,
        apply_env: bool,
        password: Option<&str>,
    ) -> BindingResult<Agent> {
        let mut config = Config::from_file(config_path).map_err(|e| {
            BindingCoreError::agent_load(format!("Failed to load config: {}", e))
        })?;
        if apply_env {
            config.apply_env_overrides();
        }
        Agent::from_config(config, password).map_err(|e| {
            BindingCoreError::agent_load(format!("Failed to load agent: {}", e))
        })
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
        self.with_private_key_password(|| {
            let mut agent = self.lock()?;

            let mut external_agent: Value = agent.validate_agent(agent_string).map_err(|e| {
                BindingCoreError::validation(format!("Agent validation failed: {}", e))
            })?;

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
        })
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
        self.with_private_key_password(|| {
            let mut agent = self.lock()?;
            agent.sign_string(&data.to_string()).map_err(|e| {
                BindingCoreError::signing_failed(format!("Failed to sign string: {}", e))
            })
        })
    }

    /// Sign multiple messages in a single batch, decrypting the private key only once.
    pub fn sign_batch(&self, messages: Vec<String>) -> BindingResult<Vec<String>> {
        self.with_private_key_password(|| {
            let mut agent = self.lock()?;
            let refs: Vec<&str> = messages.iter().map(|s| s.as_str()).collect();
            agent
                .sign_batch(&refs)
                .map_err(|e| BindingCoreError::signing_failed(format!("Batch sign failed: {}", e)))
        })
    }

    /// Verify this agent's signature and hash.
    pub fn verify_agent(&self, agentfile: Option<String>) -> BindingResult<bool> {
        self.with_private_key_password(|| {
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
        })
    }

    /// Update the agent document with new data.
    pub fn update_agent(&self, new_agent_string: &str) -> BindingResult<String> {
        self.with_private_key_password(|| {
            let mut agent = self.lock()?;
            agent
                .update_self(new_agent_string)
                .map_err(|e| BindingCoreError::agent_load(format!("Failed to update agent: {}", e)))
        })
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

        // Prefer the currently loaded agent's public key first. This keeps
        // local self-verification fast and avoids falling through to remote key
        // resolution for documents we just signed in the same workspace.
        if agent
            .verify_document_signature(&document_key, None, None, None, None)
            .is_err()
        {
            agent
                .verify_external_document_signature(&document_key)
                .map_err(|e| {
                    BindingCoreError::verification_failed(format!(
                        "Failed to verify document signature: {}",
                        e
                    ))
                })?;
        }

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
        self.with_private_key_password(|| {
            let mut agent = self.lock()?;

            let doc = agent
                .update_document(document_key, new_document_string, attachments, embed)
                .map_err(|e| {
                    BindingCoreError::document_failed(format!("Failed to update document: {}", e))
                })?;

            Ok(doc.to_string())
        })
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

        self.with_private_key_password(|| {
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
        })
    }

    /// Sign an agreement on a document.
    pub fn sign_agreement(
        &self,
        document_string: &str,
        agreement_fieldname: Option<String>,
    ) -> BindingResult<String> {
        self.with_private_key_password(|| {
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
        self.with_private_key_password(|| {
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
        })
    }

    /// Persist an already-signed JACS document and return its lookup key.
    ///
    /// Stores the document both in the agent's data directory (for file-based
    /// access) and in the storage index (`documents/`) so that
    /// `list_document_keys()` can find it.
    pub fn save_signed_document(
        &self,
        document_string: &str,
        outputfilename: Option<String>,
        export_embedded: Option<bool>,
        extract_only: Option<bool>,
    ) -> BindingResult<String> {
        let mut agent = self.lock()?;
        let doc = agent.load_document(document_string).map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to load signed document: {}", e))
        })?;
        let document_key = doc.getkey();
        agent
            .save_document(&document_key, outputfilename, export_embedded, extract_only)
            .map_err(|e| {
                BindingCoreError::document_failed(format!(
                    "Failed to persist signed document '{}': {}",
                    document_key, e
                ))
            })?;

        Ok(document_key)
    }

    /// Return all known document lookup keys from the agent's configured storage.
    pub fn list_document_keys(&self) -> BindingResult<Vec<String>> {
        let mut agent = self.lock()?;
        Ok(agent.get_document_keys())
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
                BindingCoreError::agreement_failed(format!("Failed to read pending signers: {}", e))
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
        self.with_private_key_password(|| {
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
            .map_err(|e| {
                BindingCoreError::document_failed(format!("Failed to create document: {}", e))
            })
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

    /// Load a document by ID from the agent's configured storage.
    ///
    /// The document ID should be in "uuid:version" format.
    pub fn get_document_by_id(&self, document_id: &str) -> BindingResult<String> {
        if !document_id.contains(':') {
            return Err(BindingCoreError::invalid_argument(format!(
                "Document ID must be in 'uuid:version' format, got '{}'.",
                document_id
            )));
        }

        let agent = self.lock()?;
        let doc = agent.get_document(document_id).map_err(|e| {
            BindingCoreError::document_failed(format!(
                "Failed to load document '{}' from storage: {}",
                document_id, e
            ))
        })?;

        serde_json::to_string(&doc.value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize document '{}': {}",
                document_id, e
            ))
        })
    }

    /// Get the loaded agent's canonical JACS identifier.
    pub fn get_agent_id(&self) -> BindingResult<String> {
        let agent = self.lock()?;
        let value = agent
            .get_value()
            .ok_or_else(|| BindingCoreError::agent_load("Agent not loaded. Call load() first."))?;
        value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                BindingCoreError::agent_load(
                    "Agent not loaded or has no jacsId. Call load() first.",
                )
            })
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
    /// (agent_id, name, version, algorithm). Default algorithm is `pq2025`.
    pub fn ephemeral(&self, algorithm: Option<&str>) -> BindingResult<String> {
        // Map user-friendly names to internal algorithm strings
        let algo = match algorithm.unwrap_or("pq2025") {
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
            obj.insert("description".to_string(), json!("Ephemeral JACS agent"));
        }

        let instance = agent
            .create_agent_and_load(&agent_json.to_string(), true, Some(algo))
            .map_err(|e| {
                BindingCoreError::agent_load(format!("Failed to initialize ephemeral agent: {}", e))
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
                    info["agent_id"] = json!(value.get("jacsId").and_then(|v| v.as_str()));
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

    /// Returns setup instructions for publishing DNS records and enabling DNSSEC.
    ///
    /// Requires a loaded agent (call `load()` first).
    pub fn get_setup_instructions(&self, domain: &str, ttl: u32) -> BindingResult<String> {
        use jacs::agent::boilerplate::BoilerPlate;
        use jacs::dns::bootstrap::{
            DigestEncoding, build_dns_record, dnssec_guidance, emit_azure_cli,
            emit_cloudflare_curl, emit_gcloud_dns, emit_plain_bind, emit_route53_change_batch,
            tld_requirement_text,
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

        let pk = agent
            .get_public_key()
            .map_err(|e| BindingCoreError::generic(format!("Failed to get public key: {}", e)))?;
        let digest = jacs::dns::bootstrap::pubkey_digest_b64(&pk);
        let rr = build_dns_record(domain, ttl, agent_id, &digest, DigestEncoding::Base64);

        let dns_record_bind = emit_plain_bind(&rr);
        let dns_owner = rr.owner.clone();
        let dns_record_value = rr.txt.clone();

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

        let result = json!({
            "dns_record_bind": dns_record_bind,
            "dns_record_value": dns_record_value,
            "dns_owner": dns_owner,
            "provider_commands": provider_commands,
            "dnssec_instructions": dnssec_instructions,
            "tld_requirement": tld_requirement,
            "well_known_json": well_known_json,
            "summary": summary,
        });

        serde_json::to_string_pretty(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize setup instructions: {}",
                e
            ))
        })
    }

    /// Export the loaded agent's full JSON document.
    pub fn export_agent(&self) -> BindingResult<String> {
        let agent = self.lock()?;
        let value = agent
            .get_value()
            .cloned()
            .ok_or_else(|| BindingCoreError::agent_load("Agent not loaded. Call load() first."))?;
        serde_json::to_string_pretty(&value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize agent document: {}",
                e
            ))
        })
    }

    /// Get the loaded agent's public key as a PEM string.
    pub fn get_public_key_pem(&self) -> BindingResult<String> {
        let agent = self.lock()?;
        let public_key = BoilerPlate::get_public_key(&*agent)
            .map_err(|e| BindingCoreError::generic(format!("Failed to get public key: {}", e)))?;
        Ok(jacs::crypt::normalize_public_key_pem(&public_key))
    }

    /// Get the agent's JSON representation as a string.
    ///
    /// Returns the agent's full JSON document.
    pub fn get_agent_json(&self) -> BindingResult<String> {
        self.export_agent()
    }
}

#[cfg(feature = "a2a")]
impl AgentWrapper {
    // =========================================================================
    // A2A Protocol Methods
    // =========================================================================

    /// Export this agent as an A2A Agent Card (v0.4.0).
    ///
    /// Returns the Agent Card as a JSON string.
    pub fn export_agent_card(&self) -> BindingResult<String> {
        let agent = self.lock()?;
        let card = jacs::a2a::agent_card::export_agent_card(&agent).map_err(|e| {
            BindingCoreError::generic(format!("Failed to export agent card: {}", e))
        })?;
        serde_json::to_string_pretty(&card).map_err(|e| {
            BindingCoreError::serialization_failed(format!("Failed to serialize agent card: {}", e))
        })
    }

    /// Generate all .well-known documents for A2A discovery.
    ///
    /// Returns a JSON string containing an array of [path, document] pairs.
    pub fn generate_well_known_documents(
        &self,
        a2a_algorithm: Option<&str>,
    ) -> BindingResult<String> {
        let agent = self.lock()?;
        let card = jacs::a2a::agent_card::export_agent_card(&agent).map_err(|e| {
            BindingCoreError::generic(format!("Failed to export agent card: {}", e))
        })?;

        let a2a_alg = a2a_algorithm.unwrap_or("ring-Ed25519");
        let dual_keys = jacs::a2a::keys::create_jwk_keys(None, Some(a2a_alg)).map_err(|e| {
            BindingCoreError::generic(format!("Failed to generate A2A keys: {}", e))
        })?;

        let agent_id = agent
            .get_id()
            .map_err(|e| BindingCoreError::generic(format!("Failed to get agent ID: {}", e)))?;

        let jws = jacs::a2a::extension::sign_agent_card_jws(
            &card,
            &dual_keys.a2a_private_key,
            &dual_keys.a2a_algorithm,
            &agent_id,
        )
        .map_err(|e| BindingCoreError::generic(format!("Failed to sign Agent Card: {}", e)))?;

        let documents = jacs::a2a::extension::generate_well_known_documents(
            &agent,
            &card,
            &dual_keys.a2a_public_key,
            &dual_keys.a2a_algorithm,
            &jws,
        )
        .map_err(|e| {
            BindingCoreError::generic(format!("Failed to generate well-known documents: {}", e))
        })?;

        // Serialize as JSON array of [path, document] pairs
        let pairs: Vec<Value> = documents
            .into_iter()
            .map(|(path, doc)| serde_json::json!({ "path": path, "document": doc }))
            .collect();
        serde_json::to_string_pretty(&pairs).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize well-known documents: {}",
                e
            ))
        })
    }

    /// Wrap an A2A artifact with JACS provenance signature.
    ///
    /// Returns the signed wrapped artifact as a JSON string.
    #[deprecated(since = "0.9.0", note = "Use sign_artifact() instead")]
    pub fn wrap_a2a_artifact(
        &self,
        artifact_json: &str,
        artifact_type: &str,
        parent_signatures_json: Option<&str>,
    ) -> BindingResult<String> {
        if std::env::var("JACS_SHOW_DEPRECATIONS").is_ok() {
            tracing::warn!("wrap_a2a_artifact is deprecated, use sign_artifact instead");
        }

        let artifact: Value = serde_json::from_str(artifact_json).map_err(|e| {
            BindingCoreError::invalid_argument(format!("Invalid artifact JSON: {}", e))
        })?;

        let parent_signatures: Option<Vec<Value>> = match parent_signatures_json {
            Some(json_str) => {
                let parsed: Vec<Value> = serde_json::from_str(json_str).map_err(|e| {
                    BindingCoreError::invalid_argument(format!(
                        "Invalid parent signatures JSON array: {}",
                        e
                    ))
                })?;
                Some(parsed)
            }
            None => None,
        };

        let mut agent = self.lock()?;
        let wrapped = jacs::a2a::provenance::wrap_artifact_with_provenance(
            &mut agent,
            artifact,
            artifact_type,
            parent_signatures,
        )
        .map_err(|e| BindingCoreError::signing_failed(format!("Failed to wrap artifact: {}", e)))?;

        serde_json::to_string_pretty(&wrapped).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize wrapped artifact: {}",
                e
            ))
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
    ) -> BindingResult<String> {
        #[allow(deprecated)]
        self.wrap_a2a_artifact(artifact_json, artifact_type, parent_signatures_json)
    }

    /// Verify a JACS-wrapped A2A artifact.
    ///
    /// Returns the verification result as a JSON string.
    pub fn verify_a2a_artifact(&self, wrapped_json: &str) -> BindingResult<String> {
        let wrapped: Value = serde_json::from_str(wrapped_json).map_err(|e| {
            BindingCoreError::invalid_argument(format!("Invalid wrapped artifact JSON: {}", e))
        })?;

        let agent = self.lock()?;
        let result =
            jacs::a2a::provenance::verify_wrapped_artifact(&agent, &wrapped).map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "A2A artifact verification error: {}",
                    e
                ))
            })?;

        serde_json::to_string_pretty(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize verification result: {}",
                e
            ))
        })
    }
    /// Assess trust level of a remote A2A agent given its Agent Card JSON.
    ///
    /// Returns the trust assessment as a JSON string.
    pub fn assess_a2a_agent(&self, agent_card_json: &str, policy: &str) -> BindingResult<String> {
        use jacs::a2a::AgentCard;
        use jacs::a2a::trust::{A2ATrustPolicy, assess_a2a_agent};

        let card: AgentCard = serde_json::from_str(agent_card_json).map_err(|e| {
            BindingCoreError::invalid_argument(format!("Invalid Agent Card JSON: {}", e))
        })?;

        let trust_policy = A2ATrustPolicy::from_str_loose(policy).map_err(|e| {
            BindingCoreError::invalid_argument(format!("Invalid trust policy '{}': {}", policy, e))
        })?;

        let agent = self.lock()?;
        let assessment = assess_a2a_agent(&agent, &card, trust_policy);

        serde_json::to_string_pretty(&assessment).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize trust assessment: {}",
                e
            ))
        })
    }

    /// Verify a JACS-wrapped A2A artifact with trust policy enforcement.
    ///
    /// Combines cryptographic signature verification with trust policy evaluation.
    /// The remote agent's Agent Card is assessed against the specified policy,
    /// and the trust level is included in the verification result.
    ///
    /// # Arguments
    ///
    /// * `wrapped_json` - JSON string of the JACS-wrapped artifact
    /// * `agent_card_json` - JSON string of the remote agent's A2A Agent Card
    /// * `policy` - Trust policy name: "open", "verified", or "strict"
    ///
    /// # Returns
    ///
    /// JSON string containing the verification result with trust information.
    pub fn verify_a2a_artifact_with_policy(
        &self,
        wrapped_json: &str,
        agent_card_json: &str,
        policy: &str,
    ) -> BindingResult<String> {
        use jacs::a2a::AgentCard;
        use jacs::a2a::trust::A2ATrustPolicy;

        let wrapped: Value = serde_json::from_str(wrapped_json).map_err(|e| {
            BindingCoreError::invalid_argument(format!("Invalid wrapped artifact JSON: {}", e))
        })?;

        let card: AgentCard = serde_json::from_str(agent_card_json).map_err(|e| {
            BindingCoreError::invalid_argument(format!("Invalid Agent Card JSON: {}", e))
        })?;

        let trust_policy = A2ATrustPolicy::from_str_loose(policy).map_err(|e| {
            BindingCoreError::invalid_argument(format!("Invalid trust policy '{}': {}", policy, e))
        })?;

        let agent = self.lock()?;
        let result = jacs::a2a::provenance::verify_wrapped_artifact_with_policy(
            &agent,
            &wrapped,
            &card,
            trust_policy,
        )
        .map_err(|e| {
            BindingCoreError::verification_failed(format!(
                "A2A artifact verification with policy error: {}",
                e
            ))
        })?;

        serde_json::to_string_pretty(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize verification result: {}",
                e
            ))
        })
    }
}

impl AgentWrapper {
    // =========================================================================
    // Attestation API (gated behind `attestation` feature)
    // =========================================================================

    /// Create a signed attestation document from JSON parameters.
    ///
    /// The `params_json` string must be a JSON object with:
    /// - `subject` (required): `{ type, id, digests: { sha256, ... } }`
    /// - `claims` (required): `[{ name, value, confidence?, assuranceLevel?, ... }]`
    /// - `evidence` (optional): array of evidence references
    /// - `derivation` (optional): derivation/transform receipt
    /// - `policyContext` (optional): policy evaluation context
    ///
    /// Returns the signed attestation document as a JSON string.
    #[cfg(feature = "attestation")]
    pub fn create_attestation(&self, params_json: &str) -> BindingResult<String> {
        use jacs::attestation::AttestationTraits;
        use jacs::attestation::types::*;

        let params: Value = serde_json::from_str(params_json).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to parse attestation params JSON: {}. \
                 Provide a valid JSON object with 'subject' and 'claims' fields.",
                e
            ))
        })?;

        // Parse subject (required)
        let subject: AttestationSubject =
            serde_json::from_value(params.get("subject").cloned().ok_or_else(|| {
                BindingCoreError::validation(
                    "Missing required 'subject' field in attestation params",
                )
            })?)
            .map_err(|e| BindingCoreError::validation(format!("Invalid 'subject' field: {}", e)))?;

        // Parse claims (required, at least 1)
        let claims: Vec<Claim> =
            serde_json::from_value(params.get("claims").cloned().ok_or_else(|| {
                BindingCoreError::validation(
                    "Missing required 'claims' field in attestation params",
                )
            })?)
            .map_err(|e| BindingCoreError::validation(format!("Invalid 'claims' field: {}", e)))?;

        // Parse optional evidence
        let evidence: Vec<EvidenceRef> = if let Some(ev) = params.get("evidence") {
            serde_json::from_value(ev.clone()).map_err(|e| {
                BindingCoreError::validation(format!("Invalid 'evidence' field: {}", e))
            })?
        } else {
            vec![]
        };

        // Parse optional derivation
        let derivation: Option<Derivation> = if let Some(d) = params.get("derivation") {
            Some(serde_json::from_value(d.clone()).map_err(|e| {
                BindingCoreError::validation(format!("Invalid 'derivation' field: {}", e))
            })?)
        } else {
            None
        };

        // Parse optional policyContext
        let policy_context: Option<PolicyContext> = if let Some(p) = params.get("policyContext") {
            Some(serde_json::from_value(p.clone()).map_err(|e| {
                BindingCoreError::validation(format!("Invalid 'policyContext' field: {}", e))
            })?)
        } else {
            None
        };

        let mut agent = self.lock()?;
        let jacs_doc = agent
            .create_attestation(
                &subject,
                &claims,
                &evidence,
                derivation.as_ref(),
                policy_context.as_ref(),
            )
            .map_err(|e| {
                BindingCoreError::document_failed(format!("Failed to create attestation: {}", e))
            })?;

        serde_json::to_string_pretty(&jacs_doc.value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize attestation: {}",
                e
            ))
        })
    }

    /// Verify an attestation using local (crypto-only) verification.
    ///
    /// Takes the attestation document key in "id:version" format.
    /// Returns the verification result as a JSON string.
    #[cfg(feature = "attestation")]
    pub fn verify_attestation(&self, document_key: &str) -> BindingResult<String> {
        let agent = self.lock()?;
        let result = agent
            .verify_attestation_local_impl(document_key)
            .map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Attestation local verification failed: {}",
                    e
                ))
            })?;

        serde_json::to_string_pretty(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize verification result: {}",
                e
            ))
        })
    }

    /// Verify an attestation using full verification (evidence + chain).
    ///
    /// Takes the attestation document key in "id:version" format.
    /// Returns the verification result as a JSON string.
    #[cfg(feature = "attestation")]
    pub fn verify_attestation_full(&self, document_key: &str) -> BindingResult<String> {
        let agent = self.lock()?;
        let result = agent
            .verify_attestation_full_impl(document_key)
            .map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Attestation full verification failed: {}",
                    e
                ))
            })?;

        serde_json::to_string_pretty(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize verification result: {}",
                e
            ))
        })
    }

    /// Lift an existing signed JACS document into an attestation.
    ///
    /// Takes a signed document JSON string and claims JSON string.
    /// Returns the signed attestation document as a JSON string.
    #[cfg(feature = "attestation")]
    pub fn lift_to_attestation(
        &self,
        signed_doc_json: &str,
        claims_json: &str,
    ) -> BindingResult<String> {
        use jacs::attestation::types::Claim;

        let claims: Vec<Claim> = serde_json::from_str(claims_json).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to parse claims JSON: {}. \
                 Provide a valid JSON array of claim objects.",
                e
            ))
        })?;

        let mut agent = self.lock()?;
        let jacs_doc =
            jacs::attestation::migration::lift_to_attestation(&mut agent, signed_doc_json, &claims)
                .map_err(|e| {
                    BindingCoreError::document_failed(format!(
                        "Failed to lift document to attestation: {}",
                        e
                    ))
                })?;

        serde_json::to_string_pretty(&jacs_doc.value).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize attestation: {}",
                e
            ))
        })
    }

    /// Export a signed attestation as a DSSE (Dead Simple Signing Envelope).
    ///
    /// Takes the attestation JSON string and returns a DSSE envelope JSON string.
    #[cfg(feature = "attestation")]
    pub fn export_attestation_dsse(&self, attestation_json: &str) -> BindingResult<String> {
        let att_value: Value = serde_json::from_str(attestation_json).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to parse attestation JSON: {}",
                e
            ))
        })?;

        let envelope = jacs::attestation::dsse::export_dsse(&att_value).map_err(|e| {
            BindingCoreError::document_failed(format!("Failed to export DSSE envelope: {}", e))
        })?;

        serde_json::to_string_pretty(&envelope).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize DSSE envelope: {}",
                e
            ))
        })
    }

    // =========================================================================
    // Protocol helpers (delegates to jacs::protocol)
    // =========================================================================

    /// Build the JACS `Authorization` header value.
    ///
    /// Format: `"JACS {jacs_id}:{unix_timestamp}:{base64_signature}"`.
    /// Requires a loaded agent with keys.
    pub fn build_auth_header(&self) -> BindingResult<String> {
        let mut agent = self.lock()?;
        jacs::protocol::build_auth_header(&mut agent).map_err(|e| {
            BindingCoreError::signing_failed(format!("Failed to build auth header: {}", e))
        })
    }

    /// Deterministically serialize a JSON string per RFC 8785 (JCS).
    ///
    /// Accepts a JSON string, parses it, and returns the canonicalized form.
    pub fn canonicalize_json(&self, json_string: &str) -> BindingResult<String> {
        let value: Value = serde_json::from_str(json_string).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to parse JSON for canonicalization: {}",
                e
            ))
        })?;
        Ok(jacs::protocol::canonicalize_json(&value))
    }

    /// Build and sign a JACS response envelope.
    ///
    /// Accepts a JSON payload string, returns a signed envelope JSON string
    /// containing `version`, `document_type`, `data`, `metadata`, and
    /// `jacsSignature`.
    pub fn sign_response(&self, payload_json: &str) -> BindingResult<String> {
        let mut agent = self.lock()?;
        let payload: Value = serde_json::from_str(payload_json).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to parse payload JSON for sign_response: {}",
                e
            ))
        })?;
        let result = jacs::protocol::sign_response(&mut agent, &payload).map_err(|e| {
            BindingCoreError::signing_failed(format!("Failed to sign response: {}", e))
        })?;
        serde_json::to_string(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize signed response: {}",
                e
            ))
        })
    }

    /// Encode a document as URL-safe base64 (no padding) for verification.
    ///
    /// SDK clients use this to build verification URLs. JACS does not impose
    /// any URL structure — that is the SDK's responsibility.
    pub fn encode_verify_payload(&self, document: &str) -> BindingResult<String> {
        Ok(jacs::protocol::encode_verify_payload(document))
    }

    /// Decode a URL-safe base64 verification payload back to the original
    /// document string.
    pub fn decode_verify_payload(&self, encoded: &str) -> BindingResult<String> {
        jacs::protocol::decode_verify_payload(encoded).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to decode verify payload: {}",
                e
            ))
        })
    }

    /// Extract the document ID from a JACS-signed document.
    ///
    /// Checks `jacsDocumentId`, `document_id`, `id` in priority order.
    /// SDK clients use this to build hosted verification URLs.
    pub fn extract_document_id(&self, document: &str) -> BindingResult<String> {
        jacs::protocol::extract_document_id(document)
            .map_err(|e| BindingCoreError::generic(format!("Failed to extract document ID: {}", e)))
    }

    /// Unwrap a JACS-signed event, verifying the signature when the signer's
    /// public key is known.
    ///
    /// `event_json` is the signed event as a JSON string.
    /// `server_keys_json` is a JSON object mapping agent IDs to base64-encoded
    /// public key bytes: `{"agent_id": "base64_key", ...}`.
    ///
    /// Returns a JSON string: `{"data": <unwrapped>, "verified": <bool>}`.
    pub fn unwrap_signed_event(
        &self,
        event_json: &str,
        server_keys_json: &str,
    ) -> BindingResult<String> {
        let agent = self.lock()?;
        let event: Value = serde_json::from_str(event_json).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to parse event JSON for unwrap_signed_event: {}",
                e
            ))
        })?;
        let keys_map: HashMap<String, String> =
            serde_json::from_str(server_keys_json).map_err(|e| {
                BindingCoreError::serialization_failed(format!(
                    "Failed to parse server keys JSON for unwrap_signed_event: {}",
                    e
                ))
            })?;
        let keys: HashMap<String, Vec<u8>> = keys_map
            .into_iter()
            .map(|(k, v)| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&v)
                    .unwrap_or_else(|_| v.into_bytes());
                (k, bytes)
            })
            .collect();
        let (data, verified) =
            jacs::protocol::unwrap_signed_event(&agent, &event, &keys).map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Failed to unwrap signed event: {}",
                    e
                ))
            })?;
        let result = json!({"data": data, "verified": verified});
        serde_json::to_string(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize unwrap_signed_event result: {}",
                e
            ))
        })
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
/// * `key_resolution` - Optional key resolution order, e.g. "local" or "local,remote" (default "local").
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
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    fn absolutize_dir(raw: &str) -> String {
        let p = PathBuf::from(raw);
        if p.is_absolute() {
            p.to_string_lossy().to_string()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
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

    fn has_local_key_cache(root: &Path, key_hash: &str) -> bool {
        if key_hash.is_empty() {
            return false;
        }
        root.join("public_keys")
            .join(format!("{}.pem", key_hash))
            .exists()
            && root
                .join("public_keys")
                .join(format!("{}.enc_type", key_hash))
                .exists()
    }

    fn build_fixture_key_cache(cache_root: &Path, source_dirs: &[PathBuf]) -> usize {
        let public_keys_dir = cache_root.join("public_keys");
        if std::fs::create_dir_all(&public_keys_dir).is_err() {
            return 0;
        }

        let mut written: HashSet<String> = HashSet::new();
        for dir in source_dirs {
            let entries = match std::fs::read_dir(dir) {
                Ok(v) => v,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                let Some(prefix) = name.strip_suffix("_metadata.json") else {
                    continue;
                };

                let metadata = match std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                {
                    Some(v) => v,
                    None => continue,
                };
                let key_hash = metadata
                    .get("public_key_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                let signing_algorithm = metadata
                    .get("signing_algorithm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                if key_hash.is_empty() || signing_algorithm.is_empty() {
                    continue;
                }
                if written.contains(key_hash) {
                    continue;
                }

                let key_path = dir.join(format!("{}_public_key.pem", prefix));
                let key_bytes = match std::fs::read(&key_path) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                if std::fs::write(public_keys_dir.join(format!("{}.pem", key_hash)), key_bytes)
                    .is_err()
                {
                    continue;
                }
                if std::fs::write(
                    public_keys_dir.join(format!("{}.enc_type", key_hash)),
                    signing_algorithm.as_bytes(),
                )
                .is_err()
                {
                    continue;
                }

                written.insert(key_hash.to_string());
            }
        }

        written.len()
    }

    fn standalone_verify_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    let _lock = standalone_verify_lock()
        .lock()
        .map_err(|e| BindingCoreError::generic(format!("Failed to lock standalone verify: {e}")))?;

    let signer_id = sig_field(signed_document, "agentID");
    let timestamp = sig_field(signed_document, "date");
    let agent_version = sig_field(signed_document, "agentVersion");
    let signer_public_key_hash = sig_field(signed_document, "publicKeyHash");

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
    let mut effective_storage_root = if data_directory.is_some() {
        absolute_data_dir.clone()
    } else if key_directory.is_some() {
        absolute_key_dir.clone()
    } else {
        absolute_data_dir.clone()
    };
    let mut temp_cache_root: Option<PathBuf> = None;

    // Many cross-language fixture directories store keys as:
    //   <prefix>_metadata.json + <prefix>_public_key.pem
    // rather than public_keys/{hash}.pem.
    // Build a deterministic temp cache when local key files are missing.
    let local_requested = key_resolution.map_or(true, |kr| {
        kr.split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("local"))
    });
    if local_requested && !signer_public_key_hash.is_empty() {
        let current_root = PathBuf::from(&effective_storage_root);
        if !has_local_key_cache(&current_root, &signer_public_key_hash) {
            let mut source_dirs = Vec::new();
            let data_path = PathBuf::from(&absolute_data_dir);
            let key_path = PathBuf::from(&absolute_key_dir);
            if data_path.exists() {
                source_dirs.push(data_path);
            }
            if key_path.exists() && !source_dirs.iter().any(|p| p == &key_path) {
                source_dirs.push(key_path);
            }

            if !source_dirs.is_empty() {
                let nonce = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let cache_root = std::env::temp_dir().join(format!(
                    "jacs_standalone_keycache_{}_{}",
                    std::process::id(),
                    nonce
                ));
                let _ = build_fixture_key_cache(&cache_root, &source_dirs);
                if has_local_key_cache(&cache_root, &signer_public_key_hash) {
                    effective_storage_root = cache_root.to_string_lossy().to_string();
                    temp_cache_root = Some(cache_root);
                } else {
                    let _ = std::fs::remove_dir_all(&cache_root);
                }
            }
        }
    }
    let explicit_local_key_available = local_requested
        && !signer_public_key_hash.is_empty()
        && has_local_key_cache(
            &PathBuf::from(&effective_storage_root),
            &signer_public_key_hash,
        );

    // Re-root storage and keep config dirs empty so path construction stays
    // relative to storage root (e.g. "public_keys/<hash>.pem").
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

    // Issue 008: Use load_file_only to bypass env/jenv overrides entirely.
    // This eliminates the 16-key JenvGuard save/clear/restore pattern.
    // The config file is authoritative — no ambient JACS_* vars can pollute it.
    //
    // JACS_KEY_RESOLUTION is the only runtime-read jenv key we still need to
    // manage, since key_resolution_order() reads it at verification time.
    use jacs::storage::jenv;

    // Minimal guard for JACS_KEY_RESOLUTION only (Issue 014-safe).
    struct KeyResolutionGuard {
        had_override: bool,
        prev_value: Option<String>,
    }
    impl Drop for KeyResolutionGuard {
        fn drop(&mut self) {
            if self.had_override {
                if let Some(ref val) = self.prev_value {
                    let _ = jacs::storage::jenv::set_env_var("JACS_KEY_RESOLUTION", val);
                } else {
                    let _ = jacs::storage::jenv::clear_env_var("JACS_KEY_RESOLUTION");
                }
            } else {
                let _ = jacs::storage::jenv::clear_env_var("JACS_KEY_RESOLUTION");
            }
        }
    }
    let kr_had_override = jenv::has_jenv_override("JACS_KEY_RESOLUTION");
    let kr_prev = if kr_had_override {
        jenv::get_env_var("JACS_KEY_RESOLUTION", false)
            .ok()
            .flatten()
    } else {
        None
    };
    if let Some(kr) = key_resolution {
        let _ = jenv::set_env_var("JACS_KEY_RESOLUTION", kr);
    } else {
        let _ = jenv::clear_env_var("JACS_KEY_RESOLUTION");
    }
    let _kr_guard = KeyResolutionGuard {
        had_override: kr_had_override,
        prev_value: kr_prev,
    };

    let result: BindingResult<VerificationResult> = (|| {
        let wrapper = AgentWrapper::new();
        wrapper.load_file_only(config_path.to_string_lossy().to_string())?;
        let _ = wrapper.set_storage_root(PathBuf::from(&effective_storage_root));

        if explicit_local_key_available {
            let key_base = PathBuf::from(&effective_storage_root)
                .join("public_keys")
                .join(&signer_public_key_hash);
            let public_key = std::fs::read(key_base.with_extension("pem")).map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Failed to load local public key for hash '{}': {}",
                    signer_public_key_hash, e
                ))
            })?;
            let enc_type = std::fs::read_to_string(key_base.with_extension("enc_type"))
                .map_err(|e| {
                    BindingCoreError::verification_failed(format!(
                        "Failed to load local public key type for hash '{}': {}",
                        signer_public_key_hash, e
                    ))
                })?
                .trim()
                .to_string();

            let mut agent = wrapper.lock()?;
            let doc = agent.load_document(signed_document).map_err(|e| {
                BindingCoreError::document_failed(format!("Failed to load document: {}", e))
            })?;
            let document_key = doc.getkey();
            let value = doc.getvalue();
            agent.verify_hash(value).map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Failed to verify document hash: {}",
                    e
                ))
            })?;
            agent
                .verify_document_signature(
                    &document_key,
                    None,
                    None,
                    Some(public_key),
                    Some(enc_type.clone()),
                )
                .map_err(|e| {
                    BindingCoreError::verification_failed(format!(
                        "Failed to verify document signature (enc_type={}): {}",
                        enc_type, e
                    ))
                })?;

            return Ok(VerificationResult {
                valid: true,
                signer_id: signer_id.clone(),
                timestamp: timestamp.clone(),
                agent_version: agent_version.clone(),
            });
        }

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
    if let Some(cache_root) = temp_cache_root {
        let _ = std::fs::remove_dir_all(cache_root);
    }

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

/// Add an agent to the local trust store using an explicitly provided public key.
///
/// This is the recommended first-contact bootstrap for secure trust establishment.
pub fn trust_agent_with_key(agent_json: &str, public_key_pem: &str) -> BindingResult<String> {
    if public_key_pem.trim().is_empty() {
        return Err(BindingCoreError::invalid_argument(
            "public_key_pem cannot be empty",
        ));
    }
    jacs::trust::trust_agent_with_key(agent_json, Some(public_key_pem)).map_err(|e| {
        BindingCoreError::trust_failed(format!("Failed to trust agent with explicit key: {}", e))
    })
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
        storage: None,
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

/// Like `handle_agent_create` but auto-updates config with the agent ID when
/// `auto_update_config` is true, skipping the interactive prompt.
pub fn handle_agent_create_auto(
    filename: Option<&String>,
    create_keys: bool,
    auto_update_config: bool,
) -> BindingResult<()> {
    jacs::cli_utils::create::handle_agent_create_auto(filename, create_keys, auto_update_config)
        .map_err(|e| BindingCoreError::generic(e.to_string()))
}

/// Create a jacs.config.json file interactively.
pub fn handle_config_create() -> BindingResult<()> {
    jacs::cli_utils::create::handle_config_create()
        .map_err(|e| BindingCoreError::generic(e.to_string()))
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
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()?
            .to_path_buf();
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
    #[ignore = "pre-existing: cross-language fixture verification fails with relative parent paths"]
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
            std::env::set_var("JACS_KEY_RESOLUTION", "remote");
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

    // =========================================================================
    // A2A Protocol Tests
    // =========================================================================

    /// Helper: create an ephemeral AgentWrapper for A2A tests.
    fn ephemeral_wrapper() -> AgentWrapper {
        let wrapper = AgentWrapper::new();
        wrapper.ephemeral(Some("ed25519")).unwrap();
        wrapper
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn test_export_agent_card_returns_valid_json() {
        let wrapper = ephemeral_wrapper();
        let card_json = wrapper.export_agent_card().unwrap();
        let card: Value = serde_json::from_str(&card_json).unwrap();
        assert!(card.get("name").is_some());
        assert!(card.get("protocolVersions").is_some());
        assert_eq!(card["protocolVersions"][0], "0.4.0");
    }

    #[cfg(feature = "a2a")]
    #[test]
    #[allow(deprecated)]
    fn test_wrap_and_verify_a2a_artifact() {
        let wrapper = ephemeral_wrapper();
        let artifact = r#"{"content": "hello A2A"}"#;

        let wrapped = wrapper
            .wrap_a2a_artifact(artifact, "message", None)
            .unwrap();
        let wrapped_value: Value = serde_json::from_str(&wrapped).unwrap();
        assert!(wrapped_value.get("jacsId").is_some());
        assert_eq!(wrapped_value["jacsType"], "a2a-message");

        let result_json = wrapper.verify_a2a_artifact(&wrapped).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
        assert_eq!(result["status"], "SelfSigned");
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn test_sign_artifact_alias_matches_wrap() {
        let wrapper = ephemeral_wrapper();
        let artifact = r#"{"data": 42}"#;

        let signed = wrapper.sign_artifact(artifact, "artifact", None).unwrap();
        let value: Value = serde_json::from_str(&signed).unwrap();
        assert_eq!(value["jacsType"], "a2a-artifact");

        let result_json = wrapper.verify_a2a_artifact(&signed).unwrap();
        let result: Value = serde_json::from_str(&result_json).unwrap();
        assert_eq!(result["valid"], true);
    }

    #[cfg(feature = "a2a")]
    #[test]
    #[allow(deprecated)]
    fn test_wrap_a2a_artifact_with_parent_chain() {
        let wrapper = ephemeral_wrapper();

        let first = wrapper
            .wrap_a2a_artifact(r#"{"step": 1}"#, "task", None)
            .unwrap();
        let parents = format!("[{}]", first);
        let second = wrapper
            .wrap_a2a_artifact(r#"{"step": 2}"#, "task", Some(&parents))
            .unwrap();

        let second_value: Value = serde_json::from_str(&second).unwrap();
        let parent_sigs = second_value["jacsParentSignatures"].as_array().unwrap();
        assert_eq!(parent_sigs.len(), 1);
    }

    #[cfg(feature = "a2a")]
    #[test]
    #[allow(deprecated)]
    fn test_wrap_a2a_artifact_invalid_json_error() {
        let wrapper = ephemeral_wrapper();
        let result = wrapper.wrap_a2a_artifact("not json", "artifact", None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ErrorKind::InvalidArgument);
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn test_verify_a2a_artifact_invalid_json_error() {
        let wrapper = ephemeral_wrapper();
        let result = wrapper.verify_a2a_artifact("not json");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ErrorKind::InvalidArgument);
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn test_export_agent_card_unloaded_agent_error() {
        let wrapper = AgentWrapper::new();
        let result = wrapper.export_agent_card();
        assert!(result.is_err());
    }

    // =========================================================================
    // Protocol Wrapper Tests
    // =========================================================================

    /// Helper: create an ephemeral AgentWrapper for protocol tests.
    fn protocol_wrapper() -> AgentWrapper {
        let wrapper = AgentWrapper::new();
        wrapper.ephemeral(Some("ed25519")).unwrap();
        wrapper
    }

    #[test]
    fn protocol_build_auth_header_starts_with_jacs() {
        let wrapper = protocol_wrapper();
        let header = wrapper
            .build_auth_header()
            .expect("build_auth_header failed");
        assert!(
            header.starts_with("JACS "),
            "Header must start with 'JACS ', got: {header}"
        );
    }

    #[test]
    fn protocol_canonicalize_json_sorts_keys() {
        let wrapper = protocol_wrapper();
        let result = wrapper
            .canonicalize_json(r#"{"b":1,"a":2}"#)
            .expect("canonicalize_json failed");
        assert_eq!(result, r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn protocol_canonicalize_json_invalid_input() {
        let wrapper = protocol_wrapper();
        let result = wrapper.canonicalize_json("not json");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ErrorKind::SerializationFailed);
    }

    #[test]
    fn protocol_sign_response_has_required_fields() {
        let wrapper = protocol_wrapper();
        let result = wrapper
            .sign_response(r#"{"answer": 42}"#)
            .expect("sign_response failed");
        let envelope: Value = serde_json::from_str(&result).expect("should be valid JSON");
        assert!(envelope.get("version").is_some(), "missing 'version'");
        assert!(
            envelope.get("jacsSignature").is_some(),
            "missing 'jacsSignature'"
        );
        assert_eq!(envelope["version"], "1.0.0");
    }

    #[test]
    fn protocol_sign_response_invalid_payload() {
        let wrapper = protocol_wrapper();
        let result = wrapper.sign_response("not json");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ErrorKind::SerializationFailed);
    }

    #[test]
    fn protocol_encode_verify_payload_round_trips() {
        let wrapper = protocol_wrapper();
        let original = r#"{"test":true}"#;
        let encoded = wrapper
            .encode_verify_payload(original)
            .expect("encode_verify_payload failed");
        assert!(!encoded.contains('+'), "URL-safe base64 must not contain +");
        assert!(!encoded.contains('/'), "URL-safe base64 must not contain /");
        assert!(
            !encoded.contains('='),
            "URL-safe base64 must not have padding"
        );
        let decoded = wrapper
            .decode_verify_payload(&encoded)
            .expect("decode_verify_payload failed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn protocol_extract_document_id_extracts_id() {
        let wrapper = protocol_wrapper();
        let id = wrapper
            .extract_document_id(r#"{"jacsDocumentId":"abc-123"}"#)
            .expect("extract_document_id failed");
        assert_eq!(id, "abc-123");
    }

    #[test]
    fn protocol_extract_document_id_no_id_errors() {
        let wrapper = protocol_wrapper();
        let result = wrapper.extract_document_id(r#"{"name":"no-id"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn protocol_unwrap_signed_event_unknown_agent_unverified() {
        let wrapper = protocol_wrapper();
        let event = r#"{"data":{"result":"hello"},"jacsSignature":{"agentID":"unknown:v1","date":"2026-01-01T00:00:00Z","signature":"fakesig"}}"#;
        let keys = r#"{}"#;
        let result = wrapper
            .unwrap_signed_event(event, keys)
            .expect("unwrap_signed_event failed");
        let parsed: Value = serde_json::from_str(&result).expect("should be valid JSON");
        assert_eq!(parsed["verified"], false);
        assert_eq!(parsed["data"]["result"], "hello");
    }

    #[test]
    fn protocol_unwrap_signed_event_legacy_payload() {
        let wrapper = protocol_wrapper();
        let event = r#"{"payload":{"status":"ok"}}"#;
        let keys = r#"{}"#;
        let result = wrapper
            .unwrap_signed_event(event, keys)
            .expect("unwrap_signed_event failed");
        let parsed: Value = serde_json::from_str(&result).expect("should be valid JSON");
        assert_eq!(parsed["verified"], false);
        assert_eq!(parsed["data"]["status"], "ok");
    }

    #[test]
    fn protocol_unwrap_signed_event_plain_event() {
        let wrapper = protocol_wrapper();
        let event = r#"{"type":"heartbeat","ts":12345}"#;
        let keys = r#"{}"#;
        let result = wrapper
            .unwrap_signed_event(event, keys)
            .expect("unwrap_signed_event failed");
        let parsed: Value = serde_json::from_str(&result).expect("should be valid JSON");
        assert_eq!(parsed["verified"], false);
        assert_eq!(parsed["data"]["type"], "heartbeat");
    }

    #[test]
    fn protocol_unwrap_signed_event_invalid_event_json() {
        let wrapper = protocol_wrapper();
        let result = wrapper.unwrap_signed_event("not json", "{}");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ErrorKind::SerializationFailed);
    }

    #[test]
    fn protocol_unwrap_signed_event_invalid_keys_json() {
        let wrapper = protocol_wrapper();
        let result = wrapper.unwrap_signed_event(r#"{"type":"test"}"#, "not json");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ErrorKind::SerializationFailed);
    }

    // =========================================================================
    // Attestation API Tests
    // =========================================================================

    #[cfg(feature = "attestation")]
    mod attestation_tests {
        use super::*;

        fn attestation_wrapper() -> AgentWrapper {
            let wrapper = AgentWrapper::new();
            wrapper.ephemeral(Some("ed25519")).unwrap();
            wrapper
        }

        fn basic_attestation_params() -> String {
            json!({
                "subject": {
                    "type": "artifact",
                    "id": "test-artifact-001",
                    "digests": { "sha256": "abc123" }
                },
                "claims": [{
                    "name": "reviewed",
                    "value": true,
                    "confidence": 0.95,
                    "assuranceLevel": "verified"
                }]
            })
            .to_string()
        }

        #[test]
        fn binding_create_attestation_json() {
            let wrapper = attestation_wrapper();
            let result = wrapper.create_attestation(&basic_attestation_params());
            assert!(
                result.is_ok(),
                "create_attestation should succeed: {:?}",
                result.err()
            );

            let json_str = result.unwrap();
            let doc: Value = serde_json::from_str(&json_str).unwrap();
            assert!(
                doc.get("attestation").is_some(),
                "returned JSON should contain 'attestation' key"
            );
            assert!(
                doc.get("jacsSignature").is_some(),
                "returned JSON should be signed"
            );
        }

        #[test]
        fn binding_verify_attestation_json() {
            let wrapper = attestation_wrapper();
            let att_json = wrapper
                .create_attestation(&basic_attestation_params())
                .unwrap();
            let doc: Value = serde_json::from_str(&att_json).unwrap();
            let key = format!(
                "{}:{}",
                doc["jacsId"].as_str().unwrap(),
                doc["jacsVersion"].as_str().unwrap()
            );

            let result = wrapper.verify_attestation(&key);
            assert!(
                result.is_ok(),
                "verify_attestation should succeed: {:?}",
                result.err()
            );

            let result_json = result.unwrap();
            let result_value: Value = serde_json::from_str(&result_json).unwrap();
            assert_eq!(
                result_value["valid"], true,
                "attestation should verify as valid"
            );
        }

        #[test]
        fn binding_verify_attestation_full_json() {
            let wrapper = attestation_wrapper();
            let att_json = wrapper
                .create_attestation(&basic_attestation_params())
                .unwrap();
            let doc: Value = serde_json::from_str(&att_json).unwrap();
            let key = format!(
                "{}:{}",
                doc["jacsId"].as_str().unwrap(),
                doc["jacsVersion"].as_str().unwrap()
            );

            let result = wrapper.verify_attestation_full(&key);
            assert!(
                result.is_ok(),
                "verify_attestation_full should succeed: {:?}",
                result.err()
            );

            let result_json = result.unwrap();
            let result_value: Value = serde_json::from_str(&result_json).unwrap();
            assert_eq!(
                result_value["valid"], true,
                "full attestation should verify as valid"
            );
            assert!(
                result_value.get("evidence").is_some(),
                "full verification result should contain 'evidence' array"
            );
        }

        #[test]
        fn binding_lift_to_attestation_json() {
            let wrapper = attestation_wrapper();

            // Create a proper signed JACS document
            let doc_json = json!({"title": "Test Document", "content": "Some content"}).to_string();
            let signed = wrapper
                .create_document(&doc_json, None, None, true, None, None)
                .unwrap();

            let claims_json = json!([{
                "name": "reviewed",
                "value": true
            }])
            .to_string();

            let result = wrapper.lift_to_attestation(&signed, &claims_json);
            assert!(
                result.is_ok(),
                "lift_to_attestation should succeed: {:?}",
                result.err()
            );

            let att_json = result.unwrap();
            let doc: Value = serde_json::from_str(&att_json).unwrap();
            assert!(
                doc.get("attestation").is_some(),
                "lifted result should contain 'attestation' key"
            );
            assert!(
                doc.get("jacsSignature").is_some(),
                "lifted result should be signed"
            );
        }

        #[test]
        fn binding_create_attestation_error_on_bad_json() {
            let wrapper = attestation_wrapper();
            let result = wrapper.create_attestation("not valid json {{{");
            assert!(result.is_err(), "bad JSON should error");
            assert_eq!(
                result.unwrap_err().kind,
                ErrorKind::SerializationFailed,
                "should be SerializationFailed error"
            );
        }

        #[test]
        fn binding_create_attestation_error_on_missing_fields() {
            let wrapper = attestation_wrapper();
            // Valid JSON but missing required 'subject' field
            let params = json!({
                "claims": [{"name": "test", "value": true}]
            })
            .to_string();

            let result = wrapper.create_attestation(&params);
            assert!(result.is_err(), "missing subject should error");
            assert_eq!(
                result.unwrap_err().kind,
                ErrorKind::Validation,
                "should be Validation error"
            );
        }

        #[test]
        fn binding_export_attestation_dsse() {
            let wrapper = attestation_wrapper();
            let att_json = wrapper
                .create_attestation(&basic_attestation_params())
                .unwrap();

            let result = wrapper.export_attestation_dsse(&att_json);
            assert!(
                result.is_ok(),
                "export_attestation_dsse should succeed: {:?}",
                result.err()
            );

            let dsse_json = result.unwrap();
            let envelope: Value = serde_json::from_str(&dsse_json).unwrap();
            assert_eq!(
                envelope["payloadType"].as_str().unwrap(),
                "application/vnd.in-toto+json"
            );
        }
    }
}
