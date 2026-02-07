//! Node.js bindings for JACS (JSON AI Communication Standard).
//!
//! This module provides Node.js bindings using NAPI-RS, built on top of the
//! shared `jacs-binding-core` crate for common functionality.

use jacs_binding_core::{AgentWrapper, BindingCoreError, BindingResult};
use napi::JsObject;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde_json::Value;

// Declare the module so it's recognized at the crate root
pub mod conversion_utils;
use conversion_utils::{js_value_to_value, value_to_js_value};

// =============================================================================
// Error Conversion: BindingCoreError -> napi::Error
// =============================================================================

/// Convert a BindingCoreError to a napi::Error.
fn to_napi_err(e: BindingCoreError) -> Error {
    Error::new(Status::GenericFailure, e.message)
}

/// Extension trait to convert BindingResult to napi::Result.
trait ToNapiResult<T> {
    fn to_napi(self) -> Result<T>;
}

impl<T> ToNapiResult<T> for BindingResult<T> {
    fn to_napi(self) -> Result<T> {
        self.map_err(to_napi_err)
    }
}

// =============================================================================
// JacsAgent Class - Primary API for concurrent usage
// =============================================================================
// Each JacsAgent instance has its own independent state. This allows multiple
// agents to be used concurrently in the same Node.js process without shared
// mutable state. This is the recommended API for all code.
// =============================================================================

/// JacsAgent is a handle to a JACS agent instance.
/// Each instance maintains its own state and can be used independently.
/// This allows multiple agents to be used concurrently in the same process.
#[napi]
pub struct JacsAgent {
    inner: AgentWrapper,
}

#[napi]
impl JacsAgent {
    /// Create a new empty JacsAgent instance.
    /// Call `load()` to initialize it with a configuration.
    #[napi(constructor)]
    pub fn new() -> Self {
        JacsAgent {
            inner: AgentWrapper::new(),
        }
    }

    /// Load an agent from a configuration file.
    #[napi]
    pub fn load(&self, config_path: String) -> Result<String> {
        self.inner.load(config_path).to_napi()
    }

    /// Sign an external agent's document with this agent's registration signature.
    #[napi]
    pub fn sign_agent(
        &self,
        agent_string: String,
        public_key: Buffer,
        public_key_enc_type: String,
    ) -> Result<String> {
        self.inner
            .sign_agent(&agent_string, public_key.to_vec(), public_key_enc_type)
            .to_napi()
    }

    /// Verify a signature on arbitrary string data.
    #[napi]
    pub fn verify_string(
        &self,
        data: String,
        signature_base64: String,
        public_key: Buffer,
        public_key_enc_type: String,
    ) -> Result<bool> {
        self.inner
            .verify_string(
                &data,
                &signature_base64,
                public_key.to_vec(),
                public_key_enc_type,
            )
            .to_napi()
    }

    /// Sign arbitrary string data with this agent's private key.
    #[napi]
    pub fn sign_string(&self, data: String) -> Result<String> {
        self.inner.sign_string(&data).to_napi()
    }

    /// Verify this agent's signature and hash.
    #[napi]
    pub fn verify_agent(&self, agentfile: Option<String>) -> Result<bool> {
        self.inner.verify_agent(agentfile).to_napi()
    }

    /// Update the agent document with new data.
    #[napi]
    pub fn update_agent(&self, new_agent_string: String) -> Result<String> {
        self.inner.update_agent(&new_agent_string).to_napi()
    }

    /// Verify a document's signature and hash.
    #[napi]
    pub fn verify_document(&self, document_string: String) -> Result<bool> {
        self.inner.verify_document(&document_string).to_napi()
    }

    /// Update an existing document.
    #[napi]
    pub fn update_document(
        &self,
        document_key: String,
        new_document_string: String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> Result<String> {
        self.inner
            .update_document(&document_key, &new_document_string, attachments, embed)
            .to_napi()
    }

    /// Verify a document's signature with an optional custom signature field.
    #[napi]
    pub fn verify_signature(
        &self,
        document_string: String,
        signature_field: Option<String>,
    ) -> Result<bool> {
        self.inner
            .verify_signature(&document_string, signature_field)
            .to_napi()
    }

    /// Create an agreement on a document.
    #[napi]
    pub fn create_agreement(
        &self,
        document_string: String,
        agentids: Vec<String>,
        question: Option<String>,
        context: Option<String>,
        agreement_fieldname: Option<String>,
    ) -> Result<String> {
        self.inner
            .create_agreement(
                &document_string,
                agentids,
                question,
                context,
                agreement_fieldname,
            )
            .to_napi()
    }

    /// Sign an agreement on a document.
    #[napi]
    pub fn sign_agreement(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> Result<String> {
        self.inner
            .sign_agreement(&document_string, agreement_fieldname)
            .to_napi()
    }

    /// Create a new JACS document.
    #[napi]
    pub fn create_document(
        &self,
        document_string: String,
        custom_schema: Option<String>,
        outputfilename: Option<String>,
        no_save: Option<bool>,
        attachments: Option<String>,
        embed: Option<bool>,
    ) -> Result<String> {
        self.inner
            .create_document(
                &document_string,
                custom_schema,
                outputfilename,
                no_save.unwrap_or(false),
                attachments.as_deref(),
                embed,
            )
            .to_napi()
    }

    /// Check an agreement on a document.
    #[napi]
    pub fn check_agreement(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> Result<String> {
        self.inner
            .check_agreement(&document_string, agreement_fieldname)
            .to_napi()
    }

    /// Verify a document looked up by ID from storage.
    ///
    /// The document_id should be in "uuid:version" format.
    #[napi]
    pub fn verify_document_by_id(&self, document_id: String) -> Result<bool> {
        self.inner.verify_document_by_id(&document_id).to_napi()
    }

    /// Re-encrypt the agent's private key with a new password.
    #[napi]
    pub fn reencrypt_key(&self, old_password: String, new_password: String) -> Result<()> {
        self.inner
            .reencrypt_key(&old_password, &new_password)
            .to_napi()
    }

    /// Sign a request payload (wraps in a JACS document).
    #[napi(ts_args_type = "params: any")]
    pub fn sign_request(&self, env: Env, params_obj: JsObject) -> Result<String> {
        let payload_value = js_value_to_value(env, params_obj.into_unknown())?;
        self.inner.sign_request(payload_value).to_napi()
    }

    /// Verify a response payload.
    #[napi]
    pub fn verify_response(&self, env: Env, document_string: String) -> Result<JsObject> {
        let payload_serde_value: Value = self.inner.verify_response(document_string).to_napi()?;

        let js_value = value_to_js_value(env, &payload_serde_value)?;

        // Create a wrapper object and set the payload as a property
        let mut result_obj = env.create_object()?;
        result_obj.set_named_property("payload", js_value)?;

        Ok(result_obj)
    }

    /// Verify a response payload and return the agent ID.
    #[napi]
    pub fn verify_response_with_agent_id(
        &self,
        env: Env,
        document_string: String,
    ) -> Result<JsObject> {
        let (payload_serde_value, agent_id) = self
            .inner
            .verify_response_with_agent_id(document_string)
            .to_napi()?;

        let js_payload = value_to_js_value(env, &payload_serde_value)?;
        let js_agent_id = env.create_string(&agent_id)?;

        let mut result_obj = env.create_object()?;
        result_obj.set_named_property("agent_id", js_agent_id)?;
        result_obj.set_named_property("payload", js_payload)?;

        Ok(result_obj)
    }
}

// ============================================================================
// Standalone utility functions (using binding-core)
// ============================================================================

/// Hash a string using SHA-256.
#[napi]
pub fn hash_string(data: String) -> Result<String> {
    Ok(jacs_binding_core::hash_string(&data))
}

/// Create a JACS configuration object.
#[napi]
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
) -> Result<String> {
    jacs_binding_core::create_config(
        jacs_use_security,
        jacs_data_directory,
        jacs_key_directory,
        jacs_agent_private_key_filename,
        jacs_agent_public_key_filename,
        jacs_agent_key_algorithm,
        jacs_private_key_password,
        jacs_agent_id_and_version,
        jacs_default_storage,
    )
    .to_napi()
}

/// Create a JACS agent programmatically (non-interactive).
#[napi]
pub fn create_agent(
    name: String,
    password: String,
    algorithm: Option<String>,
    data_directory: Option<String>,
    key_directory: Option<String>,
    config_path: Option<String>,
    agent_type: Option<String>,
    description: Option<String>,
    domain: Option<String>,
    default_storage: Option<String>,
) -> Result<String> {
    jacs_binding_core::create_agent_programmatic(
        &name,
        &password,
        algorithm.as_deref(),
        data_directory.as_deref(),
        key_directory.as_deref(),
        config_path.as_deref(),
        agent_type.as_deref(),
        description.as_deref(),
        domain.as_deref(),
        default_storage.as_deref(),
    )
    .to_napi()
}

// ============================================================================
// Trust Store Functions (using binding-core)
// ============================================================================

/// Add an agent to the local trust store.
#[napi]
pub fn trust_agent(agent_json: String) -> Result<String> {
    jacs_binding_core::trust_agent(&agent_json).to_napi()
}

/// List all trusted agent IDs.
#[napi]
pub fn list_trusted_agents() -> Result<Vec<String>> {
    jacs_binding_core::list_trusted_agents().to_napi()
}

/// Remove an agent from the trust store.
#[napi]
pub fn untrust_agent(agent_id: String) -> Result<()> {
    jacs_binding_core::untrust_agent(&agent_id).to_napi()
}

/// Check if an agent is in the trust store.
#[napi]
pub fn is_trusted(agent_id: String) -> bool {
    jacs_binding_core::is_trusted(&agent_id)
}

/// Get a trusted agent's JSON document.
#[napi]
pub fn get_trusted_agent(agent_id: String) -> Result<String> {
    jacs_binding_core::get_trusted_agent(&agent_id).to_napi()
}

// ============================================================================
// Legacy API (deprecated - use JacsAgent class instead)
// These functions use a global singleton for backwards compatibility.
// They will be removed in a future version.
// ============================================================================

use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};

lazy_static! {
    static ref LEGACY_AGENT: Arc<Mutex<AgentWrapper>> = Arc::new(Mutex::new(AgentWrapper::new()));
}

/// @deprecated Use `new JacsAgent()` and `agent.load()` instead.
#[napi]
pub fn load(config_path: String) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to lock agent: {}", e),
        )
    })?;
    agent.load(config_path).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn sign_agent(
    agent_string: String,
    public_key: Buffer,
    public_key_enc_type: String,
) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent
        .sign_agent(&agent_string, public_key.to_vec(), public_key_enc_type)
        .to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_string(
    data: String,
    signature_base64: String,
    public_key: Buffer,
    public_key_enc_type: String,
) -> Result<bool> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent
        .verify_string(
            &data,
            &signature_base64,
            public_key.to_vec(),
            public_key_enc_type,
        )
        .to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn sign_string(data: String) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent.sign_string(&data).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_agent(agentfile: Option<String>) -> Result<bool> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent.verify_agent(agentfile).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn update_agent(new_agent_string: String) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent.update_agent(&new_agent_string).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_document(document_string: String) -> Result<bool> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent.verify_document(&document_string).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn update_document(
    document_key: String,
    new_document_string: String,
    attachments: Option<Vec<String>>,
    embed: Option<bool>,
) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent
        .update_document(&document_key, &new_document_string, attachments, embed)
        .to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_signature(document_string: String, signature_field: Option<String>) -> Result<bool> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent
        .verify_signature(&document_string, signature_field)
        .to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn create_agreement(
    document_string: String,
    agentids: Vec<String>,
    question: Option<String>,
    context: Option<String>,
    agreement_fieldname: Option<String>,
) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent
        .create_agreement(
            &document_string,
            agentids,
            question,
            context,
            agreement_fieldname,
        )
        .to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn sign_agreement(
    document_string: String,
    agreement_fieldname: Option<String>,
) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent
        .sign_agreement(&document_string, agreement_fieldname)
        .to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn create_document(
    document_string: String,
    custom_schema: Option<String>,
    outputfilename: Option<String>,
    no_save: Option<bool>,
    attachments: Option<String>,
    embed: Option<bool>,
) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent
        .create_document(
            &document_string,
            custom_schema,
            outputfilename,
            no_save.unwrap_or(false),
            attachments.as_deref(),
            embed,
        )
        .to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn check_agreement(
    document_string: String,
    agreement_fieldname: Option<String>,
) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent
        .check_agreement(&document_string, agreement_fieldname)
        .to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi(ts_args_type = "params: any")]
pub fn sign_request(env: Env, params_obj: JsObject) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    let payload_value = js_value_to_value(env, params_obj.into_unknown())?;
    agent.sign_request(payload_value).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_response(env: Env, document_string: String) -> Result<JsObject> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let payload_serde_value: Value = agent.verify_response(document_string).to_napi()?;

    let js_value = value_to_js_value(env, &payload_serde_value)?;

    let mut result_obj = env.create_object()?;
    result_obj.set_named_property("payload", js_value)?;

    Ok(result_obj)
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_response_with_agent_id(env: Env, document_string: String) -> Result<JsObject> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let (payload_serde_value, agent_id) = agent
        .verify_response_with_agent_id(document_string)
        .to_napi()?;

    let js_payload = value_to_js_value(env, &payload_serde_value)?;
    let js_agent_id = env.create_string(&agent_id)?;

    let mut result_obj = env.create_object()?;
    result_obj.set_named_property("agent_id", js_agent_id)?;
    result_obj.set_named_property("payload", js_payload)?;

    Ok(result_obj)
}

// ============================================================================
// HAI Functions (using binding-core HAI module)
// ============================================================================

/// Information about a public key fetched from HAI key service.
///
/// This struct contains the public key data and metadata returned by
/// the HAI key distribution service.
#[napi(object)]
pub struct RemotePublicKeyInfo {
    /// The raw public key bytes (DER encoded).
    pub public_key: Buffer,
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
///   the most recent version. If not provided, defaults to "latest".
///
/// # Returns
///
/// Returns a `RemotePublicKeyInfo` object containing the public key, algorithm, and hash.
///
/// # Environment Variables
///
/// * `HAI_KEYS_BASE_URL` - Base URL for the key service. Defaults to `https://keys.hai.ai`.
///
/// # Example
///
/// ```javascript
/// const { fetchRemoteKey } = require('@hai-ai/jacs');
///
/// const keyInfo = fetchRemoteKey('550e8400-e29b-41d4-a716-446655440000', 'latest');
/// console.log('Algorithm:', keyInfo.algorithm);
/// console.log('Hash:', keyInfo.publicKeyHash);
/// ```
#[napi]
pub fn fetch_remote_key(agent_id: String, version: Option<String>) -> Result<RemotePublicKeyInfo> {
    let version_str = version.as_deref().unwrap_or("latest");

    let key_info = jacs_binding_core::fetch_remote_key(&agent_id, version_str)
        .map_err(|e| Error::new(Status::GenericFailure, e.message))?;

    Ok(RemotePublicKeyInfo {
        public_key: Buffer::from(key_info.public_key),
        algorithm: key_info.algorithm,
        public_key_hash: key_info.public_key_hash,
        agent_id: key_info.agent_id,
        version: key_info.version,
    })
}
