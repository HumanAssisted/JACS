//! Node.js bindings for JACS (JSON AI Communication Standard).
//!
//! This module provides Node.js bindings using NAPI-RS, built on top of the
//! shared `jacs-binding-core` crate for common functionality.
//!
//! ## Async-First API (v0.7.0)
//!
//! All JacsAgent methods have both async (default) and sync variants:
//! - `agent.load(configPath)` → returns `Promise<string>` (async, default)
//! - `agent.loadSync(configPath)` → returns `string` (sync, blocks event loop)
//!
//! Methods using V8 thread-local types (`Env`, `JsObject`) remain sync-only:
//! `signRequest`, `verifyResponse`, `verifyResponseWithAgentId`.

use std::sync::Arc;

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
// Async Task Types
// =============================================================================
// Generic task structs for running AgentWrapper methods off the main V8 thread.
// Uses NAPI AsyncTask which dispatches compute() to the libuv thread pool.
// Three variants by return type: String, bool, void.

type AgentFn<T> = Box<dyn FnOnce(&AgentWrapper) -> BindingResult<T> + Send>;

pub struct AgentStringTask {
    agent: Arc<AgentWrapper>,
    func: Option<AgentFn<String>>,
}

impl Task for AgentStringTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let f = self.func.take().expect("task already executed");
        f(&self.agent).map_err(to_napi_err)
    }

    fn resolve(&mut self, _env: Env, output: String) -> Result<String> {
        Ok(output)
    }
}

pub struct AgentBoolTask {
    agent: Arc<AgentWrapper>,
    func: Option<AgentFn<bool>>,
}

impl Task for AgentBoolTask {
    type Output = bool;
    type JsValue = bool;

    fn compute(&mut self) -> Result<Self::Output> {
        let f = self.func.take().expect("task already executed");
        f(&self.agent).map_err(to_napi_err)
    }

    fn resolve(&mut self, _env: Env, output: bool) -> Result<bool> {
        Ok(output)
    }
}

pub struct AgentVoidTask {
    agent: Arc<AgentWrapper>,
    func: Option<AgentFn<()>>,
}

impl Task for AgentVoidTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        let f = self.func.take().expect("task already executed");
        f(&self.agent).map_err(to_napi_err)
    }

    fn resolve(&mut self, _env: Env, _output: ()) -> Result<()> {
        Ok(())
    }
}

/// Standalone async task (no agent reference needed).
pub struct StandaloneStringTask {
    func: Option<Box<dyn FnOnce() -> BindingResult<String> + Send>>,
}

impl Task for StandaloneStringTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let f = self.func.take().expect("task already executed");
        f().map_err(to_napi_err)
    }

    fn resolve(&mut self, _env: Env, output: String) -> Result<String> {
        Ok(output)
    }
}

// =============================================================================
// JacsAgent Class - Primary API
// =============================================================================
// Each JacsAgent instance has its own independent state. This allows multiple
// agents to be used concurrently in the same Node.js process without shared
// mutable state. This is the recommended API for all code.
//
// The inner AgentWrapper is wrapped in Arc so async tasks can hold a reference
// while running on the libuv thread pool.
// =============================================================================

/// JacsAgent is a handle to a JACS agent instance.
/// Each instance maintains its own state and can be used independently.
/// This allows multiple agents to be used concurrently in the same process.
#[napi]
pub struct JacsAgent {
    inner: Arc<AgentWrapper>,
}

#[napi]
impl JacsAgent {
    /// Create a new empty JacsAgent instance.
    /// Call `load()` to initialize it with a configuration.
    #[napi(constructor)]
    pub fn new() -> Self {
        JacsAgent {
            inner: Arc::new(AgentWrapper::new()),
        }
    }

    // =========================================================================
    // Sync methods (explicit opt-in, blocks event loop)
    // Use these only when you need synchronous execution.
    // =========================================================================

    /// Load an agent from a configuration file (sync, blocks event loop).
    #[napi(js_name = "loadSync")]
    pub fn load_sync(&self, config_path: String) -> Result<String> {
        self.inner.load(config_path).to_napi()
    }

    /// Create an ephemeral in-memory agent (sync, blocks event loop).
    #[napi(js_name = "ephemeralSync")]
    pub fn ephemeral_sync(&self, algorithm: Option<String>) -> Result<String> {
        self.inner.ephemeral(algorithm.as_deref()).to_napi()
    }

    /// Sign an external agent's document (sync, blocks event loop).
    #[napi(js_name = "signAgentSync")]
    pub fn sign_agent_sync(
        &self,
        agent_string: String,
        public_key: Buffer,
        public_key_enc_type: String,
    ) -> Result<String> {
        self.inner
            .sign_agent(&agent_string, public_key.to_vec(), public_key_enc_type)
            .to_napi()
    }

    /// Verify a signature on arbitrary string data (sync, blocks event loop).
    #[napi(js_name = "verifyStringSync")]
    pub fn verify_string_sync(
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

    /// Sign arbitrary string data (sync, blocks event loop).
    #[napi(js_name = "signStringSync")]
    pub fn sign_string_sync(&self, data: String) -> Result<String> {
        self.inner.sign_string(&data).to_napi()
    }

    /// Verify this agent's signature and hash (sync, blocks event loop).
    #[napi(js_name = "verifyAgentSync")]
    pub fn verify_agent_sync(&self, agentfile: Option<String>) -> Result<bool> {
        self.inner.verify_agent(agentfile).to_napi()
    }

    /// Update the agent document (sync, blocks event loop).
    #[napi(js_name = "updateAgentSync")]
    pub fn update_agent_sync(&self, new_agent_string: String) -> Result<String> {
        self.inner.update_agent(&new_agent_string).to_napi()
    }

    /// Verify a document's signature and hash (sync, blocks event loop).
    #[napi(js_name = "verifyDocumentSync")]
    pub fn verify_document_sync(&self, document_string: String) -> Result<bool> {
        self.inner.verify_document(&document_string).to_napi()
    }

    /// Update an existing document (sync, blocks event loop).
    #[napi(js_name = "updateDocumentSync")]
    pub fn update_document_sync(
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

    /// Verify a document's signature with optional custom field (sync, blocks event loop).
    #[napi(js_name = "verifySignatureSync")]
    pub fn verify_signature_sync(
        &self,
        document_string: String,
        signature_field: Option<String>,
    ) -> Result<bool> {
        self.inner
            .verify_signature(&document_string, signature_field)
            .to_napi()
    }

    /// Create an agreement on a document (sync, blocks event loop).
    #[napi(js_name = "createAgreementSync")]
    pub fn create_agreement_sync(
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

    /// Create an agreement with extended options (sync, blocks event loop).
    #[napi(js_name = "createAgreementWithOptionsSync")]
    pub fn create_agreement_with_options_sync(
        &self,
        document_string: String,
        agentids: Vec<String>,
        question: Option<String>,
        context: Option<String>,
        agreement_fieldname: Option<String>,
        timeout: Option<String>,
        quorum: Option<u32>,
        required_algorithms: Option<Vec<String>>,
        minimum_strength: Option<String>,
    ) -> Result<String> {
        self.inner
            .create_agreement_with_options(
                &document_string,
                agentids,
                question,
                context,
                agreement_fieldname,
                timeout,
                quorum,
                required_algorithms,
                minimum_strength,
            )
            .to_napi()
    }

    /// Sign an agreement on a document (sync, blocks event loop).
    #[napi(js_name = "signAgreementSync")]
    pub fn sign_agreement_sync(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> Result<String> {
        self.inner
            .sign_agreement(&document_string, agreement_fieldname)
            .to_napi()
    }

    /// Create a new JACS document (sync, blocks event loop).
    #[napi(js_name = "createDocumentSync")]
    pub fn create_document_sync(
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

    /// Check an agreement on a document (sync, blocks event loop).
    #[napi(js_name = "checkAgreementSync")]
    pub fn check_agreement_sync(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> Result<String> {
        self.inner
            .check_agreement(&document_string, agreement_fieldname)
            .to_napi()
    }

    /// Get setup instructions (sync, blocks event loop).
    #[napi(js_name = "getSetupInstructionsSync")]
    pub fn get_setup_instructions_sync(&self, domain: String, ttl: Option<u32>) -> Result<String> {
        self.inner
            .get_setup_instructions(&domain, ttl.unwrap_or(3600))
            .to_napi()
    }

    /// Register with HAI.ai (sync, blocks event loop).
    #[napi(js_name = "registerWithHaiSync")]
    pub fn register_with_hai_sync(
        &self,
        api_key: Option<String>,
        hai_url: Option<String>,
        preview: Option<bool>,
    ) -> Result<String> {
        self.inner
            .register_with_hai(
                api_key.as_deref(),
                hai_url.as_deref().unwrap_or("https://hai.ai"),
                preview.unwrap_or(false),
            )
            .to_napi()
    }

    /// Returns diagnostic information as a JSON string.
    /// Lightweight — no async variant needed.
    #[napi]
    pub fn diagnostics(&self) -> String {
        self.inner.diagnostics()
    }

    /// Verify a document by ID (sync, blocks event loop).
    #[napi(js_name = "verifyDocumentByIdSync")]
    pub fn verify_document_by_id_sync(&self, document_id: String) -> Result<bool> {
        self.inner.verify_document_by_id(&document_id).to_napi()
    }

    /// Re-encrypt the agent's private key (sync, blocks event loop).
    #[napi(js_name = "reencryptKeySync")]
    pub fn reencrypt_key_sync(&self, old_password: String, new_password: String) -> Result<()> {
        self.inner
            .reencrypt_key(&old_password, &new_password)
            .to_napi()
    }

    // =========================================================================
    // V8-thread-only methods (cannot be async — use Env/JsObject)
    // =========================================================================

    /// Sign a request payload (wraps in a JACS document).
    /// Sync-only: uses V8 thread-local JsObject.
    #[napi(ts_args_type = "params: any")]
    pub fn sign_request(&self, env: Env, params_obj: JsObject) -> Result<String> {
        let payload_value = js_value_to_value(env, params_obj.into_unknown())?;
        self.inner.sign_request(payload_value).to_napi()
    }

    /// Verify a response payload.
    /// Sync-only: returns V8 thread-local JsObject.
    #[napi]
    pub fn verify_response(&self, env: Env, document_string: String) -> Result<JsObject> {
        let payload_serde_value: Value = self.inner.verify_response(document_string).to_napi()?;
        let js_value = value_to_js_value(env, &payload_serde_value)?;
        let mut result_obj = env.create_object()?;
        result_obj.set_named_property("payload", js_value)?;
        Ok(result_obj)
    }

    /// Verify a response payload and return the agent ID.
    /// Sync-only: returns V8 thread-local JsObject.
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

    // =========================================================================
    // Async methods (default, returns Promise<T>)
    // These run on the libuv thread pool via NAPI AsyncTask.
    // =========================================================================

    /// Load an agent from a configuration file.
    #[napi(js_name = "load", ts_return_type = "Promise<string>")]
    pub fn load_async(&self, config_path: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.load(config_path))),
        })
    }

    /// Create an ephemeral in-memory agent.
    #[napi(js_name = "ephemeral", ts_return_type = "Promise<string>")]
    pub fn ephemeral_async(&self, algorithm: Option<String>) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.ephemeral(algorithm.as_deref()))),
        })
    }

    /// Sign an external agent's document.
    #[napi(js_name = "signAgent", ts_return_type = "Promise<string>")]
    pub fn sign_agent_async(
        &self,
        agent_string: String,
        public_key: Buffer,
        public_key_enc_type: String,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        let pk = public_key.to_vec();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.sign_agent(&agent_string, pk, public_key_enc_type)
            })),
        })
    }

    /// Verify a signature on arbitrary string data.
    #[napi(js_name = "verifyString", ts_return_type = "Promise<boolean>")]
    pub fn verify_string_async(
        &self,
        data: String,
        signature_base64: String,
        public_key: Buffer,
        public_key_enc_type: String,
    ) -> AsyncTask<AgentBoolTask> {
        let agent = self.inner.clone();
        let pk = public_key.to_vec();
        AsyncTask::new(AgentBoolTask {
            agent,
            func: Some(Box::new(move |a| {
                a.verify_string(&data, &signature_base64, pk, public_key_enc_type)
            })),
        })
    }

    /// Sign arbitrary string data with this agent's private key.
    #[napi(js_name = "signString", ts_return_type = "Promise<string>")]
    pub fn sign_string_async(&self, data: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.sign_string(&data))),
        })
    }

    /// Verify this agent's signature and hash.
    #[napi(js_name = "verifyAgent", ts_return_type = "Promise<boolean>")]
    pub fn verify_agent_async(&self, agentfile: Option<String>) -> AsyncTask<AgentBoolTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentBoolTask {
            agent,
            func: Some(Box::new(move |a| a.verify_agent(agentfile))),
        })
    }

    /// Update the agent document with new data.
    #[napi(js_name = "updateAgent", ts_return_type = "Promise<string>")]
    pub fn update_agent_async(&self, new_agent_string: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.update_agent(&new_agent_string))),
        })
    }

    /// Verify a document's signature and hash.
    #[napi(js_name = "verifyDocument", ts_return_type = "Promise<boolean>")]
    pub fn verify_document_async(&self, document_string: String) -> AsyncTask<AgentBoolTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentBoolTask {
            agent,
            func: Some(Box::new(move |a| a.verify_document(&document_string))),
        })
    }

    /// Update an existing document.
    #[napi(js_name = "updateDocument", ts_return_type = "Promise<string>")]
    pub fn update_document_async(
        &self,
        document_key: String,
        new_document_string: String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.update_document(&document_key, &new_document_string, attachments, embed)
            })),
        })
    }

    /// Verify a document's signature with an optional custom signature field.
    #[napi(js_name = "verifySignature", ts_return_type = "Promise<boolean>")]
    pub fn verify_signature_async(
        &self,
        document_string: String,
        signature_field: Option<String>,
    ) -> AsyncTask<AgentBoolTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentBoolTask {
            agent,
            func: Some(Box::new(move |a| {
                a.verify_signature(&document_string, signature_field)
            })),
        })
    }

    /// Create an agreement on a document.
    #[napi(js_name = "createAgreement", ts_return_type = "Promise<string>")]
    pub fn create_agreement_async(
        &self,
        document_string: String,
        agentids: Vec<String>,
        question: Option<String>,
        context: Option<String>,
        agreement_fieldname: Option<String>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.create_agreement(
                    &document_string,
                    agentids,
                    question,
                    context,
                    agreement_fieldname,
                )
            })),
        })
    }

    /// Create an agreement with extended options.
    #[napi(
        js_name = "createAgreementWithOptions",
        ts_return_type = "Promise<string>"
    )]
    pub fn create_agreement_with_options_async(
        &self,
        document_string: String,
        agentids: Vec<String>,
        question: Option<String>,
        context: Option<String>,
        agreement_fieldname: Option<String>,
        timeout: Option<String>,
        quorum: Option<u32>,
        required_algorithms: Option<Vec<String>>,
        minimum_strength: Option<String>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.create_agreement_with_options(
                    &document_string,
                    agentids,
                    question,
                    context,
                    agreement_fieldname,
                    timeout,
                    quorum,
                    required_algorithms,
                    minimum_strength,
                )
            })),
        })
    }

    /// Sign an agreement on a document.
    #[napi(js_name = "signAgreement", ts_return_type = "Promise<string>")]
    pub fn sign_agreement_async(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.sign_agreement(&document_string, agreement_fieldname)
            })),
        })
    }

    /// Create a new JACS document.
    #[napi(js_name = "createDocument", ts_return_type = "Promise<string>")]
    pub fn create_document_async(
        &self,
        document_string: String,
        custom_schema: Option<String>,
        outputfilename: Option<String>,
        no_save: Option<bool>,
        attachments: Option<String>,
        embed: Option<bool>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.create_document(
                    &document_string,
                    custom_schema,
                    outputfilename,
                    no_save.unwrap_or(false),
                    attachments.as_deref(),
                    embed,
                )
            })),
        })
    }

    /// Check an agreement on a document.
    #[napi(js_name = "checkAgreement", ts_return_type = "Promise<string>")]
    pub fn check_agreement_async(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.check_agreement(&document_string, agreement_fieldname)
            })),
        })
    }

    /// Get setup instructions for DNS records, DNSSEC, and HAI registration.
    #[napi(js_name = "getSetupInstructions", ts_return_type = "Promise<string>")]
    pub fn get_setup_instructions_async(
        &self,
        domain: String,
        ttl: Option<u32>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.get_setup_instructions(&domain, ttl.unwrap_or(3600))
            })),
        })
    }

    /// Register this agent with HAI.ai.
    #[napi(js_name = "registerWithHai", ts_return_type = "Promise<string>")]
    pub fn register_with_hai_async(
        &self,
        api_key: Option<String>,
        hai_url: Option<String>,
        preview: Option<bool>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.register_with_hai(
                    api_key.as_deref(),
                    hai_url.as_deref().unwrap_or("https://hai.ai"),
                    preview.unwrap_or(false),
                )
            })),
        })
    }

    /// Verify a document looked up by ID from storage.
    #[napi(js_name = "verifyDocumentById", ts_return_type = "Promise<boolean>")]
    pub fn verify_document_by_id_async(&self, document_id: String) -> AsyncTask<AgentBoolTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentBoolTask {
            agent,
            func: Some(Box::new(move |a| a.verify_document_by_id(&document_id))),
        })
    }

    /// Re-encrypt the agent's private key with a new password.
    #[napi(js_name = "reencryptKey", ts_return_type = "Promise<void>")]
    pub fn reencrypt_key_async(
        &self,
        old_password: String,
        new_password: String,
    ) -> AsyncTask<AgentVoidTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentVoidTask {
            agent,
            func: Some(Box::new(move |a| {
                a.reencrypt_key(&old_password, &new_password)
            })),
        })
    }
}

// ============================================================================
// Standalone utility functions (using binding-core)
// ============================================================================

/// Hash a string using SHA-256. Sync-only (pure CPU, fast).
#[napi]
pub fn hash_string(data: String) -> Result<String> {
    Ok(jacs_binding_core::hash_string(&data))
}

/// Create a JACS configuration object. Sync-only (minimal CPU).
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

/// Create a JACS agent programmatically (sync, blocks event loop).
#[napi(js_name = "createAgentSync")]
pub fn create_agent_sync(
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

/// Create a JACS agent programmatically (async, returns Promise).
#[napi(js_name = "createAgent", ts_return_type = "Promise<string>")]
pub fn create_agent_async(
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
) -> AsyncTask<StandaloneStringTask> {
    AsyncTask::new(StandaloneStringTask {
        func: Some(Box::new(move || {
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
        })),
    })
}

// ============================================================================
// Trust Store Functions (using binding-core)
// Sync-only — these are fast local file lookups.
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
// Audit (security audit and health checks)
// ============================================================================

/// Run a security audit (sync, blocks event loop).
#[napi(js_name = "auditSync")]
pub fn audit_sync(config_path: Option<String>, recent_n: Option<u32>) -> Result<String> {
    jacs_binding_core::audit(config_path.as_deref(), recent_n).to_napi()
}

/// Run a security audit (async, returns Promise).
#[napi(js_name = "audit", ts_return_type = "Promise<string>")]
pub fn audit_async(
    config_path: Option<String>,
    recent_n: Option<u32>,
) -> AsyncTask<StandaloneStringTask> {
    AsyncTask::new(StandaloneStringTask {
        func: Some(Box::new(move || {
            jacs_binding_core::audit(config_path.as_deref(), recent_n)
        })),
    })
}

// ============================================================================
// Legacy API (deprecated - use JacsAgent class instead)
// These functions use a global singleton for backwards compatibility.
// They will be removed in a future version.
// ============================================================================

use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref LEGACY_AGENT: Arc<Mutex<AgentWrapper>> = Arc::new(Mutex::new(AgentWrapper::new()));
}

/// @deprecated Use `new JacsAgent()` and `agent.load()` instead.
#[napi(js_name = "legacyLoad")]
pub fn legacy_load(config_path: String) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to lock agent: {}", e),
        )
    })?;
    agent.load(config_path).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi(js_name = "legacySignAgent")]
pub fn legacy_sign_agent(
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
#[napi(js_name = "legacyVerifyString")]
pub fn legacy_verify_string(
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
#[napi(js_name = "legacySignString")]
pub fn legacy_sign_string(data: String) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent.sign_string(&data).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi(js_name = "legacyVerifyAgent")]
pub fn legacy_verify_agent(agentfile: Option<String>) -> Result<bool> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent.verify_agent(agentfile).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi(js_name = "legacyUpdateAgent")]
pub fn legacy_update_agent(new_agent_string: String) -> Result<String> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent.update_agent(&new_agent_string).to_napi()
}

/// Result of verify_document_standalone. Exposed to JS as { valid, signerId, timestamp, agentVersion }.
#[napi(object)]
pub struct VerifyStandaloneResult {
    pub valid: bool,
    /// Signer agent ID; exposed to JS as signerId (camelCase).
    pub signer_id: String,
    /// Signing timestamp from jacsSignature.date.
    pub timestamp: String,
    /// Signer agent version from jacsSignature.agentVersion.
    pub agent_version: String,
}

/// Verify a signed JACS document without loading an agent.
/// Returns { valid, signerId }. Does not use global agent state.
#[napi]
pub fn verify_document_standalone(
    signed_document: String,
    key_resolution: Option<String>,
    data_directory: Option<String>,
    key_directory: Option<String>,
) -> Result<VerifyStandaloneResult> {
    let r = jacs_binding_core::verify_document_standalone(
        &signed_document,
        key_resolution.as_deref(),
        data_directory.as_deref(),
        key_directory.as_deref(),
    )
    .to_napi()?;
    Ok(VerifyStandaloneResult {
        valid: r.valid,
        signer_id: r.signer_id,
        timestamp: r.timestamp,
        agent_version: r.agent_version,
    })
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi(js_name = "legacyVerifyDocument")]
pub fn legacy_verify_document(document_string: String) -> Result<bool> {
    let agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;
    agent.verify_document(&document_string).to_napi()
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi(js_name = "legacyUpdateDocument")]
pub fn legacy_update_document(
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
#[napi(js_name = "legacyVerifySignature")]
pub fn legacy_verify_signature(
    document_string: String,
    signature_field: Option<String>,
) -> Result<bool> {
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
#[napi(js_name = "legacyCreateAgreement")]
pub fn legacy_create_agreement(
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
#[napi(js_name = "legacySignAgreement")]
pub fn legacy_sign_agreement(
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
#[napi(js_name = "legacyCreateDocument")]
pub fn legacy_create_document(
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
#[napi(js_name = "legacyCheckAgreement")]
pub fn legacy_check_agreement(
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
#[napi(ts_args_type = "params: any", js_name = "legacySignRequest")]
pub fn legacy_sign_request(env: Env, params_obj: JsObject) -> Result<String> {
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
#[napi(js_name = "legacyVerifyResponse")]
pub fn legacy_verify_response(env: Env, document_string: String) -> Result<JsObject> {
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
#[napi(js_name = "legacyVerifyResponseWithAgentId")]
pub fn legacy_verify_response_with_agent_id(env: Env, document_string: String) -> Result<JsObject> {
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

/// Build a verification URL for a signed JACS document.
#[napi]
pub fn generate_verify_link(document: String, base_url: String) -> Result<String> {
    jacs_binding_core::hai::generate_verify_link(&document, &base_url)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))
}
