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

use jacs_binding_core::{AgentWrapper, BindingCoreError, BindingResult, SimpleAgentWrapper};
use napi::bindgen_prelude::*;
use napi::{JsObject, JsUnknown};
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
// SimpleAgent Async Task Types (Task 11)
// =============================================================================
// `SimpleAgentWrapper` is `Clone` (Arc-backed inside), so we just clone it into
// each task. The closure does the real work on the libuv thread pool. The
// task's `Output` is a `serde_json::Value` produced off-thread; `resolve()`
// then converts it into a JS value on the V8 thread.

type SimpleAgentFn<T> = Box<dyn FnOnce(&SimpleAgentWrapper) -> BindingResult<T> + Send>;

/// Async task whose result is a `serde_json::Value` parsed from a JSON string
/// returned by SimpleAgentWrapper. Resolves to a JS object (parsed) on the
/// main thread.
pub struct SimpleAgentJsonTask {
    agent: SimpleAgentWrapper,
    func: Option<SimpleAgentFn<Value>>,
}

impl Task for SimpleAgentJsonTask {
    type Output = Value;
    type JsValue = JsUnknown;

    fn compute(&mut self) -> Result<Self::Output> {
        let f = self.func.take().expect("task already executed");
        f(&self.agent).map_err(to_napi_err)
    }

    fn resolve(&mut self, env: Env, output: Value) -> Result<JsUnknown> {
        value_to_js_value(env, &output)
    }
}

/// Async task whose result is an owned JSON/document string.
pub struct SimpleAgentStringTask {
    agent: SimpleAgentWrapper,
    func: Option<SimpleAgentFn<String>>,
}

impl Task for SimpleAgentStringTask {
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

/// Async task whose result is `Option<String>` (used by extractMediaSignature).
pub struct SimpleAgentOptionStringTask {
    agent: SimpleAgentWrapper,
    func: Option<SimpleAgentFn<Option<String>>>,
}

impl Task for SimpleAgentOptionStringTask {
    type Output = Option<String>;
    type JsValue = Option<String>;

    fn compute(&mut self) -> Result<Self::Output> {
        let f = self.func.take().expect("task already executed");
        f(&self.agent).map_err(to_napi_err)
    }

    fn resolve(&mut self, _env: Env, output: Option<String>) -> Result<Option<String>> {
        Ok(output)
    }
}

/// Parse a JSON string returned by `SimpleAgentWrapper::*_json` into a
/// `serde_json::Value`. Maps parse failures to a binding-core error so they
/// propagate through `to_napi_err` consistently.
fn parse_json_value(json_str: &str, context: &str) -> BindingResult<Value> {
    serde_json::from_str(json_str).map_err(|e| {
        BindingCoreError::serialization_failed(format!("{}: failed to parse JSON: {}", context, e))
    })
}

// =============================================================================
// JacsAgent Class - Primary API
// =============================================================================
// Each JacsAgent instance has its own loaded agent state. This allows multiple
// agents to coexist in the same Node.js process. Password-protected operations
// are synchronized internally while the Rust core still resolves decryption
// passwords through JACS_PRIVATE_KEY_PASSWORD.
//
// The inner AgentWrapper is wrapped in Arc so async tasks can hold a reference
// while running on the libuv thread pool.
// =============================================================================

/// JacsAgent is a handle to a JACS agent instance.
/// Each instance maintains its own loaded state and can be used independently.
/// This allows multiple agents to be used in the same process.
#[napi]
pub struct JacsAgent {
    inner: Arc<AgentWrapper>,
}

#[napi]
impl JacsAgent {
    /// Create a new empty JacsAgent instance.
    /// Call `load()` to initialize it with a configuration.
    #[napi(constructor)]
    #[allow(clippy::new_without_default)]
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

    /// Load an agent from a configuration file and return canonical metadata (sync).
    #[napi(js_name = "loadWithInfoSync")]
    pub fn load_with_info_sync(&self, config_path: String) -> Result<String> {
        self.inner.load_with_info(config_path).to_napi()
    }

    /// Configure a per-instance private-key password for later load/sign calls.
    #[napi(js_name = "setPrivateKeyPassword")]
    pub fn set_private_key_password(&self, password: Option<String>) -> Result<()> {
        self.inner.set_private_key_password(password).to_napi()
    }

    /// Export the agent's identity JSON for P2P exchange (sync).
    #[napi(js_name = "exportAgent")]
    pub fn export_agent(&self) -> Result<String> {
        self.inner.export_agent().to_napi()
    }

    /// Get the public key as a PEM string (sync).
    #[napi(js_name = "getPublicKeyPem")]
    pub fn get_public_key_pem(&self) -> Result<String> {
        self.inner.get_public_key_pem().to_napi()
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
    #[allow(clippy::too_many_arguments)]
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

    /// Load a document by ID from storage (sync, blocks event loop).
    #[napi(js_name = "getDocumentByIdSync")]
    pub fn get_document_by_id_sync(&self, document_id: String) -> Result<String> {
        self.inner.get_document_by_id(&document_id).to_napi()
    }

    /// Rotate the agent's keys (sync, blocks event loop).
    #[napi(js_name = "rotateKeysSync")]
    pub fn rotate_keys_sync(&self, algorithm: Option<String>) -> Result<String> {
        self.inner.rotate_keys(algorithm.as_deref()).to_napi()
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

    /// Load an agent from a configuration file and return canonical metadata.
    #[napi(js_name = "loadWithInfo", ts_return_type = "Promise<string>")]
    pub fn load_with_info_async(&self, config_path: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.load_with_info(config_path))),
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
    #[allow(clippy::too_many_arguments)]
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

    /// Get setup instructions for DNS records and DNSSEC.
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

    /// Verify a document looked up by ID from storage.
    #[napi(js_name = "verifyDocumentById", ts_return_type = "Promise<boolean>")]
    pub fn verify_document_by_id_async(&self, document_id: String) -> AsyncTask<AgentBoolTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentBoolTask {
            agent,
            func: Some(Box::new(move |a| a.verify_document_by_id(&document_id))),
        })
    }

    /// Load a document by ID from storage.
    #[napi(js_name = "getDocumentById", ts_return_type = "Promise<string>")]
    pub fn get_document_by_id_async(&self, document_id: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.get_document_by_id(&document_id))),
        })
    }

    /// Rotate the agent's cryptographic keys.
    #[napi(js_name = "rotateKeys", ts_return_type = "Promise<string>")]
    pub fn rotate_keys_async(&self, algorithm: Option<String>) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.rotate_keys(algorithm.as_deref()))),
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

    // =========================================================================
    // Format Conversion (stateless -- no agent lock needed)
    // =========================================================================

    /// Convert a JSON string to YAML.
    #[napi(js_name = "toYamlSync")]
    pub fn to_yaml_sync(&self, json_str: String) -> Result<String> {
        jacs::convert::jacs_to_yaml(&json_str).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Convert a YAML string to pretty-printed JSON.
    #[napi(js_name = "fromYamlSync")]
    pub fn from_yaml_sync(&self, yaml_str: String) -> Result<String> {
        jacs::convert::yaml_to_jacs(&yaml_str).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Convert a JSON string to a self-contained HTML document.
    #[napi(js_name = "toHtmlSync")]
    pub fn to_html_sync(&self, json_str: String) -> Result<String> {
        jacs::convert::jacs_to_html(&json_str).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Extract JSON from an HTML document produced by toHtml().
    #[napi(js_name = "fromHtmlSync")]
    pub fn from_html_sync(&self, html_str: String) -> Result<String> {
        jacs::convert::html_to_jacs(&html_str).map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Convert a YAML string to JSON and verify the resulting document.
    /// Returns true if verification succeeds.
    #[napi(js_name = "verifyYamlSync")]
    pub fn verify_yaml_sync(&self, yaml_str: String) -> Result<bool> {
        let json_str = jacs::convert::yaml_to_jacs(&yaml_str)
            .map_err(|e| Error::from_reason(e.to_string()))?;
        self.inner.verify_document(&json_str).to_napi()
    }

    // =========================================================================
    // Format Conversion (async variants -- stateless, no agent lock needed)
    // =========================================================================

    /// Convert a JSON string to YAML (async).
    #[napi(js_name = "toYaml", ts_return_type = "Promise<string>")]
    pub fn to_yaml_async(&self, json_str: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |_| {
                jacs::convert::jacs_to_yaml(&json_str).map_err(|e| BindingCoreError {
                    message: e.to_string(),
                    kind: jacs_binding_core::ErrorKind::SerializationFailed,
                })
            })),
        })
    }

    /// Convert a YAML string to pretty-printed JSON (async).
    #[napi(js_name = "fromYaml", ts_return_type = "Promise<string>")]
    pub fn from_yaml_async(&self, yaml_str: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |_| {
                jacs::convert::yaml_to_jacs(&yaml_str).map_err(|e| BindingCoreError {
                    message: e.to_string(),
                    kind: jacs_binding_core::ErrorKind::SerializationFailed,
                })
            })),
        })
    }

    /// Convert a JSON string to a self-contained HTML document (async).
    #[napi(js_name = "toHtml", ts_return_type = "Promise<string>")]
    pub fn to_html_async(&self, json_str: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |_| {
                jacs::convert::jacs_to_html(&json_str).map_err(|e| BindingCoreError {
                    message: e.to_string(),
                    kind: jacs_binding_core::ErrorKind::SerializationFailed,
                })
            })),
        })
    }

    /// Extract JSON from an HTML document produced by toHtml() (async).
    #[napi(js_name = "fromHtml", ts_return_type = "Promise<string>")]
    pub fn from_html_async(&self, html_str: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |_| {
                jacs::convert::html_to_jacs(&html_str).map_err(|e| BindingCoreError {
                    message: e.to_string(),
                    kind: jacs_binding_core::ErrorKind::SerializationFailed,
                })
            })),
        })
    }

    /// Convert a YAML string to JSON and verify the resulting document (async).
    #[napi(js_name = "verifyYaml", ts_return_type = "Promise<boolean>")]
    pub fn verify_yaml_async(&self, yaml_str: String) -> AsyncTask<AgentBoolTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentBoolTask {
            agent,
            func: Some(Box::new(move |a| {
                let json_str =
                    jacs::convert::yaml_to_jacs(&yaml_str).map_err(|e| BindingCoreError {
                        message: e.to_string(),
                        kind: jacs_binding_core::ErrorKind::SerializationFailed,
                    })?;
                a.verify_document(&json_str)
            })),
        })
    }
}

// =============================================================================
// A2A Protocol Methods — only available with the `a2a` feature
// =============================================================================

#[cfg(feature = "a2a")]
#[napi]
impl JacsAgent {
    // =========================================================================
    // A2A Protocol Methods (sync)
    // =========================================================================

    /// Export this agent as an A2A Agent Card (sync, blocks event loop).
    #[napi(js_name = "exportAgentCardSync")]
    pub fn export_agent_card_sync(&self) -> Result<String> {
        self.inner.export_agent_card().to_napi()
    }

    /// Generate the native .well-known A2A document set (sync, blocks event loop).
    #[napi(js_name = "generateWellKnownDocumentsSync")]
    pub fn generate_well_known_documents_sync(
        &self,
        a2a_algorithm: Option<String>,
    ) -> Result<String> {
        self.inner
            .generate_well_known_documents(a2a_algorithm.as_deref())
            .to_napi()
    }

    /// Wrap an A2A artifact with JACS provenance signature (sync).
    #[napi(js_name = "wrapA2aArtifactSync")]
    #[allow(deprecated)]
    pub fn wrap_a2a_artifact_sync(
        &self,
        artifact_json: String,
        artifact_type: String,
        parent_signatures_json: Option<String>,
    ) -> Result<String> {
        self.inner
            .wrap_a2a_artifact(
                &artifact_json,
                &artifact_type,
                parent_signatures_json.as_deref(),
            )
            .to_napi()
    }

    /// Sign an A2A artifact (sync). Alias for wrapA2aArtifactSync.
    #[napi(js_name = "signArtifactSync")]
    pub fn sign_artifact_sync(
        &self,
        artifact_json: String,
        artifact_type: String,
        parent_signatures_json: Option<String>,
    ) -> Result<String> {
        self.inner
            .sign_artifact(
                &artifact_json,
                &artifact_type,
                parent_signatures_json.as_deref(),
            )
            .to_napi()
    }

    /// Verify a JACS-wrapped A2A artifact (sync).
    #[napi(js_name = "verifyA2aArtifactSync")]
    pub fn verify_a2a_artifact_sync(&self, wrapped_json: String) -> Result<String> {
        self.inner.verify_a2a_artifact(&wrapped_json).to_napi()
    }

    /// Verify a JACS-wrapped A2A artifact with policy-aware trust assessment (sync).
    #[napi(js_name = "verifyA2aArtifactWithPolicySync")]
    pub fn verify_a2a_artifact_with_policy_sync(
        &self,
        wrapped_json: String,
        agent_card_json: String,
        policy: String,
    ) -> Result<String> {
        self.inner
            .verify_a2a_artifact_with_policy(&wrapped_json, &agent_card_json, &policy)
            .to_napi()
    }

    /// Assess a remote agent's trust level based on its Agent Card and a policy (sync).
    #[napi(js_name = "assessA2aAgentSync")]
    pub fn assess_a2a_agent_sync(&self, agent_card_json: String, policy: String) -> Result<String> {
        self.inner
            .assess_a2a_agent(&agent_card_json, &policy)
            .to_napi()
    }

    // =========================================================================
    // A2A Protocol Methods (async)
    // =========================================================================

    /// Export this agent as an A2A Agent Card.
    #[napi(js_name = "exportAgentCard", ts_return_type = "Promise<string>")]
    pub fn export_agent_card_async(&self) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.export_agent_card())),
        })
    }

    /// Generate the native .well-known A2A document set.
    #[napi(
        js_name = "generateWellKnownDocuments",
        ts_return_type = "Promise<string>"
    )]
    pub fn generate_well_known_documents_async(
        &self,
        a2a_algorithm: Option<String>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.generate_well_known_documents(a2a_algorithm.as_deref())
            })),
        })
    }

    /// Wrap an A2A artifact with JACS provenance signature.
    #[napi(js_name = "wrapA2aArtifact", ts_return_type = "Promise<string>")]
    pub fn wrap_a2a_artifact_async(
        &self,
        artifact_json: String,
        artifact_type: String,
        parent_signatures_json: Option<String>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                #[allow(deprecated)]
                a.wrap_a2a_artifact(
                    &artifact_json,
                    &artifact_type,
                    parent_signatures_json.as_deref(),
                )
            })),
        })
    }

    /// Sign an A2A artifact. Alias for wrapA2aArtifact.
    #[napi(js_name = "signArtifact", ts_return_type = "Promise<string>")]
    pub fn sign_artifact_async(
        &self,
        artifact_json: String,
        artifact_type: String,
        parent_signatures_json: Option<String>,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.sign_artifact(
                    &artifact_json,
                    &artifact_type,
                    parent_signatures_json.as_deref(),
                )
            })),
        })
    }

    /// Verify a JACS-wrapped A2A artifact.
    #[napi(js_name = "verifyA2aArtifact", ts_return_type = "Promise<string>")]
    pub fn verify_a2a_artifact_async(&self, wrapped_json: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.verify_a2a_artifact(&wrapped_json))),
        })
    }

    /// Verify a JACS-wrapped A2A artifact with policy-aware trust assessment.
    #[napi(
        js_name = "verifyA2aArtifactWithPolicy",
        ts_return_type = "Promise<string>"
    )]
    pub fn verify_a2a_artifact_with_policy_async(
        &self,
        wrapped_json: String,
        agent_card_json: String,
        policy: String,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.verify_a2a_artifact_with_policy(&wrapped_json, &agent_card_json, &policy)
            })),
        })
    }

    /// Assess a remote agent's trust level based on its Agent Card and a policy.
    #[napi(js_name = "assessA2aAgent", ts_return_type = "Promise<string>")]
    pub fn assess_a2a_agent_async(
        &self,
        agent_card_json: String,
        policy: String,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.assess_a2a_agent(&agent_card_json, &policy)
            })),
        })
    }
}

#[napi]
impl JacsAgent {
    // =========================================================================
    // HAI SDK Methods (sync)
    // =========================================================================

    /// Build a JACS auth header for HTTP requests (sync, blocks event loop).
    #[napi(js_name = "buildAuthHeaderSync")]
    pub fn build_auth_header_sync(&self) -> Result<String> {
        self.inner.build_auth_header().to_napi()
    }

    /// Deterministically serialize JSON per RFC 8785 / JCS (sync, blocks event loop).
    #[napi(js_name = "canonicalizeJsonSync")]
    pub fn canonicalize_json_sync(&self, json_string: String) -> Result<String> {
        self.inner.canonicalize_json(&json_string).to_napi()
    }

    /// Sign a response payload, returning a signed envelope JSON (sync, blocks event loop).
    #[napi(js_name = "signResponseSync")]
    pub fn sign_response_sync(&self, payload_json: String) -> Result<String> {
        self.inner.sign_response(&payload_json).to_napi()
    }

    /// Encode a document as URL-safe base64 for verification (sync).
    #[napi(js_name = "encodeVerifyPayloadSync")]
    pub fn encode_verify_payload_sync(&self, document: String) -> Result<String> {
        self.inner.encode_verify_payload(&document).to_napi()
    }

    /// Decode a URL-safe base64 verification payload (sync).
    #[napi(js_name = "decodeVerifyPayloadSync")]
    pub fn decode_verify_payload_sync(&self, encoded: String) -> Result<String> {
        self.inner.decode_verify_payload(&encoded).to_napi()
    }

    /// Extract the document ID from a JACS-signed document (sync).
    #[napi(js_name = "extractDocumentIdSync")]
    pub fn extract_document_id_sync(&self, document: String) -> Result<String> {
        self.inner.extract_document_id(&document).to_napi()
    }

    /// Unwrap and verify a signed event against known server public keys (sync, blocks event loop).
    #[napi(js_name = "unwrapSignedEventSync")]
    pub fn unwrap_signed_event_sync(
        &self,
        event_json: String,
        server_keys_json: String,
    ) -> Result<String> {
        self.inner
            .unwrap_signed_event(&event_json, &server_keys_json)
            .to_napi()
    }

    // =========================================================================
    // HAI SDK Methods (async)
    // =========================================================================

    /// Build a JACS auth header for HTTP requests.
    #[napi(js_name = "buildAuthHeader", ts_return_type = "Promise<string>")]
    pub fn build_auth_header_async(&self) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.build_auth_header())),
        })
    }

    /// Deterministically serialize JSON per RFC 8785 / JCS.
    #[napi(js_name = "canonicalizeJson", ts_return_type = "Promise<string>")]
    pub fn canonicalize_json_async(&self, json_string: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.canonicalize_json(&json_string))),
        })
    }

    /// Sign a response payload, returning a signed envelope JSON.
    #[napi(js_name = "signResponse", ts_return_type = "Promise<string>")]
    pub fn sign_response_async(&self, payload_json: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.sign_response(&payload_json))),
        })
    }

    /// Encode a document as URL-safe base64 for verification.
    #[napi(js_name = "encodeVerifyPayload", ts_return_type = "Promise<string>")]
    pub fn encode_verify_payload_async(&self, document: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.encode_verify_payload(&document))),
        })
    }

    /// Decode a URL-safe base64 verification payload.
    #[napi(js_name = "decodeVerifyPayload", ts_return_type = "Promise<string>")]
    pub fn decode_verify_payload_async(&self, encoded: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.decode_verify_payload(&encoded))),
        })
    }

    /// Extract the document ID from a JACS-signed document.
    #[napi(js_name = "extractDocumentId", ts_return_type = "Promise<string>")]
    pub fn extract_document_id_async(&self, document: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.extract_document_id(&document))),
        })
    }

    /// Unwrap and verify a signed event against known server public keys.
    #[napi(js_name = "unwrapSignedEvent", ts_return_type = "Promise<string>")]
    pub fn unwrap_signed_event_async(
        &self,
        event_json: String,
        server_keys_json: String,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.unwrap_signed_event(&event_json, &server_keys_json)
            })),
        })
    }
}

// =============================================================================
// Attestation methods on JacsAgent (feature-gated, separate impl block)
// =============================================================================
// In a separate `impl` block so the #[napi] macro only generates registration
// code when the attestation feature is enabled.

#[cfg(feature = "attestation")]
#[napi]
impl JacsAgent {
    /// Create a signed attestation document (sync).
    #[napi(js_name = "createAttestationSync")]
    pub fn create_attestation_sync(&self, params_json: String) -> Result<String> {
        self.inner.create_attestation(&params_json).to_napi()
    }

    /// Verify an attestation -- local tier (sync).
    #[napi(js_name = "verifyAttestationSync")]
    pub fn verify_attestation_sync(&self, document_key: String) -> Result<String> {
        self.inner.verify_attestation(&document_key).to_napi()
    }

    /// Verify an attestation -- full tier (sync).
    #[napi(js_name = "verifyAttestationFullSync")]
    pub fn verify_attestation_full_sync(&self, document_key: String) -> Result<String> {
        self.inner.verify_attestation_full(&document_key).to_napi()
    }

    /// Lift a signed document to attestation (sync).
    #[napi(js_name = "liftToAttestationSync")]
    pub fn lift_to_attestation_sync(
        &self,
        signed_doc_json: String,
        claims_json: String,
    ) -> Result<String> {
        self.inner
            .lift_to_attestation(&signed_doc_json, &claims_json)
            .to_napi()
    }

    /// Export an attestation as a DSSE envelope (sync).
    #[napi(js_name = "exportAttestationDsseSync")]
    pub fn export_attestation_dsse_sync(&self, attestation_json: String) -> Result<String> {
        self.inner
            .export_attestation_dsse(&attestation_json)
            .to_napi()
    }

    /// Create a signed attestation document (async).
    #[napi(js_name = "createAttestation", ts_return_type = "Promise<string>")]
    pub fn create_attestation_async(&self, params_json: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.create_attestation(&params_json))),
        })
    }

    /// Verify an attestation -- local tier (async).
    #[napi(js_name = "verifyAttestation", ts_return_type = "Promise<string>")]
    pub fn verify_attestation_async(&self, document_key: String) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.verify_attestation(&document_key))),
        })
    }

    /// Verify an attestation -- full tier (async).
    #[napi(js_name = "verifyAttestationFull", ts_return_type = "Promise<string>")]
    pub fn verify_attestation_full_async(
        &self,
        document_key: String,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.verify_attestation_full(&document_key))),
        })
    }

    /// Lift a signed document to attestation (async).
    #[napi(js_name = "liftToAttestation", ts_return_type = "Promise<string>")]
    pub fn lift_to_attestation_async(
        &self,
        signed_doc_json: String,
        claims_json: String,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.lift_to_attestation(&signed_doc_json, &claims_json)
            })),
        })
    }

    /// Export an attestation as a DSSE envelope (async).
    #[napi(js_name = "exportAttestationDsse", ts_return_type = "Promise<string>")]
    pub fn export_attestation_dsse_async(
        &self,
        attestation_json: String,
    ) -> AsyncTask<AgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(AgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.export_attestation_dsse(&attestation_json)
            })),
        })
    }
}

// =============================================================================
// JacsSimpleAgent Class - Simplified API using SimpleAgentWrapper
// =============================================================================
// This class wraps SimpleAgentWrapper from binding-core, providing the narrow
// SimpleAgent contract with JSON-in/JSON-out FFI boundary. This ensures all
// language bindings share the same FFI contract.
// =============================================================================

/// JacsSimpleAgent is a simplified JACS agent for the narrow contract.
///
/// It exposes the same methods as Python's SimpleAgent and Go's simple API,
/// all backed by `SimpleAgentWrapper` from `jacs-binding-core`.
#[napi(js_name = "JacsSimpleAgent")]
pub struct JacsSimpleAgent {
    inner: SimpleAgentWrapper,
}

#[napi]
impl JacsSimpleAgent {
    /// Create a new agent with persistent identity.
    /// Returns a JSON string with agent info (agent_id, name, public_key_path, config_path).
    #[napi(factory, js_name = "create")]
    pub fn create_agent(
        name: String,
        purpose: Option<String>,
        key_algorithm: Option<String>,
    ) -> Result<JacsSimpleAgent> {
        let (wrapper, _info_json) =
            SimpleAgentWrapper::create(&name, purpose.as_deref(), key_algorithm.as_deref())
                .to_napi()?;
        Ok(JacsSimpleAgent { inner: wrapper })
    }

    /// Get the agent info JSON from the last create/ephemeral call.
    /// Must be called after create() or ephemeral().
    #[napi(js_name = "getAgentId")]
    pub fn get_agent_id(&self) -> Result<String> {
        self.inner.get_agent_id().to_napi()
    }

    /// Load an existing agent from a config file.
    #[napi(factory, js_name = "load")]
    pub fn load_agent(
        config_path: Option<String>,
        strict: Option<bool>,
    ) -> Result<JacsSimpleAgent> {
        let wrapper = SimpleAgentWrapper::load(config_path.as_deref(), strict).to_napi()?;
        Ok(JacsSimpleAgent { inner: wrapper })
    }

    /// Create an ephemeral (in-memory, throwaway) agent.
    #[napi(factory, js_name = "ephemeral")]
    pub fn ephemeral_agent(algorithm: Option<String>) -> Result<JacsSimpleAgent> {
        let (wrapper, _info_json) =
            SimpleAgentWrapper::ephemeral(algorithm.as_deref()).to_napi()?;
        Ok(JacsSimpleAgent { inner: wrapper })
    }

    /// Create an agent with full programmatic control via JSON parameters.
    #[napi(factory, js_name = "createWithParams")]
    pub fn create_with_params(params_json: String) -> Result<JacsSimpleAgent> {
        let (wrapper, _info_json) =
            SimpleAgentWrapper::create_with_params(&params_json).to_napi()?;
        Ok(JacsSimpleAgent { inner: wrapper })
    }

    /// Whether the agent is in strict mode.
    #[napi(js_name = "isStrict")]
    pub fn is_strict(&self) -> bool {
        self.inner.is_strict()
    }

    /// Config file path, if loaded from disk.
    #[napi(js_name = "configPath")]
    pub fn config_path(&self) -> Option<String> {
        self.inner.config_path()
    }

    /// Get the JACS key ID (signing key identifier).
    #[napi(js_name = "keyId")]
    pub fn key_id(&self) -> Result<String> {
        self.inner.key_id().to_napi()
    }

    /// Export the agent's identity JSON for P2P exchange.
    #[napi(js_name = "exportAgent")]
    pub fn export_agent(&self) -> Result<String> {
        self.inner.export_agent().to_napi()
    }

    /// Get the public key as a PEM string.
    #[napi(js_name = "getPublicKeyPem")]
    pub fn get_public_key_pem(&self) -> Result<String> {
        self.inner.get_public_key_pem().to_napi()
    }

    /// Get the public key as base64-encoded raw bytes.
    #[napi(js_name = "getPublicKeyBase64")]
    pub fn get_public_key_base64(&self) -> Result<String> {
        self.inner.get_public_key_base64().to_napi()
    }

    /// Runtime diagnostic info as a JSON string.
    #[napi]
    pub fn diagnostics(&self) -> String {
        self.inner.diagnostics()
    }

    /// Export this agent's did:wba identifier.
    #[napi(js_name = "exportW3cDid")]
    pub fn export_w3c_did(&self, origin: Option<String>) -> Result<String> {
        self.inner.export_w3c_did(origin.as_deref()).to_napi()
    }

    /// Export this agent's did:wba DID document as JSON.
    #[napi(js_name = "exportW3cDidDocument")]
    pub fn export_w3c_did_document(&self, origin: Option<String>) -> Result<String> {
        self.inner
            .export_w3c_did_document_json(origin.as_deref())
            .to_napi()
    }

    /// Export this agent's W3C agent description as JSON.
    #[napi(js_name = "exportW3cAgentDescription")]
    pub fn export_w3c_agent_description(&self, origin: Option<String>) -> Result<String> {
        self.inner
            .export_w3c_agent_description_json(origin.as_deref())
            .to_napi()
    }

    /// Generate W3C well-known discovery documents as JSON keyed by path.
    #[napi(js_name = "generateW3cWellKnown")]
    pub fn generate_w3c_well_known(&self, origin: Option<String>) -> Result<String> {
        self.inner
            .generate_w3c_well_known_json(origin.as_deref())
            .to_napi()
    }

    /// Create a request-bound DID authentication proof from JSON params.
    #[napi(js_name = "signW3cRequest")]
    pub fn sign_w3c_request(&self, params_json: String) -> Result<String> {
        self.inner.sign_w3c_request_json(&params_json).to_napi()
    }

    /// Verify a request-bound DID authentication proof.
    #[napi(js_name = "verifyW3cRequest")]
    pub fn verify_w3c_request(
        &self,
        proof_json: String,
        did_document_json: String,
        body: Option<String>,
        max_age_seconds: Option<u32>,
        method: Option<String>,
        url: Option<String>,
    ) -> Result<String> {
        self.inner
            .verify_w3c_request_json(
                &proof_json,
                &did_document_json,
                body.as_deref(),
                u64::from(max_age_seconds.unwrap_or(300)),
                method.as_deref(),
                url.as_deref(),
            )
            .to_napi()
    }

    /// Verify the agent's own document signature. Returns JSON VerificationResult.
    #[napi(js_name = "verifySelf")]
    pub fn verify_self(&self) -> Result<String> {
        self.inner.verify_self().to_napi()
    }

    /// Verify a signed document JSON string. Returns JSON VerificationResult.
    #[napi(js_name = "verify")]
    pub fn verify_json(&self, signed_document: String) -> Result<String> {
        self.inner.verify_json(&signed_document).to_napi()
    }

    /// Verify a signed document with an explicit public key (base64-encoded).
    /// Returns JSON VerificationResult.
    #[napi(js_name = "verifyWithKey")]
    pub fn verify_with_key(
        &self,
        signed_document: String,
        public_key_base64: String,
    ) -> Result<String> {
        self.inner
            .verify_with_key_json(&signed_document, &public_key_base64)
            .to_napi()
    }

    /// Verify a stored document by its ID (e.g., "uuid:version").
    /// Returns JSON VerificationResult.
    #[napi(js_name = "verifyById")]
    pub fn verify_by_id(&self, document_id: String) -> Result<String> {
        self.inner.verify_by_id_json(&document_id).to_napi()
    }

    /// Sign a JSON message string. Returns the signed JACS document JSON.
    #[napi(js_name = "signMessage")]
    pub fn sign_message(&self, data_json: String) -> Result<String> {
        self.inner.sign_message_json(&data_json).to_napi()
    }

    /// Sign raw bytes and return the signature as base64.
    #[napi(js_name = "signRawBytes")]
    pub fn sign_raw_bytes(&self, data: Buffer) -> Result<String> {
        self.inner.sign_raw_bytes_base64(data.as_ref()).to_napi()
    }

    /// Sign a file with optional content embedding.
    /// Returns the signed JACS document JSON.
    #[napi(js_name = "signFile")]
    pub fn sign_file(&self, file_path: String, embed: bool) -> Result<String> {
        self.inner.sign_file_json(&file_path, embed).to_napi()
    }

    // =========================================================================
    // Agreement v2 (feature-gated in Rust, enabled for the default Node build)
    // =========================================================================

    /// Create a standalone JACS agreement v2 document.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "createAgreementV2", ts_return_type = "Promise<string>")]
    pub fn create_agreement_v2_async(
        &self,
        input_json: String,
    ) -> AsyncTask<SimpleAgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(SimpleAgentStringTask {
            agent,
            func: Some(Box::new(move |a| a.create_agreement_v2_json(&input_json))),
        })
    }

    /// Sync variant of createAgreementV2.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "createAgreementV2Sync")]
    pub fn create_agreement_v2_sync(&self, input_json: String) -> Result<String> {
        self.inner.create_agreement_v2_json(&input_json).to_napi()
    }

    /// Apply an agreement v2 mutation and return the successor document JSON.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "applyAgreementV2", ts_return_type = "Promise<string>")]
    pub fn apply_agreement_v2_async(
        &self,
        document_json: String,
        mutation_json: String,
    ) -> AsyncTask<SimpleAgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(SimpleAgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.apply_agreement_v2_json(&document_json, &mutation_json)
            })),
        })
    }

    /// Sync variant of applyAgreementV2.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "applyAgreementV2Sync")]
    pub fn apply_agreement_v2_sync(
        &self,
        document_json: String,
        mutation_json: String,
    ) -> Result<String> {
        self.inner
            .apply_agreement_v2_json(&document_json, &mutation_json)
            .to_napi()
    }

    /// Add this agent's signer, witness, or notary agreement signature.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "signAgreementV2", ts_return_type = "Promise<string>")]
    pub fn sign_agreement_v2_async(
        &self,
        document_json: String,
        role: Option<String>,
    ) -> AsyncTask<SimpleAgentStringTask> {
        let agent = self.inner.clone();
        let role = role.unwrap_or_else(|| "signer".to_string());
        AsyncTask::new(SimpleAgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.sign_agreement_v2_json(&document_json, &role)
            })),
        })
    }

    /// Sync variant of signAgreementV2.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "signAgreementV2Sync")]
    pub fn sign_agreement_v2_sync(
        &self,
        document_json: String,
        role: Option<String>,
    ) -> Result<String> {
        let role = role.unwrap_or_else(|| "signer".to_string());
        self.inner
            .sign_agreement_v2_json(&document_json, &role)
            .to_napi()
    }

    /// Verify agreement v2 hash, role, status, transcript, and signature invariants.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "verifyAgreementV2", ts_return_type = "Promise<any>")]
    pub fn verify_agreement_v2_async(
        &self,
        document_json: String,
    ) -> AsyncTask<SimpleAgentJsonTask> {
        let agent = self.inner.clone();
        AsyncTask::new(SimpleAgentJsonTask {
            agent,
            func: Some(Box::new(move |a| {
                let json = a.verify_agreement_v2_json(&document_json)?;
                parse_json_value(&json, "agreement v2 verification report")
            })),
        })
    }

    /// Sync variant of verifyAgreementV2.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "verifyAgreementV2Sync")]
    pub fn verify_agreement_v2_sync(&self, env: Env, document_json: String) -> Result<JsUnknown> {
        let json = self
            .inner
            .verify_agreement_v2_json(&document_json)
            .to_napi()?;
        let value =
            parse_json_value(&json, "agreement v2 verification report").map_err(to_napi_err)?;
        value_to_js_value(env, &value)
    }

    /// Detect whether two successor versions are transcript-only mergeable.
    #[cfg(feature = "agreements")]
    #[napi(
        js_name = "detectAgreementV2BranchConflict",
        ts_return_type = "Promise<any>"
    )]
    pub fn detect_agreement_v2_branch_conflict_async(
        &self,
        base_document_json: String,
        left_document_json: String,
        right_document_json: String,
    ) -> AsyncTask<SimpleAgentJsonTask> {
        let agent = self.inner.clone();
        AsyncTask::new(SimpleAgentJsonTask {
            agent,
            func: Some(Box::new(move |a| {
                let json = a.detect_agreement_v2_branch_conflict_json(
                    &base_document_json,
                    &left_document_json,
                    &right_document_json,
                )?;
                parse_json_value(&json, "agreement v2 branch analysis")
            })),
        })
    }

    /// Sync variant of detectAgreementV2BranchConflict.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "detectAgreementV2BranchConflictSync")]
    pub fn detect_agreement_v2_branch_conflict_sync(
        &self,
        env: Env,
        base_document_json: String,
        left_document_json: String,
        right_document_json: String,
    ) -> Result<JsUnknown> {
        let json = self
            .inner
            .detect_agreement_v2_branch_conflict_json(
                &base_document_json,
                &left_document_json,
                &right_document_json,
            )
            .to_napi()?;
        let value = parse_json_value(&json, "agreement v2 branch analysis").map_err(to_napi_err)?;
        value_to_js_value(env, &value)
    }

    /// Auto-merge two transcript-only branches.
    #[cfg(feature = "agreements")]
    #[napi(
        js_name = "mergeAgreementV2TranscriptBranches",
        ts_return_type = "Promise<string>"
    )]
    pub fn merge_agreement_v2_transcript_branches_async(
        &self,
        base_document_json: String,
        left_document_json: String,
        right_document_json: String,
    ) -> AsyncTask<SimpleAgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(SimpleAgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.merge_agreement_v2_transcript_branches_json(
                    &base_document_json,
                    &left_document_json,
                    &right_document_json,
                )
            })),
        })
    }

    /// Sync variant of mergeAgreementV2TranscriptBranches.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "mergeAgreementV2TranscriptBranchesSync")]
    pub fn merge_agreement_v2_transcript_branches_sync(
        &self,
        base_document_json: String,
        left_document_json: String,
        right_document_json: String,
    ) -> Result<String> {
        self.inner
            .merge_agreement_v2_transcript_branches_json(
                &base_document_json,
                &left_document_json,
                &right_document_json,
            )
            .to_napi()
    }

    /// Resolve a conflicting branch by applying an explicit resolution mutation.
    #[cfg(feature = "agreements")]
    #[napi(
        js_name = "resolveAgreementV2BranchConflict",
        ts_return_type = "Promise<string>"
    )]
    pub fn resolve_agreement_v2_branch_conflict_async(
        &self,
        base_document_json: String,
        previous_document_json: String,
        side_branch_document_json: String,
        mutation_json: String,
    ) -> AsyncTask<SimpleAgentStringTask> {
        let agent = self.inner.clone();
        AsyncTask::new(SimpleAgentStringTask {
            agent,
            func: Some(Box::new(move |a| {
                a.resolve_agreement_v2_branch_conflict_json(
                    &base_document_json,
                    &previous_document_json,
                    &side_branch_document_json,
                    &mutation_json,
                )
            })),
        })
    }

    /// Sync variant of resolveAgreementV2BranchConflict.
    #[cfg(feature = "agreements")]
    #[napi(js_name = "resolveAgreementV2BranchConflictSync")]
    pub fn resolve_agreement_v2_branch_conflict_sync(
        &self,
        base_document_json: String,
        previous_document_json: String,
        side_branch_document_json: String,
        mutation_json: String,
    ) -> Result<String> {
        self.inner
            .resolve_agreement_v2_branch_conflict_json(
                &base_document_json,
                &previous_document_json,
                &side_branch_document_json,
                &mutation_json,
            )
            .to_napi()
    }

    // =========================================================================
    // Format Conversion
    // =========================================================================

    /// Convert a JSON string to YAML.
    #[napi(js_name = "toYaml")]
    pub fn to_yaml(&self, json_str: String) -> Result<String> {
        self.inner.to_yaml(&json_str).to_napi()
    }

    /// Convert a YAML string to pretty-printed JSON.
    #[napi(js_name = "fromYaml")]
    pub fn from_yaml(&self, yaml_str: String) -> Result<String> {
        self.inner.from_yaml(&yaml_str).to_napi()
    }

    /// Convert a JSON string to a self-contained HTML document.
    #[napi(js_name = "toHtml")]
    pub fn to_html(&self, json_str: String) -> Result<String> {
        self.inner.to_html(&json_str).to_napi()
    }

    /// Extract JSON from an HTML document produced by toHtml().
    #[napi(js_name = "fromHtml")]
    pub fn from_html(&self, html_str: String) -> Result<String> {
        self.inner.from_html(&html_str).to_napi()
    }

    /// Convert a YAML string to JSON and verify the resulting document.
    /// Equivalent to calling fromYaml() followed by verify().
    #[napi(js_name = "verifyYaml")]
    pub fn verify_yaml(&self, yaml_str: String) -> Result<String> {
        let json_str = self.inner.from_yaml(&yaml_str).to_napi()?;
        self.inner.verify_json(&json_str).to_napi()
    }

    // =========================================================================
    // Key Management
    // =========================================================================

    /// Rotate the agent's cryptographic keys.
    /// Optionally change the signing algorithm.
    /// Returns a JSON string of the RotationResult.
    #[napi(js_name = "rotateKeys")]
    pub fn rotate_keys(&self, algorithm: Option<String>) -> Result<String> {
        self.inner.rotate_keys(algorithm.as_deref()).to_napi()
    }

    // =========================================================================
    // Inline text + media signing (Task 11 — PRD §3.1, §3.2, §4.1, §4.2).
    // =========================================================================
    //
    // Each public verb on JacsSimpleAgent has THREE NAPI bindings:
    //   1. The async parity name (e.g., signTextFile) — matches binding-core
    //      `sign_text_file_json` after _json suffix stripping.
    //   2. The short alias (e.g., signText) — matches CLI verb / README usage.
    //   3. A *Sync variant for both names that blocks the V8 thread.
    //
    // Both names go through the same SimpleAgentWrapper method.

    /// Sign a text/markdown file in place by appending an inline JACS
    /// signature block. Returns the parsed `SignTextOutcome` object.
    #[napi(js_name = "signTextFile", ts_return_type = "Promise<SignTextOutcome>")]
    pub fn sign_text_file_async(
        &self,
        file_path: String,
        no_backup: Option<bool>,
    ) -> AsyncTask<SimpleAgentJsonTask> {
        let agent = self.inner.clone();
        let opts = build_sign_text_opts(no_backup.unwrap_or(false));
        AsyncTask::new(SimpleAgentJsonTask {
            agent,
            func: Some(Box::new(move |a| {
                let json = a.sign_text_file_json(&file_path, &opts)?;
                parse_json_value(&json, "sign_text_file outcome")
            })),
        })
    }

    /// Short alias for [`signTextFile`]. Both wrap `sign_text_file_json`.
    #[napi(js_name = "signText", ts_return_type = "Promise<SignTextOutcome>")]
    pub fn sign_text_async(
        &self,
        file_path: String,
        no_backup: Option<bool>,
    ) -> AsyncTask<SimpleAgentJsonTask> {
        self.sign_text_file_async(file_path, no_backup)
    }

    /// Sync variant of [`signTextFile`]. Returns parsed JSON via `serde_json::Value`.
    #[napi(js_name = "signTextFileSync")]
    pub fn sign_text_file_sync(
        &self,
        env: Env,
        file_path: String,
        no_backup: Option<bool>,
    ) -> Result<JsUnknown> {
        let opts = build_sign_text_opts(no_backup.unwrap_or(false));
        let json = self
            .inner
            .sign_text_file_json(&file_path, &opts)
            .to_napi()?;
        let value = parse_json_value(&json, "sign_text_file outcome").map_err(to_napi_err)?;
        value_to_js_value(env, &value)
    }

    /// Sync variant of the [`signText`] alias.
    #[napi(js_name = "signTextSync")]
    pub fn sign_text_sync(
        &self,
        env: Env,
        file_path: String,
        no_backup: Option<bool>,
    ) -> Result<JsUnknown> {
        self.sign_text_file_sync(env, file_path, no_backup)
    }

    /// Verify an inline JACS signature in a text/markdown file. Returns the
    /// parsed `VerifyTextResult` object. With `{ strict: true }`, missing-
    /// signature rejects the Promise with /no JACS signature found/.
    #[napi(
        js_name = "verifyTextFile",
        ts_return_type = "Promise<VerifyTextResult>"
    )]
    pub fn verify_text_file_async(
        &self,
        file_path: String,
        opts: Option<VerifyTextOptsNapi>,
    ) -> AsyncTask<SimpleAgentJsonTask> {
        let agent = self.inner.clone();
        let opts_json = build_verify_text_opts_json(opts);
        AsyncTask::new(SimpleAgentJsonTask {
            agent,
            func: Some(Box::new(move |a| {
                let json = a.verify_text_file_json(&file_path, &opts_json)?;
                parse_json_value(&json, "verify_text_file result")
            })),
        })
    }

    /// Short alias for [`verifyTextFile`].
    #[napi(js_name = "verifyText", ts_return_type = "Promise<VerifyTextResult>")]
    pub fn verify_text_async(
        &self,
        file_path: String,
        opts: Option<VerifyTextOptsNapi>,
    ) -> AsyncTask<SimpleAgentJsonTask> {
        self.verify_text_file_async(file_path, opts)
    }

    /// Sync variant of [`verifyTextFile`].
    #[napi(js_name = "verifyTextFileSync")]
    pub fn verify_text_file_sync(
        &self,
        env: Env,
        file_path: String,
        opts: Option<VerifyTextOptsNapi>,
    ) -> Result<JsUnknown> {
        let opts_json = build_verify_text_opts_json(opts);
        let json = self
            .inner
            .verify_text_file_json(&file_path, &opts_json)
            .to_napi()?;
        let value = parse_json_value(&json, "verify_text_file result").map_err(to_napi_err)?;
        value_to_js_value(env, &value)
    }

    /// Sync variant of the [`verifyText`] alias.
    #[napi(js_name = "verifyTextSync")]
    pub fn verify_text_sync(
        &self,
        env: Env,
        file_path: String,
        opts: Option<VerifyTextOptsNapi>,
    ) -> Result<JsUnknown> {
        self.verify_text_file_sync(env, file_path, opts)
    }

    /// Sign a PNG / JPEG / WebP image, embedding a JACS signature. Returns
    /// the parsed `SignImageOutcome` object (out_path, signer_id, format).
    #[napi(js_name = "signImage", ts_return_type = "Promise<SignImageOutcome>")]
    pub fn sign_image_async(
        &self,
        input_path: String,
        output_path: String,
        opts: Option<SignImageOptsNapi>,
    ) -> AsyncTask<SimpleAgentJsonTask> {
        let agent = self.inner.clone();
        let opts_json = build_sign_image_opts_json(opts);
        AsyncTask::new(SimpleAgentJsonTask {
            agent,
            func: Some(Box::new(move |a| {
                let json = a.sign_image_json(&input_path, &output_path, &opts_json)?;
                parse_json_value(&json, "sign_image outcome")
            })),
        })
    }

    /// Sync variant of [`signImage`].
    #[napi(js_name = "signImageSync")]
    pub fn sign_image_sync(
        &self,
        env: Env,
        input_path: String,
        output_path: String,
        opts: Option<SignImageOptsNapi>,
    ) -> Result<JsUnknown> {
        let opts_json = build_sign_image_opts_json(opts);
        let json = self
            .inner
            .sign_image_json(&input_path, &output_path, &opts_json)
            .to_napi()?;
        let value = parse_json_value(&json, "sign_image outcome").map_err(to_napi_err)?;
        value_to_js_value(env, &value)
    }

    /// Verify an embedded JACS signature in a PNG / JPEG / WebP image.
    /// Returns the parsed `VerifyImageResult` object. With `{ strict: true }`,
    /// missing-signature rejects the Promise with /no JACS signature found/.
    #[napi(js_name = "verifyImage", ts_return_type = "Promise<VerifyImageResult>")]
    pub fn verify_image_async(
        &self,
        file_path: String,
        opts: Option<VerifyImageOptsNapi>,
    ) -> AsyncTask<SimpleAgentJsonTask> {
        let agent = self.inner.clone();
        let opts_json = build_verify_image_opts_json(opts);
        AsyncTask::new(SimpleAgentJsonTask {
            agent,
            func: Some(Box::new(move |a| {
                let json = a.verify_image_json(&file_path, &opts_json)?;
                parse_json_value(&json, "verify_image result")
            })),
        })
    }

    /// Sync variant of [`verifyImage`].
    #[napi(js_name = "verifyImageSync")]
    pub fn verify_image_sync(
        &self,
        env: Env,
        file_path: String,
        opts: Option<VerifyImageOptsNapi>,
    ) -> Result<JsUnknown> {
        let opts_json = build_verify_image_opts_json(opts);
        let json = self
            .inner
            .verify_image_json(&file_path, &opts_json)
            .to_napi()?;
        let value = parse_json_value(&json, "verify_image result").map_err(to_napi_err)?;
        value_to_js_value(env, &value)
    }

    /// Extract the JACS signature payload embedded in a signed image.
    /// Returns the decoded JACS signed-document JSON string by default, or the
    /// base64url wire form when `{ rawPayload: true }`. Returns `null` when
    /// the input has no JACS signature.
    #[napi(
        js_name = "extractMediaSignature",
        ts_return_type = "Promise<string | null>"
    )]
    pub fn extract_media_signature_async(
        &self,
        file_path: String,
        opts: Option<ExtractMediaOptsNapi>,
    ) -> AsyncTask<SimpleAgentOptionStringTask> {
        let agent = self.inner.clone();
        let raw = opts.and_then(|o| o.raw_payload).unwrap_or(false);
        let opts_json = build_extract_media_opts_json(raw);
        AsyncTask::new(SimpleAgentOptionStringTask {
            agent,
            func: Some(Box::new(move |a| {
                let envelope = a.extract_media_signature_json(&file_path, &opts_json)?;
                parse_extract_media_envelope(&envelope)
            })),
        })
    }

    /// Sync variant of [`extractMediaSignature`].
    #[napi(js_name = "extractMediaSignatureSync")]
    pub fn extract_media_signature_sync(
        &self,
        file_path: String,
        opts: Option<ExtractMediaOptsNapi>,
    ) -> Result<Option<String>> {
        let raw = opts.and_then(|o| o.raw_payload).unwrap_or(false);
        let opts_json = build_extract_media_opts_json(raw);
        let envelope = self
            .inner
            .extract_media_signature_json(&file_path, &opts_json)
            .to_napi()?;
        parse_extract_media_envelope(&envelope).map_err(to_napi_err)
    }
}

// ============================================================================
// Inline-text / media option types and helpers (Task 11)
// ============================================================================

/// Options for `verifyText` / `verifyTextFile`.
#[napi(object)]
#[derive(Default)]
pub struct VerifyTextOptsNapi {
    /// PRD §C1: when true, missing signatures reject the Promise with
    /// /no JACS signature found/. Default false (permissive — typed status).
    pub strict: Option<bool>,
    /// PRD §4.1.5: directory of `<signer_id>.public.pem` files for offline
    /// verification.
    pub key_dir: Option<String>,
}

/// Options for `signImage` / `signImageSync`.
#[napi(object)]
#[derive(Default)]
pub struct SignImageOptsNapi {
    /// PRD §4.2.4: enable LSB embedding for re-encode survivability (PNG/JPEG only).
    pub robust: Option<bool>,
    /// Optional explicit format override ("png" | "jpeg" | "webp").
    pub format: Option<String>,
    /// PRD §4.2.2: refuse if the input image already carries a JACS signature.
    pub refuse_overwrite: Option<bool>,
}

/// Options for `verifyImage` / `verifyImageSync`.
#[napi(object)]
#[derive(Default)]
pub struct VerifyImageOptsNapi {
    /// C1: see `VerifyTextOptsNapi.strict`.
    pub strict: Option<bool>,
    /// PRD §4.1.5: see `VerifyTextOptsNapi.key_dir`.
    pub key_dir: Option<String>,
    /// PRD §4.2.4: scan the LSB channel as a fallback when the metadata
    /// payload is missing. Default false.
    pub robust: Option<bool>,
}

/// Options for `extractMediaSignature` / `extractMediaSignatureSync`.
#[napi(object)]
#[derive(Default)]
pub struct ExtractMediaOptsNapi {
    /// PRD §3.2: when true, return the raw base64url wire form instead of the
    /// decoded JACS signed-document JSON. Default false (decoded JSON).
    pub raw_payload: Option<bool>,
}

fn build_sign_text_opts(no_backup: bool) -> String {
    serde_json::json!({ "backup": !no_backup }).to_string()
}

fn build_verify_text_opts_json(opts: Option<VerifyTextOptsNapi>) -> String {
    let opts = opts.unwrap_or_default();
    let mut obj = serde_json::Map::new();
    obj.insert(
        "strict".to_string(),
        serde_json::Value::Bool(opts.strict.unwrap_or(false)),
    );
    if let Some(p) = opts.key_dir {
        obj.insert("keyDir".to_string(), serde_json::Value::String(p));
    }
    serde_json::Value::Object(obj).to_string()
}

fn build_sign_image_opts_json(opts: Option<SignImageOptsNapi>) -> String {
    let opts = opts.unwrap_or_default();
    let mut obj = serde_json::Map::new();
    obj.insert(
        "robust".to_string(),
        serde_json::Value::Bool(opts.robust.unwrap_or(false)),
    );
    if let Some(f) = opts.format {
        obj.insert("formatHint".to_string(), serde_json::Value::String(f));
    }
    obj.insert(
        "refuseOverwrite".to_string(),
        serde_json::Value::Bool(opts.refuse_overwrite.unwrap_or(false)),
    );
    serde_json::Value::Object(obj).to_string()
}

fn build_verify_image_opts_json(opts: Option<VerifyImageOptsNapi>) -> String {
    let opts = opts.unwrap_or_default();
    let mut obj = serde_json::Map::new();
    obj.insert(
        "strict".to_string(),
        serde_json::Value::Bool(opts.strict.unwrap_or(false)),
    );
    if let Some(p) = opts.key_dir {
        obj.insert("keyDir".to_string(), serde_json::Value::String(p));
    }
    obj.insert(
        "robust".to_string(),
        serde_json::Value::Bool(opts.robust.unwrap_or(false)),
    );
    serde_json::Value::Object(obj).to_string()
}

fn build_extract_media_opts_json(raw_payload: bool) -> String {
    serde_json::json!({ "rawPayload": raw_payload }).to_string()
}

/// Convert the `{ "present": bool, "payload": string|null }` envelope from
/// `SimpleAgentWrapper::extract_media_signature_json` into Option<String>.
/// Returns `Ok(None)` when present=false; `Ok(Some(payload))` otherwise.
fn parse_extract_media_envelope(envelope_json: &str) -> BindingResult<Option<String>> {
    let v: Value = serde_json::from_str(envelope_json).map_err(|e| {
        BindingCoreError::serialization_failed(format!(
            "extract_media_signature envelope parse failed: {}",
            e
        ))
    })?;
    if v.get("present").and_then(|x| x.as_bool()) == Some(true) {
        Ok(v.get("payload").and_then(|p| p.as_str().map(String::from)))
    } else {
        Ok(None)
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
#[allow(clippy::too_many_arguments)]
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
#[allow(clippy::too_many_arguments)]
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
#[allow(clippy::too_many_arguments)]
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

/// Add an agent to the local trust store with an explicit public key.
#[napi]
pub fn trust_agent_with_key(agent_json: String, public_key_pem: String) -> Result<String> {
    jacs_binding_core::trust_agent_with_key(&agent_json, &public_key_pem).to_napi()
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

#[napi(js_name = "ensureNetworkAccess")]
pub fn ensure_network_access_js(capability: String) -> Result<()> {
    jacs_binding_core::ensure_network_access(&capability).to_napi()
}

#[napi(js_name = "fetchAgentCard")]
pub fn fetch_agent_card_js(base_url: String, timeout_ms: Option<u32>) -> Result<String> {
    jacs_binding_core::fetch_agent_card(&base_url, timeout_ms.map(u64::from)).to_napi()
}

#[napi(js_name = "fetchRemoteKeyLookup")]
pub fn fetch_remote_key_lookup_js(
    base_url: Option<String>,
    jacs_id: Option<String>,
    version: Option<String>,
    public_key_hash: Option<String>,
    timeout_ms: Option<u32>,
) -> Result<String> {
    jacs_binding_core::fetch_remote_key_lookup(
        base_url.as_deref(),
        jacs_id.as_deref(),
        version.as_deref(),
        public_key_hash.as_deref(),
        timeout_ms.map(u64::from),
    )
    .to_napi()
}

#[napi(js_name = "hashPublicKeyBase64")]
pub fn hash_public_key_base64_js(public_key_base64: String) -> Result<String> {
    jacs_binding_core::hash_public_key_base64(&public_key_base64).to_napi()
}

#[napi(js_name = "buildJwkSetFromPublicKey")]
pub fn build_jwk_set_from_public_key_js(
    public_key_base64: String,
    key_algorithm: String,
    key_id: String,
) -> Result<String> {
    jacs_binding_core::build_jwk_set_from_public_key(&public_key_base64, &key_algorithm, &key_id)
        .to_napi()
}

#[napi(js_name = "resolvePrivateKeyPassword")]
pub fn resolve_private_key_password_js(
    config_path: Option<String>,
    key_directory: Option<String>,
    explicit_password: Option<String>,
) -> Result<String> {
    jacs_binding_core::resolve_private_key_password(
        config_path.as_deref(),
        key_directory.as_deref(),
        explicit_password.as_deref(),
    )
    .to_napi()
}

#[napi(js_name = "quickstartPrivateKeyPassword")]
pub fn quickstart_private_key_password_js(
    config_path: Option<String>,
    key_directory: Option<String>,
) -> Result<String> {
    jacs_binding_core::quickstart_private_key_password(
        config_path.as_deref(),
        key_directory.as_deref(),
    )
    .to_napi()
}

// =============================================================================
// MCP path policy delegate (PRD §4.2.6, Issue 022)
// =============================================================================
//
// Single source of truth for MCP file-path validation across Rust + Python +
// Node. `jacsnpm/mcp.ts` calls this from each MCP tool case arm so Node's
// path validation matches Rust byte-for-byte. The Rust helper enforces the
// full six-layer policy (base-dir + canonicalisation, absolute-path
// rejection, traversal rejection, NUL byte rejection, symlink rejection,
// output-overwrite gate).
//
// Throws if `kind` is not `"input"` or `"output"`, or if the policy rejects.
// On accept, returns the resolved canonical path string.
#[napi(js_name = "jacsMcpResolveInputPath")]
pub fn jacs_mcp_resolve_input_path(raw: String, kind: Option<String>) -> Result<String> {
    let kind_str = kind.unwrap_or_else(|| "input".to_string());
    let kind_enum = match kind_str.as_str() {
        "input" => jacs_mcp::path_policy::PathKind::Input,
        "output" => jacs_mcp::path_policy::PathKind::Output,
        other => {
            return Err(napi::Error::from_reason(format!(
                "invalid kind: {}, expected 'input' or 'output'",
                other
            )));
        }
    };
    jacs_mcp::path_policy::resolve(&raw, kind_enum)
        .map(|p| p.display().to_string())
        .map_err(|e| napi::Error::from_reason(format!("{}", e)))
}
