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
