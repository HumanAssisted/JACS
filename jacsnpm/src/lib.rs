use ::jacs as jacs_core;
use jacs_core::agent::document::DocumentTraits;
use jacs_core::agent::payloads::PayloadTraits;
use jacs_core::agent::{AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME, Agent};
use jacs_core::crypt::KeyManager;
use jacs_core::crypt::hash::hash_string as jacs_hash_string;
use napi::JsObject;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde_json::Value;
use std::sync::Arc;
use std::sync::Mutex;

// Declare the module so it's recognized at the crate root
pub mod conversion_utils;
use conversion_utils::{js_value_to_value, value_to_js_value};

/// JacsAgent is a handle to a JACS agent instance.
/// Each instance maintains its own state and can be used independently.
/// This allows multiple agents to be used concurrently in the same process.
#[napi]
pub struct JacsAgent {
    inner: Arc<Mutex<Agent>>,
}

#[napi]
impl JacsAgent {
    /// Create a new empty JacsAgent instance.
    /// Call `load()` to initialize it with a configuration.
    #[napi(constructor)]
    pub fn new() -> Self {
        JacsAgent {
            inner: Arc::new(Mutex::new(jacs_core::get_empty_agent())),
        }
    }

    /// Load an agent from a configuration file.
    #[napi]
    pub fn load(&self, config_path: String) -> Result<String> {
        let mut agent_ref = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to lock agent: {}", e),
            )
        })?;
        agent_ref.load_by_config(config_path).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to load agent: {}", e),
            )
        })?;
        Ok("Agent loaded".to_string())
    }

    /// Sign an external agent's document with this agent's registration signature.
    #[napi]
    pub fn sign_agent(
        &self,
        agent_string: String,
        public_key: Buffer,
        public_key_enc_type: String,
    ) -> Result<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        let mut external_agent: Value = agent.validate_agent(&agent_string).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Agent validation failed: {}", e),
            )
        })?;

        // Proceed with signature verification
        agent
            .signature_verification_procedure(
                &external_agent,
                None,
                &AGENT_SIGNATURE_FIELDNAME.to_string(),
                public_key.to_vec(),
                Some(public_key_enc_type),
                None,
                None,
            )
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Signature verification failed: {}", e),
                )
            })?;

        // If all previous steps pass, proceed with signing
        let registration_signature = agent
            .signing_procedure(
                &external_agent,
                None,
                &AGENT_REGISTRATION_SIGNATURE_FIELDNAME.to_string(),
            )
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Signing procedure failed: {}", e),
                )
            })?;
        external_agent[AGENT_REGISTRATION_SIGNATURE_FIELDNAME] = registration_signature;
        Ok(external_agent.to_string())
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
        let agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        if data.is_empty()
            || signature_base64.is_empty()
            || public_key.is_empty()
            || public_key_enc_type.is_empty()
        {
            return Err(Error::new(
                Status::InvalidArg,
                format!(
                    "One parameter is empty: data: {}, signature_base64: {}, public_key_enc_type: {}",
                    data, signature_base64, public_key_enc_type
                ),
            ));
        }

        match agent.verify_string(
            &data,
            &signature_base64,
            public_key.to_vec(),
            Some(public_key_enc_type),
        ) {
            Ok(_) => Ok(true),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Signature verification failed: {}", e),
            )),
        }
    }

    /// Sign arbitrary string data with this agent's private key.
    #[napi]
    pub fn sign_string(&self, data: String) -> Result<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        let signed_string = agent.sign_string(&data).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to sign string: {}", e),
            )
        })?;

        Ok(signed_string)
    }

    /// Verify this agent's signature and hash.
    #[napi]
    pub fn verify_agent(&self, agentfile: Option<String>) -> Result<bool> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        if let Some(file) = agentfile {
            // Load agent from file using the FileLoader trait
            let agent_result = jacs_core::load_agent(Some(file));
            match agent_result {
                Ok(loaded_agent) => {
                    // Replace the current agent
                    *agent = loaded_agent;
                }
                Err(e) => {
                    return Err(Error::new(
                        Status::GenericFailure,
                        format!("Failed to load agent: {}", e),
                    ));
                }
            }
        }

        agent.verify_self_signature().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to verify agent signature: {}", e),
            )
        })?;

        match agent.verify_self_hash() {
            Ok(_) => Ok(true),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to verify agent hash: {}", e),
            )),
        }
    }

    /// Update the agent document with new data.
    #[napi]
    pub fn update_agent(&self, new_agent_string: String) -> Result<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        match agent.update_self(&new_agent_string) {
            Ok(updated) => Ok(updated),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to update agent: {}", e),
            )),
        }
    }

    /// Verify a document's signature and hash.
    #[napi]
    pub fn verify_document(&self, document_string: String) -> Result<bool> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        // Load document using the DocumentTraits trait
        let doc_result = agent.load_document(&document_string);
        let doc = match doc_result {
            Ok(doc) => doc,
            Err(e) => {
                return Err(Error::new(
                    Status::GenericFailure,
                    format!("Failed to load document: {}", e),
                ));
            }
        };

        let document_key = doc.getkey();
        let value = doc.getvalue();

        // Verify hash
        agent.verify_hash(value).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to verify document hash: {}", e),
            )
        })?;

        // Verify signature using the DocumentTraits trait method
        match agent.verify_external_document_signature(&document_key) {
            Ok(_) => Ok(true),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to verify document signature: {}", e),
            )),
        }
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
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        // Use the DocumentTraits trait method
        match agent.update_document(&document_key, &new_document_string, attachments, embed) {
            Ok(doc) => Ok(doc.to_string()),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to update document: {}", e),
            )),
        }
    }

    /// Verify a document's signature with an optional custom signature field.
    #[napi]
    pub fn verify_signature(&self, document_string: String, signature_field: Option<String>) -> Result<bool> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        // Load document using the DocumentTraits trait
        let doc_result = agent.load_document(&document_string);
        let doc = match doc_result {
            Ok(doc) => doc,
            Err(e) => {
                return Err(Error::new(
                    Status::GenericFailure,
                    format!("Failed to load document: {}", e),
                ));
            }
        };

        let document_key = doc.getkey();
        let sig_field_ref = signature_field.as_ref();

        // Verify signature using the DocumentTraits trait method
        match agent.verify_document_signature(
            &document_key,
            sig_field_ref.map(|s| s.as_str()),
            None,
            None,
            None,
        ) {
            Ok(_) => Ok(true),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to verify signature: {}", e),
            )),
        }
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
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        match jacs_core::shared::document_add_agreement(
            &mut agent,
            &document_string,
            agentids,
            None,     // custom_schema
            None,     // save_filename
            question, // question
            context,  // context
            None,     // export_embedded
            None,     // extract_only
            false,    // load_only
            agreement_fieldname,
        ) {
            Ok(result) => Ok(result),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to create agreement: {}", e),
            )),
        }
    }

    /// Sign an agreement on a document.
    #[napi]
    pub fn sign_agreement(&self, document_string: String, agreement_fieldname: Option<String>) -> Result<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        match jacs_core::shared::document_sign_agreement(
            &mut agent,
            &document_string,
            None,
            None,
            None,
            None,
            false,
            agreement_fieldname,
        ) {
            Ok(result) => Ok(result),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to sign agreement: {}", e),
            )),
        }
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
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        match jacs_core::shared::document_create(
            &mut agent,
            &document_string,
            custom_schema,
            outputfilename,
            no_save.unwrap_or(false),
            attachments.as_deref(),
            embed,
        ) {
            Ok(result) => Ok(result),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to create document: {}", e),
            )),
        }
    }

    /// Check an agreement on a document.
    #[napi]
    pub fn check_agreement(&self, document_string: String, agreement_fieldname: Option<String>) -> Result<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        match jacs_core::shared::document_check_agreement(
            &mut agent,
            &document_string,
            None,
            agreement_fieldname,
        ) {
            Ok(result) => Ok(result),
            Err(e) => Err(Error::new(
                Status::GenericFailure,
                format!("Failed to check agreement: {}", e),
            )),
        }
    }

    /// Sign a request payload (wraps in a JACS document).
    #[napi(ts_args_type = "params: any")]
    pub fn sign_request(&self, env: Env, params_obj: JsObject) -> Result<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        let payload_value = js_value_to_value(env, params_obj.into_unknown())?;

        let wrapper_value = serde_json::json!({
            "jacs_payload": payload_value
        });

        let wrapper_string = serde_json::to_string(&wrapper_value).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to serialize wrapper JSON: {}", e),
            )
        })?;

        let outputfilename: Option<String> = None;
        let attachments: Option<String> = None;
        let no_save = true;
        let docresult = jacs_core::shared::document_create(
            &mut agent,
            &wrapper_string,
            None,
            outputfilename,
            no_save,
            attachments.as_deref(),
            Some(false),
        )
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to create document: {}", e),
            )
        })?;

        Ok(docresult)
    }

    /// Verify a response payload.
    #[napi]
    pub fn verify_response(&self, env: Env, document_string: String) -> Result<JsObject> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        let payload_serde_value: Value = agent
            .verify_payload(document_string, None)
            .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;

        let js_value = value_to_js_value(env, &payload_serde_value)?;

        // Create a wrapper object and set the payload as a property
        let mut result_obj = env.create_object()?;
        result_obj.set_named_property("payload", js_value)?;

        Ok(result_obj)
    }

    /// Verify a response payload and return the agent ID.
    #[napi]
    pub fn verify_response_with_agent_id(&self, env: Env, document_string: String) -> Result<JsObject> {
        let mut agent = self.inner.lock().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to acquire agent lock: {}", e),
            )
        })?;

        let (payload_serde_value, agent_id) = agent
            .verify_payload_with_agent_id(document_string, None)
            .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;

        let js_payload = value_to_js_value(env, &payload_serde_value)?;
        let js_agent_id = env.create_string(&agent_id)?;

        let mut result_obj = env.create_object()?;
        result_obj.set_named_property("agent_id", js_agent_id)?;
        result_obj.set_named_property("payload", js_payload)?;

        Ok(result_obj)
    }
}

// ============================================================================
// Standalone utility functions (don't require an agent instance)
// ============================================================================

/// Hash a string using SHA-256.
#[napi]
pub fn hash_string(data: String) -> Result<String> {
    Ok(jacs_hash_string(&data))
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
    let config = jacs_core::config::Config::new(
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

    match serde_json::to_string_pretty(&config) {
        Ok(serialized) => Ok(serialized),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to serialize config: {}", e),
        )),
    }
}

// ============================================================================
// Legacy API (deprecated - use JacsAgent class instead)
// These functions use a global singleton for backwards compatibility.
// They will be removed in a future version.
// ============================================================================

use lazy_static::lazy_static;

lazy_static! {
    static ref LEGACY_AGENT: Arc<Mutex<Agent>> = {
        Arc::new(Mutex::new(jacs_core::get_empty_agent()))
    };
}

/// @deprecated Use `new JacsAgent()` and `agent.load()` instead.
#[napi]
pub fn load(config_path: String) -> Result<String> {
    let mut agent_ref = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to lock agent: {}", e),
        )
    })?;
    agent_ref.load_by_config(config_path).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to load agent: {}", e),
        )
    })?;
    Ok("Agent loaded".to_string())
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn sign_agent(
    agent_string: String,
    public_key: Buffer,
    public_key_enc_type: String,
) -> Result<String> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let mut external_agent: Value = agent.validate_agent(&agent_string).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Agent validation failed: {}", e),
        )
    })?;

    agent
        .signature_verification_procedure(
            &external_agent,
            None,
            &AGENT_SIGNATURE_FIELDNAME.to_string(),
            public_key.to_vec(),
            Some(public_key_enc_type),
            None,
            None,
        )
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Signature verification failed: {}", e),
            )
        })?;

    let registration_signature = agent
        .signing_procedure(
            &external_agent,
            None,
            &AGENT_REGISTRATION_SIGNATURE_FIELDNAME.to_string(),
        )
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Signing procedure failed: {}", e),
            )
        })?;
    external_agent[AGENT_REGISTRATION_SIGNATURE_FIELDNAME] = registration_signature;
    Ok(external_agent.to_string())
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

    if data.is_empty()
        || signature_base64.is_empty()
        || public_key.is_empty()
        || public_key_enc_type.is_empty()
    {
        return Err(Error::new(
            Status::InvalidArg,
            format!(
                "One parameter is empty: data: {}, signature_base64: {}, public_key_enc_type: {}",
                data, signature_base64, public_key_enc_type
            ),
        ));
    }

    match agent.verify_string(
        &data,
        &signature_base64,
        public_key.to_vec(),
        Some(public_key_enc_type),
    ) {
        Ok(_) => Ok(true),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Signature verification failed: {}", e),
        )),
    }
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn sign_string(data: String) -> Result<String> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let signed_string = agent.sign_string(&data).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to sign string: {}", e),
        )
    })?;

    Ok(signed_string)
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_agent(agentfile: Option<String>) -> Result<bool> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    if let Some(file) = agentfile {
        let agent_result = jacs_core::load_agent(Some(file));
        match agent_result {
            Ok(loaded_agent) => {
                *agent = loaded_agent;
            }
            Err(e) => {
                return Err(Error::new(
                    Status::GenericFailure,
                    format!("Failed to load agent: {}", e),
                ));
            }
        }
    }

    agent.verify_self_signature().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to verify agent signature: {}", e),
        )
    })?;

    match agent.verify_self_hash() {
        Ok(_) => Ok(true),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to verify agent hash: {}", e),
        )),
    }
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn update_agent(new_agent_string: String) -> Result<String> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    match agent.update_self(&new_agent_string) {
        Ok(updated) => Ok(updated),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to update agent: {}", e),
        )),
    }
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_document(document_string: String) -> Result<bool> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let doc_result = agent.load_document(&document_string);
    let doc = match doc_result {
        Ok(doc) => doc,
        Err(e) => {
            return Err(Error::new(
                Status::GenericFailure,
                format!("Failed to load document: {}", e),
            ));
        }
    };

    let document_key = doc.getkey();
    let value = doc.getvalue();

    agent.verify_hash(value).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to verify document hash: {}", e),
        )
    })?;

    match agent.verify_external_document_signature(&document_key) {
        Ok(_) => Ok(true),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to verify document signature: {}", e),
        )),
    }
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn update_document(
    document_key: String,
    new_document_string: String,
    attachments: Option<Vec<String>>,
    embed: Option<bool>,
) -> Result<String> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    match agent.update_document(&document_key, &new_document_string, attachments, embed) {
        Ok(doc) => Ok(doc.to_string()),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to update document: {}", e),
        )),
    }
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_signature(document_string: String, signature_field: Option<String>) -> Result<bool> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let doc_result = agent.load_document(&document_string);
    let doc = match doc_result {
        Ok(doc) => doc,
        Err(e) => {
            return Err(Error::new(
                Status::GenericFailure,
                format!("Failed to load document: {}", e),
            ));
        }
    };

    let document_key = doc.getkey();
    let sig_field_ref = signature_field.as_ref();

    match agent.verify_document_signature(
        &document_key,
        sig_field_ref.map(|s| s.as_str()),
        None,
        None,
        None,
    ) {
        Ok(_) => Ok(true),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to verify signature: {}", e),
        )),
    }
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
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    match jacs_core::shared::document_add_agreement(
        &mut agent,
        &document_string,
        agentids,
        None,
        None,
        question,
        context,
        None,
        None,
        false,
        agreement_fieldname,
    ) {
        Ok(result) => Ok(result),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to create agreement: {}", e),
        )),
    }
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn sign_agreement(document_string: String, agreement_fieldname: Option<String>) -> Result<String> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    match jacs_core::shared::document_sign_agreement(
        &mut agent,
        &document_string,
        None,
        None,
        None,
        None,
        false,
        agreement_fieldname,
    ) {
        Ok(result) => Ok(result),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to sign agreement: {}", e),
        )),
    }
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
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    match jacs_core::shared::document_create(
        &mut agent,
        &document_string,
        custom_schema,
        outputfilename,
        no_save.unwrap_or(false),
        attachments.as_deref(),
        embed,
    ) {
        Ok(result) => Ok(result),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to create document: {}", e),
        )),
    }
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn check_agreement(document_string: String, agreement_fieldname: Option<String>) -> Result<String> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    match jacs_core::shared::document_check_agreement(
        &mut agent,
        &document_string,
        None,
        agreement_fieldname,
    ) {
        Ok(result) => Ok(result),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to create agreement: {}", e),
        )),
    }
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi(ts_args_type = "params: any")]
pub fn sign_request(env: Env, params_obj: JsObject) -> Result<String> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let payload_value = js_value_to_value(env, params_obj.into_unknown())?;

    let wrapper_value = serde_json::json!({
        "jacs_payload": payload_value
    });

    let wrapper_string = serde_json::to_string(&wrapper_value).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to serialize wrapper JSON: {}", e),
        )
    })?;

    let outputfilename: Option<String> = None;
    let attachments: Option<String> = None;
    let no_save = true;
    let docresult = jacs_core::shared::document_create(
        &mut agent,
        &wrapper_string,
        None,
        outputfilename,
        no_save,
        attachments.as_deref(),
        Some(false),
    )
    .map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to create document: {}", e),
        )
    })?;

    Ok(docresult)
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_response(env: Env, document_string: String) -> Result<JsObject> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let payload_serde_value: Value = agent
        .verify_payload(document_string, None)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;

    let js_value = value_to_js_value(env, &payload_serde_value)?;

    let mut result_obj = env.create_object()?;
    result_obj.set_named_property("payload", js_value)?;

    Ok(result_obj)
}

/// @deprecated Use `new JacsAgent()` and instance methods instead.
#[napi]
pub fn verify_response_with_agent_id(env: Env, document_string: String) -> Result<JsObject> {
    let mut agent = LEGACY_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let (payload_serde_value, agent_id) = agent
        .verify_payload_with_agent_id(document_string, None)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;

    let js_payload = value_to_js_value(env, &payload_serde_value)?;
    let js_agent_id = env.create_string(&agent_id)?;

    let mut result_obj = env.create_object()?;
    result_obj.set_named_property("agent_id", js_agent_id)?;
    result_obj.set_named_property("payload", js_payload)?;

    Ok(result_obj)
}
