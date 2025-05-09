use ::jacs as jacs_core;
use jacs_core::agent::document::DocumentTraits;
use jacs_core::agent::{AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME, Agent};
use jacs_core::crypt::KeyManager;
use jacs_core::crypt::hash::hash_string as jacs_hash_string;
use lazy_static::lazy_static;
use napi::JsObject;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde_json::Value;
use std::sync::Arc;
use std::sync::Mutex;

// Declare the module so it's recognized at the crate root
pub mod conversion_utils;
use conversion_utils::{js_value_to_value, value_to_js_value};

lazy_static! {
    pub static ref JACS_AGENT: Arc<Mutex<Agent>> = {
        let agent: Arc<Mutex<Agent>> = Arc::new(Mutex::new(jacs_core::get_empty_agent()));
        return agent;
    };
}

#[napi]
fn load(config_path: String) -> Result<String> {
    let mut agent_ref = JACS_AGENT.lock().map_err(|e| {
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

#[napi]
fn sign_agent(
    agent_string: String,
    public_key: Buffer,
    public_key_enc_type: String,
) -> Result<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
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

#[napi]
fn verify_string(
    data: String,
    signature_base64: String,
    public_key: Buffer,
    public_key_enc_type: String,
) -> Result<bool> {
    let agent = JACS_AGENT.lock().map_err(|e| {
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

#[napi]
fn sign_string(data: String) -> Result<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
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

#[napi]
fn hash_string(data: String) -> Result<String> {
    Ok(jacs_hash_string(&data))
}

#[napi]
fn create_config(
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

#[napi]
fn verify_agent(agentfile: Option<String>) -> Result<bool> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
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

#[napi]
fn update_agent(new_agent_string: String) -> Result<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
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

#[napi]
fn verify_document(document_string: String) -> Result<bool> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
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

#[napi]
fn update_document(
    document_key: String,
    new_document_string: String,
    attachments: Option<Vec<String>>,
    embed: Option<bool>,
) -> Result<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
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

#[napi]
fn verify_signature(document_string: String, signature_field: Option<String>) -> Result<bool> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
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
    let sig_field_ref = signature_field.as_ref(); // .map(|s| s.as_str());

    // Verify signature using the DocumentTraits trait method
    // FIXME get the public key from the document
    match agent.verify_document_signature(&document_key, sig_field_ref, None, None, None) {
        Ok(_) => Ok(true),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to verify signature: {}", e),
        )),
    }
}

#[napi]
fn create_agreement(
    document_string: String,
    agentids: Vec<String>,
    question: Option<String>,
    context: Option<String>,
    agreement_fieldname: Option<String>,
) -> Result<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
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

#[napi]
fn sign_agreement(document_string: String, agreement_fieldname: Option<String>) -> Result<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
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

#[napi]
fn create_document(
    document_string: String,
    custom_schema: Option<String>,
    outputfilename: Option<String>,
    no_save: Option<bool>,
    attachments: Option<String>,
    embed: Option<bool>,
) -> Result<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
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
        attachments.as_ref(),
        embed,
    ) {
        Ok(result) => Ok(result),
        Err(e) => Err(Error::new(
            Status::GenericFailure,
            format!("Failed to create document: {}", e),
        )),
    }
}

#[napi]
fn check_agreement(document_string: String, agreement_fieldname: Option<String>) -> Result<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
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

#[napi(ts_args_type = "params: any")]
fn sign_request(env: Env, params_obj: JsObject) -> Result<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
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
        attachments.as_ref(),
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

#[napi]
fn verify_response(env: Env, document_string: String) -> Result<JsObject> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let doc = agent.load_document(&document_string).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to load document: {}", e),
        )
    })?;

    let document_key = doc.getkey();
    let value = doc.getvalue();

    agent.verify_hash(value).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to verify document hash: {}", e),
        )
    })?;

    agent
        .verify_external_document_signature(&document_key)
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to verify document signature: {}", e),
            )
        })?;

    let payload = value.get("jacs_payload").ok_or_else(|| {
        Error::new(
            Status::GenericFailure,
            "'jacs_payload' field not found in document value".to_string(),
        )
    })?;

    let js_value = value_to_js_value(env, payload)?;
    Ok(js_value.try_into()?)
}

#[napi]
fn verify_response_with_agent_id(env: Env, document_string: String) -> Result<JsObject> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to acquire JACS_AGENT lock: {}", e),
        )
    })?;

    let doc = agent.load_document(&document_string).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to load document: {}", e),
        )
    })?;

    let document_key = doc.getkey();
    let value = doc.getvalue();

    agent.verify_hash(value).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to verify document hash: {}", e),
        )
    })?;

    agent
        .verify_external_document_signature(&document_key)
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to verify document signature: {}", e),
            )
        })?;

    let payload = value.get("jacs_payload").ok_or_else(|| {
        Error::new(
            Status::GenericFailure,
            "'jacs_payload' field not found in document value".to_string(),
        )
    })?;

    let agent_id = agent
        .get_document_signature_agent_id(&document_key)
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to get agent id: {}", e),
            )
        })?;

    let js_payload = value_to_js_value(env, payload)?;
    let js_agent_id = env.create_string(&agent_id)?;

    // Create a JavaScript object to hold both values
    let mut result_obj = env.create_object()?;
    result_obj.set_named_property("agent_id", js_agent_id)?;
    result_obj.set_named_property("payload", js_payload)?;

    Ok(result_obj)
}
