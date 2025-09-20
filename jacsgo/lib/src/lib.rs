use ::jacs as jacs_core;
use jacs_core::agent::document::DocumentTraits;
use jacs_core::agent::payloads::PayloadTraits;
use jacs_core::agent::{AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME, Agent};
use jacs_core::crypt::KeyManager;
use jacs_core::crypt::hash::hash_string as jacs_hash_string;
use lazy_static::lazy_static;
use libc::{c_char, c_int, size_t};
use serde_json::Value;
use std::ffi::{CStr, CString};
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::Mutex;

// Declare the module so it's recognized at the crate root
pub mod conversion_utils;
use conversion_utils::{json_to_c_string, c_string_to_json};

lazy_static! {
    pub static ref JACS_AGENT: Arc<Mutex<Agent>> = {
        let agent: Arc<Mutex<Agent>> = Arc::new(Mutex::new(jacs_core::get_empty_agent()));
        return agent;
    };
}

/// Load JACS configuration from the specified path
#[no_mangle]
pub extern "C" fn jacs_load(config_path: *const c_char) -> c_int {
    if config_path.is_null() {
        return -1;
    }

    let config_path_str = match unsafe { CStr::from_ptr(config_path) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let mut agent_ref = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return -3,
    };

    match agent_ref.load_by_config(config_path_str.to_string()) {
        Ok(_) => 0,
        Err(_) => -4,
    }
}

/// Free a string allocated by Rust
#[no_mangle]
pub extern "C" fn jacs_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        // Reconstruct the CString to properly deallocate
        let _ = CString::from_raw(s);
    }
}

/// Sign a string and return the signature
#[no_mangle]
pub extern "C" fn jacs_sign_string(data: *const c_char) -> *mut c_char {
    if data.is_null() {
        return ptr::null_mut();
    }

    let data_str = match unsafe { CStr::from_ptr(data) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match agent.sign_string(&data_str.to_string()) {
        Ok(signature) => match CString::new(signature) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Hash a string using JACS hashing
#[no_mangle]
pub extern "C" fn jacs_hash_string(data: *const c_char) -> *mut c_char {
    if data.is_null() {
        return ptr::null_mut();
    }

    let data_str = match unsafe { CStr::from_ptr(data) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let hash = jacs_hash_string(&data_str.to_string());
    
    match CString::new(hash) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Verify a string signature
#[no_mangle]
pub extern "C" fn jacs_verify_string(
    data: *const c_char,
    signature_base64: *const c_char,
    public_key: *const u8,
    public_key_len: size_t,
    public_key_enc_type: *const c_char,
) -> c_int {
    if data.is_null() || signature_base64.is_null() || public_key.is_null() || public_key_enc_type.is_null() {
        return -1;
    }

    let data_str = match unsafe { CStr::from_ptr(data) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let signature_str = match unsafe { CStr::from_ptr(signature_base64) }.to_str() {
        Ok(s) => s,
        Err(_) => return -3,
    };

    let enc_type_str = match unsafe { CStr::from_ptr(public_key_enc_type) }.to_str() {
        Ok(s) => s,
        Err(_) => return -4,
    };

    let public_key_vec = unsafe { slice::from_raw_parts(public_key, public_key_len) }.to_vec();

    let agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return -5,
    };

    match agent.verify_string(
        &data_str.to_string(),
        &signature_str.to_string(),
        public_key_vec,
        Some(enc_type_str.to_string()),
    ) {
        Ok(_) => 0,
        Err(_) => -6,
    }
}

/// Sign an agent
#[no_mangle]
pub extern "C" fn jacs_sign_agent(
    agent_string: *const c_char,
    public_key: *const u8,
    public_key_len: size_t,
    public_key_enc_type: *const c_char,
) -> *mut c_char {
    if agent_string.is_null() || public_key.is_null() || public_key_enc_type.is_null() {
        return ptr::null_mut();
    }

    let agent_str = match unsafe { CStr::from_ptr(agent_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let enc_type_str = match unsafe { CStr::from_ptr(public_key_enc_type) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let public_key_vec = unsafe { slice::from_raw_parts(public_key, public_key_len) }.to_vec();

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    let mut external_agent: Value = match agent.validate_agent(agent_str) {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    // Proceed with signature verification
    if let Err(_) = agent.signature_verification_procedure(
        &external_agent,
        None,
        &AGENT_SIGNATURE_FIELDNAME.to_string(),
        public_key_vec,
        Some(enc_type_str.to_string()),
        None,
        None,
    ) {
        return ptr::null_mut();
    }

    // If all previous steps pass, proceed with signing
    let registration_signature = match agent.signing_procedure(
        &external_agent,
        None,
        &AGENT_REGISTRATION_SIGNATURE_FIELDNAME.to_string(),
    ) {
        Ok(sig) => sig,
        Err(_) => return ptr::null_mut(),
    };

    external_agent[AGENT_REGISTRATION_SIGNATURE_FIELDNAME] = registration_signature;

    match CString::new(external_agent.to_string()) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Create a JACS configuration
#[no_mangle]
pub extern "C" fn jacs_create_config(
    jacs_use_security: *const c_char,
    jacs_data_directory: *const c_char,
    jacs_key_directory: *const c_char,
    jacs_agent_private_key_filename: *const c_char,
    jacs_agent_public_key_filename: *const c_char,
    jacs_agent_key_algorithm: *const c_char,
    jacs_private_key_password: *const c_char,
    jacs_agent_id_and_version: *const c_char,
    jacs_default_storage: *const c_char,
) -> *mut c_char {
    let config = jacs_core::config::Config::new(
        c_string_to_option(jacs_use_security),
        c_string_to_option(jacs_data_directory),
        c_string_to_option(jacs_key_directory),
        c_string_to_option(jacs_agent_private_key_filename),
        c_string_to_option(jacs_agent_public_key_filename),
        c_string_to_option(jacs_agent_key_algorithm),
        c_string_to_option(jacs_private_key_password),
        c_string_to_option(jacs_agent_id_and_version),
        c_string_to_option(jacs_default_storage),
    );

    match serde_json::to_string_pretty(&config) {
        Ok(serialized) => match CString::new(serialized) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Verify an agent
#[no_mangle]
pub extern "C" fn jacs_verify_agent(agentfile: *const c_char) -> c_int {
    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return -1,
    };

    if !agentfile.is_null() {
        let file_str = match unsafe { CStr::from_ptr(agentfile) }.to_str() {
            Ok(s) => s,
            Err(_) => return -2,
        };

        // Load agent from file
        let agent_result = jacs_core::load_agent(Some(file_str.to_string()));
        match agent_result {
            Ok(loaded_agent) => {
                *agent = loaded_agent;
            }
            Err(_) => return -3,
        }
    }

    if let Err(_) = agent.verify_self_signature() {
        return -4;
    }

    match agent.verify_self_hash() {
        Ok(_) => 0,
        Err(_) => -5,
    }
}

/// Update an agent
#[no_mangle]
pub extern "C" fn jacs_update_agent(new_agent_string: *const c_char) -> *mut c_char {
    if new_agent_string.is_null() {
        return ptr::null_mut();
    }

    let agent_str = match unsafe { CStr::from_ptr(new_agent_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match agent.update_self(agent_str) {
        Ok(updated) => match CString::new(updated) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Verify a document
#[no_mangle]
pub extern "C" fn jacs_verify_document(document_string: *const c_char) -> c_int {
    if document_string.is_null() {
        return -1;
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return -3,
    };

    let doc = match agent.load_document(doc_str) {
        Ok(doc) => doc,
        Err(_) => return -4,
    };

    let document_key = doc.getkey();
    let value = doc.getvalue();

    if let Err(_) = agent.verify_hash(value) {
        return -5;
    }

    match agent.verify_external_document_signature(&document_key) {
        Ok(_) => 0,
        Err(_) => -6,
    }
}

/// Update a document
#[no_mangle]
pub extern "C" fn jacs_update_document(
    document_key: *const c_char,
    new_document_string: *const c_char,
    attachments_json: *const c_char,
    embed: c_int,
) -> *mut c_char {
    if document_key.is_null() || new_document_string.is_null() {
        return ptr::null_mut();
    }

    let key_str = match unsafe { CStr::from_ptr(document_key) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let doc_str = match unsafe { CStr::from_ptr(new_document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let attachments = if !attachments_json.is_null() {
        match unsafe { CStr::from_ptr(attachments_json) }.to_str() {
            Ok(s) => match serde_json::from_str::<Vec<String>>(s) {
                Ok(vec) => Some(vec),
                Err(_) => None,
            },
            Err(_) => None,
        }
    } else {
        None
    };

    let embed_opt = if embed != 0 { Some(true) } else { None };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match agent.update_document(key_str, doc_str, attachments, embed_opt) {
        Ok(doc) => match CString::new(doc.to_string()) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Create a document
#[no_mangle]
pub extern "C" fn jacs_create_document(
    document_string: *const c_char,
    custom_schema: *const c_char,
    outputfilename: *const c_char,
    no_save: c_int,
    attachments: *const c_char,
    embed: c_int,
) -> *mut c_char {
    if document_string.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    let embed_opt = if embed > 0 { Some(true) } else if embed < 0 { Some(false) } else { None };

    match jacs_core::shared::document_create(
        &mut agent,
        doc_str,
        c_string_to_option(custom_schema),
        c_string_to_option(outputfilename),
        no_save != 0,
        c_string_to_option(attachments).as_ref(),
        embed_opt,
    ) {
        Ok(result) => match CString::new(result) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Create an agreement
#[no_mangle]
pub extern "C" fn jacs_create_agreement(
    document_string: *const c_char,
    agentids_json: *const c_char,
    question: *const c_char,
    context: *const c_char,
    agreement_fieldname: *const c_char,
) -> *mut c_char {
    if document_string.is_null() || agentids_json.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let agentids_str = match unsafe { CStr::from_ptr(agentids_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let agentids: Vec<String> = match serde_json::from_str(agentids_str) {
        Ok(ids) => ids,
        Err(_) => return ptr::null_mut(),
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match jacs_core::shared::document_add_agreement(
        &mut agent,
        doc_str,
        agentids,
        None,
        None,
        c_string_to_option(question),
        c_string_to_option(context),
        None,
        None,
        false,
        c_string_to_option(agreement_fieldname),
    ) {
        Ok(result) => match CString::new(result) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Sign an agreement
#[no_mangle]
pub extern "C" fn jacs_sign_agreement(
    document_string: *const c_char,
    agreement_fieldname: *const c_char,
) -> *mut c_char {
    if document_string.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match jacs_core::shared::document_sign_agreement(
        &mut agent,
        doc_str,
        None,
        None,
        None,
        None,
        false,
        c_string_to_option(agreement_fieldname),
    ) {
        Ok(result) => match CString::new(result) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Check an agreement
#[no_mangle]
pub extern "C" fn jacs_check_agreement(
    document_string: *const c_char,
    agreement_fieldname: *const c_char,
) -> *mut c_char {
    if document_string.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match jacs_core::shared::document_check_agreement(
        &mut agent,
        doc_str,
        None,
        c_string_to_option(agreement_fieldname),
    ) {
        Ok(result) => match CString::new(result) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Sign a request (for MCP)
#[no_mangle]
pub extern "C" fn jacs_sign_request(payload_json: *const c_char) -> *mut c_char {
    if payload_json.is_null() {
        return ptr::null_mut();
    }

    let payload_str = match unsafe { CStr::from_ptr(payload_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let payload_value: Value = match serde_json::from_str(payload_str) {
        Ok(val) => val,
        Err(_) => return ptr::null_mut(),
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match agent.sign_payload(payload_value) {
        Ok(signed) => match CString::new(signed) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Verify a response (for MCP)
#[no_mangle]
pub extern "C" fn jacs_verify_response(document_string: *const c_char) -> *mut c_char {
    if document_string.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match agent.verify_payload(doc_str.to_string(), None) {
        Ok(payload) => json_to_c_string(&payload),
        Err(_) => ptr::null_mut(),
    }
}

/// Verify a response with agent ID (for MCP)
#[no_mangle]
pub extern "C" fn jacs_verify_response_with_agent_id(
    document_string: *const c_char,
    agent_id_out: *mut *mut c_char,
) -> *mut c_char {
    if document_string.is_null() || agent_id_out.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match agent.verify_payload_with_agent_id(doc_str.to_string(), None) {
        Ok((payload, agent_id)) => {
            // Set the agent_id output parameter
            match CString::new(agent_id) {
                Ok(c_string) => unsafe { *agent_id_out = c_string.into_raw() },
                Err(_) => unsafe { *agent_id_out = ptr::null_mut() },
            }
            
            // Return the payload
            json_to_c_string(&payload)
        }
        Err(_) => {
            unsafe { *agent_id_out = ptr::null_mut() }
            ptr::null_mut()
        }
    }
}

/// Verify a signature on a document
#[no_mangle]
pub extern "C" fn jacs_verify_signature(
    document_string: *const c_char,
    signature_field: *const c_char,
) -> c_int {
    if document_string.is_null() {
        return -1;
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let mut agent = match JACS_AGENT.lock() {
        Ok(agent) => agent,
        Err(_) => return -3,
    };

    let doc = match agent.load_document(doc_str) {
        Ok(doc) => doc,
        Err(_) => return -4,
    };

    let document_key = doc.getkey();
    let sig_field_opt = c_string_to_option(signature_field);

    match agent.verify_document_signature(&document_key, sig_field_opt.as_ref(), None, None, None) {
        Ok(_) => 0,
        Err(_) => -5,
    }
}

// Helper function to convert C string pointer to Option<String>
fn c_string_to_option(c_str: *const c_char) -> Option<String> {
    if c_str.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(c_str) }.to_str().ok().map(|s| s.to_string())
    }
}
