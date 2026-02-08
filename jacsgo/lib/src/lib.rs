use ::jacs as jacs_core;
use jacs_core::agent::document::DocumentTraits;
use jacs_core::agent::payloads::PayloadTraits;
use jacs_core::agent::{AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME, Agent};
use jacs_core::crypt::KeyManager;
use jacs_core::crypt::hash::hash_string as core_hash_string;
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
use conversion_utils::json_to_c_string;

// ============================================================================
// JacsAgent Handle API - Recommended for concurrent usage
// ============================================================================
// Each JacsAgent handle has independent state, allowing multiple agents to be
// used concurrently in the same process. This is the recommended API for new code.

/// Opaque handle to a JACS agent instance.
/// Each handle maintains independent state and can be used concurrently.
pub struct JacsAgentHandle {
    agent: Arc<Mutex<Agent>>,
}

/// Create a new JacsAgent handle.
/// Returns a pointer to the handle, or null on failure.
/// The handle must be freed with jacs_agent_free() when no longer needed.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_new() -> *mut JacsAgentHandle {
    let handle = Box::new(JacsAgentHandle {
        agent: Arc::new(Mutex::new(jacs_core::get_empty_agent())),
    });
    Box::into_raw(handle)
}

/// Free a JacsAgent handle.
/// After this call, the handle pointer is invalid and must not be used.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_free(handle: *mut JacsAgentHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle);
        }
    }
}

/// Load JACS configuration into an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_load(
    handle: *mut JacsAgentHandle,
    config_path: *const c_char,
) -> c_int {
    if handle.is_null() || config_path.is_null() {
        return -1;
    }

    let config_path_str = match unsafe { CStr::from_ptr(config_path) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let handle_ref = unsafe { &*handle };
    let mut agent_ref = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return -3,
    };

    match agent_ref.load_by_config(config_path_str.to_string()) {
        Ok(_) => 0,
        Err(_) => -4,
    }
}

/// Sign a string using an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_sign_string(
    handle: *mut JacsAgentHandle,
    data: *const c_char,
) -> *mut c_char {
    if handle.is_null() || data.is_null() {
        return ptr::null_mut();
    }

    let data_str = match unsafe { CStr::from_ptr(data) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
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

/// Verify a string signature using an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_verify_string(
    handle: *mut JacsAgentHandle,
    data: *const c_char,
    signature_base64: *const c_char,
    public_key: *const u8,
    public_key_len: size_t,
    public_key_enc_type: *const c_char,
) -> c_int {
    if handle.is_null()
        || data.is_null()
        || signature_base64.is_null()
        || public_key.is_null()
        || public_key_enc_type.is_null()
    {
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

    let handle_ref = unsafe { &*handle };
    let agent = match handle_ref.agent.lock() {
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

/// Sign a request payload using an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_sign_request(
    handle: *mut JacsAgentHandle,
    payload_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() || payload_json.is_null() {
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

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
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

/// Verify a response payload using an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_verify_response(
    handle: *mut JacsAgentHandle,
    document_string: *const c_char,
) -> *mut c_char {
    if handle.is_null() || document_string.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match agent.verify_payload(doc_str.to_string(), None) {
        Ok(payload) => json_to_c_string(&payload),
        Err(_) => ptr::null_mut(),
    }
}

/// Create an agreement using an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_create_agreement(
    handle: *mut JacsAgentHandle,
    document_string: *const c_char,
    agentids_json: *const c_char,
    question: *const c_char,
    context: *const c_char,
    agreement_fieldname: *const c_char,
) -> *mut c_char {
    if handle.is_null() || document_string.is_null() || agentids_json.is_null() {
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

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match jacs_core::shared::document_add_agreement(
        &mut agent,
        &doc_str.to_string(),
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

/// Sign an agreement using an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_sign_agreement(
    handle: *mut JacsAgentHandle,
    document_string: *const c_char,
    agreement_fieldname: *const c_char,
) -> *mut c_char {
    if handle.is_null() || document_string.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match jacs_core::shared::document_sign_agreement(
        &mut agent,
        &doc_str.to_string(),
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

/// Check an agreement using an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_check_agreement(
    handle: *mut JacsAgentHandle,
    document_string: *const c_char,
    agreement_fieldname: *const c_char,
) -> *mut c_char {
    if handle.is_null() || document_string.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match jacs_core::shared::document_check_agreement(
        &mut agent,
        &doc_str.to_string(),
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

/// Verify an agent using a handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_verify_agent(
    handle: *mut JacsAgentHandle,
    agentfile: *const c_char,
) -> c_int {
    if handle.is_null() {
        return -1;
    }

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return -2,
    };

    if !agentfile.is_null() {
        let file_str = match unsafe { CStr::from_ptr(agentfile) }.to_str() {
            Ok(s) => s,
            Err(_) => return -3,
        };

        let agent_result = jacs_core::load_agent(Some(file_str.to_string()));
        match agent_result {
            Ok(loaded_agent) => {
                *agent = loaded_agent;
            }
            Err(_) => return -4,
        }
    }

    if let Err(_) = agent.verify_self_signature() {
        return -5;
    }

    match agent.verify_self_hash() {
        Ok(_) => 0,
        Err(_) => -6,
    }
}

/// Create a document using an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_create_document(
    handle: *mut JacsAgentHandle,
    document_string: *const c_char,
    custom_schema: *const c_char,
    outputfilename: *const c_char,
    no_save: c_int,
    attachments: *const c_char,
    embed: c_int,
) -> *mut c_char {
    if handle.is_null() || document_string.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    let embed_opt = if embed > 0 {
        Some(true)
    } else if embed < 0 {
        Some(false)
    } else {
        None
    };

    match jacs_core::shared::document_create(
        &mut agent,
        &doc_str.to_string(),
        c_string_to_option(custom_schema),
        c_string_to_option(outputfilename),
        no_save != 0,
        c_string_to_option(attachments).as_deref(),
        embed_opt,
    ) {
        Ok(result) => match CString::new(result) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Verify a document using an agent handle.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_verify_document(
    handle: *mut JacsAgentHandle,
    document_string: *const c_char,
) -> c_int {
    if handle.is_null() || document_string.is_null() {
        return -1;
    }

    let doc_str = match unsafe { CStr::from_ptr(document_string) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return -3,
    };

    let doc = match agent.load_document(&doc_str.to_string()) {
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

/// Verify a document by its ID from storage using an agent handle.
/// The document_id should be in "uuid:version" format.
/// Returns 0 on success (valid), -1 to -6 for various errors.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_verify_document_by_id(
    handle: *mut JacsAgentHandle,
    document_id: *const c_char,
) -> c_int {
    if handle.is_null() || document_id.is_null() {
        return -1;
    }

    let doc_id_str = match unsafe { CStr::from_ptr(document_id) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    // Validate format
    if !doc_id_str.contains(':') {
        return -3;
    }

    use jacs_core::storage::StorageDocumentTraits;

    let storage = match jacs_core::storage::MultiStorage::default_new() {
        Ok(s) => s,
        Err(_) => return -4,
    };

    let doc = match storage.get_document(doc_id_str) {
        Ok(d) => d,
        Err(_) => return -5,
    };

    let doc_str = match serde_json::to_string(&doc.value) {
        Ok(s) => s,
        Err(_) => return -6,
    };

    let handle_ref = unsafe { &*handle };
    let mut agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return -7,
    };

    let loaded_doc = match agent.load_document(&doc_str) {
        Ok(d) => d,
        Err(_) => return -8,
    };

    let document_key = loaded_doc.getkey();
    let value = loaded_doc.getvalue();

    if let Err(_) = agent.verify_hash(value) {
        return -9;
    }

    match agent.verify_external_document_signature(&document_key) {
        Ok(_) => 0,
        Err(_) => -10,
    }
}

/// Re-encrypt the agent's private key with a new password.
/// Returns 0 on success, negative values on error.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_reencrypt_key(
    handle: *mut JacsAgentHandle,
    old_password: *const c_char,
    new_password: *const c_char,
) -> c_int {
    if handle.is_null() || old_password.is_null() || new_password.is_null() {
        return -1;
    }

    let old_pw = match unsafe { CStr::from_ptr(old_password) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let new_pw = match unsafe { CStr::from_ptr(new_password) }.to_str() {
        Ok(s) => s,
        Err(_) => return -3,
    };

    let handle_ref = unsafe { &*handle };
    let agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return -4,
    };

    // Get key path from agent config
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

    let encrypted_data = match std::fs::read(&key_path) {
        Ok(d) => d,
        Err(_) => return -5,
    };

    use jacs_core::crypt::aes_encrypt::reencrypt_private_key;
    let re_encrypted = match reencrypt_private_key(&encrypted_data, old_pw, new_pw) {
        Ok(d) => d,
        Err(_) => return -6,
    };

    match std::fs::write(&key_path, &re_encrypted) {
        Ok(_) => 0,
        Err(_) => -7,
    }
}

/// Get the agent's JSON representation as a string.
/// Returns a C string that must be freed with jacs_free_string(), or null on error.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_agent_get_json(handle: *mut JacsAgentHandle) -> *mut c_char {
    if handle.is_null() {
        return ptr::null_mut();
    }

    let handle_ref = unsafe { &*handle };
    let agent = match handle_ref.agent.lock() {
        Ok(agent) => agent,
        Err(_) => return ptr::null_mut(),
    };

    match agent.get_value() {
        Some(value) => match CString::new(value.to_string()) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

// ============================================================================
// Legacy Global Singleton API - Deprecated, use JacsAgent handle API instead
// ============================================================================
// The following functions use a global singleton for backwards compatibility.
// New code should use the jacs_agent_* functions above.

lazy_static! {
    /// @deprecated Use jacs_agent_new() instead.
    pub static ref JACS_AGENT: Arc<Mutex<Agent>> = {
        let agent: Arc<Mutex<Agent>> = Arc::new(Mutex::new(jacs_core::get_empty_agent()));
        return agent;
    };
}

/// Load JACS configuration from the specified path
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub extern "C" fn jacs_hash_string(data: *const c_char) -> *mut c_char {
    if data.is_null() {
        return ptr::null_mut();
    }

    let data_str = match unsafe { CStr::from_ptr(data) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let hash = core_hash_string(&data_str.to_string());

    match CString::new(hash) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Verify a string signature
#[unsafe(no_mangle)]
pub extern "C" fn jacs_verify_string(
    data: *const c_char,
    signature_base64: *const c_char,
    public_key: *const u8,
    public_key_len: size_t,
    public_key_enc_type: *const c_char,
) -> c_int {
    if data.is_null()
        || signature_base64.is_null()
        || public_key.is_null()
        || public_key_enc_type.is_null()
    {
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

    match agent.update_self(&agent_str.to_string()) {
        Ok(updated) => match CString::new(updated) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Verify a document
#[unsafe(no_mangle)]
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

    let doc = match agent.load_document(&doc_str.to_string()) {
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

/// Verify a signed document without loading an agent (standalone).
/// Returns a JSON string `{"valid":bool,"signer_id":"..."}` that must be freed with jacs_free_string, or null on error.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_verify_document_standalone(
    signed_document: *const c_char,
    key_resolution: *const c_char,
    data_directory: *const c_char,
    key_directory: *const c_char,
) -> *mut c_char {
    if signed_document.is_null() {
        return ptr::null_mut();
    }
    let doc_str = match unsafe { CStr::from_ptr(signed_document) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let kr = if key_resolution.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(key_resolution) }.to_str().ok()
    };
    let dd = if data_directory.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(data_directory) }.to_str().ok()
    };
    let kd = if key_directory.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(key_directory) }.to_str().ok()
    };
    match jacs_binding_core::verify_document_standalone(doc_str, kr, dd, kd) {
        Ok(r) => {
            let json = serde_json::json!({ "valid": r.valid, "signer_id": r.signer_id });
            match CString::new(json.to_string()) {
                Ok(cs) => cs.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Update a document
#[unsafe(no_mangle)]
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

    match agent.update_document(
        &key_str.to_string(),
        &doc_str.to_string(),
        attachments,
        embed_opt,
    ) {
        Ok(doc) => match CString::new(doc.to_string()) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Create a document
#[unsafe(no_mangle)]
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

    let embed_opt = if embed > 0 {
        Some(true)
    } else if embed < 0 {
        Some(false)
    } else {
        None
    };

    match jacs_core::shared::document_create(
        &mut agent,
        &doc_str.to_string(),
        c_string_to_option(custom_schema),
        c_string_to_option(outputfilename),
        no_save != 0,
        c_string_to_option(attachments).as_deref(),
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
#[unsafe(no_mangle)]
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
        &doc_str.to_string(),
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
#[unsafe(no_mangle)]
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
        &doc_str.to_string(),
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
#[unsafe(no_mangle)]
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
        &doc_str.to_string(),
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

    let doc = match agent.load_document(&doc_str.to_string()) {
        Ok(doc) => doc,
        Err(_) => return -4,
    };

    let document_key = doc.getkey();
    let sig_field_opt = c_string_to_option(signature_field);

    match agent.verify_document_signature(&document_key, sig_field_opt.as_deref(), None, None, None)
    {
        Ok(_) => 0,
        Err(_) => -5,
    }
}

/// Run a read-only security audit and health checks.
/// config_path and recent_n may be null for defaults.
/// Returns a JSON string that must be freed with jacs_free_string(), or null on error.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_audit(
    config_path: *const c_char,
    recent_n: c_int,
) -> *mut c_char {
    let config = if config_path.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(config_path) }.to_str() {
            Ok(s) => Some(s),
            Err(_) => return ptr::null_mut(),
        }
    };

    let recent = if recent_n > 0 {
        Some(recent_n as u32)
    } else {
        None
    };

    match jacs_binding_core::audit(config, recent) {
        Ok(json_string) => match CString::new(json_string) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

/// Generate a verification URL for a signed JACS document.
/// Returns a C string that must be freed with jacs_free_string(), or null on error.
#[unsafe(no_mangle)]
pub extern "C" fn jacs_generate_verify_link(
    document: *const c_char,
    base_url: *const c_char,
) -> *mut c_char {
    if document.is_null() || base_url.is_null() {
        return ptr::null_mut();
    }

    let doc_str = match unsafe { CStr::from_ptr(document) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let base_url_str = match unsafe { CStr::from_ptr(base_url) }.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match jacs_binding_core::hai::generate_verify_link(doc_str, base_url_str) {
        Ok(url) => match CString::new(url) {
            Ok(c_string) => c_string.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

// Helper function to convert C string pointer to Option<String>
fn c_string_to_option(c_str: *const c_char) -> Option<String> {
    if c_str.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(c_str) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }
}
