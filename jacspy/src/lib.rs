use ::jacs as jacs_core;
use jacs_core::agent::document::DocumentTraits;
use jacs_core::agent::payloads::PayloadTraits; 
use jacs_core::agent::{AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME, Agent};
use jacs_core::crypt::KeyManager;
use jacs_core::crypt::hash::hash_string as jacs_hash_string;
use lazy_static::lazy_static;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use serde_json::Value;
use std::sync::Arc;
use std::sync::Mutex;
// use pyo3::types::PyDateTime;

// Declare the module so it's recognized at the crate root
pub mod conversion_utils;

lazy_static! {
    pub static ref JACS_AGENT: Arc<Mutex<Agent>> = {
        let agent: Arc<Mutex<Agent>> = Arc::new(Mutex::new(jacs_core::get_empty_agent()));
        return agent;
    };
}

fn log_to_python(py: Python, message: &str, log_level: &str) -> PyResult<()> {
    let logging = py.import("logging")?;
    logging.call_method1(log_level, (message,))?;
    Ok(())
}

#[pyfunction]
fn load(py: Python, config_path: &str) -> PyResult<String> {
    let mut agent_ref = JACS_AGENT.lock().expect("Failed to lock agent");
    agent_ref
        .load_by_config(config_path.to_string())
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to load agent: {}",
                e
            ))
        })?;
    Ok("Agent loaded".to_string())
}

// expects self signed agents
#[pyfunction]
fn sign_agent(
    py: Python,
    agent_string: &str,
    public_key: &[u8],
    public_key_enc_type: &str,
) -> PyResult<String> {
    let mut agent = JACS_AGENT.lock().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to acquire JACS_AGENT lock: {}",
            e
        ))
    })?;

    let mut external_agent: Value = agent.validate_agent(agent_string).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Agent validation failed: {}", e))
    })?;

    // Attempt to log to Python
    // let public_key_string = String::from_utf8(public_key.to_vec()).expect("Invalid UTF-8");
    // let public_key_rehash2 = jacs_hash_string(&public_key_string);
    // let public_key_string_lossy = String::from_utf8_lossy(public_key).to_string();
    // let public_key_rehash3 = jacs_hash_string(&public_key_string_lossy);

    // let astr  = format!("{:?}", public_key) ;
    // let public_key_rehash5 = jacs_hash_string(&astr);
    // log_to_python(py, &format!("sign_agent public_key {:?} {:?} {:?}      {}", public_key_rehash5, public_key_rehash3, public_key_rehash2, String::from_utf8_lossy(public_key)), "error")?;

    // Proceed with signature verification
    agent
        .signature_verification_procedure(
            &external_agent,
            None,
            &AGENT_SIGNATURE_FIELDNAME.to_string(),
            public_key.to_vec(),
            Some(public_key_enc_type.to_string()),
            None,
            None,
        )
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Signature verification failed: {}",
                e
            ))
        })?;

    // If all previous steps pass, proceed with signing
    let registration_signature = agent
        .signing_procedure(
            &external_agent,
            None,
            &AGENT_REGISTRATION_SIGNATURE_FIELDNAME.to_string(),
        )
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Signing procedure failed: {}",
                e
            ))
        })?;
    external_agent[AGENT_REGISTRATION_SIGNATURE_FIELDNAME] = registration_signature;
    Ok(external_agent.to_string())
}

#[pyfunction]
fn verify_string(
    data: &str,
    signature_base64: &str,
    public_key: &[u8],
    public_key_enc_type: &str,
) -> PyResult<bool> {
    // Convert the public_key Vec<u8> to a Python bytes object
    // let py_public_key = PyBytes::new(Python::acquire_gil().python(), &public_key);
    let agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    if data.is_empty()
        || signature_base64.is_empty()
        || public_key.is_empty()
        || public_key_enc_type.is_empty()
    {
        return Err(PyErr::new::<pyo3::exceptions::PyException, _>(format!(
            "one param is empty \ndata {} \nsignature_base64 {} \npublic_key {:?} \npublic_key_enc_type {} ",
            data, signature_base64, public_key, public_key_enc_type
        )));
    }
    match agent.verify_string(
        &data.to_string(),
        &signature_base64.to_string(),
        public_key.to_vec(),
        Some(public_key_enc_type.to_string()),
    ) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyException, _>(format!(
            "signature fail: {}",
            e
        ))),
    }

    // let result = catch_unwind(AssertUnwindSafe(|| {
    //     match agent.verify_string(&data.to_string(), &signature_base64.to_string(), public_key.to_vec(), Some(public_key_enc_type.to_string())) {
    //         Ok(v) => Ok(v),
    //         Err(e) => Err(PyErr::new::<pyo3::exceptions::PyException, _>(format!("signature fail: {}", e))),
    //     }

    // }));

    // match result {
    //     Ok(result) => Ok(result),
    //     Err(_) => Err(PyErr::new::<pyo3::exceptions::PyException, _>(
    //         "An internal error occurred.",
    //     )),
    // }
}

#[pyfunction]
fn sign_string(py: Python, data: &str) -> PyResult<String> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    let signed_string = agent.sign_string(&data.to_string()).expect("string sig");

    // // Add a timestamp field to the JSON payload object
    // let timestamp = chrono::Utc::now().timestamp();
    // payload["sending-timestamp"] = serde_json::Value::Number(timestamp.into());
    // payload["sending-agent"] = serde_json::Value::String(agent_id_and_version.into());

    // let payload_str = serde_json::to_string(&payload).expect("Failed to serialize JSON");

    // let payload_signature = self.agent.sign_string(&payload_str).expect("string sig");
    Ok(signed_string)
}

#[pyfunction]
fn hash_string(data: &str) -> PyResult<String> {
    return Ok(jacs_hash_string(&data.to_string()));
}

#[pyfunction]
fn create_config(
    py: Python,
    jacs_use_security: Option<String>,
    jacs_data_directory: Option<String>,
    jacs_key_directory: Option<String>,
    jacs_agent_private_key_filename: Option<String>,
    jacs_agent_public_key_filename: Option<String>,
    jacs_agent_key_algorithm: Option<String>,
    jacs_private_key_password: Option<String>,
    jacs_agent_id_and_version: Option<String>,
    jacs_default_storage: Option<String>,
) -> PyResult<String> {
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
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to serialize config: {}",
            e
        ))),
    }
}

#[pyfunction]
fn verify_agent(py: Python, agentfile: Option<String>) -> PyResult<bool> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

    if let Some(file) = agentfile {
        // Load agent from file using the FileLoader trait
        let agent_result = jacs_core::load_agent(Some(file));
        match agent_result {
            Ok(loaded_agent) => {
                // Replace the current agent
                *agent = loaded_agent;
            }
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to load agent: {}",
                    e
                )));
            }
        }
    }

    match agent.verify_self_signature() {
        Ok(_) => (),
        Err(e) => {
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to verify agent signature: {}",
                e
            )));
        }
    }

    match agent.verify_self_hash() {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to verify agent hash: {}",
            e
        ))),
    }
}

#[pyfunction]
fn update_agent(py: Python, new_agent_string: String) -> PyResult<String> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

    match agent.update_self(&new_agent_string) {
        Ok(updated) => Ok(updated),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to update agent: {}",
            e
        ))),
    }
}

#[pyfunction]
fn verify_document(py: Python, document_string: String) -> PyResult<bool> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

    // Load document using the DocumentTraits trait
    let doc_result = agent.load_document(&document_string);
    let doc = match doc_result {
        Ok(doc) => doc,
        Err(e) => {
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to load document: {}",
                e
            )));
        }
    };

    let document_key = doc.getkey();
    let value = doc.getvalue();

    // Verify hash
    match agent.verify_hash(value) {
        Ok(_) => (),
        Err(e) => {
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to verify document hash: {}",
                e
            )));
        }
    }

    // Verify signature using the DocumentTraits trait method
    match agent.verify_external_document_signature(&document_key) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to verify document signature: {}",
            e
        ))),
    }
}

#[pyfunction]
fn update_document(
    py: Python,
    document_key: String,
    new_document_string: String,
    attachments: Option<Vec<String>>,
    embed: Option<bool>,
) -> PyResult<String> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

    // Use the DocumentTraits trait method
    match agent.update_document(&document_key, &new_document_string, attachments, embed) {
        Ok(doc) => Ok(doc.to_string()),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to update document: {}",
            e
        ))),
    }
}

#[pyfunction]
fn verify_signature(
    py: Python,
    document_string: String,
    signature_field: Option<String>,
) -> PyResult<bool> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

    // Load document using the DocumentTraits trait
    let doc_result = agent.load_document(&document_string);
    let doc = match doc_result {
        Ok(doc) => doc,
        Err(e) => {
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to load document: {}",
                e
            )));
        }
    };

    let document_key = doc.getkey();
    let sig_field_ref = signature_field.as_ref();

    // Verify signature using the DocumentTraits trait method
    // FIXME get the public key from the document
    match agent.verify_document_signature(&document_key, sig_field_ref, None, None, None) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to verify signature: {}",
            e
        ))),
    }
}

#[pyfunction]
fn create_agreement(
    py: Python,
    document_string: String,
    agentids: Vec<String>,
    question: Option<String>,
    context: Option<String>,
    agreement_fieldname: Option<String>,
) -> PyResult<String> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

    // The function expects None for these parameters, not references
    match jacs_core::shared::document_add_agreement(
        &mut agent,
        &document_string,
        agentids,
        None,     // custom_schema
        None,     // save_filename
        question, // question - pass None, not a reference
        context,  // context - pass None, not a reference
        None,     // export_embedded
        None,     // extract_only
        false,    // load_only
        agreement_fieldname,
    ) {
        Ok(result) => Ok(result),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to create agreement: {}",
            e
        ))),
    }
}

#[pyfunction]
fn sign_agreement(
    py: Python,
    document_string: String,
    agreement_fieldname: Option<String>,
) -> PyResult<String> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

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
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to sign agreement: {}",
            e
        ))),
    }
}

#[pyfunction]
fn create_document(
    py: Python,
    document_string: String,
    custom_schema: Option<String>,
    outputfilename: Option<String>,
    no_save: Option<bool>,
    attachments: Option<String>,
    embed: Option<bool>,
) -> PyResult<String> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

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
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to create document: {}",
            e
        ))),
    }
}

#[pyfunction]
fn check_agreement(
    py: Python,
    document_string: String,
    agreement_fieldname: Option<String>,
) -> PyResult<String> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

    match jacs_core::shared::document_check_agreement(
        &mut agent,
        &document_string,
        None,
        agreement_fieldname,
    ) {
        Ok(result) => Ok(result),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to check agreement: {}",
            e
        ))),
    }
}

#[pyfunction]
fn sign_request(py: Python, params_obj: PyObject) -> PyResult<String> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");

    let bound_params = params_obj.bind(py);
    let payload_value = conversion_utils::pyany_to_value(py, bound_params)?;
    let payload_string = agent.sign_payload(payload_value).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to sign payload: {}",
            e
        ))
    })?;
    Ok(payload_string)
}

/**
 * a jacs document is verified and then the payload is returned in the type is was first created as
 */
#[pyfunction]
fn verify_response(py: Python, document_string: String) -> PyResult<PyObject> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    let payload = agent.verify_payload(document_string, None).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to load document: {}", e))
    })?;

    conversion_utils::value_to_pyobject(py, &payload)
}

#[pyfunction]
fn verify_response_with_agent_id(py: Python, document_string: String) -> PyResult<PyObject> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    let (payload, agent_id) = agent.verify_payload_with_agent_id(document_string, None).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to load document: {}", e))
    })?;
    let py_payload = conversion_utils::value_to_pyobject(py, &payload)?;
    let py_agent_id: Py<pyo3::types::PyString> =
        pyo3::types::PyString::new_bound(py, &agent_id).into();

    let tuple_bound_ref =
        pyo3::types::PyTuple::new_bound(py, &[py_agent_id.into_py(py), py_payload]);
    let py_object_tuple = tuple_bound_ref.to_object(py);

    Ok(py_object_tuple)
}

#[pymodule]
fn jacs(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3::prepare_freethreaded_python();
    // pyo3::types::PyDateTime::init_type();

    #[pyfn(m, name = "log_to_python")]
    fn py_log_to_python(py: Python, message: String, log_level: String) -> PyResult<()> {
        log_to_python(py, &message, &log_level)
    }

    m.add_function(wrap_pyfunction!(verify_string, m)?)?;
    m.add_function(wrap_pyfunction!(hash_string, m)?)?;
    m.add_function(wrap_pyfunction!(sign_string, m)?)?;
    m.add_function(wrap_pyfunction!(load, m)?)?;
    m.add_function(wrap_pyfunction!(verify_response_with_agent_id, m)?)?;

    m.add_function(wrap_pyfunction!(sign_agent, m)?)?;
    m.add_function(wrap_pyfunction!(create_config, m)?)?;
    m.add_function(wrap_pyfunction!(verify_agent, m)?)?;
    m.add_function(wrap_pyfunction!(update_agent, m)?)?;
    m.add_function(wrap_pyfunction!(verify_document, m)?)?;
    m.add_function(wrap_pyfunction!(update_document, m)?)?;
    m.add_function(wrap_pyfunction!(verify_signature, m)?)?;
    m.add_function(wrap_pyfunction!(create_agreement, m)?)?;
    m.add_function(wrap_pyfunction!(sign_agreement, m)?)?;
    m.add_function(wrap_pyfunction!(create_document, m)?)?;
    m.add_function(wrap_pyfunction!(check_agreement, m)?)?;

    m.add_function(wrap_pyfunction!(sign_request, m)?)?;
    m.add_function(wrap_pyfunction!(verify_response, m)?)?;

    Ok(())
}
