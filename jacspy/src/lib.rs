use jacs::agent::{AGENT_REGISTRATION_SIGNATURE_FIELDNAME, AGENT_SIGNATURE_FIELDNAME, Agent};
use jacs::config::set_env_vars;
use jacs::crypt::KeyManager;
use jacs::crypt::hash::hash_string as jacs_hash_string;
use jacs::load_agent_by_id;
use lazy_static::lazy_static;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use serde_json::Value;
use std::sync::Arc;
use std::sync::Mutex;

// Add these imports for the trait methods to be available
use jacs::agent::document::DocumentTraits;

// mod zkp;
// use std::panic::{catch_unwind, AssertUnwindSafe};

// todo replace with new jacs config file that is baked in where we want immutable changes

lazy_static! {
    pub static ref JACS_AGENT: Arc<Mutex<Agent>> = {
        let _ = set_env_vars(false, None, false);
        let mut agent = load_agent_by_id();
        Arc::new(Mutex::new(agent))

    };
    // todo use    load agent private key for system
}

fn log_to_python(py: Python, message: &str, log_level: &str) -> PyResult<()> {
    let logging = py.import("logging")?;
    logging.call_method1(log_level, (message,))?;
    Ok(())
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
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
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
fn hash_string(data: &str) -> PyResult<String> {
    return Ok(jacs_hash_string(&data.to_string()));
}

#[pyfunction]
fn create_config(
    py: Python,
    jacs_use_filesystem: Option<String>,
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
    let config = jacs::config::Config::new(
        "https://hai.ai/schemas/jacs.config.schema.json".to_string(),
        jacs_use_filesystem,
        jacs_use_security,
        jacs_data_directory,
        jacs_key_directory,
        jacs_agent_private_key_filename,
        jacs_agent_public_key_filename,
        jacs_agent_key_algorithm,
        Some("v1".to_string()),
        Some("v1".to_string()),
        Some("v1".to_string()),
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
        let agent_result = jacs::load_agent(Some(file));
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
    match agent.verify_document_signature(&document_key, None, None, None, None) {
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
    match jacs::shared::document_add_agreement(
        &mut agent,
        &document_string,
        agentids,
        None,  // custom_schema
        None,  // save_filename
        question,  // question - pass None, not a reference
        context,  // context - pass None, not a reference
        None,  // export_embedded
        None,  // extract_only
        false, // load_only
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

    match jacs::shared::document_sign_agreement(
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

    match jacs::shared::document_create(
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

    match jacs::shared::document_check_agreement(
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

#[pymodule]
fn jacspy(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[pyfn(m, name = "log_to_python")]
    fn py_log_to_python(py: Python, message: String, log_level: String) -> PyResult<()> {
        log_to_python(py, &message, &log_level)
    }

    m.add_function(wrap_pyfunction!(verify_string, m)?)?;
    m.add_function(wrap_pyfunction!(hash_string, m)?)?;
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

    Ok(())
}
