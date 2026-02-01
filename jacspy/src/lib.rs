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

// Declare the module so it's recognized at the crate root
pub mod conversion_utils;

// =============================================================================
// JacsAgent Class - Preferred API for concurrent usage
// =============================================================================
// Each JacsAgent instance has its own independent state. This allows multiple
// agents to be used concurrently in the same Python process without shared
// mutable state. This is the recommended API for new code.
//
// The Arc<Mutex<Agent>> pattern ensures thread-safety:
// - Arc allows shared ownership across Python references
// - Mutex protects internal Agent state from data races
// - Works correctly with Python's GIL and future free-threading (Python 3.13+)
// =============================================================================

/// A JACS agent instance for signing and verifying documents.
///
/// Each JacsAgent has independent state, allowing multiple agents to be used
/// concurrently. This is the recommended API for new code.
///
/// Example:
///     agent = jacs.JacsAgent()
///     agent.load("/path/to/config.json")
///     signed = agent.sign_string("hello")
#[pyclass]
pub struct JacsAgent {
    inner: Arc<Mutex<Agent>>,
}

#[pymethods]
impl JacsAgent {
    #[new]
    fn new() -> Self {
        JacsAgent {
            inner: Arc::new(Mutex::new(jacs_core::get_empty_agent())),
        }
    }

    /// Load agent configuration from a file path.
    fn load(&self, config_path: String) -> PyResult<String> {
        let mut agent_ref = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to lock agent: {}",
                e
            ))
        })?;
        agent_ref.load_by_config(config_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to load agent: {}",
                e
            ))
        })?;
        Ok("Agent loaded".to_string())
    }

    /// Sign an external agent's document with this agent's registration signature.
    fn sign_agent(
        &self,
        agent_string: &str,
        public_key: &[u8],
        public_key_enc_type: &str,
    ) -> PyResult<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;

        let mut external_agent: Value = agent.validate_agent(agent_string).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Agent validation failed: {}",
                e
            ))
        })?;

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

    /// Verify a signature on data using a public key.
    fn verify_string(
        &self,
        data: &str,
        signature_base64: &str,
        public_key: &[u8],
        public_key_enc_type: &str,
    ) -> PyResult<bool> {
        let agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;

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
    }

    /// Sign a string and return the base64-encoded signature.
    fn sign_string(&self, data: &str) -> PyResult<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;
        let signed_string = agent.sign_string(&data.to_string()).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to sign string: {}",
                e
            ))
        })?;
        Ok(signed_string)
    }

    /// Verify this agent's self-signature.
    fn verify_agent(&self, agentfile: Option<String>) -> PyResult<bool> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;

        if let Some(file) = agentfile {
            let agent_result = jacs_core::load_agent(Some(file));
            match agent_result {
                Ok(loaded_agent) => {
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

    /// Update this agent with new data.
    fn update_agent(&self, new_agent_string: String) -> PyResult<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;

        match agent.update_self(&new_agent_string) {
            Ok(updated) => Ok(updated),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to update agent: {}",
                e
            ))),
        }
    }

    /// Verify a document's signature and hash.
    fn verify_document(&self, document_string: String) -> PyResult<bool> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;

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

        match agent.verify_hash(value) {
            Ok(_) => (),
            Err(e) => {
                return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to verify document hash: {}",
                    e
                )));
            }
        }

        match agent.verify_external_document_signature(&document_key) {
            Ok(_) => Ok(true),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to verify document signature: {}",
                e
            ))),
        }
    }

    /// Update an existing document.
    fn update_document(
        &self,
        document_key: String,
        new_document_string: String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> PyResult<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;

        match agent.update_document(&document_key, &new_document_string, attachments, embed) {
            Ok(doc) => Ok(doc.to_string()),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to update document: {}",
                e
            ))),
        }
    }

    /// Verify a signature field on a document.
    fn verify_signature(
        &self,
        document_string: String,
        signature_field: Option<String>,
    ) -> PyResult<bool> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;

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

        match agent.verify_document_signature(
            &document_key,
            sig_field_ref.map(|s| s.as_str()),
            None,
            None,
            None,
        ) {
            Ok(_) => Ok(true),
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to verify signature: {}",
                e
            ))),
        }
    }

    /// Create an agreement on a document requiring signatures from specified agents.
    fn create_agreement(
        &self,
        document_string: String,
        agentids: Vec<String>,
        question: Option<String>,
        context: Option<String>,
        agreement_fieldname: Option<String>,
    ) -> PyResult<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
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
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create agreement: {}",
                e
            ))),
        }
    }

    /// Sign an agreement on a document.
    fn sign_agreement(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> PyResult<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
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
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to sign agreement: {}",
                e
            ))),
        }
    }

    /// Create a new signed document.
    fn create_document(
        &self,
        document_string: String,
        custom_schema: Option<String>,
        outputfilename: Option<String>,
        no_save: Option<bool>,
        attachments: Option<String>,
        embed: Option<bool>,
    ) -> PyResult<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
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
            Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create document: {}",
                e
            ))),
        }
    }

    /// Check agreement status on a document.
    fn check_agreement(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> PyResult<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;

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

    /// Sign a request payload and return a signed JACS document.
    fn sign_request(&self, py: Python, params_obj: PyObject) -> PyResult<String> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;

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

    /// Verify a response document and return the payload.
    fn verify_response(&self, py: Python, document_string: String) -> PyResult<PyObject> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;
        let payload = agent.verify_payload(document_string, None).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to load document: {}",
                e
            ))
        })?;

        conversion_utils::value_to_pyobject(py, &payload)
    }

    /// Verify a response document and return (payload, agent_id).
    fn verify_response_with_agent_id(
        &self,
        py: Python,
        document_string: String,
    ) -> PyResult<PyObject> {
        let mut agent = self.inner.lock().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to acquire agent lock: {}",
                e
            ))
        })?;
        let (payload, agent_id) = agent
            .verify_payload_with_agent_id(document_string, None)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to load document: {}",
                    e
                ))
            })?;
        let py_payload = conversion_utils::value_to_pyobject(py, &payload)?;
        let py_agent_id: Py<pyo3::types::PyString> =
            pyo3::types::PyString::new_bound(py, &agent_id).into();

        let tuple_bound_ref =
            pyo3::types::PyTuple::new_bound(py, &[py_agent_id.into_py(py), py_payload]);
        let py_object_tuple = tuple_bound_ref.to_object(py);

        Ok(py_object_tuple)
    }
}

// =============================================================================
// Legacy Global Singleton - Deprecated, use JacsAgent class instead
// =============================================================================
// These functions use a global shared agent for backward compatibility.
// New code should use the JacsAgent class for better concurrency support.
// =============================================================================

lazy_static! {
    /// @deprecated Use JacsAgent class instead for new code.
    /// Global agent for legacy function compatibility.
    pub static ref JACS_AGENT: Arc<Mutex<Agent>> = {
        Arc::new(Mutex::new(jacs_core::get_empty_agent()))
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
    match agent.verify_document_signature(
        &document_key,
        sig_field_ref.map(|s| s.as_str()),
        None,
        None,
        None,
    ) {
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
        attachments.as_deref(),
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
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to sign payload: {}", e))
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
    let (payload, agent_id) = agent
        .verify_payload_with_agent_id(document_string, None)
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to load document: {}",
                e
            ))
        })?;
    let py_payload = conversion_utils::value_to_pyobject(py, &payload)?;
    let py_agent_id: Py<pyo3::types::PyString> =
        pyo3::types::PyString::new_bound(py, &agent_id).into();

    let tuple_bound_ref =
        pyo3::types::PyTuple::new_bound(py, &[py_agent_id.into_py(py), py_payload]);
    let py_object_tuple = tuple_bound_ref.to_object(py);

    Ok(py_object_tuple)
}

#[pyfunction]
fn handle_agent_create_py(filename: Option<String>, create_keys: bool) -> PyResult<()> {
    jacs_core::cli_utils::create::handle_agent_create(filename.as_ref(), create_keys)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn handle_config_create_py() -> PyResult<()> {
    jacs_core::cli_utils::create::handle_config_create()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn create_documents_py(
    filename: Option<String>,
    directory: Option<String>,
    outputfilename: Option<String>,
    attachments: Option<String>,
    embed: Option<bool>,
    no_save: bool,
    schema: Option<String>,
) -> PyResult<()> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    jacs_core::cli_utils::document::create_documents(
        &mut agent,
        filename.as_ref(),
        directory.as_ref(),
        outputfilename.as_ref(),
        attachments.as_deref(),
        embed,
        no_save,
        schema.as_ref(),
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn update_documents_py(
    new_filename: String,
    original_filename: String,
    outputfilename: Option<String>,
    attachment_links: Option<Vec<String>>,
    embed: Option<bool>,
    no_save: bool,
    schema: Option<String>,
) -> PyResult<()> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    jacs_core::cli_utils::document::update_documents(
        &mut agent,
        &new_filename,
        &original_filename,
        outputfilename.as_ref(),
        attachment_links,
        embed,
        no_save,
        schema.as_ref(),
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn create_agreement_py(
    agentids: Vec<String>,
    filename: Option<String>,
    schema: Option<String>,
    no_save: bool,
    directory: Option<String>,
) -> PyResult<()> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    jacs_core::cli_utils::document::create_agreement(
        &mut agent,
        agentids,
        filename.as_ref(),
        schema.as_ref(),
        no_save,
        directory.as_ref(),
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn check_agreement_py(
    schema: Option<String>,
    filename: Option<String>,
    directory: Option<String>,
) -> PyResult<()> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    jacs_core::cli_utils::document::check_agreement(
        &mut agent, // Clone the dereferenced Agent
        schema.as_ref(),
        filename.as_ref(),
        directory.as_ref(),
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn sign_documents_py(
    schema: Option<String>,
    filename: Option<String>,
    directory: Option<String>,
) -> PyResult<()> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    jacs_core::cli_utils::document::sign_documents(
        &mut agent,
        schema.as_ref(),
        filename.as_ref(),
        directory.as_ref(),
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn verify_documents_py(
    schema: Option<String>,
    filename: Option<String>,
    directory: Option<String>,
) -> PyResult<()> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    jacs_core::cli_utils::document::verify_documents(
        &mut agent,
        schema.as_ref(),
        filename.as_ref(),
        directory.as_ref(),
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn extract_documents_py(
    schema: Option<String>,
    filename: Option<String>,
    directory: Option<String>,
) -> PyResult<()> {
    let mut agent = JACS_AGENT.lock().expect("JACS_AGENT lock");
    jacs_core::cli_utils::document::extract_documents(
        &mut agent,
        schema.as_ref(),
        filename.as_ref(),
        directory.as_ref(),
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

// =============================================================================
// Simplified API Functions - New in v0.5.0
// =============================================================================
// These functions provide a streamlined interface for common operations.
// They use the jacs::simple module from the core library.
// =============================================================================

/// Create a new JACS agent with cryptographic keys.
///
/// Args:
///     name: Human-readable name for the agent
///     purpose: Optional description of the agent's purpose
///     key_algorithm: Signing algorithm ("ed25519", "rsa-pss", or "pq2025")
///
/// Returns:
///     dict with agent_id, name, public_key_path, config_path
#[pyfunction]
fn create_simple(
    name: &str,
    purpose: Option<&str>,
    key_algorithm: Option<&str>,
) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let info = jacs_core::simple::create(name, purpose, key_algorithm).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to create agent: {}",
                e
            ))
        })?;

        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("agent_id", &info.agent_id)?;
        dict.set_item("name", &info.name)?;
        dict.set_item("public_key_path", &info.public_key_path)?;
        dict.set_item("config_path", &info.config_path)?;
        Ok(dict.into())
    })
}

/// Load an existing agent from configuration.
///
/// Args:
///     config_path: Path to jacs.config.json (default: "./jacs.config.json")
#[pyfunction]
fn load_simple(config_path: Option<&str>) -> PyResult<()> {
    jacs_core::simple::load(config_path).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to load agent: {}", e))
    })
}

/// Verify the loaded agent's own integrity.
///
/// Returns:
///     dict with valid, signer_id, timestamp, errors
#[pyfunction]
fn verify_self_simple() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let result = jacs_core::simple::verify_self().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to verify self: {}",
                e
            ))
        })?;

        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("valid", result.valid)?;
        dict.set_item("signer_id", &result.signer_id)?;
        dict.set_item("timestamp", &result.timestamp)?;
        let errors: Vec<String> = result.errors;
        dict.set_item("errors", errors)?;
        Ok(dict.into())
    })
}

/// Sign a message and return a signed JACS document.
///
/// Args:
///     data: JSON string or dict to sign
///
/// Returns:
///     dict with raw, document_id, agent_id, timestamp
#[pyfunction]
fn sign_message_simple(py: Python, data: PyObject) -> PyResult<PyObject> {
    let bound_data = data.bind(py);
    let json_value = conversion_utils::pyany_to_value(py, bound_data)?;

    let signed = jacs_core::simple::sign_message(&json_value).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to sign message: {}", e))
    })?;

    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("raw", &signed.raw)?;
    dict.set_item("document_id", &signed.document_id)?;
    dict.set_item("agent_id", &signed.agent_id)?;
    dict.set_item("timestamp", &signed.timestamp)?;
    Ok(dict.into())
}

/// Sign a file with optional embedding.
///
/// Args:
///     file_path: Path to the file to sign
///     embed: If true, embed file content in document
///
/// Returns:
///     dict with raw, document_id, agent_id, timestamp
#[pyfunction]
fn sign_file_simple(file_path: &str, embed: bool) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let signed = jacs_core::simple::sign_file(file_path, embed).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to sign file: {}", e))
        })?;

        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("raw", &signed.raw)?;
        dict.set_item("document_id", &signed.document_id)?;
        dict.set_item("agent_id", &signed.agent_id)?;
        dict.set_item("timestamp", &signed.timestamp)?;
        Ok(dict.into())
    })
}

/// Verify a signed JACS document.
///
/// Args:
///     signed_document: JSON string of the signed document
///
/// Returns:
///     dict with valid, data, signer_id, timestamp, attachments, errors
#[pyfunction]
fn verify_simple(py: Python, signed_document: &str) -> PyResult<PyObject> {
    let result = jacs_core::simple::verify(signed_document).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to verify: {}", e))
    })?;

    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("valid", result.valid)?;
    dict.set_item("signer_id", &result.signer_id)?;
    dict.set_item("timestamp", &result.timestamp)?;
    let errors: Vec<String> = result.errors;
    dict.set_item("errors", errors)?;

    // Convert data to Python object
    let py_data = conversion_utils::value_to_pyobject(py, &result.data)?;
    dict.set_item("data", py_data)?;

    // Convert attachments to list of dicts
    let attachments_list = pyo3::types::PyList::empty(py);
    for att in &result.attachments {
        let att_dict = pyo3::types::PyDict::new(py);
        att_dict.set_item("filename", &att.filename)?;
        att_dict.set_item("mime_type", &att.mime_type)?;
        att_dict.set_item("hash", &att.hash)?;
        att_dict.set_item("embedded", att.embedded)?;
        attachments_list.append(att_dict)?;
    }
    dict.set_item("attachments", attachments_list)?;

    Ok(dict.into())
}

/// Export the current agent's identity JSON for P2P exchange.
///
/// Returns:
///     The agent JSON document as a string
#[pyfunction]
fn export_agent_simple() -> PyResult<String> {
    jacs_core::simple::export_agent().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to export agent: {}", e))
    })
}

/// Get the current agent's public key in PEM format.
///
/// Returns:
///     The public key as a PEM string
#[pyfunction]
fn get_public_key_pem_simple() -> PyResult<String> {
    jacs_core::simple::get_public_key_pem().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to get public key: {}",
            e
        ))
    })
}

// =============================================================================
// Trust Store Functions
// =============================================================================

/// Add an agent to the local trust store.
///
/// Args:
///     agent_json: The full agent JSON string
///
/// Returns:
///     The agent ID if successfully trusted
#[pyfunction]
fn trust_agent_simple(agent_json: &str) -> PyResult<String> {
    jacs_core::trust::trust_agent(agent_json).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to trust agent: {}", e))
    })
}

/// List all trusted agent IDs.
///
/// Returns:
///     List of agent IDs in the trust store
#[pyfunction]
fn list_trusted_agents_simple() -> PyResult<Vec<String>> {
    jacs_core::trust::list_trusted_agents().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to list trusted agents: {}",
            e
        ))
    })
}

/// Remove an agent from the trust store.
///
/// Args:
///     agent_id: The ID of the agent to untrust
#[pyfunction]
fn untrust_agent_simple(agent_id: &str) -> PyResult<()> {
    jacs_core::trust::untrust_agent(agent_id).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to untrust agent: {}",
            e
        ))
    })
}

/// Check if an agent is in the trust store.
///
/// Args:
///     agent_id: The ID of the agent to check
///
/// Returns:
///     True if the agent is trusted
#[pyfunction]
fn is_trusted_simple(agent_id: &str) -> bool {
    jacs_core::trust::is_trusted(agent_id)
}

/// Get a trusted agent's JSON document.
///
/// Args:
///     agent_id: The ID of the agent
///
/// Returns:
///     The agent JSON string
#[pyfunction]
fn get_trusted_agent_simple(agent_id: &str) -> PyResult<String> {
    jacs_core::trust::get_trusted_agent(agent_id).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to get trusted agent: {}",
            e
        ))
    })
}

#[pymodule]
fn jacs(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3::prepare_freethreaded_python();

    // Add the JacsAgent class - recommended API for new code
    m.add_class::<JacsAgent>()?;

    // =============================================================================
    // Simplified API - New in v0.5.0
    // =============================================================================
    m.add_function(wrap_pyfunction!(create_simple, m)?)?;
    m.add_function(wrap_pyfunction!(load_simple, m)?)?;
    m.add_function(wrap_pyfunction!(verify_self_simple, m)?)?;
    m.add_function(wrap_pyfunction!(sign_message_simple, m)?)?;
    m.add_function(wrap_pyfunction!(sign_file_simple, m)?)?;
    m.add_function(wrap_pyfunction!(verify_simple, m)?)?;
    m.add_function(wrap_pyfunction!(export_agent_simple, m)?)?;
    m.add_function(wrap_pyfunction!(get_public_key_pem_simple, m)?)?;

    // Trust store functions
    m.add_function(wrap_pyfunction!(trust_agent_simple, m)?)?;
    m.add_function(wrap_pyfunction!(list_trusted_agents_simple, m)?)?;
    m.add_function(wrap_pyfunction!(untrust_agent_simple, m)?)?;
    m.add_function(wrap_pyfunction!(is_trusted_simple, m)?)?;
    m.add_function(wrap_pyfunction!(get_trusted_agent_simple, m)?)?;

    #[pyfn(m, name = "log_to_python")]
    fn py_log_to_python(py: Python, message: String, log_level: String) -> PyResult<()> {
        log_to_python(py, &message, &log_level)
    }

    // Legacy functions using global singleton - deprecated, use JacsAgent class instead
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
