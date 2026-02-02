//! Python bindings for JACS (JSON AI Communication Standard).
//!
//! This module provides Python bindings using PyO3, built on top of the
//! shared `jacs-binding-core` crate for common functionality.

use ::jacs as jacs_core;
use jacs_binding_core::{AgentWrapper, BindingCoreError, BindingResult};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

// Declare the module so it's recognized at the crate root
pub mod conversion_utils;

// =============================================================================
// Error Conversion: BindingCoreError -> PyErr
// =============================================================================

/// Convert a BindingCoreError to a PyErr.
fn to_py_err(e: BindingCoreError) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.message)
}

/// Extension trait to convert BindingResult to PyResult.
trait ToPyResult<T> {
    fn to_py(self) -> PyResult<T>;
}

impl<T> ToPyResult<T> for BindingResult<T> {
    fn to_py(self) -> PyResult<T> {
        self.map_err(to_py_err)
    }
}

// =============================================================================
// JacsAgent Class - Primary API for concurrent usage
// =============================================================================
// Each JacsAgent instance has its own independent state. This allows multiple
// agents to be used concurrently in the same Python process without shared
// mutable state. This is the recommended API for all code.
//
// The Arc<Mutex<Agent>> pattern ensures thread-safety:
// - Arc allows shared ownership across Python references
// - Mutex protects internal Agent state from data races
// - Works correctly with Python's GIL and future free-threading (Python 3.13+)
// =============================================================================

/// A JACS agent instance for signing and verifying documents.
///
/// Each JacsAgent has independent state, allowing multiple agents to be used
/// concurrently. This is the recommended API for all code.
///
/// Example:
///     agent = jacs.JacsAgent()
///     agent.load("/path/to/config.json")
///     signed = agent.sign_string("hello")
#[pyclass]
pub struct JacsAgent {
    inner: AgentWrapper,
}

#[pymethods]
impl JacsAgent {
    #[new]
    fn new() -> Self {
        JacsAgent {
            inner: AgentWrapper::new(),
        }
    }

    /// Load agent configuration from a file path.
    fn load(&self, config_path: String) -> PyResult<String> {
        self.inner.load(config_path).to_py()
    }

    /// Sign an external agent's document with this agent's registration signature.
    fn sign_agent(
        &self,
        agent_string: &str,
        public_key: &[u8],
        public_key_enc_type: &str,
    ) -> PyResult<String> {
        self.inner
            .sign_agent(agent_string, public_key.to_vec(), public_key_enc_type.to_string())
            .to_py()
    }

    /// Verify a signature on data using a public key.
    fn verify_string(
        &self,
        data: &str,
        signature_base64: &str,
        public_key: &[u8],
        public_key_enc_type: &str,
    ) -> PyResult<bool> {
        self.inner
            .verify_string(
                data,
                signature_base64,
                public_key.to_vec(),
                public_key_enc_type.to_string(),
            )
            .to_py()
    }

    /// Sign a string and return the base64-encoded signature.
    fn sign_string(&self, data: &str) -> PyResult<String> {
        self.inner.sign_string(data).to_py()
    }

    /// Verify this agent's self-signature.
    fn verify_agent(&self, agentfile: Option<String>) -> PyResult<bool> {
        self.inner.verify_agent(agentfile).to_py()
    }

    /// Update this agent with new data.
    fn update_agent(&self, new_agent_string: String) -> PyResult<String> {
        self.inner.update_agent(&new_agent_string).to_py()
    }

    /// Verify a document's signature and hash.
    fn verify_document(&self, document_string: String) -> PyResult<bool> {
        self.inner.verify_document(&document_string).to_py()
    }

    /// Update an existing document.
    fn update_document(
        &self,
        document_key: String,
        new_document_string: String,
        attachments: Option<Vec<String>>,
        embed: Option<bool>,
    ) -> PyResult<String> {
        self.inner
            .update_document(&document_key, &new_document_string, attachments, embed)
            .to_py()
    }

    /// Verify a signature field on a document.
    fn verify_signature(
        &self,
        document_string: String,
        signature_field: Option<String>,
    ) -> PyResult<bool> {
        self.inner
            .verify_signature(&document_string, signature_field)
            .to_py()
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
        self.inner
            .create_agreement(&document_string, agentids, question, context, agreement_fieldname)
            .to_py()
    }

    /// Sign an agreement on a document.
    fn sign_agreement(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> PyResult<String> {
        self.inner
            .sign_agreement(&document_string, agreement_fieldname)
            .to_py()
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
        self.inner
            .create_document(
                &document_string,
                custom_schema,
                outputfilename,
                no_save.unwrap_or(false),
                attachments.as_deref(),
                embed,
            )
            .to_py()
    }

    /// Check agreement status on a document.
    fn check_agreement(
        &self,
        document_string: String,
        agreement_fieldname: Option<String>,
    ) -> PyResult<String> {
        self.inner
            .check_agreement(&document_string, agreement_fieldname)
            .to_py()
    }

    /// Sign a request payload and return a signed JACS document.
    fn sign_request(&self, py: Python, params_obj: PyObject) -> PyResult<String> {
        let bound_params = params_obj.bind(py);
        let payload_value = conversion_utils::pyany_to_value(py, bound_params)?;
        self.inner.sign_request(payload_value).to_py()
    }

    /// Verify a response document and return the payload.
    fn verify_response(&self, py: Python, document_string: String) -> PyResult<PyObject> {
        let payload = self.inner.verify_response(document_string).to_py()?;
        conversion_utils::value_to_pyobject(py, &payload)
    }

    /// Verify a response document and return (payload, agent_id).
    fn verify_response_with_agent_id(
        &self,
        py: Python,
        document_string: String,
    ) -> PyResult<PyObject> {
        let (payload, agent_id) = self
            .inner
            .verify_response_with_agent_id(document_string)
            .to_py()?;

        let py_payload = conversion_utils::value_to_pyobject(py, &payload)?;
        let py_agent_id: Py<pyo3::types::PyString> =
            pyo3::types::PyString::new(py, &agent_id).into();

        let tuple_bound_ref =
            pyo3::types::PyTuple::new(py, &[py_agent_id.into_py(py), py_payload])?;
        let py_object_tuple = tuple_bound_ref.into_py(py);

        Ok(py_object_tuple)
    }

    /// Hash a string using the JACS hash function.
    #[staticmethod]
    fn hash_string(data: &str) -> PyResult<String> {
        Ok(jacs_binding_core::hash_string(data))
    }
}

// =============================================================================
// SimpleAgent Class - Simplified API (Recommended for new code)
// =============================================================================
// This class wraps jacs_core::simple::SimpleAgent, providing an instance-based
// API without any global state. This is the preferred API for Python.
// =============================================================================

/// A simplified JACS agent for common signing and verification operations.
///
/// This class provides a clean, easy-to-use API for the most common JACS
/// operations. Each instance maintains its own state, allowing multiple
/// agents to operate concurrently.
///
/// Example:
///     # Create a new agent
///     agent, info = jacs.SimpleAgent.create("my-agent")
///     print(f"Created agent: {info['agent_id']}")
///
///     # Sign a message
///     signed = agent.sign_message({"action": "approve"})
///     print(f"Document ID: {signed['document_id']}")
///
///     # Load an existing agent
///     agent = jacs.SimpleAgent.load("./jacs.config.json")
///     result = agent.verify_self()
///     assert result['valid']
#[pyclass]
pub struct SimpleAgent {
    inner: jacs_core::simple::SimpleAgent,
}

#[pymethods]
impl SimpleAgent {
    /// Create a new JACS agent with cryptographic keys.
    ///
    /// Args:
    ///     name: Human-readable name for the agent
    ///     purpose: Optional description of the agent's purpose
    ///     key_algorithm: Signing algorithm ("ed25519", "rsa-pss", or "pq2025")
    ///
    /// Returns:
    ///     Tuple of (SimpleAgent instance, dict with agent_id, name, public_key_path, config_path)
    #[staticmethod]
    fn create(
        py: Python,
        name: &str,
        purpose: Option<&str>,
        key_algorithm: Option<&str>,
    ) -> PyResult<(Self, PyObject)> {
        let (agent, info) =
            jacs_core::simple::SimpleAgent::create(name, purpose, key_algorithm).map_err(|e| {
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

        Ok((SimpleAgent { inner: agent }, dict.into()))
    }

    /// Load an existing agent from configuration.
    ///
    /// Args:
    ///     config_path: Path to jacs.config.json (default: "./jacs.config.json")
    ///
    /// Returns:
    ///     A SimpleAgent instance
    #[staticmethod]
    fn load(config_path: Option<&str>) -> PyResult<Self> {
        let agent = jacs_core::simple::SimpleAgent::load(config_path).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to load agent: {}",
                e
            ))
        })?;
        Ok(SimpleAgent { inner: agent })
    }

    /// Verify the loaded agent's own integrity.
    ///
    /// Returns:
    ///     dict with valid, signer_id, timestamp, errors
    fn verify_self(&self, py: Python) -> PyResult<PyObject> {
        let result = self.inner.verify_self().map_err(|e| {
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
    }

    /// Sign a message and return a signed JACS document.
    ///
    /// Args:
    ///     data: JSON-serializable data to sign (dict, list, or string)
    ///
    /// Returns:
    ///     dict with raw, document_id, agent_id, timestamp
    fn sign_message(&self, py: Python, data: PyObject) -> PyResult<PyObject> {
        let bound_data = data.bind(py);
        let json_value = conversion_utils::pyany_to_value(py, bound_data)?;

        let signed = self.inner.sign_message(&json_value).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to sign message: {}",
                e
            ))
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
    fn sign_file(&self, py: Python, file_path: &str, embed: bool) -> PyResult<PyObject> {
        let signed = self.inner.sign_file(file_path, embed).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to sign file: {}",
                e
            ))
        })?;

        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("raw", &signed.raw)?;
        dict.set_item("document_id", &signed.document_id)?;
        dict.set_item("agent_id", &signed.agent_id)?;
        dict.set_item("timestamp", &signed.timestamp)?;
        Ok(dict.into())
    }

    /// Verify a signed JACS document.
    ///
    /// Args:
    ///     signed_document: JSON string of the signed document
    ///
    /// Returns:
    ///     dict with valid, data, signer_id, timestamp, attachments, errors
    fn verify(&self, py: Python, signed_document: &str) -> PyResult<PyObject> {
        let result = self.inner.verify(signed_document).map_err(|e| {
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
    fn export_agent(&self) -> PyResult<String> {
        self.inner.export_agent().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to export agent: {}",
                e
            ))
        })
    }

    /// Get the current agent's public key in PEM format.
    ///
    /// Returns:
    ///     The public key as a PEM string
    fn get_public_key_pem(&self) -> PyResult<String> {
        self.inner.get_public_key_pem().map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to get public key: {}",
                e
            ))
        })
    }
}

// =============================================================================
// Stateless Utility Functions (using binding-core)
// =============================================================================
// These functions don't require any agent state and can be called directly.
// =============================================================================

/// Hash a string using the JACS hash function.
#[pyfunction]
fn hash_string(data: &str) -> PyResult<String> {
    Ok(jacs_binding_core::hash_string(data))
}

/// Create a JACS configuration JSON string.
#[pyfunction]
fn create_config(
    _py: Python,
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
    .to_py()
}

/// Create agent and config files interactively (CLI utility).
#[pyfunction]
fn handle_agent_create_py(filename: Option<String>, create_keys: bool) -> PyResult<()> {
    jacs_binding_core::handle_agent_create(filename.as_ref(), create_keys).to_py()
}

/// Create a jacs.config.json file interactively (CLI utility).
#[pyfunction]
fn handle_config_create_py() -> PyResult<()> {
    jacs_binding_core::handle_config_create().to_py()
}

// =============================================================================
// Trust Store Functions (using binding-core)
// =============================================================================
// These are stateless functions that interact with the global trust store.
// The trust store itself is designed to be shared across agent instances.
// =============================================================================

/// Add an agent to the local trust store.
///
/// Args:
///     agent_json: The full agent JSON string
///
/// Returns:
///     The agent ID if successfully trusted
#[pyfunction]
fn trust_agent(agent_json: &str) -> PyResult<String> {
    jacs_binding_core::trust_agent(agent_json).to_py()
}

/// List all trusted agent IDs.
///
/// Returns:
///     List of agent IDs in the trust store
#[pyfunction]
fn list_trusted_agents() -> PyResult<Vec<String>> {
    jacs_binding_core::list_trusted_agents().to_py()
}

/// Remove an agent from the trust store.
///
/// Args:
///     agent_id: The ID of the agent to untrust
#[pyfunction]
fn untrust_agent(agent_id: &str) -> PyResult<()> {
    jacs_binding_core::untrust_agent(agent_id).to_py()
}

/// Check if an agent is in the trust store.
///
/// Args:
///     agent_id: The ID of the agent to check
///
/// Returns:
///     True if the agent is trusted
#[pyfunction]
fn is_trusted(agent_id: &str) -> bool {
    jacs_binding_core::is_trusted(agent_id)
}

/// Get a trusted agent's JSON document.
///
/// Args:
///     agent_id: The ID of the agent
///
/// Returns:
///     The agent JSON string
#[pyfunction]
fn get_trusted_agent(agent_id: &str) -> PyResult<String> {
    jacs_binding_core::get_trusted_agent(agent_id).to_py()
}

// =============================================================================
// Legacy Module-Level Functions (Deprecated)
// =============================================================================
// These functions are provided for backward compatibility only.
// New code should use JacsAgent or SimpleAgent classes instead.
//
// NOTE: These functions create a new agent instance for each call,
// which means they do NOT share state between calls. This is a change
// from the previous lazy_static! global singleton behavior.
// =============================================================================

fn log_to_python(py: Python, message: &str, log_level: &str) -> PyResult<()> {
    let logging = py.import("logging")?;
    logging.call_method1(log_level, (message,))?;
    Ok(())
}

/// Load an agent from a config file.
///
/// DEPRECATED: Use JacsAgent().load() or SimpleAgent.load() instead.
///
/// NOTE: This function creates a temporary agent that is discarded after loading.
/// For stateful operations, use JacsAgent or SimpleAgent classes.
#[pyfunction]
fn load(_py: Python, config_path: &str) -> PyResult<String> {
    let agent = AgentWrapper::new();
    agent.load(config_path.to_string()).to_py()
}

/// Sign an external agent with registration signature.
///
/// DEPRECATED: Use JacsAgent().sign_agent() instead.
#[pyfunction]
fn sign_agent(
    _py: Python,
    _agent_string: &str,
    _public_key: &[u8],
    _public_key_enc_type: &str,
) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "sign_agent() is deprecated. Use JacsAgent().sign_agent() instead. \
         You must create a JacsAgent instance and load it first."
    ))
}

/// Verify a string signature.
///
/// DEPRECATED: Use JacsAgent().verify_string() instead.
#[pyfunction]
fn verify_string(
    data: &str,
    signature_base64: &str,
    public_key: &[u8],
    public_key_enc_type: &str,
) -> PyResult<bool> {
    // This is a stateless operation that can be done with an empty agent
    let agent = AgentWrapper::new();
    agent
        .verify_string(
            data,
            signature_base64,
            public_key.to_vec(),
            public_key_enc_type.to_string(),
        )
        .to_py()
}

/// Sign a string.
///
/// DEPRECATED: Use JacsAgent().sign_string() instead.
#[pyfunction]
fn sign_string(_py: Python, _data: &str) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "sign_string() is deprecated. Use JacsAgent().sign_string() instead. \
         You must create a JacsAgent instance and load it first."
    ))
}

/// Verify an agent's self-signature.
///
/// DEPRECATED: Use JacsAgent().verify_agent() or SimpleAgent.verify_self() instead.
#[pyfunction]
fn verify_agent(_py: Python, _agentfile: Option<String>) -> PyResult<bool> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_agent() is deprecated. Use JacsAgent().verify_agent() or \
         SimpleAgent.load().verify_self() instead."
    ))
}

/// Update an agent.
///
/// DEPRECATED: Use JacsAgent().update_agent() instead.
#[pyfunction]
fn update_agent(_py: Python, _new_agent_string: String) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "update_agent() is deprecated. Use JacsAgent().update_agent() instead. \
         You must create a JacsAgent instance and load it first."
    ))
}

/// Verify a document.
///
/// DEPRECATED: Use JacsAgent().verify_document() or SimpleAgent.verify() instead.
#[pyfunction]
fn verify_document(_py: Python, _document_string: String) -> PyResult<bool> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_document() is deprecated. Use JacsAgent().verify_document() or \
         SimpleAgent.load().verify() instead."
    ))
}

/// Update a document.
///
/// DEPRECATED: Use JacsAgent().update_document() instead.
#[pyfunction]
fn update_document(
    _py: Python,
    _document_key: String,
    _new_document_string: String,
    _attachments: Option<Vec<String>>,
    _embed: Option<bool>,
) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "update_document() is deprecated. Use JacsAgent().update_document() instead. \
         You must create a JacsAgent instance and load it first."
    ))
}

/// Verify a signature on a document.
///
/// DEPRECATED: Use JacsAgent().verify_signature() instead.
#[pyfunction]
fn verify_signature(
    _py: Python,
    _document_string: String,
    _signature_field: Option<String>,
) -> PyResult<bool> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_signature() is deprecated. Use JacsAgent().verify_signature() instead. \
         You must create a JacsAgent instance and load it first."
    ))
}

/// Create an agreement.
///
/// DEPRECATED: Use JacsAgent().create_agreement() instead.
#[pyfunction]
fn create_agreement(
    _py: Python,
    _document_string: String,
    _agentids: Vec<String>,
    _question: Option<String>,
    _context: Option<String>,
    _agreement_fieldname: Option<String>,
) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "create_agreement() is deprecated. Use JacsAgent().create_agreement() instead. \
         You must create a JacsAgent instance and load it first."
    ))
}

/// Sign an agreement.
///
/// DEPRECATED: Use JacsAgent().sign_agreement() instead.
#[pyfunction]
fn sign_agreement(
    _py: Python,
    _document_string: String,
    _agreement_fieldname: Option<String>,
) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "sign_agreement() is deprecated. Use JacsAgent().sign_agreement() instead. \
         You must create a JacsAgent instance and load it first."
    ))
}

/// Create a document.
///
/// DEPRECATED: Use JacsAgent().create_document() or SimpleAgent.sign_message() instead.
#[pyfunction]
fn create_document(
    _py: Python,
    _document_string: String,
    _custom_schema: Option<String>,
    _outputfilename: Option<String>,
    _no_save: Option<bool>,
    _attachments: Option<String>,
    _embed: Option<bool>,
) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "create_document() is deprecated. Use JacsAgent().create_document() or \
         SimpleAgent.load().sign_message() instead."
    ))
}

/// Check an agreement.
///
/// DEPRECATED: Use JacsAgent().check_agreement() instead.
#[pyfunction]
fn check_agreement(
    _py: Python,
    _document_string: String,
    _agreement_fieldname: Option<String>,
) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "check_agreement() is deprecated. Use JacsAgent().check_agreement() instead. \
         You must create a JacsAgent instance and load it first."
    ))
}

/// Sign a request payload.
///
/// DEPRECATED: Use JacsAgent().sign_request() or SimpleAgent.sign_message() instead.
#[pyfunction]
fn sign_request(_py: Python, _params_obj: PyObject) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "sign_request() is deprecated. Use JacsAgent().sign_request() or \
         SimpleAgent.load().sign_message() instead."
    ))
}

/// Verify a response.
///
/// DEPRECATED: Use JacsAgent().verify_response() or SimpleAgent.verify() instead.
#[pyfunction]
fn verify_response(_py: Python, _document_string: String) -> PyResult<PyObject> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_response() is deprecated. Use JacsAgent().verify_response() or \
         SimpleAgent.load().verify() instead."
    ))
}

/// Verify a response and return agent ID.
///
/// DEPRECATED: Use JacsAgent().verify_response_with_agent_id() instead.
#[pyfunction]
fn verify_response_with_agent_id(_py: Python, _document_string: String) -> PyResult<PyObject> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_response_with_agent_id() is deprecated. \
         Use JacsAgent().verify_response_with_agent_id() instead."
    ))
}

// =============================================================================
// Deprecated Simple API Functions
// =============================================================================
// These module-level functions are deprecated. Use SimpleAgent class instead.
// =============================================================================

/// Create a new JACS agent.
///
/// DEPRECATED: Use SimpleAgent.create() instead.
#[pyfunction]
fn create_simple(
    _name: &str,
    _purpose: Option<&str>,
    _key_algorithm: Option<&str>,
) -> PyResult<PyObject> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "create_simple() is deprecated. Use SimpleAgent.create() instead, which returns \
         both the agent instance and info dict."
    ))
}

/// Load an existing agent.
///
/// DEPRECATED: Use SimpleAgent.load() instead.
#[pyfunction]
fn load_simple(_config_path: Option<&str>) -> PyResult<()> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "load_simple() is deprecated. Use SimpleAgent.load() instead."
    ))
}

/// Verify self.
///
/// DEPRECATED: Use SimpleAgent.load().verify_self() instead.
#[pyfunction]
fn verify_self_simple() -> PyResult<PyObject> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_self_simple() is deprecated. Use SimpleAgent.load().verify_self() instead."
    ))
}

/// Sign a message.
///
/// DEPRECATED: Use SimpleAgent.load().sign_message() instead.
#[pyfunction]
fn sign_message_simple(_py: Python, _data: PyObject) -> PyResult<PyObject> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "sign_message_simple() is deprecated. Use SimpleAgent.load().sign_message() instead."
    ))
}

/// Sign a file.
///
/// DEPRECATED: Use SimpleAgent.load().sign_file() instead.
#[pyfunction]
fn sign_file_simple(_file_path: &str, _embed: bool) -> PyResult<PyObject> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "sign_file_simple() is deprecated. Use SimpleAgent.load().sign_file() instead."
    ))
}

/// Verify a signed document.
///
/// DEPRECATED: Use SimpleAgent.load().verify() instead.
#[pyfunction]
fn verify_simple(_py: Python, _signed_document: &str) -> PyResult<PyObject> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_simple() is deprecated. Use SimpleAgent.load().verify() instead."
    ))
}

/// Export agent identity.
///
/// DEPRECATED: Use SimpleAgent.load().export_agent() instead.
#[pyfunction]
fn export_agent_simple() -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "export_agent_simple() is deprecated. Use SimpleAgent.load().export_agent() instead."
    ))
}

/// Get public key PEM.
///
/// DEPRECATED: Use SimpleAgent.load().get_public_key_pem() instead.
#[pyfunction]
fn get_public_key_pem_simple() -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "get_public_key_pem_simple() is deprecated. \
         Use SimpleAgent.load().get_public_key_pem() instead."
    ))
}

// Deprecated trust functions with _simple suffix
#[pyfunction]
fn trust_agent_simple(agent_json: &str) -> PyResult<String> {
    trust_agent(agent_json)
}

#[pyfunction]
fn list_trusted_agents_simple() -> PyResult<Vec<String>> {
    list_trusted_agents()
}

#[pyfunction]
fn untrust_agent_simple(agent_id: &str) -> PyResult<()> {
    untrust_agent(agent_id)
}

#[pyfunction]
fn is_trusted_simple(agent_id: &str) -> bool {
    is_trusted(agent_id)
}

#[pyfunction]
fn get_trusted_agent_simple(agent_id: &str) -> PyResult<String> {
    get_trusted_agent(agent_id)
}

#[pymodule]
fn jacs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyo3::prepare_freethreaded_python();

    // =============================================================================
    // Primary API Classes (Recommended)
    // =============================================================================
    m.add_class::<JacsAgent>()?;
    m.add_class::<SimpleAgent>()?;

    // =============================================================================
    // Stateless Utility Functions
    // =============================================================================
    m.add_function(wrap_pyfunction!(hash_string, m)?)?;
    m.add_function(wrap_pyfunction!(create_config, m)?)?;
    m.add_function(wrap_pyfunction!(handle_agent_create_py, m)?)?;
    m.add_function(wrap_pyfunction!(handle_config_create_py, m)?)?;

    // =============================================================================
    // Trust Store Functions
    // =============================================================================
    m.add_function(wrap_pyfunction!(trust_agent, m)?)?;
    m.add_function(wrap_pyfunction!(list_trusted_agents, m)?)?;
    m.add_function(wrap_pyfunction!(untrust_agent, m)?)?;
    m.add_function(wrap_pyfunction!(is_trusted, m)?)?;
    m.add_function(wrap_pyfunction!(get_trusted_agent, m)?)?;

    // =============================================================================
    // Legacy Functions (Deprecated - for backward compatibility)
    // =============================================================================
    // These functions either error with deprecation messages or provide
    // limited functionality. New code should use JacsAgent or SimpleAgent.

    #[pyfn(m, name = "log_to_python")]
    fn py_log_to_python(py: Python, message: String, log_level: String) -> PyResult<()> {
        log_to_python(py, &message, &log_level)
    }

    m.add_function(wrap_pyfunction!(load, m)?)?;
    m.add_function(wrap_pyfunction!(sign_agent, m)?)?;
    m.add_function(wrap_pyfunction!(verify_string, m)?)?;
    m.add_function(wrap_pyfunction!(sign_string, m)?)?;
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
    m.add_function(wrap_pyfunction!(verify_response_with_agent_id, m)?)?;

    // Deprecated simple API functions
    m.add_function(wrap_pyfunction!(create_simple, m)?)?;
    m.add_function(wrap_pyfunction!(load_simple, m)?)?;
    m.add_function(wrap_pyfunction!(verify_self_simple, m)?)?;
    m.add_function(wrap_pyfunction!(sign_message_simple, m)?)?;
    m.add_function(wrap_pyfunction!(sign_file_simple, m)?)?;
    m.add_function(wrap_pyfunction!(verify_simple, m)?)?;
    m.add_function(wrap_pyfunction!(export_agent_simple, m)?)?;
    m.add_function(wrap_pyfunction!(get_public_key_pem_simple, m)?)?;

    // Deprecated trust functions with _simple suffix (kept for compatibility)
    m.add_function(wrap_pyfunction!(trust_agent_simple, m)?)?;
    m.add_function(wrap_pyfunction!(list_trusted_agents_simple, m)?)?;
    m.add_function(wrap_pyfunction!(untrust_agent_simple, m)?)?;
    m.add_function(wrap_pyfunction!(is_trusted_simple, m)?)?;
    m.add_function(wrap_pyfunction!(get_trusted_agent_simple, m)?)?;

    Ok(())
}
