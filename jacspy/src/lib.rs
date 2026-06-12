//! Python bindings for JACS (JSON AI Communication Standard).
//!
//! This module provides Python bindings using PyO3, built on top of the
//! shared `jacs-binding-core` crate for common functionality.

use ::jacs as jacs_core;
use jacs_binding_core::{AgentWrapper, BindingCoreError, BindingResult, SimpleAgentWrapper};
use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

// Declare the module so it's recognized at the crate root
pub mod conversion_utils;

// =============================================================================
// Error Conversion: BindingCoreError -> PyErr
// =============================================================================

// =============================================================================
// Custom Python exception classes (Task 03 + Task 10).
// =============================================================================
//
// `MissingSignatureError` is raised by strict-mode verify bindings (PRD §4.1.2,
// C1) so callers can `except jacs.MissingSignatureError:` without parsing
// error strings. The Python-side class lives at `jacs.types.MissingSignatureError`
// (defined in jacspy/python/jacs/types.py) and is also re-exported as
// `jacs.MissingSignatureError`. The Rust binding raises via the registered
// PyType from this module (see `register_missing_signature_error` in the
// `#[pymodule]` init below).

use pyo3::exceptions::PyException;

pyo3::create_exception!(jacs, MissingSignatureError, PyException);

/// Convert a BindingCoreError to a PyErr.
///
/// Maps `ErrorKind::MissingSignature` to the Python `MissingSignatureError`
/// exception so callers can branch on type instead of message text. Other
/// kinds map to `PyRuntimeError` to preserve the existing behaviour.
fn to_py_err(e: BindingCoreError) -> PyErr {
    if matches!(e.kind, jacs_binding_core::ErrorKind::MissingSignature) {
        PyErr::new::<MissingSignatureError, _>(e.message)
    } else {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.message)
    }
}

fn py_runtime_err(context: &str, err: impl std::fmt::Display) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{}: {}", context, err))
}

fn map_py_runtime_result<T, E: std::fmt::Display>(
    result: Result<T, E>,
    context: &str,
) -> PyResult<T> {
    result.map_err(|e| py_runtime_err(context, e))
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
// Each JacsAgent instance has its own loaded agent state. This allows multiple
// agents to coexist in the same Python process. Password-protected operations
// are synchronized internally while the Rust core still resolves decryption
// passwords through JACS_PRIVATE_KEY_PASSWORD.
//
// The Arc<Mutex<Agent>> pattern ensures thread-safety:
// - Arc allows shared ownership across Python references
// - Mutex protects internal Agent state from data races
// - Works correctly with Python's GIL and future free-threading (Python 3.13+)
// =============================================================================

/// A JACS agent instance for signing and verifying documents.
///
/// Each JacsAgent has independent loaded state, allowing multiple agents to be
/// used in the same process. This is the recommended API for all code.
///
/// Example:
/// ```python
/// agent = jacs.JacsAgent()
/// agent.load("/path/to/config.json")
/// signed = agent.sign_string("hello")
/// ```
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

    /// Load agent configuration and return canonical loaded-agent metadata JSON.
    fn load_with_info(&self, config_path: String) -> PyResult<String> {
        self.inner.load_with_info(config_path).to_py()
    }

    /// Configure a per-instance private-key password for later load/sign calls.
    ///
    /// Pass ``None`` to clear the configured password and fall back to the
    /// process environment / keychain behavior in the Rust core.
    #[pyo3(signature = (password=None))]
    fn set_private_key_password(&self, password: Option<String>) -> PyResult<()> {
        self.inner.set_private_key_password(password).to_py()
    }

    /// Sign an external agent's document with this agent's registration signature.
    fn sign_agent(
        &self,
        agent_string: &str,
        public_key: &[u8],
        public_key_enc_type: &str,
    ) -> PyResult<String> {
        self.inner
            .sign_agent(
                agent_string,
                public_key.to_vec(),
                public_key_enc_type.to_string(),
            )
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

    /// Sign multiple messages in a single batch (one key decryption).
    ///
    /// Args:
    ///     messages: List of strings to sign
    ///
    /// Returns:
    ///     List of base64-encoded signatures, one per message
    #[pyo3(signature = (messages,))]
    fn sign_batch(&self, messages: Vec<String>) -> PyResult<Vec<String>> {
        self.inner.sign_batch(messages).to_py()
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
            .create_agreement(
                &document_string,
                agentids,
                question,
                context,
                agreement_fieldname,
            )
            .to_py()
    }

    /// Create an agreement with extended options (timeout, quorum, algorithm constraints).
    ///
    /// Args:
    ///     document_string: The document JSON string
    ///     agentids: List of agent IDs required to sign
    ///     question: Optional question or purpose
    ///     context: Optional additional context
    ///     agreement_fieldname: Optional custom field name
    ///     timeout: Optional ISO 8601 deadline
    ///     quorum: Optional minimum signatures required (M-of-N)
    ///     required_algorithms: Optional list of accepted algorithms
    ///     minimum_strength: Optional "classical" or "post-quantum"
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (document_string, agentids, question=None, context=None, agreement_fieldname=None, timeout=None, quorum=None, required_algorithms=None, minimum_strength=None))]
    fn create_agreement_with_options(
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
    ) -> PyResult<String> {
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
    fn sign_request(&self, py: Python, params_obj: Py<PyAny>) -> PyResult<String> {
        let bound_params = params_obj.bind(py);
        let payload_value = conversion_utils::pyany_to_value(py, bound_params)?;
        self.inner.sign_request(payload_value).to_py()
    }

    /// Verify a response document and return the payload.
    fn verify_response(&self, py: Python, document_string: String) -> PyResult<Py<PyAny>> {
        let payload = self.inner.verify_response(document_string).to_py()?;
        conversion_utils::value_to_pyobject(py, &payload)
    }

    /// Verify a response document and return (payload, agent_id).
    fn verify_response_with_agent_id(
        &self,
        py: Python,
        document_string: String,
    ) -> PyResult<Py<PyAny>> {
        let (payload, agent_id) = self
            .inner
            .verify_response_with_agent_id(document_string)
            .to_py()?;

        let py_payload = conversion_utils::value_to_pyobject(py, &payload)?;
        let items = vec![agent_id.into_py_any(py)?, py_payload];
        let tuple = pyo3::types::PyTuple::new(py, items)?;
        Ok(tuple.into_any().unbind())
    }

    /// Verify a document by its ID from storage.
    ///
    /// Args:
    ///     document_id: Document ID in "uuid:version" format
    ///
    /// Returns:
    ///     True if the document is valid
    fn verify_document_by_id(&self, document_id: &str) -> PyResult<bool> {
        self.inner.verify_document_by_id(document_id).to_py()
    }

    /// Load a document by its ID from the configured storage backend.
    ///
    /// Args:
    ///     document_id: Document ID in "uuid:version" format
    ///
    /// Returns:
    ///     The raw JSON document string
    fn get_document_by_id(&self, document_id: &str) -> PyResult<String> {
        self.inner.get_document_by_id(document_id).to_py()
    }

    /// Rotate the agent's cryptographic keys.
    ///
    /// Generates a new keypair, archives the old keys, creates a new agent version,
    /// and re-signs the config file. Optionally changes the signing algorithm.
    ///
    /// Args:
    ///     algorithm: Optional new algorithm ("ring-Ed25519", "pq2025").
    ///               If None, keeps the current algorithm.
    ///
    /// Returns:
    ///     JSON string containing the RotationResult (old_version, new_version,
    ///     new_public_key_hash, transition_proof, etc.)
    #[pyo3(signature = (algorithm=None))]
    fn rotate_keys(&self, algorithm: Option<&str>) -> PyResult<String> {
        self.inner.rotate_keys(algorithm).to_py()
    }

    /// Re-encrypt the agent's private key with a new password.
    ///
    /// Args:
    ///     old_password: Current password
    ///     new_password: New password (must meet password requirements)
    fn reencrypt_key(&self, old_password: &str, new_password: &str) -> PyResult<()> {
        self.inner.reencrypt_key(old_password, new_password).to_py()
    }

    /// Get the agent's JSON document.
    ///
    /// Returns:
    ///     The agent JSON document as a string
    fn get_agent_json(&self) -> PyResult<String> {
        self.inner.get_agent_json().to_py()
    }

    /// Export the loaded agent's full JSON document.
    fn export_agent(&self) -> PyResult<String> {
        self.inner.export_agent().to_py()
    }

    /// Get the current agent's public key in PEM format.
    fn get_public_key_pem(&self) -> PyResult<String> {
        self.inner.get_public_key_pem().to_py()
    }

    /// Get setup instructions for publishing DNS records and DNSSEC.
    ///
    /// Args:
    ///     domain: The domain to publish DNS TXT records under
    ///     ttl: TTL in seconds for the DNS record (e.g. 3600)
    ///
    /// Returns:
    ///     JSON string with dns_record_bind, provider_commands, dnssec_instructions, etc.
    #[pyo3(signature = (domain, ttl=3600))]
    fn get_setup_instructions(&self, domain: &str, ttl: Option<u32>) -> PyResult<String> {
        self.inner
            .get_setup_instructions(domain, ttl.unwrap_or(3600))
            .to_py()
    }

    /// Returns diagnostic information as a JSON string.
    fn diagnostics(&self) -> PyResult<String> {
        Ok(self.inner.diagnostics())
    }

    /// Hash a string using the JACS hash function.
    #[staticmethod]
    fn hash_string(data: &str) -> PyResult<String> {
        Ok(jacs_binding_core::hash_string(data))
    }

    // =========================================================================
    // A2A Protocol Methods (require `a2a` feature)
    // =========================================================================

    /// Export this agent as an A2A Agent Card (v0.4.0).
    ///
    /// Returns the Agent Card as a JSON string.
    #[cfg(feature = "a2a")]
    fn export_agent_card(&self) -> PyResult<String> {
        self.inner.export_agent_card().to_py()
    }

    /// Generate the native .well-known A2A document set for the loaded agent.
    #[cfg(feature = "a2a")]
    #[pyo3(signature = (a2a_algorithm=None))]
    fn generate_well_known_documents(&self, a2a_algorithm: Option<&str>) -> PyResult<String> {
        self.inner
            .generate_well_known_documents(a2a_algorithm)
            .to_py()
    }

    /// Wrap an A2A artifact with JACS provenance signature.
    ///
    /// Args:
    ///     artifact_json: JSON string of the artifact to wrap
    ///     artifact_type: Type label (e.g., "artifact", "result")
    ///     parent_signatures_json: Optional JSON array of parent signatures
    ///
    /// Returns:
    ///     JSON string of the wrapped, signed artifact
    #[cfg(feature = "a2a")]
    #[pyo3(signature = (artifact_json, artifact_type, parent_signatures_json=None))]
    #[allow(deprecated)]
    fn wrap_a2a_artifact(
        &self,
        artifact_json: &str,
        artifact_type: &str,
        parent_signatures_json: Option<&str>,
    ) -> PyResult<String> {
        self.inner
            .wrap_a2a_artifact(artifact_json, artifact_type, parent_signatures_json)
            .to_py()
    }

    /// Sign an A2A artifact with JACS provenance.
    ///
    /// Alias for wrap_a2a_artifact(). This is the recommended primary API name.
    #[cfg(feature = "a2a")]
    #[pyo3(signature = (artifact_json, artifact_type, parent_signatures_json=None))]
    fn sign_artifact(
        &self,
        artifact_json: &str,
        artifact_type: &str,
        parent_signatures_json: Option<&str>,
    ) -> PyResult<String> {
        self.inner
            .sign_artifact(artifact_json, artifact_type, parent_signatures_json)
            .to_py()
    }

    /// Verify a JACS-wrapped A2A artifact.
    ///
    /// Args:
    ///     wrapped_json: JSON string of the wrapped artifact to verify
    ///
    /// Returns:
    ///     JSON string containing the verification result
    #[cfg(feature = "a2a")]
    fn verify_a2a_artifact(&self, wrapped_json: &str) -> PyResult<String> {
        self.inner.verify_a2a_artifact(wrapped_json).to_py()
    }

    /// Verify a JACS-wrapped A2A artifact with policy-aware trust assessment.
    ///
    /// Args:
    ///     wrapped_json: JSON string of the wrapped artifact
    ///     agent_card_json: JSON string of the signer's Agent Card
    ///     policy: Trust policy ("open", "verified", "strict")
    ///
    /// Returns:
    ///     JSON string containing the verification result with trust assessment
    #[cfg(feature = "a2a")]
    fn verify_a2a_artifact_with_policy(
        &self,
        wrapped_json: &str,
        agent_card_json: &str,
        policy: &str,
    ) -> PyResult<String> {
        self.inner
            .verify_a2a_artifact_with_policy(wrapped_json, agent_card_json, policy)
            .to_py()
    }

    /// Assess a remote agent's trust level based on its Agent Card and a policy.
    ///
    /// Args:
    ///     agent_card_json: JSON string of the Agent Card
    ///     policy: Trust policy ("open", "verified", "strict")
    ///
    /// Returns:
    ///     JSON string containing the trust assessment result
    #[cfg(feature = "a2a")]
    fn assess_a2a_agent(&self, agent_card_json: &str, policy: &str) -> PyResult<String> {
        self.inner.assess_a2a_agent(agent_card_json, policy).to_py()
    }

    // =========================================================================
    // Attestation methods (feature-gated)
    // =========================================================================

    /// Create a signed attestation document.
    ///
    /// Args:
    ///     params_json: JSON string containing subject, claims, evidence, derivation, policyContext
    ///
    /// Returns:
    ///     JSON string of the signed attestation document
    #[cfg(feature = "attestation")]
    fn create_attestation(&self, params_json: &str) -> PyResult<String> {
        self.inner.create_attestation(params_json).to_py()
    }

    /// Verify an attestation (local tier: crypto + hash only).
    ///
    /// Args:
    ///     document_key: The "id:version" key of the attestation document
    ///
    /// Returns:
    ///     JSON string containing the verification result
    #[cfg(feature = "attestation")]
    fn verify_attestation(&self, document_key: &str) -> PyResult<String> {
        self.inner.verify_attestation(document_key).to_py()
    }

    /// Verify an attestation (full tier: crypto + evidence + chain).
    ///
    /// Args:
    ///     document_key: The "id:version" key of the attestation document
    ///
    /// Returns:
    ///     JSON string containing the full verification result
    #[cfg(feature = "attestation")]
    fn verify_attestation_full(&self, document_key: &str) -> PyResult<String> {
        self.inner.verify_attestation_full(document_key).to_py()
    }

    /// Lift a signed document into an attestation.
    ///
    /// Args:
    ///     signed_doc_json: JSON string of the signed document
    ///     claims_json: JSON string of the claims array
    ///
    /// Returns:
    ///     JSON string of the lifted attestation document
    #[cfg(feature = "attestation")]
    fn lift_to_attestation(&self, signed_doc_json: &str, claims_json: &str) -> PyResult<String> {
        self.inner
            .lift_to_attestation(signed_doc_json, claims_json)
            .to_py()
    }

    /// Export an attestation as a DSSE envelope.
    ///
    /// Args:
    ///     attestation_json: JSON string of the attestation document
    ///
    /// Returns:
    ///     JSON string of the DSSE envelope
    #[cfg(feature = "attestation")]
    fn export_attestation_dsse(&self, attestation_json: &str) -> PyResult<String> {
        self.inner.export_attestation_dsse(attestation_json).to_py()
    }

    // =========================================================================
    // HAI SDK Protocol Methods
    // =========================================================================

    /// Build an Authorization header value for this agent.
    ///
    /// Returns:
    ///     The header value string (e.g. "JACS ...")
    #[pyo3(name = "build_auth_header")]
    fn py_build_auth_header(&self) -> PyResult<String> {
        self.inner.build_auth_header().to_py()
    }

    /// Canonicalize a JSON string using RFC 8785 (JCS).
    ///
    /// Args:
    ///     json_string: Any valid JSON string
    ///
    /// Returns:
    ///     The canonicalized JSON string
    #[pyo3(name = "canonicalize_json")]
    fn py_canonicalize_json(&self, json_string: &str) -> PyResult<String> {
        self.inner.canonicalize_json(json_string).to_py()
    }

    /// Sign a response payload and return a signed JACS document string.
    ///
    /// Args:
    ///     payload_json: JSON string of the payload to sign
    ///
    /// Returns:
    ///     JSON string of the signed document
    #[pyo3(name = "sign_response")]
    fn py_sign_response(&self, payload_json: &str) -> PyResult<String> {
        self.inner.sign_response(payload_json).to_py()
    }

    /// Generate a verification link for a document.
    ///
    /// Args:
    ///     document: JSON string of the signed document
    ///     document: The document string to encode
    ///
    /// Returns:
    ///     URL-safe base64 encoded string (no padding)
    #[pyo3(name = "encode_verify_payload")]
    fn py_encode_verify_payload(&self, document: &str) -> PyResult<String> {
        self.inner.encode_verify_payload(document).to_py()
    }

    /// Decode a URL-safe base64 verification payload back to the original document.
    ///
    /// Args:
    ///     encoded: The base64url-encoded string
    ///
    /// Returns:
    ///     The original document string
    #[pyo3(name = "decode_verify_payload")]
    fn py_decode_verify_payload(&self, encoded: &str) -> PyResult<String> {
        self.inner.decode_verify_payload(encoded).to_py()
    }

    /// Extract the document ID from a JACS-signed document.
    ///
    /// Checks jacsDocumentId, document_id, id in priority order.
    ///
    /// Args:
    ///     document: JSON string of the signed document
    ///
    /// Returns:
    ///     The document ID string
    #[pyo3(name = "extract_document_id")]
    fn py_extract_document_id(&self, document: &str) -> PyResult<String> {
        self.inner.extract_document_id(document).to_py()
    }

    /// Unwrap and verify a signed event against server public keys.
    ///
    /// Args:
    ///     event_json: JSON string of the signed event
    ///     server_keys_json: JSON string of the server's public keys
    ///
    /// Returns:
    ///     JSON string with "data" and "verified" fields
    #[pyo3(name = "unwrap_signed_event")]
    fn py_unwrap_signed_event(&self, event_json: &str, server_keys_json: &str) -> PyResult<String> {
        self.inner
            .unwrap_signed_event(event_json, server_keys_json)
            .to_py()
    }

    // =========================================================================
    // Format Conversion (stateless -- no agent lock needed)
    // =========================================================================

    /// Convert a JSON string to YAML.
    fn to_yaml(&self, json_str: &str) -> PyResult<String> {
        jacs_core::convert::jacs_to_yaml(json_str)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Convert a YAML string to pretty-printed JSON.
    #[allow(clippy::wrong_self_convention)]
    fn from_yaml(&self, yaml_str: &str) -> PyResult<String> {
        jacs_core::convert::yaml_to_jacs(yaml_str)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Convert a JSON string to a self-contained HTML document.
    fn to_html(&self, json_str: &str) -> PyResult<String> {
        jacs_core::convert::jacs_to_html(json_str)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Extract JSON from an HTML document produced by to_html().
    #[allow(clippy::wrong_self_convention)]
    fn from_html(&self, html_str: &str) -> PyResult<String> {
        jacs_core::convert::html_to_jacs(html_str)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Convert a YAML string to JSON and verify the resulting document.
    ///
    /// Returns True if verification succeeds.
    fn verify_yaml(&self, yaml_str: &str) -> PyResult<bool> {
        let json_str = jacs_core::convert::yaml_to_jacs(yaml_str)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        self.inner.verify_document(&json_str).to_py()
    }
}

// =============================================================================
// SimpleAgent Class - Simplified API (Recommended for new code)
// =============================================================================
// This class wraps SimpleAgentWrapper from binding-core, ensuring all language
// bindings share the same FFI contract. This is the preferred API for Python.
// =============================================================================

/// A simplified JACS agent for common signing and verification operations.
///
/// This class provides a clean, easy-to-use API for the most common JACS
/// operations. Each instance maintains its own state, allowing multiple
/// agents to operate concurrently.
///
/// Backed by `SimpleAgentWrapper` from `jacs-binding-core` to ensure
/// identical FFI contract across Python, Node.js, and Go bindings.
///
/// Example:
/// ```python
/// # Create a new agent
/// agent, info = jacs.SimpleAgent.create("my-agent")
/// print(f"Created agent: {info['agent_id']}")
///
/// # Sign a message
/// signed = agent.sign_message({"action": "approve"})
/// print(f"Document ID: {signed['document_id']}")
///
/// # Load an existing agent
/// agent = jacs.SimpleAgent.load("./jacs.config.json")
/// result = agent.verify_self()
/// assert result["valid"]
/// ```
#[pyclass]
pub struct SimpleAgent {
    inner: SimpleAgentWrapper,
}

const SIMPLE_AGENT_CREATE_INFO_KEYS: &[&str] =
    &["agent_id", "name", "public_key_path", "config_path"];
const SIMPLE_AGENT_EPHEMERAL_INFO_KEYS: &[&str] = &["agent_id", "name", "algorithm", "version"];
const SIMPLE_AGENT_EXTENDED_INFO_KEYS: &[&str] = &[
    "agent_id",
    "name",
    "public_key_path",
    "config_path",
    "version",
    "algorithm",
    "private_key_path",
    "data_directory",
    "key_directory",
    "domain",
    "dns_record",
];

fn parse_json_value(json_str: &str, label: &str) -> PyResult<serde_json::Value> {
    serde_json::from_str(json_str).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to parse {}: {}",
            label, e
        ))
    })
}

fn py_json_arg_to_string(py: Python, value: Py<PyAny>, label: &str) -> PyResult<String> {
    let bound = value.bind(py);
    if let Ok(raw_json) = bound.extract::<String>() {
        return Ok(raw_json);
    }

    let json_value = conversion_utils::pyany_to_value(py, bound)?;
    serde_json::to_string(&json_value).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to serialize {}: {}",
            label, e
        ))
    })
}

#[cfg(feature = "agreements")]
fn wrapper_json_to_py_preserve_kind(
    py: Python,
    result: BindingResult<String>,
    context: &str,
) -> PyResult<Py<PyAny>> {
    let raw = result.to_py()?;
    let value = parse_json_value(&raw, context)?;
    json_value_to_py(py, &value)
}

fn agent_info_json_to_pydict(py: Python, info_json: &str, keys: &[&str]) -> PyResult<Py<PyAny>> {
    let info = parse_json_value(info_json, "agent info")?;
    let dict = pyo3::types::PyDict::new(py);

    for key in keys {
        dict.set_item(*key, info.get(*key).and_then(|v| v.as_str()).unwrap_or(""))?;
    }

    Ok(dict.into())
}

fn signed_document_json_to_pydict(py: Python, signed_raw: &str) -> PyResult<Py<PyAny>> {
    let signed_doc = parse_json_value(signed_raw, "signed document")?;
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("raw", signed_raw)?;
    dict.set_item(
        "document_id",
        signed_doc
            .get("jacsId")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )?;
    dict.set_item(
        "agent_id",
        signed_doc
            .get("jacsSignature")
            .and_then(|v| v.get("agentID"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )?;
    dict.set_item(
        "timestamp",
        signed_doc
            .get("jacsSignature")
            .and_then(|v| v.get("date"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    )?;
    Ok(dict.into())
}

fn verification_result_json_to_pydict(
    py: Python,
    result_json: &str,
    include_data: bool,
    include_attachments: bool,
) -> PyResult<Py<PyAny>> {
    let result = parse_json_value(result_json, "verification result")?;
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("valid", result["valid"].as_bool().unwrap_or(false))?;
    dict.set_item("signer_id", result["signer_id"].as_str().unwrap_or(""))?;
    dict.set_item("timestamp", result["timestamp"].as_str().unwrap_or(""))?;
    let errors: Vec<String> = result["errors"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    dict.set_item("errors", errors)?;

    if include_data {
        let data_value = result
            .get("data")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let py_data = conversion_utils::value_to_pyobject(py, &data_value)?;
        dict.set_item("data", py_data)?;
    }

    if include_attachments {
        let attachments_list = pyo3::types::PyList::empty(py);
        if let Some(atts) = result["attachments"].as_array() {
            for att in atts {
                let att_dict = pyo3::types::PyDict::new(py);
                att_dict.set_item("filename", att["filename"].as_str().unwrap_or(""))?;
                att_dict.set_item("mime_type", att["mime_type"].as_str().unwrap_or(""))?;
                att_dict.set_item("hash", att["hash"].as_str().unwrap_or(""))?;
                att_dict.set_item("embedded", att["embedded"].as_bool().unwrap_or(false))?;
                attachments_list.append(att_dict)?;
            }
        }
        dict.set_item("attachments", attachments_list)?;
    }

    Ok(dict.into())
}

fn simple_agent_with_info<E: std::fmt::Display>(
    py: Python,
    result: Result<(SimpleAgentWrapper, String), E>,
    context: &str,
    keys: &[&str],
) -> PyResult<(SimpleAgent, Py<PyAny>)> {
    let (wrapper, info_json) = map_py_runtime_result(result, context)?;
    let dict = agent_info_json_to_pydict(py, &info_json, keys)?;
    Ok((SimpleAgent { inner: wrapper }, dict))
}

impl SimpleAgent {
    fn signed_document_result<E: std::fmt::Display>(
        &self,
        py: Python,
        result: Result<String, E>,
        context: &str,
    ) -> PyResult<Py<PyAny>> {
        let signed_raw = map_py_runtime_result(result, context)?;
        signed_document_json_to_pydict(py, &signed_raw)
    }

    fn verification_result<E: std::fmt::Display>(
        &self,
        py: Python,
        result: Result<String, E>,
        context: &str,
        include_data: bool,
        include_attachments: bool,
    ) -> PyResult<Py<PyAny>> {
        let result_json = map_py_runtime_result(result, context)?;
        verification_result_json_to_pydict(py, &result_json, include_data, include_attachments)
    }
}

#[pymethods]
impl SimpleAgent {
    /// Create a new JACS agent with cryptographic keys.
    ///
    /// Args:
    ///     name: Human-readable name for the agent
    ///     purpose: Optional description of the agent's purpose
    ///     key_algorithm: Signing algorithm ("ed25519" or "pq2025")
    ///
    /// Returns:
    ///     Tuple of (SimpleAgent instance, dict with agent_id, name, public_key_path, config_path)
    #[staticmethod]
    fn create(
        py: Python,
        name: &str,
        purpose: Option<&str>,
        key_algorithm: Option<&str>,
    ) -> PyResult<(Self, Py<PyAny>)> {
        simple_agent_with_info(
            py,
            SimpleAgentWrapper::create(name, purpose, key_algorithm),
            "Failed to create agent",
            SIMPLE_AGENT_CREATE_INFO_KEYS,
        )
    }

    /// Load an existing agent from configuration.
    ///
    /// Args:
    ///     config_path: Path to jacs.config.json (default: "./jacs.config.json")
    ///
    /// Returns:
    ///     A SimpleAgent instance
    #[staticmethod]
    #[pyo3(signature = (config_path=None, strict=None))]
    fn load(config_path: Option<&str>, strict: Option<bool>) -> PyResult<Self> {
        let wrapper = map_py_runtime_result(
            SimpleAgentWrapper::load(config_path, strict),
            "Failed to load agent",
        )?;
        Ok(SimpleAgent { inner: wrapper })
    }

    /// Create an ephemeral in-memory agent. No config, no files, no env vars needed.
    ///
    /// Args:
    ///     algorithm: Signing algorithm ("ed25519", "pq2025"). Default: "pq2025"
    ///
    /// Returns:
    ///     Tuple of (SimpleAgent instance, dict with agent_id, name, algorithm, version)
    #[staticmethod]
    #[pyo3(signature = (algorithm=None))]
    fn ephemeral(py: Python, algorithm: Option<&str>) -> PyResult<(Self, Py<PyAny>)> {
        simple_agent_with_info(
            py,
            SimpleAgentWrapper::ephemeral(algorithm),
            "Failed to create ephemeral agent",
            SIMPLE_AGENT_EPHEMERAL_INFO_KEYS,
        )
    }

    /// Returns whether this agent is in strict mode.
    fn is_strict(&self) -> bool {
        self.inner.is_strict()
    }

    /// Config file path, if loaded from disk.
    ///
    /// Returns:
    ///     The config file path as a string, or None if ephemeral/not loaded from disk
    fn config_path(&self) -> Option<String> {
        self.inner.config_path()
    }

    /// Verify the loaded agent's own integrity.
    ///
    /// Returns:
    ///     dict with valid, signer_id, timestamp, errors
    fn verify_self(&self, py: Python) -> PyResult<Py<PyAny>> {
        self.verification_result(
            py,
            self.inner.verify_self(),
            "Failed to verify self",
            false,
            false,
        )
    }

    /// Sign a message and return a signed JACS document.
    ///
    /// Args:
    ///     data: JSON-serializable data to sign (dict, list, or string)
    ///
    /// Returns:
    ///     dict with raw, document_id, agent_id, timestamp
    fn sign_message(&self, py: Python, data: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let bound_data = data.bind(py);
        let json_value = conversion_utils::pyany_to_value(py, bound_data)?;
        let data_json = map_py_runtime_result(
            serde_json::to_string(&json_value),
            "Failed to serialize data",
        )?;
        self.signed_document_result(
            py,
            self.inner.sign_message_json(&data_json),
            "Failed to sign message",
        )
    }

    /// Sign a file with optional embedding.
    ///
    /// Args:
    ///     file_path: Path to the file to sign
    ///     embed: If true, embed file content in document
    ///
    /// Returns:
    ///     dict with raw, document_id, agent_id, timestamp
    fn sign_file(&self, py: Python, file_path: &str, embed: bool) -> PyResult<Py<PyAny>> {
        self.signed_document_result(
            py,
            self.inner.sign_file_json(file_path, embed),
            "Failed to sign file",
        )
    }

    /// Create a standalone JACS agreement v2 document.
    ///
    /// Args:
    ///     input: JSON string or dict matching CreateAgreementV2.
    ///
    /// Returns:
    ///     JSON string of the signed agreement document.
    #[cfg(feature = "agreements")]
    fn create_agreement_v2(&self, py: Python, input: Py<PyAny>) -> PyResult<String> {
        let input_json = py_json_arg_to_string(py, input, "agreement v2 create input")?;
        let inner = &self.inner;
        let result = py.detach(|| inner.create_agreement_v2_json(&input_json));
        result.to_py()
    }

    /// Apply an agreement v2 mutation and return the successor document JSON.
    #[cfg(feature = "agreements")]
    fn apply_agreement_v2(
        &self,
        py: Python,
        document_json: &str,
        mutation: Py<PyAny>,
    ) -> PyResult<String> {
        let mutation_json = py_json_arg_to_string(py, mutation, "agreement v2 mutation")?;
        let document_json = document_json.to_string();
        let inner = &self.inner;
        let result = py.detach(|| inner.apply_agreement_v2_json(&document_json, &mutation_json));
        result.to_py()
    }

    /// Add this agent's signer, witness, or notary agreement signature.
    #[cfg(feature = "agreements")]
    #[pyo3(signature = (document_json, role="signer"))]
    fn sign_agreement_v2(&self, py: Python, document_json: &str, role: &str) -> PyResult<String> {
        let document_json = document_json.to_string();
        let role = role.to_string();
        let inner = &self.inner;
        let result = py.detach(|| inner.sign_agreement_v2_json(&document_json, &role));
        result.to_py()
    }

    /// Verify agreement v2 hash, role, status, transcript, and signature invariants.
    #[cfg(feature = "agreements")]
    fn verify_agreement_v2(&self, py: Python, document_json: &str) -> PyResult<Py<PyAny>> {
        let document_json = document_json.to_string();
        let inner = &self.inner;
        let result = py.detach(|| inner.verify_agreement_v2_json(&document_json));
        wrapper_json_to_py_preserve_kind(py, result, "agreement v2 verification report")
    }

    /// Detect whether two successor versions are transcript-only mergeable.
    #[cfg(feature = "agreements")]
    fn detect_agreement_v2_branch_conflict(
        &self,
        py: Python,
        base_document_json: &str,
        left_document_json: &str,
        right_document_json: &str,
    ) -> PyResult<Py<PyAny>> {
        let base_document_json = base_document_json.to_string();
        let left_document_json = left_document_json.to_string();
        let right_document_json = right_document_json.to_string();
        let inner = &self.inner;
        let result = py.detach(|| {
            inner.detect_agreement_v2_branch_conflict_json(
                &base_document_json,
                &left_document_json,
                &right_document_json,
            )
        });
        wrapper_json_to_py_preserve_kind(py, result, "agreement v2 branch analysis")
    }

    /// Auto-merge two transcript-only branches.
    #[cfg(feature = "agreements")]
    fn merge_agreement_v2_transcript_branches(
        &self,
        py: Python,
        base_document_json: &str,
        left_document_json: &str,
        right_document_json: &str,
    ) -> PyResult<String> {
        let base_document_json = base_document_json.to_string();
        let left_document_json = left_document_json.to_string();
        let right_document_json = right_document_json.to_string();
        let inner = &self.inner;
        let result = py.detach(|| {
            inner.merge_agreement_v2_transcript_branches_json(
                &base_document_json,
                &left_document_json,
                &right_document_json,
            )
        });
        result.to_py()
    }

    /// Resolve a conflicting branch by applying an explicit resolution mutation.
    #[cfg(feature = "agreements")]
    fn resolve_agreement_v2_branch_conflict(
        &self,
        py: Python,
        base_document_json: &str,
        previous_document_json: &str,
        side_branch_document_json: &str,
        mutation: Py<PyAny>,
    ) -> PyResult<String> {
        let mutation_json =
            py_json_arg_to_string(py, mutation, "agreement v2 branch resolution mutation")?;
        let base_document_json = base_document_json.to_string();
        let previous_document_json = previous_document_json.to_string();
        let side_branch_document_json = side_branch_document_json.to_string();
        let inner = &self.inner;
        let result = py.detach(|| {
            inner.resolve_agreement_v2_branch_conflict_json(
                &base_document_json,
                &previous_document_json,
                &side_branch_document_json,
                &mutation_json,
            )
        });
        result.to_py()
    }

    /// Verify a signed JACS document.
    ///
    /// Args:
    ///     signed_document: JSON string of the signed document
    ///
    /// Returns:
    ///     dict with valid, data, signer_id, timestamp, attachments, errors
    fn verify(&self, py: Python, signed_document: &str) -> PyResult<Py<PyAny>> {
        self.verification_result(
            py,
            self.inner.verify_json(signed_document),
            "Failed to verify",
            true,
            true,
        )
    }

    /// Sign a raw string and return the base64-encoded signature.
    ///
    /// This provides the same raw-string signing as JacsAgent.sign_string(),
    /// using the underlying KeyManager::sign_string() via sign_raw_bytes().
    ///
    /// Args:
    ///     data: The UTF-8 string to sign
    ///
    /// Returns:
    ///     Base64-encoded signature string
    fn sign_string(&self, data: &str) -> PyResult<String> {
        map_py_runtime_result(
            self.inner.sign_raw_bytes_base64(data.as_bytes()),
            "Failed to sign string",
        )
    }

    /// Export the current agent's identity JSON for P2P exchange.
    ///
    /// Returns:
    ///     The agent JSON document as a string
    fn export_agent(&self) -> PyResult<String> {
        map_py_runtime_result(self.inner.export_agent(), "Failed to export agent")
    }

    /// Get the current agent's public key in PEM format.
    ///
    /// Returns:
    ///     The public key as a PEM string
    fn get_public_key_pem(&self) -> PyResult<String> {
        map_py_runtime_result(self.inner.get_public_key_pem(), "Failed to get public key")
    }

    /// Get the agent's unique ID.
    fn get_agent_id(&self) -> PyResult<String> {
        map_py_runtime_result(self.inner.get_agent_id(), "Failed to get agent ID")
    }

    /// Get the JACS key ID (signing key identifier).
    fn key_id(&self) -> PyResult<String> {
        map_py_runtime_result(self.inner.key_id(), "Failed to get key ID")
    }

    /// Get the public key as base64-encoded raw bytes.
    fn get_public_key_base64(&self) -> PyResult<String> {
        map_py_runtime_result(
            self.inner.get_public_key_base64(),
            "Failed to get public key base64",
        )
    }

    /// Get runtime diagnostic info as a JSON string.
    fn diagnostics(&self) -> String {
        self.inner.diagnostics()
    }

    /// Export this agent's did:wba identifier for W3C interop.
    #[pyo3(signature = (origin=None))]
    fn export_w3c_did(&self, origin: Option<&str>) -> PyResult<String> {
        map_py_runtime_result(
            self.inner.export_w3c_did(origin),
            "Failed to export W3C DID",
        )
    }

    /// Export this agent's did:wba DID document.
    #[pyo3(signature = (origin=None))]
    fn export_w3c_did_document(&self, py: Python, origin: Option<&str>) -> PyResult<Py<PyAny>> {
        let json_str = self.inner.export_w3c_did_document_json(origin).to_py()?;
        let value = parse_json_value(&json_str, "W3C DID document")?;
        json_value_to_py(py, &value)
    }

    /// Export this agent's W3C agent description document.
    #[pyo3(signature = (origin=None))]
    fn export_w3c_agent_description(
        &self,
        py: Python,
        origin: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let json_str = self
            .inner
            .export_w3c_agent_description_json(origin)
            .to_py()?;
        let value = parse_json_value(&json_str, "W3C agent description")?;
        json_value_to_py(py, &value)
    }

    /// Generate W3C well-known discovery documents keyed by URL path.
    #[pyo3(signature = (origin=None))]
    fn generate_w3c_well_known(&self, py: Python, origin: Option<&str>) -> PyResult<Py<PyAny>> {
        let json_str = self.inner.generate_w3c_well_known_json(origin).to_py()?;
        let value = parse_json_value(&json_str, "W3C well-known documents")?;
        json_value_to_py(py, &value)
    }

    /// Create a request-bound DID authentication proof.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (method, url, *, body=None, nonce=None, created=None, origin=None))]
    fn sign_w3c_request(
        &self,
        py: Python,
        method: &str,
        url: &str,
        body: Option<&str>,
        nonce: Option<&str>,
        created: Option<&str>,
        origin: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let params = serde_json::json!({
            "method": method,
            "url": url,
            "body": body,
            "nonce": nonce,
            "created": created,
            "origin": origin
        });
        let json_str = self
            .inner
            .sign_w3c_request_json(&params.to_string())
            .to_py()?;
        let value = parse_json_value(&json_str, "W3C request proof")?;
        json_value_to_py(py, &value)
    }

    /// Verify a request-bound DID authentication proof.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (proof_json, did_document_json, *, body=None, max_age_seconds=300, method=None, url=None))]
    fn verify_w3c_request(
        &self,
        py: Python,
        proof_json: &str,
        did_document_json: &str,
        body: Option<&str>,
        max_age_seconds: u64,
        method: Option<&str>,
        url: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let json_str = self
            .inner
            .verify_w3c_request_json(
                proof_json,
                did_document_json,
                body,
                max_age_seconds,
                method,
                url,
            )
            .to_py()?;
        let value = parse_json_value(&json_str, "W3C request proof verification")?;
        json_value_to_py(py, &value)
    }

    /// Create a new JACS agent with full programmatic control.
    ///
    /// Args:
    ///     name: Human-readable name for the agent
    ///     password: Password for encrypting the private key
    ///     algorithm: Signing algorithm (default: "pq2025")
    ///     data_directory: Directory for data storage (default: "./jacs_data")
    ///     key_directory: Directory for keys (default: "./jacs_keys")
    ///     config_path: Config file path (default: "./jacs.config.json")
    ///     agent_type: Agent type (default: "ai")
    ///     description: Agent description (default: "")
    ///     domain: Agent domain for DNSSEC (optional)
    ///     default_storage: Storage backend (default: "fs")
    ///
    /// Returns:
    ///     Tuple of (SimpleAgent, dict with agent info)
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (name, password, algorithm=None, data_directory=None, key_directory=None, config_path=None, agent_type=None, description=None, domain=None, default_storage=None))]
    fn create_agent(
        py: Python,
        name: &str,
        password: &str,
        algorithm: Option<&str>,
        data_directory: Option<&str>,
        key_directory: Option<&str>,
        config_path: Option<&str>,
        agent_type: Option<&str>,
        description: Option<&str>,
        domain: Option<&str>,
        default_storage: Option<&str>,
    ) -> PyResult<(Self, Py<PyAny>)> {
        let params = serde_json::json!({
            "name": name,
            "password": password,
            "algorithm": algorithm.unwrap_or("pq2025"),
            "data_directory": data_directory.unwrap_or("./jacs_data"),
            "key_directory": key_directory.unwrap_or("./jacs_keys"),
            "config_path": config_path.unwrap_or("./jacs.config.json"),
            "agent_type": agent_type.unwrap_or("ai"),
            "description": description.unwrap_or(""),
            "domain": domain.unwrap_or(""),
            "default_storage": default_storage.unwrap_or("fs"),
        });

        let params_json = params.to_string();
        simple_agent_with_info(
            py,
            SimpleAgentWrapper::create_with_params(&params_json),
            "Failed to create agent",
            SIMPLE_AGENT_EXTENDED_INFO_KEYS,
        )
    }

    /// Create a new JACS agent from a JSON parameters string.
    ///
    /// This matches the API shape of Node's `JacsSimpleAgent.createWithParams(paramsJSON)`
    /// and Go's `CreateSimpleAgentWithParams(paramsJSON)`.
    ///
    /// Args:
    ///     params_json: A JSON string of CreateAgentParams fields
    ///         (e.g., `{"name":"foo","password":"bar","algorithm":"ed25519"}`)
    ///
    /// Returns:
    ///     Tuple of (SimpleAgent, dict with agent info)
    #[staticmethod]
    fn create_with_params(py: Python, params_json: &str) -> PyResult<(Self, Py<PyAny>)> {
        simple_agent_with_info(
            py,
            SimpleAgentWrapper::create_with_params(params_json),
            "Failed to create agent with params",
            SIMPLE_AGENT_EXTENDED_INFO_KEYS,
        )
    }

    /// Verify a document by its ID from storage.
    ///
    /// Args:
    ///     document_id: Document ID in "uuid:version" format
    ///
    /// Returns:
    ///     dict with valid, data, signer_id, timestamp, attachments, errors
    fn verify_by_id(&self, py: Python, document_id: &str) -> PyResult<Py<PyAny>> {
        self.verification_result(
            py,
            self.inner.verify_by_id_json(document_id),
            "Failed to verify by ID",
            true,
            false,
        )
    }

    /// Verify a signed document with an explicit public key (base64-encoded).
    ///
    /// Args:
    ///     signed_document: JSON string of the signed document
    ///     public_key_base64: Base64-encoded public key bytes
    ///
    /// Returns:
    ///     dict with valid, data, signer_id, timestamp, attachments, errors
    fn verify_with_key(
        &self,
        py: Python,
        signed_document: &str,
        public_key_base64: &str,
    ) -> PyResult<Py<PyAny>> {
        self.verification_result(
            py,
            self.inner
                .verify_with_key_json(signed_document, public_key_base64),
            "Failed to verify with key",
            true,
            false,
        )
    }

    /// Rotate the agent's cryptographic keys.
    ///
    /// Generates a new keypair, archives the old keys, creates a new agent version,
    /// and re-signs the config file. Optionally changes the signing algorithm.
    ///
    /// Args:
    ///     algorithm: Optional new algorithm ("ring-Ed25519", "pq2025").
    ///               If None, keeps the current algorithm.
    ///
    /// Returns:
    ///     JSON string containing the RotationResult
    #[pyo3(signature = (algorithm=None))]
    fn rotate_keys(&self, algorithm: Option<&str>) -> PyResult<String> {
        let result = jacs_core::simple::advanced::rotate(self.inner.inner_ref(), algorithm)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Key rotation failed: {}",
                    e
                ))
            })?;
        serde_json::to_string(&result).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize rotation result: {}",
                e
            ))
        })
    }

    /// Re-encrypt the agent's private key with a new password.
    ///
    /// Args:
    ///     old_password: Current password
    ///     new_password: New password (must meet password requirements)
    fn reencrypt_key(&self, old_password: &str, new_password: &str) -> PyResult<()> {
        jacs_core::simple::advanced::reencrypt_key(
            self.inner.inner_ref(),
            old_password,
            new_password,
        )
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to re-encrypt key: {}",
                e
            ))
        })
    }

    // =========================================================================
    // Attestation methods (feature-gated)
    // =========================================================================

    /// Create a signed attestation document.
    ///
    /// Args:
    ///     params_json: JSON string containing subject, claims, evidence, derivation, policyContext
    ///
    /// Returns:
    ///     JSON string of the signed attestation document
    #[cfg(feature = "attestation")]
    fn create_attestation(&self, params_json: &str) -> PyResult<String> {
        jacs_core::attestation::simple::create_from_json(self.inner.inner_ref(), params_json)
            .map(|d| d.raw)
            .map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to create attestation: {}",
                    e
                ))
            })
    }

    /// Verify an attestation (local tier: crypto + hash only).
    #[cfg(feature = "attestation")]
    fn verify_attestation(&self, document_key: &str) -> PyResult<String> {
        let result = jacs_core::attestation::simple::verify(self.inner.inner_ref(), document_key)
            .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to verify attestation: {}",
                e
            ))
        })?;
        serde_json::to_string(&result).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize result: {}",
                e
            ))
        })
    }

    /// Verify an attestation (full tier: crypto + evidence + chain).
    #[cfg(feature = "attestation")]
    fn verify_attestation_full(&self, document_key: &str) -> PyResult<String> {
        let result =
            jacs_core::attestation::simple::verify_full(self.inner.inner_ref(), document_key)
                .map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "Failed to verify attestation (full): {}",
                        e
                    ))
                })?;
        serde_json::to_string(&result).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to serialize result: {}",
                e
            ))
        })
    }

    /// Lift a signed document into an attestation.
    #[cfg(feature = "attestation")]
    fn lift_to_attestation(&self, signed_doc_json: &str, claims_json: &str) -> PyResult<String> {
        jacs_core::attestation::simple::lift_from_json(
            self.inner.inner_ref(),
            signed_doc_json,
            claims_json,
        )
        .map(|d| d.raw)
        .map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to lift to attestation: {}",
                e
            ))
        })
    }

    /// Export an attestation as a DSSE envelope.
    #[cfg(feature = "attestation")]
    fn export_dsse(&self, attestation_json: &str) -> PyResult<String> {
        jacs_core::attestation::simple::export_dsse(attestation_json).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to export DSSE: {}",
                e
            ))
        })
    }

    // =========================================================================
    // Format Conversion
    // =========================================================================

    /// Convert a JSON string to YAML.
    ///
    /// Args:
    ///     json_str: A valid JSON string
    ///
    /// Returns:
    ///     YAML representation of the JSON document
    #[pyo3(signature = (json_str))]
    fn to_yaml(&self, json_str: &str) -> PyResult<String> {
        self.inner.to_yaml(json_str).to_py()
    }

    /// Convert a YAML string to JSON.
    ///
    /// Args:
    ///     yaml_str: A valid YAML string
    ///
    /// Returns:
    ///     Pretty-printed JSON representation
    #[allow(clippy::wrong_self_convention)]
    #[pyo3(signature = (yaml_str))]
    fn from_yaml(&self, yaml_str: &str) -> PyResult<String> {
        self.inner.from_yaml(yaml_str).to_py()
    }

    /// Convert a JSON string to a self-contained HTML document.
    ///
    /// Args:
    ///     json_str: A valid JSON string
    ///
    /// Returns:
    ///     Self-contained HTML document with embedded JSON
    #[pyo3(signature = (json_str))]
    fn to_html(&self, json_str: &str) -> PyResult<String> {
        self.inner.to_html(json_str).to_py()
    }

    /// Extract JSON from an HTML document produced by to_html().
    ///
    /// Args:
    ///     html_str: An HTML string containing embedded JACS JSON
    ///
    /// Returns:
    ///     The extracted JSON string
    #[allow(clippy::wrong_self_convention)]
    #[pyo3(signature = (html_str))]
    fn from_html(&self, html_str: &str) -> PyResult<String> {
        self.inner.from_html(html_str).to_py()
    }

    /// Convert a YAML string to JSON and verify the resulting document.
    ///
    /// This is equivalent to calling from_yaml() followed by verify().
    ///
    /// Args:
    ///     yaml_str: A valid YAML string containing a signed JACS document
    ///
    /// Returns:
    ///     Verification result JSON string
    #[pyo3(signature = (yaml_str))]
    fn verify_yaml(&self, yaml_str: &str) -> PyResult<String> {
        let json_str = self.inner.from_yaml(yaml_str).to_py()?;
        self.inner.verify_json(&json_str).to_py()
    }

    // =========================================================================
    // Inline text and media signing (PRD §3.1, §3.2, §4.1, §4.2; Task 10)
    // =========================================================================

    /// Sign a text/markdown file in place by appending an inline JACS
    /// signature block (PRD §4.1).
    ///
    /// Args:
    ///     file_path: Path to the file to sign
    ///     no_backup: Skip the automatic ``<path>.bak`` backup. Default False.
    ///
    /// Returns:
    ///     dict with `path`, `signers_added`, `backup_path`.
    #[pyo3(signature = (file_path, *, no_backup=false))]
    fn sign_text_file(&self, py: Python, file_path: &str, no_backup: bool) -> PyResult<Py<PyAny>> {
        let opts = serde_json::json!({"backup": !no_backup}).to_string();
        let json_str = self.inner.sign_text_file_json(file_path, &opts).to_py()?;
        let value = parse_json_value(&json_str, "sign_text_file outcome")?;
        json_value_to_py(py, &value)
    }

    /// Short alias for [`sign_text_file`] (matches the CLI verb).
    #[pyo3(signature = (file_path, *, no_backup=false))]
    fn sign_text(&self, py: Python, file_path: &str, no_backup: bool) -> PyResult<Py<PyAny>> {
        self.sign_text_file(py, file_path, no_backup)
    }

    /// Verify inline JACS signatures embedded in a text/markdown file
    /// (PRD §4.1, §4.1.5, C1).
    ///
    /// Args:
    ///     file_path: Path to the file
    ///     strict: When True, missing signature raises ``MissingSignatureError``.
    ///         Default False (permissive: returns ``status: "missing_signature"``).
    ///     key_dir: Optional directory of ``<signer_id>.public.pem`` files for
    ///         offline verification.
    ///
    /// Returns:
    ///     dict with `status` (`"signed"` | `"missing_signature"` | `"malformed"`)
    ///     and `signatures` list.
    #[pyo3(signature = (file_path, *, strict=false, key_dir=None))]
    fn verify_text_file(
        &self,
        py: Python,
        file_path: &str,
        strict: bool,
        key_dir: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let opts = build_verify_text_opts(strict, key_dir);
        let json_str = self.inner.verify_text_file_json(file_path, &opts).to_py()?;
        let value = parse_json_value(&json_str, "verify_text_file result")?;
        json_value_to_py(py, &value)
    }

    /// Short alias for [`verify_text_file`] (matches the CLI verb).
    #[pyo3(signature = (file_path, *, strict=false, key_dir=None))]
    fn verify_text(
        &self,
        py: Python,
        file_path: &str,
        strict: bool,
        key_dir: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        self.verify_text_file(py, file_path, strict, key_dir)
    }

    /// Sign a PNG / JPEG / WebP image by embedding a JACS signature
    /// (PRD §4.2).
    ///
    /// Args:
    ///     input_path: Source image path
    ///     output_path: Path to write the signed image to (may equal input_path)
    ///     robust: PRD §4.2.3 LSB embedding for re-encode survivability
    ///         (PNG/JPEG only). Default False.
    ///     format: Optional explicit format override ("png" | "jpeg" | "webp")
    ///     refuse_overwrite: If True, refuse if input already carries a JACS
    ///         signature (PRD §4.2.2 single-signer guard). Default False.
    ///
    /// Returns:
    ///     dict with `out_path`, `signer_id`, `format`, `robust`, `backup_path`.
    #[pyo3(signature = (input_path, output_path, *, robust=false, format=None, refuse_overwrite=false))]
    fn sign_image(
        &self,
        py: Python,
        input_path: &str,
        output_path: &str,
        robust: bool,
        format: Option<&str>,
        refuse_overwrite: bool,
    ) -> PyResult<Py<PyAny>> {
        let mut obj = serde_json::Map::new();
        obj.insert("robust".to_string(), serde_json::Value::Bool(robust));
        if let Some(f) = format {
            obj.insert(
                "formatHint".to_string(),
                serde_json::Value::String(f.to_string()),
            );
        }
        obj.insert(
            "refuseOverwrite".to_string(),
            serde_json::Value::Bool(refuse_overwrite),
        );
        let opts = serde_json::Value::Object(obj).to_string();
        let json_str = self
            .inner
            .sign_image_json(input_path, output_path, &opts)
            .to_py()?;
        let value = parse_json_value(&json_str, "sign_image outcome")?;
        json_value_to_py(py, &value)
    }

    /// Verify an embedded JACS signature in a PNG / JPEG / WebP image
    /// (PRD §4.2, §4.1.5, C1).
    ///
    /// Args:
    ///     file_path: Path to the signed image
    ///     strict: When True, missing signature raises ``MissingSignatureError``.
    ///     key_dir: Optional directory of ``<signer_id>.public.pem`` files.
    ///     robust: When True, scan the LSB channel for a robust-mode payload
    ///         when no metadata payload is found (PRD §4.2.4). Default False.
    ///
    /// Returns:
    ///     dict with `status`, `signer_id`, `algorithm`, `format`,
    ///     `embedding_channels`.
    #[pyo3(signature = (file_path, *, strict=false, key_dir=None, robust=false))]
    fn verify_image(
        &self,
        py: Python,
        file_path: &str,
        strict: bool,
        key_dir: Option<&str>,
        robust: bool,
    ) -> PyResult<Py<PyAny>> {
        let opts = build_verify_image_opts(strict, key_dir, robust);
        let json_str = self.inner.verify_image_json(file_path, &opts).to_py()?;
        let value = parse_json_value(&json_str, "verify_image result")?;
        json_value_to_py(py, &value)
    }

    /// Extract the JACS signature payload embedded in a signed image
    /// (PRD §3.2).
    ///
    /// Args:
    ///     file_path: Path to a signed image
    ///     raw_payload: When True, return the raw base64url wire form instead
    ///         of the decoded JACS signed-document JSON. Default False.
    ///
    /// Returns:
    ///     The payload string when present, or None if the image carries no
    ///     JACS signature.
    #[pyo3(signature = (file_path, *, raw_payload=false))]
    fn extract_media_signature(
        &self,
        file_path: &str,
        raw_payload: bool,
    ) -> PyResult<Option<String>> {
        let opts = serde_json::json!({"rawPayload": raw_payload}).to_string();
        let envelope_json = self
            .inner
            .extract_media_signature_json(file_path, &opts)
            .to_py()?;
        let value = parse_json_value(&envelope_json, "extract_media_signature envelope")?;
        if value.get("present").and_then(|v| v.as_bool()) == Some(true) {
            Ok(value
                .get("payload")
                .and_then(|v| v.as_str().map(String::from)))
        } else {
            Ok(None)
        }
    }
}

// =============================================================================
// Inline / media helper functions (Task 10).
// =============================================================================

fn build_verify_text_opts(strict: bool, key_dir: Option<&str>) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("strict".to_string(), serde_json::Value::Bool(strict));
    if let Some(p) = key_dir {
        obj.insert(
            "keyDir".to_string(),
            serde_json::Value::String(p.to_string()),
        );
    }
    serde_json::Value::Object(obj).to_string()
}

fn build_verify_image_opts(strict: bool, key_dir: Option<&str>, robust: bool) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("strict".to_string(), serde_json::Value::Bool(strict));
    if let Some(p) = key_dir {
        obj.insert(
            "keyDir".to_string(),
            serde_json::Value::String(p.to_string()),
        );
    }
    obj.insert("robust".to_string(), serde_json::Value::Bool(robust));
    serde_json::Value::Object(obj).to_string()
}

/// Convert a `serde_json::Value` into a `Py<PyAny>` by going through `json.loads`.
/// We already have helpers in `conversion_utils` for the other direction; for
/// JSON returned by the wrapper layer, the simplest faithful conversion is to
/// hand it to Python's stdlib `json.loads`.
fn json_value_to_py(py: Python, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    let json_string = serde_json::to_string(value).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "Failed to re-serialize JSON for Python conversion: {}",
            e
        ))
    })?;
    let json_module = py.import("json")?;
    let py_obj = json_module.call_method1("loads", (json_string,))?;
    Ok(py_obj.unbind())
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

/// Verify a signed JACS document without loading an agent.
#[pyfunction]
#[pyo3(signature = (signed_document, key_resolution=None, data_directory=None, key_directory=None))]
fn verify_document_standalone(
    py: Python,
    signed_document: &str,
    key_resolution: Option<&str>,
    data_directory: Option<&str>,
    key_directory: Option<&str>,
) -> PyResult<Py<PyAny>> {
    let r = jacs_binding_core::verify_document_standalone(
        signed_document,
        key_resolution,
        data_directory,
        key_directory,
    )
    .to_py()?;
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("valid", r.valid)?;
    dict.set_item("signer_id", r.signer_id)?;
    dict.set_item("timestamp", r.timestamp)?;
    dict.set_item("agent_version", r.agent_version)?;
    Ok(dict.into())
}

/// Verify an agent's DNS TXT record matches its public key hash.
#[pyfunction]
#[pyo3(signature = (agent_json, domain))]
fn verify_agent_dns(py: Python, agent_json: &str, domain: &str) -> PyResult<Py<PyAny>> {
    let r = jacs_binding_core::verify_agent_dns(agent_json, domain).to_py()?;
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("verified", r.verified)?;
    dict.set_item("agent_id", &r.agent_id)?;
    dict.set_item("domain", &r.domain)?;
    dict.set_item("document_hash", &r.document_hash)?;
    dict.set_item("dns_hash", &r.dns_hash)?;
    dict.set_item("message", &r.message)?;
    Ok(dict.into())
}

/// Create a JACS configuration JSON string.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
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

/// Add an agent to the local trust store using an explicit public key PEM.
///
/// Args:
///     agent_json: The full agent JSON string
///     public_key_pem: PEM-encoded public key used to verify self-signature
///
/// Returns:
///     The agent ID if successfully trusted
#[pyfunction]
fn trust_agent_with_key(agent_json: &str, public_key_pem: &str) -> PyResult<String> {
    jacs_binding_core::trust_agent_with_key(agent_json, public_key_pem).to_py()
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
// Audit (security audit and health checks)
// =============================================================================

/// Run a read-only security audit and health checks.
///
/// Returns the audit result as a JSON string (risks, health_checks, summary).
/// Does not modify state.
///
/// Args:
///     config_path: Optional path to jacs config file.
///     recent_n: Optional number of recent documents to re-verify (default from config).
///
/// Returns:
///     JSON string of the audit result (parse with json.loads() for a dict).
#[pyfunction]
#[pyo3(signature = (config_path=None, recent_n=None))]
fn audit(config_path: Option<&str>, recent_n: Option<u32>) -> PyResult<String> {
    jacs_binding_core::audit(config_path, recent_n).to_py()
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
         You must create a JacsAgent instance and load it first.",
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
         You must create a JacsAgent instance and load it first.",
    ))
}

/// Verify an agent's self-signature.
///
/// DEPRECATED: Use JacsAgent().verify_agent() or SimpleAgent.verify_self() instead.
#[pyfunction]
fn verify_agent(_py: Python, _agentfile: Option<String>) -> PyResult<bool> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_agent() is deprecated. Use JacsAgent().verify_agent() or \
         SimpleAgent.load().verify_self() instead.",
    ))
}

/// Update an agent.
///
/// DEPRECATED: Use JacsAgent().update_agent() instead.
#[pyfunction]
fn update_agent(_py: Python, _new_agent_string: String) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "update_agent() is deprecated. Use JacsAgent().update_agent() instead. \
         You must create a JacsAgent instance and load it first.",
    ))
}

/// Verify a document.
///
/// DEPRECATED: Use JacsAgent().verify_document() or SimpleAgent.verify() instead.
#[pyfunction]
fn verify_document(_py: Python, _document_string: String) -> PyResult<bool> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_document() is deprecated. Use JacsAgent().verify_document() or \
         SimpleAgent.load().verify() instead.",
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
         You must create a JacsAgent instance and load it first.",
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
         You must create a JacsAgent instance and load it first.",
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
         You must create a JacsAgent instance and load it first.",
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
         You must create a JacsAgent instance and load it first.",
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
         SimpleAgent.load().sign_message() instead.",
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
         You must create a JacsAgent instance and load it first.",
    ))
}

/// Sign a request payload.
///
/// DEPRECATED: Use JacsAgent().sign_request() or SimpleAgent.sign_message() instead.
#[pyfunction]
fn sign_request(_py: Python, _params_obj: Py<PyAny>) -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "sign_request() is deprecated. Use JacsAgent().sign_request() or \
         SimpleAgent.load().sign_message() instead.",
    ))
}

/// Verify a response.
///
/// DEPRECATED: Use JacsAgent().verify_response() or SimpleAgent.verify() instead.
#[pyfunction]
fn verify_response(_py: Python, _document_string: String) -> PyResult<Py<PyAny>> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_response() is deprecated. Use JacsAgent().verify_response() or \
         SimpleAgent.load().verify() instead.",
    ))
}

/// Verify a response and return agent ID.
///
/// DEPRECATED: Use JacsAgent().verify_response_with_agent_id() instead.
#[pyfunction]
fn verify_response_with_agent_id(_py: Python, _document_string: String) -> PyResult<Py<PyAny>> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_response_with_agent_id() is deprecated. \
         Use JacsAgent().verify_response_with_agent_id() instead.",
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
) -> PyResult<Py<PyAny>> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "create_simple() is deprecated. Use SimpleAgent.create() instead, which returns \
         both the agent instance and info dict.",
    ))
}

/// Load an existing agent.
///
/// DEPRECATED: Use SimpleAgent.load() instead.
#[pyfunction]
fn load_simple(_config_path: Option<&str>) -> PyResult<()> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "load_simple() is deprecated. Use SimpleAgent.load() instead.",
    ))
}

/// Verify self.
///
/// DEPRECATED: Use SimpleAgent.load().verify_self() instead.
#[pyfunction]
fn verify_self_simple() -> PyResult<Py<PyAny>> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_self_simple() is deprecated. Use SimpleAgent.load().verify_self() instead.",
    ))
}

/// Sign a message.
///
/// DEPRECATED: Use SimpleAgent.load().sign_message() instead.
#[pyfunction]
fn sign_message_simple(_py: Python, _data: Py<PyAny>) -> PyResult<Py<PyAny>> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "sign_message_simple() is deprecated. Use SimpleAgent.load().sign_message() instead.",
    ))
}

/// Sign a file.
///
/// DEPRECATED: Use SimpleAgent.load().sign_file() instead.
#[pyfunction]
fn sign_file_simple(_file_path: &str, _embed: bool) -> PyResult<Py<PyAny>> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "sign_file_simple() is deprecated. Use SimpleAgent.load().sign_file() instead.",
    ))
}

/// Verify a signed document.
///
/// DEPRECATED: Use SimpleAgent.load().verify() instead.
#[pyfunction]
fn verify_simple(_py: Python, _signed_document: &str) -> PyResult<Py<PyAny>> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "verify_simple() is deprecated. Use SimpleAgent.load().verify() instead.",
    ))
}

/// Export agent identity.
///
/// DEPRECATED: Use SimpleAgent.load().export_agent() instead.
#[pyfunction]
fn export_agent_simple() -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "export_agent_simple() is deprecated. Use SimpleAgent.load().export_agent() instead.",
    ))
}

/// Get public key PEM.
///
/// DEPRECATED: Use SimpleAgent.load().get_public_key_pem() instead.
#[pyfunction]
fn get_public_key_pem_simple() -> PyResult<String> {
    Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
        "get_public_key_pem_simple() is deprecated. \
         Use SimpleAgent.load().get_public_key_pem() instead.",
    ))
}

#[pyfunction]
#[pyo3(signature = (config_path=None, key_directory=None, explicit_password=None))]
fn resolve_private_key_password(
    config_path: Option<String>,
    key_directory: Option<String>,
    explicit_password: Option<String>,
) -> PyResult<String> {
    jacs_binding_core::resolve_private_key_password(
        config_path.as_deref(),
        key_directory.as_deref(),
        explicit_password.as_deref(),
    )
    .to_py()
}

#[pyfunction]
#[pyo3(signature = (config_path=None, key_directory=None))]
fn quickstart_private_key_password(
    config_path: Option<String>,
    key_directory: Option<String>,
) -> PyResult<String> {
    jacs_binding_core::quickstart_private_key_password(
        config_path.as_deref(),
        key_directory.as_deref(),
    )
    .to_py()
}

#[pyfunction]
fn ensure_network_access(capability: &str) -> PyResult<()> {
    jacs_binding_core::ensure_network_access(capability).to_py()
}

#[pyfunction]
#[pyo3(signature = (base_url, timeout_ms=None))]
fn fetch_agent_card(base_url: &str, timeout_ms: Option<u64>) -> PyResult<String> {
    jacs_binding_core::fetch_agent_card(base_url, timeout_ms).to_py()
}

#[pyfunction]
#[pyo3(signature = (base_url=None, jacs_id=None, version=None, public_key_hash=None, timeout_ms=None))]
fn fetch_remote_key_lookup(
    base_url: Option<String>,
    jacs_id: Option<String>,
    version: Option<String>,
    public_key_hash: Option<String>,
    timeout_ms: Option<u64>,
) -> PyResult<String> {
    jacs_binding_core::fetch_remote_key_lookup(
        base_url.as_deref(),
        jacs_id.as_deref(),
        version.as_deref(),
        public_key_hash.as_deref(),
        timeout_ms,
    )
    .to_py()
}

#[pyfunction]
fn hash_public_key_base64(public_key_base64: &str) -> PyResult<String> {
    jacs_binding_core::hash_public_key_base64(public_key_base64).to_py()
}

#[pyfunction]
fn build_jwk_set_from_public_key(
    public_key_base64: &str,
    key_algorithm: &str,
    key_id: &str,
) -> PyResult<String> {
    jacs_binding_core::build_jwk_set_from_public_key(public_key_base64, key_algorithm, key_id)
        .to_py()
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

#[pyfunction]
#[pyo3(signature = (config_path=None, recent_n=None))]
fn audit_simple(config_path: Option<&str>, recent_n: Option<u32>) -> PyResult<String> {
    audit(config_path, recent_n)
}

// =============================================================================
// MCP path policy delegate (PRD §4.2.6, Issue 022)
// =============================================================================
//
// Single source of truth for MCP file-path validation. Python's
// `_validate_mcp_file_path` (in `jacspy/python/jacs/adapters/mcp.py`)
// delegates to this function so Python enforcement matches Rust
// byte-for-byte. Removing the local heuristic eliminates a drift surface
// that the PRD §4.2.6 review previously called out.
//
// Returns the resolved canonical path string on accept; raises
// `ValueError` with the rejection reason on policy failure.
#[pyfunction]
#[pyo3(signature = (raw, kind="input"))]
fn jacs_mcp_resolve_input_path(raw: &str, kind: &str) -> PyResult<String> {
    let kind_enum = match kind {
        "input" => jacs_mcp::path_policy::PathKind::Input,
        "output" => jacs_mcp::path_policy::PathKind::Output,
        other => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "invalid kind: {}, expected 'input' or 'output'",
                other
            )));
        }
    };
    jacs_mcp::path_policy::resolve(raw, kind_enum)
        .map(|p| p.display().to_string())
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))
}

// Hoisted out of the `#[pymodule]` body: the inline `#[pyfn]` form is
// deprecated (removal planned upstream); registered below via add_function.
#[pyfunction]
#[pyo3(name = "log_to_python")]
fn py_log_to_python(py: Python, message: String, log_level: String) -> PyResult<()> {
    log_to_python(py, &message, &log_level)
}

#[pymodule]
fn jacs(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    Python::initialize();

    // =============================================================================
    // Primary API Classes (Recommended)
    // =============================================================================
    m.add_class::<JacsAgent>()?;
    m.add_class::<SimpleAgent>()?;

    // =============================================================================
    // Custom exception classes (Task 03 + Task 10).
    // =============================================================================
    // `MissingSignatureError` is raised in strict-mode verify_text / verify_image
    // (PRD §4.1.2, C1). Pure-Python `jacs.MissingSignatureError` in
    // jacspy/python/jacs/types.py is the user-facing alias; the Rust binding
    // raises *this* PyType so callers can `except jacs.MissingSignatureError:`.
    // The Python `__init__.py` re-exports the native class as
    // `MissingSignatureError` so the canonical Python class IS this one.
    m.add(
        "MissingSignatureError",
        _py.get_type::<MissingSignatureError>(),
    )?;

    // =============================================================================
    // Stateless Utility Functions
    // =============================================================================
    m.add_function(wrap_pyfunction!(hash_string, m)?)?;
    m.add_function(wrap_pyfunction!(verify_document_standalone, m)?)?;
    m.add_function(wrap_pyfunction!(create_config, m)?)?;
    m.add_function(wrap_pyfunction!(handle_agent_create_py, m)?)?;
    m.add_function(wrap_pyfunction!(handle_config_create_py, m)?)?;
    m.add_function(wrap_pyfunction!(resolve_private_key_password, m)?)?;
    m.add_function(wrap_pyfunction!(quickstart_private_key_password, m)?)?;
    m.add_function(wrap_pyfunction!(ensure_network_access, m)?)?;
    m.add_function(wrap_pyfunction!(fetch_agent_card, m)?)?;
    m.add_function(wrap_pyfunction!(fetch_remote_key_lookup, m)?)?;
    m.add_function(wrap_pyfunction!(hash_public_key_base64, m)?)?;
    m.add_function(wrap_pyfunction!(build_jwk_set_from_public_key, m)?)?;

    // =============================================================================
    // Trust Store Functions
    // =============================================================================
    m.add_function(wrap_pyfunction!(trust_agent, m)?)?;
    m.add_function(wrap_pyfunction!(trust_agent_with_key, m)?)?;
    m.add_function(wrap_pyfunction!(list_trusted_agents, m)?)?;
    m.add_function(wrap_pyfunction!(untrust_agent, m)?)?;
    m.add_function(wrap_pyfunction!(is_trusted, m)?)?;
    m.add_function(wrap_pyfunction!(get_trusted_agent, m)?)?;
    m.add_function(wrap_pyfunction!(audit, m)?)?;
    m.add_function(wrap_pyfunction!(verify_agent_dns, m)?)?;

    // =============================================================================
    // Legacy Functions (Deprecated - for backward compatibility)
    // =============================================================================
    // These functions either error with deprecation messages or provide
    // limited functionality. New code should use JacsAgent or SimpleAgent.

    m.add_function(wrap_pyfunction!(py_log_to_python, m)?)?;
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
    m.add_function(wrap_pyfunction!(audit_simple, m)?)?;

    // MCP path policy delegate (PRD §4.2.6, Issue 022).
    m.add_function(wrap_pyfunction!(jacs_mcp_resolve_input_path, m)?)?;

    Ok(())
}
