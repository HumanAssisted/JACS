//! `SimpleAgentWrapper` — thin FFI adapter over the narrow `SimpleAgent` contract.
//!
//! This module contains zero business logic. Every method delegates to
//! `jacs::simple::SimpleAgent` and marshals the result to FFI-safe types
//! (String in/out, base64 for bytes, JSON for structured data).

use crate::{BindingCoreError, BindingResult, ErrorKind};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jacs::simple::SimpleAgent;
use serde::Serialize;
use std::sync::Arc;

/// Thread-safe, Clone-able FFI wrapper around the narrow [`SimpleAgent`] contract.
///
/// All methods return `BindingResult<String>` (or simple scalars) so that
/// language bindings (Python/PyO3, Node/NAPI, Go/CGo) never touch Rust-only types.
#[derive(Clone)]
pub struct SimpleAgentWrapper {
    inner: Arc<SimpleAgent>,
}

// Compile-time proof of thread safety.
const _: () = {
    fn _assert<T: Send + Sync>() {}
    let _ = _assert::<SimpleAgentWrapper>;
};

fn serialize_json<T: Serialize>(value: &T, context: &str) -> BindingResult<String> {
    serde_json::to_string(value).map_err(|e| {
        BindingCoreError::serialization_failed(format!("Failed to serialize {}: {}", context, e))
    })
}

fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn decode_base64(input: &str, label: &str) -> BindingResult<Vec<u8>> {
    STANDARD
        .decode(input)
        .map_err(|e| BindingCoreError::invalid_argument(format!("Invalid base64 {}: {}", label, e)))
}

fn conversion_error(operation: &str, err: impl std::fmt::Display) -> BindingCoreError {
    BindingCoreError::new(
        ErrorKind::SerializationFailed,
        format!("{} failed: {}", operation, err),
    )
}

impl SimpleAgentWrapper {
    // WARNING: If you add or remove a public method here, update BOTH:
    //   1. binding-core/tests/fixtures/method_parity.json  (canonical method list)
    //   2. binding-core/tests/method_parity.rs::known_methods()  (compile-time anchor)
    // All language bindings (Python, Node, Go) have parity tests against that fixture.

    // =========================================================================
    // Constructors
    // =========================================================================

    /// Create a new agent with persistent identity.
    ///
    /// Returns `(wrapper, info_json)` where `info_json` is a serialized
    /// [`jacs::simple::AgentInfo`].
    pub fn create(
        name: &str,
        purpose: Option<&str>,
        key_algorithm: Option<&str>,
    ) -> BindingResult<(Self, String)> {
        let (agent, info) = SimpleAgent::create(name, purpose, key_algorithm)
            .map_err(|e| BindingCoreError::agent_load(format!("Failed to create agent: {}", e)))?;
        let info_json = crate::serialize_agent_info(&info)?;

        Ok((Self::from_agent(agent), info_json))
    }

    /// Load an existing agent from a config file.
    pub fn load(config_path: Option<&str>, strict: Option<bool>) -> BindingResult<Self> {
        let (wrapper, _info_json) = Self::load_with_info(config_path, strict)?;
        Ok(wrapper)
    }

    /// Load an existing agent from a config file and return canonical metadata.
    pub fn load_with_info(
        config_path: Option<&str>,
        strict: Option<bool>,
    ) -> BindingResult<(Self, String)> {
        let requested_path = config_path.unwrap_or("./jacs.config.json");
        let resolved_config_path = crate::resolve_existing_config_path(requested_path)?;
        let agent = SimpleAgent::load(Some(&resolved_config_path), strict)
            .map_err(|e| BindingCoreError::agent_load(format!("Failed to load agent: {}", e)))?;
        let info = agent
            .loaded_info()
            .map_err(|e| BindingCoreError::agent_load(format!("Failed to load agent: {}", e)))?;
        let info_json = crate::serialize_agent_info(&info)?;

        Ok((Self::from_agent(agent), info_json))
    }

    /// Create an ephemeral (in-memory, throwaway) agent.
    ///
    /// Returns `(wrapper, info_json)`.
    pub fn ephemeral(algorithm: Option<&str>) -> BindingResult<(Self, String)> {
        let (agent, info) = SimpleAgent::ephemeral(algorithm).map_err(|e| {
            BindingCoreError::agent_load(format!("Failed to create ephemeral agent: {}", e))
        })?;
        let info_json = crate::serialize_agent_info(&info)?;

        Ok((Self::from_agent(agent), info_json))
    }

    /// Create an agent with full programmatic control via JSON parameters.
    ///
    /// `params_json` is a JSON string of [`CreateAgentParams`] fields.
    /// The `storage` field is skipped during deserialization (use builder for that).
    /// Returns `(wrapper, info_json)` where `info_json` is a serialized
    /// [`jacs::simple::AgentInfo`].
    pub fn create_with_params(params_json: &str) -> BindingResult<(Self, String)> {
        let params: jacs::simple::CreateAgentParams =
            serde_json::from_str(params_json).map_err(|e| {
                BindingCoreError::invalid_argument(format!("Invalid CreateAgentParams JSON: {}", e))
            })?;

        let (agent, info) = SimpleAgent::create_with_params(params).map_err(|e| {
            BindingCoreError::agent_load(format!("Failed to create agent with params: {}", e))
        })?;
        let info_json = crate::serialize_agent_info(&info)?;

        Ok((Self::from_agent(agent), info_json))
    }

    /// Wrap an existing `SimpleAgent` in a `SimpleAgentWrapper`.
    pub fn from_agent(agent: SimpleAgent) -> Self {
        Self {
            inner: Arc::new(agent),
        }
    }

    /// Get a reference to the inner `SimpleAgent`.
    ///
    /// This is intended for advanced operations (attestation, reencrypt, etc.)
    /// that need direct access to the underlying agent. Language bindings
    /// should prefer the wrapper methods for the narrow contract.
    pub fn inner_ref(&self) -> &SimpleAgent {
        &self.inner
    }

    // =========================================================================
    // Identity / Introspection
    // =========================================================================

    /// Get the agent's unique ID.
    pub fn get_agent_id(&self) -> BindingResult<String> {
        self.inner
            .get_agent_id()
            .map_err(|e| BindingCoreError::generic(format!("Failed to get agent ID: {}", e)))
    }

    /// Get the JACS key ID (signing key identifier).
    pub fn key_id(&self) -> BindingResult<String> {
        self.inner
            .key_id()
            .map_err(|e| BindingCoreError::generic(format!("Failed to get key ID: {}", e)))
    }

    /// Whether the agent is in strict mode.
    pub fn is_strict(&self) -> bool {
        self.inner.is_strict()
    }

    /// Config file path, if loaded from disk.
    pub fn config_path(&self) -> Option<String> {
        self.inner.config_path().map(|s| s.to_string())
    }

    /// Export the agent's identity JSON for P2P exchange.
    pub fn export_agent(&self) -> BindingResult<String> {
        self.inner
            .export_agent()
            .map_err(|e| BindingCoreError::generic(format!("Failed to export agent: {}", e)))
    }

    /// Get the public key as a PEM string.
    pub fn get_public_key_pem(&self) -> BindingResult<String> {
        self.inner.get_public_key_pem().map_err(|e| {
            BindingCoreError::key_not_found(format!("Failed to get public key PEM: {}", e))
        })
    }

    /// Get the public key as base64-encoded raw bytes (FFI-safe).
    pub fn get_public_key_base64(&self) -> BindingResult<String> {
        let bytes = self.inner.get_public_key().map_err(|e| {
            BindingCoreError::key_not_found(format!("Failed to get public key: {}", e))
        })?;
        Ok(encode_base64(&bytes))
    }

    /// Runtime diagnostic info as a JSON string.
    pub fn diagnostics(&self) -> String {
        self.inner.diagnostics().to_string()
    }

    // =========================================================================
    // Verification
    // =========================================================================

    /// Verify the agent's own document signature. Returns JSON `VerificationResult`.
    pub fn verify_self(&self) -> BindingResult<String> {
        let result = self.inner.verify_self().map_err(|e| {
            BindingCoreError::verification_failed(format!("Verify self failed: {}", e))
        })?;
        serialize_json(&result, "VerificationResult")
    }

    /// Verify a signed document JSON string. Returns JSON `VerificationResult`.
    pub fn verify_json(&self, signed_document: &str) -> BindingResult<String> {
        let result = self.inner.verify(signed_document).map_err(|e| {
            BindingCoreError::verification_failed(format!("Verification failed: {}", e))
        })?;
        serialize_json(&result, "VerificationResult")
    }

    /// Verify a signed document with an explicit public key (base64-encoded).
    /// Returns JSON `VerificationResult`.
    pub fn verify_with_key_json(
        &self,
        signed_document: &str,
        public_key_base64: &str,
    ) -> BindingResult<String> {
        let key_bytes = decode_base64(public_key_base64, "public key")?;

        let result = self
            .inner
            .verify_with_key(signed_document, key_bytes)
            .map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Verification with key failed: {}",
                    e
                ))
            })?;
        serialize_json(&result, "VerificationResult")
    }

    /// Verify a stored document by its ID (e.g., "uuid:version").
    /// Returns JSON `VerificationResult`.
    pub fn verify_by_id_json(&self, document_id: &str) -> BindingResult<String> {
        let result = self.inner.verify_by_id(document_id).map_err(|e| {
            BindingCoreError::verification_failed(format!("Verify by ID failed: {}", e))
        })?;
        serialize_json(&result, "VerificationResult")
    }

    // =========================================================================
    // Signing
    // =========================================================================

    /// Sign a JSON message string. Returns the signed JACS document JSON.
    pub fn sign_message_json(&self, data_json: &str) -> BindingResult<String> {
        let value: serde_json::Value = serde_json::from_str(data_json).map_err(|e| {
            BindingCoreError::invalid_argument(format!("Invalid JSON input: {}", e))
        })?;

        let signed = self
            .inner
            .sign_message(&value)
            .map_err(|e| BindingCoreError::signing_failed(format!("Sign message failed: {}", e)))?;

        Ok(signed.raw)
    }

    /// Sign raw bytes and return the signature as base64 (FFI-safe).
    pub fn sign_raw_bytes_base64(&self, data: &[u8]) -> BindingResult<String> {
        let sig_bytes = self.inner.sign_raw_bytes(data).map_err(|e| {
            BindingCoreError::signing_failed(format!("Sign raw bytes failed: {}", e))
        })?;
        Ok(encode_base64(&sig_bytes))
    }

    /// Sign a file with optional content embedding.
    /// Returns the signed JACS document JSON.
    pub fn sign_file_json(&self, file_path: &str, embed: bool) -> BindingResult<String> {
        let signed = self
            .inner
            .sign_file(file_path, embed)
            .map_err(|e| BindingCoreError::signing_failed(format!("Sign file failed: {}", e)))?;
        Ok(signed.raw)
    }

    // =========================================================================
    // Format Conversion (stateless -- no agent lock needed)
    // =========================================================================

    /// Convert a JSON string to YAML.
    pub fn to_yaml(&self, json_str: &str) -> BindingResult<String> {
        jacs::convert::jacs_to_yaml(json_str).map_err(|e| conversion_error("to_yaml", e))
    }

    /// Convert a YAML string to pretty-printed JSON.
    pub fn from_yaml(&self, yaml_str: &str) -> BindingResult<String> {
        jacs::convert::yaml_to_jacs(yaml_str).map_err(|e| conversion_error("from_yaml", e))
    }

    /// Convert a JSON string to a self-contained HTML document.
    pub fn to_html(&self, json_str: &str) -> BindingResult<String> {
        jacs::convert::jacs_to_html(json_str).map_err(|e| conversion_error("to_html", e))
    }

    /// Extract JSON from an HTML document produced by `to_html`.
    pub fn from_html(&self, html_str: &str) -> BindingResult<String> {
        jacs::convert::html_to_jacs(html_str).map_err(|e| conversion_error("from_html", e))
    }

    // =========================================================================
    // Key rotation
    // =========================================================================

    /// Rotate the agent's cryptographic keys.
    ///
    /// Optionally change the signing algorithm. Returns a JSON string of the
    /// `RotationResult` (jacs_id, old_version, new_version, key hash, proof).
    pub fn rotate_keys(&self, algorithm: Option<&str>) -> BindingResult<String> {
        let result = jacs::simple::advanced::rotate(&self.inner, algorithm).map_err(|e| {
            BindingCoreError::new(ErrorKind::Generic, format!("Key rotation failed: {}", e))
        })?;
        serialize_json(&result, "rotation result")
    }

    // =========================================================================
    // Inline text + media signature methods (Task 05 + Task 06, PRD §4.1, §4.2)
    // =========================================================================

    /// Sign a text / markdown file in-place. PRD §4.1.
    ///
    /// `opts_json` accepts:
    /// - `""` | `"null"` | `"{}"` — defaults (`backup: true`, `allow_duplicate: false`).
    /// - `{"backup": false}` — disable .bak.
    /// - `{"allow_duplicate": true}` — allow duplicate-signer no-op to still write.
    ///
    /// Returns a JSON string of [`jacs::simple::types::SignTextOutcome`].
    pub fn sign_text_file_json(&self, path: &str, opts_json: &str) -> BindingResult<String> {
        let opts = parse_sign_text_options(opts_json)?;
        let outcome = jacs::simple::advanced::sign_text_file(&self.inner, path, opts)
            .map_err(|e| map_jacs_err(e, "sign_text_file"))?;
        serialize_json(&outcome, "sign_text_file outcome")
    }

    /// Verify a signed text file. PRD §4.1, §4.1.5.
    ///
    /// `opts_json` accepts:
    /// - `""` | `"null"` | `"{}"` — strict=false, key_dir=None (permissive).
    /// - `{"strict": true}` — strict mode (missing-signature returns Err).
    /// - `{"keyDir": "/abs/path"}` — `--key-dir` override.
    /// - `{"strict": true, "keyDir": "..."}` — both.
    ///
    /// Permissive returns JSON with a `status` discriminator. Strict mode on
    /// an unsigned file returns `Err(BindingCoreError::missing_signature(path))`.
    pub fn verify_text_file_json(&self, path: &str, opts_json: &str) -> BindingResult<String> {
        let opts = parse_verify_options(opts_json)?;
        let strict = opts.strict;
        match jacs::simple::advanced::verify_text_file(&self.inner, path, opts) {
            Ok(result) => serialize_verify_text_result(&result),
            Err(jacs::error::JacsError::MissingSignature(p)) if strict => {
                Err(BindingCoreError::missing_signature(format!(
                    "no JACS signature found in {}",
                    p
                )))
            }
            Err(e) => Err(BindingCoreError::verification_failed(format!(
                "verify_text_file: {}",
                e
            ))),
        }
    }

    /// Sign an image (PNG/JPEG/WebP). PRD §4.2.
    ///
    /// `opts_json` accepts (all keys optional):
    /// - `{"robust": bool}` — enable LSB embedding (PNG/JPEG only).
    /// - `{"refuseOverwrite": bool}` — refuse if input already signed.
    /// - `{"backup": bool}` — auto-backup before in-place writes (default true).
    /// - `{"unsafeBakMode": 0o644}` — override the default 0o600 backup mode.
    pub fn sign_image_json(
        &self,
        in_path: &str,
        out_path: &str,
        opts_json: &str,
    ) -> BindingResult<String> {
        let opts = parse_sign_image_options(opts_json)?;
        let outcome = jacs::simple::advanced::sign_image(&self.inner, in_path, out_path, opts)
            .map_err(|e| map_jacs_err(e, "sign_image"))?;
        serialize_json(&outcome, "sign_image outcome")
    }

    /// Verify an image signature. PRD §4.2.
    ///
    /// `opts_json` accepts:
    /// - `{"strict": bool}` — strict-mode missing-signature is an error.
    /// - `{"keyDir": "/abs/path"}` — `--key-dir` override.
    /// - `{"robust": bool}` — scan LSB channel as a fallback (default false).
    pub fn verify_image_json(&self, path: &str, opts_json: &str) -> BindingResult<String> {
        let opts = parse_verify_image_options(opts_json)?;
        let strict = opts.base.strict;
        match jacs::simple::advanced::verify_image(&self.inner, path, opts) {
            Ok(result) => serialize_json(&result, "verify_image result"),
            Err(jacs::error::JacsError::MissingSignature(p)) if strict => {
                Err(BindingCoreError::missing_signature(format!(
                    "no JACS signature found in {}",
                    p
                )))
            }
            Err(e) => Err(BindingCoreError::verification_failed(format!(
                "verify_image: {}",
                e
            ))),
        }
    }

    /// Extract the JACS signature payload from an image. PRD §3.2.
    ///
    /// `opts_json` accepts `{"rawPayload": bool}` (default false = decoded JSON).
    /// Returns a JSON envelope `{ "present": bool, "payload": string | null }`.
    pub fn extract_media_signature_json(
        &self,
        path: &str,
        opts_json: &str,
    ) -> BindingResult<String> {
        let raw = parse_extract_options(opts_json)?;
        let result = if raw {
            jacs::simple::advanced::extract_media_signature_raw(path)
        } else {
            jacs::simple::advanced::extract_media_signature(path)
        };
        let payload = result.map_err(|e| map_jacs_err(e, "extract_media_signature"))?;
        let envelope = serde_json::json!({
            "present": payload.is_some(),
            "payload": payload,
        });
        Ok(envelope.to_string())
    }
}

// =============================================================================
// Option parsing helpers
// =============================================================================

fn map_jacs_err(e: jacs::error::JacsError, op: &str) -> BindingCoreError {
    use jacs::error::JacsError;
    match e {
        JacsError::MissingSignature(p) => BindingCoreError::missing_signature(p),
        JacsError::ValidationError(msg) => BindingCoreError::invalid_argument(msg),
        JacsError::FileNotFound { path } => {
            BindingCoreError::invalid_argument(format!("file not found: {}", path))
        }
        JacsError::FileReadFailed { path, reason } => {
            BindingCoreError::invalid_argument(format!("read {} failed: {}", path, reason))
        }
        JacsError::FileWriteFailed { path, reason } => BindingCoreError::new(
            ErrorKind::Generic,
            format!("write {} failed: {}", path, reason),
        ),
        other => BindingCoreError::new(ErrorKind::Generic, format!("{}: {}", op, other)),
    }
}

fn opts_is_default(s: &str) -> bool {
    let t = s.trim();
    t.is_empty() || t == "null" || t == "{}"
}

fn parse_sign_text_options(opts_json: &str) -> BindingResult<jacs::simple::types::SignTextOptions> {
    if opts_is_default(opts_json) {
        return Ok(jacs::simple::types::SignTextOptions::default());
    }
    let v: serde_json::Value = serde_json::from_str(opts_json).map_err(|e| {
        BindingCoreError::invalid_argument(format!("sign_text_file opts: {}", e))
    })?;
    let mut o = jacs::simple::types::SignTextOptions::default();
    if let Some(b) = v.get("backup").and_then(|x| x.as_bool()) {
        o.backup = b;
    }
    if let Some(b) = v.get("allow_duplicate").and_then(|x| x.as_bool()) {
        o.allow_duplicate = b;
    }
    if let Some(b) = v.get("allowDuplicate").and_then(|x| x.as_bool()) {
        o.allow_duplicate = b;
    }
    Ok(o)
}

fn parse_verify_options(opts_json: &str) -> BindingResult<jacs::inline::VerifyOptions> {
    if opts_is_default(opts_json) {
        return Ok(jacs::inline::VerifyOptions::default());
    }
    let v: serde_json::Value = serde_json::from_str(opts_json)
        .map_err(|e| BindingCoreError::invalid_argument(format!("verify opts: {}", e)))?;
    let strict = v.get("strict").and_then(|x| x.as_bool()).unwrap_or(false);
    let key_dir = v
        .get("keyDir")
        .or_else(|| v.get("key_dir"))
        .and_then(|x| x.as_str())
        .map(std::path::PathBuf::from);
    Ok(jacs::inline::VerifyOptions { strict, key_dir })
}

fn parse_sign_image_options(opts_json: &str) -> BindingResult<jacs::simple::types::SignImageOptions> {
    if opts_is_default(opts_json) {
        return Ok(jacs::simple::types::SignImageOptions::default());
    }
    let v: serde_json::Value = serde_json::from_str(opts_json)
        .map_err(|e| BindingCoreError::invalid_argument(format!("sign_image opts: {}", e)))?;
    let mut o = jacs::simple::types::SignImageOptions::default();
    if let Some(b) = v.get("robust").and_then(|x| x.as_bool()) {
        o.robust = b;
    }
    if let Some(b) = v
        .get("refuseOverwrite")
        .or_else(|| v.get("refuse_overwrite"))
        .and_then(|x| x.as_bool())
    {
        o.refuse_overwrite = b;
    }
    if let Some(b) = v.get("backup").and_then(|x| x.as_bool()) {
        o.backup = b;
    }
    if let Some(n) = v
        .get("unsafeBakMode")
        .or_else(|| v.get("unsafe_bak_mode"))
        .and_then(|x| x.as_u64())
    {
        o.unsafe_bak_mode = Some(n as u32);
    }
    if let Some(s) = v
        .get("formatHint")
        .or_else(|| v.get("format_hint"))
        .and_then(|x| x.as_str())
    {
        o.format_hint = Some(s.to_string());
    }
    Ok(o)
}

fn parse_verify_image_options(
    opts_json: &str,
) -> BindingResult<jacs::simple::types::VerifyImageOptions> {
    if opts_is_default(opts_json) {
        return Ok(jacs::simple::types::VerifyImageOptions::default());
    }
    let v: serde_json::Value = serde_json::from_str(opts_json)
        .map_err(|e| BindingCoreError::invalid_argument(format!("verify_image opts: {}", e)))?;
    let strict = v.get("strict").and_then(|x| x.as_bool()).unwrap_or(false);
    let key_dir = v
        .get("keyDir")
        .or_else(|| v.get("key_dir"))
        .and_then(|x| x.as_str())
        .map(std::path::PathBuf::from);
    let scan_robust = v
        .get("robust")
        .or_else(|| v.get("scan_robust"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    Ok(jacs::simple::types::VerifyImageOptions {
        base: jacs::inline::VerifyOptions { strict, key_dir },
        scan_robust,
    })
}

fn parse_extract_options(opts_json: &str) -> BindingResult<bool> {
    if opts_is_default(opts_json) {
        return Ok(false);
    }
    let v: serde_json::Value = serde_json::from_str(opts_json).map_err(|e| {
        BindingCoreError::invalid_argument(format!("extract_media_signature opts: {}", e))
    })?;
    Ok(v.get("rawPayload")
        .or_else(|| v.get("raw_payload"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false))
}

fn serialize_verify_text_result(
    result: &jacs::inline::VerifyTextResult,
) -> BindingResult<String> {
    use jacs::inline::{SignatureStatus, VerifyTextResult};
    let v = match result {
        VerifyTextResult::MissingSignature => {
            serde_json::json!({"status": "missing_signature"})
        }
        VerifyTextResult::Malformed(detail) => {
            serde_json::json!({"status": "malformed", "error": detail})
        }
        VerifyTextResult::Signed { signatures } => {
            let entries: Vec<serde_json::Value> = signatures
                .iter()
                .map(|e| {
                    let (status_str, error) = match &e.status {
                        SignatureStatus::Valid => ("valid", None),
                        SignatureStatus::InvalidSignature => ("invalid_signature", None),
                        SignatureStatus::HashMismatch => ("hash_mismatch", None),
                        SignatureStatus::KeyNotFound => ("key_not_found", None),
                        SignatureStatus::UnsupportedAlgorithm => {
                            ("unsupported_algorithm", None)
                        }
                        SignatureStatus::Malformed(s) => ("malformed", Some(s.clone())),
                    };
                    let mut o = serde_json::json!({
                        "signer_id": e.signer_id,
                        "algorithm": e.algorithm,
                        "timestamp": e.timestamp,
                        "status": status_str,
                    });
                    if let Some(err) = error {
                        o["error"] = serde_json::Value::String(err);
                    }
                    o
                })
                .collect();
            serde_json::json!({"status": "signed", "signatures": entries})
        }
    };
    Ok(v.to_string())
}

// =============================================================================
// Free functions for Go FFI (C-style calling convention friendly)
// =============================================================================

/// Sign a JSON message — free function for Go FFI.
pub fn sign_message_json(wrapper: &SimpleAgentWrapper, data_json: &str) -> BindingResult<String> {
    wrapper.sign_message_json(data_json)
}

/// Verify a signed document — free function for Go FFI.
pub fn verify_json(wrapper: &SimpleAgentWrapper, signed_document: &str) -> BindingResult<String> {
    wrapper.verify_json(signed_document)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a wrapper for conversion tests. Conversion methods are stateless
    /// so we only need a default wrapper (no agent loaded).
    fn test_wrapper() -> SimpleAgentWrapper {
        let (wrapper, _info) =
            SimpleAgentWrapper::ephemeral(Some("ed25519")).expect("ephemeral agent");
        wrapper
    }

    #[test]
    fn to_yaml_valid_json_succeeds() {
        let wrapper = test_wrapper();
        let result = wrapper.to_yaml(r#"{"key": "value"}"#);
        assert!(result.is_ok(), "to_yaml should succeed for valid JSON");
        let yaml = result.unwrap();
        assert!(yaml.contains("key"), "YAML should contain 'key'");
        assert!(yaml.contains("value"), "YAML should contain 'value'");
    }

    #[test]
    fn from_yaml_valid_yaml_succeeds() {
        let wrapper = test_wrapper();
        let result = wrapper.from_yaml("key: value\n");
        assert!(result.is_ok(), "from_yaml should succeed for valid YAML");
        let json = result.unwrap();
        assert!(json.contains("\"key\""), "JSON should contain key");
        assert!(json.contains("\"value\""), "JSON should contain value");
    }

    #[test]
    fn to_html_valid_json_succeeds() {
        let wrapper = test_wrapper();
        let result = wrapper.to_html(r#"{"key": "value"}"#);
        assert!(result.is_ok(), "to_html should succeed for valid JSON");
        let html = result.unwrap();
        assert!(html.contains("<!DOCTYPE html>"), "HTML should have DOCTYPE");
        assert!(
            html.contains(r#"id="jacs-data">"#),
            "HTML should have jacs-data script tag"
        );
    }

    #[test]
    fn from_html_valid_html_succeeds() {
        let wrapper = test_wrapper();
        let json = r#"{"key": "value"}"#;
        let html = wrapper.to_html(json).unwrap();
        let result = wrapper.from_html(&html);
        assert!(result.is_ok(), "from_html should succeed for valid HTML");
        assert_eq!(result.unwrap(), json, "Extracted JSON should match input");
    }

    #[test]
    fn yaml_round_trip_preserves_content() {
        let wrapper = test_wrapper();
        let json = r#"{"hello": "world", "count": 42}"#;
        let yaml = wrapper.to_yaml(json).unwrap();
        let back = wrapper.from_yaml(&yaml).unwrap();
        let original: serde_json::Value = serde_json::from_str(json).unwrap();
        let reconstituted: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert_eq!(
            original, reconstituted,
            "YAML round-trip should preserve content"
        );
    }

    #[test]
    fn html_round_trip_preserves_content() {
        let wrapper = test_wrapper();
        let json = r#"{"hello": "world", "count": 42}"#;
        let html = wrapper.to_html(json).unwrap();
        let back = wrapper.from_html(&html).unwrap();
        assert_eq!(back, json, "HTML round-trip should preserve exact JSON");
    }

    #[test]
    fn to_yaml_invalid_json_returns_serialization_failed() {
        let wrapper = test_wrapper();
        let result = wrapper.to_yaml("{not valid json}");
        assert!(result.is_err(), "to_yaml should fail for invalid JSON");
        let err = result.unwrap_err();
        assert_eq!(
            err.kind,
            crate::ErrorKind::SerializationFailed,
            "Error should be SerializationFailed, got: {:?}",
            err.kind
        );
    }

    #[test]
    fn from_yaml_invalid_yaml_returns_serialization_failed() {
        let wrapper = test_wrapper();
        let result = wrapper.from_yaml("{{{{ not yaml ::::");
        assert!(result.is_err(), "from_yaml should fail for invalid YAML");
        let err = result.unwrap_err();
        assert_eq!(
            err.kind,
            crate::ErrorKind::SerializationFailed,
            "Error should be SerializationFailed, got: {:?}",
            err.kind
        );
    }

    #[test]
    fn from_html_no_script_tag_returns_serialization_failed() {
        let wrapper = test_wrapper();
        let result = wrapper.from_html("<html><body>No jacs data here</body></html>");
        assert!(
            result.is_err(),
            "from_html should fail without jacs-data tag"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind,
            crate::ErrorKind::SerializationFailed,
            "Error should be SerializationFailed, got: {:?}",
            err.kind
        );
    }
}
