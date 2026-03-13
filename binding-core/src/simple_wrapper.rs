//! `SimpleAgentWrapper` — thin FFI adapter over the narrow `SimpleAgent` contract.
//!
//! This module contains zero business logic. Every method delegates to
//! `jacs::simple::SimpleAgent` and marshals the result to FFI-safe types
//! (String in/out, base64 for bytes, JSON for structured data).

use crate::{BindingCoreError, BindingResult};
use jacs::simple::SimpleAgent;
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

impl SimpleAgentWrapper {
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

        let info_json = serde_json::to_string(&info).map_err(|e| {
            BindingCoreError::serialization_failed(format!("Failed to serialize AgentInfo: {}", e))
        })?;

        Ok((
            Self {
                inner: Arc::new(agent),
            },
            info_json,
        ))
    }

    /// Load an existing agent from a config file.
    pub fn load(config_path: Option<&str>, strict: Option<bool>) -> BindingResult<Self> {
        let agent = SimpleAgent::load(config_path, strict)
            .map_err(|e| BindingCoreError::agent_load(format!("Failed to load agent: {}", e)))?;
        Ok(Self {
            inner: Arc::new(agent),
        })
    }

    /// Create an ephemeral (in-memory, throwaway) agent.
    ///
    /// Returns `(wrapper, info_json)`.
    pub fn ephemeral(algorithm: Option<&str>) -> BindingResult<(Self, String)> {
        let (agent, info) = SimpleAgent::ephemeral(algorithm).map_err(|e| {
            BindingCoreError::agent_load(format!("Failed to create ephemeral agent: {}", e))
        })?;

        let info_json = serde_json::to_string(&info).map_err(|e| {
            BindingCoreError::serialization_failed(format!("Failed to serialize AgentInfo: {}", e))
        })?;

        Ok((
            Self {
                inner: Arc::new(agent),
            },
            info_json,
        ))
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

        let info_json = serde_json::to_string(&info).map_err(|e| {
            BindingCoreError::serialization_failed(format!("Failed to serialize AgentInfo: {}", e))
        })?;

        Ok((
            Self {
                inner: Arc::new(agent),
            },
            info_json,
        ))
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
        use base64::Engine;
        let bytes = self.inner.get_public_key().map_err(|e| {
            BindingCoreError::key_not_found(format!("Failed to get public key: {}", e))
        })?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
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
        serde_json::to_string(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize VerificationResult: {}",
                e
            ))
        })
    }

    /// Verify a signed document JSON string. Returns JSON `VerificationResult`.
    pub fn verify_json(&self, signed_document: &str) -> BindingResult<String> {
        let result = self.inner.verify(signed_document).map_err(|e| {
            BindingCoreError::verification_failed(format!("Verification failed: {}", e))
        })?;
        serde_json::to_string(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize VerificationResult: {}",
                e
            ))
        })
    }

    /// Verify a signed document with an explicit public key (base64-encoded).
    /// Returns JSON `VerificationResult`.
    pub fn verify_with_key_json(
        &self,
        signed_document: &str,
        public_key_base64: &str,
    ) -> BindingResult<String> {
        use base64::Engine;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(public_key_base64)
            .map_err(|e| {
                BindingCoreError::invalid_argument(format!("Invalid base64 public key: {}", e))
            })?;

        let result = self
            .inner
            .verify_with_key(signed_document, key_bytes)
            .map_err(|e| {
                BindingCoreError::verification_failed(format!(
                    "Verification with key failed: {}",
                    e
                ))
            })?;
        serde_json::to_string(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize VerificationResult: {}",
                e
            ))
        })
    }

    /// Verify a stored document by its ID (e.g., "uuid:version").
    /// Returns JSON `VerificationResult`.
    pub fn verify_by_id_json(&self, document_id: &str) -> BindingResult<String> {
        let result = self.inner.verify_by_id(document_id).map_err(|e| {
            BindingCoreError::verification_failed(format!("Verify by ID failed: {}", e))
        })?;
        serde_json::to_string(&result).map_err(|e| {
            BindingCoreError::serialization_failed(format!(
                "Failed to serialize VerificationResult: {}",
                e
            ))
        })
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
        use base64::Engine;
        let sig_bytes = self.inner.sign_raw_bytes(data).map_err(|e| {
            BindingCoreError::signing_failed(format!("Sign raw bytes failed: {}", e))
        })?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&sig_bytes))
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
