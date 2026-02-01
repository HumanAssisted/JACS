//! Unified error types for the JACS simplified API.
//!
//! This module provides a comprehensive error taxonomy that maps to
//! user-friendly error messages with actionable guidance.

use std::error::Error;
use std::fmt;

/// Unified error type for all JACS simplified API operations.
///
/// Each variant includes contextual information to help users
/// understand what went wrong and how to fix it.
#[derive(Debug)]
pub enum JacsError {
    // === Configuration Errors ===
    /// Configuration file not found at the specified path.
    ConfigNotFound {
        path: String,
    },

    /// Configuration file exists but contains invalid data.
    ConfigInvalid {
        field: String,
        reason: String,
    },

    // === Key Errors ===
    /// Private or public key file not found.
    KeyNotFound {
        path: String,
    },

    /// Failed to decrypt the private key (wrong password or corrupted).
    KeyDecryptionFailed {
        reason: String,
    },

    /// Failed to generate a new keypair.
    KeyGenerationFailed {
        algorithm: String,
        reason: String,
    },

    // === Signing Errors ===
    /// Signing operation failed.
    SigningFailed {
        reason: String,
    },

    // === Verification Errors ===
    /// Signature does not match the expected value.
    SignatureInvalid {
        expected: String,
        got: String,
    },

    /// Document hash does not match the expected value.
    HashMismatch {
        expected: String,
        got: String,
    },

    /// Document structure is invalid or missing required fields.
    DocumentMalformed {
        field: String,
        reason: String,
    },

    /// The agent that signed the document is not in the trust store.
    SignerUnknown {
        agent_id: String,
    },

    // === DNS Errors ===
    /// DNS lookup failed for the specified domain.
    DnsLookupFailed {
        domain: String,
        reason: String,
    },

    /// Expected DNS TXT record not found.
    DnsRecordMissing {
        domain: String,
    },

    /// DNS TXT record found but contains invalid data.
    DnsRecordInvalid {
        domain: String,
        reason: String,
    },

    // === File Errors ===
    /// File not found at the specified path.
    FileNotFound {
        path: String,
    },

    /// Failed to read file contents.
    FileReadFailed {
        path: String,
        reason: String,
    },

    /// Could not determine MIME type for the file.
    MimeTypeUnknown {
        path: String,
    },

    // === Trust Store Errors ===
    /// Agent is not in the local trust store.
    AgentNotTrusted {
        agent_id: String,
    },

    // === Registration Errors ===
    /// Registration with a registry (e.g., HAI.ai) failed.
    RegistrationFailed {
        reason: String,
    },

    // === Agent State Errors ===
    /// No agent is currently loaded. Call create() or load() first.
    AgentNotLoaded,

    // === Wrapped Errors ===
    /// Wrapper for underlying errors from the existing API.
    Internal {
        message: String,
    },
}

impl fmt::Display for JacsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Configuration
            JacsError::ConfigNotFound { path } => {
                write!(
                    f,
                    "Configuration not found at '{}'. Run jacs.create(name=\"...\") to create a new agent.",
                    path
                )
            }
            JacsError::ConfigInvalid { field, reason } => {
                write!(f, "Invalid configuration field '{}': {}", field, reason)
            }

            // Keys
            JacsError::KeyNotFound { path } => {
                write!(
                    f,
                    "Key file not found at '{}'. Ensure keys were generated during agent creation.",
                    path
                )
            }
            JacsError::KeyDecryptionFailed { reason } => {
                write!(f, "Failed to decrypt private key: {}", reason)
            }
            JacsError::KeyGenerationFailed { algorithm, reason } => {
                write!(
                    f,
                    "Failed to generate {} keypair: {}",
                    algorithm, reason
                )
            }

            // Signing
            JacsError::SigningFailed { reason } => {
                write!(f, "Signing failed: {}", reason)
            }

            // Verification
            JacsError::SignatureInvalid { expected, got } => {
                write!(
                    f,
                    "Invalid signature: expected '{}...', got '{}...'",
                    &expected[..expected.len().min(16)],
                    &got[..got.len().min(16)]
                )
            }
            JacsError::HashMismatch { expected, got } => {
                write!(
                    f,
                    "Hash mismatch: document may have been tampered with. Expected '{}...', got '{}...'",
                    &expected[..expected.len().min(16)],
                    &got[..got.len().min(16)]
                )
            }
            JacsError::DocumentMalformed { field, reason } => {
                write!(f, "Malformed document: field '{}' - {}", field, reason)
            }
            JacsError::SignerUnknown { agent_id } => {
                write!(
                    f,
                    "Unknown signer '{}'. Use jacs.trust_agent() to add them to your trust store.",
                    agent_id
                )
            }

            // DNS
            JacsError::DnsLookupFailed { domain, reason } => {
                write!(f, "DNS lookup failed for '{}': {}", domain, reason)
            }
            JacsError::DnsRecordMissing { domain } => {
                write!(
                    f,
                    "DNS TXT record not found for '{}'. Add the record shown by `jacs dns-record`.",
                    domain
                )
            }
            JacsError::DnsRecordInvalid { domain, reason } => {
                write!(f, "Invalid DNS record for '{}': {}", domain, reason)
            }

            // Files
            JacsError::FileNotFound { path } => {
                write!(f, "File not found: '{}'", path)
            }
            JacsError::FileReadFailed { path, reason } => {
                write!(f, "Failed to read '{}': {}", path, reason)
            }
            JacsError::MimeTypeUnknown { path } => {
                write!(
                    f,
                    "Could not determine MIME type for '{}'. The file will be treated as application/octet-stream.",
                    path
                )
            }

            // Trust
            JacsError::AgentNotTrusted { agent_id } => {
                write!(
                    f,
                    "Agent '{}' is not trusted. Use jacs.trust_agent() to add them.",
                    agent_id
                )
            }

            // Registration
            JacsError::RegistrationFailed { reason } => {
                write!(f, "Registration failed: {}", reason)
            }

            // Agent state
            JacsError::AgentNotLoaded => {
                write!(
                    f,
                    "No agent loaded. Call jacs.create(name=\"...\") or jacs.load() first."
                )
            }

            // Internal
            JacsError::Internal { message } => {
                write!(f, "{}", message)
            }
        }
    }
}

impl Error for JacsError {}

impl From<Box<dyn Error>> for JacsError {
    fn from(err: Box<dyn Error>) -> Self {
        JacsError::Internal {
            message: err.to_string(),
        }
    }
}

impl From<std::io::Error> for JacsError {
    fn from(err: std::io::Error) -> Self {
        JacsError::Internal {
            message: err.to_string(),
        }
    }
}

impl From<serde_json::Error> for JacsError {
    fn from(err: serde_json::Error) -> Self {
        JacsError::DocumentMalformed {
            field: "json".to_string(),
            reason: err.to_string(),
        }
    }
}

impl From<String> for JacsError {
    fn from(err: String) -> Self {
        JacsError::Internal { message: err }
    }
}

impl From<&str> for JacsError {
    fn from(err: &str) -> Self {
        JacsError::Internal {
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_config_not_found() {
        let err = JacsError::ConfigNotFound {
            path: "./jacs.config.json".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("jacs.config.json"));
        assert!(msg.contains("create"));
    }

    #[test]
    fn test_error_display_agent_not_loaded() {
        let err = JacsError::AgentNotLoaded;
        let msg = err.to_string();
        assert!(msg.contains("create"));
        assert!(msg.contains("load"));
    }

    #[test]
    fn test_error_from_string() {
        let err: JacsError = "test error".into();
        assert!(matches!(err, JacsError::Internal { .. }));
    }
}
