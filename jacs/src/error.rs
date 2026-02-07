//! Unified error types for the JACS crate.
//!
//! This module provides a comprehensive error taxonomy that maps to
//! user-friendly error messages with actionable guidance.
//!
//! # Error Categories
//!
//! The error types are organized into two groups:
//!
//! 1. **High-level category errors** - Broad categories for general error handling:
//!    - `ConfigError` - Configuration loading/parsing errors
//!    - `CryptoError` - Cryptographic operation errors
//!    - `SchemaError` - Schema validation errors
//!    - `AgentError` - Agent lifecycle errors
//!    - `DocumentError` - Document operations errors
//!    - `NetworkError` - Network/HTTP errors
//!    - `TrustError` - Trust store errors
//!    - `IoError` - IO wrapper
//!    - `ValidationError` - Input validation errors
//!
//! 2. **Specific error variants** - Detailed errors for precise error handling
//!
//! # Example
//!
//! ```rust,ignore
//! use jacs::error::JacsError;
//!
//! fn load_config(path: &str) -> Result<Config, JacsError> {
//!     let content = std::fs::read_to_string(path)
//!         .map_err(|e| JacsError::ConfigError(format!("Failed to read config at '{}': {}", path, e)))?;
//!     // ...
//! }
//! ```

use std::error::Error;
use std::fmt;

/// Unified error type for all JACS operations.
///
/// Each variant includes contextual information to help users
/// understand what went wrong and how to fix it.
#[derive(Debug)]
pub enum JacsError {
    // ==========================================================================
    // HIGH-LEVEL CATEGORY ERRORS
    // These are broad categories useful for converting from format!() errors
    // and providing consistent error handling across the crate.
    // ==========================================================================
    /// Configuration loading or parsing error.
    ///
    /// Use this for errors related to:
    /// - Missing or invalid configuration files
    /// - Invalid configuration values
    /// - Environment variable issues
    ConfigError(String),

    /// Cryptographic operation error.
    ///
    /// Use this for errors related to:
    /// - Key generation failures
    /// - Encryption/decryption failures
    /// - Signature creation/verification failures
    /// - Hash computation failures
    CryptoError(String),

    /// Schema validation error.
    ///
    /// Use this for errors related to:
    /// - JSON schema validation failures
    /// - Schema loading/parsing errors
    /// - Schema compilation errors
    SchemaError(String),

    /// Agent lifecycle error.
    ///
    /// Use this for errors related to:
    /// - Agent creation failures
    /// - Agent loading failures
    /// - Agent state transitions
    AgentError(String),

    /// Document operation error.
    ///
    /// Use this for errors related to:
    /// - Document creation failures
    /// - Document loading failures
    /// - Document signing/verification failures
    DocumentError(String),

    /// Network or HTTP error.
    ///
    /// Use this for errors related to:
    /// - HTTP request failures
    /// - Connection errors
    /// - DNS resolution failures
    /// - TLS/SSL errors
    NetworkError(String),

    /// Trust store error.
    ///
    /// Use this for errors related to:
    /// - Trust store operations
    /// - Trusted agent management
    /// - Public key cache operations
    TrustError(String),

    /// IO error wrapper.
    ///
    /// Wraps `std::io::Error` for file and IO operations.
    IoError(std::io::Error),

    /// Input validation error.
    ///
    /// Use this for errors related to:
    /// - Invalid function arguments
    /// - Malformed input data
    /// - Constraint violations
    ValidationError(String),

    // ==========================================================================
    // SPECIFIC ERROR VARIANTS
    // These provide detailed error information for precise error handling.
    // ==========================================================================

    // === Configuration Errors ===
    /// Configuration file not found at the specified path.
    ConfigNotFound { path: String },

    /// Configuration file exists but contains invalid data.
    ConfigInvalid { field: String, reason: String },

    // === Key Errors ===
    /// Private or public key file not found.
    KeyNotFound { path: String },

    /// Failed to decrypt the private key (wrong password or corrupted).
    KeyDecryptionFailed { reason: String },

    /// Failed to generate a new keypair.
    KeyGenerationFailed { algorithm: String, reason: String },

    // === Signing Errors ===
    /// Signing operation failed.
    SigningFailed { reason: String },

    // === Verification Errors ===
    /// Signature does not match the expected value.
    SignatureInvalid { expected: String, got: String },

    /// Signature verification failed (cryptographic check failed).
    SignatureVerificationFailed { reason: String },

    /// Document hash does not match the expected value.
    HashMismatch { expected: String, got: String },

    /// Document structure is invalid or missing required fields.
    DocumentMalformed { field: String, reason: String },

    /// The agent that signed the document is not in the trust store.
    SignerUnknown { agent_id: String },

    // === DNS Errors ===
    /// DNS lookup failed for the specified domain.
    DnsLookupFailed { domain: String, reason: String },

    /// Expected DNS TXT record not found.
    DnsRecordMissing { domain: String },

    /// DNS TXT record found but contains invalid data.
    DnsRecordInvalid { domain: String, reason: String },

    // === Size Limit Errors ===
    /// Document exceeds the maximum allowed size.
    ///
    /// The default maximum size is 10MB, configurable via `JACS_MAX_DOCUMENT_SIZE`.
    DocumentTooLarge { size: usize, max_size: usize },

    // === File Errors ===
    /// File not found at the specified path.
    FileNotFound { path: String },

    /// Failed to read file contents.
    FileReadFailed { path: String, reason: String },

    /// Failed to write file contents.
    FileWriteFailed { path: String, reason: String },

    /// Failed to create a directory.
    DirectoryCreateFailed { path: String, reason: String },

    /// Could not determine MIME type for the file.
    MimeTypeUnknown { path: String },

    // === Trust Store Errors ===
    /// Agent is not in the local trust store.
    AgentNotTrusted { agent_id: String },

    // === Registration Errors ===
    /// Registration with a registry (e.g., HAI.ai) failed.
    RegistrationFailed { reason: String },

    // === Storage Errors ===
    /// Generic storage backend error.
    StorageError(String),

    // === Database Errors ===
    /// Database operation failed.
    DatabaseError { operation: String, reason: String },

    // === Verification Claim Errors ===
    /// Agent's verification claim could not be satisfied.
    ///
    /// This occurs when an agent claims a verification level (e.g., "verified" or
    /// "verified-hai.ai") but the required security conditions are not met.
    VerificationClaimFailed { claim: String, reason: String },

    // === Agent State Errors ===
    /// No agent is currently loaded. Call create() or load() first.
    AgentNotLoaded,

    // === Wrapped Errors ===
    /// Wrapper for underlying errors from the existing API.
    ///
    /// Note: Prefer using specific category errors (ConfigError, CryptoError, etc.)
    /// over Internal when the error category is known.
    Internal { message: String },
}

impl fmt::Display for JacsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // High-level category errors
            JacsError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            JacsError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            JacsError::SchemaError(msg) => write!(f, "Schema error: {}", msg),
            JacsError::AgentError(msg) => write!(f, "Agent error: {}", msg),
            JacsError::DocumentError(msg) => write!(f, "Document error: {}", msg),
            JacsError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            JacsError::TrustError(msg) => write!(f, "Trust store error: {}", msg),
            JacsError::IoError(err) => write!(f, "IO error: {}", err),
            JacsError::ValidationError(msg) => write!(f, "Validation error: {}", msg),

            // Specific configuration errors
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
                write!(f, "Failed to generate {} keypair: {}", algorithm, reason)
            }

            // Signing
            JacsError::SigningFailed { reason } => {
                write!(f, "Document signing failed: {}", reason)
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
            JacsError::SignatureVerificationFailed { reason } => {
                write!(f, "Signature verification failed: {}", reason)
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

            // Size limits
            JacsError::DocumentTooLarge { size, max_size } => {
                write!(
                    f,
                    "Document too large: {} bytes exceeds maximum allowed size of {} bytes. \
                    To increase the limit, set JACS_MAX_DOCUMENT_SIZE environment variable.",
                    size, max_size
                )
            }

            // Files
            JacsError::FileNotFound { path } => {
                write!(
                    f,
                    "File not found: '{}'. Ensure the file path is correct or create the file first.",
                    path
                )
            }
            JacsError::FileReadFailed { path, reason } => {
                write!(
                    f,
                    "Failed to read file '{}': {}. Check that the file exists and has read permissions.",
                    path, reason
                )
            }
            JacsError::FileWriteFailed { path, reason } => {
                write!(
                    f,
                    "Failed to write file '{}': {}. Check that the directory exists and has write permissions.",
                    path, reason
                )
            }
            JacsError::DirectoryCreateFailed { path, reason } => {
                write!(
                    f,
                    "Failed to create directory '{}': {}. Check that the parent directory exists and has write permissions.",
                    path, reason
                )
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

            // Storage
            JacsError::StorageError(msg) => write!(f, "Storage error: {}", msg),

            // Database
            JacsError::DatabaseError { operation, reason } => {
                write!(f, "Database error during '{}': {}", operation, reason)
            }

            // Verification Claims
            JacsError::VerificationClaimFailed { claim, reason } => {
                write!(
                    f,
                    "Verification claim '{}' failed: {}\n\n\
                    Fix: ",
                    claim, reason
                )?;
                // Provide claim-specific actionable guidance
                match claim.as_str() {
                    "verified" | "verified-hai.ai"
                        if reason.contains("jacsAgentDomain") || reason.contains("domain") =>
                    {
                        write!(
                            f,
                            "Add \"jacsAgentDomain\": \"your-domain.com\" to your agent,\n     \
                            or use \"jacsVerificationClaim\": \"unverified\" if DNS verification is not needed."
                        )?;
                    }
                    "verified-hai.ai"
                        if reason.contains("not registered") || reason.contains("HAI.ai") =>
                    {
                        write!(
                            f,
                            "Register your agent at https://hai.ai before using the 'verified-hai.ai' claim,\n     \
                            or use \"jacsVerificationClaim\": \"verified\" for DNS-only verification."
                        )?;
                    }
                    _ if reason.contains("downgrade") || reason.contains("Cannot downgrade") => {
                        write!(
                            f,
                            "Verification claims cannot be downgraded for security. Create a new agent if you need a lower claim level."
                        )?;
                    }
                    _ => {
                        write!(
                            f,
                            "Ensure all security requirements for '{}' are met.",
                            claim
                        )?;
                    }
                }
                write!(
                    f,
                    "\n\nSee: https://hai.ai/docs/jacs/security#verification-claims"
                )
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
        JacsError::IoError(err)
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

    // ==========================================================================
    // HIGH-LEVEL CATEGORY ERROR TESTS
    // ==========================================================================

    #[test]
    fn test_config_error_display() {
        let err = JacsError::ConfigError("missing required field 'name'".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Configuration error"));
        assert!(msg.contains("missing required field"));
    }

    #[test]
    fn test_crypto_error_display() {
        let err = JacsError::CryptoError("key generation failed".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Cryptographic error"));
        assert!(msg.contains("key generation"));
    }

    #[test]
    fn test_schema_error_display() {
        let err = JacsError::SchemaError("schema validation failed".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Schema error"));
        assert!(msg.contains("validation failed"));
    }

    #[test]
    fn test_agent_error_display() {
        let err = JacsError::AgentError("failed to load agent".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Agent error"));
        assert!(msg.contains("failed to load"));
    }

    #[test]
    fn test_document_error_display() {
        let err = JacsError::DocumentError("document signing failed".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Document error"));
        assert!(msg.contains("signing failed"));
    }

    #[test]
    fn test_network_error_display() {
        let err = JacsError::NetworkError("connection refused".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Network error"));
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn test_trust_error_display() {
        let err = JacsError::TrustError("trust store not found".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Trust store error"));
        assert!(msg.contains("not found"));
    }

    #[test]
    fn test_io_error_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = JacsError::IoError(io_err);
        let msg = err.to_string();
        assert!(msg.contains("IO error"));
        assert!(msg.contains("file not found"));
    }

    #[test]
    fn test_validation_error_display() {
        let err = JacsError::ValidationError("invalid input".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Validation error"));
        assert!(msg.contains("invalid input"));
    }

    #[test]
    fn test_io_error_from_std_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let jacs_err: JacsError = io_err.into();
        assert!(matches!(jacs_err, JacsError::IoError(_)));
        let msg = jacs_err.to_string();
        assert!(msg.contains("access denied"));
    }

    // ==========================================================================
    // SPECIFIC ERROR VARIANT TESTS
    // ==========================================================================

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

    #[test]
    fn test_error_is_send_sync() {
        // Ensure JacsError can be sent across threads
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        // These will fail to compile if JacsError doesn't implement Send/Sync
        // Note: IoError contains std::io::Error which is Send + Sync
        assert_send::<JacsError>();
        assert_sync::<JacsError>();
    }

    #[test]
    fn test_error_implements_std_error() {
        let err = JacsError::ConfigError("test".to_string());
        // Verify it implements std::error::Error
        let _: &dyn Error = &err;
    }

    #[test]
    fn test_error_debug_format() {
        let err = JacsError::CryptoError("test crypto error".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("CryptoError"));
        assert!(debug_str.contains("test crypto error"));
    }

    // ==========================================================================
    // FILE OPERATION ERROR TESTS
    // ==========================================================================

    #[test]
    fn test_file_not_found_error_is_actionable() {
        let err = JacsError::FileNotFound {
            path: "/path/to/missing.json".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/path/to/missing.json"),
            "Should include the file path"
        );
        assert!(
            msg.contains("Ensure") || msg.contains("create"),
            "Should provide guidance"
        );
    }

    #[test]
    fn test_file_read_failed_error_is_actionable() {
        let err = JacsError::FileReadFailed {
            path: "/path/to/file.json".to_string(),
            reason: "permission denied".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/path/to/file.json"),
            "Should include the file path"
        );
        assert!(
            msg.contains("permission denied"),
            "Should include the reason"
        );
        assert!(
            msg.contains("permission") || msg.contains("Check"),
            "Should provide guidance"
        );
    }

    #[test]
    fn test_file_write_failed_error_is_actionable() {
        let err = JacsError::FileWriteFailed {
            path: "/path/to/output.json".to_string(),
            reason: "disk full".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/path/to/output.json"),
            "Should include the file path"
        );
        assert!(msg.contains("disk full"), "Should include the reason");
        assert!(
            msg.contains("write") || msg.contains("Check"),
            "Should provide guidance"
        );
    }

    #[test]
    fn test_directory_create_failed_error_is_actionable() {
        let err = JacsError::DirectoryCreateFailed {
            path: "/path/to/new_dir".to_string(),
            reason: "permission denied".to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/path/to/new_dir"),
            "Should include the directory path"
        );
        assert!(
            msg.contains("permission denied"),
            "Should include the reason"
        );
        assert!(
            msg.contains("parent") || msg.contains("Check"),
            "Should suggest checking parent directory"
        );
    }

    // ==========================================================================
    // VERIFICATION CLAIM ERROR TESTS
    // ==========================================================================

    #[test]
    fn test_verification_claim_domain_error_is_actionable() {
        let err = JacsError::VerificationClaimFailed {
            claim: "verified".to_string(),
            reason: "Verified agents must have jacsAgentDomain set".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("verified"), "Should state the claim");
        assert!(
            msg.contains("jacsAgentDomain"),
            "Should mention the required field"
        );
        assert!(msg.contains("Fix:"), "Should provide fix guidance");
        assert!(msg.contains("hai.ai/docs"), "Should include docs link");
    }

    #[test]
    fn test_verification_claim_hai_registration_error_is_actionable() {
        let err = JacsError::VerificationClaimFailed {
            claim: "verified-hai.ai".to_string(),
            reason: "Agent 'test-agent' is not registered with HAI.ai".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("verified-hai.ai"), "Should state the claim");
        assert!(
            msg.contains("not registered") || msg.contains("HAI.ai"),
            "Should mention registration"
        );
        assert!(msg.contains("Fix:"), "Should provide fix guidance");
        assert!(
            msg.contains("https://hai.ai"),
            "Should include registration link"
        );
    }

    // ==========================================================================
    // STORAGE & DATABASE ERROR TESTS
    // ==========================================================================

    #[test]
    fn test_storage_error_display() {
        let err = JacsError::StorageError("backend unavailable".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Storage error"));
        assert!(msg.contains("backend unavailable"));
    }

    #[test]
    fn test_database_error_display() {
        let err = JacsError::DatabaseError {
            operation: "store".to_string(),
            reason: "connection refused".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("Database error"));
        assert!(msg.contains("store"));
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn test_database_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<JacsError>();

        // Verify new variants specifically work across threads
        let err = JacsError::DatabaseError {
            operation: "query".to_string(),
            reason: "timeout".to_string(),
        };
        let handle = std::thread::spawn(move || err.to_string());
        let msg = handle.join().unwrap();
        assert!(msg.contains("timeout"));
    }

    #[test]
    fn test_verification_claim_downgrade_error_is_actionable() {
        let err = JacsError::VerificationClaimFailed {
            claim: "unverified".to_string(),
            reason: "Cannot downgrade from 'verified' to 'unverified'. Create a new agent instead."
                .to_string(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("downgrade") || msg.contains("Cannot"),
            "Should explain downgrade block"
        );
        assert!(msg.contains("Fix:"), "Should provide fix guidance");
        assert!(
            msg.contains("new agent"),
            "Should suggest creating new agent"
        );
    }
}
