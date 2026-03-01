//! Email-specific error types for the JACS email signing system.
//!
//! These error types follow the PRD error taxonomy and provide
//! consistent, actionable error reporting across all implementations.

/// Email-specific errors for the JACS email signing and verification system.
///
/// These map 1:1 to the PRD error taxonomy (lines 658-678).
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    /// The input is not valid RFC 5322 (malformed or ambiguous).
    #[error("Invalid email format: {0}")]
    InvalidEmailFormat(String),

    /// Canonicalization produced an ambiguous or invalid result.
    #[error("Canonicalization failed: {0}")]
    CanonicalizationFailed(String),

    /// No `jacs-signature.json` attachment was found in the email.
    #[error("Missing jacs-signature.json attachment")]
    MissingJacsSignature,

    /// The extracted JACS document is malformed or its hash does not match.
    #[error("Invalid JACS document: {0}")]
    InvalidJacsDocument(String),

    /// Cryptographic signature verification failed.
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// The public key for the signer could not be found.
    #[error("Signer key not found: {0}")]
    SignerKeyNotFound(String),

    /// Identity fields in the JACS document do not match the registry.
    #[error("Identity mismatch: {0}")]
    IdentityMismatch(String),

    /// DNS TXT record verification failed.
    #[error("DNS verification failed: {0}")]
    DNSVerificationFailed(String),

    /// Email content hashes do not match the signed payload.
    #[error("Content tampered: {0}")]
    ContentTampered(String),

    /// Forwarding chain verification failed.
    #[error("Chain verification failed: {0}")]
    ChainVerificationFailed(String),

    /// The algorithm in the signature does not match the public key's algorithm.
    #[error("Algorithm mismatch: {0}")]
    AlgorithmMismatch(String),

    /// A replay of a previously verified email was detected.
    /// Runtime detection (24h TTL, cache key = issuer + metadata.hash) is
    /// implemented at the HAI API layer, not in JACS.
    #[error("Replay detected: {0}")]
    ReplayDetected(String),

    /// The email exceeds the maximum allowed size (25 MB).
    #[error("Email too large: {size} bytes (max {max} bytes)")]
    EmailTooLarge {
        /// Actual email size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },

    /// A feature referenced in the email is not supported.
    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),
}

/// Maximum email size in bytes (25 MB).
pub const MAX_EMAIL_SIZE: usize = 25 * 1024 * 1024;

/// Check that email size is within the allowed limit.
pub fn check_email_size(raw_email: &[u8]) -> Result<(), EmailError> {
    if raw_email.len() > MAX_EMAIL_SIZE {
        return Err(EmailError::EmailTooLarge {
            size: raw_email.len(),
            max: MAX_EMAIL_SIZE,
        });
    }
    Ok(())
}

impl From<EmailError> for crate::error::JacsError {
    fn from(e: EmailError) -> Self {
        crate::error::JacsError::CryptoError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_email_format_error() {
        let err = EmailError::InvalidEmailFormat("missing From header".to_string());
        assert_eq!(err.to_string(), "Invalid email format: missing From header");
    }

    #[test]
    fn canonicalization_failed_error() {
        let err = EmailError::CanonicalizationFailed("duplicate From header".to_string());
        assert_eq!(
            err.to_string(),
            "Canonicalization failed: duplicate From header"
        );
    }

    #[test]
    fn missing_jacs_signature_error() {
        let err = EmailError::MissingJacsSignature;
        assert_eq!(err.to_string(), "Missing jacs-signature.json attachment");
    }

    #[test]
    fn invalid_jacs_document_error() {
        let err = EmailError::InvalidJacsDocument("hash mismatch".to_string());
        assert_eq!(err.to_string(), "Invalid JACS document: hash mismatch");
    }

    #[test]
    fn signature_verification_failed_error() {
        let err = EmailError::SignatureVerificationFailed("wrong key".to_string());
        assert_eq!(
            err.to_string(),
            "Signature verification failed: wrong key"
        );
    }

    #[test]
    fn content_tampered_error() {
        let err = EmailError::ContentTampered("body hash mismatch".to_string());
        assert_eq!(err.to_string(), "Content tampered: body hash mismatch");
    }

    #[test]
    fn chain_verification_failed_error() {
        let err = EmailError::ChainVerificationFailed("broken parent link".to_string());
        assert_eq!(
            err.to_string(),
            "Chain verification failed: broken parent link"
        );
    }

    #[test]
    fn email_too_large_error() {
        let err = EmailError::EmailTooLarge {
            size: 30_000_000,
            max: MAX_EMAIL_SIZE,
        };
        assert_eq!(
            err.to_string(),
            "Email too large: 30000000 bytes (max 26214400 bytes)"
        );
    }

    #[test]
    fn algorithm_mismatch_error() {
        let err = EmailError::AlgorithmMismatch("expected ed25519, got rsa".to_string());
        assert_eq!(
            err.to_string(),
            "Algorithm mismatch: expected ed25519, got rsa"
        );
    }

    #[test]
    fn all_errors_implement_display_and_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(EmailError::InvalidEmailFormat("test".to_string())),
            Box::new(EmailError::CanonicalizationFailed("test".to_string())),
            Box::new(EmailError::MissingJacsSignature),
            Box::new(EmailError::InvalidJacsDocument("test".to_string())),
            Box::new(EmailError::SignatureVerificationFailed("test".to_string())),
            Box::new(EmailError::SignerKeyNotFound("test".to_string())),
            Box::new(EmailError::IdentityMismatch("test".to_string())),
            Box::new(EmailError::DNSVerificationFailed("test".to_string())),
            Box::new(EmailError::ContentTampered("test".to_string())),
            Box::new(EmailError::ChainVerificationFailed("test".to_string())),
            Box::new(EmailError::AlgorithmMismatch("test".to_string())),
            Box::new(EmailError::ReplayDetected("test".to_string())),
            Box::new(EmailError::EmailTooLarge {
                size: 100,
                max: 50,
            }),
            Box::new(EmailError::UnsupportedFeature("test".to_string())),
        ];
        // All 14 error types are represented.
        assert_eq!(errors.len(), 14);
        for err in &errors {
            // Verify Display is implemented (non-empty string).
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn check_email_size_within_limit() {
        let small_email = vec![0u8; 1000];
        assert!(check_email_size(&small_email).is_ok());
    }

    #[test]
    fn check_email_size_exceeds_limit() {
        let big_email = vec![0u8; MAX_EMAIL_SIZE + 1];
        let result = check_email_size(&big_email);
        assert!(result.is_err());
        match result.unwrap_err() {
            EmailError::EmailTooLarge { size, max } => {
                assert_eq!(size, MAX_EMAIL_SIZE + 1);
                assert_eq!(max, MAX_EMAIL_SIZE);
            }
            _ => panic!("Expected EmailTooLarge"),
        }
    }

    #[test]
    fn email_error_converts_to_jacs_error() {
        let email_err = EmailError::MissingJacsSignature;
        let jacs_err: crate::error::JacsError = email_err.into();
        let msg = format!("{}", jacs_err);
        assert!(msg.contains("Missing jacs-signature.json"));
    }
}
