//! JACS email signing and verification module.
//!
//! Provides two primary functions for signing emails with JACS detached
//! signatures and verifying those signatures. The email-specific code
//! computes hashes and compares them — all cryptographic operations are
//! handled by the JACS agent via `SimpleAgent`.
//!
//! ## Quick start
//!
//! ```ignore
//! use jacs::email::{sign_email, verify_email_with_agent, verify_email_content};
//! use jacs::simple::SimpleAgent;
//!
//! // Sign: pass a SimpleAgent — all crypto is handled by JACS
//! let signed_eml = sign_email(&raw_eml, &my_agent)?;
//!
//! // Verify: one call — crypto + content hash comparison
//! let result = verify_email_with_agent(&signed_eml, &my_agent)?;
//! assert!(result.valid);
//! ```
//!
//! ## Key design points
//!
//! - Signing uses `SimpleAgent::sign_message()` to create a real JACS document.
//!   No manual crypto in the email module.
//! - Verification uses `SimpleAgent::verify()` for cryptographic verification.
//!   Legacy `DefaultEmailVerifier` is still available for backward compatibility.
//! - Forwarding is built-in: if the email already has a `jacs-signature.json`,
//!   [`sign_email`] renames it and links via `parent_signature_hash`.
//!
//! See the full guide: `docs/jacsbook/src/guides/email-signing.md`

pub(crate) mod attachment;
pub(crate) mod canonicalize;
mod sign;
mod verify;

// Public error types (needed by callers to handle errors).
pub mod error;
pub use error::EmailError;

// Public type definitions (needed to inspect results and documents).
pub mod types;
pub use types::{
    AttachmentEntry, BodyPartEntry, ChainEntry, ContentVerificationResult,
    EmailSignatureHeaders, EmailSignaturePayload, FieldResult, FieldStatus,
    JacsEmailMetadata, JacsEmailSignature, JacsEmailSignatureDocument,
    ParsedAttachment, ParsedBodyPart, ParsedEmailParts, SignedHeaderEntry,
    VerifiedEmailDocument,
};

// Signing: the primary sender-side function.
pub use sign::{canonicalize_json_rfc8785, sign_email};

// Verification: simple one-call API + two-step API + trait + default impl.
pub use verify::{
    verify_email, verify_email_content, verify_email_document,
    verify_email_document_with_agent, verify_email_with_agent,
    DefaultEmailVerifier, EmailVerifier, normalize_algorithm,
};

// Attachment operations (needed by HAI API to peek at doc before full verify).
pub use attachment::{add_jacs_attachment, get_jacs_attachment, remove_jacs_attachment};

// Canonicalization utilities (needed by fixture conformance tests).
pub use canonicalize::{canonicalize_header, extract_email_parts};

/// Shared mutex for email tests that involve signing/verification.
///
/// The JACS keystore reads process-global env vars at signing time.
/// This mutex must be held by all email tests that create agents and
/// sign/verify emails to prevent env var stomping between modules.
#[cfg(test)]
pub(crate) static EMAIL_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
