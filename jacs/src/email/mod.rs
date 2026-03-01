//! JACS email signing and verification module.
//!
//! Provides two primary functions for signing emails with JACS detached
//! signatures and verifying those signatures. The email-specific code
//! computes hashes and compares them — cryptography is handled by the
//! JACS crypto layer (`crypt::ringwrapper`, `crypt::rsawrapper`,
//! `crypt::pq2025`).
//!
//! ## Quick start
//!
//! ```ignore
//! use jacs::email::{sign_email, verify_email, EmailSigner, DefaultEmailVerifier};
//!
//! // Sign: your agent implements EmailSigner (algorithm comes from agent keys)
//! let signed_eml = sign_email(&raw_eml, &my_agent)?;
//!
//! // Verify: one call — crypto + content hash comparison
//! let result = verify_email(&signed_eml, &sender_public_key, &DefaultEmailVerifier)?;
//! assert!(result.valid);
//!
//! // Or two-step — inspect the JACS document before content comparison
//! let (doc, parts) = jacs::email::verify_email_document(&signed_eml, &key, &DefaultEmailVerifier)?;
//! println!("Signed by: {} using {}", doc.metadata.issuer, doc.signature.algorithm);
//! let result = jacs::email::verify_email_content(&doc, &parts);
//! ```
//!
//! ## Key design points
//!
//! - The signing algorithm is **never hardcoded** — it is read from the
//!   agent's key configuration via [`EmailSigner::algorithm()`].
//! - [`DefaultEmailVerifier`] handles Ed25519, RSA-PSS, and PQ2025/ML-DSA-87
//!   automatically, including key format conversion.
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
};

// Signing: the primary sender-side function + trait.
pub use sign::{canonicalize_json_rfc8785, sign_email, EmailSigner};

// Verification: simple one-call API + two-step API + trait + default impl.
pub use verify::{
    verify_email, verify_email_content, verify_email_document,
    DefaultEmailVerifier, EmailVerifier, normalize_algorithm,
};

// Attachment operations (needed by HAI API to peek at doc before full verify).
pub use attachment::{add_jacs_attachment, get_jacs_attachment, remove_jacs_attachment};
