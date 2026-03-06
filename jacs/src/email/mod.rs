//! JACS email signing and verification module.
//!
//! Provides functions for signing emails with JACS detached signatures and
//! verifying those signatures. All cryptographic operations are handled by
//! the JACS agent via `SimpleAgent`.
//!
//! ## Quick start
//!
//! ```ignore
//! use jacs::email::{sign_email, verify_email, verify_email_content};
//! use jacs::simple::SimpleAgent;
//!
//! // Sign: pass a SimpleAgent — all crypto is handled by JACS
//! let signed_eml = sign_email(&raw_eml, &my_agent)?;
//!
//! // Verify: crypto + content hash comparison
//! let pubkey = sender_agent.get_public_key()?;
//! let result = verify_email(&signed_eml, &my_agent, &pubkey)?;
//! assert!(result.valid);
//! ```
//!
//! ## Key design points
//!
//! - Signing uses `SimpleAgent::sign_message()` to create a real JACS document.
//!   No manual crypto in the email module.
//! - Verification uses `SimpleAgent::verify_with_key()` for cryptographic
//!   verification against an arbitrary sender's public key.
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
    AttachmentEntry, BodyPartEntry, ChainEntry, ContentVerificationResult, EmailSignatureHeaders,
    EmailSignaturePayload, FieldResult, FieldStatus, JacsEmailMetadata, JacsEmailSignature,
    JacsEmailSignatureDocument, ParsedAttachment, ParsedBodyPart, ParsedEmailParts,
    SignedHeaderEntry, VerifiedEmailDocument,
};

// Signing: the primary sender-side function.
pub use sign::{canonicalize_json_rfc8785, sign_email};

// Verification: one-call API + two-step API + content-only API.
pub use verify::{normalize_algorithm, verify_email, verify_email_content, verify_email_document};

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

/// Restores process env vars on drop for email tests that temporarily override them.
#[cfg(test)]
pub(crate) struct EmailTestEnvGuard {
    previous: Vec<(&'static str, Option<String>)>,
}

#[cfg(test)]
impl EmailTestEnvGuard {
    pub(crate) fn set(vars: &[(&'static str, String)]) -> Self {
        let mut previous = Vec::with_capacity(vars.len());
        for (key, value) in vars {
            let prior = std::env::var(key).ok();
            previous.push((*key, prior));
            // SAFETY: Email tests hold EMAIL_TEST_MUTEX while mutating env vars.
            unsafe {
                std::env::set_var(key, value);
            }
        }
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for EmailTestEnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            // SAFETY: Email tests hold EMAIL_TEST_MUTEX while mutating env vars.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}
