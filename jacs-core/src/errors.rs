//! `jacs-core` error type.
//!
//! `CoreError` is the protocol-layer error enum surfaced by every operation
//! in `jacs-core` (sign, verify, envelope decrypt, agreement quorum, schema
//! lookup, …). It is **deliberately** independent of `jacs::JacsError` so
//! `jacs-core` can compile for `wasm32-unknown-unknown` without dragging in
//! native-only crates. The native facade converts via `From<CoreError> for
//! jacs::JacsError` (lives in `jacs/src/error.rs`).
//!
//! ## Serialization contract
//!
//! Every `CoreError` serializes as
//!
//! ```json
//! { "code": "VariantName", "message": "human readable text", "details": { … } }
//! ```
//!
//! `details` is only present when the variant carries structured fields
//! (e.g. `AlgorithmMismatch { expected, actual }`); single-`String`
//! variants omit it. The shape is stable — `jacs-wasm` exposes it as
//! `JacsWasmError` to browser callers, and the `code` discriminator is
//! load-bearing for client-side error handling. See PRD §3.1.

use serde::Serialize;
use serde::ser::SerializeStruct;
use thiserror::Error;

/// Protocol-layer error.
///
/// One variant per failure mode. Variant names are stable wire identifiers
/// (they appear as the `code` field of the serialized error); do not rename
/// without bumping the JACS WASM contract.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// The supplied password does not unlock the encrypted private key.
    #[error("invalid password")]
    InvalidPassword,

    /// The supplied password is structurally invalid (e.g. empty).
    #[error("invalid password format: {0}")]
    InvalidPasswordFormat(String),

    /// The agent has been locked via `clear_secrets`; sign operations are
    /// rejected until re-unlocked. Verification still works.
    #[error("agent is locked; call unlock before signing")]
    Locked,

    /// The caller asked for one algorithm but the loaded material is a
    /// different one.
    #[error("algorithm mismatch: expected {expected}, got {actual}")]
    AlgorithmMismatch {
        /// The algorithm the caller requested.
        expected: String,
        /// The algorithm actually present on the loaded material.
        actual: String,
    },

    /// The algorithm identifier or envelope magic is unknown / reserved.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The JACS document is structurally invalid (missing field, wrong
    /// type, malformed canonical bytes, …).
    #[error("malformed document: {0}")]
    MalformedDocument(String),

    /// A key blob is malformed (wrong length, bad PKCS#8 structure, …).
    #[error("malformed key: {0}")]
    MalformedKey(String),

    /// The encrypted-key envelope is structurally invalid (short, bad
    /// JSON, missing field, …). Distinct from `InvalidPassword`.
    #[error("malformed envelope: {0}")]
    MalformedEnvelope(String),

    /// The cryptographic signature did not verify against the supplied
    /// public key + payload.
    #[error("signature invalid: {0}")]
    SignatureInvalid(String),

    /// AEAD encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// AEAD decryption failed (tag mismatch, KDF error, …). Distinct from
    /// `InvalidPassword`, which is the specific case where the password
    /// itself was wrong.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// JSON schema validation failed.
    #[error("schema invalid: {0}")]
    SchemaInvalid(String),

    /// Multi-party agreement quorum / payload check failed.
    #[error("agreement failed: {0}")]
    AgreementFailed(String),
}

impl CoreError {
    /// Stable wire identifier for this error (the `code` field of the
    /// serialized payload). Match this in client code instead of comparing
    /// to the localized `message`.
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::InvalidPassword => "InvalidPassword",
            CoreError::InvalidPasswordFormat(_) => "InvalidPasswordFormat",
            CoreError::Locked => "Locked",
            CoreError::AlgorithmMismatch { .. } => "AlgorithmMismatch",
            CoreError::UnsupportedAlgorithm(_) => "UnsupportedAlgorithm",
            CoreError::MalformedDocument(_) => "MalformedDocument",
            CoreError::MalformedKey(_) => "MalformedKey",
            CoreError::MalformedEnvelope(_) => "MalformedEnvelope",
            CoreError::SignatureInvalid(_) => "SignatureInvalid",
            CoreError::EncryptionFailed(_) => "EncryptionFailed",
            CoreError::DecryptionFailed(_) => "DecryptionFailed",
            CoreError::SchemaInvalid(_) => "SchemaInvalid",
            CoreError::AgreementFailed(_) => "AgreementFailed",
        }
    }
}

impl Serialize for CoreError {
    /// Stable JSON shape: `{ code, message, details? }`. `details` is only
    /// present when the variant has structured fields beyond a single
    /// human-readable string. This shape is the wire contract — see module
    /// docs.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let details = match self {
            CoreError::AlgorithmMismatch { expected, actual } => Some(serde_json::json!({
                "expected": expected,
                "actual": actual,
            })),
            // Single-`String` variants do not need `details` — the message
            // already carries the only payload.
            _ => None,
        };

        let mut s = serializer.serialize_struct(
            "CoreError",
            if details.is_some() { 3 } else { 2 },
        )?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", &self.to_string())?;
        if let Some(d) = details {
            s.serialize_field("details", &d)?;
        }
        s.end()
    }
}
