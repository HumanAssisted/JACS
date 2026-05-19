//! Canonical JSON serialization per RFC 8785 (JSON Canonicalization Scheme).
//!
//! `jacs-core` is the single source for canonicalization across the
//! workspace. Every signing / verification / hashing path must route here
//! so the bytes produced for signing in one binding match the bytes
//! reconstructed for verification in another. Direct calls to
//! `serde_json_canonicalizer::to_string` elsewhere in `jacs/src/` are a
//! DRY violation — `scripts/forbidden-deps.sh` is not the watchdog for
//! that, but a grep guard in CI (Task 025 cleanup) is the long-term plan.
//!
//! Two entry points exist for historical reasons:
//!
//! - [`canonicalize_json`] — infallible (returns `"null"` on the
//!   essentially-impossible serializer failure). This is the
//!   backwards-compatible signature used by `jacs::protocol`,
//!   `jacs::email`, and `jacs::simple`.
//! - [`canonicalize_json_try`] — fallible, returns
//!   [`crate::CoreError::MalformedDocument`] on failure. Use this when
//!   the caller wants the error to propagate (e.g.
//!   `jacs::attestation::digest`, `jacs::agent::canonicalize_json`).

use crate::CoreError;

/// Deterministically serialize a [`serde_json::Value`] per RFC 8785.
///
/// Returns the canonical UTF-8 string. On the rare serializer failure
/// (only possible for non-JSON-representable inputs that `serde_json`
/// already disallows in `Value`), returns `"null"` to match the
/// long-standing `jacs::protocol::canonicalize_json` contract.
pub fn canonicalize_json(value: &serde_json::Value) -> String {
    serde_json_canonicalizer::to_string(value).unwrap_or_else(|_| "null".to_string())
}

/// Fallible variant of [`canonicalize_json`]: returns
/// [`CoreError::MalformedDocument`] on serializer failure instead of the
/// `"null"` fallback. Use this in code paths that must propagate canonical
/// errors (digest computation, agent signing internals).
pub fn canonicalize_json_try(value: &serde_json::Value) -> Result<String, CoreError> {
    serde_json_canonicalizer::to_string(value)
        .map_err(|e| CoreError::MalformedDocument(format!("canonicalize failed: {e}")))
}
