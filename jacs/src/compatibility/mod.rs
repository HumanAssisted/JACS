//! Ecosystem compatibility surfaces (P2).
//!
//! Everything in this module is about making a JACS agent legible to
//! OUTSIDE ecosystems (W3C DID/VC, JOSE, A2A, AP2) without touching the
//! native signing contract: native `jacsSignature` stays PQ, and the
//! ES256 `ecosystem_signing` key is authorized per-export by the
//! native-root-signed binding in [`binding`].

pub mod ap2;
pub mod binding;
pub mod exports;
// References crate::agreements::v2 — compiled only with the feature so
// default-feature `-D warnings` builds stay clean (P2 Task 004c).
#[cfg(feature = "agreements")]
pub mod vc;

/// Decrypt the ES256 ecosystem private key with the agent's password.
/// The plaintext PKCS#8 DER lives ONLY in the returned zeroizing buffer —
/// the one place the signing exporters' decrypt sequence (and its
/// zeroization guarantee) is written down.
pub(crate) fn decrypt_ecosystem_private_key(
    agent: &crate::agent::Agent,
    compat: &crate::keystore::compat::CompatKeyInfo,
) -> Result<crate::crypt::aes_encrypt::ZeroizingVec, crate::error::JacsError> {
    let password = agent.resolve_password()?;
    let encrypted = std::fs::read(&compat.private_key_path).map_err(|e| {
        crate::error::JacsError::FileReadFailed {
            path: compat.private_key_path.clone(),
            reason: e.to_string(),
        }
    })?;
    crate::crypt::aes_encrypt::decrypt_private_key_secure_with_password(&encrypted, &password)
}

/// PRD §9.8 counter: one successful ecosystem export, labeled by format.
/// Called unconditionally next to each `ecosystem_export_generated` event
/// (cheap no-op unless the `otlp-metrics` feature is enabled). `format`
/// is always one of the SIX binding scopes — the PRD §9.4 bijection
/// (`binding::ALL_SCOPES`), pinned by the label-set test in
/// `tests/compatibility_observability.rs` — low cardinality.
pub(crate) fn record_export_generated(format: &str) {
    let mut tags = std::collections::HashMap::new();
    tags.insert("format".to_string(), format.to_string());
    crate::observability::metrics::increment_counter(
        "jacs_compatibility_export_total",
        1,
        Some(tags),
    );
}

/// PRD §9.8 counter: one exporter failure, labeled by format plus a FIXED
/// reason string (`missing_key`, `no_binding`, `binding_invalid`,
/// `scope_denied`, `invalid_input`) — never raw error text, so the metric
/// label set stays low-cardinality.
pub(crate) fn record_export_error(format: &str, reason: &'static str) {
    let mut tags = std::collections::HashMap::new();
    tags.insert("format".to_string(), format.to_string());
    tags.insert("reason".to_string(), reason.to_string());
    crate::observability::metrics::increment_counter(
        "jacs_compatibility_export_error_total",
        1,
        Some(tags),
    );
}
