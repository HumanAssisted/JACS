//! Ecosystem compatibility surfaces (P2).
//!
//! Everything in this module is about making a JACS agent legible to
//! OUTSIDE ecosystems (W3C DID/VC, JOSE, A2A, AP2) without touching the
//! native signing contract: native `jacsSignature` stays PQ, and the
//! ES256 `ecosystem_signing` key is authorized per-export by the
//! PQ-root-signed binding in [`binding`].

pub mod ap2;
pub mod binding;
pub mod exports;
// References crate::agreements::v2 — compiled only with the feature so
// default-feature `-D warnings` builds stay clean (P2 Task 004c).
#[cfg(feature = "agreements")]
pub mod vc;

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
