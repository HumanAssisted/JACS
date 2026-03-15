//! Evidence adapter trait and adapter registry.
//!
//! Adapters normalize external evidence into attestation claims.

pub mod a2a;
pub mod email;

use crate::attestation::types::{Claim, EvidenceRef, EvidenceVerificationResult};
use crate::error::JacsError;
use serde_json::Value;

/// Trait for normalizing external evidence into attestation claims.
/// Adapters are stored on Agent as Vec<Box<dyn EvidenceAdapter>> behind feature flag.
pub trait EvidenceAdapter: Send + Sync + std::fmt::Debug {
    /// Returns the kind string (e.g., "a2a", "email", "jwt").
    fn kind(&self) -> &str;

    /// Normalize raw evidence bytes + metadata into claims + evidence reference.
    fn normalize(
        &self,
        raw: &[u8],
        metadata: &Value,
    ) -> Result<(Vec<Claim>, EvidenceRef), JacsError>;

    /// Verify a previously created evidence reference.
    fn verify_evidence(
        &self,
        evidence: &EvidenceRef,
    ) -> Result<EvidenceVerificationResult, JacsError>;
}

/// Returns the default set of evidence adapters.
pub fn default_adapters() -> Vec<Box<dyn EvidenceAdapter>> {
    vec![Box::new(a2a::A2aAdapter), Box::new(email::EmailAdapter)]
}
