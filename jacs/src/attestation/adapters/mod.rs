//! Evidence adapter trait and adapter registry.
//!
//! Adapters normalize external evidence into attestation claims.

pub mod a2a;
pub mod email;

use crate::attestation::types::{
    AssuranceLevel, Claim, DigestSet, EvidenceRef, EvidenceVerificationResult,
};
use crate::error::JacsError;
use serde_json::Value;

/// Trait for normalizing external evidence into attestation claims.
/// Adapters are stored on Agent as Vec<Box<dyn EvidenceAdapter>> behind feature flag.
pub trait EvidenceAdapter: Send + Sync + std::fmt::Debug {
    /// Returns the kind string (e.g., "a2a", "email", "jwt").
    fn kind(&self) -> &str;

    /// Normalize raw evidence bytes + metadata into claims + evidence reference.
    ///
    /// Both inputs are untrusted. Digest computation alone must not produce a
    /// `Verified` claim; that assurance requires actual protocol/signature
    /// verification against an explicit trust policy.
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

/// Build a truthful digest-recording claim for an adapter that does not
/// authenticate arbitrary evidence bytes.
///
/// Computing (and later comparing) a digest does not authenticate a protocol
/// message, verify a transport signature, or establish signer trust. Adapters
/// that perform those checks must use a separate verifier API carrying typed,
/// verified provenance rather than trusting caller-supplied metadata.
pub(super) fn digest_recorded_claim(kind: &str, digests: &DigestSet) -> Claim {
    Claim {
        name: format!("{kind}-evidence-digest-recorded"),
        value: Value::String(digests.sha256.clone()),
        confidence: None,
        assurance_level: Some(AssuranceLevel::SelfAsserted),
        issuer: None,
        issued_at: Some(crate::time_utils::now_rfc3339()),
    }
}

/// Returns the default set of evidence adapters.
pub fn default_adapters() -> Vec<Box<dyn EvidenceAdapter>> {
    vec![Box::new(a2a::A2aAdapter), Box::new(email::EmailAdapter)]
}
