//! Attestation module: types, creation, verification, adapters, and migration.
//!
//! Gated behind the `attestation` feature flag.
//! "Signing says WHO. Attestation says WHO plus WHY."

pub mod adapters;
pub mod create;
pub mod digest;
pub mod dsse;
pub mod migration;
pub mod simple;
pub mod types;
pub mod verify;

use crate::agent::document::JACSDocument;
use std::error::Error;
use types::*;

/// Core attestation trait, implemented on Agent.
pub trait AttestationTraits {
    /// Create a signed attestation document.
    fn create_attestation(
        &mut self,
        subject: &AttestationSubject,
        claims: &[Claim],
        evidence: &[EvidenceRef],
        derivation: Option<&Derivation>,
        policy_context: Option<&PolicyContext>,
    ) -> Result<JACSDocument, Box<dyn Error>>;

    /// Verify attestation: crypto + hash only. No network, no derivation walk. Hot-path default.
    fn verify_attestation_local(
        &self,
        document_key: &str,
    ) -> Result<AttestationVerificationResult, Box<dyn Error>>;

    /// Verify attestation: crypto + evidence fetch + derivation chain. Explicit opt-in.
    fn verify_attestation_full(
        &self,
        document_key: &str,
    ) -> Result<AttestationVerificationResult, Box<dyn Error>>;
}
