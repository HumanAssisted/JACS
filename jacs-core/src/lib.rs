//! JACS portable protocol layer.
//!
//! `jacs-core` holds the protocol bits of JACS that must compile for both
//! native and `wasm32-unknown-unknown` targets: canonical JSON, signing
//! algorithm dispatch, encrypted-key envelopes, embedded schemas, and
//! agreement payload logic. It performs **no I/O**, opens no files, makes
//! no network calls, and pulls in no native-only crates. See
//! `docs/jacs/JACS_WASM_PRD.md` for the full split rationale.

pub mod agent;
pub mod canonical;
pub mod envelope;
pub mod errors;
pub mod material;
pub mod schema;
pub mod sign;
pub mod verify;

pub use agent::CoreAgent;
pub use errors::CoreError;
pub use material::{AgentMaterial, UnlockSecret};
pub use sign::{DetachedSigner, Ed25519DalekSigner, Pq2025Signer, SigningAlgorithm};
pub use verify::VerificationOutcome;

/// Test helper: generate a fresh Ed25519 signer for fixture builders. Kept
/// inside the crate (not feature-gated) because integration tests under
/// `tests/` are external consumers and cannot reach private items. The
/// underlying primitive is already pub through `Ed25519DalekSigner::
/// generate`; this re-export is purely a discoverability hint for test
/// authors building encrypted-material fixtures.
pub fn ed25519_signer_for_tests() -> Ed25519DalekSigner {
    Ed25519DalekSigner::generate().expect("ephemeral ed25519 keypair")
}
