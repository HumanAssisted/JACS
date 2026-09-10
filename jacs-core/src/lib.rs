//! JACS portable protocol layer.
//!
//! `jacs-core` holds the protocol bits of JACS that must compile for both
//! native and `wasm32-unknown-unknown` targets: canonical JSON, signing
//! algorithm dispatch, encrypted-key envelopes, embedded schemas, and
//! agreement payload logic. It performs **no I/O**, opens no files, makes
//! no network calls, and pulls in no native-only crates. See
//! `docs/jacs/JACS_WASM_PRD.md` for the full split rationale.

pub mod agent;
pub mod agreements;
pub mod canonical;
pub mod envelope;
pub mod errors;
pub mod human_approval;
pub mod identity;
pub mod lifecycle;
pub mod material;
pub mod response_context;
pub mod schema;
pub mod sign;
pub mod signing;
pub mod signing_context;
pub mod strict_json;
pub mod verification;
pub mod verification_registry;
pub mod verify;

pub use agent::CoreAgent;
pub use errors::CoreError;
pub use material::{AgentMaterial, UnlockSecret};
pub use sign::{DetachedSigner, Ed25519DalekSigner, Pq2025Signer, SigningAlgorithm};
pub use signing::{
    AuthorityClassifiedPreparedDocumentV1, MediaCanonicalizationV1, MediaClaimFormatV1,
    MediaClaimV1, MediaEmbeddingChannelV1, NativeDocumentHeaderV1, NativeMessageHeaderV1,
    PreparedDocumentV2, PreparedSigningError, PreparedSigningFailurePhase, PreparedSigningOutcome,
    PurposeIsolationAssurance, RestrictedSigningProvider, SignatureMetadataV2, SigningKeyContext,
    SigningKeyScope, SigningOperation, SigningProfileBindingV1, SigningPurpose, document_hash_v1,
    prepare_authority_classified_artifact_v2_with_id,
    prepare_authority_classified_message_v2_with_id,
    prepare_authority_classified_native_artifact_v2,
    prepare_authority_classified_native_message_v2, prepare_document_v2,
    prepare_document_v2_for_context, prepare_media_claim_v2, prepare_message_v2,
    prepare_message_v2_with_id, prepare_message_v2_with_id_for_context, prepare_native_artifact_v2,
    prepare_native_artifact_v2_for_context, prepare_native_message_v2,
    prepare_native_message_v2_for_context,
};
pub use signing_context::{
    AuthoritySigningClassificationV1, SigningContextSelectionV1, SigningInputBindingV1,
    SigningInputEncodingV1, SigningKeyRoleV1, SigningOperationContextV1,
    SigningRequestAuthClaimsV2, SigningRequestContextV1, SigningSchemaBindingV1,
};
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
