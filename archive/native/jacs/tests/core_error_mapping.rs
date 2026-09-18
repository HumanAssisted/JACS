//! Wave 1 / Task 004: `From<CoreError> for JacsError` mapping tests.
//!
//! Per PRD §4.4 + §9, every `CoreError` variant must map to an existing
//! `JacsError` variant — never to `JacsError::Internal`. These tests pin
//! the mapping in place; if you add a `CoreError` variant later, you must
//! extend both the `From` impl in `jacs/src/error.rs` and the parameterized
//! test below.

use jacs::error::JacsError;
use jacs_core::CoreError;

#[test]
fn core_error_maps_to_jacs_error_signature_invalid() {
    let err: JacsError = CoreError::SignatureInvalid("byte mismatch".into()).into();
    match err {
        JacsError::SignatureVerificationFailed { reason } => {
            assert!(reason.contains("byte mismatch"));
        }
        other => panic!("expected SignatureVerificationFailed, got {other:?}"),
    }
}

#[test]
fn core_error_maps_to_jacs_error_invalid_password() {
    let err: JacsError = CoreError::InvalidPassword.into();
    assert!(matches!(err, JacsError::KeyDecryptionFailed { .. }));
}

#[test]
fn core_error_maps_to_jacs_error_malformed_document() {
    let err: JacsError = CoreError::MalformedDocument("missing $signature".into()).into();
    match err {
        JacsError::DocumentMalformed { field, reason } => {
            assert_eq!(field, "document");
            assert!(reason.contains("missing $signature"));
        }
        other => panic!("expected DocumentMalformed, got {other:?}"),
    }
}

#[test]
fn core_error_maps_to_jacs_error_schema_invalid() {
    let err: JacsError = CoreError::SchemaInvalid("bad draft-7 ref".into()).into();
    assert!(matches!(err, JacsError::SchemaError(_)));
}

/// Parameterized: every `CoreError` variant must map to a non-`Internal`
/// `JacsError`. This is the binding contract from PRD §9 ("no new
/// JacsError variants — CoreError → JacsError is a From conversion using
/// existing variants"). If a new `CoreError` variant is added without a
/// dedicated `From` arm, it will fall through to `Internal` (or fail to
/// compile if the match is exhaustive) and this assertion will fire.
#[test]
fn every_core_error_variant_maps_to_non_internal_jacs_error() {
    let variants: Vec<CoreError> = vec![
        CoreError::InvalidPassword,
        CoreError::InvalidPasswordFormat("empty".into()),
        CoreError::Locked,
        CoreError::AlgorithmMismatch {
            expected: "ed25519".into(),
            actual: "pq2025".into(),
        },
        CoreError::UnsupportedAlgorithm("rsa".into()),
        CoreError::MalformedDocument("missing field".into()),
        CoreError::MalformedKey("bad PKCS#8".into()),
        CoreError::MalformedEnvelope("truncated".into()),
        CoreError::SignatureInvalid("bad bytes".into()),
        CoreError::EncryptionFailed("aead".into()),
        CoreError::DecryptionFailed("tag mismatch".into()),
        CoreError::SchemaInvalid("draft-7 compile".into()),
        CoreError::AgreementFailed("quorum".into()),
    ];

    for variant in variants {
        let code = variant.code();
        let mapped: JacsError = variant.into();
        assert!(
            !matches!(mapped, JacsError::Internal { .. }),
            "CoreError::{code} mapped to JacsError::Internal — PRD §9 forbids this",
        );
    }
}
