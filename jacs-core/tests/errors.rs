//! Wave 1 / Task 004 tests for the `CoreError` enum and its serialization
//! contract. The shape (`{ code, message, details? }`) is the wire
//! contract used by `jacs-wasm`'s `JacsWasmError`; do not relax these
//! assertions without bumping the contract.

use jacs_core::CoreError;
use serde_json::Value;

#[test]
fn core_error_serializes_with_code() {
    let err = CoreError::InvalidPassword;
    let v: Value = serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();

    assert_eq!(v["code"], "InvalidPassword");
    assert!(v["message"].as_str().is_some(), "message must be a string");
    // Single-string variants emit no `details` field.
    assert!(v.get("details").is_none());
}

#[test]
fn algorithm_mismatch_serializes_with_details() {
    let err = CoreError::AlgorithmMismatch {
        expected: "ed25519".into(),
        actual: "pq2025".into(),
    };
    let s = serde_json::to_string(&err).unwrap();
    let v: Value = serde_json::from_str(&s).unwrap();

    assert_eq!(v["code"], "AlgorithmMismatch");
    assert_eq!(v["details"]["expected"], "ed25519");
    assert_eq!(v["details"]["actual"], "pq2025");
    // Sanity: message mentions both algorithms.
    let msg = v["message"].as_str().unwrap();
    assert!(msg.contains("ed25519"));
    assert!(msg.contains("pq2025"));
}

#[test]
fn unsupported_algorithm_carries_string_message() {
    let err = CoreError::UnsupportedAlgorithm("JAA1".into());
    let v: Value = serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();

    assert_eq!(v["code"], "UnsupportedAlgorithm");
    assert!(v["message"].as_str().unwrap().contains("JAA1"));
    // Reserved-prefix variants don't have structured `details`.
    assert!(v.get("details").is_none());
}

#[test]
fn locked_variant_serializes_with_code_locked() {
    // PRD §3.1: clearSecrets() then sign must throw with `code: "Locked"`.
    let err = CoreError::Locked;
    let v: Value = serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();

    assert_eq!(v["code"], "Locked");
    assert!(v["message"].as_str().is_some());
}

#[test]
fn every_variant_has_distinct_code_and_serializes_cleanly() {
    // Exercise every variant. If a new variant is added without a `code()`
    // arm or serializer arm, this test will fail to compile or to round
    // through serde_json. This is the parameterized "every variant"
    // smoke check the task spec asks for at the `jacs-core` layer.
    let variants: Vec<CoreError> = vec![
        CoreError::InvalidPassword,
        CoreError::InvalidPasswordFormat("empty".into()),
        CoreError::Locked,
        CoreError::AlgorithmMismatch {
            expected: "ed25519".into(),
            actual: "pq2025".into(),
        },
        CoreError::UnsupportedAlgorithm("rsa".into()),
        CoreError::MalformedDocument("missing field $signature".into()),
        CoreError::MalformedKey("bad PKCS#8 wrapper".into()),
        CoreError::MalformedEnvelope("truncated".into()),
        CoreError::SignatureInvalid("bytes don't match".into()),
        CoreError::EncryptionFailed("aead error".into()),
        CoreError::DecryptionFailed("tag mismatch".into()),
        CoreError::SchemaInvalid("draft-7 compile error".into()),
        CoreError::AgreementFailed("quorum not reached".into()),
    ];

    let mut seen_codes = std::collections::HashSet::new();
    for err in variants {
        let s = serde_json::to_string(&err).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        let code = v["code"].as_str().expect("code is a string").to_string();
        assert!(
            seen_codes.insert(code.clone()),
            "duplicate code {code} — variants must have distinct codes"
        );
        // Display string must be non-empty (used as `message`).
        assert!(!err.to_string().is_empty(), "variant {code} had empty Display");
    }
}
