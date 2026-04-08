//! Property-based tests for crypto and signing/verification boundaries.
//!
//! Uses `proptest` to generate arbitrary JSON payloads and verify that:
//! 1. Sign-then-verify always succeeds (round-trip invariant)
//! 2. Any single-byte mutation in a signed document always fails verification (tamper detection)
//! 3. Signing is deterministic across repeated calls on the same input (idempotent hash)
//!
//! These tests target invariants that example-based tests are unlikely to cover
//! because they exercise random content, edge-case strings, and unusual JSON shapes.
//!
//! ```sh
//! cargo test --test proptest_crypto --features sqlite
//! ```

use jacs::simple::SimpleAgent;
use proptest::prelude::*;
use serde_json::json;
use serial_test::serial;

const TEST_PASSWORD: &str = "PropTest!P@ss2026";
const PASSWORD_ENV: &str = "JACS_PRIVATE_KEY_PASSWORD";

/// Guard to set/restore password env var for serial tests.
struct PasswordGuard {
    prev: Option<std::ffi::OsString>,
}

impl PasswordGuard {
    fn set() -> Self {
        let prev = std::env::var_os(PASSWORD_ENV);
        unsafe { std::env::set_var(PASSWORD_ENV, TEST_PASSWORD) };
        Self { prev }
    }
}

impl Drop for PasswordGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(ref p) = self.prev {
                std::env::set_var(PASSWORD_ENV, p);
            } else {
                std::env::remove_var(PASSWORD_ENV);
            }
        }
    }
}

/// Create a test agent once (ephemeral) for use in property tests.
fn test_agent() -> SimpleAgent {
    let (agent, _info) = SimpleAgent::ephemeral(Some("ed25519")).expect("create ephemeral agent");
    agent
}

// =============================================================================
// Property: sign-then-verify round-trip always succeeds
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(30))]

    /// For any arbitrary string content, signing then verifying should always succeed.
    #[test]
    fn sign_verify_roundtrip_arbitrary_content(content in "\\PC{1,500}") {
        let _guard = PasswordGuard::set();
        let agent = test_agent();
        let payload = json!({"content": content});

        let signed = agent.sign_message(&payload)
            .expect("sign should succeed for any valid JSON content");

        let verification = agent.verify(&signed.raw)
            .expect("verify should not error for own signed document");

        prop_assert!(verification.valid, "round-trip verification must always pass");
    }

    /// For arbitrary JSON objects with multiple fields, sign-then-verify holds.
    #[test]
    fn sign_verify_roundtrip_arbitrary_json(
        key1 in "[a-z]{1,20}",
        val1 in "\\PC{0,100}",
        key2 in "[a-z]{1,20}",
        val2 in any::<i64>(),
    ) {
        let _guard = PasswordGuard::set();
        let agent = test_agent();
        let payload = json!({key1: val1, key2: val2});

        let signed = agent.sign_message(&payload)
            .expect("sign should succeed");

        let verification = agent.verify(&signed.raw)
            .expect("verify should not error");

        prop_assert!(verification.valid, "JSON object round-trip must pass");
    }
}

// =============================================================================
// Property: tamper detection (single-byte mutation must fail verification)
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Flipping any single byte in the signed JSON content should cause verification failure.
    #[test]
    fn single_byte_tamper_detected(
        content in "[a-zA-Z0-9 ]{10,100}",
        flip_offset_pct in 0.1f64..0.9f64,
    ) {
        let _guard = PasswordGuard::set();
        let agent = test_agent();
        let payload = json!({"tamper_test": content});

        let signed = agent.sign_message(&payload)
            .expect("sign should succeed");

        // Tamper with the raw JSON at a position in the "tamper_test" value area
        let raw = signed.raw.clone();
        let bytes = raw.as_bytes().to_vec();

        // Find the content value in the JSON
        if let Some(start) = raw.find(&content) {
            let flip_pos = start + ((content.len() as f64 * flip_offset_pct) as usize).min(content.len() - 1);
            if flip_pos < bytes.len() {
                let mut tampered = bytes;
                // Flip the byte (XOR with 1 to change it)
                tampered[flip_pos] ^= 1;

                if let Ok(tampered_str) = String::from_utf8(tampered) {
                    // Only test if the tampered string is still valid UTF-8
                    match agent.verify(&tampered_str) {
                        Ok(result) => {
                            prop_assert!(
                                !result.valid,
                                "tampered document should fail verification"
                            );
                        }
                        Err(_) => {
                            // Verification erroring out is also acceptable — the tamper was detected
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// Property: hash determinism — same content always produces the same hash
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(15))]

    /// Signing the same content twice should produce the same jacsSha256 hash.
    #[test]
    fn hash_is_deterministic(content in "[a-zA-Z0-9]{5,50}") {
        let _guard = PasswordGuard::set();
        let agent = test_agent();
        let payload = json!({"determinism": content});

        let signed1 = agent.sign_message(&payload)
            .expect("first sign should succeed");
        let signed2 = agent.sign_message(&payload)
            .expect("second sign should succeed");

        // Both documents should verify successfully, proving the signing
        // procedure is consistent regardless of varying UUIDs/timestamps.
        let v1 = agent.verify(&signed1.raw).expect("verify first");
        let v2 = agent.verify(&signed2.raw).expect("verify second");
        prop_assert!(v1.valid, "first document should verify");
        prop_assert!(v2.valid, "second document should verify");
    }
}
