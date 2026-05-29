//! Security hardening tests for JACS v0.9.3
//!
//! These tests verify fixes for four security findings:
//! 1. HIGH: save_private_key must not silently write unencrypted keys
//! 2. HIGH: sign_detached must reject non-UTF8 messages (not degrade to "")
//! 3. MEDIUM: trust_a2a_card must warn that cards are unverified
//! 4. LOW: password file reads must reject overly permissive file modes

use std::env;

/// RAII guard for environment variable manipulation.
/// Restores the previous value (or unsets) on drop.
struct EnvVarGuard {
    key: String,
    original: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &str, value: &str) -> Self {
        let original = env::var(key).ok();
        // SAFETY: tests run serially (#[serial]) so no concurrent env mutation
        unsafe { env::set_var(key, value) };
        Self {
            key: key.to_string(),
            original,
        }
    }

    fn unset(key: &str) -> Self {
        let original = env::var(key).ok();
        // SAFETY: tests run serially (#[serial]) so no concurrent env mutation
        unsafe { env::remove_var(key) };
        Self {
            key: key.to_string(),
            original,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: tests run serially (#[serial]) so no concurrent env mutation
        match &self.original {
            Some(val) => unsafe { env::set_var(&self.key, val) },
            None => unsafe { env::remove_var(&self.key) },
        }
    }
}

fn recompute_jacs_sha256(value: &mut serde_json::Value) {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("jacsSha256");
    }
    let canonical = serde_json_canonicalizer::to_string(value).expect("canonicalize document");
    let digest = jacs::crypt::hash::hash_string(&canonical);
    value["jacsSha256"] = serde_json::json!(digest);
}

// =============================================================================
// Finding 2: sign_detached must reject non-UTF8 messages
// =============================================================================

mod sign_detached_non_utf8 {
    use jacs::keystore::InMemoryKeyStore;
    use jacs::keystore::KeySpec;
    use jacs::keystore::KeyStore;

    #[test]
    fn rejects_non_utf8_message_ed25519() {
        let store = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (priv_key, _pub_key) = store.generate(&spec).expect("keygen");

        // Invalid UTF-8 sequence
        let bad_bytes: &[u8] = &[0xFF, 0xFE, 0x80, 0x81];

        let result = store.sign_detached(&priv_key, bad_bytes, "ring-Ed25519");
        assert!(
            result.is_err(),
            "sign_detached must reject non-UTF8 messages, not silently sign empty string"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.to_lowercase().contains("utf") || err_msg.to_lowercase().contains("valid"),
            "Error message should mention UTF-8 validity, got: {}",
            err_msg
        );
    }

    #[cfg(feature = "pq-tests")]
    #[test]
    fn rejects_non_utf8_message_pq2025() {
        let store = InMemoryKeyStore::new("pq2025");
        let spec = KeySpec {
            algorithm: "pq2025".to_string(),
            key_id: None,
        };
        let (priv_key, _pub_key) = store.generate(&spec).expect("keygen");

        let bad_bytes: &[u8] = &[0xFF, 0xFE, 0x80, 0x81];

        let result = store.sign_detached(&priv_key, bad_bytes, "pq2025");
        assert!(
            result.is_err(),
            "sign_detached must reject non-UTF8 messages for pq2025"
        );
    }

    /// Valid UTF-8 messages must still sign successfully.
    #[test]
    fn accepts_valid_utf8_message() {
        let store = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (priv_key, _pub_key) = store.generate(&spec).expect("keygen");

        let valid_bytes = b"hello world";
        let result = store.sign_detached(&priv_key, valid_bytes, "ring-Ed25519");
        assert!(result.is_ok(), "Valid UTF-8 should sign successfully");
    }

    /// Empty message (valid UTF-8) should still work.
    #[test]
    fn accepts_empty_message() {
        let store = InMemoryKeyStore::new("ring-Ed25519");
        let spec = KeySpec {
            algorithm: "ring-Ed25519".to_string(),
            key_id: None,
        };
        let (priv_key, _pub_key) = store.generate(&spec).expect("keygen");

        let result = store.sign_detached(&priv_key, b"", "ring-Ed25519");
        assert!(result.is_ok(), "Empty (valid UTF-8) message should sign");
    }
}

// =============================================================================
// Finding 5: elliptic-curve private-key operations remain supported
// =============================================================================

mod elliptic_curve_private_key_operations {
    use jacs::keystore::{InMemoryKeyStore, KeySpec, KeyStore};
    use jacs::simple::SimpleAgent;

    #[test]
    fn creates_ed25519_ephemeral_agent() {
        let (agent, info) =
            SimpleAgent::ephemeral(Some("ed25519")).expect("Ed25519 ephemeral should be supported");
        assert!(info.algorithm.contains("Ed25519"));
        let signed = agent
            .sign_message(&serde_json::json!({"curve": "ed25519"}))
            .expect("sign");
        assert!(agent.verify(&signed.raw).expect("verify").valid);
    }

    #[test]
    fn creates_ed25519_keystore_key() {
        let store = InMemoryKeyStore::new("ring-Ed25519");
        let (private_key, public_key) = store
            .generate(&KeySpec {
                algorithm: "ring-Ed25519".to_string(),
                key_id: None,
            })
            .expect("Ed25519 key generation should work");
        assert!(!private_key.is_empty());
        assert_eq!(public_key.len(), 32);
    }

    #[cfg(feature = "a2a")]
    #[test]
    fn ed25519_a2a_key_generation_and_signing() {
        use jacs::a2a::keys::{create_jwk_keys, sign_jws, verify_jws};

        let keys = create_jwk_keys(Some("ring-Ed25519"), Some("ring-Ed25519"))
            .expect("Ed25519 A2A key generation should work");
        let jws = sign_jws(
            br#"{"sub":"test"}"#,
            &keys.a2a_private_key,
            "ring-Ed25519",
            "kid",
        )
        .expect("Ed25519 A2A signing should work");
        let payload = verify_jws(&jws, &keys.a2a_public_key, "ring-Ed25519")
            .expect("Ed25519 A2A verification should work");
        assert_eq!(payload, br#"{"sub":"test"}"#);
    }
}

// =============================================================================
// Signature v2: signed preimage must bind field names and signature metadata
// =============================================================================

mod signature_v2_binding {
    use super::{EnvVarGuard, recompute_jacs_sha256};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use jacs::simple::SimpleAgent;
    use serde_json::{Value, json};

    fn signed_doc() -> (SimpleAgent, Value) {
        let (agent, _) = SimpleAgent::ephemeral(Some("ed25519")).expect("ephemeral agent");
        let signed = agent
            .sign_message(&json!({
                "amount": 100,
                "currency": "USD",
                "recipient": "alice"
            }))
            .expect("sign message");
        let value: Value = serde_json::from_str(&signed.raw).expect("signed JSON");
        (agent, value)
    }

    fn legacy_payload(value: &Value) -> String {
        let fields = value
            .pointer("/jacsSignature/fields")
            .and_then(Value::as_array)
            .expect("legacy fields");
        fields
            .iter()
            .map(|field| {
                let field = field.as_str().expect("field name");
                serde_json_canonicalizer::to_string(&value[field]).expect("canonical value")
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn new_signatures_emit_v2_content_version() {
        let (_agent, value) = signed_doc();
        assert_eq!(
            value
                .pointer("/jacsSignature/signatureContentVersion")
                .and_then(|v| v.as_str()),
            Some("jacs-signature-v2")
        );
    }

    #[test]
    fn refute_native_verify_body_tamper_keeping_identity_fields() {
        // Reproduces the EXACT attack from the disputed finding:
        // tamper the business payload while leaving jacsId/jacsVersion/jacsVersionDate/
        // jacsOriginalVersion/jacsOriginalDate untouched, recompute jacsSha256, and verify.
        let (agent, mut value) = signed_doc();

        eprintln!(
            "SIGNED DOC:\n{}",
            serde_json::to_string_pretty(&value).unwrap()
        );

        // Mutate a signed body field.
        value["amount"] = json!(9000);
        value["recipient"] = json!("mallory");

        recompute_jacs_sha256(&mut value);

        let tampered = serde_json::to_string(&value).expect("serialize tampered doc");
        let result = agent.verify(&tampered).expect("verification result");
        assert!(
            !result.valid,
            "tampering the document body MUST invalidate the signature"
        );
    }

    #[test]
    fn refute_native_verify_added_unsigned_field_is_caught() {
        // Attacker appends a brand-new field not present at signing time.
        // build_signature_content_v2 reconstructs the preimage ONLY from the signed
        // fields list, so the new field would be invisible to the signature check.
        // The jacsSha256 hash (over the whole doc) is what catches this -- verify the
        // full pipeline rejects it.
        let (agent, mut value) = signed_doc();
        value["injected"] = json!("attacker controlled");
        recompute_jacs_sha256(&mut value);

        let tampered = serde_json::to_string(&value).expect("serialize");
        let result = agent.verify(&tampered).expect("verification result");
        assert!(
            !result.valid,
            "adding an unsigned field MUST invalidate the document"
        );
    }

    #[test]
    fn rejects_field_rebinding_even_when_hash_is_recomputed() {
        let (agent, mut value) = signed_doc();
        let original_content = value["content"].clone();

        value["shadowContent"] = original_content;
        value["content"]["amount"] = json!(9000);
        value["jacsSignature"]["fields"] = json!([
            "$schema",
            "jacsId",
            "jacsLevel",
            "jacsOriginalDate",
            "jacsOriginalVersion",
            "jacsType",
            "jacsVersion",
            "jacsVersionDate",
            "shadowContent"
        ]);
        recompute_jacs_sha256(&mut value);

        let tampered = serde_json::to_string(&value).expect("serialize tampered doc");
        let result = agent.verify(&tampered).expect("verification result");
        assert!(
            !result.valid,
            "changing signed field names must invalidate the v2 signature"
        );
    }

    #[test]
    fn rejects_signature_metadata_tampering() {
        for pointer in [
            "/jacsSignature/signingAlgorithm",
            "/jacsSignature/publicKeyHash",
            "/jacsSignature/iat",
            "/jacsSignature/jti",
        ] {
            let (agent, mut value) = signed_doc();
            match pointer {
                "/jacsSignature/signingAlgorithm" => {
                    value["jacsSignature"]["signingAlgorithm"] = json!("pq2025")
                }
                "/jacsSignature/publicKeyHash" => {
                    value["jacsSignature"]["publicKeyHash"] = json!("00")
                }
                "/jacsSignature/iat" => value["jacsSignature"]["iat"] = json!(123),
                "/jacsSignature/jti" => value["jacsSignature"]["jti"] = json!("tampered"),
                _ => unreachable!(),
            }
            recompute_jacs_sha256(&mut value);

            let tampered = serde_json::to_string(&value).expect("serialize tampered doc");
            let result = agent.verify(&tampered).expect("verification result");
            assert!(
                !result.valid,
                "tampering {pointer} must invalidate the v2 signature"
            );
        }
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn missing_algorithm_fails_unless_legacy_detection_is_explicitly_enabled() {
        let (agent, mut value) = signed_doc();
        let _allow_guard = EnvVarGuard::unset("JACS_ALLOW_LEGACY_ALGORITHM_DETECTION");
        value["jacsSignature"]
            .as_object_mut()
            .expect("signature object")
            .remove("signatureContentVersion");
        let signature = agent
            .sign_raw_bytes(legacy_payload(&value).as_bytes())
            .expect("legacy-sign payload");
        value["jacsSignature"]["signature"] = json!(STANDARD.encode(signature));
        value["jacsSignature"]
            .as_object_mut()
            .expect("signature object")
            .remove("signingAlgorithm");
        recompute_jacs_sha256(&mut value);

        let legacy_missing_alg = serde_json::to_string(&value).expect("serialize doc");
        let blocked = agent
            .verify(&legacy_missing_alg)
            .expect("verification result");
        assert!(
            !blocked.valid,
            "legacy algorithm detection should be disabled by default"
        );

        let _legacy_guard = EnvVarGuard::set("JACS_ALLOW_LEGACY_ALGORITHM_DETECTION", "true");
        let allowed = agent
            .verify(&legacy_missing_alg)
            .expect("verification result");
        assert!(
            allowed.valid,
            "explicit legacy algorithm detection opt-in should preserve old documents"
        );
    }
}

// =============================================================================
// Private key encryption v2: new writes use Argon2id JSON envelopes
// =============================================================================

mod private_key_encryption_v2 {
    use jacs::crypt::aes_encrypt::{
        decrypt_private_key_secure_with_password, encrypt_private_key_with_password,
    };

    #[test]
    fn new_private_key_encryption_uses_argon2id_json_envelope() {
        let encrypted =
            encrypt_private_key_with_password(b"private key bytes", "Argon2id!Strong#Password123")
                .expect("encrypt private key");

        let envelope: serde_json::Value =
            serde_json::from_slice(&encrypted).expect("new encryption should be JSON");
        assert_eq!(envelope["jacsEncryptedPrivateKeyVersion"], 2);
        assert_eq!(envelope["kdf"]["name"], "Argon2id");
        assert_eq!(envelope["cipher"], "AES-256-GCM");

        let decrypted =
            decrypt_private_key_secure_with_password(&encrypted, "Argon2id!Strong#Password123")
                .expect("decrypt v2 envelope");
        assert_eq!(decrypted.as_slice(), b"private key bytes");
    }
}

// =============================================================================
// Finding 3: trust_a2a_card must warn about unverified cards
// =============================================================================

mod trust_a2a_card_unverified {
    use jacs::trust::trust_a2a_card;

    /// trust_a2a_card should accept a card with a valid agent ID.
    /// The function docs and tracing warn that cards are NOT cryptographically verified.
    #[test]
    #[serial_test::serial]
    fn trust_a2a_card_accepts_valid_card() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let trust_dir = temp_dir.path().canonicalize().expect("canonical tempdir");
        // SAFETY: tests run serially
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", trust_dir.to_str().unwrap());
        }

        let agent_id = "550e8400-e29b-41d4-a716-446655440000:660e8400-e29b-41d4-a716-446655440000";
        let card_json = r#"{"name": "test-agent", "url": "https://example.com"}"#;

        let result = trust_a2a_card(agent_id, card_json);
        assert!(result.is_ok(), "trust_a2a_card should succeed for valid ID");

        unsafe {
            std::env::remove_var("JACS_TRUST_STORE_DIR");
        }
    }
}

// =============================================================================
// Finding 4: password file permission checks (Unix only)
// =============================================================================

#[cfg(unix)]
mod password_file_permissions {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    #[test]
    fn rejects_world_readable_password_file() {
        let mut tmpfile = NamedTempFile::new().expect("create temp file");
        write!(tmpfile, "my-secret-password").expect("write");
        tmpfile.flush().expect("flush");

        let perms = fs::Permissions::from_mode(0o644);
        fs::set_permissions(tmpfile.path(), perms).expect("set perms");

        let result = jacs::cli_utils::read_password_file_checked(tmpfile.path());
        assert!(
            result.is_err(),
            "Should reject world-readable password file (mode 0644)"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("permission") || err.contains("readable"),
            "Error should mention permissions, got: {}",
            err
        );
    }

    #[test]
    fn rejects_group_readable_password_file() {
        let mut tmpfile = NamedTempFile::new().expect("create temp file");
        write!(tmpfile, "my-secret-password").expect("write");
        tmpfile.flush().expect("flush");

        let perms = fs::Permissions::from_mode(0o640);
        fs::set_permissions(tmpfile.path(), perms).expect("set perms");

        let result = jacs::cli_utils::read_password_file_checked(tmpfile.path());
        assert!(
            result.is_err(),
            "Should reject group-readable password file (mode 0640)"
        );
    }

    #[test]
    fn accepts_owner_only_password_file() {
        let mut tmpfile = NamedTempFile::new().expect("create temp file");
        write!(tmpfile, "my-secret-password").expect("write");
        tmpfile.flush().expect("flush");

        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(tmpfile.path(), perms).expect("set perms");

        let result = jacs::cli_utils::read_password_file_checked(tmpfile.path());
        assert!(result.is_ok(), "Should accept owner-only password file");
        assert_eq!(result.unwrap(), "my-secret-password");
    }

    #[test]
    fn accepts_owner_readonly_password_file() {
        let mut tmpfile = NamedTempFile::new().expect("create temp file");
        write!(tmpfile, "my-secret-password").expect("write");
        tmpfile.flush().expect("flush");

        let perms = fs::Permissions::from_mode(0o400);
        fs::set_permissions(tmpfile.path(), perms).expect("set perms");

        let result = jacs::cli_utils::read_password_file_checked(tmpfile.path());
        assert!(result.is_ok(), "Should accept owner-readonly password file");
    }
}

// =============================================================================
// Finding 1: save_private_key must refuse plaintext write
// =============================================================================

mod save_private_key_no_plaintext {
    use super::EnvVarGuard;
    use serial_test::serial;

    /// When JACS_PRIVATE_KEY_PASSWORD is not set, save_private_key must error.
    /// We test the policy function directly.
    #[test]
    #[serial]
    fn require_password_rejects_empty() {
        let _guard = EnvVarGuard::unset("JACS_PRIVATE_KEY_PASSWORD");
        let result = jacs::keystore::require_encryption_password(None, None);
        assert!(
            result.is_err(),
            "Must reject missing JACS_PRIVATE_KEY_PASSWORD"
        );
    }

    #[test]
    #[serial]
    fn require_password_rejects_whitespace_only() {
        let _guard = EnvVarGuard::set("JACS_PRIVATE_KEY_PASSWORD", "   ");
        let result = jacs::keystore::require_encryption_password(None, None);
        assert!(
            result.is_err(),
            "Must reject whitespace-only JACS_PRIVATE_KEY_PASSWORD"
        );
    }

    #[test]
    #[serial]
    fn require_password_accepts_valid() {
        let _guard = EnvVarGuard::set("JACS_PRIVATE_KEY_PASSWORD", "strong-password-123");
        let result = jacs::keystore::require_encryption_password(None, None);
        assert!(result.is_ok(), "Must accept valid password");
    }
}
