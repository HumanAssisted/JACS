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
        // SAFETY: tests run serially
        unsafe {
            std::env::set_var("JACS_TRUST_STORE_DIR", temp_dir.path().to_str().unwrap());
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
        let result = jacs::keystore::require_encryption_password(None);
        assert!(
            result.is_err(),
            "Must reject missing JACS_PRIVATE_KEY_PASSWORD"
        );
    }

    #[test]
    #[serial]
    fn require_password_rejects_whitespace_only() {
        let _guard = EnvVarGuard::set("JACS_PRIVATE_KEY_PASSWORD", "   ");
        let result = jacs::keystore::require_encryption_password(None);
        assert!(
            result.is_err(),
            "Must reject whitespace-only JACS_PRIVATE_KEY_PASSWORD"
        );
    }

    #[test]
    #[serial]
    fn require_password_accepts_valid() {
        let _guard = EnvVarGuard::set("JACS_PRIVATE_KEY_PASSWORD", "strong-password-123");
        let result = jacs::keystore::require_encryption_password(None);
        assert!(result.is_ok(), "Must accept valid password");
    }
}
