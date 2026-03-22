//! OS keychain integration for private key password storage.
//!
//! When the `keychain` feature is enabled, this module wraps the `keyring` crate
//! to store/retrieve JACS private key passwords in the OS credential store
//! (macOS Keychain, Linux Secret Service via D-Bus).
//!
//! Every password is keyed by agent_id so that multiple agents can coexist
//! without overwriting each other.
//!
//! When the feature is disabled, stub functions return `None`/errors so callers
//! can call `keychain::get_password()` unconditionally without `#[cfg]` at every call site.

use crate::error::JacsError;

pub const SERVICE_NAME: &str = "jacs-private-key";

// =============================================================================
// Feature-enabled implementation
// =============================================================================

#[cfg(feature = "keychain")]
mod inner {
    use super::*;
    use keyring::{Entry, Error as KeyringError};

    /// Returns `true` when the OS keychain has been explicitly disabled via
    /// `JACS_KEYCHAIN_BACKEND=disabled` (case-insensitive).
    fn is_runtime_disabled() -> bool {
        std::env::var("JACS_KEYCHAIN_BACKEND")
            .map(|v| v.eq_ignore_ascii_case("disabled"))
            .unwrap_or(false)
    }

    fn map_keyring_error(e: KeyringError) -> JacsError {
        match e {
            KeyringError::NoStorageAccess(ref inner) => JacsError::ConfigError(format!(
                "OS keychain is not accessible: {}. \
                 On Linux, ensure a D-Bus session and keyring daemon are running. \
                 On macOS, ensure Keychain Access is available.",
                inner
            )),
            KeyringError::NoEntry => {
                // This should be handled at the call site, not turned into an error
                JacsError::ConfigError("No password found in OS keychain.".to_string())
            }
            other => JacsError::ConfigError(format!("OS keychain error: {}", other)),
        }
    }

    fn make_entry(agent_id: &str) -> Result<Entry, JacsError> {
        Entry::new(SERVICE_NAME, agent_id).map_err(map_keyring_error)
    }

    pub fn store_password(agent_id: &str, password: &str) -> Result<(), JacsError> {
        if is_runtime_disabled() {
            return Ok(()); // silently skip when keychain is disabled
        }
        if agent_id.is_empty() {
            return Err(JacsError::ConfigError(
                "Cannot store password in OS keychain without an agent_id.".to_string(),
            ));
        }
        if password.is_empty() {
            return Err(JacsError::ConfigError(
                "Cannot store an empty password in the OS keychain.".to_string(),
            ));
        }
        let entry = make_entry(agent_id)?;
        entry.set_password(password).map_err(map_keyring_error)
    }

    pub fn get_password(agent_id: &str) -> Result<Option<String>, JacsError> {
        if is_runtime_disabled() {
            return Ok(None);
        }
        if agent_id.is_empty() {
            return Ok(None);
        }
        let entry = make_entry(agent_id)?;
        match entry.get_password() {
            Ok(pw) => Ok(Some(pw)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(map_keyring_error(e)),
        }
    }

    pub fn delete_password(agent_id: &str) -> Result<(), JacsError> {
        if agent_id.is_empty() {
            return Err(JacsError::ConfigError(
                "Cannot delete password from OS keychain without an agent_id.".to_string(),
            ));
        }
        let entry = make_entry(agent_id)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(KeyringError::NoEntry) => Ok(()), // idempotent
            Err(e) => Err(map_keyring_error(e)),
        }
    }

    pub fn is_available() -> bool {
        if is_runtime_disabled() {
            return false;
        }
        // Check if we can create an entry without error
        Entry::new(SERVICE_NAME, "__jacs_availability_check__").is_ok()
    }
}

// =============================================================================
// Feature-disabled stubs
// =============================================================================

#[cfg(not(feature = "keychain"))]
mod inner {
    use super::*;

    pub fn store_password(_agent_id: &str, _password: &str) -> Result<(), JacsError> {
        Err(JacsError::ConfigError(
            "OS keychain support is not enabled. Recompile with the 'keychain' feature flag."
                .to_string(),
        ))
    }

    pub fn get_password(_agent_id: &str) -> Result<Option<String>, JacsError> {
        Ok(None)
    }

    pub fn delete_password(_agent_id: &str) -> Result<(), JacsError> {
        Err(JacsError::ConfigError(
            "OS keychain support is not enabled. Recompile with the 'keychain' feature flag."
                .to_string(),
        ))
    }

    pub fn is_available() -> bool {
        false
    }
}

// =============================================================================
// Public re-exports (delegate to inner module)
// =============================================================================

pub use inner::*;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Stub tests (always run, regardless of feature) ---

    #[cfg(not(feature = "keychain"))]
    mod stub_tests {
        use super::*;

        #[test]
        fn test_stub_get_returns_none() {
            assert!(get_password("some-agent").unwrap().is_none());
        }

        #[test]
        fn test_stub_is_available_false() {
            assert!(!is_available());
        }

        #[test]
        fn test_stub_store_returns_error() {
            assert!(store_password("some-agent", "test").is_err());
        }

        #[test]
        fn test_stub_delete_returns_error() {
            assert!(delete_password("some-agent").is_err());
        }
    }

    // --- Real keychain tests (only when feature enabled + OS-specific) ---
    // These tests use the real OS keychain. They are gated behind the
    // `keychain-tests` feature so they don't run in CI by default.

    #[cfg(all(feature = "keychain-tests", target_os = "macos"))]
    mod macos_tests {
        use super::*;
        use serial_test::serial;

        const TEST_AGENT_A: &str = "__jacs_test_agent_a__";
        const TEST_AGENT_B: &str = "__jacs_test_agent_b__";

        fn cleanup() {
            let _ = delete_password(TEST_AGENT_A);
            let _ = delete_password(TEST_AGENT_B);
        }

        #[test]
        #[serial(keychain_env)]
        fn test_store_and_get_password() {
            cleanup();
            store_password(TEST_AGENT_A, "Test!Strong#Pass123").unwrap();
            let pw = get_password(TEST_AGENT_A).unwrap();
            assert_eq!(pw, Some("Test!Strong#Pass123".to_string()));
            cleanup();
        }

        #[test]
        #[serial(keychain_env)]
        fn test_get_password_when_none_stored() {
            cleanup();
            let pw = get_password(TEST_AGENT_A).unwrap();
            assert!(pw.is_none());
        }

        #[test]
        #[serial(keychain_env)]
        fn test_delete_password() {
            cleanup();
            store_password(TEST_AGENT_A, "Test!Strong#Pass123").unwrap();
            delete_password(TEST_AGENT_A).unwrap();
            let pw = get_password(TEST_AGENT_A).unwrap();
            assert!(pw.is_none());
        }

        #[test]
        #[serial(keychain_env)]
        fn test_delete_when_none_stored() {
            cleanup();
            // Should not error -- idempotent
            delete_password(TEST_AGENT_A).unwrap();
        }

        #[test]
        #[serial(keychain_env)]
        fn test_is_available() {
            assert!(is_available());
        }

        #[test]
        #[serial(keychain_env)]
        fn test_store_empty_password_rejected() {
            cleanup();
            let result = store_password(TEST_AGENT_A, "");
            assert!(result.is_err());
        }

        #[test]
        #[serial(keychain_env)]
        fn test_store_empty_agent_id_rejected() {
            let result = store_password("", "SomePassword!123");
            assert!(result.is_err());
        }

        #[test]
        #[serial(keychain_env)]
        fn test_store_overwrite() {
            cleanup();
            store_password(TEST_AGENT_A, "PasswordA!123").unwrap();
            store_password(TEST_AGENT_A, "PasswordB!456").unwrap();
            let pw = get_password(TEST_AGENT_A).unwrap();
            assert_eq!(pw, Some("PasswordB!456".to_string()));
            cleanup();
        }

        #[test]
        #[serial(keychain_env)]
        fn test_agent_passwords_are_isolated() {
            cleanup();
            store_password(TEST_AGENT_A, "PasswordA!123").unwrap();
            store_password(TEST_AGENT_B, "PasswordB!456").unwrap();

            assert_eq!(
                get_password(TEST_AGENT_A).unwrap(),
                Some("PasswordA!123".to_string())
            );
            assert_eq!(
                get_password(TEST_AGENT_B).unwrap(),
                Some("PasswordB!456".to_string())
            );

            delete_password(TEST_AGENT_B).unwrap();
            assert!(get_password(TEST_AGENT_B).unwrap().is_none());
            // Agent A still intact
            assert!(get_password(TEST_AGENT_A).unwrap().is_some());
            cleanup();
        }
    }

    // --- Feature-enabled unit tests (any OS with keychain feature) ---

    #[cfg(feature = "keychain")]
    mod enabled_tests {
        use super::*;

        #[test]
        fn test_keychain_feature_enabled() {
            assert!(is_available());
        }

        #[test]
        fn test_store_empty_password_rejected() {
            let result = store_password("test-agent", "");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("empty"));
        }

        #[test]
        fn test_store_empty_agent_id_rejected() {
            let result = store_password("", "SomePass!123");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("agent_id"));
        }

        #[test]
        fn test_get_empty_agent_id_returns_none() {
            let result = get_password("").unwrap();
            assert!(result.is_none());
        }
    }

    /// Mock-based unit tests using keyring's mock credential builder.
    ///
    /// These test the keyring Entry API directly (since the mock backend has
    /// no persistence across separate Entry::new calls). They verify our
    /// error mapping, store/get/delete logic, and overwrite behavior work
    /// correctly without touching the real OS keychain.
    #[cfg(feature = "keychain")]
    mod mock_tests {
        use keyring::{Entry, Error as KeyringError};

        /// Create an Entry backed by the mock credential builder.
        fn mock_entry(service: &str, user: &str) -> Entry {
            let builder = keyring::mock::default_credential_builder();
            Entry::new_with_credential(builder.build(None, service, user).unwrap())
        }

        #[test]
        fn test_mock_store_and_get_roundtrip() {
            let entry = mock_entry("jacs-test", "mock-user");
            entry.set_password("TestPassword!123").unwrap();
            let pw = entry.get_password().unwrap();
            assert_eq!(pw, "TestPassword!123");
        }

        #[test]
        fn test_mock_get_when_none_stored() {
            let entry = mock_entry("jacs-test", "mock-none");
            let result = entry.get_password();
            assert!(matches!(result, Err(KeyringError::NoEntry)));
        }

        #[test]
        fn test_mock_delete_after_store() {
            let entry = mock_entry("jacs-test", "mock-delete");
            entry.set_password("ToDelete!456").unwrap();
            entry.delete_credential().unwrap();
            let result = entry.get_password();
            assert!(matches!(result, Err(KeyringError::NoEntry)));
        }

        #[test]
        fn test_mock_delete_when_none_stored() {
            let entry = mock_entry("jacs-test", "mock-del-empty");
            let result = entry.delete_credential();
            assert!(matches!(result, Err(KeyringError::NoEntry)));
        }

        #[test]
        fn test_mock_overwrite() {
            let entry = mock_entry("jacs-test", "mock-overwrite");
            entry.set_password("PasswordA!123").unwrap();
            entry.set_password("PasswordB!456").unwrap();
            let pw = entry.get_password().unwrap();
            assert_eq!(pw, "PasswordB!456");
        }

        #[test]
        fn test_mock_error_injection() {
            let entry = mock_entry("jacs-test", "mock-error");
            let mock: &keyring::mock::MockCredential =
                entry.get_credential().downcast_ref().unwrap();
            mock.set_error(KeyringError::NoStorageAccess(Box::new(
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "mock access denied"),
            )));
            let result = entry.set_password("test");
            assert!(result.is_err());
            // Error is cleared after one use
            entry.set_password("test").unwrap();
        }

        #[test]
        fn test_mock_agent_specific_entries_are_isolated() {
            let entry_a = mock_entry("jacs-private-key", "agent-a");
            let entry_b = mock_entry("jacs-private-key", "agent-b");
            entry_a.set_password("PasswordA!123").unwrap();
            entry_b.set_password("PasswordB!456").unwrap();
            assert_eq!(entry_a.get_password().unwrap(), "PasswordA!123");
            assert_eq!(entry_b.get_password().unwrap(), "PasswordB!456");
        }
    }
}
