//! OS keychain integration for private key password storage.
//!
//! When the `keychain` feature is enabled, this module wraps the `keyring` crate
//! to store/retrieve JACS private key passwords in the OS credential store
//! (macOS Keychain, Linux Secret Service via D-Bus).
//!
//! When the feature is disabled, stub functions return `None`/errors so callers
//! can call `keychain::get_password()` unconditionally without `#[cfg]` at every call site.

use crate::error::JacsError;

pub const SERVICE_NAME: &str = "jacs-private-key";
pub const DEFAULT_USER: &str = "default";

// =============================================================================
// Feature-enabled implementation
// =============================================================================

#[cfg(feature = "keychain")]
mod inner {
    use super::*;
    use keyring::{Entry, Error as KeyringError};

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

    fn make_entry(user: &str) -> Result<Entry, JacsError> {
        Entry::new(SERVICE_NAME, user).map_err(map_keyring_error)
    }

    pub fn store_password(password: &str) -> Result<(), JacsError> {
        if password.is_empty() {
            return Err(JacsError::ConfigError(
                "Cannot store an empty password in the OS keychain.".to_string(),
            ));
        }
        let entry = make_entry(DEFAULT_USER)?;
        entry.set_password(password).map_err(map_keyring_error)
    }

    pub fn store_password_for_agent(agent_id: &str, password: &str) -> Result<(), JacsError> {
        if password.is_empty() {
            return Err(JacsError::ConfigError(
                "Cannot store an empty password in the OS keychain.".to_string(),
            ));
        }
        let entry = make_entry(agent_id)?;
        entry.set_password(password).map_err(map_keyring_error)
    }

    pub fn get_password() -> Result<Option<String>, JacsError> {
        let entry = make_entry(DEFAULT_USER)?;
        match entry.get_password() {
            Ok(pw) => Ok(Some(pw)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(map_keyring_error(e)),
        }
    }

    pub fn get_password_for_agent(agent_id: &str) -> Result<Option<String>, JacsError> {
        let entry = make_entry(agent_id)?;
        match entry.get_password() {
            Ok(pw) => Ok(Some(pw)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(map_keyring_error(e)),
        }
    }

    pub fn delete_password() -> Result<(), JacsError> {
        let entry = make_entry(DEFAULT_USER)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(KeyringError::NoEntry) => Ok(()), // idempotent
            Err(e) => Err(map_keyring_error(e)),
        }
    }

    pub fn delete_password_for_agent(agent_id: &str) -> Result<(), JacsError> {
        let entry = make_entry(agent_id)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(KeyringError::NoEntry) => Ok(()), // idempotent
            Err(e) => Err(map_keyring_error(e)),
        }
    }

    pub fn is_available() -> bool {
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

    pub fn store_password(_password: &str) -> Result<(), JacsError> {
        Err(JacsError::ConfigError(
            "OS keychain support is not enabled. Recompile with the 'keychain' feature flag."
                .to_string(),
        ))
    }

    pub fn store_password_for_agent(_agent_id: &str, _password: &str) -> Result<(), JacsError> {
        Err(JacsError::ConfigError(
            "OS keychain support is not enabled. Recompile with the 'keychain' feature flag."
                .to_string(),
        ))
    }

    pub fn get_password() -> Result<Option<String>, JacsError> {
        Ok(None)
    }

    pub fn get_password_for_agent(_agent_id: &str) -> Result<Option<String>, JacsError> {
        Ok(None)
    }

    pub fn delete_password() -> Result<(), JacsError> {
        Err(JacsError::ConfigError(
            "OS keychain support is not enabled. Recompile with the 'keychain' feature flag."
                .to_string(),
        ))
    }

    pub fn delete_password_for_agent(_agent_id: &str) -> Result<(), JacsError> {
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
            assert!(get_password().unwrap().is_none());
        }

        #[test]
        fn test_stub_get_for_agent_returns_none() {
            assert!(get_password_for_agent("test-agent").unwrap().is_none());
        }

        #[test]
        fn test_stub_is_available_false() {
            assert!(!is_available());
        }

        #[test]
        fn test_stub_store_returns_error() {
            assert!(store_password("test").is_err());
        }

        #[test]
        fn test_stub_delete_returns_error() {
            assert!(delete_password().is_err());
        }
    }

    // --- Real keychain tests (only when feature enabled + OS-specific) ---
    // These tests use the real OS keychain. They are gated behind the
    // `keychain-tests` feature so they don't run in CI by default.

    #[cfg(all(feature = "keychain-tests", target_os = "macos"))]
    mod macos_tests {
        use super::*;
        use serial_test::serial;

        // Use a unique service-scoped user to avoid collisions with real data.
        // Tests clean up after themselves.
        const TEST_USER: &str = "__jacs_test_keychain__";
        const TEST_AGENT: &str = "__jacs_test_agent_id__";

        fn cleanup() {
            let _ = delete_password();
            let _ = delete_password_for_agent(TEST_AGENT);
        }

        #[test]
        #[serial]
        fn test_store_and_get_password() {
            cleanup();
            store_password("Test!Strong#Pass123").unwrap();
            let pw = get_password().unwrap();
            assert_eq!(pw, Some("Test!Strong#Pass123".to_string()));
            cleanup();
        }

        #[test]
        #[serial]
        fn test_get_password_when_none_stored() {
            cleanup();
            let pw = get_password().unwrap();
            assert!(pw.is_none());
        }

        #[test]
        #[serial]
        fn test_delete_password() {
            cleanup();
            store_password("Test!Strong#Pass123").unwrap();
            delete_password().unwrap();
            let pw = get_password().unwrap();
            assert!(pw.is_none());
        }

        #[test]
        #[serial]
        fn test_delete_when_none_stored() {
            cleanup();
            // Should not error — idempotent
            delete_password().unwrap();
        }

        #[test]
        #[serial]
        fn test_is_available() {
            assert!(is_available());
        }

        #[test]
        #[serial]
        fn test_store_empty_password_rejected() {
            cleanup();
            let result = store_password("");
            assert!(result.is_err());
        }

        #[test]
        #[serial]
        fn test_store_overwrite() {
            cleanup();
            store_password("PasswordA!123").unwrap();
            store_password("PasswordB!456").unwrap();
            let pw = get_password().unwrap();
            assert_eq!(pw, Some("PasswordB!456".to_string()));
            cleanup();
        }

        #[test]
        #[serial]
        fn test_agent_specific_password() {
            cleanup();
            store_password("Default!Pass123").unwrap();
            store_password_for_agent(TEST_AGENT, "Agent!Pass456").unwrap();

            assert_eq!(get_password().unwrap(), Some("Default!Pass123".to_string()));
            assert_eq!(
                get_password_for_agent(TEST_AGENT).unwrap(),
                Some("Agent!Pass456".to_string())
            );

            delete_password_for_agent(TEST_AGENT).unwrap();
            assert!(get_password_for_agent(TEST_AGENT).unwrap().is_none());
            // Default still intact
            assert!(get_password().unwrap().is_some());
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
            let result = store_password("");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("empty"));
        }

        #[test]
        fn test_store_empty_password_for_agent_rejected() {
            let result = store_password_for_agent("test", "");
            assert!(result.is_err());
        }
    }
}
