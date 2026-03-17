//! macOS keychain integration tests.
//!
//! These tests use the real macOS Keychain and are gated behind:
//!   `#[cfg(all(target_os = "macos", feature = "keychain-tests"))]`
//!
//! Run with: `cargo test -p jacs --features keychain-tests -- keychain_macos`

#![cfg(all(target_os = "macos", feature = "keychain-tests"))]

use jacs::crypt::aes_encrypt::resolve_private_key_password;
use jacs::keystore::keychain;
use serial_test::serial;

/// RAII guard that restores JACS_PRIVATE_KEY_PASSWORD env var on drop.
struct EnvGuard {
    previous: Option<String>,
}

impl EnvGuard {
    fn new() -> Self {
        let previous = std::env::var("JACS_PRIVATE_KEY_PASSWORD").ok();
        Self { previous }
    }

    /// Unset the env var so keychain fallback is exercised.
    fn unset(&self) {
        // SAFETY: test is #[serial], single-threaded
        unsafe {
            std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            if let Some(ref v) = self.previous {
                std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", v);
            } else {
                std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
            }
        }
    }
}

fn cleanup() {
    let _ = keychain::delete_password();
}

const TEST_PASSWORD: &str = "Test!Keychain#Str0ng2026";

#[test]
#[serial]
fn test_macos_keychain_resolve_password_prefers_env_var() {
    let _guard = EnvGuard::new();
    cleanup();

    // Store one password in keychain
    keychain::store_password("KeychainPassword!123").unwrap();

    // Set a different password in env var
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "EnvVarPassword!456");
    }

    // resolve should prefer env var
    let pw = resolve_private_key_password().unwrap();
    assert_eq!(pw, "EnvVarPassword!456");

    cleanup();
}

#[test]
#[serial]
fn test_macos_keychain_resolve_password_falls_back_to_keychain() {
    let _guard = EnvGuard::new();
    cleanup();

    // Store password in keychain
    keychain::store_password(TEST_PASSWORD).unwrap();

    // Unset env var
    _guard.unset();

    // resolve should fall back to keychain
    let pw = resolve_private_key_password().unwrap();
    assert_eq!(pw, TEST_PASSWORD);

    cleanup();
}

#[test]
#[serial]
fn test_macos_keychain_resolve_password_fails_when_both_empty() {
    let _guard = EnvGuard::new();
    cleanup();

    // No env var, no keychain
    _guard.unset();

    let result = resolve_private_key_password();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("No private key password available"));

    cleanup();
}

#[test]
#[serial]
fn test_macos_keychain_resolve_respects_disabled_backend() {
    let _guard = EnvGuard::new();
    cleanup();

    // Store password in keychain
    keychain::store_password(TEST_PASSWORD).unwrap();

    // Unset password env var
    _guard.unset();

    // Disable keychain backend
    unsafe {
        std::env::set_var("JACS_KEYCHAIN_BACKEND", "disabled");
    }

    // Should fail — keychain is disabled and no env var
    let result = resolve_private_key_password();
    assert!(result.is_err());

    // Cleanup
    unsafe {
        std::env::remove_var("JACS_KEYCHAIN_BACKEND");
    }
    cleanup();
}
