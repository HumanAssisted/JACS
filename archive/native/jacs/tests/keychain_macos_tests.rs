//! macOS keychain integration tests.
//!
//! These tests use the real macOS Keychain and are gated behind:
//!   `#[cfg(all(target_os = "macos", feature = "keychain-tests"))]`
//!
//! Run with: `cargo test -p jacs --features keychain-tests -- keychain_macos`

#![cfg(all(target_os = "macos", feature = "keychain-tests"))]

use jacs::crypt::aes_encrypt::resolve_private_key_password;
use jacs::keystore::keychain;
use jacs::simple::{CreateAgentParams, SimpleAgent};
use serial_test::serial;
use tempfile::TempDir;

const TEST_AGENT: &str = "__test_macos_agent__";
const TEST_PASSWORD: &str = "Test!Keychain#Str0ng2026";

/// RAII guard that restores JACS_PRIVATE_KEY_PASSWORD and JACS_KEYCHAIN_BACKEND env vars on drop.
struct EnvGuard {
    previous_password: Option<String>,
    previous_backend: Option<String>,
}

impl EnvGuard {
    fn new() -> Self {
        let previous_password = std::env::var("JACS_PRIVATE_KEY_PASSWORD").ok();
        let previous_backend = std::env::var("JACS_KEYCHAIN_BACKEND").ok();
        Self {
            previous_password,
            previous_backend,
        }
    }

    /// Unset the password env var so keychain fallback is exercised.
    /// Clears both the real process env var AND the jenv thread-safe override store.
    fn unset(&self) {
        // SAFETY: test is #[serial], single-threaded
        unsafe {
            std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
        }
        // Also clear the thread-safe override store used by resolve_private_key_password()
        let _ = jacs::storage::jenv::clear_env_var("JACS_PRIVATE_KEY_PASSWORD");
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            // Restore password
            if let Some(ref v) = self.previous_password {
                std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", v);
            } else {
                std::env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
            }
            // Restore backend
            if let Some(ref v) = self.previous_backend {
                std::env::set_var("JACS_KEYCHAIN_BACKEND", v);
            } else {
                std::env::remove_var("JACS_KEYCHAIN_BACKEND");
            }
        }
    }
}

fn cleanup() {
    let _ = keychain::delete_password(TEST_AGENT);
}

#[test]
#[serial]
fn test_macos_keychain_resolve_password_prefers_env_var() {
    let _guard = EnvGuard::new();
    cleanup();

    // Store one password in keychain
    keychain::store_password(TEST_AGENT, "KeychainPassword!123").unwrap();

    // Set a different password in env var
    unsafe {
        std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", "EnvVarPassword!456");
    }

    // resolve should prefer env var
    let pw = resolve_private_key_password(None, Some(TEST_AGENT)).unwrap();
    assert_eq!(pw, "EnvVarPassword!456");

    cleanup();
}

#[test]
#[serial]
fn test_macos_keychain_resolve_password_falls_back_to_keychain() {
    let _guard = EnvGuard::new();
    cleanup();

    // Store password in keychain
    keychain::store_password(TEST_AGENT, TEST_PASSWORD).unwrap();

    // Unset env var
    _guard.unset();

    // resolve should fall back to keychain
    let pw = resolve_private_key_password(None, Some(TEST_AGENT)).unwrap();
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

    let result = resolve_private_key_password(None, Some(TEST_AGENT));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("No private key password available"));

    cleanup();
}

#[test]
#[serial]
fn test_macos_keychain_resolve_skips_keychain_without_agent_id() {
    let _guard = EnvGuard::new();
    cleanup();

    // Store password in keychain
    keychain::store_password(TEST_AGENT, TEST_PASSWORD).unwrap();

    // Unset env var
    _guard.unset();

    // resolve with no agent_id should NOT find the keychain password
    let result = resolve_private_key_password(None, None);
    assert!(result.is_err());

    cleanup();
}

#[test]
#[serial]
fn test_macos_keychain_resolve_respects_disabled_backend() {
    let _guard = EnvGuard::new();
    cleanup();

    // Store password in keychain
    keychain::store_password(TEST_AGENT, TEST_PASSWORD).unwrap();

    // Unset password env var
    _guard.unset();

    // Disable keychain backend
    unsafe {
        std::env::set_var("JACS_KEYCHAIN_BACKEND", "disabled");
    }

    // Should fail -- keychain is disabled and no env var
    let result = resolve_private_key_password(None, Some(TEST_AGENT));
    assert!(result.is_err());

    // EnvGuard restores JACS_KEYCHAIN_BACKEND on drop
    cleanup();
}

/// End-to-end test: store password in keychain FIRST, then create agent,
/// sign, verify -- all without JACS_PRIVATE_KEY_PASSWORD env var.
/// This proves the full stack works from keychain to signed document.
#[test]
#[serial]
fn test_macos_keychain_agent_sign_verify_no_env_var() {
    let _guard = EnvGuard::new();
    cleanup();

    let password = "Test!EndToEnd#Str0ng2026";

    // 1. Store password in keychain under a known agent_id and unset env var
    let agent_id = "__test_e2e_agent__";
    keychain::store_password(agent_id, password).unwrap();
    _guard.unset(); // Remove JACS_PRIVATE_KEY_PASSWORD from env AND jenv store

    // Sanity check: keychain has the password, env var does not
    assert_eq!(
        keychain::get_password(agent_id).unwrap(),
        Some(password.to_string())
    );
    let resolved = resolve_private_key_password(None, Some(agent_id))
        .expect("resolve should find keychain password");
    assert_eq!(resolved, password);

    // 2. Create agent in a temp directory. The password param is required for
    //    create_with_params (it sets the env var internally for key generation),
    //    but after creation the env var is restored/cleared by EnvRestoreGuard.
    let tmp = TempDir::new().expect("create temp dir");
    let data_dir = tmp.path().join("data");
    let key_dir = tmp.path().join("keys");
    let config_path = tmp.path().join("jacs.config.json");

    let params = CreateAgentParams::builder()
        .name("keychain-e2e-agent")
        .password(password)
        .algorithm("ring-Ed25519")
        .data_directory(data_dir.to_str().unwrap())
        .key_directory(key_dir.to_str().unwrap())
        .config_path(config_path.to_str().unwrap())
        .build();
    let (_agent, _info) = SimpleAgent::create_with_params(params).expect("create agent");
    // Drop the agent -- we'll reload from disk to prove keychain path works
    drop(_agent);

    // 3. Ensure env var is still cleared (create_with_params restores on drop)
    _guard.unset();

    // 4. Load agent from disk -- password resolved via keychain
    let loaded_agent = SimpleAgent::load(Some(config_path.to_str().unwrap()), None)
        .expect("load agent from disk with keychain password");

    // 5. Sign a document with the reloaded agent
    let signed = loaded_agent
        .sign_message(&serde_json::json!({"test": "keychain e2e"}))
        .expect("sign message with keychain password");

    // 6. Verify the signed document
    let result = loaded_agent.verify(&signed.raw).expect("verify signed doc");
    assert!(
        result.valid,
        "Verification failed after keychain-based load: {:?}",
        result.errors
    );

    let _ = keychain::delete_password(agent_id);
    cleanup();
}
