use jacs::agent::payloads::PayloadTraits;
use serde_json::json;
use serial_test::serial;
use std::time::Duration;

mod utils;
use utils::load_test_agent_one;

struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        // SAFETY: this test module is serial; env mutation is isolated.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }

    fn unset(key: &'static str) -> Self {
        let previous = std::env::var(key).ok();
        // SAFETY: this test module is serial; env mutation is isolated.
        unsafe {
            std::env::remove_var(key);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: this test module is serial; env mutation is isolated.
        unsafe {
            if let Some(value) = &self.previous {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}

#[test]
#[serial]
fn verify_payload_default_window_allows_recent_message() {
    let _guard = EnvVarGuard::unset("JACS_PAYLOAD_MAX_REPLAY_SECONDS");
    let mut agent = load_test_agent_one();
    let signed = agent
        .sign_payload(json!({ "test": "default-window" }))
        .expect("payload signing should succeed");

    std::thread::sleep(Duration::from_secs(2));

    let payload = agent
        .verify_payload(signed, None)
        .expect("default 5-minute replay window should accept a 2-second-old payload");
    assert_eq!(payload["test"], "default-window");
}

#[test]
#[serial]
fn verify_payload_env_override_can_be_strict() {
    let _guard = EnvVarGuard::set("JACS_PAYLOAD_MAX_REPLAY_SECONDS", "1");
    let mut agent = load_test_agent_one();
    let signed = agent
        .sign_payload(json!({ "test": "strict-env-window" }))
        .expect("payload signing should succeed");

    std::thread::sleep(Duration::from_secs(2));

    let err = agent
        .verify_payload(signed, None)
        .expect_err("strict 1-second env replay window should reject old payload");
    assert!(
        err.to_string().contains("Signature too old"),
        "unexpected error: {}",
        err
    );
}

#[test]
#[serial]
fn verify_payload_explicit_argument_overrides_env_window() {
    let _guard = EnvVarGuard::set("JACS_PAYLOAD_MAX_REPLAY_SECONDS", "1");
    let mut agent = load_test_agent_one();
    let signed = agent
        .sign_payload(json!({ "test": "explicit-override" }))
        .expect("payload signing should succeed");

    std::thread::sleep(Duration::from_secs(2));

    let payload = agent
        .verify_payload(signed, Some(300))
        .expect("explicit replay window should override strict env setting");
    assert_eq!(payload["test"], "explicit-override");
}

#[test]
#[serial]
fn verify_payload_replay_nonce_retention_tracks_payload_window() {
    let _guard_payload = EnvVarGuard::set("JACS_PAYLOAD_MAX_REPLAY_SECONDS", "5");
    let _guard_iat = EnvVarGuard::set("JACS_MAX_IAT_SKEW_SECONDS", "1");
    let mut agent = load_test_agent_one();
    let signed = agent
        .sign_payload(json!({ "test": "replay-window-alignment" }))
        .expect("payload signing should succeed");

    agent
        .verify_payload(signed.clone(), None)
        .expect("first verification should succeed");

    std::thread::sleep(Duration::from_secs(2));

    let err = agent
        .verify_payload(signed, None)
        .expect_err("replay nonce should remain blocked for the full payload window");
    assert!(
        err.to_string().contains("Replay attack detected"),
        "unexpected error: {}",
        err
    );
}
