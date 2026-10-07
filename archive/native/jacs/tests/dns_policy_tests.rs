use jacs::dns::bootstrap as dns;

use jacs::storage::jenv::{clear_env_var, get_env_var, has_jenv_override, set_env_var};
use serial_test::serial;

// Public strict/relaxed policy is checked with network explicitly disabled.
// Actual unsigned/forged DNS responses are covered by loopback unit tests.
struct DisabledNetwork(Vec<(&'static str, Option<String>)>);
impl DisabledNetwork {
    fn new() -> Self {
        let previous = ["JACS_ALLOW_NETWORK", "JACS_ALLOW_DNS"]
            .into_iter()
            .map(|key| {
                let value = if has_jenv_override(key) {
                    get_env_var(key, false).unwrap()
                } else {
                    None
                };
                set_env_var(key, "false").unwrap();
                (key, value)
            })
            .collect();
        Self(previous)
    }
}
impl Drop for DisabledNetwork {
    fn drop(&mut self) {
        for (key, previous) in &self.0 {
            if let Some(value) = previous {
                set_env_var(key, value).unwrap();
            } else {
                clear_env_var(key).unwrap();
            }
        }
    }
}

fn sample_pubkey() -> Vec<u8> {
    // Stable bytes for deterministic hashes
    b"dns-policy-test-public-key".to_vec()
}

#[test]
#[serial]
fn dns_fails_strict_returns_err() {
    let _network = DisabledNetwork::new();
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld"; // reserved test name; no network request

    let res = dns::verify_pubkey_via_dns_or_embedded(&pk, agent_id, Some(domain), None, true);
    assert!(res.is_err());
}

#[test]
#[serial]
fn dns_fails_non_strict_with_embedded_b64_ok() {
    let _network = DisabledNetwork::new();
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld";
    let b64 = dns::pubkey_digest_b64(&pk);
    let res =
        dns::verify_pubkey_via_dns_or_embedded(&pk, agent_id, Some(domain), Some(&b64), false);
    assert!(res.is_ok());
}

#[test]
#[serial]
fn dns_fails_non_strict_with_embedded_hex_ok() {
    let _network = DisabledNetwork::new();
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld";
    let hex = dns::pubkey_digest_hex(&pk);
    let res =
        dns::verify_pubkey_via_dns_or_embedded(&pk, agent_id, Some(domain), Some(&hex), false);
    assert!(res.is_ok());
}

#[test]
#[serial]
fn dns_fails_non_strict_with_legacy_hex_ok() {
    let _network = DisabledNetwork::new();
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld";
    let legacy_hex = jacs::crypt::hash::hash_public_key(pk.clone());
    let res = dns::verify_pubkey_via_dns_or_embedded(
        &pk,
        agent_id,
        Some(domain),
        Some(&legacy_hex),
        false,
    );
    assert!(res.is_ok());
}

#[test]
#[serial]
fn disabled_dns_strict_refuses_even_matching_embedded_fingerprint() {
    let _network = DisabledNetwork::new();
    let pk = sample_pubkey();
    let fingerprint = dns::pubkey_digest_b64(&pk);
    assert!(
        dns::verify_pubkey_via_dns_or_embedded(
            &pk,
            "sample-agent",
            Some("example.test"),
            Some(&fingerprint),
            true
        )
        .is_err()
    );
}

#[test]
#[serial]
fn disabled_dns_relaxed_still_refuses_wrong_embedded_fingerprint() {
    let _network = DisabledNetwork::new();
    assert!(
        dns::verify_pubkey_via_dns_or_embedded(
            &sample_pubkey(),
            "sample-agent",
            Some("example.test"),
            Some("wrong-fingerprint"),
            false
        )
        .is_err()
    );
}
