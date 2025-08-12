use jacs::dns::bootstrap as dns;

// These tests exercise the DNS helper directly. They intentionally point at a domain
// that is unlikely to exist so the DNSSEC lookup path fails, allowing us to test
// strict vs non-strict behavior and embedded fallbacks deterministically.

fn sample_pubkey() -> Vec<u8> {
    // Stable bytes for deterministic hashes
    b"dns-policy-test-public-key".to_vec()
}

#[test]
fn dns_fails_strict_returns_err() {
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld"; // ensure lookup fails

    let res = dns::verify_pubkey_via_dns_or_embedded(&pk, agent_id, Some(domain), None);
    assert!(res.is_err());
}

#[test]
fn dns_fails_non_strict_with_embedded_b64_ok() {
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld";
    let b64 = dns::pubkey_digest_b64(&pk);
    let res = dns::verify_pubkey_via_dns_or_embedded(&pk, agent_id, Some(domain), Some(&b64));
    assert!(res.is_ok());
}

#[test]
fn dns_fails_non_strict_with_embedded_hex_ok() {
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld";
    let hex = dns::pubkey_digest_hex(&pk);
    let res = dns::verify_pubkey_via_dns_or_embedded(&pk, agent_id, Some(domain), Some(&hex));
    assert!(res.is_ok());
}

#[test]
fn dns_fails_non_strict_with_legacy_hex_ok() {
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld";
    let legacy_hex = jacs::crypt::hash::hash_public_key(pk.clone());
    let res =
        dns::verify_pubkey_via_dns_or_embedded(&pk, agent_id, Some(domain), Some(&legacy_hex));
    assert!(res.is_ok());
}
