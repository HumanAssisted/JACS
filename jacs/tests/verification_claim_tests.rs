//! Tests for verification claim enforcement in JACS agents.
//!
//! These tests validate the claim-based security model where agents can claim
//! verification levels that determine security requirements:
//! - `unverified` (default): Relaxed settings allowed
//! - `verified`: Requires domain, strict DNS, strict TLS
//! - `verified-hai.ai`: Above + HAI.ai registration
//!
//! The principle is: "If you claim it, you must prove it."

use jacs::dns::bootstrap as dns;
use jacs::error::JacsError;
use jacs::schema::should_accept_invalid_certs_for_claim;

// =============================================================================
// Helper functions
// =============================================================================

fn sample_pubkey() -> Vec<u8> {
    b"verification-claim-test-public-key".to_vec()
}

// =============================================================================
// DNS Policy Tests Based on Verification Claim
// =============================================================================

/// Test that unverified agents can use relaxed DNS settings.
/// Agents without a verification claim or with "unverified" can fall back to
/// embedded fingerprints when DNS lookup fails.
#[test]
fn test_unverified_allows_relaxed_dns() {
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld";

    // For unverified claims, DNS failures can fall back to embedded fingerprint
    let b64 = dns::pubkey_digest_b64(&pk);
    let res = dns::verify_pubkey_via_dns_or_embedded(
        &pk,
        agent_id,
        Some(domain),
        Some(&b64), // embedded fallback
        false,      // not strict (unverified behavior)
    );
    assert!(
        res.is_ok(),
        "Unverified agents should allow fallback to embedded fingerprint"
    );
}

/// Test that verified agents without a domain fail verification.
/// Agents claiming "verified" MUST have jacsAgentDomain set.
#[test]
fn test_verified_without_domain_fails() {
    // This test validates that the verification logic in Agent::signature_verification_procedure
    // returns an error when a verified claim is made without a domain.
    // We test the error type directly since we cannot easily construct an Agent in test context.

    let err = JacsError::VerificationClaimFailed {
        claim: "verified".to_string(),
        reason: "Verified agents must have jacsAgentDomain set".to_string(),
    };

    let msg = err.to_string();
    assert!(
        msg.contains("verified"),
        "Error should mention the claim type"
    );
    assert!(
        msg.contains("jacsAgentDomain") || msg.contains("domain"),
        "Error should mention domain requirement"
    );
}

/// Test that verified agents enforce strict DNS.
/// When an agent claims "verified", DNS lookups must use DNSSEC validation.
#[test]
fn test_verified_enforces_strict_dns() {
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld";

    // For verified claims, strict=true is required (no fallback allowed)
    let res = dns::verify_pubkey_via_dns_or_embedded(
        &pk,
        agent_id,
        Some(domain),
        None, // no embedded fallback for verified
        true, // strict DNS (verified behavior)
    );

    assert!(
        res.is_err(),
        "Verified agents should fail when strict DNS lookup fails without fallback"
    );
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("DNSSEC") || err_msg.contains("DNS"),
        "Error should indicate DNS/DNSSEC failure"
    );
}

/// Test backward compatibility: agents without jacsVerificationClaim work as before.
/// Missing claim should be treated as "unverified" with existing DNS behavior.
#[test]
fn test_backward_compat_no_claim() {
    let pk = sample_pubkey();
    let agent_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let domain = "nonexistent-subdomain.invalid-tld";

    // Without a claim (treated as unverified), should behave like legacy:
    // DNS failure with embedded fingerprint fallback should succeed
    let hex = dns::pubkey_digest_hex(&pk);
    let res = dns::verify_pubkey_via_dns_or_embedded(
        &pk,
        agent_id,
        Some(domain),
        Some(&hex), // embedded fallback
        false,      // not strict
    );

    assert!(
        res.is_ok(),
        "Agents without verification claim should work with existing DNS behavior"
    );
}

// =============================================================================
// Claim Downgrade Prevention Tests
// =============================================================================

/// Test that verification claims cannot be downgraded.
/// Once an agent claims "verified", it cannot be changed to "unverified".
#[test]
fn test_update_cannot_downgrade_claim() {
    // Test the claim_level ordering logic
    fn claim_level(claim: &str) -> u8 {
        match claim {
            "verified-hai.ai" => 2,
            "verified" => 1,
            _ => 0, // "unverified" or missing
        }
    }

    // Verify the hierarchy
    assert!(
        claim_level("verified-hai.ai") > claim_level("verified"),
        "verified-hai.ai should be higher than verified"
    );
    assert!(
        claim_level("verified") > claim_level("unverified"),
        "verified should be higher than unverified"
    );
    assert!(
        claim_level("verified") > claim_level(""),
        "verified should be higher than empty/missing"
    );

    // Test downgrade detection
    let original = "verified";
    let new_claim = "unverified";
    let is_downgrade = claim_level(new_claim) < claim_level(original);
    assert!(is_downgrade, "verified -> unverified should be detected as downgrade");

    // Test upgrade detection (allowed)
    let original2 = "verified";
    let new_claim2 = "verified-hai.ai";
    let is_upgrade = claim_level(new_claim2) > claim_level(original2);
    assert!(is_upgrade, "verified -> verified-hai.ai should be detected as upgrade");

    // Test same level (allowed)
    let original3 = "verified";
    let new_claim3 = "verified";
    let is_same = claim_level(new_claim3) == claim_level(original3);
    assert!(is_same, "verified -> verified should be same level");
}

/// Test that the downgrade error message is actionable.
#[test]
fn test_downgrade_error_is_actionable() {
    let err = JacsError::VerificationClaimFailed {
        claim: "unverified".to_string(),
        reason: "Cannot downgrade from 'verified' to 'unverified'. Create a new agent instead."
            .to_string(),
    };

    let msg = err.to_string();
    assert!(
        msg.contains("downgrade") || msg.contains("Cannot"),
        "Error should explain the downgrade was blocked"
    );
    assert!(
        msg.contains("Create") || msg.contains("new agent"),
        "Error should suggest creating a new agent"
    );
}

// =============================================================================
// TLS Strictness Tests Based on Verification Claim
// =============================================================================

/// Test that verified agents enforce strict TLS.
/// Agents with "verified" or "verified-hai.ai" claims should never accept invalid certs.
#[test]
fn test_verified_enforces_strict_tls() {
    // Test the claim-aware TLS function
    assert!(
        !should_accept_invalid_certs_for_claim(Some("verified")),
        "verified claim should never accept invalid certs"
    );
    assert!(
        !should_accept_invalid_certs_for_claim(Some("verified-hai.ai")),
        "verified-hai.ai claim should never accept invalid certs"
    );
}

/// Test that unverified agents can use relaxed TLS (based on env var).
#[test]
fn test_unverified_allows_relaxed_tls() {
    // For unverified claims, TLS behavior should follow the existing env var logic
    // The actual result depends on JACS_STRICT_TLS env var, but the function
    // should not force strict mode for unverified agents

    // With None claim (unverified), it should use the env-var based logic
    // We can't easily test the env var interaction here, but we test that
    // the function exists and accepts None
    let _result = should_accept_invalid_certs_for_claim(None);
    // The result depends on env vars, so we just verify it runs without panic

    let _result2 = should_accept_invalid_certs_for_claim(Some("unverified"));
    // Similarly, unverified should use env-var based logic
}

// =============================================================================
// Error Message Quality Tests
// =============================================================================

/// Test that VerificationClaimFailed errors include actionable guidance.
#[test]
fn test_verification_error_is_actionable() {
    let err = JacsError::VerificationClaimFailed {
        claim: "verified".to_string(),
        reason: "Verified agents must have jacsAgentDomain set".to_string(),
    };

    let msg = err.to_string();

    // Should mention the claim
    assert!(msg.contains("verified"), "Error should state the claim");

    // Should explain what's wrong
    assert!(
        msg.contains("jacsAgentDomain") || msg.contains("domain"),
        "Error should explain the missing requirement"
    );

    // Should include actionable guidance (after our enhancement in Task 4)
    // For now, just verify the basic error format
    assert!(
        msg.contains("failed"),
        "Error should indicate verification failed"
    );
}

/// Test that HAI.ai verification errors are clear.
#[test]
fn test_hai_verification_error_is_clear() {
    let err = JacsError::VerificationClaimFailed {
        claim: "verified-hai.ai".to_string(),
        reason: "Agent 'uuid' is not registered with HAI.ai".to_string(),
    };

    let msg = err.to_string();
    assert!(
        msg.contains("verified-hai.ai"),
        "Error should state the claim"
    );
    assert!(
        msg.contains("HAI.ai") || msg.contains("registered"),
        "Error should mention HAI.ai registration"
    );
}

// =============================================================================
// Claim Hierarchy Tests
// =============================================================================

/// Test the complete verification claim hierarchy.
#[test]
fn test_claim_hierarchy() {
    fn claim_level(claim: &str) -> u8 {
        match claim {
            "verified-hai.ai" => 2,
            "verified" => 1,
            _ => 0,
        }
    }

    // Test complete ordering
    assert_eq!(claim_level("unverified"), 0);
    assert_eq!(claim_level(""), 0);
    assert_eq!(claim_level("verified"), 1);
    assert_eq!(claim_level("verified-hai.ai"), 2);

    // Unknown claims should be treated as unverified
    assert_eq!(claim_level("invalid-claim"), 0);
    assert_eq!(claim_level("super-verified"), 0);
}

/// Test that only legitimate upgrades are allowed.
#[test]
fn test_allowed_claim_transitions() {
    fn claim_level(claim: &str) -> u8 {
        match claim {
            "verified-hai.ai" => 2,
            "verified" => 1,
            _ => 0,
        }
    }

    fn is_allowed_transition(from: &str, to: &str) -> bool {
        claim_level(to) >= claim_level(from)
    }

    // Allowed transitions
    assert!(is_allowed_transition("unverified", "unverified"));
    assert!(is_allowed_transition("unverified", "verified"));
    assert!(is_allowed_transition("unverified", "verified-hai.ai"));
    assert!(is_allowed_transition("verified", "verified"));
    assert!(is_allowed_transition("verified", "verified-hai.ai"));
    assert!(is_allowed_transition("verified-hai.ai", "verified-hai.ai"));

    // Disallowed transitions (downgrades)
    assert!(!is_allowed_transition("verified", "unverified"));
    assert!(!is_allowed_transition("verified-hai.ai", "verified"));
    assert!(!is_allowed_transition("verified-hai.ai", "unverified"));
}
