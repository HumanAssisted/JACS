//! Security-focused tests for network endpoint policy.

use jacs::dns::bootstrap::verify_hai_registration_sync;
use serial_test::serial;

const TEST_AGENT_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

#[test]
#[serial]
fn verify_hai_registration_rejects_non_https_api_url() {
    // SAFETY: serial test; env var mutation is isolated for this test.
    unsafe {
        std::env::set_var("HAI_API_URL", "ftp://example.com");
    }

    let result = verify_hai_registration_sync(TEST_AGENT_ID, "deadbeef");

    // SAFETY: serial test cleanup.
    unsafe {
        std::env::remove_var("HAI_API_URL");
    }

    assert!(result.is_err(), "non-HTTPS URL must be rejected");
    let err = result.err().expect("expected policy error");
    assert!(
        err.contains("must use HTTPS"),
        "unexpected error message: {}",
        err
    );
}

#[test]
#[serial]
fn verify_hai_registration_allows_localhost_http_for_testing() {
    // SAFETY: serial test; env var mutation is isolated for this test.
    unsafe {
        std::env::set_var("HAI_API_URL", "http://localhost:1");
    }

    let result = verify_hai_registration_sync(TEST_AGENT_ID, "deadbeef");

    // SAFETY: serial test cleanup.
    unsafe {
        std::env::remove_var("HAI_API_URL");
    }

    // localhost over HTTP is allowed for tests/dev, so failure should be network-related,
    // not a scheme policy failure.
    assert!(
        result.is_err(),
        "localhost test URL should still fail without a server"
    );
    let err = result.err().expect("expected connection error");
    assert!(
        !err.contains("must use HTTPS"),
        "localhost HTTP should be allowed, got: {}",
        err
    );
}
