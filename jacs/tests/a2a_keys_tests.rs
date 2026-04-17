#![cfg(feature = "a2a")]
use jacs::a2a::keys::create_jwk_keys;

#[test]
fn test_create_dual_keys_rejects_rsa() {
    let err = create_jwk_keys(Some("rsa"), Some("rsa"))
        .err()
        .expect("RSA dual-key generation should be blocked");
    assert!(
        err.to_string().contains("RUSTSEC-2023-0071"),
        "error should explain the RSA security block, got: {}",
        err
    );
}
