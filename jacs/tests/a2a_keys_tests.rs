use jacs::a2a::keys::create_jwk_keys;

#[test]
fn test_create_dual_keys_ephemeral() {
    // No environment setup needed - keys are ephemeral
    let result = create_jwk_keys(Some("rsa"), Some("rsa"));

    assert!(result.is_ok(), "Failed to create keys: {:?}", result.err());

    let keys = result.unwrap();
    assert!(!keys.jacs_private_key.is_empty());
    assert!(!keys.a2a_private_key.is_empty());
}
