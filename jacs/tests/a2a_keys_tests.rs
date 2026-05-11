#![cfg(feature = "a2a")]
use jacs::a2a::keys::create_jwk_keys;

#[test]
fn test_create_dual_keys_ed25519() {
    let keys = create_jwk_keys(Some("ring-Ed25519"), Some("ring-Ed25519"))
        .expect("Ed25519 dual-key generation should succeed");
    assert_eq!(keys.jacs_algorithm, "ring-Ed25519");
    assert_eq!(keys.a2a_algorithm, "ring-Ed25519");
    assert_eq!(keys.jacs_public_key.len(), 32);
    assert_eq!(keys.a2a_public_key.len(), 32);
}
