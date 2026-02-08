use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
use std::env;
mod utils;
use utils::{PASSWORD_ENV_VAR, TEST_PASSWORD_ALT, create_agent_v1, create_pq2025_test_agent};

#[test]
fn test_pq2025_keygen() {
    let mut agent = create_pq2025_test_agent().expect("Failed to create pq2025 test agent");

    let result = agent.generate_keys();
    assert!(result.is_ok(), "Key generation failed: {:?}", result.err());

    let public = agent.get_public_key().unwrap();
    println!("ML-DSA-87 public key size: {} bytes", public.len());

    // ML-DSA-87 public keys are 2592 bytes
    assert!(
        public.len() > 2000,
        "Public key should be ~2592 bytes, got {}",
        public.len()
    );
    assert!(
        public.len() < 3000,
        "Public key should be ~2592 bytes, got {}",
        public.len()
    );
}

#[test]
fn test_pq2025_sign_verify() {
    let mut agent = create_pq2025_test_agent().expect("Failed to create pq2025 test agent");

    agent.generate_keys().expect("Key generation failed");

    let test_data = "JACS with ML-DSA-87 - Post-Quantum 2025".to_string();
    let signature = agent.sign_string(&test_data).expect("Signing failed");

    println!("Signature (base64): {}", signature);
    println!("Signature length: {}", signature.len());

    let public = agent.get_public_key().unwrap();
    let result = agent.verify_string(
        &test_data,
        &signature,
        public.clone(),
        Some("pq2025".to_string()),
    );

    assert!(result.is_ok(), "Verification failed: {:?}", result.err());
}

#[test]
fn test_pq2025_sign_verify_wrong_message() {
    let mut agent = create_pq2025_test_agent().expect("Failed to create pq2025 test agent");

    agent.generate_keys().expect("Key generation failed");

    let original_data = "Original message".to_string();
    let tampered_data = "Tampered message".to_string();

    let signature = agent.sign_string(&original_data).expect("Signing failed");

    let public = agent.get_public_key().unwrap();
    let result = agent.verify_string(
        &tampered_data,
        &signature,
        public,
        Some("pq2025".to_string()),
    );

    assert!(
        result.is_err(),
        "Verification should fail for tampered message"
    );
}

#[test]
fn test_pq2025_kem_seal_open() {
    use jacs::crypt::kem::{generate_kem_keys, open, seal};

    let result = generate_kem_keys();
    assert!(
        result.is_ok(),
        "KEM key generation failed: {:?}",
        result.err()
    );

    let (sk, pk) = result.unwrap();
    println!("ML-KEM-768 public key size: {} bytes", pk.len());
    println!("ML-KEM-768 private key size: {} bytes", sk.len());

    let plaintext = b"Secret quantum-safe message for JACS";
    let aad = b"associated data context";

    let seal_result = seal(&pk, aad, plaintext);
    assert!(seal_result.is_ok(), "Seal failed: {:?}", seal_result.err());

    let (kem_ct, nonce, aead_ct) = seal_result.unwrap();
    println!("KEM ciphertext size: {} bytes", kem_ct.len());
    println!("AEAD ciphertext size: {} bytes", aead_ct.len());

    let open_result = open(&sk, &kem_ct, aad, &nonce, &aead_ct);
    assert!(open_result.is_ok(), "Open failed: {:?}", open_result.err());

    let decrypted = open_result.unwrap();
    assert_eq!(
        plaintext,
        &decrypted[..],
        "Decrypted plaintext doesn't match original"
    );
}

#[test]
fn test_pq2025_kem_wrong_key() {
    use jacs::crypt::kem::{generate_kem_keys, open, seal};

    let (_sk1, pk1) = generate_kem_keys().expect("KEM keygen 1 failed");
    let (sk2, _pk2) = generate_kem_keys().expect("KEM keygen 2 failed");

    let plaintext = b"Secret message";
    let aad = b"aad";

    let (kem_ct, nonce, aead_ct) = seal(&pk1, aad, plaintext).expect("Seal failed");

    // Try to decrypt with wrong private key
    let result = open(&sk2, &kem_ct, aad, &nonce, &aead_ct);
    assert!(
        result.is_err(),
        "Decryption should fail with wrong private key"
    );
}

#[test]
fn test_pq2025_kem_wrong_aad() {
    use jacs::crypt::kem::{generate_kem_keys, open, seal};

    let (sk, pk) = generate_kem_keys().expect("KEM keygen failed");

    let plaintext = b"Secret message";
    let aad_original = b"original aad";
    let aad_tampered = b"tampered aad";

    let (kem_ct, nonce, aead_ct) = seal(&pk, aad_original, plaintext).expect("Seal failed");

    // Try to decrypt with wrong AAD
    let result = open(&sk, &kem_ct, aad_tampered, &nonce, &aead_ct);
    assert!(result.is_err(), "Decryption should fail with wrong AAD");
}

// Interop test: verify old signatures still work
#[test]
fn test_legacy_pq_dilithium_still_works() {
    use jacs::config::Config;

    unsafe {
        env::set_var("JACS_USE_SECURITY", "false");
        env::set_var("JACS_DATA_DIRECTORY", "tests/scratch/dilithium_data");
        env::set_var("JACS_KEY_DIRECTORY", "tests/scratch/dilithium_keys");
        env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "dilithium_private.bin");
        env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "dilithium_public.bin");
        env::set_var("JACS_AGENT_KEY_ALGORITHM", "pq-dilithium");
        env::set_var(PASSWORD_ENV_VAR, TEST_PASSWORD_ALT);
    }

    let mut agent = create_agent_v1().expect("Agent schema should have instantiated");

    // Override config with dilithium-specific env vars
    let config = Config::new(
        Some("false".to_string()),
        Some(std::env::var("JACS_DATA_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_KEY_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PRIVATE_KEY_FILENAME").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PUBLIC_KEY_FILENAME").unwrap_or_default()),
        Some("pq-dilithium".to_string()), // Explicit
        Some(std::env::var(PASSWORD_ENV_VAR).unwrap_or_default()),
        None,
        Some("fs".to_string()),
    );
    agent.config = Some(config);
    let gen_result = agent.generate_keys();
    assert!(
        gen_result.is_ok(),
        "Legacy key generation failed: {:?}",
        gen_result.err()
    );

    let data = "Backward compatibility test".to_string();
    let sig_result = agent.sign_string(&data);
    assert!(
        sig_result.is_ok(),
        "Legacy signing failed: {:?}",
        sig_result.err()
    );

    let sig = sig_result.unwrap();
    let pk = agent.get_public_key().unwrap();
    let verify_result = agent.verify_string(&data, &sig, pk, Some("pq-dilithium".to_string()));

    assert!(
        verify_result.is_ok(),
        "Legacy verification failed: {:?}",
        verify_result.err()
    );
}

#[test]
fn test_pq2025_with_agent_save_load() {
    let mut agent = create_pq2025_test_agent().expect("Failed to create pq2025 test agent");

    agent.generate_keys().expect("Key generation failed");

    // Save keys
    let save_result = agent.fs_save_keys();
    assert!(
        save_result.is_ok(),
        "Key save failed: {:?}",
        save_result.err()
    );

    // Create a new agent and load the keys (using the same env vars)
    let mut agent2 = create_pq2025_test_agent().expect("Failed to create second pq2025 test agent");
    let load_result = agent2.fs_load_keys();
    assert!(
        load_result.is_ok(),
        "Key load failed: {:?}",
        load_result.err()
    );

    // Sign with first agent
    let test_data = "Test message for load/save".to_string();
    let signature = agent.sign_string(&test_data).expect("Signing failed");

    // Verify with second agent (loaded keys)
    let public = agent2.get_public_key().unwrap();
    let result = agent2.verify_string(&test_data, &signature, public, Some("pq2025".to_string()));

    assert!(
        result.is_ok(),
        "Verification with loaded keys failed: {:?}",
        result.err()
    );
}
