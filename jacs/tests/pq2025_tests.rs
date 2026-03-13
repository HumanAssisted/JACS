#![cfg(feature = "pq-tests")]
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::loaders::FileLoader;
use jacs::config::Config;
use jacs::crypt::KeyManager;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
mod utils;
use utils::{PASSWORD_ENV_VAR, TEST_PASSWORD, create_agent_v1};

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("test environment lock poisoned")
}

fn configure_unique_pq2025_env(test_name: &str) -> (PathBuf, PathBuf) {
    let sanitized_name: String = test_name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
        .as_nanos();
    let base = PathBuf::from("tests").join("scratch").join(format!(
        "jacs-pq2025-{sanitized_name}-{}-{nonce}",
        std::process::id()
    ));
    let data_dir = base.join("data");
    let key_dir = base.join("keys");
    std::fs::create_dir_all(&data_dir).expect("failed to create test data directory");
    std::fs::create_dir_all(&key_dir).expect("failed to create test key directory");

    unsafe {
        std::env::set_var("JACS_USE_SECURITY", "false");
        std::env::set_var(
            "JACS_DATA_DIRECTORY",
            data_dir.to_string_lossy().to_string(),
        );
        std::env::set_var("JACS_KEY_DIRECTORY", key_dir.to_string_lossy().to_string());
        std::env::set_var("JACS_AGENT_PRIVATE_KEY_FILENAME", "pq2025_private.bin.enc");
        std::env::set_var("JACS_AGENT_PUBLIC_KEY_FILENAME", "pq2025_public.bin");
        std::env::set_var("JACS_AGENT_KEY_ALGORITHM", "pq2025");
        std::env::set_var(PASSWORD_ENV_VAR, TEST_PASSWORD);
    }

    (data_dir, key_dir)
}

fn create_pq2025_test_agent_from_env() -> Result<jacs::agent::Agent, Box<dyn std::error::Error>> {
    let mut agent = create_agent_v1()?;
    let config = Config::new(
        Some("false".to_string()),
        Some(std::env::var("JACS_DATA_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_KEY_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PRIVATE_KEY_FILENAME").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PUBLIC_KEY_FILENAME").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_KEY_ALGORITHM").unwrap_or_default()),
        Some(std::env::var(PASSWORD_ENV_VAR).unwrap_or_default()),
        None,
        Some("fs".to_string()),
    );
    agent.config = Some(config);
    Ok(agent)
}

#[test]
fn test_pq2025_keygen() {
    let _env_guard = env_guard();
    let _ = configure_unique_pq2025_env("test_pq2025_keygen");
    let mut agent =
        create_pq2025_test_agent_from_env().expect("Failed to create pq2025 test agent");

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
    let _env_guard = env_guard();
    let _ = configure_unique_pq2025_env("test_pq2025_sign_verify");
    let mut agent =
        create_pq2025_test_agent_from_env().expect("Failed to create pq2025 test agent");

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
    let _env_guard = env_guard();
    let _ = configure_unique_pq2025_env("test_pq2025_sign_verify_wrong_message");
    let mut agent =
        create_pq2025_test_agent_from_env().expect("Failed to create pq2025 test agent");

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
    let _env_guard = env_guard();
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
    let _env_guard = env_guard();
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
    let _env_guard = env_guard();
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

#[test]
fn test_supported_algorithms_exclude_legacy_dilithium() {
    let _env_guard = env_guard();
    let supported = jacs::crypt::supported_verification_algorithms();
    let pq_supported = jacs::crypt::supported_pq_algorithms();

    assert!(
        supported.contains(&"pq2025"),
        "Expected pq2025 in supported verification algorithms"
    );
    assert!(
        !supported.contains(&"pq-dilithium"),
        "Legacy pq-dilithium should not be supported"
    );
    assert_eq!(
        pq_supported,
        vec!["pq2025"],
        "Expected only pq2025 in supported post-quantum algorithms"
    );
}

#[test]
fn test_pq_dilithium_key_generation_is_rejected() {
    let _env_guard = env_guard();
    let _ = configure_unique_pq2025_env("test_pq_dilithium_key_generation_is_rejected");

    let mut agent = create_agent_v1().expect("Agent schema should have instantiated");
    let config = Config::new(
        Some("false".to_string()),
        Some(std::env::var("JACS_DATA_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_KEY_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PRIVATE_KEY_FILENAME").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PUBLIC_KEY_FILENAME").unwrap_or_default()),
        Some("pq-dilithium".to_string()),
        Some(std::env::var(PASSWORD_ENV_VAR).unwrap_or_default()),
        None,
        Some("fs".to_string()),
    );
    agent.config = Some(config);

    let err = agent
        .generate_keys()
        .expect_err("pq-dilithium key generation should be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("Unsupported key algorithm"),
        "Unexpected error for rejected legacy algorithm: {}",
        msg
    );
}

#[test]
fn test_verify_rejects_legacy_dilithium_algorithm_hint() {
    let _env_guard = env_guard();
    let _ = configure_unique_pq2025_env("test_verify_rejects_legacy_dilithium_algorithm_hint");
    let mut agent =
        create_pq2025_test_agent_from_env().expect("Failed to create pq2025 test agent");
    agent.generate_keys().expect("Key generation failed");

    let data = "pq2025-only verification test".to_string();
    let signature = agent.sign_string(&data).expect("Signing failed");
    let public_key = agent.get_public_key().expect("public key should exist");

    let result = agent.verify_string(&data, &signature, public_key, Some("pq-dilithium".into()));
    assert!(
        result.is_err(),
        "Verification with legacy pq-dilithium algorithm hint should fail"
    );
}

#[test]
fn test_pq2025_key_generation_requires_password_env() {
    let _env_guard = env_guard();
    let _ = configure_unique_pq2025_env("test_pq2025_key_generation_requires_password_env");

    let previous_password = std::env::var(PASSWORD_ENV_VAR).ok();
    unsafe {
        std::env::remove_var(PASSWORD_ENV_VAR);
    }

    let mut agent = create_agent_v1().expect("Agent schema should have instantiated");
    let config = Config::new(
        Some("false".to_string()),
        Some(std::env::var("JACS_DATA_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_KEY_DIRECTORY").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PRIVATE_KEY_FILENAME").unwrap_or_default()),
        Some(std::env::var("JACS_AGENT_PUBLIC_KEY_FILENAME").unwrap_or_default()),
        Some("pq2025".to_string()),
        None,
        None,
        Some("fs".to_string()),
    );
    agent.config = Some(config);

    let err = agent
        .generate_keys()
        .expect_err("key generation should fail when password is missing");
    let msg = err.to_string();
    assert!(
        msg.contains(PASSWORD_ENV_VAR),
        "Expected missing password error to mention {}. Got: {}",
        PASSWORD_ENV_VAR,
        msg
    );

    unsafe {
        if let Some(password) = previous_password {
            std::env::set_var(PASSWORD_ENV_VAR, password);
        }
    }
}

#[test]
fn test_pq2025_with_agent_save_load() {
    let _env_guard = env_guard();
    let _ = configure_unique_pq2025_env("test_pq2025_with_agent_save_load");
    let mut agent =
        create_pq2025_test_agent_from_env().expect("Failed to create pq2025 test agent");

    agent.generate_keys().expect("Key generation failed");

    // Create a new agent and load the keys (using the same env vars)
    let mut agent2 =
        create_pq2025_test_agent_from_env().expect("Failed to create second pq2025 test agent");
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
