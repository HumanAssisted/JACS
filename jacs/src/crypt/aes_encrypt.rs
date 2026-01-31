use crate::storage::jenv::get_required_env_var;
use aes_gcm::AeadCore;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;

/// Number of PBKDF2 iterations for key derivation.
/// 100,000 iterations provides reasonable security against brute-force attacks.
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256.
fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypt a private key with a password using AES-256-GCM.
///
/// The encrypted output format is: salt (16 bytes) || nonce (12 bytes) || ciphertext
///
/// Key derivation uses PBKDF2-HMAC-SHA256 with 100,000 iterations.
pub fn encrypt_private_key(private_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Password is required but can be empty (false)
    let password = get_required_env_var("JACS_PRIVATE_KEY_PASSWORD", false)?;

    // Generate a random salt
    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt[..]);

    // Derive key using PBKDF2-HMAC-SHA256
    let key = derive_key_from_password(&password, &salt);

    // Create cipher instance
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);

    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt private key
    let encrypted_data = cipher
        .encrypt(&nonce, private_key)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    // Combine the salt, nonce, and encrypted data into one Vec to return
    let mut encrypted_key_with_salt_and_nonce = salt.to_vec();
    encrypted_key_with_salt_and_nonce.extend_from_slice(nonce.as_slice());
    encrypted_key_with_salt_and_nonce.extend_from_slice(&encrypted_data);

    Ok(encrypted_key_with_salt_and_nonce)
}

/// Decrypt a private key with a password using AES-256-GCM.
///
/// Expects input format: salt (16 bytes) || nonce (12 bytes) || ciphertext
///
/// Key derivation uses PBKDF2-HMAC-SHA256 with 100,000 iterations.
pub fn decrypt_private_key(
    encrypted_key_with_salt_and_nonce: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Password is required but can be empty (false)
    let password = get_required_env_var("JACS_PRIVATE_KEY_PASSWORD", false)?;

    if encrypted_key_with_salt_and_nonce.len() < 16 + 12 {
        return Err("encrypted data is too short".into());
    }

    // Split the data into salt, nonce, and encrypted key
    let (salt, rest) = encrypted_key_with_salt_and_nonce.split_at(16);
    let (nonce, encrypted_data) = rest.split_at(12);

    // Derive key using PBKDF2-HMAC-SHA256
    let key = derive_key_from_password(&password, salt);

    // Create cipher instance
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);

    // Decrypt private key
    let decrypted_data = cipher
        .decrypt(Nonce::from_slice(nonce), encrypted_data)
        .map_err(|e| {
            format!(
                "AES-GCM decryption failed (wrong password or corrupted data): {}",
                e
            )
        })?;

    Ok(decrypted_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    // Helper functions for setting/removing env vars in tests
    // These are unsafe in Rust 2024 edition due to potential data races
    fn set_test_password(password: &str) {
        // SAFETY: These tests run serially (via #[serial]) and don't share state with other threads
        unsafe {
            env::set_var("JACS_PRIVATE_KEY_PASSWORD", password);
        }
    }

    fn remove_test_password() {
        // SAFETY: These tests run serially (via #[serial]) and don't share state with other threads
        unsafe {
            env::remove_var("JACS_PRIVATE_KEY_PASSWORD");
        }
    }

    #[test]
    #[serial]
    fn test_encrypt_decrypt_roundtrip() {
        // Set test password
        set_test_password("test_password_123");

        let original_key = b"this is a test private key data that should be encrypted";

        // Encrypt
        let encrypted = encrypt_private_key(original_key).expect("encryption should succeed");

        // Verify encrypted data is larger than original (salt + nonce + auth tag)
        assert!(encrypted.len() > original_key.len());

        // Decrypt
        let decrypted = decrypt_private_key(&encrypted).expect("decryption should succeed");

        // Verify roundtrip
        assert_eq!(original_key.as_slice(), decrypted.as_slice());

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_wrong_password_fails() {
        // Set password for encryption
        set_test_password("correct_password");

        let original_key = b"secret data";
        let encrypted = encrypt_private_key(original_key).expect("encryption should succeed");

        // Change password before decryption
        set_test_password("wrong_password");

        // Decryption should fail with wrong password
        let result = decrypt_private_key(&encrypted);
        assert!(result.is_err());

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_truncated_data_fails() {
        set_test_password("test_password");

        // Data too short (less than salt + nonce = 28 bytes)
        let short_data = vec![0u8; 20];
        let result = decrypt_private_key(&short_data);
        assert!(result.is_err());

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_different_salts_produce_different_ciphertexts() {
        set_test_password("test_password");

        let original_key = b"test data";

        // Encrypt twice - should produce different ciphertexts due to random salt/nonce
        let encrypted1 = encrypt_private_key(original_key).expect("encryption should succeed");
        let encrypted2 = encrypt_private_key(original_key).expect("encryption should succeed");

        // Ciphertexts should be different (different random salt and nonce)
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        let decrypted1 = decrypt_private_key(&encrypted1).expect("decryption should succeed");
        let decrypted2 = decrypt_private_key(&encrypted2).expect("decryption should succeed");
        assert_eq!(decrypted1, decrypted2);
        assert_eq!(original_key.as_slice(), decrypted1.as_slice());

        remove_test_password();
    }
}
