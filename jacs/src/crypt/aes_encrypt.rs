use crate::crypt::private_key::ZeroizingVec;
use crate::storage::jenv::get_required_env_var;
use aes_gcm::AeadCore;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;
use zeroize::Zeroize;

/// Number of PBKDF2 iterations for key derivation.
/// 100,000 iterations provides reasonable security against brute-force attacks.
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Minimum password length for key encryption.
const MIN_PASSWORD_LENGTH: usize = 8;

/// Validates that the password meets minimum security requirements.
///
/// # Requirements
/// - At least 8 characters long
/// - Not empty or whitespace-only
fn validate_password(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let trimmed = password.trim();

    if trimmed.is_empty() {
        return Err("Password cannot be empty or whitespace-only. Set JACS_PRIVATE_KEY_PASSWORD to a secure password.".into());
    }

    if trimmed.len() < MIN_PASSWORD_LENGTH {
        return Err(format!(
            "Password must be at least {} characters long (got {} characters). Use a stronger password for JACS_PRIVATE_KEY_PASSWORD.",
            MIN_PASSWORD_LENGTH,
            trimmed.len()
        ).into());
    }

    Ok(())
}

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
///
/// # Security Requirements
///
/// The password (from `JACS_PRIVATE_KEY_PASSWORD` environment variable) must:
/// - Be at least 8 characters long
/// - Not be empty or whitespace-only
pub fn encrypt_private_key(private_key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Password is required and must be non-empty
    let password = get_required_env_var("JACS_PRIVATE_KEY_PASSWORD", true)?;

    // Validate password strength
    validate_password(&password)?;

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
///
/// # Security Requirements
///
/// The password (from `JACS_PRIVATE_KEY_PASSWORD` environment variable) must:
/// - Be at least 8 characters long
/// - Not be empty or whitespace-only
///
/// # Security Note
///
/// This function returns a regular `Vec<u8>` for backwards compatibility.
/// For new code, prefer `decrypt_private_key_secure` which returns a
/// `ZeroizingVec` that automatically zeroizes memory on drop.
pub fn decrypt_private_key(
    encrypted_key_with_salt_and_nonce: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Delegate to secure version and extract the inner Vec
    // Note: This loses the zeroization guarantee, but maintains API compatibility
    let secure = decrypt_private_key_secure(encrypted_key_with_salt_and_nonce)?;
    // Clone the data out - the original ZeroizingVec will be zeroized when dropped
    Ok(secure.as_slice().to_vec())
}

/// Decrypt a private key with a password using AES-256-GCM.
///
/// This is the secure version that returns a `ZeroizingVec` which automatically
/// zeroizes the decrypted key material when it goes out of scope.
///
/// Expects input format: salt (16 bytes) || nonce (12 bytes) || ciphertext
///
/// Key derivation uses PBKDF2-HMAC-SHA256 with 100,000 iterations.
///
/// # Security Requirements
///
/// The password (from `JACS_PRIVATE_KEY_PASSWORD` environment variable) must:
/// - Be at least 8 characters long
/// - Not be empty or whitespace-only
///
/// # Security Guarantees
///
/// - The decrypted private key is wrapped in `ZeroizingVec` which securely
///   erases memory when dropped
/// - The derived encryption key is also zeroized after use
pub fn decrypt_private_key_secure(
    encrypted_key_with_salt_and_nonce: &[u8],
) -> Result<ZeroizingVec, Box<dyn std::error::Error>> {
    // Password is required and must be non-empty
    let password = get_required_env_var("JACS_PRIVATE_KEY_PASSWORD", true)?;

    // Validate password strength
    validate_password(&password)?;

    if encrypted_key_with_salt_and_nonce.len() < 16 + 12 {
        return Err("encrypted data is too short".into());
    }

    // Split the data into salt, nonce, and encrypted key
    let (salt, rest) = encrypted_key_with_salt_and_nonce.split_at(16);
    let (nonce, encrypted_data) = rest.split_at(12);

    // Derive key using PBKDF2-HMAC-SHA256
    let mut key = derive_key_from_password(&password, salt);

    // Create cipher instance
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);

    // Zeroize the derived key immediately after creating the cipher
    key.zeroize();

    // Decrypt private key
    let decrypted_data = cipher
        .decrypt(Nonce::from_slice(nonce), encrypted_data)
        .map_err(|e| {
            format!(
                "AES-GCM decryption failed (wrong password or corrupted data): {}",
                e
            )
        })?;

    Ok(ZeroizingVec::new(decrypted_data))
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

    #[test]
    #[serial]
    fn test_empty_password_rejected() {
        set_test_password("");

        let original_key = b"secret data";
        let result = encrypt_private_key(original_key);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("empty") || err_msg.contains("whitespace"));

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_whitespace_only_password_rejected() {
        set_test_password("   \t\n  ");

        let original_key = b"secret data";
        let result = encrypt_private_key(original_key);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("empty") || err_msg.contains("whitespace"));

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_short_password_rejected() {
        // Password with only 5 characters (less than MIN_PASSWORD_LENGTH of 8)
        set_test_password("short");

        let original_key = b"secret data";
        let result = encrypt_private_key(original_key);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("8 characters"));

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_minimum_length_password_accepted() {
        // Exactly 8 characters - should be accepted
        set_test_password("12345678");

        let original_key = b"secret data";
        let result = encrypt_private_key(original_key);
        assert!(result.is_ok(), "8-character password should be accepted");

        remove_test_password();
    }

    #[test]
    fn test_validate_password_unit() {
        // Unit tests for validate_password function directly
        assert!(validate_password("").is_err());
        assert!(validate_password("   ").is_err());
        assert!(validate_password("\t\n").is_err());
        assert!(validate_password("short").is_err());
        assert!(validate_password("1234567").is_err()); // 7 chars
        assert!(validate_password("12345678").is_ok()); // 8 chars - minimum
        assert!(validate_password("longpassword123").is_ok());
    }
}
