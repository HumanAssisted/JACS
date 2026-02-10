use crate::crypt::constants::{
    AES_256_KEY_SIZE, AES_GCM_NONCE_SIZE, DIGIT_POOL_SIZE, LOWERCASE_POOL_SIZE,
    MAX_CONSECUTIVE_IDENTICAL_CHARS, MAX_SEQUENTIAL_CHARS, MIN_ENCRYPTED_HEADER_SIZE,
    MIN_ENTROPY_BITS, MIN_PASSWORD_LENGTH, MODERATE_UNIQUENESS_PENALTY,
    MODERATE_UNIQUENESS_THRESHOLD, PBKDF2_ITERATIONS, PBKDF2_ITERATIONS_LEGACY, PBKDF2_SALT_SIZE,
    SEVERE_UNIQUENESS_PENALTY, SEVERE_UNIQUENESS_THRESHOLD, SINGLE_CLASS_MIN_ENTROPY_BITS,
    SPECIAL_CHAR_POOL_SIZE, UPPERCASE_POOL_SIZE,
};
use crate::crypt::private_key::ZeroizingVec;
use crate::error::JacsError;
use crate::storage::jenv::get_required_env_var;
use aes_gcm::AeadCore;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;
use tracing::warn;
use zeroize::Zeroize;

/// Common weak passwords that should be rejected regardless of calculated entropy.
const WEAK_PASSWORDS: &[&str] = &[
    "password",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty123",
    "letmein123",
    "welcome123",
    "admin123",
    "password1",
    "password123",
    "iloveyou1",
    "sunshine1",
    "princess1",
    "football1",
    "monkey123",
    "shadow123",
    "master123",
    "dragon123",
    "trustno1",
    "abc12345",
    "abcd1234",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm123",
];

/// Returns a human-readable description of JACS password requirements.
///
/// This can be displayed to users before password prompts or included in error messages
/// to help them choose a valid password.
pub fn password_requirements() -> String {
    format!(
        "Password Requirements:\n\
         - At least {} characters long\n\
         - Not empty or whitespace-only\n\
         - Not a common/easily-guessed password\n\
         - No 4+ identical characters in a row (e.g., 'aaaa')\n\
         - No 5+ sequential characters (e.g., '12345', 'abcde')\n\
         - Minimum {:.0} bits of entropy\n\
         - Recommended: use at least 2 character types (uppercase, lowercase, digits, symbols)\n\
         \n\
         Tip: Set the password via the JACS_PRIVATE_KEY_PASSWORD environment variable.",
        MIN_PASSWORD_LENGTH, MIN_ENTROPY_BITS
    )
}

/// Calculate effective entropy of a password in bits.
///
/// This estimates the keyspace based on character pool size and password length,
/// then applies penalties for weak patterns like repetition and limited uniqueness.
fn calculate_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    // Determine character pool size based on what's used
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    let mut pool_size = 0;
    if has_lower {
        pool_size += LOWERCASE_POOL_SIZE;
    }
    if has_upper {
        pool_size += UPPERCASE_POOL_SIZE;
    }
    if has_digit {
        pool_size += DIGIT_POOL_SIZE;
    }
    if has_special {
        pool_size += SPECIAL_CHAR_POOL_SIZE;
    }

    // At minimum, pool size is the number of unique characters
    let unique_chars: std::collections::HashSet<char> = password.chars().collect();
    pool_size = pool_size.max(unique_chars.len());

    if pool_size == 0 {
        return 0.0;
    }

    // Base entropy: log2(pool_size) * length
    let bits_per_char = (pool_size as f64).log2();
    let len = password.len() as f64;
    let base_entropy = bits_per_char * len;

    // Apply penalty for low uniqueness (many repeated characters)
    let uniqueness_ratio = unique_chars.len() as f64 / len;
    let uniqueness_penalty = if uniqueness_ratio < SEVERE_UNIQUENESS_THRESHOLD {
        SEVERE_UNIQUENESS_PENALTY
    } else if uniqueness_ratio < MODERATE_UNIQUENESS_THRESHOLD {
        MODERATE_UNIQUENESS_PENALTY
    } else {
        1.0 // No penalty
    };

    base_entropy * uniqueness_penalty
}

/// Check if password contains consecutive repeated characters (e.g., "aaa", "111")
fn has_excessive_repetition(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    let mut consecutive = 1;

    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            consecutive += 1;
            if consecutive >= MAX_CONSECUTIVE_IDENTICAL_CHARS {
                return true;
            }
        } else {
            consecutive = 1;
        }
    }

    false
}

/// Check if password contains sequential characters (e.g., "1234", "abcd")
fn has_sequential_pattern(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    let mut ascending = 1;
    let mut descending = 1;

    for i in 1..chars.len() {
        let prev = chars[i - 1] as i32;
        let curr = chars[i] as i32;

        if curr == prev + 1 {
            ascending += 1;
            descending = 1;
            if ascending >= MAX_SEQUENTIAL_CHARS {
                return true;
            }
        } else if curr == prev - 1 {
            descending += 1;
            ascending = 1;
            if descending >= MAX_SEQUENTIAL_CHARS {
                return true;
            }
        } else {
            ascending = 1;
            descending = 1;
        }
    }

    false
}

/// Count the number of distinct character classes used in the password.
/// Classes: lowercase, uppercase, digits, special characters
fn count_character_classes(password: &str) -> usize {
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    [has_lower, has_upper, has_digit, has_special]
        .iter()
        .filter(|&&b| b)
        .count()
}

/// Validates that the password meets minimum security requirements.
///
/// # Requirements
/// - At least 8 characters long
/// - Not empty or whitespace-only
/// - Not in the list of common weak passwords
/// - Minimum 40 bits of entropy
/// - No excessive character repetition (4+ same chars in a row)
/// - No long sequential patterns (5+ ascending/descending chars)
/// - At least 2 different character classes (recommended)
fn validate_password(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let trimmed = password.trim();

    if trimmed.is_empty() {
        return Err(format!(
            "Password cannot be empty or whitespace-only.\n\n{}",
            password_requirements()
        )
        .into());
    }

    if trimmed.len() < MIN_PASSWORD_LENGTH {
        return Err(JacsError::CryptoError(format!(
            "Password must be at least {} characters long (got {} characters).\n\nRequirements: use at least {} characters with mixed character types. \
            Set JACS_PRIVATE_KEY_PASSWORD to a secure password.",
            MIN_PASSWORD_LENGTH,
            trimmed.len(),
            MIN_PASSWORD_LENGTH
        )).into());
    }

    // Check against common weak passwords (case-insensitive)
    let lower = trimmed.to_lowercase();
    if WEAK_PASSWORDS.contains(&lower.as_str()) {
        return Err(format!(
            "Password is too common and easily guessable. Please use a unique password.\n\n{}",
            password_requirements()
        )
        .into());
    }

    // Check for excessive repetition
    if has_excessive_repetition(trimmed) {
        return Err(format!(
            "Password contains too many repeated characters (4+ in a row). Use more variety.\n\n{}",
            password_requirements()
        )
        .into());
    }

    // Check for sequential patterns
    if has_sequential_pattern(trimmed) {
        return Err(format!(
            "Password contains sequential characters (like '12345' or 'abcde'). Use a less predictable pattern.\n\n{}",
            password_requirements()
        )
        .into());
    }

    // Calculate entropy
    let entropy = calculate_entropy(trimmed);
    if entropy < MIN_ENTROPY_BITS {
        let char_classes = count_character_classes(trimmed);
        let suggestion = if char_classes < 2 {
            "Try mixing uppercase, lowercase, numbers, and symbols."
        } else {
            "Try using a longer password with more varied characters."
        };
        return Err(JacsError::CryptoError(format!(
            "Password entropy too low ({:.1} bits, minimum is {:.0} bits). {}\n\nRequirements: {}",
            entropy, MIN_ENTROPY_BITS, suggestion,
            "use at least 8 characters with mixed character types (uppercase, lowercase, digits, symbols)."
        ))
        .into());
    }

    // Single character class passwords are allowed if they have sufficient entropy
    // through length (e.g., a long lowercase-only passphrase)
    // The 28-bit minimum entropy check above already provides baseline security
    // We use SINGLE_CLASS_MIN_ENTROPY_BITS as threshold for single-class passwords,
    // which is equivalent to ~11 lowercase characters or ~8 alphanumeric characters
    let char_classes = count_character_classes(trimmed);
    if char_classes < 2 && entropy < SINGLE_CLASS_MIN_ENTROPY_BITS {
        return Err(JacsError::CryptoError(format!(
            "Password uses only {} character class(es) with insufficient length. Use at least 2 character types (uppercase, lowercase, digits, symbols) or use a longer password.\n\n{}",
            char_classes,
            password_requirements()
        )).into());
    }

    Ok(())
}

/// Check if a password meets JACS requirements without performing any encryption.
///
/// Returns `Ok(())` if the password is acceptable, or `Err` with a detailed message
/// explaining which rule failed and the full requirements.
pub fn check_password_strength(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    validate_password(password)
}

/// Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256 with a specific iteration count.
fn derive_key_with_iterations(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> [u8; AES_256_KEY_SIZE] {
    let mut key = [0u8; AES_256_KEY_SIZE];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

/// Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256.
fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; AES_256_KEY_SIZE] {
    derive_key_with_iterations(password, salt, PBKDF2_ITERATIONS)
}

/// Encrypt a private key with a password using AES-256-GCM.
///
/// The encrypted output format is: salt (16 bytes) || nonce (12 bytes) || ciphertext
///
/// Key derivation uses PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2024).
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
    let mut salt = [0u8; PBKDF2_SALT_SIZE];
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
/// Key derivation uses PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2024),
/// with automatic fallback to legacy 100,000 iterations for pre-0.6.0 keys.
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
#[deprecated(
    since = "0.6.0",
    note = "Use decrypt_private_key_secure() which returns ZeroizingVec for automatic memory zeroization"
)]
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
/// Key derivation uses PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2024).
/// For backwards compatibility, if decryption fails with the current iteration count,
/// it falls back to the legacy 100,000 iterations and logs a migration warning.
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
    // Note: We don't validate password strength during decryption because:
    // 1. The password must match whatever was used during encryption
    // 2. Existing keys may have been encrypted with older/weaker passwords
    // Password strength is validated only during encrypt_private_key()
    let password = get_required_env_var("JACS_PRIVATE_KEY_PASSWORD", true)?;

    if encrypted_key_with_salt_and_nonce.len() < MIN_ENCRYPTED_HEADER_SIZE {
        return Err(JacsError::CryptoError(format!(
            "Encrypted private key file is corrupted or truncated: expected at least {} bytes, got {} bytes. \
            The key file may have been damaged during transfer or storage. \
            Try regenerating your keys with 'jacs keygen' or restore from a backup.",
            MIN_ENCRYPTED_HEADER_SIZE,
            encrypted_key_with_salt_and_nonce.len()
        )).into());
    }

    // Split the data into salt, nonce, and encrypted key
    let (salt, rest) = encrypted_key_with_salt_and_nonce.split_at(PBKDF2_SALT_SIZE);
    let (nonce, encrypted_data) = rest.split_at(AES_GCM_NONCE_SIZE);

    // Try decryption with current iteration count first, then fall back to legacy.
    // This allows seamless migration from pre-0.6.0 keys encrypted with 100k iterations
    // to the new 600k iteration count.
    let nonce_slice = Nonce::from_slice(nonce);

    // Attempt with current iterations (600k)
    let mut key = derive_key_from_password(&password, salt);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    key.zeroize();

    if let Ok(decrypted_data) = cipher.decrypt(nonce_slice, encrypted_data) {
        return Ok(ZeroizingVec::new(decrypted_data));
    }

    // Fall back to legacy iterations (100k) for pre-0.6.0 encrypted keys
    let mut legacy_key = derive_key_with_iterations(&password, salt, PBKDF2_ITERATIONS_LEGACY);
    let legacy_cipher_key = Key::<Aes256Gcm>::from_slice(&legacy_key);
    let legacy_cipher = Aes256Gcm::new(legacy_cipher_key);
    legacy_key.zeroize();

    let decrypted_data = legacy_cipher
        .decrypt(nonce_slice, encrypted_data)
        .map_err(|_| {
            "Private key decryption failed: incorrect password or corrupted key file. \
            Check that JACS_PRIVATE_KEY_PASSWORD matches the password used during key generation. \
            If the key file is corrupted, you may need to regenerate your keys."
                .to_string()
        })?;

    warn!(
        "MIGRATION: Private key was decrypted using legacy PBKDF2 iteration count ({}). \
        Re-encrypt your private key to upgrade to the current iteration count ({}) \
        for improved security. Run 'jacs keygen' to regenerate keys.",
        PBKDF2_ITERATIONS_LEGACY, PBKDF2_ITERATIONS
    );

    Ok(ZeroizingVec::new(decrypted_data))
}

/// Decrypt data with an explicit password (no env var dependency).
///
/// This is useful for re-encryption workflows where both old and new passwords
/// are provided as parameters.
pub fn decrypt_with_password(
    encrypted_data: &[u8],
    password: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted_data.len() < MIN_ENCRYPTED_HEADER_SIZE {
        return Err(JacsError::CryptoError(format!(
            "Encrypted data too short: expected at least {} bytes, got {} bytes.",
            MIN_ENCRYPTED_HEADER_SIZE,
            encrypted_data.len()
        ))
        .into());
    }

    let (salt, rest) = encrypted_data.split_at(PBKDF2_SALT_SIZE);
    let (nonce, ciphertext) = rest.split_at(AES_GCM_NONCE_SIZE);
    let nonce_slice = Nonce::from_slice(nonce);

    // Try current iterations first
    let mut key = derive_key_from_password(password, salt);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    key.zeroize();

    if let Ok(decrypted) = cipher.decrypt(nonce_slice, ciphertext) {
        return Ok(decrypted);
    }

    // Fall back to legacy iterations
    let mut legacy_key = derive_key_with_iterations(password, salt, PBKDF2_ITERATIONS_LEGACY);
    let legacy_cipher_key = Key::<Aes256Gcm>::from_slice(&legacy_key);
    let legacy_cipher = Aes256Gcm::new(legacy_cipher_key);
    legacy_key.zeroize();

    legacy_cipher.decrypt(nonce_slice, ciphertext).map_err(|_| {
        "Decryption failed: incorrect password or corrupted data."
            .to_string()
            .into()
    })
}

/// Encrypt data with an explicit password (no env var dependency).
pub fn encrypt_with_password(
    data: &[u8],
    password: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    validate_password(password)?;

    let mut salt = [0u8; PBKDF2_SALT_SIZE];
    rand::rng().fill(&mut salt[..]);

    let key = derive_key_from_password(password, &salt);
    let cipher_key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted = cipher
        .encrypt(&nonce, data)
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    let mut result = salt.to_vec();
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&encrypted);
    Ok(result)
}

/// Re-encrypt a private key from one password to another.
///
/// Decrypts with `old_password`, validates `new_password`, then re-encrypts.
///
/// # Arguments
///
/// * `encrypted_data` - The currently encrypted private key data
/// * `old_password` - The current password
/// * `new_password` - The new password (must meet password requirements)
///
/// # Returns
///
/// The re-encrypted private key data.
pub fn reencrypt_private_key(
    encrypted_data: &[u8],
    old_password: &str,
    new_password: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Decrypt with old password
    let plaintext = decrypt_with_password(encrypted_data, old_password)?;

    // Encrypt with new password (validates new_password internally)
    let re_encrypted = encrypt_with_password(&plaintext, new_password)?;

    Ok(re_encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env;

    // Helper functions for setting/removing env vars in tests.
    // These are unsafe in Rust 2024 edition due to potential data races when other threads
    // read environment variables concurrently.

    fn set_test_password(password: &str) {
        // SAFETY: `env::set_var` is unsafe because concurrent reads from other threads
        // could observe a partially-written value or cause undefined behavior. This is
        // safe here because:
        // 1. All tests using this helper are marked #[serial], ensuring single-threaded execution
        // 2. The password is set before any code reads JACS_PRIVATE_KEY_PASSWORD
        // 3. No background threads are spawned that might read this variable
        // 4. The serial_test crate guarantees mutual exclusion with other #[serial] tests
        // Violating these invariants (e.g., removing #[serial]) could cause data races.
        unsafe {
            env::set_var("JACS_PRIVATE_KEY_PASSWORD", password);
        }
    }

    fn remove_test_password() {
        // SAFETY: `env::remove_var` is unsafe for the same reasons as `env::set_var`.
        // This is safe here because:
        // 1. Called only from #[serial] tests ensuring single-threaded execution
        // 2. This is called in cleanup after the test completes, when no concurrent reads occur
        // 3. The serial_test crate ensures this completes before any other test starts
        // If #[serial] is removed or background threads are added, this could cause UB.
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
        // Exactly 8 characters with variety - should be accepted
        // Note: "12345678" is rejected as a common weak password
        set_test_password("xK9m$pL2");

        let original_key = b"secret data";
        let result = encrypt_private_key(original_key);
        assert!(
            result.is_ok(),
            "8-character varied password should be accepted: {:?}",
            result.err()
        );

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
        // Note: "12345678" is rejected as a common weak password
        assert!(validate_password("12345678").is_err());
        // Use a non-weak 8-char password with variety
        assert!(validate_password("xK9m$pL2").is_ok());
        assert!(validate_password("MyP@ssw0rd!").is_ok()); // Strong password
    }

    // ==================== Entropy Tests ====================

    #[test]
    fn test_entropy_calculation() {
        // All same characters should have low entropy (penalized for low uniqueness)
        let low_entropy = calculate_entropy("aaaaaaaa");
        assert!(
            low_entropy < 20.0,
            "Repeated chars should have low entropy due to uniqueness penalty: {}",
            low_entropy
        );

        // Mixed lowercase characters should have decent entropy
        let medium_entropy = calculate_entropy("abcdefgh");
        assert!(
            medium_entropy > 30.0,
            "8 unique lowercase chars should have decent entropy: {}",
            medium_entropy
        );

        // Complex password with multiple character classes should have high entropy
        let high_entropy = calculate_entropy("aB3$xY9@kL");
        assert!(
            high_entropy > 50.0,
            "Complex password should have high entropy: {}",
            high_entropy
        );

        // Verify entropy increases with character diversity
        let lowercase_only = calculate_entropy("abcdefgh");
        let mixed_case = calculate_entropy("aBcDeFgH");
        let with_numbers = calculate_entropy("aBcD1234");
        let with_special = calculate_entropy("aB1$cD2@");

        assert!(
            mixed_case > lowercase_only,
            "Mixed case should have higher entropy than lowercase only"
        );
        assert!(
            with_numbers > mixed_case,
            "Adding numbers should increase entropy"
        );
        assert!(
            with_special > with_numbers,
            "Adding special chars should increase entropy"
        );
    }

    #[test]
    fn test_common_weak_passwords_rejected() {
        // All these common passwords should be rejected
        let weak_passwords = [
            "password",
            "Password",
            "PASSWORD",
            "12345678",
            "qwerty123",
            "letmein123",
            "password123",
            "trustno1",
        ];

        for pwd in weak_passwords {
            let result = validate_password(pwd);
            assert!(
                result.is_err(),
                "Common password '{}' should be rejected",
                pwd
            );
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("common") || err_msg.contains("guessable"),
                "Error for '{}' should mention common/guessable: {}",
                pwd,
                err_msg
            );
        }
    }

    #[test]
    fn test_repetition_rejected() {
        // 4+ repeated characters should be rejected
        let repetitive_passwords = ["aaaa1234", "pass1111", "xxxx5678", "ab@@@@cd"];

        for pwd in repetitive_passwords {
            let result = validate_password(pwd);
            assert!(
                result.is_err(),
                "Repetitive password '{}' should be rejected",
                pwd
            );
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("repeated"),
                "Error for '{}' should mention repetition: {}",
                pwd,
                err_msg
            );
        }
    }

    #[test]
    fn test_sequential_patterns_rejected() {
        // 5+ sequential characters should be rejected
        let sequential_passwords = ["12345abc", "abcdefgh", "98765xyz", "zyxwvuts"];

        for pwd in sequential_passwords {
            let result = validate_password(pwd);
            assert!(
                result.is_err(),
                "Sequential password '{}' should be rejected",
                pwd
            );
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("sequential") || err_msg.contains("entropy"),
                "Error for '{}' should mention sequential or entropy: {}",
                pwd,
                err_msg
            );
        }
    }

    #[test]
    fn test_low_entropy_single_class_rejected() {
        // All lowercase, low diversity passwords
        let low_entropy_passwords = ["aaaaabbb", "zzzzzzzz", "qqqqqqqq"];

        for pwd in low_entropy_passwords {
            let result = validate_password(pwd);
            assert!(
                result.is_err(),
                "Low entropy password '{}' should be rejected",
                pwd
            );
        }
    }

    #[test]
    fn test_strong_passwords_accepted() {
        // These should all pass validation
        let strong_passwords = [
            "MyP@ssw0rd!",
            "Tr0ub4dor&3",
            "correct-horse-battery",
            "xK9$mN2@pL5!",
            "SecurePass#2024",
            "n0t-a-w3ak-p@ss",
        ];

        for pwd in strong_passwords {
            let result = validate_password(pwd);
            assert!(
                result.is_ok(),
                "Strong password '{}' should be accepted: {:?}",
                pwd,
                result.err()
            );
        }
    }

    #[test]
    fn test_character_class_counting() {
        assert_eq!(count_character_classes("abcdefgh"), 1); // lowercase only
        assert_eq!(count_character_classes("ABCDEFGH"), 1); // uppercase only
        assert_eq!(count_character_classes("12345678"), 1); // digits only
        assert_eq!(count_character_classes("!@#$%^&*"), 1); // special only
        assert_eq!(count_character_classes("abcABC12"), 3); // lower + upper + digit
        assert_eq!(count_character_classes("aB1!"), 4); // all four classes
    }

    #[test]
    fn test_has_excessive_repetition_detection() {
        assert!(!has_excessive_repetition("abc123")); // No repetition
        assert!(!has_excessive_repetition("aabcc")); // 2 is okay
        assert!(!has_excessive_repetition("aaabbb")); // 3 is okay
        assert!(has_excessive_repetition("aaaab")); // 4 consecutive is bad
        assert!(has_excessive_repetition("x1111y")); // 4 consecutive digits
    }

    #[test]
    fn test_has_sequential_pattern_detection() {
        assert!(!has_sequential_pattern("abc12")); // Short sequence okay
        assert!(!has_sequential_pattern("1234x")); // 4 in a row okay
        assert!(has_sequential_pattern("12345")); // 5 ascending bad
        assert!(has_sequential_pattern("abcde")); // 5 letters bad
        assert!(has_sequential_pattern("54321")); // 5 descending bad
        assert!(has_sequential_pattern("edcba")); // 5 letters descending bad
    }

    #[test]
    #[serial]
    fn test_encryption_with_weak_password_fails() {
        // Try to encrypt with a weak password - should fail validation
        set_test_password("password");

        let original_key = b"secret data";
        let result = encrypt_private_key(original_key);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("common") || err_msg.contains("guessable"),
            "Should reject common password: {}",
            err_msg
        );

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_encryption_with_strong_password_succeeds() {
        // Use a properly strong password
        set_test_password("MyStr0ng!Pass#2024");

        let original_key = b"secret data";
        let result = encrypt_private_key(original_key);
        assert!(result.is_ok(), "Strong password should work: {:?}", result);

        // Also verify decryption works
        let encrypted = result.unwrap();
        let decrypted = decrypt_private_key(&encrypted);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap().as_slice(), original_key);

        remove_test_password();
    }

    // ==================== Additional Negative Tests for Security ====================

    #[test]
    #[serial]
    fn test_very_long_password_works_or_fails_gracefully() {
        // 100KB password - should work or fail gracefully (not crash/panic)
        let long_password = "A".repeat(100_000);
        set_test_password(&long_password);

        let original_key = b"secret data";
        let result = encrypt_private_key(original_key);
        // The result can be Ok or Err, but it should NOT panic
        // If it succeeds, decryption should also work
        if let Ok(encrypted) = result {
            let decrypted = decrypt_private_key(&encrypted);
            assert!(
                decrypted.is_ok(),
                "If encryption with long password succeeds, decryption should too"
            );
            assert_eq!(decrypted.unwrap().as_slice(), original_key);
        }
        // If it fails, that's acceptable too - just ensure no panic occurred

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_corrupted_encrypted_data_fails_gracefully() {
        set_test_password("MyStr0ng!Pass#2024");

        let original_key = b"secret data";
        let encrypted = encrypt_private_key(original_key).expect("encryption should succeed");

        // Corrupt different parts of the encrypted data
        let test_cases = vec![
            ("corrupted salt", {
                let mut data = encrypted.clone();
                data[0] ^= 0xFF;
                data[8] ^= 0xFF;
                data
            }),
            ("corrupted nonce", {
                let mut data = encrypted.clone();
                data[16] ^= 0xFF; // Nonce starts at byte 16
                data[20] ^= 0xFF;
                data
            }),
            ("corrupted ciphertext", {
                let mut data = encrypted.clone();
                let mid = data.len() / 2;
                data[mid] ^= 0xFF;
                data
            }),
            ("corrupted auth tag", {
                let mut data = encrypted.clone();
                let last = data.len() - 1;
                data[last] ^= 0xFF;
                data[last - 8] ^= 0xFF;
                data
            }),
        ];

        for (description, corrupted_data) in test_cases {
            let result = decrypt_private_key(&corrupted_data);
            assert!(
                result.is_err(),
                "Decryption with {} should fail",
                description
            );
        }

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_all_zeros_encrypted_data_rejected() {
        set_test_password("MyStr0ng!Pass#2024");

        // All zeros (valid length but garbage)
        let zeros = vec![0u8; 100];
        let result = decrypt_private_key(&zeros);
        assert!(
            result.is_err(),
            "All-zeros encrypted data should be rejected"
        );

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_all_ones_encrypted_data_rejected() {
        set_test_password("MyStr0ng!Pass#2024");

        // All 0xFF (valid length but garbage)
        let ones = vec![0xFF; 100];
        let result = decrypt_private_key(&ones);
        assert!(
            result.is_err(),
            "All-ones encrypted data should be rejected"
        );

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_empty_plaintext_encryption() {
        set_test_password("MyStr0ng!Pass#2024");

        // Empty data should be encryptable and decryptable
        let empty_data = b"";
        let encrypted = encrypt_private_key(empty_data);
        assert!(encrypted.is_ok(), "Empty data encryption should succeed");

        let decrypted = decrypt_private_key(&encrypted.unwrap());
        assert!(decrypted.is_ok(), "Empty data decryption should succeed");
        assert_eq!(decrypted.unwrap().as_slice(), empty_data.as_slice());

        remove_test_password();
    }

    #[test]
    #[serial]
    fn test_large_plaintext_encryption() {
        set_test_password("MyStr0ng!Pass#2024");

        // 1MB of data
        let large_data = vec![0x42u8; 1_000_000];
        let encrypted = encrypt_private_key(&large_data);
        assert!(encrypted.is_ok(), "Large data encryption should succeed");

        let decrypted = decrypt_private_key(&encrypted.unwrap());
        assert!(decrypted.is_ok(), "Large data decryption should succeed");
        assert_eq!(decrypted.unwrap().as_slice(), large_data.as_slice());

        remove_test_password();
    }

    #[test]
    fn test_unicode_password_validation() {
        // Unicode passwords should work if they meet entropy requirements
        // This tests the password validation with various unicode strings
        let unicode_passwords = [
            // High entropy unicode (should pass)
            ("P@ssw0rd\u{1F600}", true),           // With emoji
            ("密码Tr0ng!Pass", true),              // Chinese characters
            ("\u{0391}\u{0392}Str0ng!P@ss", true), // Greek letters
            // Low entropy unicode (should fail)
            ("\u{1F600}\u{1F600}\u{1F600}\u{1F600}", false), // Just 4 emojis
        ];

        for (password, should_pass) in unicode_passwords {
            let result = validate_password(password);
            if should_pass {
                assert!(
                    result.is_ok(),
                    "Unicode password '{}' should be accepted: {:?}",
                    password,
                    result.err()
                );
            } else {
                assert!(
                    result.is_err(),
                    "Low entropy unicode password '{}' should be rejected",
                    password
                );
            }
        }
    }

    #[test]
    fn test_password_with_null_bytes_handled() {
        // Passwords with null bytes could cause issues in C-string contexts
        // These should either be accepted (if they meet entropy) or rejected gracefully
        let passwords_with_nulls = ["pass\0word12!@AB", "\0passwordAB12!@", "passwordAB12!@\0"];

        for password in passwords_with_nulls {
            let result = validate_password(password);
            // Just verify no panic occurs - result can be ok or err
            let _ = result;
        }
    }

    #[test]
    fn test_password_boundary_lengths() {
        // Test exact boundary conditions
        // 7 characters (one below minimum) should fail
        let seven_chars = "aB1$xY9";
        assert!(
            validate_password(seven_chars).is_err(),
            "7-character password should be rejected"
        );

        // 8 characters with variety should pass
        let eight_chars = "aB1$xY90";
        assert!(
            validate_password(eight_chars).is_ok(),
            "8-character varied password should be accepted: {:?}",
            validate_password(eight_chars).err()
        );
    }

    #[test]
    fn test_keyboard_pattern_passwords() {
        // Common keyboard patterns should be rejected
        let keyboard_patterns = [
            "qwertyuiop", // Top row
            "asdfghjkl",  // Middle row
            "zxcvbnm123", // Bottom row + numbers
        ];

        for pattern in keyboard_patterns {
            let result = validate_password(pattern);
            assert!(
                result.is_err(),
                "Keyboard pattern '{}' should be rejected",
                pattern
            );
        }
    }

    #[test]
    fn test_leet_speak_common_passwords() {
        // Common passwords in leet speak might have higher entropy
        // but if they're still in the weak list, they should be rejected
        let result = validate_password("trustno1");
        assert!(
            result.is_err(),
            "trustno1 should be rejected as a common weak password"
        );
    }

    #[test]
    fn test_password_requirements_returns_string() {
        let reqs = password_requirements();
        assert!(
            reqs.contains("8 characters"),
            "Should mention minimum character count: {}",
            reqs
        );
        assert!(
            reqs.contains("JACS_PRIVATE_KEY_PASSWORD"),
            "Should mention env var: {}",
            reqs
        );
        assert!(reqs.contains("entropy"), "Should mention entropy: {}", reqs);
    }

    #[test]
    fn test_empty_password_error_contains_requirements() {
        let result = validate_password("");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Requirements") || err_msg.contains("Password Requirements"),
            "Empty password error should include requirements text: {}",
            err_msg
        );
    }

    #[test]
    #[serial]
    fn test_decrypt_with_missing_password_env_var() {
        // Remove the password environment variable
        remove_test_password();

        // Create some dummy encrypted data (minimum valid length)
        let dummy_encrypted = vec![0u8; 50];

        // Decryption should fail because password env var is not set
        let result = decrypt_private_key(&dummy_encrypted);
        assert!(
            result.is_err(),
            "Decryption without password env var should fail"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("JACS_PRIVATE_KEY_PASSWORD")
                || err_msg.contains("password")
                || err_msg.contains("environment"),
            "Error should mention missing password: {}",
            err_msg
        );
    }

    // ==================== Re-encryption Tests ====================

    #[test]
    fn test_reencrypt_roundtrip() {
        let old_password = "OldP@ssw0rd!2024";
        let new_password = "NewStr0ng!Pass#2025";

        // Encrypt with old password
        let original_data = b"this is a secret private key for testing re-encryption";
        let encrypted =
            encrypt_with_password(original_data, old_password).expect("encryption should succeed");

        // Re-encrypt from old to new
        let re_encrypted = reencrypt_private_key(&encrypted, old_password, new_password)
            .expect("re-encryption should succeed");

        // Decrypt with new password
        let decrypted = decrypt_with_password(&re_encrypted, new_password)
            .expect("decryption with new password should succeed");

        assert_eq!(original_data.as_slice(), decrypted.as_slice());

        // Old password should NOT work anymore
        let old_result = decrypt_with_password(&re_encrypted, old_password);
        assert!(
            old_result.is_err(),
            "Old password should not decrypt re-encrypted data"
        );
    }

    #[test]
    fn test_reencrypt_wrong_old_password_fails() {
        let correct_password = "CorrectP@ss!2024";
        let wrong_password = "WrongP@ssw0rd!99";
        let new_password = "NewStr0ng!Pass#2025";

        let original_data = b"secret key data";
        let encrypted = encrypt_with_password(original_data, correct_password)
            .expect("encryption should succeed");

        let result = reencrypt_private_key(&encrypted, wrong_password, new_password);
        assert!(
            result.is_err(),
            "Re-encryption with wrong old password should fail"
        );
    }

    #[test]
    fn test_reencrypt_weak_new_password_fails() {
        let old_password = "OldP@ssw0rd!2024";
        let weak_new_password = "password"; // common weak password

        let original_data = b"secret key data";
        let encrypted =
            encrypt_with_password(original_data, old_password).expect("encryption should succeed");

        let result = reencrypt_private_key(&encrypted, old_password, weak_new_password);
        assert!(
            result.is_err(),
            "Re-encryption with weak new password should fail"
        );
    }

    #[test]
    fn test_encrypt_decrypt_with_password_roundtrip() {
        let password = "TestP@ssw0rd!2024";
        let data = b"test data for explicit password functions";

        let encrypted = encrypt_with_password(data, password).expect("encryption should succeed");

        let decrypted =
            decrypt_with_password(&encrypted, password).expect("decryption should succeed");

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }
}
