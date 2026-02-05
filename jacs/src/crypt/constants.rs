//! Cryptographic constants for JACS.
//!
//! This module centralizes all magic numbers used in cryptographic operations,
//! making them easier to audit, update, and understand.

// ============================================================================
// AES-GCM Constants
// ============================================================================

/// AES-256 key size in bytes (256 bits).
pub const AES_256_KEY_SIZE: usize = 32;

/// AES-GCM nonce size in bytes (96 bits as recommended by NIST SP 800-38D).
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// Salt length for password-based key derivation in bytes.
/// 128 bits provides sufficient entropy to prevent rainbow table attacks.
pub const PBKDF2_SALT_SIZE: usize = 16;

/// Minimum encrypted data size: salt (16) + nonce (12) = 28 bytes.
/// Any encrypted payload must be at least this size to contain the header.
pub const MIN_ENCRYPTED_HEADER_SIZE: usize = PBKDF2_SALT_SIZE + AES_GCM_NONCE_SIZE;

// ============================================================================
// PBKDF2 / Password Derivation Constants
// ============================================================================

/// Number of PBKDF2 iterations for key derivation.
/// 600,000 iterations per OWASP 2024 recommendation for PBKDF2-HMAC-SHA256.
/// This adds approximately 19.2 bits of work factor.
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Legacy iteration count for migration from pre-0.6.0 keys.
pub const PBKDF2_ITERATIONS_LEGACY: u32 = 100_000;

/// Minimum password length for key encryption.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Minimum entropy bits required for a password.
/// 28 bits provides reasonable protection against offline attacks when combined
/// with PBKDF2's 100k iterations (which effectively adds ~17 bits of work factor).
pub const MIN_ENTROPY_BITS: f64 = 28.0;

/// Entropy threshold for single character class passwords.
/// Passwords using only one character class (e.g., all lowercase) must have
/// at least this many bits of entropy to compensate for lack of variety.
pub const SINGLE_CLASS_MIN_ENTROPY_BITS: f64 = 35.0;

// ============================================================================
// Password Pattern Detection Constants
// ============================================================================

/// Maximum consecutive identical characters allowed before rejection.
/// 4 or more identical characters in a row (e.g., "aaaa") is rejected.
pub const MAX_CONSECUTIVE_IDENTICAL_CHARS: usize = 4;

/// Maximum sequential characters allowed before rejection.
/// 5 or more sequential characters (e.g., "12345" or "abcde") is rejected.
pub const MAX_SEQUENTIAL_CHARS: usize = 5;

// ============================================================================
// Entropy Calculation Constants (Character Pool Sizes)
// ============================================================================

/// Number of lowercase letters in English alphabet (a-z).
pub const LOWERCASE_POOL_SIZE: usize = 26;

/// Number of uppercase letters in English alphabet (A-Z).
pub const UPPERCASE_POOL_SIZE: usize = 26;

/// Number of digits (0-9).
pub const DIGIT_POOL_SIZE: usize = 10;

/// Approximate number of common special characters.
pub const SPECIAL_CHAR_POOL_SIZE: usize = 32;

/// Uniqueness ratio threshold for severe entropy penalty.
/// Passwords with less than 50% unique characters get a 0.5x penalty.
pub const SEVERE_UNIQUENESS_THRESHOLD: f64 = 0.5;

/// Uniqueness ratio threshold for moderate entropy penalty.
/// Passwords with 50-75% unique characters get a 0.75x penalty.
pub const MODERATE_UNIQUENESS_THRESHOLD: f64 = 0.75;

/// Severe penalty multiplier for low uniqueness passwords.
pub const SEVERE_UNIQUENESS_PENALTY: f64 = 0.5;

/// Moderate penalty multiplier for medium uniqueness passwords.
pub const MODERATE_UNIQUENESS_PENALTY: f64 = 0.75;

// ============================================================================
// RSA Constants
// ============================================================================

/// RSA key size in bits for production use.
/// 4096 bits provides security margin beyond current recommendations.
pub const RSA_KEY_BITS: usize = 4096;

/// RSA key size in bits for test use only.
/// 2048 bits is faster for tests while still being cryptographically valid.
#[cfg(test)]
pub const RSA_TEST_KEY_BITS: usize = 2048;

// ============================================================================
// Ed25519 Constants
// ============================================================================

/// Ed25519 public key size in bytes.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

// ============================================================================
// ML-KEM-768 (FIPS-203) Constants
// ============================================================================

/// ML-KEM-768 encapsulation key (public key) size in bytes.
pub const ML_KEM_768_ENCAPS_KEY_SIZE: usize = 1184;

/// ML-KEM-768 decapsulation key (private key) size in bytes.
pub const ML_KEM_768_DECAPS_KEY_SIZE: usize = 2400;

/// ML-KEM-768 ciphertext size in bytes.
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;

// ============================================================================
// ML-DSA-87 (FIPS-204) Constants
// ============================================================================

/// ML-DSA-87 private key size in bytes.
pub const ML_DSA_87_PRIVATE_KEY_SIZE: usize = 4896;

/// ML-DSA-87 public key size in bytes.
pub const ML_DSA_87_PUBLIC_KEY_SIZE: usize = 2592;

/// ML-DSA-87 signature size in bytes.
pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4627;

// ============================================================================
// Algorithm Detection Heuristic Constants
// ============================================================================

/// Minimum key length (in bytes) to consider for RSA detection.
pub const RSA_MIN_KEY_LENGTH: usize = 100;

/// Minimum key length (in bytes) to consider for Dilithium detection.
pub const DILITHIUM_MIN_KEY_LENGTH: usize = 1000;

/// Non-ASCII ratio threshold for Ed25519 detection.
/// Ed25519 keys typically have high non-ASCII content (>50%).
pub const ED25519_NON_ASCII_RATIO: f32 = 0.5;

/// Non-ASCII ratio threshold below which RSA is likely.
/// RSA PEM keys are mostly ASCII (<20% non-ASCII).
pub const RSA_NON_ASCII_RATIO: f32 = 0.2;

/// Non-ASCII ratio threshold for Dilithium detection.
/// Dilithium keys have significant non-ASCII content (>30%).
pub const DILITHIUM_NON_ASCII_RATIO: f32 = 0.3;

/// Key length threshold for distinguishing small PQ keys.
pub const PQ_SMALL_KEY_THRESHOLD: usize = 500;

// ============================================================================
// Dilithium Signature Size Detection
// ============================================================================

/// Lower bound for alternative Dilithium signature size detection.
pub const DILITHIUM_ALT_SIG_SIZE_MIN: usize = 4640;

/// Upper bound for alternative Dilithium signature size detection.
pub const DILITHIUM_ALT_SIG_SIZE_MAX: usize = 4650;

// ============================================================================
// HKDF Domain Separation
// ============================================================================

/// HKDF info string for JACS PQ2025 AEAD key derivation.
pub const HKDF_INFO_JACS_PQ2025_AEAD: &[u8] = b"jacs-pq2025-aead";
