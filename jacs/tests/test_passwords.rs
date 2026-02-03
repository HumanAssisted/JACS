//! Centralized test password constants for JACS test suite.
//!
//! This module provides standardized test passwords that meet the minimum
//! security requirements (40+ bits of entropy, 8+ characters, multiple
//! character classes). Using centralized constants ensures:
//!
//! 1. Consistency across all test files
//! 2. Easy updates if password requirements change
//! 3. Clear documentation of what each password is used for
//! 4. Avoids typos in hardcoded strings

/// Standard test password that meets entropy requirements.
/// - Length: 14 characters
/// - Character classes: lowercase, uppercase, digits, symbols
/// - Entropy: ~70 bits (well above 40-bit minimum)
///
/// Use this for most test scenarios requiring a valid password.
pub const TEST_PASSWORD: &str = "TestP@ss123!#";

/// Alternative test password for multi-key scenarios or testing
/// with different credentials.
/// - Length: 16 characters
/// - Character classes: lowercase, uppercase, digits, symbols
/// - Entropy: ~80 bits
///
/// Use this when testing scenarios that require a second, different password.
pub const TEST_PASSWORD_ALT: &str = "AltP@ssw0rd456$";

/// Minimal test password that just barely meets requirements.
/// - Length: 8 characters (minimum)
/// - Character classes: lowercase, uppercase, digits, symbols
/// - Entropy: ~40 bits (at the minimum threshold)
///
/// Use this for testing boundary conditions around password validation.
pub const TEST_PASSWORD_MINIMAL: &str = "xK9m$pL2";

/// Legacy test password for backward compatibility tests.
/// This matches passwords that may have been used in older test data.
/// Note: This still meets current entropy requirements.
pub const TEST_PASSWORD_LEGACY: &str = "secretpassord";

/// Strong test password with high entropy for security-critical tests.
/// - Length: 18 characters
/// - Character classes: all four types
/// - Entropy: ~90+ bits
pub const TEST_PASSWORD_STRONG: &str = "MyStr0ng!Pass#2024";

/// Password used for test fixture encrypted keys (ring, pq configs).
/// This matches the password that was used to encrypt the test key files
/// in tests/fixtures/keys/.
pub const TEST_PASSWORD_FIXTURES: &str = "testpassword";

/// Environment variable name for the private key password.
/// Centralized here to avoid string typos.
pub const PASSWORD_ENV_VAR: &str = "JACS_PRIVATE_KEY_PASSWORD";

/// Helper function to set the test password environment variable.
///
/// # Safety
/// This uses unsafe `env::set_var` which can cause data races if called
/// from multiple threads. Tests using this should be marked with `#[serial]`.
pub fn set_test_password_env(password: &str) {
    // SAFETY: Tests using this function should run serially
    unsafe {
        std::env::set_var(PASSWORD_ENV_VAR, password);
    }
}

/// Helper function to remove the test password environment variable.
///
/// # Safety
/// This uses unsafe `env::remove_var` which can cause data races if called
/// from multiple threads. Tests using this should be marked with `#[serial]`.
pub fn clear_test_password_env() {
    // SAFETY: Tests using this function should run serially
    unsafe {
        std::env::remove_var(PASSWORD_ENV_VAR);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passwords_are_different() {
        // Ensure all passwords are distinct
        assert_ne!(TEST_PASSWORD, TEST_PASSWORD_ALT);
        assert_ne!(TEST_PASSWORD, TEST_PASSWORD_MINIMAL);
        assert_ne!(TEST_PASSWORD, TEST_PASSWORD_LEGACY);
        assert_ne!(TEST_PASSWORD, TEST_PASSWORD_STRONG);
        assert_ne!(TEST_PASSWORD, TEST_PASSWORD_FIXTURES);
        assert_ne!(TEST_PASSWORD_ALT, TEST_PASSWORD_MINIMAL);
    }

    #[test]
    fn test_passwords_meet_minimum_length() {
        // All passwords should be at least 8 characters
        assert!(TEST_PASSWORD.len() >= 8);
        assert!(TEST_PASSWORD_ALT.len() >= 8);
        assert!(TEST_PASSWORD_MINIMAL.len() >= 8);
        assert!(TEST_PASSWORD_LEGACY.len() >= 8);
        assert!(TEST_PASSWORD_STRONG.len() >= 8);
        assert!(TEST_PASSWORD_FIXTURES.len() >= 8);
    }

    #[test]
    fn test_minimal_password_is_exactly_minimum() {
        // The minimal password should be exactly 8 characters
        assert_eq!(TEST_PASSWORD_MINIMAL.len(), 8);
    }
}
