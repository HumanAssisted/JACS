use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::{
    error::{KeyRejected, Unspecified},
    rand,
    signature::{self, KeyPair, UnparsedPublicKey},
};
use std::error::Error;
use std::fmt;
use tracing::{debug, trace, warn};

#[must_use = "generated keys must be stored securely"]
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    trace!("Generating Ed25519 keypair");
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(RingError)?;
    let key_pair =
        signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).map_err(KeyRejectedError)?;
    let public_key = key_pair.public_key().as_ref().to_vec();
    let private_key = pkcs8_bytes.as_ref().to_vec();
    debug!(
        public_key_len = public_key.len(),
        private_key_len = private_key.len(),
        "Ed25519 keypair generated"
    );
    Ok((private_key, public_key))
}

#[must_use = "signature must be stored or transmitted"]
pub fn sign_string(secret_key: Vec<u8>, data: &String) -> Result<String, Box<dyn Error>> {
    trace!(data_len = data.len(), "Ed25519 signing starting");
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(&secret_key).map_err(KeyRejectedError)?;
    let signature = key_pair.sign(data.as_bytes());
    let signature_bytes = signature.as_ref();
    let signature_base64 = STANDARD.encode(signature_bytes);
    trace!(
        signature_len = signature_base64.len(),
        "Ed25519 signing completed"
    );
    Ok(signature_base64)
}

#[must_use = "signature verification result must be checked"]
pub fn verify_string(
    public_key: Vec<u8>,
    data: &str,
    signature_base64: &str,
) -> Result<(), Box<dyn Error>> {
    trace!(
        data_len = data.len(),
        public_key_len = public_key.len(),
        "Ed25519 verification starting"
    );
    let signature_bytes = STANDARD.decode(signature_base64)?;
    let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key);
    match public_key.verify(data.as_bytes(), &signature_bytes) {
        Ok(()) => {
            debug!("Ed25519 signature verification succeeded");
            Ok(())
        }
        Err(e) => {
            warn!("Ed25519 signature verification failed");
            Err(RingError(e).into())
        }
    }
}

#[derive(Debug)]
struct RingError(Unspecified);

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 cryptographic operation failed: {:?}", self.0)
    }
}

impl Error for RingError {}

impl From<Unspecified> for RingError {
    fn from(error: Unspecified) -> Self {
        RingError(error)
    }
}

#[derive(Debug)]
struct KeyRejectedError(KeyRejected);

impl fmt::Display for KeyRejectedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Ed25519 key parsing failed (invalid PKCS#8 format or corrupted key): {:?}",
            self.0
        )
    }
}

impl Error for KeyRejectedError {}

impl From<KeyRejected> for KeyRejectedError {
    fn from(error: KeyRejected) -> Self {
        KeyRejectedError(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Negative Tests for Signature Verification ====================

    #[test]
    fn test_verify_empty_signature_rejected() {
        let (_, public_key) = generate_keys().expect("key generation should succeed");
        let data = "test data to verify";

        // Empty base64 string decodes to empty bytes
        let result = verify_string(public_key, data, "");
        assert!(result.is_err(), "Empty signature should be rejected");
    }

    #[test]
    fn test_verify_malformed_base64_signature_rejected() {
        let (_, public_key) = generate_keys().expect("key generation should succeed");
        let data = "test data to verify";

        // Invalid base64 characters
        let invalid_signatures = [
            "!!!not-valid-base64!!!",
            "abc@#$%",
            "SGVsbG8gV29ybGQ", // Valid base64 but wrong length for Ed25519
            "====",            // Only padding
        ];

        for invalid_sig in invalid_signatures {
            let result = verify_string(public_key.clone(), data, invalid_sig);
            assert!(
                result.is_err(),
                "Malformed signature '{}' should be rejected",
                invalid_sig
            );
        }
    }

    #[test]
    fn test_verify_wrong_signature_rejected() {
        let (private_key, public_key) = generate_keys().expect("key generation should succeed");
        let original_data = "original data".to_string();
        let tampered_data = "tampered data";

        // Sign the original data
        let signature = sign_string(private_key, &original_data).expect("signing should succeed");

        // Verify with tampered data should fail
        let result = verify_string(public_key, tampered_data, &signature);
        assert!(
            result.is_err(),
            "Signature verification with tampered data should fail"
        );
    }

    #[test]
    fn test_verify_signature_from_different_key_rejected() {
        let (private_key_1, _public_key_1) =
            generate_keys().expect("key generation should succeed");
        let (_, public_key_2) = generate_keys().expect("key generation should succeed");
        let data = "test data".to_string();

        // Sign with key 1
        let signature = sign_string(private_key_1, &data).expect("signing should succeed");

        // Verify with key 2 should fail
        let result = verify_string(public_key_2, &data, &signature);
        assert!(
            result.is_err(),
            "Signature from different key should be rejected"
        );
    }

    #[test]
    fn test_verify_truncated_signature_rejected() {
        let (private_key, public_key) = generate_keys().expect("key generation should succeed");
        let data = "test data".to_string();

        // Sign the data
        let signature = sign_string(private_key, &data).expect("signing should succeed");

        // Truncate the signature (take only half)
        let truncated = &signature[..signature.len() / 2];
        let result = verify_string(public_key, &data, truncated);
        assert!(result.is_err(), "Truncated signature should be rejected");
    }

    #[test]
    fn test_verify_corrupted_signature_rejected() {
        let (private_key, public_key) = generate_keys().expect("key generation should succeed");
        let data = "test data".to_string();

        // Sign the data
        let signature = sign_string(private_key, &data).expect("signing should succeed");

        // Corrupt the signature by flipping some bytes
        let mut sig_bytes = STANDARD.decode(&signature).expect("decode should succeed");
        if !sig_bytes.is_empty() {
            sig_bytes[0] ^= 0xFF; // Flip first byte
            let mid = sig_bytes.len() / 2;
            sig_bytes[mid] ^= 0xFF; // Flip middle byte
        }
        let corrupted = STANDARD.encode(&sig_bytes);

        let result = verify_string(public_key, &data, &corrupted);
        assert!(result.is_err(), "Corrupted signature should be rejected");
    }

    #[test]
    fn test_verify_invalid_public_key_rejected() {
        let (private_key, _) = generate_keys().expect("key generation should succeed");
        let data = "test data".to_string();

        // Sign the data
        let signature = sign_string(private_key, &data).expect("signing should succeed");

        // Use invalid public keys
        let invalid_public_keys: Vec<Vec<u8>> = vec![
            vec![],         // Empty
            vec![0u8; 16],  // Too short
            vec![0u8; 32],  // Right length but all zeros
            vec![0xFF; 32], // Right length but all 0xFF
            vec![0u8; 64],  // Too long
        ];

        for invalid_key in invalid_public_keys {
            let result = verify_string(invalid_key.clone(), &data, &signature);
            assert!(
                result.is_err(),
                "Invalid public key (len={}) should be rejected",
                invalid_key.len()
            );
        }
    }

    #[test]
    fn test_sign_with_invalid_private_key_rejected() {
        let data = "test data".to_string();

        // Invalid private keys
        let invalid_private_keys: Vec<Vec<u8>> = vec![
            vec![],          // Empty
            vec![0u8; 32],   // Too short (not valid PKCS#8)
            vec![0xFF; 100], // Random garbage
        ];

        for invalid_key in invalid_private_keys {
            let result = sign_string(invalid_key.clone(), &data);
            assert!(
                result.is_err(),
                "Invalid private key (len={}) should be rejected for signing",
                invalid_key.len()
            );
        }
    }

    // ==================== Positive Tests ====================

    #[test]
    fn test_sign_verify_roundtrip() {
        let (private_key, public_key) = generate_keys().expect("key generation should succeed");
        let data = "test data for signing".to_string();

        let signature = sign_string(private_key, &data).expect("signing should succeed");
        let result = verify_string(public_key, &data, &signature);
        assert!(
            result.is_ok(),
            "Valid signature should verify: {:?}",
            result
        );
    }

    #[test]
    fn test_sign_empty_data() {
        let (private_key, public_key) = generate_keys().expect("key generation should succeed");
        let data = "".to_string();

        let signature = sign_string(private_key, &data).expect("signing empty data should succeed");
        let result = verify_string(public_key, &data, &signature);
        assert!(result.is_ok(), "Signature of empty data should verify");
    }

    #[test]
    fn test_sign_large_data() {
        let (private_key, public_key) = generate_keys().expect("key generation should succeed");
        let data = "x".repeat(1_000_000); // 1MB of data

        let signature = sign_string(private_key, &data).expect("signing large data should succeed");
        let result = verify_string(public_key, &data, &signature);
        assert!(result.is_ok(), "Signature of large data should verify");
    }
}
