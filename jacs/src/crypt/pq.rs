use pqcrypto_dilithium::dilithium5::{
    DetachedSignature, PublicKey, SecretKey, detached_sign, keypair, verify_detached_signature,
};
use pqcrypto_traits::sign::DetachedSignature as DetachedSignatureTrait;
use pqcrypto_traits::sign::PublicKey as PublicKeyTrait;
use pqcrypto_traits::sign::SecretKey as SecretKeyTrait;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use std::error::Error;
use tracing::{debug, trace, warn};

#[must_use = "generated keys must be stored securely"]
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    trace!("Generating Dilithium5 keypair");
    let (pk, sk) = keypair();
    let sk_bytes = sk.as_bytes().to_vec();
    let pk_bytes = pk.as_bytes().to_vec();
    debug!(
        public_key_len = pk_bytes.len(),
        private_key_len = sk_bytes.len(),
        "Dilithium5 keypair generated"
    );
    Ok((sk_bytes, pk_bytes))
}

#[must_use = "signature must be stored or transmitted"]
pub fn sign_string(secret_key: Vec<u8>, data: &String) -> Result<String, Box<dyn Error>> {
    trace!(data_len = data.len(), "Dilithium5 signing starting");
    let secret_key_obj: SecretKey = SecretKey::from_bytes(&secret_key)?;
    // Produce a detached signature, not a signed message
    let signature: DetachedSignature = detached_sign(data.as_bytes(), &secret_key_obj);
    let signature_base64 = B64.encode(signature.as_bytes());
    trace!(
        signature_len = signature_base64.len(),
        "Dilithium5 signing completed"
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
        "Dilithium5 verification starting"
    );
    let signature_bytes = B64.decode(signature_base64)?;
    let signature = DetachedSignature::from_bytes(&signature_bytes)?;
    let pk = PublicKey::from_bytes(&public_key)?;
    match verify_detached_signature(&signature, data.as_bytes(), &pk) {
        Ok(()) => {
            debug!("Dilithium5 signature verification succeeded");
            Ok(())
        }
        Err(e) => {
            warn!("Dilithium5 signature verification failed");
            Err(format!("Dilithium5 signature verification failed: {:?}", e).into())
        }
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
            "====", // Only padding
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
        let mut sig_bytes = B64.decode(&signature).expect("decode should succeed");
        if !sig_bytes.is_empty() {
            sig_bytes[0] ^= 0xFF; // Flip first byte
            let mid = sig_bytes.len() / 2;
            sig_bytes[mid] ^= 0xFF; // Flip middle byte
        }
        let corrupted = B64.encode(&sig_bytes);

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
            vec![],           // Empty
            vec![0u8; 16],    // Too short
            vec![0u8; 100],   // Wrong length
            vec![0xFF; 1000], // Random garbage
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
            vec![0u8; 32],   // Too short
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
        let data = "x".repeat(100_000); // 100KB of data

        let signature = sign_string(private_key, &data).expect("signing large data should succeed");
        let result = verify_string(public_key, &data, &signature);
        assert!(result.is_ok(), "Signature of large data should verify");
    }
}
