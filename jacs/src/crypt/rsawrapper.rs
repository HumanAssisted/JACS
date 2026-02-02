use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::pss::VerifyingKey;
use rsa::pss::{BlindedSigningKey, Signature};
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256;
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::{RandomizedSigner, SignatureEncoding, Verifier};
use tracing::{debug, trace, warn};

/// best for pure Rust, least secure
// Use smaller key size for tests, larger for production
static BITSOFBITS: usize = 4096; // Production value
//static BITSOFBITS: usize = 2048;

/// returns public, public_filepath, private, private_filepath
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, BITSOFBITS)
        .map_err(|e| format!("Failed to generate RSA key: {}", e))?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::CRLF)?;

    Ok((
        private_key_pem.as_bytes().to_vec(),
        public_key_pem.as_bytes().to_vec(),
    ))
}

pub fn sign_string(
    private_key_content: Vec<u8>,
    data: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let private_key_content_converted = std::str::from_utf8(&private_key_content)
        .map_err(|e| format!("Private key is not valid UTF-8: {}", e))?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_content_converted)?;
    let signing_key = BlindedSigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign_with_rng(&mut OsRng, data.as_bytes());
    let signature_bytes = signature.to_bytes();
    let signature_base64 = B64.encode(&signature_bytes);
    trace!(
        data_len = data.len(),
        signature_len = signature_base64.len(),
        "RSA-PSS signing completed"
    );
    Ok(signature_base64)
}

pub fn verify_string(
    public_key_content: Vec<u8>,
    data: &str,
    signature_base64: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key_content_converted = std::str::from_utf8(&public_key_content)
        .map_err(|e| format!("Public key is not valid UTF-8: {}", e))?;

    trace!(
        public_key_len = public_key_content.len(),
        "Parsing RSA public key"
    );

    let public_key = RsaPublicKey::from_public_key_pem(public_key_content_converted)?;

    // Updated instantiation of VerifyingKey
    let verifying_key = VerifyingKey::<Sha256>::from(public_key);

    trace!(
        data_len = data.len(),
        signature_len = signature_base64.len(),
        "RSA-PSS verification starting"
    );

    let signature_bytes = B64.decode(signature_base64)?;
    let signature = Signature::try_from(signature_bytes.as_slice())?;

    let result = verifying_key.verify(data.as_bytes(), &signature);

    match result {
        Ok(()) => {
            debug!("RSA-PSS signature verification succeeded");
            Ok(())
        }
        Err(e) => {
            warn!("RSA-PSS signature verification failed");
            Err(Box::new(std::io::Error::other(format!(
                "Signature verification failed: {}",
                e
            ))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use smaller key size for tests to speed up key generation
    // Production code uses 4096 bits but tests can use 2048 for speed
    fn generate_test_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| format!("Failed to generate RSA key: {}", e))?;
        let public_key = RsaPublicKey::from(&private_key);

        let private_key_pem = private_key.to_pkcs8_pem(LineEnding::CRLF)?;
        let public_key_pem = public_key.to_public_key_pem(LineEnding::CRLF)?;

        Ok((
            private_key_pem.as_bytes().to_vec(),
            public_key_pem.as_bytes().to_vec(),
        ))
    }

    // ==================== Negative Tests for Signature Verification ====================

    #[test]
    fn test_verify_empty_signature_rejected() {
        let (_, public_key) = generate_test_keys().expect("key generation should succeed");
        let data = "test data to verify";

        // Empty base64 string
        let result = verify_string(public_key, data, "");
        assert!(result.is_err(), "Empty signature should be rejected");
    }

    #[test]
    fn test_verify_malformed_base64_signature_rejected() {
        let (_, public_key) = generate_test_keys().expect("key generation should succeed");
        let data = "test data to verify";

        // Invalid base64 characters
        let invalid_signatures = [
            "!!!not-valid-base64!!!",
            "abc@#$%",
            "====",             // Only padding
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
        let (private_key, public_key) = generate_test_keys().expect("key generation should succeed");
        let original_data = "original data";
        let tampered_data = "tampered data";

        // Sign the original data
        let signature = sign_string(private_key, original_data).expect("signing should succeed");

        // Verify with tampered data should fail
        let result = verify_string(public_key, tampered_data, &signature);
        assert!(
            result.is_err(),
            "Signature verification with tampered data should fail"
        );
    }

    #[test]
    fn test_verify_signature_from_different_key_rejected() {
        let (private_key_1, _public_key_1) = generate_test_keys().expect("key generation should succeed");
        let (_, public_key_2) = generate_test_keys().expect("key generation should succeed");
        let data = "test data";

        // Sign with key 1
        let signature = sign_string(private_key_1, data).expect("signing should succeed");

        // Verify with key 2 should fail
        let result = verify_string(public_key_2, data, &signature);
        assert!(
            result.is_err(),
            "Signature from different key should be rejected"
        );
    }

    #[test]
    fn test_verify_truncated_signature_rejected() {
        let (private_key, public_key) = generate_test_keys().expect("key generation should succeed");
        let data = "test data";

        // Sign the data
        let signature = sign_string(private_key, data).expect("signing should succeed");

        // Truncate the signature (take only half)
        let truncated = &signature[..signature.len() / 2];
        let result = verify_string(public_key, data, truncated);
        assert!(result.is_err(), "Truncated signature should be rejected");
    }

    #[test]
    fn test_verify_corrupted_signature_rejected() {
        let (private_key, public_key) = generate_test_keys().expect("key generation should succeed");
        let data = "test data";

        // Sign the data
        let signature = sign_string(private_key, data).expect("signing should succeed");

        // Corrupt the signature by flipping some bytes
        let mut sig_bytes = B64.decode(&signature).expect("decode should succeed");
        if !sig_bytes.is_empty() {
            sig_bytes[0] ^= 0xFF; // Flip first byte
            let mid = sig_bytes.len() / 2;
            sig_bytes[mid] ^= 0xFF; // Flip middle byte
        }
        let corrupted = B64.encode(&sig_bytes);

        let result = verify_string(public_key, data, &corrupted);
        assert!(result.is_err(), "Corrupted signature should be rejected");
    }

    #[test]
    fn test_verify_invalid_public_key_rejected() {
        let (private_key, _) = generate_test_keys().expect("key generation should succeed");
        let data = "test data";

        // Sign the data
        let signature = sign_string(private_key, data).expect("signing should succeed");

        // Use invalid public keys
        let invalid_public_keys: Vec<Vec<u8>> = vec![
            vec![],                      // Empty
            b"not a pem key".to_vec(),   // Invalid format
            b"-----BEGIN PUBLIC KEY-----\nInvalid\n-----END PUBLIC KEY-----".to_vec(),
        ];

        for invalid_key in invalid_public_keys {
            let result = verify_string(invalid_key.clone(), data, &signature);
            assert!(
                result.is_err(),
                "Invalid public key should be rejected"
            );
        }
    }

    #[test]
    fn test_verify_non_utf8_public_key_rejected() {
        let (private_key, _) = generate_test_keys().expect("key generation should succeed");
        let data = "test data";

        // Sign the data
        let signature = sign_string(private_key, data).expect("signing should succeed");

        // Non-UTF8 bytes
        let invalid_key = vec![0xFF, 0xFE, 0x00, 0x01];
        let result = verify_string(invalid_key, data, &signature);
        assert!(result.is_err(), "Non-UTF8 public key should be rejected");
    }

    #[test]
    fn test_sign_with_invalid_private_key_rejected() {
        let data = "test data";

        // Invalid private keys
        let invalid_private_keys: Vec<Vec<u8>> = vec![
            vec![],                      // Empty
            b"not a pem key".to_vec(),   // Invalid format
            b"-----BEGIN PRIVATE KEY-----\nInvalid\n-----END PRIVATE KEY-----".to_vec(),
        ];

        for invalid_key in invalid_private_keys {
            let result = sign_string(invalid_key.clone(), data);
            assert!(
                result.is_err(),
                "Invalid private key should be rejected for signing"
            );
        }
    }

    #[test]
    fn test_sign_with_non_utf8_private_key_rejected() {
        let data = "test data";

        // Non-UTF8 bytes
        let invalid_key = vec![0xFF, 0xFE, 0x00, 0x01];
        let result = sign_string(invalid_key, data);
        assert!(result.is_err(), "Non-UTF8 private key should be rejected");
    }

    // ==================== Positive Tests ====================

    #[test]
    fn test_sign_verify_roundtrip() {
        let (private_key, public_key) = generate_test_keys().expect("key generation should succeed");
        let data = "test data for signing";

        let signature = sign_string(private_key, data).expect("signing should succeed");
        let result = verify_string(public_key, data, &signature);
        assert!(result.is_ok(), "Valid signature should verify: {:?}", result);
    }

    #[test]
    fn test_sign_empty_data() {
        let (private_key, public_key) = generate_test_keys().expect("key generation should succeed");
        let data = "";

        let signature = sign_string(private_key, data).expect("signing empty data should succeed");
        let result = verify_string(public_key, data, &signature);
        assert!(result.is_ok(), "Signature of empty data should verify");
    }
}
