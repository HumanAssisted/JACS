//! ML-DSA (FIPS-204) signature implementation for post-quantum security
//! Uses ML-DSA-87 (security level 5)

use super::constants::{
    ML_DSA_87_PRIVATE_KEY_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SIGNATURE_SIZE,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use std::error::Error;
use tracing::{debug, trace, warn};

/// Generate ML-DSA-87 keypair
/// Returns (private_key_bytes, public_key_bytes)
#[must_use = "generated keys must be stored securely"]
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let (pk, sk) = ml_dsa_87::KG::try_keygen()?;
    let sk_bytes = sk.into_bytes().to_vec();
    let pk_bytes = pk.into_bytes().to_vec();
    trace!(
        sk_len = sk_bytes.len(),
        pk_len = pk_bytes.len(),
        "ML-DSA-87 keypair generated"
    );
    Ok((sk_bytes, pk_bytes))
}

/// Sign string data with ML-DSA-87 private key
#[must_use = "signature must be stored or transmitted"]
pub fn sign_string(secret_key: Vec<u8>, data: &String) -> Result<String, Box<dyn Error>> {
    trace!(data_len = data.len(), "ML-DSA-87 signing starting");
    // Convert Vec<u8> to fixed-size array
    let sk_array: [u8; ML_DSA_87_PRIVATE_KEY_SIZE] =
        secret_key.try_into().map_err(|v: Vec<u8>| {
            format!(
                "Invalid private key length for ML-DSA-87: expected {} bytes, got {} bytes",
                ML_DSA_87_PRIVATE_KEY_SIZE,
                v.len()
            )
        })?;
    let sk = ml_dsa_87::PrivateKey::try_from_bytes(sk_array)?;
    let sig = sk.try_sign(data.as_bytes(), b"")?; // empty context - returns [u8; 4627]
    let encoded = B64.encode(sig);
    trace!(signature_len = encoded.len(), "ML-DSA-87 signing completed");
    Ok(encoded)
}

/// Verify ML-DSA-87 signature
#[must_use = "signature verification result must be checked"]
pub fn verify_string(
    public_key: Vec<u8>,
    data: &str,
    signature_base64: &str,
) -> Result<(), Box<dyn Error>> {
    trace!(
        data_len = data.len(),
        public_key_len = public_key.len(),
        "ML-DSA-87 verification starting"
    );
    // Convert Vec<u8> to fixed-size array
    let pk_array: [u8; ML_DSA_87_PUBLIC_KEY_SIZE] =
        public_key.try_into().map_err(|v: Vec<u8>| {
            format!(
                "Invalid public key length for ML-DSA-87: expected {} bytes, got {} bytes",
                ML_DSA_87_PUBLIC_KEY_SIZE,
                v.len()
            )
        })?;
    let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_array)?;

    let sig_bytes = B64.decode(signature_base64)?;
    let sig_array: [u8; ML_DSA_87_SIGNATURE_SIZE] =
        sig_bytes.try_into().map_err(|v: Vec<u8>| {
            format!(
                "Invalid signature length for ML-DSA-87: expected {} bytes, got {} bytes",
                ML_DSA_87_SIGNATURE_SIZE,
                v.len()
            )
        })?;

    // verify() returns bool, not Result
    if pk.verify(data.as_bytes(), &sig_array, b"") {
        debug!("ML-DSA-87 signature verification succeeded");
        Ok(())
    } else {
        warn!("ML-DSA-87 signature verification failed");
        Err("ML-DSA signature verification failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (private_key, public_key) = generate_keys().expect("key generation should succeed");
        let data = "ml-dsa-87 test message".to_string();

        let signature = sign_string(private_key, &data).expect("signing should succeed");
        let result = verify_string(public_key, &data, &signature);
        assert!(result.is_ok(), "valid signature should verify");
    }

    #[test]
    fn test_verify_wrong_message_rejected() {
        let (private_key, public_key) = generate_keys().expect("key generation should succeed");
        let original_data = "original message".to_string();
        let tampered_data = "tampered message";

        let signature = sign_string(private_key, &original_data).expect("signing should succeed");
        let result = verify_string(public_key, tampered_data, &signature);
        assert!(result.is_err(), "tampered message should not verify");
    }

    #[test]
    fn test_verify_malformed_base64_signature_rejected() {
        let (_, public_key) = generate_keys().expect("key generation should succeed");
        let data = "test data";

        for invalid_sig in ["!!!not-base64!!!", "abc@#$%", "===="] {
            let result = verify_string(public_key.clone(), data, invalid_sig);
            assert!(result.is_err(), "malformed signature should be rejected");
        }
    }

    #[test]
    fn test_verify_wrong_signature_length_rejected() {
        let (private_key, public_key) = generate_keys().expect("key generation should succeed");
        let data = "test data".to_string();

        let signature = sign_string(private_key, &data).expect("signing should succeed");
        let mut sig_bytes = B64.decode(&signature).expect("decode should succeed");
        sig_bytes.truncate(sig_bytes.len().saturating_sub(8));
        let truncated = B64.encode(sig_bytes);

        let result = verify_string(public_key, &data, &truncated);
        assert!(
            result.is_err(),
            "signature with wrong length should be rejected"
        );
    }

    #[test]
    fn test_verify_invalid_public_key_length_rejected() {
        let (private_key, _) = generate_keys().expect("key generation should succeed");
        let data = "test data".to_string();
        let signature = sign_string(private_key, &data).expect("signing should succeed");

        let invalid_public_keys = vec![vec![], vec![0u8; 64], vec![0xFF; 1024]];
        for invalid_key in invalid_public_keys {
            let result = verify_string(invalid_key, &data, &signature);
            assert!(result.is_err(), "invalid public key should be rejected");
        }
    }

    #[test]
    fn test_sign_invalid_private_key_length_rejected() {
        let data = "test data".to_string();
        for invalid_key in [vec![], vec![0u8; 64], vec![0xAA; 1024]] {
            let result = sign_string(invalid_key, &data);
            assert!(result.is_err(), "invalid private key should be rejected");
        }
    }
}
