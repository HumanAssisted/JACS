//! Native facade for ML-DSA (FIPS-204) post-quantum signatures.
//!
//! After Task 011 (Wave 6), the protocol-layer pq2025 code lives in
//! [`jacs_core::sign::Pq2025Signer`]. This module is now a thin wrapper
//! that preserves the historical native API surface (`generate_keys`,
//! `sign_string`, `verify_string`) plus the existing `tracing` log
//! lines (PRD §10.1 — operational surface unchanged).

use crate::error::JacsError;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use jacs_core::sign::{DetachedSigner, Pq2025Signer};
use tracing::{debug, trace, warn};

/// Generate an ML-DSA-87 keypair.
///
/// Returns `(private_key_bytes, public_key_bytes)`.
#[must_use = "generated keys must be stored securely"]
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), JacsError> {
    let signer = Pq2025Signer::generate()
        .map_err(|e| JacsError::CryptoError(format!("ML-DSA-87 key generation failed: {e}")))?;
    let pk_bytes = signer.public_key().to_vec();
    // Pull the private bytes back out via export. We do this by re-signing
    // a known message and re-deriving — but the simpler path is the
    // export helper on the signer.
    let sk_bytes = signer
        .export_private_bytes()
        .map_err(|e| JacsError::CryptoError(format!("ML-DSA-87 export failed: {e}")))?;
    trace!(
        sk_len = sk_bytes.len(),
        pk_len = pk_bytes.len(),
        "ML-DSA-87 keypair generated"
    );
    Ok((sk_bytes, pk_bytes))
}

/// Sign string data with an ML-DSA-87 private key.
#[must_use = "signature must be stored or transmitted"]
pub fn sign_string(secret_key: Vec<u8>, data: &String) -> Result<String, JacsError> {
    trace!(data_len = data.len(), "ML-DSA-87 signing starting");
    let signer = Pq2025Signer::from_private_bytes(&secret_key).map_err(|e| {
        // Preserve the historical message shape that existing tests
        // (`test_sign_invalid_private_key_length_rejected`) accept.
        let msg = e.to_string();
        if msg.contains("expected") && msg.contains("got") {
            JacsError::from(format!(
                "Invalid private key length for ML-DSA-87: expected 4896 bytes, got {} bytes",
                secret_key.len()
            ))
        } else {
            JacsError::CryptoError(format!(
                "ML-DSA-87 private key deserialization failed: {msg}"
            ))
        }
    })?;
    let sig = signer
        .sign(data.as_bytes())
        .map_err(|e| JacsError::CryptoError(format!("ML-DSA-87 signing failed: {e}")))?;
    let encoded = B64.encode(sig);
    trace!(signature_len = encoded.len(), "ML-DSA-87 signing completed");
    Ok(encoded)
}

/// Verify an ML-DSA-87 signature.
#[must_use = "signature verification result must be checked"]
pub fn verify_string(
    public_key: Vec<u8>,
    data: &str,
    signature_base64: &str,
) -> Result<(), JacsError> {
    trace!(
        data_len = data.len(),
        public_key_len = public_key.len(),
        "ML-DSA-87 verification starting"
    );
    let sig_bytes = B64
        .decode(signature_base64)
        .map_err(|e| JacsError::CryptoError(format!("Invalid base64 signature: {}", e)))?;
    match Pq2025Signer::verify(&public_key, data.as_bytes(), &sig_bytes) {
        Ok(()) => {
            debug!("ML-DSA-87 signature verification succeeded");
            Ok(())
        }
        Err(e) => {
            warn!("ML-DSA-87 signature verification failed");
            Err(JacsError::from(format!(
                "ML-DSA signature verification failed: {e}"
            )))
        }
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
