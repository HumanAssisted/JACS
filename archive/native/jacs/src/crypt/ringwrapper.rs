//! Native facade for Ed25519 sign / verify / generate.
//!
//! After Task 011 (Wave 6), the protocol-layer Ed25519 code lives in
//! [`jacs_core::sign::Ed25519DalekSigner`]. This module is now a thin
//! wrapper that preserves the historical native API surface
//! (`generate_keys`, `sign_string`, `verify_string`) plus the existing
//! `tracing` log lines (PRD §10.1 — operational surface unchanged).
//!
//! `ring` is still pulled in as a build-time dep elsewhere in `jacs`,
//! but no `ring::*` types remain in this file. Removal from the
//! workspace is deferred to a follow-up per PRD §9.

use crate::error::JacsError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jacs_core::sign::{DetachedSigner, Ed25519DalekSigner};
use tracing::{debug, trace, warn};

/// Generate a fresh Ed25519 keypair.
///
/// Returns `(pkcs8_v2_private_key_bytes, raw_public_key_bytes)` —
/// historically the PKCS#8 wrapping was what `ring::Ed25519KeyPair::
/// generate_pkcs8` produced. After the delegation we emit equivalent
/// PKCS#8 v2 via `ed25519-dalek` so existing storage code reads and
/// writes the same on-disk format.
#[must_use = "generated keys must be stored securely"]
pub fn generate_keys() -> Result<(Vec<u8>, Vec<u8>), JacsError> {
    trace!("Generating Ed25519 keypair");
    let signer = Ed25519DalekSigner::generate().map_err(|e| {
        JacsError::CryptoError(format!("Ed25519 cryptographic operation failed: {e:?}"))
    })?;
    // Reconstruct the PKCS#8 v2 byte sequence so callers (e.g.
    // `keystore::FsEncryptedStore`) keep the same on-disk private-key
    // format.
    let public_key = signer.public_key().to_vec();
    let pkcs8_bytes = export_pkcs8_v2(&signer)?;
    debug!(
        public_key_len = public_key.len(),
        private_key_len = pkcs8_bytes.len(),
        "Ed25519 keypair generated"
    );
    Ok((pkcs8_bytes, public_key))
}

/// Sign `data` with `secret_key` (PKCS#8 v1 or v2 bytes).
#[must_use = "signature must be stored or transmitted"]
pub fn sign_string(secret_key: Vec<u8>, data: &String) -> Result<String, JacsError> {
    trace!(data_len = data.len(), "Ed25519 signing starting");
    let signer = Ed25519DalekSigner::from_pkcs8(&secret_key).map_err(|e| {
        JacsError::CryptoError(format!(
            "Ed25519 key parsing failed (invalid PKCS#8 format or corrupted key): {e:?}"
        ))
    })?;
    let sig = signer.sign(data.as_bytes()).map_err(|e| {
        JacsError::CryptoError(format!("Ed25519 cryptographic operation failed: {e:?}"))
    })?;
    let signature_base64 = STANDARD.encode(&sig);
    trace!(
        signature_len = signature_base64.len(),
        "Ed25519 signing completed"
    );
    Ok(signature_base64)
}

/// Verify a base64-STANDARD-encoded Ed25519 signature.
#[must_use = "signature verification result must be checked"]
pub fn verify_string(
    public_key: Vec<u8>,
    data: &str,
    signature_base64: &str,
) -> Result<(), JacsError> {
    trace!(
        data_len = data.len(),
        public_key_len = public_key.len(),
        "Ed25519 verification starting"
    );
    let signature_bytes = STANDARD
        .decode(signature_base64)
        .map_err(|e| JacsError::CryptoError(format!("Invalid base64 signature: {}", e)))?;
    match Ed25519DalekSigner::verify(&public_key, data.as_bytes(), &signature_bytes) {
        Ok(()) => {
            debug!("Ed25519 signature verification succeeded");
            Ok(())
        }
        Err(e) => {
            warn!("Ed25519 signature verification failed");
            Err(JacsError::CryptoError(format!(
                "Ed25519 cryptographic operation failed: {e:?}"
            )))
        }
    }
}

/// Re-export the raw private scalar wrapped as a minimal PKCS#8 v2 byte
/// sequence so consumers of `generate_keys()` keep the same on-disk
/// format that the legacy ring path produced.
///
/// The wrapping bytes are deterministic and well-known — we construct
/// them by hand to avoid pulling extra encoding deps:
///
/// ```text
/// 30 51                       SEQUENCE (81 bytes)
///   02 01 01                  INTEGER 1                (PKCS#8 v2)
///   30 05                     SEQUENCE (5 bytes)       AlgorithmIdentifier
///     06 03 2b 65 70          OID 1.3.101.112          (Ed25519)
///   04 22                     OCTET STRING (34 bytes)  CurvePrivateKey
///     04 20 <32 priv bytes>   OCTET STRING (32 bytes)
///   81 21                     [1] (33 bytes)           publicKey, IMPLICIT
///     00 <32 pub bytes>       leading 0x00 + 32 public-key bytes
/// ```
fn export_pkcs8_v2(signer: &Ed25519DalekSigner) -> Result<Vec<u8>, JacsError> {
    // The signer only exposes the public key + sign API; to reconstruct
    // PKCS#8 we need the private scalar. The cleanest path is to ask
    // ed25519-dalek for the PKCS#8 v2 encoding directly via the same
    // `pkcs8` feature jacs-core already depends on.
    //
    // We do this by going back through `jacs_core` rather than calling
    // `ed25519-dalek` here — the `jacs` crate must not depend on
    // `ed25519-dalek` directly per the PRD (jacs-core owns Ed25519).
    signer
        .export_pkcs8_v2()
        .map_err(|e| JacsError::CryptoError(format!("Ed25519 PKCS#8 export failed: {e:?}")))
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
