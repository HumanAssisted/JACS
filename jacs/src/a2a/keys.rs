//! Key management for A2A integration
//! Handles dual key generation (PQC for JACS, RSA/ECDSA for A2A)

use crate::error::JacsError;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::error::Error;
use tracing::info;

/// JWK (JSON Web Key) structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    pub use_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>, // RSA modulus
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>, // RSA exponent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>, // ECDSA x coordinate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>, // ECDSA y coordinate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>, // ECDSA curve
}

/// Dual key pair for JACS and A2A
pub struct DualKeyPair {
    pub jacs_private_key: Vec<u8>,
    pub jacs_public_key: Vec<u8>,
    pub jacs_algorithm: String,
    pub a2a_private_key: Vec<u8>,
    pub a2a_public_key: Vec<u8>,
    pub a2a_algorithm: String,
}

/// Create dual keys for both JACS (PQC) and A2A (RSA/ECDSA) compatibility
/// These keys are ephemeral (in-memory only) - they are NOT persisted to disk
pub fn create_jwk_keys(
    jacs_algorithm: Option<&str>,
    a2a_algorithm: Option<&str>,
) -> Result<DualKeyPair, Box<dyn Error>> {
    // Default algorithms
    let jacs_alg = jacs_algorithm.unwrap_or("dilithium");
    let a2a_alg = a2a_algorithm.unwrap_or("rsa");

    info!(
        "Generating ephemeral dual keys: JACS={}, A2A={}",
        jacs_alg, a2a_alg
    );

    // Generate keys directly in memory without file persistence
    let (jacs_private, jacs_public) = match jacs_alg {
        "dilithium" | "pq-dilithium" => crate::crypt::pq::generate_keys()?,
        "rsa" => crate::crypt::rsawrapper::generate_keys()?,
        "ring-Ed25519" => crate::crypt::ringwrapper::generate_keys()?,
        "ecdsa" | "es256" => {
            return Err(JacsError::CryptoError(
                "ECDSA key generation for A2A is not yet implemented in this build".to_string(),
            )
            .into());
        }
        _ => {
            return Err(JacsError::CryptoError(format!(
                "Unsupported JACS algorithm: {}",
                jacs_alg
            ))
            .into());
        }
    };

    let (a2a_private, a2a_public) = match a2a_alg {
        "rsa" => crate::crypt::rsawrapper::generate_keys()?,
        "ring-Ed25519" => crate::crypt::ringwrapper::generate_keys()?,
        "ecdsa" | "es256" => {
            return Err(JacsError::CryptoError(
                "ECDSA key generation for A2A is not yet implemented in this build".to_string(),
            )
            .into());
        }
        _ => {
            return Err(
                JacsError::CryptoError(format!("Unsupported A2A algorithm: {}", a2a_alg)).into(),
            );
        }
    };

    Ok(DualKeyPair {
        jacs_private_key: jacs_private,
        jacs_public_key: jacs_public,
        jacs_algorithm: jacs_alg.to_string(),
        a2a_private_key: a2a_private,
        a2a_public_key: a2a_public,
        a2a_algorithm: a2a_alg.to_string(),
    })
}

/// Export RSA public key as JWK
pub fn export_rsa_as_jwk(public_key: &[u8], key_id: &str) -> Result<Jwk, Box<dyn Error>> {
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey};

    // Parse PEM-encoded RSA public key
    let pem_str = std::str::from_utf8(public_key)?;
    let pem = pem::parse(pem_str)?;

    // Try PKCS#1 first; if it fails, fall back to PKCS#8 SubjectPublicKeyInfo
    let rsa_key = match RsaPublicKey::from_pkcs1_der(pem.contents()) {
        Ok(k) => k,
        Err(_) => RsaPublicKey::from_public_key_der(pem.contents())?,
    };

    // Extract modulus and exponent
    let n = rsa_key.n();
    let e = rsa_key.e();

    // Convert to base64url
    let n_bytes = n.to_bytes_be();
    let e_bytes = e.to_bytes_be();

    let jwk = Jwk {
        kty: "RSA".to_string(),
        kid: key_id.to_string(),
        alg: "RS256".to_string(),
        use_: "sig".to_string(),
        n: Some(general_purpose::URL_SAFE_NO_PAD.encode(&n_bytes)),
        e: Some(general_purpose::URL_SAFE_NO_PAD.encode(&e_bytes)),
        x: None,
        y: None,
        crv: None,
    };

    Ok(jwk)
}

/// Export ECDSA public key as JWK
pub fn export_ed25519_as_jwk(public_key: &[u8], key_id: &str) -> Result<Jwk, Box<dyn Error>> {
    let key_bytes = match public_key.len() {
        32 => public_key.to_vec(),
        _ => {
            return Err(JacsError::CryptoError(format!(
                "Ed25519 public key must be 32 bytes, got {} bytes",
                public_key.len()
            ))
            .into());
        }
    };

    Ok(Jwk {
        kty: "OKP".to_string(),
        kid: key_id.to_string(),
        alg: "EdDSA".to_string(),
        use_: "sig".to_string(),
        n: None,
        e: None,
        x: Some(general_purpose::URL_SAFE_NO_PAD.encode(key_bytes)),
        y: None,
        crv: Some("Ed25519".to_string()),
    })
}

/// Export a public key as JWK based on algorithm
pub fn export_as_jwk(
    public_key: &[u8],
    algorithm: &str,
    key_id: &str,
) -> Result<Jwk, Box<dyn Error>> {
    match algorithm {
        "rsa" => export_rsa_as_jwk(public_key, key_id),
        "ring-Ed25519" => export_ed25519_as_jwk(public_key, key_id),
        "ecdsa" | "es256" => Err(JacsError::CryptoError(
            "ECDSA JWK export is not yet implemented in this build".to_string(),
        )
        .into()),
        _ => Err(JacsError::CryptoError(format!("Cannot export {} key as JWK", algorithm)).into()),
    }
}

/// Create a JWK set document
pub fn create_jwk_set(jwks: Vec<Jwk>) -> Value {
    json!({
        "keys": jwks
    })
}

/// Sign data using JWS with the A2A-compatible key
pub fn sign_jws(
    payload: &[u8],
    private_key: &[u8],
    algorithm: &str,
    key_id: &str,
) -> Result<String, Box<dyn Error>> {
    // Create JWS header
    let header = json!({
        "alg": match algorithm {
            "rsa" => "RS256",
            "ring-Ed25519" => "EdDSA",
            "ecdsa" | "es256" => return Err(JacsError::CryptoError("ECDSA JWS signing is not yet implemented in this build".to_string()).into()),
            _ => return Err(JacsError::CryptoError(format!("Unsupported JWS algorithm: {}", algorithm)).into()),
        },
        "typ": "JWT",
        "kid": key_id
    });

    // Base64url encode header and payload
    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);

    // Create signing input
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Sign directly using the crypto wrappers
    let signature = match algorithm {
        "rsa" => {
            let sig_b64 =
                crate::crypt::rsawrapper::sign_string(private_key.to_vec(), &signing_input)?;
            general_purpose::STANDARD.decode(&sig_b64)?
        }
        "ring-Ed25519" => {
            let sig_b64 =
                crate::crypt::ringwrapper::sign_string(private_key.to_vec(), &signing_input)?;
            general_purpose::STANDARD.decode(&sig_b64)?
        }
        "ecdsa" | "es256" => {
            return Err(JacsError::CryptoError(
                "ECDSA JWS signing is not yet implemented in this build".to_string(),
            )
            .into());
        }
        _ => {
            return Err(
                JacsError::CryptoError(format!("Unsupported algorithm: {}", algorithm)).into(),
            );
        }
    };

    // Base64url encode signature
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&signature);

    // Construct JWS compact serialization
    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

/// Verify a JWS compact serialization using a public key.
///
/// Parses the JWS compact format (`header.payload.signature`), extracts the
/// algorithm from the header, and verifies the signature using the appropriate
/// crypto backend.
///
/// # Arguments
///
/// * `jws` - JWS compact serialization string
/// * `public_key` - The public key bytes for verification
/// * `algorithm` - The key algorithm (e.g., "rsa", "ring-Ed25519")
///
/// # Returns
///
/// `Ok(payload_bytes)` if the signature is valid, or an error if verification fails.
pub fn verify_jws(
    jws: &str,
    public_key: &[u8],
    algorithm: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(JacsError::CryptoError(format!(
            "Invalid JWS format: expected 3 parts, got {}",
            parts.len()
        ))
        .into());
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64_url = parts[2];

    // Decode and validate header
    let header_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| JacsError::CryptoError(format!("Invalid JWS header encoding: {}", e)))?;
    let header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JacsError::CryptoError(format!("Invalid JWS header JSON: {}", e)))?;

    // Verify algorithm matches
    let expected_alg = match algorithm {
        "rsa" => "RS256",
        "ring-Ed25519" => "EdDSA",
        _ => {
            return Err(JacsError::CryptoError(format!(
                "Unsupported JWS verification algorithm: {}",
                algorithm
            ))
            .into());
        }
    };
    if let Some(header_alg) = header.get("alg").and_then(|v| v.as_str()) {
        if header_alg != expected_alg {
            return Err(JacsError::CryptoError(format!(
                "JWS algorithm mismatch: header says '{}', expected '{}'",
                header_alg, expected_alg
            ))
            .into());
        }
    }

    // Reconstruct signing input
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Decode the signature from base64url to raw bytes, then re-encode as standard base64
    // (the crypto verify_string functions expect standard base64)
    let signature_bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64_url)
        .map_err(|e| JacsError::CryptoError(format!("Invalid JWS signature encoding: {}", e)))?;
    let signature_standard_b64 = general_purpose::STANDARD.encode(&signature_bytes);

    // Verify the signature
    match algorithm {
        "rsa" => {
            crate::crypt::rsawrapper::verify_string(
                public_key.to_vec(),
                &signing_input,
                &signature_standard_b64,
            )?;
        }
        "ring-Ed25519" => {
            crate::crypt::ringwrapper::verify_string(
                public_key.to_vec(),
                &signing_input,
                &signature_standard_b64,
            )?;
        }
        _ => {
            return Err(JacsError::CryptoError(format!(
                "Unsupported verification algorithm: {}",
                algorithm
            ))
            .into());
        }
    }

    // Decode and return payload
    let payload = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| JacsError::CryptoError(format!("Invalid JWS payload encoding: {}", e)))?;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_jwk_set() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test-key".to_string(),
            alg: "RS256".to_string(),
            use_: "sig".to_string(),
            n: Some("test_n".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };

        let jwk_set = create_jwk_set(vec![jwk]);
        assert!(jwk_set["keys"].is_array());
    }
}
