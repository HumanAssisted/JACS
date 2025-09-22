//! Key management for A2A integration
//! Handles dual key generation (PQC for JACS, RSA/ECDSA for A2A)

use crate::keystore::{FsEncryptedStore, KeySpec, KeyStore};
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
pub fn create_jwk_keys(
    jacs_algorithm: Option<&str>,
    a2a_algorithm: Option<&str>,
) -> Result<DualKeyPair, Box<dyn Error>> {
    // Default algorithms
    let jacs_alg = jacs_algorithm.unwrap_or("dilithium");
    let a2a_alg = a2a_algorithm.unwrap_or("rsa");

    info!("Generating dual keys: JACS={}, A2A={}", jacs_alg, a2a_alg);

    let ks = FsEncryptedStore;

    // Map algorithms to KeyStore format
    let jacs_algo_mapped = match jacs_alg {
        "dilithium" => "pq-dilithium",
        "rsa" => "RSA-PSS",
        "ecdsa" | "es256" => "ring-Ed25519", // Using Ed25519 for ECDSA equivalent
        _ => jacs_alg,
    };

    let a2a_algo_mapped = match a2a_alg {
        "rsa" => "RSA-PSS",
        "ecdsa" | "es256" => "ring-Ed25519", // Using Ed25519 for ECDSA equivalent
        _ => return Err(format!("Unsupported A2A algorithm: {}", a2a_alg).into()),
    };

    // Generate JACS key (post-quantum or traditional)
    let jacs_spec = KeySpec {
        algorithm: jacs_algo_mapped.to_string(),
        key_id: None,
    };
    let (jacs_private, jacs_public) = ks.generate(&jacs_spec)?;

    // Generate A2A-compatible key (RSA or ECDSA)
    let a2a_spec = KeySpec {
        algorithm: a2a_algo_mapped.to_string(),
        key_id: None,
    };
    let (a2a_private, a2a_public) = ks.generate(&a2a_spec)?;

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
    use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};

    // Parse PEM-encoded RSA public key
    let pem_str = std::str::from_utf8(public_key)?;
    let pem = pem::parse(pem_str)?;
    let rsa_key = RsaPublicKey::from_pkcs1_der(&pem.contents())?;

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
pub fn export_ecdsa_as_jwk(_public_key: &[u8], key_id: &str) -> Result<Jwk, Box<dyn Error>> {
    // For now, return a placeholder - full ECDSA support would require
    // parsing the key and extracting x,y coordinates
    Ok(Jwk {
        kty: "EC".to_string(),
        kid: key_id.to_string(),
        alg: "ES256".to_string(),
        use_: "sig".to_string(),
        n: None,
        e: None,
        x: Some(general_purpose::URL_SAFE_NO_PAD.encode(b"placeholder_x")),
        y: Some(general_purpose::URL_SAFE_NO_PAD.encode(b"placeholder_y")),
        crv: Some("P-256".to_string()),
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
        "ecdsa" | "es256" => export_ecdsa_as_jwk(public_key, key_id),
        _ => Err(format!("Cannot export {} key as JWK", algorithm).into()),
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
            "ecdsa" | "es256" => "ES256",
            _ => return Err(format!("Unsupported JWS algorithm: {}", algorithm).into()),
        },
        "typ": "JWT",
        "kid": key_id
    });

    // Base64url encode header and payload
    let header_b64 = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(payload);

    // Create signing input
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Sign using the appropriate algorithm
    let ks = FsEncryptedStore;
    let algo_mapped = match algorithm {
        "rsa" => "RSA-PSS",
        "ecdsa" | "es256" => "ring-Ed25519",
        _ => return Err(format!("Unsupported algorithm: {}", algorithm).into()),
    };

    let signature = ks.sign_detached(private_key, signing_input.as_bytes(), algo_mapped)?;

    // Base64url encode signature
    let signature_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&signature);

    // Construct JWS compact serialization
    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_dual_keys() {
        let result = create_jwk_keys(Some("rsa"), Some("rsa"));
        assert!(result.is_ok());

        let keys = result.unwrap();
        assert!(!keys.jacs_private_key.is_empty());
        assert!(!keys.a2a_private_key.is_empty());
    }

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
