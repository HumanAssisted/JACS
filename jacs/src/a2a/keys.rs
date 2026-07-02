//! Key management for A2A integration.
//! Handles dual key generation for JACS plus interoperable Ed25519 A2A keys.

use crate::error::JacsError;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::info;

/// The deliberate FR25 wall (P2 §9.6): ES256 signing IS implemented, but
/// never through this generic caller-chosen-algorithm JWS API — only the
/// named, scope-checked exporters may produce ES256 signatures.
const ES256_JWS_WALL: &str = "ES256 JWS signing is not available through this generic API; \
     use the named exporters (A2A agent card, AP2 mandate, Agreement-v2 VC)";

/// JWK (JSON Web Key) structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    pub use_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
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

/// Create dual keys for both JACS (PQC) and A2A compatibility.
/// These keys are ephemeral (in-memory only) - they are NOT persisted to disk
pub fn create_jwk_keys(
    jacs_algorithm: Option<&str>,
    a2a_algorithm: Option<&str>,
) -> Result<DualKeyPair, JacsError> {
    // Default algorithms
    let jacs_alg = jacs_algorithm.unwrap_or("pq2025");
    let a2a_alg = a2a_algorithm.unwrap_or("ring-Ed25519");

    info!(
        "Generating ephemeral dual keys: JACS={}, A2A={}",
        jacs_alg, a2a_alg
    );

    // ES256 keygen helper (P2 Task 004-B): private = PKCS#8 DER, public =
    // SEC1 uncompressed point (65 bytes) so JWK x/y export can slice it.
    // Delegates to the compatibility ES256 module — the STUB CARVE-OUT is
    // deliberate: only key generation and JWK export delegate; the ES256
    // arms of sign_jws / verify_jws below keep returning errors (FR25 —
    // no generic caller-chosen-algorithm ES256 signing surface). That
    // also means the ES256 PRIVATE halves minted here have NO consumer in
    // this module: callers can only export the public half as a JWK, by
    // design.
    let es256_pair = || -> Result<(Vec<u8>, Vec<u8>), JacsError> {
        let mut kp = crate::crypt::es256::generate_es256_keypair()?;
        // MOVE (not copy) the plaintext DER out of its `Zeroizing` wrapper:
        // `DualKeyPair` holds plain ephemeral `Vec<u8>`s for every algorithm,
        // and `mem::take` transfers the allocation so no duplicate plaintext
        // buffer is left behind un-wiped (the emptied wrapper still zeroizes
        // on drop).
        let private = std::mem::take(&mut *kp.private_pkcs8_der);
        Ok((private, kp.public_sec1_uncompressed))
    };

    // Generate keys directly in memory without file persistence
    let (jacs_private, jacs_public) = match jacs_alg {
        "pq2025" => crate::crypt::pq2025::generate_keys()?,
        "ring-Ed25519" => crate::crypt::ringwrapper::generate_keys()?,
        "ecdsa" | "es256" => es256_pair()?,
        _ => {
            return Err(JacsError::CryptoError(format!(
                "Unsupported JACS algorithm: {}",
                jacs_alg
            )));
        }
    };

    let (a2a_private, a2a_public) = match a2a_alg {
        "ring-Ed25519" => crate::crypt::ringwrapper::generate_keys()?,
        "ecdsa" | "es256" => es256_pair()?,
        _ => {
            return Err(JacsError::CryptoError(format!(
                "Unsupported A2A algorithm: {}",
                a2a_alg
            )));
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

/// Export Ed25519 public key as JWK
pub fn export_ed25519_as_jwk(public_key: &[u8], key_id: &str) -> Result<Jwk, JacsError> {
    let key_bytes = match public_key.len() {
        32 => public_key.to_vec(),
        _ => {
            return Err(JacsError::CryptoError(format!(
                "Ed25519 public key must be 32 bytes, got {} bytes",
                public_key.len()
            )));
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

/// Export an ES256 (P-256) public key as JWK from its SEC1 uncompressed
/// point (65 bytes: 0x04 || x || y). P2 Task 004-B stub carve-out: JWK
/// EXPORT delegates to real code; ES256 signing in `sign_jws` does not.
pub fn export_es256_as_jwk(public_key: &[u8], key_id: &str) -> Result<Jwk, JacsError> {
    let (x, y) = crate::crypt::es256::jwk_xy_from_sec1(public_key)?;
    Ok(Jwk {
        kty: "EC".to_string(),
        kid: key_id.to_string(),
        alg: "ES256".to_string(),
        use_: "sig".to_string(),
        n: None,
        e: None,
        x: Some(x),
        y: Some(y),
        crv: Some("P-256".to_string()),
    })
}

/// Export a public key as JWK based on algorithm
pub fn export_as_jwk(public_key: &[u8], algorithm: &str, key_id: &str) -> Result<Jwk, JacsError> {
    match algorithm {
        "ring-Ed25519" => export_ed25519_as_jwk(public_key, key_id),
        "ecdsa" | "es256" => export_es256_as_jwk(public_key, key_id),
        _ => Err(JacsError::CryptoError(format!(
            "Cannot export {} key as JWK",
            algorithm
        ))),
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
) -> Result<String, JacsError> {
    crate::crypt::ensure_private_key_operation_allowed(algorithm, "A2A JWS signing")?;

    // Create JWS header. The ES256 arms are a deliberate FR25 wall, not a
    // missing feature: ES256 signing exists but is only reachable through
    // the named, scope-checked exporters.
    let header = json!({
        "alg": match algorithm {
            "ring-Ed25519" => "EdDSA",
            "ecdsa" | "es256" => return Err(JacsError::CryptoError(ES256_JWS_WALL.to_string())),
            _ => return Err(JacsError::CryptoError(format!("Unsupported JWS algorithm: {}", algorithm))),
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
        "ring-Ed25519" => {
            let sig_b64 =
                crate::crypt::ringwrapper::sign_string(private_key.to_vec(), &signing_input)?;
            general_purpose::STANDARD.decode(&sig_b64)?
        }
        "ecdsa" | "es256" => {
            // Unreachable in practice (the header match above already
            // returned), kept so both arms state the same FR25 wall.
            return Err(JacsError::CryptoError(ES256_JWS_WALL.to_string()));
        }
        _ => {
            return Err(JacsError::CryptoError(format!(
                "Unsupported algorithm: {}",
                algorithm
            )));
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
/// * `algorithm` - The key algorithm (for example, "ring-Ed25519")
///
/// # Returns
///
/// `Ok(payload_bytes)` if the signature is valid, or an error if verification fails.
pub fn verify_jws(jws: &str, public_key: &[u8], algorithm: &str) -> Result<Vec<u8>, JacsError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(JacsError::CryptoError(format!(
            "Invalid JWS format: expected 3 parts, got {}",
            parts.len()
        )));
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
        "ring-Ed25519" => "EdDSA",
        _ => {
            return Err(JacsError::CryptoError(format!(
                "Unsupported JWS verification algorithm: {}",
                algorithm
            )));
        }
    };
    if let Some(header_alg) = header.get("alg").and_then(|v| v.as_str())
        && header_alg != expected_alg
    {
        return Err(JacsError::CryptoError(format!(
            "JWS algorithm mismatch: header says '{}', expected '{}'",
            header_alg, expected_alg
        )));
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
            )));
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
            kty: "OKP".to_string(),
            kid: "test-key".to_string(),
            alg: "EdDSA".to_string(),
            use_: "sig".to_string(),
            n: None,
            e: None,
            x: Some("test_x".to_string()),
            y: None,
            crv: Some("Ed25519".to_string()),
        };

        let jwk_set = create_jwk_set(vec![jwk]);
        assert!(jwk_set["keys"].is_array());
    }
}
