//! ES256 (ECDSA P-256) ecosystem compatibility keys — keygen + encoding.
//!
//! P2 Task 002: ES256 is NEVER a native JACS signing algorithm. This module
//! only generates and encodes the `ecosystem_signing` compatibility keypair
//! that later tasks use for targeted ecosystem exports (JWKS/DID/A2A cards,
//! AP2 mandates, Agreement-v2-as-VC). Native `jacsSignature` production and
//! verification cannot reach this module.
//!
//! Buy/build note (PRD §9.9): P-256 arithmetic comes from the narrow
//! RustCrypto stack (`p256`), not a broad JOSE framework, and not `ring`
//! (which must stay out of portable core paths).
//!
//! Storage: the private key is PKCS#8 DER, encrypted at rest with the
//! existing AES-256-GCM + Argon2id V2 envelope; the public key is SPKI PEM.
//! The PQ signing library is never used as encryption.

use crate::error::JacsError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use sha2::{Digest, Sha256};

/// A freshly generated ES256 compatibility keypair, ready for storage.
pub struct Es256Keypair {
    /// PKCS#8 v1 DER private key (to be envelope-encrypted before disk).
    pub private_pkcs8_der: Vec<u8>,
    /// SPKI PEM public key (written as-is).
    pub public_spki_pem: String,
    /// SEC1 uncompressed public point (0x04 || x || y), 65 bytes.
    pub public_sec1_uncompressed: Vec<u8>,
    /// RFC 7638 JWK thumbprint (base64url, SHA-256) — the stable `kid`.
    pub kid: String,
}

/// Generate a new P-256 keypair for the `ecosystem_signing` role.
pub fn generate_es256_keypair() -> Result<Es256Keypair, JacsError> {
    let secret = p256::SecretKey::random(&mut rand_core::OsRng);
    let public = secret.public_key();

    let private_pkcs8_der = secret
        .to_pkcs8_der()
        .map_err(|e| JacsError::CryptoError(format!("ES256 PKCS#8 encoding failed: {e}")))?
        .as_bytes()
        .to_vec();

    let public_spki_pem = public
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| JacsError::CryptoError(format!("ES256 SPKI encoding failed: {e}")))?;

    let point = public.to_encoded_point(false);
    let public_sec1_uncompressed = point.as_bytes().to_vec();

    let kid = rfc7638_thumbprint_p256(&public_sec1_uncompressed)?;

    Ok(Es256Keypair {
        private_pkcs8_der,
        public_spki_pem,
        public_sec1_uncompressed,
        kid,
    })
}

/// RFC 7638 JWK thumbprint for a P-256 key from its SEC1 uncompressed point.
///
/// Required members for EC keys, lexicographic order, no whitespace:
/// `{"crv":"P-256","kty":"EC","x":"<b64url>","y":"<b64url>"}` → SHA-256 →
/// base64url (no padding).
pub fn rfc7638_thumbprint_p256(sec1_uncompressed: &[u8]) -> Result<String, JacsError> {
    if sec1_uncompressed.len() != 65 || sec1_uncompressed[0] != 0x04 {
        return Err(JacsError::CryptoError(
            "ES256 thumbprint requires a SEC1 uncompressed point (65 bytes, 0x04 prefix)"
                .to_string(),
        ));
    }
    let x = URL_SAFE_NO_PAD.encode(&sec1_uncompressed[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&sec1_uncompressed[33..65]);
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es256_keypair_generates_and_encodes() {
        let kp = generate_es256_keypair().expect("keygen");
        assert!(!kp.private_pkcs8_der.is_empty());
        assert!(kp.public_spki_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(kp.public_sec1_uncompressed.len(), 65);
        assert_eq!(kp.public_sec1_uncompressed[0], 0x04);
        // RFC 7638 thumbprints are 32 bytes -> 43 base64url chars, no padding.
        assert_eq!(kp.kid.len(), 43);
        assert!(!kp.kid.contains('='));
    }

    #[test]
    fn rfc7638_thumbprint_is_deterministic_and_distinct() {
        let a = generate_es256_keypair().expect("keygen");
        let again = rfc7638_thumbprint_p256(&a.public_sec1_uncompressed).expect("thumbprint");
        assert_eq!(a.kid, again);
        let b = generate_es256_keypair().expect("keygen");
        assert_ne!(a.kid, b.kid);
    }

    #[test]
    fn thumbprint_rejects_compressed_points() {
        let err = rfc7638_thumbprint_p256(&[0x02; 33]).expect_err("compressed rejected");
        assert!(err.to_string().contains("SEC1"));
    }
}
