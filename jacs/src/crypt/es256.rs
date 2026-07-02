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

/// Multibase/Multikey encoding of a P-256 public key from its SPKI PEM:
/// multicodec `p256-pub` (varint 0x80 0x24) + 33-byte compressed SEC1
/// point, base58btc with the `z` prefix. This is the `publicKeyMultibase`
/// form required by `Multikey` verification methods — the type
/// `ecdsa-jcs-2019` Data Integrity verifiers resolve.
pub fn multikey_from_spki_pem(pem: &str) -> Result<String, JacsError> {
    use p256::pkcs8::DecodePublicKey;
    let public = p256::PublicKey::from_public_key_pem(pem)
        .map_err(|e| JacsError::CryptoError(format!("ES256 SPKI PEM parse failed: {e}")))?;
    let compressed = public.to_encoded_point(true);
    let mut bytes = vec![0x80u8, 0x24u8]; // varint multicodec p256-pub (0x1200)
    bytes.extend_from_slice(compressed.as_bytes());
    Ok(format!("z{}", bs58::encode(bytes).into_string()))
}

/// Sign `signing_input` with the (decrypted, PKCS#8 DER) ES256 private
/// key, returning the JOSE signature form: fixed-width 64-byte `r || s`.
///
/// `pub(crate)` on purpose (P2 FR25): raw ES256 signing is never public
/// API — only named, scope-checked exporters (A2A card, AP2 mandate,
/// Agreement-v2-as-VC) reach it. There is no arbitrary-document +
/// caller-chosen-algorithm surface.
// Until Task 004b (AP2 mandate) lands, the only caller is the a2a-gated
// card exporter — allow dead_code in default-feature builds only.
#[cfg_attr(not(feature = "a2a"), allow(dead_code))]
pub(crate) fn sign_es256_jose(
    private_pkcs8_der: &[u8],
    signing_input: &[u8],
) -> Result<Vec<u8>, JacsError> {
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(private_pkcs8_der)
        .map_err(|e| JacsError::CryptoError(format!("ES256 PKCS#8 private parse failed: {e}")))?;
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a JOSE-form (64-byte `r || s`) ES256 signature against a SPKI
/// PEM public key. Used by exporter tests and JACS-side re-verification;
/// never reachable from native document verification.
pub fn verify_es256_jose(
    public_spki_pem: &str,
    signing_input: &[u8],
    signature_rs: &[u8],
) -> Result<(), JacsError> {
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;
    let verifying_key = p256::ecdsa::VerifyingKey::from_public_key_pem(public_spki_pem)
        .map_err(|e| JacsError::CryptoError(format!("ES256 SPKI PEM parse failed: {e}")))?;
    let signature = p256::ecdsa::Signature::from_slice(signature_rs)
        .map_err(|e| JacsError::CryptoError(format!("ES256 signature parse failed: {e}")))?;
    verifying_key
        .verify(signing_input, &signature)
        .map_err(|e| JacsError::CryptoError(format!("ES256 verification failed: {e}")))
}

/// Derive the base64url JWK `x`/`y` coordinates from an ES256 SPKI PEM
/// public key (as written to `jacs.ecosystem.public.pem`).
pub fn jwk_xy_from_spki_pem(pem: &str) -> Result<(String, String), JacsError> {
    use p256::pkcs8::DecodePublicKey;
    let public = p256::PublicKey::from_public_key_pem(pem)
        .map_err(|e| JacsError::CryptoError(format!("ES256 SPKI PEM parse failed: {e}")))?;
    let point = public.to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 {
        return Err(JacsError::CryptoError(
            "unexpected SEC1 point length for P-256".to_string(),
        ));
    }
    Ok((
        URL_SAFE_NO_PAD.encode(&bytes[1..33]),
        URL_SAFE_NO_PAD.encode(&bytes[33..65]),
    ))
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
