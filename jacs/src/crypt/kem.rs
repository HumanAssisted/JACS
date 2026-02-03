//! ML-KEM (FIPS-203) Key Encapsulation Mechanism
//! Provides seal/open operations using ML-KEM-768 + HKDF + AES-GCM

use super::constants::{
    AES_256_KEY_SIZE, AES_GCM_NONCE_SIZE, HKDF_INFO_JACS_PQ2025_AEAD, ML_KEM_768_CIPHERTEXT_SIZE,
    ML_KEM_768_DECAPS_KEY_SIZE, ML_KEM_768_ENCAPS_KEY_SIZE,
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use std::error::Error;

/// Generate ML-KEM-768 keypair
/// Returns (private_key_bytes, public_key_bytes)
pub fn generate_kem_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let (ek, dk) = ml_kem_768::KG::try_keygen()?;
    Ok((dk.into_bytes().to_vec(), ek.into_bytes().to_vec()))
}

/// Seal (encrypt) data to recipient's public key
/// Returns (kem_ciphertext, nonce, aead_ciphertext)
#[allow(clippy::type_complexity)]
pub fn seal(
    recipient_pub: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; AES_GCM_NONCE_SIZE], Vec<u8>), Box<dyn Error>> {
    // Convert slice to fixed-size array
    let ek_array: [u8; ML_KEM_768_ENCAPS_KEY_SIZE] = recipient_pub
        .try_into()
        .map_err(|_| {
            format!(
                "Invalid encapsulation key length for ML-KEM-768: expected {} bytes, got {} bytes",
                ML_KEM_768_ENCAPS_KEY_SIZE, recipient_pub.len()
            )
        })?;
    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_array)?;
    let (ss, ct) = ek.try_encaps()?;

    // KDF: shared secret -> AES key
    let hk = Hkdf::<Sha256>::new(None, &ss.into_bytes());
    let mut aead_key = [0u8; AES_256_KEY_SIZE];
    hk.expand(HKDF_INFO_JACS_PQ2025_AEAD, &mut aead_key)
        .map_err(|e| format!("HKDF key derivation failed during ML-KEM-768 seal: {}", e))?;

    // AEAD encrypt
    let cipher = Aes256Gcm::new_from_slice(&aead_key)?;
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
    rand::rng().fill(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| format!("AES-GCM encryption failed during ML-KEM-768 seal: {}", e))?;

    Ok((ct.into_bytes().to_vec(), nonce_bytes, ciphertext))
}

/// Open (decrypt) sealed data with private key
pub fn open(
    private_key: &[u8],
    kem_ct: &[u8],
    aad: &[u8],
    nonce: &[u8; AES_GCM_NONCE_SIZE],
    aead_ct: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Convert slices to fixed-size arrays
    let dk_array: [u8; ML_KEM_768_DECAPS_KEY_SIZE] = private_key
        .try_into()
        .map_err(|_| {
            format!(
                "Invalid decapsulation key length for ML-KEM-768: expected {} bytes, got {} bytes",
                ML_KEM_768_DECAPS_KEY_SIZE, private_key.len()
            )
        })?;
    let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_array)?;

    let ct_array: [u8; ML_KEM_768_CIPHERTEXT_SIZE] = kem_ct
        .try_into()
        .map_err(|_| {
            format!(
                "Invalid KEM ciphertext length for ML-KEM-768: expected {} bytes, got {} bytes",
                ML_KEM_768_CIPHERTEXT_SIZE, kem_ct.len()
            )
        })?;
    let ct = ml_kem_768::CipherText::try_from_bytes(ct_array)?;

    let ss = dk.try_decaps(&ct)?;

    // KDF
    let hk = Hkdf::<Sha256>::new(None, &ss.into_bytes());
    let mut aead_key = [0u8; AES_256_KEY_SIZE];
    hk.expand(HKDF_INFO_JACS_PQ2025_AEAD, &mut aead_key)
        .map_err(|e| format!("HKDF key derivation failed during ML-KEM-768 open: {}", e))?;

    // AEAD decrypt
    let cipher = Aes256Gcm::new_from_slice(&aead_key)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload { msg: aead_ct, aad },
        )
        .map_err(|e| {
            format!(
                "AES-GCM decryption failed during ML-KEM-768 open (wrong key or corrupted data): {}",
                e
            )
        })?;

    Ok(plaintext)
}
