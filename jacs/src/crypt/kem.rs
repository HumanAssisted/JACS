//! ML-KEM (FIPS-203) Key Encapsulation Mechanism
//! Provides seal/open operations using ML-KEM-768 + HKDF + AES-GCM

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
pub fn seal(
    recipient_pub: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 12], Vec<u8>), Box<dyn Error>> {
    // Convert slice to fixed-size array
    let ek_array: [u8; 1184] = recipient_pub
        .try_into()
        .map_err(|_| "Invalid public key length for ML-KEM-768")?;
    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_array)?;
    let (ss, ct) = ek.try_encaps()?;

    // KDF: shared secret -> AES key
    let hk = Hkdf::<Sha256>::new(None, &ss.into_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(b"jacs-pq2025-aead", &mut aead_key)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    // AEAD encrypt
    let cipher = Aes256Gcm::new_from_slice(&aead_key)?;
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    Ok((ct.into_bytes().to_vec(), nonce_bytes, ciphertext))
}

/// Open (decrypt) sealed data with private key
pub fn open(
    private_key: &[u8],
    kem_ct: &[u8],
    aad: &[u8],
    nonce: &[u8; 12],
    aead_ct: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Convert slices to fixed-size arrays
    let dk_array: [u8; 2400] = private_key
        .try_into()
        .map_err(|_| "Invalid private key length for ML-KEM-768")?;
    let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_array)?;

    let ct_array: [u8; 1088] = kem_ct
        .try_into()
        .map_err(|_| "Invalid ciphertext length for ML-KEM-768")?;
    let ct = ml_kem_768::CipherText::try_from_bytes(ct_array)?;

    let ss = dk.try_decaps(&ct)?;

    // KDF
    let hk = Hkdf::<Sha256>::new(None, &ss.into_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(b"jacs-pq2025-aead", &mut aead_key)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    // AEAD decrypt
    let cipher = Aes256Gcm::new_from_slice(&aead_key)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload { msg: aead_ct, aad },
        )
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;

    Ok(plaintext)
}
