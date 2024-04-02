use ring::aead::BoundKey;
use ring::aead::UnboundKey;
use ring::rand::SecureRandom;
use ring::{aead, pbkdf2, rand};
use std::num::NonZeroU32;

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(100_000).unwrap();
const PBKDF2_SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;

// Encrypts a private key using a password
pub fn encrypt_private_key(
    password: &str,
    private_key: &[u8],
) -> Result<Vec<u8>, ring::error::Unspecified> {
    let rng = rand::SystemRandom::new();
    let mut salt = [0; PBKDF2_SALT_LEN];
    rng.fill(&mut salt)?;

    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        PBKDF2_ALG,
        PBKDF2_ITERATIONS,
        &salt,
        password.as_bytes(),
        &mut key,
    );

    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce)?;

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key)?;
    let mut sealing_key = aead::SealingKey::new(unbound_key, &nonce)?;

    let aad = aead::Aad::empty();

    let mut in_out = private_key.to_vec();
    in_out.extend_from_slice(&[0u8; TAG_LEN]);

    let tag = sealing_key.seal_in_place_separate_tag(aad, &mut in_out)?;

    let mut encrypted_data = Vec::with_capacity(salt.len() + nonce.len() + in_out.len() + TAG_LEN);
    encrypted_data.extend_from_slice(&salt);
    encrypted_data.extend_from_slice(&nonce);
    encrypted_data.extend_from_slice(&in_out);
    encrypted_data.extend_from_slice(tag.as_ref());

    Ok(encrypted_data)
}

// Decrypts an encrypted private key using a password
pub fn decrypt_private_key(
    password: &str,
    encrypted_data: &[u8],
) -> Result<Vec<u8>, ring::error::Unspecified> {
    if encrypted_data.len() < PBKDF2_SALT_LEN + KEY_LEN {
        return Err(ring::error::Unspecified);
    }

    let (salt, rest) = encrypted_data.split_at(PBKDF2_SALT_LEN);
    let (nonce, rest) = rest.split_at(12);
    let (encrypted_private_key, tag) = rest.split_at(rest.len() - TAG_LEN);

    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        PBKDF2_ALG,
        PBKDF2_ITERATIONS,
        salt,
        password.as_bytes(),
        &mut key,
    );

    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key)?;
    let mut opening_key = aead::OpeningKey::new(unbound_key, &nonce)?;

    let aad = aead::Aad::empty();

    let mut in_out = encrypted_private_key.to_vec();
    let decrypted_data = opening_key.open_in_place(aad, &mut in_out, tag)?;

    Ok(decrypted_data.to_vec())
}
