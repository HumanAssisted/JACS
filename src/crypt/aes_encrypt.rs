use aes_gcm::AeadCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::str;

// Encrypt a private key with a password
pub fn encrypt_private_key(
    password: &str,
    private_key: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Generate a random salt
    let mut salt = [0u8; 16];
    thread_rng().fill(&mut salt[..]);

    // Derive key using PBKDF2 with SHA-256
    let mut key = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(&salt);
    let hash = hasher.finalize();
    key.copy_from_slice(&hash[..32]);

    // Create cipher instance
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt private key
    let encrypted_data = cipher
        .encrypt(&nonce, private_key)
        .expect("encryption failure!");

    // Combine the salt, nonce, and encrypted data into one Vec to return
    let mut encrypted_key_with_salt_and_nonce = salt.to_vec();
    encrypted_key_with_salt_and_nonce.extend_from_slice(nonce.as_slice());
    encrypted_key_with_salt_and_nonce.extend_from_slice(&encrypted_data);

    Ok(encrypted_key_with_salt_and_nonce)
}

// Decrypt the private key with the password
pub fn decrypt_private_key(
    password: &str,
    encrypted_key_with_salt_and_nonce: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted_key_with_salt_and_nonce.len() < 16 + 12 {
        return Err("encrypted data is too short".into());
    }

    // Split the data into salt, nonce, and encrypted key
    let (salt, rest) = encrypted_key_with_salt_and_nonce.split_at(16);
    let (nonce, encrypted_data) = rest.split_at(12);

    // Derive key using PBKDF2 with SHA-256
    let mut key = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let hash = hasher.finalize();
    key.copy_from_slice(&hash[..32]);

    // Create cipher instance
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    // Decrypt private key
    let decrypted_data = cipher
        .decrypt(&Nonce::from_slice(nonce), encrypted_data)
        .expect("decryption failure!");

    Ok(decrypted_data)
}
