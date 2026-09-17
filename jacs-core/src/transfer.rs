//! Portable, password-encrypted device transfer. This module performs no I/O.
//!
//! The relay must separately authenticate both devices, bind the ciphertext to
//! the link session, expire it, and consume it once. These helpers pin the
//! receiving identity and rewrap the key before it reaches persistent storage.

use crate::{AgentMaterial, CoreAgent, CoreError, SigningAlgorithm, UnlockSecret};
use aes_gcm::aead::rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Device linking is for small identity/key bundles, not attached documents.
pub const MAX_TRANSFER_MATERIAL_BYTES: usize = 128 * 1024;
pub const TRANSFER_CODE_WORD_COUNT: usize = 6;
/// Six independent choices from a fixed 2048-word vocabulary, with replacement.
pub const TRANSFER_CODE_ENTROPY_BITS: usize = 66;
const WORDS: &str = include_str!("transfer-words.txt");

/// Generate a six-word transfer code with 66 bits of CSPRNG entropy.
///
/// Vocabulary: BIP-39 English (MIT); this is NOT a wallet mnemonic and has no
/// checksum. Each 11-bit index is uniform; words may repeat. Display the code
/// only on the sending device, never in the QR/session or an HTTP request.
pub fn generate_transfer_code() -> Result<Zeroizing<String>, CoreError> {
    let words: Vec<&str> = WORDS.lines().collect();
    if words.len() != 2048 {
        return Err(CoreError::EncryptionFailed(
            "invalid transfer vocabulary".into(),
        ));
    }
    let mut random = Zeroizing::new([0u8; TRANSFER_CODE_WORD_COUNT * 2]);
    OsRng
        .try_fill_bytes(random.as_mut())
        .map_err(|_| CoreError::EncryptionFailed("secure randomness unavailable".into()))?;
    let mut code = Zeroizing::new(String::with_capacity(64));
    for (position, bytes) in random.chunks_exact(2).enumerate() {
        // The vocabulary size is a power of two, so masking introduces no bias.
        let index = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]) & 2047);
        if position != 0 {
            code.push(' ');
        }
        code.push_str(words[index]);
    }
    Ok(code)
}

/// Validate public identity plus envelope before KDF work or relay storage.
/// This checks the public bundle, not knowledge of its password/private key.
pub fn validate_transfer_material(material: &AgentMaterial) -> Result<(), CoreError> {
    let bytes =
        serde_json::to_vec(material).map_err(|e| CoreError::MalformedDocument(e.to_string()))?;
    if bytes.len() > MAX_TRANSFER_MATERIAL_BYTES {
        return Err(CoreError::MalformedEnvelope(
            "transfer material exceeds 128 KiB".into(),
        ));
    }
    // Config is deliberately omitted on portable export. Requiring an empty
    // object prevents accidentally relaying local paths, credentials or keys.
    if material
        .config
        .as_object()
        .is_none_or(|config| !config.is_empty())
    {
        return Err(CoreError::MalformedDocument(
            "transfer config must be an empty object".into(),
        ));
    }
    crate::envelope::validate_encrypted_private_key(&material.encrypted_private_key)?;
    CoreAgent::validate_identity(&material.agent, &material.public_key, material.algorithm)?;
    Ok(())
}

/// Import only the identity/key freshly fetched from a trusted registration.
/// Obtain these expectations independently; never trust the values in the blob.
pub fn import_transferred_agent(
    material: AgentMaterial,
    code: &str,
    expected_agent_id: &str,
    expected_public_key: &[u8],
    expected_algorithm: SigningAlgorithm,
) -> Result<CoreAgent, CoreError> {
    validate_transfer_material(&material)?;
    if expected_agent_id.is_empty()
        || material.agent["jacsId"].as_str() != Some(expected_agent_id)
        || material.public_key != expected_public_key
        || material.algorithm != expected_algorithm
    {
        return Err(CoreError::MalformedKey(
            "transfer does not match the registered identity and key".into(),
        ));
    }
    CoreAgent::from_encrypted_material(material, UnlockSecret::Password(code))
}

/// Rewrap for destination storage; the temporary unlocked handle is cleared on
/// both success and failure. The caller persists only the returned ciphertext.
pub fn reencrypt_transferred_material(
    material: AgentMaterial,
    code: &str,
    expected_agent_id: &str,
    expected_public_key: &[u8],
    expected_algorithm: SigningAlgorithm,
    storage_password: &str,
) -> Result<AgentMaterial, CoreError> {
    if storage_password.is_empty() || storage_password == code {
        return Err(CoreError::InvalidPasswordFormat(
            "destination secret must be nonempty and different from the transfer code".into(),
        ));
    }
    let mut agent = import_transferred_agent(
        material,
        code,
        expected_agent_id,
        expected_public_key,
        expected_algorithm,
    )?;
    let result = agent.export_encrypted_material(storage_password);
    agent.clear_secrets();
    result
}
