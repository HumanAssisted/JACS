//! `AgentMaterial` and `UnlockSecret`: the inputs to `CoreAgent::from_encrypted_material`.
//!
//! `AgentMaterial` is the serializable bundle a browser caller (or any
//! storage-agnostic loader) holds for an agent: the agent's JACS document,
//! its config, its public key, the encrypted private-key envelope, and
//! the signing algorithm. It is the over-the-wire shape for
//! `localStore.saveEncryptedAgent` / `loadEncryptedAgent` in
//! `jacs-wasm::local_store`.
//!
//! `UnlockSecret` is the password / raw-key choice the caller passes when
//! constructing a `CoreAgent`. `Password` runs the encrypted envelope through
//! the `envelope::decrypt_private_key` sniffer (V2 Argon2id JSON plus legacy
//! PBKDF2 raw binary). `RawPrivateKey` skips decryption entirely, used
//! internally by `CoreAgent::ephemeral` and by callers who already hold the
//! decrypted bytes.
//!
//! See PRD §4.2.

use crate::sign::SigningAlgorithm;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Persisted bundle for an encrypted JACS agent.
///
/// The shape is JSON-friendly so it can be written to `localStorage` (via
/// `jacs-wasm::local_store::save_encrypted_agent`) as a single string blob
/// without further unpacking. The two `Vec<u8>` fields are
/// base64-serialized by `serde_json` when the bundle is JSON-encoded
/// (via the default `serde(with = …)` path below).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMaterial {
    /// The agent's `jacs.config.json` contents (parsed as JSON).
    pub config: Value,
    /// The agent's JACS document (the `agent.json` body, including
    /// `jacsId`, `jacsVersion`, `jacsSignature`, etc.).
    pub agent: Value,
    /// Raw public-key bytes (algorithm-specific encoding — Ed25519 is the
    /// 32-byte verifying key, pq2025 is the 2592-byte ML-DSA-87 public
    /// key).
    #[serde(with = "base64_bytes")]
    pub public_key: Vec<u8>,
    /// The encrypted private-key envelope. Either the V2 Argon2id JSON
    /// envelope (current writer) or the legacy raw-binary PBKDF2 envelope
    /// (legacy reader). `envelope::decrypt_private_key` sniffs which one
    /// it is.
    #[serde(with = "base64_bytes")]
    pub encrypted_private_key: Vec<u8>,
    /// The signing algorithm tied to the keys above.
    pub algorithm: SigningAlgorithm,
}

/// Caller's choice for how to unlock the encrypted private key.
///
/// Borrowing here lets the caller keep ownership of the password
/// string / raw-key buffer. The lifetime of the underlying secret is
/// the caller's concern; `CoreAgent::from_encrypted_material` only
/// reads from it during construction.
pub enum UnlockSecret<'a> {
    /// Run the password through the envelope decryptor. The password
    /// itself is borrowed — it is never copied into the resulting
    /// `CoreAgent`, only the decrypted private key bytes are (and
    /// those are wrapped + zeroized).
    Password(&'a str),
    /// Skip decryption. The provided bytes are interpreted directly as
    /// the algorithm-specific raw private key (Ed25519 PKCS#8 or raw
    /// 32-byte scalar; pq2025 ML-DSA-87 4896-byte private key). Used
    /// by `CoreAgent::ephemeral` and by callers who already hold the
    /// decrypted bytes (for example after running a custom key store).
    RawPrivateKey(SecretBox<Vec<u8>>),
}

// -----------------------------------------------------------------------------
// Internal: base64 helper for `Vec<u8>` fields so the JSON form is small and
// human-readable. Mirrors how the native side encodes binary fields in
// configs / agent JSON documents.
// -----------------------------------------------------------------------------

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
