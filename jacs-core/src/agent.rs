//! `CoreAgent`: protocol-layer agent state — no I/O, no schema validation.
//!
//! `CoreAgent` carries the four things needed to sign or verify on the
//! protocol layer:
//!
//! 1. The signing algorithm (`SigningAlgorithm`).
//! 2. The public-key bytes (always present, even after `clear_secrets`).
//! 3. An optional `DetachedSigner` (present when unlocked, dropped when
//!    locked).
//! 4. The agent JSON document (for `agent_id` / `agent_version` extraction
//!    when constructing signature payloads in Task 013).
//!
//! It is intentionally minimal — no DNS, no registry, no schema validation,
//! no `MultiStorage`. Those live in `jacs` / `jacs-wasm` on top of this.
//!
//! See PRD §4.2, §4.4.

use crate::envelope::decrypt_private_key;
use crate::material::{AgentMaterial, UnlockSecret};
use crate::sign::{
    DetachedSigner, Ed25519DalekSigner, Pq2025Signer, SigningAlgorithm,
};
use crate::{CoreError};
use secrecy::ExposeSecret;
use serde_json::{Value, json};

// =========================================================================
// CoreAgent
// =========================================================================

/// In-memory agent holding the optional unlocked signer + the published
/// public key + the embedded agent JSON.
///
/// `CoreAgent` is constructed by either:
///
/// - [`CoreAgent::from_encrypted_material`] — production path, takes an
///   `AgentMaterial` and an `UnlockSecret`.
/// - [`CoreAgent::ephemeral`] — testing / one-off path, generates a fresh
///   keypair and synthesizes a minimal agent JSON.
///
/// Signing and verification methods are added in Task 013 and live in the
/// `verify` module + an extended `impl` block.
pub struct CoreAgent {
    /// The signer is dropped when `clear_secrets` runs; the trait's own
    /// implementations zeroize their private-key bytes on drop.
    pub(crate) signer: Option<Box<dyn DetachedSigner>>,
    pub(crate) algorithm: SigningAlgorithm,
    pub(crate) public_key: Vec<u8>,
    pub(crate) agent_json: Value,
}

impl std::fmt::Debug for CoreAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreAgent")
            .field("algorithm", &self.algorithm)
            .field("public_key_len", &self.public_key.len())
            .field("unlocked", &self.signer.is_some())
            .finish()
    }
}

impl CoreAgent {
    /// Construct from encrypted material plus an unlock secret.
    ///
    /// `Password` runs the envelope through the V2/legacy sniffer in
    /// `envelope::decrypt_private_key`. `RawPrivateKey` takes the bytes
    /// as-is.
    ///
    /// Errors mirror the underlying primitives: `InvalidPassword`,
    /// `MalformedEnvelope`, `MalformedKey`, `UnsupportedAlgorithm`.
    pub fn from_encrypted_material(
        material: AgentMaterial,
        secret: UnlockSecret<'_>,
    ) -> Result<Self, CoreError> {
        let signer: Box<dyn DetachedSigner> = match secret {
            UnlockSecret::Password(password) => {
                let decrypted =
                    decrypt_private_key(&material.encrypted_private_key, password)?;
                build_signer(material.algorithm, decrypted.as_slice())?
            }
            UnlockSecret::RawPrivateKey(secret_box) => {
                build_signer(material.algorithm, secret_box.expose_secret())?
            }
        };

        // Sanity check: the public key the caller stored must match the
        // public key derived from the unlocked private key. Otherwise the
        // agent could sign with one key while presenting another, which
        // would yield silent verification failures downstream.
        if signer.public_key() != material.public_key.as_slice() {
            return Err(CoreError::MalformedKey(
                "stored public key does not match the key derived from the unlocked private key"
                    .into(),
            ));
        }

        Ok(Self {
            signer: Some(signer),
            algorithm: material.algorithm,
            public_key: material.public_key,
            agent_json: material.agent,
        })
    }

    /// Generate a fresh ephemeral agent for the given algorithm. Synthesizes
    /// a minimal agent JSON via [`ephemeral_agent_json`] so the result
    /// looks like an agent for downstream sign / verify code paths (Task
    /// 013) without taking a dependency on the full native agent loader.
    pub fn ephemeral(algorithm: SigningAlgorithm) -> Result<Self, CoreError> {
        let signer: Box<dyn DetachedSigner> = match algorithm {
            SigningAlgorithm::Ed25519 => Box::new(Ed25519DalekSigner::generate()?),
            SigningAlgorithm::Pq2025 => Box::new(Pq2025Signer::generate()?),
        };
        let public_key = signer.public_key().to_vec();
        let agent_json = ephemeral_agent_json(algorithm, &public_key);
        Ok(Self {
            signer: Some(signer),
            algorithm,
            public_key,
            agent_json,
        })
    }

    /// The signing algorithm of this agent.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Raw public-key bytes. Survives `clear_secrets` — verification with
    /// this agent still works after the private key is dropped.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// `true` iff a signer is currently held (a private key is unlocked).
    pub fn is_unlocked(&self) -> bool {
        self.signer.is_some()
    }

    /// Idempotent secret eviction. After this call:
    ///
    /// - `is_unlocked()` returns `false`.
    /// - `sign_message` (Task 013) returns `CoreError::Locked`.
    /// - `public_key`, `algorithm`, `verify`, `verify_with_key` continue to
    ///   work.
    pub fn clear_secrets(&mut self) {
        if let Some(signer) = self.signer.as_mut() {
            // Belt-and-braces: ask the trait impl to wipe its inner secret
            // before we drop the box. Both `Ed25519DalekSigner` and
            // `Pq2025Signer` already zeroize on drop, but exercising the
            // hook keeps the contract aligned with what the trait
            // promises (idempotent, no panic, no observable change after
            // the second call).
            signer.clear_secrets();
        }
        self.signer = None;
    }

    /// Borrow a clone of the embedded agent JSON. Used by callers (browser
    /// or native facade) that want to re-emit the agent record without
    /// taking ownership of the `CoreAgent`.
    pub fn export_agent(&self) -> Value {
        self.agent_json.clone()
    }
}

// =========================================================================
// Internal helpers
// =========================================================================

/// Build the concrete signer for the given algorithm + decrypted private
/// key bytes.
///
/// `Ed25519` accepts either PKCS#8 v1/v2 DER (the shape that
/// `ring::Ed25519KeyPair::generate_pkcs8` emits, and that
/// `Ed25519DalekSigner::export_pkcs8_v2` round-trips) or the raw 32-byte
/// scalar. `Pq2025` accepts the 4896-byte ML-DSA-87 private key.
fn build_signer(
    algorithm: SigningAlgorithm,
    private_key_bytes: &[u8],
) -> Result<Box<dyn DetachedSigner>, CoreError> {
    match algorithm {
        SigningAlgorithm::Ed25519 => {
            // Prefer PKCS#8 — that's what the native `ring` path emits and
            // what the V2 envelope stores after `Ed25519DalekSigner::
            // export_pkcs8_v2`. Fall back to the raw-scalar shape (32
            // bytes) so callers who deliberately store the bare key
            // through `UnlockSecret::RawPrivateKey` still work.
            if private_key_bytes.len() == 32 {
                Ok(Box::new(Ed25519DalekSigner::from_private_scalar(
                    private_key_bytes,
                )?))
            } else {
                Ok(Box::new(Ed25519DalekSigner::from_pkcs8(private_key_bytes)?))
            }
        }
        SigningAlgorithm::Pq2025 => Ok(Box::new(Pq2025Signer::from_private_bytes(
            private_key_bytes,
        )?)),
    }
}

/// Synthesize the minimal agent JSON used by `CoreAgent::ephemeral`. The
/// shape mirrors the fields native `SimpleAgent::ephemeral` exposes after
/// it runs the full agent-builder pipeline:
///
/// - `jacsId` — a fresh UUID v4 so the agent has a stable identifier even
///   without a persisted record.
/// - `jacsVersion` — a literal `"v1"` placeholder. The native facade will
///   overwrite this when the same material is persisted; on the wasm side
///   it suffices as a non-empty version string.
/// - `name` — `"ephemeral"`.
/// - `algorithm` — the wire form (`"ed25519"` / `"pq2025"`).
/// - `publicKeyLen` — for diagnostics only; the raw bytes themselves stay
///   on the `CoreAgent` and are not embedded.
///
/// DRY note: there is exactly one helper for ephemeral agent JSON shape
/// (this function). `CoreAgent::ephemeral` is the only caller; callers
/// that want to override the shape should construct an `AgentMaterial`
/// and route through `from_encrypted_material` instead.
pub fn ephemeral_agent_json(algorithm: SigningAlgorithm, public_key: &[u8]) -> Value {
    json!({
        "jacsId": uuid::Uuid::new_v4().to_string(),
        "jacsVersion": "v1",
        "name": "ephemeral",
        "algorithm": algorithm.as_str(),
        "publicKeyLen": public_key.len(),
    })
}
