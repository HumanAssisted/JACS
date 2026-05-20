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

use crate::CoreError;
use crate::envelope::decrypt_private_key;
use crate::material::{AgentMaterial, UnlockSecret};
use crate::sign::{DetachedSigner, Ed25519DalekSigner, Pq2025Signer, SigningAlgorithm};
use crate::verify::{
    VerificationOutcome, build_signature_content_v2, build_signature_metadata,
    default_signed_fields, sha256_hex, verify_document,
};
use base64::Engine as _;
use secrecy::ExposeSecret;
use serde_json::{Value, json};

/// Placement key for the JACS document signature. Mirrors
/// `jacs::storage::JACS_SIGNATURE_FIELDNAME`. Hardcoded here because
/// jacs-core does not depend on jacs.
const JACS_SIGNATURE_FIELDNAME: &str = "jacsSignature";

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
                let decrypted = decrypt_private_key(&material.encrypted_private_key, password)?;
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

    /// Round-trip the unlocked agent into an `AgentMaterial` whose
    /// `encrypted_private_key` is encrypted under `password` with the
    /// V2 Argon2id envelope (`envelope::encrypt_private_key`).
    ///
    /// The result is the same shape `from_encrypted_material` accepts —
    /// the wasm browser layer round-trips through this method to
    /// implement `BrowserAgent.save(storageKey)` / `load(storageKey,
    /// {password})` (HAIAI_WASM Issue 003) without any local crypto in
    /// the wrapper.
    ///
    /// Returns `CoreError::Locked` if the signer has been cleared, or
    /// the underlying `EncryptionFailed` if envelope encryption fails.
    pub fn export_encrypted_material(&self, password: &str) -> Result<AgentMaterial, CoreError> {
        let signer = self.signer.as_ref().ok_or(CoreError::Locked)?;
        let raw_private = signer.export_private_key_bytes()?;
        let encrypted = crate::envelope::encrypt_private_key(&raw_private, password)?;
        // Zeroize the intermediate plaintext as soon as we have the
        // ciphertext — defense-in-depth even though `raw_private` will
        // drop at scope exit anyway. Using `zeroize::Zeroize` keeps the
        // wipe explicit + compiler-resistant.
        use zeroize::Zeroize as _;
        let mut raw_private = raw_private;
        raw_private.zeroize();
        Ok(AgentMaterial {
            // Browser ephemeral agents don't carry a full `jacs.config.json`
            // — emit an empty object as a placeholder. Round-trip readers
            // (CoreAgent::from_encrypted_material) ignore `config`; the
            // shape is preserved purely for storage-layer consumers
            // (jacs-wasm::local_store::validate_encrypted_material_shape).
            config: serde_json::json!({}),
            agent: self.agent_json.clone(),
            public_key: self.public_key.clone(),
            encrypted_private_key: encrypted,
            algorithm: self.algorithm,
        })
    }

    // =====================================================================
    // sign / verify
    // =====================================================================

    /// Sign a JSON payload as a JACS message and return the signed
    /// document. Shape:
    ///
    /// ```json
    /// {
    ///   "jacsType": "message",
    ///   "jacsLevel": "raw",
    ///   "content": { ... },
    ///   "jacsSignature": { ... }
    /// }
    /// ```
    ///
    /// The canonical signature payload is built per PRD §4.5 (v2 layout,
    /// `serde_json_canonicalizer` for canonical JSON). The signer must be
    /// unlocked; otherwise returns `CoreError::Locked`.
    pub fn sign_message(&mut self, data: &Value) -> Result<Value, CoreError> {
        // Build the wrapper document. The wasm layer signs documents in
        // this exact shape so verifiers reconstruct the same canonical
        // bytes regardless of platform.
        let mut document = json!({
            "jacsType": "message",
            "jacsLevel": "raw",
            "content": data,
        });
        self.sign_document_inplace(&mut document, JACS_SIGNATURE_FIELDNAME)?;
        Ok(document)
    }

    /// Sign `document` in place, attaching the signature object under
    /// `placement_key`. Used by `sign_message` (placement key `"jacsSignature"`)
    /// and by `jacs-core::agreements` in Task 014.
    ///
    /// Returns `CoreError::Locked` if the signer has been cleared.
    pub fn sign_document_inplace(
        &mut self,
        document: &mut Value,
        placement_key: &str,
    ) -> Result<(), CoreError> {
        let signer = self.signer.as_ref().ok_or(CoreError::Locked)?;
        let algorithm = self.algorithm;
        let public_key_hash = sha256_hex(&self.public_key);
        let agent_id = self
            .agent_json
            .get("jacsId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let agent_version = self
            .agent_json
            .get("jacsVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let date = chrono::Utc::now().to_rfc3339();
        let iat = chrono::Utc::now().timestamp();
        let jti = uuid::Uuid::now_v7().to_string();
        let fields = default_signed_fields(document, placement_key);

        // The metadata used for the canonical payload — `signature` field
        // is empty here; `build_signature_content_v2` strips it anyway, but
        // making it explicit keeps the shape consistent with what the
        // verifier reconstructs.
        let metadata = build_signature_metadata(
            &agent_id,
            &agent_version,
            &date,
            iat,
            &jti,
            algorithm,
            &public_key_hash,
            &fields,
        );

        let canonical = build_signature_content_v2(document, &fields, placement_key, &metadata)?;
        let sig_bytes = signer.sign(canonical.as_bytes())?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);

        // Build the final signature object: same shape as `metadata`, with
        // the real signature filled in.
        let mut sig_object = metadata;
        sig_object["signature"] = json!(signature_b64);

        document
            .as_object_mut()
            .ok_or_else(|| {
                CoreError::MalformedDocument(
                    "document must be a JSON object to attach a signature".into(),
                )
            })?
            .insert(placement_key.to_string(), sig_object);

        Ok(())
    }

    /// Sign exact `bytes` with the unlocked signer and return the raw
    /// signature bytes. No JSON wrapping, no canonicalization, no
    /// metadata — the caller decides what bytes are signed.
    ///
    /// Use this for protocol primitives where the verifier reconstructs
    /// the exact same byte string from independent inputs (auth headers,
    /// nonce-bound challenges, JWT-style payloads). For JACS document
    /// signing, use `sign_message` / `sign_document_inplace` instead so
    /// the verifier can reproduce the canonical payload from the
    /// document's published fields.
    ///
    /// Returns `CoreError::Locked` if `clear_secrets` has been called.
    pub fn sign_raw_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>, CoreError> {
        let signer = self.signer.as_ref().ok_or(CoreError::Locked)?;
        signer.sign(bytes)
    }

    /// Static verify path for `sign_raw_bytes` output. Returns `Ok(true)`
    /// when the signature matches, `Ok(false)` when it does not, and
    /// `Err(CoreError::UnsupportedAlgorithm)` / `MalformedKey` /
    /// `MalformedDocument` if the inputs are structurally invalid.
    ///
    /// Mirrors `verify_with_key` for document signing — the verifier
    /// does not need an unlocked agent because it only requires the
    /// public key bytes + algorithm.
    pub fn verify_raw_bytes_with_key(
        public_key: &[u8],
        algorithm: SigningAlgorithm,
        bytes: &[u8],
        signature: &[u8],
    ) -> Result<bool, CoreError> {
        match algorithm {
            SigningAlgorithm::Ed25519 => {
                match Ed25519DalekSigner::verify(public_key, bytes, signature) {
                    Ok(()) => Ok(true),
                    // The underlying verify surface returns `CoreError::SignatureInvalid`
                    // for a cryptographic mismatch and a structural error for
                    // bad inputs (wrong key length, bad signature length).
                    // Surface the structural errors as Err; map signature
                    // mismatch to Ok(false) so callers can branch on a
                    // valid bool without try-catching for the happy-path.
                    Err(CoreError::SignatureInvalid(_)) => Ok(false),
                    Err(other) => Err(other),
                }
            }
            SigningAlgorithm::Pq2025 => match Pq2025Signer::verify(public_key, bytes, signature) {
                Ok(()) => Ok(true),
                Err(CoreError::SignatureInvalid(_)) => Ok(false),
                Err(other) => Err(other),
            },
        }
    }

    /// Verify a signed JACS document against this agent's public key +
    /// algorithm. Always uses the `jacsSignature` placement key.
    ///
    /// Returns `CoreError::AlgorithmMismatch` if the document was signed
    /// under a different algorithm than this agent. Returns a
    /// `VerificationOutcome` with `valid = false` and one entry in
    /// `errors` when the signature itself does not verify.
    pub fn verify(&self, signed: &Value) -> Result<VerificationOutcome, CoreError> {
        verify_document(
            signed,
            &self.public_key,
            self.algorithm,
            JACS_SIGNATURE_FIELDNAME,
        )
    }

    /// Static verify path — does not require an unlocked agent.
    ///
    /// `public_key` and `algorithm` must match what the document was signed
    /// under; otherwise the cryptographic check fails and the returned
    /// outcome has `valid = false`. The signed document's
    /// `signingAlgorithm` field is checked against `algorithm` and returns
    /// `CoreError::AlgorithmMismatch` on conflict — this is a typed
    /// failure (algorithm choice errors are different from bad
    /// signatures).
    pub fn verify_with_key(
        signed: &Value,
        public_key: &[u8],
        algorithm: SigningAlgorithm,
    ) -> Result<VerificationOutcome, CoreError> {
        verify_document(signed, public_key, algorithm, JACS_SIGNATURE_FIELDNAME)
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
