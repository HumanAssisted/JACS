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
use crate::sign::{DetachedSigner, Ed25519DalekSigner, P256Signer, Pq2025Signer, SigningAlgorithm};
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
        Self::import_material(material, secret, false)
    }

    /// Explicit migration path for unsigned material exported by older core
    /// releases. Only use after independently authenticating the legacy agent
    /// ID and public key; encryption alone did not bind its identity metadata.
    /// Signed input still receives all normal validation, including tamper checks.
    /// The resulting agent is self-signed and future exports use strict imports.
    pub fn from_legacy_encrypted_material(
        material: AgentMaterial,
        secret: UnlockSecret<'_>,
    ) -> Result<Self, CoreError> {
        Self::import_material(material, secret, true)
    }

    fn import_material(
        material: AgentMaterial,
        secret: UnlockSecret<'_>,
        allow_unsigned: bool,
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

        // Do not route unsigned input through the creation API without an
        // explicit migration choice: removing a signature must never turn an
        // untrusted imported identity into a new, locally authenticated one.
        if !allow_unsigned || material.agent.get(JACS_SIGNATURE_FIELDNAME).is_some() {
            validate_agent_identity(
                &material.agent,
                material.algorithm,
                &material.public_key,
                true,
            )?;
        }
        Self::from_signer(signer, material.agent)
    }

    /// Construct an agent backed by an outside signer (including a key that
    /// never leaves Android Keystore or the iOS Secure Enclave).
    ///
    /// Existing signed identities must authenticate this exact public key,
    /// algorithm, ID and version. An unsigned object describes a *new* identity:
    /// missing headers are generated and the object is self-signed. Do not use
    /// this creation path to accept an untrusted transferred identity; use
    /// `from_encrypted_material` and pin the expected ID/public key instead.
    pub fn from_signer(
        signer: Box<dyn DetachedSigner>,
        agent_json: Value,
    ) -> Result<Self, CoreError> {
        let algorithm = signer.algorithm();
        let public_key = signer.public_key().to_vec();
        crate::identity::canonical_key_id(algorithm.as_str(), &public_key)?;
        let signed = agent_json.get(JACS_SIGNATURE_FIELDNAME).is_some();
        let agent_json = if signed {
            agent_json
        } else {
            let supplied = agent_json.as_object().ok_or_else(|| {
                CoreError::MalformedDocument("agent must be a JSON object".into())
            })?;
            let mut initial = ephemeral_agent_json(algorithm, &public_key);
            initial
                .as_object_mut()
                .expect("generated object")
                .extend(supplied.clone());
            initial
        };
        validate_agent_identity(&agent_json, algorithm, &public_key, signed)?;
        let mut agent = Self {
            signer: Some(signer),
            algorithm,
            public_key,
            agent_json,
        };
        if !signed {
            let mut document = agent.agent_json.clone();
            agent.sign_identity_document(&mut document)?;
            agent.agent_json = document;
        }
        Ok(agent)
    }

    /// Generate a new self-signed identity and software keypair. The same
    /// exported identity can be imported and verified on every target.
    pub fn ephemeral(algorithm: SigningAlgorithm) -> Result<Self, CoreError> {
        let signer: Box<dyn DetachedSigner> = match algorithm {
            SigningAlgorithm::Ed25519 => Box::new(Ed25519DalekSigner::generate()?),
            SigningAlgorithm::Pq2025 => Box::new(Pq2025Signer::generate()?),
            SigningAlgorithm::Es256 => Box::new(P256Signer::generate()?),
        };
        let agent_json = ephemeral_agent_json(algorithm, signer.public_key());
        Self::from_signer(signer, agent_json)
    }

    /// Merge identity metadata, advance the version, and self-sign with the
    /// existing key. ID, key, algorithm, provenance and generated signature
    /// fields cannot be changed here. Supplying an unchanged protected field
    /// is allowed so callers may pass a full exported document.
    ///
    /// On any validation, callback or signing failure the current identity is
    /// unchanged. Key rotation is a separate operation, not a metadata edit.
    pub fn update_agent(&mut self, updates: &Value) -> Result<Value, CoreError> {
        self.update_agent_with_prepare(updates, |_, _| Ok::<(), CoreError>(()))
            .map(|(updated, ())| updated)
    }

    /// Prepare a self-signed next identity while keeping the current identity
    /// available to a request-auth callback. Commit only after that callback
    /// succeeds. This lets HAI authenticate the new registration document with
    /// the previously registered ID/version, including hardware-held keys,
    /// without exporting private material or mutating state on auth denial.
    ///
    /// The callback receives the old agent and the complete signed candidate;
    /// its returned value can contain the exact serialized request bytes and
    /// their authentication header. No HTTP is performed by the core.
    pub fn update_agent_with_prepare<T, E: From<CoreError>>(
        &mut self,
        updates: &Value,
        prepare: impl FnOnce(&CoreAgent, &Value) -> Result<T, E>,
    ) -> Result<(Value, T), E> {
        let candidate = self.prepare_agent_update(updates)?;
        let prepared = prepare(self, &candidate)?;
        let committed = self.commit_agent_update(&candidate)?;
        Ok((committed, prepared))
    }

    /// Build and self-sign the next identity without changing the active one.
    /// Async transports authenticate with the active version, submit this exact
    /// candidate, and call `commit_agent_update` only after successful admission.
    pub fn prepare_agent_update(&self, updates: &Value) -> Result<Value, CoreError> {
        self.signer.as_ref().ok_or(CoreError::Locked)?;
        let updates = updates.as_object().ok_or_else(|| {
            CoreError::MalformedDocument("agent updates must be a JSON object".into())
        })?;
        const PROTECTED: &[&str] = &[
            "jacsId",
            "jacsVersion",
            "jacsPreviousVersion",
            "jacsVersionDate",
            "jacsOriginalVersion",
            "jacsOriginalDate",
            "jacsType",
            "$schema",
            "algorithm",
            "signingAlgorithm",
            "jacsAgentKeyAlgorithm",
            "publicKey",
            "jacsPublicKey",
            "publicKeyLen",
            "publicKeyHash",
            "jacsPublicKeyHash",
            "jacsSignature",
            "jacsSha256",
            "jacsKeyRotationProof",
            "jacsRegistration",
        ];
        for (field, value) in updates {
            if PROTECTED.contains(&field.as_str()) && self.agent_json.get(field) != Some(value) {
                return Err(CoreError::MalformedDocument(format!(
                    "identity field '{field}' cannot be changed by update_agent"
                )));
            }
        }
        let mut candidate = self.agent_json.clone();
        candidate
            .as_object_mut()
            .expect("validated identity")
            .extend(updates.clone());
        if verification_claim_level(&candidate) < verification_claim_level(&self.agent_json) {
            return Err(CoreError::MalformedDocument(
                "verification claim cannot be downgraded".into(),
            ));
        }
        candidate["jacsPreviousVersion"] = self.agent_json["jacsVersion"].clone();
        candidate["jacsVersion"] = json!(uuid::Uuid::new_v4().to_string());
        candidate["jacsVersionDate"] = json!(chrono::Utc::now().to_rfc3339());
        // Registration attests a specific version and cannot survive an edit.
        candidate
            .as_object_mut()
            .expect("validated identity")
            .remove("jacsRegistration");
        self.sign_identity_document(&mut candidate)?;
        Ok(candidate)
    }

    /// Commit an authenticated next-version candidate after external admission.
    /// Rechecks the full signature/checksum, immutable identity metadata and exact
    /// predecessor. A competing local update makes the prepared candidate stale;
    /// failures leave the active identity unchanged. No new signing is required.
    pub fn commit_agent_update(&mut self, prepared: &Value) -> Result<Value, CoreError> {
        self.signer.as_ref().ok_or(CoreError::Locked)?;
        Self::validate_identity(prepared, &self.public_key, self.algorithm)?;
        for field in [
            "jacsId",
            "jacsOriginalVersion",
            "jacsOriginalDate",
            "jacsType",
            "$schema",
            "algorithm",
            "signingAlgorithm",
            "jacsAgentKeyAlgorithm",
            "publicKey",
            "jacsPublicKey",
            "publicKeyLen",
            "publicKeyHash",
            "jacsPublicKeyHash",
            "jacsKeyRotationProof",
        ] {
            if prepared.get(field) != self.agent_json.get(field) {
                return Err(CoreError::MalformedDocument(format!(
                    "prepared update changes protected identity field '{field}'"
                )));
            }
        }
        let active_version = required_identity_string(&self.agent_json, "jacsVersion")?;
        let new_version = required_identity_string(prepared, "jacsVersion")?;
        if prepared.get("jacsPreviousVersion").and_then(Value::as_str) != Some(active_version)
            || new_version == active_version
            || prepared["jacsSignature"]
                .get("agentVersion")
                .and_then(Value::as_str)
                != Some(new_version)
        {
            return Err(CoreError::MalformedDocument(
                "prepared update is stale or has an invalid version link".into(),
            ));
        }
        if prepared.get("jacsSha256").is_none() || prepared.get("jacsRegistration").is_some() {
            return Err(CoreError::MalformedDocument(
                "prepared update requires its checksum and must not retain an old registration"
                    .into(),
            ));
        }
        if verification_claim_level(prepared) < verification_claim_level(&self.agent_json) {
            return Err(CoreError::MalformedDocument(
                "verification claim cannot be downgraded".into(),
            ));
        }
        self.agent_json = prepared.clone();
        Ok(prepared.clone())
    }

    fn sign_identity_document(&self, document: &mut Value) -> Result<(), CoreError> {
        let id = required_identity_string(document, "jacsId")?.to_owned();
        let version = required_identity_string(document, "jacsVersion")?.to_owned();
        let object = document.as_object_mut().expect("validated identity");
        object.remove(JACS_SIGNATURE_FIELDNAME);
        object.remove("jacsSha256");
        self.sign_document_for_identity(document, JACS_SIGNATURE_FIELDNAME, &id, &version)?;
        document["jacsSha256"] = json!(crate::document_hash_v1(document)?);
        // Verify callback output before publishing a new identity. An external
        // provider can return invalid bytes or refer to a replaced platform key.
        validate_agent_identity(document, self.algorithm, &self.public_key, true)
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

    /// Public key in the native-compatible registration format. This is a
    /// presentation format; key pinning must compare `public_key()` raw bytes.
    pub fn public_key_pem(&self) -> Result<String, CoreError> {
        crate::sign::public_key_pem(&self.public_key, self.algorithm)
    }

    /// Authenticate a self-signed identity against an explicit, canonical raw
    /// key and algorithm. Supports the native legacy public-key hash convention
    /// only after verifying the signature with the supplied exact key. Callers
    /// accepting a transfer must independently pin its expected agent ID/key.
    pub fn validate_identity(
        agent: &Value,
        public_key: &[u8],
        algorithm: SigningAlgorithm,
    ) -> Result<(), CoreError> {
        crate::identity::canonical_key_id(algorithm.as_str(), public_key)?;
        validate_agent_identity(agent, algorithm, public_key, true)
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
        // Wrap the plaintext immediately so it is wiped on every exit path,
        // including an envelope-encryption error. The encrypted material is
        // the only private-key representation allowed to escape this method.
        let raw_private = zeroize::Zeroizing::new(signer.export_private_key_bytes()?);
        let encrypted = crate::envelope::encrypt_private_key(raw_private.as_slice(), password)?;
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
        let agent_id = required_identity_string(&self.agent_json, "jacsId")?;
        let agent_version = required_identity_string(&self.agent_json, "jacsVersion")?;
        self.sign_document_for_identity(document, placement_key, agent_id, agent_version)
    }

    fn sign_document_for_identity(
        &self,
        document: &mut Value,
        placement_key: &str,
        agent_id: &str,
        agent_version: &str,
    ) -> Result<(), CoreError> {
        let signer = self.signer.as_ref().ok_or(CoreError::Locked)?;
        let algorithm = self.algorithm;
        let public_key_hash = sha256_hex(&self.public_key);
        let date = chrono::Utc::now().to_rfc3339();
        let iat = chrono::Utc::now().timestamp();
        let jti = uuid::Uuid::now_v7().to_string();
        let fields = default_signed_fields(document, placement_key);

        // The metadata used for the canonical payload — `signature` field
        // is empty here; `build_signature_content_v2` strips it anyway, but
        // making it explicit keeps the shape consistent with what the
        // verifier reconstructs.
        let metadata = build_signature_metadata(
            agent_id,
            agent_version,
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
            SigningAlgorithm::Es256 => match P256Signer::verify(public_key, bytes, signature) {
                Ok(()) => Ok(true),
                Err(CoreError::SignatureInvalid(_)) => Ok(false),
                Err(other) => Err(other),
            },
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
        SigningAlgorithm::Es256 => Ok(Box::new(P256Signer::from_private_bytes(private_key_bytes)?)),
        SigningAlgorithm::Pq2025 => Ok(Box::new(Pq2025Signer::from_private_bytes(
            private_key_bytes,
        )?)),
    }
}

/// Produce unsigned initial identity metadata for `CoreAgent::from_signer`.
/// New identities use UUID versions and native-compatible document headers.
pub fn ephemeral_agent_json(algorithm: SigningAlgorithm, public_key: &[u8]) -> Value {
    let version = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "$schema": "https://hai.ai/schemas/agent/v1/agent.schema.json",
        "jacsId": uuid::Uuid::new_v4().to_string(),
        "jacsVersion": version,
        "jacsVersionDate": now,
        "jacsOriginalVersion": version,
        "jacsOriginalDate": now,
        "jacsType": "agent",
        "jacsLevel": "config",
        "jacsAgentType": "ai",
        "name": "ephemeral",
        "algorithm": algorithm.as_str(),
        "publicKey": base64::engine::general_purpose::STANDARD.encode(public_key),
        "publicKeyLen": public_key.len(),
    })
}

fn verification_claim_level(value: &Value) -> u8 {
    match value.get("jacsVerificationClaim").and_then(Value::as_str) {
        Some("verified-registry" | "verified-hai.ai") => 2,
        Some("verified") => 1,
        _ => 0,
    }
}

fn required_identity_string<'a>(agent: &'a Value, field: &str) -> Result<&'a str, CoreError> {
    agent
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            CoreError::MalformedDocument(format!("agent '{field}' must be a nonempty string"))
        })
}

fn validate_agent_identity(
    agent: &Value,
    algorithm: SigningAlgorithm,
    public_key: &[u8],
    require_signature: bool,
) -> Result<(), CoreError> {
    if !agent.is_object() {
        return Err(CoreError::MalformedDocument(
            "agent must be a JSON object".into(),
        ));
    }
    let id = required_identity_string(agent, "jacsId")?;
    let version = required_identity_string(agent, "jacsVersion")?;
    for field in ["algorithm", "signingAlgorithm", "jacsAgentKeyAlgorithm"] {
        if let Some(value) = agent.get(field) {
            let raw = value.as_str().ok_or_else(|| {
                CoreError::MalformedDocument(format!("agent '{field}' must be a string"))
            })?;
            let declared = SigningAlgorithm::from_wire_str(raw)
                .ok_or_else(|| CoreError::UnsupportedAlgorithm(raw.to_owned()))?;
            if declared != algorithm {
                return Err(CoreError::AlgorithmMismatch {
                    expected: algorithm.to_string(),
                    actual: raw.to_owned(),
                });
            }
        }
    }
    for field in ["publicKey", "jacsPublicKey"] {
        if let Some(value) = agent.get(field) {
            let encoded = value.as_str().ok_or_else(|| {
                CoreError::MalformedKey(format!("agent '{field}' must be base64"))
            })?;
            let declared = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| CoreError::MalformedKey(format!("agent '{field}' must be base64")))?;
            if declared != public_key {
                return Err(CoreError::MalformedKey(format!(
                    "agent '{field}' differs from signer public key"
                )));
            }
        }
    }
    if agent
        .get("publicKeyLen")
        .is_some_and(|value| value.as_u64() != Some(public_key.len() as u64))
    {
        return Err(CoreError::MalformedKey(
            "agent publicKeyLen differs from signer public key".into(),
        ));
    }
    let key_hash = sha256_hex(public_key);
    for field in ["publicKeyHash", "jacsPublicKeyHash"] {
        if agent
            .get(field)
            .is_some_and(|value| value.as_str() != Some(key_hash.as_str()))
        {
            return Err(CoreError::MalformedKey(format!(
                "agent '{field}' differs from signer public key"
            )));
        }
    }
    if require_signature {
        let signature = agent.get(JACS_SIGNATURE_FIELDNAME).ok_or_else(|| {
            CoreError::MalformedDocument(
                "agent self-signature required; unsigned legacy material needs explicit migration"
                    .into(),
            )
        })?;
        if signature.get("agentID").and_then(Value::as_str) != Some(id) {
            return Err(CoreError::MalformedDocument(
                "agent self-signature ID mismatch".into(),
            ));
        }
        let signature_version = signature.get("agentVersion").and_then(Value::as_str);
        if signature_version != Some(version) {
            // Native update_self historically recorded the authorizing previous
            // agent version in the signature. Accept only that exact link, with
            // both endpoints authenticated by the verified document signature.
            let previous = agent
                .get("jacsPreviousVersion")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && *value != version);
            let fields = signature.get("fields").and_then(Value::as_array);
            let endpoints_signed = ["jacsVersion", "jacsPreviousVersion"].iter().all(|field| {
                fields
                    .is_some_and(|fields| fields.iter().any(|value| value.as_str() == Some(field)))
            });
            if previous.is_none() || signature_version != previous || !endpoints_signed {
                return Err(CoreError::MalformedDocument(
                    "agent self-signature version mismatch".into(),
                ));
            }
        }
        let outcome = verify_document(agent, public_key, algorithm, JACS_SIGNATURE_FIELDNAME)?;
        if !outcome.valid {
            return Err(CoreError::SignatureInvalid(
                "agent self-signature did not verify".into(),
            ));
        }
        // Native releases hashed a BOM-aware, lossy Unicode rendering of the
        // raw key. Accept that historical spelling only after exact-key
        // cryptographic verification, never as a substitute for verification.
        let declared_hash = signature.get("publicKeyHash").and_then(Value::as_str);
        if declared_hash != Some(key_hash.as_str()) {
            let legacy_hash = crate::verify::legacy_public_key_hash(public_key);
            if declared_hash != Some(legacy_hash.as_str()) {
                return Err(CoreError::MalformedKey(
                    "agent self-signature publicKeyHash mismatch".into(),
                ));
            }
        }
        if let Some(checksum) = agent.get("jacsSha256") {
            let expected = crate::document_hash_v1(agent)?;
            if checksum.as_str() != Some(expected.as_str()) {
                return Err(CoreError::MalformedDocument(
                    "agent jacsSha256 checksum mismatch".into(),
                ));
            }
        }
    }
    Ok(())
}
