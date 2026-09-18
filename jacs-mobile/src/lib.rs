//! Thin mobile FFI facade over `jacs-core`. No HTTP, filesystem or raw private
//! key API. Material JSON is byte-for-byte compatible with `jacs-wasm`.

use base64::Engine as _;
use jacs_core::{
    AgentMaterial, CoreAgent, CoreError, DetachedSigner, SigningAlgorithm, UnlockSecret,
};
use serde_json::Value;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum MobileAlgorithm {
    Ed25519,
    #[default]
    Pq2025,
    Es256,
}

impl From<MobileAlgorithm> for SigningAlgorithm {
    fn from(value: MobileAlgorithm) -> Self {
        match value {
            MobileAlgorithm::Ed25519 => Self::Ed25519,
            MobileAlgorithm::Pq2025 => Self::Pq2025,
            MobileAlgorithm::Es256 => Self::Es256,
        }
    }
}

impl From<SigningAlgorithm> for MobileAlgorithm {
    fn from(value: SigningAlgorithm) -> Self {
        match value {
            SigningAlgorithm::Ed25519 => Self::Ed25519,
            SigningAlgorithm::Pq2025 => Self::Pq2025,
            SigningAlgorithm::Es256 => Self::Es256,
        }
    }
}

/// Errors preserve the portable core's stable `code` rather than requiring
/// Swift/Kotlin clients to parse human-readable messages.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("{code}: {detail}")]
    Core { code: String, detail: String },
    #[error("invalid JSON: {detail}")]
    InvalidJson { detail: String },
    #[error("agent operation is already in progress")]
    Busy,
    #[error("agent state is unavailable")]
    Unavailable,
}

impl From<CoreError> for MobileError {
    fn from(error: CoreError) -> Self {
        Self::Core {
            code: error.code().into(),
            detail: error.to_string(),
        }
    }
}

impl From<serde_json::Error> for MobileError {
    fn from(error: serde_json::Error) -> Self {
        Self::InvalidJson {
            detail: error.to_string(),
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EncryptedAgentMaterial {
    pub config_json: String,
    pub agent_json: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub algorithm: MobileAlgorithm,
}

impl TryFrom<EncryptedAgentMaterial> for AgentMaterial {
    type Error = MobileError;
    fn try_from(value: EncryptedAgentMaterial) -> Result<Self, Self::Error> {
        Ok(Self {
            config: parse_json(&value.config_json)?,
            agent: parse_json(&value.agent_json)?,
            public_key: value.public_key,
            encrypted_private_key: value.encrypted_private_key,
            algorithm: value.algorithm.into(),
        })
    }
}

impl From<AgentMaterial> for EncryptedAgentMaterial {
    fn from(value: AgentMaterial) -> Self {
        Self {
            config_json: value.config.to_string(),
            agent_json: value.agent.to_string(),
            public_key: value.public_key,
            encrypted_private_key: value.encrypted_private_key,
            algorithm: value.algorithm.into(),
        }
    }
}

/// Explicit display/input only. Do not log, persist or send the code to storage.
#[derive(uniffi::Record)]
pub struct MobileRecoveryExport {
    pub code: String,
    pub material: EncryptedAgentMaterial,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MobileVerification {
    pub valid: bool,
    pub signer_id: String,
    pub timestamp: String,
    pub document_json: String,
    pub errors: Vec<String>,
}

impl From<jacs_core::VerificationOutcome> for MobileVerification {
    fn from(value: jacs_core::VerificationOutcome) -> Self {
        Self {
            valid: value.valid,
            signer_id: value.signer_id,
            timestamp: value.timestamp,
            document_json: value.data.to_string(),
            errors: value.errors,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PlatformSignerError {
    #[error("platform authentication required")]
    AuthenticationRequired,
    #[error("platform authentication cancelled")]
    Cancelled,
    #[error("platform signer unavailable: {detail}")]
    Unavailable { detail: String },
    #[error("platform signing failed: {detail}")]
    Failed { detail: String },
}

/// Implement in the native app. Only public keys and message/signature bytes
/// cross FFI. ES256 takes the ORIGINAL message, hashes once with SHA-256, and
/// returns 64-byte P1363 r||s (not DER). Its public key is SEC1 uncompressed.
/// Callbacks must not re-enter this MobileAgent. Run operations off the UI
/// thread; Android must complete BiometricPrompt authorization beforehand.
#[uniffi::export(callback_interface)]
pub trait PlatformSigner: Send + Sync {
    fn algorithm(&self) -> MobileAlgorithm;
    fn public_key(&self) -> Result<Vec<u8>, PlatformSignerError>;
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, PlatformSignerError>;
    /// Release session authentication and in-memory references, not the OS key.
    fn clear_secrets(&self);
}

struct CallbackSigner {
    callback: Box<dyn PlatformSigner>,
    algorithm: SigningAlgorithm,
    public_key: Vec<u8>,
    cleared: bool,
}

fn callback_error(error: PlatformSignerError) -> CoreError {
    match error {
        PlatformSignerError::AuthenticationRequired | PlatformSignerError::Cancelled => {
            CoreError::Locked
        }
        other => CoreError::SignerUnavailable(other.to_string()),
    }
}

impl DetachedSigner for CallbackSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.cleared {
            return Err(CoreError::Locked);
        }
        let mut signature = self
            .callback
            .sign(message.to_vec())
            .map_err(callback_error)?;
        if self.algorithm == SigningAlgorithm::Es256 {
            let parsed = p256::ecdsa::Signature::from_slice(&signature).map_err(|_| {
                CoreError::SignatureInvalid("platform ES256 signature must be 64-byte P1363".into())
            })?;
            signature = parsed.normalize_s().to_bytes().to_vec();
        }
        // A faulty/malicious callback cannot return a purported signed document.
        jacs_core::verify::verify_detached(self.algorithm, &self.public_key, message, &signature)?;
        Ok(signature)
    }
    fn clear_secrets(&mut self) {
        if !self.cleared {
            self.cleared = true;
            self.callback.clear_secrets();
        }
    }
    fn export_private_key_bytes(&self) -> Result<Vec<u8>, CoreError> {
        if self.cleared {
            Err(CoreError::Locked)
        } else {
            Err(CoreError::NotExportable)
        }
    }
}

impl Drop for CallbackSigner {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

/// Stateful Rust handle. A nonblocking lock prevents callback re-entry deadlocks.
#[derive(uniffi::Object)]
pub struct MobileAgent {
    inner: Mutex<CoreAgent>,
}

impl MobileAgent {
    fn wrap(agent: CoreAgent) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(agent),
        })
    }
    fn lock(&self) -> Result<MutexGuard<'_, CoreAgent>, MobileError> {
        self.inner.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => MobileError::Busy,
            std::sync::TryLockError::Poisoned(_) => MobileError::Unavailable,
        })
    }
}

#[uniffi::export]
impl MobileAgent {
    /// Recommended creation path: exportable ML-DSA-87 (pq2025). A failure is
    /// returned to the caller; this never falls back to a classical algorithm.
    #[uniffi::constructor]
    pub fn create_default() -> Result<Arc<Self>, MobileError> {
        Self::create(MobileAlgorithm::Pq2025)
    }

    /// Human identity, self-signed as human in its first version; PQ only.
    #[uniffi::constructor]
    pub fn create_human() -> Result<Arc<Self>, MobileError> {
        Ok(Self::wrap(CoreAgent::create_human()?))
    }

    /// Explicit algorithm selection for compatibility. Prefer create_default
    /// for new portable identities.
    #[uniffi::constructor]
    pub fn create(algorithm: MobileAlgorithm) -> Result<Arc<Self>, MobileError> {
        Ok(Self::wrap(CoreAgent::ephemeral(algorithm.into())?))
    }

    #[uniffi::constructor]
    pub fn import_encrypted_agent(
        material: EncryptedAgentMaterial,
        password: String,
    ) -> Result<Arc<Self>, MobileError> {
        let password = Zeroizing::new(password);
        Ok(Self::wrap(CoreAgent::from_encrypted_material(
            material.try_into()?,
            UnlockSecret::Password(&password),
        )?))
    }

    #[uniffi::constructor]
    pub fn from_platform_signer(
        callback: Box<dyn PlatformSigner>,
        agent_json: String,
    ) -> Result<Arc<Self>, MobileError> {
        let algorithm = callback.algorithm().into();
        let public_key = callback.public_key().map_err(callback_error)?;
        let signer = CallbackSigner {
            callback,
            algorithm,
            public_key,
            cleared: false,
        };
        Ok(Self::wrap(CoreAgent::from_signer(
            Box::new(signer),
            parse_json(&agent_json)?,
        )?))
    }

    /// Expectations must come from authenticated registration, not the QR or blob.
    #[uniffi::constructor]
    pub fn import_pinned(
        material: EncryptedAgentMaterial,
        code: String,
        expected_agent_id: String,
        expected_public_key: Vec<u8>,
        expected_algorithm: MobileAlgorithm,
    ) -> Result<Arc<Self>, MobileError> {
        let code = Zeroizing::new(code);
        Ok(Self::wrap(jacs_core::transfer::import_transferred_agent(
            material.try_into()?,
            &code,
            &expected_agent_id,
            &expected_public_key,
            expected_algorithm.into(),
        )?))
    }

    /// Durable recovery import. Pins come from trusted registration, not material.
    #[uniffi::constructor]
    pub fn import_recovery(
        material: EncryptedAgentMaterial,
        code: String,
        expected_agent_id: String,
        expected_public_key: Vec<u8>,
        expected_algorithm: MobileAlgorithm,
    ) -> Result<Arc<Self>, MobileError> {
        let code = Zeroizing::new(code);
        Ok(Self::wrap(jacs_core::recovery::import_recovery(
            material.try_into()?,
            &code,
            &expected_agent_id,
            &expected_public_key,
            expected_algorithm.into(),
        )?))
    }

    /// The owned native vault calls this; never expose MobileAgent through an app bridge.
    pub fn export_recovery(&self) -> Result<MobileRecoveryExport, MobileError> {
        let agent = self.lock()?;
        let recovery = jacs_core::recovery::export_recovery(&agent)?;
        Ok(MobileRecoveryExport {
            code: recovery.code.to_string(),
            material: recovery.material.into(),
        })
    }

    pub fn algorithm(&self) -> Result<MobileAlgorithm, MobileError> {
        Ok(self.lock()?.algorithm().into())
    }
    pub fn public_key(&self) -> Result<Vec<u8>, MobileError> {
        Ok(self.lock()?.public_key().to_vec())
    }
    pub fn get_public_key_base64(&self) -> Result<String, MobileError> {
        Ok(base64::engine::general_purpose::STANDARD.encode(self.lock()?.public_key()))
    }
    pub fn get_public_key_hash(&self) -> Result<String, MobileError> {
        Ok(jacs_core::verify::sha256_hex(self.lock()?.public_key()))
    }
    pub fn get_public_key_pem_base64(&self) -> Result<String, MobileError> {
        Ok(base64::engine::general_purpose::STANDARD
            .encode(self.lock()?.public_key_pem()?.as_bytes()))
    }

    pub fn is_unlocked(&self) -> Result<bool, MobileError> {
        Ok(self.lock()?.is_unlocked())
    }
    pub fn export_agent_json(&self) -> Result<String, MobileError> {
        Ok(self.lock()?.export_agent().to_string())
    }

    pub fn export_encrypted_agent(
        &self,
        password: String,
    ) -> Result<EncryptedAgentMaterial, MobileError> {
        let password = Zeroizing::new(password);
        Ok(self.lock()?.export_encrypted_material(&password)?.into())
    }

    /// Complete JACS document, with exact input JSON as content and fresh root headers.
    pub fn sign_document_json(&self, json: String) -> Result<String, MobileError> {
        Ok(self.lock()?.sign_document(&parse_json(&json)?)?.to_string())
    }

    pub fn sign_message_json(&self, json: String) -> Result<String, MobileError> {
        Ok(self.lock()?.sign_message(&parse_json(&json)?)?.to_string())
    }

    /// Detached signature for authenticated API requests; UTF-8 input, base64 output.
    pub fn sign_string(&self, message: String) -> Result<String, MobileError> {
        Ok(base64::engine::general_purpose::STANDARD
            .encode(self.lock()?.sign_raw_bytes(message.as_bytes())?))
    }

    /// HAI request-auth-v2, bound to the exact method/URL/body/audience.
    pub fn build_request_auth_header(
        &self,
        method: String,
        url: String,
        body: Vec<u8>,
        audience: String,
    ) -> Result<String, MobileError> {
        Ok(self
            .lock()?
            .build_request_auth_header(&method, &url, &body, &audience)?)
    }

    pub fn verify_json(&self, json: String) -> Result<MobileVerification, MobileError> {
        Ok(self.lock()?.verify(&parse_json(&json)?)?.into())
    }

    pub fn update_agent(&self, updates_json: String) -> Result<String, MobileError> {
        Ok(self
            .lock()?
            .update_agent(&parse_json(&updates_json)?)?
            .to_string())
    }

    /// Sign a candidate update while keeping the current registered version active.
    pub fn prepare_agent_update_json(&self, updates_json: String) -> Result<String, MobileError> {
        Ok(self
            .lock()?
            .prepare_agent_update(&parse_json(&updates_json)?)?
            .to_string())
    }

    /// Commit only after the registry explicitly accepts this exact candidate.
    pub fn commit_agent_update_json(&self, candidate_json: String) -> Result<String, MobileError> {
        Ok(self
            .lock()?
            .commit_agent_update(&parse_json(&candidate_json)?)?
            .to_string())
    }

    /// Relock the handle on background, logout and after transferring material.
    /// Verification and public metadata access remain available afterwards.
    pub fn clear_secrets(&self) -> Result<(), MobileError> {
        self.lock()?.clear_secrets();
        Ok(())
    }
}

impl Drop for MobileAgent {
    fn drop(&mut self) {
        // Also clear a poisoned mutex on drop; no secret survives handle disposal.
        match self.inner.get_mut() {
            Ok(agent) => agent.clear_secrets(),
            Err(poisoned) => poisoned.into_inner().clear_secrets(),
        }
    }
}

#[uniffi::export]
pub fn verify_with_key(
    json: String,
    public_key: Vec<u8>,
    algorithm: MobileAlgorithm,
) -> Result<MobileVerification, MobileError> {
    Ok(CoreAgent::verify_with_key(&parse_json(&json)?, &public_key, algorithm.into())?.into())
}

/// String-only browser/RN parity facade, without JS Buffer/btoa dependencies.
#[uniffi::export]
pub fn verify_with_key_json(
    json: String,
    public_key_base64: String,
    algorithm: MobileAlgorithm,
) -> Result<String, MobileError> {
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key_base64)
        .map_err(|_| CoreError::MalformedKey("invalid public key base64".into()))?;
    let outcome = CoreAgent::verify_with_key(&parse_json(&json)?, &public_key, algorithm.into())?;
    Ok(serde_json::to_string(&outcome)?)
}

/// Serialization uses core's base64 binary fields and exact WASM wire shape.
#[uniffi::export]
pub fn material_to_json(material: EncryptedAgentMaterial) -> Result<String, MobileError> {
    Ok(serde_json::to_string(&AgentMaterial::try_from(material)?)?)
}

/// Parsing alone does not establish identity. Import and compare the public
/// key/agent ID against a trusted registration before persisting a linked agent.
#[uniffi::export]
pub fn material_from_json(json: String) -> Result<EncryptedAgentMaterial, MobileError> {
    if json.len() > MAX_JSON_BYTES {
        return Err(CoreError::MalformedDocument("material JSON exceeds 1 MiB".into()).into());
    }
    Ok(jacs_core::strict_json::deserialize_strict_json::<AgentMaterial>(&json)?.into())
}

/// Cheap paste validation; no KDF, handle, storage or biometrics.
#[uniffi::export]
pub fn normalize_recovery_code(code: String) -> Result<String, MobileError> {
    let code = Zeroizing::new(code);
    Ok(jacs_core::recovery::normalize_recovery_code(&code)?.to_string())
}

/// Verify downloaded ciphertext against trusted registration. Only public identity
/// JSON is returned; the temporary unlocked key is cleared inside core.
#[uniffi::export]
pub fn verify_recovery(
    material: EncryptedAgentMaterial,
    code: String,
    expected_agent_id: String,
    expected_public_key: Vec<u8>,
    expected_algorithm: MobileAlgorithm,
) -> Result<String, MobileError> {
    let code = Zeroizing::new(code);
    Ok(jacs_core::recovery::verify_recovery(
        material.try_into()?,
        &code,
        &expected_agent_id,
        &expected_public_key,
        expected_algorithm.into(),
    )?
    .to_string())
}

/// Durable recovery code: 128 CSPRNG bits, distinct from device transfer.
#[uniffi::export]
pub fn generate_recovery_code() -> Result<String, MobileError> {
    Ok(jacs_core::recovery::generate_recovery_code()?.to_string())
}

/// Six independently sampled words (66 bits); display only on the sending device.
#[uniffi::export]
pub fn generate_transfer_code() -> Result<String, MobileError> {
    Ok(jacs_core::transfer::generate_transfer_code()?.to_string())
}

/// Validate/pin/decrypt/rewrap without leaving an unlocked handle behind.
#[uniffi::export]
pub fn reencrypt_transferred_material(
    material: EncryptedAgentMaterial,
    code: String,
    expected_agent_id: String,
    expected_public_key: Vec<u8>,
    expected_algorithm: MobileAlgorithm,
    storage_password: String,
) -> Result<EncryptedAgentMaterial, MobileError> {
    let code = Zeroizing::new(code);
    let storage_password = Zeroizing::new(storage_password);
    Ok(jacs_core::transfer::reencrypt_transferred_material(
        material.try_into()?,
        &code,
        &expected_agent_id,
        &expected_public_key,
        expected_algorithm.into(),
        &storage_password,
    )?
    .into())
}

const MAX_JSON_BYTES: usize = 1024 * 1024;
fn parse_json(json: &str) -> Result<Value, MobileError> {
    if json.len() > MAX_JSON_BYTES {
        return Err(CoreError::MalformedDocument("JSON exceeds 1 MiB".into()).into());
    }
    Ok(jacs_core::strict_json::parse_strict_json(json)?)
}
