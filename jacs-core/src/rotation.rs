//! Portable, staged key rotation. No storage, registration or I/O is performed.
//!
//! `jacs-key-rotation-v2` deliberately strengthens the archived native proof:
//! the old key authorizes the exact old identity and unsigned new identity,
//! both versions, canonical raw-key hashes, algorithms and timestamp. A legacy
//! unversioned `JACS_KEY_ROTATION:` proof is not accepted by this verifier.
//! Registry migration must explicitly adopt this version; do not fall back to
//! legacy verification after a V2 verification failure.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    AgentMaterial, CoreAgent, CoreError, DetachedSigner, Ed25519DalekSigner, P256Signer,
    Pq2025Signer, SigningAlgorithm, canonical::canonicalize_json_try, verify::sha256_hex,
};

const PROOF_VERSION: &str = "jacs-key-rotation-v2";
const ROTATION_DOMAIN: &str = "JACS_KEY_ROTATION_V2\n";
const COMMIT_DOMAIN: &str = "JACS_KEY_ROTATION_COMMIT_V2\n";

struct PendingSigner(Option<Box<dyn DetachedSigner>>);

impl Drop for PendingSigner {
    fn drop(&mut self) {
        if let Some(signer) = self.0.as_mut() {
            signer.clear_secrets();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationContext {
    version: String,
    #[serde(rename = "agentID")]
    agent_id: String,
    old_agent_version: String,
    new_agent_version: String,
    signing_algorithm: String,
    new_signing_algorithm: String,
    old_public_key_hash: String,
    new_public_key_hash: String,
    old_agent_hash: String,
    new_agent_hash: String,
    timestamp: String,
}

/// Opaque, non-serializable pending key replacement. The old agent stays active
/// while the caller exports the encrypted candidate and obtains registration
/// admission. Dropping a stage clears its candidate signer; no plaintext key
/// appears in its proof or Debug representation.
pub struct PreparedKeyRotation {
    old_identity: Value,
    old_public_key: Vec<u8>,
    old_algorithm: SigningAlgorithm,
    candidate: CoreAgent,
}

impl std::fmt::Debug for PreparedKeyRotation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedKeyRotation")
            .field("old_algorithm", &self.old_algorithm)
            .field("new_algorithm", &self.candidate.algorithm())
            .finish_non_exhaustive()
    }
}

impl Drop for PreparedKeyRotation {
    fn drop(&mut self) {
        self.candidate.clear_secrets();
    }
}

impl PreparedKeyRotation {
    pub fn agent(&self) -> Value {
        self.candidate.export_agent()
    }
    pub fn proof(&self) -> Value {
        self.candidate.agent_json["jacsKeyRotationProof"].clone()
    }
    pub fn public_key(&self) -> &[u8] {
        self.candidate.public_key()
    }
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.candidate.algorithm()
    }

    /// Export only the encrypted candidate, suitable for atomic storage by the
    /// caller. A hardware-held candidate correctly returns `NotExportable`.
    pub fn export_encrypted_material(&self, password: &str) -> Result<AgentMaterial, CoreError> {
        self.candidate.export_encrypted_material(password)
    }
}

impl CoreAgent {
    /// Stage a fresh software key. Omission selects PQ2025. Post-quantum agents
    /// cannot downgrade to classical algorithms, even with an explicit request.
    /// This operation never changes the active identity or signer.
    pub fn prepare_key_rotation(
        &self,
        algorithm: Option<SigningAlgorithm>,
    ) -> Result<PreparedKeyRotation, CoreError> {
        let algorithm = algorithm.unwrap_or(SigningAlgorithm::Pq2025);
        rotation_policy(self.algorithm, algorithm)?;
        self.signer.as_ref().ok_or(CoreError::Locked)?;
        let signer: Box<dyn DetachedSigner> = match algorithm {
            SigningAlgorithm::Ed25519 => Box::new(Ed25519DalekSigner::generate()?),
            SigningAlgorithm::Pq2025 => Box::new(Pq2025Signer::generate()?),
            SigningAlgorithm::Es256 => Box::new(P256Signer::generate()?),
        };
        self.prepare_key_rotation_with_signer(signer)
    }

    /// Stage an outside signer without ever exporting either private key.
    /// Both the old-key authorization and the new self-signature are verified
    /// before the candidate is returned. Provider errors leave the old agent intact.
    pub fn prepare_key_rotation_with_signer(
        &self,
        signer: Box<dyn DetachedSigner>,
    ) -> Result<PreparedKeyRotation, CoreError> {
        let mut pending_signer = PendingSigner(Some(signer));
        let signer = pending_signer.0.as_ref().expect("pending signer");
        self.signer.as_ref().ok_or(CoreError::Locked)?;
        Self::validate_identity(&self.agent_json, &self.public_key, self.algorithm)?;
        let algorithm = signer.algorithm();
        rotation_policy(self.algorithm, algorithm)?;
        let public_key = signer.public_key().to_vec();
        crate::identity::canonical_key_id(algorithm.as_str(), &public_key)?;
        if public_key == self.public_key {
            return Err(invalid("key rotation requires a different public key"));
        }
        let timestamp = chrono::Utc::now().to_rfc3339();
        let mut candidate = self.agent_json.clone();
        let object = candidate
            .as_object_mut()
            .ok_or_else(|| invalid("identity must be an object"))?;
        for field in [
            "jacsSignature",
            "jacsSha256",
            "jacsRegistration",
            "jacsKeyRotationProof",
        ] {
            object.remove(field);
        }
        object.insert(
            "jacsPreviousVersion".into(),
            self.agent_json["jacsVersion"].clone(),
        );
        object.insert(
            "jacsVersion".into(),
            json!(uuid::Uuid::new_v4().to_string()),
        );
        object.insert("jacsVersionDate".into(), json!(timestamp));
        for field in ["algorithm", "signingAlgorithm", "jacsAgentKeyAlgorithm"] {
            if field == "algorithm" || object.contains_key(field) {
                object.insert(field.into(), json!(algorithm.as_str()));
            }
        }
        for field in ["publicKey", "jacsPublicKey"] {
            if field == "publicKey" || object.contains_key(field) {
                object.insert(field.into(), json!(STANDARD.encode(&public_key)));
            }
        }
        object.insert("publicKeyLen".into(), json!(public_key.len()));
        for field in ["publicKeyHash", "jacsPublicKeyHash"] {
            if object.contains_key(field) {
                object.insert(field.into(), json!(sha256_hex(&public_key)));
            }
        }
        let context = RotationContext {
            version: PROOF_VERSION.into(),
            agent_id: required(&self.agent_json, "jacsId")?.into(),
            old_agent_version: required(&self.agent_json, "jacsVersion")?.into(),
            new_agent_version: required(&candidate, "jacsVersion")?.into(),
            signing_algorithm: self.algorithm.as_str().into(),
            new_signing_algorithm: algorithm.as_str().into(),
            old_public_key_hash: sha256_hex(&self.public_key),
            new_public_key_hash: sha256_hex(&public_key),
            old_agent_hash: identity_hash(&self.agent_json)?,
            new_agent_hash: identity_hash(&candidate)?,
            timestamp,
        };
        let mut proof = serde_json::to_value(context)
            .map_err(|_| invalid("rotation context encoding failed"))?;
        let transition_message = format!("{ROTATION_DOMAIN}{}", canonicalize_json_try(&proof)?);
        let signature = self.sign_raw_bytes(transition_message.as_bytes())?;
        if !Self::verify_raw_bytes_with_key(
            &self.public_key,
            self.algorithm,
            transition_message.as_bytes(),
            &signature,
        )? {
            return Err(CoreError::SignatureInvalid(
                "old provider returned invalid rotation authorization".into(),
            ));
        }
        proof["transitionMessage"] = json!(transition_message);
        proof["signature"] = json!(STANDARD.encode(signature));
        candidate["jacsKeyRotationProof"] = proof;
        let mut new_agent = CoreAgent {
            signer: pending_signer.0.take(),
            algorithm,
            public_key,
            agent_json: candidate.clone(),
        };
        // Match from_signer's canonical-key and verified callback invariants,
        // preserving the existing complete identity rather than merging defaults.
        if let Err(error) = new_agent.sign_identity_document(&mut candidate) {
            new_agent.clear_secrets();
            return Err(error);
        }
        new_agent.agent_json = candidate;
        let prepared = PreparedKeyRotation {
            old_identity: self.agent_json.clone(),
            old_public_key: self.public_key.clone(),
            old_algorithm: self.algorithm,
            candidate: new_agent,
        };
        self.verify_key_rotation(
            &prepared.agent(),
            prepared.public_key(),
            prepared.algorithm(),
        )?;
        Ok(prepared)
    }

    /// Verify a V2 transition against this independently trusted prior identity
    /// and key. Works after `clear_secrets`; no signing or private key is needed.
    pub fn verify_key_rotation(
        &self,
        candidate: &Value,
        new_public_key: &[u8],
        new_algorithm: SigningAlgorithm,
    ) -> Result<(), CoreError> {
        verify_key_rotation(
            &self.agent_json,
            &self.public_key,
            self.algorithm,
            candidate,
            new_public_key,
            new_algorithm,
        )
    }

    /// Commit precisely this opaque stage after durable storage/admission.
    /// Competing metadata updates/rotations make it stale. All validation and
    /// a fresh candidate-provider signature check precede mutation. The old
    /// signer's clear hook runs and its handle is dropped on successful commit.
    pub fn commit_key_rotation(
        &mut self,
        mut prepared: PreparedKeyRotation,
    ) -> Result<Value, CoreError> {
        self.signer.as_ref().ok_or(CoreError::Locked)?;
        if self.agent_json != prepared.old_identity
            || self.public_key != prepared.old_public_key
            || self.algorithm != prepared.old_algorithm
        {
            return Err(invalid(
                "prepared rotation is stale or belongs to another identity",
            ));
        }
        self.verify_key_rotation(
            &prepared.agent(),
            prepared.public_key(),
            prepared.algorithm(),
        )?;
        let challenge = format!(
            "{COMMIT_DOMAIN}{}",
            canonicalize_json_try(&prepared.proof())?
        );
        let signature = prepared.candidate.sign_raw_bytes(challenge.as_bytes())?;
        if !Self::verify_raw_bytes_with_key(
            prepared.public_key(),
            prepared.algorithm(),
            challenge.as_bytes(),
            &signature,
        )? {
            return Err(CoreError::SignatureInvalid(
                "candidate provider no longer controls the prepared key".into(),
            ));
        }
        self.clear_secrets();
        self.signer = prepared.candidate.signer.take();
        self.algorithm = prepared.candidate.algorithm;
        self.public_key = std::mem::take(&mut prepared.candidate.public_key);
        self.agent_json = std::mem::take(&mut prepared.candidate.agent_json);
        Ok(self.export_agent())
    }
}

/// Verify with an independently trusted old identity/public key/algorithm.
/// Neither public key is taken from self-asserted proof fields. V2 verifies the
/// old authorization and complete new self-signature; older proofs are rejected.
pub fn verify_key_rotation(
    old_identity: &Value,
    old_public_key: &[u8],
    old_algorithm: SigningAlgorithm,
    candidate: &Value,
    new_public_key: &[u8],
    new_algorithm: SigningAlgorithm,
) -> Result<(), CoreError> {
    rotation_policy(old_algorithm, new_algorithm)?;
    CoreAgent::validate_identity(old_identity, old_public_key, old_algorithm)?;
    CoreAgent::validate_identity(candidate, new_public_key, new_algorithm)?;
    let proof = candidate
        .get("jacsKeyRotationProof")
        .ok_or_else(|| invalid("missing rotation proof"))?;
    let transition_message = required(proof, "transitionMessage")?;
    let signature = STANDARD
        .decode(required(proof, "signature")?)
        .map_err(|_| invalid("rotation signature must be base64"))?;
    let mut unsigned = proof.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or_else(|| invalid("rotation proof must be an object"))?;
    object.remove("transitionMessage");
    object.remove("signature");
    let context: RotationContext = serde_json::from_value(unsigned.clone())
        .map_err(|_| invalid("invalid or unsupported rotation proof fields"))?;
    let old_version = required(old_identity, "jacsVersion")?;
    let new_version = required(candidate, "jacsVersion")?;
    let mut new_unsigned = candidate.clone();
    for field in ["jacsSignature", "jacsSha256", "jacsKeyRotationProof"] {
        new_unsigned
            .as_object_mut()
            .expect("validated identity")
            .remove(field);
    }
    if context.version != PROOF_VERSION
        || context.agent_id != required(old_identity, "jacsId")?
        || context.agent_id != required(candidate, "jacsId")?
        || context.old_agent_version != old_version
        || context.new_agent_version != new_version
        || old_version == new_version
        || candidate["jacsPreviousVersion"].as_str() != Some(old_version)
        || candidate["jacsSignature"]["agentVersion"].as_str() != Some(new_version)
        || context.signing_algorithm != old_algorithm.as_str()
        || context.new_signing_algorithm != new_algorithm.as_str()
        || context.old_public_key_hash != sha256_hex(old_public_key)
        || context.new_public_key_hash != sha256_hex(new_public_key)
        || old_public_key == new_public_key
        || context.old_agent_hash != identity_hash(old_identity)?
        || context.new_agent_hash != identity_hash(&new_unsigned)?
        || context.timestamp != required(candidate, "jacsVersionDate")?
        || chrono::DateTime::parse_from_rfc3339(&context.timestamp).is_err()
        || candidate.get("jacsRegistration").is_some()
        || candidate.get("jacsSha256").is_none()
    {
        return Err(invalid(
            "rotation proof does not bind the exact identities, versions and keys",
        ));
    }
    for field in [
        "jacsOriginalVersion",
        "jacsOriginalDate",
        "jacsType",
        "$schema",
    ] {
        if old_identity.get(field) != candidate.get(field) {
            return Err(invalid("rotation changes immutable identity provenance"));
        }
    }
    let signed_fields = candidate["jacsSignature"]["fields"]
        .as_array()
        .ok_or_else(|| invalid("rotation self-signature has no authenticated field set"))?;
    for field in candidate.as_object().expect("validated identity").keys() {
        if field != "jacsSignature"
            && field != "jacsSha256"
            && !signed_fields
                .iter()
                .any(|value| value.as_str() == Some(field.as_str()))
        {
            return Err(invalid(
                "rotation self-signature must authenticate the complete candidate",
            ));
        }
    }
    let expected_message = format!("{ROTATION_DOMAIN}{}", canonicalize_json_try(&unsigned)?);
    if transition_message != expected_message
        || !CoreAgent::verify_raw_bytes_with_key(
            old_public_key,
            old_algorithm,
            expected_message.as_bytes(),
            &signature,
        )?
    {
        return Err(CoreError::SignatureInvalid(
            "rotation is not authorized by the trusted old key".into(),
        ));
    }
    Ok(())
}

fn identity_hash(identity: &Value) -> Result<String, CoreError> {
    Ok(sha256_hex(canonicalize_json_try(identity)?.as_bytes()))
}

fn required<'a>(value: &'a Value, field: &str) -> Result<&'a str, CoreError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("missing rotation identity field '{field}'")))
}

fn rotation_policy(old: SigningAlgorithm, new: SigningAlgorithm) -> Result<(), CoreError> {
    if old == SigningAlgorithm::Pq2025 && new != SigningAlgorithm::Pq2025 {
        return Err(CoreError::UnsupportedAlgorithm(
            "post-quantum key rotation cannot downgrade to a classical algorithm".into(),
        ));
    }
    Ok(())
}

fn invalid(message: &str) -> CoreError {
    CoreError::MalformedDocument(message.into())
}
