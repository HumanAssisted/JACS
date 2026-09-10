// Allow deprecated config functions during 12-Factor migration (see task ARCH-005)
#![allow(deprecated)]

pub mod agreement;
pub mod boilerplate;
pub mod document;
pub mod loaders;
pub mod payloads;
pub mod security;

use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::DocumentTraits;
use crate::crypt::hash::{hash_public_key, hash_string};
use crate::error::JacsError;
use crate::storage::MultiStorage;

use crate::config::{Config, load_config_12factor, load_config_12factor_optional};

use crate::crypt::private_key::ZeroizingVec;

use crate::crypt::KeyManager;
use crate::keystore::{FsEncryptedStore, KeyPaths, KeySpec, KeyStore};

#[cfg(not(target_arch = "wasm32"))]
use crate::dns::bootstrap::verify_registry_registration_sync;
use crate::dns::bootstrap::{pubkey_digest_hex, verify_pubkey_via_dns_or_embedded};
use crate::observability::convenience::{
    SecurityOutcome, SecurityPolicy, SecuritySource, record_agent_operation,
    record_security_outcome, record_signature_verification, security_outcome_for_error,
};
use crate::schema::Schema;
use crate::schema::utils::{EmbeddedSchemaResolver, ValueExt};
use crate::time_utils;
use jsonschema::{Draft, Validator};
use loaders::FileLoader;
use serde_json::{Value, json, to_value};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::validation::{are_valid_uuid_parts, require_relative_path_safe};
use secrecy::{ExposeSecret, SecretBox};

/// Normalize a verification claim value.
///
/// Maps the deprecated `"verified-hai.ai"` alias to `"verified-registry"` and logs
/// a deprecation warning. All other values pass through unchanged.
///
/// This alias will be removed in the next major version.
pub fn normalize_verification_claim(claim: &str) -> &str {
    if claim == "verified-hai.ai" {
        warn!(
            "Verification claim \"verified-hai.ai\" is deprecated. \
             Use \"verified-registry\" instead. This alias will be removed in the next major version."
        );
        "verified-registry"
    } else {
        claim
    }
}

/// this field is only ignored by itself, but other
/// document signatures and hashes include this to detect tampering
pub const DOCUMENT_AGREEMENT_HASH_FIELDNAME: &str = "jacsAgreementHash";

// these fields generally exclude themselves when hashing
pub const SHA256_FIELDNAME: &str = "jacsSha256";
pub const AGENT_SIGNATURE_FIELDNAME: &str = "jacsSignature";
pub const AGENT_REGISTRATION_SIGNATURE_FIELDNAME: &str = "jacsRegistration";
pub const AGENT_AGREEMENT_FIELDNAME: &str = "jacsAgreement";
pub const DOCUMENT_AGENT_SIGNATURE_FIELDNAME: &str = "jacsSignature";
pub const JACS_VERSION_FIELDNAME: &str = "jacsVersion";
pub const JACS_VERSION_DATE_FIELDNAME: &str = "jacsVersionDate";
pub const JACS_PREVIOUS_VERSION_FIELDNAME: &str = "jacsPreviousVersion";
pub const SIGNATURE_CONTENT_VERSION_FIELDNAME: &str = "signatureContentVersion";
pub const SIGNATURE_CONTENT_VERSION_V2: &str = "jacs-signature-v2";
pub const SIGNATURE_CONTENT_DOMAIN_V2: &str = "jacs.signature.v2";
pub(crate) const ALLOW_LEGACY_SIGNATURE_CONTENT_ENV: &str = "JACS_ALLOW_LEGACY_SIGNATURE_CONTENT";
pub(crate) const REJECT_LEGACY_SIGNATURE_CONTENT_ENV: &str = "JACS_REJECT_LEGACY_SIGNATURE_CONTENT";
pub(crate) const ALLOW_UNSIGNED_AGENT_CONFIG_ENV: &str = "JACS_ALLOW_UNSIGNED_AGENT_CONFIG";
const MAX_LOCAL_PUBLIC_KEY_BYTES: usize = 64 * 1024;

thread_local! {
    /// Explicit, thread-scoped authorization used only by the migration API.
    ///
    /// Normal verification must never toggle process-global state merely to
    /// inspect a legacy document. A depth counter permits nested migration
    /// helpers while restoring the previous state on every return path.
    static LEGACY_MIGRATION_SCOPE_DEPTH: Cell<u32> = const { Cell::new(0) };
}

fn env_truthy(name: &str) -> bool {
    crate::storage::jenv::get_env_var(name, false)
        .ok()
        .flatten()
        .is_some_and(|value| value.eq_ignore_ascii_case("true") || value == "1")
}

/// Whether normal verification may accept legacy-v1 signature content.
///
/// The secure default is deny. Compatibility is an explicit opt-in and the
/// historical reject flag always wins. The migration API has a separate
/// thread-scoped authorization so it does not weaken unrelated verification.
pub(crate) fn legacy_signature_content_allowed() -> bool {
    if LEGACY_MIGRATION_SCOPE_DEPTH.with(|depth| depth.get() > 0) {
        return true;
    }
    !env_truthy(REJECT_LEGACY_SIGNATURE_CONTENT_ENV)
        && env_truthy(ALLOW_LEGACY_SIGNATURE_CONTENT_ENV)
}

/// Run an explicit legacy migration operation without changing process-global
/// verification policy.
pub(crate) fn with_legacy_signature_migration_scope<T>(f: impl FnOnce() -> T) -> T {
    struct ScopeGuard;
    impl Drop for ScopeGuard {
        fn drop(&mut self) {
            LEGACY_MIGRATION_SCOPE_DEPTH.with(|depth| {
                depth.set(depth.get().saturating_sub(1));
            });
        }
    }

    LEGACY_MIGRATION_SCOPE_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
    let _guard = ScopeGuard;
    f()
}

pub(crate) fn legacy_signature_refusal(signature_key_from: &str) -> JacsError {
    JacsError::SignatureVerificationFailed {
        reason: format!(
            "Refusing to verify legacy v1 signature content for '{}' (missing '{}'). \
             Legacy v1 does not authenticate signature metadata (agentID, date, jti, \
             signingAlgorithm). Re-sign or migrate the document. For an explicitly \
             audited compatibility workflow only, set {}=true.",
            signature_key_from,
            SIGNATURE_CONTENT_VERSION_FIELDNAME,
            ALLOW_LEGACY_SIGNATURE_CONTENT_ENV
        ),
    }
}

// these fields are ignored when hashing
pub const JACS_IGNORE_FIELDS: [&str; 5] = [
    SHA256_FIELDNAME,
    AGENT_SIGNATURE_FIELDNAME,
    DOCUMENT_AGENT_SIGNATURE_FIELDNAME,
    AGENT_AGREEMENT_FIELDNAME,
    AGENT_REGISTRATION_SIGNATURE_FIELDNAME,
];

#[derive(Debug)]
enum ConfigPreflight {
    Unsigned,
    SignedCurrent(Option<crate::keystore::RotationJournal>),
    SignedHistorical(crate::keystore::RotationJournal),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ConfigUse {
    NewAgent,
    ExistingAgent,
}

/// Controls how signature payload content is built from document fields.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SignatureContentMode {
    /// Canonicalized field values (includes non-string JSON types).
    CanonicalV2,
}

/// Extract the signature `fields` array from a signature object.
pub(crate) fn extract_signature_fields(
    json_value: &Value,
    signature_key_from: &str,
) -> Option<Vec<String>> {
    let arr = json_value
        .get(signature_key_from)?
        .get("fields")?
        .as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        if let Some(field) = entry.as_str() {
            out.push(field.to_string());
        }
    }
    Some(out)
}

pub(crate) fn canonicalize_json(value: &Value) -> Result<String, JacsError> {
    // Delegate to jacs_core so the bytes signed here are identical to the
    // bytes verified anywhere else in the workspace (PRD §4.4).
    jacs_core::canonical::canonicalize_json_try(value).map_err(JacsError::from)
}

fn validate_signature_temporal_claims(
    json_value: &Value,
    signature_key_from: &str,
) -> Result<(), JacsError> {
    let signature = json_value.get(signature_key_from).ok_or_else(|| {
        JacsError::SignatureVerificationFailed {
            reason: format!(
                "Missing '{}' signature object while validating temporal claims.",
                signature_key_from
            ),
        }
    })?;

    let iat = signature
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| JacsError::SignatureVerificationFailed {
            reason: format!(
                "Missing or invalid '{}.iat'. Signature metadata must include a Unix timestamp.",
                signature_key_from
            ),
        })?;

    if iat < 0 {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!(
                "Invalid '{}.iat': timestamp must be non-negative.",
                signature_key_from
            ),
        });
    }

    let jti = signature
        .get("jti")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .ok_or_else(|| JacsError::SignatureVerificationFailed {
            reason: format!(
                "Missing or invalid '{}.jti'. Signature metadata must include a nonce.",
                signature_key_from
            ),
        })?;

    if jti.is_empty() {
        return Err(JacsError::SignatureVerificationFailed {
            reason: format!(
                "Invalid '{}.jti': nonce cannot be empty.",
                signature_key_from
            ),
        });
    }

    // Intentionally NO iat-skew check here. JACS document signatures are
    // archival: a signed document is valid for the working life of the
    // signing key, with no time-of-day freshness requirement. HTTP/API
    // payload replay protection lives in `crate::replay` and is gated on
    // `JACS_PAYLOAD_MAX_REPLAY_SECONDS`. Future work: cross-check `iat`
    // against the signing key's rotation timeline so signatures produced
    // by a key that has since been rotated out are rejected.
    let _ = iat;
    Ok(())
}

pub(crate) fn build_signature_content(
    json_value: &Value,
    keys: Option<Vec<String>>,
    placement_key: &str,
    _mode: SignatureContentMode,
) -> Result<(String, Vec<String>), JacsError> {
    debug!("build_signature_content keys:\n{:?}", keys);
    let defaults = keys.is_none();
    let mut accepted_fields = match keys {
        Some(keys) => keys,
        None => json_value
            .as_object()
            .unwrap_or(&serde_json::Map::new())
            .keys()
            .filter(|&key| key != placement_key && !JACS_IGNORE_FIELDS.contains(&key.as_str()))
            .map(std::string::ToString::to_string)
            .collect(),
    };

    // Canonical default behavior: stable ordering by field name.
    if defaults {
        accepted_fields.sort();
    }

    // Eliminate duplicates while preserving order.
    let mut seen = HashSet::new();
    accepted_fields.retain(|field| seen.insert(field.clone()));

    let mut content_parts: Vec<String> = Vec::with_capacity(accepted_fields.len());
    for key in &accepted_fields {
        if key == placement_key || JACS_IGNORE_FIELDS.contains(&key.as_str()) {
            let error_message = format!(
                "Field names for signature must not include reserved key '{}' (reserved: {:?})",
                key, JACS_IGNORE_FIELDS
            );
            error!("{}", error_message);
            return Err(error_message.into());
        }
        if let Some(value) = json_value.get(key) {
            content_parts.push(canonicalize_json(value)?);
        }
    }

    let content = content_parts.join(" ");
    debug!(
        "build_signature_content result: {:?} fields {:?} mode {:?}",
        content, accepted_fields, _mode
    );
    Ok((content, accepted_fields))
}

pub(crate) fn build_signature_content_v2(
    json_value: &Value,
    fields: Vec<String>,
    placement_key: &str,
    signature_metadata: &Value,
) -> Result<String, JacsError> {
    let mut metadata = signature_metadata.clone();
    let metadata_obj =
        metadata
            .as_object_mut()
            .ok_or_else(|| JacsError::SignatureVerificationFailed {
                reason: format!(
                    "Signature metadata at '{}' must be a JSON object.",
                    placement_key
                ),
            })?;
    metadata_obj.remove("signature");

    let mut field_entries = Vec::with_capacity(fields.len());
    for key in fields {
        if key == placement_key || JACS_IGNORE_FIELDS.contains(&key.as_str()) {
            return Err(JacsError::SignatureVerificationFailed {
                reason: format!(
                    "Field names for signature must not include reserved key '{}'.",
                    key
                ),
            });
        }
        let value = json_value
            .get(&key)
            .ok_or_else(|| JacsError::SignatureVerificationFailed {
                reason: format!(
                    "Signed field '{}' is missing while building v2 signature payload.",
                    key
                ),
            })?;
        field_entries.push(json!({
            "name": key,
            "value": value
        }));
    }

    let payload = json!({
        "domain": SIGNATURE_CONTENT_DOMAIN_V2,
        "placementKey": placement_key,
        "fields": field_entries,
        "signatureMetadata": metadata
    });

    canonicalize_json(&payload)
}

// Just use Vec<u8> directly since it already implements the needed traits
pub type PrivateKey = Vec<u8>;
pub type SecretPrivateKey = SecretBox<Vec<u8>>;

/// Decrypt a private key using an agent-scoped password if available.
pub(crate) fn decrypt_with_agent_password(
    key: &[u8],
    password: Option<&str>,
    agent_id: Option<&str>,
) -> Result<ZeroizingVec, JacsError> {
    let resolved = crate::crypt::aes_encrypt::resolve_private_key_password(password, agent_id)?;
    crate::crypt::aes_encrypt::decrypt_private_key_secure_with_password(key, &resolved)
}

/// # Thread Safety
///
/// `Agent` is **not internally synchronized** by design. All mutable fields
/// (value, id, version, keys, etc.) are unprotected because every production
/// entry point wraps `Agent` in an external `Mutex`:
///
/// - `SimpleAgent` (`simple/core.rs`): `agent: Mutex<Agent>`
/// - `AgentWrapper` (`binding-core`): `inner: Arc<Mutex<Agent>>`
/// - `FilesystemDocumentService`: `Arc<Mutex<Agent>>`
/// - `JacsMcpServer`: `Arc<AgentWrapper>` (which holds `Arc<Mutex<Agent>>`)
///
/// Adding field-level synchronization (e.g., `Arc<Mutex<Value>>` on each field)
/// would double-lock with the external Mutex, adding overhead without benefit.
/// The one exception is `document_schemas` which uses `Arc<Mutex<>>` because
/// it was designed for independent schema loading that can outlive a single
/// lock scope.
///
/// **If you use `Agent` directly (without `SimpleAgent` or `AgentWrapper`),
/// you must provide your own synchronization.**
pub struct Agent {
    /// the JSONSchema used
    /// todo use getter
    pub schema: Schema,
    /// the agent JSON struct — protected by external Mutex (see struct-level docs)
    value: Option<Value>,
    /// use getter
    pub config: Option<Config>,
    //  todo make read commands public but not write commands
    storage: MultiStorage,
    /// custom schemas that can be loaded to check documents
    /// the resolver might ahve trouble TEST
    document_schemas: Arc<Mutex<HashMap<String, Validator>>>,
    /// everything needed for the agent to sign things
    pub(crate) id: Option<String>,
    version: Option<String>,
    public_key: Option<Vec<u8>>,
    private_key: Option<SecretPrivateKey>,
    key_algorithm: Option<String>,
    /// optional key store for ephemeral agents (replaces FsEncryptedStore)
    key_store: Option<Box<dyn KeyStore>>,
    /// true for ephemeral agents (in-memory keys, no AES encryption)
    ephemeral: bool,
    /// control DNS strictness for public key verification
    dns_strict: bool,
    /// whether DNS validation is enabled (None means derive from config/domain presence)
    dns_validate_enabled: Option<bool>,
    /// whether DNS validation is required (must have domain and successful DNS check)
    dns_required: Option<bool>,
    /// Resolved filesystem paths for key material (set from Config at construction).
    /// When `Some`, `FsEncryptedStore::new(paths)` uses these instead of env reads.
    key_paths: Option<KeyPaths>,
    /// Agent-scoped private key password. When `Some`, `resolve_private_key_password`
    /// returns this immediately without touching env/jenv. Enables safe concurrent
    /// multi-agent usage.
    password: Option<String>,
    /// TEST-ONLY compatibility fixture mode. It models a pre-compat-key
    /// Ed25519 identity; normal public creation also supports Ed25519 but
    /// follows the current keyring/bootstrap behavior.
    legacy_ed25519_keygen_for_fixtures: bool,
    /// Evidence adapters for attestation (gated behind `attestation` feature).
    #[cfg(feature = "attestation")]
    pub adapters: Vec<Box<dyn crate::attestation::adapters::EvidenceAdapter>>,
}

/// Manual `Debug` for `Agent` (SEC-3).
///
/// The derived `Debug` would render the agent-scoped `password` field (the
/// at-rest private-key password) in plaintext anywhere an `Agent` is formatted
/// via `{:?}` — including panic backtraces and downstream logging. This impl
/// redacts the password and shows only non-secret identity/state fields.
impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("key_algorithm", &self.key_algorithm)
            .field("ephemeral", &self.ephemeral)
            .field("has_private_key", &self.private_key.is_some())
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.value {
            Some(value) => {
                let json_string = serde_json::to_string_pretty(value).map_err(|_| fmt::Error)?;
                write!(f, "{}", json_string)
            }
            None => write!(f, "No Agent Loaded"),
        }
    }
}

impl Agent {
    pub fn new(
        agentversion: &str,
        headerversion: &str,
        signature_version: &str,
    ) -> Result<Self, JacsError> {
        let schema = Schema::new(agentversion, headerversion, signature_version)?;
        let document_schemas_map = Arc::new(Mutex::new(HashMap::new()));
        let config = Some(load_config_12factor_optional(None)?);
        let key_paths = config
            .as_ref()
            .map(Self::key_paths_from_config)
            .transpose()?;
        Ok(Self {
            schema,
            value: None,
            config,
            storage: MultiStorage::default_new()?,
            document_schemas: document_schemas_map,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
            key_store: None,
            ephemeral: false,
            dns_strict: false,
            dns_validate_enabled: None,
            dns_required: None,
            key_paths,
            password: None,
            legacy_ed25519_keygen_for_fixtures: false,
            #[cfg(feature = "attestation")]
            adapters: crate::attestation::adapters::default_adapters(),
        })
    }

    /// Authenticate persisted configuration before a caller uses any of its
    /// path, storage, database, or network settings for an existing identity.
    ///
    /// This stateless guard is intended for wrappers that must resolve local
    /// password/key context before constructing an Agent. Full identity loads
    /// must still use [`Agent::from_config`] or `SimpleAgent::load`, which also
    /// bind the config to the loaded agent and complete safe rotation recovery.
    pub fn verify_existing_config_before_use(config: &Config) -> Result<(), JacsError> {
        let schema = Schema::new("v1", "v1", "v1")?;
        let source_path = config
            .source_path()
            .map(|path| path.to_string_lossy().into_owned());
        Self::verify_config_before_use(
            &schema,
            config,
            source_path.as_deref(),
            ConfigUse::ExistingAgent,
        )
        .map(|_| ())
    }

    /// Authenticate an existing on-disk template before reusing it while
    /// creating a new identity. Unsigned templates are accepted only when
    /// they do not already select an identity.
    pub fn verify_new_config_before_use(config: &Config) -> Result<(), JacsError> {
        let schema = Schema::new("v1", "v1", "v1")?;
        let source_path = config
            .source_path()
            .map(|path| path.to_string_lossy().into_owned());
        match Self::verify_config_before_use(
            &schema,
            config,
            source_path.as_deref(),
            ConfigUse::NewAgent,
        )? {
            ConfigPreflight::Unsigned | ConfigPreflight::SignedCurrent(None) => Ok(()),
            ConfigPreflight::SignedCurrent(Some(_))
            | ConfigPreflight::SignedHistorical(_) => Err(JacsError::ConfigError(
                "Resolve the existing config's pending key rotation before reusing it for a new identity."
                    .to_string(),
            )),
        }
    }

    pub(crate) fn install_verified_config_context(
        &mut self,
        config: Config,
        config_path: &str,
    ) -> Result<(), JacsError> {
        match Self::verify_config_before_use(
            &self.schema,
            &config,
            Some(config_path),
            ConfigUse::ExistingAgent,
        )? {
            ConfigPreflight::Unsigned | ConfigPreflight::SignedCurrent(None) => {}
            ConfigPreflight::SignedCurrent(Some(_)) | ConfigPreflight::SignedHistorical(_) => {
                return Err(JacsError::ConfigError(
                    "A nearby config has pending key-rotation recovery; load through the config path before loading an explicit agent file."
                        .to_string(),
                ));
            }
        }
        let storage_type = config
            .jacs_default_storage()
            .as_deref()
            .unwrap_or("fs")
            .to_string();
        let (storage_root, config) =
            Self::calculate_storage_root_and_normalize(config, "explicit agent-file load")?;
        self.config = Some(config);
        self.refresh_key_paths_from_config()?;
        self.storage = MultiStorage::_new(
            Self::local_agent_storage_type(&storage_type, "explicit agent-file load"),
            storage_root,
        )?;
        Ok(())
    }

    /// Create and load an agent from a pre-built Config and optional password.
    ///
    /// This is the canonical one-call agent loading API. Callers compose their
    /// own config (via `Config::from_file()` + optional `apply_env_overrides()`)
    /// and pass the password directly -- no env var side-channels needed.
    ///
    /// # Arguments
    /// * `config` - A pre-built Config (not re-read from file)
    /// * `password` - Optional private key password. If None, falls back to
    ///   `JACS_PRIVATE_KEY_PASSWORD` env var inside keystore operations.
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut config = Config::from_file("jacs.config.json")?;
    /// config.apply_env_overrides();
    /// let agent = Agent::from_config(config, Some("my-password"))?;
    /// ```
    pub fn from_config(mut config: Config, password: Option<&str>) -> Result<Self, JacsError> {
        // Preserve the authenticated bytes before normalization consumes the
        // runtime-only Config metadata.
        let config_raw_json = config.raw_json.clone();
        let config_source_path = config
            .source_path()
            .map(|path| path.to_string_lossy().into_owned());

        let schema = Schema::new("v1", "v1", "v1")?;
        let config_use = if config
            .jacs_agent_id_and_version()
            .as_deref()
            .is_some_and(|lookup| !lookup.trim().is_empty())
        {
            ConfigUse::ExistingAgent
        } else {
            ConfigUse::NewAgent
        };
        let config_preflight = Self::verify_config_before_use(
            &schema,
            &config,
            config_source_path.as_deref(),
            config_use,
        )?;
        if config_use == ConfigUse::ExistingAgent
            && let Some(path) = config_source_path.as_deref()
        {
            let mut agent = Self::new("v1", "v1", "v1")?;
            agent.password = password.map(String::from);
            agent.apply_preflighted_config_and_load(
                config,
                "Agent::from_config",
                path,
                config_preflight,
                config_raw_json,
            )?;
            return Ok(agent);
        }
        let document_schemas_map = Arc::new(Mutex::new(HashMap::new()));

        // Calculate storage root and normalize config directories
        let (storage_root, normalized_config) =
            Self::calculate_storage_root_and_normalize(config, "Agent::from_config")?;
        config = normalized_config;

        let storage_type: String = config
            .jacs_default_storage()
            .as_deref()
            .unwrap_or("fs")
            .to_string();
        let file_storage_type = Self::local_agent_storage_type(&storage_type, "Agent::from_config");

        let storage = MultiStorage::_new(file_storage_type, storage_root).map_err(|e| {
            format!(
                "Agent::from_config failed: Could not initialize storage type '{}': {}",
                storage_type, e
            )
        })?;

        let lookup_id: String = config
            .jacs_agent_id_and_version()
            .as_deref()
            .unwrap_or("")
            .to_string();

        let mut agent = Self {
            schema,
            value: None,
            config: Some(config),
            storage,
            document_schemas: document_schemas_map,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
            key_store: None,
            ephemeral: false,
            dns_strict: false,
            dns_validate_enabled: None,
            dns_required: None,
            key_paths: None,
            password: password.map(String::from),
            legacy_ed25519_keygen_for_fixtures: false,
            #[cfg(feature = "attestation")]
            adapters: crate::attestation::adapters::default_adapters(),
        };

        // Compute key_paths from the normalized config
        agent.refresh_key_paths_from_config()?;

        if !lookup_id.is_empty() {
            let agent_string = agent.fs_agent_load(&lookup_id).map_err(|e| {
                format!(
                    "Agent::from_config failed: Could not load agent '{}': {}",
                    lookup_id, e
                )
            })?;
            agent.load(&agent_string).map_err(|e| {
                let err_msg = format!(
                    "Agent::from_config failed: Agent '{}' validation or key loading failed: {}",
                    lookup_id, e
                );
                JacsError::Internal { message: err_msg }
            })?;
        }

        agent.finish_config_verification(
            config_preflight,
            &config_raw_json,
            config_source_path.as_deref(),
        )?;

        Ok(agent)
    }

    /// Load an existing agent's authenticated public identity and document
    /// storage without reading a password or private-key file.
    ///
    /// This is the read-side constructor for verification-only processes. It
    /// deliberately refuses pending key-rotation recovery because recovery can
    /// re-sign configuration and therefore belongs to an authorized signing
    /// process. The resulting `Agent` has no private key and all existing
    /// signing methods continue to fail through their normal locked/key-missing
    /// checks.
    pub fn from_config_public_only(mut config: Config) -> Result<Self, JacsError> {
        let config_raw_json = config.raw_json.clone();
        let config_source_path = config
            .source_path()
            .map(|path| path.to_string_lossy().into_owned())
            .ok_or_else(|| {
                JacsError::ConfigError(
                    "Public-only loading requires an authenticated config file path.".into(),
                )
            })?;
        let lookup_id = config
            .jacs_agent_id_and_version()
            .as_deref()
            .filter(|lookup| !lookup.trim().is_empty())
            .ok_or_else(|| {
                JacsError::ConfigError(
                    "Public-only loading requires jacs_agent_id_and_version.".into(),
                )
            })?
            .to_string();
        let schema = Schema::new("v1", "v1", "v1")?;
        let config_preflight = Self::verify_config_before_use(
            &schema,
            &config,
            Some(&config_source_path),
            ConfigUse::ExistingAgent,
        )?;
        match &config_preflight {
            ConfigPreflight::Unsigned | ConfigPreflight::SignedCurrent(None) => {}
            ConfigPreflight::SignedCurrent(Some(_)) | ConfigPreflight::SignedHistorical(_) => {
                return Err(JacsError::ConfigError(
                    "Public-only loading refuses pending key-rotation recovery; complete recovery in an authorized local signing process first."
                        .into(),
                ));
            }
        }

        // Read only the configured public key through the same bounded,
        // no-follow path used by signed-config preflight. No password or
        // private-key locator is consulted.
        let public_key = Self::read_config_public_key(&config)?;
        let key_algorithm = config.get_key_algorithm()?;
        let storage_type = config
            .jacs_default_storage()
            .as_deref()
            .unwrap_or("fs")
            .to_string();
        let (storage_root, normalized_config) =
            Self::calculate_storage_root_and_normalize(config, "Agent::from_config_public_only")?;
        config = normalized_config;
        let file_storage_type =
            Self::local_agent_storage_type(&storage_type, "Agent::from_config_public_only");
        let storage = MultiStorage::_new(file_storage_type, storage_root).map_err(|error| {
            JacsError::Internal {
                message: format!(
                    "Agent::from_config_public_only failed to initialize storage type '{}': {}",
                    storage_type, error
                ),
            }
        })?;
        let document_schemas_map = Arc::new(Mutex::new(HashMap::new()));
        let mut agent = Self {
            schema,
            value: None,
            config: Some(config),
            storage,
            document_schemas: document_schemas_map,
            id: None,
            version: None,
            key_algorithm: Some(key_algorithm),
            public_key: Some(public_key),
            private_key: None,
            key_store: None,
            ephemeral: false,
            dns_strict: false,
            dns_validate_enabled: None,
            dns_required: None,
            key_paths: None,
            password: None,
            legacy_ed25519_keygen_for_fixtures: false,
            #[cfg(feature = "attestation")]
            adapters: crate::attestation::adapters::default_adapters(),
        };
        let agent_string =
            agent
                .fs_agent_load(&lookup_id)
                .map_err(|error| JacsError::Internal {
                    message: format!(
                        "Agent::from_config_public_only failed to load public agent '{}': {}",
                        lookup_id, error
                    ),
                })?;
        let value = agent.validate_agent(&agent_string)?;
        let id = value.get_str("jacsId").ok_or_else(|| {
            JacsError::AgentError("Public agent document is missing jacsId.".into())
        })?;
        let version = value.get_str("jacsVersion").ok_or_else(|| {
            JacsError::AgentError("Public agent document is missing jacsVersion.".into())
        })?;
        if lookup_id != format!("{id}:{version}") || !are_valid_uuid_parts(&id, &version) {
            return Err(JacsError::AgentError(
                "Public agent identity/version does not match the authenticated config lookup."
                    .into(),
            ));
        }
        agent.id = Some(id);
        agent.version = Some(version);
        agent.value = Some(value);
        agent.verify_self_signature()?;

        match config_preflight {
            ConfigPreflight::Unsigned => {}
            ConfigPreflight::SignedCurrent(None) => {
                let json = config_raw_json.as_ref().ok_or_else(|| {
                    JacsError::ConfigError(
                        "Authenticated config provenance was lost during public-only loading."
                            .into(),
                    )
                })?;
                agent.verify_config(json)?;
            }
            ConfigPreflight::SignedCurrent(Some(_)) | ConfigPreflight::SignedHistorical(_) => {
                unreachable!("pending rotation was rejected before storage initialization")
            }
        }
        if agent.private_key.is_some() || agent.password.is_some() || agent.key_store.is_some() {
            return Err(JacsError::Internal {
                message: "Public-only loader materialized signing state.".into(),
            });
        }
        Ok(agent)
    }

    /// Calculate storage root from config and normalize directory paths.
    ///
    /// Returns `(storage_root, normalized_config)`. The config is modified
    /// in place to normalize relative/absolute directory paths.
    fn calculate_storage_root_and_normalize(
        config: Config,
        caller: &str,
    ) -> Result<(std::path::PathBuf, Config), JacsError> {
        let storage_type: String = config
            .jacs_default_storage()
            .as_deref()
            .unwrap_or("")
            .to_string();
        let uses_filesystem_paths = Self::storage_uses_local_agent_filesystem(&storage_type);
        if !uses_filesystem_paths {
            return Ok((std::env::current_dir()?, config));
        }

        let config_dir = config
            .config_dir()
            .unwrap_or_else(|| std::path::Path::new("."));
        let config_dir_absolute = Self::normalize_lexical_path(&if config_dir.is_absolute() {
            config_dir.to_path_buf()
        } else {
            std::env::current_dir()?.join(config_dir)
        });

        let mut config_value = to_value(&config).map_err(|e| {
            format!(
                "{} failed: Could not serialize configuration: {}",
                caller, e
            )
        })?;
        let mut has_external_absolute = false;
        for field in ["jacs_data_directory", "jacs_key_directory"] {
            if let Some(dir) = config_value.get(field).and_then(|v| v.as_str()) {
                let dir_path = std::path::Path::new(dir);
                if dir_path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
                {
                    return Err(format!(
                        "{} failed: Config field '{}' contains unsafe parent-directory segment ('..'): '{}'",
                        caller, field, dir
                    )
                    .into());
                }
                if dir_path.is_absolute() {
                    let normalized_abs = Self::normalize_lexical_path(dir_path);
                    if let Ok(relative_tail) = normalized_abs.strip_prefix(&config_dir_absolute) {
                        let relative = relative_tail
                            .to_string_lossy()
                            .trim_start_matches('/')
                            .to_string();
                        if relative.is_empty() {
                            has_external_absolute = true;
                            config_value[field] =
                                json!(normalized_abs.to_string_lossy().to_string());
                        } else {
                            config_value[field] = json!(relative);
                        }
                    } else {
                        has_external_absolute = true;
                        config_value[field] = json!(normalized_abs.to_string_lossy().to_string());
                    }
                } else {
                    let normalized_rel = Self::normalize_lexical_path(dir_path);
                    config_value[field] = json!(normalized_rel.to_string_lossy().to_string());
                }
            }
        }

        let storage_root = if has_external_absolute {
            for field in ["jacs_data_directory", "jacs_key_directory"] {
                if let Some(dir) = config_value.get(field).and_then(|v| v.as_str()) {
                    let dir_path = std::path::Path::new(dir);
                    if !dir_path.is_absolute() {
                        let abs = Self::normalize_lexical_path(&config_dir_absolute.join(dir_path));
                        config_value[field] = json!(abs.to_string_lossy().to_string());
                    }
                }
            }
            std::path::PathBuf::from("/")
        } else {
            config_dir_absolute
        };

        let mut normalized_config: Config = serde_json::from_value(config_value).map_err(|e| {
            format!(
                "{} failed: Could not normalize filesystem directories in config: {}",
                caller, e
            )
        })?;
        // Preserve runtime-only provenance since serde(skip) drops it during
        // the normalization round-trip. Later consumers must not lose the fact
        // that this configuration came from authenticated on-disk bytes.
        normalized_config.set_config_dir(config.config_dir().map(std::path::PathBuf::from));
        normalized_config.set_source_path(config.source_path().map(std::path::PathBuf::from));
        normalized_config.is_signed = config.is_signed;
        normalized_config.raw_json = config.raw_json.clone();

        Ok((storage_root, normalized_config))
    }

    fn storage_uses_local_agent_filesystem(storage_type: &str) -> bool {
        matches!(storage_type, "fs" | "rusqlite" | "sqlite" | "remote")
    }

    fn local_agent_storage_type(storage_type: &str, caller: &str) -> String {
        match storage_type {
            "rusqlite" | "sqlite" => "fs".to_string(),
            "remote" => {
                warn!(
                    "{} received jacs_default_storage=remote. 'remote' is an outer provider routing label, not a native JACS storage backend; using fs for local agent material.",
                    caller
                );
                "fs".to_string()
            }
            other => other.to_string(),
        }
    }

    /// Create an ephemeral agent with in-memory keys and storage.
    /// No config file, no directories, no environment variables needed.
    ///
    /// `pq2025` is the default. Explicit `ed25519` / `ring-Ed25519` requests
    /// create genuine Ed25519 keys; unknown algorithms return a typed error.
    pub fn ephemeral(algorithm: &str) -> Result<Self, JacsError> {
        let algorithm = crate::crypt::resolve_new_agent_algorithm(algorithm)?;
        Self::ephemeral_unresolved(&algorithm, false)
    }

    /// TEST-ONLY: build a pre-compat-key Ed25519 fixture. Public ephemeral
    /// creation supports Ed25519; this helper preserves historical fixture
    /// construction semantics and is not exposed through bindings/CLI/MCP.
    #[doc(hidden)]
    pub fn ephemeral_legacy_ed25519_for_fixtures() -> Result<Self, JacsError> {
        Self::ephemeral_unresolved("ring-Ed25519", true)
    }

    fn ephemeral_unresolved(
        algorithm: &str,
        legacy_ed25519_keygen_for_fixtures: bool,
    ) -> Result<Self, JacsError> {
        let config = Config::builder()
            .key_algorithm(algorithm)
            .default_storage("memory")
            .build();
        let storage = MultiStorage::new("memory".to_string())?;
        let schema = Schema::new("v1", "v1", "v1")?;
        let key_store = crate::keystore::InMemoryKeyStore::new(algorithm);
        Ok(Self {
            schema,
            value: None,
            config: Some(config),
            storage,
            document_schemas: Arc::new(Mutex::new(HashMap::new())),
            id: None,
            version: None,
            public_key: None,
            private_key: None,
            key_algorithm: None,
            key_store: Some(Box::new(key_store)),
            ephemeral: true,
            dns_strict: false,
            dns_validate_enabled: None,
            dns_required: None,
            key_paths: None,
            password: None,
            legacy_ed25519_keygen_for_fixtures,
            #[cfg(feature = "attestation")]
            adapters: crate::attestation::adapters::default_adapters(),
        })
    }

    /// TEST-ONLY: mark an agent as a pre-compat-key Ed25519 fixture (mirrors
    /// `SimpleAgent::create_legacy_ed25519_agent_for_fixtures`). Not part of
    /// the supported API and never exposed through bindings/CLI/MCP.
    #[doc(hidden)]
    pub fn allow_legacy_ed25519_keygen_for_fixtures(&mut self) {
        self.legacy_ed25519_keygen_for_fixtures = true;
    }

    /// True when the fixture-only Ed25519 key-generation hatch is enabled.
    pub(crate) fn legacy_ed25519_keygen_allowed(&self) -> bool {
        self.legacy_ed25519_keygen_for_fixtures
    }

    /// Returns true if this is an ephemeral (in-memory) agent.
    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral
    }

    /// Get a reference to the agent's key store, if any.
    pub fn get_key_store(&self) -> Option<&dyn KeyStore> {
        self.key_store.as_deref()
    }

    /// Get the agent's resolved key paths, if any.
    pub fn key_paths(&self) -> Option<&KeyPaths> {
        self.key_paths.as_ref()
    }

    /// Set the agent's key paths explicitly.
    pub fn set_key_paths(&mut self, paths: KeyPaths) {
        self.key_paths = Some(paths);
    }

    /// Build `KeyPaths` from a `Config`.
    ///
    /// Used both at construction time (before `self` exists) and after config
    /// updates.  Centralises the default-value logic so every call site stays
    /// in sync.
    fn key_paths_from_config(c: &Config) -> Result<KeyPaths, JacsError> {
        let configured_directory = c.jacs_key_directory().as_deref().unwrap_or("./jacs_keys");
        let resolved_directory = c.resolve_config_relative_path(configured_directory)?;
        let key_directory = resolved_directory.to_str().ok_or_else(|| {
            JacsError::ConfigError(format!(
                "Resolved key directory is not valid UTF-8: '{}'",
                resolved_directory.display()
            ))
        })?;
        Ok(KeyPaths {
            key_directory: key_directory.to_string(),
            private_key_filename: c
                .jacs_agent_private_key_filename()
                .clone()
                .unwrap_or_else(|| crate::simple::core::DEFAULT_PRIVATE_KEY_FILENAME.to_string()),
            public_key_filename: c
                .jacs_agent_public_key_filename()
                .clone()
                .unwrap_or_else(|| crate::simple::core::DEFAULT_PUBLIC_KEY_FILENAME.to_string()),
        })
    }

    /// Rebuild `self.key_paths` from `self.config`.
    ///
    /// Must be called after every `self.config = Some(...)` assignment so that
    /// `build_fs_store()` picks up the new key directory (Issue 012).
    fn refresh_key_paths_from_config(&mut self) -> Result<(), JacsError> {
        if let Some(ref c) = self.config {
            self.key_paths = Some(Self::key_paths_from_config(c)?);
        }
        Ok(())
    }

    /// Get the agent-scoped password, if set.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Set the agent-scoped password.
    pub fn set_password(&mut self, password: Option<String>) {
        self.password = password;
    }

    /// Resolve the private key password using the agent-scoped password if available,
    /// falling back to env/jenv/keychain.
    pub fn resolve_password(&self) -> Result<String, JacsError> {
        crate::crypt::aes_encrypt::resolve_private_key_password(
            self.password.as_deref(),
            self.id.as_deref(),
        )
    }

    /// Build an `FsEncryptedStore` from the agent's `key_paths` and `password`.
    pub fn build_fs_store(&self) -> Result<FsEncryptedStore, JacsError> {
        match self.key_paths.as_ref() {
            Some(paths) => Ok(FsEncryptedStore::with_password(
                paths.clone(),
                self.password.clone(),
            )),
            None => Err(JacsError::ConfigError(
                "Agent has no key_paths set. Ensure the agent was created with a config \
                that includes jacs_key_directory, or call set_key_paths() before key operations."
                    .to_string(),
            )),
        }
    }

    pub fn set_dns_strict(&mut self, strict: bool) {
        self.dns_strict = strict;
    }

    pub fn set_dns_validate(&mut self, enabled: bool) {
        self.dns_validate_enabled = Some(enabled);
        if !enabled {
            self.dns_strict = false;
        }
    }
    pub fn set_dns_required(&mut self, required: bool) {
        self.dns_required = Some(required);
    }

    /// Register a custom evidence adapter with this agent.
    /// The adapter will be consulted during full attestation verification
    /// when evidence of a matching kind is encountered.
    #[cfg(feature = "attestation")]
    pub fn register_adapter(
        &mut self,
        adapter: Box<dyn crate::attestation::adapters::EvidenceAdapter>,
    ) {
        self.adapters.push(adapter);
    }

    #[must_use = "agent loading result must be checked for errors"]
    pub fn load_by_id(&mut self, lookup_id: String) -> Result<(), JacsError> {
        let start_time = std::time::Instant::now();
        let default_config_path = crate::paths::default_config_path();
        let default_config_path = default_config_path.to_string_lossy().to_string();
        let result = (|| -> Result<(), JacsError> {
            if std::path::Path::new(&default_config_path).exists() {
                let mut config = Config::from_file(&default_config_path).map_err(|e| {
                    JacsError::ConfigError(format!(
                        "load_by_id failed for agent '{}': Could not load configuration '{}': {}",
                        lookup_id, default_config_path, e
                    ))
                })?;
                config.apply_env_overrides();
                let configured_lookup = config.jacs_agent_id_and_version().as_deref().unwrap_or("");
                if configured_lookup != lookup_id {
                    return Err(JacsError::ConfigError(format!(
                        "load_by_id requested '{}' but signed config '{}' selects '{}'.",
                        lookup_id, default_config_path, configured_lookup
                    )));
                }
                return self.apply_config_and_load(config, "load_by_id", &default_config_path);
            }

            // No persisted config: environment/programmatic values are the
            // explicit trust source. Still stage the load so failure cannot
            // partially replace this Agent.
            let config = load_config_12factor_optional(None).map_err(|e| {
                JacsError::ConfigError(format!(
                    "load_by_id failed for agent '{}': Could not build environment configuration: {}",
                    lookup_id, e
                ))
            })?;
            let (storage_root, config) =
                Self::calculate_storage_root_and_normalize(config, "load_by_id")?;
            let storage_type = config
                .jacs_default_storage()
                .as_deref()
                .unwrap_or("fs")
                .to_string();
            let mut staged = Self::new(
                crate::config::constants::JACS_AGENT_SCHEMA_VERSION,
                crate::config::constants::JACS_HEADER_SCHEMA_VERSION,
                crate::config::constants::JACS_SIGNATURE_SCHEMA_VERSION,
            )?;
            staged.dns_strict = self.dns_strict;
            staged.dns_validate_enabled = self.dns_validate_enabled;
            staged.dns_required = self.dns_required;
            staged.password = self.password.clone();
            staged.config = Some(config);
            staged.refresh_key_paths_from_config()?;
            staged.storage = MultiStorage::_new(
                Self::local_agent_storage_type(&storage_type, "load_by_id"),
                storage_root,
            )?;
            let agent_string = staged.fs_agent_load(&lookup_id).map_err(|e| {
                JacsError::ConfigError(format!(
                    "load_by_id failed for agent '{}': Could not load agent file: {}",
                    lookup_id, e
                ))
            })?;
            staged.load(&agent_string).map_err(|e| {
                JacsError::ConfigError(format!(
                    "load_by_id failed for agent '{}': Agent validation or key loading failed: {}",
                    lookup_id, e
                ))
            })?;
            self.commit_loaded_state(staged);
            Ok(())
        })();

        let duration_ms = start_time.elapsed().as_millis() as u64;
        let success = result.is_ok();

        record_agent_operation("load_by_id", &lookup_id, success, duration_ms);

        if success {
            info!("Successfully loaded agent by ID: {}", lookup_id);
        } else {
            error!("Failed to load agent by ID: {}", lookup_id);
        }

        result
    }

    #[must_use = "agent loading result must be checked for errors"]
    pub fn load_by_config(&mut self, path: String) -> Result<(), JacsError> {
        // load config string
        let mut config = load_config_12factor(Some(&path)).map_err(|e| {
            format!(
                "load_by_config failed: Could not load configuration from '{}': {}",
                path, e
            )
        })?;

        // Ensure config_dir is set (fallback to path's parent if Config::from_file
        // did not set it, e.g. when loaded via load_config_12factor).
        if config.config_dir().is_none() {
            let fallback_dir = std::path::Path::new(&path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            config.set_config_dir(Some(fallback_dir.to_path_buf()));
        }

        self.apply_config_and_load(config, "load_by_config", &path)
    }

    /// Load agent configuration from a file **without** applying env/jenv overrides.
    ///
    /// This is the isolation-safe counterpart of `load_by_config`. It reads
    /// configuration exclusively from the specified file, ignoring any ambient
    /// `JACS_*` environment variables or jenv overrides. This eliminates the need
    /// for save/clear/restore guard patterns around the load call (Issue 008).
    #[must_use = "agent loading result must be checked for errors"]
    pub fn load_by_config_file_only(&mut self, path: String) -> Result<(), JacsError> {
        let mut config = crate::config::load_config_file_only(&path).map_err(|e| {
            format!(
                "load_by_config_file_only failed: Could not load configuration from '{}': {}",
                path, e
            )
        })?;

        // Ensure config_dir is set (fallback to path's parent if Config::from_file
        // did not set it, e.g. when loaded via load_config_file_only).
        if config.config_dir().is_none() {
            let fallback_dir = std::path::Path::new(&path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            config.set_config_dir(Some(fallback_dir.to_path_buf()));
        }

        self.apply_config_and_load(config, "load_by_config_file_only", &path)
    }

    /// Shared helper for `load_by_config` and `load_by_config_file_only`.
    ///
    /// Takes a pre-loaded `Config` (with `config_dir` already set), calculates the
    /// storage root via [`calculate_storage_root_and_normalize`], initializes storage,
    /// and loads the agent identity if configured.
    fn apply_config_and_load(
        &mut self,
        config: Config,
        caller: &str,
        path: &str,
    ) -> Result<(), JacsError> {
        // Authenticate the persisted bytes before using any config-controlled
        // storage, key, database, or network setting.
        let config_preflight = Self::verify_config_before_use(
            &self.schema,
            &config,
            Some(path),
            ConfigUse::ExistingAgent,
        )?;
        let config_raw_json = config.raw_json.clone();

        // Build into a disposable Agent and commit only after every signature,
        // identity, key, storage, and rotation check succeeds. A failed load
        // therefore cannot leave an existing Agent half-reconfigured.
        let mut staged = Self::new(
            crate::config::constants::JACS_AGENT_SCHEMA_VERSION,
            crate::config::constants::JACS_HEADER_SCHEMA_VERSION,
            crate::config::constants::JACS_SIGNATURE_SCHEMA_VERSION,
        )?;
        staged.dns_strict = self.dns_strict;
        staged.dns_validate_enabled = self.dns_validate_enabled;
        staged.dns_required = self.dns_required;
        staged.password = self.password.clone();
        staged.legacy_ed25519_keygen_for_fixtures = self.legacy_ed25519_keygen_for_fixtures;
        staged.apply_preflighted_config_and_load(
            config,
            caller,
            path,
            config_preflight,
            config_raw_json,
        )?;
        self.commit_loaded_state(staged);
        Ok(())
    }

    fn apply_preflighted_config_and_load(
        &mut self,
        config: Config,
        caller: &str,
        path: &str,
        config_preflight: ConfigPreflight,
        config_raw_json: Option<Value>,
    ) -> Result<(), JacsError> {
        let lookup_id: String = config
            .jacs_agent_id_and_version()
            .as_deref()
            .unwrap_or("")
            .to_string();
        if lookup_id.trim().is_empty() {
            return Err(JacsError::ConfigError(
                "Existing-agent load requires a non-empty jacs_agent_id_and_version; refusing to return an unloaded agent."
                    .to_string(),
            ));
        }
        let storage_type: String = config
            .jacs_default_storage()
            .as_deref()
            .unwrap_or("")
            .to_string();

        let (storage_root, config) = Self::calculate_storage_root_and_normalize(config, caller)?;

        self.config = Some(config);
        // Refresh key_paths from the new config so build_fs_store() uses the
        // correct key directory, not stale paths from construction time (Issue 012).
        self.refresh_key_paths_from_config()?;
        let file_storage_type = Self::local_agent_storage_type(&storage_type, caller);
        self.storage = MultiStorage::_new(file_storage_type, storage_root).map_err(|e| {
            format!(
                "{} failed: Could not initialize storage type '{}' (from config '{}'): {}",
                caller, storage_type, path, e
            )
        })?;

        // Only an authenticated historical config plus its bound journal may
        // select crash-recovery behavior. An arbitrary journal beside a current
        // config is ignored.
        let mut effective_lookup_id = lookup_id.clone();
        if let ConfigPreflight::SignedHistorical(journal) = &config_preflight {
            info!(
                event = "signed_config_rotation_recovery_started",
                stage = %journal.stage,
                agent_id = %journal.agent_id,
                "Authenticated stale config and rotation journal found; checking for the next agent version"
            );
            if let Some(newer_id) = self.find_latest_agent_version_on_disk(&lookup_id) {
                info!(
                    "Found newer agent version on disk: {} (config had: {})",
                    newer_id, lookup_id
                );
                effective_lookup_id = newer_id;
            }
        }

        if !effective_lookup_id.is_empty() {
            let agent_string = self.fs_agent_load(&effective_lookup_id).map_err(|e| {
                format!(
                    "{} failed: Could not load agent '{}' (specified in config '{}'): {}",
                    caller, effective_lookup_id, path, e
                )
            })?;
            self.load(&agent_string).map_err(|e| {
                let err_msg = format!(
                    "{} failed: Agent '{}' validation or key loading failed (config '{}'): {}",
                    caller, effective_lookup_id, path, e
                );
                JacsError::Internal { message: err_msg }
            })?;
        }

        self.finish_config_verification(config_preflight, &config_raw_json, Some(path))?;

        Ok(())
    }

    fn commit_loaded_state(&mut self, mut staged: Self) {
        self.value = staged.value.take();
        self.config = staged.config.take();
        self.storage = staged.storage;
        self.id = staged.id.take();
        self.version = staged.version.take();
        self.key_algorithm = staged.key_algorithm.take();
        self.public_key = staged.public_key.take();
        self.private_key = staged.private_key.take();
        self.key_store = staged.key_store.take();
        self.ephemeral = staged.ephemeral;
        self.key_paths = staged.key_paths.take();
    }

    /// Replace the internal storage with a pre-configured [`MultiStorage`].
    ///
    /// This allows callers to inject a custom storage backend (e.g., in-memory
    /// for testing, or a pre-configured filesystem backend with a specific root).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// Scan the agent data directory for the direct child of an agent version.
    ///
    /// Given a lookup_id like `{agent_id}:{version}`, extracts the agent_id
    /// and searches for files whose authenticated rotation chain names the
    /// supplied version as `jacsPreviousVersion`. It never falls forward to an
    /// unrelated newer version.
    ///
    /// Used during crash recovery to find the newer agent version that was
    /// saved to disk before the process crashed.
    fn find_latest_agent_version_on_disk(&self, current_lookup_id: &str) -> Option<String> {
        let parts: Vec<&str> = current_lookup_id.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }
        let agent_id = parts[0];
        let current_version = parts[1];

        // Build the agent directory path from config
        let data_dir = self
            .config
            .as_ref()?
            .jacs_data_directory()
            .as_deref()
            .unwrap_or("jacs_data")
            .to_string();

        // The agent files are stored under {storage_root}/{data_dir}/agent/.
        // Resolve through the already-authenticated staged storage root rather
        // than assuming the process CWD equals the config directory.
        let data_path = std::path::Path::new(&data_dir);
        let agent_dir = if data_path.is_absolute() {
            data_path.join("agent")
        } else if let Some(root) = self.storage.root() {
            root.join(data_path).join("agent")
        } else {
            data_path.join("agent")
        };
        if !agent_dir.exists() {
            return None;
        }

        let prefix = format!("{}:", agent_id);
        let mut direct_child: Option<(String, Option<String>, Option<std::time::SystemTime>)> =
            None;

        fn candidate_is_newer(
            candidate: &(String, Option<String>, Option<std::time::SystemTime>),
            current: Option<&(String, Option<String>, Option<std::time::SystemTime>)>,
        ) -> bool {
            let Some(current) = current else {
                return true;
            };

            match (candidate.1.as_deref(), current.1.as_deref()) {
                (Some(candidate_date), Some(current_date)) if candidate_date != current_date => {
                    candidate_date > current_date
                }
                (Some(_), None) => true,
                (None, Some(_)) => false,
                _ => match (candidate.2, current.2) {
                    (Some(candidate_mtime), Some(current_mtime)) => candidate_mtime > current_mtime,
                    (Some(_), None) => true,
                    _ => false,
                },
            }
        }

        if let Ok(entries) = std::fs::read_dir(&agent_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && name.starts_with(&prefix)
                    && name.ends_with(".json")
                {
                    // Extract lookup_id from filename (strip .json)
                    let lookup = name.trim_end_matches(".json");
                    if lookup == current_lookup_id {
                        continue;
                    }

                    let modified = entry.metadata().and_then(|m| m.modified()).ok();
                    let mut version_date: Option<String> = None;
                    let mut previous_version: Option<String> = None;

                    if let Ok(content) = crate::secure_io::read_to_string_no_follow(entry.path())
                        && let Ok(doc) = serde_json::from_str::<Value>(&content)
                    {
                        if let Some(date_str) = doc["jacsVersionDate"].as_str() {
                            version_date = Some(date_str.to_string());
                        }
                        if let Some(previous) = doc[JACS_PREVIOUS_VERSION_FIELDNAME].as_str() {
                            previous_version = Some(previous.to_string());
                        }
                    }

                    let candidate = (lookup.to_string(), version_date, modified);
                    if previous_version.as_deref() == Some(current_version)
                        && candidate_is_newer(&candidate, direct_child.as_ref())
                    {
                        direct_child = Some(candidate.clone());
                    }
                }
            }
        }

        // Only the direct child is eligible. The loaded child and transition
        // proof are cryptographically checked before any config is repaired.
        direct_child
            .map(|(lookup, _, _)| lookup)
            .filter(|id| id != current_lookup_id)
    }

    fn normalize_lexical_path(path: &std::path::Path) -> std::path::PathBuf {
        let mut normalized = std::path::PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                other => normalized.push(other.as_os_str()),
            }
        }
        normalized
    }

    fn absolute_lexical_path(path: &std::path::Path) -> Result<std::path::PathBuf, JacsError> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        Ok(Self::normalize_lexical_path(&absolute))
    }

    fn resolve_config_directory(
        config: &Config,
        configured: Option<&str>,
        default: &str,
        field: &str,
    ) -> Result<std::path::PathBuf, JacsError> {
        let directory = configured.unwrap_or(default).trim();
        if directory.is_empty() {
            return Err(JacsError::ConfigError(format!(
                "Config field '{}' must not be empty.",
                field
            )));
        }
        let directory_path = std::path::Path::new(directory);
        if directory_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(JacsError::ConfigError(format!(
                "Config field '{}' contains an unsafe parent-directory segment: '{}'.",
                field, directory
            )));
        }

        if directory_path.is_absolute() {
            return Ok(Self::normalize_lexical_path(directory_path));
        }
        let base = config
            .config_dir()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        Ok(Self::absolute_lexical_path(&base)?.join(Self::normalize_lexical_path(directory_path)))
    }

    fn read_config_public_key(config: &Config) -> Result<Vec<u8>, JacsError> {
        let key_directory = Self::resolve_config_directory(
            config,
            config.jacs_key_directory().as_deref(),
            "./jacs_keys",
            "jacs_key_directory",
        )?;
        let filename = config
            .jacs_agent_public_key_filename()
            .as_deref()
            .unwrap_or(crate::simple::core::DEFAULT_PUBLIC_KEY_FILENAME);
        require_relative_path_safe(filename).map_err(|e| {
            JacsError::ConfigError(format!(
                "Config public-key filename '{}' is unsafe: {}",
                filename, e
            ))
        })?;
        let path = key_directory.join(filename);
        crate::secure_io::read_no_follow_bounded(&path, MAX_LOCAL_PUBLIC_KEY_BYTES).map_err(|e| {
            JacsError::ConfigError(format!(
                "Could not securely read the configured public key '{}': {}",
                path.display(),
                e
            ))
        })
    }

    fn read_archived_config_public_key(
        config: &Config,
        public_key_hash: &str,
    ) -> Result<Vec<u8>, JacsError> {
        if public_key_hash.len() != 64
            || !public_key_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(JacsError::ConfigError(
                "Config signature publicKeyHash must be a 64-character hexadecimal SHA-256 digest."
                    .to_string(),
            ));
        }
        let data_directory = Self::resolve_config_directory(
            config,
            config.jacs_data_directory().as_deref(),
            "./jacs_data",
            "jacs_data_directory",
        )?;
        let relative = format!("public_keys/{}.pem", public_key_hash);
        require_relative_path_safe(&relative)?;
        let path = data_directory.join(relative);
        let public_key =
            crate::secure_io::read_no_follow_bounded(&path, MAX_LOCAL_PUBLIC_KEY_BYTES).map_err(
                |e| {
                    JacsError::ConfigError(format!(
                        "Could not securely read the content-addressed config key '{}': {}",
                        path.display(),
                        e
                    ))
                },
            )?;
        let actual_hash = hash_public_key(&public_key);
        if actual_hash != public_key_hash {
            return Err(JacsError::ConfigError(format!(
                "Content-addressed config key hash mismatch: expected '{}', found '{}'.",
                public_key_hash, actual_hash
            )));
        }
        Ok(public_key)
    }

    fn load_rotation_journal_for_config(
        config: &Config,
    ) -> Result<Option<crate::keystore::RotationJournal>, JacsError> {
        let key_directory = Self::resolve_config_directory(
            config,
            config.jacs_key_directory().as_deref(),
            "./jacs_keys",
            "jacs_key_directory",
        )?;
        let journal_path =
            crate::keystore::RotationJournal::journal_path(&key_directory.to_string_lossy());
        crate::keystore::RotationJournal::load_strict(&journal_path)
    }

    fn validate_rotation_journal_preflight(
        config_json: &Value,
        config_path: &str,
        journal: &crate::keystore::RotationJournal,
    ) -> Result<(), JacsError> {
        let expected_path = Self::absolute_lexical_path(std::path::Path::new(config_path))?;
        let journal_path = Self::absolute_lexical_path(std::path::Path::new(&journal.config_path))?;
        if expected_path != journal_path {
            return Err(JacsError::ConfigError(format!(
                "Rotation journal config path '{}' does not match the loaded config '{}'.",
                journal_path.display(),
                expected_path.display()
            )));
        }

        let expected_lookup = format!("{}:{}", journal.agent_id, journal.old_version);
        let actual_lookup = config_json
            .get("jacs_agent_id_and_version")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError(
                    "Signed config is missing jacs_agent_id_and_version.".to_string(),
                )
            })?;
        if actual_lookup != expected_lookup && journal.stage != "config_signed" {
            return Err(JacsError::ConfigError(format!(
                "Config lookup '{}' does not match the journal's pre-rotation identity '{}'.",
                actual_lookup, expected_lookup
            )));
        }

        let signature_key_hash = config_json
            .get(AGENT_SIGNATURE_FIELDNAME)
            .and_then(|signature| signature.get("publicKeyHash"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError("Config signature is missing publicKeyHash".to_string())
            })?;
        if journal.stage != "config_signed" && signature_key_hash != journal.old_key_hash {
            return Err(JacsError::ConfigError(format!(
                "Config signature key hash '{}' does not match rotation journal old key hash '{}'.",
                signature_key_hash, journal.old_key_hash
            )));
        }
        if journal.algorithm.trim().is_empty() {
            return Err(JacsError::ConfigError(
                "Rotation journal algorithm must not be empty.".to_string(),
            ));
        }
        Ok(())
    }

    fn record_config_security_outcome(
        config: &Config,
        outcome: SecurityOutcome,
        policy: SecurityPolicy,
    ) {
        record_security_outcome(
            SecuritySource::Config,
            outcome,
            policy,
            config.jacs_agent_id_and_version().as_deref(),
            None,
        );
    }

    fn verify_config_before_use(
        schema: &Schema,
        config: &Config,
        config_path: Option<&str>,
        config_use: ConfigUse,
    ) -> Result<ConfigPreflight, JacsError> {
        // Programmatic/env-only config has no persisted bytes to authenticate;
        // the caller or process environment is the trust source.
        let Some(raw_json) = config.raw_json.as_ref() else {
            return Ok(ConfigPreflight::Unsigned);
        };

        if !config.is_signed {
            let persisted_identity = raw_json
                .get("jacs_agent_id_and_version")
                .and_then(Value::as_str)
                .is_some_and(|lookup| !lookup.trim().is_empty());
            if config_use == ConfigUse::NewAgent && persisted_identity {
                if env_truthy(ALLOW_UNSIGNED_AGENT_CONFIG_ENV) {
                    Self::record_config_security_outcome(
                        config,
                        SecurityOutcome::Unverified,
                        SecurityPolicy::Permissive,
                    );
                    warn!(
                        event = "unsigned_agent_config_allowed",
                        config_path = config_path.unwrap_or("<pre-built>"),
                        "SECURITY: reusing an unsigned config that selected an identity was explicitly enabled for migration"
                    );
                    return Ok(ConfigPreflight::Unsigned);
                }
                warn!(
                    event = "unsigned_agent_config_refused",
                    config_path = config_path.unwrap_or("<pre-built>"),
                    "Refusing unsigned persisted config that already selects an identity"
                );
                Self::record_config_security_outcome(
                    config,
                    SecurityOutcome::PolicyRejected,
                    SecurityPolicy::Strict,
                );
                return Err(JacsError::ConfigError(format!(
                    "Refusing unsigned agent config that already selects an identity. Re-sign or migrate it; for an explicitly audited one-time migration only, set {}=true.",
                    ALLOW_UNSIGNED_AGENT_CONFIG_ENV
                )));
            }
            if config_use == ConfigUse::ExistingAgent {
                if env_truthy(ALLOW_UNSIGNED_AGENT_CONFIG_ENV) {
                    Self::record_config_security_outcome(
                        config,
                        SecurityOutcome::Unverified,
                        SecurityPolicy::Permissive,
                    );
                    warn!(
                        event = "unsigned_agent_config_allowed",
                        config_path = config_path.unwrap_or("<pre-built>"),
                        "SECURITY: loading an existing identity from an unsigned config was explicitly enabled; migrate and re-sign it immediately"
                    );
                    return Ok(ConfigPreflight::Unsigned);
                }
                warn!(
                    event = "unsigned_agent_config_refused",
                    config_path = config_path.unwrap_or("<pre-built>"),
                    "Refusing unsigned persisted agent config"
                );
                Self::record_config_security_outcome(
                    config,
                    SecurityOutcome::PolicyRejected,
                    SecurityPolicy::Strict,
                );
                return Err(JacsError::ConfigError(format!(
                    "Refusing unsigned agent config for an existing-agent load. Re-sign or migrate the config; for an explicitly audited one-time migration only, set {}=true.",
                    ALLOW_UNSIGNED_AGENT_CONFIG_ENV
                )));
            }
            return Ok(ConfigPreflight::Unsigned);
        }

        let verification = (|| {
            let declared_key_hash = raw_json
                .get(AGENT_SIGNATURE_FIELDNAME)
                .and_then(|signature| signature.get("publicKeyHash"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JacsError::ConfigError("Config signature is missing publicKeyHash".to_string())
                })?;
            let current_key = Self::read_config_public_key(config)?;
            let current_key_hash = hash_public_key(&current_key);
            let signed_key = if current_key_hash == declared_key_hash {
                current_key.clone()
            } else {
                Self::read_archived_config_public_key(config, declared_key_hash)?
            };
            Self::verify_config_signature_with_schema_and_public_key(
                schema,
                raw_json,
                &signed_key,
            )?;
            let signed_algorithm = raw_json
                .get(AGENT_SIGNATURE_FIELDNAME)
                .and_then(|signature| signature.get("signingAlgorithm"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JacsError::ConfigError(
                        "Config signature is missing signingAlgorithm".to_string(),
                    )
                })?;
            let configured_algorithm = config.get_key_algorithm()?;
            if signed_algorithm != configured_algorithm {
                return Err(JacsError::ConfigError(format!(
                    "Config signing algorithm '{}' does not match configured agent algorithm '{}'.",
                    signed_algorithm, configured_algorithm
                )));
            }

            if current_key_hash == declared_key_hash {
                let completion_journal = if let (Some(path), Some(journal)) =
                    (config_path, Self::load_rotation_journal_for_config(config)?)
                {
                    Self::validate_rotation_journal_preflight(raw_json, path, &journal)?;
                    if journal.stage != "config_signed" {
                        return Err(JacsError::ConfigError(format!(
                            "Rotation journal stage '{}' cannot accompany a config signed by the current key; manual recovery is required.",
                            journal.stage
                        )));
                    }
                    Some(journal)
                } else {
                    None
                };
                return Ok(ConfigPreflight::SignedCurrent(completion_journal));
            }

            if config_use != ConfigUse::ExistingAgent {
                return Err(JacsError::ConfigError(format!(
                    "Config is signed by historical key '{}' but the current configured key is '{}'.",
                    declared_key_hash, current_key_hash
                )));
            }
            let path = config_path.ok_or_else(|| {
                JacsError::ConfigError(
                    "A historical signed config requires its original path for bounded rotation recovery."
                        .to_string(),
                )
            })?;
            let journal = Self::load_rotation_journal_for_config(config)?.ok_or_else(|| {
                JacsError::ConfigError(format!(
                    "Config is signed by historical key '{}' but no rotation journal is present.",
                    declared_key_hash
                ))
            })?;
            Self::validate_rotation_journal_preflight(raw_json, path, &journal)?;
            if journal.stage != "agent_saved" {
                return Err(JacsError::ConfigError(format!(
                    "Rotation journal stage '{}' is not safe for forward recovery; expected 'agent_saved'.",
                    journal.stage
                )));
            }
            Ok(ConfigPreflight::SignedHistorical(journal))
        })();

        match verification {
            Ok(preflight) => {
                Self::record_config_security_outcome(
                    config,
                    SecurityOutcome::Valid,
                    SecurityPolicy::Strict,
                );
                Ok(preflight)
            }
            Err(error) => {
                Self::record_config_security_outcome(
                    config,
                    security_outcome_for_error(&error),
                    SecurityPolicy::Strict,
                );
                warn!(
                    event = "signed_config_verification_failed",
                    config_path = config_path.unwrap_or("<pre-built>"),
                    reason = %error,
                    "Signed config failed verification before applying configuration"
                );
                Err(JacsError::ConfigError(format!(
                    "Signed config failed verification before applying configuration: {}",
                    error
                )))
            }
        }
    }

    /// Verify a signed config with an explicit key without constructing or
    /// mutating an Agent. This is shared by normal preflight and historical
    /// rotation recovery so neither path has weaker field-coverage rules.
    fn verify_config_signature_with_schema_and_public_key(
        schema: &Schema,
        config_json: &Value,
        public_key: &[u8],
    ) -> Result<(), JacsError> {
        let json_str = serde_json::to_string(config_json).map_err(|e| {
            JacsError::ConfigError(format!(
                "serialize config for explicit-key verification: {e}"
            ))
        })?;
        let validated = schema.validate_header(&json_str)?;
        let original_hash = validated
            .get(SHA256_FIELDNAME)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError("Signed config is missing jacsSha256".to_string())
            })?;
        let mut hash_input = validated.clone();
        hash_input
            .as_object_mut()
            .ok_or_else(|| JacsError::ConfigError("Config must be a JSON object".to_string()))?
            .remove(SHA256_FIELDNAME);
        let actual_hash = hash_string(&canonicalize_json(&hash_input)?);
        if original_hash != actual_hash {
            return Err(JacsError::ConfigError(format!(
                "Config hash mismatch: declared '{}', computed '{}'.",
                original_hash, actual_hash
            )));
        }
        validate_signature_temporal_claims(&validated, AGENT_SIGNATURE_FIELDNAME)?;

        let signature_metadata = validated.get(AGENT_SIGNATURE_FIELDNAME).ok_or_else(|| {
            JacsError::ConfigError("Config signature is missing jacsSignature metadata".to_string())
        })?;
        let signer_id = signature_metadata
            .get("agentID")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError("Config signature is missing agentID".to_string())
            })?;
        let signer_version = signature_metadata
            .get("agentVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError("Config signature is missing agentVersion".to_string())
            })?;
        let selected_identity = validated
            .get("jacs_agent_id_and_version")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError(
                    "Signed config is missing jacs_agent_id_and_version".to_string(),
                )
            })?;
        let signer_identity = format!("{}:{}", signer_id, signer_version);
        if signer_identity != selected_identity {
            return Err(JacsError::ConfigError(format!(
                "Config signature identity '{}' does not match selected identity '{}'.",
                signer_identity, selected_identity
            )));
        }
        let declared_public_key_hash = signature_metadata
            .get("publicKeyHash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError("Config signature is missing publicKeyHash".to_string())
            })?;
        let actual_public_key_hash = hash_public_key(public_key);
        if declared_public_key_hash != actual_public_key_hash {
            return Err(JacsError::ConfigError(format!(
                "Config signature publicKeyHash '{}' does not match the explicit key '{}'.",
                declared_public_key_hash, actual_public_key_hash
            )));
        }

        let algorithm = signature_metadata
            .get("signingAlgorithm")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError("Config signature is missing signingAlgorithm".to_string())
            })?;
        match signature_metadata
            .get(SIGNATURE_CONTENT_VERSION_FIELDNAME)
            .and_then(Value::as_str)
        {
            Some(SIGNATURE_CONTENT_VERSION_V2) => {
                let core_algorithm = jacs_core::sign::SigningAlgorithm::from_wire_str(algorithm)
                    .ok_or_else(|| {
                        JacsError::ConfigError(format!(
                            "Unsupported config signing algorithm '{}'.",
                            algorithm
                        ))
                    })?;
                let outcome = jacs_core::verify::verify_document(
                    &validated,
                    public_key,
                    core_algorithm,
                    AGENT_SIGNATURE_FIELDNAME,
                )
                .map_err(|e| {
                    JacsError::ConfigError(format!("Config signature structure is invalid: {}", e))
                })?;
                if !outcome.valid {
                    return Err(JacsError::ConfigError(format!(
                        "Config cryptographic signature is invalid: {}",
                        outcome.errors.join("; ")
                    )));
                }
            }
            Some(other) => {
                return Err(JacsError::ConfigError(format!(
                    "Unsupported config signature content version '{}'.",
                    other
                )));
            }
            None => {
                if !legacy_signature_content_allowed() {
                    return Err(legacy_signature_refusal(AGENT_SIGNATURE_FIELDNAME));
                }
                let fields = extract_signature_fields(&validated, AGENT_SIGNATURE_FIELDNAME);
                let (payload, _) = build_signature_content(
                    &validated,
                    fields,
                    AGENT_SIGNATURE_FIELDNAME,
                    SignatureContentMode::CanonicalV2,
                )?;
                let signature = signature_metadata
                    .get("signature")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        JacsError::ConfigError(
                            "Config signature is missing signature bytes".to_string(),
                        )
                    })?;
                crate::crypt::verify_string_with_algorithm(
                    public_key.to_vec(),
                    &payload,
                    signature,
                    algorithm,
                )?;
            }
        }
        Ok(())
    }

    fn verify_config_signature_with_public_key(
        &self,
        config_json: &Value,
        public_key: &[u8],
    ) -> Result<(), JacsError> {
        Self::verify_config_signature_with_schema_and_public_key(
            &self.schema,
            config_json,
            public_key,
        )
    }

    fn validate_loaded_rotation_transition(
        &self,
        journal: &crate::keystore::RotationJournal,
    ) -> Result<Vec<u8>, JacsError> {
        let current_agent_id = self.id.as_deref().ok_or(JacsError::AgentNotLoaded)?;
        if current_agent_id != journal.agent_id {
            return Err(JacsError::ConfigError(format!(
                "Rotation journal agent '{}' does not match loaded agent '{}'.",
                journal.agent_id, current_agent_id
            )));
        }

        let current_value = self.value.as_ref().ok_or(JacsError::AgentNotLoaded)?;
        let previous_version = current_value
            .get(JACS_PREVIOUS_VERSION_FIELDNAME)
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JacsError::ConfigError(
                "Current agent document is missing jacsPreviousVersion required for crash recovery."
                    .to_string(),
            )
            })?;
        if previous_version != journal.old_version {
            return Err(JacsError::ConfigError(format!(
                "Rotation journal old_version '{}' does not match current agent previous version '{}'.",
                journal.old_version, previous_version
            )));
        }

        let current_algorithm = current_value
            .get(AGENT_SIGNATURE_FIELDNAME)
            .and_then(|signature| signature.get("signingAlgorithm"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError(
                    "Current agent signature is missing signingAlgorithm.".to_string(),
                )
            })?;
        if current_algorithm != journal.algorithm {
            return Err(JacsError::ConfigError(format!(
                "Rotation journal algorithm '{}' does not match the loaded agent algorithm '{}'.",
                journal.algorithm, current_algorithm
            )));
        }

        let transition_proof = current_value
            .get("jacsKeyRotationProof")
            .ok_or_else(|| JacsError::ConfigError(
                "Current agent document is missing jacsKeyRotationProof required for crash recovery."
                    .to_string(),
            ))?;
        let proof_old_hash = transition_proof
            .get("oldPublicKeyHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JacsError::ConfigError("Transition proof is missing oldPublicKeyHash".to_string())
            })?;
        if proof_old_hash != journal.old_key_hash {
            return Err(JacsError::ConfigError(format!(
                "Rotation journal old_key_hash '{}' does not match transition proof hash '{}'.",
                journal.old_key_hash, proof_old_hash
            )));
        }

        let current_public_key = self.get_public_key()?;
        let current_public_key_hash = hash_public_key(&current_public_key);
        let proof_new_hash = transition_proof
            .get("newPublicKeyHash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JacsError::ConfigError("Transition proof is missing newPublicKeyHash".to_string())
            })?;
        if proof_new_hash != current_public_key_hash {
            return Err(JacsError::ConfigError(format!(
                "Transition proof newPublicKeyHash '{}' does not match the loaded agent key '{}'.",
                proof_new_hash, current_public_key_hash
            )));
        }

        let old_public_key = self
            .fs_load_public_key(&journal.old_key_hash)
            .map_err(|e| {
                JacsError::ConfigError(format!(
                    "Failed to load historical public key '{}' needed for crash recovery: {}",
                    journal.old_key_hash, e
                ))
            })?;
        Self::verify_transition_proof(transition_proof, &old_public_key).map_err(|e| {
            JacsError::ConfigError(format!(
                "Transition proof does not validate against the historical key: {}",
                e
            ))
        })?;

        Ok(old_public_key)
    }

    fn validate_rotation_recovery_candidate(
        &self,
        config_json: &Value,
        journal: &crate::keystore::RotationJournal,
    ) -> Result<(), JacsError> {
        let old_public_key = self.validate_loaded_rotation_transition(journal)?;

        let expected_lookup = format!("{}:{}", journal.agent_id, journal.old_version);
        let actual_lookup = config_json
            .get("jacs_agent_id_and_version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JacsError::ConfigError("Config is missing jacs_agent_id_and_version".to_string())
            })?;
        if actual_lookup != expected_lookup {
            return Err(JacsError::ConfigError(format!(
                "Config lookup '{}' does not match the stale pre-rotation identity '{}'.",
                actual_lookup, expected_lookup
            )));
        }

        self.verify_config_signature_with_public_key(config_json, &old_public_key)
            .map_err(|e| {
                JacsError::ConfigError(format!(
                    "Config does not verify with the historical pre-rotation key: {}",
                    e
                ))
            })?;

        Ok(())
    }

    fn validate_completed_rotation_candidate(
        &self,
        config_json: &Value,
        journal: &crate::keystore::RotationJournal,
    ) -> Result<(), JacsError> {
        let _old_public_key = self.validate_loaded_rotation_transition(journal)?;
        let expected_lookup = format!(
            "{}:{}",
            self.id.as_deref().ok_or(JacsError::AgentNotLoaded)?,
            self.version.as_deref().ok_or(JacsError::AgentNotLoaded)?
        );
        let actual_lookup = config_json
            .get("jacs_agent_id_and_version")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                JacsError::ConfigError("Config is missing jacs_agent_id_and_version".to_string())
            })?;
        if actual_lookup != expected_lookup {
            return Err(JacsError::ConfigError(format!(
                "Completed-rotation config lookup '{}' does not match loaded identity '{}'.",
                actual_lookup, expected_lookup
            )));
        }
        Ok(())
    }

    fn attempt_rotation_recovery(
        &mut self,
        config_json: &Value,
        config_path: &str,
        journal: &crate::keystore::RotationJournal,
    ) -> Result<(), JacsError> {
        self.validate_rotation_recovery_candidate(config_json, journal)?;
        self.attempt_config_repair(config_json, config_path)
    }

    fn finish_config_verification(
        &mut self,
        preflight: ConfigPreflight,
        raw_json: &Option<Value>,
        config_path: Option<&str>,
    ) -> Result<(), JacsError> {
        let Some(json) = raw_json.as_ref() else {
            return match preflight {
                ConfigPreflight::Unsigned => Ok(()),
                _ => Err(JacsError::ConfigError(
                    "Authenticated config provenance was lost during agent loading.".to_string(),
                )),
            };
        };

        match preflight {
            ConfigPreflight::Unsigned => Ok(()),
            ConfigPreflight::SignedCurrent(completion_journal) => {
                self.verify_config(json).map_err(|error| {
                    warn!(
                        event = "signed_config_loaded_identity_mismatch",
                        reason = %error,
                        "Signed config did not verify against the loaded identity"
                    );
                    JacsError::ConfigError(format!(
                        "Signed config failed verification against the loaded identity: {}",
                        error
                    ))
                })?;
                if let Some(journal) = completion_journal {
                    self.validate_completed_rotation_candidate(json, &journal)
                        .map_err(|error| {
                            JacsError::ConfigError(format!(
                                "Completed rotation journal validation failed: {}",
                                error
                            ))
                        })?;
                    journal.complete()?;
                    info!(
                        event = "signed_config_rotation_recovery_completed",
                        stage = "config_signed",
                        agent_id = %journal.agent_id,
                        "Removed completed rotation journal after validating the new config and transition proof"
                    );
                }
                Ok(())
            }
            ConfigPreflight::SignedHistorical(journal) => {
                let path = config_path.ok_or_else(|| {
                    JacsError::ConfigError(
                        "Historical config recovery requires the original config path.".to_string(),
                    )
                })?;
                self.attempt_rotation_recovery(json, path, &journal)
                    .map_err(|error| {
                        warn!(
                            event = "signed_config_rotation_recovery_refused",
                            stage = %journal.stage,
                            agent_id = %journal.agent_id,
                            reason = %error,
                            "Refused signed-config rotation recovery"
                        );
                        JacsError::ConfigError(format!(
                            "Signed config historical recovery failed: {}",
                            error
                        ))
                    })?;
                journal.complete()?;
                info!(
                    event = "signed_config_rotation_recovery_completed",
                    stage = %journal.stage,
                    agent_id = %journal.agent_id,
                    "Config auto-repaired after authenticated incomplete rotation"
                );
                Ok(())
            }
        }
    }

    /// Attempt to repair an inconsistent config after a crash during rotation.
    ///
    /// Re-signs the config with the current key, updates `jacs_agent_id_and_version`
    /// to match the agent's current identity, and writes the repaired config to disk.
    fn attempt_config_repair(
        &mut self,
        config_json: &Value,
        config_path: &str,
    ) -> Result<(), JacsError> {
        let mut config_value = config_json.clone();

        // Update jacs_agent_id_and_version to match current agent state
        if let (Some(id), Some(ver)) = (self.id.as_ref(), self.version.as_ref())
            && let Some(obj) = config_value.as_object_mut()
        {
            obj.insert(
                "jacs_agent_id_and_version".to_string(),
                json!(format!("{}:{}", id, ver)),
            );
            if let Some(algorithm) = self.key_algorithm.as_ref() {
                obj.insert("jacs_agent_key_algorithm".to_string(), json!(algorithm));
            }
        }

        // Re-sign config
        let signed = if config_value.get("jacsSignature").is_some() {
            self.update_config(&config_value)?
        } else {
            self.sign_config(&config_value)?
        };

        // Write to disk
        let json_str = serde_json::to_string_pretty(&signed).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize repaired config: {}", e),
        })?;
        crate::secure_io::write_atomic_replace_no_symlink(
            config_path,
            json_str.as_bytes(),
            0o644,
            true,
        )
        .map_err(|e| JacsError::Internal {
            message: format!(
                "Failed to write repaired config to '{}': {}",
                config_path, e
            ),
        })?;

        let mut repaired_config: Config =
            serde_json::from_value(signed.clone()).map_err(|error| {
                JacsError::ConfigError(format!(
                    "Repaired config could not be installed in memory: {}",
                    error
                ))
            })?;
        let source_path = Self::absolute_lexical_path(std::path::Path::new(config_path))?;
        repaired_config.set_config_dir(source_path.parent().map(std::path::PathBuf::from));
        repaired_config.set_source_path(Some(source_path));
        repaired_config.is_signed = true;
        repaired_config.raw_json = Some(signed);
        let (_, repaired_config) = Self::calculate_storage_root_and_normalize(
            repaired_config,
            "rotation config recovery",
        )?;
        self.config = Some(repaired_config);
        self.refresh_key_paths_from_config()?;

        Ok(())
    }

    /// let storage = MultiStorage::new("memory".to_string())?;
    /// agent.set_storage(storage);
    /// ```
    pub fn set_storage(&mut self, storage: MultiStorage) {
        self.storage = storage;
    }

    /// Returns a reference to the agent's internal storage backend.
    ///
    /// This is primarily used by [`service_from_agent`](crate::document::service_from_agent)
    /// to reuse the correctly-rooted `MultiStorage` that `load_by_config` set up,
    /// rather than creating a new one with a potentially-relative base directory.
    pub fn storage_ref(&self) -> &MultiStorage {
        &self.storage
    }

    /// Replace the internal storage with one rooted at `root`.
    ///
    /// This is used by `verify_document_standalone` so that absolute
    /// data/key directory paths work regardless of the current working
    /// directory.  `MultiStorage::clean_path` strips leading slashes,
    /// turning absolute paths into paths relative to the FS store root.
    /// By rooting at `/` the resolved path is still correct.
    pub fn set_storage_root(&mut self, root: std::path::PathBuf) -> Result<(), JacsError> {
        let storage_type: String = self
            .config
            .as_ref()
            .and_then(|c| c.jacs_default_storage().clone())
            .unwrap_or_else(|| "fs".to_string());
        let file_storage_type = Self::local_agent_storage_type(&storage_type, "set_storage_root");
        self.storage = MultiStorage::_new(file_storage_type, root)?;
        Ok(())
    }

    /// Returns true if the agent is fully initialized and ready for signing/verification.
    ///
    /// Checks that all required state is present: ID, version, keys, config, and value.
    pub fn ready(&self) -> bool {
        self.id.is_some()
            && self.version.is_some()
            && self.public_key.is_some()
            && self.private_key.is_some()
            && self.config.is_some()
            && self.value.is_some()
    }

    /// Get the agent's JSON value
    pub fn get_value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    /// Get the verification claim from the agent's value.
    ///
    /// Returns the normalized claim as a string, or None if not set.
    /// Valid claims are: "unverified", "verified", "verified-registry".
    /// The deprecated "verified-hai.ai" is accepted but normalized to "verified-registry"
    /// with a deprecation warning. It will be removed in the next major version.
    fn get_verification_claim(&self) -> Option<String> {
        let raw = self
            .value
            .as_ref()?
            .get("jacsVerificationClaim")?
            .as_str()?;
        Some(normalize_verification_claim(raw).to_string())
    }

    /// Get the agent's key algorithm
    pub fn get_key_algorithm(&self) -> Option<&String> {
        self.key_algorithm.as_ref()
    }

    pub fn set_keys(
        &mut self,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        key_algorithm: &str,
    ) -> Result<(), JacsError> {
        let resolved_pw = crate::crypt::aes_encrypt::resolve_private_key_password(
            self.password.as_deref(),
            self.id.as_deref(),
        )?;
        let private_key_encrypted = crate::crypt::aes_encrypt::encrypt_private_key_with_password(
            &private_key,
            &resolved_pw,
        )?;
        // Box the Vec<u8> before creating SecretBox
        self.private_key = Some(SecretBox::new(Box::new(private_key_encrypted)));
        self.public_key = Some(public_key);
        self.key_algorithm = Some(key_algorithm.to_string());
        Ok(())
    }

    /// Store keys without AES encryption. For ephemeral agents only.
    /// The raw private key bytes are wrapped in SecretBox directly.
    pub fn set_keys_raw(&mut self, private_key: Vec<u8>, public_key: Vec<u8>, key_algorithm: &str) {
        self.private_key = Some(SecretBox::new(Box::new(private_key)));
        self.public_key = Some(public_key);
        self.key_algorithm = Some(key_algorithm.to_string());
    }

    #[must_use = "private key must be used for signing operations"]
    pub fn get_private_key(&self) -> Result<&SecretPrivateKey, JacsError> {
        match &self.private_key {
            Some(private_key) => Ok(private_key),
            None => {
                let agent_id = self.id.as_deref().unwrap_or("<uninitialized>");
                Err(JacsError::KeyNotFound {
                    path: format!(
                        "Private key for agent '{}': Call fs_load_keys() or fs_preload_keys() first, or ensure keys are generated during agent creation.",
                        agent_id
                    ),
                })
            }
        }
    }

    #[must_use = "agent loading result must be checked for errors"]
    pub fn load(&mut self, agent_string: &str) -> Result<(), JacsError> {
        // validate schema
        // then load
        // then load keys
        // then validate signatures
        match &self.validate_agent(agent_string) {
            Ok(value) => {
                self.value = Some(value.clone());
                if let Some(ref value) = self.value {
                    self.id = value.get_str("jacsId");
                    self.version = value.get_str("jacsVersion");
                }

                // Validate that ID and Version are valid UUIDs
                if let (Some(id), Some(version)) = (&self.id, &self.version)
                    && !are_valid_uuid_parts(id, version)
                {
                    warn!("ID and Version must be UUID");
                }
            }
            Err(e) => {
                error!("Agent validation failed: {}", e);
                return Err(JacsError::AgentError(format!(
                    "Agent load failed at schema validation step: {}. \
                    Ensure the agent JSON conforms to the JACS agent schema.",
                    e
                )));
            }
        }

        let agent_id_for_errors = self.id.as_deref().unwrap_or("<unknown>").to_string();

        if self.id.is_some() {
            // check if keys are already loaded
            if self.public_key.is_none() || self.private_key.is_none() {
                if self.ephemeral {
                    // Ephemeral agents should already have keys set; skip fs
                    warn!(
                        "Ephemeral agent missing keys during load — keys should be set before load()"
                    );
                } else {
                    self.fs_load_keys().map_err(|e| {
                        format!(
                            "Agent load failed for '{}' at key loading step: {}",
                            agent_id_for_errors, e
                        )
                    })?;
                }
            } else {
                info!("Keys already loaded for agent");
            }

            self.verify_self_signature().map_err(|e| {
                format!(
                    "Agent load failed for '{}' at signature verification step: {}. \
                    The agent's signature may be invalid or the keys may not match.",
                    agent_id_for_errors, e
                )
            })?;
        }

        Ok(())
    }

    #[must_use = "signature verification result must be checked"]
    pub fn verify_self_signature(&mut self) -> Result<(), JacsError> {
        let agent_id = self.id.as_deref().unwrap_or("<unknown>");
        let public_key = self.get_public_key().map_err(|e| {
            format!(
                "verify_self_signature failed for agent '{}': Could not retrieve public key: {}",
                agent_id, e
            )
        })?;
        // validate header
        let signature_key_from = AGENT_SIGNATURE_FIELDNAME;
        match self.value.as_ref() {
            Some(embedded_value) => self.signature_verification_procedure(
                embedded_value,
                None,
                signature_key_from,
                public_key,
                None,
                None,
                None,
            ).map_err(|e| {
                format!(
                    "verify_self_signature failed for agent '{}': Signature verification failed: {}",
                    agent_id, e
                ).into()
            }),
            None => {
                let error_message = format!(
                    "verify_self_signature failed for agent '{}': Agent value is not loaded. \
                    Ensure the agent is properly initialized before verifying signature.",
                    agent_id
                );
                error!("{}", error_message);
                Err(error_message.into())
            }
        }
    }

    // fn unset_self(&mut self) {
    //     self.id = None;
    //     self.version = None;
    //     self.value = None;
    // }

    pub fn get_agent_for_doc(
        &mut self,
        document_key: String,
        signature_key_from: Option<&str>,
    ) -> Result<String, JacsError> {
        let document = self.get_document(&document_key)?;
        let document_value = document.getvalue();
        let signature_key_from_final =
            signature_key_from.unwrap_or(DOCUMENT_AGENT_SIGNATURE_FIELDNAME);
        self.get_signature_agent_id_and_version(document_value, signature_key_from_final)
    }

    fn get_signature_agent_id_and_version(
        &self,
        json_value: &Value,
        signature_key_from: &str,
    ) -> Result<String, JacsError> {
        let agentid = json_value[signature_key_from]["agentID"]
            .as_str()
            .unwrap_or("")
            .trim_matches('"');
        let agentversion = json_value[signature_key_from]["agentVersion"]
            .as_str()
            .unwrap_or("")
            .trim_matches('"');
        Ok(format!("{}:{}", agentid, agentversion))
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(
        name = "jacs.signature_verification",
        skip(self, json_value, fields, public_key, signature),
        fields(signature_key_from, public_key_enc_type)
    )]
    pub fn signature_verification_procedure(
        &self,
        json_value: &Value,
        fields: Option<&[String]>,
        signature_key_from: &str,
        public_key: Vec<u8>,
        public_key_enc_type: Option<String>,
        original_public_key_hash: Option<String>,
        signature: Option<String>,
    ) -> Result<(), JacsError> {
        let start_time = std::time::Instant::now();
        let resolved_fields = fields
            .map(|s| s.to_vec())
            .or_else(|| extract_signature_fields(json_value, signature_key_from));

        debug!(
            "signature_verification_procedure placement_key:\n{}",
            signature_key_from
        );
        validate_signature_temporal_claims(json_value, signature_key_from)?;

        // A discovered hash-addressed key is only an integrity candidate. When
        // independent enrollment exists, enforce it before any DNS/registry
        // resolution or candidate-key verification can succeed.
        if signature_key_from == DOCUMENT_AGENT_SIGNATURE_FIELDNAME && signature.is_none() {
            crate::trust::verify_document_identity_binding(json_value)?;
        }

        let public_key_hash: String = match original_public_key_hash {
            Some(orig) => orig,
            _ => json_value[signature_key_from]["publicKeyHash"]
                .as_str()
                .unwrap_or("")
                .trim_matches('"')
                .to_string(),
        };

        // An explicit resolver/key algorithm must agree with the signed claim.
        // Never silently verify using a different algorithm than the envelope.
        let claimed_algorithm = json_value[signature_key_from]["signingAlgorithm"].as_str();
        if claimed_algorithm.is_none()
            && json_value[signature_key_from][SIGNATURE_CONTENT_VERSION_FIELDNAME].as_str()
                == Some(SIGNATURE_CONTENT_VERSION_V2)
        {
            return Err(JacsError::SignatureVerificationFailed {
                reason: "Document signature v2 requires an explicit signed algorithm".to_string(),
            });
        }
        let resolved_public_key_enc_type = crate::verification::matching_algorithm(
            claimed_algorithm,
            public_key_enc_type.as_deref(),
        )?;

        // DNS policy resolution
        let maybe_domain = self
            .value
            .as_ref()
            .and_then(|v| v.get("jacsAgentDomain").and_then(|x| x.as_str()))
            .or_else(|| {
                self.config
                    .as_ref()
                    .and_then(|c| c.jacs_agent_domain().as_deref())
            });

        let maybe_agent_id = json_value
            .get(signature_key_from)
            .and_then(|sig| sig.get("agentID"))
            .and_then(|v| v.as_str());

        // Claim-based policy enforcement
        // "If you claim it, you must prove it"
        let verification_claim = self.get_verification_claim();
        let domain_present = maybe_domain.is_some();
        let (validate, strict, required) = match verification_claim.as_deref() {
            // "verified-hai.ai" kept as fallback during deprecation period (normalized above)
            Some("verified") | Some("verified-registry") | Some("verified-hai.ai") => {
                // Verified claims MUST use strict settings
                if !domain_present {
                    return Err(JacsError::VerificationClaimFailed {
                        claim: verification_claim.unwrap_or_default(),
                        reason: "Verified agents must have jacsAgentDomain set".to_string(),
                    });
                }
                // For verified claims: validate=true, strict=true, required=true
                (true, true, true)
            }
            _ => {
                // Unverified or missing claim: explicit setters win, then the
                // persisted config's DNS policy (`jacs_dns_validate` /
                // `jacs_dns_required`, e.g. stamped alongside the creation
                // domain), then the existing default (presence of domain).
                let validate = self
                    .dns_validate_enabled
                    .or_else(|| self.config.as_ref().and_then(|c| *c.jacs_dns_validate()))
                    .unwrap_or(domain_present);
                let strict = self.dns_strict;
                let required = self
                    .dns_required
                    .or_else(|| self.config.as_ref().and_then(|c| *c.jacs_dns_required()))
                    .unwrap_or(domain_present);
                (validate, strict, required)
            }
        };

        if validate && domain_present {
            if let (Some(domain), Some(agent_id_for_dns)) = (maybe_domain, maybe_agent_id) {
                // Allow embedded fallback only if not required
                let embedded = if required {
                    None
                } else {
                    Some(&public_key_hash)
                };
                if let Err(e) = verify_pubkey_via_dns_or_embedded(
                    &public_key,
                    agent_id_for_dns,
                    Some(domain),
                    embedded.map(|s| s.as_str()),
                    strict,
                ) {
                    error!("public key identity check failed: {}", e);
                    return Err(e);
                }
            } else if required {
                return Err("DNS validation failed: domain required but not configured".into());
            }
        } else {
            // DNS not validated -> rely on embedded fingerprint
            let public_key_rehash = hash_public_key(&public_key);
            if public_key_rehash != public_key_hash {
                let error_message = format!(
                    "Incorrect public key used to verify signature public_key_rehash {} public_key_hash {} ",
                    public_key_rehash, public_key_hash
                );
                error!("{}", error_message);

                let algorithm = resolved_public_key_enc_type.as_deref().unwrap_or("unknown");
                record_signature_verification("unknown_agent", false, algorithm);

                return Err(error_message.into());
            }
        }

        // Registry verification for verified-registry claims
        // This MUST succeed for agents claiming registry-verified status
        // "verified-hai.ai" kept as fallback during deprecation period (normalized above)
        #[cfg(not(target_arch = "wasm32"))]
        if matches!(
            verification_claim.as_deref(),
            Some("verified-registry") | Some("verified-hai.ai")
        ) {
            let agent_id_for_registry = maybe_agent_id.or(self.id.as_deref()).unwrap_or_default();
            let pk_hash = pubkey_digest_hex(&public_key);

            match verify_registry_registration_sync(agent_id_for_registry, &pk_hash) {
                Ok(registration) => {
                    info!(
                        "Registry verification successful for agent '{}': verified at {:?}",
                        agent_id_for_registry, registration.verified_at
                    );
                }
                Err(e) => {
                    error!(
                        "Registry verification failed for agent '{}': {}",
                        agent_id_for_registry, e
                    );
                    return Err(JacsError::VerificationClaimFailed {
                        claim: verification_claim.unwrap_or_default(),
                        reason: e.to_string(),
                    });
                }
            }
        }

        let provided_signature = signature.as_deref();
        let signature_base64 = match provided_signature {
            Some(sig) => sig.to_string(),
            _ => json_value[signature_key_from]["signature"]
                .as_str()
                .unwrap_or("")
                .trim_matches('"')
                .to_string(),
        };

        let standard_signature = json_value[signature_key_from]["signature"]
            .as_str()
            .unwrap_or("")
            .trim_matches('"');

        debug!(
            "\n\n\n standard sig {}  \n agreement special sig \n{:?} \nchosen signature_base64\n {} \n\n\n",
            standard_signature, provided_signature, signature_base64
        );
        let signature_content_version = json_value[signature_key_from]
            .get(SIGNATURE_CONTENT_VERSION_FIELDNAME)
            .and_then(Value::as_str);
        let document_values_string = match signature_content_version {
            Some(SIGNATURE_CONTENT_VERSION_V2) => {
                let metadata_fields = extract_signature_fields(json_value, signature_key_from)
                    .ok_or_else(|| JacsError::SignatureVerificationFailed {
                        reason: format!(
                            "Missing '{}.fields' for v2 signature verification.",
                            signature_key_from
                        ),
                    })?;
                if let Some(explicit_fields) = &resolved_fields
                    && explicit_fields != &metadata_fields
                {
                    return Err(JacsError::SignatureVerificationFailed {
                        reason: format!(
                            "Explicit verification fields do not match signed '{}.fields' metadata.",
                            signature_key_from
                        ),
                    });
                }
                // SECURITY (SV-5): a v2 signature authenticates only the fields named
                // in `<placement>.fields`. `jacsSha256` is not itself signed, so an
                // attacker can append an unsigned top-level field, recompute the hash,
                // and slip unauthenticated data past both the signature and hash
                // checks. The document signature (`jacsSignature`) is the one that must
                // attest the *whole* document: `signing_procedure` enumerates every
                // non-reserved top-level field for it, so a genuine document never
                // carries extra unsigned keys. Agreement placements (`jacsAgreement`,
                // `agreementSignature`) intentionally sign a trimmed subset and are
                // exempt. Reject any top-level key under a document signature that is
                // not a signed field, a reserved JACS field, or the placement itself.
                if signature_key_from == DOCUMENT_AGENT_SIGNATURE_FIELDNAME
                    && let Some(obj) = json_value.as_object()
                {
                    for key in obj.keys() {
                        if key == signature_key_from
                            || JACS_IGNORE_FIELDS.contains(&key.as_str())
                            || metadata_fields.iter().any(|field| field == key)
                        {
                            continue;
                        }
                        return Err(JacsError::SignatureVerificationFailed {
                            reason: format!(
                                "Unsigned top-level field '{}' is present but not covered by \
                                 '{}.fields'; the v2 signature does not authenticate it.",
                                key, signature_key_from
                            ),
                        });
                    }
                }
                build_signature_content_v2(
                    json_value,
                    metadata_fields,
                    signature_key_from,
                    &json_value[signature_key_from],
                )?
            }
            Some(other) => {
                return Err(JacsError::SignatureVerificationFailed {
                    reason: format!("Unsupported signature content version '{}'.", other),
                });
            }
            None => {
                // SECURITY (SV-4): a legacy v1 signature does NOT authenticate the
                // signature metadata (agentID, date, jti, signingAlgorithm), so a
                // tamperer could rewrite those mutable fields without invalidating
                // the signature. Normal verification therefore denies v1 by default.
                // Compatibility requires an explicit opt-in; migration uses a
                // thread-scoped authorization that cannot weaken other requests.
                if !legacy_signature_content_allowed() {
                    return Err(legacy_signature_refusal(signature_key_from));
                }
                warn!(
                    event = "legacy_signature_content_verified",
                    agent_id = self.id.as_deref().unwrap_or("<unknown>"),
                    signature_key_from,
                    "SECURITY: verifying LEGACY v1 signature content; its metadata \
                     (agentID, date, jti, signingAlgorithm) is NOT authenticated and must \
                     not be trusted as proof of signer/time. This compatibility path was \
                     explicitly enabled; migrate and re-sign the document as v2."
                );
                let (payload, _) = build_signature_content(
                    json_value,
                    resolved_fields.clone(),
                    signature_key_from,
                    SignatureContentMode::CanonicalV2,
                )?;
                payload
            }
        };
        debug!(
            "signature_verification_procedure canonical payload:\n{}",
            document_values_string
        );
        let result = self.verify_string(
            &document_values_string,
            &signature_base64,
            public_key.clone(),
            resolved_public_key_enc_type.clone(),
        );

        let duration_ms = start_time.elapsed().as_millis() as u64;
        let success = result.is_ok();
        let algorithm = resolved_public_key_enc_type.as_deref().unwrap_or("unknown");
        let agent_id = json_value
            .get("jacsId")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown_agent");
        let signer_id = json_value
            .get(signature_key_from)
            .and_then(|sig| sig.get("agentID"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let timestamp = json_value
            .get(signature_key_from)
            .and_then(|sig| sig.get("date"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        record_signature_verification(agent_id, success, algorithm);

        if success {
            info!(
                event = "verification_complete",
                document_id = %agent_id,
                signer_id = %signer_id,
                algorithm = %algorithm,
                timestamp = %timestamp,
                valid = true,
                duration_ms = duration_ms,
                "Signature verification successful"
            );
        } else {
            error!(
                event = "verification_complete",
                document_id = %agent_id,
                signer_id = %signer_id,
                algorithm = %algorithm,
                valid = false,
                duration_ms = duration_ms,
                "Signature verification failed"
            );
        }

        result
    }

    /// Generates a signature JSON fragment for the specified JSON value.
    ///
    /// This function takes a JSON value, an optional list of fields to include in the signature,
    /// and a placement key. It retrieves the values of the specified fields from the JSON value,
    /// signs them using the agent's signing key, and returns a new JSON value containing the
    /// signature and related metadata.
    ///
    /// If no fields are provided, the function will choose system default fields. Note that if
    /// the system default fields change, it could cause problems with signature verification.
    ///
    /// # Arguments
    ///
    /// * `json_value` - A reference to the JSON value to be signed.
    /// * `fields` - An optional reference to a vector of field names to include in the signature.
    ///   If `None`, system default fields will be used.
    /// * `placement_key` - A reference to a string representing the key where the signature
    ///   should be placed in the resulting JSON value.
    ///
    /// # Returns
    ///
    /// * `Ok(Value)` - A new JSON value containing the signature and related metadata.
    /// * `Err(JacsError)` - An error occurred while generating the signature.
    ///
    ///
    /// # Errors
    ///
    /// This function may return an error in the following cases:
    ///
    /// * If the specified fields are not found in the JSON value.
    /// * If an error occurs while signing the values.
    /// * If an error occurs while serializing the accepted fields.
    /// * If an error occurs while retrieving the agent's public key.
    /// * If an error occurs while validating the generated signature against the schema.
    #[tracing::instrument(
        name = "jacs.signing_procedure",
        skip(self, json_value, fields),
        fields(placement_key)
    )]
    pub fn signing_procedure(
        &mut self,
        json_value: &Value,
        fields: Option<&[String]>,
        placement_key: &str,
    ) -> Result<Value, JacsError> {
        debug!("placement_key:\n{}", placement_key);
        let (_, accepted_fields) =
            Agent::get_values_as_string(json_value, fields.map(|s| s.to_vec()), placement_key)?;
        let agent_id = self.id.clone().unwrap_or_default();
        let agent_version = self.version.clone().unwrap_or_default();
        let date = time_utils::now_rfc3339();
        let iat = time_utils::now_timestamp();
        let jti = Uuid::now_v7().to_string();

        let config = self.config.as_ref().ok_or_else(|| {
            let agent_id = self.id.as_deref().unwrap_or("<uninitialized>");
            format!(
                "signing_procedure failed for agent '{}': Agent config is not initialized. \
                Ensure the agent is properly loaded with a valid configuration.",
                agent_id
            )
        })?;
        let signing_algorithm = config.get_key_algorithm()?;
        let serialized_fields = to_value(&accepted_fields)?;
        let public_key = self.get_public_key()?;
        let public_key_hash = hash_public_key(&public_key);
        debug!("hash {:?} ", public_key_hash);
        //TODO fields must never include sha256 at top level
        // error
        let mut signature_document = json!({
            // based on v1
            "agentID": agent_id,
            "agentVersion": agent_version,
            "date": date,
            "iat": iat,
            "jti": jti,
            "signature":"",
            "signingAlgorithm":signing_algorithm,
            "publicKeyHash": public_key_hash,
            "fields": serialized_fields,
            SIGNATURE_CONTENT_VERSION_FIELDNAME: SIGNATURE_CONTENT_VERSION_V2
        });
        let document_values_string = build_signature_content_v2(
            json_value,
            accepted_fields,
            placement_key,
            &signature_document,
        )?;
        debug!(
            "signing_procedure v2 document_values_string:\n\n{}\n\n",
            document_values_string
        );
        let signature = self.sign_string(&document_values_string)?;
        debug!("signing_procedure created signature :\n{}", signature);
        signature_document["signature"] = json!(signature);
        // TODO add sha256 of public key
        // validate signature schema
        self.schema.validate_signature(&signature_document)?;

        info!(
            event = "signing_procedure_complete",
            agent_id = %agent_id,
            algorithm = %signing_algorithm,
            timestamp = %date,
            placement_key = %placement_key,
            "Signing procedure completed"
        );

        Ok(signature_document)
    }

    /// given a set of fields, return a single string
    /// this function critical to all signatures
    /// placement_key is where this signature will go, so it should not be using itself
    /// TODO warn on missing keys
    fn get_values_as_string(
        json_value: &Value,
        keys: Option<Vec<String>>,
        placement_key: &str,
    ) -> Result<(String, Vec<String>), JacsError> {
        build_signature_content(
            json_value,
            keys,
            placement_key,
            SignatureContentMode::CanonicalV2,
        )
    }

    /// verify the hash of a complete document that has SHA256_FIELDNAME
    #[must_use = "hash verification result must be checked"]
    pub fn verify_hash(&self, doc: &Value) -> Result<bool, JacsError> {
        let original_hash_string = doc[SHA256_FIELDNAME].as_str().unwrap_or("").to_string();
        let new_hash_string = self.hash_doc(doc)?;

        if original_hash_string != new_hash_string {
            let error_message = format!(
                "Hashes don't match for doc {:?} {:?}! {:?} != {:?}",
                doc.get_str("jacsId")
                    .unwrap_or_else(|| "unknown".to_string()),
                doc.get_str("jacsVersion")
                    .unwrap_or_else(|| "unknown".to_string()),
                original_hash_string,
                new_hash_string
            );
            error!("{}", error_message);
            return Err(error_message.into());
        }
        Ok(true)
    }

    /// verify the hash where the document is the agent itself.
    #[must_use = "hash verification result must be checked"]
    pub fn verify_self_hash(&self) -> Result<bool, JacsError> {
        match &self.value {
            Some(embedded_value) => self.verify_hash(embedded_value),
            None => {
                let error_message = "Value is None";
                error!("{}", error_message);
                Err(error_message.into())
            }
        }
    }

    pub fn get_schema_keys(&mut self) -> Vec<String> {
        match self.document_schemas.lock() {
            Ok(document_schemas) => document_schemas.keys().map(|k| k.to_string()).collect(),
            Err(_) => Vec::new(), // Return empty vec if lock is poisoned
        }
    }

    /// pass in modified agent's JSON
    /// the function will replace it's internal value after:
    /// versioning
    /// resigning
    /// rehashing
    #[must_use = "updated agent JSON must be used or stored"]
    pub fn update_self(&mut self, new_agent_string: &str) -> Result<String, JacsError> {
        let mut new_self: Value = self.schema.validate_agent(new_agent_string)?;
        let original_self = self.value.as_ref().ok_or_else(|| {
            let agent_id = self.id.as_deref().unwrap_or("<uninitialized>");
            format!(
                "update_self failed for agent '{}': Agent value is not loaded. \
                Load the agent first before attempting to update it.",
                agent_id
            )
        })?;
        let orginal_id = &original_self.get_str("jacsId");
        let orginal_version = &original_self.get_str("jacsVersion");
        // check which fields are different
        let new_doc_orginal_id = &new_self.get_str("jacsId");
        let new_doc_orginal_version = &new_self.get_str("jacsVersion");
        if (orginal_id != new_doc_orginal_id) || (orginal_version != new_doc_orginal_version) {
            return Err(JacsError::AgentError(format!(
                "The id/versions do not match for old and new agent:  . {:?}{:?}",
                new_doc_orginal_id, new_doc_orginal_version
            )));
        }

        // Prevent verification claim downgrade
        // Security: Once an agent claims verified status, it cannot be downgraded
        fn claim_level(claim: &str) -> u8 {
            match claim {
                // "verified-hai.ai" kept as fallback during deprecation period
                "verified-registry" | "verified-hai.ai" => 2,
                "verified" => 1,
                _ => 0, // "unverified" or missing
            }
        }

        let original_claim = original_self
            .get("jacsVerificationClaim")
            .and_then(|v| v.as_str())
            .unwrap_or("unverified");
        let new_claim = new_self
            .get("jacsVerificationClaim")
            .and_then(|v| v.as_str())
            .unwrap_or("unverified");

        if claim_level(new_claim) < claim_level(original_claim) {
            return Err(JacsError::VerificationClaimFailed {
                claim: new_claim.to_string(),
                reason: format!(
                    "Cannot downgrade from '{}' to '{}'. Create a new agent instead.",
                    original_claim, new_claim
                ),
            });
        }

        // validate schema
        let new_version = Uuid::new_v4().to_string();
        let last_version = &original_self["jacsVersion"];
        let versioncreated = time_utils::now_rfc3339();

        new_self["jacsPreviousVersion"] = last_version.clone();
        new_self["jacsVersion"] = json!(new_version.to_string());
        new_self["jacsVersionDate"] = json!(versioncreated.to_string());

        // generate new keys?
        // sign new version
        new_self[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&new_self, None, AGENT_SIGNATURE_FIELDNAME)?;
        // hash new version
        let document_hash = self.hash_doc(&new_self)?;
        new_self[SHA256_FIELDNAME] = json!(document_hash.to_string());
        //replace ones self
        self.version = new_self.get_str("jacsVersion");
        self.value = Some(new_self.clone());
        self.validate_agent(&self.to_string())?;
        self.verify_self_signature()?;
        Ok(new_self.to_string())
    }

    /// Rotates the agent's keys and creates a new version of the agent document.
    ///
    /// Unlike `update_self` which re-signs with the *existing* key, this method:
    /// 1. Archives old keys (filesystem) or discards them (ephemeral)
    /// 2. Generates a new keypair
    /// 3. Creates a new agent version
    /// 4. Signs the new document with the **new** key
    /// 5. Produces a `jacsKeyRotationProof` signed with the **old** key
    ///
    /// # Arguments
    ///
    /// * `algorithm_override` - If `Some`, use this algorithm for the new keys
    ///   instead of reading from config. The config's `jacs_agent_key_algorithm`
    ///   is also updated in memory.
    ///
    /// Returns `(new_version, new_public_key_bytes, signed_agent_json)`.
    pub fn rotate_self(
        &mut self,
        algorithm_override: Option<&str>,
    ) -> Result<(String, Vec<u8>, Value), JacsError> {
        // Clone the current agent value up front to avoid borrow conflicts
        let original_value = self
            .value
            .as_ref()
            .ok_or_else(|| {
                let agent_id = self.id.as_deref().unwrap_or("<uninitialized>");
                format!(
                    "rotate_self failed for agent '{}': Agent value is not loaded.",
                    agent_id
                )
            })?
            .clone();

        let old_version = original_value
            .get_str("jacsVersion")
            .ok_or("Agent has no jacsVersion")?;

        let agent_id = original_value
            .get_str("jacsId")
            .ok_or("Agent has no jacsId")?;

        // Capture old key material BEFORE rotation for transition proof
        let old_public_key = self.get_public_key()?.clone();
        let old_key_hash = hash_public_key(&old_public_key);
        let old_algorithm = {
            let config = self.config.as_ref().ok_or("Agent config not initialized")?;
            config.get_key_algorithm()?
        };
        crate::crypt::ensure_private_key_operation_allowed(
            &old_algorithm,
            "rotation proof signing",
        )?;

        // Get old private key bytes for signing the transition proof
        let old_private_key_bytes = {
            let binding = self.get_private_key()?;
            if self.ephemeral {
                ZeroizingVec::new(binding.expose_secret().clone())
            } else {
                crate::agent::decrypt_with_agent_password(
                    binding.expose_secret(),
                    self.password(),
                    self.id.as_deref(),
                )?
            }
        };

        let key_algorithm =
            crate::crypt::resolve_rotation_algorithm(&old_algorithm, algorithm_override)?;
        crate::crypt::ensure_private_key_operation_allowed(&key_algorithm, "key rotation")?;

        let spec = KeySpec {
            algorithm: key_algorithm.clone(),
            key_id: None,
        };

        // Rotate keys: ephemeral uses in-memory key_store, FS uses FsEncryptedStore
        let (new_private_key, new_public_key) = if let Some(ref ks) = self.key_store {
            ks.rotate(&old_version, &spec)?
        } else {
            self.build_fs_store()?.rotate(&old_version, &spec)?
        };

        // Compute new key hash for transition proof
        let new_key_hash = hash_public_key(&new_public_key);

        // Build transition proof BEFORE setting new keys (we still have old key bytes)
        let timestamp = time_utils::now_rfc3339();
        let transition_message = format!(
            "JACS_KEY_ROTATION:{}:{}:{}:{}",
            agent_id, old_key_hash, new_key_hash, timestamp
        );

        // Sign the transition message with the OLD private key
        let old_ks: Box<dyn KeyStore> =
            Box::new(crate::keystore::InMemoryKeyStore::new(&old_algorithm));
        let sig_bytes = old_ks
            .sign_detached(
                old_private_key_bytes.as_slice(),
                transition_message.as_bytes(),
                &old_algorithm,
            )
            .map_err(|e| format!("Failed to sign transition proof with old key: {}", e))?;
        let transition_signature =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sig_bytes);

        let transition_proof = json!({
            "transitionMessage": transition_message,
            "signature": transition_signature,
            "signingAlgorithm": old_algorithm,
            "oldPublicKeyHash": old_key_hash,
            "newPublicKeyHash": new_key_hash,
            "timestamp": timestamp,
        });

        // Set new keys on the agent
        if self.ephemeral {
            self.set_keys_raw(new_private_key, new_public_key.clone(), &key_algorithm);
        } else {
            self.set_keys(new_private_key, new_public_key.clone(), &key_algorithm)?;
        }

        // Keep authenticated config metadata aligned with the selected key.
        // This matters for both same-algorithm replacement and an explicit
        // Ed25519→PQ upgrade.
        if let Some(ref mut config) = self.config {
            config.set_key_algorithm(key_algorithm.clone())?;
        }

        // Build new version document
        let new_version = Uuid::new_v4().to_string();
        let version_date = time_utils::now_rfc3339();

        let mut new_doc = original_value.clone();
        new_doc["jacsPreviousVersion"] = json!(old_version);
        new_doc["jacsVersion"] = json!(new_version.clone());
        new_doc["jacsVersionDate"] = json!(version_date);

        // Embed transition proof in the new agent document
        new_doc["jacsKeyRotationProof"] = transition_proof;

        // Remove old signature and hash — they will be regenerated with new key
        if let Some(obj) = new_doc.as_object_mut() {
            obj.remove(AGENT_SIGNATURE_FIELDNAME);
            obj.remove(SHA256_FIELDNAME);
        }

        // Sign with the new key
        new_doc[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&new_doc, None, AGENT_SIGNATURE_FIELDNAME)?;
        let document_hash = self.hash_doc(&new_doc)?;
        new_doc[SHA256_FIELDNAME] = json!(document_hash.to_string());

        // Update in-memory state
        self.version = Some(new_version.clone());
        self.value = Some(new_doc.clone());

        // Verify the new self-signature
        self.verify_self_signature()?;

        // Save public key hash (skip for ephemeral)
        if !self.ephemeral {
            let public_key_hash = hash_public_key(&new_public_key);
            let _ = self.fs_save_remote_public_key(
                &public_key_hash,
                &new_public_key,
                key_algorithm.as_bytes(),
            );
        }

        Ok((new_version, new_public_key, new_doc))
    }

    /// Verify a `jacsKeyRotationProof` using the old public key.
    ///
    /// The proof contains a `transitionMessage` signed with the old key. This
    /// function re-derives the expected message from the proof's metadata and
    /// checks the cryptographic signature against `old_public_key_bytes`.
    ///
    /// Returns `Ok(())` if the proof is valid, or `Err` if verification fails.
    pub fn verify_transition_proof(
        proof: &Value,
        old_public_key_bytes: &[u8],
    ) -> Result<(), JacsError> {
        let msg = proof["transitionMessage"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing transitionMessage".into()))?;
        let sig_b64 = proof["signature"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing signature".into()))?;
        let algorithm = proof["signingAlgorithm"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing signingAlgorithm".into()))?;
        let old_public_key_hash = proof["oldPublicKeyHash"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing oldPublicKeyHash".into()))?;
        let new_public_key_hash = proof["newPublicKeyHash"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing newPublicKeyHash".into()))?;
        let timestamp = proof["timestamp"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing timestamp".into()))?;

        let computed_old_hash = hash_public_key(old_public_key_bytes);
        if computed_old_hash != old_public_key_hash {
            return Err(JacsError::ConfigError(format!(
                "Transition proof oldPublicKeyHash '{}' does not match the supplied historical key '{}'.",
                old_public_key_hash, computed_old_hash
            )));
        }

        const PREFIX: &str = "JACS_KEY_ROTATION:";
        let expected_suffix = format!(
            ":{}:{}:{}",
            old_public_key_hash, new_public_key_hash, timestamp
        );
        let agent_id = msg
            .strip_prefix(PREFIX)
            .and_then(|rest| rest.strip_suffix(&expected_suffix))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                JacsError::ConfigError(
                    "Transition proof message does not match the structured proof fields.".into(),
                )
            })?;
        uuid::Uuid::parse_str(agent_id).map_err(|e| {
            JacsError::ConfigError(format!(
                "Transition proof contains invalid agent ID '{}': {}",
                agent_id, e
            ))
        })?;

        // Use the appropriate verify function based on algorithm
        let verified = match algorithm {
            "ring-Ed25519" => crate::crypt::ringwrapper::verify_string(
                old_public_key_bytes.to_vec(),
                msg,
                sig_b64,
            )
            .is_ok(),
            "pq2025" => {
                crate::crypt::pq2025::verify_string(old_public_key_bytes.to_vec(), msg, sig_b64)
                    .is_ok()
            }
            _ => {
                return Err(JacsError::ConfigError(format!(
                    "Unknown algorithm in transition proof: {}",
                    algorithm
                )));
            }
        };

        if verified {
            Ok(())
        } else {
            Err(JacsError::ConfigError(
                "Transition proof signature verification failed".into(),
            ))
        }
    }

    /// Verify a key-rotation proof and bind it to the relying party's expected
    /// stable identity and candidate new public key.
    ///
    /// Registry and directory services should use this method instead of
    /// [`Self::verify_transition_proof`] alone. The detached proof authenticates
    /// its own fields with the old key; this stricter method additionally
    /// prevents transplanting that proof onto another identity or candidate
    /// key. Public keys must be the raw algorithm-specific bytes used by JACS.
    pub fn verify_transition_proof_for_rotation(
        proof: &Value,
        expected_agent_id: &str,
        old_public_key_bytes: &[u8],
        new_public_key_bytes: &[u8],
    ) -> Result<(), JacsError> {
        uuid::Uuid::parse_str(expected_agent_id).map_err(|error| {
            JacsError::ConfigError(format!(
                "Expected rotation agent ID '{}' is invalid: {}",
                expected_agent_id, error
            ))
        })?;
        Self::verify_transition_proof(proof, old_public_key_bytes)?;

        let old_key_hash = proof["oldPublicKeyHash"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing oldPublicKeyHash".to_string()))?;
        let new_key_hash = proof["newPublicKeyHash"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing newPublicKeyHash".to_string()))?;
        let timestamp = proof["timestamp"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing timestamp".to_string()))?;
        let transition_message = proof["transitionMessage"]
            .as_str()
            .ok_or_else(|| JacsError::ConfigError("proof missing transitionMessage".to_string()))?;

        let computed_new_key_hash = hash_public_key(new_public_key_bytes);
        if new_key_hash != computed_new_key_hash {
            return Err(JacsError::ConfigError(format!(
                "Transition proof newPublicKeyHash '{}' does not match the candidate key '{}'.",
                new_key_hash, computed_new_key_hash
            )));
        }

        let expected_message = format!(
            "JACS_KEY_ROTATION:{}:{}:{}:{}",
            expected_agent_id, old_key_hash, new_key_hash, timestamp
        );
        if transition_message != expected_message {
            return Err(JacsError::ConfigError(
                "Transition proof is not bound to the expected agent identity and candidate key."
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_header(&mut self, json: &str) -> Result<Value, JacsError> {
        let value = self.schema.validate_header(json)?;

        // check hash
        let _ = self.verify_hash(&value)?;
        // check signature

        Ok(value)
    }

    pub fn validate_agent(&mut self, json: &str) -> Result<Value, JacsError> {
        let value = self.schema.validate_agent(json)?;
        //
        // additional validation
        // check hash
        let _ = self.verify_hash(&value)?;
        // check signature

        Ok(value)
    }

    //// accepts local file system path or Urls
    #[must_use = "schema loading result must be checked for errors"]
    pub fn load_custom_schemas(&mut self, schema_paths: &[String]) -> Result<(), String> {
        let mut schemas = self.document_schemas.lock().map_err(|e| e.to_string())?;
        for path in schema_paths {
            let schema_value =
                crate::schema::utils::resolve_schema_with_config(path, self.config.as_ref())
                    .map_err(|e| e.to_string())?;
            let retriever = match self.config.as_ref() {
                Some(c) => EmbeddedSchemaResolver::with_config(c),
                None => EmbeddedSchemaResolver::new(),
            };
            let schema = Validator::options()
                .with_draft(Draft::Draft7)
                .with_retriever(retriever)
                .build(&schema_value)
                .map_err(|e| e.to_string())?;
            schemas.insert(path.clone(), schema);
        }
        Ok(())
    }

    #[must_use = "save result must be checked for errors"]
    pub fn save(&self) -> Result<String, JacsError> {
        let agent_string = self.as_string()?;
        let lookup_id = self.get_lookup_id()?;
        self.fs_agent_save(&lookup_id, &agent_string)
    }

    /// create an agent, and provde id and version as a result
    #[must_use = "created agent value must be used"]
    pub fn create_agent_and_load(
        &mut self,
        json: &str,
        create_keys: bool,
        _create_keys_algorithm: Option<&str>,
    ) -> Result<Value, JacsError> {
        // validate schema json string
        // make sure id and version are empty
        let mut instance = self.schema.create(json)?;

        self.id = instance.get_str("jacsId");
        self.version = instance.get_str("jacsVersion");

        if create_keys {
            if let Some(ref ks) = self.key_store {
                // Ephemeral: use the in-memory key store
                // Clone the Box<dyn KeyStore> reference data we need before mutable borrow
                //
                // Resolve the requested supported algorithm without
                // substitution. The fixture flag preserves historical
                // pre-compat-key construction semantics.
                let requested = {
                    let config = self.config.as_ref().ok_or("Agent config not initialized")?;
                    config.get_key_algorithm()?
                };
                let algo = if self.legacy_ed25519_keygen_for_fixtures {
                    requested.clone()
                } else {
                    crate::crypt::resolve_new_agent_algorithm(&requested)?
                };
                if algo != requested
                    && let Some(cfg) = self.config.as_mut()
                {
                    // Keep the config consistent with the keys actually
                    // minted so subsequent signing dispatches correctly.
                    cfg.set_key_algorithm(algo.clone())?;
                }
                let spec = KeySpec {
                    algorithm: algo.clone(),
                    key_id: None,
                };
                let (private_key, public_key) = ks.generate(&spec)?;
                self.set_keys_raw(private_key, public_key, &algo);
            } else {
                // Filesystem path applies the same no-substitution resolver.
                self.generate_keys()?;
            }
        }
        if !self.ephemeral && (self.public_key.is_none() || self.private_key.is_none()) {
            self.fs_load_keys()?;
        }

        // Cache the agent's own public key under its hash so self-signed
        // documents (including legacy v1 agreements) resolve through the same
        // lookup path. Ephemeral agents write this into their memory storage.
        if let (Some(public_key), Some(key_algorithm)) = (&self.public_key, &self.key_algorithm) {
            let public_key_hash = hash_public_key(public_key);
            let _ = self.fs_save_remote_public_key(
                &public_key_hash,
                public_key,
                key_algorithm.as_bytes(),
            );
        }

        // schema.create will call this "document" otherwise
        instance["jacsType"] = json!("agent");
        instance["jacsLevel"] = json!("config");
        instance["$schema"] = json!("https://hai.ai/schemas/agent/v1/agent.schema.json");
        instance[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&instance, None, AGENT_SIGNATURE_FIELDNAME)?;
        // write  file to disk at [jacs]/agents/
        // run as agent
        // validate the agent schema now
        let document_hash = self.hash_doc(&instance)?;
        instance[SHA256_FIELDNAME] = json!(document_hash.to_string());
        self.value = Some(instance.clone());
        self.verify_self_signature()?;
        Ok(instance)
    }

    /// Sign a config JSON value, producing a JACS document with header fields.
    ///
    /// Uses `Schema::create` for initial ID/version assignment.
    /// The resulting JSON has `jacsType: "config"`, `jacsLevel: "config"`,
    /// a `jacsSignature`, and `jacsSha256`.
    pub fn sign_config(&mut self, config_json: &Value) -> Result<Value, JacsError> {
        let json_str = serde_json::to_string(config_json)
            .map_err(|e| JacsError::ConfigError(format!("serialize config: {e}")))?;
        let mut instance = self.schema.create(&json_str)?;
        instance["jacsType"] = json!("config");
        instance["jacsLevel"] = json!("config");
        instance["$schema"] = json!("https://hai.ai/schemas/jacs.config.schema.json");
        instance[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&instance, None, AGENT_SIGNATURE_FIELDNAME)?;
        let document_hash = self.hash_doc(&instance)?;
        instance[SHA256_FIELDNAME] = json!(document_hash);
        Ok(instance)
    }

    /// Verify a previously signed config document: schema + hash + signature.
    ///
    /// This mirrors the same checks that `SimpleAgent::verify()` performs:
    /// 1. `validate_header` — schema validation + `verify_hash`
    /// 2. `signature_verification_procedure` — cryptographic signature check
    pub fn verify_config(&mut self, config_json: &Value) -> Result<(), JacsError> {
        let json_str = serde_json::to_string(config_json)
            .map_err(|e| JacsError::ConfigError(format!("serialize config for verify: {e}")))?;
        self.validate_header(&json_str)?;

        // Signature verification (matches SimpleAgent::verify path)
        let public_key = self.get_public_key()?;
        self.signature_verification_procedure(
            config_json,
            None,
            AGENT_SIGNATURE_FIELDNAME,
            public_key,
            None,
            None,
            None,
        )?;
        Ok(())
    }

    /// Update and re-sign an existing signed config document.
    ///
    /// Bumps `jacsVersion`, sets `jacsPreviousVersion`, re-signs and re-hashes.
    /// `jacsId` is preserved.
    pub fn update_config(&mut self, config_json: &Value) -> Result<Value, JacsError> {
        let mut doc = config_json.clone();
        let prev_version = doc
            .get("jacsVersion")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JacsError::ConfigError("update_config: missing jacsVersion".to_string())
            })?
            .to_string();
        let new_version = uuid::Uuid::new_v4().to_string();
        doc["jacsPreviousVersion"] = json!(prev_version);
        doc["jacsVersion"] = json!(new_version);
        doc["jacsVersionDate"] = json!(crate::time_utils::now_rfc3339());

        if let Some(obj) = doc.as_object_mut() {
            obj.remove(AGENT_SIGNATURE_FIELDNAME);
            obj.remove(SHA256_FIELDNAME);
        }

        doc[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&doc, None, AGENT_SIGNATURE_FIELDNAME)?;
        let document_hash = self.hash_doc(&doc)?;
        doc[SHA256_FIELDNAME] = json!(document_hash);
        Ok(doc)
    }

    /// Returns an `AgentBuilder` for constructing an `Agent` with a fluent API.
    ///
    /// # Example
    /// ```rust,ignore
    /// use jacs::agent::Agent;
    ///
    /// // Build an agent with default v1 versions
    /// let agent = Agent::builder().build()?;
    ///
    /// // Build an agent with custom configuration
    /// let agent = Agent::builder()
    ///     .config_path("path/to/jacs.config.json")
    ///     .dns_strict(true)
    ///     .build()?;
    ///
    /// // Build an agent with explicit versions
    /// let agent = Agent::builder()
    ///     .agent_version("v1")
    ///     .header_version("v1")
    ///     .signature_version("v1")
    ///     .build()?;
    /// ```
    pub fn builder() -> AgentBuilder {
        AgentBuilder::new()
    }

    /// Verifies multiple signatures in a batch operation.
    ///
    /// This method processes each verification sequentially. For CPU-bound signature
    /// verification, this is often efficient due to the cryptographic operations
    /// being compute-intensive. If parallel verification is needed, consider using
    /// rayon's `par_iter()` on the input slice externally.
    ///
    /// # Arguments
    ///
    /// * `items` - A slice of tuples containing:
    ///   - `data`: The string data that was signed
    ///   - `signature`: The base64-encoded signature
    ///   - `public_key`: The public key bytes for verification
    ///   - `algorithm`: Optional algorithm hint (e.g., "ring-Ed25519", "pq2025")
    ///
    /// # Returns
    ///
    /// A vector of `Result<(), JacsError>` in the same order as the input items.
    /// - `Ok(())` indicates the signature is valid
    /// - `Err(JacsError)` indicates verification failed with a specific reason
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::agent::Agent;
    ///
    /// let agent = Agent::builder().build()?;
    ///
    /// let items = vec![
    ///     ("message1".to_string(), sig1, pk1.clone(), None),
    ///     ("message2".to_string(), sig2, pk2.clone(), Some("ring-Ed25519".to_string())),
    /// ];
    ///
    /// let results = agent.verify_batch(&items);
    /// for (i, result) in results.iter().enumerate() {
    ///     match result {
    ///         Ok(()) => println!("Item {} verified successfully", i),
    ///         Err(e) => println!("Item {} failed: {}", i, e),
    ///     }
    /// }
    /// ```
    ///
    /// # Performance Notes
    ///
    /// - Verification is sequential; for parallel verification, use rayon externally
    /// - Each verification is independent and does not short-circuit on failure
    /// - The method returns all results even if some verifications fail
    #[must_use]
    pub fn verify_batch(
        &self,
        items: &[(String, String, Vec<u8>, Option<String>)],
    ) -> Vec<Result<(), JacsError>> {
        items
            .iter()
            .map(|(data, signature, public_key, algorithm)| {
                self.verify_string(data, signature, public_key.clone(), algorithm.clone())
                    .map_err(|e| JacsError::SignatureVerificationFailed {
                        reason: e.to_string(),
                    })
            })
            .collect()
    }
}

/// A builder for constructing `Agent` instances with a fluent API.
///
/// This provides a more ergonomic way to create agents compared to calling
/// `Agent::new()` directly, with sensible defaults for common use cases.
///
/// # Defaults
/// - `agent_version`: "v1"
/// - `header_version`: "v1"
/// - `signature_version`: "v1"
/// - `dns_strict`: false
/// - `dns_validate`: None (derived from config/domain presence)
/// - `dns_required`: None (derived from config/domain presence)
///
/// # Example
/// ```rust,ignore
/// use jacs::agent::AgentBuilder;
///
/// // Simplest usage - all defaults
/// let agent = AgentBuilder::new().build()?;
///
/// // With config file
/// let agent = AgentBuilder::new()
///     .config_path("/path/to/config.json")
///     .build()?;
///
/// // With inline config
/// let config = Config::with_defaults();
/// let agent = AgentBuilder::new()
///     .config(config)
///     .build()?;
/// ```
#[derive(Debug, Default)]
pub struct AgentBuilder {
    agent_version: Option<String>,
    header_version: Option<String>,
    signature_version: Option<String>,
    config_path: Option<String>,
    config: Option<Config>,
    dns_strict: Option<bool>,
    dns_validate: Option<bool>,
    dns_required: Option<bool>,
}

impl AgentBuilder {
    /// Creates a new `AgentBuilder` with default values.
    ///
    /// Default versions are all "v1".
    pub fn new() -> Self {
        Self {
            agent_version: None,
            header_version: None,
            signature_version: None,
            config_path: None,
            config: None,
            dns_strict: None,
            dns_validate: None,
            dns_required: None,
        }
    }

    /// Sets the agent schema version (default: "v1").
    pub fn agent_version(mut self, version: &str) -> Self {
        self.agent_version = Some(version.to_string());
        self
    }

    /// Sets the header schema version (default: "v1").
    pub fn header_version(mut self, version: &str) -> Self {
        self.header_version = Some(version.to_string());
        self
    }

    /// Sets the signature schema version (default: "v1").
    pub fn signature_version(mut self, version: &str) -> Self {
        self.signature_version = Some(version.to_string());
        self
    }

    /// Sets all schema versions at once (agent, header, signature).
    ///
    /// This is a convenience method for setting all versions to the same value.
    pub fn all_versions(mut self, version: &str) -> Self {
        self.agent_version = Some(version.to_string());
        self.header_version = Some(version.to_string());
        self.signature_version = Some(version.to_string());
        self
    }

    /// Sets the path to a JACS config file to load.
    ///
    /// If set, the config will be loaded from this path during `build()`.
    /// This takes precedence over any config set via `config()`.
    ///
    /// # Example
    /// ```rust,ignore
    /// let agent = Agent::builder()
    ///     .config_path("./jacs.config.json")
    ///     .build()?;
    /// ```
    pub fn config_path(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_string());
        self
    }

    /// Sets a pre-built config directly.
    ///
    /// Note: If `config_path()` is also set, the path takes precedence
    /// and this config will be ignored.
    ///
    /// # Example
    /// ```rust,ignore
    /// let config = Config::with_defaults();
    /// let agent = Agent::builder()
    ///     .config(config)
    ///     .build()?;
    /// ```
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets whether DNS validation should be strict.
    ///
    /// When strict, DNS verification must succeed (no fallback to embedded fingerprint).
    pub fn dns_strict(mut self, strict: bool) -> Self {
        self.dns_strict = Some(strict);
        self
    }

    /// Sets whether DNS validation is enabled.
    ///
    /// If None, DNS validation is derived from config/domain presence.
    pub fn dns_validate(mut self, enabled: bool) -> Self {
        self.dns_validate = Some(enabled);
        self
    }

    /// Sets whether DNS validation is required.
    ///
    /// When required, the agent must have a domain and DNS validation must succeed.
    pub fn dns_required(mut self, required: bool) -> Self {
        self.dns_required = Some(required);
        self
    }

    /// Builds the `Agent` with the configured options.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Schema initialization fails
    /// - Config file loading fails (if `config_path` was set)
    /// - Storage initialization fails
    ///
    /// # Example
    /// ```rust,ignore
    /// let agent = Agent::builder()
    ///     .config_path("./jacs.config.json")
    ///     .dns_strict(true)
    ///     .build()?;
    /// ```
    #[must_use = "agent build result must be checked for errors"]
    pub fn build(self) -> Result<Agent, JacsError> {
        // Use defaults if not specified
        let agent_version = self.agent_version.unwrap_or_else(|| "v1".to_string());
        let header_version = self.header_version.unwrap_or_else(|| "v1".to_string());
        let signature_version = self.signature_version.unwrap_or_else(|| "v1".to_string());

        // Initialize schema
        let schema = Schema::new(&agent_version, &header_version, &signature_version)
            .map_err(|e| JacsError::SchemaError(format!("Failed to initialize schema: {}", e)))?;

        // Load config
        let config = if let Some(path) = self.config_path {
            // Load from path using 12-Factor compliant loading
            Some(load_config_12factor(Some(&path)).map_err(|e| {
                JacsError::ConfigError(format!("Failed to load config from '{}': {}", path, e))
            })?)
        } else if let Some(cfg) = self.config {
            // Use provided config
            Some(cfg)
        } else {
            // Use 12-Factor loading with defaults + env vars
            Some(load_config_12factor(None).map_err(|e| {
                JacsError::ConfigError(format!("Failed to load default config: {}", e))
            })?)
        };

        if let Some(config) = config.as_ref() {
            let config_use = if config
                .jacs_agent_id_and_version()
                .as_deref()
                .is_some_and(|lookup| !lookup.trim().is_empty())
            {
                ConfigUse::ExistingAgent
            } else {
                ConfigUse::NewAgent
            };
            let source_path = config
                .source_path()
                .map(|path| path.to_string_lossy().into_owned());
            match Agent::verify_config_before_use(
                &schema,
                config,
                source_path.as_deref(),
                config_use,
            )? {
                ConfigPreflight::Unsigned | ConfigPreflight::SignedCurrent(None) => {}
                ConfigPreflight::SignedCurrent(Some(_)) | ConfigPreflight::SignedHistorical(_) => {
                    return Err(JacsError::ConfigError(
                        "AgentBuilder cannot complete pending key-rotation recovery; load the identity with Agent::from_config or SimpleAgent::load instead."
                            .to_string(),
                    ));
                }
            }
        }

        // Initialize storage
        let storage = MultiStorage::default_new()
            .map_err(|e| JacsError::ConfigError(format!("Failed to initialize storage: {}", e)))?;

        let document_schemas = Arc::new(Mutex::new(HashMap::new()));

        // Build key paths from config
        let key_paths = config
            .as_ref()
            .map(Agent::key_paths_from_config)
            .transpose()?;

        // Create the agent
        let mut agent = Agent {
            schema,
            value: None,
            config,
            storage,
            document_schemas,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
            key_store: None,
            ephemeral: false,
            dns_strict: self.dns_strict.unwrap_or(false),
            dns_validate_enabled: self.dns_validate,
            dns_required: self.dns_required,
            key_paths,
            password: None,
            legacy_ed25519_keygen_for_fixtures: false,
            #[cfg(feature = "attestation")]
            adapters: crate::attestation::adapters::default_adapters(),
        };

        // Apply DNS settings if specified
        if let Some(strict) = self.dns_strict {
            agent.set_dns_strict(strict);
        }
        if let Some(validate) = self.dns_validate {
            agent.set_dns_validate(validate);
        }
        if let Some(required) = self.dns_required {
            agent.set_dns_required(required);
        }

        Ok(agent)
    }

    /// Builds an `Agent` and loads it from the specified agent ID.
    ///
    /// This is a convenience method that combines `build()` with `load_by_id()`.
    ///
    /// # Arguments
    /// * `agent_id` - The agent ID in format "uuid:version_uuid"
    ///
    /// # Example
    /// ```rust,ignore
    /// let agent = Agent::builder()
    ///     .config_path("./jacs.config.json")
    ///     .build_and_load("123e4567-e89b-12d3-a456-426614174000:123e4567-e89b-12d3-a456-426614174001")?;
    /// ```
    #[must_use = "agent build and load result must be checked for errors"]
    pub fn build_and_load(self, agent_id: &str) -> Result<Agent, JacsError> {
        let mut agent = self.build()?;
        agent.load_by_id(agent_id.to_string()).map_err(|e| {
            JacsError::AgentError(format!("Failed to load agent '{}': {}", agent_id, e))
        })?;
        Ok(agent)
    }
}

#[cfg(test)]
mod verification_claim_normalization_tests {
    use super::normalize_verification_claim;

    #[test]
    fn verified_registry_passes_through_unchanged() {
        assert_eq!(
            normalize_verification_claim("verified-registry"),
            "verified-registry"
        );
    }

    #[test]
    fn verified_hai_ai_normalizes_to_verified_registry() {
        assert_eq!(
            normalize_verification_claim("verified-hai.ai"),
            "verified-registry"
        );
    }

    #[test]
    fn unverified_passes_through_unchanged() {
        assert_eq!(normalize_verification_claim("unverified"), "unverified");
    }

    #[test]
    fn verified_passes_through_unchanged() {
        assert_eq!(normalize_verification_claim("verified"), "verified");
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;

    #[test]
    fn programmatic_config_uses_a_lexically_normal_storage_root() {
        let config = Config::new(
            Some("false".to_string()),
            Some("data".to_string()),
            Some("keys".to_string()),
            None,
            None,
            Some("ring-Ed25519".to_string()),
            None,
            None,
            Some("fs".to_string()),
        );

        let (root, _) = Agent::calculate_storage_root_and_normalize(config, "test")
            .expect("programmatic filesystem config should resolve");

        let current_dir = std::env::current_dir().expect("current directory");
        assert_eq!(root.to_string_lossy(), current_dir.to_string_lossy());
    }

    #[test]
    fn test_agent_builder_default_values() {
        // Build an agent with all defaults
        let agent = Agent::builder()
            .build()
            .expect("Should build with defaults");

        // Verify the agent was created (not loaded, so no value)
        assert!(agent.get_value().is_none());
        // Config should be loaded
        assert!(agent.config.is_some());
    }

    #[test]
    fn test_ready_false_on_fresh_agent() {
        let agent = Agent::builder().build().expect("Should build");
        // A freshly built agent has config but no id, keys, or value
        assert!(
            !agent.ready(),
            "ready() should be false without keys/id/value"
        );
    }

    #[test]
    fn test_agent_builder_new_equals_default() {
        // AgentBuilder::new() and AgentBuilder::default() should produce equivalent builders
        let builder_new = AgentBuilder::new();
        let builder_default = AgentBuilder::default();

        // Both should have None for all fields
        assert!(builder_new.agent_version.is_none());
        assert!(builder_new.header_version.is_none());
        assert!(builder_new.signature_version.is_none());
        assert!(builder_new.config_path.is_none());
        assert!(builder_new.config.is_none());
        assert!(builder_new.dns_strict.is_none());
        assert!(builder_new.dns_validate.is_none());
        assert!(builder_new.dns_required.is_none());

        assert!(builder_default.agent_version.is_none());
        assert!(builder_default.header_version.is_none());
        assert!(builder_default.signature_version.is_none());
        assert!(builder_default.config_path.is_none());
        assert!(builder_default.config.is_none());
        assert!(builder_default.dns_strict.is_none());
        assert!(builder_default.dns_validate.is_none());
        assert!(builder_default.dns_required.is_none());
    }

    #[test]
    fn test_agent_builder_custom_versions() {
        // Build an agent with custom versions
        let agent = Agent::builder()
            .agent_version("v1")
            .header_version("v1")
            .signature_version("v1")
            .build()
            .expect("Should build with custom versions");

        // Verify the agent was created
        assert!(agent.config.is_some());
    }

    #[test]
    fn test_agent_builder_all_versions() {
        // Test the all_versions convenience method
        let builder = AgentBuilder::new().all_versions("v1");

        assert_eq!(builder.agent_version, Some("v1".to_string()));
        assert_eq!(builder.header_version, Some("v1".to_string()));
        assert_eq!(builder.signature_version, Some("v1".to_string()));
    }

    #[test]
    fn test_agent_builder_dns_settings() {
        // Build an agent with DNS settings
        let agent = Agent::builder()
            .dns_strict(true)
            .dns_validate(true)
            .dns_required(false)
            .build()
            .expect("Should build with DNS settings");

        // Verify DNS settings were applied
        assert!(agent.dns_strict);
        assert_eq!(agent.dns_validate_enabled, Some(true));
        assert_eq!(agent.dns_required, Some(false));
    }

    #[test]
    fn test_agent_builder_with_config() {
        // Build an agent with a direct config
        let config = Config::with_defaults();
        let agent = Agent::builder()
            .config(config)
            .build()
            .expect("Should build with config");

        // Verify config was used
        assert!(agent.config.is_some());
    }

    #[test]
    fn test_agent_builder_fluent_api() {
        // Verify the fluent API returns Self at each step
        let agent = Agent::builder()
            .agent_version("v1")
            .header_version("v1")
            .signature_version("v1")
            .dns_strict(false)
            .dns_validate(true)
            .build()
            .expect("Should build with fluent API");

        assert!(agent.config.is_some());
    }

    #[test]
    fn test_agent_builder_method_exists() {
        // Verify Agent::builder() returns an AgentBuilder
        let builder = Agent::builder();
        assert!(builder.agent_version.is_none());
    }

    #[test]
    fn test_agent_builder_config_path_invalid() {
        // Build with an invalid config path should fail
        let result = Agent::builder()
            .config_path("/nonexistent/path/to/config.json")
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("config"));
    }

    #[test]
    fn test_verify_batch_empty_input() {
        // Test that verify_batch handles empty input gracefully
        let agent = Agent::builder()
            .build()
            .expect("Should build with defaults");
        let items: Vec<(String, String, Vec<u8>, Option<String>)> = vec![];
        let results = agent.verify_batch(&items);
        assert!(results.is_empty());
    }

    #[test]
    fn test_verify_batch_returns_correct_count() {
        // Test that verify_batch returns one result per input item
        let agent = Agent::builder()
            .build()
            .expect("Should build with defaults");

        // Create invalid items (they will fail verification, but we are testing the count)
        let items: Vec<(String, String, Vec<u8>, Option<String>)> = vec![
            (
                "data1".to_string(),
                "invalid_sig".to_string(),
                vec![1, 2, 3],
                None,
            ),
            (
                "data2".to_string(),
                "invalid_sig".to_string(),
                vec![4, 5, 6],
                None,
            ),
            (
                "data3".to_string(),
                "invalid_sig".to_string(),
                vec![7, 8, 9],
                None,
            ),
        ];

        let results = agent.verify_batch(&items);
        assert_eq!(results.len(), 3);

        // All should fail since these are invalid signatures
        for result in &results {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_build_signature_content_canonical_includes_non_string_fields() {
        let value = json!({
            "content": {"z": 1, "a": 2},
            "title": "hello"
        });
        let keys = Some(vec![
            "content".to_string(),
            "title".to_string(),
            "enabled".to_string(),
        ]);
        let value = value
            .as_object()
            .cloned()
            .map(serde_json::Value::Object)
            .unwrap_or_default();
        let mut value = value;
        value["enabled"] = json!(true);

        let (canonical_payload, _) = build_signature_content(
            &value,
            keys,
            AGENT_SIGNATURE_FIELDNAME,
            SignatureContentMode::CanonicalV2,
        )
        .expect("canonical payload should build");

        assert!(
            canonical_payload.contains("{\"a\":2,\"z\":1}"),
            "canonical payload should include canonicalized object value"
        );
        assert!(
            canonical_payload.contains("\"hello\""),
            "canonical payload should include JSON-encoded strings"
        );
        assert!(
            canonical_payload.contains("true"),
            "canonical payload should include boolean values"
        );
    }

    #[test]
    fn test_build_signature_content_default_fields_sorted() {
        let value = json!({
            "z": "last",
            "a": "first",
            AGENT_SIGNATURE_FIELDNAME: {"fields": []},
            SHA256_FIELDNAME: "ignored"
        });

        let (_, fields) = build_signature_content(
            &value,
            None,
            AGENT_SIGNATURE_FIELDNAME,
            SignatureContentMode::CanonicalV2,
        )
        .expect("canonical payload should build");

        assert_eq!(fields, vec!["a".to_string(), "z".to_string()]);
    }

    #[test]
    fn test_extract_signature_fields_reads_signature_metadata() {
        let value = json!({
            AGENT_SIGNATURE_FIELDNAME: {
                "fields": ["b", "a", "content"]
            }
        });

        let fields = extract_signature_fields(&value, AGENT_SIGNATURE_FIELDNAME)
            .expect("fields should be extracted");
        assert_eq!(fields, vec!["b", "a", "content"]);
    }
}

#[cfg(test)]
mod ephemeral_tests {
    use super::*;
    use crate::create_minimal_blank_agent;

    fn make_agent_json() -> String {
        create_minimal_blank_agent("ai".to_string(), None, None, None).unwrap()
    }

    #[test]
    fn test_ephemeral_creates_without_config_file() {
        let agent = Agent::ephemeral("pq2025").unwrap();
        assert!(agent.is_ephemeral());
        assert!(agent.config.is_some());
        // No files should be created — config is in-memory
    }

    #[test]
    fn test_ephemeral_creates_without_env_vars() {
        // No JACS_KEY_DIRECTORY or JACS_PRIVATE_KEY_PASSWORD needed
        let agent = Agent::ephemeral("pq2025").unwrap();
        assert!(agent.is_ephemeral());
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn test_ephemeral_create_agent_and_load() {
        let mut agent = Agent::ephemeral("pq2025").unwrap();
        let json = make_agent_json();
        let result = agent.create_agent_and_load(&json, true, Some("pq2025"));
        assert!(
            result.is_ok(),
            "create_agent_and_load failed: {:?}",
            result.err()
        );
        let instance = result.unwrap();
        assert!(instance.get("jacsId").is_some());
        assert!(instance.get("jacsVersion").is_some());
        assert!(instance.get("jacsSignature").is_some());
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn test_ephemeral_sign_and_verify_round_trip() {
        use crate::agent::document::DocumentTraits;

        let mut agent = Agent::ephemeral("pq2025").unwrap();
        let json = make_agent_json();
        agent
            .create_agent_and_load(&json, true, Some("pq2025"))
            .unwrap();

        // Sign a document
        let doc_json = r#"{"message": "hello world"}"#;
        let signed = agent
            .create_document_and_load(doc_json, None, None)
            .unwrap();
        let value = signed.getvalue();
        assert!(
            value.get("jacsSignature").is_some(),
            "Document should have signature"
        );
        assert!(
            value.get("jacsSha256").is_some(),
            "Document should have hash"
        );

        // Verify the document via key lookup
        let lookup = signed.getkey();
        let result = agent.verify_document_signature(&lookup, None, None, None, None);
        assert!(
            result.is_ok(),
            "Document verification failed: {:?}",
            result.err()
        );
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn test_ephemeral_agent_is_ready() {
        let mut agent = Agent::ephemeral("pq2025").unwrap();
        let json = make_agent_json();
        agent
            .create_agent_and_load(&json, true, Some("pq2025"))
            .unwrap();
        assert!(
            agent.ready(),
            "Ephemeral agent should be ready after create_agent_and_load"
        );
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn test_ephemeral_no_files_on_disk() {
        let temp = std::env::temp_dir().join("jacs_ephemeral_test_no_files");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        let mut agent = Agent::ephemeral("pq2025").unwrap();
        let json = make_agent_json();
        agent
            .create_agent_and_load(&json, true, Some("pq2025"))
            .unwrap();

        // Temp dir should still be empty
        let entries: Vec<_> = std::fs::read_dir(&temp).unwrap().collect();
        assert!(
            entries.is_empty(),
            "Ephemeral agent should not create files"
        );
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[cfg(feature = "pq-tests")]
    #[test]
    #[serial_test::serial(jacs_env)]
    fn test_ephemeral_pq2025() {
        let mut agent = Agent::ephemeral("pq2025").unwrap();
        let json = make_agent_json();
        let result = agent.create_agent_and_load(&json, true, Some("pq2025"));
        assert!(
            result.is_ok(),
            "pq2025 ephemeral agent failed: {:?}",
            result.err()
        );
    }

    // =========================================================================
    // Config signing / verification / update
    // =========================================================================

    fn make_config_json() -> serde_json::Value {
        serde_json::json!({
            "jacs_data_directory": "/data",
            "jacs_key_directory": "/keys",
            "jacs_agent_private_key_filename": "priv.pem",
            "jacs_agent_public_key_filename": "pub.pem",
            "jacs_agent_key_algorithm": "ring-Ed25519",
            "jacs_default_storage": "fs",
            "agent_email": "bot@hai.ai"
        })
    }

    fn ready_ephemeral_agent() -> Agent {
        let mut agent = Agent::ephemeral("pq2025").unwrap();
        let json = make_agent_json();
        agent
            .create_agent_and_load(&json, true, Some("pq2025"))
            .unwrap();
        agent
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn test_sign_config_produces_header_fields() {
        let mut agent = ready_ephemeral_agent();
        let config = make_config_json();
        let signed = agent.sign_config(&config).expect("sign_config");

        assert!(signed.get("jacsId").is_some(), "must have jacsId");
        assert!(signed.get("jacsVersion").is_some(), "must have jacsVersion");
        assert!(
            signed.get("jacsSignature").is_some(),
            "must have jacsSignature"
        );
        assert!(signed.get("jacsSha256").is_some(), "must have jacsSha256");
        assert_eq!(signed["jacsType"].as_str().unwrap(), "config");
        assert_eq!(signed["jacsLevel"].as_str().unwrap(), "config");
        assert_eq!(
            signed["agent_email"].as_str().unwrap(),
            "bot@hai.ai",
            "original config field preserved"
        );
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn test_verify_config_valid() {
        let mut agent = ready_ephemeral_agent();
        let signed = agent.sign_config(&make_config_json()).unwrap();
        agent
            .verify_config(&signed)
            .expect("valid config must verify");
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn test_verify_config_detects_tampering() {
        let mut agent = ready_ephemeral_agent();
        let mut signed = agent.sign_config(&make_config_json()).unwrap();
        signed["agent_email"] = json!("evil@attacker.com");
        let result = agent.verify_config(&signed);
        assert!(result.is_err(), "tampered config must fail verification");
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn test_update_config_bumps_version() {
        let mut agent = ready_ephemeral_agent();
        let signed_v1 = agent.sign_config(&make_config_json()).unwrap();
        let v1_id = signed_v1["jacsId"].as_str().unwrap().to_string();
        let v1_version = signed_v1["jacsVersion"].as_str().unwrap().to_string();

        let mut modified = signed_v1.clone();
        modified["agent_email"] = json!("new@hai.ai");

        let signed_v2 = agent.update_config(&modified).expect("update_config");

        assert_eq!(
            signed_v2["jacsId"].as_str().unwrap(),
            v1_id,
            "jacsId must be preserved"
        );
        assert_ne!(
            signed_v2["jacsVersion"].as_str().unwrap(),
            v1_version,
            "jacsVersion must change"
        );
        assert_eq!(
            signed_v2["jacsPreviousVersion"].as_str().unwrap(),
            v1_version,
            "must record previous version"
        );
        assert_eq!(signed_v2["agent_email"].as_str().unwrap(), "new@hai.ai");

        agent
            .verify_config(&signed_v2)
            .expect("updated config must verify");
    }

    #[test]
    #[serial_test::serial(jacs_env)]
    fn audit_previous_version_is_signed_and_tamperproof() {
        let mut agent = ready_ephemeral_agent();
        let signed_v1 = agent.sign_config(&make_config_json()).unwrap();
        let mut modified = signed_v1.clone();
        modified["agent_email"] = json!("new@hai.ai");
        let signed_v2 = agent.update_config(&modified).expect("update_config");

        // 1. Is jacsPreviousVersion in the signed fields list?
        let fields = signed_v2[AGENT_SIGNATURE_FIELDNAME]["fields"]
            .as_array()
            .unwrap();
        let field_names: Vec<&str> = fields.iter().filter_map(|f| f.as_str()).collect();
        println!("SIGNED FIELDS: {:?}", field_names);
        assert!(
            field_names.contains(&"jacsPreviousVersion"),
            "AUDIT: jacsPreviousVersion must be in the signed fields list"
        );

        // 2. Tamper with jacsPreviousVersion -> verification must fail.
        let mut tampered = signed_v2.clone();
        tampered["jacsPreviousVersion"] = json!("forged-previous-version-uuid");
        let result = agent.verify_config(&tampered);
        println!("TAMPER VERIFY RESULT: {:?}", result.is_err());
        assert!(
            result.is_err(),
            "AUDIT: tampering with jacsPreviousVersion must break verification"
        );
    }

    // SV-4: legacy v1 signature content (no signatureContentVersion) carries
    // unauthenticated metadata. It is refused by default; only an explicitly
    // scoped migration/compatibility operation may reach cryptographic verify.
    #[test]
    #[serial_test::serial(jacs_env)]
    fn legacy_v1_signature_content_default_reject_sv4() {
        let mut agent = ready_ephemeral_agent();
        let signed = agent.sign_config(&make_config_json()).unwrap();

        // Simulate a legacy v1 document by stripping the signatureContentVersion
        // marker from the signature object.
        let mut legacy = signed.clone();
        legacy[AGENT_SIGNATURE_FIELDNAME]
            .as_object_mut()
            .expect("signature object")
            .remove(SIGNATURE_CONTENT_VERSION_FIELDNAME);

        let public_key = agent.get_public_key().expect("public key");

        let rejected = agent.signature_verification_procedure(
            &legacy,
            None,
            AGENT_SIGNATURE_FIELDNAME,
            public_key.clone(),
            None,
            None,
            None,
        );
        let err = rejected.expect_err("default mode must refuse legacy v1 signature content");
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("legacy v1") || msg.contains("Refusing to verify legacy"),
            "default rejection must explain the v1 gate, got: {msg}"
        );

        // Explicit migration scope reaches cryptographic verification. This
        // fixture was originally signed as v2, so stripping the marker makes
        // the legacy payload differ and the signature should then fail for the
        // cryptographic reason rather than the policy gate.
        let compatibility_result = with_legacy_signature_migration_scope(|| {
            agent.signature_verification_procedure(
                &legacy,
                None,
                AGENT_SIGNATURE_FIELDNAME,
                public_key,
                None,
                None,
                None,
            )
        });
        let compatibility_err =
            compatibility_result.expect_err("stripped v2 signature must not verify as v1");
        assert!(
            !format!("{compatibility_err:?}").contains("Refusing to verify legacy"),
            "explicit migration scope must bypass only the policy gate"
        );
    }

    // SEC-3: the agent-scoped private-key password must never appear in Debug
    // output (panic backtraces, downstream {:?} logging).
    #[test]
    fn agent_debug_redacts_password_sec3() {
        let mut agent = Agent::ephemeral("pq2025").unwrap();
        agent.set_password(Some("AgentSecretPw123!".to_string()));
        let dbg = format!("{:?}", agent);
        assert!(
            !dbg.contains("AgentSecretPw123!"),
            "Agent Debug leaked the private-key password: {dbg}"
        );
        assert!(
            dbg.contains("REDACTED"),
            "Agent Debug should show a redaction marker: {dbg}"
        );
    }
}
