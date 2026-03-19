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
use crate::crypt::hash::hash_public_key;
use crate::error::JacsError;
use crate::storage::MultiStorage;

use crate::config::{Config, load_config_12factor, load_config_12factor_optional};

use crate::crypt::private_key::ZeroizingVec;

use crate::crypt::KeyManager;
use crate::keystore::{FsEncryptedStore, KeyPaths, KeySpec, KeyStore};

#[cfg(not(target_arch = "wasm32"))]
use crate::dns::bootstrap::verify_registry_registration_sync;
use crate::dns::bootstrap::{pubkey_digest_hex, verify_pubkey_via_dns_or_embedded};
use crate::observability::convenience::{record_agent_operation, record_signature_verification};
use crate::schema::Schema;
use crate::schema::utils::{EmbeddedSchemaResolver, ValueExt};
use crate::time_utils;
use jsonschema::{Draft, Validator};
use loaders::FileLoader;
use serde_json::{Value, json, to_value};
use serde_json_canonicalizer::to_string as to_canonical_string;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::validation::are_valid_uuid_parts;
use secrecy::SecretBox;

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
pub const TASK_START_AGREEMENT_FIELDNAME: &str = "jacsStartAgreement";
pub const TASK_END_AGREEMENT_FIELDNAME: &str = "jacsEndAgreement";
pub const DOCUMENT_AGENT_SIGNATURE_FIELDNAME: &str = "jacsSignature";
pub const JACS_VERSION_FIELDNAME: &str = "jacsVersion";
pub const JACS_VERSION_DATE_FIELDNAME: &str = "jacsVersionDate";
pub const JACS_PREVIOUS_VERSION_FIELDNAME: &str = "jacsPreviousVersion";

// these fields are ignored when hashing
pub const JACS_IGNORE_FIELDS: [&str; 7] = [
    SHA256_FIELDNAME,
    AGENT_SIGNATURE_FIELDNAME,
    DOCUMENT_AGENT_SIGNATURE_FIELDNAME,
    AGENT_AGREEMENT_FIELDNAME,
    AGENT_REGISTRATION_SIGNATURE_FIELDNAME,
    TASK_START_AGREEMENT_FIELDNAME,
    TASK_END_AGREEMENT_FIELDNAME,
];

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
    let canonical = to_canonical_string(value)
        .map_err(|e| std::io::Error::other(format!("Failed to canonicalize JSON: {}", e)))?;
    Ok(canonical)
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
        }
        .into());
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
        }
        .into());
    }

    time_utils::validate_signature_iat(iat)?;
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

// Just use Vec<u8> directly since it already implements the needed traits
pub type PrivateKey = Vec<u8>;
pub type SecretPrivateKey = SecretBox<Vec<u8>>;

/// Decrypt a private key using an agent-scoped password if available.
pub(crate) fn decrypt_with_agent_password(
    key: &[u8],
    password: Option<&str>,
) -> Result<ZeroizingVec, JacsError> {
    let resolved = crate::crypt::aes_encrypt::resolve_private_key_password(password)?;
    crate::crypt::aes_encrypt::decrypt_private_key_secure_with_password(key, &resolved)
}

#[derive(Debug)]
pub struct Agent {
    /// the JSONSchema used
    /// todo use getter
    pub schema: Schema,
    /// the agent JSON Struct
    /// TODO make this threadsafe
    value: Option<Value>,
    /// use getter
    pub config: Option<Config>,
    //  todo make read commands public but not write commands
    storage: MultiStorage,
    /// custom schemas that can be loaded to check documents
    /// the resolver might ahve trouble TEST
    document_schemas: Arc<Mutex<HashMap<String, Validator>>>,
    /// everything needed for the agent to sign things
    id: Option<String>,
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
    /// Evidence adapters for attestation (gated behind `attestation` feature).
    #[cfg(feature = "attestation")]
    pub adapters: Vec<Box<dyn crate::attestation::adapters::EvidenceAdapter>>,
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
        let key_paths = config.as_ref().map(Self::key_paths_from_config);
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
            #[cfg(feature = "attestation")]
            adapters: crate::attestation::adapters::default_adapters(),
        })
    }

    /// Create an ephemeral agent with in-memory keys and storage.
    /// No config file, no directories, no environment variables needed.
    pub fn ephemeral(algorithm: &str) -> Result<Self, JacsError> {
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
            #[cfg(feature = "attestation")]
            adapters: crate::attestation::adapters::default_adapters(),
        })
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
    fn key_paths_from_config(c: &Config) -> KeyPaths {
        KeyPaths {
            key_directory: c
                .jacs_key_directory()
                .clone()
                .unwrap_or_else(|| "./jacs_keys".to_string()),
            private_key_filename: c
                .jacs_agent_private_key_filename()
                .clone()
                .unwrap_or_else(|| crate::simple::core::DEFAULT_PRIVATE_KEY_FILENAME.to_string()),
            public_key_filename: c
                .jacs_agent_public_key_filename()
                .clone()
                .unwrap_or_else(|| crate::simple::core::DEFAULT_PUBLIC_KEY_FILENAME.to_string()),
        }
    }

    /// Rebuild `self.key_paths` from `self.config`.
    ///
    /// Must be called after every `self.config = Some(...)` assignment so that
    /// `build_fs_store()` picks up the new key directory (Issue 012).
    fn refresh_key_paths_from_config(&mut self) {
        if let Some(ref c) = self.config {
            self.key_paths = Some(Self::key_paths_from_config(c));
        }
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
        crate::crypt::aes_encrypt::resolve_private_key_password(self.password.as_deref())
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

        self.config = Some(
            load_config_12factor_optional(Some(&default_config_path)).map_err(|e| {
                format!(
                    "load_by_id failed for agent '{}': Could not find or load configuration: {}",
                    lookup_id, e
                )
            })?,
        );
        self.refresh_key_paths_from_config();
        debug!("load_by_id config {:?}", self.config);

        let agent_string = self.fs_agent_load(&lookup_id).map_err(|e| {
            format!(
                "load_by_id failed for agent '{}': Could not load agent file: {}",
                lookup_id, e
            )
        })?;
        let result: Result<(), JacsError> = self.load(&agent_string).map_err(|e| {
            format!(
                "load_by_id failed for agent '{}': Agent validation or key loading failed: {}",
                lookup_id, e
            )
            .into()
        });

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
        // Clone values needed for error messages to avoid borrow conflicts
        let lookup_id: String = config
            .jacs_agent_id_and_version()
            .as_deref()
            .unwrap_or("")
            .to_string();
        let storage_type: String = config
            .jacs_default_storage()
            .as_deref()
            .unwrap_or("")
            .to_string();
        let uses_filesystem_paths = matches!(storage_type.as_str(), "fs" | "rusqlite" | "sqlite");
        let storage_root = if uses_filesystem_paths {
            let config_dir = std::path::Path::new(&path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let config_dir_absolute = if config_dir.is_absolute() {
                config_dir.to_path_buf()
            } else {
                std::env::current_dir()?.join(config_dir)
            };
            let normalize_path = |p: &std::path::Path| -> std::path::PathBuf {
                let mut normalized = std::path::PathBuf::new();
                for component in p.components() {
                    match component {
                        std::path::Component::CurDir => {}
                        std::path::Component::ParentDir => {
                            normalized.pop();
                        }
                        other => normalized.push(other.as_os_str()),
                    }
                }
                normalized
            };

            // Normalize configured filesystem directories.
            // - Relative directories are treated as config-dir relative.
            // - Absolute directories inside the config-dir root are rewritten
            //   to relative paths so storage can stay rooted at config_dir.
            // - Absolute directories outside config_dir require root "/".
            let mut config_value = to_value(&config).map_err(|e| {
                format!(
                    "load_by_config failed: Could not serialize configuration from '{}': {}",
                    path, e
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
                            "load_by_config failed: Config field '{}' in '{}' contains unsafe parent-directory segment ('..'): '{}'",
                            field, path, dir
                        )
                        .into());
                    }
                    if dir_path.is_absolute() {
                        let normalized_abs = normalize_path(dir_path);
                        if let Ok(relative_tail) = normalized_abs.strip_prefix(&config_dir_absolute)
                        {
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
                            config_value[field] =
                                json!(normalized_abs.to_string_lossy().to_string());
                        }
                    } else {
                        let normalized_rel = normalize_path(dir_path);
                        config_value[field] = json!(normalized_rel.to_string_lossy().to_string());
                    }
                }
            }

            let storage_root = if has_external_absolute {
                // When rooting at "/", convert any remaining relative dirs to
                // absolute config-dir-based paths so they remain stable.
                for field in ["jacs_data_directory", "jacs_key_directory"] {
                    if let Some(dir) = config_value.get(field).and_then(|v| v.as_str()) {
                        let dir_path = std::path::Path::new(dir);
                        if !dir_path.is_absolute() {
                            let abs = normalize_path(&config_dir_absolute.join(dir_path));
                            config_value[field] = json!(abs.to_string_lossy().to_string());
                        }
                    }
                }
                std::path::PathBuf::from("/")
            } else {
                config_dir_absolute
            };

            config = serde_json::from_value(config_value).map_err(|e| {
                format!(
                    "load_by_config failed: Could not normalize filesystem directories in config '{}': {}",
                    path, e
                )
            })?;
            storage_root
        } else {
            std::env::current_dir()?
        };

        self.config = Some(config);
        // Refresh key_paths from the new config so build_fs_store() uses the
        // correct key directory, not stale paths from construction time (Issue 012).
        self.refresh_key_paths_from_config();
        let file_storage_type = if matches!(storage_type.as_str(), "rusqlite" | "sqlite") {
            "fs".to_string()
        } else {
            storage_type.clone()
        };
        self.storage = MultiStorage::_new(file_storage_type, storage_root).map_err(|e| {
            format!(
                "load_by_config failed: Could not initialize storage type '{}' (from config '{}'): {}",
                storage_type, path, e
            )
        })?;
        if !lookup_id.is_empty() {
            let agent_string = self.fs_agent_load(&lookup_id).map_err(|e| {
                format!(
                    "load_by_config failed: Could not load agent '{}' (specified in config '{}'): {}",
                    lookup_id, path, e
                )
            })?;
            self.load(&agent_string).map_err(|e| {
                let err_msg = format!(
                    "load_by_config failed: Agent '{}' validation or key loading failed (config '{}'): {}",
                    lookup_id, path, e
                );
                JacsError::Internal { message: err_msg }
            })
        } else {
            Ok(())
        }
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
        let lookup_id: String = config
            .jacs_agent_id_and_version()
            .as_deref()
            .unwrap_or("")
            .to_string();
        let storage_type: String = config
            .jacs_default_storage()
            .as_deref()
            .unwrap_or("")
            .to_string();
        let uses_filesystem_paths = matches!(storage_type.as_str(), "fs" | "rusqlite" | "sqlite");
        let storage_root = if uses_filesystem_paths {
            let config_dir = std::path::Path::new(&path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let config_dir_absolute = if config_dir.is_absolute() {
                config_dir.to_path_buf()
            } else {
                std::env::current_dir()?.join(config_dir)
            };
            let normalize_path = |p: &std::path::Path| -> std::path::PathBuf {
                let mut normalized = std::path::PathBuf::new();
                for component in p.components() {
                    match component {
                        std::path::Component::CurDir => {}
                        std::path::Component::ParentDir => {
                            normalized.pop();
                        }
                        other => normalized.push(other.as_os_str()),
                    }
                }
                normalized
            };

            let mut config_value = to_value(&config).map_err(|e| {
                format!(
                    "load_by_config_file_only failed: Could not serialize configuration from '{}': {}",
                    path, e
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
                            "load_by_config_file_only failed: Config field '{}' in '{}' contains unsafe parent-directory segment ('..'): '{}'",
                            field, path, dir
                        )
                        .into());
                    }
                    if dir_path.is_absolute() {
                        let normalized_abs = normalize_path(dir_path);
                        if let Ok(relative_tail) = normalized_abs.strip_prefix(&config_dir_absolute)
                        {
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
                            config_value[field] =
                                json!(normalized_abs.to_string_lossy().to_string());
                        }
                    } else {
                        let normalized_rel = normalize_path(dir_path);
                        config_value[field] = json!(normalized_rel.to_string_lossy().to_string());
                    }
                }
            }

            let storage_root = if has_external_absolute {
                for field in ["jacs_data_directory", "jacs_key_directory"] {
                    if let Some(dir) = config_value.get(field).and_then(|v| v.as_str()) {
                        let dir_path = std::path::Path::new(dir);
                        if !dir_path.is_absolute() {
                            let abs = normalize_path(&config_dir_absolute.join(dir_path));
                            config_value[field] = json!(abs.to_string_lossy().to_string());
                        }
                    }
                }
                std::path::PathBuf::from("/")
            } else {
                config_dir_absolute
            };

            config = serde_json::from_value(config_value).map_err(|e| {
                format!(
                    "load_by_config_file_only failed: Could not normalize filesystem directories in config '{}': {}",
                    path, e
                )
            })?;
            storage_root
        } else {
            std::env::current_dir()?
        };

        self.config = Some(config);
        self.refresh_key_paths_from_config();
        let file_storage_type = if matches!(storage_type.as_str(), "rusqlite" | "sqlite") {
            "fs".to_string()
        } else {
            storage_type.clone()
        };
        self.storage = MultiStorage::_new(file_storage_type, storage_root).map_err(|e| {
            format!(
                "load_by_config_file_only failed: Could not initialize storage type '{}' (from config '{}'): {}",
                storage_type, path, e
            )
        })?;
        if !lookup_id.is_empty() {
            let agent_string = self.fs_agent_load(&lookup_id).map_err(|e| {
                format!(
                    "load_by_config_file_only failed: Could not load agent '{}' (specified in config '{}'): {}",
                    lookup_id, path, e
                )
            })?;
            self.load(&agent_string).map_err(|e| {
                let err_msg = format!(
                    "load_by_config_file_only failed: Agent '{}' validation or key loading failed (config '{}'): {}",
                    lookup_id, path, e
                );
                JacsError::Internal { message: err_msg }
            })
        } else {
            Ok(())
        }
    }

    /// Replace the internal storage with a pre-configured [`MultiStorage`].
    ///
    /// This allows callers to inject a custom storage backend (e.g., in-memory
    /// for testing, or a pre-configured filesystem backend with a specific root).
    ///
    /// # Example
    ///
    /// ```rust,ignore
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
        let file_storage_type = if matches!(storage_type.as_str(), "rusqlite" | "sqlite") {
            "fs".to_string()
        } else {
            storage_type
        };
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
        let resolved_pw =
            crate::crypt::aes_encrypt::resolve_private_key_password(self.password.as_deref())?;
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
                }.into())
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
                ))
                .into());
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

        let public_key_hash: String = match original_public_key_hash {
            Some(orig) => orig,
            _ => json_value[signature_key_from]["publicKeyHash"]
                .as_str()
                .unwrap_or("")
                .trim_matches('"')
                .to_string(),
        };

        // Prefer explicit signingAlgorithm from function argument, then from the
        // document signature. Only fall back to key-format heuristics when absent.
        let resolved_public_key_enc_type = public_key_enc_type.or_else(|| {
            json_value[signature_key_from]["signingAlgorithm"]
                .as_str()
                .map(std::string::ToString::to_string)
        });

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
                    }
                    .into());
                }
                // For verified claims: validate=true, strict=true, required=true
                (true, true, true)
            }
            _ => {
                // Unverified or missing claim: use existing defaults (presence of domain)
                let validate = self.dns_validate_enabled.unwrap_or(domain_present);
                let strict = self.dns_strict;
                let required = self.dns_required.unwrap_or(domain_present);
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
                    &agent_id_for_dns,
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

            match verify_registry_registration_sync(&agent_id_for_registry, &pk_hash) {
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
        let (document_values_string, _) = build_signature_content(
            json_value,
            resolved_fields.clone(),
            signature_key_from,
            SignatureContentMode::CanonicalV2,
        )?;
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
        let (document_values_string, accepted_fields) =
            Agent::get_values_as_string(json_value, fields.map(|s| s.to_vec()), placement_key)?;
        debug!(
            "signing_procedure document_values_string:\n\n{}\n\n",
            document_values_string
        );
        let signature = self.sign_string(&document_values_string)?;
        debug!("signing_procedure created signature :\n{}", signature);
        let binding = String::new();
        let agent_id = self.id.as_ref().unwrap_or(&binding);
        let agent_version = self.version.as_ref().unwrap_or(&binding);
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

        let serialized_fields = match to_value(accepted_fields) {
            Ok(value) => value,
            Err(err) => return Err(err.into()),
        };
        let public_key = self.get_public_key()?;
        let public_key_hash = hash_public_key(&public_key);
        debug!("hash {:?} ", public_key_hash);
        //TODO fields must never include sha256 at top level
        // error
        let signature_document = json!({
            // based on v1
            "agentID": agent_id,
            "agentVersion": agent_version,
            "date": date,
            "iat": iat,
            "jti": jti,
            "signature":signature,
            "signingAlgorithm":signing_algorithm,
            "publicKeyHash": public_key_hash,
            "fields": serialized_fields
        });
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
            ))
            .into());
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
            }
            .into());
        }

        // validate schema
        let new_version = Uuid::new_v4().to_string();
        let last_version = &original_self["jacsVersion"];
        let versioncreated = time_utils::now_rfc3339();

        new_self["jacsPreviousVersion"] = last_version.clone();
        new_self["jacsVersion"] = json!(format!("{}", new_version));
        new_self["jacsVersionDate"] = json!(format!("{}", versioncreated));

        // generate new keys?
        // sign new version
        new_self[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&new_self, None, AGENT_SIGNATURE_FIELDNAME)?;
        // hash new version
        let document_hash = self.hash_doc(&new_self)?;
        new_self[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
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
    ///
    /// Returns `(new_version, new_public_key_bytes, signed_agent_json)`.
    pub fn rotate_self(&mut self) -> Result<(String, Vec<u8>, Value), JacsError> {
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

        // Determine key algorithm
        let key_algorithm = {
            let config = self.config.as_ref().ok_or("Agent config not initialized")?;
            config.get_key_algorithm()?
        };

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

        // Set new keys on the agent
        if self.ephemeral {
            self.set_keys_raw(new_private_key, new_public_key.clone(), &key_algorithm);
        } else {
            self.set_keys(new_private_key, new_public_key.clone(), &key_algorithm)?;
        }

        // Build new version document
        let new_version = Uuid::new_v4().to_string();
        let version_date = time_utils::now_rfc3339();

        let mut new_doc = original_value.clone();
        new_doc["jacsPreviousVersion"] = json!(old_version);
        new_doc["jacsVersion"] = json!(new_version.clone());
        new_doc["jacsVersionDate"] = json!(version_date);

        // Remove old signature and hash — they will be regenerated with new key
        if let Some(obj) = new_doc.as_object_mut() {
            obj.remove(AGENT_SIGNATURE_FIELDNAME);
            obj.remove(SHA256_FIELDNAME);
        }

        // Sign with the new key
        new_doc[AGENT_SIGNATURE_FIELDNAME] =
            self.signing_procedure(&new_doc, None, AGENT_SIGNATURE_FIELDNAME)?;
        let document_hash = self.hash_doc(&new_doc)?;
        new_doc[SHA256_FIELDNAME] = json!(format!("{}", document_hash));

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
                let algo = {
                    let config = self.config.as_ref().ok_or("Agent config not initialized")?;
                    config.get_key_algorithm()?
                };
                let spec = KeySpec {
                    algorithm: algo.clone(),
                    key_id: None,
                };
                let (private_key, public_key) = ks.generate(&spec)?;
                self.set_keys_raw(private_key, public_key, &algo);
            } else {
                self.generate_keys()?;
            }
        }
        if !self.ephemeral && (self.public_key.is_none() || self.private_key.is_none()) {
            self.fs_load_keys()?;
        }

        // Save public key hash — skip for ephemeral (no filesystem)
        if !self.ephemeral {
            if let (Some(public_key), Some(key_algorithm)) = (&self.public_key, &self.key_algorithm)
            {
                let public_key_hash = hash_public_key(public_key);
                let _ = self.fs_save_remote_public_key(
                    &public_key_hash,
                    public_key,
                    key_algorithm.as_bytes(),
                );
            }
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
        instance[SHA256_FIELDNAME] = json!(format!("{}", document_hash));
        self.value = Some(instance.clone());
        self.verify_self_signature()?;
        Ok(instance)
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
    ///   - `algorithm`: Optional algorithm hint (e.g., "ring-Ed25519", "RSA-PSS")
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

        // Initialize storage
        let storage = MultiStorage::default_new()
            .map_err(|e| JacsError::ConfigError(format!("Failed to initialize storage: {}", e)))?;

        let document_schemas = Arc::new(Mutex::new(HashMap::new()));

        // Build key paths from config
        let key_paths = config.as_ref().map(Agent::key_paths_from_config);

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
        let agent = Agent::ephemeral("ring-Ed25519").unwrap();
        assert!(agent.is_ephemeral());
        assert!(agent.config.is_some());
        // No files should be created — config is in-memory
    }

    #[test]
    fn test_ephemeral_creates_without_env_vars() {
        // No JACS_KEY_DIRECTORY or JACS_PRIVATE_KEY_PASSWORD needed
        let agent = Agent::ephemeral("ring-Ed25519").unwrap();
        assert!(agent.is_ephemeral());
    }

    #[test]
    fn test_ephemeral_create_agent_and_load() {
        let mut agent = Agent::ephemeral("ring-Ed25519").unwrap();
        let json = make_agent_json();
        let result = agent.create_agent_and_load(&json, true, Some("ring-Ed25519"));
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
    fn test_ephemeral_sign_and_verify_round_trip() {
        use crate::agent::document::DocumentTraits;

        let mut agent = Agent::ephemeral("ring-Ed25519").unwrap();
        let json = make_agent_json();
        agent
            .create_agent_and_load(&json, true, Some("ring-Ed25519"))
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
    fn test_ephemeral_agent_is_ready() {
        let mut agent = Agent::ephemeral("ring-Ed25519").unwrap();
        let json = make_agent_json();
        agent
            .create_agent_and_load(&json, true, Some("ring-Ed25519"))
            .unwrap();
        assert!(
            agent.ready(),
            "Ephemeral agent should be ready after create_agent_and_load"
        );
    }

    #[test]
    fn test_ephemeral_no_files_on_disk() {
        let temp = std::env::temp_dir().join("jacs_ephemeral_test_no_files");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();

        let mut agent = Agent::ephemeral("ring-Ed25519").unwrap();
        let json = make_agent_json();
        agent
            .create_agent_and_load(&json, true, Some("ring-Ed25519"))
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
}
