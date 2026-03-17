//! Core `SimpleAgent` definition and narrow contract methods.
//!
//! This module contains the `SimpleAgent` struct and the 19 methods that form
//! the narrow public API contract (Section 4.1.2 of `ARCHITECTURE_UPGRADE.md`).
//!
//! Advanced methods (agreements, A2A, attestation, batch, agent management)
//! live in sibling modules: [`super::advanced`], [`super::batch`], etc.

use crate::agent::Agent;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::DocumentTraits;
use crate::create_minimal_blank_agent;
use crate::error::JacsError;
use crate::mime::mime_from_extension;
use crate::schema::utils::{ValueExt, check_document_size};
use serde_json::{Value, json};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use tracing::{debug, info, warn};

use super::types::*;

// =============================================================================
// Constants (pub(crate) so advanced methods in mod.rs can also use them)
// =============================================================================

pub(crate) const DEFAULT_PRIVATE_KEY_FILENAME: &str = "jacs.private.pem.enc";
pub(crate) const DEFAULT_PUBLIC_KEY_FILENAME: &str = "jacs.public.pem";

// =============================================================================
// Helper Functions
// =============================================================================

pub(crate) fn build_agent_document(
    agent_type: &str,
    name: &str,
    description: &str,
) -> Result<Value, JacsError> {
    let template =
        create_minimal_blank_agent(agent_type.to_string(), None, None, None).map_err(|e| {
            JacsError::Internal {
                message: format!("Failed to create minimal agent template: {}", e),
            }
        })?;

    let mut agent_json: Value =
        serde_json::from_str(&template).map_err(|e| JacsError::Internal {
            message: format!("Failed to parse minimal agent template JSON: {}", e),
        })?;

    let obj = agent_json
        .as_object_mut()
        .ok_or_else(|| JacsError::Internal {
            message: "Generated minimal agent template is not a JSON object".to_string(),
        })?;

    obj.insert("name".to_string(), json!(name));
    obj.insert("description".to_string(), json!(description));
    Ok(agent_json)
}

/// Write .gitignore and .dockerignore in the key directory to prevent
/// accidental exposure of private keys and password files.
pub(crate) fn write_key_directory_ignore_files(key_dir: &Path) {
    let ignore_content = "# JACS private key material — do NOT commit or ship\n\
        *.pem\n\
        *.pem.enc\n\
        .jacs_password\n\
        *.key\n\
        *.key.enc\n";

    let gitignore_path = key_dir.join(".gitignore");
    if !gitignore_path.exists() {
        if let Err(e) = std::fs::write(&gitignore_path, ignore_content) {
            warn!("Could not write {}: {}", gitignore_path.display(), e);
        }
    }

    let dockerignore_path = key_dir.join(".dockerignore");
    if !dockerignore_path.exists() {
        if let Err(e) = std::fs::write(&dockerignore_path, ignore_content) {
            warn!("Could not write {}: {}", dockerignore_path.display(), e);
        }
    }
}

/// Resolve strict mode: explicit parameter wins, then env var, then false.
pub(crate) fn resolve_strict(explicit: Option<bool>) -> bool {
    if let Some(s) = explicit {
        return s;
    }
    std::env::var("JACS_STRICT_MODE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Mutex to prevent concurrent environment variable stomping during creation.
pub(crate) static CREATE_MUTEX: Mutex<()> = Mutex::new(());

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn resolve_config_relative_path(config_path: &Path, candidate: &str) -> PathBuf {
    let candidate_path = Path::new(candidate);
    if candidate_path.is_absolute() {
        normalize_path(candidate_path)
    } else {
        let config_dir = config_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        normalize_path(&config_dir.join(candidate_path))
    }
}

/// Build canonical `AgentInfo` for an agent that has already been loaded.
///
/// The returned filesystem paths are resolved against the config file location
/// so higher-level wrappers do not need to reopen the config to rebuild
/// metadata.
pub fn build_loaded_agent_info(
    agent: &crate::agent::Agent,
    config_path: &str,
) -> Result<AgentInfo, JacsError> {
    let resolved_config_path = if Path::new(config_path).is_absolute() {
        normalize_path(Path::new(config_path))
    } else {
        normalize_path(&std::env::current_dir()?.join(config_path))
    };

    let agent_value = agent
        .get_value()
        .cloned()
        .ok_or(JacsError::AgentNotLoaded)?;
    let config = agent.config.as_ref();

    let key_directory = resolve_config_relative_path(
        &resolved_config_path,
        config
            .and_then(|cfg| cfg.jacs_key_directory().as_deref())
            .unwrap_or("./jacs_keys"),
    );
    let data_directory = resolve_config_relative_path(
        &resolved_config_path,
        config
            .and_then(|cfg| cfg.jacs_data_directory().as_deref())
            .unwrap_or("./jacs_data"),
    );
    let public_key_filename = config
        .and_then(|cfg| cfg.jacs_agent_public_key_filename().as_deref())
        .unwrap_or(DEFAULT_PUBLIC_KEY_FILENAME);
    let private_key_filename = config
        .and_then(|cfg| cfg.jacs_agent_private_key_filename().as_deref())
        .unwrap_or(DEFAULT_PRIVATE_KEY_FILENAME);

    Ok(AgentInfo {
        agent_id: agent_value["jacsId"].as_str().unwrap_or("").to_string(),
        name: agent_value["name"].as_str().unwrap_or("").to_string(),
        public_key_path: key_directory
            .join(public_key_filename)
            .to_string_lossy()
            .into_owned(),
        config_path: resolved_config_path.to_string_lossy().into_owned(),
        version: agent_value["jacsVersion"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        algorithm: config
            .and_then(|cfg| cfg.jacs_agent_key_algorithm().as_deref())
            .unwrap_or("")
            .to_string(),
        private_key_path: key_directory
            .join(private_key_filename)
            .to_string_lossy()
            .into_owned(),
        data_directory: data_directory.to_string_lossy().into_owned(),
        key_directory: key_directory.to_string_lossy().into_owned(),
        domain: agent_value
            .get("jacsAgentDomain")
            .and_then(|v| v.as_str())
            .or_else(|| agent_value.get("domain").and_then(|v| v.as_str()))
            .or_else(|| config.and_then(|cfg| cfg.jacs_agent_domain().as_deref()))
            .unwrap_or("")
            .to_string(),
        dns_record: String::new(),
    })
}

/// Extracts file attachments from a JACS document.
pub(crate) fn extract_attachments(doc: &Value) -> Vec<Attachment> {
    let mut attachments = Vec::new();

    if let Some(files) = doc.get("jacsFiles").and_then(|f| f.as_array()) {
        for file in files {
            let filename = file["path"].as_str().unwrap_or("unknown").to_string();
            let mime_type = file["mimetype"]
                .as_str()
                .unwrap_or("application/octet-stream")
                .to_string();
            let hash = file["sha256"].as_str().unwrap_or("").to_string();
            let embedded = file["embed"].as_bool().unwrap_or(false);

            let content = if embedded {
                if let Some(contents_b64) = file["contents"].as_str() {
                    use base64::{Engine as _, engine::general_purpose::STANDARD};
                    STANDARD.decode(contents_b64).unwrap_or_default()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            attachments.push(Attachment {
                filename,
                mime_type,
                content,
                hash,
                embedded,
            });
        }
    }

    attachments
}

// =============================================================================
// SimpleAgent - Instance-based API (Recommended)
// =============================================================================

/// A wrapper around the JACS Agent that provides a simplified, instance-based API.
///
/// This struct owns an Agent instance and provides methods for common operations
/// like signing and verification. Unlike the deprecated module-level functions,
/// `SimpleAgent` does not use global mutable state, making it thread-safe when
/// used with appropriate synchronization.
///
/// # Narrow Contract (19 methods)
///
/// These are the ONLY public methods on `SimpleAgent`. This list is the
/// single source of truth (Section 4.1.2 of `ARCHITECTURE_UPGRADE.md`).
/// Advanced operations live in [`super::advanced`], [`super::batch`], etc.
///
/// | # | Method | Purpose |
/// |---|--------|---------|
/// | 1 | [`create`](Self::create) | Create agent with defaults |
/// | 2 | [`create_with_params`](Self::create_with_params) | Create agent with full control |
/// | 3 | [`load`](Self::load) | Load existing agent from disk |
/// | 4 | [`ephemeral`](Self::ephemeral) | Create throwaway agent (no disk) |
/// | 5 | [`verify_self`](Self::verify_self) | Verify own agent document signature |
/// | 6 | [`sign_message`](Self::sign_message) | Sign a JSON value |
/// | 7 | [`sign_raw_bytes`](Self::sign_raw_bytes) | Sign raw byte data |
/// | 8 | [`sign_file`](Self::sign_file) | Sign a file |
/// | 9 | [`verify`](Self::verify) | Verify a signed document string |
/// | 10 | [`verify_with_key`](Self::verify_with_key) | Verify with explicit public key |
/// | 11 | [`verify_by_id`](Self::verify_by_id) | Verify a stored document by ID |
/// | 12 | [`export_agent`](Self::export_agent) | Export agent identity JSON |
/// | 13 | [`get_public_key`](Self::get_public_key) | Get public key as raw bytes |
/// | 14 | [`get_public_key_pem`](Self::get_public_key_pem) | Get public key as PEM string |
/// | 15 | [`get_agent_id`](Self::get_agent_id) | Get agent ID |
/// | 16 | [`key_id`](Self::key_id) | Get key ID |
/// | 17 | [`diagnostics`](Self::diagnostics) | Runtime diagnostic info |
/// | 18 | [`is_strict`](Self::is_strict) | Check strict mode |
/// | 19 | [`config_path`](Self::config_path) | Get config file path |
///
/// # Thread Safety
///
/// `SimpleAgent` uses interior mutability via `Mutex` to allow safe concurrent
/// access to the underlying Agent. Multiple threads can share a `SimpleAgent`
/// wrapped in an `Arc`.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use std::sync::Arc;
///
/// // Create and share across threads
/// let agent = Arc::new(SimpleAgent::create("my-agent", None, None)?);
///
/// let agent_clone = Arc::clone(&agent);
/// std::thread::spawn(move || {
///     let signed = agent_clone.sign_message(&serde_json::json!({"thread": 1})).unwrap();
/// });
/// ```
pub struct SimpleAgent {
    pub(crate) agent: Mutex<Agent>,
    pub(crate) config_path: Option<String>,
    /// When true, verification failures return `Err` instead of `Ok(valid=false)`.
    /// Resolved from explicit param > `JACS_STRICT_MODE` env var > false.
    pub(crate) strict: bool,
}

// =============================================================================
// Narrow Contract Methods (19 total -- see doc comment on SimpleAgent)
// =============================================================================

impl SimpleAgent {
    /// Returns whether this agent is in strict mode.
    pub fn is_strict(&self) -> bool {
        self.strict
    }

    /// Returns the JACS agent ID, used as the signing key identifier.
    /// Derived from the underlying Agent — no cached copy needed.
    pub fn key_id(&self) -> Result<String, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        Ok(agent.get_id().unwrap_or_default())
    }

    /// Creates a new JACS agent with persistent identity.
    ///
    /// This generates cryptographic keys, creates configuration files, and saves
    /// them to the current working directory.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for the agent
    /// * `purpose` - Optional description of the agent's purpose
    /// * `key_algorithm` - Signing algorithm: "pq2025" (default), "ed25519", or "rsa-pss"
    ///
    /// # Returns
    ///
    /// A `SimpleAgent` instance ready for use, along with `AgentInfo` containing
    /// the agent ID, name, and file paths.
    ///
    /// # Files Created
    ///
    /// * `./jacs.config.json` - Configuration file
    /// * `./jacs.agent.json` - Signed agent identity (in jacs_data/agent/)
    /// * `./jacs_keys/` - Directory containing public and private keys
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::create("my-agent", Some("Signing documents"), None)?;
    /// println!("Agent created successfully");
    /// ```
    #[must_use = "agent creation result must be checked for errors"]
    pub fn create(
        name: &str,
        purpose: Option<&str>,
        key_algorithm: Option<&str>,
    ) -> Result<(Self, AgentInfo), JacsError> {
        // Delegate to create_with_params() to avoid duplicated initialization logic.
        // Uses default paths (./jacs_data, ./jacs_keys, ./jacs.config.json) and
        // falls back to JACS_PRIVATE_KEY_PASSWORD env var for the password.
        let mut builder = CreateAgentParams::builder().name(name);

        if let Some(desc) = purpose {
            builder = builder.description(desc);
        }

        if let Some(algo) = key_algorithm {
            builder = builder.algorithm(algo);
        }

        Self::create_with_params(builder.build())
    }

    /// Creates a new JACS agent with full programmatic control.
    ///
    /// Unlike `create()`, this method accepts all parameters explicitly, making it
    /// suitable for non-interactive use from bindings and automation.
    ///
    /// # Arguments
    ///
    /// * `params` - `CreateAgentParams` with all creation parameters
    ///
    /// # Returns
    ///
    /// A `SimpleAgent` instance and `AgentInfo` with the created agent's details.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::{SimpleAgent, CreateAgentParams};
    ///
    /// let params = CreateAgentParams::builder()
    ///     .name("my-agent")
    ///     .password("MyStr0ng!Pass#2024")
    ///     .algorithm("pq2025")
    ///     .data_directory("/tmp/test_data")
    ///     .key_directory("/tmp/test_keys")
    ///     .config_path("/tmp/test.config.json")
    ///     .build();
    ///
    /// let (agent, info) = SimpleAgent::create_with_params(params)?;
    /// ```
    #[must_use = "agent creation result must be checked for errors"]
    pub fn create_with_params(params: CreateAgentParams) -> Result<(Self, AgentInfo), JacsError> {
        struct EnvRestoreGuard {
            previous: Vec<(String, Option<String>)>,
        }

        impl Drop for EnvRestoreGuard {
            fn drop(&mut self) {
                for (key, value) in &self.previous {
                    unsafe {
                        if let Some(v) = value {
                            std::env::set_var(key, v);
                        } else {
                            std::env::remove_var(key);
                        }
                    }
                }
            }
        }

        // Acquire creation mutex to prevent concurrent env var stomping
        let _lock = CREATE_MUTEX.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire creation lock: {}", e),
        })?;

        // Resolve password: params > env var > error
        let password = if !params.password.is_empty() {
            params.password.clone()
        } else {
            std::env::var("JACS_PRIVATE_KEY_PASSWORD").unwrap_or_default()
        };

        if password.is_empty() {
            return Err(JacsError::ConfigError(
                "Password is required for agent creation. \
                Either pass it in CreateAgentParams.password or set the JACS_PRIVATE_KEY_PASSWORD environment variable."
                    .to_string(),
            ));
        }

        let algorithm = if params.algorithm.is_empty() {
            "pq2025".to_string()
        } else {
            // Normalize user-friendly algorithm names to internal names,
            // matching ephemeral() and quickstart() behaviour.
            match params.algorithm.as_str() {
                "ed25519" => "ring-Ed25519".to_string(),
                "rsa-pss" => "RSA-PSS".to_string(),
                other => other.to_string(),
            }
        };

        info!(
            "Creating new agent '{}' with algorithm '{}' (programmatic)",
            params.name, algorithm
        );

        // Create directories (including agent/ and public_keys/ subdirs that save() expects)
        let keys_dir = Path::new(&params.key_directory);
        let data_dir = Path::new(&params.data_directory);

        fs::create_dir_all(keys_dir).map_err(|e| JacsError::DirectoryCreateFailed {
            path: keys_dir.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
        fs::create_dir_all(data_dir.join("agent")).map_err(|e| {
            JacsError::DirectoryCreateFailed {
                path: data_dir.join("agent").to_string_lossy().to_string(),
                reason: e.to_string(),
            }
        })?;
        fs::create_dir_all(data_dir.join("public_keys")).map_err(|e| {
            JacsError::DirectoryCreateFailed {
                path: data_dir.join("public_keys").to_string_lossy().to_string(),
                reason: e.to_string(),
            }
        })?;

        // Protect key directory from accidental git commits / Docker inclusion
        write_key_directory_ignore_files(keys_dir);

        let env_keys = [
            "JACS_PRIVATE_KEY_PASSWORD",
            "JACS_DATA_DIRECTORY",
            "JACS_KEY_DIRECTORY",
            "JACS_AGENT_KEY_ALGORITHM",
            "JACS_DEFAULT_STORAGE",
            "JACS_AGENT_PRIVATE_KEY_FILENAME",
            "JACS_AGENT_PUBLIC_KEY_FILENAME",
        ];
        let previous_env = env_keys
            .iter()
            .map(|k| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        let _env_restore_guard = EnvRestoreGuard {
            previous: previous_env,
        };

        // Set env vars for the keystore layer (within the mutex lock)
        // SAFETY: We hold CREATE_MUTEX, ensuring no concurrent env var access
        unsafe {
            std::env::set_var("JACS_PRIVATE_KEY_PASSWORD", &password);
            std::env::set_var("JACS_DATA_DIRECTORY", &params.data_directory);
            std::env::set_var("JACS_KEY_DIRECTORY", &params.key_directory);
            std::env::set_var("JACS_AGENT_KEY_ALGORITHM", &algorithm);
            std::env::set_var("JACS_DEFAULT_STORAGE", &params.default_storage);
            std::env::set_var(
                "JACS_AGENT_PRIVATE_KEY_FILENAME",
                DEFAULT_PRIVATE_KEY_FILENAME,
            );
            std::env::set_var(
                "JACS_AGENT_PUBLIC_KEY_FILENAME",
                DEFAULT_PUBLIC_KEY_FILENAME,
            );
        }

        // Create a minimal agent JSON
        let description = if params.description.is_empty() {
            "JACS agent".to_string()
        } else {
            params.description.clone()
        };

        let agent_json = build_agent_document(&params.agent_type, &params.name, &description)?;

        // Create the agent
        let mut agent = crate::get_empty_agent();

        let instance = agent
            .create_agent_and_load(&agent_json.to_string(), true, Some(&algorithm))
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to create agent: {}", e),
            })?;

        // Extract agent info
        let agent_id = instance["jacsId"].as_str().unwrap_or("unknown").to_string();
        let version = instance["jacsVersion"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        let lookup_id = format!("{}:{}", agent_id, version);

        // Resolve the config: if one already exists at config_path, read it
        // and only update the agent ID. Log differences between existing values
        // and params so the caller knows. If no config exists, create one fresh.
        let config_path = Path::new(&params.config_path);
        let config_str = if config_path.exists() {
            let existing_str =
                fs::read_to_string(config_path).map_err(|e| JacsError::Internal {
                    message: format!(
                        "Failed to read existing config '{}': {}",
                        params.config_path, e
                    ),
                })?;
            let mut existing: serde_json::Value =
                serde_json::from_str(&existing_str).map_err(|e| JacsError::Internal {
                    message: format!("Failed to parse existing config: {}", e),
                })?;

            // Log differences between existing config and params
            let check = |field: &str, existing_val: Option<&str>, param_val: &str| {
                if let Some(ev) = existing_val {
                    if ev != param_val {
                        warn!(
                            "Config '{}' differs: existing='{}', param='{}'. Keeping existing value.",
                            field, ev, param_val
                        );
                    }
                }
            };
            check(
                "jacs_data_directory",
                existing.get("jacs_data_directory").and_then(|v| v.as_str()),
                &params.data_directory,
            );
            check(
                "jacs_key_directory",
                existing.get("jacs_key_directory").and_then(|v| v.as_str()),
                &params.key_directory,
            );
            check(
                "jacs_agent_key_algorithm",
                existing
                    .get("jacs_agent_key_algorithm")
                    .and_then(|v| v.as_str()),
                &algorithm,
            );
            check(
                "jacs_default_storage",
                existing
                    .get("jacs_default_storage")
                    .and_then(|v| v.as_str()),
                &params.default_storage,
            );

            // Only update the agent ID (the new agent we just created)
            if let Some(obj) = existing.as_object_mut() {
                obj.insert("jacs_agent_id_and_version".to_string(), json!(lookup_id));
            }

            let updated_str =
                serde_json::to_string_pretty(&existing).map_err(|e| JacsError::Internal {
                    message: format!("Failed to serialize updated config: {}", e),
                })?;
            fs::write(config_path, &updated_str).map_err(|e| JacsError::Internal {
                message: format!("Failed to write config to '{}': {}", params.config_path, e),
            })?;
            info!(
                "Updated existing config '{}' with new agent ID {}",
                params.config_path, lookup_id
            );
            updated_str
        } else {
            // No config exists -- create config with all required fields
            let mut config_map = serde_json::Map::new();
            config_map.insert(
                "$schema".to_string(),
                json!("https://hai.ai/schemas/jacs.config.schema.json"),
            );
            config_map.insert("jacs_agent_id_and_version".to_string(), json!(lookup_id));
            config_map.insert("jacs_agent_key_algorithm".to_string(), json!(algorithm));
            config_map.insert(
                "jacs_data_directory".to_string(),
                json!(params.data_directory),
            );
            config_map.insert(
                "jacs_key_directory".to_string(),
                json!(params.key_directory),
            );
            config_map.insert(
                "jacs_default_storage".to_string(),
                json!(params.default_storage),
            );
            config_map.insert(
                "jacs_agent_private_key_filename".to_string(),
                json!(DEFAULT_PRIVATE_KEY_FILENAME),
            );
            config_map.insert(
                "jacs_agent_public_key_filename".to_string(),
                json!(DEFAULT_PUBLIC_KEY_FILENAME),
            );
            let config_json = Value::Object(config_map);

            let new_str =
                serde_json::to_string_pretty(&config_json).map_err(|e| JacsError::Internal {
                    message: format!("Failed to serialize config: {}", e),
                })?;
            // Create parent directories if needed
            if let Some(parent) = config_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).map_err(|e| JacsError::DirectoryCreateFailed {
                        path: parent.to_string_lossy().to_string(),
                        reason: e.to_string(),
                    })?;
                }
            }
            fs::write(config_path, &new_str).map_err(|e| JacsError::Internal {
                message: format!("Failed to write config to '{}': {}", params.config_path, e),
            })?;
            info!(
                "Created new config '{}' for agent {}",
                params.config_path, lookup_id
            );
            new_str
        };

        // Set the agent's in-memory config from the resolved config so save()
        // uses the correct data_directory and key_directory.
        let validated_config_value =
            crate::config::validate_config(&config_str).map_err(|e| JacsError::Internal {
                message: format!("Failed to validate config: {}", e),
            })?;
        agent.config = Some(serde_json::from_value(validated_config_value).map_err(|e| {
            JacsError::Internal {
                message: format!("Failed to parse config: {}", e),
            }
        })?);

        // Save the agent (uses directories from the resolved config)
        agent.save().map_err(|e| JacsError::Internal {
            message: format!("Failed to save agent: {}", e),
        })?;

        // If a custom storage backend was provided, inject it now.
        // The agent.save() above uses the default filesystem storage to persist
        // the agent identity. After that, we switch to the caller's storage
        // for all subsequent document operations.
        if let Some(custom_storage) = params.storage.clone() {
            agent.set_storage(custom_storage);
        }

        // Handle DNS record generation if domain is set
        let mut dns_record = String::new();
        if !params.domain.is_empty() {
            if let Ok(pk) = agent.get_public_key() {
                let digest = crate::dns::bootstrap::pubkey_digest_b64(&pk);
                let rr = crate::dns::bootstrap::build_dns_record(
                    &params.domain,
                    3600,
                    &agent_id,
                    &digest,
                    crate::dns::bootstrap::DigestEncoding::Base64,
                );
                dns_record = crate::dns::bootstrap::emit_plain_bind(&rr);
            }
        }

        let private_key_path = format!("{}/{}", params.key_directory, DEFAULT_PRIVATE_KEY_FILENAME);
        let public_key_path = format!("{}/{}", params.key_directory, DEFAULT_PUBLIC_KEY_FILENAME);

        info!(
            "Agent '{}' created successfully with ID {} (programmatic)",
            params.name, agent_id
        );

        let info = AgentInfo {
            agent_id,
            name: params.name.clone(),
            public_key_path,
            config_path: params.config_path.clone(),
            version,
            algorithm: algorithm.clone(),
            private_key_path,
            data_directory: params.data_directory.clone(),
            key_directory: params.key_directory.clone(),
            domain: params.domain.clone(),
            dns_record,
        };

        Ok((
            Self {
                agent: Mutex::new(agent),
                config_path: Some(params.config_path),

                strict: resolve_strict(None),
            },
            info,
        ))
    }

    /// Loads an existing agent from a configuration file.
    ///
    /// # Arguments
    ///
    /// * `config_path` - Path to the configuration file (default: "./jacs.config.json")
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None, None)?;  // Load from ./jacs.config.json
    /// // or with strict mode:
    /// let agent = SimpleAgent::load(Some("./my-agent/jacs.config.json"), Some(true))?;
    /// ```
    #[must_use = "agent loading result must be checked for errors"]
    pub fn load(config_path: Option<&str>, strict: Option<bool>) -> Result<Self, JacsError> {
        let path = config_path.unwrap_or("./jacs.config.json");

        debug!("Loading agent from config: {}", path);

        if !Path::new(path).exists() {
            return Err(JacsError::ConfigNotFound {
                path: path.to_string(),
            });
        }

        let mut agent = crate::get_empty_agent();
        agent
            .load_by_config(path.to_string())
            .map_err(|e| JacsError::ConfigInvalid {
                field: "config".to_string(),
                reason: e.to_string(),
            })?;

        info!("Agent loaded successfully from {}", path);

        Ok(Self {
            agent: Mutex::new(agent),
            config_path: Some(path.to_string()),
            strict: resolve_strict(strict),
        })
    }

    /// Returns canonical metadata for the currently loaded agent.
    pub fn loaded_info(&self) -> Result<AgentInfo, JacsError> {
        let config_path = self
            .config_path
            .as_deref()
            .ok_or(JacsError::AgentNotLoaded)?
            .to_string();
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        build_loaded_agent_info(&agent, &config_path)
    }

    /// Creates an ephemeral in-memory agent. No config file, no directories,
    /// no environment variables, no password needed.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Signing algorithm: "pq2025" (default), "ed25519", or "rsa-pss"
    ///
    /// # Returns
    ///
    /// A `SimpleAgent` instance with in-memory keys, along with `AgentInfo`.
    /// Keys are lost when the agent is dropped.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let (agent, info) = SimpleAgent::ephemeral(None)?;
    /// let signed = agent.sign_message(&serde_json::json!({"hello": "world"}))?;
    /// ```
    #[must_use = "ephemeral agent result must be checked for errors"]
    pub fn ephemeral(algorithm: Option<&str>) -> Result<(Self, AgentInfo), JacsError> {
        // Map user-friendly names to internal algorithm strings
        let algo = match algorithm.unwrap_or("pq2025") {
            "ed25519" => "ring-Ed25519",
            "rsa-pss" => "RSA-PSS",
            "pq2025" => "pq2025",
            other => other,
        };

        let mut agent = Agent::ephemeral(algo).map_err(|e| JacsError::Internal {
            message: format!("Failed to create ephemeral agent: {}", e),
        })?;

        let agent_json = build_agent_document("ai", "ephemeral", "Ephemeral JACS agent")?;
        let instance = agent
            .create_agent_and_load(&agent_json.to_string(), true, Some(algo))
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to initialize ephemeral agent: {}", e),
            })?;

        let agent_id = instance["jacsId"].as_str().unwrap_or("").to_string();
        let version = instance["jacsVersion"].as_str().unwrap_or("").to_string();
        let info = AgentInfo {
            agent_id,
            name: "ephemeral".to_string(),
            public_key_path: String::new(),
            config_path: String::new(),
            version,
            algorithm: algo.to_string(),
            private_key_path: String::new(),
            data_directory: String::new(),
            key_directory: String::new(),
            domain: String::new(),
            dns_record: String::new(),
        };

        Ok((
            Self {
                agent: Mutex::new(agent),
                config_path: None,

                strict: resolve_strict(None),
            },
            info,
        ))
    }

    /// Verifies the loaded agent's own identity.
    ///
    /// This checks:
    /// 1. Self-signature validity
    /// 2. Document hash integrity
    /// 3. DNS TXT record (if domain is configured)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let result = agent.verify_self()?;
    /// assert!(result.valid);
    /// ```
    #[must_use = "self-verification result must be checked"]
    pub fn verify_self(&self) -> Result<VerificationResult, JacsError> {
        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Verify self-signature
        let sig_result = agent.verify_self_signature();
        let hash_result = agent.verify_self_hash();

        let mut errors = Vec::new();

        if let Err(e) = sig_result {
            errors.push(format!("Signature verification failed: {}", e));
        }

        if let Err(e) = hash_result {
            errors.push(format!("Hash verification failed: {}", e));
        }

        let valid = errors.is_empty();

        // In strict mode, verification failure is a hard error
        if self.strict && !valid {
            return Err(JacsError::SignatureVerificationFailed {
                reason: errors.join("; "),
            });
        }

        // Extract agent info
        let agent_value = agent.get_value().cloned().unwrap_or(json!({}));
        let agent_id = agent_value.get_str_or("jacsId", "");
        let agent_name = agent_value.get_str("name");
        let timestamp = agent_value.get_str_or("jacsVersionDate", "");

        Ok(VerificationResult {
            valid,
            data: agent_value,
            signer_id: agent_id.clone(),
            signer_name: agent_name,
            timestamp,
            attachments: vec![],
            errors,
        })
    }

    /// Signs arbitrary data as a JACS message.
    ///
    /// # IMPORTANT: Signing is Sacred
    ///
    /// **Signing a document is an irreversible, permanent commitment.** Once signed:
    /// - The signature creates cryptographic proof binding you to the content
    /// - You cannot deny having signed (non-repudiation)
    /// - The signed document can be verified by anyone forever
    /// - You are accountable for the content you signed
    ///
    /// **Before signing, always:**
    /// - Read and understand the complete document content
    /// - Verify the data represents your actual intent
    /// - Confirm you have authority to make this commitment
    ///
    /// The data can be a JSON object, string, or any serializable value.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign (will be JSON-serialized)
    ///
    /// # Returns
    ///
    /// A `SignedDocument` containing the full signed document.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    /// use serde_json::json;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// // Review data carefully before signing!
    /// let signed = agent.sign_message(&json!({"action": "approve", "amount": 100}))?;
    /// println!("Document ID: {}", signed.document_id);
    /// ```
    #[must_use = "signed document must be used or stored"]
    pub fn sign_message(&self, data: &Value) -> Result<SignedDocument, JacsError> {
        debug!("sign_message() called");

        // Wrap the data in a minimal document structure
        let doc_content = json!({
            "jacsType": "message",
            "jacsLevel": "raw",
            "content": data
        });

        // Check document size before processing
        let doc_string = doc_content.to_string();
        check_document_size(&doc_string)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let jacs_doc = agent
            .create_document_and_load(&doc_string, None, None)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!(
                    "{}. Ensure the agent is properly initialized with load() or create() and has valid keys.",
                    e
                ),
            })?;

        info!("Message signed: document_id={}", jacs_doc.id);

        SignedDocument::from_jacs_document(jacs_doc, "document")
    }

    /// Sign raw bytes and return the raw signature bytes.
    ///
    /// This is a low-level signing method used by JACS email signing and other
    /// protocols that need to sign arbitrary data (not JSON documents).
    /// The data must be valid UTF-8 (JACS canonical payloads always are).
    ///
    /// Returns the raw signature bytes (decoded from the base64 output of the
    /// underlying crypto module).
    pub fn sign_raw_bytes(&self, data: &[u8]) -> Result<Vec<u8>, JacsError> {
        use crate::crypt::KeyManager;
        use base64::Engine;

        let data_str = std::str::from_utf8(data).map_err(|e| JacsError::Internal {
            message: format!("Data is not valid UTF-8: {}", e),
        })?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let sig_b64 = agent
            .sign_string(data_str)
            .map_err(|e| JacsError::SigningFailed {
                reason: format!("Raw byte signing failed: {}", e),
            })?;

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .map_err(|e| JacsError::Internal {
                message: format!("Failed to decode signature base64: {}", e),
            })?;

        Ok(sig_bytes)
    }

    /// Get the JACS agent ID.
    ///
    /// Returns the agent's unique identifier from the exported agent JSON.
    pub fn get_agent_id(&self) -> Result<String, JacsError> {
        // Use export_agent which returns the agent document JSON
        let agent_json = self.export_agent()?;
        let doc: serde_json::Value =
            serde_json::from_str(&agent_json).map_err(|e| JacsError::Internal {
                message: format!("Failed to parse agent JSON: {}", e),
            })?;

        // Try to extract the agent ID from the document.
        // The canonical field is "jacsId"; also check legacy field names.
        let agent_id = doc
            .pointer("/jacsId")
            .or_else(|| doc.pointer("/jacsAgentID"))
            .or_else(|| doc.pointer("/id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| JacsError::Internal {
                message: "Agent ID not found in agent document".to_string(),
            })?;

        Ok(agent_id.to_string())
    }

    /// Signs a file with optional content embedding.
    ///
    /// # IMPORTANT: Signing is Sacred
    ///
    /// **Signing a file is an irreversible, permanent commitment.** Your signature:
    /// - Cryptographically binds you to the file's exact contents
    /// - Cannot be revoked or denied (non-repudiation)
    /// - Creates permanent proof that you attested to this file
    /// - Makes you accountable for the file content forever
    ///
    /// **Before signing any file:**
    /// - Review the complete file contents
    /// - Verify the file has not been tampered with
    /// - Confirm you intend to attest to this specific file
    /// - Understand your signature is permanent and verifiable
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file to sign
    /// * `embed` - If true, embed file content; if false, store only hash reference
    ///
    /// # Returns
    ///
    /// A `SignedDocument` containing the signed file reference or embedded content.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    ///
    /// // Review file before signing! Embed the file content
    /// let signed = agent.sign_file("contract.pdf", true)?;
    ///
    /// // Or just reference it by hash
    /// let signed = agent.sign_file("large-video.mp4", false)?;
    /// ```
    #[must_use = "signed document must be used or stored"]
    pub fn sign_file(&self, file_path: &str, embed: bool) -> Result<SignedDocument, JacsError> {
        // Check file exists
        if !Path::new(file_path).exists() {
            return Err(JacsError::FileNotFound {
                path: file_path.to_string(),
            });
        }

        let mime_type = mime_from_extension(file_path);
        let filename = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Create document with file attachment
        let doc_content = json!({
            "jacsType": "file",
            "jacsLevel": "raw",
            "filename": filename,
            "mimetype": mime_type
        });

        let attachment = vec![file_path.to_string()];

        let jacs_doc = agent
            .create_document_and_load(&doc_content.to_string(), Some(attachment), Some(embed))
            .map_err(|e| JacsError::SigningFailed {
                reason: format!(
                    "File signing failed for '{}': {}. Verify the file exists and the agent has valid keys.",
                    file_path, e
                ),
            })?;

        SignedDocument::from_jacs_document(jacs_doc, "document")
    }

    /// Verifies a signed document and extracts its content.
    ///
    /// This function auto-detects whether the document contains a message or file.
    ///
    /// # Arguments
    ///
    /// * `signed_document` - The JSON string of the signed document
    ///
    /// # Returns
    ///
    /// A `VerificationResult` with the verification status and extracted content.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let result = agent.verify(&signed_json)?;
    /// if result.valid {
    ///     println!("Content: {}", result.data);
    /// } else {
    ///     println!("Verification failed: {:?}", result.errors);
    /// }
    /// ```
    #[must_use = "verification result must be checked"]
    pub fn verify(&self, signed_document: &str) -> Result<VerificationResult, JacsError> {
        debug!("verify() called");
        Self::validate_json_input(signed_document)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        // Load the document
        let jacs_doc =
            agent
                .load_document(signed_document)
                .map_err(|e| JacsError::DocumentMalformed {
                    field: "document".to_string(),
                    reason: e.to_string(),
                })?;

        let document_key = jacs_doc.getkey();

        // Verify the signature using the agent's own key
        let mut errors = Vec::new();
        if let Err(e) = agent.verify_document_signature(&document_key, None, None, None, None) {
            errors.push(e.to_string());
        }

        // Verify hash
        if let Err(e) = agent.verify_hash(&jacs_doc.value) {
            errors.push(format!("Hash verification failed: {}", e));
        }

        self.build_verification_result(&jacs_doc.value, errors, "Document verified")
    }

    /// Verifies a signed JACS document using a provided public key.
    ///
    /// This is identical to [`verify()`](Self::verify) but uses the supplied
    /// `public_key` bytes instead of the agent's own key. This allows any
    /// agent to verify documents signed by a different agent, given the
    /// signer's public key (e.g., from a registry or trust store).
    ///
    /// # Arguments
    ///
    /// * `signed_document` - The JSON string of the signed JACS document
    /// * `public_key` - The signer's public key bytes (PEM file content)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // agent_b verifies a document that agent_a signed
    /// let result = agent_b.verify_with_key(&signed_doc, agent_a_pubkey)?;
    /// if result.valid {
    ///     println!("Verified: signed by {}", result.signer_id);
    /// }
    /// ```
    #[must_use = "verification result must be checked"]
    pub fn verify_with_key(
        &self,
        signed_document: &str,
        public_key: Vec<u8>,
    ) -> Result<VerificationResult, JacsError> {
        debug!("verify_with_key() called");
        Self::validate_json_input(signed_document)?;

        let mut agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let mut errors = Vec::new();

        // Load the document. In non-strict mode, if load_document fails (e.g.
        // hash mismatch on a tampered doc), we still want to report the failure
        // as a verification result rather than a hard error.
        let jacs_doc = match agent.load_document(signed_document) {
            Ok(doc) => doc,
            Err(e) if !self.strict => {
                // Fall back to parsing the JSON directly so we can still
                // extract signer info and report the error softly.
                let value: Value = serde_json::from_str(signed_document).map_err(|parse_err| {
                    JacsError::DocumentMalformed {
                        field: "json".to_string(),
                        reason: parse_err.to_string(),
                    }
                })?;
                errors.push(format!("Document load failed: {}", e));
                return self.build_verification_result(&value, errors, "Document load failed");
            }
            Err(e) => {
                return Err(JacsError::DocumentMalformed {
                    field: "document".to_string(),
                    reason: e.to_string(),
                });
            }
        };

        let document_key = jacs_doc.getkey();

        // Verify the signature using the provided public key
        if let Err(e) =
            agent.verify_document_signature(&document_key, None, None, Some(public_key), None)
        {
            errors.push(e.to_string());
        }

        // Verify hash
        if let Err(e) = agent.verify_hash(&jacs_doc.value) {
            errors.push(format!("Hash verification failed: {}", e));
        }

        self.build_verification_result(&jacs_doc.value, errors, "Document verified with key")
    }

    /// Validates that the input string is well-formed JSON suitable for verification.
    ///
    /// Checks: looks like JSON, within size limits, parses successfully.
    fn validate_json_input(signed_document: &str) -> Result<(), JacsError> {
        let trimmed = signed_document.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('{') && !trimmed.starts_with('[') {
            return Err(JacsError::DocumentMalformed {
                field: "json".to_string(),
                reason: format!(
                    "Input does not appear to be a JSON document. \
                    If you have a document ID (e.g., 'uuid:version'), use verify_by_id() instead. \
                    Received: '{}'",
                    if trimmed.len() > 60 {
                        &trimmed[..60]
                    } else {
                        trimmed
                    }
                ),
            });
        }

        check_document_size(signed_document)?;

        let _: Value =
            serde_json::from_str(signed_document).map_err(|e| JacsError::DocumentMalformed {
                field: "json".to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    /// Builds a `VerificationResult` from a document value and accumulated errors.
    ///
    /// Handles strict mode enforcement, signer info extraction, content extraction,
    /// and attachment extraction. Used by `verify()`, `verify_with_key()`, and
    /// the `verify_with_key()` fallback path.
    fn build_verification_result(
        &self,
        doc_value: &Value,
        errors: Vec<String>,
        log_label: &str,
    ) -> Result<VerificationResult, JacsError> {
        let valid = errors.is_empty();

        // In strict mode, verification failure is a hard error
        if self.strict && !valid {
            return Err(JacsError::SignatureVerificationFailed {
                reason: errors.join("; "),
            });
        }

        let signer_id = doc_value.get_path_str_or(&["jacsSignature", "agentID"], "");
        let timestamp = doc_value.get_path_str_or(&["jacsSignature", "date"], "");

        info!("{}: valid={}, signer={}", log_label, valid, signer_id);

        let data = if let Some(content) = doc_value.get("content") {
            content.clone()
        } else {
            doc_value.clone()
        };

        let attachments = extract_attachments(doc_value);

        Ok(VerificationResult {
            valid,
            data,
            signer_id,
            signer_name: None,
            timestamp,
            attachments,
            errors,
        })
    }

    /// Verifies a signed document looked up by its document ID from storage.
    ///
    /// This is a convenience method for when you have a document ID (e.g., "uuid:version")
    /// rather than the full JSON string.
    ///
    /// # Arguments
    ///
    /// * `document_id` - The document ID in "uuid:version" format
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use jacs::simple::SimpleAgent;
    ///
    /// let agent = SimpleAgent::load(None)?;
    /// let result = agent.verify_by_id("abc123:1")?;
    /// assert!(result.valid);
    /// ```
    #[must_use = "verification result must be checked"]
    pub fn verify_by_id(&self, document_id: &str) -> Result<VerificationResult, JacsError> {
        debug!("verify_by_id() called with id: {}", document_id);

        // Validate document_id format
        let parts: Vec<&str> = document_id.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(JacsError::DocumentMalformed {
                field: "document_id".to_string(),
                reason: format!(
                    "Expected format 'uuid:version', got '{}'. \
                    Use verify() with the full JSON document string instead.",
                    document_id
                ),
            });
        }

        // Load from the already-configured agent storage backend (fs, memory, s3, etc.).
        let doc_str = {
            let agent = self.agent.lock().map_err(|e| JacsError::Internal {
                message: format!("Failed to acquire agent lock: {}", e),
            })?;
            let jacs_doc = agent
                .get_document(document_id)
                .map_err(|e| JacsError::Internal {
                    message: format!(
                        "Failed to load document '{}' from agent storage: {}",
                        document_id, e
                    ),
                })?;

            serde_json::to_string(&jacs_doc.value).map_err(|e| JacsError::Internal {
                message: format!("Failed to serialize document '{}': {}", document_id, e),
            })?
        };

        self.verify(&doc_str)
    }

    /// Exports the agent's identity JSON for P2P exchange.
    #[must_use = "exported agent data must be used"]
    pub fn export_agent(&self) -> Result<String, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;

        let value = agent
            .get_value()
            .cloned()
            .ok_or(JacsError::AgentNotLoaded)?;
        serde_json::to_string_pretty(&value).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize agent: {}", e),
        })
    }

    /// Returns the agent's public key bytes from memory.
    ///
    /// This returns the raw public key bytes as stored in the agent's internal
    /// state. The format depends on the algorithm (e.g., raw 32 bytes for
    /// Ed25519, PEM for RSA-PSS). These bytes are the same format expected by
    /// [`verify_with_key()`](Self::verify_with_key) and
    /// [`verify_document_signature()`](crate::agent::document::DocumentTraits::verify_document_signature).
    #[must_use = "public key data must be used"]
    pub fn get_public_key(&self) -> Result<Vec<u8>, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        use crate::agent::boilerplate::BoilerPlate;
        agent.get_public_key().map_err(|e| JacsError::Internal {
            message: format!("Failed to get public key: {}", e),
        })
    }

    /// Returns the agent's public key in PEM format.
    #[must_use = "public key data must be used"]
    pub fn get_public_key_pem(&self) -> Result<String, JacsError> {
        let agent = self.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        let public_key = agent.get_public_key().map_err(|e| JacsError::Internal {
            message: format!("Failed to get public key: {}", e),
        })?;
        Ok(crate::crypt::normalize_public_key_pem(&public_key))
    }

    /// Returns diagnostic information including loaded agent details.
    pub fn diagnostics(&self) -> serde_json::Value {
        let mut info = super::diagnostics(); // call the standalone version

        if let Ok(agent) = self.agent.lock() {
            if agent.ready() {
                info["agent_loaded"] = serde_json::json!(true);
                if let Some(value) = agent.get_value() {
                    info["agent_id"] =
                        serde_json::json!(value.get("jacsId").and_then(|v| v.as_str()));
                    info["agent_version"] =
                        serde_json::json!(value.get("jacsVersion").and_then(|v| v.as_str()));
                }
            }
            if let Some(config) = &agent.config {
                if let Some(dir) = config.jacs_data_directory().as_ref() {
                    info["data_directory"] = serde_json::json!(dir);
                }
                if let Some(dir) = config.jacs_key_directory().as_ref() {
                    info["key_directory"] = serde_json::json!(dir);
                }
                if let Some(storage) = config.jacs_default_storage().as_ref() {
                    info["default_storage"] = serde_json::json!(storage);
                }
                if let Some(algo) = config.jacs_agent_key_algorithm().as_ref() {
                    info["key_algorithm"] = serde_json::json!(algo);
                }
            }
        }

        info
    }

    /// Returns the path to the configuration file, if available.
    pub fn config_path(&self) -> Option<&str> {
        self.config_path.as_deref()
    }
}
