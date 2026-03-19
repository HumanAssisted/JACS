//! Advanced SimpleAgent operations — free functions (Phase 5, narrow contract).
//!
//! These functions accept a `&SimpleAgent` reference and provide advanced
//! agent-management operations. They were previously methods on `SimpleAgent`
//! and were moved here as part of Phase 5 (narrow contract).

use crate::agent::SHA256_FIELDNAME;
use crate::agent::boilerplate::BoilerPlate;
use crate::agent::document::DocumentTraits;
use crate::crypt::hash::hash_string;
use crate::error::JacsError;
use crate::protocol::canonicalize_json;
use crate::schema::utils::ValueExt;
use crate::simple::SimpleAgent;
use crate::simple::types::*;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

/// Re-encrypts the agent's private key from one password to another.
///
/// This reads the encrypted private key file, decrypts with the old password,
/// validates the new password, re-encrypts, and writes the updated file.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent whose key to re-encrypt
/// * `old_password` - The current password protecting the private key
/// * `new_password` - The new password (must meet password requirements)
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use jacs::simple::advanced;
///
/// let agent = SimpleAgent::load(None, None)?;
/// advanced::reencrypt_key(&agent, "OldP@ss123!", "NewStr0ng!Pass#2025")?;
/// println!("Key re-encrypted successfully");
/// ```
pub fn reencrypt_key(
    agent: &SimpleAgent,
    old_password: &str,
    new_password: &str,
) -> Result<(), JacsError> {
    use crate::crypt::aes_encrypt::reencrypt_private_key;

    // Find the private key file
    let key_path = if let Some(ref config_path) = agent.config_path {
        // Try to read config to find key directory
        let config_str =
            fs::read_to_string(config_path).map_err(|e| JacsError::FileReadFailed {
                path: config_path.clone(),
                reason: e.to_string(),
            })?;
        let config: Value =
            serde_json::from_str(&config_str).map_err(|e| JacsError::ConfigInvalid {
                field: "json".to_string(),
                reason: e.to_string(),
            })?;
        let key_dir = config["jacs_key_directory"]
            .as_str()
            .unwrap_or("./jacs_keys");
        let key_filename = config["jacs_agent_private_key_filename"]
            .as_str()
            .unwrap_or("jacs.private.pem.enc");
        format!("{}/{}", key_dir, key_filename)
    } else {
        "./jacs_keys/jacs.private.pem.enc".to_string()
    };

    info!("Re-encrypting private key at: {}", key_path);

    // Read encrypted key
    let encrypted_data = fs::read(&key_path).map_err(|e| JacsError::FileReadFailed {
        path: key_path.clone(),
        reason: e.to_string(),
    })?;

    // Re-encrypt
    let re_encrypted = reencrypt_private_key(&encrypted_data, old_password, new_password)
        .map_err(|e| JacsError::CryptoError(format!("Re-encryption failed: {}", e)))?;

    // Write back
    fs::write(&key_path, &re_encrypted).map_err(|e| JacsError::Internal {
        message: format!("Failed to write re-encrypted key to '{}': {}", key_path, e),
    })?;

    info!("Private key re-encrypted successfully");
    Ok(())
}

/// Returns setup instructions for publishing the agent's DNS record
/// and enabling DNSSEC.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to generate instructions for
/// * `domain` - The domain to publish the DNS TXT record under
/// * `ttl` - TTL in seconds for the DNS record (e.g. 3600)
pub fn get_setup_instructions(
    agent: &SimpleAgent,
    domain: &str,
    ttl: u32,
) -> Result<SetupInstructions, JacsError> {
    use crate::dns::bootstrap::{
        DigestEncoding, build_dns_record, dnssec_guidance, emit_azure_cli, emit_cloudflare_curl,
        emit_gcloud_dns, emit_plain_bind, emit_route53_change_batch, tld_requirement_text,
    };

    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to lock agent: {}", e),
    })?;

    let agent_value = inner.get_value().cloned().unwrap_or(json!({}));
    let agent_id = agent_value.get_str_or("jacsId", "");
    if agent_id.is_empty() {
        return Err(JacsError::AgentNotLoaded);
    }

    let pk = inner.get_public_key().map_err(|e| JacsError::Internal {
        message: format!("Failed to get public key: {}", e),
    })?;
    let digest = crate::dns::bootstrap::pubkey_digest_b64(&pk);
    let rr = build_dns_record(domain, ttl, &agent_id, &digest, DigestEncoding::Base64);

    let dns_record_bind = emit_plain_bind(&rr);
    let dns_record_value = rr.txt.clone();
    let dns_owner = rr.owner.clone();

    // Provider commands
    let mut provider_commands = std::collections::HashMap::new();
    provider_commands.insert("bind".to_string(), dns_record_bind.clone());
    provider_commands.insert("route53".to_string(), emit_route53_change_batch(&rr));
    provider_commands.insert("gcloud".to_string(), emit_gcloud_dns(&rr, "YOUR_ZONE_NAME"));
    provider_commands.insert(
        "azure".to_string(),
        emit_azure_cli(&rr, "YOUR_RG", domain, "_v1.agent.jacs"),
    );
    provider_commands.insert(
        "cloudflare".to_string(),
        emit_cloudflare_curl(&rr, "YOUR_ZONE_ID"),
    );

    // DNSSEC guidance per provider
    let mut dnssec_instructions = std::collections::HashMap::new();
    for name in &["aws", "cloudflare", "azure", "gcloud"] {
        dnssec_instructions.insert(name.to_string(), dnssec_guidance(name).to_string());
    }

    let tld_requirement = tld_requirement_text().to_string();

    // .well-known JSON
    let well_known = json!({
        "jacs_agent_id": agent_id,
        "jacs_public_key_hash": digest,
        "jacs_dns_record": dns_owner,
    });
    let well_known_json = serde_json::to_string_pretty(&well_known).unwrap_or_default();

    // Build summary
    let summary = format!(
        "Setup instructions for agent {agent_id} on domain {domain}:\n\
         \n\
         1. DNS: Publish the following TXT record:\n\
         {bind}\n\
         \n\
         2. DNSSEC: {dnssec}\n\
         \n\
         3. Domain requirement: {tld}\n\
         \n\
         4. .well-known: Serve the well-known JSON at /.well-known/jacs-agent.json",
        agent_id = agent_id,
        domain = domain,
        bind = dns_record_bind,
        dnssec = dnssec_guidance("aws"),
        tld = tld_requirement,
    );

    Ok(SetupInstructions {
        dns_record_bind,
        dns_record_value,
        dns_owner,
        provider_commands,
        dnssec_instructions,
        tld_requirement,
        well_known_json,
        summary,
    })
}

/// Rotates the agent's cryptographic keys.
///
/// This generates a new keypair, archives the old keys (for filesystem-backed
/// agents), creates a new agent version with the new public key, self-signs it,
/// and updates the config file.
///
/// The old keys remain on disk (archived with a version suffix) so that
/// documents signed with the old key can still be verified.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent whose keys to rotate
///
/// # Returns
///
/// A [`RotationResult`] containing the old and new version strings, the new
/// public key in PEM format, and the complete self-signed agent JSON.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::SimpleAgent;
/// use jacs::simple::advanced;
///
/// let (agent, _info) = SimpleAgent::create("my-agent", None, None)?;
/// let rotation = advanced::rotate(&agent)?;
/// println!("Rotated from {} to {}", rotation.old_version, rotation.new_version);
/// ```
pub fn rotate(agent: &SimpleAgent) -> Result<RotationResult, JacsError> {
    use crate::crypt::hash::hash_public_key;

    info!("Starting key rotation");

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    // 1. Capture pre-rotation state
    let agent_value = inner
        .get_value()
        .cloned()
        .ok_or(JacsError::AgentNotLoaded)?;
    let jacs_id = agent_value["jacsId"]
        .as_str()
        .ok_or(JacsError::AgentNotLoaded)?
        .to_string();
    let old_version = agent_value["jacsVersion"]
        .as_str()
        .ok_or_else(|| JacsError::Internal {
            message: "Agent has no jacsVersion".to_string(),
        })?
        .to_string();

    // 2. Delegate to Agent::rotate_self() (archives keys, generates new, signs, verifies)
    let (new_version, new_public_key, new_doc) =
        inner.rotate_self().map_err(|e| JacsError::Internal {
            message: format!("Key rotation failed: {}", e),
        })?;

    // 3. Save agent document to disk (non-ephemeral only)
    if !inner.is_ephemeral() {
        inner.save().map_err(|e| JacsError::Internal {
            message: format!("Failed to save rotated agent: {}", e),
        })?;
    }

    // 4. Update config file with the new version
    if let Some(ref config_path) = agent.config_path {
        let config_path_p = Path::new(config_path);
        if config_path_p.exists() {
            let config_str =
                fs::read_to_string(config_path_p).map_err(|e| JacsError::Internal {
                    message: format!("Failed to read config for rotation update: {}", e),
                })?;
            let mut config_value: Value =
                serde_json::from_str(&config_str).map_err(|e| JacsError::Internal {
                    message: format!("Failed to parse config: {}", e),
                })?;

            let new_lookup = format!("{}:{}", jacs_id, new_version);
            if let Some(obj) = config_value.as_object_mut() {
                obj.insert("jacs_agent_id_and_version".to_string(), json!(new_lookup));
            }

            let updated_str =
                serde_json::to_string_pretty(&config_value).map_err(|e| JacsError::Internal {
                    message: format!("Failed to serialize updated config: {}", e),
                })?;
            fs::write(config_path_p, updated_str).map_err(|e| JacsError::Internal {
                message: format!("Failed to write updated config: {}", e),
            })?;

            info!(
                "Config updated with new version: {}:{}",
                jacs_id, new_version
            );
        }
    }

    // 5. Build the PEM string for the new public key
    let new_public_key_pem = crate::crypt::normalize_public_key_pem(&new_public_key);
    drop(inner); // Release lock

    let new_public_key_hash = hash_public_key(&new_public_key);
    let signed_agent_json =
        serde_json::to_string_pretty(&new_doc).map_err(|e| JacsError::Internal {
            message: format!("Failed to serialize rotated agent: {}", e),
        })?;

    info!(
        "Key rotation complete: {} -> {} (id={})",
        old_version, new_version, jacs_id
    );

    Ok(RotationResult {
        jacs_id,
        old_version,
        new_version,
        new_public_key_pem,
        new_public_key_hash,
        signed_agent_json,
    })
}

/// Migrates a legacy agent document that predates a schema change.
///
/// Agents created before the `iat` (issued-at timestamp) and `jti` (unique
/// nonce) fields were added to the `jacsSignature` schema will fail
/// validation on load. This function works around that by:
///
/// 1. Reading the raw agent JSON from disk (bypassing schema validation)
/// 2. Patching in temporary `iat` and `jti` values if they are missing
/// 3. Writing the patched JSON back to disk
/// 4. Loading the agent normally (now passes schema validation)
/// 5. Calling `update_agent()` to produce a properly re-signed new version
/// 6. Saving the new version and updating the config file
///
/// This is a standalone function because the agent cannot be loaded yet (that is
/// the whole point of migration).
///
/// # Arguments
///
/// * `config_path` - Path to the JACS config file (default: `./jacs.config.json`)
///
/// # Returns
///
/// A [`MigrateResult`] describing what was patched and the new version.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::advanced;
///
/// let result = advanced::migrate_agent(None)?;
/// println!("Migrated {} -> {}", result.old_version, result.new_version);
/// println!("Patched fields: {:?}", result.patched_fields);
/// ```
pub fn migrate_agent(config_path: Option<&str>) -> Result<MigrateResult, JacsError> {
    let path = config_path.unwrap_or("./jacs.config.json");

    info!("Starting agent migration from config: {}", path);

    if !Path::new(path).exists() {
        return Err(JacsError::ConfigNotFound {
            path: path.to_string(),
        });
    }

    // Step 1: Load config to find the agent file
    let config =
        crate::config::load_config_12factor(Some(path)).map_err(|e| JacsError::ConfigInvalid {
            field: "config".to_string(),
            reason: format!("Could not load configuration from '{}': {}", path, e),
        })?;

    let id_and_version = config
        .jacs_agent_id_and_version()
        .as_deref()
        .unwrap_or("")
        .to_string();
    if id_and_version.is_empty() {
        return Err(JacsError::ConfigInvalid {
            field: "jacs_agent_id_and_version".to_string(),
            reason: "Agent ID and version not set in config".to_string(),
        });
    }

    let data_dir = config
        .jacs_data_directory()
        .as_deref()
        .unwrap_or("jacs_data")
        .to_string();

    // Step 2: Construct the agent file path (same logic as fs_agent_load)
    let config_dir = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let agent_file = if Path::new(&data_dir).is_absolute() {
        Path::new(&data_dir)
            .join("agent")
            .join(format!("{}.json", id_and_version))
    } else {
        config_dir
            .join(&data_dir)
            .join("agent")
            .join(format!("{}.json", id_and_version))
    };

    info!("Migration: reading agent file at {:?}", agent_file);

    if !agent_file.exists() {
        return Err(JacsError::Internal {
            message: format!(
                "Agent file not found at '{}'. Check jacs_data_directory and jacs_agent_id_and_version in config.",
                agent_file.display()
            ),
        });
    }

    // Step 3: Read and parse the raw JSON
    let raw_json = fs::read_to_string(&agent_file).map_err(|e| JacsError::Internal {
        message: format!(
            "Failed to read agent file '{}': {}",
            agent_file.display(),
            e
        ),
    })?;

    let mut agent_value: Value =
        serde_json::from_str(&raw_json).map_err(|e| JacsError::Internal {
            message: format!(
                "Failed to parse agent JSON from '{}': {}",
                agent_file.display(),
                e
            ),
        })?;

    // Capture pre-migration version info
    let jacs_id = agent_value["jacsId"].as_str().unwrap_or("").to_string();
    let old_version = agent_value["jacsVersion"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if jacs_id.is_empty() || old_version.is_empty() {
        return Err(JacsError::Internal {
            message: "Agent document is missing jacsId or jacsVersion".to_string(),
        });
    }

    // Step 4: Patch jacsSignature if iat/jti are missing
    let mut patched_fields: Vec<String> = Vec::new();

    if let Some(sig) = agent_value.get_mut("jacsSignature") {
        if sig.get("iat").is_none() {
            let iat = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            sig["iat"] = json!(iat);
            patched_fields.push("iat".to_string());
            info!("Migration: patched missing 'iat' field with {}", iat);
        }

        if sig.get("jti").is_none() {
            let jti = uuid::Uuid::now_v7().to_string();
            sig["jti"] = json!(jti);
            patched_fields.push("jti".to_string());
            info!("Migration: patched missing 'jti' field with {}", jti);
        }
    } else {
        return Err(JacsError::Internal {
            message: "Agent document is missing jacsSignature object".to_string(),
        });
    }

    // Step 5: Recompute hash and write patched JSON back to disk (only if changes were made)
    if !patched_fields.is_empty() {
        let mut hash_copy = agent_value.clone();
        if let Some(obj) = hash_copy.as_object_mut() {
            obj.remove(SHA256_FIELDNAME);
        }
        let canonical = canonicalize_json(&hash_copy);
        let new_hash = hash_string(&canonical);
        agent_value[SHA256_FIELDNAME] = json!(new_hash);
        patched_fields.push(SHA256_FIELDNAME.to_string());
        info!("Migration: recomputed {} after patching", SHA256_FIELDNAME);

        let patched_json =
            serde_json::to_string_pretty(&agent_value).map_err(|e| JacsError::Internal {
                message: format!("Failed to serialize patched agent: {}", e),
            })?;
        fs::write(&agent_file, &patched_json).map_err(|e| JacsError::Internal {
            message: format!(
                "Failed to write patched agent to '{}': {}",
                agent_file.display(),
                e
            ),
        })?;
        info!(
            "Migration: wrote patched agent to {} (fields: {:?})",
            agent_file.display(),
            patched_fields
        );
    } else {
        info!("Migration: no fields needed patching, agent already has iat and jti");
    }

    // Step 6: Load the agent normally (should now pass schema validation)
    let simple_agent = SimpleAgent::load(Some(path), None)?;

    // Step 7: Export current agent doc, then call update_agent to re-sign
    let agent_doc = simple_agent.export_agent()?;
    let updated_json = update_agent(&simple_agent, &agent_doc)?;

    // Step 8: Parse new version from the updated document
    let updated_value: Value =
        serde_json::from_str(&updated_json).map_err(|e| JacsError::Internal {
            message: format!("Failed to parse updated agent JSON: {}", e),
        })?;
    let new_version = updated_value["jacsVersion"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Step 9: Save the updated agent to disk
    {
        let inner = simple_agent.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock: {}", e),
        })?;
        inner.save().map_err(|e| JacsError::Internal {
            message: format!("Failed to save migrated agent: {}", e),
        })?;
    }

    // Step 10: Update config file with the new version
    let config_path_p = Path::new(path);
    if config_path_p.exists() {
        let config_str = fs::read_to_string(config_path_p).map_err(|e| JacsError::Internal {
            message: format!("Failed to read config for migration update: {}", e),
        })?;
        let mut config_value: Value =
            serde_json::from_str(&config_str).map_err(|e| JacsError::Internal {
                message: format!("Failed to parse config: {}", e),
            })?;

        let new_lookup = format!("{}:{}", jacs_id, new_version);
        if let Some(obj) = config_value.as_object_mut() {
            obj.insert("jacs_agent_id_and_version".to_string(), json!(new_lookup));
        }

        let updated_str =
            serde_json::to_string_pretty(&config_value).map_err(|e| JacsError::Internal {
                message: format!("Failed to serialize updated config: {}", e),
            })?;
        fs::write(config_path_p, updated_str).map_err(|e| JacsError::Internal {
            message: format!("Failed to write updated config: {}", e),
        })?;

        info!(
            "Migration: config updated with new version {}:{}",
            jacs_id, new_version
        );
    }

    info!(
        "Agent migration complete: {} -> {} (id={}), patched: {:?}",
        old_version, new_version, jacs_id, patched_fields
    );

    Ok(MigrateResult {
        jacs_id,
        old_version,
        new_version,
        patched_fields,
    })
}

/// Zero-config persistent agent creation.
///
/// If a config file already exists at `config_path` (default: `./jacs.config.json`),
/// loads the existing agent. Otherwise, creates a new persistent agent with keys
/// on disk and a minimal config file.
///
/// `JACS_PRIVATE_KEY_PASSWORD` must be set (or provided by caller wrappers).
/// Quickstart fails hard if no password is available.
///
/// # Arguments
///
/// * `name` - Agent name to use when creating a new config/identity
/// * `domain` - Agent domain to use for DNS/public-key verification workflows
/// * `description` - Optional human-readable description for a newly created agent
/// * `algorithm` - Signing algorithm (default: "pq2025"). Also: "ed25519", "rsa-pss"
/// * `config_path` - Config file path (default: "./jacs.config.json")
///
/// # Returns
///
/// A `SimpleAgent` with persistent keys on disk, along with `AgentInfo`.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::simple::advanced;
///
/// let (agent, info) = advanced::quickstart(
///     "my-agent",
///     "agent.example.com",
///     Some("My JACS agent"),
///     None,
///     None,
/// )?;
/// let signed = agent.sign_message(&serde_json::json!({"hello": "world"}))?;
/// ```
#[must_use = "quickstart result must be checked for errors"]
pub fn quickstart(
    name: &str,
    domain: &str,
    description: Option<&str>,
    algorithm: Option<&str>,
    config_path: Option<&str>,
) -> Result<(SimpleAgent, AgentInfo), JacsError> {
    let config = config_path.unwrap_or("./jacs.config.json");

    // If config already exists, load the existing agent
    if Path::new(config).exists() {
        info!(
            "quickstart: found existing config at {}, loading agent",
            config
        );
        let agent = SimpleAgent::load(Some(config), None)?;

        let mut info = agent.loaded_info()?;
        if info.name.is_empty() {
            info.name = name.to_string();
        }
        if info.domain.is_empty() {
            info.domain = domain.to_string();
        }

        return Ok((agent, info));
    }

    // No existing config -- create a new persistent agent
    info!(
        "quickstart: no config at {}, creating new persistent agent",
        config
    );

    if name.trim().is_empty() {
        return Err(JacsError::ConfigError(
            "Quickstart requires a non-empty agent name.".to_string(),
        ));
    }
    if domain.trim().is_empty() {
        return Err(JacsError::ConfigError(
            "Quickstart requires a non-empty domain.".to_string(),
        ));
    }

    // Resolve password from env var, OS keychain, or fail with helpful message.
    let password = crate::crypt::aes_encrypt::resolve_private_key_password(None)?;

    // Use create_with_params for full control
    let algo = match algorithm.unwrap_or("pq2025") {
        "ed25519" => "ring-Ed25519",
        "rsa-pss" => "RSA-PSS",
        "pq2025" => "pq2025",
        other => other,
    };

    let params = CreateAgentParams {
        name: name.to_string(),
        password: password.clone(),
        algorithm: algo.to_string(),
        config_path: config.to_string(),
        description: description.unwrap_or("").to_string(),
        domain: domain.to_string(),
        ..Default::default()
    };

    let result = SimpleAgent::create_with_params(params)?;

    // Store the password in the OS keychain when available (PRD Decision #1).
    // This means future operations "just work" without env vars or password files.
    if crate::keystore::keychain::is_available() {
        match crate::keystore::keychain::store_password(&password) {
            Ok(()) => {
                info!("Password stored in OS keychain (service: jacs-private-key)");
            }
            Err(e) => {
                warn!("Could not store password in OS keychain: {}", e);
            }
        }
    }

    Ok(result)
}

/// Updates the agent's own document with new data and re-signs it.
///
/// # Arguments
///
/// * `agent` - The SimpleAgent to update
/// * `new_agent_data` - JSON string with the updated agent data
pub fn update_agent(agent: &SimpleAgent, new_agent_data: &str) -> Result<String, JacsError> {
    use crate::schema::utils::check_document_size;
    check_document_size(new_agent_data)?;

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    inner
        .update_self(new_agent_data)
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to update agent: {}", e),
        })
}

/// Updates an existing document with new data and re-signs it.
#[must_use = "updated document must be used or stored"]
pub fn update_document(
    agent: &SimpleAgent,
    document_id: &str,
    new_data: &str,
    attachments: Option<Vec<String>>,
    embed: Option<bool>,
) -> Result<SignedDocument, JacsError> {
    use crate::schema::utils::check_document_size;
    check_document_size(new_data)?;

    let mut inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;

    let jacs_doc = inner
        .update_document(document_id, new_data, attachments, embed)
        .map_err(|e| JacsError::Internal {
            message: format!("Failed to update document: {}", e),
        })?;

    SignedDocument::from_jacs_document(jacs_doc, "document")
}
