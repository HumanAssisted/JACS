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
/// let rotation = advanced::rotate(&agent, None)?;
/// println!("Rotated from {} to {}", rotation.old_version, rotation.new_version);
/// ```
pub fn rotate(agent: &SimpleAgent, algorithm: Option<&str>) -> Result<RotationResult, JacsError> {
    let inner = agent.agent.lock().map_err(|e| JacsError::Internal {
        message: format!("Failed to acquire agent lock: {}", e),
    })?;
    drop(inner); // Release before calling rotate_with_mutex which re-locks
    rotate_with_mutex(&agent.agent, agent.config_path.as_deref(), algorithm)
}

/// Core rotation logic that operates on a `Mutex<Agent>` directly.
///
/// This is the single authoritative rotation path. Both `rotate()` (for
/// `SimpleAgent`) and binding-core `AgentWrapper::rotate_keys()` call this.
pub fn rotate_with_mutex(
    agent_mutex: &std::sync::Mutex<crate::agent::Agent>,
    config_path: Option<&str>,
    algorithm: Option<&str>,
) -> Result<RotationResult, JacsError> {
    use crate::crypt::hash::hash_public_key;
    use crate::keystore::RotationJournal;

    info!("Starting key rotation");

    let mut inner = agent_mutex.lock().map_err(|e| JacsError::Internal {
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

    // Capture old public key hash for journal
    let old_public_key = inner.get_public_key().map_err(|e| JacsError::Internal {
        message: format!("Failed to get old public key: {}", e),
    })?;
    let old_key_hash = hash_public_key(&old_public_key);

    // Resolve algorithm
    let effective_algorithm = match algorithm {
        Some(algo) => algo.to_string(),
        None => {
            let config = inner.config.as_ref().ok_or(JacsError::AgentNotLoaded)?;
            config.get_key_algorithm()?
        }
    };

    // 1a. Write rotation journal (non-ephemeral only)
    let mut journal = if !inner.is_ephemeral() {
        let key_dir = inner
            .config
            .as_ref()
            .and_then(|c| c.jacs_key_directory().as_deref().map(String::from))
            .unwrap_or_else(|| "./jacs_keys".to_string());
        let config_path_str = config_path.unwrap_or("./jacs.config.json");
        Some(RotationJournal::create(
            &key_dir,
            &jacs_id,
            &old_version,
            &old_key_hash,
            &effective_algorithm,
            config_path_str,
        )?)
    } else {
        None
    };

    // 2. Delegate to Agent::rotate_self() (archives keys, generates new, signs, verifies)
    let (new_version, new_public_key, new_doc) =
        inner
            .rotate_self(algorithm)
            .map_err(|e| JacsError::Internal {
                message: format!("Key rotation failed: {}", e),
            })?;

    // 2a. Advance journal to keys_rotated
    if let Some(ref mut j) = journal {
        j.advance("keys_rotated")?;
    }

    // 3. Save agent document to disk (non-ephemeral only)
    if !inner.is_ephemeral() {
        inner.save().map_err(|e| JacsError::Internal {
            message: format!("Failed to save rotated agent: {}", e),
        })?;
    }

    // 3a. Advance journal to agent_saved
    if let Some(ref mut j) = journal {
        j.advance("agent_saved")?;
    }

    // 4. Update config file with the new version
    if let Some(config_p) = config_path {
        let config_path_p = Path::new(config_p);
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

            // If algorithm was overridden, update the config field
            if algorithm.is_some() {
                if let Some(obj) = config_value.as_object_mut() {
                    obj.insert(
                        "jacs_agent_key_algorithm".to_string(),
                        json!(effective_algorithm),
                    );
                }
            }

            let signed_config = if config_value.get("jacsSignature").is_some() {
                inner
                    .update_config(&config_value)
                    .map_err(|e| JacsError::Internal {
                        message: format!("Failed to re-sign config after rotation: {}", e),
                    })?
            } else {
                inner
                    .sign_config(&config_value)
                    .map_err(|e| JacsError::Internal {
                        message: format!("Failed to sign config after rotation: {}", e),
                    })?
            };

            let updated_str =
                serde_json::to_string_pretty(&signed_config).map_err(|e| JacsError::Internal {
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

    // 4a. Advance journal to config_signed, then delete it
    if let Some(ref mut j) = journal {
        j.advance("config_signed")?;
        j.complete()?;
    }

    // 5. Build the PEM string for the new public key
    let new_public_key_pem = crate::crypt::normalize_public_key_pem(&new_public_key);

    // Extract transition proof from the new document
    let transition_proof = new_doc
        .get("jacsKeyRotationProof")
        .map(|p| serde_json::to_string(p).unwrap_or_default());

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
        transition_proof,
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
    #[allow(deprecated)]
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

        let mut inner = simple_agent.agent.lock().map_err(|e| JacsError::Internal {
            message: format!("Failed to acquire agent lock for config signing: {}", e),
        })?;
        let signed_config = if config_value.get("jacsSignature").is_some() {
            inner
                .update_config(&config_value)
                .map_err(|e| JacsError::Internal {
                    message: format!("Failed to re-sign config after migration: {}", e),
                })?
        } else {
            inner
                .sign_config(&config_value)
                .map_err(|e| JacsError::Internal {
                    message: format!("Failed to sign config after migration: {}", e),
                })?
        };
        drop(inner);

        let updated_str =
            serde_json::to_string_pretty(&signed_config).map_err(|e| JacsError::Internal {
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
/// * `algorithm` - Signing algorithm (default: "pq2025"). Also: "ed25519"
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
    let password = crate::crypt::aes_encrypt::resolve_private_key_password(None, None)?;

    // Use create_with_params for full control
    let algo = match algorithm.unwrap_or("pq2025") {
        "ed25519" => "ring-Ed25519",
        "rsa-pss" => "RSA-PSS",
        "pq2025" => "pq2025",
        other => other,
    };
    crate::crypt::ensure_private_key_operation_allowed(algo, "key generation")?;

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
        match crate::keystore::keychain::store_password(&result.1.agent_id, &password) {
            Ok(()) => {
                info!(
                    "Password stored in OS keychain (service: jacs-private-key, agent: {})",
                    result.1.agent_id
                );
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

// =============================================================================
// Inline text signature file operations (Task 05, PRD §4.1)
// =============================================================================

/// Encode a JACS agent ID into a filesystem-safe filename per PRD §4.1.5.
///
/// - Replaces `:` with `%3A` (colon is invalid in NTFS / problematic on Windows).
/// - Replaces literal `..` sequences with `%2E%2E` (path traversal mitigation).
/// - Other characters allowed by the safety whitelist pass through unchanged.
///
/// Pre-conditions: caller MUST validate `signer_id` against
/// [`is_signer_id_safe`] first; this helper assumes the input is already safe.
pub fn encode_signer_id_for_filename(signer_id: &str) -> String {
    // Replace `..` first to avoid creating sequences when we percent-encode `:`.
    let no_dotdot = signer_id.replace("..", "%2E%2E");
    no_dotdot.replace(':', "%3A")
}

/// Whitelist check for `signer_id`. Returns false for any input containing
/// characters outside `[A-Za-z0-9:_.-]`, longer than 256 bytes, or empty.
pub(crate) fn is_signer_id_safe(signer_id: &str) -> bool {
    if signer_id.is_empty() || signer_id.len() > 256 {
        return false;
    }
    signer_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_' || c == '.' || c == '-')
}

/// Default key resolver composing self → key_dir → trust store → DNS (TODO).
///
/// Callers in this module wire one of these up around a `SimpleAgent` and an
/// optional `--key-dir` path before calling `crate::inline::verify_inline`.
pub(crate) struct DefaultKeyResolver<'a> {
    agent: &'a SimpleAgent,
    key_dir: Option<&'a std::path::Path>,
}

impl<'a> DefaultKeyResolver<'a> {
    pub(crate) fn new(agent: &'a SimpleAgent, key_dir: Option<&'a std::path::Path>) -> Self {
        Self { agent, key_dir }
    }
}

impl<'a> crate::inline::KeyResolver for DefaultKeyResolver<'a> {
    fn resolve(&self, signer_id: &str) -> Option<crate::inline::ResolvedKey> {
        // 1. Self key — short-circuit if the signer is the loaded agent.
        //
        // Returns the RAW public-key bytes (32-byte for Ed25519, 2592-byte
        // for ML-DSA-87, PEM string bytes for RSA-PSS). This matches the
        // contract of the low-level crypt primitives:
        // `ringwrapper::verify_string` / `pq2025::verify_string` /
        // `rsawrapper::verify_string` all accept the bytes the algorithm
        // natively expects, NOT a PEM-armored form. The publicKeyHash check
        // in the verifier first calls `normalize_public_key_pem` which is
        // tolerant of both raw and PEM input.
        if let Ok(my_id) = self.agent.get_agent_id()
            && my_id == signer_id
        {
            let raw = self.agent.get_public_key().ok()?;
            let algorithm = crate::crypt::detect_algorithm_from_public_key(&raw)
                .ok()
                .map(inline_algorithm_tag)
                .unwrap_or_else(|| "ed25519".to_string());
            return Some(crate::inline::ResolvedKey {
                public_key_pem: raw,
                algorithm,
            });
        }

        // 2. --key-dir override (when provided). Filename safety per PRD §4.1.5.
        if let Some(dir) = self.key_dir {
            if !is_signer_id_safe(signer_id) {
                // Invalid signer_id — refuse the lookup. Verifier surfaces
                // (downstream) as KeyNotFound when the resolver returns None.
                return None;
            }
            let encoded = encode_signer_id_for_filename(signer_id);
            let candidate = dir.join(format!("{}.public.pem", encoded));
            if candidate.exists() {
                // Defence-in-depth: canonical-path check rejects symlink escapes.
                if let (Ok(c_can), Ok(d_can)) = (
                    std::fs::canonicalize(&candidate),
                    std::fs::canonicalize(dir),
                ) && !c_can.starts_with(&d_can)
                {
                    return None;
                }
                if let Ok(pem_bytes) = std::fs::read(&candidate) {
                    return resolved_from_pem_or_raw(&pem_bytes);
                }
                // File exists but unreadable — fall through to trust store.
            }
            // Not in key_dir — fall through (key_dir is additive per PRD §4.1.5).
        }

        // 3. Local trust store.
        if let Ok(json) = crate::trust::get_trusted_agent(signer_id)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&json)
        {
            let pem_str = value
                .get("jacsAgentPublicKey")
                .and_then(|v| v.as_str())
                .or_else(|| value.get("publicKey").and_then(|v| v.as_str()))
                .map(|s| s.to_string());
            if let Some(pem) = pem_str {
                return resolved_from_pem_or_raw(pem.as_bytes());
            }
        }

        // 4. DNS — TODO in v0.11.0; resolver returns None producing KeyNotFound.
        None
    }
}

/// Build a `ResolvedKey` from key bytes that may be a PEM file (on-disk in
/// `--key-dir` or in a trust-store agent doc) or a raw key blob. We try
/// `pem::parse` first; if that yields valid PEM, the contents go to the
/// downstream crypt primitive (which accepts PEM for RSA-PSS) and the raw
/// bytes go to ed25519/pq2025 primitives. The publicKeyHash check uses
/// `normalize_public_key_pem` which tolerates both.
fn resolved_from_pem_or_raw(pem_bytes: &[u8]) -> Option<crate::inline::ResolvedKey> {
    // Try to extract the inner key bytes from the PEM block. For Ed25519 and
    // pq2025, the PEM body IS the raw bytes (after base64 decode); for
    // RSA-PSS, the body is DER and the verify primitive needs the PEM bytes
    // back — so we keep the original PEM bytes for RSA but raw bytes for
    // others.
    let inner = match pem::parse(pem_bytes) {
        Ok(block) => block.into_contents(),
        Err(_) => pem_bytes.to_vec(),
    };
    let algorithm = crate::crypt::detect_algorithm_from_public_key(&inner)
        .ok()
        .map(inline_algorithm_tag)
        .unwrap_or_else(|| "ed25519".to_string());
    let key_bytes = match algorithm.as_str() {
        "rsa-pss" => pem_bytes.to_vec(),
        _ => inner,
    };
    Some(crate::inline::ResolvedKey {
        public_key_pem: key_bytes,
        algorithm,
    })
}

/// Map JACS-internal algorithm names (e.g. `Display` of
/// [`crate::crypt::CryptoSigningAlgorithm`] or PEM-derived strings) to the
/// lower-case tags used in inline signature blocks.
fn inline_algorithm_tag<T: std::fmt::Display>(algo: T) -> String {
    let s = algo.to_string();
    match s.as_str() {
        "ring-Ed25519" | "ed25519" | "Ed25519" => "ed25519".to_string(),
        "pq2025" | "ML-DSA-87" | "ml-dsa-87" => "pq2025".to_string(),
        "RSA-PSS" | "rsa-pss" => "rsa-pss".to_string(),
        _ => s.to_lowercase(),
    }
}

/// Sign the contents of a text file in-place. PRD §4.1.
///
/// Atomic-write semantics: a sibling temp file is written and atomically renamed
/// over `path`. On any error, the temp file is auto-cleaned and the original
/// file is unchanged. If `opts.backup` is true (the default), the original is
/// copied to `<path>.bak` before the sign.
///
/// Duplicate-signer detection: if the file already contains a valid signature
/// from this agent over the unchanged content, the call is a no-op (no second
/// block written, no error, no .bak update). The returned `SignTextOutcome.signers_added`
/// is 0 in that case.
pub fn sign_text_file(
    agent: &SimpleAgent,
    path: &str,
    opts: SignTextOptions,
) -> Result<SignTextOutcome, JacsError> {
    use std::io::Write;

    let path_obj = std::path::Path::new(path);
    let original = std::fs::read_to_string(path).map_err(|e| JacsError::FileReadFailed {
        path: path.to_string(),
        reason: e.to_string(),
    })?;

    let new_content = crate::inline::sign_inline(&original, agent)?;

    let signers_added = if new_content == original { 0 } else { 1 };

    // Idempotent no-op: file unchanged, skip write/backup.
    if signers_added == 0 && !opts.allow_duplicate {
        return Ok(SignTextOutcome {
            path: path.to_string(),
            signers_added: 0,
            backup_path: None,
        });
    }

    // Write backup BEFORE we touch the file. If backup fails, abort.
    let backup_path = if opts.backup {
        let bak = format!("{}.bak", path);
        std::fs::copy(path, &bak).map_err(|e| JacsError::FileWriteFailed {
            path: bak.clone(),
            reason: e.to_string(),
        })?;
        Some(bak)
    } else {
        None
    };

    // Atomic write via tempfile in the same directory.
    let parent = path_obj
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp =
        tempfile::NamedTempFile::new_in(parent).map_err(|e| JacsError::FileWriteFailed {
            path: path.to_string(),
            reason: format!("create tempfile: {}", e),
        })?;
    tmp.write_all(new_content.as_bytes())
        .map_err(|e| JacsError::FileWriteFailed {
            path: path.to_string(),
            reason: format!("write tempfile: {}", e),
        })?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| JacsError::FileWriteFailed {
            path: path.to_string(),
            reason: format!("sync tempfile: {}", e),
        })?;

    // Preserve mode bits (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            let _ = std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode));
        }
    }

    tmp.persist(path).map_err(|e| JacsError::FileWriteFailed {
        path: path.to_string(),
        reason: format!("persist tempfile: {}", e),
    })?;

    Ok(SignTextOutcome {
        path: path.to_string(),
        signers_added,
        backup_path,
    })
}

/// Verify every signature block in a text file. PRD §4.1, §4.1.5.
///
/// Permissive (`opts.strict == false`, default): missing-signature returns
/// `Ok(VerifyTextResult::MissingSignature)`; never `Err`.
///
/// Strict (`opts.strict == true`): missing-signature returns
/// `Err(JacsError::MissingSignature)`. File-level malformed (BEGIN with no
/// matching END) returns `Err(JacsError::ValidationError(...))` with a
/// `"malformed signature block"` prefix.
///
/// Per-block failures (bad YAML, invalid signature, unknown signer) NEVER
/// escalate to `Err` — they appear as `SignatureStatus` entries inside the
/// returned `Signed { signatures }` variant.
pub fn verify_text_file(
    agent: &SimpleAgent,
    path: &str,
    opts: crate::inline::VerifyOptions,
) -> Result<crate::inline::VerifyTextResult, JacsError> {
    let framed = std::fs::read_to_string(path).map_err(|e| JacsError::FileReadFailed {
        path: path.to_string(),
        reason: e.to_string(),
    })?;

    let key_dir_owned = opts.key_dir.clone();
    let resolver = DefaultKeyResolver::new(agent, key_dir_owned.as_deref());
    match crate::inline::verify_inline(&framed, &resolver, opts) {
        Ok(result) => Ok(result),
        Err(crate::inline::InlineVerifyError::MissingSignature) => {
            Err(JacsError::MissingSignature(path.to_string()))
        }
        Err(crate::inline::InlineVerifyError::Malformed(s)) => Err(JacsError::ValidationError(
            format!("malformed signature block: {}", s),
        )),
    }
}

// =============================================================================
// Image / media signature operations (Task 06, PRD §4.2)
// =============================================================================

/// Sign an image file. PRD §4.2.5.
///
/// Reads `in_path`, embeds a JACS signed-document JSON payload in the format-
/// appropriate metadata chunk (PNG iTXt / JPEG APP11 / WebP XMP), and writes
/// to `out_path`. Atomic-write + optional `.bak` backup per PRD §4.2.4a.
pub fn sign_image(
    agent: &SimpleAgent,
    in_path: &str,
    out_path: &str,
    opts: SignImageOptions,
) -> Result<SignedMedia, JacsError> {
    use std::io::Write;

    let bytes = std::fs::read(in_path).map_err(|e| JacsError::FileReadFailed {
        path: in_path.to_string(),
        reason: e.to_string(),
    })?;

    // Format detection — clean error on unsupported.
    let fmt = jacs_media::detect_format(&bytes).map_err(|_| {
        JacsError::ValidationError(format!("unsupported format for image at '{}'", in_path))
    })?;
    let format_str = match fmt {
        jacs_media::MediaFormat::Png => "png",
        jacs_media::MediaFormat::Jpeg => "jpeg",
        jacs_media::MediaFormat::WebP => "webp",
    };

    // Refuse-overwrite guard (PRD §4.2.2).
    if opts.refuse_overwrite
        && let Ok(Some(_)) = jacs_media::extract_signature(&bytes, false)
    {
        return Err(JacsError::ValidationError(
            "input already carries a JACS signature — pass refuse_overwrite=false to replace"
                .to_string(),
        ));
    }

    // Canonical hash — robust selector per PRD §4.2.3.
    let canonical_hash = if opts.robust {
        jacs_media::canonical_hash_robust(&bytes).map_err(media_to_jacs_err)?
    } else {
        jacs_media::canonical_hash(&bytes).map_err(media_to_jacs_err)?
    };
    let canonicalization = if opts.robust {
        "jacs-media-v1-robust"
    } else {
        "jacs-media-v1"
    };

    // publicKeyHash field per PRD §4.2.2.
    let signer_pem = agent.get_public_key_pem()?;
    let normalised_pem = crate::crypt::normalize_public_key_pem(signer_pem.as_bytes());
    let pkh_raw = sha256_bytes_local(normalised_pem.as_bytes());
    let public_key_hash = format!("sha256-b64url:{}", base64url_nopad_local(&pkh_raw));

    // Pixel-hash for robust mode. Reuse canonical_hash_robust as the pixel
    // hash — both are sha256 over the canonicalised, LSB-zeroed pixel bytes,
    // so they are necessarily equal. Document as such; future versions could
    // diverge if we add a separate pre-LSB pixel commitment.
    let pixel_hash = if opts.robust {
        Some(format!(
            "sha256-b64url:{}",
            base64url_nopad_local(&canonical_hash)
        ))
    } else {
        None
    };

    let claim = json!({
        "mediaSignatureVersion": 1,
        "format": format_str,
        "canonicalization": canonicalization,
        "hashAlgorithm": "sha256",
        "contentHash": base64url_nopad_local(&canonical_hash),
        "publicKeyHash": public_key_hash,
        "embeddingChannels": if opts.robust {
            json!(["metadata", "lsb"])
        } else {
            json!(["metadata"])
        },
        "robust": opts.robust,
        "pixelHash": pixel_hash,
    });

    // Sign the claim — sign_message wraps into a SignedDocument and persists.
    let signed_doc = agent.sign_message(&claim)?;

    // Embed via jacs-media. The wire format is base64url-encoded JSON
    // (PRD §4.2.2 C3) so the WebP XMP attribute does not break on JSON
    // quote characters.
    let payload_b64url = base64url_nopad_local(signed_doc.raw.as_bytes());
    let new_bytes =
        jacs_media::embed_signature(&bytes, &payload_b64url, opts.robust, opts.refuse_overwrite)
            .map_err(media_to_jacs_err)?;

    // Determine backup behavior and write.
    let in_canon = std::fs::canonicalize(in_path).ok();
    let out_canon = std::fs::canonicalize(out_path).ok();
    let in_place = match (in_canon.as_ref(), out_canon.as_ref()) {
        (Some(a), Some(b)) => a == b,
        _ => in_path == out_path,
    };

    let backup_path = if opts.backup && (in_place || std::path::Path::new(out_path).exists()) {
        let bak = format!("{}.bak", out_path);
        // Symlink reject: refuse to follow an existing .bak that is a symlink.
        if let Ok(meta) = std::fs::symlink_metadata(&bak)
            && meta.file_type().is_symlink()
        {
            return Err(JacsError::ValidationError(format!(
                "refusing to follow symlink at backup path '{}'",
                bak
            )));
        }
        // Backup source: when in_place, the source bytes ARE the input bytes
        // we already read. Otherwise, only back up if out_path exists.
        let src_bytes: Vec<u8> = if in_place {
            bytes.clone()
        } else {
            std::fs::read(out_path).unwrap_or_else(|_| Vec::new())
        };
        std::fs::write(&bak, &src_bytes).map_err(|e| JacsError::FileWriteFailed {
            path: bak.clone(),
            reason: e.to_string(),
        })?;
        // Apply backup mode bits (Unix only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = opts.unsafe_bak_mode.unwrap_or(0o600);
            let _ = std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(mode));
        }
        Some(bak)
    } else {
        None
    };

    // Atomic write of new_bytes to out_path.
    let out_path_obj = std::path::Path::new(out_path);
    let parent = out_path_obj
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp =
        tempfile::NamedTempFile::new_in(parent).map_err(|e| JacsError::FileWriteFailed {
            path: out_path.to_string(),
            reason: format!("create tempfile: {}", e),
        })?;
    tmp.write_all(&new_bytes)
        .map_err(|e| JacsError::FileWriteFailed {
            path: out_path.to_string(),
            reason: format!("write tempfile: {}", e),
        })?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| JacsError::FileWriteFailed {
            path: out_path.to_string(),
            reason: format!("sync tempfile: {}", e),
        })?;

    // Mode preservation: if out_path exists, mirror its mode; else mirror in_path.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode_src = if out_path_obj.exists() {
            out_path
        } else {
            in_path
        };
        if let Ok(meta) = std::fs::metadata(mode_src) {
            let mode = meta.permissions().mode();
            let _ = std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode));
        }
    }

    tmp.persist(out_path)
        .map_err(|e| JacsError::FileWriteFailed {
            path: out_path.to_string(),
            reason: format!("persist tempfile: {}", e),
        })?;

    let signer_id = agent.get_agent_id()?;
    Ok(SignedMedia {
        out_path: out_path.to_string(),
        signer_id,
        format: format_str.to_string(),
        robust: opts.robust,
        backup_path,
    })
}

/// Verify the JACS signature embedded in an image. PRD §4.2.5.
pub fn verify_image(
    agent: &SimpleAgent,
    path: &str,
    opts: VerifyImageOptions,
) -> Result<MediaVerificationResult, JacsError> {
    let bytes = std::fs::read(path).map_err(|e| JacsError::FileReadFailed {
        path: path.to_string(),
        reason: e.to_string(),
    })?;

    // Format detection.
    let fmt = match jacs_media::detect_format(&bytes) {
        Ok(f) => f,
        Err(_) => {
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::UnsupportedFormat,
                signer_id: None,
                algorithm: None,
                format: None,
                embedding_channels: None,
            });
        }
    };
    let format_str = match fmt {
        jacs_media::MediaFormat::Png => "png",
        jacs_media::MediaFormat::Jpeg => "jpeg",
        jacs_media::MediaFormat::WebP => "webp",
    };

    // Extract payload. The wire form is base64url-encoded JSON (PRD §4.2.2 C3).
    let raw_b64 = match jacs_media::extract_signature(&bytes, opts.scan_robust) {
        Ok(Some(p)) => p,
        Ok(None) => {
            if opts.base.strict {
                return Err(JacsError::MissingSignature(path.to_string()));
            }
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::MissingSignature,
                signer_id: None,
                algorithm: None,
                format: Some(format_str.to_string()),
                embedding_channels: None,
            });
        }
        Err(e) => {
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::Malformed(format!("{}", e)),
                signer_id: None,
                algorithm: None,
                format: Some(format_str.to_string()),
                embedding_channels: None,
            });
        }
    };

    // Decode base64url → JSON string.
    use base64::Engine;
    let payload = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw_b64.as_bytes())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
    {
        Some(s) => s,
        None => {
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::Malformed(
                    "embedded payload is not valid base64url JSON".to_string(),
                ),
                signer_id: None,
                algorithm: None,
                format: Some(format_str.to_string()),
                embedding_channels: None,
            });
        }
    };

    // Parse signed document.
    let signed_doc_value: serde_json::Value = match serde_json::from_str(&payload) {
        Ok(v) => v,
        Err(e) => {
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::Malformed(format!("payload not JSON: {}", e)),
                signer_id: None,
                algorithm: None,
                format: Some(format_str.to_string()),
                embedding_channels: None,
            });
        }
    };

    // Schema validation: read inner content (the SignedMediaClaim).
    let claim = match signed_doc_value.pointer("/content") {
        Some(c) => c,
        None => {
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::Malformed(
                    "signed document missing /content".to_string(),
                ),
                signer_id: None,
                algorithm: None,
                format: Some(format_str.to_string()),
                embedding_channels: None,
            });
        }
    };

    let media_sig_ver = claim.get("mediaSignatureVersion").and_then(|v| v.as_u64());
    if media_sig_ver != Some(1) {
        return Ok(MediaVerificationResult {
            status: MediaVerifyStatus::Malformed(format!(
                "unsupported mediaSignatureVersion: {:?}",
                media_sig_ver
            )),
            signer_id: None,
            algorithm: None,
            format: Some(format_str.to_string()),
            embedding_channels: None,
        });
    }
    let claim_format = claim.get("format").and_then(|v| v.as_str()).unwrap_or("");
    if claim_format != format_str {
        return Ok(MediaVerificationResult {
            status: MediaVerifyStatus::Malformed(format!(
                "format mismatch: claim says {}, actual is {}",
                claim_format, format_str
            )),
            signer_id: None,
            algorithm: None,
            format: Some(format_str.to_string()),
            embedding_channels: None,
        });
    }
    let claim_hash_algo = claim
        .get("hashAlgorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if claim_hash_algo != "sha256" {
        return Ok(MediaVerificationResult {
            status: MediaVerifyStatus::Malformed(format!(
                "unsupported hashAlgorithm: {}",
                claim_hash_algo
            )),
            signer_id: None,
            algorithm: None,
            format: Some(format_str.to_string()),
            embedding_channels: None,
        });
    }
    let canonicalization = claim
        .get("canonicalization")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let claim_pkh = match claim.get("publicKeyHash").and_then(|v| v.as_str()) {
        Some(s) if s.starts_with("sha256-b64url:") => s.to_string(),
        _ => {
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::Malformed(
                    "publicKeyHash missing or malformed".to_string(),
                ),
                signer_id: None,
                algorithm: None,
                format: Some(format_str.to_string()),
                embedding_channels: None,
            });
        }
    };

    // Hash check using the canonicaliser the claim names.
    let computed_hash = match canonicalization {
        "jacs-media-v1" => jacs_media::canonical_hash(&bytes).map_err(media_to_jacs_err)?,
        "jacs-media-v1-robust" => {
            jacs_media::canonical_hash_robust(&bytes).map_err(media_to_jacs_err)?
        }
        other => {
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::Malformed(format!(
                    "unsupported canonicalization: {}",
                    other
                )),
                signer_id: None,
                algorithm: None,
                format: Some(format_str.to_string()),
                embedding_channels: None,
            });
        }
    };
    let claim_hash = claim
        .get("contentHash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if claim_hash != base64url_nopad_local(&computed_hash) {
        return Ok(MediaVerificationResult {
            status: MediaVerifyStatus::HashMismatch,
            signer_id: None,
            algorithm: None,
            format: Some(format_str.to_string()),
            embedding_channels: None,
        });
    }

    // Identify signer in the SignedDocument's outer jacsSignature.
    let signer_id = signed_doc_value
        .pointer("/jacsSignature/agentID")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let algorithm = signed_doc_value
        .pointer("/jacsSignature/signing_algorithm")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Resolve key based on signer identity.
    let resolver = DefaultKeyResolver::new(agent, opts.base.key_dir.as_deref());
    let signer_id_str = match signer_id.as_ref() {
        Some(s) => s,
        None => {
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::Malformed(
                    "signed document missing jacsSignature.agentID".to_string(),
                ),
                signer_id: None,
                algorithm: None,
                format: Some(format_str.to_string()),
                embedding_channels: None,
            });
        }
    };

    let resolved = match crate::inline::KeyResolver::resolve(&resolver, signer_id_str) {
        Some(r) => r,
        None => {
            if opts.base.strict {
                return Err(JacsError::TrustError(format!(
                    "key not found for signer '{}'",
                    signer_id_str
                )));
            }
            return Ok(MediaVerificationResult {
                status: MediaVerifyStatus::KeyNotFound,
                signer_id,
                algorithm,
                format: Some(format_str.to_string()),
                embedding_channels: None,
            });
        }
    };

    // PublicKeyHash check (PRD §4.2.2 + §4.1.1 parity).
    let resolved_pem_normalised = crate::crypt::normalize_public_key_pem(&resolved.public_key_pem);
    let resolved_pkh_raw = sha256_bytes_local(resolved_pem_normalised.as_bytes());
    let expected_pkh = format!("sha256-b64url:{}", base64url_nopad_local(&resolved_pkh_raw));
    if expected_pkh != claim_pkh {
        if opts.base.strict {
            return Err(JacsError::TrustError(format!(
                "publicKeyHash mismatch for signer '{}': resolved key does not match claim",
                signer_id_str
            )));
        }
        return Ok(MediaVerificationResult {
            status: MediaVerifyStatus::KeyNotFound,
            signer_id,
            algorithm,
            format: Some(format_str.to_string()),
            embedding_channels: None,
        });
    }

    // Verify cryptographic signature. Same-agent path uses agent.verify;
    // cross-agent path uses verify_with_key with the resolved key bytes.
    //
    // We pass `resolved.public_key_pem` directly (the resolver returns RAW
    // bytes for ed25519/pq2025 and PEM bytes for RSA-PSS) because
    // `verify_document_signature` re-hashes its `public_key` argument with
    // `hash_public_key()` and compares to the embedded `jacsSignature.publicKeyHash`,
    // which was computed at sign time over the same RAW (or PEM-for-RSA) form.
    // Re-armoring through `normalize_public_key_pem` would silently break that
    // comparison for ed25519/pq2025 cross-agent verification.
    let my_id = agent.get_agent_id().ok();
    let verify_result = if my_id.as_deref() == Some(signer_id_str) {
        agent.verify(&payload)
    } else {
        agent.verify_with_key(&payload, resolved.public_key_pem.clone())
    };

    let status = match verify_result {
        Ok(v) => {
            if v.valid {
                MediaVerifyStatus::Valid
            } else {
                MediaVerifyStatus::InvalidSignature
            }
        }
        Err(JacsError::HashMismatch { .. }) => MediaVerifyStatus::HashMismatch,
        Err(_) => MediaVerifyStatus::InvalidSignature,
    };

    let embedding_channels = match status {
        MediaVerifyStatus::Valid => Some(
            if claim
                .get("robust")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                "metadata+lsb".to_string()
            } else {
                "metadata".to_string()
            },
        ),
        _ => None,
    };

    Ok(MediaVerificationResult {
        status,
        signer_id,
        algorithm,
        format: Some(format_str.to_string()),
        embedding_channels,
    })
}

/// Extract the embedded JACS signed-document JSON. Returns the **decoded**
/// JSON string by default — for the base64url wire form (as written to the
/// metadata chunk) use [`extract_media_signature_raw`].
pub fn extract_media_signature(path: &str) -> Result<Option<String>, JacsError> {
    use base64::Engine;
    let bytes = std::fs::read(path).map_err(|e| JacsError::FileReadFailed {
        path: path.to_string(),
        reason: e.to_string(),
    })?;
    match jacs_media::extract_signature(&bytes, false).map_err(media_to_jacs_err)? {
        Some(raw_b64) => {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(raw_b64.as_bytes())
                .map_err(|e| {
                    JacsError::ValidationError(format!("media payload base64url decode: {}", e))
                })?;
            let json = String::from_utf8(decoded).map_err(|e| {
                JacsError::ValidationError(format!("media payload not UTF-8: {}", e))
            })?;
            Ok(Some(json))
        }
        None => Ok(None),
    }
}

/// Like [`extract_media_signature`] but returns the **raw** base64url-encoded
/// payload as written to the metadata chunk. Useful for byte-for-byte relay,
/// fuzzing, and protocol debugging.
pub fn extract_media_signature_raw(path: &str) -> Result<Option<String>, JacsError> {
    let bytes = std::fs::read(path).map_err(|e| JacsError::FileReadFailed {
        path: path.to_string(),
        reason: e.to_string(),
    })?;
    jacs_media::extract_signature(&bytes, false).map_err(media_to_jacs_err)
}

// =============================================================================
// Local helpers
// =============================================================================

fn media_to_jacs_err(e: jacs_media::MediaError) -> JacsError {
    use jacs_media::MediaError;
    match e {
        MediaError::PayloadTooLarge { limit, actual } => JacsError::ValidationError(format!(
            "image signature payload exceeds format limit: actual {} > pixel capacity / chunk limit {}",
            actual, limit
        )),
        MediaError::Unsupported(msg) => {
            JacsError::ValidationError(format!("media unsupported: {}", msg))
        }
        MediaError::UnsupportedFormat => {
            JacsError::ValidationError("unsupported media format".to_string())
        }
        MediaError::Parse(s) => JacsError::ValidationError(format!("media parse error: {}", s)),
        MediaError::Encode(s) => JacsError::ValidationError(format!("media encode error: {}", s)),
    }
}

fn sha256_bytes_local(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn base64url_nopad_local(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
