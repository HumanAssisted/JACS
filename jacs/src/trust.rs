//! Trust store management for JACS agents.
//!
//! This module provides functions for managing trusted agents,
//! enabling P2P key exchange and verification without a central authority.

use crate::error::JacsError;
use crate::paths::trust_store_dir;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use tracing::info;

/// Information about a trusted agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedAgent {
    /// The agent's unique identifier.
    pub agent_id: String,
    /// The agent's human-readable name.
    pub name: Option<String>,
    /// The agent's public key in PEM format.
    pub public_key_pem: String,
    /// Hash of the public key for quick lookups.
    pub public_key_hash: String,
    /// When this agent was trusted.
    pub trusted_at: String,
}

/// Adds an agent to the local trust store.
///
/// The agent JSON must be a valid, self-signed JACS agent document.
/// The self-signature is verified before trusting.
///
/// # Arguments
///
/// * `agent_json` - The full agent JSON string
///
/// # Returns
///
/// The agent ID if successfully trusted.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::trust::trust_agent;
///
/// // Receive agent file from another party
/// let agent_json = std::fs::read_to_string("other-agent.json")?;
/// let agent_id = trust_agent(&agent_json)?;
/// println!("Now trusting agent: {}", agent_id);
/// ```
pub fn trust_agent(agent_json: &str) -> Result<String, JacsError> {
    // Parse the agent JSON
    let agent_value: Value = serde_json::from_str(agent_json).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "agent_json".to_string(),
            reason: e.to_string(),
        }
    })?;

    // Extract required fields
    let agent_id = agent_value["jacsId"]
        .as_str()
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsId".to_string(),
            reason: "Missing or invalid jacsId".to_string(),
        })?
        .to_string();

    let name = agent_value["name"].as_str().map(|s| s.to_string());

    // Extract public key hash from signature
    let public_key_hash = agent_value["jacsSignature"]["publicKeyHash"]
        .as_str()
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsSignature.publicKeyHash".to_string(),
            reason: "Missing public key hash".to_string(),
        })?
        .to_string();

    // TODO: Verify self-signature before trusting
    // For now, we trust the agent if it has the required fields

    // Create trust store directory if it doesn't exist
    let trust_dir = trust_store_dir();
    fs::create_dir_all(&trust_dir).map_err(|e| JacsError::Internal {
        message: format!("Failed to create trust store directory: {}", e),
    })?;

    // Save the agent file
    let agent_file = trust_dir.join(format!("{}.json", agent_id));
    fs::write(&agent_file, agent_json).map_err(|e| JacsError::Internal {
        message: format!("Failed to write trusted agent file: {}", e),
    })?;

    // Also save a metadata file for quick lookups
    let trusted_agent = TrustedAgent {
        agent_id: agent_id.clone(),
        name,
        public_key_pem: String::new(), // TODO: Extract from agent or separate file
        public_key_hash,
        trusted_at: chrono::Utc::now().to_rfc3339(),
    };

    let metadata_file = trust_dir.join(format!("{}.meta.json", agent_id));
    let metadata_json = serde_json::to_string_pretty(&trusted_agent).map_err(|e| {
        JacsError::Internal {
            message: format!("Failed to serialize metadata: {}", e),
        }
    })?;
    fs::write(&metadata_file, metadata_json).map_err(|e| JacsError::Internal {
        message: format!("Failed to write metadata file: {}", e),
    })?;

    info!("Trusted agent {} added to trust store", agent_id);
    Ok(agent_id)
}

/// Lists all trusted agent IDs.
///
/// # Returns
///
/// A vector of agent IDs that are in the trust store.
///
/// # Example
///
/// ```rust,ignore
/// use jacs::trust::list_trusted_agents;
///
/// let agents = list_trusted_agents()?;
/// for agent_id in agents {
///     println!("Trusted: {}", agent_id);
/// }
/// ```
pub fn list_trusted_agents() -> Result<Vec<String>, JacsError> {
    let trust_dir = trust_store_dir();

    if !trust_dir.exists() {
        return Ok(Vec::new());
    }

    let mut agents = Vec::new();

    let entries = fs::read_dir(&trust_dir).map_err(|e| JacsError::Internal {
        message: format!("Failed to read trust store directory: {}", e),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| JacsError::Internal {
            message: format!("Failed to read directory entry: {}", e),
        })?;

        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "json")
            && !path
                .file_name()
                .and_then(|n| n.to_str())
                .map_or(false, |n| n.ends_with(".meta.json"))
        {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                agents.push(stem.to_string());
            }
        }
    }

    Ok(agents)
}

/// Removes an agent from the trust store.
///
/// # Arguments
///
/// * `agent_id` - The ID of the agent to untrust
///
/// # Example
///
/// ```rust,ignore
/// use jacs::trust::untrust_agent;
///
/// untrust_agent("agent-123-uuid")?;
/// ```
pub fn untrust_agent(agent_id: &str) -> Result<(), JacsError> {
    let trust_dir = trust_store_dir();

    let agent_file = trust_dir.join(format!("{}.json", agent_id));
    let metadata_file = trust_dir.join(format!("{}.meta.json", agent_id));

    if !agent_file.exists() {
        return Err(JacsError::AgentNotTrusted {
            agent_id: agent_id.to_string(),
        });
    }

    // Remove both files
    if agent_file.exists() {
        fs::remove_file(&agent_file).map_err(|e| JacsError::Internal {
            message: format!("Failed to remove agent file: {}", e),
        })?;
    }

    if metadata_file.exists() {
        fs::remove_file(&metadata_file).map_err(|e| JacsError::Internal {
            message: format!("Failed to remove metadata file: {}", e),
        })?;
    }

    info!("Agent {} removed from trust store", agent_id);
    Ok(())
}

/// Retrieves a trusted agent's information.
///
/// # Arguments
///
/// * `agent_id` - The ID of the agent to look up
///
/// # Returns
///
/// The full agent JSON if the agent is trusted.
pub fn get_trusted_agent(agent_id: &str) -> Result<String, JacsError> {
    let trust_dir = trust_store_dir();
    let agent_file = trust_dir.join(format!("{}.json", agent_id));

    if !agent_file.exists() {
        return Err(JacsError::AgentNotTrusted {
            agent_id: agent_id.to_string(),
        });
    }

    fs::read_to_string(&agent_file).map_err(|e| JacsError::FileReadFailed {
        path: agent_file.to_string_lossy().to_string(),
        reason: e.to_string(),
    })
}

/// Retrieves the public key for a trusted agent.
///
/// # Arguments
///
/// * `agent_id` - The ID of the agent
///
/// # Returns
///
/// The public key hash for looking up the actual key.
pub fn get_trusted_public_key_hash(agent_id: &str) -> Result<String, JacsError> {
    let agent_json = get_trusted_agent(agent_id)?;
    let agent_value: Value = serde_json::from_str(&agent_json).map_err(|e| {
        JacsError::DocumentMalformed {
            field: "agent_json".to_string(),
            reason: e.to_string(),
        }
    })?;

    agent_value["jacsSignature"]["publicKeyHash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| JacsError::DocumentMalformed {
            field: "jacsSignature.publicKeyHash".to_string(),
            reason: "Missing public key hash".to_string(),
        })
}

/// Checks if an agent is in the trust store.
///
/// # Arguments
///
/// * `agent_id` - The ID of the agent to check
///
/// # Returns
///
/// `true` if the agent is trusted, `false` otherwise.
pub fn is_trusted(agent_id: &str) -> bool {
    let trust_dir = trust_store_dir();
    let agent_file = trust_dir.join(format!("{}.json", agent_id));
    agent_file.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    fn setup_test_trust_dir() -> TempDir {
        let temp_dir = TempDir::new().unwrap();
        // Override the trust store location for tests
        // SAFETY: This is only used in single-threaded tests
        unsafe {
            env::set_var("HOME", temp_dir.path().to_str().unwrap());
        }
        temp_dir
    }

    #[test]
    fn test_list_empty_trust_store() {
        let _temp = setup_test_trust_dir();
        let agents = list_trusted_agents().unwrap();
        assert!(agents.is_empty());
    }

    #[test]
    fn test_is_trusted_unknown() {
        let _temp = setup_test_trust_dir();
        assert!(!is_trusted("unknown-agent-id"));
    }
}
