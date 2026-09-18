use crate::agent::Agent;
use crate::error::JacsError;

pub trait BoilerPlate {
    fn get_id(&self) -> Result<String, JacsError>;
    fn get_public_key(&self) -> Result<Vec<u8>, JacsError>;
    fn get_version(&self) -> Result<String, JacsError>;
    fn as_string(&self) -> Result<String, JacsError>;
    fn get_lookup_id(&self) -> Result<String, JacsError>;
}

impl BoilerPlate for Agent {
    fn get_id(&self) -> Result<String, JacsError> {
        match &self.id {
            Some(id) => Ok(id.to_string()),
            None => Err(
                "get_id failed: Agent ID is not set. The agent may not be fully loaded or created. \
                Call load(), load_by_id(), or create_agent_and_load() first.".into()
            ),
        }
    }

    fn get_public_key(&self) -> Result<Vec<u8>, JacsError> {
        match &self.public_key {
            Some(public_key) => Ok(public_key.to_vec()),
            None => {
                let agent_id = self.id.as_deref().unwrap_or("<uninitialized>");
                Err(JacsError::KeyNotFound {
                    path: format!(
                        "Public key for agent '{}': Call fs_load_keys() or fs_preload_keys() first, or ensure keys are generated during agent creation.",
                        agent_id
                    ),
                })
            }
        }
    }

    fn get_version(&self) -> Result<String, JacsError> {
        match &self.version {
            Some(version) => Ok(version.to_string()),
            None => {
                let agent_id = self.id.as_deref().unwrap_or("<uninitialized>");
                Err(JacsError::AgentError(format!(
                    "get_version failed for agent '{}': Agent version is not set. \
                    The agent may not be fully loaded or created.",
                    agent_id
                )))
            }
        }
    }

    // for internal uses
    // Display trait is implemented for external uses
    fn as_string(&self) -> Result<String, JacsError> {
        match &self.value {
            Some(value) => serde_json::to_string_pretty(value).map_err(|e| {
                JacsError::AgentError(format!(
                    "as_string failed: Could not serialize agent to JSON: {}",
                    e
                ))
            }),
            None => Err(JacsError::AgentNotLoaded),
        }
    }

    /// combination of id and value
    fn get_lookup_id(&self) -> Result<String, JacsError> {
        // return the id and version
        let id = &self.get_id()?;
        let version = &self.get_version()?;
        Ok(format!("{}:{}", id, version))
    }
}
