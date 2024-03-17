use crate::agent::Agent;
use log::{debug, error, warn};
use std::env;
use std::error::Error;
use std::{fs, path::PathBuf};

/// abstract traits that must be implemented by importing libraries
pub trait FileLoader {
    // fn load_json_by_path(&self, filepath: &String) -> String;
    /// needed for foriegn agents and to verify signatures
    fn load_remote_public_key(&self, agentid: &String) -> Result<String, Box<dyn Error>>;
    fn load_local_public_key(&self, agentid: &String) -> Result<String, Box<dyn Error>>;
    fn load_local_unencrypted_private_key(
        &self,
        agentid: &String,
    ) -> Result<String, Box<dyn Error>>;
    fn save_agent_string(&self, agent_string: &String) -> Result<String, Box<dyn Error>>;
    fn load_local_agent_by_id(&self, agentid: &String) -> Result<String, Box<dyn Error>>;
    fn load_remote_agent_by_id(&self, path: &String) -> String;
    fn create_local_agent_by_path(&self, path: &String) -> String;

    // these are expected to be valid JSON, but not necessarily
    //
    fn load_local_document(&self, filepath: &String) -> Result<String, Box<dyn Error>>;
    fn load_local_document_by_id(&self, document_id: &String) -> Result<String, Box<dyn Error>>;

    fn load_remote_document(&self, filepath: &String) -> Result<String, Box<dyn Error>>;

    fn load_remote_document_by_id(&self, document_id: &String) -> Result<String, Box<dyn Error>>;
}

// #[cfg(test)]
impl FileLoader for Agent {
    fn load_remote_public_key(&self, agentid: &String) -> Result<String, Box<dyn Error>> {
        Ok("".to_string())
    }
    fn load_local_public_key(&self, agentid: &String) -> Result<String, Box<dyn Error>> {
        Ok("".to_string())
    }
    fn load_local_unencrypted_private_key(
        &self,
        agentid: &String,
    ) -> Result<String, Box<dyn Error>> {
        Ok("".to_string())
    }

    fn save_agent_string(&self, agent_string: &String) -> Result<String, Box<dyn Error>> {
        // Implementation of save method for Agent
        Ok("".to_string())
    }

    fn load_local_agent_by_id(&self, agent_id: &String) -> Result<String, Box<dyn Error>> {
        // Implementation of load_local_agent_by_id method for Agent
        let current_dir = env::current_dir()?;
        let document_path: PathBuf = current_dir
            .join("examples")
            .join("agents")
            .join(format!("{}.json", agent_id));
        let json_data = fs::read_to_string(document_path);
        match json_data {
            Ok(data) => {
                debug!("testing data {}", data);
                Ok(data.to_string())
            }
            Err(e) => {
                panic!("Failed to find agent: {} {}", agent_id, e);
            }
        }
    }

    fn load_local_document(&self, filepath: &String) -> Result<String, Box<dyn Error>> {
        let current_dir = env::current_dir()?;
        let document_path: PathBuf = current_dir.join(filepath);
        let json_data = fs::read_to_string(document_path);
        match json_data {
            Ok(data) => {
                debug!("testing data {}", data);
                Ok(data.to_string())
            }
            Err(e) => {
                panic!("Failed to find file: {} {}", filepath, e);
            }
        }
    }
    fn load_remote_document(&self, filepath: &String) -> Result<String, Box<dyn Error>> {
        return Ok("".to_string());
    }

    fn load_local_document_by_id(&self, document_id: &String) -> Result<String, Box<dyn Error>> {
        return Ok("".to_string());
    }

    fn load_remote_document_by_id(&self, document_id: &String) -> Result<String, Box<dyn Error>> {
        return Ok("".to_string());
    }

    fn load_remote_agent_by_id(&self, path: &String) -> String {
        // Implementation of load_local_agent_by_path method for Agent
        return "".to_string();
    }

    fn create_local_agent_by_path(&self, path: &String) -> String {
        // Implementation of create_local_agent_by_path method for Agent
        return "".to_string();
    }
}
