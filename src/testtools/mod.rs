use std::error::Error;

use crate::agent::Agent;
pub use crate::loaders::FileLoader;
use std::env;
use std::{fs, path::PathBuf};

/// this is an example of how other libraries can use JACS agents
/// and implement their own loading and saving functions

impl FileLoader for Agent {
    fn save_agent_string(&self, agent_string: &String) -> Result<String, Box<dyn Error>> {
        // Implementation of save method for Agent
        Ok("".to_string())
    }

    fn load_local_agent_by_id(&self, agent_id: &String) -> Result<String, Box<dyn Error>> {
        // Implementation of load_local_agent_by_id method for Agent
        let current_dir = env::current_dir()?;
        let schema_path: PathBuf = current_dir
            .join("examples")
            .join("agents")
            .join(format!("{}.json", agent_id));
        let json_data = fs::read_to_string(schema_path);
        match json_data {
            Ok(data) => {
                println!("testing data {}", data);
                Ok(data.to_string())
            }
            Err(e) => {
                panic!("Failed to find agent: {} {}", agent_id, e);
            }
        }
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
