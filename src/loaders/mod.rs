use std::error::Error;
pub mod testloader;

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
