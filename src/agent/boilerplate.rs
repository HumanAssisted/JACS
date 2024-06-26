use crate::agent::Agent;
use std::error::Error;

pub trait BoilerPlate {
    fn get_id(&self) -> Result<String, Box<dyn Error>>;
    fn get_public_key(&self) -> Result<Vec<u8>, Box<dyn Error>>;
    fn get_version(&self) -> Result<String, Box<dyn Error>>;
    fn as_string(&self) -> Result<String, Box<dyn Error>>;
    fn get_lookup_id(&self) -> Result<String, Box<dyn Error>>;
}

impl BoilerPlate for Agent {
    fn get_id(&self) -> Result<String, Box<dyn Error>> {
        match &self.id {
            Some(id) => Ok(id.to_string()),
            None => Err("id is None".into()),
        }
    }

    fn get_public_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        match &self.public_key {
            Some(public_key) => Ok(public_key.to_vec()),
            None => Err("public_key is None".into()),
        }
    }

    fn get_version(&self) -> Result<String, Box<dyn Error>> {
        match &self.version {
            Some(version) => Ok(version.to_string()),
            None => Err("id is None".into()),
        }
    }

    // for internal uses
    // Display trait is implemented for external uses
    fn as_string(&self) -> Result<String, Box<dyn Error>> {
        match &self.value {
            Some(value) => serde_json::to_string_pretty(value).map_err(|e| e.into()),
            None => Err("Value is None".into()),
        }
    }

    /// combination of id and value
    fn get_lookup_id(&self) -> Result<String, Box<dyn Error>> {
        // return the id and version
        let id = &self.get_id()?;
        let version = &self.get_version()?;
        return Ok(format!("{}:{}", id, version));
    }
}
