use crate::crypt::rsawrapper;
use crate::loaders::FileLoader;
use crate::schema::Schema;
use crate::schema::ValueExt;
use serde_json::Value;
use std::error::Error;
use std::fmt;

pub struct Agent<T: FileLoader> {
    schema: Schema,
    loader: T,
    value: Option<Value>,
    id: Option<String>,
    version: Option<String>,
    public_key: Option<String>,
    private_key: Option<String>,
    key_algorithm: Option<String>,
}

impl<T: FileLoader> fmt::Display for Agent<T> {
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

impl<T: FileLoader> Agent<T> {
    pub fn new(loader: T, version: &str) -> Result<Self, Box<dyn Error>> {
        let schema = Schema::new("agent", version)?;
        Ok(Self {
            schema,
            loader,
            value: None,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
        })
    }

    pub fn id(&self) -> Result<String, Box<dyn Error>> {
        match &self.id {
            Some(id) => Ok(id.to_string()),
            None => Err("id is None".into()),
        }
    }

    pub fn version(&self) -> Result<String, Box<dyn Error>> {
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

    pub fn save(&self) -> Result<String, Box<dyn Error>> {
        let agent_string = self.as_string()?;
        return self.loader.save_agent_string(&agent_string);
    }

    // loads and validates agent
    pub fn load(&mut self, id: String, _version: Option<String>) -> Result<(), Box<dyn Error>> {
        let agent_string = self.loader.load_local_agent_by_id(&id)?;
        match &self.validate(&agent_string) {
            Ok(value) => {
                self.value = Some(value.clone());
                if let Some(ref value) = self.value {
                    self.id = value.get_str("id");
                    self.version = value.get_str("version");
                }
                Ok(())
            }
            Err(e) => Err(e),
        };
        return Ok(());
    }

    // pub fn load(&mut self, json_data: &String, privatekeypath: &String){
    //     let result = self.validate(json_data);
    //     match result {
    //         Ok(data) => {

    //         }
    //         Err(e) => {
    //             return Err(format!("Failed to read 'examples/myagent.json': {}", e));
    //         }
    //     };

    //     // now load keys
    //     self.value = Some(value);
    //     self.value = Some(value);
    //     // if they don't exist tell them they must create first

    // }

    /// returns path and filename of keys
    pub fn newkeys(
        &mut self,
        algorithm: &String,
        filepath_prefix: &String,
    ) -> Result<(String, String), String> {
        // make sure the actor has an id and is loaded
        let agent_id = &self.id;
        let agent_version = &self.version;

        if algorithm == "rsa-pss" {
            let (private_key_path, public_key_path) =
                rsawrapper::generate_keys(filepath_prefix).map_err(|e| e.to_string())?;
            Ok((private_key_path, public_key_path))
        } else if algorithm == "ring-Ed25519" {
            Err("ring-Ed25519 key generation is not implemented.".to_string())
        } else if algorithm == "pq-dilithium" {
            Err("pq-dilithium key generation is not implemented.".to_string())
        } else {
            // Handle other algorithms or return an error
            Err(format!(
                "{} is not a known or implemented algorithm.",
                algorithm
            ))
        }
    }

    pub fn validate(&mut self, json: &str) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        let value = self.schema.validate(json)?;

        // additional validation
        return Ok(value);
    }

    pub fn create(&mut self, json: &str) -> Result<(), String> {
        // create json string
        // validate schema json string
        // make sure id and version are empty
        // create keys
        // self-sign as owner
        // validate signature
        // save
        // updatekey is the except we increment version and preserve id
        // update actions produces signatures
        // self.validate();

        Ok(())
    }

    pub fn edit(&mut self, _json: &str) -> Result<(), String> {
        // validate new json string
        // diff strings
        // validate editor can make changes

        Ok(())
    }
}

/*

todo

 - load actor and sign and act on other things
 - which requires a private key
 - also a verifier
 - remote public key or embeeded?


EVERY resource(actor) and task has

1. hash/checksum based on
  - previous hash, id, version
2. signature based on hash



*/
