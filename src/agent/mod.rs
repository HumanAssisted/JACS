// pub mod document;
pub mod boilerplate;
pub mod loaders;

use crate::crypt::rsawrapper;
use crate::schema::utils::ValueExt;
use crate::schema::Schema;
use boilerplate::BoilerPlate;
use jsonschema::{Draft, JSONSchema};
use loaders::FileLoader;

use log::{debug, error, warn};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use uuid::Uuid;

pub struct Agent {
    /// the JSONSchema used
    schema: Schema,
    /// the agent JSON Struct
    value: Option<Value>,
    /// custom schemas that can be loaded to check documents
    /// the resolver might ahve trouble TEST
    document_schemas: HashMap<String, JSONSchema>,

    /// everything needed for the agent to sign things
    id: Option<String>,
    version: Option<String>,
    public_key: Option<String>,
    private_key: Option<String>,
    key_algorithm: Option<String>,
}

impl fmt::Display for Agent {
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

impl Agent {
    pub fn new(agentversion: &String, headerversion: &String) -> Result<Self, Box<dyn Error>> {
        let schema = Schema::new(agentversion, headerversion)?;
        let mut document_schemas_map: HashMap<String, JSONSchema> = HashMap::new();
        Ok(Self {
            schema,
            value: None,
            document_schemas: document_schemas_map,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
        })
    }

    // loads and validates agent
    pub fn load_by_id(
        &mut self,
        id: String,
        _version: Option<String>,
    ) -> Result<(), Box<dyn Error>> {
        let agent_string = self.load_local_agent_by_id(&id)?;
        return self.load(&agent_string);
    }

    pub fn ready(&mut self) -> bool {
        true
    }

    fn get_private_key(&self) -> Result<String, Box<dyn Error>> {
        match &self.private_key {
            Some(private_key) => Ok(private_key.to_string()),
            None => Err("private_key is None".into()),
        }
    }

    pub fn load(&mut self, agent_string: &String) -> Result<(), Box<dyn Error>> {
        match &self.validate_agent(&agent_string) {
            Ok(value) => {
                self.value = Some(value.clone());
                if let Some(ref value) = self.value {
                    self.id = value.get_str("id");
                    self.version = value.get_str("version");
                }
            }
            Err(e) => {
                error!("ERROR document ERROR {}", e);
                return Err(e.to_string().into());
            }
        }

        if self.id.is_some() {
            let id_string = self.id.clone().expect("string expected").to_string();
            //self.public_key = Some(self.loader.load_local_public_key(&id_string)?);
            //self.private_key = Some(self.loader.load_local_unencrypted_private_key(&id_string)?);
        }

        return Ok(());
    }

    pub fn load_document(&mut self, document_string: &String) -> Result<(), Box<dyn Error>> {
        match &self.validate_header(&document_string) {
            Ok(value) => {
                // self.value = Some(value.clone());
                // if let Some(ref value) = self.value {
                //     self.id = value.get_str("id");
                //     self.version = value.get_str("version");
                // }
                // save document
            }
            Err(e) => {
                error!("ERROR document ERROR {}", e);
                return Err(e.to_string().into());
            }
        }

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

    pub fn validate_header(
        &mut self,
        json: &str,
    ) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        let value = self.schema.validate_header(json)?;

        // additional validation
        return Ok(value);
    }

    pub fn validate_agent(
        &mut self,
        json: &str,
    ) -> Result<Value, Box<dyn std::error::Error + 'static>> {
        let value = self.schema.validate_agent(json)?;

        // additional validation
        return Ok(value);
    }

    /// create an agent, and provde id and version as a result
    pub fn create_agent_and_use(
        &mut self,
        json: &String,
        create_keys: bool,
        _create_keys_algorithm: Option<&String>,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let instance = self.schema.create(json)?;
        self.value = Some(instance.clone());

        //let instance = self.schema.create(json)?;

        // self.value = Some(instance.clone());
        // if let Some(ref value) = self.value {
        //     self.id = value.get_str("id");
        //     self.version = value.get_str("version");
        // }

        if create_keys {
            // chose algorithm
            // create pub and private key
            // place in dir [jacs]/keys/[agent-id]/key|pubkey
            // self sign if agent
        }

        // write  file to disk at [jacs]/agents/
        // run as agent
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
