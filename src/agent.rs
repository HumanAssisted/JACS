use crate::crypt::rsawrapper;
use crate::schema::Schema;
use crate::schema::ValueExt;
use serde_json::Value;
use std::io::Error;

pub struct Agent {
    schema: Schema,
    value: Option<Value>,
    id: Option<String>,
    version: Option<String>,
    public_key: Option<String>,
    private_key: Option<String>,
    key_algorithm: Option<String>,
}

impl Agent {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("agent", version)?;
        Ok(Self {
            schema,
            value: None,
            id: None,
            version: None,
            key_algorithm: None,
            public_key: None,
            private_key: None,
        })
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

    /// validate also loads the
    pub fn validate(&mut self, json: &str) -> Result<(), String> {
        let value = self.schema.validate(json)?;
        self.value = Some(value);
        if let Some(ref value) = self.value {
            self.id = value.get_str("id");
            self.version = value.get_str("version");
        }
        // additional validation
        Ok(())
    }

    pub fn create(&mut self, _json: &str) -> Result<(), String> {
        // create json string
        // validate json string
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