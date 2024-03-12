use super::Schema;
use serde_json::Value;
use std::io::Error;

pub struct Agent {
    schema: Schema,
    value: Option<Value>,
}

impl Agent {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("agent", version)?;
        Ok(Self {
            schema,
            value: None,
        })
    }

    pub fn newkeys(
        &mut self,
        algorithm: &String,
        filepath: &String,
    ) -> Result<(String, String), String> {
        if algorithm == "rsa-pss" {
        } else if algorithm == "ring-Ed25519" {
        } else if algorithm == "pq-dilithium" {
        }

        return Err(format!(
            "{} is not a known or implemented algorithm.",
            algorithm
        ));
    }

    pub fn validate(&mut self, json: &str) -> Result<(), String> {
        let value = self.schema.validate(json)?;
        self.value = Some(value);
        // additional validation
        Ok(())
    }

    pub fn create(&mut self, _json: &str) -> Result<(), String> {
        // create json string
        // validate json string
        // diff
        // sign as owner
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
