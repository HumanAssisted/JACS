use jsonschema::{Draft, JSONSchema};
use log::{debug, error, warn};
use serde_json::Value;
use std::env;
use std::io::Error;
use std::{fs, path::PathBuf};
use url::Url;

pub mod signature;
pub mod utils;

use signature::SignatureVerifiers;
use utils::LocalSchemaResolver;

pub struct Schema {
    compiled: JSONSchema,
}

impl Schema {
    pub fn new(schema_type: &str, version: &str) -> Result<Self, Error> {
        let current_dir = env::current_dir()?;
        let schema_path: PathBuf = current_dir
            .join("schemas")
            .join(schema_type)
            .join(version)
            .join(format!("{}.schema.json", schema_type));

        let data = match fs::read_to_string(schema_path.clone()) {
            Ok(data) => {
                debug!("Schema is {:?}", data);
                data
            }
            Err(e) => {
                let error_message = format!("Failed to read schema file: {}", e);
                error!("{}", error_message);
                return Err(e);
            }
        };

        let base_path = PathBuf::from(".");
        let schema: Value = serde_json::from_str(&data)?;
        let localresolver = LocalSchemaResolver::new(base_path);

        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(localresolver)
            .compile(&schema)
            .expect("A valid schema");

        Ok(Self { compiled })
    }

    pub fn validate(&self, json: &str) -> Result<Value, String> {
        let instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            }
            Err(e) => {
                let error_message = format!("Invalid JSON: {}", e);
                warn!("validate error {:?}", error_message);
                return Err(error_message);
            }
        };

        let validation_result = self.compiled.validate(&instance);

        match validation_result {
            Ok(_) => Ok(instance.clone()),
            Err(errors) => {
                let error_messages: Vec<String> =
                    errors.into_iter().map(|e| e.to_string()).collect();
                Err(error_messages.first().cloned().unwrap_or_else(|| {
                    "Unexpected error during validation: no error messages found".to_string()
                }))
            }
        }
    }

    /// utilty function to retrieve the list of fields
    /// this is especially useful for signatures
    pub fn get_array_of_values(&self, signature: serde_json::Value, fieldname: &String) -> String {
        if let Some(array_field) = signature.get(fieldname).and_then(Value::as_array) {
            let mut result_strings = Vec::new();
            for value in array_field {
                if let Some(string_value) = value.as_str() {
                    result_strings.push(string_value.to_string());
                }
            }
            return format!("Result Strings: {:?}", result_strings);
        }
        "".to_string()
    }

    pub fn create_signature(&self) {}

    /// give a signature field
    pub fn check_signature(&self, fieldname: &String) {}

    pub fn create(
        &self,
        json: &str,
        create_keys: bool,
        create_keys_algorithm: &String,
    ) -> Result<Value, String> {
        let result = self.validate(json);
        // check version and create if not present

        // generate keys
        if create_keys {
            // chose algorithm
            // create pub and private key
            // place in dir [jacs]/keys/[agent-id]/key|pubkey
            // self sign if agent
        }

        // write file to disk at [jacs]/agents/
        // run as agent

        result
    }
}
