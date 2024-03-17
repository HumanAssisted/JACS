use jsonschema::{Draft, JSONSchema};
use log::{debug, error, warn};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::io::Error;
use std::{fs, path::PathBuf};
use url::Url;
use uuid::Uuid;

pub mod signature;
pub mod utils;

use signature::SignatureVerifiers;
use utils::{EmbeddedSchemaResolver, DEFAULT_SCHEMA_STRINGS};

pub struct Schema {
    /// used to validate any JACS document
    headerschema: JSONSchema,
    /// used to validate any JACS agent
    agentschema: JSONSchema,
    // schemas: HashMap<String, JSONSchema>
}

impl Schema {
    pub fn new(agentversion: &String, headerversion: &String) -> Result<Self, Error> {
        let current_dir = env::current_dir()?;
        let mut schemas: HashMap<String, JSONSchema> = HashMap::new();
        // TODO load these to hashmap that is compiled into binary
        let agent_schema_path: PathBuf = current_dir
            .join("schemas")
            .join("agent")
            .join(agentversion)
            .join(format!("agent.schema.json"));

        let header_schema_path: PathBuf = current_dir
            .join("schemas")
            .join("header")
            .join(agentversion)
            .join(format!("header.schema.json"));

        let agentdata = match fs::read_to_string(agent_schema_path.clone()) {
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

        let headerdata = match fs::read_to_string(agent_schema_path.clone()) {
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

        let agentschemaResult: Value = serde_json::from_str(&agentdata)?;
        let headerchemaResult: Value = serde_json::from_str(&headerdata)?;

        let agentschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new()) // current_dir.clone()
            .compile(&agentschemaResult)
            .expect("A valid schema");

        let headerschema = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .with_resolver(EmbeddedSchemaResolver::new())
            .compile(&headerchemaResult)
            .expect("A valid schema");

        Ok(Self {
            headerschema,
            agentschema,
        })
    }

    pub fn validate_header(&self, json: &str) -> Result<Value, String> {
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

        let validation_result = self.headerschema.validate(&instance);

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

    pub fn validate_agent(&self, json: &str) -> Result<Value, String> {
        let instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            }
            Err(e) => {
                let error_message = format!("Invalid JSON for agent: {}", e);
                warn!("validate error {:?}", error_message);
                return Err(error_message);
            }
        };

        let validation_result = self.agentschema.validate(&instance);

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

    ///
    pub fn create(&self, json: &str) -> Result<Value, String> {
        // load document
        let result = self.validate_header(json);
        // check id and version is not present
        let id = Uuid::new_v4();
        let version = Uuid::new_v4();

        // write file to disk at [jacs]/agents/
        // run as agent

        result
    }
}
