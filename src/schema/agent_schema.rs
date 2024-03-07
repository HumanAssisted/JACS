use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use std::fs;
use std::io::Error;
use std::env;
use std::path::PathBuf;
use log::{debug, error, warn};

pub struct AgentSchema {
    schema: Value,
}

impl AgentSchema {
    pub fn new() -> Result<Self, Error> {
        // Get the current working directory
        let current_dir = env::current_dir()?;

        // Construct the absolute path to the schema file
        let schema_path: PathBuf = current_dir.join("schemas").join("agent-schema.json");
        let data = match fs::read_to_string(schema_path.clone()) {
            Ok(data) => {
                debug!("Schema IS {:?}", data);
                data
            },
            Err(e) => {
                let error_message = format!("Failed to read schema file: {}", e);
                error!("{}", error_message);
                return Err(e);
            }
        };

        let schema: Value = serde_json::from_str(&data)?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        let instance: serde_json::Value = match serde_json::from_str(json) {
            Ok(value) => {
                debug!("validate json {:?}", value);
                value
            },
            Err(e) => {
                let error_message = format!("Invalid JSON: {}", e);
                warn!("validate error {:?}", error_message);
                return Err(error_message);
            }
        };

        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&self.schema)
            .expect("A valid schema");

        let validation_result = compiled.validate(&instance);

        match validation_result {
            Ok(_) => Ok(()),
            Err(errors) => {
                let error_messages: Vec<String> = errors.into_iter().map(|e| e.to_string()).collect();
                if let Some(error_message) = error_messages.first() {
                    Err(error_message.clone())
                } else {
                    Err("Unexpected error during validation: no error messages found".to_string())
                }
            }
        }
    }
}