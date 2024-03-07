use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use std::fs;
use std::io::Error;

pub struct AgentSchema {
    schema: Value,
}

impl AgentSchema {
    pub fn new() -> Result<Self, Error> {
        // Load the schema from file during initialization
        let data = fs::read_to_string("schemas/agent_schema.json")?;
        let schema: Value = serde_json::from_str(&data)?;
        Ok(Self { schema })
    }
    pub fn validate(&self, json: &str) -> Result<(), String> {
        let instance: serde_json::Value = serde_json::from_str(json)
            .map_err(|e| e.to_string())?; // Convert serde_json::Error to String here
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&self.schema)
            .expect("A valid schema");

        let result = compiled.validate(&instance);
        match result {
            Ok(_) => Ok(()),
            Err(errors) => {
                let error_messages: Vec<String> = errors.into_iter().map(|e| e.to_string()).collect();
                if let Some(error_message) = error_messages.first() {
                    Err(error_message.clone())
                } else {
                    // No errors should not be possible in this branch
                    Err("Unexpected error during validation: no error messages found".to_string())
                }
            }
        }
    }
}