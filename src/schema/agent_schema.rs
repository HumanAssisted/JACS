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

    pub fn validate(&self, json: &str) -> Result<(), jsonschema::ValidationError> {
        let instance = serde_json::from_str(json)?;
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft7)
            .compile(&self.schema)
            .expect("A valid schema");
        compiled.validate(&instance)?;
        Ok(())
    }
}