use std::io::Error;
use crate::schema::validate::Schema;


pub struct AgentSchema {
    schema: Schema,
}

impl AgentSchema {
    pub fn new() -> Result<Self, Error> {
        let schema = Schema::new("agent-schema.json")?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        // Perform additional custom validation for AgentSchema
        // ...
        Ok(())
    }
}