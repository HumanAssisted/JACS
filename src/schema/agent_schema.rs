use crate::schema::validate::Schema;
use std::io::Error;

pub struct AgentSchema {
    schema: Schema,
}

impl AgentSchema {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("agent", version)?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        // Perform additional custom validation for AgentSchema
        // ...
        Ok(())
    }
}
