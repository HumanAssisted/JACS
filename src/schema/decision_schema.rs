use crate::schema::validate::Schema;
use std::io::Error;

pub struct DecisionSchema {
    schema: Schema,
}

impl DecisionSchema {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("decision", version)?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        Ok(())
    }
}
