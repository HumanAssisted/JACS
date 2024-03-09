use crate::schema::validate::Schema;
use std::io::Error;

pub struct DecisionSchema {
    schema: Schema,
}

impl DecisionSchema {
    pub fn new() -> Result<Self, Error> {
        let schema = Schema::new("decision")?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        Ok(())
    }
}
