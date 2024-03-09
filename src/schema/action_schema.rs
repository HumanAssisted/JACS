use crate::schema::validate::Schema;
use std::io::Error;

pub struct ActionSchema {
    schema: Schema,
}

impl ActionSchema {
    pub fn new() -> Result<Self, Error> {
        let schema = Schema::new("action")?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        Ok(())
    }
}
