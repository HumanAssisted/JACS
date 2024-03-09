use crate::schema::validate::Schema;
use std::io::Error;

pub struct ResourceSchema {
    schema: Schema,
}

impl ResourceSchema {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("resource", version)?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        Ok(())
    }
}
