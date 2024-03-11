use crate::schema::validate::Schema;
use std::io::Error;

pub struct Resource {
    schema: Schema,
}

impl Resource {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("resource", version)?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        Ok(())
    }
}
