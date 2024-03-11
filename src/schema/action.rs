use crate::schema::validate::Schema;
use std::io::Error;

pub struct Action {
    schema: Schema,
}

impl Action {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("action", version)?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        Ok(())
    }
}
