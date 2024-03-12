use super::Schema;
use std::io::Error;

pub struct Signature {
    schema: Schema,
}

impl Signature {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("signature", version)?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        Ok(())
    }
}
