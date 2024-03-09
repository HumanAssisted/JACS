use crate::schema::validate::Schema;
use std::io::Error;

pub struct TaskSchema {
    schema: Schema,
}

impl TaskSchema {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("task", version)?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        Ok(())
    }
}
