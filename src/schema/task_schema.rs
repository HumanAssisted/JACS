use std::io::Error;
use crate::schema::validate::Schema;


pub struct TaskSchema {
    schema: Schema,
}

impl TaskSchema {
    pub fn new() -> Result<Self, Error> {
        let schema = Schema::new("task")?;
        Ok(Self { schema })
    }

    pub fn validate(&self, json: &str) -> Result<(), String> {
        self.schema.validate(json)?;
        Ok(())
    }
}