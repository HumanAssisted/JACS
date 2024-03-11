use crate::schema::validate::Schema;
use std::io::Error;
use serde_json::Value;

pub struct Agent {
    schema: Schema,
    value: Option<Value>,
}



impl Agent {
    pub fn new(version: &str) -> Result<Self, Error> {
        let schema = Schema::new("agent", version)?;
        Ok(Self { schema , value: None})
    }

    pub fn validate(&mut self, json: &str) -> Result<(), String> {
         let value = self.schema.validate(json)?;
        self.value = Some(value);
        // additional validation
        Ok(())
    }

    pub fn create(&mut self, _json: &str) -> Result<(), String> {
        // create json string
        // validate json string
        // diff
        // sign as owner
        // self.validate();

        Ok(())
    }

    pub fn edit(&mut self, _json: &str) -> Result<(), String> {
        // validate new json string
        // diff strings
        // validate editor can make changes

        Ok(())
    }
}

/*

todo
 - validate returns error not string
 - make errors to string function for use in logging
 - return serde Value or string?
 - edit as decision - create a decision object while creating the change

*/