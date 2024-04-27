use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
mod utils;

use utils::{load_local_document, load_test_agent_one, load_test_agent_two};
// use color_eyre::eyre::Result;
use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
static SCHEMA: &str = "examples/raw/custom.schema.json";

#[test]
fn test_hai_fields_custom_schema_and_custom_document() {
    // cargo test   --test task_tests test_hai_fields_custom_schema_and_custom_document -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string =
        load_local_document(&"examples/documents/9e647c2a-3d4b-422a-8c26-722a3e5d31ee:7a2056f0-b262-4102-ba38-7b45cad709ce.json".to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    println!("loaded valid {}", document_key);
    let document_copy = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document_copy.getvalue())
        .unwrap();

    let value = document_copy.getvalue();
    println!("found schema {}", value["$schema"]);
    let extracted_fields_result = agent.schema.extract_hai_fields(&value, "meta");
    match extracted_fields_result {
        Err(error) => {
            println!(" ERROR {}", error.to_string());
            assert!(false);
        }
        Ok(extracted_fields) => println!("{}", extracted_fields.to_string()),
    }
}
