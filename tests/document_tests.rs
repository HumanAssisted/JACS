use jacs::agent::loaders::FileLoader;
mod utils;
use utils::load_test_agent_one;

static SCHEMA: &str = "examples/documents/my-custom-doctype.schema.json";

#[test]
fn test_load_custom_schema_and_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = agent
        .load_local_document(&"examples/documents/my-special-document.json".to_string())
        .unwrap();
    let document_key = agent.load_document(&document_string).unwrap();
    println!("loaded valid {}", document_key)
    //validate_document_with_custom_schema
}

#[test]
fn test_load_custom_schema_and_custom_invalid_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = agent
        .load_local_document(&"examples/documents/my-special-document-broken.json".to_string())
        .unwrap();
    let document_key = agent.load_document(&document_string).unwrap();
    println!("loaded valid  {}", document_key)
    //validate_document_with_custom_schema
}
