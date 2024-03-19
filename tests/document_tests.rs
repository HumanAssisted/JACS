use jacs::agent::loaders::FileLoader;
mod utils;
use utils::load_test_agent_one;

#[test]
fn test_load_custom_schema_and_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = ["examples/documents/my-custom-doctype.schema.json".to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = agent
        .load_local_document(&"examples/documents/my-special-document.json".to_string())
        .unwrap();
    agent.load_document(&document_string).unwrap();

    //validate_document_with_custom_schema
}
