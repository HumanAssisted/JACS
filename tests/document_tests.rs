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
    println!("loaded valid {}", document_key);
    let document = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document.getvalue())
        .unwrap();
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
    println!("loaded valid  {}", document_key);
    let document = agent.get_document(&document_key).unwrap();

    match agent.validate_document_with_custom_schema(&SCHEMA, &document.getvalue()) {
        Ok(()) => {
            // Validation succeeded
            println!("Document validation succeeded and should not have");
            assert!(false);
        }
        Err(error) => {
            // Validation failed
            eprintln!("Document validation failed: {}", error);
            assert!(true);
        }
    }
}

#[test]
fn test_load_custom_schema_and_new_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = agent
        .load_local_document(&"examples/documents/my-special-new-document.json".to_string())
        .unwrap();
    let document_key = agent.create_document_and_load(&document_string).unwrap();
    println!("loaded valid {}", document_key);
    let document = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document.getvalue())
        .unwrap();
}
