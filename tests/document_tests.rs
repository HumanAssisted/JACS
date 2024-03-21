use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
mod utils;
use utils::{load_test_agent_one, set_test_env_vars};
// use color_eyre::eyre::Result;

static SCHEMA: &str = "examples/documents/my-custom-doctype.schema.json";
//color_eyre::install().unwrap();
#[test]
fn test_load_custom_schema_and_custom_document() {
    set_test_env_vars();
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
fn test_load_document_sign_and_verify() {
    color_eyre::install().unwrap();
    set_test_env_vars();
    // cargo test   --test document_tests -- --nocapture test_load_document_sign_and_verify
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = agent
        .load_local_document(&"examples/documents/my-special-document.json".to_string())
        .unwrap();
    let document_key = agent.load_document(&document_string).unwrap();
    println!("loaded valid {}", document_key);
    let signature_field_name = "test-signature".to_string();
    let mut fields: Vec<String> = Vec::new();
    fields.push("favorite-snack".to_string());
}

#[test]
fn test_load_custom_schema_and_custom_invalid_document() {
    set_test_env_vars();
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
    set_test_env_vars();
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

#[test]
fn test_load_custom_schema_and_custom_document_and_update() {
    // cargo test   --test document_tests -- --nocapture
    set_test_env_vars();
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = agent
        .load_local_document(&"examples/documents/my-special-document.json".to_string())
        .unwrap();
    let document_key = agent.load_document(&document_string).unwrap();

    let modified_document_string = agent
        .load_local_document(&"examples/documents/my-special-document-modified.json".to_string())
        .unwrap();

    let new_document_key = agent
        .update_document(&document_key, &modified_document_string)
        .unwrap();
    println!(
        "new_document_key {} {}",
        new_document_key, modified_document_string
    );
    let document = agent.get_document(&new_document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document.getvalue())
        .unwrap();
}
