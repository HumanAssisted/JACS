use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
mod utils;

use utils::{load_local_document, load_test_agent_one, load_test_agent_two, set_test_env_vars};
// use color_eyre::eyre::Result;
use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
static SCHEMA: &str = "examples/documents/custom.schema.json";
//color_eyre::install().unwrap();
#[test]
fn test_load_custom_schema_and_custom_document() {
    set_test_env_vars();
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string =
        load_local_document(&"examples/documents/e4b3ac57-71f4-4128-b0c4-a44a3bb4d98d:975f4523-e2e0-4b64-9c31-c718796fbdb1.json".to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    println!("loaded valid {}", document_key);
    let document_copy = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document_copy.getvalue())
        .unwrap();
}

#[test]
fn test_load_custom_schema_and_custom_invalid_document() {
    set_test_env_vars();
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = load_local_document(&"examples/raw/not-fruit.json".to_string()).unwrap();
    let document = agent.create_document_and_load(&document_string).unwrap();
    println!("loaded valid doc {}", document.to_string());
    let document_key = document.getkey();
    let document_ref = agent.get_document(&document_key).unwrap();

    // let _ = agent.save_document(&document_key);
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
#[ignore]
fn test_create() {
    set_test_env_vars();
    // RUST_BACKTRACE=1 cargo test document_tests -- --test test_create
    utils::generate_new_docs();
}

#[test]
fn test_load_custom_schema_and_new_custom_document() {
    set_test_env_vars();
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string =
        load_local_document(&"examples/raw/favorite-fruit.json".to_string()).unwrap();
    let document = agent.create_document_and_load(&document_string).unwrap();
    println!("loaded valid doc {}", document.to_string());
    let document_key = document.getkey();
    let document_ref = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document.getvalue())
        .unwrap();
    // let _ = agent.save_document(&document_key);
}

#[test]
fn test_load_custom_schema_and_custom_document_and_update_and_verify_signature() {
    // cargo test   --test document_tests -- --nocapture
    set_test_env_vars();
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string =
        load_local_document(&"examples/documents/e4b3ac57-71f4-4128-b0c4-a44a3bb4d98d:975f4523-e2e0-4b64-9c31-c718796fbdb1.json".to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let modified_document_string =
        load_local_document(&"examples/documents/MODIFIED_e4b3ac57-71f4-4128-b0c4-a44a3bb4d98d:975f4523-e2e0-4b64-9c31-c718796fbdb1.json".to_string())
            .unwrap();

    let new_document = agent
        .update_document(&document_key, &modified_document_string)
        .unwrap();

    let new_document_key = new_document.getkey();

    let new_document_ref = agent.get_document(&new_document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document.getvalue())
        .unwrap();

    println!("updated {} {}", new_document_key, new_document_ref);
    agent
        .verify_document_signature(
            &new_document_key,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
            None,
            None,
        )
        .unwrap();

    let agent_one_public_key = agent.get_public_key().unwrap();
    let mut agent2 = load_test_agent_two();
    let new_document_string = new_document_ref.to_string();
    let copy_newdocument = agent2.load_document(&new_document_string).unwrap();
    let copy_newdocument_key = copy_newdocument.getkey();
    println!("new document with sig: /n {}", new_document_string);
    agent
        .verify_document_signature(
            &copy_newdocument_key,
            &DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string(),
            None,
            Some(agent_one_public_key),
        )
        .unwrap();
}
