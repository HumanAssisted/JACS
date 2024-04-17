use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
mod utils;

use utils::{load_local_document, load_test_agent_one, load_test_agent_two};
// use color_eyre::eyre::Result;
use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
static SCHEMA: &str = "examples/raw/custom.schema.json";
//color_eyre::install().unwrap();
#[test]
fn test_load_custom_schema_and_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string =
        load_local_document(&"examples/documents/e957d062-d684-456b-8680-14a1c4edcb2a:5599ac70-a3d6-429b-85ae-c9b17c78d2c5.json".to_string()).unwrap();
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
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = load_local_document(&"examples/raw/not-fruit.json".to_string()).unwrap();
    let document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    println!("loaded valid doc {}", document.to_string());
    let document_key = document.getkey();
    let _document_ref = agent.get_document(&document_key).unwrap();

    // let _ = agent.save_document(&document_key, None, None);
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
    // RUST_BACKTRACE=1 cargo test document_tests -- --test test_create
    utils::generate_new_docs();
}

#[test]
#[ignore]
fn test_create_attachments() {
    // RUST_BACKTRACE=1 cargo test document_tests -- --test test_create_attachments
    utils::generate_new_docs_with_attachments(true);
}

#[test]
fn test_create_attachments_no_save() {
    // RUST_BACKTRACE=1 cargo test document_tests -- --test test_create_attachments_no_save
    utils::generate_new_docs_with_attachments(false);
}

#[test]
fn test_load_custom_schema_and_new_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string =
        load_local_document(&"examples/raw/favorite-fruit.json".to_string()).unwrap();
    let document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    println!("loaded valid doc {}", document.to_string());
    let document_key = document.getkey();
    let document_ref = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document.getvalue())
        .unwrap();
    // let _ = agent.save_document(&document_key, None, None);
}

#[test]
fn test_load_custom_schema_and_custom_document_and_update_and_verify_signature() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string =
        load_local_document(&"examples/documents/e957d062-d684-456b-8680-14a1c4edcb2a:5599ac70-a3d6-429b-85ae-c9b17c78d2c5.json".to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let modified_document_string =
        load_local_document(&"examples/documents/MODIFIED_e957d062-d684-456b-8680-14a1c4edcb2a:5599ac70-a3d6-429b-85ae-c9b17c78d2c5.json".to_string())
            .unwrap();

    let new_document = agent
        .update_document(&document_key, &modified_document_string, None, None)
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
            Some(&DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string()),
            None,
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
            Some(&DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string()),
            None,
            Some(agent_one_public_key),
            None,
        )
        .unwrap();
}
