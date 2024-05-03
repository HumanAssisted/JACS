use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;

mod utils;
use utils::DOCTESTFILE;

use utils::{load_local_document, load_test_agent_one, load_test_agent_two};
// use color_eyre::eyre::Result;
use httpmock::{Method, MockServer};
use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
use reqwest::blocking::Client;

static SCHEMA: &str = "examples/raw/custom.schema.json";

static TESTFILE_MODIFIED: &str = "examples/documents/MODIFIED_9a8f9f64-ec0c-4d8f-9b21-f7ff1f1dc2ad:fce5f150-f672-4a04-ac67-44c74ce27062.json";
//color_eyre::install().unwrap();
#[test]
fn test_load_custom_schema_and_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();

    // Start a local mock server
    let server = MockServer::start();

    // Create a mock on the server for the custom schema
    let schema_mock = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/custom.schema.json");
        then.status(200)
            .body(r#"{"$schema": "http://json-schema.org/draft-07/schema#","$id": "https://hai.ai/examples/documents/custom.schema.json","title": "Agent","description": "General schema for human, hybrid, and AI agents","allOf": [{"$ref": "https://hai.ai/schemas/header/v1/header.schema.json"},{"favorite-snack": {"description": "name that snack ","type": "string"}}],"required": ["favorite-snack"]}"#);
    });

    // Replace the actual schema URL with the mock server's URL
    let schemas = [server.url("/custom.schema.json").to_string()];
    agent.load_custom_schemas(&schemas);

    let document_string = load_local_document(&DOCTESTFILE.to_string()).unwrap();
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

    // Start a local mock server
    let server = MockServer::start();

    // Create a mock on the server for the custom schema
    let schema_mock = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/custom.schema.json");
        then.status(200)
            .body(r#"{"$schema": "http://json-schema.org/draft-07/schema#","$id": "https://hai.ai/examples/documents/custom.schema.json","title": "Agent","description": "General schema for human, hybrid, and AI agents","allOf": [{"$ref": "https://hai.ai/schemas/header/v1/header.schema.json"},{"favorite-snack": {"description": "name that snack ","type": "string"}}],"required": ["favorite-snack"]}"#);
    });

    // Replace the actual schema URL with the mock server's URL
    let schemas = [server.url("/custom.schema.json").to_string()];
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
    // RUST_BACKTRACE=1 cargo test  --test document_tests test_create  -- --nocapture
    utils::generate_new_docs();
}

#[test]
#[ignore]
fn test_create_attachments() {
    // RUST_BACKTRACE=1 cargo test --test document_tests test_create_attachments  --
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

    // Start a local mock server
    let server = MockServer::start();

    // Create a mock on the server for the custom schema
    let schema_mock = server.mock(|when, then| {
        when.method(Method::GET)
            .path("/custom.schema.json");
        then.status(200)
            .body(r#"{"$schema": "http://json-schema.org/draft-07/schema#","$id": "https://hai.ai/examples/documents/custom.schema.json","title": "Agent","description": "General schema for human, hybrid, and AI agents","allOf": [{"$ref": "https://hai.ai/schemas/header/v1/header.schema.json"},{"favorite-snack": {"description": "name that snack ","type": "string"}}],"required": ["favorite-snack"]}"#);
    });

    // Replace the actual schema URL with the mock server's URL
    let schemas = [server.url("/custom.schema.json").to_string()];
    agent.load_custom_schemas(&schemas);

    let document_string =
        load_local_document(&"examples/raw/favorite-fruit.json".to_string()).unwrap();
    let document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    println!("loaded valid doc {}", document.to_string());
    let document_key = document.getkey();
    let _document_ref = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document.getvalue())
        .unwrap();
    // let _ = agent.save_document(&document_key, None, None);
}

#[test]
fn test_load_custom_schema_and_new_custom_document_agent_two() {
    // cargo test   --test document_tests -- --nocapture test_load_custom_schema_and_new_custom_document_agent_two
    let mut agent = load_test_agent_two();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string =
        load_local_document(&"examples/raw/favorite-fruit.json".to_string()).unwrap();
    let document = agent
        .create_document_and_load(&document_string, None, None)
        .unwrap();
    println!("loaded valid doc {}", document.to_string());
    let document_key = document.getkey();
    let _document_ref = agent.get_document(&document_key).unwrap();
    agent
        .validate_document_with_custom_schema(&SCHEMA, &document.getvalue())
        .unwrap();
    //let _ = agent.save_document(&document_key, None, None, None);
}

#[test]
fn test_load_custom_schema_and_custom_document_and_update_and_verify_signature() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();
    let schemas = [SCHEMA.to_string()];
    agent.load_custom_schemas(&schemas);
    let document_string = load_local_document(&DOCTESTFILE.to_string()).unwrap();
    let document = agent.load_document(&document_string).unwrap();
    let document_key = document.getkey();
    let modified_document_string = load_local_document(&TESTFILE_MODIFIED.to_string()).unwrap();

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
