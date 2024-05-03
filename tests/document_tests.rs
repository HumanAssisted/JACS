use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::KeyManager;
use jsonschema::{CompilationOptions, Draft, JSONSchema};
mod utils;
use utils::DOCTESTFILE;

use utils::{load_local_document, load_test_agent_one, load_test_agent_two};
// use color_eyre::eyre::Result;
use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
extern crate env_logger;
use log::{error, info};

// Define the correct path for the custom schema
static SCHEMA: &str = "/home/ubuntu/JACS/examples/raw/custom.schema.json";

static TESTFILE_MODIFIED: &str = "examples/documents/MODIFIED_9a8f9f64-ec0c-4d8f-9b21-f7ff1f1dc2ad:fce5f150-f672-4a04-ac67-44c74ce27062.json";
//color_eyre::install().unwrap();

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;

    #[test]
    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
}

#[test]
fn test_load_custom_schema_and_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();

    match agent.load_custom_schemas(&[SCHEMA.to_string()]) {
        Ok(_) => {
            info!("Schemas loaded successfully in test_load_custom_schema_and_custom_document.")
        }
        Err(e) => {
            error!(
                "Error in test_load_custom_schema_and_custom_document loading schemas: {}",
                e
            );
            assert!(
                false,
                "Failed to load schemas in test_load_custom_schema_and_custom_document"
            );
        }
    }

    let document_string = match load_local_document(&DOCTESTFILE.to_string()) {
        Ok(content) => content,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document loading local document: {}",
            e
        ),
    };

    let document = match agent.load_document(&document_string) {
        Ok(doc) => doc,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document loading document: {}",
            e
        ),
    };

    info!("loaded valid {}", document.getkey());

    match agent.validate_document_with_custom_schema(&SCHEMA, &document.getvalue()) {
        Ok(_) => info!("Document is valid in test_load_custom_schema_and_custom_document."),
        Err(e) => panic!(
            "Document validation error in test_load_custom_schema_and_custom_document: {}",
            e
        ),
    }
}

#[test]
fn test_load_custom_schema_and_custom_invalid_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();

    match agent.load_custom_schemas(&[SCHEMA.to_string()]) {
        Ok(_) => info!(
            "Schemas loaded successfully in test_load_custom_schema_and_custom_invalid_document."
        ),
        Err(e) => {
            error!(
                "Error in test_load_custom_schema_and_custom_invalid_document loading schemas: {}",
                e
            );
            assert!(
                false,
                "Failed to load schemas in test_load_custom_schema_and_custom_invalid_document"
            );
        }
    };

    let document_string = match load_local_document(&"examples/raw/not-fruit.json".to_string()) {
        Ok(content) => content,
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_invalid_document loading local document: {}", e),
    };

    let document = match agent.create_document_and_load(&document_string, None, None) {
        Ok(doc) => doc,
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_invalid_document creating and loading document: {}", e),
    };

    info!("loaded valid doc {}", document.to_string());

    match agent.validate_document_with_custom_schema(&SCHEMA, &document.getvalue()) {
        Ok(()) => {
            // Validation succeeded
            panic!("Document validation succeeded in test_load_custom_schema_and_custom_invalid_document and should not have");
            assert!(false);
        }
        Err(error) => {
            // Validation failed
            info!("Document validation failed in test_load_custom_schema_and_custom_invalid_document: {}", error);
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

    match agent.load_custom_schemas(&[SCHEMA.to_string()]) {
        Ok(_) => {
            info!("Schemas loaded successfully in test_load_custom_schema_and_new_custom_document.")
        }
        Err(e) => {
            error!(
                "Error in test_load_custom_schema_and_new_custom_document loading schemas: {}",
                e
            );
            assert!(
                false,
                "Failed to load schemas in test_load_custom_schema_and_new_custom_document"
            );
        }
    };

    let document_string = match load_local_document(&"examples/raw/favorite-fruit.json".to_string())
    {
        Ok(content) => content,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_new_custom_document loading local document: {}",
            e
        ),
    };

    let document = match agent.create_document_and_load(&document_string, None, None) {
        Ok(doc) => doc,
        Err(e) => panic!("Error in test_load_custom_schema_and_new_custom_document creating and loading document: {}", e),
    };

    info!("loaded valid doc {}", document.to_string());

    let document_key = document.getkey();

    let document_ref = match agent.get_document(&document_key) {
        Ok(doc_ref) => doc_ref,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_new_custom_document getting document: {}",
            e
        ),
    };

    match agent.validate_document_with_custom_schema(&SCHEMA, &document.getvalue()) {
        Ok(_) => info!("Document is valid in test_load_custom_schema_and_new_custom_document."),
        Err(e) => panic!(
            "Document validation error in test_load_custom_schema_and_new_custom_document: {}",
            e
        ),
    };
}

#[test]
fn test_load_custom_schema_and_new_custom_document_agent_two() {
    // cargo test   --test document_tests -- --nocapture test_load_custom_schema_and_new_custom_document_agent_two
    let mut agent = load_test_agent_two();

    match agent.load_custom_schemas(&[SCHEMA.to_string()]) {
        Ok(_) => info!("Schemas loaded successfully in test_load_custom_schema_and_new_custom_document_agent_two."),
        Err(e) => {
            error!("Error in test_load_custom_schema_and_new_custom_document_agent_two loading schemas: {}", e);
            assert!(false, "Failed to load schemas in test_load_custom_schema_and_new_custom_document_agent_two");
        },
    };

    let document_string = match load_local_document(&"examples/raw/favorite-fruit.json".to_string()) {
        Ok(content) => content,
        Err(e) => panic!("Error in test_load_custom_schema_and_new_custom_document_agent_two loading local document: {}", e),
    };

    let document = match agent.create_document_and_load(&document_string, None, None) {
        Ok(doc) => doc,
        Err(e) => panic!("Error in test_load_custom_schema_and_new_custom_document_agent_two creating and loading document: {}", e),
    };

    info!("loaded valid doc {}", document.to_string());

    let document_key = document.getkey();

    let document_ref = match agent.get_document(&document_key) {
        Ok(doc_ref) => doc_ref,
        Err(e) => panic!("Error in test_load_custom_schema_and_new_custom_document_agent_two getting document: {}", e),
    };

    match agent.validate_document_with_custom_schema(&SCHEMA, &document.getvalue()) {
        Ok(_) => info!("Document is valid in test_load_custom_schema_and_new_custom_document_agent_two."),
        Err(e) => panic!("Document validation error in test_load_custom_schema_and_new_custom_document_agent_two: {}", e),
    };
}

#[test]
fn test_load_custom_schema_and_custom_document_and_update_and_verify_signature() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();

    match agent.load_custom_schemas(&[SCHEMA.to_string()]) {
        Ok(_) => info!("Schemas loaded successfully in test_load_custom_schema_and_custom_document_and_update_and_verify_signature."),
        Err(e) => {
            error!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading schemas: {}", e);
            assert!(false, "Failed to load schemas in test_load_custom_schema_and_custom_document_and_update_and_verify_signature");
        },
    };

    let document_string = match load_local_document(&DOCTESTFILE.to_string()) {
        Ok(content) => content,
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading local document: {}", e),
    };

    let document = match agent.load_document(&document_string) {
        Ok(doc) => doc,
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading document: {}", e),
    };

    let document_key = document.getkey();
    let modified_document_string = match load_local_document(&TESTFILE_MODIFIED.to_string()) {
        Ok(content) => content,
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading modified document: {}", e),
    };

    let new_document = match agent.update_document(&document_key, &modified_document_string, None, None) {
        Ok(doc) => doc,
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature updating document: {}", e),
    };

    let new_document_key = new_document.getkey();

    let new_document_ref = match agent.get_document(&new_document_key) {
        Ok(doc_ref) => doc_ref,
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature getting new document: {}", e),
    };

    match agent.validate_document_with_custom_schema(&SCHEMA, &document.getvalue()) {
        Ok(_) => info!("Document is valid in test_load_custom_schema_and_custom_document_and_update_and_verify_signature."),
        Err(e) => panic!("Document validation error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature: {}", e),
    };

    info!("updated {} {}", new_document_key, new_document_ref);

    match agent.verify_document_signature(
        &new_document_key,
        Some(&DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string()),
        None,
        None,
        None,
    ) {
        Ok(_) => info!("Document signature verified in test_load_custom_schema_and_custom_document_and_update_and_verify_signature."),
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature verifying document signature: {}", e),
    };

    let agent_one_public_key = match agent.get_public_key() {
        Ok(key) => key,
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature getting agent one public key: {}", e),
    };

    let mut agent2 = load_test_agent_two();
    let new_document_string = new_document_ref.to_string();
    let copy_newdocument = match agent2.load_document(&new_document_string) {
        Ok(doc) => doc,
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading document copy: {}", e),
    };

    let copy_newdocument_key = copy_newdocument.getkey();
    info!("new document with sig: /n {}", new_document_string);

    match agent.verify_document_signature(
        &copy_newdocument_key,
        Some(&DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string()),
        None,
        Some(agent_one_public_key),
        None,
    ) {
        Ok(_) => info!("Document signature verified in test_load_custom_schema_and_custom_document_and_update_and_verify_signature."),
        Err(e) => panic!("Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature verifying document signature: {}", e),
    };
}
