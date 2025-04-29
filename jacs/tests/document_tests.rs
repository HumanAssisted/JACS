use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
mod utils;
use utils::DOCTESTFILECONFIG;
use utils::TESTFILE_MODIFIED;

use utils::{load_local_document, load_test_agent_one, load_test_agent_two};
// use color_eyre::eyre::Result;
use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
extern crate env_logger;
use log::{error, info};

// Define the correct absolute path for the custom schema

static SCHEMA: &str = "custom.schema.json";

fn get_raw_schema_path() -> String {
    let fixtures_dir = utils::find_fixtures_dir();
    let schema_path = fixtures_dir.join("raw").join(SCHEMA);
    schema_path.to_string_lossy().to_string()
}

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
fn test_load_all() {
    // cargo test   --test document_tests -- --nocapture test_load_all
    let mut agent = load_test_agent_one();
    let save_docs = true;
    let load_only_recent = true;
    let all_docs = agent
        .load_all(save_docs, load_only_recent)
        .expect("load_all");
    println!("all_docs {}  ", all_docs.len());
}

#[test]
fn test_load_only_recent() {
    // cargo test   --test document_tests -- --nocapture test_load_only_recent
    let mut agent = load_test_agent_one();
    let save_docs = true;
    let load_only_recent = true;
    let all_docs = agent
        .load_all(save_docs, load_only_recent)
        .expect("load_all");

    // most recent version
    // 85175625-e190-40a8-8e58-06451e281809:4223ba44-1a68-48d6-b0ed-de70006eb3e1
    for doc in all_docs {
        let id = doc.id.clone();
        let version = doc.version.clone();
        let key = doc.getkey();
        if id == "85175625-e190-40a8-8e58-06451e281809"
            && version != "4223ba44-1a68-48d6-b0ed-de70006eb3e1"
        {
            assert!(false, "test_load_only_recent failed");
            println!("doc {}  ", key);
        }
    }
}

#[test]
fn test_load_custom_schema_and_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();

    match agent.load_custom_schemas(&[get_raw_schema_path()]) {
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

    let document_string = match load_local_document(&DOCTESTFILECONFIG.to_string()) {
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

    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), &document.getvalue()) {
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

    info!("Starting to load custom schemas.");
    match agent.load_custom_schemas(&[get_raw_schema_path()]) {
        Ok(_) => info!("Schemas loaded successfully."),
        Err(e) => {
            error!("Error loading schemas: {}", e);
            assert!(false, "Failed to load schemas");
        }
    };
    info!("Custom schemas loaded, proceeding to create and load document.");

    let document_string = match load_local_document(
        &"tests/fixtures/raw/not-fruit.json".to_string(),
    ) {
        Ok(content) => {
            info!("Local document loaded successfully.");
            content
        }
        Err(e) => {
            error!("Error loading local document: {}", e);
            panic!(
                "Error in test_load_custom_schema_and_custom_invalid_document loading local document: {}",
                e
            );
        }
    };

    info!("Document string loaded, proceeding to create document.");
    let document = match agent.create_document_and_load(&document_string, None, None) {
        Ok(doc) => {
            info!("Document created and loaded successfully.");
            doc
        }
        Err(e) => {
            error!("Error creating and loading document: {}", e);
            panic!(
                "Error in test_load_custom_schema_and_custom_invalid_document creating and loading document: {}",
                e
            );
        }
    };

    info!("Document loaded, proceeding to validate document.");
    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), &document.getvalue()) {
        Ok(()) => {
            info!("Document validation succeeded, which should not happen.");
            panic!(
                "Document validation succeeded in test_load_custom_schema_and_custom_invalid_document and should not have"
            );
        }
        Err(error) => {
            info!("Document validation failed as expected: {}", error);
            assert!(true);
        }
    }
    info!("Document validation completed.");
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
    // RUST_BACKTRACE=1 cargo test --test document_tests test_create_attachments  -- --nocapture
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

    match agent.load_custom_schemas(&[get_raw_schema_path()]) {
        Ok(_) => info!("Schemas loaded successfully."),
        Err(e) => {
            error!("Error loading schemas: {}", e);
            assert!(false, "Failed to load schemas");
        }
    };

    let document_string = match load_local_document(
        &"tests/fixtures/raw/favorite-fruit.json".to_string(),
    ) {
        Ok(content) => content,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_new_custom_document loading local document: {}",
            e
        ),
    };

    let document = match agent.create_document_and_load(&document_string, None, None) {
        Ok(doc) => doc,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_new_custom_document creating and loading document: {}",
            e
        ),
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

    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), &document.getvalue()) {
        Ok(_) => info!("Document is valid in test_load_custom_schema_and_new_custom_document."),
        Err(e) => panic!(
            "Document validation error in test_load_custom_schema_and_new_custom_document: {}",
            e
        ),
    };
}

#[test]
fn test_load_custom_schema_and_new_custom_document_agent_two() {
    info!("test_load_custom_schema_and_new_custom_document_agent_two: Test case started");
    let mut agent = load_test_agent_two();
    info!("test_load_custom_schema_and_new_custom_document_agent_two: Agent loaded");

    info!(
        "test_load_custom_schema_and_new_custom_document_agent_two: Attempting to load custom schemas"
    );
    match agent.load_custom_schemas(&[get_raw_schema_path()]) {
        Ok(_) => info!(
            "test_load_custom_schema_and_new_custom_document_agent_two: Custom schemas loaded successfully"
        ),
        Err(e) => {
            error!(
                "test_load_custom_schema_and_new_custom_document_agent_two: Error loading schemas: {}",
                e
            );
            assert!(
                false,
                "test_load_custom_schema_and_new_custom_document_agent_two: Failed to load schemas"
            );
        }
    };

    info!(
        "test_load_custom_schema_and_new_custom_document_agent_two: Attempting to load local document"
    );
    let document_string = match load_local_document(
        &"tests/fixtures/raw/favorite-fruit.json".to_string(),
    ) {
        Ok(content) => {
            info!(
                "test_load_custom_schema_and_new_custom_document_agent_two: Local document loaded successfully"
            );
            content
        }
        Err(e) => panic!(
            "test_load_custom_schema_and_new_custom_document_agent_two: Error loading local document: {}",
            e
        ),
    };

    info!(
        "test_load_custom_schema_and_new_custom_document_agent_two: Attempting to create and load document"
    );
    let document = match agent.create_document_and_load(&document_string, None, None) {
        Ok(doc) => {
            info!(
                "test_load_custom_schema_and_new_custom_document_agent_two: Document created and loaded successfully"
            );
            doc
        }
        Err(e) => panic!(
            "test_load_custom_schema_and_new_custom_document_agent_two: Error creating and loading document: {}",
            e
        ),
    };

    info!(
        "test_load_custom_schema_and_new_custom_document_agent_two: Attempting to validate document with custom schema"
    );
    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), &document.getvalue()) {
        Ok(_) => info!(
            "test_load_custom_schema_and_new_custom_document_agent_two: Document validation completed"
        ),
        Err(e) => panic!(
            "test_load_custom_schema_and_new_custom_document_agent_two: Document validation error: {}",
            e
        ),
    };
}

#[test]
fn test_load_custom_schema_and_custom_document_and_update_and_verify_signature() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one();

    match agent.load_custom_schemas(&[get_raw_schema_path()]) {
        Ok(_) => info!(
            "Schemas loaded successfully in test_load_custom_schema_and_custom_document_and_update_and_verify_signature."
        ),
        Err(e) => {
            error!(
                "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading schemas: {}",
                e
            );
            assert!(
                false,
                "Failed to load schemas in test_load_custom_schema_and_custom_document_and_update_and_verify_signature"
            );
        }
    };

    let document_string = match load_local_document(&DOCTESTFILECONFIG.to_string()) {
        Ok(content) => content,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading local document: {}",
            e
        ),
    };

    let document = match agent.load_document(&document_string) {
        Ok(doc) => doc,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading document: {}",
            e
        ),
    };

    let document_key = document.getkey();
    let modified_document_string = match load_local_document(&TESTFILE_MODIFIED.to_string()) {
        Ok(content) => content,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading modified document: {}",
            e
        ),
    };

    let new_document = match agent.update_document(
        &document_key,
        &modified_document_string,
        None,
        None,
    ) {
        Ok(doc) => doc,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature updating document: {}",
            e
        ),
    };

    let new_document_key = new_document.getkey();

    let new_document_ref = match agent.get_document(&new_document_key) {
        Ok(doc_ref) => doc_ref,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature getting new document: {}",
            e
        ),
    };

    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), &document.getvalue()) {
        Ok(_) => info!(
            "Document is valid in test_load_custom_schema_and_custom_document_and_update_and_verify_signature."
        ),
        Err(e) => panic!(
            "Document validation error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature: {}",
            e
        ),
    };

    info!("updated {} {}", new_document_key, new_document_ref);

    match agent.verify_document_signature(
        &new_document_key,
        Some(&DOCUMENT_AGENT_SIGNATURE_FIELDNAME.to_string()),
        None,
        None,
        None,
    ) {
        Ok(_) => info!(
            "Document signature verified in test_load_custom_schema_and_custom_document_and_update_and_verify_signature."
        ),
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature verifying document signature: {}",
            e
        ),
    };

    let agent_one_public_key = match agent.get_public_key() {
        Ok(key) => key,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature getting agent one public key: {}",
            e
        ),
    };

    let mut agent2 = load_test_agent_two();
    let new_document_string = new_document_ref.to_string();
    let copy_newdocument = match agent2.load_document(&new_document_string) {
        Ok(doc) => doc,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature loading document copy: {}",
            e
        ),
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
        Ok(_) => info!(
            "Document signature verified in test_load_custom_schema_and_custom_document_and_update_and_verify_signature."
        ),
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_custom_document_and_update_and_verify_signature verifying document signature: {}",
            e
        ),
    };
}
