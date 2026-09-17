use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::DocumentTraits;
use jacs::agent::loaders::FileLoader;
use jacs::crypt::hash::hash_public_key;
mod utils;

use utils::{
    create_owned_config_fixture_document, load_local_document, load_test_agent_one_ed25519,
    load_test_agent_two_ed25519, raw_fixture, set_min_test_env_vars,
};
// use color_eyre::eyre::Result;
use jacs::agent::DOCUMENT_AGENT_SIGNATURE_FIELDNAME;
extern crate env_logger;
use log::{error, info};
use serial_test::serial;

// Define the correct path for the custom schema

static SCHEMA: &str = "custom.schema.json";

fn get_raw_schema_path() -> String {
    // Use a relative path from the crate root (CWD during `cargo test`).
    // Absolute paths get their leading '/' stripped by the schema resolver,
    // then treated as relative by the storage backend, causing path doubling.
    format!("tests/fixtures/raw/{}", SCHEMA)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial(jacs_env)]
    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
}

#[test]
#[serial(jacs_env)]
fn test_load_all() {
    // cargo test   --test document_tests -- --nocapture test_load_all
    let mut agent = load_test_agent_one_ed25519();
    let save_docs = true;
    let load_only_recent = true;
    let all_docs = agent
        .load_all(save_docs, load_only_recent)
        .expect("load_all");
    println!("all_docs {}  ", all_docs.len());
}

#[test]
#[serial(jacs_env)]
fn test_load_only_recent() {
    // cargo test   --test document_tests -- --nocapture test_load_only_recent
    let mut agent = load_test_agent_one_ed25519();
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
            panic!("test_load_only_recent failed: doc {}", key);
        }
    }
}

#[test]
#[serial(jacs_env)]
fn test_load_custom_schema_and_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one_ed25519();

    match agent.load_custom_schemas(&[get_raw_schema_path()]) {
        Ok(_) => {
            info!("Schemas loaded successfully in test_load_custom_schema_and_custom_document.")
        }
        Err(e) => {
            panic!(
                "Failed to load schemas in test_load_custom_schema_and_custom_document: {}",
                e
            );
        }
    }

    let document_key = create_owned_config_fixture_document(&mut agent);
    let document = agent
        .get_document(&document_key)
        .expect("fresh Ed25519-owned custom fixture should be loaded");

    info!("loaded valid {}", document.getkey());

    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), document.getvalue()) {
        Ok(_) => info!("Document is valid in test_load_custom_schema_and_custom_document."),
        Err(e) => panic!(
            "Document validation error in test_load_custom_schema_and_custom_document: {}",
            e
        ),
    }
}

#[test]
#[serial(jacs_env)]
fn test_load_custom_schema_and_custom_invalid_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one_ed25519();

    info!("Starting to load custom schemas.");
    match agent.load_custom_schemas(&[get_raw_schema_path()]) {
        Ok(_) => info!("Schemas loaded successfully."),
        Err(e) => {
            panic!("Failed to load schemas: {}", e);
        }
    };
    info!("Custom schemas loaded, proceeding to create and load document.");

    let document_string = match load_local_document(
        &raw_fixture("not-fruit.json").to_string_lossy().to_string(),
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
    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), document.getvalue()) {
        Ok(()) => {
            info!("Document validation succeeded, which should not happen.");
            panic!(
                "Document validation succeeded in test_load_custom_schema_and_custom_invalid_document and should not have"
            );
        }
        Err(error) => {
            info!("Document validation failed as expected: {}", error);
            // Expected: invalid document should fail validation
        }
    }
    info!("Document validation completed.");
}

// NOTE: test_create and test_create_attachments were removed — they were ignored
// side-effectful document generators, not real tests. Document creation is tested
// extensively in document_lifecycle.rs and document_fs.rs.

#[test]
#[serial(jacs_env)]
fn test_create_attachments_no_save() {
    // RUST_BACKTRACE=1 cargo test document_tests -- --test test_create_attachments_no_save
    utils::generate_new_docs_with_attachments(false);
}

#[test]
#[serial(jacs_env)]
fn test_load_custom_schema_and_new_custom_document() {
    // cargo test   --test document_tests -- --nocapture
    let mut agent = load_test_agent_one_ed25519();

    match agent.load_custom_schemas(&[get_raw_schema_path()]) {
        Ok(_) => info!("Schemas loaded successfully."),
        Err(e) => {
            panic!("Failed to load schemas: {}", e);
        }
    };

    let document_string = match load_local_document(
        &raw_fixture("favorite-fruit.json")
            .to_string_lossy()
            .to_string(),
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

    info!("loaded valid doc {}", document);

    let document_key = document.getkey();

    let _document_ref = match agent.get_document(&document_key) {
        Ok(doc_ref) => doc_ref,
        Err(e) => panic!(
            "Error in test_load_custom_schema_and_new_custom_document getting document: {}",
            e
        ),
    };

    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), document.getvalue()) {
        Ok(_) => info!("Document is valid in test_load_custom_schema_and_new_custom_document."),
        Err(e) => panic!(
            "Document validation error in test_load_custom_schema_and_new_custom_document: {}",
            e
        ),
    };
}

#[test]
#[serial(jacs_env)]
fn test_load_custom_schema_and_new_custom_document_agent_two() {
    info!("test_load_custom_schema_and_new_custom_document_agent_two: Test case started");
    set_min_test_env_vars();
    let mut agent = load_test_agent_two_ed25519();
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
            panic!(
                "test_load_custom_schema_and_new_custom_document_agent_two: Failed to load schemas: {e}"
            );
        }
    };

    info!(
        "test_load_custom_schema_and_new_custom_document_agent_two: Attempting to load local document"
    );
    let document_string = match load_local_document(
        &raw_fixture("favorite-fruit.json")
            .to_string_lossy()
            .to_string(),
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
    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), document.getvalue()) {
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
#[serial(jacs_env)]
fn test_load_custom_schema_and_custom_document_and_update_and_verify_signature() {
    // cargo test   --test document_tests -- --nocapture
    // Create a fresh Ed25519-owned document, then update and verify against
    // the same active signing key.
    let mut agent = load_test_agent_one_ed25519();

    match agent.load_custom_schemas(&[get_raw_schema_path()]) {
        Ok(_) => info!(
            "Schemas loaded successfully in test_load_custom_schema_and_custom_document_and_update_and_verify_signature."
        ),
        Err(e) => {
            panic!(
                "Failed to load schemas in test_load_custom_schema_and_custom_document_and_update_and_verify_signature: {}",
                e
            );
        }
    };

    let raw_source = match load_local_document(
        &raw_fixture("favorite-fruit.json")
            .to_string_lossy()
            .to_string(),
    ) {
        Ok(content) => content,
        Err(e) => panic!(
            "Error loading raw source for test_load_custom_schema_and_custom_document_and_update_and_verify_signature: {}",
            e
        ),
    };

    let document = match agent.create_document_and_load(&raw_source, None, None) {
        Ok(doc) => doc,
        Err(e) => panic!(
            "Error creating fresh Ed25519-owned document in test_load_custom_schema_and_custom_document_and_update_and_verify_signature: {}",
            e
        ),
    };

    let document_key = document.getkey();

    let mut modified_value = document.getvalue().clone();
    modified_value["favorite-snack"] = serde_json::json!("mango");
    let modified_document_string =
        serde_json::to_string(&modified_value).expect("re-serialize modified document for update");

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

    match agent.validate_document_with_custom_schema(&get_raw_schema_path(), document.getvalue()) {
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
        Some(DOCUMENT_AGENT_SIGNATURE_FIELDNAME),
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

    let mut agent2 = load_test_agent_two_ed25519();
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
        Some(DOCUMENT_AGENT_SIGNATURE_FIELDNAME),
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

#[test]
#[serial(jacs_env)]
fn test_update_document_rejects_non_owner_editor() {
    let mut owner = load_test_agent_one_ed25519();
    let mut non_owner = load_test_agent_two_ed25519();

    let original_key = create_owned_config_fixture_document(&mut owner);
    let original_document = owner
        .get_document(&original_key)
        .expect("Owner should load source document");
    let original_key = original_document.getkey();
    let owner_public_key = owner.get_public_key().expect("owner public key");
    let owner_public_key_hash = hash_public_key(&owner_public_key);
    non_owner
        .fs_save_remote_public_key(&owner_public_key_hash, &owner_public_key, b"ring-Ed25519")
        .expect("cache owner public key");
    let original_document_string =
        serde_json::to_string_pretty(original_document.getvalue()).expect("serialize original");
    non_owner
        .load_document(&original_document_string)
        .expect("non-owner should load source document before update attempt");

    let mut modified_value = original_document.getvalue().clone();
    modified_value["favorite-snack"] = serde_json::json!("mango");
    let modified_document_string =
        serde_json::to_string(&modified_value).expect("serialize modified document");
    let result = non_owner.update_document(&original_key, &modified_document_string, None, None);

    assert!(
        result.is_err(),
        "A different agent identity should not be allowed to update the owner's document"
    );
    let err = result
        .expect_err("result was asserted as error")
        .to_string();
    assert!(
        err.contains("cannot be updated by"),
        "Unexpected error message: {}",
        err
    );
}
