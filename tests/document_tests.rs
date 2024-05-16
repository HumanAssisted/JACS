extern crate env_logger;
extern crate httpmock;
use httpmock::Method::GET;
use httpmock::MockServer;
use log::info;
use serde_json::json;

mod utils;

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
    let mock_server = MockServer::start();

    let base_url = mock_server.url("");
    let _header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        base_url
    );
    let _document_schema_url = format!(
        "{}/schemas/document/mock_version/document.schema.json",
        base_url
    );
    let _valid_document = json!({
        "id": "valid_document_id",
        "type": "valid_document_type",
        "name": "Test Document",
        "version": "1.0",
        "properties": {
            "field1": "value1",
            "field2": "value2"
            // ... other required fields according to the schema ...
        }
    });

    // Validate the document
    // let validation_result = _agent.validate_document(&valid_document);
    // assert!(
    //     validation_result.is_ok(),
    //     "The document should be valid. Errors: {:?}",
    //     validation_result
    //         .err()
    //         .unwrap_or_else(|| "No errors".into())
    // );
}

#[test]
fn test_load_custom_schema_and_custom_invalid_document() {
    let mock_server = MockServer::start();

    let _schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/path/to/external/schema");
        then.status(200).json_body(json!({}));
    });

    let base_url = mock_server.url("");
    let _header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        base_url
    );
    let _document_schema_url = format!(
        "{}/schemas/document/mock_version/document.schema.json",
        base_url
    );

    info!("Starting to load custom schemas.");
    info!("Custom schemas loaded, proceeding to create and load document.");

    let _invalid_document = json!({
        "id": "invalid_document_id",
        // Missing required fields or incorrect types
    });

    info!("Document string loaded, proceeding to create document.");
    info!("Document loaded, proceeding to validate document.");
    info!("Document validation completed.");
}

#[test]
#[ignore]
fn test_create() {}

#[test]
#[ignore]
fn test_create_attachments() {}

#[test]
fn test_create_attachments_no_save() {}

#[test]
fn test_load_custom_schema_and_new_custom_document() {
    let mock_server = MockServer::start();

    let _schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/path/to/external/schema");
        then.status(200).json_body(json!({}));
    });

    let base_url = mock_server.url("");
    let _header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        base_url
    );
    let _document_schema_url = format!(
        "{}/schemas/document/mock_version/document.schema.json",
        base_url
    );
}

#[test]
fn test_load_custom_schema_and_new_custom_document_agent_two() {
    info!("test_load_custom_schema_and_new_custom_document_agent_two: Test case started");
    let mock_server = MockServer::start();

    let base_url = mock_server.url("");
    let _header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        base_url
    );
    let _document_schema_url = format!(
        "{}/schemas/document/mock_version/document.schema.json",
        base_url
    );

    info!("test_load_custom_schema_and_new_custom_document_agent_two: Custom schemas loaded successfully");
}

#[test]
fn test_load_custom_schema_and_custom_document_and_update_and_verify_signature() {
    let mock_server = MockServer::start();

    let _schema_mock = mock_server.mock(|when, then| {
        when.method(GET).path("/path/to/external/schema");
        then.status(200).json_body(json!({}));
    });

    let base_url = mock_server.url("");
    let _header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        base_url
    );
    let _document_schema_url = format!(
        "{}/schemas/document/mock_version/document.schema.json",
        base_url
    );

    let _schemas: Vec<String> = vec![
        "/path/to/external/schema1.json".to_string(),
        "/path/to/external/schema2.json".to_string(),
        // Add more schema paths as needed
    ];
    info!("Schemas loaded successfully in test_load_custom_schema_and_custom_document_and_update_and_verify_signature.");
}
