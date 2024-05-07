use httpmock::Method::GET;
use httpmock::MockServer;
use jacs::agent::agreement::Agreement;
use jacs::agent::boilerplate::BoilerPlate;
use jacs::agent::document::Document;
use jacs::agent::AGENT_AGREEMENT_FIELDNAME;
use serde_json::json;

#[test]
fn test_create_agreement() {
    let mock_server = MockServer::start();

    let _base_url = mock_server.url("");
    let _header_schema_url = format!(
        "{}/schemas/header/{}/header.schema.json",
        _base_url, "mock_version"
    );
    let _document_schema_url = format!(
        "{}/schemas/document/{}/document.schema.json",
        _base_url, "mock_version"
    );

    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/mock_version/header.schema.json");
        then.status(200).json_body(json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Mock Header Schema",
            "type": "object",
            "properties": {
                "version": {
                    "type": "string"
                },
                "identifier": {
                    "type": "string"
                }
            },
            "required": ["version", "identifier"]
        }));
    });

    let _document_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/document/mock_version/document.schema.json");
        then.status(200).json_body(json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Mock Document Schema",
            "type": "object",
            "properties": {
                "title": {
                    "type": "string"
                },
                "content": {
                    "type": "string"
                }
            },
            "required": ["title", "content"]
        }));
    });

    const DOCID: &str = "test_document";
    let _document_path = format!("examples/documents/{}.json", DOCID);
}

#[test]
fn test_add_and_remove_agents() {
    let mock_server = MockServer::start();

    let _base_url = mock_server.url("");
    let _header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        _base_url
    );
    let _document_schema_url = format!(
        "{}/schemas/document/mock_version/document.schema.json",
        _base_url
    );

    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/mock_version/header.schema.json");
        then.status(200).json_body(json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Mock Header Schema",
            "type": "object",
            "properties": {
                "version": {
                    "type": "string"
                },
                "identifier": {
                    "type": "string"
                }
            },
            "required": ["version", "identifier"]
        }));
    });

    let _document_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/document/mock_version/document.schema.json");
        then.status(200).json_body(json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Mock Document Schema",
            "type": "object",
            "properties": {
                "title": {
                    "type": "string"
                },
                "content": {
                    "type": "string"
                }
            },
            "required": ["title", "content"]
        }));
    });

    const DOCID: &str = "test_document";
    let _document_path = format!("examples/documents/{}.json", DOCID);
    let _agents_orig: Vec<String> = vec!["mariko".to_string(), "takeda".to_string()];
    let _agents_to_add: Vec<String> = vec!["gaijin".to_string()];
    let _agents_to_remove: Vec<String> = vec!["mariko".to_string()];
}

#[test]
fn test_sign_agreement() {
    let mock_server = MockServer::start();

    let _base_url = mock_server.url("");
    let _header_schema_url = format!(
        "{}/schemas/header/mock_version/header.schema.json",
        _base_url
    );
    let _document_schema_url = format!(
        "{}/schemas/document/mock_version/document.schema.json",
        _base_url
    );

    let _header_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/header/mock_version/header.schema.json");
        then.status(200).json_body(json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Mock Header Schema",
            "type": "object",
            "properties": {
                "version": {
                    "type": "string"
                },
                "identifier": {
                    "type": "string"
                }
            },
            "required": ["version", "identifier"]
        }));
    });

    let _document_schema_mock = mock_server.mock(|when, then| {
        when.method(GET)
            .path("/schemas/document/mock_version/document.schema.json");
        then.status(200).json_body(json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Mock Document Schema",
            "type": "object",
            "properties": {
                "title": {
                    "type": "string"
                },
                "content": {
                    "type": "string"
                }
            },
            "required": ["title", "content"]
        }));
    });

    const DOCID: &str = "test_document";
    let _document_path = format!("examples/documents/{}.json", DOCID);
}
