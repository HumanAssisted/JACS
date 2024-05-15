use httpmock::Method::GET; // Importing the GET method from httpmock
use httpmock::MockServer;
use jacs::schema::ValidationError; // Importing the custom ValidationError struct
use jsonschema::JSONSchema; // Importing the JSONSchema struct
use reqwest::Client; // Importing the Client struct from reqwest
use serde_json::json; // Importing the json! macro and Value

mod utils;

#[tokio::test]
async fn test_update_agent_and_verify_versions() -> Result<(), String> {
    // Start the mock server to serve the schema files
    let mock_server = MockServer::start();

    // Setup schema mocks
    mock_server.mock(|when, then| {
        when.method(GET).path("/header.schema.json");
        then.status(200)
            .body_from_file("schemas/header/v1/header.schema.json");
    });

    // ... (rest of the mock server setup remains unchanged)

    // Create a reqwest client instance with SSL verification disabled
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to create reqwest client with disabled SSL verification");

    // Define a valid example agent JSON structure
    let example_agent_json = json!({
        "jacsId": "unique_id",
        "jacsVersion": "1.0",
        "jacsVersionDate": "2024-05-10T00:00:00Z",
        "jacsOriginalVersion": "1.0",
        "jacsOriginalDate": "2024-05-10T00:00:00Z",
        "agent_id": "12345",
        "agent_name": "Test Agent",
        "agent_type": "Test Type",
        // ... (rest of the agent JSON structure remains unchanged)
    });

    // Replace the placeholder URLs with the actual MockServer URLs for schema validation
    // ... (URL replacement code remains unchanged)

    // Fetch the schema using the reqwest client with SSL verification disabled
    let header_schema_str = client
        .get(mock_server.url("/header.schema.json"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .text()
        .await
        .map_err(|e| e.to_string())?;

    // Parse the fetched schema string into a JSON value
    let header_schema_json = serde_json::from_str(&header_schema_str).map_err(|e| e.to_string())?;

    // Create a JSONSchema object from the JSON value
    let header_schema = JSONSchema::compile(&header_schema_json).map_err(|e| e.to_string())?;

    // Validate the example agent JSON data against the fetched schema
    header_schema.validate(&example_agent_json).map_err(|e| {
        ValidationError {
            errors: e.into_iter().map(|err| err.to_string()).collect(),
        }
        .to_string()
    })?;

    Ok(())
}
