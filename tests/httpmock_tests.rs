// This file contains tests that use httpmock to mock network calls.

use httpmock::{Method, MockServer};
use reqwest::blocking::Client;

#[test]
fn test_httpmock_simple_get() {
    // Start a local mock server
    let server = MockServer::start();

    // Create a mock on the server
    let hello_mock = server.mock(|when, then| {
        when.method(Method::GET).path("/hello");
        then.status(200).body("Hello, World!");
    });

    // Use reqwest to send an HTTP request to the mock server
    let response = Client::new()
        .get(&format!("{}/hello", &server.base_url()))
        .send()
        .unwrap();

    // Ensure the mock server received the request
    hello_mock.assert();
    // Ensure the response is as expected
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().unwrap(), "Hello, World!");
}
