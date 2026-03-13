//! Tests for `DocumentServiceWrapper` — JSON-in/JSON-out document API adapter.
//!
//! These tests use an in-memory mock DocumentService to verify that the
//! wrapper correctly marshals JSON inputs/outputs without testing the
//! actual filesystem backend.

use jacs::agent::document::JACSDocument;
use jacs::document::DocumentService;
use jacs::document::types::{
    CreateOptions, DocumentDiff, DocumentSummary, DocumentVisibility, ListFilter, UpdateOptions,
};
use jacs::error::JacsError;
use jacs::search::{SearchMethod, SearchQuery, SearchResults};
use jacs_binding_core::{DocumentServiceWrapper, ErrorKind};
use serde_json::{Value, json};
use std::sync::Mutex;

// =============================================================================
// In-memory mock DocumentService
// =============================================================================

struct MockDocumentService {
    docs: Mutex<Vec<(String, Value)>>,
}

impl MockDocumentService {
    fn new() -> Self {
        Self {
            docs: Mutex::new(Vec::new()),
        }
    }

    fn make_doc(id: &str, version: &str, value: Value) -> JACSDocument {
        let jacs_type = value["jacsType"]
            .as_str()
            .unwrap_or("artifact")
            .to_string();
        JACSDocument {
            id: id.to_string(),
            version: version.to_string(),
            value,
            jacs_type,
        }
    }
}

impl DocumentService for MockDocumentService {
    fn create(&self, json: &str, options: CreateOptions) -> Result<JACSDocument, JacsError> {
        let value: Value = serde_json::from_str(json).map_err(|e| JacsError::Internal {
            message: format!("Invalid JSON: {}", e),
        })?;

        let id = format!("doc-{}", self.docs.lock().unwrap().len() + 1);
        let version = "1".to_string();
        let key = format!("{}:{}", id, version);

        let doc_value = json!({
            "jacsId": id,
            "jacsVersion": version,
            "jacsType": options.jacs_type,
            "content": value
        });

        let doc = MockDocumentService::make_doc(&id, &version, doc_value.clone());
        self.docs.lock().unwrap().push((key, doc_value));
        Ok(doc)
    }

    fn get(&self, key: &str) -> Result<JACSDocument, JacsError> {
        let docs = self.docs.lock().unwrap();
        for (k, v) in docs.iter() {
            if k == key {
                let parts: Vec<&str> = key.splitn(2, ':').collect();
                return Ok(MockDocumentService::make_doc(
                    parts[0],
                    parts.get(1).unwrap_or(&"1"),
                    v.clone(),
                ));
            }
        }
        Err(JacsError::Internal {
            message: format!("Document '{}' not found", key),
        })
    }

    fn get_latest(&self, document_id: &str) -> Result<JACSDocument, JacsError> {
        let docs = self.docs.lock().unwrap();
        for (k, v) in docs.iter().rev() {
            if k.starts_with(&format!("{}:", document_id)) {
                let parts: Vec<&str> = k.splitn(2, ':').collect();
                return Ok(MockDocumentService::make_doc(
                    parts[0],
                    parts.get(1).unwrap_or(&"1"),
                    v.clone(),
                ));
            }
        }
        Err(JacsError::Internal {
            message: format!("Document '{}' not found", document_id),
        })
    }

    fn update(
        &self,
        document_id: &str,
        new_json: &str,
        _options: UpdateOptions,
    ) -> Result<JACSDocument, JacsError> {
        let new_value: Value = serde_json::from_str(new_json).map_err(|e| JacsError::Internal {
            message: format!("Invalid JSON: {}", e),
        })?;

        let version = "2".to_string();
        let key = format!("{}:{}", document_id, version);

        let doc_value = json!({
            "jacsId": document_id,
            "jacsVersion": version,
            "jacsType": "artifact",
            "content": new_value
        });

        let doc = MockDocumentService::make_doc(document_id, &version, doc_value.clone());
        self.docs.lock().unwrap().push((key, doc_value));
        Ok(doc)
    }

    fn remove(&self, key: &str) -> Result<JACSDocument, JacsError> {
        self.get(key)
    }

    fn list(&self, _filter: ListFilter) -> Result<Vec<DocumentSummary>, JacsError> {
        let docs = self.docs.lock().unwrap();
        let summaries: Vec<DocumentSummary> = docs
            .iter()
            .map(|(key, v)| {
                let parts: Vec<&str> = key.splitn(2, ':').collect();
                DocumentSummary {
                    key: key.clone(),
                    document_id: parts[0].to_string(),
                    version: parts.get(1).unwrap_or(&"1").to_string(),
                    jacs_type: v["jacsType"]
                        .as_str()
                        .unwrap_or("artifact")
                        .to_string(),
                    visibility: DocumentVisibility::Private,
                    created_at: "2026-03-12T00:00:00Z".to_string(),
                    agent_id: "mock-agent".to_string(),
                }
            })
            .collect();
        Ok(summaries)
    }

    fn versions(&self, document_id: &str) -> Result<Vec<JACSDocument>, JacsError> {
        let docs = self.docs.lock().unwrap();
        let versions: Vec<JACSDocument> = docs
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{}:", document_id)))
            .map(|(k, v)| {
                let parts: Vec<&str> = k.splitn(2, ':').collect();
                MockDocumentService::make_doc(
                    parts[0],
                    parts.get(1).unwrap_or(&"1"),
                    v.clone(),
                )
            })
            .collect();
        Ok(versions)
    }

    fn diff(&self, key_a: &str, key_b: &str) -> Result<DocumentDiff, JacsError> {
        Ok(DocumentDiff {
            key_a: key_a.to_string(),
            key_b: key_b.to_string(),
            diff_text: "mock diff".to_string(),
            additions: 1,
            deletions: 0,
        })
    }

    fn search(&self, _query: SearchQuery) -> Result<SearchResults, JacsError> {
        Ok(SearchResults {
            results: vec![],
            total_count: 0,
            method: SearchMethod::FieldMatch,
        })
    }

    fn create_batch(
        &self,
        documents: &[&str],
        options: CreateOptions,
    ) -> Result<Vec<JACSDocument>, Vec<JacsError>> {
        let mut results = Vec::new();
        for doc in documents {
            match self.create(doc, options.clone()) {
                Ok(d) => results.push(d),
                Err(e) => return Err(vec![e]),
            }
        }
        Ok(results)
    }

    fn visibility(&self, _key: &str) -> Result<DocumentVisibility, JacsError> {
        Ok(DocumentVisibility::Private)
    }

    fn set_visibility(
        &self,
        _key: &str,
        _visibility: DocumentVisibility,
    ) -> Result<(), JacsError> {
        Ok(())
    }
}

// =============================================================================
// Helper
// =============================================================================

fn mock_wrapper() -> DocumentServiceWrapper {
    DocumentServiceWrapper::new(Box::new(MockDocumentService::new()))
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_create_json_returns_signed_document() {
    let wrapper = mock_wrapper();
    let result = wrapper.create_json(r#"{"title": "Test"}"#, None);
    assert!(result.is_ok(), "create_json should succeed: {:?}", result.err());

    let doc: Value = serde_json::from_str(&result.unwrap()).expect("should be valid JSON");
    assert!(doc.get("jacsId").is_some(), "should have jacsId");
    assert!(doc.get("content").is_some(), "should have content");
}

#[test]
fn test_create_json_with_options() {
    let wrapper = mock_wrapper();
    let options = r#"{"jacs_type": "message", "visibility": "public"}"#;
    let result = wrapper.create_json(r#"{"body": "hello"}"#, Some(options));
    assert!(result.is_ok());

    let doc: Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(doc["jacsType"], "message");
}

#[test]
fn test_get_json_retrieves_created_document() {
    let wrapper = mock_wrapper();
    let created = wrapper
        .create_json(r#"{"title": "Test"}"#, None)
        .unwrap();
    let doc: Value = serde_json::from_str(&created).unwrap();
    let id = doc["jacsId"].as_str().unwrap();
    let version = doc["jacsVersion"].as_str().unwrap();
    let key = format!("{}:{}", id, version);

    let result = wrapper.get_json(&key);
    assert!(result.is_ok(), "get_json should succeed: {:?}", result.err());

    let fetched: Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(fetched["jacsId"], doc["jacsId"]);
}

#[test]
fn test_list_json_returns_summaries() {
    let wrapper = mock_wrapper();
    wrapper.create_json(r#"{"title": "Doc1"}"#, None).unwrap();
    wrapper.create_json(r#"{"title": "Doc2"}"#, None).unwrap();

    let result = wrapper.list_json(None);
    assert!(result.is_ok());

    let summaries: Vec<Value> = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(summaries.len(), 2);
}

#[test]
fn test_list_json_with_filter() {
    let wrapper = mock_wrapper();
    wrapper.create_json(r#"{"title": "Doc1"}"#, None).unwrap();

    let filter = r#"{"jacs_type": "artifact", "limit": 10}"#;
    let result = wrapper.list_json(Some(filter));
    assert!(result.is_ok());
}

#[test]
fn test_search_json_returns_results() {
    let wrapper = mock_wrapper();
    let query = r#"{"query": "test query", "limit": 10, "offset": 0}"#;
    let result = wrapper.search_json(query);
    assert!(result.is_ok());

    let results: Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(results["total_count"], 0);
}

#[test]
fn test_invalid_json_returns_clear_error() {
    let wrapper = mock_wrapper();
    let result = wrapper.create_json("not valid json {{{", None);
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(
        err.message.contains("Invalid JSON"),
        "error should mention invalid JSON: {}",
        err.message
    );
}

#[test]
fn test_invalid_options_json_returns_clear_error() {
    let wrapper = mock_wrapper();
    let result = wrapper.create_json(r#"{"title": "Test"}"#, Some("bad options"));
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidArgument);
}

#[test]
fn test_invalid_filter_json_returns_clear_error() {
    let wrapper = mock_wrapper();
    let result = wrapper.list_json(Some("bad filter"));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind, ErrorKind::InvalidArgument);
}

#[test]
fn test_invalid_search_query_returns_clear_error() {
    let wrapper = mock_wrapper();
    let result = wrapper.search_json("bad query");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind, ErrorKind::InvalidArgument);
}

#[test]
fn test_update_json() {
    let wrapper = mock_wrapper();
    let created = wrapper
        .create_json(r#"{"title": "Original"}"#, None)
        .unwrap();
    let doc: Value = serde_json::from_str(&created).unwrap();
    let id = doc["jacsId"].as_str().unwrap();

    let result = wrapper.update_json(id, r#"{"title": "Updated"}"#, None);
    assert!(result.is_ok());

    let updated: Value = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(updated["jacsVersion"], "2");
}

#[test]
fn test_remove_json() {
    let wrapper = mock_wrapper();
    let created = wrapper
        .create_json(r#"{"title": "To Remove"}"#, None)
        .unwrap();
    let doc: Value = serde_json::from_str(&created).unwrap();
    let key = format!(
        "{}:{}",
        doc["jacsId"].as_str().unwrap(),
        doc["jacsVersion"].as_str().unwrap()
    );

    let result = wrapper.remove_json(&key);
    assert!(result.is_ok());
}

#[test]
fn test_document_service_wrapper_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DocumentServiceWrapper>();
}

#[test]
fn test_get_nonexistent_returns_error() {
    let wrapper = mock_wrapper();
    let result = wrapper.get_json("nonexistent:1");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind, ErrorKind::DocumentFailed);
}
