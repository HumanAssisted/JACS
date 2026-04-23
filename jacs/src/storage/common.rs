use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use crate::search::{SearchHit, SearchMethod, SearchResults};
use serde_json::Value;

/// Parse a document key in the form `id:version`.
///
/// Versions may contain additional colons; only the first colon splits the key.
pub fn parse_document_key(key: &str) -> Result<(&str, &str), JacsError> {
    let (id, version) = key
        .split_once(':')
        .ok_or_else(|| format!("Invalid document key '{}': expected 'id:version'", key))?;
    Ok((id, version))
}

/// Reconstruct a stored document from canonical JSON text.
pub fn document_from_raw_json(raw: &str) -> Result<JACSDocument, JacsError> {
    let value: Value = serde_json::from_str(raw)?;
    document_from_value(value)
}

/// Reconstruct a stored document from canonical JSON bytes.
pub fn document_from_raw_bytes(raw: &[u8]) -> Result<JACSDocument, JacsError> {
    let value: Value = serde_json::from_slice(raw)?;
    document_from_value(value)
}

/// Extract the signing agent id from a document signature if present.
pub fn extract_signature_agent_id(value: &Value) -> Option<String> {
    value
        .get("jacsSignature")
        .and_then(|signature| {
            signature
                .get("agentID")
                .or_else(|| signature.get("jacsSignatureAgentId"))
        })
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Traverse a JSON value using a dot-separated field path.
pub fn get_nested_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

/// Check whether a nested field matches an exact string representation.
pub fn field_matches_exact(value: &Value, field_path: &str, expected: &str) -> bool {
    get_nested_field(value, field_path).is_some_and(|field_value| match field_value {
        Value::String(s) => s == expected,
        other => other.to_string().trim_matches('"') == expected,
    })
}

/// Wrap exact field-filter matches into a consistent `SearchResults` shape.
pub fn build_field_filter_search_results(
    docs: Vec<JACSDocument>,
    field_path: &str,
) -> SearchResults {
    let total_count = docs.len();
    let matched_field = field_path.to_string();
    let results = docs
        .into_iter()
        .map(|document| SearchHit {
            document,
            score: 1.0,
            matched_fields: vec![matched_field.clone()],
        })
        .collect();

    SearchResults {
        results,
        total_count,
        method: SearchMethod::FieldMatch,
    }
}

fn document_from_value(value: Value) -> Result<JACSDocument, JacsError> {
    let id = value
        .get("jacsId")
        .and_then(|v| v.as_str())
        .ok_or("Document missing required field: jacsId")?
        .to_string();
    let version = value
        .get("jacsVersion")
        .and_then(|v| v.as_str())
        .ok_or("Document missing required field: jacsVersion")?
        .to_string();
    let jacs_type = value
        .get("jacsType")
        .and_then(|v| v.as_str())
        .ok_or("Document missing required field: jacsType")?
        .to_string();

    Ok(JACSDocument {
        id,
        version,
        value,
        jacs_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageDocumentTraits;
    use crate::testing::make_test_doc;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    struct MockStorage {
        docs: Mutex<HashMap<String, JACSDocument>>,
        store_failures: HashSet<String>,
        get_failures: HashSet<String>,
        stored_keys: Mutex<Vec<String>>,
        fetched_keys: Mutex<Vec<String>>,
    }

    impl MockStorage {
        fn new(docs: Vec<JACSDocument>) -> Self {
            let docs = docs
                .into_iter()
                .map(|doc| (doc.getkey(), doc))
                .collect::<HashMap<_, _>>();
            Self {
                docs: Mutex::new(docs),
                store_failures: HashSet::new(),
                get_failures: HashSet::new(),
                stored_keys: Mutex::new(Vec::new()),
                fetched_keys: Mutex::new(Vec::new()),
            }
        }

        fn with_store_failures(mut self, failures: &[&str]) -> Self {
            self.store_failures = failures.iter().map(|key| key.to_string()).collect();
            self
        }

        fn with_get_failures(mut self, failures: &[&str]) -> Self {
            self.get_failures = failures.iter().map(|key| key.to_string()).collect();
            self
        }
    }

    impl StorageDocumentTraits for MockStorage {
        fn store_document(&self, doc: &JACSDocument) -> Result<(), JacsError> {
            let key = doc.getkey();
            if self.store_failures.contains(&key) {
                return Err(JacsError::StorageError(format!("store failure: {}", key)));
            }

            self.docs
                .lock()
                .expect("lock docs")
                .insert(key.clone(), doc.clone());
            self.stored_keys.lock().expect("lock stored keys").push(key);
            Ok(())
        }

        fn get_document(&self, key: &str) -> Result<JACSDocument, JacsError> {
            self.fetched_keys
                .lock()
                .expect("lock fetched keys")
                .push(key.to_string());
            if self.get_failures.contains(key) {
                return Err(JacsError::StorageError(format!("get failure: {}", key)));
            }

            self.docs
                .lock()
                .expect("lock docs")
                .get(key)
                .cloned()
                .ok_or_else(|| JacsError::StorageError(format!("missing doc: {}", key)))
        }

        fn remove_document(&self, _key: &str) -> Result<JACSDocument, JacsError> {
            unimplemented!("not needed in these unit tests")
        }

        fn list_documents(&self, _prefix: &str) -> Result<Vec<String>, JacsError> {
            unimplemented!("not needed in these unit tests")
        }

        fn document_exists(&self, _key: &str) -> Result<bool, JacsError> {
            unimplemented!("not needed in these unit tests")
        }

        fn get_documents_by_agent(&self, _agent_id: &str) -> Result<Vec<String>, JacsError> {
            unimplemented!("not needed in these unit tests")
        }

        fn get_document_versions(&self, _document_id: &str) -> Result<Vec<String>, JacsError> {
            unimplemented!("not needed in these unit tests")
        }

        fn get_latest_document(&self, _document_id: &str) -> Result<JACSDocument, JacsError> {
            unimplemented!("not needed in these unit tests")
        }

        fn merge_documents(
            &self,
            _doc_id: &str,
            _v1: &str,
            _v2: &str,
        ) -> Result<JACSDocument, JacsError> {
            unimplemented!("not needed in these unit tests")
        }
    }

    #[test]
    fn parse_document_key_accepts_colons_in_version() {
        let (id, version) = parse_document_key("doc-1:v1:extra").expect("parse key");
        assert_eq!(id, "doc-1");
        assert_eq!(version, "v1:extra");
    }

    #[test]
    fn parse_document_key_rejects_missing_separator() {
        let err = parse_document_key("invalid-key").expect_err("key should be rejected");
        assert!(err.to_string().contains("expected 'id:version'"));
    }

    #[test]
    fn document_from_raw_json_extracts_required_fields() {
        let raw = json!({
            "jacsId": "doc-1",
            "jacsVersion": "v1",
            "jacsType": "config",
            "payload": {"ok": true}
        })
        .to_string();

        let doc = document_from_raw_json(&raw).expect("document from json");
        assert_eq!(doc.id, "doc-1");
        assert_eq!(doc.version, "v1");
        assert_eq!(doc.jacs_type, "config");
        assert_eq!(doc.value["payload"]["ok"], true);
    }

    #[test]
    fn document_from_raw_bytes_extracts_required_fields() {
        let raw = json!({
            "jacsId": "doc-2",
            "jacsVersion": "v2",
            "jacsType": "artifact",
            "content": "hello"
        })
        .to_string();

        let doc = document_from_raw_bytes(raw.as_bytes()).expect("document from bytes");
        assert_eq!(doc.id, "doc-2");
        assert_eq!(doc.version, "v2");
        assert_eq!(doc.jacs_type, "artifact");
    }

    #[test]
    fn extract_signature_agent_id_supports_both_signature_keys() {
        let legacy = json!({
            "jacsSignature": {
                "agentID": "agent-legacy"
            }
        });
        let binding = json!({
            "jacsSignature": {
                "jacsSignatureAgentId": "agent-binding"
            }
        });

        assert_eq!(
            extract_signature_agent_id(&legacy),
            Some("agent-legacy".to_string())
        );
        assert_eq!(
            extract_signature_agent_id(&binding),
            Some("agent-binding".to_string())
        );
    }

    #[test]
    fn get_nested_field_resolves_dot_paths() {
        let value = json!({
            "metadata": {
                "status": {
                    "state": "active"
                }
            }
        });

        assert_eq!(
            get_nested_field(&value, "metadata.status.state"),
            Some(&json!("active"))
        );
        assert!(get_nested_field(&value, "metadata.status.missing").is_none());
    }

    #[test]
    fn field_matches_exact_handles_strings_and_scalars() {
        let value = json!({
            "metadata": {
                "status": "active",
                "priority": 3,
                "published": true
            }
        });

        assert!(field_matches_exact(&value, "metadata.status", "active"));
        assert!(field_matches_exact(&value, "metadata.priority", "3"));
        assert!(field_matches_exact(&value, "metadata.published", "true"));
        assert!(!field_matches_exact(&value, "metadata.status", "inactive"));
    }

    #[test]
    fn build_field_filter_search_results_sets_shape_consistently() {
        let docs = vec![
            make_test_doc("search-1", "v1", "config", None),
            make_test_doc("search-2", "v1", "config", None),
        ];

        let results = build_field_filter_search_results(docs, "metadata.status");

        assert_eq!(results.total_count, 2);
        assert_eq!(results.method, SearchMethod::FieldMatch);
        assert_eq!(results.results.len(), 2);
        assert_eq!(results.results[0].matched_fields, vec!["metadata.status"]);
        assert_eq!(results.results[1].matched_fields, vec!["metadata.status"]);
    }

    #[test]
    fn default_store_documents_returns_keys_in_input_order() {
        let storage = MockStorage::new(Vec::new());
        let docs = vec![
            make_test_doc("bulk-store-2", "v1", "config", None),
            make_test_doc("bulk-store-1", "v1", "config", None),
        ];

        let keys = storage
            .store_documents(docs.clone())
            .expect("store_documents should succeed");

        assert_eq!(keys, vec!["bulk-store-2:v1", "bulk-store-1:v1"]);
        assert_eq!(
            storage
                .stored_keys
                .lock()
                .expect("lock stored keys")
                .clone(),
            vec!["bulk-store-2:v1", "bulk-store-1:v1"]
        );
    }

    #[test]
    fn default_store_documents_aggregates_partial_failures_in_input_order() {
        let storage = MockStorage::new(Vec::new())
            .with_store_failures(&["bulk-store-fail-2:v1", "bulk-store-fail-3:v1"]);
        let docs = vec![
            make_test_doc("bulk-store-fail-1", "v1", "config", None),
            make_test_doc("bulk-store-fail-2", "v1", "config", None),
            make_test_doc("bulk-store-fail-3", "v1", "config", None),
        ];

        let errors = storage
            .store_documents(docs)
            .expect_err("store_documents should aggregate failures");

        assert_eq!(errors.len(), 2);
        assert!(errors[0].to_string().contains("bulk-store-fail-2:v1"));
        assert!(errors[1].to_string().contains("bulk-store-fail-3:v1"));
        assert_eq!(
            storage
                .stored_keys
                .lock()
                .expect("lock stored keys")
                .clone(),
            vec!["bulk-store-fail-1:v1"]
        );
    }

    #[test]
    fn default_get_documents_returns_documents_in_requested_order() {
        let doc_a = make_test_doc("bulk-get-1", "v1", "config", None);
        let doc_b = make_test_doc("bulk-get-2", "v1", "config", None);
        let storage = MockStorage::new(vec![doc_a.clone(), doc_b.clone()]);

        let docs = storage
            .get_documents(vec![doc_b.getkey(), doc_a.getkey()])
            .expect("get_documents should succeed");

        assert_eq!(docs[0].getkey(), "bulk-get-2:v1");
        assert_eq!(docs[1].getkey(), "bulk-get-1:v1");
        assert_eq!(
            storage
                .fetched_keys
                .lock()
                .expect("lock fetched keys")
                .clone(),
            vec!["bulk-get-2:v1", "bulk-get-1:v1"]
        );
    }

    #[test]
    fn default_get_documents_aggregates_partial_failures_in_request_order() {
        let doc_a = make_test_doc("bulk-get-fail-1", "v1", "config", None);
        let doc_b = make_test_doc("bulk-get-fail-2", "v1", "config", None);
        let doc_c = make_test_doc("bulk-get-fail-3", "v1", "config", None);
        let storage = MockStorage::new(vec![doc_a, doc_b, doc_c])
            .with_get_failures(&["bulk-get-fail-1:v1", "bulk-get-fail-3:v1"]);

        let errors = storage
            .get_documents(vec![
                "bulk-get-fail-1:v1".to_string(),
                "bulk-get-fail-2:v1".to_string(),
                "bulk-get-fail-3:v1".to_string(),
            ])
            .expect_err("get_documents should aggregate failures");

        assert_eq!(errors.len(), 2);
        assert!(errors[0].to_string().contains("bulk-get-fail-1:v1"));
        assert!(errors[1].to_string().contains("bulk-get-fail-3:v1"));
        assert_eq!(
            storage
                .fetched_keys
                .lock()
                .expect("lock fetched keys")
                .clone(),
            vec![
                "bulk-get-fail-1:v1",
                "bulk-get-fail-2:v1",
                "bulk-get-fail-3:v1"
            ]
        );
    }
}
