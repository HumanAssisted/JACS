//! Search abstraction and embedding traits for JACS document backends.
//!
//! This module defines:
//! - [`SearchProvider`] trait — unified search interface for all backends
//! - [`SearchQuery`], [`SearchResults`], [`SearchHit`], [`SearchMethod`] — query/result types
//! - [`SearchCapabilities`] — backend capability reporting
//! - [`FieldFilter`] — field-level search filtering
//! - [`EmbeddingProvider`] trait — user-provided embedding generation for vector search
//! - [`NoopEmbeddingProvider`] — default no-op for backends without vector search
//!
//! # Search Design
//!
//! The [`SearchProvider`] trait hides whether the backend uses fulltext search
//! (FTS5, tsvector), vector similarity (pgvector, HNSW), hybrid, or simple
//! field matching. Callers never know or care which method is used.
//!
//! All storage backends implement `SearchProvider`. Backends without native
//! search capabilities implement it with `capabilities()` returning all false
//! and `search()` returning an appropriate error. This gives callers a uniform
//! interface — they call `search()` generically and handle the result.
//!
//! The [`SearchMethod`] enum in results tells the caller what method was used,
//! but the query interface is the same regardless.
//!
//! # Embedding Design
//!
//! JACS core does NOT generate embeddings itself — users bring their own
//! embedding provider (e.g., OpenAI, local model) when configuring a backend
//! that supports vector search.
//!
//! ```rust,ignore
//! use jacs::search::EmbeddingProvider;
//!
//! struct MyEmbedder;
//! impl EmbeddingProvider for MyEmbedder {
//!     fn embed(&self, content: &str) -> Result<Vec<f64>, Box<dyn std::error::Error + Send + Sync>> {
//!         Ok(vec![0.1, 0.2, 0.3])
//!     }
//!     fn dimensions(&self) -> usize { 3 }
//!     fn model_id(&self) -> &str { "my-model" }
//! }
//! ```

use crate::agent::document::JACSDocument;
use crate::error::JacsError;
use serde::{Deserialize, Serialize};
use std::error::Error;

// =============================================================================
// SearchProvider Trait
// =============================================================================

/// Search interface for JACS document backends.
///
/// Backends that support fulltext, vector, or hybrid search implement
/// this trait. Backends without native search support should implement
/// `capabilities()` returning all `false` and `search()` returning
/// `Err(JacsError::SearchError("search not supported".into()))`.
///
/// NOTE: `JacsError::SearchError` is planned (Task 057). Until then,
/// use `JacsError::StorageError` as a temporary substitute.
///
/// # Object Safety
///
/// This trait is object-safe: `Box<dyn SearchProvider>` is valid.
///
/// # Thread Safety
///
/// Implementors must be `Send + Sync` so the trait object can be shared
/// across threads.
pub trait SearchProvider: Send + Sync {
    /// Search documents using the given query.
    ///
    /// The backend decides whether to use fulltext, vector similarity,
    /// or hybrid search. The caller doesn't know or care — they get
    /// back ranked results with scores.
    fn search(&self, query: SearchQuery) -> Result<SearchResults, JacsError>;

    /// Reports what search capabilities this backend supports.
    ///
    /// Callers can use this to adjust their UI or fall back to
    /// alternative strategies when a capability is unavailable.
    fn capabilities(&self) -> SearchCapabilities;
}

// =============================================================================
// Query Types
// =============================================================================

/// Search query that hides implementation details.
///
/// Backends may implement fulltext, vector, hybrid, or none.
/// The same `SearchQuery` struct works for all backends — unsupported
/// fields are simply ignored by backends that don't understand them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    /// Natural language or keyword query string.
    pub query: String,

    /// Optional: restrict to a specific `jacsType`.
    pub jacs_type: Option<String>,

    /// Optional: restrict to documents signed by a specific agent.
    pub agent_id: Option<String>,

    /// Optional: restrict to a specific field path (JSONB query).
    pub field_filter: Option<FieldFilter>,

    /// Maximum results to return.
    pub limit: usize,

    /// Pagination offset.
    pub offset: usize,

    /// Optional: minimum relevance score (0.0 - 1.0).
    pub min_score: Option<f64>,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            query: String::new(),
            jacs_type: None,
            agent_id: None,
            field_filter: None,
            limit: 10,
            offset: 0,
            min_score: None,
        }
    }
}

/// A field-level filter for narrowing search results.
///
/// Restricts results to documents where the specified JSON field path
/// matches the given value. Used for JSONB queries in database backends
/// or field-level filtering in simpler backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldFilter {
    /// JSON field path (e.g., `"jacsCommitmentStatus"`, `"metadata.category"`).
    pub field_path: String,

    /// Expected value for the field.
    pub value: String,
}

// =============================================================================
// Result Types
// =============================================================================

/// Results from a search operation.
///
/// Contains the matched documents with scores, the total count of
/// matches (for pagination), and which search method the backend used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    /// The matched documents, ordered by relevance score (highest first).
    pub results: Vec<SearchHit>,

    /// Total number of matching documents (may exceed `results.len()`
    /// when pagination is in effect).
    pub total_count: usize,

    /// Backend reports what search method was used.
    pub method: SearchMethod,
}

/// A single search result with relevance metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    /// The matched document.
    pub document: JACSDocument,

    /// Relevance score (0.0 - 1.0, higher is more relevant).
    pub score: f64,

    /// Which field(s) matched, if applicable.
    /// Empty for backends that don't track field-level matches.
    pub matched_fields: Vec<String>,
}

// =============================================================================
// Search Method & Capabilities
// =============================================================================

/// The search method used by a backend to produce results.
///
/// Returned in [`SearchResults::method`] so callers know what type
/// of search was performed, even though the query interface is uniform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchMethod {
    /// Backend used full-text search (e.g., SQLite FTS5, PostgreSQL tsvector).
    FullText,

    /// Backend used vector similarity search (e.g., pgvector, HNSW).
    Vector,

    /// Backend used a combination of fulltext + vector.
    Hybrid,

    /// Backend did a simple field/prefix match (filesystem).
    FieldMatch,

    /// Backend does not support search; returned empty results.
    Unsupported,
}

/// Describes the search capabilities of a storage backend.
///
/// Backends report their capabilities so callers can adjust their
/// behavior (e.g., show different UI, fall back to listing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchCapabilities {
    /// Whether the backend supports full-text search.
    pub fulltext: bool,

    /// Whether the backend supports vector similarity search.
    pub vector: bool,

    /// Whether the backend supports hybrid (fulltext + vector) search.
    pub hybrid: bool,

    /// Whether the backend supports field-level filtering.
    pub field_filter: bool,
}

impl SearchCapabilities {
    /// Returns capabilities for a backend that supports no search.
    pub fn none() -> Self {
        Self {
            fulltext: false,
            vector: false,
            hybrid: false,
            field_filter: false,
        }
    }
}

impl Default for SearchCapabilities {
    fn default() -> Self {
        Self::none()
    }
}

// =============================================================================
// EmbeddingProvider Trait
// =============================================================================

/// User-provided embedding generator. JACS core does not include LLM clients.
/// Backends that support vector search accept an optional `EmbeddingProvider`.
///
/// This trait is object-safe and can be used as `Box<dyn EmbeddingProvider>`.
///
/// # Implementors
///
/// Implement this trait to connect your embedding model (OpenAI, Cohere, local
/// model, etc.) to a JACS storage backend that supports vector search.
pub trait EmbeddingProvider: Send + Sync {
    /// Generate an embedding vector for the given text content.
    ///
    /// Returns a vector of f64 values representing the embedding.
    /// The length of the returned vector must match [`Self::dimensions()`].
    fn embed(&self, content: &str) -> Result<Vec<f64>, Box<dyn Error + Send + Sync>>;

    /// Embedding dimensionality (e.g., 1536 for text-embedding-3-small).
    ///
    /// This is used by storage backends to configure their vector columns.
    fn dimensions(&self) -> usize;

    /// Model identifier for provenance tracking.
    ///
    /// Stored alongside embeddings so consumers know which model produced them.
    /// Examples: "text-embedding-3-small", "all-MiniLM-L6-v2".
    fn model_id(&self) -> &str;
}

/// A no-op embedding provider for backends that don't use vector search.
///
/// All calls to [`embed()`](EmbeddingProvider::embed) return an error indicating
/// that embedding is not configured. This is the default when no user-provided
/// embedding provider is supplied.
pub struct NoopEmbeddingProvider;

impl EmbeddingProvider for NoopEmbeddingProvider {
    fn embed(&self, _content: &str) -> Result<Vec<f64>, Box<dyn Error + Send + Sync>> {
        Err("Embedding not configured: no EmbeddingProvider was supplied. \
             To use vector search, provide an EmbeddingProvider implementation \
             when configuring your storage backend."
            .into())
    }

    fn dimensions(&self) -> usize {
        0
    }

    fn model_id(&self) -> &str {
        "noop"
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // =========================================================================
    // SearchProvider Object Safety Tests
    // =========================================================================

    /// Verify that `SearchProvider` is object-safe by referencing a trait object.
    #[test]
    fn search_provider_is_object_safe() {
        fn _assert_object_safe(_: &dyn SearchProvider) {}
    }

    /// Verify that `SearchProvider` requires `Send + Sync`.
    #[test]
    fn search_provider_is_send_sync() {
        fn _assert_send_sync<T: Send + Sync + ?Sized>() {}
        _assert_send_sync::<dyn SearchProvider>();
    }

    // =========================================================================
    // SearchQuery Tests
    // =========================================================================

    #[test]
    fn search_query_default_is_sensible() {
        let query = SearchQuery::default();
        assert_eq!(query.query, "");
        assert_eq!(query.limit, 10);
        assert_eq!(query.offset, 0);
        assert!(query.jacs_type.is_none());
        assert!(query.agent_id.is_none());
        assert!(query.field_filter.is_none());
        assert!(query.min_score.is_none());
    }

    #[test]
    fn search_query_with_all_fields() {
        let query = SearchQuery {
            query: "authentication middleware".to_string(),
            jacs_type: Some("artifact".to_string()),
            agent_id: Some("agent-123".to_string()),
            field_filter: Some(FieldFilter {
                field_path: "category".to_string(),
                value: "security".to_string(),
            }),
            limit: 20,
            offset: 5,
            min_score: Some(0.7),
        };
        assert_eq!(query.query, "authentication middleware");
        assert_eq!(query.jacs_type.as_deref(), Some("artifact"));
        assert_eq!(query.agent_id.as_deref(), Some("agent-123"));
        assert!(query.field_filter.is_some());
        assert_eq!(query.limit, 20);
        assert_eq!(query.offset, 5);
        assert_eq!(query.min_score, Some(0.7));
    }

    // =========================================================================
    // SearchResults / SearchHit Tests
    // =========================================================================

    #[test]
    fn search_results_with_unsupported_method() {
        let results = SearchResults {
            results: vec![],
            total_count: 0,
            method: SearchMethod::Unsupported,
        };
        assert_eq!(results.method, SearchMethod::Unsupported);
        assert_eq!(results.total_count, 0);
        assert!(results.results.is_empty());
    }

    #[test]
    fn search_hit_can_be_constructed() {
        let doc = JACSDocument {
            id: "doc-1".to_string(),
            version: "v1".to_string(),
            jacs_type: "artifact".to_string(),
            value: json!({"jacsId": "doc-1", "jacsVersion": "v1", "jacsType": "artifact"}),
        };

        let hit = SearchHit {
            document: doc,
            score: 0.95,
            matched_fields: vec!["content".to_string()],
        };
        assert_eq!(hit.score, 0.95);
        assert_eq!(hit.matched_fields, vec!["content"]);
        assert_eq!(hit.document.id, "doc-1");
    }

    // =========================================================================
    // SearchMethod Tests
    // =========================================================================

    #[test]
    fn search_method_has_all_five_variants() {
        let methods = vec![
            SearchMethod::FullText,
            SearchMethod::Vector,
            SearchMethod::Hybrid,
            SearchMethod::FieldMatch,
            SearchMethod::Unsupported,
        ];
        for i in 0..methods.len() {
            for j in (i + 1)..methods.len() {
                assert_ne!(methods[i], methods[j]);
            }
        }
    }

    // =========================================================================
    // SearchCapabilities Tests
    // =========================================================================

    #[test]
    fn search_capabilities_none_returns_all_false() {
        let caps = SearchCapabilities::none();
        assert!(!caps.fulltext);
        assert!(!caps.vector);
        assert!(!caps.hybrid);
        assert!(!caps.field_filter);
    }

    #[test]
    fn search_capabilities_default_is_none() {
        let caps = SearchCapabilities::default();
        assert_eq!(caps, SearchCapabilities::none());
    }

    #[test]
    fn search_capabilities_reports_correctly() {
        let caps = SearchCapabilities {
            fulltext: true,
            vector: false,
            hybrid: false,
            field_filter: true,
        };
        assert!(caps.fulltext);
        assert!(!caps.vector);
        assert!(!caps.hybrid);
        assert!(caps.field_filter);
    }

    // =========================================================================
    // FieldFilter Tests
    // =========================================================================

    #[test]
    fn field_filter_can_be_constructed() {
        let filter = FieldFilter {
            field_path: "jacsCommitmentStatus".to_string(),
            value: "active".to_string(),
        };
        assert_eq!(filter.field_path, "jacsCommitmentStatus");
        assert_eq!(filter.value, "active");
    }

    // =========================================================================
    // EmbeddingProvider Object Safety Tests
    // =========================================================================

    #[test]
    fn embedding_provider_is_object_safe() {
        let provider: Box<dyn EmbeddingProvider> = Box::new(NoopEmbeddingProvider);
        assert_eq!(provider.dimensions(), 0);
        assert_eq!(provider.model_id(), "noop");
    }

    #[test]
    fn embedding_provider_box_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Box<dyn EmbeddingProvider>>();
    }

    // =========================================================================
    // NoopEmbeddingProvider Tests
    // =========================================================================

    #[test]
    fn noop_embed_returns_error() {
        let provider = NoopEmbeddingProvider;
        let result = provider.embed("test content");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not configured"),
            "Error should explain that embedding is not configured, got: {}",
            err_msg
        );
    }

    #[test]
    fn noop_dimensions_is_zero() {
        let provider = NoopEmbeddingProvider;
        assert_eq!(provider.dimensions(), 0);
    }

    #[test]
    fn noop_model_id_is_noop() {
        let provider = NoopEmbeddingProvider;
        assert_eq!(provider.model_id(), "noop");
    }

    // =========================================================================
    // Mock EmbeddingProvider Tests
    // =========================================================================

    struct MockEmbeddingProvider {
        dims: usize,
        model: String,
    }

    impl MockEmbeddingProvider {
        fn new(dims: usize, model: &str) -> Self {
            Self {
                dims,
                model: model.to_string(),
            }
        }
    }

    impl EmbeddingProvider for MockEmbeddingProvider {
        fn embed(&self, _content: &str) -> Result<Vec<f64>, Box<dyn Error + Send + Sync>> {
            Ok(vec![0.1; self.dims])
        }

        fn dimensions(&self) -> usize {
            self.dims
        }

        fn model_id(&self) -> &str {
            &self.model
        }
    }

    #[test]
    fn mock_provider_can_be_created_and_called() {
        let provider = MockEmbeddingProvider::new(1536, "text-embedding-3-small");

        assert_eq!(provider.dimensions(), 1536);
        assert_eq!(provider.model_id(), "text-embedding-3-small");

        let embedding = provider.embed("hello world").expect("embed should succeed");
        assert_eq!(embedding.len(), 1536);
        assert!((embedding[0] - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn mock_provider_works_as_trait_object() {
        let provider: Box<dyn EmbeddingProvider> =
            Box::new(MockEmbeddingProvider::new(768, "all-MiniLM-L6-v2"));

        assert_eq!(provider.dimensions(), 768);
        assert_eq!(provider.model_id(), "all-MiniLM-L6-v2");

        let embedding = provider.embed("test").expect("embed should succeed");
        assert_eq!(embedding.len(), 768);
    }

    #[test]
    fn mock_provider_is_send_sync() {
        let provider: Box<dyn EmbeddingProvider> =
            Box::new(MockEmbeddingProvider::new(3, "test-model"));

        let handle = std::thread::spawn(move || {
            provider.embed("cross-thread").expect("embed should work")
        });
        let result = handle.join().expect("thread should complete");
        assert_eq!(result.len(), 3);
    }
}
