# Phase 2: Database Storage Backend (Steps 96-175)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)

**Status**: Not started
**Step Range**: 96-175
**Summary**: Implement the generic database storage trait, PostgreSQL reference implementation, vector search, MultiStorage integration, domain-specific queries, and runtime index generator CLI tooling.

---

## Phase 2A: Generic Database Trait (Steps 96-115)

**Step 96.** Write test `test_database_document_traits_definition` -- trait is object-safe and can be used as `dyn DatabaseDocumentTraits`.

**Step 97.** Define `DatabaseDocumentTraits` trait in `src/storage/database_traits.rs`.

**Step 98.** Write test `test_database_document_traits_with_mock` -- mock implementation validates trait contract.

**Step 99.** Add `DatabaseError { operation: String, reason: String }` and `StorageError(String)` to `JacsError` enum.

**Step 100.** Write test `test_jacs_error_send_sync` -- verify JacsError remains Send + Sync.

**Step 101.** Add `StorageType::Database` variant (cfg-gated).

**Step 102.** Add sqlx optional dep in `Cargo.toml` under wasm32-excluded section.

**Step 103.** Add pgvector optional dep, define feature flags: `database = ["dep:sqlx", "dep:tokio"]`, `database-vector = ["database", "dep:pgvector"]`.

**Step 104.** Create `src/storage/database.rs` -- `DatabaseStorage` struct with `PgPool` + `tokio::runtime::Handle`.

**Step 105.** Define SQL migration: `jacs_document` table (jacs_id UUID, jacs_version UUID, agent_id UUID, jacs_type TEXT, file_contents JSONB, timestamps, PK on jacs_id+jacs_version).

**Step 106.** Define vector migration (behind `database-vector`): vector column + HNSW index.

**Step 107.** Implement `StorageDocumentTraits` for `DatabaseStorage`: store, get, remove, list, exists, get_by_agent, get_versions, get_latest. Convert `sqlx::Error` to `JacsError::DatabaseError { operation, reason }` at boundary.

**Step 108.** Implement `DatabaseDocumentTraits` for `DatabaseStorage`: query_by_type, query_by_field, search_text, count_by_type, query_updates_for_target, query_commitments_by_status, query_todos_for_agent, query_overdue_commitments.

**Step 109.** Add `pub mod database;` and `pub mod database_traits;` to `src/storage/mod.rs` (cfg-gated).

**Step 110.** Write integration test `test_database_storage_new_connection` (feature-gated + testcontainers).

**Step 111.** Write test `test_database_storage_migration`.

**Step 112.** Write test `test_database_store_and_retrieve`.

**Step 113.** Write test `test_database_list_by_type`.

**Step 114.** Write test `test_database_query_updates_for_target` -- retrieve update chain from DB.

**Step 115.** Write test `test_database_query_commitments_by_status`.

---

## Phase 2B: Vector Search (Steps 116-130)

**Step 116.** Write test `test_database_vector_storage`.

**Step 117.** Write test `test_database_vector_search` (cosine similarity).

**Step 118.** Add vector storage/search methods to `DatabaseStorage`.

**Step 119.** Write test `test_vector_search_by_type`.

**Step 120.** Write test `test_vector_search_ranking`.

**Step 121.** Add `extract_embedding_vector()` utility.

**Step 122.** Write test `test_extract_embedding_from_document`.

**Step 123.** Auto-extract embeddings on store.

**Step 124.** Write test `test_auto_vector_extraction_on_store`.

**Step 125.** Add JSONB query methods: `query_documents_jsonb()`.

**Step 126.** Write test `test_jsonb_query_commitment_status`.

**Step 127.** Write test `test_jsonb_query_commitments_by_date_range`.

**Step 128.** Add pagination (offset/limit).

**Step 129.** Write test `test_paginated_query`.

**Step 130.** Run full vector search integration suite.

---

## Phase 2C: MultiStorage Integration (Steps 131-150)

**Step 131.** Write test `test_multi_storage_with_database`.

**Step 132.** Modify `MultiStorage::_new()` for `StorageType::Database`.

**Step 133.** Add `database: Option<Arc<DatabaseStorage>>` to `MultiStorage` (cfg-gated).

**Step 134.** Create `StorageBackend` enum: `ObjectStore(MultiStorage) | Database(Arc<DatabaseStorage>)`.

**Step 135.** Route document operations through `StorageDocumentTraits` for database backend.

**Step 136.** Write test `test_database_backed_document_create`.

**Step 137.** Write test `test_database_backed_document_update`.

**Step 138.** Write test `test_database_backed_document_verify` -- signature survives JSONB round-trip.

**Step 139.** Implement `CachedMultiStorage` support for database.

**Step 140.** Write test `test_cached_database_storage`.

**Step 141.** Add `JACS_DATABASE_URL` to Config struct + env var loading.

**Step 142.** Update `jacs.config.schema.json`.

**Step 143.** Write test `test_config_database_url`.

**Step 144.** Write test `test_config_database_url_env_override`.

**Step 145.** Add pool config: `JACS_DATABASE_MAX_CONNECTIONS`, `JACS_DATABASE_MIN_CONNECTIONS`, `JACS_DATABASE_CONNECT_TIMEOUT_SECS`.

**Step 146.** Write test `test_database_pool_configuration`.

**Step 147.** Write test `test_optimistic_locking_on_concurrent_update` -- two agents update same doc, one fails.

**Step 148.** Storage migration tooling: `export_to_filesystem()`, `import_from_filesystem()`.

**Step 149.** Write test `test_documents_verifiable_after_migration`.

**Step 150.** Add CI: `cargo check --target wasm32-unknown-unknown`.

---

## Phase 2D: Domain Queries & Index Generator (Steps 151-175)

**Step 151-154.** Tests: commitments by status, todos for agent, updates for target, overdue commitments.

**Step 155.** Domain-specific query methods: `query_commitments_by_status()`, `query_todos_for_agent()`, `query_updates_for_target()`, `query_overdue_commitments()`.

**Step 156.** Write test `test_semantic_commitment_search` (vector search).

**Step 157.** Add full-text search (tsvector + GIN index).

**Step 158-159.** Tests: fulltext search, combined vector + text search.

**Step 160.** Aggregation queries: `count_documents_by_type()`, `count_commitments_by_status()`, `count_todos_by_agent()`, `count_updates_by_action()`.

**Step 161.** Write test `test_aggregation_queries`.

**Step 162.** Transaction support: `create_commitment_with_updates()`.

**Step 163.** Write test `test_transactional_commitment_creation`.

**Step 164.** Write test `test_suggest_indexes_for_all_types` -- index generator for todo, commitment, update.

**Step 165.** Create `src/storage/index_advisor.rs`:
- `pub struct IndexRecommendation { table, column_expr, index_type, condition, sql }`
- `pub fn suggest_indexes(schema_types: &[&str], backend: &str) -> Vec<IndexRecommendation>`

**Step 166.** Implement Postgres-specific index generation (GIN, HNSW, partial).

**Step 167.** Implement generic recommendations for non-Postgres backends.

**Step 168.** Add CLI subcommand: `jacs db suggest-indexes --backend postgres --types todo,commitment,update`.

**Step 169.** Write CLI test for index suggestion.

**Step 170-171.** CLI: `jacs db migrate`, `jacs db status`.

**Step 172-173.** CLI: `jacs db export`, `jacs db import` with verification.

**Step 174.** Write test `test_cli_full_database_workflow`.

**Step 175.** Run full Phase 2 suite + WASM check.
