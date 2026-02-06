# Phase 2: Database Storage Backend (Steps 96-175)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)

**Status**: Not started
**Step Range**: 96-175
**Dependencies**: Phase 1 (Steps 1-95) must be complete. Requires Commitment, Update, Todo List, and Conversation schemas to exist and pass validation. Requires `StorageDocumentTraits` (already implemented in `jacs/src/storage/mod.rs:422-444`), `JacsError` enum (already in `jacs/src/error.rs`), and `JACSDocument` struct (already in `jacs/src/agent/document.rs`).

---

## What This Phase Delivers

Phase 2 adds a full relational database backend to JACS so that documents can be stored in PostgreSQL (or any future database) instead of the filesystem. This enables:

- **Structured queries** across thousands of documents (find all overdue commitments, list all todos for an agent, get the update chain for a document)
- **Vector search** over document embeddings using pgvector, enabling semantic similarity queries ("find commitments similar to this one")
- **Full-text search** over document content using PostgreSQL tsvector + GIN indexes
- **JSONB queries** against document fields without extracting them into separate columns
- **Optimistic locking** via `jacsVersion` so multiple agents can work concurrently with database-level consistency
- **Runtime index generation** as a CLI tool that recommends (but does not automatically apply) database indexes based on document types in use
- **Storage migration tooling** to export documents from database to filesystem and vice versa, with cryptographic verification after migration

The filesystem remains the default. Database storage is entirely opt-in via feature flags and configuration.

---

## Architecture: Database Storage

### What We Want

A generic database storage trait that extends the existing `StorageDocumentTraits` with query capabilities that only a database can provide: type-based queries, field-based queries, text search, vector search, version history lookups, and domain-specific queries for commitments, todos, and updates.

### Why a Generic Trait

Different deployments use different databases. The reference implementation targets PostgreSQL (with pgvector for embeddings), but the trait itself is backend-agnostic. A future implementation could target SQLite for single-agent local use, DuckDB for analytics workloads, or a cloud-native database. The trait defines WHAT queries are available; each backend defines HOW they execute.

This mirrors the existing pattern: `StorageDocumentTraits` is implemented by both `MultiStorage` (filesystem/S3/HTTP) and `CachedMultiStorage` (with in-memory cache). `DatabaseDocumentTraits` extends this with richer query capabilities.

### The Trait Definition

The `DatabaseDocumentTraits` trait extends `StorageDocumentTraits`. It is defined in a new file `src/storage/database_traits.rs`:

```rust
pub trait DatabaseDocumentTraits: StorageDocumentTraits {
    fn query_by_type(&self, jacs_type: &str, limit: usize, offset: usize) -> Result<Vec<JACSDocument>, ...>;
    fn query_by_field(&self, field_path: &str, value: &str) -> Result<Vec<JACSDocument>, ...>;
    fn search_text(&self, query: &str, jacs_type: Option<&str>) -> Result<Vec<JACSDocument>, ...>;
    fn search_vector(&self, vector: &[f32], limit: usize) -> Result<Vec<(JACSDocument, f32)>, ...>;
    fn suggest_indexes(&self, document_types: &[&str]) -> Result<Vec<IndexRecommendation>, ...>;
    fn count_by_type(&self, jacs_type: &str) -> Result<usize, ...>;
    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, ...>;
    fn get_latest(&self, jacs_id: &str) -> Result<JACSDocument, ...>;
    fn query_updates_for_target(&self, target_id: &str) -> Result<Vec<JACSDocument>, ...>;
    fn query_commitments_by_status(&self, status: &str) -> Result<Vec<JACSDocument>, ...>;
    fn query_todos_for_agent(&self, agent_id: &str) -> Result<Vec<JACSDocument>, ...>;
    fn query_overdue_commitments(&self) -> Result<Vec<JACSDocument>, ...>;
}
```

**Key design notes on each method:**

| Method | Purpose |
|--------|---------|
| `query_by_type` | Paginated listing of all documents of a given `jacsType` (e.g., "commitment", "todo", "update") |
| `query_by_field` | JSONB path query -- find documents where a nested field matches a value (e.g., `$.jacsCommitmentStatus` = `"active"`) |
| `search_text` | Full-text search using PostgreSQL tsvector + GIN index, optionally scoped to a document type |
| `search_vector` | Cosine similarity search over embedding vectors (pgvector HNSW index), returns documents with similarity scores |
| `suggest_indexes` | Generates `IndexRecommendation` structs for the given document types -- does NOT create indexes |
| `count_by_type` | Fast count query for dashboard/status use cases |
| `get_versions` | All versions of a document ordered by `jacsVersionDate` |
| `get_latest` | Most recent version of a document by `jacsVersionDate` |
| `query_updates_for_target` | All Update documents targeting a given document ID, ordered by creation date |
| `query_commitments_by_status` | All commitments with a given status (e.g., "active", "disputed") |
| `query_todos_for_agent` | All todo lists owned by a specific agent |
| `query_overdue_commitments` | All commitments where `jacsCommitmentEndDate < NOW()` and status is not terminal |

### Sync Trait, Async Bridged Internally

The trait is synchronous, matching the existing `StorageDocumentTraits` pattern. The existing codebase uses `futures_executor::block_on()` in `MultiStorage` (see `jacs/src/storage/mod.rs:290`). The `DatabaseStorage` implementation uses `tokio::runtime::Handle::block_on()` instead, because sqlx requires a tokio runtime. The Handle is obtained from the ambient tokio runtime or created during `DatabaseStorage::new()`.

This means callers never deal with async. The database implementation manages the async bridge internally. This is a deliberate architectural choice: JACS is primarily used as a library embedded in other applications. Exposing async traits would force all consumers to be async, which is unacceptable for Python bindings (via PyO3), Go bindings (via CGo), and WASM targets.

### Concurrency Model

Only one active storage backend is used at a time per agent instance. When multiple agent instances (separate processes or threads) use the database backend concurrently, consistency is enforced at the database level:

- **Optimistic locking via `jacsVersion`**: Each document version has a unique UUID. When updating a document, the SQL uses `WHERE jacs_id = $1 AND jacs_version = $2` (the expected previous version). If another agent updated the document first, the WHERE clause matches zero rows and the update fails with a conflict error. The caller must re-read and retry.
- **No distributed locks**: JACS does not use `SELECT FOR UPDATE` or advisory locks. The version-based optimistic locking is sufficient because JACS documents are immutable once signed -- updates create new versions rather than modifying existing ones.

### Runtime Index Generator

The index generator is a CLI tool, NOT automatic indexing. The philosophy: databases in production are managed by DBAs or platform teams. JACS generates recommendations; humans review and apply them.

The CLI command `jacs db suggest-indexes` analyzes the document types in use and outputs SQL DDL statements. Example output:

```sql
-- Recommended indexes for document types: commitment, todo, update
-- Generated by: jacs db suggest-indexes --backend postgres --types commitment,todo,update

-- Type-based lookups (all document types)
CREATE INDEX idx_jacs_document_type ON jacs_document (jacs_type);

-- Commitment status queries
CREATE INDEX idx_jacs_commitment_status ON jacs_document
  USING GIN ((file_contents->'jacsCommitmentStatus'))
  WHERE jacs_type = 'commitment';

-- Overdue commitment detection
CREATE INDEX idx_jacs_commitment_end_date ON jacs_document
  USING BTREE ((file_contents->>'jacsCommitmentEndDate'))
  WHERE jacs_type = 'commitment';

-- Todo list ownership
CREATE INDEX idx_jacs_todo_agent ON jacs_document (agent_id)
  WHERE jacs_type = 'todo';

-- Update chain traversal
CREATE INDEX idx_jacs_update_target ON jacs_document
  USING GIN ((file_contents->'jacsUpdateTargetId'))
  WHERE jacs_type = 'update';

-- Full-text search (GIN index on tsvector)
CREATE INDEX idx_jacs_document_fts ON jacs_document
  USING GIN (to_tsvector('english', file_contents::text));

-- Vector similarity search (HNSW index, requires pgvector)
CREATE INDEX idx_jacs_document_embedding ON jacs_document
  USING hnsw (embedding vector_cosine_ops)
  WITH (m = 16, ef_construction = 64);
```

Each recommendation is returned as an `IndexRecommendation` struct containing the table, column expression, index type, optional WHERE condition, and the full SQL statement.

### Storage Backend Selection

The existing `StorageType` enum in `jacs/src/storage/mod.rs:149` is extended with a `Database` variant, cfg-gated behind the `database` feature:

```rust
#[derive(Debug, AsRefStr, Display, EnumString, Clone, PartialEq)]
pub enum StorageType {
    #[strum(serialize = "aws")]
    AWS,
    #[strum(serialize = "fs")]
    FS,
    #[strum(serialize = "hai")]
    HAI,
    #[strum(serialize = "memory")]
    Memory,
    #[cfg(target_arch = "wasm32")]
    #[strum(serialize = "local")]
    WebLocal,
    #[cfg(all(not(target_arch = "wasm32"), feature = "database"))]
    #[strum(serialize = "database")]
    Database,
}
```

A new `StorageBackend` enum wraps the routing decision:

```rust
pub enum StorageBackend {
    ObjectStore(MultiStorage),
    Database(Arc<DatabaseStorage>),
}
```

All document operations route through `StorageDocumentTraits`. When the backend is `Database`, the `DatabaseStorage` impl handles storage. When the backend is `ObjectStore`, the existing `MultiStorage` impl handles storage. The `StorageBackend` enum implements `StorageDocumentTraits` by delegating to the active variant.

### Configuration

Two environment variables control database storage, following JACS's existing 12-Factor App pattern (defaults -> config file -> env vars):

- `JACS_DEFAULT_STORAGE=database` -- selects the database backend (default remains `fs`)
- `JACS_DATABASE_URL=postgres://user:password@host:5432/jacs` -- PostgreSQL connection string

Additional optional pool configuration:

- `JACS_DATABASE_MAX_CONNECTIONS=10` -- maximum pool size
- `JACS_DATABASE_MIN_CONNECTIONS=1` -- minimum pool size
- `JACS_DATABASE_CONNECT_TIMEOUT_SECS=30` -- connection timeout

These are added to the existing Config struct in `jacs/src/config/mod.rs` and to `jacs.config.schema.json`.

### Keys Always From Filesystem

Even when documents are stored in a database, cryptographic keys and `agent.json` are ALWAYS loaded from the filesystem (or keyservers). Keys are never stored in the database. This is Architectural Decision 11 from the parent plan. The rationale: databases are shared infrastructure with many access paths. Keys require the security properties of a filesystem with proper permissions, or a dedicated key management system.

---

## Phase 2A: Generic Database Trait (Steps 96-115)

**Step 96.** Write test `test_database_document_traits_definition` -- trait is object-safe and can be used as `dyn DatabaseDocumentTraits`.
- **Why**: The trait must be object-safe so it can be used as a trait object (`Box<dyn DatabaseDocumentTraits>`). If any method uses generics, `Self` by value, or other non-object-safe patterns, this test catches it at compile time. Object safety is essential for the `StorageBackend` enum to hold any implementation.
- **What**: Define a function that accepts `&dyn DatabaseDocumentTraits` and call it with a mock. The test passes if the code compiles. Also verify the trait is a supertrait of `StorageDocumentTraits` by confirming that `store_document()` and `get_document()` are callable through the `dyn DatabaseDocumentTraits` reference.
- **Where**: `jacs/tests/database_trait_tests.rs`. Follow the pattern in `jacs/tests/` where each test file is a standalone integration test. Gate with `#[cfg(feature = "database")]`.

**Step 97.** Define `DatabaseDocumentTraits` trait in `src/storage/database_traits.rs`.
- **Why**: This is the core abstraction that enables pluggable database backends. It must be defined before any implementation.
- **What**: Create `jacs/src/storage/database_traits.rs` containing: (1) the `DatabaseDocumentTraits` trait as shown in the Architecture section above, (2) the `IndexRecommendation` struct with fields `table: String`, `column_expr: String`, `index_type: String` (e.g., "btree", "gin", "hnsw"), `condition: Option<String>` (partial index WHERE clause), `sql: String` (full DDL statement), and (3) any associated error type aliases. All methods return `Result<..., Box<dyn Error>>` to match `StorageDocumentTraits`.
- **Where**: New file `jacs/src/storage/database_traits.rs`. The module declaration goes in `src/storage/mod.rs` (Step 109).

**Step 98.** Write test `test_database_document_traits_with_mock` -- mock implementation validates trait contract.
- **Why**: Before building the real PostgreSQL implementation, a mock proves the trait contract is implementable and tests can exercise every method. This validates the API design before committing to it.
- **What**: Create `MockDatabaseStorage` struct that stores documents in a `HashMap<String, JACSDocument>`. Implement `StorageDocumentTraits` (store/get/remove/list/exists using the HashMap) and `DatabaseDocumentTraits` (query methods filter the HashMap in memory). Test that: (1) storing a document and retrieving it by type works, (2) `count_by_type` returns correct counts, (3) `get_versions` returns all versions of a document, (4) `query_commitments_by_status` filters correctly, (5) `suggest_indexes` returns non-empty recommendations for known types.
- **Where**: `jacs/tests/database_trait_tests.rs`, in a submodule `mod mock_tests`.

**Step 99.** Add `DatabaseError { operation: String, reason: String }` and `StorageError(String)` to `JacsError` enum.
- **Why**: Database operations can fail in ways distinct from IO or document errors (connection pool exhausted, query timeout, constraint violation, migration failure). Having dedicated error variants enables callers to match on database-specific failures. `StorageError` is the generic storage category; `DatabaseError` carries the specific operation that failed.
- **What**: Add two new variants to the `JacsError` enum in `jacs/src/error.rs`: (1) `StorageError(String)` for generic storage failures, (2) `DatabaseError { operation: String, reason: String }` for database-specific failures. Add corresponding `Display` implementations: `StorageError` displays as `"Storage error: {msg}"`, `DatabaseError` displays as `"Database error during '{operation}': {reason}"`. Add `From<sqlx::Error>` impl (cfg-gated) that converts to `DatabaseError { operation: "query".into(), reason: err.to_string() }`.
- **Where**: `jacs/src/error.rs`. Add variants in the "SPECIFIC ERROR VARIANTS" section after the existing `RegistrationFailed` variant.

**Step 100.** Write test `test_jacs_error_send_sync` -- verify JacsError remains Send + Sync.
- **Why**: `JacsError` is currently `Send + Sync` (verified by existing test `test_error_is_send_sync` in `jacs/src/error.rs:662`). The new `DatabaseError` and `StorageError` variants must not break this. If either variant contained a non-Send type (e.g., `Rc<T>`), it would break thread safety for all error handling in the crate.
- **What**: Compile-time assertion: `fn assert_send_sync<T: Send + Sync>() {}; assert_send_sync::<JacsError>();`. Also test the new variants specifically: create a `DatabaseError`, send it across a thread via `std::thread::spawn`, verify it arrives intact.
- **Where**: `jacs/src/error.rs` in the existing `mod tests` block, or `jacs/tests/database_trait_tests.rs`.

**Step 101.** Add `StorageType::Database` variant (cfg-gated).
- **Why**: The `StorageType` enum drives backend selection in `MultiStorage::_new()`. Adding a `Database` variant allows the configuration system to select database storage via `JACS_DEFAULT_STORAGE=database`.
- **What**: Add `#[cfg(all(not(target_arch = "wasm32"), feature = "database"))] #[strum(serialize = "database")] Database` variant to the `StorageType` enum in `jacs/src/storage/mod.rs:149`. The double cfg-gate excludes it from WASM builds (no database in browser) and from builds without the `database` feature flag.
- **Where**: `jacs/src/storage/mod.rs`, in the `StorageType` enum definition.

**Step 102.** Add sqlx optional dep in `Cargo.toml` under wasm32-excluded section.
- **Why**: sqlx is the async PostgreSQL driver. It must be optional (not everyone needs database support) and excluded from WASM targets (sqlx uses tokio which does not compile for wasm32).
- **What**: Add to `jacs/Cargo.toml`: `sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "postgres", "json", "uuid", "chrono"], optional = true }`. Place it in the existing section with other optional dependencies. Verify it compiles on native targets and that `cargo check --target wasm32-unknown-unknown` still passes without the feature.
- **Where**: `jacs/Cargo.toml`, in the `[dependencies]` section.

**Step 103.** Add pgvector optional dep, define feature flags: `database = ["dep:sqlx", "dep:tokio"]`, `database-vector = ["database", "dep:pgvector"]`.
- **Why**: Vector search is a separate concern from basic database storage. Some deployments may use PostgreSQL without pgvector installed. The two-tier feature flag lets users opt into basic database support or full vector support.
- **What**: Add to `jacs/Cargo.toml`: (1) `pgvector = { version = "0.4", optional = true, features = ["sqlx"] }` in dependencies, (2) `database = ["dep:sqlx", "dep:tokio"]` in `[features]`, (3) `database-vector = ["database", "dep:pgvector"]` in `[features]`, (4) `database-tests = ["database"]` in `[features]` for integration test gating. Also add `tokio = { version = "1", features = ["rt-multi-thread", "macros"], optional = true }` if not already present (it is at line 99 as optional).
- **Where**: `jacs/Cargo.toml`, in `[dependencies]` and `[features]` sections.

**Step 104.** Create `src/storage/database.rs` -- `DatabaseStorage` struct with `PgPool` + `tokio::runtime::Handle`.
- **Why**: This is the core struct that holds the database connection pool and the tokio runtime handle for async bridging. All database operations go through this struct.
- **What**: Create `jacs/src/storage/database.rs` containing: (1) `pub struct DatabaseStorage { pool: PgPool, handle: tokio::runtime::Handle }`, (2) `DatabaseStorage::new(database_url: &str) -> Result<Self, JacsError>` that creates a `PgPool` from the URL and obtains or creates a tokio Handle, (3) `DatabaseStorage::with_pool(pool: PgPool, handle: Handle) -> Self` for testing with pre-configured pools, (4) helper method `fn block_on<F: Future>(&self, f: F) -> F::Output` that calls `self.handle.block_on(f)`. Gate the entire file with `#[cfg(all(not(target_arch = "wasm32"), feature = "database"))]`.
- **Where**: New file `jacs/src/storage/database.rs`.

**Step 105.** Define SQL migration: `jacs_document` table (jacs_id UUID, jacs_version UUID, agent_id UUID, jacs_type TEXT, file_contents JSONB, timestamps, PK on jacs_id+jacs_version).
- **Why**: The `jacs_document` table is the single table that stores all JACS document types. Using JSONB for the full document content means we do not need separate tables per document type. The composite primary key `(jacs_id, jacs_version)` mirrors JACS's versioning model where each document version is immutable.
- **What**: Create SQL migration file `jacs/migrations/001_create_jacs_document.sql` containing: `CREATE TABLE jacs_document (jacs_id UUID NOT NULL, jacs_version UUID NOT NULL, agent_id UUID, jacs_type TEXT NOT NULL, file_contents JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (jacs_id, jacs_version))`. Add basic indexes: `CREATE INDEX idx_jacs_document_type ON jacs_document (jacs_type)`, `CREATE INDEX idx_jacs_document_agent ON jacs_document (agent_id)`. Add a migration runner method to `DatabaseStorage`: `pub fn run_migrations(&self) -> Result<(), JacsError>`.
- **Where**: New file `jacs/migrations/001_create_jacs_document.sql` and migration runner in `jacs/src/storage/database.rs`.

**Step 106.** Define vector migration (behind `database-vector`): vector column + HNSW index.
- **Why**: Vector search requires a dedicated column with a specific data type (`vector(1536)` for OpenAI-compatible embeddings) and an HNSW index for efficient approximate nearest neighbor search.
- **What**: Create migration file `jacs/migrations/002_add_vector_column.sql` containing: `ALTER TABLE jacs_document ADD COLUMN embedding vector(1536)` and `CREATE INDEX idx_jacs_document_embedding ON jacs_document USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)`. The dimension 1536 matches OpenAI's text-embedding-ada-002; a configuration option allows different dimensions. Gate the migration behind a runtime check for the pgvector extension.
- **Where**: New file `jacs/migrations/002_add_vector_column.sql`.

**Step 107.** Implement `StorageDocumentTraits` for `DatabaseStorage`: store, get, remove, list, exists, get_by_agent, get_versions, get_latest. Convert `sqlx::Error` to `JacsError::DatabaseError { operation, reason }` at boundary.
- **Why**: `DatabaseStorage` must implement the base `StorageDocumentTraits` before it can implement `DatabaseDocumentTraits` (which is a supertrait). This enables `DatabaseStorage` to be used anywhere the existing `MultiStorage` is used.
- **What**: Implement all 12 methods of `StorageDocumentTraits` in `jacs/src/storage/database.rs`. Key implementation details: (1) `store_document` serializes `JACSDocument.value` to JSONB and INSERTs with `ON CONFLICT DO NOTHING` (immutable versions), (2) `get_document` SELECTs by composite key `jacs_id:jacs_version` parsed from the key string, (3) `remove_document` moves to an `archive` schema or marks as deleted (soft delete), (4) `list_documents` queries by prefix/type, (5) `document_exists` uses `SELECT 1 ... LIMIT 1`. Every sqlx error is converted at the boundary: `sqlx::Error` -> `JacsError::DatabaseError { operation: "store".into(), reason: e.to_string() }`. No sqlx types leak across the public API.
- **Where**: `jacs/src/storage/database.rs`, `impl StorageDocumentTraits for DatabaseStorage` block.

**Step 108.** Implement `DatabaseDocumentTraits` for `DatabaseStorage`: query_by_type, query_by_field, search_text, count_by_type, query_updates_for_target, query_commitments_by_status, query_todos_for_agent, query_overdue_commitments.
- **Why**: These are the database-specific query methods that justify having a database backend. Filesystem storage cannot efficiently support these queries.
- **What**: Implement all 12 methods of `DatabaseDocumentTraits`. Key SQL patterns: (1) `query_by_type` uses `WHERE jacs_type = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, (2) `query_by_field` uses `WHERE file_contents @> jsonb_build_object($1, $2)` for JSONB containment, (3) `search_text` uses `WHERE to_tsvector('english', file_contents::text) @@ plainto_tsquery('english', $1)`, (4) `query_overdue_commitments` uses `WHERE jacs_type = 'commitment' AND (file_contents->>'jacsCommitmentEndDate')::timestamptz < NOW() AND file_contents->>'jacsCommitmentStatus' NOT IN ('completed', 'failed', 'revoked')`. Each method deserializes JSONB back to `JACSDocument` using the same field extraction pattern as `MultiStorage::get_document`.
- **Where**: `jacs/src/storage/database.rs`, `impl DatabaseDocumentTraits for DatabaseStorage` block.

**Step 109.** Add `pub mod database;` and `pub mod database_traits;` to `src/storage/mod.rs` (cfg-gated).
- **Why**: Module declarations wire the new files into the crate's module tree. Without this, the new code is unreachable.
- **What**: Add two lines to `jacs/src/storage/mod.rs` after the existing `pub mod jenv;` declaration: `#[cfg(all(not(target_arch = "wasm32"), feature = "database"))] pub mod database;` and `#[cfg(all(not(target_arch = "wasm32"), feature = "database"))] pub mod database_traits;`. Also add re-exports: `#[cfg(all(not(target_arch = "wasm32"), feature = "database"))] pub use database::DatabaseStorage;` and `#[cfg(all(not(target_arch = "wasm32"), feature = "database"))] pub use database_traits::{DatabaseDocumentTraits, IndexRecommendation};`.
- **Where**: `jacs/src/storage/mod.rs`, near line 22.

**Step 110.** Write integration test `test_database_storage_new_connection` (feature-gated + testcontainers).
- **Why**: Validates that `DatabaseStorage::new()` can connect to a real PostgreSQL instance and that the connection pool is healthy. This is the first test that requires a running database.
- **What**: Use `testcontainers` crate to spin up a PostgreSQL container. Create `DatabaseStorage::new(container_url)`. Assert the pool is connected by calling a simple query (`SELECT 1`). Verify the pool respects configured max connections. Test with an invalid URL and verify it returns `JacsError::DatabaseError`.
- **Where**: `jacs/tests/database_integration_tests.rs`. Gate with `#[cfg(all(feature = "database", feature = "database-tests"))]`. Use `testcontainers::GenericImage` for `postgres:16-alpine`.

**Step 111.** Write test `test_database_storage_migration`.
- **Why**: Validates that the SQL migration creates the `jacs_document` table with the correct schema.
- **What**: Connect to test database, run migrations, verify: (1) `jacs_document` table exists, (2) columns `jacs_id`, `jacs_version`, `agent_id`, `jacs_type`, `file_contents`, `created_at`, `updated_at` exist with correct types, (3) primary key is `(jacs_id, jacs_version)`, (4) running migrations a second time is idempotent (no error).
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 112.** Write test `test_database_store_and_retrieve`.
- **Why**: End-to-end validation that a `JACSDocument` can survive the store -> JSONB serialization -> retrieval -> deserialization round trip with all fields intact. This is the most critical test: if JSONB serialization loses or modifies any field, signature verification will fail.
- **What**: Create a `JACSDocument` with known values (id, version, jacs_type, value with nested JSON). Store it via `store_document()`. Retrieve it via `get_document()`. Assert field-by-field equality. Crucially, assert that `doc.value` (the full JSON) is byte-for-byte equivalent after deserialization, because JACS signatures depend on exact JSON content.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 113.** Write test `test_database_list_by_type`.
- **Why**: Validates the `query_by_type` method, which is the most commonly used database query (e.g., "list all commitments", "list all todos").
- **What**: Store 5 commitments, 3 todos, and 2 updates. Call `query_by_type("commitment", 10, 0)` and assert 5 results. Call `query_by_type("todo", 10, 0)` and assert 3. Call `query_by_type("commitment", 2, 0)` and assert 2 (limit). Call `query_by_type("commitment", 2, 3)` and assert 2 (offset). Call `query_by_type("nonexistent", 10, 0)` and assert 0.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 114.** Write test `test_database_query_updates_for_target` -- retrieve update chain from DB.
- **Why**: Update chains are how JACS tracks the semantic history of a document. Given a commitment ID, you need to find all updates that target it, in chronological order.
- **What**: Create a commitment document (target). Create 3 update documents, each with `jacsUpdateTargetId` pointing to the commitment's `jacsId`. Store all 4. Call `query_updates_for_target(commitment_id)`. Assert: (1) exactly 3 results returned, (2) results are ordered by `jacsVersionDate` ascending, (3) each result has `jacsType = "update"`, (4) each result's `jacsUpdateTargetId` matches the commitment ID.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 115.** Write test `test_database_query_commitments_by_status`.
- **Why**: Querying commitments by status is a primary use case for mediation and dashboard views. An agent needs to see all "disputed" commitments, or all "active" commitments.
- **What**: Store 3 commitments with status "active", 2 with "pending", 1 with "disputed". Call `query_commitments_by_status("active")` and assert 3. Call `query_commitments_by_status("disputed")` and assert 1. Call `query_commitments_by_status("completed")` and assert 0.
- **Where**: `jacs/tests/database_integration_tests.rs`.

---

## Phase 2B: Vector Search (Steps 116-130)

**Step 116.** Write test `test_database_vector_storage`.
- **Why**: Validates that a document with an embedding vector can be stored and the vector column is populated correctly.
- **What**: Create a `JACSDocument` with a `jacsEmbedding` field containing a 1536-dimensional float vector. Store it. Query the raw `embedding` column in the database and verify it matches the input vector (within floating-point tolerance).
- **Where**: `jacs/tests/database_vector_tests.rs`. Gate with `#[cfg(all(feature = "database-vector", feature = "database-tests"))]`.

**Step 117.** Write test `test_database_vector_search` (cosine similarity).
- **Why**: Validates that `search_vector` returns documents ranked by cosine similarity to the query vector.
- **What**: Store 5 documents with different embedding vectors. Create a query vector that is very similar to document #3. Call `search_vector(query_vec, 3)`. Assert: (1) document #3 is the first result, (2) exactly 3 results returned, (3) similarity scores are in descending order, (4) similarity scores are between 0.0 and 1.0.
- **Where**: `jacs/tests/database_vector_tests.rs`.

**Step 118.** Add vector storage/search methods to `DatabaseStorage`.
- **Why**: Implements the `search_vector` method and the internal logic for storing embedding vectors alongside documents.
- **What**: Add to `DatabaseStorage`: (1) `store_vector(jacs_id: &str, jacs_version: &str, vector: &[f32]) -> Result<(), JacsError>` that UPDATE-s the `embedding` column, (2) modify `store_document` to automatically extract and store the embedding if `jacsEmbedding` is present in the document, (3) implement `search_vector` using `SELECT *, embedding <=> $1::vector AS distance FROM jacs_document ORDER BY distance LIMIT $2`. Gate with `#[cfg(feature = "database-vector")]`.
- **Where**: `jacs/src/storage/database.rs`.

**Step 119.** Write test `test_vector_search_by_type`.
- **Why**: Vector search should be filterable by document type. You want "find commitments similar to X" not "find any document similar to X".
- **What**: Store commitments and todos with embeddings. Search with a type filter. Assert only commitments are returned.
- **Where**: `jacs/tests/database_vector_tests.rs`.

**Step 120.** Write test `test_vector_search_ranking`.
- **Why**: Validates that documents with more similar embeddings rank higher than dissimilar ones.
- **What**: Create 3 documents with embeddings at known angles. Query with a vector identical to document A. Assert A ranks first, then the next-closest, then the farthest. Verify the similarity scores reflect the expected cosine distances.
- **Where**: `jacs/tests/database_vector_tests.rs`.

**Step 121.** Add `extract_embedding_vector()` utility.
- **Why**: Documents carry embeddings in the `jacsEmbedding` field (from header.schema.json). This utility extracts the float vector from the JSON structure for storage in the pgvector column.
- **What**: Create `pub fn extract_embedding_vector(doc: &JACSDocument) -> Option<Vec<f32>>` that reads `doc.value["jacsEmbedding"]["jacsEmbeddingVector"]` and parses it as `Vec<f32>`. Return `None` if the field is absent or unparseable.
- **Where**: `jacs/src/storage/database.rs` or a new `jacs/src/storage/embedding_utils.rs`.

**Step 122.** Write test `test_extract_embedding_from_document`.
- **Why**: The extraction utility must handle all edge cases: present with valid data, present with wrong type, absent entirely.
- **What**: Test with: (1) document with valid embedding -- returns `Some(vec)` with correct values, (2) document without `jacsEmbedding` -- returns `None`, (3) document with `jacsEmbedding` but no `jacsEmbeddingVector` -- returns `None`, (4) document with malformed vector data -- returns `None`.
- **Where**: `jacs/tests/database_vector_tests.rs`.

**Step 123.** Auto-extract embeddings on store.
- **Why**: When a document with an embedding is stored, the vector should automatically be extracted and stored in the `embedding` column without requiring the caller to do it manually.
- **What**: Modify `DatabaseStorage::store_document()` (the `StorageDocumentTraits` impl) to call `extract_embedding_vector()` after the INSERT and, if a vector is found, UPDATE the `embedding` column. This is done in a single transaction.
- **Where**: `jacs/src/storage/database.rs`, in the `store_document` method.

**Step 124.** Write test `test_auto_vector_extraction_on_store`.
- **Why**: Validates the automatic extraction behavior from Step 123.
- **What**: Store a document with a `jacsEmbedding` field. Without calling any vector-specific method, query the `embedding` column directly and verify it is populated. Store a document WITHOUT `jacsEmbedding` and verify the `embedding` column is NULL.
- **Where**: `jacs/tests/database_vector_tests.rs`.

**Step 125.** Add JSONB query methods: `query_documents_jsonb()`.
- **Why**: JSONB containment queries (`@>`) and path queries (`->`, `->>`) allow filtering documents by any nested field without predefined indexes. This is the general-purpose query method.
- **What**: Add `pub fn query_documents_jsonb(&self, jsonb_filter: &Value, jacs_type: Option<&str>, limit: usize, offset: usize) -> Result<Vec<JACSDocument>, Box<dyn Error>>` to `DatabaseStorage`. Uses `WHERE file_contents @> $1::jsonb` with optional type filter. Also implement `query_by_field` in terms of this method.
- **Where**: `jacs/src/storage/database.rs`.

**Step 126.** Write test `test_jsonb_query_commitment_status`.
- **Why**: Validates JSONB containment query for the most common use case: filtering commitments by status.
- **What**: Store commitments with various statuses. Query with `{"jacsCommitmentStatus": "active"}`. Assert only active commitments returned.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 127.** Write test `test_jsonb_query_commitments_by_date_range`.
- **Why**: Date range queries are essential for finding overdue commitments or upcoming deadlines.
- **What**: Store commitments with various end dates. Query using the JSONB path operator and date comparison. Assert correct filtering.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 128.** Add pagination (offset/limit).
- **Why**: All list/query methods must support pagination to handle large result sets without loading everything into memory.
- **What**: Verify that all `query_*` methods in `DatabaseDocumentTraits` accept `limit` and `offset` parameters where appropriate. Add pagination to methods that currently lack it. Ensure consistent ordering (by `created_at DESC` unless otherwise specified) so pagination is deterministic.
- **Where**: `jacs/src/storage/database.rs` and `jacs/src/storage/database_traits.rs`.

**Step 129.** Write test `test_paginated_query`.
- **Why**: Validates that pagination produces correct, non-overlapping result pages.
- **What**: Store 25 documents of the same type. Query page 1 (limit=10, offset=0), page 2 (limit=10, offset=10), page 3 (limit=10, offset=20). Assert: page 1 has 10 results, page 2 has 10, page 3 has 5. Assert no document appears in multiple pages. Assert total across all pages equals 25.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 130.** Run full vector search integration suite.
- **Why**: Integration checkpoint. All vector search tests must pass together, validating the complete vector pipeline: store with embedding -> auto-extract -> search -> rank.
- **What**: Run `cargo test --features database-vector,database-tests`. All tests in `database_vector_tests.rs` must pass. Verify no regressions in non-vector database tests.
- **Where**: CI command, not a code file.

---

## Phase 2C: MultiStorage Integration (Steps 131-150)

**Step 131.** Write test `test_multi_storage_with_database`.
- **Why**: Validates that the existing `MultiStorage` infrastructure can route to the database backend.
- **What**: Create a `MultiStorage` with `StorageType::Database`. Store a document. Retrieve it. Assert equality. This test proves the integration point between the existing storage routing and the new database backend.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 132.** Modify `MultiStorage::_new()` for `StorageType::Database`.
- **Why**: The `MultiStorage::_new()` method (at `jacs/src/storage/mod.rs:188`) initializes storage backends based on `StorageType`. It needs a new branch for `Database`.
- **What**: Add a `StorageType::Database` match arm that reads `JACS_DATABASE_URL` from the environment, creates a `DatabaseStorage`, and stores it in the `MultiStorage` struct. The `DatabaseStorage` is wrapped in `Arc` for thread safety.
- **Where**: `jacs/src/storage/mod.rs`, in the `_new()` method.

**Step 133.** Add `database: Option<Arc<DatabaseStorage>>` to `MultiStorage` (cfg-gated).
- **Why**: `MultiStorage` needs to hold a reference to the `DatabaseStorage` for routing document operations.
- **What**: Add `#[cfg(all(not(target_arch = "wasm32"), feature = "database"))] database: Option<Arc<DatabaseStorage>>` field to the `MultiStorage` struct at `jacs/src/storage/mod.rs:137`. Initialize it in `_new()`. Add it to the struct constructor in `Ok(Self { ... })`.
- **Where**: `jacs/src/storage/mod.rs`, `MultiStorage` struct definition.

**Step 134.** Create `StorageBackend` enum: `ObjectStore(MultiStorage) | Database(Arc<DatabaseStorage>)`.
- **Why**: Higher-level code (the `Schema` struct, agent operations) needs a single type that can be either filesystem or database storage. The `StorageBackend` enum provides this.
- **What**: Define `pub enum StorageBackend { ObjectStore(MultiStorage), #[cfg(all(not(target_arch = "wasm32"), feature = "database"))] Database(Arc<DatabaseStorage>) }` in `jacs/src/storage/mod.rs`. Implement `StorageDocumentTraits` for `StorageBackend` by delegating to the active variant.
- **Where**: `jacs/src/storage/mod.rs`, after the `StorageType` enum.

**Step 135.** Route document operations through `StorageDocumentTraits` for database backend.
- **Why**: All existing document operations (create, sign, verify, update) must work identically regardless of whether the backend is filesystem or database.
- **What**: Audit all call sites that use `MultiStorage` directly. Replace with `StorageBackend` or `dyn StorageDocumentTraits` where needed. Key locations: `Schema` struct methods in `src/schema/mod.rs`, agent document operations in `src/agent/`, and CRUD modules.
- **Where**: `jacs/src/schema/mod.rs`, `jacs/src/agent/`, various CRUD files.

**Step 136.** Write test `test_database_backed_document_create`.
- **Why**: Validates that the full document creation flow (create -> validate schema -> assign header fields -> sign -> store) works with the database backend.
- **What**: Using the database backend, create a commitment document via `create_minimal_commitment()`, pass it through schema validation, sign it, store it. Retrieve it. Verify the document is valid and all header fields are populated.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 137.** Write test `test_database_backed_document_update`.
- **Why**: Validates that document updates (create new version with `jacsPreviousVersion` chain) work correctly with database storage.
- **What**: Create and store a commitment. Update its status by creating a new version. Store the new version. Call `get_versions(commitment_id)` and assert 2 versions exist. Call `get_latest(commitment_id)` and assert it returns the updated version.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 138.** Write test `test_database_backed_document_verify` -- signature survives JSONB round-trip.
- **Why**: This is the critical correctness test for database storage. PostgreSQL JSONB normalizes JSON (sorts keys, removes extra whitespace). If the original JSON was signed with a specific byte order, JSONB normalization could change the hash and break verification. JACS must handle this correctly.
- **What**: Create a document with known JSON content. Sign it. Store in database. Retrieve from database. Verify the signature. The test MUST pass, proving that either: (a) JACS signs a canonical form that is invariant to JSONB normalization, or (b) the raw JSON string is preserved alongside the JSONB (using a TEXT column or JSONB with explicit ordering). If this test fails, it reveals a fundamental incompatibility that must be resolved before database storage can ship.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 139.** Implement `CachedMultiStorage` support for database.
- **Why**: `CachedMultiStorage` wraps `MultiStorage` with an in-memory cache. It should also work with the database backend, caching frequently accessed documents to reduce database round trips.
- **What**: Modify `CachedMultiStorage` to work with `StorageBackend` instead of just `MultiStorage`. When the backend is `Database`, the cache still operates the same way: check cache first, fall back to database on miss, update cache on store.
- **Where**: `jacs/src/storage/mod.rs`, `CachedMultiStorage` struct and impls.

**Step 140.** Write test `test_cached_database_storage`.
- **Why**: Validates that caching works correctly with the database backend.
- **What**: Create a `CachedMultiStorage` with database backend. Store a document. Retrieve it (populates cache). Retrieve it again (served from cache -- verify by checking that no additional database query was issued, or by timing). Clear cache. Retrieve again (should hit database).
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 141.** Add `JACS_DATABASE_URL` to Config struct + env var loading.
- **Why**: The Config struct in `jacs/src/config/mod.rs` handles all JACS configuration. Database URL must be part of this system.
- **What**: Add `pub database_url: Option<String>` to the Config struct. Load from: (1) config file field `"databaseUrl"`, (2) env var `JACS_DATABASE_URL` (overrides config file), (3) default `None`. When `JACS_DEFAULT_STORAGE=database` is set but `JACS_DATABASE_URL` is not, return `JacsError::ConfigError("JACS_DATABASE_URL is required when JACS_DEFAULT_STORAGE=database")`.
- **Where**: `jacs/src/config/mod.rs`.

**Step 142.** Update `jacs.config.schema.json`.
- **Why**: The config schema must document the new database fields for validation and documentation.
- **What**: Add to `jacs.config.schema.json`: `"databaseUrl"` (string, format: "uri"), `"databaseMaxConnections"` (integer, default: 10, minimum: 1), `"databaseMinConnections"` (integer, default: 1, minimum: 0), `"databaseConnectTimeoutSecs"` (integer, default: 30, minimum: 1). Add `"database"` to the `"defaultStorage"` enum values.
- **Where**: `jacs/schemas/jacs.config.schema.json`.

**Step 143.** Write test `test_config_database_url`.
- **Why**: Validates that the database URL is correctly loaded from config file.
- **What**: Create a config file with `"databaseUrl": "postgres://localhost/jacs_test"`. Load config. Assert `config.database_url == Some("postgres://localhost/jacs_test")`.
- **Where**: `jacs/tests/config_tests.rs` or `jacs/src/config/mod.rs` test module.

**Step 144.** Write test `test_config_database_url_env_override`.
- **Why**: Environment variables must override config file values (12-Factor App principle).
- **What**: Create config file with `"databaseUrl": "postgres://from-config/jacs"`. Set env var `JACS_DATABASE_URL=postgres://from-env/jacs`. Load config. Assert `config.database_url == Some("postgres://from-env/jacs")`.
- **Where**: `jacs/tests/config_tests.rs`.

**Step 145.** Add pool config: `JACS_DATABASE_MAX_CONNECTIONS`, `JACS_DATABASE_MIN_CONNECTIONS`, `JACS_DATABASE_CONNECT_TIMEOUT_SECS`.
- **Why**: Connection pool tuning is essential for production deployments. Defaults are reasonable but must be overridable.
- **What**: Add three fields to Config: `database_max_connections: Option<u32>` (default 10), `database_min_connections: Option<u32>` (default 1), `database_connect_timeout_secs: Option<u64>` (default 30). Load from env vars. Pass to `PgPoolOptions` in `DatabaseStorage::new()`.
- **Where**: `jacs/src/config/mod.rs` and `jacs/src/storage/database.rs`.

**Step 146.** Write test `test_database_pool_configuration`.
- **Why**: Validates that pool settings from config/env are actually applied to the database connection pool.
- **What**: Set `JACS_DATABASE_MAX_CONNECTIONS=5`. Create `DatabaseStorage`. Verify the pool's max size is 5 (via `pool.options().max_connections()`).
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 147.** Write test `test_optimistic_locking_on_concurrent_update` -- two agents update same doc, one fails.
- **Why**: Validates the concurrency model. When two agents attempt to create a new version of the same document simultaneously, only one should succeed if they both reference the same previous version.
- **What**: Store document version V1. Spawn two threads. Both read V1 and attempt to store V2 with `jacsPreviousVersion = V1.jacsVersion`. One succeeds, one gets a conflict error (either a unique constraint violation on the composite key if they generate the same version UUID -- unlikely -- or the application-level check that `jacsPreviousVersion` matches the actual latest). Assert exactly one success and one failure.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 148.** Storage migration tooling: `export_to_filesystem()`, `import_from_filesystem()`.
- **Why**: Users need to move between storage backends. A deployment might start with filesystem and migrate to database, or export from database for backup/audit.
- **What**: Add to `DatabaseStorage`: (1) `pub fn export_to_filesystem(&self, fs_storage: &MultiStorage, jacs_type: Option<&str>) -> Result<usize, JacsError>` that queries all documents (optionally filtered by type) and stores each one via `fs_storage.store_document()`. Returns count exported. (2) `pub fn import_from_filesystem(&self, fs_storage: &MultiStorage) -> Result<usize, JacsError>` that lists all documents in filesystem storage and stores each via `self.store_document()`. Returns count imported.
- **Where**: `jacs/src/storage/database.rs`.

**Step 149.** Write test `test_documents_verifiable_after_migration`.
- **Why**: The most important migration property: documents must remain cryptographically verifiable after export/import. If migration corrupts JSON in any way, signatures break.
- **What**: Create 5 signed documents in database storage. Export to filesystem. For each exported document, load from filesystem, verify signature. Import the same documents back to a fresh database. For each imported document, load from database, verify signature. All 10 verifications must pass.
- **Where**: `jacs/tests/database_integration_tests.rs`.

**Step 150.** Add CI: `cargo check --target wasm32-unknown-unknown`.
- **Why**: The database feature must not break WASM compilation. All database code is behind `#[cfg(not(target_arch = "wasm32"))]` but a single leaked import or missing cfg-gate would break WASM builds.
- **What**: Add to CI pipeline: `cargo check --target wasm32-unknown-unknown` (no features -- base compilation). Also `cargo check --target wasm32-unknown-unknown --features "..."` with all non-database features to verify no regression.
- **Where**: CI configuration file (e.g., `.github/workflows/ci.yml`).

---

## Phase 2D: Domain Queries & Index Generator (Steps 151-175)

**Step 151.** Write test `test_domain_query_commitments_by_status`.
- **Why**: End-to-end test for the commitment status query in the context of the full document lifecycle (create -> sign -> store -> query).
- **What**: Create and store signed commitments with statuses: 3 "active", 2 "pending", 1 "completed", 1 "disputed". Query each status. Assert counts match. Verify all returned documents are valid signed documents.
- **Where**: `jacs/tests/database_domain_tests.rs`.

**Step 152.** Write test `test_domain_query_todos_for_agent`.
- **Why**: Todo lists are private to an agent. The query must filter by `agent_id` and return only todos owned by that agent.
- **What**: Create todos for agent A (3 lists) and agent B (2 lists). Query for agent A. Assert 3 results. Query for agent B. Assert 2 results. Query for nonexistent agent C. Assert 0 results.
- **Where**: `jacs/tests/database_domain_tests.rs`.

**Step 153.** Write test `test_domain_query_updates_for_target`.
- **Why**: The update chain is how JACS tracks semantic history. This test validates the chain retrieval in order.
- **What**: Create a commitment. Create 5 updates targeting it, each with a different `jacsUpdateAction` (e.g., "status_change", "modify", "progress_update", "reassign", "complete"). Query updates for the commitment. Assert 5 results in chronological order. Assert each update's `jacsUpdateAction` matches what was stored.
- **Where**: `jacs/tests/database_domain_tests.rs`.

**Step 154.** Write test `test_domain_query_overdue_commitments`.
- **Why**: Overdue commitment detection is a critical operational query for any agent system. Agents need to know what they have failed to deliver.
- **What**: Create commitments: 2 with `jacsCommitmentEndDate` in the past and status "active" (overdue), 1 with end date in the past and status "completed" (not overdue -- already done), 1 with end date in the future and status "active" (not overdue yet). Query overdue. Assert exactly 2 results. Assert both have past end dates and non-terminal statuses.
- **Where**: `jacs/tests/database_domain_tests.rs`.

**Step 155.** Domain-specific query methods: `query_commitments_by_status()`, `query_todos_for_agent()`, `query_updates_for_target()`, `query_overdue_commitments()`.
- **Why**: These are the most commonly needed queries for agent collaboration workflows. They deserve optimized implementations rather than relying on generic JSONB queries.
- **What**: If not already fully implemented in Step 108, refine these methods with: (1) proper index usage (partial indexes scoped to document type), (2) correct date handling for overdue detection (timezone-aware comparison), (3) pagination support, (4) result ordering (updates by date ascending, commitments by status then date). Ensure the SQL for each method uses the indexes recommended by the index generator.
- **Where**: `jacs/src/storage/database.rs`.

**Step 156.** Write test `test_semantic_commitment_search` (vector search).
- **Why**: Validates that you can find semantically similar commitments using embedding vectors. Use case: "find commitments similar to this one" for deduplication or context gathering.
- **What**: Store 5 commitments with embeddings representing different topics. Search with a vector similar to commitment #2. Assert commitment #2 ranks first. Assert results are filtered to type "commitment" only.
- **Where**: `jacs/tests/database_domain_tests.rs`. Gate with `database-vector` feature.

**Step 157.** Add full-text search (tsvector + GIN index).
- **Why**: Full-text search enables natural language queries over document content ("find commitments about quarterly reports"). This complements vector search: text search for exact keyword matching, vector search for semantic similarity.
- **What**: Add migration `003_add_fulltext_search.sql`: `ALTER TABLE jacs_document ADD COLUMN fts_vector tsvector GENERATED ALWAYS AS (to_tsvector('english', file_contents::text)) STORED;` and `CREATE INDEX idx_jacs_document_fts ON jacs_document USING GIN (fts_vector);`. Implement `search_text` in `DatabaseStorage` using `WHERE fts_vector @@ plainto_tsquery('english', $1)`.
- **Where**: New migration file `jacs/migrations/003_add_fulltext_search.sql` and `jacs/src/storage/database.rs`.

**Step 158.** Write test `test_fulltext_search`.
- **Why**: Validates that full-text search returns relevant documents and ranks them by relevance.
- **What**: Store documents with known text content. Search for a keyword that appears in some but not all documents. Assert correct documents returned. Assert documents with the keyword in titles/descriptions rank higher than those with it in nested fields.
- **Where**: `jacs/tests/database_domain_tests.rs`.

**Step 159.** Write test `test_combined_vector_and_text_search`.
- **Why**: Some queries benefit from combining text search (precision) with vector search (recall). Validate that the two can be used together.
- **What**: Store documents with both text content and embeddings. Perform a text search and a vector search for the same conceptual query. Assert that the intersection of results contains the most relevant documents. This is a validation test, not a new API -- it demonstrates the workflow of combining two query methods.
- **Where**: `jacs/tests/database_domain_tests.rs`.

**Step 160.** Aggregation queries: `count_documents_by_type()`, `count_commitments_by_status()`, `count_todos_by_agent()`, `count_updates_by_action()`.
- **Why**: Dashboard and monitoring use cases need counts without fetching all documents. These are O(1) with proper indexes vs O(n) with document-level queries.
- **What**: Add to `DatabaseStorage`: `pub fn count_documents_by_type(&self) -> Result<HashMap<String, usize>, Box<dyn Error>>` using `SELECT jacs_type, COUNT(*) FROM jacs_document GROUP BY jacs_type`. Similarly for the other three, each using appropriate GROUP BY clauses on JSONB fields.
- **Where**: `jacs/src/storage/database.rs`.

**Step 161.** Write test `test_aggregation_queries`.
- **Why**: Validates that all aggregation methods return correct counts.
- **What**: Store a known set of documents (10 commitments with mixed statuses, 5 todos across 3 agents, 8 updates with mixed actions). Run each aggregation query. Assert counts match expected values exactly.
- **Where**: `jacs/tests/database_domain_tests.rs`.

**Step 162.** Transaction support: `create_commitment_with_updates()`.
- **Why**: Creating a commitment and its initial update (e.g., "status_change" from none to "pending") should be atomic. If the update INSERT fails, the commitment INSERT should be rolled back.
- **What**: Add `pub fn create_commitment_with_updates(&self, commitment: &JACSDocument, updates: &[JACSDocument]) -> Result<(), JacsError>` that wraps the store operations in a database transaction (`BEGIN` / `COMMIT` / `ROLLBACK`).
- **Where**: `jacs/src/storage/database.rs`.

**Step 163.** Write test `test_transactional_commitment_creation`.
- **Why**: Validates atomicity: if one document in the transaction is invalid, nothing is stored.
- **What**: Create a valid commitment and an invalid update (e.g., missing required field). Call `create_commitment_with_updates`. Assert the call fails. Assert the commitment was NOT stored (rolled back). Then call with all valid documents. Assert both are stored.
- **Where**: `jacs/tests/database_domain_tests.rs`.

**Step 164.** Write test `test_suggest_indexes_for_all_types` -- index generator for todo, commitment, update.
- **Why**: Validates that the index generator produces correct SQL for all known document types.
- **What**: Call `suggest_indexes(&["commitment", "todo", "update"])`. Assert: (1) at least 5 recommendations returned, (2) each recommendation has valid SQL, (3) commitment recommendations include status index and date index, (4) todo recommendations include agent_id index, (5) update recommendations include target_id index. Parse each SQL statement to verify it is syntactically valid.
- **Where**: `jacs/tests/database_domain_tests.rs`.

**Step 165.** Create `src/storage/index_advisor.rs`.
- **Why**: Index recommendation logic is complex enough to warrant its own module. It needs to know about document types, their commonly queried fields, and the target database's index capabilities.
- **What**: Create `jacs/src/storage/index_advisor.rs` containing: (1) `pub struct IndexRecommendation { pub table: String, pub column_expr: String, pub index_type: String, pub condition: Option<String>, pub sql: String }`, (2) `pub fn suggest_indexes(schema_types: &[&str], backend: &str) -> Vec<IndexRecommendation>` that generates recommendations based on known query patterns for each document type. The function is pure -- it does not query the database.
- **Where**: New file `jacs/src/storage/index_advisor.rs`.

**Step 166.** Implement Postgres-specific index generation (GIN, HNSW, partial).
- **Why**: PostgreSQL supports specialized index types (GIN for JSONB, HNSW for vectors, partial indexes with WHERE) that are not available in all databases.
- **What**: In `index_advisor.rs`, implement `fn postgres_indexes(schema_types: &[&str]) -> Vec<IndexRecommendation>` that generates: GIN indexes for JSONB fields, HNSW indexes for vector columns, partial indexes scoped to specific `jacs_type` values, BTREE indexes for date fields used in range queries. Each recommendation includes the full `CREATE INDEX` DDL statement.
- **Where**: `jacs/src/storage/index_advisor.rs`.

**Step 167.** Implement generic recommendations for non-Postgres backends.
- **Why**: For future database backends (SQLite, DuckDB), generate recommendations using only standard SQL index types (BTREE, basic). This ensures the index advisor is useful even without PostgreSQL-specific features.
- **What**: Implement `fn generic_indexes(schema_types: &[&str]) -> Vec<IndexRecommendation>` that generates standard BTREE indexes on commonly queried columns. Add a note in each recommendation that the SQL is generic and may need backend-specific adjustments.
- **Where**: `jacs/src/storage/index_advisor.rs`.

**Step 168.** Add CLI subcommand: `jacs db suggest-indexes --backend postgres --types todo,commitment,update`.
- **Why**: The CLI is the user-facing entry point for the index generator. Users run this command, review the output, and apply the recommended indexes to their database.
- **What**: Add `db` subcommand group to the JACS CLI with `suggest-indexes` subcommand. Arguments: `--backend` (required, one of "postgres", "generic"), `--types` (required, comma-separated list of document types), `--output` (optional, file path; defaults to stdout). Output format: SQL DDL with comments explaining each index.
- **Where**: `jacs/src/main.rs` or `jacs/src/cli/mod.rs` (depending on CLI structure).

**Step 169.** Write CLI test for index suggestion.
- **Why**: CLI tests validate the user-facing interface end-to-end.
- **What**: Run `jacs db suggest-indexes --backend postgres --types commitment`. Assert: (1) exit code 0, (2) output contains `CREATE INDEX`, (3) output contains `commitment`, (4) output contains `GIN` (for JSONB index). Run with invalid backend. Assert non-zero exit code and helpful error message.
- **Where**: `jacs/tests/cli_tests.rs`.

**Step 170.** Add CLI subcommand: `jacs db migrate`.
- **Why**: Users need a simple command to run database migrations, creating or updating the schema.
- **What**: Add `migrate` subcommand under `jacs db`. It reads `JACS_DATABASE_URL` from config/env, connects to the database, and runs all pending migrations. Outputs which migrations were applied. Supports `--dry-run` flag to show what would be applied without executing.
- **Where**: CLI module and `jacs/src/storage/database.rs` (migration runner).

**Step 171.** Add CLI subcommand: `jacs db status`.
- **Why**: Users need to check the database connection and migration status before running operations.
- **What**: Add `status` subcommand under `jacs db`. It connects to the database, reports: (1) connection status (success/failure), (2) database version (PostgreSQL version string), (3) migrations applied (list with timestamps), (4) document counts by type, (5) pgvector extension status (installed/not installed).
- **Where**: CLI module.

**Step 172.** Add CLI subcommand: `jacs db export`.
- **Why**: Export documents from database to filesystem for backup, audit, or migration.
- **What**: Add `export` subcommand under `jacs db`. Arguments: `--output-dir` (required), `--type` (optional, filter by document type), `--verify` (optional, verify signatures during export). Calls `export_to_filesystem()`. Outputs count of exported documents.
- **Where**: CLI module.

**Step 173.** Add CLI subcommand: `jacs db import` with verification.
- **Why**: Import documents from filesystem to database, verifying signatures during import to ensure integrity.
- **What**: Add `import` subcommand under `jacs db`. Arguments: `--input-dir` (required), `--verify` (default true, verify each document's signature before importing), `--skip-existing` (optional, skip documents already in DB). Calls `import_from_filesystem()`. Outputs count of imported documents and any verification failures.
- **Where**: CLI module.

**Step 174.** Write test `test_cli_full_database_workflow`.
- **Why**: End-to-end test of the complete CLI database workflow: migrate -> create documents -> query -> export -> import -> verify.
- **What**: Using a testcontainers PostgreSQL instance: (1) `jacs db migrate` -- assert success, (2) create and store 3 commitments and 2 todos via Rust API, (3) `jacs db status` -- assert shows correct counts, (4) `jacs db suggest-indexes --backend postgres --types commitment,todo` -- assert valid output, (5) `jacs db export --output-dir /tmp/jacs-export --verify` -- assert 5 documents exported, (6) `jacs db import --input-dir /tmp/jacs-export --verify` into a fresh database -- assert 5 imported, (7) verify all documents in the new database.
- **Where**: `jacs/tests/cli_database_tests.rs`.

**Step 175.** Run full Phase 2 suite + WASM check.
- **Why**: Final integration checkpoint for Phase 2. All database tests must pass and WASM compilation must not be broken.
- **What**: Run: (1) `cargo test` (all non-database tests still pass), (2) `cargo test --features database,database-tests` (all database tests pass), (3) `cargo test --features database-vector,database-tests` (all vector tests pass), (4) `cargo check --target wasm32-unknown-unknown` (WASM compilation succeeds), (5) `cargo clippy --all-features -- -D warnings` (no new warnings). All five must pass for Phase 2 to be considered complete.
- **Where**: CI pipeline and local development.

---

## Files Created/Modified

| File | Action | Description |
|------|--------|-------------|
| `jacs/src/storage/database_traits.rs` | **Create** | `DatabaseDocumentTraits` trait definition, `IndexRecommendation` struct |
| `jacs/src/storage/database.rs` | **Create** | `DatabaseStorage` struct, `StorageDocumentTraits` impl, `DatabaseDocumentTraits` impl, migration runner, export/import methods |
| `jacs/src/storage/index_advisor.rs` | **Create** | Index recommendation engine: `suggest_indexes()`, Postgres-specific and generic generators |
| `jacs/src/storage/mod.rs` | **Modify** | Add `pub mod database`, `pub mod database_traits`, `pub mod index_advisor` (cfg-gated). Add `StorageType::Database` variant. Add `StorageBackend` enum. |
| `jacs/src/error.rs` | **Modify** | Add `StorageError(String)` and `DatabaseError { operation, reason }` variants to `JacsError` |
| `jacs/src/config/mod.rs` | **Modify** | Add `database_url`, `database_max_connections`, `database_min_connections`, `database_connect_timeout_secs` fields |
| `jacs/schemas/jacs.config.schema.json` | **Modify** | Add database configuration properties, add "database" to defaultStorage enum |
| `jacs/Cargo.toml` | **Modify** | Add `sqlx`, `pgvector`, `testcontainers` deps. Add `database`, `database-vector`, `database-tests` features |
| `jacs/migrations/001_create_jacs_document.sql` | **Create** | `jacs_document` table DDL with indexes |
| `jacs/migrations/002_add_vector_column.sql` | **Create** | pgvector embedding column + HNSW index |
| `jacs/migrations/003_add_fulltext_search.sql` | **Create** | tsvector column + GIN index for full-text search |
| `jacs/tests/database_trait_tests.rs` | **Create** | Trait definition tests, mock implementation tests |
| `jacs/tests/database_integration_tests.rs` | **Create** | Database CRUD tests, JSONB query tests, pagination tests, migration tests, concurrency tests |
| `jacs/tests/database_vector_tests.rs` | **Create** | Vector storage, search, ranking, auto-extraction tests |
| `jacs/tests/database_domain_tests.rs` | **Create** | Domain query tests (commitments, todos, updates, overdue), aggregation tests, transaction tests, index advisor tests |
| `jacs/tests/cli_database_tests.rs` | **Create** | CLI database workflow tests |
| CLI module (location TBD) | **Modify** | Add `jacs db` subcommand group: `migrate`, `status`, `suggest-indexes`, `export`, `import` |
