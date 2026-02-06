# JACS Roadmap

## Current: v0.6.0 (In Progress)

### Completed
- Phase 0: Signed Agent State Documents (agentstate.schema.json, MCP tools)
- Phase 1: Schema Design & CRUD (Commitment, Todo List, Conversation, cross-references)
- Phase 2 Core: Database Storage Backend (PostgreSQL reference impl, generic trait)

### In Progress
- Phase 3: Runtime Configuration (JacsConfigProvider trait, AgentBuilder integration)

---

## Deferred Features (Post v0.6.0)

### Database: Additional Backends
- **SQLite** with vector search (via sqlite-vss or similar)
- **DuckDB** for analytics workloads
- **LanceDB** for native vector database
- Priority: Trait is generic (`DatabaseDocumentTraits`), new backends implement it

### Database: Vector Search (pgvector)
- `search_vector()` method on `DatabaseDocumentTraits`
- pgvector HNSW index for cosine similarity
- Auto-extract embeddings from `jacsEmbedding` on store
- `database-vector` feature flag (depends on `database`)
- Migration: `ALTER TABLE jacs_document ADD COLUMN embedding vector(1536)`

### Database: Full-Text Search
- PostgreSQL `tsvector` + GIN index
- `search_text()` method on `DatabaseDocumentTraits`
- Combined vector + text search workflows
- Migration: generated tsvector column + GIN index

### Database: Index Advisor
- `jacs db suggest-indexes --backend postgres --types commitment,todo`
- `IndexRecommendation` struct with DDL output
- Postgres-specific (GIN, HNSW, partial indexes) and generic (BTREE) generators
- Pure function -- does not query the database, only generates SQL

### Database: CLI Subcommands
- `jacs db migrate` -- run pending migrations
- `jacs db status` -- connection status, migration status, document counts
- `jacs db suggest-indexes` -- generate index recommendations
- `jacs db export --output-dir ./backup --type commitment --verify`
- `jacs db import --input-dir ./backup --verify --skip-existing`

### Database: Advanced Queries
- `query_documents_jsonb()` -- JSONB containment queries
- `query_overdue_commitments()` -- date-range + status filtering
- `count_documents_by_type()` -- aggregation queries
- Transaction support for multi-document operations
- Full pagination on all query methods

### Database: Storage Migration Tooling
- `export_to_filesystem()` / `import_from_filesystem()`
- Signature verification during migration
- Bidirectional: filesystem <-> database

### MCP Server: New Document Tools
- Commitment CRUD tools (create, list, update status, dispute, verify)
- Todo list tools (create, add item, update status, list)
- Conversation tools (start thread, reply, list thread)
- Database query tools (when database feature enabled)

### Language Bindings
- Python (`jacspy/`): Commitment, Todo, Conversation functions
- Node.js (`jacsnpm/`): Same coverage
- Go (`jacsgo/`): Same coverage
- Validate API ergonomics across all bindings

### Runtime Configuration (Phase 3)
- `JacsConfigProvider` trait for higher-level libraries
- `RuntimeConfig` with `RwLock<Config>` for mutation
- `AgentBuilder` integration with `.config_provider(Arc<dyn JacsConfigProvider>)`
- Observability runtime reconfiguration

### End-to-End & Polish (Phase 5)
- Cross-feature integration tests
- Benchmarks (goal creation/signing, db round-trip, vector search)
- Fuzz tests for schema validation
- `cargo clippy --all-features -- -D warnings`
- WASM compatibility verification
- Version bump and release

---

## Design Decisions for Future Reference

### Multiple Database Backends
The `DatabaseDocumentTraits` trait is intentionally database-agnostic. Each backend implements the same trait. The PostgreSQL implementation is the reference. Future backends (SQLite, DuckDB, LanceDB) implement the same trait with backend-specific optimizations.

### TEXT + JSONB Dual Column Strategy
PostgreSQL JSONB normalizes JSON (sorts keys, removes whitespace). JACS signatures depend on exact JSON byte order. Solution: store raw JSON as TEXT (signature-safe retrieval) plus JSONB (for queries). The `raw_contents` TEXT column preserves the exact signed bytes. The `file_contents` JSONB column enables efficient queries.

### Append-Only Model
Documents are immutable once stored. New versions create new rows keyed by `(jacs_id, jacs_version)`. No UPDATE operations on existing rows. This matches JACS's cryptographic model where each version is independently signed.

### Keys Never in Database
Even with database storage, cryptographic keys and `agent.json` always load from filesystem or keyservers. The database stores signed documents only.
