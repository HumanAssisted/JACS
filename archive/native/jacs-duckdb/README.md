# jacs-duckdb

DuckDB in-process storage backend for JACS documents.

## Install

```sh
cargo add jacs-duckdb
```

## Quick Start

```rust
use jacs_duckdb::DuckDbStorage;
use jacs::storage::database_traits::DatabaseDocumentTraits;

// In-memory (great for tests)
let storage = DuckDbStorage::in_memory().expect("create in-memory DuckDB");
storage.run_migrations().expect("create tables");

// File-backed
let storage = DuckDbStorage::new("path/to/db.duckdb").expect("open DuckDB file");
storage.run_migrations().expect("create tables");
```

## Design

- **In-process**: No external server needed — DuckDB runs embedded via the `bundled` feature
- **Append-only**: New versions create new rows; `INSERT OR IGNORE` for idempotent writes
- **Soft delete**: Tombstone flag rather than hard DELETE
- **Search**: `json_extract_string()` for field queries, `LIKE` for keyword search

## More Info

See the [JACS README](https://github.com/nickthecook/JACS#readme) for the full storage backend overview.
