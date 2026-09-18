# jacs-redb

Redb embedded key-value storage backend for JACS documents.

## Install

```sh
cargo add jacs-redb
```

## Quick Start

```rust
use jacs_redb::RedbStorage;
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;

// In-memory (great for tests)
let storage = RedbStorage::in_memory().expect("create in-memory redb");
storage.run_migrations().expect("run migrations");

// File-backed
let storage = RedbStorage::new("path/to/db.redb").expect("open redb file");
storage.run_migrations().expect("run migrations");
```

## Design

- **Pure Rust**: No C bindings, no external services — just add the crate
- **Manual secondary indexes**: Type, agent, and version indexes via separate tables
- **Append-only**: Idempotent inserts skip if key exists
- **Soft delete**: Tombstone index for soft-delete markers
- **No search**: Redb has no native fulltext or vector search; `SearchProvider` reports all capabilities as `false`

## More Info

See the [JACS README](https://github.com/nickthecook/JACS#readme) for the full storage backend overview.
