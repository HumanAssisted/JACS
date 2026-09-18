# jacs-postgresql

PostgreSQL storage backend for JACS documents.

## Install

```sh
cargo add jacs-postgresql
```

## Quick Start

```rust
use jacs_postgresql::PostgresStorage;
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;

let storage = PostgresStorage::new(&database_url, None, None, None)?;
storage.run_migrations()?;
```

## Design

- **Dual-column storage**: TEXT (`raw_contents`) for signature verification + JSONB (`file_contents`) for queries
- **Append-only**: New versions create new rows keyed by `(jacs_id, jacs_version)`
- **Soft delete**: `remove_document` sets `tombstoned = true` rather than deleting rows
- **Fulltext search**: PostgreSQL `tsvector` via the `SearchProvider` trait

## Connection

Pass a standard PostgreSQL connection string (`postgres://user:pass@host/db`). The crate uses [sqlx](https://docs.rs/sqlx) with the tokio-rustls runtime.

## More Info

See the [JACS README](https://github.com/nickthecook/JACS#readme) for the full storage backend overview.
