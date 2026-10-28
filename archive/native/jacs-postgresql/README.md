# jacs-postgresql

PostgreSQL storage backend for JACS documents.

## Install

```sh
cargo add jacs-postgresql jacs
cargo add tokio --features rt-multi-thread,macros
```

## Quick Start

```rust
use jacs_postgresql::PostgresStorage;
use jacs::storage::StorageDocumentTraits;
use jacs::storage::database_traits::DatabaseDocumentTraits;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let storage = PostgresStorage::new(&database_url, None, None, None)?;
    storage.run_migrations()?;
    Ok(())
}
```

## Design

- **Dual-column storage**: TEXT (`raw_contents`) for signature verification + JSONB (`file_contents`) for queries
- **Append-only**: New versions create new rows keyed by `(jacs_id, jacs_version)`
- **Soft delete**: `remove_document` sets `tombstoned = true` rather than deleting rows
- **Fulltext search**: PostgreSQL `tsvector` via the `SearchProvider` trait

## Connection

Pass a standard PostgreSQL connection string (`postgres://user:pass@host/db`). The crate uses [sqlx](https://docs.rs/sqlx) with the tokio-rustls runtime.

## More Info

See the [JACS README](https://humanassisted.github.io/JACS/native/advanced/storage.html) for the full storage backend overview.
