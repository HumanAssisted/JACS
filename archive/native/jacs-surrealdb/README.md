# jacs-surrealdb

SurrealDB storage backend for JACS documents.

## Install

```sh
cargo add jacs-surrealdb
```

## Quick Start

```rust
use jacs_surrealdb::SurrealDbStorage;
use jacs::storage::database_traits::DatabaseDocumentTraits;

let storage = SurrealDbStorage::in_memory_async().await?;
storage.run_migrations()?;
```

## Design

- **Embedded or server mode**: In-memory for tests, connect to a SurrealDB server for production
- **Native JSON**: Uses SCHEMAFULL tables with native JSON object storage
- **Append-only**: Compound record IDs `[jacs_id, jacs_version]` give natural idempotency
- **Soft delete**: Tombstone pattern preserves audit history
- **Search**: `CONTAINS` substring matching on `raw_contents`

## More Info

See the [JACS README](https://github.com/nickthecook/JACS#readme) for the full storage backend overview.
