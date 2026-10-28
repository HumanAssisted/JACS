# jacs-surrealdb

SurrealDB storage backend for JACS documents.

## Install

```sh
cargo add jacs-surrealdb jacs
cargo add tokio --features rt-multi-thread,macros
```

## Quick Start

```rust
use jacs_surrealdb::SurrealDbStorage;
use jacs::storage::database_traits::DatabaseDocumentTraits;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = SurrealDbStorage::in_memory_async().await?;
    storage.run_migrations()?;
    Ok(())
}
```

## Design

- **Embedded in-memory mode**: This crate enables `kv-mem`; it does not expose a remote-server connector
- **Native JSON**: Uses SCHEMAFULL tables with native JSON object storage
- **Append-only**: Compound record IDs `[jacs_id, jacs_version]` give natural idempotency
- **Soft delete**: Tombstone pattern preserves audit history
- **Search**: `CONTAINS` substring matching on `raw_contents`

## More Info

See the [JACS README](https://humanassisted.github.io/JACS/native/advanced/storage.html) for the full storage backend overview.
