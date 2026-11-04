# jacs-surrealdb

SurrealDB storage backend for JACS documents.

## Install

`jacs-surrealdb` has been held at 0.15.0 since the 0.16.0 release (see
[release status](https://github.com/HumanAssisted/JACS/blob/main/docs/release-status.md))
and requires `jacs` 0.15 until it is released again. With `jacs` 0.16, Cargo
builds two copies of `jacs` and the Quick Start does not compile.

```sh
cargo add jacs-surrealdb@0.15 jacs@0.15
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
