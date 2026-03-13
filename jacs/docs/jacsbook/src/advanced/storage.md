# Storage Backends

JACS has two storage layers today:

- Low-level file/object storage via `MultiStorage`
- Signed document CRUD/search via `DocumentService`

Those are related, but they are not identical. The most important rule is the signed-document contract:

- Every `DocumentService` read verifies the stored JACS document before returning it.
- Every `create()` and `update()` verifies the signed document before persisting it.
- If an update payload changes an already-signed JACS document without re-signing it, the write fails.
- Visibility changes create a new signed version instead of mutating metadata in place.

## Built-in Core Backends

| Backend | Config Value | Core Surface | Notes |
|---------|--------------|--------------|-------|
| Filesystem | `fs` | `MultiStorage` + `DocumentService` | Default. Signed JSON files on disk. |
| Local indexed SQLite | `rusqlite` | `DocumentService` + `SearchProvider` | Stores signed documents in a local SQLite DB with FTS search. |
| AWS object storage | `aws` | `MultiStorage` | Object-store backend. |
| Memory | `memory` | `MultiStorage` | Non-persistent, useful for tests and temporary flows. |
| Browser local storage | `local` | `MultiStorage` | WASM-only. |

For local indexed document search in JACS core, use `rusqlite`.

## Filesystem (`fs`)

Filesystem is the default signed-document backend.

```json
{
  "jacs_default_storage": "fs",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys"
}
```

Typical layout:

```text
jacs_data/
├── agent/
│   └── {agent-id}:{agent-version}.json
└── documents/
    ├── {document-id}:{version}.json
    └── archive/
```

Use filesystem when you want the simplest possible deployment, inspectable files, and no local database dependency.

## Local Indexed SQLite (`rusqlite`)

`rusqlite` is the built-in indexed document backend used by the upgraded bindings and MCP search path.

```json
{
  "jacs_default_storage": "rusqlite",
  "jacs_data_directory": "./jacs_data",
  "jacs_key_directory": "./jacs_keys"
}
```

With this setting:

- Signed documents are stored in `./jacs_data/jacs_documents.sqlite3`
- Full-text search comes from SQLite FTS
- `DocumentService` reads and writes enforce verification
- Updating visibility creates a new signed successor version

Use `rusqlite` when you want local full-text search, filtered document queries, and a single-machine deployment.

## AWS (`aws`)

AWS support is an object-store backend for lower-level storage operations.

```json
{
  "jacs_default_storage": "aws"
}
```

Required environment variables:

```bash
export JACS_ENABLE_AWS_BUCKET_NAME="my-jacs-bucket"
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-west-2"
```

Use `aws` when you need remote object storage. If you also need a richer signed-document query surface, use one of the database-focused crates below.

## Memory (`memory`)

Memory storage is non-persistent:

```json
{
  "jacs_default_storage": "memory"
}
```

Use it for tests, temporary operations, and ephemeral agent flows.

## Extracted Backend Crates

Several richer database backends now live outside the JACS core crate:

- `jacs-postgresql`
- `jacs-duckdb`
- `jacs-redb`
- `jacs-surrealdb`

These crates implement the same storage/search traits in their own packages. They are not built-in `jacs_default_storage` values for the core crate.

## Choosing a Backend

| Scenario | Recommendation |
|----------|----------------|
| Default local usage | `fs` |
| Local search + filtering | `rusqlite` |
| Ephemeral tests | `memory` |
| Remote object storage | `aws` |
| Postgres / vector / multi-model needs | Use an extracted backend crate |

## Migration Notes

Switching backends does not migrate data automatically.

When you change `jacs_default_storage`:

1. Export the signed documents you need to keep.
2. Update the config value.
3. Create/import the new backend’s data store.
4. Re-run verification on imported documents as part of migration validation.
