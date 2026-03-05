# Databases

The old database chapter mixed real Rust storage backends with a speculative cross-language cookbook. This page is now intentionally narrower.

## What Exists Today

Database-backed storage is a **Rust-core story**, not a unified cross-language product surface.

Current Rust feature flags include:

- `database` for PostgreSQL
- `sqlite`
- `rusqlite-storage`
- `duckdb-storage`
- `surrealdb-storage`
- `redb-storage`

## What To Do In Practice

- Start with filesystem-backed signed envelopes unless you already know you need a database backend.
- If you need Rust storage internals, read [Storage Backends](../advanced/storage.md) and inspect `jacs/src/storage/`.
- If you need a polished database cookbook for Python or Node, that is not a first-class book workflow yet.
