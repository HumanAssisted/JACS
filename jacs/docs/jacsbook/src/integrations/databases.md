# Databases

The old database chapter mixed real Rust storage backends with a speculative cross-language cookbook. This page is now intentionally narrower.

## What Exists Today

Database-backed storage is a **Rust-core story**, not a unified cross-language product surface.

Current Rust feature flags include:

- `sqlite` for the built-in `rusqlite` document backend
- `sqlx-sqlite` for the async SQLite variant
- extracted crates such as `jacs-postgresql`, `jacs-duckdb`, `jacs-redb`, and `jacs-surrealdb`

## What To Do In Practice

- Start with filesystem-backed signed envelopes unless you already know you need indexed local search.
- Use `rusqlite` when you want the upgraded local `DocumentService` path for bindings and MCP.
- If you need Rust storage internals, read [Storage Backends](../advanced/storage.md) and inspect `jacs/src/storage/`.
- If you need a polished database cookbook for Python or Node, that is not a first-class book workflow yet.
