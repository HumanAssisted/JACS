# Phase 5: End-to-End, Docs & Polish (Steps 262-281)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)

**Status**: Not started
**Step Range**: 262-281
**Summary**: End-to-end integration tests across all document types and storage backends, documentation, benchmarks, and final quality checks.

---

## End-to-End Tests (Steps 262-266)

**Step 262-266.** End-to-end tests:
- Full commitment lifecycle: create commitment -> sign agreement -> update -> complete with all four document types
- Database round-trips for all 4 document types
- Mixed storage: fs for keys, db for documents
- Concurrent agents updating same commitment
- Storage migration: filesystem <-> database with signature verification

---

## Documentation (Steps 267-276)

**Step 267-271.** Rustdoc comments for all new public types/functions.

**Step 272-274.** Documentation: `todo-tracking.md`, `database-storage.md`, `runtime-configuration.md`, updated README, CHANGELOG.

**Step 275-276.** JSON examples, config examples, `cargo doc` verification.

---

## Benchmarks & Quality (Steps 277-281)

**Step 277-278.** Benchmarks: commitment creation/signing, todo list operations, db round-trip, vector search.

**Step 279.** `cargo clippy --all-features -- -D warnings` + `cargo fmt`.

**Step 280.** WASM check + fuzz tests for all schema validation.

**Step 281.** Full test: `cargo test --all-features` AND `cargo test` (without database). Version bump.

---

## Verification & Testing Strategy

### Test Categories

| Category | What | How to Run |
|----------|------|-----------|
| Unit | Schema validation (positive + negative), CRUD, config parsing | `cargo test` |
| Schema Positive | Every valid enum value, optional field combinations | `cargo test` |
| Schema Negative | Missing required fields, invalid enums, bad UUID format, bad dates | `cargo test` |
| Integration (DB) | Database storage, queries, migrations, optimistic locking | `cargo test --features database,database-tests` |
| MCP | Tool execution, response format | `cargo test` (jacs-mcp crate) |
| CLI | Command-line workflows | `cargo test --features cli` |
| Bindings | Python/Node/Go function calls | `cd jacspy && pytest` / `cd jacsnpm && npm test` |
| WASM | Compilation check (no runtime) | `cargo check --target wasm32-unknown-unknown` |
| Regression | All existing tests unchanged | `cargo test` |

### Key Verification Scenarios

1. **Todo list lifecycle**: Create list -> add goal/task items -> complete items -> archive -> verify all versions signed
2. **Commitment agreement**: Agent A proposes -> Agent B signs -> verify both signatures -> try to modify -> verification fails
3. **Commitment disagreement**: Agent A proposes -> Agent B formally disagrees with reason -> document enters contested state -> Agent A amends terms -> Agent B agrees
4. **Update chain**: Create commitment -> "commit" update -> "inform" update -> "delay" update -> "close-success" update -> verify chain integrity and all signatures
5. **Conversation to commitment**: Create thread -> exchange messages -> create commitment referencing thread -> sign agreement -> create "inform" update
6. **Todo-to-commitment promotion**: Private goal item -> create commitment with todoRef -> sign agreement -> todo item gets relatedCommitmentId
7. **Database round-trip**: Store signed document in DB -> retrieve -> verify signature matches
8. **Storage migration**: Filesystem docs -> import to DB -> verify signatures -> export back to filesystem -> verify again
9. **Mixed storage**: Keys from filesystem, documents from database, same agent
10. **Cross-language**: Create commitment in Python, verify in Rust via MCP, create update from Node

### Schema Test Coverage Matrix

| Schema | Positive Tests | Negative Tests | Integration Tests |
|--------|---------------|----------------|-------------------|
| Commitment | minimal, terms, dates, Q&A, completion Q&A, recurrence, agreement, task ref, conversation ref, todo ref, owner, all statuses, dispute, standalone | invalid status, bad dates, invalid date format | signing, two-agent agreement, immutable after agreement, disagreement workflow |
| Update | minimal, all 15 action types, all 3 target types, note, chain, agent assignment | invalid action, invalid target, non-UUID target, missing target, missing action | signing, chain verification, multi-agent updates, header fields, semantic category coverage |
| Todo | minimal, goal item, task item, childItemIds, all statuses, all priorities, commitment ref, conversation ref, archive refs, tags | invalid status, invalid itemtype, missing description, missing status, missing itemtype, missing name, comprehensive rejects | signing, resign, versioning, archive workflow, multiple lists |
| Conversation | message with thread, ordering, multi-agent, produces commitment | (uses existing message schema tests) | signing, multi-agent messages |

---

## How to Run Tests

```bash
# Basic (no database, no external deps)
cargo test

# With database features compiled (but no DB tests)
cargo test --features database

# Full database integration tests (local PostgreSQL)
export JACS_TEST_DATABASE_URL="postgres://user:pass@localhost:5432/jacs_test"
cargo test --features database,database-tests

# Full database integration tests (Docker via testcontainers)
cargo test --features database,database-tests  # auto-provisions if Docker running

# WASM compilation check
cargo check --target wasm32-unknown-unknown

# All features
cargo test --all-features

# Clippy
cargo clippy --all-features -- -D warnings

# Benchmarks
cargo bench --features database

# MCP server tests
cd jacs-mcp && cargo test

# Python bindings
cd jacspy && pip install -e . && pytest

# Node bindings
cd jacsnpm && npm install && npm test
```
