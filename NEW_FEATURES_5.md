# Phase 5: End-to-End Tests, Documentation & Polish (Steps 262-281)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)

**Status**: Not started
**Step Range**: 262-281
**Dependencies**: Phase 0 (Signed Agent State), Phase 1 (Schema & CRUD), Phase 2 (Database Storage), Phase 3 (Runtime Configuration), Phase 4 (MCP & Bindings)

---

## What This Phase Delivers

Phase 5 is the integration and release-readiness phase. By this point, Phases 0-4 have delivered the individual components: signed agent state documents, four new document schemas (Commitment, Update, Todo List, Conversation enhancements), a PostgreSQL-backed database storage layer, runtime configuration, MCP tools, and language bindings. Phase 5 ties everything together with:

1. **End-to-end integration tests** (Steps 262-266) that exercise multi-agent workflows spanning all four document types, both storage backends (filesystem and database), and mixed-storage configurations. These tests prove the system works as a whole, not just in isolation.
2. **Comprehensive documentation** (Steps 267-276) including rustdoc comments on all public APIs, user-facing guides for each major feature, JSON examples for every document type, and configuration examples.
3. **Performance benchmarks** (Steps 277-278) establishing baseline metrics for commitment creation/signing, todo list operations, database round-trips, and vector search latency.
4. **Final quality gates** (Steps 279-281) including clippy, formatting, WASM compilation checks, fuzz testing for schema validation, and a full test suite pass with and without database features.

---

## End-to-End Tests (Steps 262-266)

These tests are the crown jewels of the test suite. Each test exercises a complete workflow that spans multiple document types, multiple agents, and potentially multiple storage backends. They are feature-gated behind `database-tests` where database access is required.

### Step 262: Full Commitment Lifecycle Test

**Test name**: `test_e2e_full_commitment_lifecycle`
**Feature gate**: `database-tests` (optional -- filesystem variant also runs without database)

This test walks through the entire lifecycle of a commitment between two agents, exercising all four document types working together. The sequence is:

1. **Agent A creates a commitment** with structured terms:
   - `jacsCommitmentDescription`: "Deliver API integration by 2026-03-15"
   - `jacsCommitmentTerms`: `{ deliverable: "REST API with OAuth2", deadline: "2026-03-15T00:00:00Z", compensation: "5000 USD" }`
   - `jacsCommitmentStatus`: "pending"
   - `jacsCommitmentStartDate` and `jacsCommitmentEndDate` set
   - `jacsCommitmentConversationRef`: references the negotiation thread UUID
   - Verify: document is signed by Agent A, schema validates, `jacsId` and `jacsVersion` are populated

2. **Agent B signs the agreement** via `jacsSignAgreement`:
   - Agent B's signature is added to `jacsAgreement.signatures`
   - `jacsAgreementHash` is computed from the commitment terms (not status)
   - Verify: both Agent A and Agent B signatures are present and valid
   - Verify: `jacsAgreement.agentIDs` contains both agent IDs
   - Verify: commitment status transitions to "active"

3. **Agent A creates a "delay" update**:
   - `jacsUpdateAction`: "delay"
   - `jacsUpdateTargetId`: commitment's `jacsId`
   - `jacsUpdateTargetType`: "commitment"
   - `jacsUpdateNote`: "Dependency on upstream API delayed by 1 week"
   - `previousUpdateId`: null (first update in chain)
   - Verify: update is signed by Agent A
   - Verify: Agent A is in the commitment's `jacsAgreement.agentIDs` (authorization check)
   - Verify: commitment gets a new version with updated `jacsCommitmentEndDate`

4. **Agent B creates an "inform" update**:
   - `jacsUpdateAction`: "inform"
   - `jacsUpdateTargetId`: same commitment `jacsId`
   - `jacsUpdateTargetType`: "commitment"
   - `jacsUpdateNote`: "Acknowledged delay, adjusting downstream timeline"
   - `previousUpdateId`: Agent A's delay update `jacsId`
   - Verify: update chain integrity -- `previousUpdateId` points to the correct prior update
   - Verify: update is signed by Agent B

5. **Agent A creates a "close-success" update**:
   - `jacsUpdateAction`: "close-success"
   - `jacsUpdateTargetId`: same commitment `jacsId`
   - `jacsUpdateTargetType`: "commitment"
   - `jacsUpdateNote`: "API delivered and verified"
   - `previousUpdateId`: Agent B's inform update `jacsId`
   - Verify: commitment status transitions to "completing" (pending Agent B's agreement)

6. **Agent B agrees to completion** via `jacsEndAgreement`:
   - Agent B signs the completion
   - Verify: commitment status transitions to "completed"
   - Verify: `jacsCommitmentCompletionAnswer` is populated

**Final verification across the entire lifecycle**:
- Retrieve all versions of the commitment and verify version chain integrity (`jacsPreviousVersion` links)
- Verify ALL signatures on every version remain valid
- Retrieve the full update chain for this commitment and verify ordering
- Verify the update chain has exactly 3 entries (delay, inform, close-success)
- Verify the conversation thread referenced by the commitment exists and is accessible
- Verify all four document types (commitment, update, conversation message, todo list if referenced) are present and cross-referenced correctly

### Step 263: Database Round-Trip Test

**Test name**: `test_e2e_database_round_trip_all_types`
**Feature gate**: `database-tests`

This test verifies that all four document types survive a round-trip through PostgreSQL JSONB storage with signatures intact. JSONB can reorder keys, change whitespace, and normalize Unicode -- this test proves our signature scheme is resilient to all of those transformations.

**Procedure for each document type**:

1. **Commitment round-trip**:
   - Create a commitment with all optional fields populated (terms, dates, Q&A, recurrence, agreement with two agents, todoRef, taskId, conversationRef)
   - Sign it with Agent A
   - Store via `DatabaseStorage::store_document()`
   - Retrieve via `DatabaseStorage::get_document()`
   - Verify: `jacsSha256` matches after round-trip
   - Verify: `jacsSignature` is still valid after round-trip
   - Verify: all fields are preserved (deep equality check on content fields)
   - Verify: `jacsType` is "commitment" in the retrieved document

2. **Todo list round-trip**:
   - Create a todo list with mixed item types (2 goals, 3 tasks) including `childItemIds`, tags, `relatedCommitmentId`, and all status/priority combinations
   - Sign and store
   - Retrieve and verify signature
   - Verify: item ordering is preserved
   - Verify: nested `childItemIds` arrays survived JSONB serialization

3. **Update round-trip**:
   - Create an update document with all 15 action types (one document per action type, stored in batch)
   - Store all 15 updates
   - Retrieve each by ID and verify signature
   - Query via `query_updates_for_target()` and verify all 15 are returned
   - Verify: `previousUpdateId` chain is intact after retrieval

4. **Conversation message round-trip**:
   - Create a conversation thread with 3 messages from 2 agents
   - Store all messages
   - Retrieve by thread ID
   - Verify: message ordering via `jacsMessagePreviousId` is intact
   - Verify: each message's signature is valid after round-trip

**Negative check**: Tamper with a retrieved document's content field (modify one character in `jacsCommitmentDescription`), then verify that signature validation FAILS. This confirms the round-trip test is actually testing something meaningful.

### Step 264: Mixed Storage Backend Test

**Test name**: `test_e2e_mixed_storage_backends`
**Feature gate**: `database-tests`

This test verifies the architecture from Decision 11 (keys always from secure locations) by running a workflow where different storage backends handle different document types simultaneously.

**Configuration**:
- **Keys and agent.json**: loaded from filesystem (`StorageType::FS`) via the standard key directory
- **Documents (commitments, updates, todos, messages)**: stored in PostgreSQL via `DatabaseStorage`
- **Agent state documents (MEMORY.md, SKILL.md wrappers)**: stored on filesystem via `MultiStorage` with `StorageType::FS`

**Test sequence**:
1. Initialize `Agent` with `JacsConfigProvider` that specifies:
   - `get_key_directory()` -> filesystem path
   - `get_storage_type()` -> `StorageType::Database`
   - `get_database_url()` -> test PostgreSQL URL
   - `get_data_directory()` -> filesystem path (for agent state docs)
2. Create and sign a commitment (stored in database)
3. Create and sign a todo list (stored in database)
4. Create and sign an agent state document for MEMORY.md (stored on filesystem)
5. Verify: commitment can be retrieved from database with valid signature
6. Verify: todo list can be retrieved from database with valid signature
7. Verify: agent state document can be retrieved from filesystem with valid signature
8. Verify: keys never touched the database (query `jacs_document` table for agent key documents, expect zero results)
9. Verify: agent can sign new documents after retrieving keys from filesystem, proving the mixed-storage pipeline is seamless

### Step 265: Concurrent Agents Test

**Test name**: `test_e2e_concurrent_agent_updates`
**Feature gate**: `database-tests`

This test verifies optimistic locking behavior when two agent instances attempt to update the same commitment simultaneously. This is critical for multi-agent systems where agents may be running in separate processes.

**Setup**:
1. Create a commitment signed by both Agent A and Agent B
2. Store in database

**Concurrent update simulation**:
1. Agent A reads the commitment (version V1)
2. Agent B reads the same commitment (also version V1)
3. Agent A creates an "inform" update targeting the commitment, producing version V2
4. Agent A stores the updated commitment successfully
5. Agent B creates a "progress" update targeting the commitment, also producing what it thinks is V2
6. Agent B attempts to store -- this MUST FAIL with a version conflict error

**Verification**:
- Agent A's update succeeded: retrieve commitment, verify it is at V2 with Agent A's update
- Agent B's update failed: verify the error is a `JacsError::DatabaseError` with `operation: "optimistic_lock"` (or similar)
- The commitment in the database has exactly 2 versions (V1 original, V2 from Agent A)
- Agent B can retry: re-read the commitment (now V2), create a new update producing V3, store successfully
- Final state: commitment has 3 versions (V1, V2, V3) with correct `jacsPreviousVersion` chain

**Why this matters**: In production, agents run concurrently. Without optimistic locking, two agents could overwrite each other's updates, breaking the version chain and potentially invalidating signatures. This test proves the system prevents that.

### Step 266: Storage Migration Test

**Test name**: `test_e2e_storage_migration_filesystem_to_database`
**Feature gate**: `database-tests`

This test verifies that documents can be migrated between storage backends with all signatures preserved. This is the upgrade path for users moving from filesystem-only JACS to database-backed JACS.

**Filesystem to database migration**:
1. Create 4 documents on filesystem (one of each type: commitment, todo, update, message)
2. Sign each with Agent A
3. Verify all signatures on filesystem
4. Read each document from filesystem
5. Store each document in database via `DatabaseStorage::store_document()`
6. Verify all signatures after database import (proves JSONB round-trip preserves signatures)
7. Verify documents are queryable via database-specific methods (`query_by_type()`, `query_commitments_by_status()`, etc.)

**Database to filesystem export**:
8. Read each document from database
9. Write each document back to filesystem (different directory to avoid overwriting originals)
10. Verify all signatures on the exported filesystem copies
11. Verify: byte-for-byte content equality is NOT required (JSONB may reorder keys), but semantic equality and signature validity ARE required

**Cross-reference integrity after migration**:
12. Verify: commitment's `jacsCommitmentConversationRef` still points to a valid message thread
13. Verify: update's `jacsUpdateTargetId` still resolves to the commitment
14. Verify: the update chain's `previousUpdateId` links are intact

**Edge case**: Migrate a commitment that has an active agreement (two agent signatures). Verify BOTH signatures are valid after migration in both directions.

---

## Documentation (Steps 267-276)

### Step 267-271: Rustdoc Comments for All New Public Types and Functions

Every new public type, trait, function, and method introduced in Phases 0-4 must have rustdoc comments. The comments must include a one-line summary, a longer description where appropriate, usage examples for key entry points, and `# Errors` sections for fallible functions.

**Key types requiring rustdoc**:

| Module | Type/Function | What to Document |
|--------|---------------|-----------------|
| `schema/commitment_crud.rs` | `create_minimal_commitment()` | Parameters, return type, schema validation, example JSON |
| `schema/commitment_crud.rs` | `create_commitment_with_terms()` | Terms object structure, deadline format |
| `schema/update_crud.rs` | `create_update()` | All 15 action types, target types, chain linking |
| `schema/update_crud.rs` | `get_update_chain()` | Chain traversal algorithm, ordering guarantees |
| `schema/todo_crud.rs` | `create_todo_list()` | List structure, item types (goal vs task) |
| `schema/todo_crud.rs` | `add_todo_item()` | Re-signing behavior, item ID generation |
| `schema/todo_crud.rs` | `archive_completed_items()` | Archive list creation, original list mutation |
| `schema/message_crud.rs` | `create_message()` | Thread linking, `jacsMessagePreviousId` |
| `schema/agentstate_crud.rs` | `create_agentstate()` | Generic wrapper, type enum, origin tracking |
| `storage/database_traits.rs` | `DatabaseDocumentTraits` | Trait contract, required methods, mock example |
| `storage/database.rs` | `DatabaseStorage` | Connection setup, pool configuration, migration |
| `storage/database.rs` | `store_document()` | JSONB storage, optimistic locking, versioning |
| `storage/database.rs` | `query_by_type()` | Type filtering, pagination |
| `storage/database.rs` | `query_updates_for_target()` | Chain reconstruction, ordering |
| `storage/database.rs` | `query_commitments_by_status()` | Status enum values, date filtering |
| `storage/database.rs` | `query_overdue_commitments()` | Date comparison logic |
| `config/mod.rs` | `JacsConfigProvider` | Trait contract, override chain, HAI integration |
| `config/mod.rs` | `AgentBuilder` | Builder pattern, `config_provider()` method |
| `config/runtime.rs` | `RuntimeConfig` | RwLock semantics, mutation methods, lock poisoning |
| `error.rs` | `JacsError::DatabaseError` | When thrown, how to handle |
| `error.rs` | `JacsError::StorageError` | When thrown, how to handle |

**Verification**: Run `cargo doc --all-features --no-deps` and confirm zero warnings. Every public item must be documented.

### Step 272-274: User-Facing Documentation

Four new Markdown documents in the `docs/` directory, each targeting a developer audience who wants to USE JACS, not contribute to it.

**Document 1: `docs/todo-tracking.md`**
- What todo lists are and how they differ from commitments (private vs shared)
- The two item types: goals (aspirational, private) and tasks (concrete, actionable)
- How goals become commitments (promotion workflow)
- Creating a todo list with the MCP tool, CLI, and Rust API
- Adding items, completing items, archiving completed items
- Version history and audit trail (every mutation re-signs)
- Linking todo items to commitments via `relatedCommitmentId`
- JSON example: a complete todo list with 2 goals and 3 tasks
- JSON example: an archived todo list

**Document 2: `docs/database-storage.md`**
- When to use database storage vs filesystem storage
- Prerequisites: PostgreSQL 14+, pgvector extension (optional)
- Configuration: `JACS_DATABASE_URL` environment variable, config file option, `JacsConfigProvider` programmatic setup
- Migration: how JACS auto-runs SQL migrations on first connection
- Schema: the `jacs_document` table structure (jacs_id, jacs_version, agent_id, jacs_type, file_contents JSONB, timestamps)
- Vector search setup (optional `database-vector` feature)
- Domain queries: querying commitments by status, updates by target, overdue commitments
- Index generation: using the CLI tool to generate recommended indexes
- Migration from filesystem: step-by-step guide
- Performance considerations: connection pooling, JSONB indexing, vacuum schedule

**Document 3: `docs/runtime-configuration.md`**
- The 12-Factor override chain: compiled defaults -> `jacs.config.json` -> environment variables -> `JacsConfigProvider`
- All configuration fields with types, defaults, and environment variable names
- Writing a custom `JacsConfigProvider` (example: HAI integration)
- `RuntimeConfig` for hot-reloading configuration without restarting
- AgentBuilder integration: `AgentBuilder::new().config_provider(my_provider).build()`
- Backward compatibility: old configs still work, new fields have sensible defaults

**Document 4: `docs/signed-agent-state.md`**
- What agent state signing is and why it matters
- The `agentstate.schema.json` wrapper: type enum, origin tracking, framework field
- Signing a MEMORY.md file (step-by-step with MCP tool)
- Signing a SKILL.md file (step-by-step)
- Signing hook scripts (mandatory content embedding for TOCTOU prevention)
- Adopting agent state from another agent (origin: "adopted")
- Verifying agent state signatures
- Framework compatibility: Claude Code, OpenClaw, LangGraph examples

### Step 275: README Updates

Update the top-level `README.md` with the following new sections:

- **"What's New in 0.6.0"** section: bullet list of signed agent state, todo tracking, commitments with agreement/disagreement, semantic update tracking, database storage, runtime configuration
- **"Document Types"** section: table listing all document types (agent, task, message, commitment, update, todo, agentstate, eval, node, program) with one-line descriptions
- **"Storage Backends"** section: filesystem, S3, HTTP, memory, web localStorage, PostgreSQL (new)
- **"Quick Start: Commitments"** section: 5-line code example showing create -> sign -> agree workflow
- **"Quick Start: Todo Lists"** section: 3-line code example showing create list -> add item -> complete
- Update the feature flags table to include `database`, `database-vector`, `database-tests`
- Update the configuration section to mention `JACS_DATABASE_URL` and `JacsConfigProvider`

### Step 276: CHANGELOG and JSON/Config Examples

**CHANGELOG.md** entry for v0.6.0:
- New document types: Commitment, Update, Todo List, Agent State
- Conversation enhancements: `jacsMessagePreviousId` for message ordering
- Agreement/Disagreement system: formal disagreement as signed cryptographic action
- Database storage: PostgreSQL backend with JSONB, vector search (optional)
- Runtime configuration: `JacsConfigProvider` trait, `RuntimeConfig` hot-reload
- MCP tools: 17 new tools for all document types
- Language bindings: Python, Node, Go support for all new types
- CLI: `jacs todo`, `jacs commitment`, `jacs update`, `jacs conversation` commands

**JSON examples** (in `docs/examples/`):

| File | Contents |
|------|----------|
| `commitment-minimal.json` | Simplest valid commitment (description + status only) |
| `commitment-full.json` | Commitment with all fields: terms, dates, Q&A, recurrence, agreement, todoRef, taskId, conversationRef |
| `commitment-agreed.json` | Commitment with two agent signatures in `jacsAgreement` |
| `commitment-disputed.json` | Commitment with a formal disagreement entry |
| `update-delay.json` | Update with action "delay" targeting a commitment |
| `update-chain.json` | Three updates chained via `previousUpdateId` |
| `todo-list.json` | Todo list with mixed goal and task items |
| `todo-list-archived.json` | Archived todo list with completed items |
| `conversation-thread.json` | Three messages in a thread with `jacsMessagePreviousId` links |
| `agentstate-memory.json` | Signed MEMORY.md wrapper with file hash reference |
| `agentstate-hook.json` | Signed hook script with embedded content |

**Config examples** (in `docs/examples/`):

| File | Contents |
|------|----------|
| `jacs.config.filesystem.json` | Default filesystem-only configuration |
| `jacs.config.database.json` | PostgreSQL configuration with connection URL |
| `jacs.config.mixed.json` | Mixed storage: keys from filesystem, documents from database |
| `jacs.config.vector.json` | Database with vector search enabled |
| `docker-compose.yml` | PostgreSQL + pgvector setup for development |

---

## Benchmarks (Steps 277-278)

### Step 277: Core Operation Benchmarks

Using `criterion` (already present in `jacs/benches/`), add benchmarks in `jacs/benches/document_operations.rs`:

| Benchmark | What It Measures | Target |
|-----------|-----------------|--------|
| `bench_commitment_create` | Time to create and validate a minimal commitment | < 1ms |
| `bench_commitment_create_full` | Time to create a commitment with all optional fields | < 2ms |
| `bench_commitment_sign` | Time to sign a commitment (Ed25519) | < 5ms |
| `bench_commitment_sign_rsa` | Time to sign a commitment (RSA-PSS 2048) | < 20ms |
| `bench_commitment_verify` | Time to verify a signed commitment | < 5ms |
| `bench_agreement_two_agents` | Time for two agents to create and sign agreement | < 15ms |
| `bench_todo_create_10_items` | Time to create a todo list with 10 items | < 3ms |
| `bench_todo_create_100_items` | Time to create a todo list with 100 items | < 20ms |
| `bench_todo_add_item_resign` | Time to add one item and re-sign a 50-item list | < 10ms |
| `bench_update_create` | Time to create an update document | < 1ms |
| `bench_update_chain_verify_10` | Time to verify a chain of 10 linked updates | < 30ms |
| `bench_update_chain_verify_100` | Time to verify a chain of 100 linked updates | < 300ms |
| `bench_schema_validate_commitment` | Schema validation only (no signing) | < 0.5ms |
| `bench_schema_validate_todo_100` | Schema validation for 100-item todo list | < 5ms |
| `bench_agentstate_sign_1kb` | Sign a 1KB agent state document | < 5ms |
| `bench_agentstate_sign_100kb` | Sign a 100KB agent state document | < 10ms |

### Step 278: Database Operation Benchmarks

Feature-gated behind `database`. Add benchmarks in `jacs/benches/database_operations.rs`:

| Benchmark | What It Measures | Target |
|-----------|-----------------|--------|
| `bench_db_store_commitment` | Store one signed commitment in PostgreSQL | < 10ms |
| `bench_db_retrieve_commitment` | Retrieve one commitment by ID | < 5ms |
| `bench_db_store_batch_100` | Store 100 documents in a batch | < 500ms |
| `bench_db_query_by_type` | Query all documents of type "commitment" (100 docs) | < 50ms |
| `bench_db_query_commitments_by_status` | Filter commitments by status | < 20ms |
| `bench_db_query_updates_for_target` | Retrieve update chain for one commitment | < 10ms |
| `bench_db_query_overdue` | Query overdue commitments with date comparison | < 20ms |
| `bench_db_vector_search` | Cosine similarity search across 1000 documents | < 100ms |
| `bench_db_jsonb_query` | JSONB path query on nested fields | < 20ms |
| `bench_db_round_trip_verify` | Store, retrieve, and verify signature (full cycle) | < 20ms |
| `bench_db_migration_100_docs` | Import 100 filesystem docs to database | < 2s |

---

## Quality Checks (Steps 279-281)

### Step 279: Linting and Formatting

Run the following checks and require zero warnings/errors:

```bash
# Clippy with all features (must pass with zero warnings)
cargo clippy --all-features -- -D warnings

# Clippy without database features (catch any cfg issues)
cargo clippy -- -D warnings

# Format check (no modifications needed)
cargo fmt --all -- --check

# Check for unused dependencies
cargo +nightly udeps --all-features
```

**Specific clippy lints to verify are clean**:
- `clippy::unwrap_used` -- no unwrap in library code (tests are OK)
- `clippy::missing_docs` -- all public items documented
- `clippy::large_enum_variant` -- JacsError variants are reasonably sized
- `clippy::cognitive_complexity` -- no function exceeds threshold

### Step 280: WASM Compilation Check and Fuzz Testing

**WASM check**:
```bash
# Verify core compiles to WASM (no database features)
cargo check --target wasm32-unknown-unknown

# Verify with specific features that should work on WASM
cargo check --target wasm32-unknown-unknown --features wasm
```

All database-related code must be behind `#[cfg(all(not(target_arch = "wasm32"), feature = "database"))]`. The WASM check verifies none of it leaks into the WASM build.

**Fuzz testing** for schema validation (using `cargo-fuzz` or `arbitrary` crate):
- Fuzz `commitment.schema.json` validation with random JSON inputs (10,000 iterations minimum)
- Fuzz `update.schema.json` validation with random JSON inputs
- Fuzz `todo.schema.json` validation with random JSON inputs
- Fuzz `agentstate.schema.json` validation with random JSON inputs
- Fuzz the `jacsId` UUID parser with random strings
- Fuzz the date-time format validator with random strings
- Verify: no panics, no undefined behavior, all invalid inputs produce clean errors

### Step 281: Full Test Suite Pass and Version Bump

**Test run 1 -- without database** (the default developer experience):
```bash
cargo test
```
This MUST pass with zero failures. Every test that requires a database must be properly feature-gated so it is skipped here.

**Test run 2 -- with all features**:
```bash
cargo test --all-features
```
This runs every test including database integration tests (requires Docker for testcontainers or a local PostgreSQL instance).

**Test run 3 -- MCP server tests**:
```bash
cd jacs-mcp && cargo test
```

**Test run 4 -- binding tests**:
```bash
cd jacspy && pip install -e . && pytest
cd jacsnpm && npm install && npm test
```

**Version bump**:
- Update `Cargo.toml` version to `0.6.0` in all workspace members
- Update `jacs.config.schema.json` version field default
- Tag the release: `git tag -a v0.6.0 -m "JACS 0.6.0: Signed agent state, commitments, database storage"`

---

## Full Verification & Testing Strategy

### Test Categories

| Category | What It Tests | How to Run | Expected Count |
|----------|--------------|------------|----------------|
| Unit | Schema validation (positive + negative), CRUD operations, config parsing, error types | `cargo test` | 150+ |
| Schema Positive | Every valid enum value, optional field combinations, cross-references, all item types | `cargo test` | 60+ |
| Schema Negative | Missing required fields, invalid enum values, bad UUID format, malformed dates, oversized strings | `cargo test` | 40+ |
| Integration (DB) | Database storage, retrieval, queries, migrations, optimistic locking, vector search | `cargo test --features database,database-tests` | 30+ |
| End-to-End | Multi-agent lifecycle, round-trips, mixed storage, concurrency, migration | `cargo test --features database,database-tests` | 5 |
| MCP | Tool execution, JSON response format, error handling, all 17 new tools | `cargo test` (jacs-mcp crate) | 20+ |
| CLI | Command-line workflows for todo, commitment, update, conversation | `cargo test --features cli` | 15+ |
| Bindings | Python function calls and type checking, Node function calls, Go function calls | `cd jacspy && pytest` / `cd jacsnpm && npm test` | 30+ |
| WASM | Compilation check (no runtime execution) | `cargo check --target wasm32-unknown-unknown` | 1 (pass/fail) |
| Fuzz | Random input resilience for all schema validators | `cargo fuzz run schema_fuzz` | 10,000+ iterations |
| Regression | All pre-existing tests remain unchanged and passing | `cargo test` | 100+ (existing) |
| Benchmarks | Performance baselines for core and database operations | `cargo bench --features database` | 27 benchmarks |

### Key Verification Scenarios

These 10 scenarios represent the critical workflows that must work correctly for JACS 0.6.0 to ship. Each scenario is covered by one or more tests across the test categories above.

1. **Todo list lifecycle**: Create list with `create_todo_list()` -> add goal and task items via `add_todo_item()` -> mark items complete via `complete_todo_item()` -> archive completed items to dated list via `archive_completed_items()` -> verify every version of both lists is signed and versions chain via `jacsPreviousVersion`.

2. **Commitment agreement**: Agent A creates commitment via `create_commitment_with_terms()` -> Agent A signs -> Agent B calls `jacsSignAgreement()` -> verify both signatures are present in `jacsAgreement.signatures` -> attempt to modify committed terms -> verify modification is rejected (agreement hash mismatch).

3. **Commitment disagreement**: Agent A creates commitment -> Agent B formally disagrees via `jacsDisagreeAgreement()` with a reason string -> document enters "disputed" status -> verify disagreement entry is signed by Agent B -> Agent A creates amended commitment with updated terms -> Agent B agrees to amended version -> verify final state is "active" with both signatures.

4. **Update chain integrity**: Create commitment -> create "commit" update (action: "commit") -> create "inform" update (action: "inform", chains to previous) -> create "delay" update (action: "delay", chains to previous) -> create "close-success" update (action: "close-success", chains to previous) -> verify chain traversal via `previousUpdateId` yields correct order -> verify all 4 signatures are valid -> verify each update's `jacsUpdateTargetId` points to the same commitment.

5. **Conversation to commitment**: Create conversation thread via `create_message()` -> Agent A sends message -> Agent B replies (chained via `jacsMessagePreviousId`) -> Agent A replies -> create commitment referencing thread via `jacsCommitmentConversationRef` -> Agent B signs agreement -> Agent A creates "inform" update referencing the commitment -> verify the entire document graph is navigable from any starting point.

6. **Todo-to-commitment promotion**: Agent A creates private todo list with a goal item "Build OAuth2 integration" -> Agent A creates commitment with `jacsCommitmentTodoRef` pointing to that goal item -> Agent B signs agreement -> todo item gets `relatedCommitmentId` pointing back to the commitment -> verify bidirectional references are consistent -> verify the todo list was re-signed after adding `relatedCommitmentId`.

7. **Database round-trip with signatures**: Store a signed document (any type) in PostgreSQL via `DatabaseStorage` -> retrieve it -> verify `jacsSha256` matches the original -> verify `jacsSignature` passes validation -> tamper with one byte of the retrieved document -> verify signature validation NOW fails. This proves signatures are not just stored but actively verified.

8. **Storage migration (filesystem to database and back)**: Create signed documents on filesystem -> read and store in database -> verify signatures in database -> read from database and write to new filesystem location -> verify signatures on new filesystem copies -> verify cross-references between documents resolve correctly in both storage backends.

9. **Mixed storage with keys on filesystem**: Configure agent with keys on filesystem and documents in database via `JacsConfigProvider` -> create and sign a commitment (proves signing works with keys from FS) -> store in database (proves document storage works in DB) -> retrieve and verify (proves verification works with keys from FS and docs from DB) -> verify keys are NOT present in the database.

10. **Cross-language round-trip**: Create a commitment in Python via `jacspy` bindings -> verify the commitment in Rust via MCP tool `verify_commitment` -> create an update targeting the commitment from Node via `jacsnpm` bindings -> retrieve the update chain in Rust -> verify all signatures across all three languages produce consistent results.

---

## Schema Test Coverage Matrix

This matrix ensures every schema has comprehensive positive, negative, and integration test coverage. Each cell lists the specific test scenarios.

| Schema | Positive Tests | Negative Tests | Integration Tests |
|--------|---------------|----------------|-------------------|
| **Commitment** | minimal (description+status only), with terms (deliverable+deadline+compensation), with dates (start+end), with Q&A (question+answer), with completion Q&A (completionQuestion+completionAnswer), with recurrence (weekly, monthly, custom), with agreement (2 agents), with taskRef, with conversationRef, with todoRef, with owner, all 7 statuses (pending/active/completing/completed/cancelled/disputed/revoked), standalone (no refs), full (all fields populated) | invalid status value, future startDate > endDate, invalid date-time format (missing timezone), missing required jacsCommitmentDescription, missing required jacsCommitmentStatus, invalid UUID in todoRef, invalid UUID in taskId, empty description string, terms with negative compensation | signing by one agent, two-agent agreement workflow, immutability after agreement (reject modifications), disagreement workflow (disagree->amend->agree), status transitions via updates, version chain verification, re-signing on amendment |
| **Update** | minimal (action+target only), all 15 action types (commit/cancel/inform/delay/escalate/reassign/progress/pause/resume/request-review/approve/reject/close-success/close-failure/close-cancelled), all 3 target types (commitment/todo/agentstate), with note, with chain (previousUpdateId), with agent assignment (assignedAgentId) | invalid action type string, invalid target type string, non-UUID targetId, missing targetId, missing action, missing targetType, action+target mismatch (if applicable) | signing by authorized agent, chain verification (5+ updates), multi-agent updates on same target, header field population (jacsId, jacsVersion, dates), semantic category coverage (all 15 actions exercised in integration) |
| **Todo** | minimal (name+items), goal item (itemType:"goal"), task item (itemType:"task"), childItemIds (parent-child), all 5 statuses (pending/in-progress/completed/cancelled/archived), all 4 priorities (low/medium/high/critical), with commitment ref (relatedCommitmentId), with conversation ref, with archive refs (archivedListIds), with tags array, mixed items (goals+tasks), 100-item list | invalid status value, invalid itemType value, missing description on item, missing status on item, missing itemType on item, missing name on list, duplicate item IDs, invalid UUID in relatedCommitmentId, empty items array, comprehensive negative (multiple errors at once) | signing and re-signing on every mutation, version chain after 10 mutations, archive workflow (complete->archive->verify both lists), multiple lists per agent, todo-to-commitment promotion with bidirectional refs |
| **Conversation** | message with threadId, message ordering (jacsMessagePreviousId), multi-agent thread (3 agents), thread that produces commitment (jacsCommitmentConversationRef back-link) | (leverages existing message schema negative tests), missing threadId, invalid previousMessageId UUID, self-referencing previousMessageId | signing each message independently, multi-agent message verification, conversation retrieval by threadId, message ordering verification, conversation-to-commitment linking |
| **Agent State** | memory type, skill type, plan type, config type, hook type (with embedded content), origin: authored, origin: adopted, origin: generated, origin: imported, framework: "claude-code", framework: "openclaw", with file hash reference (jacsFiles), with embedded content, minimal (type only) | invalid type enum, missing type, hook without embedded content (must fail per Decision P0-3), invalid origin enum, invalid framework string, missing file reference for non-embedded types | signing and verification, re-signing on update, adopt workflow (Agent B adopts Agent A's skill), load from filesystem, verify after round-trip |

---

## How to Run Tests

```bash
# ============================================================
# BASIC: No database, no external dependencies
# Runs all unit tests, schema positive/negative tests, CRUD tests
# This is the default developer experience
# ============================================================
cargo test

# ============================================================
# DATABASE FEATURES COMPILED (but no DB tests executed)
# Verifies database code compiles without errors
# Useful for CI on PRs that touch database code
# ============================================================
cargo test --features database

# ============================================================
# FULL DATABASE INTEGRATION TESTS (local PostgreSQL)
# Requires a running PostgreSQL instance
# Set the URL to your test database (will be wiped!)
# ============================================================
export JACS_TEST_DATABASE_URL="postgres://user:pass@localhost:5432/jacs_test"
cargo test --features database,database-tests

# ============================================================
# FULL DATABASE INTEGRATION TESTS (Docker via testcontainers)
# Requires Docker running. Testcontainers auto-provisions a
# PostgreSQL instance, runs tests, then tears it down.
# No manual DB setup required.
# ============================================================
cargo test --features database,database-tests
# (auto-provisions PostgreSQL container if Docker is running)

# ============================================================
# WASM COMPILATION CHECK
# Verifies core library compiles to WebAssembly
# Database features must NOT leak into this build
# ============================================================
cargo check --target wasm32-unknown-unknown

# ============================================================
# ALL FEATURES (the full monty)
# Runs every single test including database, vector search, etc.
# Requires Docker or local PostgreSQL
# ============================================================
cargo test --all-features

# ============================================================
# CLIPPY (lint check -- must produce zero warnings)
# ============================================================
cargo clippy --all-features -- -D warnings

# ============================================================
# FORMAT CHECK (must produce no diff)
# ============================================================
cargo fmt --all -- --check

# ============================================================
# BENCHMARKS
# Runs all criterion benchmarks (core + database)
# Results saved to target/criterion/ for comparison
# ============================================================
cargo bench --features database

# ============================================================
# MCP SERVER TESTS
# Tests all 17+ MCP tools for correct execution and response format
# ============================================================
cd jacs-mcp && cargo test

# ============================================================
# PYTHON BINDINGS
# Installs jacspy in editable mode, runs pytest suite
# Covers all new document type operations
# ============================================================
cd jacspy && pip install -e . && pytest

# ============================================================
# NODE BINDINGS
# Installs jacsnpm dependencies, runs test suite
# Covers all new document type operations
# ============================================================
cd jacsnpm && npm install && npm test

# ============================================================
# GO BINDINGS
# Runs Go test suite for core binding functions
# ============================================================
cd jacsgo/lib && go test ./...

# ============================================================
# FUZZ TESTING (requires cargo-fuzz)
# Runs schema validation fuzz tests for 60 seconds each
# ============================================================
cargo fuzz run fuzz_commitment_schema -- -max_total_time=60
cargo fuzz run fuzz_update_schema -- -max_total_time=60
cargo fuzz run fuzz_todo_schema -- -max_total_time=60
cargo fuzz run fuzz_agentstate_schema -- -max_total_time=60

# ============================================================
# DOCUMENTATION BUILD (must produce zero warnings)
# ============================================================
cargo doc --all-features --no-deps

# ============================================================
# FULL RELEASE VALIDATION (run all of the above in sequence)
# ============================================================
cargo fmt --all -- --check \
  && cargo clippy --all-features -- -D warnings \
  && cargo test \
  && cargo test --all-features \
  && cargo check --target wasm32-unknown-unknown \
  && cargo doc --all-features --no-deps \
  && cargo bench --features database \
  && echo "All checks passed. Ready for v0.6.0 release."
```
