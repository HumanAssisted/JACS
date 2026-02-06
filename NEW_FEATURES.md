# JACS 0.6.0 Feature Enhancement Plan

## Signed Agent State, Todo Tracking, Database Storage, Runtime Configuration

**Date**: 2026-02-05
**Version**: 0.6.0
**Status**: Architecture complete, ready for implementation
**Total Steps**: 321+ (40 Phase 0 + 281 Phases 1-5, TDD-driven, phased)

---

## Table of Contents -- Phase Documents

| Phase | Document | Steps | Summary |
|-------|----------|-------|---------|
| **0** | [NEW_FEATURES_0.md](./NEW_FEATURES_0.md) | 0.1-0.40 (40) | **Signed Agent State Documents** -- Sign MEMORY.md, SKILL.md, plans, configs, hooks. Generic `agentstate.schema.json` wrapper. MCP tools for sign/verify/load/adopt. |
| **1** | [NEW_FEATURES_1.md](./NEW_FEATURES_1.md) | 1-95 (95) | **Schema Design & CRUD** -- Four document types: Commitment, Update, Todo List, Conversation enhancements. Agreement/Disagreement architecture. Cross-reference integrity. |
| **2** | [NEW_FEATURES_2.md](./NEW_FEATURES_2.md) | 96-175 (80) | **Database Storage Backend** -- Generic `DatabaseDocumentTraits` trait, PostgreSQL reference impl, vector search, MultiStorage integration, domain queries, index generator CLI. |
| **3** | [NEW_FEATURES_3.md](./NEW_FEATURES_3.md) | 176-225 (50) | **Runtime Configuration** -- `JacsConfigProvider` trait, `AgentBuilder` integration, HAI pattern, observability runtime config, backward compatibility. |
| **4** | [NEW_FEATURES_4.md](./NEW_FEATURES_4.md) | 226-261 (36) | **MCP & Bindings Integration** -- MCP server tools for all types, Python/Node/Go bindings, CLI integration. |
| **5** | [NEW_FEATURES_5.md](./NEW_FEATURES_5.md) | 262-281 (20) | **End-to-End, Docs & Polish** -- Integration tests, documentation, benchmarks, WASM verification, release. |

---

## The Big Idea: Signed Everything

**No agent framework signs its state files.** Claude Code's MEMORY.md, OpenClaw's SKILL.md, LangGraph's checkpoints -- all unsigned. Any process can modify them without detection.

JACS 0.6.0 changes this. Starting with **Phase 0**, every agent state file gets a cryptographically signed wrapper. Then Phases 1-5 add the document types needed for agent-to-agent collaboration: commitments (shared agreements), todo lists (private work tracking), updates (semantic change history), and conversations (signed message threads).

This positions JACS as the universal signing layer for ALL agent frameworks.

---

## Background & Motivation

### What JACS Is Today

JACS (JSON Agent Communication Standard) is a Rust library that creates cryptographic identity for AI agents. It provides:

- **Agent identity** via composite UUIDs (`agent_id:agent_version`)
- **Cryptographic signing** with RSA-PSS, Ed25519, Dilithium, ML-DSA-87
- **Document management** with JSON Schema Draft 7 validation
- **Multi-agent agreements** with immutable hash verification
- **Task lifecycle** with 7 states (creating -> completed)
- **Message system** with thread support
- **Multi-language bindings** (Rust core + Python/Node/Go/MCP)
- **Multi-backend storage** (Filesystem, S3, HTTP, Memory, Web localStorage)
- **12-Factor App configuration** (defaults -> config file -> env vars)

### Where the Ideas Come From

- **HAI-2024** (`/personal/HAI-2024/`): Python/FastAPI system that tracked commitments and todo lists. Used a hierarchical model: Goal > Task > Commitment with PostgreSQL + vector embeddings. **Key insights preserved: (a) todo lists are separate from commitments; (b) update tracking with 15 semantic action types provides critical audit trail for mediation; (c) goals are private todo items that become shared via commitments.**

- **libhai** (`/personal/libhai/`): Rust client library with database connectors (PostgreSQL via sqlx, DuckDB), HNSW vector indexes, document management wrapping JACS. Demonstrated the database storage pattern we want to bring into JACS core.

- **hai** (`/personal/hai/`): Production system using JACS 0.5.1 for 3-tier agent verification. Configures JACS via env vars at runtime, stores JACS documents in PostgreSQL. Shows what a JACS consumer needs from runtime configuration.

### Original Requirements

> 1. We want to use JACS to track todo lists. In 2024 we would track todo lists. You can look at the python code to see how we stored commitments - there are todo lists that are separate from plans/commitments. This is a key idea to retain.
>
> 2. libhai had connectors to various databases - not clear we need this, but we want to make sure it is easy - a mode where it doesn't read and write from the filesystem, instead is connected to a database for documents it saves and retrieves.
>
> 3. Keys and agent.json are always loaded from secure locations, like the filesystem or keyservers. It's not clear how loaders/db/telemetry is configured, but ideally it's runtime, not compile time because higher level libraries need this too.

---

## Codebase Exploration Findings

### JACS Current Architecture

**Workspace structure**: Monorepo with `jacs/` (core), `binding-core/`, `jacspy/`, `jacsnpm/`, `jacsgo/lib`, `jacs-mcp/`.

**Schema system**: JSON Schema Draft 7 files in `jacs/schemas/{type}/v1/{type}.schema.json`. Component schemas in `jacs/schemas/components/{type}/v1/{type}.schema.json`. Embedded at compile time via `include_str!()` in `phf_map!` in `src/schema/utils.rs:216`. Every document schema uses `allOf` with `header.schema.json`. The `Schema` struct in `src/schema/mod.rs:210` holds pre-compiled `Validator` instances.

**Existing schemas** (17 total):
- Top-level documents: agent, header, task, message, eval, node, program
- Components: signature, files, agreement, action, unit, tool, service, contact, embedding
- Config: jacs.config.schema.json

**Header fields** (from `header.schema.json`): `jacsId`, `jacsVersion`, `jacsVersionDate`, `jacsBranch`, `jacsType`, `jacsSignature`, `jacsRegistration`, `jacsAgreement`, `jacsAgreementHash`, `jacsPreviousVersion`, `jacsOriginalVersion`, `jacsOriginalDate`, `jacsSha256`, `jacsFiles`, `jacsEmbedding`, `jacsLevel` (enum: raw/config/artifact/derived). Required: jacsId, jacsType, jacsVersion, jacsVersionDate, jacsOriginalVersion, jacsOriginalDate, jacsLevel, $schema.

**CRUD pattern**: Each type has `{type}_crud.rs` in `src/schema/` (e.g., `task_crud.rs`) with `create_minimal_{type}()` returning `serde_json::Value`. Follow `task_crud.rs`, NOT `eval_crud.rs` (commented out, not wired in).

**Storage**: `MultiStorage` wraps `object_store` crate. `StorageType` enum: AWS, FS, HAI, Memory, WebLocal. `StorageDocumentTraits` is synchronous. Async bridged via `futures_executor::block_on()`.

### Agent Framework Landscape (No Signing Today)

| Framework | Memory File | Skill File | Plan File | Config File | Hook File | Signs Files? |
|-----------|------------|------------|-----------|-------------|-----------|-------------|
| **Claude Code** | MEMORY.md, CLAUDE.md | SKILL.md | plans/*.md | settings.json | hooks in settings | **No** |
| **OpenAI Codex** | AGENTS.md | -- | PLANS.md | -- | -- | **No** |
| **OpenClaw** | workspace memory | SKILL.md + scripts/ | -- | openclaw.plugin.json | -- | **No** |
| **LangGraph** | checkpoints (JSON/DB) | tool definitions | -- | -- | -- | **No** |
| **AutoGPT** | AutoGpt.json | -- | -- | ai_settings.yaml | -- | **No** |

---

## Review Findings

### DevRel Review
- **Commitment-first onboarding**: Commitments work standalone, hierarchy is optional
- **Dispute/revocation flow**: Added "disputed"/"revoked" statuses to commitment schema
- **Storage migration tooling**: Must ship with database support, not as afterthought
- **Language binding signatures early**: Validate API ergonomics before locking Rust implementation
- **Simplified CLI**: `jacs commitment create --description "..." --by "2026-03-01"` without ceremony

### Rust Systems Review
- **Async/sync bridging**: `DatabaseStorage` uses `tokio::runtime::Handle::block_on()` internally, keeping traits sync
- **WASM double-gating**: `#[cfg(all(not(target_arch = "wasm32"), feature = "database"))]` everywhere
- **Error handling**: Convert `sqlx::Error` to String at boundary, never change `JacsError` shape between features
- **Testing**: Feature-gated test modules + `testcontainers` for CI
- **Schema struct**: Add fields to existing `Schema` struct (pragmatic)
- **StorageBackend enum**: `ObjectStore(MultiStorage) | Database(Arc<DatabaseStorage>)`
- **Don't repeat eval_crud.rs anti-pattern**: Wire all new CRUD modules into `schema/mod.rs` properly

---

## Key Architectural Decisions

### Decision 1: Todo Lists Are Private, Commitments Are Shared
Todo lists belong to a single agent and are re-signed on every change. Commitments are shared between agents and use the agreement system. Mixing private mutable state with shared immutable agreements in one document would break signatures.

### Decision 2: Inline Items (Not Separate Documents) for Todo Lists
Todo items (goals, tasks) are inline within the todo list document, not separate JACS documents. The entire list is the signed unit. Version history provides the audit trail.

### Decision 3: Multiple Todo Lists Per Agent (Partitioned)
Agents can have multiple named todo lists, partitioned by context or time. Archiving completed items into dated lists keeps active lists performant while preserving history.

### Decision 4: Conversations Are Linked Messages, Not Nested Documents
Each message in a conversation is a separate signed document linked by thread ID. Messages come from different agents at different times.

### Decision 5: Goals Are Private Todo Items, Shared via Commitments
Goals are inline items (`itemType: "goal"`) within a private todo list. There is NO standalone goal.schema.json. When a goal needs to be shared between agents, it is expressed as a Commitment document.

### Decision 6: Update Tracking Preserves Semantic Context
Updates are independently signed documents with 15 semantic action types from HAI-2024. They chain via `previousUpdateId`. For mediation, knowing WHY something changed is as important as knowing WHAT changed.

### Decision 7: Generic Database Trait, Not Postgres-Specific
Define `DatabaseDocumentTraits` as a generic trait. Ship Postgres as the reference implementation.

### Decision 8: Sync Traits, Async Bridged Internally
`StorageDocumentTraits` and `DatabaseDocumentTraits` are sync. Database implementations bridge async internally via `Handle::block_on()`.

### Decision 9: Runtime Index Generator, Not Auto-Indexing
CLI tool generates recommended indexes. Users review and apply.

### Decision 10: Sign + Verify for MCP, Not Full Negotiation
MCP tools handle signing and verification. Negotiation happens in conversations.

### Decision 11: Keys Always From Secure Locations
Even with database storage, keys and agent.json load from filesystem or keyservers only.

### Decision 12: Formal Disagreement Is a Signed Cryptographic Action
Agents can formally DISAGREE by signing a disagreement entry. This is distinct from not signing (pending) and from agreeing. For mediation, "hasn't responded" vs "explicitly refuses" is critical.

### Decision 13: Agreement Hash Covers Terms, Not Status
`jacsAgreementHash` is computed from the document's TERMS (content fields) not from status or metadata. Agreement signatures survive status changes.

### Decision 14: Updates Drive Status Changes
When an agent creates an Update document targeting another document, JACS automatically creates a new version of the target with updated status. The Update is the API; the version change is the side effect.

### Decision 15: Completion Requires Multi-Agent Agreement
For shared documents (commitments), terminal status changes require agreement from ALL signing parties.

### Decision 16: Only Agreement Signers Can Create Updates
Only agents listed in a document's `jacsAgreement.agentIDs` can create Update documents targeting that document.

### Decision P0-1: Generic Schema, Not Per-Type Schemas
One `agentstate.schema.json` with `jacsAgentStateType` enum, not separate `memory.schema.json`, `skill.schema.json`, etc.

### Decision P0-2: `jacsFiles` for File References, Not Custom Fields
Reuse the existing `jacsFiles` array from header for file path + hash + embed.

### Decision P0-3: Hooks Always Embed Content
Hook-type agentstate documents MUST embed their code content to prevent TOCTOU attacks.

### Decision P0-4: Origin Tracking for Trust Differentiation
`jacsAgentStateOrigin` distinguishes authored, adopted, generated, and imported content.

### Decision P0-5: Framework Field for Cross-Platform Compatibility
`jacsAgentStateFramework` records which agent framework the file is for.

---

## Critical Files Reference

| File | Line | Role |
|------|------|------|
| `jacs/src/schema/mod.rs` | 210 | `Schema` struct -- add `agentstateschema`, `todoschema`, `commitmentschema`, `updateschema` Validator fields |
| `jacs/src/schema/mod.rs` | 16-24 | Module declarations -- add new CRUD module declarations |
| `jacs/src/schema/mod.rs` | 48 | `build_validator()` helper -- reuse for all new schemas |
| `jacs/src/schema/utils.rs` | 216 | `DEFAULT_SCHEMA_STRINGS` phf_map -- add new include_str! entries |
| `jacs/src/schema/utils.rs` | 235 | `SCHEMA_SHORT_NAME` phf_map -- add short name mappings |
| `jacs/src/schema/task_crud.rs` | 1-56 | Pattern to follow for CRUD modules |
| `jacs/src/storage/mod.rs` | 150 | `StorageType` enum -- add `Database` variant (cfg-gated) |
| `jacs/src/storage/mod.rs` | 145 | `MultiStorage` struct -- add database field |
| `jacs/src/storage/mod.rs` | 422-444 | `StorageDocumentTraits` -- extend with `DatabaseDocumentTraits` |
| `jacs/src/config/mod.rs` | whole | Config struct, 12-Factor loading -- add database_url, JacsConfigProvider trait |
| `jacs/src/error.rs` | whole | `JacsError` enum -- add `StorageError`, `DatabaseError` variants |
| `jacs/Cargo.toml` | 99 | Existing tokio optional dep -- `database` feature activates it |
| `jacs/schemas/message/v1/message.schema.json` | whole | Add `jacsMessagePreviousId` for ordering |
| `jacs/schemas/components/agreement/v1/agreement.schema.json` | whole | Extend with disagreements array |
| `jacs/schemas/header/v1/header.schema.json` | whole | Header with jacsEmbedding, jacsAgreement |
| `jacs-mcp/` | whole | MCP server -- add all new tools |
| `jacspy/` | whole | Python bindings -- expose new functions |
| `jacsnpm/` | whole | Node bindings -- expose new functions |

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
