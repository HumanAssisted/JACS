# NEW_FEATURES.md - JACS Feature Enhancement Plan

## Todo Tracking, Database Storage, Runtime Configuration

**Date**: 2026-02-05
**Status**: Architecture refined through Q&A + restored removed items, ready for implementation
**Estimated Steps**: 281+ (TDD-driven, phased)

---

## Table of Contents

1. [Background & Motivation](#background--motivation)
2. [Original Requirements](#original-requirements)
3. [Architecture: The Four Document Types](#architecture-the-four-document-types)
4. [Architecture: Database Storage](#architecture-database-storage)
5. [Architecture: Runtime Configuration](#architecture-runtime-configuration)
6. [Architecture: MCP Integration](#architecture-mcp-integration)
7. [Codebase Exploration Findings](#codebase-exploration-findings)
8. [Review Findings](#review-findings)
9. [Key Architectural Decisions](#key-architectural-decisions)
10. [Critical Files Reference](#critical-files-reference)
11. [Phase 1: Schema Design & CRUD](#phase-1-schema-design--crud-steps-1-95)
12. [Phase 2: Database Storage Backend](#phase-2-database-storage-backend-steps-96-175)
13. [Phase 3: Runtime Configuration](#phase-3-runtime-configuration-steps-176-225)
14. [Phase 4: MCP & Bindings Integration](#phase-4-mcp--bindings-integration-steps-226-261)
15. [Phase 5: End-to-End, Docs & Polish](#phase-5-end-to-end-docs--polish-steps-262-281)
16. [Verification & Testing Strategy](#verification--testing-strategy)
17. [How to Run Tests](#how-to-run-tests)

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

---

## Original Requirements

> 1. We want to use JACS to track todo lists. In 2024 we would track todo lists. You can look at the python code to see how we stored commitments - there are todo lists that are separate from plans/commitments. This is a key idea to retain.
>
> 2. libhai had connectors to various databases - not clear we need this, but we want to make sure it is easy - a mode where it doesn't read and write from the filesystem, instead is connected to a database for documents it saves and retrieves.
>
> 3. Keys and agent.json are always loaded from secure locations, like the filesystem or keyservers. It's not clear how loaders/db/telemetry is configured, but ideally it's runtime, not compile time because higher level libraries need this too.

---

## Architecture: The Four Document Types

Through iterative design review and Q&A, we identified **four distinct document types** that JACS needs to support. Each has different ownership, signing, and lifecycle semantics.

**Design principle: Goals are NOT standalone documents.** Goals are todo items (`itemType: "goal"`) within a private todo list. When a goal needs to be SHARED between agents, you create a Commitment referencing that todo item. The Commitment carries the agreement/disagreement mechanism. This keeps the schema count minimal while preserving full functionality.

### 1. Todo List (Private, Inline Items, Versioned)

**What it is**: A todo list is a PRIVATE document belonging to a single agent. It contains inline items -- goals (broad, long-term objectives) and tasks (smaller, detailed actions). The entire list is one signed document.

**Why we want it**: In HAI-2024, agents tracked their work via todo lists. An agent needs a private, signed record of what it intends to do, what's in progress, and what's done. This is the agent's internal state -- not shared with other agents.

**How it works**:
- Each todo list is a single signed JACS document with its own `jacsId` and `jacsVersion`
- Items are inline within the document (not separate documents). This is like how `task.schema.json` embeds `jacsTaskActionsDesired` inline as an array of action objects
- Goals are broad items (e.g., "Ship Q1 features") that may contain or reference smaller tasks (e.g., "Write auth module", "Add tests")
- Items have states (pending, in-progress, completed, abandoned)
- When anything changes (item added, completed, reprioritized), the ENTIRE list is re-signed with a new `jacsVersion`. The version history provides the audit trail.
- An agent can have **multiple todo lists** -- partitioned by context (e.g., "active work", "completed-2026-01", "completed-2026-02"). Over time, completed items accumulate. Archiving completed items into dated lists keeps active lists performant.
- Todo lists reference each other and reference commitments/conversations by UUID
- Todo items can reference Commitment documents (via `relatedCommitmentId`) when a private goal/task has been formalized into a shared agreement
- **Each todo item has a stable UUID (`itemId`)** for referencing. References between items use `itemId` (not array indices) so they survive list mutations.

**How goals become shared**: An agent has a private goal in their todo list. When they need another agent to commit to it, they create a Commitment document. The commitment's `jacsCommitmentTodoRef` points to `list-uuid:item-uuid`. The todo item's `relatedCommitmentId` points back. The commitment carries the `jacsAgreement` with agreement/disagreement mechanism.

**Tree structure**: Todo items form a tree by level of abstraction. Goals (broad) have `childItemIds` pointing to sub-goals and tasks (detailed). This tree is within a single list or across lists (by referencing items in other lists via `list-uuid:item-uuid`).

**Schema design considerations**:
- Uses existing JSON Schema `$ref` composition: todo items reference the todoitem component schema for structure
- The list document uses `allOf` with `header.schema.json` for standard JACS fields
- Items within the list are defined as a JSON array of objects with their own sub-schema
- Goals vs tasks within the list: goals are items with `itemType: "goal"`, tasks are items with `itemType: "task"`. Goals can have `childItemIds` referencing other items by UUID.
- Each item has a stable `itemId` (UUID) assigned on creation, immutable across re-signing
- `jacsLevel: "config"` (private working document, not derived)

**Example structure**:
```json
{
  "$schema": "https://hai.ai/schemas/todo/v1/todo.schema.json",
  "jacsId": "uuid-of-this-list",
  "jacsVersion": "version-uuid",
  "jacsType": "todo",
  "jacsLevel": "config",
  "jacsTodoName": "Active Work",
  "jacsTodoItems": [
    {
      "itemId": "item-uuid-aaa",
      "itemType": "goal",
      "description": "Ship Q1 features",
      "status": "active",
      "childItemIds": ["item-uuid-bbb", "item-uuid-ccc"]
    },
    {
      "itemId": "item-uuid-bbb",
      "itemType": "task",
      "description": "Write auth module",
      "status": "completed",
      "completedDate": "2026-01-15T10:00:00Z"
    },
    {
      "itemId": "item-uuid-ccc",
      "itemType": "task",
      "description": "Add integration tests",
      "status": "in-progress",
      "assignedAgent": "agent-uuid",
      "relatedCommitmentId": "commitment-uuid"
    }
  ],
  "jacsTodoArchiveRefs": ["completed-2026-01-list-uuid"],
  "jacsSignature": { ... }
}
```

### 2. Commitment (Shared, Agreement-Based, Standalone)

**What it is**: A commitment is a SHARED document representing a binding agreement between agents. It contains specific terms, dates, amounts, and conditions. Multi-agent signing uses the existing `jacsAgreement` system.

**Why we want it**: When agents negotiate and agree to do something, we need a cryptographically signed record of what was agreed, by whom, and when. This is the foundation for accountability and conflict resolution. Unlike todo lists (which are private), commitments are shared between all parties.

**How it works**:
- Each commitment is a standalone signed JACS document
- Multi-agent commitments use the existing `agreement.schema.json` component -- the `jacsAgreement` field requires signatures from all specified `agentIDs`
- A commitment can reference the conversation thread that produced it (via UUID to a message thread)
- A commitment can reference a todo list item (via `jacsCommitmentTodoRef: "list-uuid:item-uuid"`) -- this is how private goals become shared commitments
- A commitment can reference a task (via `jacsCommitmentTaskId`) but this is optional -- commitments work standalone
- Commitments are effectively immutable once all parties sign the agreement. If terms need to change, a NEW commitment is created (possibly referencing the old one)
- Status tracks the commitment lifecycle: pending (proposed), active (all parties signed), completed, failed, renegotiated, disputed, revoked
- Question/Answer fields support structured prompts: `jacsCommitmentQuestion`/`jacsCommitmentAnswer` for the initial agreement, `jacsCommitmentCompletionQuestion`/`jacsCommitmentCompletionAnswer` for completion verification
- Recurrence patterns for recurring commitments (e.g., weekly standup)
- Owner signature field for single-agent commitments

**Why separate from todo lists**: Todo lists are private and mutable (re-signed on each change). Commitments are shared and effectively immutable once agreed. Mixing these in one document would mean a private todo change invalidates a shared agreement's signature. They MUST be separate documents.

**Schema design considerations**:
- Uses `allOf` with `header.schema.json` for standard JACS fields
- References `agreement.schema.json` component via `$ref` for multi-agent signing
- References `signature.schema.json` component for individual agent signatures (owner)
- Can reference a conversation thread via UUID (the negotiation that led to this commitment)
- Can reference todo list items via `list-uuid:item-uuid` (what this commitment fulfills)
- Dispute/revocation fields per DevRel review: `jacsCommitmentDisputeReason`
- `jacsAgreement.disagreements` array for formal disagreement (see Agreement architecture section)

**Example structure**:
```json
{
  "$schema": "https://hai.ai/schemas/commitment/v1/commitment.schema.json",
  "jacsId": "commitment-uuid",
  "jacsVersion": "version-uuid",
  "jacsType": "commitment",
  "jacsLevel": "config",
  "jacsCommitmentDescription": "Agent A delivers Q1 report to Agent B by March 1, 2026",
  "jacsCommitmentTerms": {
    "deliverable": "Q1 financial report",
    "deadline": "2026-03-01T17:00:00Z",
    "format": "PDF",
    "compensation": { "amount": 500, "currency": "USD" }
  },
  "jacsCommitmentQuestion": "Do you agree to deliver the Q1 report by March 1?",
  "jacsCommitmentAnswer": "Yes, I agree to the terms.",
  "jacsCommitmentStatus": "active",
  "jacsCommitmentStartDate": "2026-01-15T00:00:00Z",
  "jacsCommitmentEndDate": "2026-03-01T17:00:00Z",
  "jacsCommitmentConversationRef": "thread-uuid-of-negotiation",
  "jacsCommitmentTodoRef": "todo-list-uuid:item-uuid-aaa",
  "jacsCommitmentOwner": { "agentID": "agent-a-uuid", "signature": "..." },
  "jacsAgreement": {
    "agentIDs": ["agent-a-uuid", "agent-b-uuid"],
    "question": "Do you agree to these terms?",
    "context": "Negotiated in thread thread-uuid",
    "signatures": [
      { "agentID": "agent-a-uuid", "signature": "...", "date": "..." },
      { "agentID": "agent-b-uuid", "signature": "...", "date": "..." }
    ]
  },
  "jacsSignature": { ... }
}
```

### 3. Conversation (Linked Messages, Individually Signed)

**What it is**: A conversation is a series of individually signed message documents linked by a thread ID. Each statement in the conversation is its own JACS document with its own signature. This uses the existing `message.schema.json`.

**Why we want it**: When agents negotiate, discuss, or exchange information, every statement needs to be independently verifiable. "Agent A said X at time T" must be provable. You can't achieve this with a single document -- each statement needs its own signature.

**How it works**:
- Each message is a separate signed JACS document using `message.schema.json`
- Messages share a `threadID` to group into a conversation
- Messages reference the previous message in the thread for ordering (via `jacsMessagePreviousId`)
- A conversation is NOT a single document -- it's a collection of message documents with a shared thread ID
- When a conversation produces a commitment, the commitment references the thread ID
- Conversations can be between 2 or more agents

**Why this pattern for conversations (not nesting)**: If you nested messages inside a conversation document, adding a new message would invalidate the parent's signature. Each message must be independently signed because each comes from a different agent at a different time. The thread ID provides grouping without requiring a single signed container.

**How this relates to existing JACS**: `message.schema.json` already exists in JACS with `threadID`, `to`, `from`, `content`, `attachments`. The conversation pattern is already partially implemented via task messages and thread IDs. What's NEW is formalizing the link between conversations and commitments, adding `jacsMessagePreviousId` for ordering, and ensuring MCP tools can create/query message threads.

### 4. Update (Semantic Change Tracking, Independently Signed)

**What it is**: An update is an independently signed document that records a semantic change to another document (task, commitment, or todo list). Each update captures not just WHAT changed, but WHY -- using action types from HAI-2024.

**Why we want it**: When a todo list is re-signed, the version diff shows what changed but not WHY. For a mediation and conflict resolution platform, the WHY is critical. "Agent A delayed the commitment" vs "Agent A expressed doubt about the commitment" vs "Agent A informed about progress" are all different semantic actions that have different implications for dispute resolution. The 15 action types from HAI-2024 capture this rich context.

**Why this was temporarily removed and why it's back**: During Q&A, updates were replaced by "re-sign the todo list and version history provides the audit trail." This lost all semantic context for changes. The version history shows diffs, but a diff saying `status: "active" -> "failed"` doesn't tell you whether it was `close-fail` (deliberate failure), `close-reject` (rejection by counterparty), or `close-ignore` (abandoned/deprioritized). For mediation use cases, this semantic information is essential.

**How it works**:
- Each update is a separate signed JACS document (like messages in a conversation)
- Updates target a specific document by `jacsUpdateTargetId` (UUID) and `jacsUpdateTargetType` (enum: task, commitment, todo)
- Updates have an `jacsUpdateAction` with one of 15 semantic action types:
  - **Closure actions**: `close-success` (completed successfully), `close-ignore` (abandoned/deprioritized), `close-fail` (failed), `close-reject` (rejected by counterparty)
  - **Lifecycle actions**: `reopen` (reactivated), `commit` (committed to doing), `doubt` (expressing uncertainty), `assign` (assigned to agent)
  - **CRUD actions**: `create` (initial creation), `update` (modified content)
  - **Renegotiation actions**: `recommit` (recommitting after setback), `reschedule` (changing timeline), `delay` (explicit delay notification), `renegotiate` (changing terms)
  - **Information actions**: `inform` (progress update without status change)
- Updates chain via `jacsUpdatePreviousUpdateId` -- forming a linked list of changes to a document, enabling reconstruction of the full timeline
- Updates include an optional `jacsUpdateNote` for human-readable context
- A component schema defines the update fields, and a top-level schema wraps it with header for signing

**Why updates are separate documents (not embedded)**: Each update needs its own signature because updates come from different agents at different times. Agent A creates a commitment, Agent B sends an update with action `doubt`. These must be independently verifiable. Also, update chains can be queried independently (e.g., "show me all updates with action `delay` for commitments in Q1").

**Example structure**:
```json
{
  "$schema": "https://hai.ai/schemas/update/v1/update.schema.json",
  "jacsId": "update-uuid",
  "jacsVersion": "version-uuid",
  "jacsType": "update",
  "jacsLevel": "config",
  "jacsUpdateTargetId": "commitment-uuid",
  "jacsUpdateTargetType": "commitment",
  "jacsUpdateAction": "delay",
  "jacsUpdateNote": "Delivery delayed by 2 weeks due to dependency on external API. New target: March 15.",
  "jacsUpdatePreviousUpdateId": "previous-update-uuid",
  "jacsUpdateAssignedAgent": "agent-uuid",
  "jacsSignature": { ... }
}
```

### How The Four Types Reference Each Other

```
                    +--------------+
                    | Conversation |  (series of signed messages, threadID links them)
                    | msg1 -> msg2 |
                    |   -> msg3    |
                    +------+-------+
                           |
                           | commitment references threadId
                           v
                    +--------------+
                    | Commitment   |  (shared, agreement-signed by multiple agents)
                    | terms, dates |
                    | jacsAgreement|
                    +------+-------+
                           ^
                           | todo items reference commitments
                           |
+----------+        +--------------+        +--------+
|  Update  | -----> | Todo List    | -----> | Task   |
|  action  | targets| (private)    |  refs  |(exists)|
|  chain   |        | [goal items] |        +--------+
|  doubt/  |        |   [tasks]    |
|  delay/  |        +--------------+
|  inform  |              ^
+----------+              |
     |                    | also targets
     | also targets       | commitments, tasks
     | commitments,       |
     | tasks         -----+
```

- **Conversations produce commitments**: A negotiation thread leads to a signed agreement.
- **Commitments are shared agreements**: Created when a private goal/task needs multi-agent agreement. Todo items reference commitments via `relatedCommitmentId`.
- **Todo lists are private views**: An agent's private checklist. Contains goal items (broad) and task items (detailed). Goals that need sharing become Commitments.
- **Updates track semantic changes**: Any document (task, commitment, todo list) can have an update chain recording WHY changes happened.
- **All references are by UUID**: No nesting of signed documents inside other signed documents (that would break signatures on parent update).

---

## Architecture: Formal Agreement, Disagreement, and Conflict Resolution

### THIS IS A CORE DESIGN PRINCIPLE

JACS is a mediation and conflict resolution platform. The agreement system is not just "multi-agent signing" -- it is the foundation for formally recording consent, dissent, and conflict between agents. Three distinct states must be clearly distinguished:

### The Three Agreement States

**1. Pending (unsigned)**: An agent has been asked to agree but has NOT yet responded. This is the DEFAULT state when a document lists an agent in `jacsAgreement.agentIDs` but that agent has no entry in `jacsAgreement.signatures`. Pending means "hasn't seen it yet" or "hasn't decided yet."

**2. Agreed (signed affirmatively)**: An agent has formally, cryptographically signed the agreement. Their signature appears in `jacsAgreement.signatures`. This is irrevocable for that version -- the agent provably agreed at that point in time.

**3. Disagreed (signed refusal)**: An agent has formally, cryptographically signed a REFUSAL. This is NOT the same as pending. This is an active, signed statement: "I have reviewed this and I disagree." This must be a signed action (not just the absence of a signature) because:
- It proves the agent SAW the document (unlike pending, where they may not have)
- It creates an auditable record of dissent for mediation
- It prevents "I never saw it" defenses in disputes
- It distinguishes "hasn't responded" from "explicitly refused"

### How Disagreement Works

The existing `agreement.schema.json` component needs to be extended:

```json
{
  "signatures": [...],
  "agentIDs": ["agent-a-uuid", "agent-b-uuid"],
  "disagreements": [
    {
      "agentID": "agent-b-uuid",
      "reason": "Terms are unacceptable. Deadline is too short.",
      "date": "2026-02-05T10:00:00Z",
      "signature": "..."
    }
  ],
  "question": "Do you agree to these terms?",
  "context": "..."
}
```

**Key properties of disagreements:**
- A `disagreement` is cryptographically signed, just like an agreement signature. The agent proves they authored the refusal.
- The `reason` field is required -- you must state WHY you disagree. This is critical for mediation.
- A disagreement is for a specific `jacsVersion` of the document. If the document is amended (new version), the disagreement applies to the OLD version. The agent must re-evaluate the new version.
- An agent cannot both agree AND disagree on the same version. If they have a signature in `signatures`, they cannot also have an entry in `disagreements` for the same version.

### Document States Derived from Agreement

When a document has a `jacsAgreement`, its effective state depends on the agreement status:

| State | Condition | Meaning |
|-------|-----------|---------|
| **Draft** | No signatures, no disagreements | Proposed but no one has responded |
| **Partially Agreed** | Some signatures, not all required | Some agents agreed, others haven't responded |
| **Fully Agreed** | All required agents have signatures | Consensus reached, document is active |
| **Contested** | At least one disagreement exists | Explicit conflict -- an agent formally disagrees |
| **Mixed** | Some signatures AND some disagreements | Partial agreement with explicit dissent from others |

### Contested State and Conflict Resolution

When a document enters **Contested** state (any agent has formally disagreed):

1. The document's effective status should reflect the conflict (e.g., commitment status becomes "disputed")
2. An Update document with action type `close-reject` is automatically created (or should be created by the disagreeing agent)
3. The disagreement reason becomes part of the mediation record
4. Resolution requires either:
   - The original document is amended (new `jacsVersion`) with updated terms, and ALL agents re-evaluate
   - A new document is created superseding the contested one
   - A mediator/arbitrator creates an Update with resolution action

### Completion Requires Agreement

For commitments (the mechanism by which private goals become shared agreements), status changes to terminal states (`completed`, `failed`) require agreement from all signing parties:

- Agent A cannot unilaterally declare a commitment "completed" -- Agent B must also agree
- If Agent A says "completed" and Agent B says "not completed" (disagreement), the commitment enters "disputed" state
- This prevents one party from claiming success without the counterparty's confirmation
- The `jacsEndAgreement` pattern from `task.schema.json` already supports this: a separate agreement specifically for confirming completion

### How This Interacts with jacsVersion and Updates

**The commitment document itself is the source of truth for terms.** The agreement hash (`jacsAgreementHash`) covers the terms/content, NOT the status field. This means:

1. When agents sign the agreement, they sign the TERMS (description, dates, deliverables, compensation)
2. Status changes (pending -> active -> completed) create new `jacsVersion` but do NOT invalidate the agreement hash
3. `jacsAgreementHash` is computed from a subset of fields (the terms) not from the entire document
4. If the TERMS need to change, that's a new commitment (or a new version that requires re-signing the agreement)

**Updates drive status changes.** When an agent creates an Update document targeting a commitment:
1. The Update document is created and signed (records WHO did WHAT and WHY)
2. JACS automatically creates a new version of the target document with the updated status (new `jacsVersion`)
3. The agreement signatures survive because `jacsAgreementHash` only covers terms, not status
4. The Update chain provides the full semantic history

**Disagreements are recorded on the document itself**, not as separate Update documents. A formal disagreement modifies the `jacsAgreement.disagreements` array on the commitment (new `jacsVersion`). This is because disagreement is about the DOCUMENT ITSELF, not about a status change.

### Example: Full Commitment Lifecycle with Disagreement

```
1. Agent A creates commitment with terms, adds Agent B to agreement
   -> Status: "pending", Agreement: {agentIDs: [A, B], signatures: []}

2. Agent B reviews and DISAGREES
   -> New jacsVersion
   -> Status: "disputed"
   -> Agreement: {agentIDs: [A, B], signatures: [], disagreements: [{agentID: B, reason: "Deadline too short"}]}

3. Agent A creates new version with amended terms (longer deadline)
   -> New jacsVersion, new jacsAgreementHash (terms changed)
   -> Status: "pending" (reset because terms changed)
   -> Agreement: {agentIDs: [A, B], signatures: [], disagreements: []} (cleared for new version)

4. Agent B reviews amended terms and AGREES
   -> New jacsVersion
   -> Agreement: {agentIDs: [A, B], signatures: [B's sig]}

5. Agent A also signs
   -> New jacsVersion
   -> Status: "active" (both signed)
   -> Agreement: {agentIDs: [A, B], signatures: [B's sig, A's sig]}

6. Work proceeds. Agent A creates Update with action "delay"
   -> Update document created (signed by A)
   -> Commitment gets new jacsVersion with no status change (delay is informational)
   -> Agreement signatures survive (terms didn't change)

7. Agent A creates Update with action "close-success"
   -> Update document created (signed by A)
   -> Commitment status NOT yet "completed" -- needs Agent B's agreement
   -> jacsEndAgreement initiated: {agentIDs: [A, B], question: "Is this completed?", signatures: [A's sig]}

8. Agent B disagrees with completion
   -> jacsEndAgreement: {disagreements: [{agentID: B, reason: "Deliverable missing section 3"}]}
   -> Status: "disputed"

9. Agent A fixes and creates new Update with action "update"
   -> Then creates another Update with action "close-success"
   -> Agent B now agrees
   -> Status: "completed"
```

---

## Architecture: Database Storage

### What We Want

A generic database storage trait that any backend can implement. JACS ships with the trait definition and a PostgreSQL reference implementation, but users can implement it for any database in any programming language (via the language bindings).

### Why Generic Trait

- Different deployments need different databases (Postgres in production, SQLite for local dev, DuckDB for analytics)
- Higher-level libraries (hai, libhai) have their own database preferences
- The JACS core shouldn't be coupled to a specific database
- Language bindings (Python, Node, Go) may want to use their native database drivers

### How It Works

**The trait** (`DatabaseDocumentTraits`) extends the existing `StorageDocumentTraits` with database-specific operations:

```rust
/// Base trait (already exists): store, get, remove, list, exists
pub trait StorageDocumentTraits { ... }

/// Extended trait for database backends: adds query, search, indexing guidance
pub trait DatabaseDocumentTraits: StorageDocumentTraits {
    fn query_by_type(&self, jacs_type: &str, limit: usize, offset: usize) -> Result<Vec<JACSDocument>, ...>;
    fn query_by_field(&self, field_path: &str, value: &str) -> Result<Vec<JACSDocument>, ...>;
    fn search_text(&self, query: &str, jacs_type: Option<&str>) -> Result<Vec<JACSDocument>, ...>;
    fn search_vector(&self, vector: &[f32], limit: usize) -> Result<Vec<(JACSDocument, f32)>, ...>;
    fn suggest_indexes(&self, document_types: &[&str]) -> Result<Vec<IndexRecommendation>, ...>;
    fn count_by_type(&self, jacs_type: &str) -> Result<usize, ...>;
    fn get_versions(&self, jacs_id: &str) -> Result<Vec<JACSDocument>, ...>;
    fn get_latest(&self, jacs_id: &str) -> Result<JACSDocument, ...>;
    fn query_updates_for_target(&self, target_id: &str) -> Result<Vec<JACSDocument>, ...>;
    fn query_commitments_by_status(&self, status: &str) -> Result<Vec<JACSDocument>, ...>;
    fn query_todos_for_agent(&self, agent_id: &str) -> Result<Vec<JACSDocument>, ...>;
    fn query_overdue_commitments(&self) -> Result<Vec<JACSDocument>, ...>;
}
```

**The trait is sync**, matching the existing `StorageDocumentTraits` and `MultiStorage` pattern. Database implementations bridge async internally (e.g., Postgres uses `tokio::runtime::Handle::block_on()`).

**One active backend** at a time per agent. The "multiple databases" capability means different deployments choose different backends, not that one agent routes to multiple DBs simultaneously.

**Consistency with concurrent agents**: When multiple agent instances access the same database, consistency comes from the database itself (transactions, constraints). JACS uses **optimistic locking** via `jacsVersion` -- UPDATE WHERE jacs_version = expected_version, fail if another instance updated first.

### Runtime Index Generator

Instead of auto-creating indexes or shipping static SQL files, JACS provides a **runtime CLI tool** that generates recommended indexes:

```bash
# Generate Postgres-specific index recommendations for all new document types
jacs db suggest-indexes --backend postgres --types todo,commitment,update

# Output:
# Recommended indexes for PostgreSQL:
# -- For 'todo' documents:
# CREATE INDEX idx_todo_name ON jacs_document((file_contents->>'jacsTodoName')) WHERE jacs_type = 'todo';
# -- For 'commitment' documents:
# CREATE INDEX idx_commitment_status ON jacs_document((file_contents->>'jacsCommitmentStatus')) WHERE jacs_type = 'commitment';
# CREATE INDEX idx_commitment_deadline ON jacs_document((file_contents->'jacsCommitmentTerms'->>'deadline')) WHERE jacs_type = 'commitment';
# -- For 'update' documents:
# CREATE INDEX idx_update_target ON jacs_document((file_contents->>'jacsUpdateTargetId')) WHERE jacs_type = 'update';
# CREATE INDEX idx_update_action ON jacs_document((file_contents->>'jacsUpdateAction')) WHERE jacs_type = 'update';
```

The generator:
- Knows the schema for each document type (from the embedded schemas)
- Generates backend-specific SQL (Postgres JSONB indexes, SQLite JSON_EXTRACT, etc.)
- Outputs Postgres as the primary target (most common) plus generic field recommendations for other DBs
- Users review, customize, and apply the recommendations

### Storage Backend Selection

The existing `MultiStorage` / `StorageType` pattern is extended:

- `StorageType::FS` -- filesystem (existing, default)
- `StorageType::AWS` -- S3 (existing)
- `StorageType::HAI` -- HTTP (existing)
- `StorageType::Memory` -- in-memory (existing)
- `StorageType::Database` -- any `DatabaseDocumentTraits` implementation (NEW)

Configuration via `JACS_DEFAULT_STORAGE=database` + `JACS_DATABASE_URL=postgres://...`

Keys and agent.json ALWAYS load from filesystem or keyservers, regardless of document storage backend.

---

## Architecture: Runtime Configuration

### What We Want

A trait-based configuration system where higher-level libraries (hai, libhai, custom apps) provide JACS configuration at runtime. This formalizes the pattern hai already uses (setting env vars before initialization) into a clean, testable interface.

### Why Runtime, Not Compile-Time

- Higher-level libraries discover their configuration at startup (reading their own config files, env vars, cloud metadata)
- The same JACS binary should work in multiple environments (dev with SQLite, staging with Postgres, prod with managed Postgres)
- Observability backends should be toggleable without recompilation
- Compile-time feature flags gate dependency INCLUSION (does the binary contain sqlx?), runtime config gates ACTIVATION (is the database actually used?)

### How It Works

```rust
/// Higher-level libraries implement this trait to configure JACS at runtime.
///
/// SECURITY: No key-related methods. Keys always from filesystem/keyservers.
pub trait JacsConfigProvider: Send + Sync {
    fn get_config(&self) -> Result<Config, Box<dyn Error>>;
    fn get_storage_type(&self) -> Option<String>;
    fn get_database_url(&self) -> Option<String>;
    fn get_data_directory(&self) -> Option<String>;
    fn get_key_directory(&self) -> Option<String>;
    fn get_observability_config(&self) -> Option<ObservabilityConfig>;
}
```

**Override chain** (highest precedence last):
1. Built-in defaults
2. Config file (`jacs.config.json`)
3. Environment variables (`JACS_*`)
4. Runtime config provider (the trait)

**Agent initialization**:
```rust
let provider = Arc::new(MyAppConfigProvider::new());
let agent = AgentBuilder::new()
    .config_provider(provider)
    .build()?;
```

---

## Architecture: MCP Integration

### What We Want

All new todo/commitment/conversation/update functionality exposed as MCP tools in jacs-mcp, jacspy, and jacsnpm. These are low-level functions available in all MCP server implementations.

### What MCP Tools Expose

**Full CRUD** for all document types:
- `create_todo_list`, `get_todo_list`, `update_todo_list` (re-signs), `archive_todo_list`
- `create_commitment`, `get_commitment`, `list_commitments`
- `create_update`, `get_updates_for_target`, `get_update_chain`
- `create_message` (adds to conversation thread), `get_thread`

**Sign + Verify** for agreements:
- `sign_commitment` -- agent signs their part of a commitment's agreement
- `verify_commitment` -- verify all signatures on a commitment are valid
- `disagree_commitment` -- agent formally disagrees with signed reason
- Negotiation happens externally (in conversations, chat, etc.). JACS handles the crypto, not the negotiation flow.

**Workflow helpers**:
- `complete_todo_item` -- marks item complete, re-signs list
- `regenerate_todo_from_commitments` -- refreshes a todo list based on active commitments
- `create_update_for_commitment` -- creates a semantic update targeting a commitment
- `promote_todo_to_commitment` -- creates a commitment from a private todo item, linking via `jacsCommitmentTodoRef`

**Query & Search**:
- `list_todos_by_status` -- filter by item status
- `search_commitments` -- find commitments by text or semantic similarity
- `find_overdue_commitments` -- commitments past deadline that aren't completed
- `get_conversation_thread` -- retrieve all messages in a thread
- `query_updates_by_action` -- find updates by action type (e.g., all "delay" updates)
- `get_update_chain_for_target` -- full semantic history of changes to a document

---

## Codebase Exploration Findings

### JACS Current Architecture (from `/personal/jacs/`)

**Workspace structure**: Monorepo with `jacs/` (core), `binding-core/`, `jacspy/`, `jacsnpm/`, `jacsgo/lib`, `jacs-mcp/`.

**Schema system**: JSON Schema Draft 7 files in `jacs/schemas/{type}/v1/{type}.schema.json`. Component schemas in `jacs/schemas/components/{type}/v1/{type}.schema.json`. Embedded at compile time via `include_str!()` in `phf_map!` in `src/schema/utils.rs:216`. Every document schema uses `allOf` with `header.schema.json`. The `Schema` struct in `src/schema/mod.rs:210` holds pre-compiled `Validator` instances.

**Existing schemas** (17 total):
- Top-level documents: agent, header, task, message, eval, node, program
- Components: signature, files, agreement, action, unit, tool, service, contact, embedding
- Config: jacs.config.schema.json

**Header fields** (from `header.schema.json`): `jacsId`, `jacsVersion`, `jacsVersionDate`, `jacsBranch`, `jacsType`, `jacsSignature`, `jacsRegistration`, `jacsAgreement`, `jacsAgreementHash`, `jacsPreviousVersion`, `jacsOriginalVersion`, `jacsOriginalDate`, `jacsSha256`, `jacsFiles`, `jacsEmbedding`, `jacsLevel` (enum: raw/config/artifact/derived). Required: jacsId, jacsType, jacsVersion, jacsVersionDate, jacsOriginalVersion, jacsOriginalDate, jacsLevel, $schema.

**Document lifecycle**: `Schema::create()` assigns `jacsId`, `jacsVersion`, `jacsVersionDate`, etc. Then `Agent::create_document_and_load()` signs and hashes it. Documents stored via `MultiStorage` implementing `StorageDocumentTraits`.

**CRUD pattern**: Each type has `{type}_crud.rs` in `src/schema/` (e.g., `task_crud.rs`) with `create_minimal_{type}()` returning `serde_json::Value`. Follow `task_crud.rs`, NOT `eval_crud.rs` (commented out, not wired in).

**Storage**: `MultiStorage` wraps `object_store` crate. `StorageType` enum: AWS, FS, HAI, Memory, WebLocal. `StorageDocumentTraits` is synchronous. Async bridged via `futures_executor::block_on()`.

**Message system**: `message.schema.json` has `threadID`, `to`, `from`, `content`, `attachments`. Already supports conversation threading.

**Task system**: `task.schema.json` has 7 states (creating, rfp, proposal, negotiation, started, review, completed), `jacsStartAgreement` and `jacsEndAgreement` for multi-agent agreements, subtask/copy/merge references, action arrays.

**Eval system**: `eval.schema.json` references a task by `taskID`, has quality descriptions, quantification units. Uses its own `signature` field (not via header). Currently has an anti-pattern: `eval_crud.rs` is entirely commented out and not declared in `mod.rs`.

### HAI-2024 Python Patterns (from `/personal/HAI-2024/`)

- **Goal > Task > Commitment** hierarchy in PostgreSQL with vector embeddings
- **Commitment fields**: description, question/answer, completion question/answer, start/end dates, recurrence, owner signature, agreement reference
- **Update tracking** with 15 action types: close-success, close-ignore, close-fail, close-reject, reopen, commit, doubt, assign, create, update, recommit, reschedule, delay, inform, renegotiate
- **Update chaining**: each update references previous update, forming linked list per target
- **Key insight**: "Todo = manifestation of a goal and goal updates (regenerated, ORDER MATTERS)"

### libhai Patterns (from `/personal/libhai/`)

- PostgreSQL via `sqlx` with `PgPool`, `jacs_document` table with JSONB + vector columns
- Runtime config: `set_haiai_env_vars()` reads config file, sets env vars
- Token/evaluation metrics to file and PostgreSQL
- HNSW vector indexes for semantic search

### hai Production Usage (from `/personal/hai/`)

- JACS 0.5.1 for 3-tier agent verification badge system
- Runtime config via env vars, graceful degradation
- PostgreSQL for JACS document storage
- Gaps: no JACS-specific telemetry, no key rotation, no batch signing

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
- **Schema struct**: Add fields to existing `Schema` struct (pragmatic). Optional refactor to `HashMap<String, Validator>` + typed accessors as separate step.
- **StorageBackend enum**: `ObjectStore(MultiStorage) | Database(Arc<DatabaseStorage>)`
- **Don't repeat eval_crud.rs anti-pattern**: Wire all new CRUD modules into `schema/mod.rs` properly

---

## Key Architectural Decisions

### Decision 1: Todo Lists Are Private, Commitments Are Shared
**Choice**: Todo lists belong to a single agent and are re-signed on every change. Commitments are shared between agents and use the agreement system.
**Why**: Mixing private mutable state with shared immutable agreements in one document would break signatures. An agent updating their private todo shouldn't invalidate a shared commitment's signatures.

### Decision 2: Inline Items (Not Separate Documents) for Todo Lists
**Choice**: Todo items (goals, tasks) are inline within the todo list document, not separate JACS documents.
**Why**: A todo list is conceptually one thing -- a checklist. Making each item a separate signed document would create massive overhead for checking off a task. The entire list is the signed unit. Version history provides the audit trail.

### Decision 3: Multiple Todo Lists Per Agent (Partitioned)
**Choice**: Agents can have multiple named todo lists, partitioned by context or time.
**Why**: Over time, completed items accumulate. An active todo list from 2026-01 shouldn't carry every completed item from the past year. Archiving completed items into dated lists (e.g., "completed-2026-01") keeps active lists performant while preserving history.

### Decision 4: Conversations Are Linked Messages, Not Nested Documents
**Choice**: Each message in a conversation is a separate signed document linked by thread ID.
**Why**: Messages come from different agents at different times. Each needs its own signature for independent verification. Nesting messages in a container document would require re-signing the container for every new message, breaking all previous signatures.

### Decision 5: Goals Are Private Todo Items, Shared via Commitments
**Choice**: Goals are inline items (`itemType: "goal"`) within a private todo list. There is NO standalone goal.schema.json. When a goal needs to be shared between agents, it is expressed as a Commitment document.
**Why**: This keeps the schema count minimal. A private goal in a todo list doesn't need multi-agent signing -- it's one agent's plan. When sharing is needed, the Commitment document already has the full agreement/disagreement mechanism. The todo item's `relatedCommitmentId` links back to the shared commitment. This avoids duplicating the agreement system in a separate goal schema.

### Decision 6: Update Tracking Preserves Semantic Context
**Choice**: Updates are independently signed documents with 15 semantic action types from HAI-2024. They chain via `previousUpdateId`.
**Why**: For mediation and conflict resolution, knowing WHY something changed is as important as knowing WHAT changed. A version diff shows the state change; an update document records the intent. "delay" vs "doubt" vs "renegotiate" have very different implications for dispute resolution.

### Decision 7: Generic Database Trait, Not Postgres-Specific
**Choice**: Define `DatabaseDocumentTraits` as a generic trait. Ship Postgres as the reference implementation.
**Why**: Different deployments use different databases. The trait lets anyone implement storage for their database of choice. JACS core shouldn't be coupled to Postgres.

### Decision 8: Sync Traits, Async Bridged Internally
**Choice**: `StorageDocumentTraits` and `DatabaseDocumentTraits` are sync. Database implementations bridge async internally.
**Why**: The entire JACS codebase is synchronous. Making traits async would require rewriting every caller. Database impls use `Handle::block_on()` internally.

### Decision 9: Runtime Index Generator, Not Auto-Indexing
**Choice**: CLI tool generates recommended indexes. Users review and apply.
**Why**: Auto-indexing removes user control and may create unwanted indexes. Users know their query patterns better than JACS does. The generator provides intelligent recommendations based on schema knowledge.

### Decision 10: Sign + Verify for MCP, Not Full Negotiation
**Choice**: MCP tools handle signing and verification. Negotiation happens in conversations.
**Why**: Negotiation is a conversation between agents (back-and-forth messages). JACS records the conversation as signed messages. When agents reach agreement, they sign a commitment. JACS handles the crypto (sign, verify), not the negotiation logic.

### Decision 11: Keys Always From Secure Locations
**Choice**: Even with database storage, keys and agent.json load from filesystem or keyservers only.
**Why**: The attack surface for agent identity must be minimal. Database connections can be compromised. Filesystem permissions and keyserver authentication are better-understood security boundary.

### Decision 12: Formal Disagreement Is a Signed Cryptographic Action
**Choice**: Agents can formally DISAGREE with a document by signing a disagreement entry in `jacsAgreement.disagreements`. This is distinct from not signing (pending) and from agreeing (signing).
**Why**: For mediation, the difference between "hasn't responded" and "explicitly refuses" is critical. A signed disagreement proves the agent SAW the document, provides a required reason, and creates an auditable dissent record. This is the foundation of conflict resolution -- you cannot mediate without knowing who disagrees and why.

### Decision 13: Agreement Hash Covers Terms, Not Status
**Choice**: `jacsAgreementHash` is computed from the document's TERMS (content fields) not from status or metadata fields. Agreement signatures survive status changes.
**Why**: Status transitions (pending -> active -> completed) are lifecycle events, not term changes. If Agent A and B agreed to "deliver report by March 1", that agreement is valid whether the current status is "active" or "delayed". Only changes to the TERMS (description, dates, deliverables) require re-signing the agreement.

### Decision 14: Updates Drive Status Changes
**Choice**: When an agent creates an Update document targeting another document, JACS automatically creates a new version of the target with updated status. The Update is the API; the version change is the side effect.
**Why**: This ensures every status change has a corresponding signed Update with semantic context. You cannot change a document's status without recording WHY. The Update document is created first, then the target document is versioned. The Update chain is the authoritative semantic history.

### Decision 15: Completion Requires Multi-Agent Agreement
**Choice**: For shared documents (commitments), terminal status changes (completed, failed) require agreement from ALL signing parties. Unilateral completion claims are not possible.
**Why**: Agent A cannot declare a commitment "completed" without Agent B confirming. If they disagree on completion, the document enters "disputed" state. This uses the existing `jacsEndAgreement` pattern from task.schema.json. This is fundamental to fair mediation -- both parties must agree on outcomes.

### Decision 16: Only Agreement Signers Can Create Updates
**Choice**: Only agents listed in a document's `jacsAgreement.agentIDs` can create Update documents targeting that document.
**Why**: Updates have legal/mediation significance (recording delays, disputes, completions). Allowing arbitrary agents to create updates about other agents' commitments would undermine trust. The signing agent's identity is verified against the agreement's agent list.

---

## Critical Files Reference

| File | Line | Role |
|------|------|------|
| `jacs/src/schema/mod.rs` | 210 | `Schema` struct -- add `todoschema`, `commitmentschema`, `updateschema` Validator fields |
| `jacs/src/schema/mod.rs` | 16-24 | Module declarations -- add `pub mod todo_crud;`, `pub mod commitment_crud;`, `pub mod update_crud;`, `pub mod conversation_crud;`, `pub mod reference_utils;` |
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
| `jacs/schemas/message/v1/message.schema.json` | whole | Existing message schema -- add `jacsMessagePreviousId` for ordering |
| `jacs/schemas/components/agreement/v1/agreement.schema.json` | whole | Existing agreement schema -- used by commitments (extended with disagreements array) |
| `jacs/schemas/header/v1/header.schema.json` | whole | Header with jacsEmbedding, jacsAgreement -- used by all document types |
| `jacs-mcp/` | whole | MCP server -- add all new tools |
| `jacspy/` | whole | Python bindings -- expose new functions |
| `jacsnpm/` | whole | Node bindings -- expose new functions |

---

## Phase 1: Schema Design & CRUD (Steps 1-95)

> **Note**: Goals are NOT standalone documents. Goals are inline todo items (`itemType: "goal"`) within a private todo list. When goals need to be shared, they are expressed as Commitments. Therefore, commitment is the FIRST schema we implement -- it's the primary shared document type.

### Phase 1A: Commitment Schema (Steps 1-25)

**Step 1.** Write test `test_create_minimal_commitment` in `jacs/tests/commitment_tests.rs`.
- **Why**: TDD. Simplest commitment -- just a description and status.
- **What**: Call `create_minimal_commitment("Deliver Q1 report")`, assert `jacsCommitmentDescription`, `jacsCommitmentStatus` = "pending", NO requirement for goal/task/thread refs.

**Step 2.** Write test `test_commitment_with_terms` -- structured terms object.
- **Why**: Commitments have structured terms (deliverable, deadline, compensation).
- **What**: Create commitment with `jacsCommitmentTerms` object containing deadline, format, compensation.

**Step 3.** Write test `test_commitment_with_dates` -- date-time format validation.
- **Why**: Start/end dates must be valid date-time format.
- **What**: Create commitment with `jacsCommitmentStartDate` and `jacsCommitmentEndDate`, validate dates.

**Step 4.** Write test `test_commitment_invalid_date_format` -- rejects malformed dates.
- **Why**: Negative test for date-time format.
- **What**: Set dates to "not-a-date", validate, expect format error.

**Step 5.** Write test `test_commitment_question_answer` -- Q&A fields.
- **Why**: HAI-2024 used question/answer fields for structured prompts.
- **What**: Create commitment with `jacsCommitmentQuestion`, `jacsCommitmentAnswer`, validate.

**Step 6.** Write test `test_commitment_completion_question_answer` -- completion Q&A.
- **Why**: Separate question/answer for completion verification.
- **What**: Create commitment with `jacsCommitmentCompletionQuestion`, `jacsCommitmentCompletionAnswer`.

**Step 7.** Write test `test_commitment_recurrence` -- recurrence pattern.
- **Why**: Recurring commitments (e.g., weekly standup).
- **What**: Create commitment with `jacsCommitmentRecurrence: {frequency: "weekly", interval: 1}`, validate.

**Step 8.** Write test `test_commitment_with_agreement` -- multi-agent commitment.
- **Why**: Multi-agent commitments use existing agreement system.
- **What**: Create commitment, add `jacsAgreement` with two agent IDs, validate.

**Step 9.** Write test `test_commitment_linked_to_todo_item` -- optional todo item reference.
- **Why**: Commitments can reference the todo item they formalize into a shared agreement.
- **What**: Create commitment with `jacsCommitmentTodoRef: "todo-list-uuid:item-uuid"`, validate format.

**Step 10.** Write test `test_commitment_linked_to_task` -- optional task reference.
- **Why**: Commitments can reference a task they serve.
- **What**: Create commitment with `jacsCommitmentTaskId: "task-uuid"`, validate.

**Step 11.** Write test `test_commitment_references_conversation` -- thread reference.
- **Why**: Commitments can reference the negotiation thread that produced them.
- **What**: Create commitment with `jacsCommitmentConversationRef: "thread-uuid"`, validate.

**Step 12.** Write test `test_commitment_references_todo_item` -- todo ref.
- **Why**: An agent's todo item can link to the commitment it fulfills.
- **What**: Create commitment with `jacsCommitmentTodoRef: "todo-list-uuid:2"`, validate.

**Step 13.** Write test `test_commitment_status_lifecycle` -- all valid status transitions.
- **Why**: Status transitions: pending -> active -> completed (or failed/disputed/revoked).
- **What**: Test each valid status value: pending, active, completed, failed, renegotiated, disputed, revoked.

**Step 14.** Write test `test_commitment_invalid_status` -- rejects invalid status.
- **Why**: Negative test for status enum.
- **What**: Set status to "invalid", validate, expect enum error.

**Step 15.** Write test `test_commitment_dispute` -- dispute with reason.
- **Why**: DevRel review: dispute flow is critical for conflict resolution platform.
- **What**: Create active commitment, set status to "disputed", add `jacsCommitmentDisputeReason`, validate.

**Step 16.** Write test `test_commitment_standalone_without_refs` -- no goal/task/thread refs needed.
- **Why**: Commitments MUST work without any goal/task/thread references. This is commitment-first onboarding.
- **What**: Create commitment with only description + status, validate passes.

**Step 17.** Write test `test_commitment_owner_signature` -- single-agent commitment.
- **Why**: Not all commitments are multi-agent. Single-agent commitments use `jacsCommitmentOwner`.
- **What**: Create commitment with `jacsCommitmentOwner` signature ref, validate.

**Step 18.** Create schema file `jacs/schemas/commitment/v1/commitment.schema.json`.
- **What**: JSON Schema Draft 7, `allOf` with header. Properties:
  - `jacsCommitmentDescription` (string, REQUIRED)
  - `jacsCommitmentTerms` (object, optional) -- flexible terms object
  - `jacsCommitmentStatus` (enum: "pending", "active", "completed", "failed", "renegotiated", "disputed", "revoked", REQUIRED)
  - `jacsCommitmentDisputeReason` (string, optional)
  - `jacsCommitmentTaskId` (UUID string, optional) -- task this serves
  - `jacsCommitmentConversationRef` (UUID string, optional) -- thread that produced this
  - `jacsCommitmentTodoRef` (string, optional) -- "todo-list-uuid:item-uuid" format linking to private todo item
  - `jacsCommitmentQuestion` (string, optional) -- prompt question
  - `jacsCommitmentAnswer` (string, optional) -- answer to prompt
  - `jacsCommitmentCompletionQuestion` (string, optional)
  - `jacsCommitmentCompletionAnswer` (string, optional)
  - `jacsCommitmentStartDate` (date-time, optional)
  - `jacsCommitmentEndDate` (date-time, optional)
  - `jacsCommitmentRecurrence` (object: { frequency, interval }, optional)
  - `jacsCommitmentOwner` -- `$ref` to signature.schema.json (optional)
  - Uses `jacsAgreement` from header for multi-agent signing

**Step 19.** Add commitment schema to `Cargo.toml`, `DEFAULT_SCHEMA_STRINGS`, `SCHEMA_SHORT_NAME`.

**Step 20.** Add `commitmentschema: Validator` to `Schema` struct, compile in `Schema::new()`.

**Step 21.** Add `validate_commitment()` method.

**Step 22.** Create `src/schema/commitment_crud.rs`:
- `create_minimal_commitment(description: &str) -> Result<Value, String>`
- `create_commitment_with_terms(description: &str, terms: Value) -> Result<Value, String>`
- `update_commitment_status(commitment: &mut Value, new_status: &str) -> Result<(), String>`
- `set_commitment_answer(commitment: &mut Value, answer: &str) -> Result<(), String>`
- `set_commitment_completion_answer(commitment: &mut Value, answer: &str) -> Result<(), String>`
- `update_commitment_dates(commitment: &mut Value, start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> Result<(), String>`
- `dispute_commitment(commitment: &mut Value, reason: &str) -> Result<(), String>`
- `revoke_commitment(commitment: &mut Value, reason: &str) -> Result<(), String>`
- `set_conversation_ref(commitment: &mut Value, thread_id: &str) -> Result<(), String>`
- `set_todo_ref(commitment: &mut Value, todo_ref: &str) -> Result<(), String>`
- `set_task_ref(commitment: &mut Value, task_id: &str) -> Result<(), String>`
- Add `pub mod commitment_crud;` to `src/schema/mod.rs`.

### Phase 1A continued: Commitment Integration Tests (Steps 23-25)

**Step 23.** Write test `test_commitment_signing_workflow` -- create, sign, verify.
- **Why**: Full signing pipeline for commitments.
- **What**: Create commitment, sign via agent, verify signature intact.

**Step 24.** Write test `test_commitment_two_agent_agreement` -- agent A proposes, agent B signs agreement.
- **Why**: Multi-agent commitment is the core use case.
- **What**: Agent A creates commitment with agreement, Agent B signs, verify both signatures.

**Step 25.** Write test `test_commitment_immutable_after_agreement` -- content changes should fail verification.
- **Why**: Once both agents sign, modifying the commitment must invalidate signatures.
- **What**: Both agents sign, modify description, verify signature fails.

### Phase 1B: Update Tracking Schema (Steps 26-50)

**Step 26.** Write test `test_create_minimal_update` in `jacs/tests/update_tests.rs`.
- **Why**: TDD. Simplest update -- target ID, type, and action.
- **What**: Call `create_minimal_update("commitment-uuid", "commitment", "inform", "Progress update")`, assert fields present.

**Step 27.** Write test `test_update_all_action_types` -- every action type accepted.
- **Why**: Positive test covering all 15 HAI-2024 action types.
- **What**: For each of `close-success`, `close-ignore`, `close-fail`, `close-reject`, `reopen`, `commit`, `doubt`, `assign`, `create`, `update`, `recommit`, `reschedule`, `delay`, `inform`, `renegotiate`: create update, validate, assert success.

**Step 28.** Write test `test_update_invalid_action_type` -- rejects unknown action.
- **Why**: Negative test for action enum.
- **What**: Set `jacsUpdateAction` to "invalid-action", validate, expect error.

**Step 29.** Write test `test_update_all_target_types` -- every target type accepted.
- **Why**: Positive test covering all target types.
- **What**: For each of `task`, `commitment`, `todo`: create update targeting it, validate.

**Step 30.** Write test `test_update_invalid_target_type` -- rejects unknown target type.
- **Why**: Negative test for target type enum.
- **What**: Set `jacsUpdateTargetType` to "invalid", validate, expect error.

**Step 31.** Write test `test_update_references_parent_document` -- UUID target ref.
- **Why**: Updates target a specific document by ID.
- **What**: Create update with `jacsUpdateTargetId: "some-uuid"`, validate.

**Step 32.** Write test `test_update_invalid_target_not_uuid` -- rejects non-UUID target.
- **Why**: Negative test for UUID format.
- **What**: Set `jacsUpdateTargetId` to "not-a-uuid", validate, expect format error.

**Step 33.** Write test `test_update_with_note` -- optional note field.
- **Why**: Notes provide human-readable context for the update.
- **What**: Create update with `jacsUpdateNote: "Delayed due to dependency"`, validate.

**Step 34.** Write test `test_update_chain` -- chained via `jacsUpdatePreviousUpdateId`.
- **Why**: Updates form a linked list per target document.
- **What**: Create update1, create update2 with `jacsUpdatePreviousUpdateId: update1.jacsId`, validate chain.

**Step 35.** Write test `test_update_with_agent_assignment` -- `jacsUpdateAssignedAgent`.
- **Why**: Some actions involve assigning work to an agent.
- **What**: Create update with action "assign" and `jacsUpdateAssignedAgent: "agent-uuid"`, validate.

**Step 36.** Write test `test_update_missing_required_target_id` -- rejects missing target.
- **Why**: Negative test. Target ID is required.
- **What**: Create update without `jacsUpdateTargetId`, validate, expect error.

**Step 37.** Write test `test_update_missing_required_action` -- rejects missing action.
- **Why**: Negative test. Action is required.
- **What**: Create update without `jacsUpdateAction`, validate, expect error.

**Step 38.** Create component schema `jacs/schemas/components/update/v1/update.schema.json`:
- **What**: Component schema defining update fields:
  - `jacsUpdateTargetId` (UUID string, required) -- document being updated
  - `jacsUpdateTargetType` (enum: "task", "commitment", "todo", required) -- type of target
  - `jacsUpdateAction` (enum of 15 action types, required) -- semantic action
  - `jacsUpdateNote` (string, optional) -- human-readable context
  - `jacsUpdatePreviousUpdateId` (UUID string, optional) -- previous update in chain
  - `jacsUpdateAssignedAgent` (UUID string, optional) -- agent assigned (for "assign" action)

**Step 39.** Create top-level `jacs/schemas/update/v1/update.schema.json`.
- **What**: `allOf` with header.schema.json + `$ref` to update component schema. This makes updates full JACS documents with signatures, IDs, versions.

**Step 40.** Add update schemas (both component and top-level) to `Cargo.toml`.

**Step 41.** Add to `DEFAULT_SCHEMA_STRINGS` and `SCHEMA_SHORT_NAME`.

**Step 42.** Add `updateschema: Validator` to `Schema` struct, compile in `Schema::new()`.

**Step 43.** Add `validate_update()` method to `Schema`.

**Step 44.** Create `src/schema/update_crud.rs`:
- `create_minimal_update(target_id: &str, target_type: &str, action: &str, note: Option<&str>) -> Result<Value, String>`
- `create_task_update(task_id: &str, action: &str, note: Option<&str>) -> Result<Value, String>` -- convenience for task updates
- `create_commitment_update(commitment_id: &str, action: &str, note: Option<&str>) -> Result<Value, String>` -- convenience for commitment updates
- `create_todo_update(todo_id: &str, action: &str, note: Option<&str>) -> Result<Value, String>` -- convenience for todo updates
- `set_previous_update(update: &mut Value, previous_id: &str) -> Result<(), String>` -- chain updates
- `set_assigned_agent(update: &mut Value, agent_id: &str) -> Result<(), String>` -- set agent
- Add `pub mod update_crud;` to `src/schema/mod.rs`.

### Phase 1B continued: Update Integration Tests (Steps 45-50)

**Step 45.** Write test `test_update_signing_and_verification` -- full signing pipeline.
- **Why**: Updates must be independently signed for auditability.
- **What**: Create update, sign via agent, verify signature.

**Step 46.** Write test `test_update_chain_verification` -- chain of signed updates.
- **Why**: Update chains must be verifiable end-to-end.
- **What**: Create 3 updates chained by previousUpdateId, sign each, verify all signatures and chain integrity.

**Step 47.** Write test `test_update_from_different_agents` -- two agents update same target.
- **Why**: Multiple agents can submit updates about the same commitment.
- **What**: Agent A creates "inform" update, Agent B creates "doubt" update, both targeting same commitment. Verify independent signatures.

**Step 48.** Write test `test_update_header_fields_present` -- verify header fields populated.
- **Why**: Ensure update schema properly inherits header fields.
- **What**: Create and sign update, verify jacsId, jacsVersion, jacsVersionDate, etc.

**Step 49.** Write test `test_update_semantic_action_coverage` -- closure, lifecycle, renegotiation, info actions.
- **Why**: Ensure all categories of actions work with full signing pipeline.
- **What**: Create and sign one update for each category: `close-success`, `commit`, `reschedule`, `inform`.

**Step 50.** Run all update tests + regression.

### Phase 1C: Todo List Schema (Steps 51-75)

**Step 51.** Write test `test_create_minimal_todo_list` in `jacs/tests/todo_tests.rs`.
- **Why**: TDD. Test the simplest todo list creation.
- **What**: Call `create_minimal_todo_list("Active Work")`, assert JSON has `$schema`, `jacsType` = "todo", `jacsTodoName`, empty `jacsTodoItems` array, `jacsLevel` = "config".

**Step 52.** Write test `test_todo_list_with_goal_item` -- goal-type inline item.
- **Why**: Todo lists contain goals (broad, long-term items).
- **What**: Create list, add goal item with `itemType: "goal"`, `description: "Ship Q1 features"`, `status: "active"`.

**Step 53.** Write test `test_todo_list_with_task_item` -- task-type inline item.
- **Why**: Todo lists contain tasks (smaller, detailed items).
- **What**: Create list, add task item with `itemType: "task"`, `description: "Write auth module"`, `status: "pending"`.

**Step 54.** Write test `test_todo_goal_with_child_tasks` -- childItemIds referencing.
- **Why**: Goals reference child tasks within the same list by stable itemId UUID.
- **What**: Create list with a goal item and two task items. Set goal's `childItemIds: ["task-item-uuid-1", "task-item-uuid-2"]`. Verify structure.

**Step 55.** Write test `test_todo_item_all_valid_statuses` -- every item status accepted.
- **Why**: Positive test covering all status values.
- **What**: For each of `pending`, `in-progress`, `completed`, `abandoned`: create item, validate.

**Step 56.** Write test `test_todo_item_invalid_status` -- rejects invalid item status.
- **Why**: Negative test for item status enum.
- **What**: Set item status to "invalid", validate, expect error.

**Step 57.** Write test `test_todo_item_all_priorities` -- every priority accepted.
- **Why**: Positive test for priority enum.
- **What**: For each of `low`, `medium`, `high`, `critical`: create item, validate.

**Step 58.** Write test `test_todo_item_references_commitment` -- relatedCommitmentId.
- **Why**: Todo items can reference a commitment UUID (the shared agreement this task fulfills).
- **What**: Create task item with `relatedCommitmentId: "some-uuid"`, validate.

**Step 59.** Write test `test_todo_item_with_tags` -- tags for categorization.
- **Why**: Todo items can have tags for filtering and organizing.
- **What**: Create item with `tags: ["q1", "high-priority"]`, validate.

**Step 60.** Write test `test_todo_item_references_conversation` -- relatedConversationThread.
- **Why**: Items can link to conversation threads.
- **What**: Create item with `relatedConversationThread: "thread-uuid"`, validate.

**Step 61.** Write test `test_todo_list_archive_refs` -- archived list references.
- **Why**: Active lists reference archived completed lists.
- **What**: Create list with `jacsTodoArchiveRefs: ["completed-list-uuid"]`, validate.

**Step 62.** Write test `test_todo_list_schema_validation_rejects_invalid` -- multiple negative cases.
- **Why**: Comprehensive negative testing.
- **What**: Test missing `jacsTodoName`, invalid `itemType` (not "goal" or "task"), missing item `description`, missing item `status`.

**Step 63.** Write test `test_todo_item_missing_required_description` -- rejects item without description.
- **Why**: Negative test for required item field.
- **What**: Create item without `description`, validate, expect error.

**Step 64.** Write test `test_todo_item_missing_required_status` -- rejects item without status.
- **Why**: Negative test for required item field.
- **What**: Create item without `status`, validate, expect error.

**Step 65.** Write test `test_todo_item_missing_required_itemtype` -- rejects item without itemType.
- **Why**: Negative test for required item field.
- **What**: Create item without `itemType`, validate, expect error.

**Step 66.** Create schema file `jacs/schemas/todo/v1/todo.schema.json`.
- **What**: JSON Schema Draft 7 with `allOf` header reference. Properties:
  - `jacsTodoName` (string, required) -- name of this todo list
  - `jacsTodoItems` (array of objects, required) -- the items, each referencing todoitem component
  - `jacsTodoArchiveRefs` (array of UUID strings, optional) -- references to archived completed lists

**Step 67.** Create todo item component schema `jacs/schemas/components/todoitem/v1/todoitem.schema.json`.
- **Why**: The item structure is complex enough to be a reusable component (like action, service, etc.).
- **What**: Defines the item object:
  - `itemType` (enum: "goal", "task", required)
  - `description` (string, required)
  - `status` (enum: "pending", "in-progress", "completed", "abandoned", required)
  - `priority` (enum: "low", "medium", "high", "critical", optional)
  - `itemId` (UUID string, required) -- stable ID for this item, immutable across re-signing
  - `childItemIds` (array of UUID strings, optional) -- references to child items by itemId
  - `relatedCommitmentId` (UUID string, optional) -- commitment that formalizes this item
  - `relatedConversationThread` (UUID string, optional)
  - `completedDate` (date-time, optional)
  - `assignedAgent` (UUID string, optional)
  - `tags` (array of strings, optional)

**Step 68.** Add todo and todoitem schemas to `Cargo.toml` include list.

**Step 69.** Add to `DEFAULT_SCHEMA_STRINGS` phf_map.

**Step 70.** Add to `SCHEMA_SHORT_NAME` map.

**Step 71.** Add `todoschema: Validator` to `Schema` struct.

**Step 72.** Compile todo validator in `Schema::new()`.

**Step 73.** Add `validate_todo()` method to `Schema`.

**Step 74.** Create `src/schema/todo_crud.rs`:
- `create_minimal_todo_list(name: &str) -> Result<Value, String>` -- empty list
- `add_todo_item(list: &mut Value, item_type: &str, description: &str, priority: Option<&str>) -> Result<(), String>`
- `update_todo_item_status(list: &mut Value, item_id: &str, new_status: &str) -> Result<(), String>`
- `mark_todo_item_complete(list: &mut Value, item_id: &str) -> Result<(), String>` -- status -> completed + sets completedDate
- `add_child_to_item(list: &mut Value, parent_item_id: &str, child_item_id: &str) -> Result<(), String>`
- `set_item_commitment_ref(list: &mut Value, item_id: &str, commitment_id: &str) -> Result<(), String>`
- `add_archive_ref(list: &mut Value, archive_list_id: &str) -> Result<(), String>`
- `remove_completed_items(list: &mut Value) -> Result<Value, String>` -- returns removed items (for archiving)
- Add `pub mod todo_crud;` to `src/schema/mod.rs`.

### Phase 1C continued: Todo Integration Tests (Steps 75-80)

**Step 75.** Write test `test_todo_list_signing_and_verification` -- full signing pipeline.
- **Why**: Todo lists participate in standard JACS signing.
- **What**: Create list, sign via agent, verify.

**Step 76.** Write test `test_todo_list_update_and_resign` -- modify list, re-sign.
- **Why**: The core lifecycle -- modify list, re-sign, verify new signature.
- **What**: Create and sign list, add item, call update (bumps version + re-signs), verify.

**Step 77.** Write test `test_todo_list_versioning_on_update` -- version changes tracked.
- **Why**: Re-signing must bump jacsVersion.
- **What**: Create list, sign, note version, add item, re-sign, verify version changed.

**Step 78.** Write test `test_todo_list_archive_workflow` -- archive completed items.
- **Why**: Lifecycle of archiving completed items.
- **What**: Create list with completed/active items. Call `remove_completed_items()`. Create archive list. Add archive ref. Sign both.

**Step 79.** Write test `test_multiple_todo_lists_per_agent` -- agent has multiple lists.
- **Why**: Agents can have multiple lists (work, personal, archived).
- **What**: Create 3 lists with same agent, verify each has unique jacsId.

**Step 80.** Run all todo tests + regression.

### Phase 1D: Conversation Enhancements (Steps 81-87)

**Step 81.** Write test `test_create_conversation_message` in `jacs/tests/conversation_tests.rs`.
- **Why**: Verify message creation with thread ID for conversation grouping.
- **What**: Create message with `threadID`, sign, verify.

**Step 82.** Write test `test_conversation_thread_ordering` -- previousId chain.
- **Why**: Messages in a thread must be orderable.
- **What**: Create 3 messages in same thread, each referencing previous via `jacsMessagePreviousId`. Verify chain.

**Step 83.** Write test `test_conversation_produces_commitment` -- core workflow.
- **Why**: Negotiation thread leads to signed commitment.
- **What**: Create message thread between 2 agents, create commitment referencing thread ID, sign agreement.

**Step 84.** Write test `test_conversation_message_from_different_agents` -- multi-agent.
- **Why**: Conversations are between multiple agents; each signs their own messages.
- **What**: Agent A creates message 1, agent B creates message 2 (same thread). Verify each signature independently.

**Step 85.** Review/enhance `message.schema.json` for conversation support.
- **What**: Add `jacsMessagePreviousId` (UUID string, optional) for message ordering within a thread.

**Step 86.** Create `src/schema/conversation_crud.rs`:
- `create_conversation_message(thread_id: &str, content: &str, previous_message_id: Option<&str>) -> Result<Value, String>`
- `start_new_conversation(content: &str) -> Result<(Value, String), String>` -- returns (message, new_thread_id)
- `get_thread_id(message: &Value) -> Result<String, String>`
- Add `pub mod conversation_crud;` to `src/schema/mod.rs`.

**Step 87.** Run all conversation tests + regression.

### Phase 1E: Cross-References, Integrity, and Full Workflow (Steps 88-95)

**Step 88.** Write test `test_todo_references_valid_commitment` -- todo item refs resolve.
- **What**: Create commitment, create todo with reference, verify reference resolves.

**Step 89.** Write test `test_commitment_references_valid_thread` -- commitment thread ref resolves.

**Step 90.** Write test `test_update_references_valid_target` -- update target ID resolves.

**Step 91.** Write test `test_cross_reference_integrity_check` -- utility function validates all UUID references.
- **What**: `validate_references(doc, storage)` returns list of references with status (valid, missing, wrong_type).

**Step 92.** Create `src/schema/reference_utils.rs`:
- `validate_references(doc: &Value, storage: &impl StorageDocumentTraits) -> Result<Vec<ReferenceValidation>, ...>`
- Add `pub mod reference_utils;` to `src/schema/mod.rs`.

**Step 93.** Write test `test_full_workflow_conversation_to_commitment_to_todo_with_updates` -- end-to-end.
- **Why**: Integration of all four document types.
- **What**: Agent A and B converse (messages in thread) -> agree on commitment (signed agreement) -> commitment linked to todo item via todoRef -> Agent A adds task to todo referencing commitment -> Agent B creates "inform" update on commitment -> Agent A creates "delay" update -> verify all signatures and references.

**Step 94.** **API ergonomics validation**: Write Python/Node binding function signatures for all four types.
- **Why**: Validate Rust API translates cleanly.
- **What**: In `jacspy/`, define: `create_commitment()`, `create_update()`, `create_todo_list()`, `add_todo_item()`, `start_conversation()`, `promote_todo_to_commitment()`, etc.

**Step 95.** Run full Phase 1 test suite: `cargo test`. All existing + new tests pass.

---

## Phase 2: Database Storage Backend (Steps 96-175)

### Phase 2A: Generic Database Trait (Steps 96-115)

**Step 96.** Write test `test_database_document_traits_definition` -- trait is object-safe and can be used as `dyn DatabaseDocumentTraits`.

**Step 97.** Define `DatabaseDocumentTraits` trait in `src/storage/database_traits.rs`.

**Step 98.** Write test `test_database_document_traits_with_mock` -- mock implementation validates trait contract.

**Step 99.** Add `DatabaseError { operation: String, reason: String }` and `StorageError(String)` to `JacsError` enum.

**Step 100.** Write test `test_jacs_error_send_sync` -- verify JacsError remains Send + Sync.

**Step 101.** Add `StorageType::Database` variant (cfg-gated).

**Step 102.** Add sqlx optional dep in `Cargo.toml` under wasm32-excluded section.

**Step 103.** Add pgvector optional dep, define feature flags: `database = ["dep:sqlx", "dep:tokio"]`, `database-vector = ["database", "dep:pgvector"]`.

**Step 104.** Create `src/storage/database.rs` -- `DatabaseStorage` struct with `PgPool` + `tokio::runtime::Handle`.

**Step 105.** Define SQL migration: `jacs_document` table (jacs_id UUID, jacs_version UUID, agent_id UUID, jacs_type TEXT, file_contents JSONB, timestamps, PK on jacs_id+jacs_version).

**Step 106.** Define vector migration (behind `database-vector`): vector column + HNSW index.

**Step 107.** Implement `StorageDocumentTraits` for `DatabaseStorage`: store, get, remove, list, exists, get_by_agent, get_versions, get_latest. Convert `sqlx::Error` to `JacsError::DatabaseError { operation, reason }` at boundary.

**Step 108.** Implement `DatabaseDocumentTraits` for `DatabaseStorage`: query_by_type, query_by_field, search_text, count_by_type, query_updates_for_target, query_commitments_by_status, query_todos_for_agent, query_overdue_commitments.

**Step 109.** Add `pub mod database;` and `pub mod database_traits;` to `src/storage/mod.rs` (cfg-gated).

**Step 110.** Write integration test `test_database_storage_new_connection` (feature-gated + testcontainers).

**Step 111.** Write test `test_database_storage_migration`.

**Step 112.** Write test `test_database_store_and_retrieve`.

**Step 113.** Write test `test_database_list_by_type`.

**Step 114.** Write test `test_database_query_updates_for_target` -- retrieve update chain from DB.

**Step 115.** Write test `test_database_query_commitments_by_status`.

### Phase 2B: Vector Search (Steps 116-130)

**Step 116.** Write test `test_database_vector_storage`.

**Step 117.** Write test `test_database_vector_search` (cosine similarity).

**Step 118.** Add vector storage/search methods to `DatabaseStorage`.

**Step 119.** Write test `test_vector_search_by_type`.

**Step 120.** Write test `test_vector_search_ranking`.

**Step 121.** Add `extract_embedding_vector()` utility.

**Step 122.** Write test `test_extract_embedding_from_document`.

**Step 123.** Auto-extract embeddings on store.

**Step 124.** Write test `test_auto_vector_extraction_on_store`.

**Step 125.** Add JSONB query methods: `query_documents_jsonb()`.

**Step 126.** Write test `test_jsonb_query_commitment_status`.

**Step 127.** Write test `test_jsonb_query_commitments_by_date_range`.

**Step 128.** Add pagination (offset/limit).

**Step 129.** Write test `test_paginated_query`.

**Step 130.** Run full vector search integration suite.

### Phase 2C: MultiStorage Integration (Steps 131-150)

**Step 131.** Write test `test_multi_storage_with_database`.

**Step 132.** Modify `MultiStorage::_new()` for `StorageType::Database`.

**Step 133.** Add `database: Option<Arc<DatabaseStorage>>` to `MultiStorage` (cfg-gated).

**Step 134.** Create `StorageBackend` enum: `ObjectStore(MultiStorage) | Database(Arc<DatabaseStorage>)`.

**Step 135.** Route document operations through `StorageDocumentTraits` for database backend.

**Step 136.** Write test `test_database_backed_document_create`.

**Step 137.** Write test `test_database_backed_document_update`.

**Step 138.** Write test `test_database_backed_document_verify` -- signature survives JSONB round-trip.

**Step 139.** Implement `CachedMultiStorage` support for database.

**Step 140.** Write test `test_cached_database_storage`.

**Step 141.** Add `JACS_DATABASE_URL` to Config struct + env var loading.

**Step 142.** Update `jacs.config.schema.json`.

**Step 143.** Write test `test_config_database_url`.

**Step 144.** Write test `test_config_database_url_env_override`.

**Step 145.** Add pool config: `JACS_DATABASE_MAX_CONNECTIONS`, `JACS_DATABASE_MIN_CONNECTIONS`, `JACS_DATABASE_CONNECT_TIMEOUT_SECS`.

**Step 146.** Write test `test_database_pool_configuration`.

**Step 147.** Write test `test_optimistic_locking_on_concurrent_update` -- two agents update same doc, one fails.

**Step 148.** Storage migration tooling: `export_to_filesystem()`, `import_from_filesystem()`.

**Step 149.** Write test `test_documents_verifiable_after_migration`.

**Step 150.** Add CI: `cargo check --target wasm32-unknown-unknown`.

### Phase 2D: Domain Queries & Index Generator (Steps 151-175)

**Step 151-154.** Tests: commitments by status, todos for agent, updates for target, overdue commitments.

**Step 155.** Domain-specific query methods: `query_commitments_by_status()`, `query_todos_for_agent()`, `query_updates_for_target()`, `query_overdue_commitments()`.

**Step 156.** Write test `test_semantic_commitment_search` (vector search).

**Step 157.** Add full-text search (tsvector + GIN index).

**Step 158-159.** Tests: fulltext search, combined vector + text search.

**Step 160.** Aggregation queries: `count_documents_by_type()`, `count_commitments_by_status()`, `count_todos_by_agent()`, `count_updates_by_action()`.

**Step 161.** Write test `test_aggregation_queries`.

**Step 162.** Transaction support: `create_commitment_with_updates()`.

**Step 163.** Write test `test_transactional_commitment_creation`.

**Step 164.** Write test `test_suggest_indexes_for_all_types` -- index generator for todo, commitment, update.

**Step 165.** Create `src/storage/index_advisor.rs`:
- `pub struct IndexRecommendation { table, column_expr, index_type, condition, sql }`
- `pub fn suggest_indexes(schema_types: &[&str], backend: &str) -> Vec<IndexRecommendation>`

**Step 166.** Implement Postgres-specific index generation (GIN, HNSW, partial).

**Step 167.** Implement generic recommendations for non-Postgres backends.

**Step 168.** Add CLI subcommand: `jacs db suggest-indexes --backend postgres --types todo,commitment,update`.

**Step 169.** Write CLI test for index suggestion.

**Step 170-171.** CLI: `jacs db migrate`, `jacs db status`.

**Step 172-173.** CLI: `jacs db export`, `jacs db import` with verification.

**Step 174.** Write test `test_cli_full_database_workflow`.

**Step 175.** Run full Phase 2 suite + WASM check.

---

## Phase 3: Runtime Configuration (Steps 176-225)

### Phase 3A: JacsConfigProvider Trait (Steps 176-195)

**Step 176.** Write test `test_jacs_config_provider_trait` (mock).

**Step 177.** Write test `test_config_provider_override_chain` (defaults -> config -> env -> provider).

**Step 178.** Define `JacsConfigProvider` trait in `src/config/mod.rs` with `get_config()`, `get_storage_type()`, `get_database_url()`, `get_data_directory()`, `get_key_directory()`, `get_observability_config()`.

**Step 179.** Default impl of `JacsConfigProvider` for `Config`.

**Step 180.** Write test `test_default_config_provider`.

**Step 181.** Create `EnvConfigProvider` impl.

**Step 182.** Write test `test_env_config_provider`.

**Step 183.** Add `config_provider: Option<Arc<dyn JacsConfigProvider>>` to `Agent`.

**Step 184.** Add `config_provider()` to `AgentBuilder` (accepts `Arc<dyn JacsConfigProvider>`).

**Step 185.** Modify `AgentBuilder::build()` to use provider if set, fallback to existing config.

**Step 186.** Write test `test_agent_builder_with_config_provider`.

**Step 187.** Add `jacs_database_url: Option<String>` to `Config`.

**Step 188.** Add `database_url` to `ConfigBuilder`.

**Step 189.** Add `JACS_DATABASE_URL` to `apply_env_overrides()` and `check_env_vars()`.

**Step 190.** Update `Config::merge()` and `Config::Display` (redacted URL).

**Step 191.** Write test `test_config_database_url_12factor`.

**Step 192.** Create `src/config/runtime.rs`: `RuntimeConfig` with `RwLock<Config>`, mutation methods. Handle lock poisoning with proper errors.

**Step 193.** Write test `test_runtime_config_mutation`.

**Step 194-195.** Backward compatibility tests: old configs still load, missing fields default correctly.

### Phase 3B: HAI Integration Pattern (Steps 196-210)

**Step 196.** Write test `test_hai_config_provider` simulating HAI's pattern.

**Step 197.** Create `HaiConfigProvider` example struct (documentation/example).

**Step 198.** Write test replicating `hai_signing::init_from_env()` pattern.

**Step 199.** Add `init_agent_from_provider()` convenience function.

**Step 200.** Write test `test_init_agent_from_provider`.

**Step 201.** Add `init_agent_from_config()` convenience function.

**Step 202.** Write test `test_init_agent_from_config`.

**Step 203.** Document security constraint: keys MUST load from secure locations only.

**Step 204.** Add validation in `AgentBuilder::build()`: if storage=Database, keys still from filesystem.

**Step 205.** Write test `test_database_storage_keys_still_from_filesystem`.

**Step 206.** Add `with_storage()` to `AgentBuilder`.

**Step 207.** Write test `test_agent_builder_with_storage`.

**Step 208.** Add `with_storage_and_database()` (cfg-gated).

**Step 209.** Write test `test_agent_builder_with_database`.

**Step 210.** Run all tests.

### Phase 3C: Observability Runtime Config (Steps 211-225)

**Step 211.** Write test `test_observability_runtime_reconfiguration`.

**Step 212.** Add `reconfigure_observability()` in `src/observability/mod.rs`.

**Step 213.** Write test `test_observability_toggle_at_runtime`.

**Step 214.** Add `ObservabilityConfig` to `JacsConfigProvider` and `RuntimeConfig`.

**Step 215.** Write test `test_runtime_config_observability`.

**Step 216.** Add `JACS_OBSERVABILITY_CONFIG` env var.

**Step 217.** Write test `test_observability_config_from_env`.

**Step 218.** Config validation for db + observability combinations.

**Step 219.** Write test `test_config_validation_complete`.

**Step 220.** Update `jacs.config.schema.json` with all new fields.

**Step 221.** Write test `test_config_schema_validation_with_new_fields`.

**Step 222-223.** Backward compatibility tests (old configs, missing fields, env overrides).

**Step 224.** Add `JACS_MIGRATION_VERSION` tracking.

**Step 225.** Full regression suite.

---

## Phase 4: MCP & Bindings Integration (Steps 226-261)

### Phase 4A: MCP Server Tools (Steps 226-242)

**Step 226.** Add MCP tool: `create_todo_list` -- creates and signs a new todo list.

**Step 227.** Add MCP tool: `add_todo_item` -- adds item to list, re-signs.

**Step 228.** Add MCP tool: `complete_todo_item` -- marks complete, re-signs.

**Step 229.** Add MCP tool: `get_todo_list` -- retrieves a todo list by ID.

**Step 230.** Add MCP tool: `archive_completed_items` -- moves completed items to archive list.

**Step 231.** Add MCP tool: `create_commitment` -- creates a commitment document.

**Step 232.** Add MCP tool: `sign_commitment` -- agent signs agreement.

**Step 233.** Add MCP tool: `verify_commitment` -- verifies all signatures.

**Step 234.** Add MCP tool: `list_commitments` -- list with optional status filter.

**Step 235.** Add MCP tool: `create_update` -- creates a semantic update document.

**Step 236.** Add MCP tool: `get_updates_for_target` -- all updates targeting a document.

**Step 237.** Add MCP tool: `get_update_chain` -- ordered update chain for a target.

**Step 238.** Add MCP tool: `send_message` -- signed message in conversation thread.

**Step 239.** Add MCP tool: `get_conversation` -- all messages in a thread.

**Step 240.** Add MCP tool: `find_overdue_commitments` -- query for past-deadline commitments.

**Step 241.** Add MCP tool: `search_documents` -- text/semantic search.

**Step 242.** Write MCP integration tests for all tools.

### Phase 4B: Language Bindings (Steps 243-257)

**Step 243-247.** Python bindings (`jacspy/`): implement all todo/commitment/update/conversation functions + MCP server examples.

**Step 248-252.** Node bindings (`jacsnpm/`): implement all functions + MCP server examples.

**Step 253-255.** Go bindings (`jacsgo/`): implement core functions.

**Step 256-257.** Run all binding test suites.

### Phase 4C: CLI Integration (Steps 258-261)

**Step 258.** CLI: `jacs todo create/list/complete/archive`
**Step 259.** CLI: `jacs commitment create/list/sign/verify/dispute`
**Step 260.** CLI: `jacs update create/list/chain`
**Step 261.** CLI: `jacs conversation start/reply/list`

---

## Phase 5: End-to-End, Docs & Polish (Steps 262-281)

**Step 262-266.** End-to-end tests:
- Full commitment lifecycle: create commitment -> sign agreement -> update -> complete with all four document types
- Database round-trips for all 4 document types
- Mixed storage: fs for keys, db for documents
- Concurrent agents updating same commitment
- Storage migration: filesystem <-> database with signature verification

**Step 267-271.** Rustdoc comments for all new public types/functions.

**Step 272-274.** Documentation: `todo-tracking.md`, `database-storage.md`, `runtime-configuration.md`, updated README, CHANGELOG.

**Step 275-276.** JSON examples, config examples, `cargo doc` verification.

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
