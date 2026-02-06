# Phase 4: MCP & Bindings Integration (Steps 226-261)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)

**Status**: Not started
**Step Range**: 226-261
**Dependencies**: Phases 1-3 must be complete. Phase 1 provides the schemas and CRUD operations for Commitment, Update, Todo List, and Conversation. Phase 2 provides `DatabaseDocumentTraits` and `MultiStorage` integration. Phase 3 provides the `JacsConfigProvider` trait and `AgentBuilder` integration that the MCP server and bindings will use to configure storage backends at runtime.

**Summary**: Expose all new todo/commitment/update/conversation functionality as MCP tools, implement language bindings for Python/Node/Go, and add CLI integration for all document types. This phase is the surface-area phase -- it takes the core Rust library capabilities built in Phases 1-3 and makes them accessible to every consumer: LLMs via MCP, applications via language bindings, and humans via CLI.

---

## What This Phase Delivers

By the end of Phase 4, every capability introduced in Phases 1-3 is reachable from outside the Rust core:

- **MCP tools** (17 new tools) that LLMs can call to create, sign, query, and verify all four document types without writing code.
- **Python bindings** (`jacspy/`) with idiomatic Python functions for CRUD, signing, and querying, plus an example MCP server wrapper.
- **Node.js bindings** (`jacsnpm/`) with TypeScript-typed NAPI functions and an MCP server example.
- **Go bindings** (`jacsgo/`) with core CRUD and signing functions exposed through CGo.
- **CLI subcommands** (`jacs todo`, `jacs commitment`, `jacs update`, `jacs conversation`) for human-driven workflows and scripting.

---

## Architecture: MCP Integration

### What We Want

All new todo/commitment/conversation/update functionality exposed as MCP tools. An LLM connected to the JACS MCP server should be able to manage an agent's entire document lifecycle -- create a todo list, promote an item to a commitment, sign the commitment with another agent, track updates against it, and query the full history -- all through tool calls.

### What MCP Tools Expose

The 17 new MCP tools are organized into four categories:

**Full CRUD** -- standard create/read/update/list operations for each document type:

| Tool | Document Type | Operation |
|------|--------------|-----------|
| `create_todo_list` | Todo List | Create + sign a new todo list |
| `get_todo_list` | Todo List | Retrieve a todo list by ID |
| `update_todo_list` | Todo List | Add/modify items, re-sign |
| `archive_todo_list` | Todo List | Move completed items to archive list |
| `create_commitment` | Commitment | Create a commitment document |
| `get_commitment` | Commitment | Retrieve a commitment by ID |
| `list_commitments` | Commitment | List with optional status filter |
| `create_update` | Update | Create a semantic update document |
| `get_updates_for_target` | Update | All updates targeting a document |
| `get_update_chain` | Update | Ordered chain for a target |
| `send_message` | Conversation | Signed message in conversation thread |
| `get_conversation` | Conversation | All messages in a thread |

**Sign + Verify** -- cryptographic operations on shared documents:

| Tool | Operation |
|------|-----------|
| `sign_commitment` | Agent signs a commitment's agreement |
| `verify_commitment` | Verifies all signatures on a commitment |
| `disagree_commitment` | Agent signs a formal disagreement (Decision 12) |

**Workflow Helpers** -- compound operations that combine CRUD + signing:

| Tool | What It Does |
|------|-------------|
| `complete_todo_item` | Marks a todo item complete + re-signs the list |
| `promote_todo_to_commitment` | Creates a commitment from a todo item, linking via `jacsCommitmentTodoRef` |
| `create_update_for_commitment` | Creates an update targeting a commitment with semantic action type |
| `regenerate_todo_from_commitments` | Rebuilds a todo list from active commitments |

**Query & Search** -- read-only filtering and search operations:

| Tool | What It Returns |
|------|----------------|
| `list_todos_by_status` | Todo lists filtered by item completion status |
| `search_commitments` | Text/semantic search across commitment descriptions and terms |
| `find_overdue_commitments` | Commitments with `jacsCommitmentEndDate` in the past and status still "active" |
| `get_conversation_thread` | Full message thread with ordering |
| `query_updates_by_action` | Updates filtered by one of the 15 semantic action types |
| `get_update_chain_for_target` | Chronological update chain for a specific document |

### Design Principle: Sign + Verify, Not Negotiate

Negotiation happens externally -- in conversations between agents, in Slack threads, in email. JACS handles the cryptography, not the negotiation flow. The MCP tools let an LLM create a commitment and sign it, but the back-and-forth negotiation that leads to that commitment is the LLM's job, not the tool's job. This matches Decision 10 from the architecture document.

### Existing MCP Infrastructure

The existing `jacs-mcp` server (in `jacs-mcp/src/hai_tools.rs`) already provides 5 tools focused on agent identity:

| Existing Tool | Purpose |
|---------------|---------|
| `fetch_agent_key` | Fetch a public key from HAI's key distribution service |
| `register_agent` | Register the local agent with HAI (requires `JACS_MCP_ALLOW_REGISTRATION=true`) |
| `verify_agent` | Verify another agent's attestation level (0-3) |
| `check_agent_status` | Check registration status with HAI |
| `unregister_agent` | Unregister an agent from HAI |

These tools use `jacs_binding_core::AgentWrapper` and the `rmcp` crate's `#[tool_router]` / `#[tool]` macros. The new Phase 4 tools follow the same pattern: define `*Params` and `*Result` structs with `schemars::JsonSchema` derive, register via the tool router, and return JSON-serialized results.

### Existing moltyjacs Tools (OpenClaw Plugin)

The moltyjacs OpenClaw plugin provides a reference for how MCP tool interfaces have been consumed in practice. Its tools include `jacs_sign`, `jacs_verify`, `jacs_verify_auto`, and `jacs_fetch_pubkey`. The Phase 4 MCP tools supersede the document-level operations from moltyjacs while retaining the same sign/verify philosophy.

### CLI Design: Commitment-First Philosophy

The CLI follows the DevRel review finding that commitments must work standalone without ceremony. No hierarchy is required. No goal document needed first. Just:

```
jacs commitment create --description "deliver report" --by "2026-03-01"
jacs commitment list --status active
jacs commitment verify <id>
jacs commitment sign <id>
jacs commitment dispute <id> --reason "deliverable does not meet spec"
```

Todo lists are equally straightforward:

```
jacs todo create --name "Q1 sprint"
jacs todo add <list-id> --item "Write integration tests" --type task
jacs todo complete <list-id> --item 3
jacs todo list --filter incomplete
jacs todo archive <list-id>
```

Updates and conversations follow the same pattern:

```
jacs update create --target <commitment-id> --action inform --message "50% complete"
jacs update chain <commitment-id>
jacs conversation start --thread "API design review"
jacs conversation reply <thread-id> --message "Approved with conditions"
jacs conversation list <thread-id>
```

### Language Bindings: Same Surface Area

Python, Node, and Go bindings expose the same CRUD + signing functions that the MCP tools and CLI use. They all go through `binding-core` which wraps the Rust `Agent` and document CRUD modules. This ensures behavioral parity: if the MCP tool can create a commitment, the Python function can too, with identical validation and signing.

---

## Phase 4A: MCP Server Tools (Steps 226-242)

### Step 226. Add MCP tool: `create_todo_list`

- **Why**: LLMs need to create signed todo lists for agent work tracking. This is the entry point for the private document lifecycle.
- **What**: Add `CreateTodoListParams` struct and `create_todo_list` tool to the MCP server. The tool creates a new todo list document, validates it against `todo.schema.json`, signs it with the local agent's key, and stores it via `MultiStorage`.
- **Input Parameters**:
  - `name` (string, required): Human-readable list name (e.g., "Q1 Sprint Tasks")
  - `items` (array of objects, optional): Initial items, each with `description` (string), `itemType` (enum: "task" | "goal"), `priority` (enum: "low" | "medium" | "high" | "critical", optional)
  - `context` (string, optional): Freeform context for the list (e.g., project name)
- **Returns**: `CreateTodoListResult` with `success` (bool), `todo_list_id` (UUID string), `version` (string), `item_count` (number), `signature_hash` (string), `error` (optional string).

### Step 227. Add MCP tool: `add_todo_item`

- **Why**: After creating a list, agents add items incrementally as work is discovered. Each addition re-signs the list, maintaining an auditable version chain.
- **What**: Add `AddTodoItemParams` struct and tool. Loads the existing list, appends the new item, bumps the version, re-signs, and stores.
- **Input Parameters**:
  - `todo_list_id` (UUID string, required): The list to add to
  - `description` (string, required): What needs to be done
  - `item_type` (enum: "task" | "goal", default "task"): Whether this is a concrete task or a higher-level goal
  - `priority` (enum: "low" | "medium" | "high" | "critical", optional)
  - `due_date` (date-time string, optional): When this item should be completed
- **Returns**: `AddTodoItemResult` with `success`, `todo_list_id`, `item_index` (number -- position in the list), `new_version` (string), `error` (optional).

### Step 228. Add MCP tool: `complete_todo_item`

- **Why**: Marking items complete is the most frequent todo operation. This is a workflow helper that sets the item's completion flag and re-signs in one atomic operation.
- **What**: Add `CompleteTodoItemParams` struct and tool. Loads list, sets the item at the given index to completed with a completion timestamp, re-signs, stores.
- **Input Parameters**:
  - `todo_list_id` (UUID string, required)
  - `item_index` (number, required): Zero-based index of the item to complete
  - `completion_note` (string, optional): Freeform note about how/why it was completed
- **Returns**: `CompleteTodoItemResult` with `success`, `todo_list_id`, `item_index`, `completed_at` (ISO 8601 timestamp), `new_version`, `remaining_incomplete` (number), `error` (optional).

### Step 229. Add MCP tool: `get_todo_list`

- **Why**: LLMs need to retrieve the current state of a todo list to reason about what work remains, display progress, or decide what to do next.
- **What**: Add `GetTodoListParams` struct and tool. Loads from storage by ID, returns the full document including all items and their statuses.
- **Input Parameters**:
  - `todo_list_id` (UUID string, required)
  - `version` (string, optional): Specific version to retrieve; defaults to latest
  - `include_completed` (bool, optional, default true): Whether to include completed items in the response
- **Returns**: `GetTodoListResult` with `success`, `todo_list` (full JSON document), `item_count` (total items), `completed_count`, `signature_valid` (bool -- verified on load), `error` (optional).

### Step 230. Add MCP tool: `archive_completed_items`

- **Why**: Active todo lists become unwieldy over time. Archiving moves completed items to a dated archive list, keeping the active list performant while preserving full history (Decision 3).
- **What**: Add `ArchiveCompletedItemsParams` struct and tool. Loads the active list, extracts all completed items, creates a new archive list document (named with a date prefix), removes completed items from the active list, re-signs both documents, stores both.
- **Input Parameters**:
  - `todo_list_id` (UUID string, required)
  - `archive_name` (string, optional): Custom name for the archive list; defaults to `"{original_name} - Archive {date}"`
- **Returns**: `ArchiveCompletedItemsResult` with `success`, `active_list_id`, `archive_list_id` (UUID of the new archive list), `items_archived` (number), `items_remaining` (number), `error` (optional).

### Step 231. Add MCP tool: `create_commitment`

- **Why**: Commitments are the primary shared document type. An LLM creates a commitment when two agents reach agreement through conversation. This is the commitment-first entry point (Decision 1).
- **What**: Add `CreateCommitmentParams` struct and tool. Creates the commitment JSON, validates against `commitment.schema.json`, signs with the creating agent's key, optionally initializes the `jacsAgreement` with agent IDs. Stores via `MultiStorage`.
- **Input Parameters**:
  - `description` (string, required): What is being committed to
  - `terms` (object, optional): Structured terms with any of `deliverable`, `deadline`, `compensation`, `conditions`
  - `start_date` (date-time string, optional)
  - `end_date` (date-time string, optional)
  - `counterparty_agent_ids` (array of UUID strings, optional): Agent IDs that should also sign this commitment
  - `todo_ref` (string, optional): Reference to the todo item this commitment formalizes, format "todo-list-uuid:item-index"
  - `conversation_ref` (UUID string, optional): Thread ID of the conversation that produced this commitment
  - `recurrence` (object, optional): `{ frequency: "daily"|"weekly"|"monthly", interval: number }`
- **Returns**: `CreateCommitmentResult` with `success`, `commitment_id`, `version`, `status` ("pending"), `agreement_hash` (string -- computed from terms per Decision 13), `awaiting_signatures` (array of agent IDs), `error` (optional).

### Step 232. Add MCP tool: `sign_commitment`

- **Why**: Multi-agent commitments require each party to sign. This tool lets an LLM acting on behalf of an agent add its cryptographic signature to the commitment's agreement.
- **What**: Add `SignCommitmentParams` struct and tool. Loads the commitment, verifies the calling agent is in the `jacsAgreement.agentIDs` list, adds the agent's signature to the agreement, re-validates, stores. If all parties have signed, transitions status from "pending" to "active".
- **Input Parameters**:
  - `commitment_id` (UUID string, required)
- **Returns**: `SignCommitmentResult` with `success`, `commitment_id`, `signer_agent_id`, `total_signatures` (number), `required_signatures` (number), `fully_signed` (bool), `new_status` (string -- "active" if fully signed, otherwise "pending"), `error` (optional).

### Step 233. Add MCP tool: `verify_commitment`

- **Why**: Before acting on a commitment, agents should verify that all signatures are intact and no content has been tampered with. This is the read-side counterpart to `sign_commitment`.
- **What**: Add `VerifyCommitmentParams` struct and tool. Loads the commitment, verifies every signature in the agreement against the stored public keys, checks the `jacsAgreementHash` matches the current terms content (Decision 13), and reports any discrepancies.
- **Input Parameters**:
  - `commitment_id` (UUID string, required)
- **Returns**: `VerifyCommitmentResult` with `success`, `commitment_id`, `all_signatures_valid` (bool), `signature_details` (array of `{ agent_id, valid, algorithm, signed_at }`), `agreement_hash_valid` (bool), `tampered_fields` (array of strings, empty if no tampering), `error` (optional).

### Step 234. Add MCP tool: `list_commitments`

- **Why**: Agents need to see their active, pending, or disputed commitments at a glance. Status filtering is the most common query pattern.
- **What**: Add `ListCommitmentsParams` struct and tool. Queries storage for commitments involving the local agent, optionally filtered by status.
- **Input Parameters**:
  - `status` (enum string, optional): Filter by `jacsCommitmentStatus` value ("pending", "active", "completed", "failed", "disputed", "revoked", "renegotiated")
  - `counterparty_agent_id` (UUID string, optional): Filter to commitments shared with a specific agent
  - `limit` (number, optional, default 50): Maximum results
  - `offset` (number, optional, default 0): Pagination offset
- **Returns**: `ListCommitmentsResult` with `success`, `commitments` (array of summary objects with `id`, `description`, `status`, `counterparties`, `created_at`, `end_date`), `total_count` (number), `error` (optional).

### Step 235. Add MCP tool: `create_update`

- **Why**: Updates are the semantic audit trail (Decision 6). Every meaningful state change -- inform, commit, doubt, reschedule, close -- is captured as a signed update document with one of 15 action types from HAI-2024.
- **What**: Add `CreateUpdateParams` struct and tool. Creates the update JSON targeting a specific document, validates the caller is an authorized signer (Decision 16), chains via `previousUpdateId`, validates against `update.schema.json`, signs, stores. If the action implies a status change on the target, creates a new version of the target with the updated status (Decision 14).
- **Input Parameters**:
  - `target_id` (UUID string, required): The document this update targets
  - `target_type` (enum: "commitment" | "task" | "todo", required)
  - `action` (enum, required): One of the 15 action types: "close-success", "close-ignore", "close-fail", "close-reject", "reopen", "commit", "doubt", "assign", "create", "update", "recommit", "reschedule", "delay", "inform", "renegotiate"
  - `message` (string, required): Human-readable description of the update
  - `metadata` (object, optional): Additional structured data relevant to the action type
- **Returns**: `CreateUpdateResult` with `success`, `update_id`, `target_id`, `action`, `previous_update_id` (UUID or null if first update), `target_new_version` (string if target was versioned, null otherwise), `error` (optional).

### Step 236. Add MCP tool: `get_updates_for_target`

- **Why**: To understand the full history of a commitment or task, agents need all updates that target it. This is critical for mediation -- knowing the sequence of actions provides context for dispute resolution.
- **What**: Add `GetUpdatesForTargetParams` struct and tool. Queries storage for all update documents where `jacsUpdateTargetId` matches.
- **Input Parameters**:
  - `target_id` (UUID string, required)
  - `action_filter` (enum string, optional): Filter to a specific action type
  - `limit` (number, optional, default 100)
  - `offset` (number, optional, default 0)
- **Returns**: `GetUpdatesForTargetResult` with `success`, `updates` (array of update summaries with `id`, `action`, `message`, `author_agent_id`, `created_at`, `previous_update_id`), `total_count`, `error` (optional).

### Step 237. Add MCP tool: `get_update_chain`

- **Why**: Updates form a linked list via `previousUpdateId`. Walking this chain gives a chronologically ordered narrative of how a document evolved, which is more meaningful than a flat list.
- **What**: Add `GetUpdateChainParams` struct and tool. Starts from the most recent update for a target and walks backward through `previousUpdateId` links, assembling the chain in chronological order.
- **Input Parameters**:
  - `target_id` (UUID string, required)
  - `max_depth` (number, optional, default 100): Maximum chain links to follow
- **Returns**: `GetUpdateChainResult` with `success`, `chain` (array of update objects in chronological order, oldest first), `chain_length` (number), `chain_complete` (bool -- false if truncated by `max_depth`), `error` (optional).

### Step 238. Add MCP tool: `send_message`

- **Why**: Conversations are signed message threads between agents (Decision 4). Each message is a separate signed document linked by thread ID and ordered via `jacsMessagePreviousId`.
- **What**: Add `SendMessageParams` struct and tool. Creates a new message document, sets the thread ID (creates a new thread if none provided), links to the previous message in the thread, validates against `message.schema.json`, signs, stores.
- **Input Parameters**:
  - `thread_id` (UUID string, optional): Existing thread to reply to; if omitted, creates a new thread
  - `content` (string, required): The message text
  - `thread_subject` (string, optional): Subject line for new threads (ignored if `thread_id` is provided)
  - `recipient_agent_ids` (array of UUID strings, optional): Intended recipients
- **Returns**: `SendMessageResult` with `success`, `message_id`, `thread_id` (UUID -- either the provided one or newly created), `previous_message_id` (UUID or null if first in thread), `signature_hash`, `error` (optional).

### Step 239. Add MCP tool: `get_conversation`

- **Why**: To display or reason about a conversation, the LLM needs all messages in a thread, ordered chronologically.
- **What**: Add `GetConversationParams` struct and tool. Queries storage for all messages with the given thread ID, orders by `jacsMessagePreviousId` chain, returns the full thread.
- **Input Parameters**:
  - `thread_id` (UUID string, required)
  - `limit` (number, optional, default 100): Maximum messages
  - `since` (date-time string, optional): Only messages after this timestamp
- **Returns**: `GetConversationResult` with `success`, `thread_id`, `subject` (string, from first message), `messages` (array of message objects with `id`, `author_agent_id`, `content`, `created_at`, `signature_valid`), `message_count`, `error` (optional).

### Step 240. Add MCP tool: `find_overdue_commitments`

- **Why**: Proactive alerting. An LLM assistant should be able to check which commitments have passed their deadline without completion, enabling it to suggest follow-up actions or create updates.
- **What**: Add `FindOverdueCommitmentsParams` struct and tool. Queries for commitments where `jacsCommitmentEndDate` is before the current timestamp and `jacsCommitmentStatus` is "active" or "pending".
- **Input Parameters**:
  - `as_of` (date-time string, optional): Override current time for testing; defaults to now
  - `include_pending` (bool, optional, default true): Whether to include "pending" commitments (not yet signed by all parties) in overdue results
- **Returns**: `FindOverdueCommitmentsResult` with `success`, `overdue` (array of commitment summaries with `id`, `description`, `end_date`, `status`, `days_overdue`), `total_count`, `error` (optional).

### Step 241. Add MCP tool: `search_documents`

- **Why**: Free-text and semantic search across all document types. When an LLM needs to find "that commitment about the API refactor" or "all updates mentioning performance", keyword and vector search provide the answer.
- **What**: Add `SearchDocumentsParams` struct and tool. Uses the database layer's text search (Phase 2) and optional vector search when embeddings are available.
- **Input Parameters**:
  - `query` (string, required): Search text
  - `document_types` (array of enum strings, optional): Filter to specific types: "commitment", "update", "todo", "message"; defaults to all
  - `limit` (number, optional, default 20)
  - `use_vector_search` (bool, optional, default false): Use vector similarity instead of text search (requires embeddings)
- **Returns**: `SearchDocumentsResult` with `success`, `results` (array of `{ id, document_type, snippet, relevance_score, created_at }`), `total_count`, `error` (optional).

### Step 242. Write MCP integration tests for all tools

- **Why**: Every tool needs an integration test that exercises the full path from MCP tool call through CRUD through storage and back. Tests catch serialization issues, schema validation failures, and storage round-trip bugs before release.
- **What**: Create `jacs-mcp/tests/phase4_integration.rs` with tests for each of the 17 new tools. Tests use an in-memory storage backend to avoid filesystem or database dependencies. Each test creates a fresh `AgentWrapper`, registers the tools, calls them via the tool router, and asserts on the returned JSON. Key test scenarios:
  - `test_todo_lifecycle`: create list -> add item -> complete item -> archive
  - `test_commitment_lifecycle`: create -> sign (two agents) -> verify -> update -> complete
  - `test_update_chain`: create multiple updates for one target, verify chain order
  - `test_conversation_thread`: send 3 messages in a thread, retrieve, verify ordering
  - `test_overdue_query`: create commitment with past end_date, find it via `find_overdue_commitments`
  - `test_search`: create several documents, search by text, verify relevance
  - `test_disagree_commitment`: create commitment, have second agent disagree, verify disagreement is recorded
  - `test_error_handling`: call tools with invalid IDs, missing required fields, unauthorized agents -- verify graceful error responses

---

## Phase 4B: Language Bindings (Steps 243-257)

### Steps 243-247. Python Bindings (`jacspy/`)

- **Why**: Python is the dominant language for AI/ML agents. LangGraph, AutoGPT, and many custom agent frameworks are Python. JACS must be callable from Python with idiomatic APIs.
- **What**: Add new functions to the `jacspy` PyO3 module that wrap the Rust CRUD and signing operations via `binding-core`. All functions go through `AgentWrapper` for consistent signing behavior.

**Step 243.** Add todo list functions to `jacspy`:
  - `create_todo_list(name: str, items: Optional[List[dict]] = None) -> dict` -- returns `{ "id", "version", "item_count" }`
  - `get_todo_list(todo_list_id: str, version: Optional[str] = None) -> dict` -- returns full document
  - `add_todo_item(todo_list_id: str, description: str, item_type: str = "task", priority: Optional[str] = None) -> dict`
  - `complete_todo_item(todo_list_id: str, item_index: int, note: Optional[str] = None) -> dict`
  - `archive_completed_items(todo_list_id: str) -> dict`

**Step 244.** Add commitment functions to `jacspy`:
  - `create_commitment(description: str, terms: Optional[dict] = None, end_date: Optional[str] = None, counterparty_ids: Optional[List[str]] = None) -> dict`
  - `get_commitment(commitment_id: str) -> dict`
  - `list_commitments(status: Optional[str] = None, limit: int = 50) -> dict`
  - `sign_commitment(commitment_id: str) -> dict`
  - `verify_commitment(commitment_id: str) -> dict`
  - `disagree_commitment(commitment_id: str, reason: str) -> dict`
  - `dispute_commitment(commitment_id: str, reason: str) -> dict`

**Step 245.** Add update functions to `jacspy`:
  - `create_update(target_id: str, target_type: str, action: str, message: str, metadata: Optional[dict] = None) -> dict`
  - `get_updates_for_target(target_id: str, action_filter: Optional[str] = None) -> dict`
  - `get_update_chain(target_id: str, max_depth: int = 100) -> dict`

**Step 246.** Add conversation functions to `jacspy`:
  - `send_message(content: str, thread_id: Optional[str] = None, subject: Optional[str] = None) -> dict`
  - `get_conversation(thread_id: str, limit: int = 100) -> dict`

**Step 247.** Add Python MCP server example:
  - Create `jacspy/examples/mcp_server.py` demonstrating how to wrap the Python bindings in a FastMCP server. This example shows Python-native MCP server creation using the same underlying JACS operations. Include a `README.md` in the examples directory explaining setup.

### Steps 248-252. Node.js Bindings (`jacsnpm/`)

- **Why**: Node.js is the runtime for many production agent deployments and MCP server implementations. The `jacsnpm` NAPI bindings must expose the same operations with TypeScript types for developer ergonomics.
- **What**: Add new NAPI functions to `jacsnpm/src/lib.rs` and update the TypeScript declarations in `jacsnpm/index.d.ts`.

**Step 248.** Add todo list functions to `jacsnpm`:
  - `createTodoList(name: string, items?: TodoItem[]): Promise<TodoListResult>`
  - `getTodoList(todoListId: string, version?: string): Promise<TodoListDocument>`
  - `addTodoItem(todoListId: string, description: string, itemType?: string, priority?: string): Promise<AddItemResult>`
  - `completeTodoItem(todoListId: string, itemIndex: number, note?: string): Promise<CompleteItemResult>`
  - `archiveCompletedItems(todoListId: string): Promise<ArchiveResult>`

**Step 249.** Add commitment functions to `jacsnpm`:
  - `createCommitment(description: string, opts?: CommitmentOptions): Promise<CommitmentResult>`
  - `getCommitment(commitmentId: string): Promise<CommitmentDocument>`
  - `listCommitments(status?: string, limit?: number): Promise<CommitmentListResult>`
  - `signCommitment(commitmentId: string): Promise<SignResult>`
  - `verifyCommitment(commitmentId: string): Promise<VerifyResult>`
  - `disagreeCommitment(commitmentId: string, reason: string): Promise<DisagreeResult>`

**Step 250.** Add update functions to `jacsnpm`:
  - `createUpdate(targetId: string, targetType: string, action: string, message: string, metadata?: object): Promise<UpdateResult>`
  - `getUpdatesForTarget(targetId: string, actionFilter?: string): Promise<UpdateListResult>`
  - `getUpdateChain(targetId: string, maxDepth?: number): Promise<UpdateChainResult>`

**Step 251.** Add conversation functions to `jacsnpm`:
  - `sendMessage(content: string, threadId?: string, subject?: string): Promise<MessageResult>`
  - `getConversation(threadId: string, limit?: number): Promise<ConversationResult>`

**Step 252.** Add Node MCP server example:
  - Create `jacsnpm/examples/mcp-server.ts` demonstrating an MCP server built with the `@modelcontextprotocol/sdk` npm package that wraps the JACS Node bindings. Include TypeScript types for all tool inputs/outputs and a `package.json` for the example.

### Steps 253-255. Go Bindings (`jacsgo/`)

- **Why**: Go is used in infrastructure-heavy agent deployments and Kubernetes-native systems. The Go bindings provide CGo-based access to core JACS operations.
- **What**: Add new Go functions to `jacsgo/` that wrap the Rust library through CGo. Go bindings cover core CRUD and signing; the full query/search surface is Python/Node-first since Go agents typically have direct database access.

**Step 253.** Add todo list and commitment functions to `jacsgo/`:
  - `CreateTodoList(name string, items []TodoItem) (*TodoListResult, error)`
  - `GetTodoList(todoListID string) (*TodoListDocument, error)`
  - `CompleteTodoItem(todoListID string, itemIndex int) (*CompleteItemResult, error)`
  - `CreateCommitment(description string, opts *CommitmentOptions) (*CommitmentResult, error)`
  - `GetCommitment(commitmentID string) (*CommitmentDocument, error)`
  - `SignCommitment(commitmentID string) (*SignResult, error)`
  - `VerifyCommitment(commitmentID string) (*VerifyResult, error)`

**Step 254.** Add update and conversation functions to `jacsgo/`:
  - `CreateUpdate(targetID, targetType, action, message string) (*UpdateResult, error)`
  - `GetUpdateChain(targetID string) (*UpdateChainResult, error)`
  - `SendMessage(content string, threadID string) (*MessageResult, error)`
  - `GetConversation(threadID string) (*ConversationResult, error)`

**Step 255.** Add Go example and tests:
  - Create `jacsgo/examples/commitment_workflow.go` demonstrating a two-agent commitment lifecycle.
  - Add test functions in `jacsgo/phase4_test.go` covering CRUD round-trips for each document type.

### Steps 256-257. Binding Test Suites

- **Why**: Language bindings must be tested independently of the Rust core to catch FFI serialization issues, memory safety problems, and API ergonomic regressions.
- **What**: Run the full test suite for each binding language.

**Step 256.** Python binding tests:
  - Create `jacspy/tests/test_phase4.py` with pytest tests for every function added in Steps 243-246.
  - Test scenarios: create todo list with items, complete items, archive; create commitment, sign with mock second agent, verify; create update chain, query by action type; send messages in thread, retrieve conversation.
  - Test error handling: invalid IDs, schema validation failures, unauthorized signing attempts.
  - Run with `cd jacspy && pip install -e . && pytest tests/test_phase4.py -v`.

**Step 257.** Node and Go binding tests:
  - Create `jacsnpm/test/phase4.test.ts` with matching test coverage for all Node functions from Steps 248-251.
  - Run Go tests with `cd jacsgo && go test -v -run TestPhase4`.
  - Run Node tests with `cd jacsnpm && npm test`.
  - Verify all three binding languages produce identical document structures for the same inputs (cross-language parity check).

---

## Phase 4C: CLI Integration (Steps 258-261)

### Step 258. CLI: `jacs todo create/list/complete/archive`

- **Why**: Human operators and shell scripts need CLI access to todo operations. The CLI is also the simplest way to verify the full stack works end-to-end during development.
- **What**: Add the `todo` subcommand group to the JACS CLI binary. Each subcommand maps directly to the corresponding Rust CRUD function. Output is JSON by default with an optional `--format table` flag for human-readable output.
  - `jacs todo create --name <name> [--items <json-array>]` -- creates and signs a new todo list
  - `jacs todo list [--filter incomplete|completed|all]` -- lists todo lists with summary
  - `jacs todo add <list-id> --item <description> [--type task|goal] [--priority low|medium|high|critical]`
  - `jacs todo complete <list-id> --item <index> [--note <text>]`
  - `jacs todo archive <list-id>` -- archives completed items
  - `jacs todo show <list-id> [--version <version>]` -- detailed view of a single list

### Step 259. CLI: `jacs commitment create/list/sign/verify/dispute`

- **Why**: Commitments are the most important shared document type. CLI access enables scripting of commitment workflows, batch signing, and CI/CD integration for automated verification.
- **What**: Add the `commitment` subcommand group.
  - `jacs commitment create --description <text> [--by <date>] [--terms <json>] [--counterparty <agent-id>...]`
  - `jacs commitment list [--status <status>] [--counterparty <agent-id>]`
  - `jacs commitment show <id>` -- detailed view with signature status
  - `jacs commitment sign <id>` -- sign the commitment's agreement
  - `jacs commitment verify <id>` -- verify all signatures and agreement hash
  - `jacs commitment dispute <id> --reason <text>` -- formally dispute the commitment
  - `jacs commitment disagree <id> --reason <text>` -- formally disagree (cryptographic action, Decision 12)

### Step 260. CLI: `jacs update create/list/chain`

- **Why**: Updates provide the semantic changelog for any document. CLI access lets operators create status updates from scripts and inspect the audit trail.
- **What**: Add the `update` subcommand group.
  - `jacs update create --target <id> --type <target-type> --action <action> --message <text> [--metadata <json>]`
  - `jacs update list --target <id> [--action <action-filter>]` -- all updates for a target
  - `jacs update chain --target <id> [--max-depth <n>]` -- chronological chain view
  - `jacs update show <update-id>` -- detailed view of a single update

### Step 261. CLI: `jacs conversation start/reply/list`

- **Why**: Conversations are signed message threads. CLI access enables scripted message flows and integration with external messaging systems that pipe messages into JACS for signing and archival.
- **What**: Add the `conversation` subcommand group.
  - `jacs conversation start --subject <text> --message <text> [--to <agent-id>...]` -- creates a new thread with the first message
  - `jacs conversation reply <thread-id> --message <text>` -- adds a signed reply
  - `jacs conversation list <thread-id> [--since <date>] [--limit <n>]` -- shows all messages in a thread
  - `jacs conversation threads [--limit <n>]` -- lists all threads the local agent participates in

---

## Files Created/Modified

| File | Action | Purpose |
|------|--------|---------|
| `jacs-mcp/src/document_tools.rs` | **Create** | All 17 new MCP tool implementations with Params/Result structs |
| `jacs-mcp/src/main.rs` | **Modify** | Register new tool module, add tools to server capabilities |
| `jacs-mcp/src/hai_tools.rs` | **Modify** | Minor: share `HaiMcpServer` struct with new tools or refactor into shared server |
| `jacs-mcp/tests/phase4_integration.rs` | **Create** | Integration tests for all 17 MCP tools |
| `jacs-mcp/Cargo.toml` | **Modify** | Add any new dependencies for test utilities |
| `binding-core/src/lib.rs` | **Modify** | Add `AgentWrapper` methods for todo, commitment, update, conversation CRUD |
| `binding-core/src/todo.rs` | **Create** | Todo-specific binding logic |
| `binding-core/src/commitment.rs` | **Create** | Commitment-specific binding logic |
| `binding-core/src/update.rs` | **Create** | Update-specific binding logic |
| `binding-core/src/conversation.rs` | **Create** | Conversation-specific binding logic |
| `jacspy/src/lib.rs` | **Modify** | Add PyO3 functions for all new document types |
| `jacspy/tests/test_phase4.py` | **Create** | Python tests for all new binding functions |
| `jacspy/examples/mcp_server.py` | **Create** | Python MCP server example using JACS bindings |
| `jacsnpm/src/lib.rs` | **Modify** | Add NAPI functions for all new document types |
| `jacsnpm/index.d.ts` | **Modify** | TypeScript type declarations for new functions |
| `jacsnpm/test/phase4.test.ts` | **Create** | Node tests for all new binding functions |
| `jacsnpm/examples/mcp-server.ts` | **Create** | Node MCP server example using JACS bindings |
| `jacsgo/phase4.go` | **Create** | Go functions for core CRUD + signing |
| `jacsgo/phase4_test.go` | **Create** | Go tests for new functions |
| `jacsgo/examples/commitment_workflow.go` | **Create** | Go example for commitment lifecycle |
| `jacs/src/bin/cli.rs` (or equivalent) | **Modify** | Add `todo`, `commitment`, `update`, `conversation` subcommand groups |
