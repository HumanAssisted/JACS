# Phase 1: Schema Design & CRUD (Steps 1-95)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)
**Status**: Design complete, ready for implementation
**Steps**: 1-95 (95 steps)
**Dependencies**: Phase 0 (Signed Agent State Documents) should be complete first
**Crate**: `jacs` (core library)

---

## What This Phase Delivers

Four new JACS document types with full JSON Schema validation, CRUD operations, signing/verification, and cross-reference integrity:

1. **Commitment** (Steps 1-25) -- shared agreements between agents
2. **Update** (Steps 26-50) -- semantic change tracking with 15 action types
3. **Todo List** (Steps 51-80) -- private agent checklists with inline goal/task items
4. **Conversation enhancements** (Steps 81-87) -- message ordering within threads
5. **Cross-references & integration** (Steps 88-95) -- reference validation and full workflow testing

---

## Architecture: The Four Document Types

**Design principle: Goals are NOT standalone documents.** Goals are todo items (`itemType: "goal"`) within a private todo list. When a goal needs to be SHARED between agents, you create a Commitment referencing that todo item. The Commitment carries the agreement/disagreement mechanism. This keeps the schema count minimal while preserving full functionality.

### 1. Todo List (Private, Inline Items, Versioned)

**What it is**: A PRIVATE document belonging to a single agent. Contains inline items -- goals (broad, long-term objectives) and tasks (smaller, detailed actions). The entire list is one signed document.

**How it works**:
- Single signed JACS document with its own `jacsId` and `jacsVersion`
- Items are inline (not separate documents), like how `task.schema.json` embeds `jacsTaskActionsDesired`
- When anything changes, the ENTIRE list is re-signed with a new `jacsVersion`
- An agent can have **multiple todo lists** partitioned by context or time
- **Each todo item has a stable UUID (`itemId`)** -- references use `itemId` not array indices
- Goals have `childItemIds` pointing to sub-goals and tasks (tree structure)
- Todo items reference Commitments via `relatedCommitmentId`
- `jacsLevel: "config"` (private working document)

**How goals become shared**: Agent has private goal in todo -> creates Commitment document -> commitment's `jacsCommitmentTodoRef` points to `list-uuid:item-uuid` -> todo item's `relatedCommitmentId` points back.

**Example**:
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
  "jacsSignature": { "..." : "..." }
}
```

### 2. Commitment (Shared, Agreement-Based, Standalone)

**What it is**: A SHARED document representing a binding agreement between agents. Multi-agent signing uses the existing `jacsAgreement` system.

**How it works**:
- Standalone signed JACS document -- works without goals, tasks, or threads
- Uses `agreement.schema.json` component for multi-agent signing
- References conversation threads, todo items, and tasks by UUID (all optional)
- Effectively immutable once signed; term changes create NEW commitments
- Status lifecycle: pending -> active -> completed/failed/renegotiated/disputed/revoked
- Question/Answer fields for structured prompts
- Recurrence patterns for recurring commitments

**Why separate from todo lists**: Todo lists are private and mutable. Commitments are shared and immutable. Mixing them would mean a private change invalidates a shared agreement's signature.

**Example**:
```json
{
  "$schema": "https://hai.ai/schemas/commitment/v1/commitment.schema.json",
  "jacsId": "commitment-uuid",
  "jacsType": "commitment",
  "jacsLevel": "config",
  "jacsCommitmentDescription": "Agent A delivers Q1 report to Agent B by March 1, 2026",
  "jacsCommitmentTerms": {
    "deliverable": "Q1 financial report",
    "deadline": "2026-03-01T17:00:00Z",
    "format": "PDF",
    "compensation": { "amount": 500, "currency": "USD" }
  },
  "jacsCommitmentStatus": "active",
  "jacsCommitmentStartDate": "2026-01-15T00:00:00Z",
  "jacsCommitmentEndDate": "2026-03-01T17:00:00Z",
  "jacsCommitmentTodoRef": "todo-list-uuid:item-uuid-aaa",
  "jacsAgreement": {
    "agentIDs": ["agent-a-uuid", "agent-b-uuid"],
    "question": "Do you agree to these terms?",
    "signatures": [
      { "agentID": "agent-a-uuid", "signature": "..." },
      { "agentID": "agent-b-uuid", "signature": "..." }
    ]
  },
  "jacsSignature": { "..." : "..." }
}
```

### 3. Conversation (Linked Messages, Individually Signed)

**What it is**: A series of individually signed message documents linked by thread ID. Uses existing `message.schema.json`.

**How it works**:
- Each message is a separate signed document
- Messages share a `threadID` for grouping
- Messages reference previous message via `jacsMessagePreviousId` for ordering
- When a conversation produces a commitment, the commitment references the thread ID

### 4. Update (Semantic Change Tracking, Independently Signed)

**What it is**: An independently signed document recording a semantic change to another document.

**How it works**:
- Targets a document by `jacsUpdateTargetId` and `jacsUpdateTargetType` (task, commitment, todo)
- 15 semantic action types from HAI-2024:
  - **Closure**: `close-success`, `close-ignore`, `close-fail`, `close-reject`
  - **Lifecycle**: `reopen`, `commit`, `doubt`, `assign`
  - **CRUD**: `create`, `update`
  - **Renegotiation**: `recommit`, `reschedule`, `delay`, `renegotiate`
  - **Information**: `inform`
- Updates chain via `jacsUpdatePreviousUpdateId` (linked list per target)

**Example**:
```json
{
  "$schema": "https://hai.ai/schemas/update/v1/update.schema.json",
  "jacsType": "update",
  "jacsLevel": "config",
  "jacsUpdateTargetId": "commitment-uuid",
  "jacsUpdateTargetType": "commitment",
  "jacsUpdateAction": "delay",
  "jacsUpdateNote": "Delivery delayed by 2 weeks due to dependency on external API.",
  "jacsUpdatePreviousUpdateId": "previous-update-uuid",
  "jacsSignature": { "..." : "..." }
}
```

### How The Four Types Reference Each Other

```
                    +--------------+
                    | Conversation |  (series of signed messages, threadID links them)
                    | msg1 -> msg2 |
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
+----------+        +--------------+
     |
     | also targets commitments, tasks
```

---

## Architecture: Formal Agreement, Disagreement, and Conflict Resolution

### The Three Agreement States

**1. Pending (unsigned)**: Agent listed in `agentIDs` but no entry in `signatures`. "Hasn't seen it yet."

**2. Agreed (signed affirmatively)**: Agent's signature in `jacsAgreement.signatures`. Irrevocable for that version.

**3. Disagreed (signed refusal)**: Agent's signed entry in `jacsAgreement.disagreements`. Proves agent SAW the document and actively refused. Requires a `reason`.

### How Disagreement Works

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
  ]
}
```

### Document States Derived from Agreement

| State | Condition | Meaning |
|-------|-----------|---------|
| **Draft** | No signatures, no disagreements | Proposed, no one responded |
| **Partially Agreed** | Some signatures, not all | Some agents agreed |
| **Fully Agreed** | All required signatures | Consensus reached |
| **Contested** | At least one disagreement | Explicit conflict |
| **Mixed** | Some signatures AND some disagreements | Partial agreement with dissent |

### Key Properties

- **Agreement hash covers TERMS, not status**: `jacsAgreementHash` computed from content fields. Status changes don't invalidate agreement.
- **Updates drive status changes**: Creating an Update targeting a document triggers JACS to version the target with updated status.
- **Disagreements on the document itself**: Not separate Update documents. A disagreement modifies `jacsAgreement.disagreements` (new `jacsVersion`).
- **Completion requires agreement**: For commitments, terminal states (completed, failed) require agreement from ALL parties.

### Full Commitment Lifecycle with Disagreement

```
1. Agent A creates commitment with terms, adds Agent B to agreement
   -> Status: "pending", Agreement: {agentIDs: [A, B], signatures: []}

2. Agent B DISAGREES
   -> Status: "disputed"
   -> Agreement: {disagreements: [{agentID: B, reason: "Deadline too short"}]}

3. Agent A amends terms (longer deadline)
   -> Status: "pending" (reset), new jacsAgreementHash, disagreements cleared

4. Agent B AGREES -> 5. Agent A AGREES
   -> Status: "active" (both signed)

6. Agent A creates Update action "delay"
   -> Agreement signatures survive (terms didn't change)

7. Agent A creates Update action "close-success"
   -> jacsEndAgreement initiated, needs Agent B's agreement

8. Agent B disagrees with completion
   -> Status: "disputed", jacsEndAgreement has disagreement

9. Agent A fixes, creates "update" then "close-success" again
   -> Agent B agrees -> Status: "completed"
```

---

## Implementation Steps

### Phase 1A: Commitment Schema (Steps 1-25)

> Commitment is the FIRST schema we implement. It's the primary shared document type and the foundation for multi-agent agreements. Commitments work standalone.

**Step 1.** Write test `test_create_minimal_commitment` in `jacs/tests/commitment_tests.rs`.
- **Why**: TDD. Simplest commitment -- just a description and status.
- **What**: Call `create_minimal_commitment("Deliver Q1 report")`, assert `jacsCommitmentDescription`, `jacsCommitmentStatus` = "pending", NO requirement for goal/task/thread refs.
- **Pattern**: Follow `jacs/tests/task_tests.rs` test structure (load agent, create doc, validate).

**Step 2.** Write test `test_commitment_with_terms` -- structured terms object.
- **Why**: Commitments have structured terms (deliverable, deadline, compensation).
- **What**: Create commitment with `jacsCommitmentTerms` object, validate preserved through schema validation.

**Step 3.** Write test `test_commitment_with_dates` -- date-time format validation.
- **Why**: Start/end dates must be valid date-time format per JSON Schema Draft 7.
- **What**: Create commitment with `jacsCommitmentStartDate` and `jacsCommitmentEndDate`, validate.

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
- **What**: Create with `jacsCommitmentRecurrence: {frequency: "weekly", interval: 1}`, validate.

**Step 8.** Write test `test_commitment_with_agreement` -- multi-agent commitment.
- **Why**: Multi-agent commitments use existing agreement system.
- **What**: Create commitment, add `jacsAgreement` with two agent IDs, validate.

**Step 9.** Write test `test_commitment_linked_to_todo_item` -- optional todo item reference.
- **Why**: Commitments can reference the todo item they formalize.
- **What**: Create with `jacsCommitmentTodoRef: "todo-list-uuid:item-uuid"`, validate format.

**Step 10.** Write test `test_commitment_linked_to_task` -- optional task reference.
- **Why**: Commitments can reference a task they serve.
- **What**: Create with `jacsCommitmentTaskId: "task-uuid"`, validate.

**Step 11.** Write test `test_commitment_references_conversation` -- thread reference.
- **Why**: Commitments can reference the negotiation thread that produced them.
- **What**: Create with `jacsCommitmentConversationRef: "thread-uuid"`, validate.

**Step 12.** Write test `test_commitment_references_todo_item` -- todo ref format.
- **Why**: Todo refs use `list-uuid:item-uuid` format.
- **What**: Create with `jacsCommitmentTodoRef: "todo-list-uuid:2"`, validate.

**Step 13.** Write test `test_commitment_status_lifecycle` -- all valid statuses.
- **Why**: Status transitions: pending -> active -> completed (or failed/disputed/revoked).
- **What**: Test each: pending, active, completed, failed, renegotiated, disputed, revoked.

**Step 14.** Write test `test_commitment_invalid_status` -- rejects invalid status.
- **Why**: Negative test for status enum.
- **What**: Set status to "invalid", validate, expect enum error.

**Step 15.** Write test `test_commitment_dispute` -- dispute with reason.
- **Why**: Dispute flow is critical for conflict resolution platform.
- **What**: Create active commitment, set status to "disputed", add `jacsCommitmentDisputeReason`, validate.

**Step 16.** Write test `test_commitment_standalone_without_refs` -- no goal/task/thread refs.
- **Why**: Commitments MUST work without any references. Commitment-first onboarding.
- **What**: Create commitment with only description + status, validate passes.

**Step 17.** Write test `test_commitment_owner_signature` -- single-agent commitment.
- **Why**: Not all commitments are multi-agent.
- **What**: Create with `jacsCommitmentOwner` signature ref, validate.

**Step 18.** Create schema file `jacs/schemas/commitment/v1/commitment.schema.json`.
- **What**: JSON Schema Draft 7, `allOf` with header. Properties:
  - `jacsCommitmentDescription` (string, REQUIRED)
  - `jacsCommitmentTerms` (object, optional)
  - `jacsCommitmentStatus` (enum: pending/active/completed/failed/renegotiated/disputed/revoked, REQUIRED)
  - `jacsCommitmentDisputeReason` (string, optional)
  - `jacsCommitmentTaskId` (UUID string, optional)
  - `jacsCommitmentConversationRef` (UUID string, optional)
  - `jacsCommitmentTodoRef` (string, optional) -- "list-uuid:item-uuid" format
  - `jacsCommitmentQuestion` / `jacsCommitmentAnswer` (strings, optional)
  - `jacsCommitmentCompletionQuestion` / `jacsCommitmentCompletionAnswer` (strings, optional)
  - `jacsCommitmentStartDate` / `jacsCommitmentEndDate` (date-time, optional)
  - `jacsCommitmentRecurrence` (object: {frequency, interval}, optional)
  - `jacsCommitmentOwner` -- `$ref` to signature.schema.json (optional)
  - Uses `jacsAgreement` from header for multi-agent signing
- **Pattern**: Follow `jacs/schemas/task/v1/task.schema.json`

**Step 19.** Add commitment schema to `Cargo.toml`, `DEFAULT_SCHEMA_STRINGS`, `SCHEMA_SHORT_NAME`.
- **Where**: `jacs/src/schema/utils.rs:216` (phf_map) and `:235` (short name map)

**Step 20.** Add `commitmentschema: Validator` to `Schema` struct, compile in `Schema::new()`.
- **Where**: `jacs/src/schema/mod.rs:210`
- **How**: Use `build_validator()` helper at line 48

**Step 21.** Add `validate_commitment()` method to `Schema`.

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
- **CRITICAL**: Wire into mod.rs properly. Do NOT repeat the `eval_crud.rs` anti-pattern.

### Phase 1A continued: Commitment Integration Tests (Steps 23-25)

**Step 23.** Write test `test_commitment_signing_workflow` -- create, sign, verify.
- **Pattern**: Follow `test_create_task_with_actions` in `jacs/tests/task_tests.rs`

**Step 24.** Write test `test_commitment_two_agent_agreement` -- agent A proposes, agent B signs.
- **Pattern**: Follow agreement signing pattern in `task_tests.rs` lines 83-157.

**Step 25.** Write test `test_commitment_immutable_after_agreement` -- modification fails verification.

### Phase 1B: Update Tracking Schema (Steps 26-50)

**Step 26.** Write test `test_create_minimal_update` in `jacs/tests/update_tests.rs`.
- **What**: Call `create_minimal_update("commitment-uuid", "commitment", "inform", "Progress update")`.

**Step 27.** Write test `test_update_all_action_types` -- every action type accepted.
- **What**: For each of all 15 types: create update, validate, assert success.

**Step 28.** Write test `test_update_invalid_action_type` -- rejects unknown action.

**Step 29.** Write test `test_update_all_target_types` -- task, commitment, todo.

**Step 30.** Write test `test_update_invalid_target_type` -- rejects unknown target.

**Step 31.** Write test `test_update_references_parent_document` -- UUID target ref.

**Step 32.** Write test `test_update_invalid_target_not_uuid` -- rejects non-UUID target.

**Step 33.** Write test `test_update_with_note` -- optional note field.

**Step 34.** Write test `test_update_chain` -- chained via `jacsUpdatePreviousUpdateId`.
- **What**: Create update1, create update2 with previous pointing to update1, validate chain.

**Step 35.** Write test `test_update_with_agent_assignment` -- `jacsUpdateAssignedAgent`.

**Step 36.** Write test `test_update_missing_required_target_id` -- rejects missing target.

**Step 37.** Write test `test_update_missing_required_action` -- rejects missing action.

**Step 38.** Create component schema `jacs/schemas/components/update/v1/update.schema.json`:
- `jacsUpdateTargetId` (UUID string, required)
- `jacsUpdateTargetType` (enum: "task", "commitment", "todo", required)
- `jacsUpdateAction` (enum of 15 action types, required)
- `jacsUpdateNote` (string, optional)
- `jacsUpdatePreviousUpdateId` (UUID string, optional)
- `jacsUpdateAssignedAgent` (UUID string, optional)
- **Pattern**: Follow `jacs/schemas/components/action/v1/action.schema.json`

**Step 39.** Create top-level `jacs/schemas/update/v1/update.schema.json`.
- **What**: `allOf` with header + `$ref` to update component.

**Step 40.** Add update schemas to `Cargo.toml`.

**Step 41.** Add to `DEFAULT_SCHEMA_STRINGS` and `SCHEMA_SHORT_NAME`.

**Step 42.** Add `updateschema: Validator` to `Schema` struct, compile.

**Step 43.** Add `validate_update()` method.

**Step 44.** Create `src/schema/update_crud.rs`:
- `create_minimal_update(target_id, target_type, action, note) -> Result<Value, String>`
- `create_task_update(task_id, action, note)` -- convenience
- `create_commitment_update(commitment_id, action, note)` -- convenience
- `create_todo_update(todo_id, action, note)` -- convenience
- `set_previous_update(update, previous_id)` -- chain updates
- `set_assigned_agent(update, agent_id)`
- Add `pub mod update_crud;` to `src/schema/mod.rs`.

### Phase 1B continued: Update Integration Tests (Steps 45-50)

**Step 45.** Write test `test_update_signing_and_verification`.

**Step 46.** Write test `test_update_chain_verification` -- 3 chained updates, all signed.

**Step 47.** Write test `test_update_from_different_agents` -- two agents update same target.

**Step 48.** Write test `test_update_header_fields_present`.

**Step 49.** Write test `test_update_semantic_action_coverage` -- one per category.

**Step 50.** Run all update tests + regression.

### Phase 1C: Todo List Schema (Steps 51-75)

**Step 51.** Write test `test_create_minimal_todo_list` in `jacs/tests/todo_tests.rs`.
- **What**: `create_minimal_todo_list("Active Work")`, assert `jacsType` = "todo", `jacsTodoName`, empty `jacsTodoItems`, `jacsLevel` = "config".

**Step 52.** Write test `test_todo_list_with_goal_item` -- goal-type inline item.

**Step 53.** Write test `test_todo_list_with_task_item` -- task-type inline item.

**Step 54.** Write test `test_todo_goal_with_child_tasks` -- childItemIds referencing by UUID.

**Step 55.** Write test `test_todo_item_all_valid_statuses` -- pending, in-progress, completed, abandoned.

**Step 56.** Write test `test_todo_item_invalid_status`.

**Step 57.** Write test `test_todo_item_all_priorities` -- low, medium, high, critical.

**Step 58.** Write test `test_todo_item_references_commitment` -- relatedCommitmentId.

**Step 59.** Write test `test_todo_item_with_tags`.

**Step 60.** Write test `test_todo_item_references_conversation` -- relatedConversationThread.

**Step 61.** Write test `test_todo_list_archive_refs`.

**Step 62.** Write test `test_todo_list_schema_validation_rejects_invalid` -- multiple negative cases.

**Step 63.** Write test `test_todo_item_missing_required_description`.

**Step 64.** Write test `test_todo_item_missing_required_status`.

**Step 65.** Write test `test_todo_item_missing_required_itemtype`.

**Step 66.** Create schema `jacs/schemas/todo/v1/todo.schema.json`.
- `jacsTodoName` (string, required)
- `jacsTodoItems` (array of objects referencing todoitem component, required)
- `jacsTodoArchiveRefs` (array of UUID strings, optional)

**Step 67.** Create component `jacs/schemas/components/todoitem/v1/todoitem.schema.json`.
- `itemType` (enum: "goal", "task", required)
- `description` (string, required)
- `status` (enum: "pending", "in-progress", "completed", "abandoned", required)
- `priority` (enum: "low", "medium", "high", "critical", optional)
- `itemId` (UUID string, required) -- stable, immutable across re-signing
- `childItemIds` (array of UUID strings, optional)
- `relatedCommitmentId` (UUID string, optional)
- `relatedConversationThread` (UUID string, optional)
- `completedDate` (date-time, optional)
- `assignedAgent` (UUID string, optional)
- `tags` (array of strings, optional)

**Step 68.** Add todo and todoitem schemas to `Cargo.toml`.

**Step 69.** Add to `DEFAULT_SCHEMA_STRINGS` phf_map.

**Step 70.** Add to `SCHEMA_SHORT_NAME` map.

**Step 71.** Add `todoschema: Validator` to `Schema` struct.

**Step 72.** Compile todo validator in `Schema::new()`.

**Step 73.** Add `validate_todo()` method.

**Step 74.** Create `src/schema/todo_crud.rs`:
- `create_minimal_todo_list(name: &str) -> Result<Value, String>`
- `add_todo_item(list, item_type, description, priority) -> Result<(), String>`
- `update_todo_item_status(list, item_id, new_status) -> Result<(), String>`
- `mark_todo_item_complete(list, item_id) -> Result<(), String>` -- sets completedDate
- `add_child_to_item(list, parent_item_id, child_item_id) -> Result<(), String>`
- `set_item_commitment_ref(list, item_id, commitment_id) -> Result<(), String>`
- `add_archive_ref(list, archive_list_id) -> Result<(), String>`
- `remove_completed_items(list) -> Result<Value, String>` -- returns removed items
- Add `pub mod todo_crud;` to `src/schema/mod.rs`.

### Phase 1C continued: Todo Integration Tests (Steps 75-80)

**Step 75.** Write test `test_todo_list_signing_and_verification`.

**Step 76.** Write test `test_todo_list_update_and_resign` -- modify, re-sign, verify.

**Step 77.** Write test `test_todo_list_versioning_on_update` -- version changes tracked.

**Step 78.** Write test `test_todo_list_archive_workflow` -- archive completed items.

**Step 79.** Write test `test_multiple_todo_lists_per_agent`.

**Step 80.** Run all todo tests + regression.

### Phase 1D: Conversation Enhancements (Steps 81-87)

**Step 81.** Write test `test_create_conversation_message` in `jacs/tests/conversation_tests.rs`.

**Step 82.** Write test `test_conversation_thread_ordering` -- previousId chain.

**Step 83.** Write test `test_conversation_produces_commitment` -- core workflow.

**Step 84.** Write test `test_conversation_message_from_different_agents`.

**Step 85.** Review/enhance `message.schema.json` -- add `jacsMessagePreviousId`.

**Step 86.** Create `src/schema/conversation_crud.rs`:
- `create_conversation_message(thread_id, content, previous_message_id)`
- `start_new_conversation(content)` -- returns (message, new_thread_id)
- `get_thread_id(message)`
- Add `pub mod conversation_crud;` to `src/schema/mod.rs`.

**Step 87.** Run all conversation tests + regression.

### Phase 1E: Cross-References, Integrity, and Full Workflow (Steps 88-95)

**Step 88.** Write test `test_todo_references_valid_commitment`.

**Step 89.** Write test `test_commitment_references_valid_thread`.

**Step 90.** Write test `test_update_references_valid_target`.

**Step 91.** Write test `test_cross_reference_integrity_check` -- utility validates all UUID refs.

**Step 92.** Create `src/schema/reference_utils.rs`:
- `validate_references(doc, storage) -> Result<Vec<ReferenceValidation>, ...>`
- Add `pub mod reference_utils;` to `src/schema/mod.rs`.

**Step 93.** Write test `test_full_workflow_conversation_to_commitment_to_todo_with_updates`.
- **What**: Agent A and B converse -> agree on commitment -> commitment linked to todo item -> Agent B creates "inform" update -> Agent A creates "delay" update -> verify all signatures and references.

**Step 94.** **API ergonomics validation**: Write Python/Node binding function signatures (not impl) for all four types.
- **Why**: Validate Rust API translates cleanly before locking implementation.

**Step 95.** Run full Phase 1 test suite: `cargo test`.

---

## Schema Test Coverage Matrix (Phase 1)

| Schema | Positive Tests | Negative Tests | Integration Tests |
|--------|---------------|----------------|-------------------|
| Commitment | minimal, terms, dates, Q&A, completion Q&A, recurrence, agreement, task ref, conversation ref, todo ref, owner, all statuses, dispute, standalone | invalid status, bad dates, invalid date format | signing, two-agent agreement, immutable after agreement |
| Update | minimal, all 15 actions, all 3 targets, note, chain, agent assignment | invalid action, invalid target, non-UUID target, missing target, missing action | signing, chain verification, multi-agent, header fields, semantic coverage |
| Todo | minimal, goal item, task item, childItemIds, all statuses, all priorities, commitment ref, conversation ref, archive refs, tags | invalid status, invalid itemtype, missing description/status/itemtype/name | signing, resign, versioning, archive workflow, multiple lists |
| Conversation | message with thread, ordering, multi-agent, produces commitment | (uses existing message schema tests) | signing, multi-agent messages |

---

## Files Created/Modified in Phase 1

| File | Action | Description |
|------|--------|-------------|
| `jacs/schemas/commitment/v1/commitment.schema.json` | CREATE | Commitment document schema |
| `jacs/schemas/components/update/v1/update.schema.json` | CREATE | Update component schema |
| `jacs/schemas/update/v1/update.schema.json` | CREATE | Update top-level schema |
| `jacs/schemas/todo/v1/todo.schema.json` | CREATE | Todo list document schema |
| `jacs/schemas/components/todoitem/v1/todoitem.schema.json` | CREATE | Todo item component schema |
| `jacs/schemas/message/v1/message.schema.json` | MODIFY | Add `jacsMessagePreviousId` |
| `jacs/src/schema/commitment_crud.rs` | CREATE | Commitment CRUD functions |
| `jacs/src/schema/update_crud.rs` | CREATE | Update CRUD functions |
| `jacs/src/schema/todo_crud.rs` | CREATE | Todo list CRUD functions |
| `jacs/src/schema/conversation_crud.rs` | CREATE | Conversation CRUD functions |
| `jacs/src/schema/reference_utils.rs` | CREATE | Cross-reference validation |
| `jacs/src/schema/mod.rs` | MODIFY | Module declarations, Schema fields, validators |
| `jacs/src/schema/utils.rs` | MODIFY | Schema entries in phf_maps |
| `jacs/Cargo.toml` | MODIFY | Include new schema files |
| `jacs/tests/commitment_tests.rs` | CREATE | Commitment test suite |
| `jacs/tests/update_tests.rs` | CREATE | Update test suite |
| `jacs/tests/todo_tests.rs` | CREATE | Todo list test suite |
| `jacs/tests/conversation_tests.rs` | CREATE | Conversation test suite |
