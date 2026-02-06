# Phase 1: Schema Design & CRUD (Steps 1-95)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)

**Status**: Not started
**Step Range**: 1-95
**Summary**: Design and implement JSON schemas, CRUD operations, and integration tests for all four new document types: Commitment, Update, Todo List, and Conversation enhancements. Includes cross-reference integrity utilities and full workflow tests.

---

> **Note**: Goals are NOT standalone documents. Goals are inline todo items (`itemType: "goal"`) within a private todo list. When goals need to be shared, they are expressed as Commitments. Therefore, commitment is the FIRST schema we implement -- it's the primary shared document type.

## Phase 1A: Commitment Schema (Steps 1-25)

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

---

## Phase 1B: Update Tracking Schema (Steps 26-50)

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

---

## Phase 1C: Todo List Schema (Steps 51-80)

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

---

## Phase 1D: Conversation Enhancements (Steps 81-87)

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

---

## Phase 1E: Cross-References, Integrity, and Full Workflow (Steps 88-95)

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
