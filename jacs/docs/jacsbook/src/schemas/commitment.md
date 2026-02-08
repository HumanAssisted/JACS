# Commitment Schema

Commitments are shared, signed agreements between agents. They represent what an agent commits to doing, optionally within a conversation or linked to a task or todo item.

**Key design**: Commitments work standalone. They do not require goals, tasks, conversations, or any other document type to be created first.

## Schema

- **ID**: `https://hai.ai/schemas/commitment/v1/commitment.schema.json`
- **Type**: `jacsType: "commitment"`
- **Level**: `jacsLevel: "config"` (editable, versioned)
- **Extends**: `header.schema.json` via `allOf`

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `jacsCommitmentDescription` | string | Human-readable description of the commitment |
| `jacsCommitmentStatus` | enum | Lifecycle status |

## Status Lifecycle

```
pending -> active -> completed
                  -> failed
                  -> renegotiated
         -> disputed
         -> revoked
```

| Status | Meaning |
|--------|---------|
| `pending` | Created but not yet started |
| `active` | Work is underway |
| `completed` | Successfully fulfilled |
| `failed` | Could not be fulfilled |
| `renegotiated` | Terms changed, replaced by new commitment |
| `disputed` | One party contests the commitment |
| `revoked` | Withdrawn by the owner |

## Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `jacsCommitmentTerms` | object | Structured terms (deliverable, deadline, compensation, etc.) |
| `jacsCommitmentDisputeReason` | string | Reason when status is `disputed` or `revoked` |
| `jacsCommitmentTaskId` | uuid | Reference to a task document |
| `jacsCommitmentConversationRef` | uuid | Thread ID of the conversation that produced this commitment |
| `jacsCommitmentTodoRef` | string | Todo item reference in format `list-uuid:item-uuid` |
| `jacsCommitmentQuestion` | string | Structured question prompt |
| `jacsCommitmentAnswer` | string | Answer to the question |
| `jacsCommitmentCompletionQuestion` | string | Question to verify completion |
| `jacsCommitmentCompletionAnswer` | string | Answer verifying completion |
| `jacsCommitmentStartDate` | date-time | When the commitment period begins |
| `jacsCommitmentEndDate` | date-time | Deadline |
| `jacsCommitmentRecurrence` | object | Recurrence pattern (`frequency` + `interval`) |
| `jacsCommitmentOwner` | signature | Single-agent owner signature |

## Cross-References

Commitments can link to other document types:

- **Conversation**: `jacsCommitmentConversationRef` holds a thread UUID
- **Todo item**: `jacsCommitmentTodoRef` uses format `list-uuid:item-uuid`
- **Task**: `jacsCommitmentTaskId` holds a task document UUID

These references are optional. Commitments work independently.

## Multi-Agent Agreements

Commitments use the standard JACS agreement mechanism from the header schema. Two or more agents can co-sign a commitment using `jacsAgreement`.

## Example

```json
{
  "$schema": "https://hai.ai/schemas/commitment/v1/commitment.schema.json",
  "jacsCommitmentDescription": "Deliver Q1 analytics report by March 15",
  "jacsCommitmentStatus": "active",
  "jacsCommitmentTerms": {
    "deliverable": "PDF report with charts",
    "deadline": "2026-03-15T00:00:00Z"
  },
  "jacsCommitmentStartDate": "2026-01-15T00:00:00Z",
  "jacsCommitmentEndDate": "2026-03-15T00:00:00Z",
  "jacsType": "commitment",
  "jacsLevel": "config"
}
```

## Rust API

```rust
use jacs::schema::commitment_crud::*;

// Create
let commitment = create_minimal_commitment("Deliver report").unwrap();

// With structured terms
let commitment = create_commitment_with_terms(
    "Weekly standup",
    serde_json::json!({"frequency": "weekly"}),
).unwrap();

// Update status
update_commitment_status(&mut commitment, "active").unwrap();

// Dispute
dispute_commitment(&mut commitment, "Terms not met").unwrap();

// Cross-references
set_conversation_ref(&mut commitment, &thread_id).unwrap();
set_todo_ref(&mut commitment, "list-uuid:item-uuid").unwrap();
set_task_ref(&mut commitment, &task_id).unwrap();
```

## Versioning

Since commitments use `jacsLevel: "config"`, they can be updated. Each update creates a new `jacsVersion` linked to the previous via `jacsPreviousVersion`. This provides a full audit trail of status changes and modifications.

## See Also

- [Todo List Schema](todo.md) - Private task tracking
- [Conversation Schema](conversation.md) - Message threading
- [Document Schema](document.md) - Header fields and signing
