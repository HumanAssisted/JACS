# Conversation Schema

Conversations use the existing message schema enhanced with thread tracking and message ordering. There is no separate "conversation" schema - conversations are sequences of signed messages sharing a thread ID.

## Schema

- **ID**: `https://hai.ai/schemas/message/v1/message.schema.json`
- **Type**: `jacsType: "message"`
- **Level**: `jacsLevel: "raw"` (immutable once signed)
- **Extends**: `header.schema.json` via `allOf`

## Message Fields

### Required

| Field | Type | Description |
|-------|------|-------------|
| `to` | string[] | Recipient agent identifiers |
| `from` | string[] | Sender agent identifiers |
| `content` | object | Message body (free-form object) |

### Optional

| Field | Type | Description |
|-------|------|-------------|
| `threadID` | string | UUID of the conversation thread |
| `jacsMessagePreviousId` | uuid | UUID of the previous message in this thread |
| `attachments` | array | File attachments |

## Threading Model

Messages form a thread via two fields:

1. **`threadID`** - All messages in a conversation share the same thread ID
2. **`jacsMessagePreviousId`** - Each message references the previous one, creating an ordered chain

```
Message 1 (threadID: "abc-123", previousId: null)
    └── Message 2 (threadID: "abc-123", previousId: msg1.jacsId)
         └── Message 3 (threadID: "abc-123", previousId: msg2.jacsId)
```

## Immutability

Messages use `jacsLevel: "raw"`, making them immutable once signed. To continue a conversation, create a new message referencing the previous one. This ensures the integrity of the conversation history.

## Example

```json
{
  "$schema": "https://hai.ai/schemas/message/v1/message.schema.json",
  "threadID": "550e8400-e29b-41d4-a716-446655440000",
  "content": {
    "body": "I agree to the proposed terms.",
    "subject": "Re: Q1 Deliverables"
  },
  "to": ["agent-b-uuid"],
  "from": ["agent-a-uuid"],
  "jacsMessagePreviousId": "660e8400-e29b-41d4-a716-446655440001",
  "jacsType": "message",
  "jacsLevel": "raw"
}
```

## Rust API

```rust
use jacs::schema::conversation_crud::*;

// Start a new conversation (generates thread ID)
let (first_msg, thread_id) = start_new_conversation(
    serde_json::json!({"body": "Hello, let's discuss terms."}),
    vec!["agent-b".to_string()],
    vec!["agent-a".to_string()],
).unwrap();

// Continue the conversation
let reply = create_conversation_message(
    &thread_id,
    serde_json::json!({"body": "Sounds good. Here are my terms."}),
    vec!["agent-a".to_string()],
    vec!["agent-b".to_string()],
    Some(&previous_message_jacs_id),
).unwrap();

// Extract thread info
let tid = get_thread_id(&message).unwrap();
let prev = get_previous_message_id(&message);
```

## Cross-References

Conversations can be referenced by other document types:

- **Commitment**: `jacsCommitmentConversationRef` stores the thread UUID
- **Todo item**: `relatedConversationThread` stores the thread UUID

This allows tracking which conversation led to a commitment or is related to a work item.

## See Also

- [Commitment Schema](commitment.md) - Agreements arising from conversations
- [Todo List Schema](todo.md) - Private task tracking
- [Document Schema](document.md) - Header fields and signing
