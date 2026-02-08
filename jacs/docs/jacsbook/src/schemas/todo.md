# Todo List Schema

Todo lists are private, signed documents belonging to a single agent. They contain inline items (goals and tasks) and are re-signed as a whole when any item changes.

## Schema

- **ID**: `https://hai.ai/schemas/todo/v1/todo.schema.json`
- **Type**: `jacsType: "todo"`
- **Level**: `jacsLevel: "config"` (editable, versioned)
- **Extends**: `header.schema.json` via `allOf`
- **Component**: `todoitem.schema.json` for inline items

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `jacsTodoName` | string | Human-readable name for this list |
| `jacsTodoItems` | array | Inline todo items |

## Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `jacsTodoArchiveRefs` | uuid[] | UUIDs of archived todo lists |

## Todo Items

Each item in `jacsTodoItems` is an inline object following `todoitem.schema.json`.

### Required Item Fields

| Field | Type | Description |
|-------|------|-------------|
| `itemId` | uuid | Stable UUID that does not change on re-signing |
| `itemType` | enum | `"goal"` (broad objective) or `"task"` (specific action) |
| `description` | string | Human-readable description |
| `status` | enum | `"pending"`, `"in-progress"`, `"completed"`, `"abandoned"` |

### Optional Item Fields

| Field | Type | Description |
|-------|------|-------------|
| `priority` | enum | `"low"`, `"medium"`, `"high"`, `"critical"` |
| `childItemIds` | uuid[] | Sub-goals or tasks under this item |
| `relatedCommitmentId` | uuid | Commitment that formalizes this item |
| `relatedConversationThread` | uuid | Conversation thread related to this item |
| `completedDate` | date-time | When the item was completed |
| `assignedAgent` | uuid | Agent assigned to this item |
| `tags` | string[] | Tags for categorization |

## Cross-References

Todo items can link to other document types:

- **Commitment**: `relatedCommitmentId` links an item to a commitment
- **Conversation**: `relatedConversationThread` links an item to a message thread

References use the `list-uuid:item-uuid` format when referenced FROM other documents (e.g., `jacsCommitmentTodoRef` on a commitment). Use `build_todo_item_ref()` and `parse_todo_item_ref()` from `reference_utils` for this format.

## Item Hierarchy

Items support parent-child relationships via `childItemIds`:

```
Goal: "Ship Q1 release"
  ├── Task: "Write documentation"
  ├── Task: "Run integration tests"
  └── Goal: "Performance optimization"
       ├── Task: "Profile database queries"
       └── Task: "Add caching layer"
```

## Example

```json
{
  "$schema": "https://hai.ai/schemas/todo/v1/todo.schema.json",
  "jacsTodoName": "Q1 Sprint",
  "jacsTodoItems": [
    {
      "itemId": "550e8400-e29b-41d4-a716-446655440001",
      "itemType": "goal",
      "description": "Ship analytics dashboard",
      "status": "in-progress",
      "priority": "high",
      "childItemIds": [
        "550e8400-e29b-41d4-a716-446655440002"
      ]
    },
    {
      "itemId": "550e8400-e29b-41d4-a716-446655440002",
      "itemType": "task",
      "description": "Build chart components",
      "status": "pending",
      "priority": "medium",
      "relatedCommitmentId": "660e8400-e29b-41d4-a716-446655440000",
      "tags": ["frontend", "charts"]
    }
  ],
  "jacsType": "todo",
  "jacsLevel": "config"
}
```

## Rust API

```rust
use jacs::schema::todo_crud::*;

// Create a list
let mut list = create_minimal_todo_list("Sprint Work").unwrap();

// Add items
let goal_id = add_todo_item(&mut list, "goal", "Ship Q1", Some("high")).unwrap();
let task_id = add_todo_item(&mut list, "task", "Write tests", None).unwrap();

// Build hierarchy
add_child_to_item(&mut list, &goal_id, &task_id).unwrap();

// Progress tracking
update_todo_item_status(&mut list, &task_id, "in-progress").unwrap();
mark_todo_item_complete(&mut list, &task_id).unwrap();

// Cross-references
set_item_commitment_ref(&mut list, &task_id, &commitment_id).unwrap();
set_item_conversation_ref(&mut list, &task_id, &thread_id).unwrap();

// Archive completed items
let completed = remove_completed_items(&mut list).unwrap();
```

## Versioning

Since todo lists use `jacsLevel: "config"`, each modification creates a new signed version. The `itemId` fields remain stable across versions, enabling consistent cross-referencing even as items are added, updated, or removed.

## See Also

- [Commitment Schema](commitment.md) - Shared agreements
- [Conversation Schema](conversation.md) - Message threading
- [Document Schema](document.md) - Header fields and signing
