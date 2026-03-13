# Todo Item Schema

```txt
https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json
```

An inline item within a todo list. Can be a goal (broad objective) or task (specific action). Each item has a stable UUID for cross-referencing.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [todoitem.schema.json](../../schemas/components/todoitem/v1/todoitem.schema.json "open original schema") |

## Todo Item Type

`object` ([Todo Item](todoitem.md))

# Todo Item Properties

| Property                                                | Type     | Required | Nullable       | Defined by                                                                                                                                                               |
| :------------------------------------------------------ | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [itemId](#itemid)                                       | `string` | Required | cannot be null | [Todo Item](todoitem-properties-itemid.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/itemId")                                       |
| [itemType](#itemtype)                                   | `string` | Required | cannot be null | [Todo Item](todoitem-properties-itemtype.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/itemType")                                   |
| [description](#description)                             | `string` | Required | cannot be null | [Todo Item](todoitem-properties-description.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/description")                             |
| [status](#status)                                       | `string` | Required | cannot be null | [Todo Item](todoitem-properties-status.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/status")                                       |
| [priority](#priority)                                   | `string` | Optional | cannot be null | [Todo Item](todoitem-properties-priority.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/priority")                                   |
| [childItemIds](#childitemids)                           | `array`  | Optional | cannot be null | [Todo Item](todoitem-properties-childitemids.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/childItemIds")                           |
| [relatedCommitmentId](#relatedcommitmentid)             | `string` | Optional | cannot be null | [Todo Item](todoitem-properties-relatedcommitmentid.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/relatedCommitmentId")             |
| [relatedConversationThread](#relatedconversationthread) | `string` | Optional | cannot be null | [Todo Item](todoitem-properties-relatedconversationthread.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/relatedConversationThread") |
| [completedDate](#completeddate)                         | `string` | Optional | cannot be null | [Todo Item](todoitem-properties-completeddate.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/completedDate")                         |
| [assignedAgent](#assignedagent)                         | `string` | Optional | cannot be null | [Todo Item](todoitem-properties-assignedagent.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/assignedAgent")                         |
| [tags](#tags)                                           | `array`  | Optional | cannot be null | [Todo Item](todoitem-properties-tags.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/tags")                                           |

## itemId

Stable UUID for this item. Does not change when the list is re-signed.

`itemId`

* is required

* Type: `string`

* cannot be null

* defined in: [Todo Item](todoitem-properties-itemid.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/itemId")

### itemId Type

`string`

### itemId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## itemType

Whether this is a broad goal or a specific task.

`itemType`

* is required

* Type: `string`

* cannot be null

* defined in: [Todo Item](todoitem-properties-itemtype.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/itemType")

### itemType Type

`string`

### itemType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value    | Explanation |
| :------- | :---------- |
| `"goal"` |             |
| `"task"` |             |

## description

Human-readable description of the item.

`description`

* is required

* Type: `string`

* cannot be null

* defined in: [Todo Item](todoitem-properties-description.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/description")

### description Type

`string`

## status

Current status of the item.

`status`

* is required

* Type: `string`

* cannot be null

* defined in: [Todo Item](todoitem-properties-status.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/status")

### status Type

`string`

### status Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value           | Explanation |
| :-------------- | :---------- |
| `"pending"`     |             |
| `"in-progress"` |             |
| `"completed"`   |             |
| `"abandoned"`   |             |

## priority

Priority level of the item.

`priority`

* is optional

* Type: `string`

* cannot be null

* defined in: [Todo Item](todoitem-properties-priority.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/priority")

### priority Type

`string`

### priority Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"low"`      |             |
| `"medium"`   |             |
| `"high"`     |             |
| `"critical"` |             |

## childItemIds

UUIDs of child items (sub-goals or tasks under a goal).

`childItemIds`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Todo Item](todoitem-properties-childitemids.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/childItemIds")

### childItemIds Type

`string[]`

## relatedCommitmentId

UUID of a commitment that formalizes this item.

`relatedCommitmentId`

* is optional

* Type: `string`

* cannot be null

* defined in: [Todo Item](todoitem-properties-relatedcommitmentid.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/relatedCommitmentId")

### relatedCommitmentId Type

`string`

### relatedCommitmentId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## relatedConversationThread

UUID of a conversation thread related to this item.

`relatedConversationThread`

* is optional

* Type: `string`

* cannot be null

* defined in: [Todo Item](todoitem-properties-relatedconversationthread.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/relatedConversationThread")

### relatedConversationThread Type

`string`

### relatedConversationThread Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## completedDate

When this item was completed.

`completedDate`

* is optional

* Type: `string`

* cannot be null

* defined in: [Todo Item](todoitem-properties-completeddate.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/completedDate")

### completedDate Type

`string`

### completedDate Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## assignedAgent

UUID of the agent assigned to this item.

`assignedAgent`

* is optional

* Type: `string`

* cannot be null

* defined in: [Todo Item](todoitem-properties-assignedagent.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/assignedAgent")

### assignedAgent Type

`string`

### assignedAgent Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## tags

Tags for categorization.

`tags`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Todo Item](todoitem-properties-tags.md "https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/tags")

### tags Type

`string[]`
