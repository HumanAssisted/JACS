# README

## Top-level Schemas

*   [Action](./action.md "General type of actions a resource or agent can take, and a set of things that can happen to a resource or agent") – `https://hai.ai/schemas/action/v1/action-schema.json`

*   [Agent](./resource.md "General schema for stateful resources") – `https://hai.ai/schemas/resource/v1/resource-schema.json`

*   [Agent](./agent.md "General schema for human, hybrid, and AI agents") – `https://hai.ai/schemas/agent/v1/agent-schema.json`

*   [Decision](./decision.md "descision is a log message of version changes, actions or edits, verified with a signature") – `https://hai.ai/schemas/decision/v1/decision-schema.json`

*   [File](./files.md "General resource for a file, document not in JACS") – `https://hai.ai/file/agent/v1/file-schema.json`

*   [Message](./message.md "A signed, immutable message from a user") – `https://hai.ai/schemas/message/v1/message-schema.json`

*   [Permission](./permission.md "Provides agents access to fields for reading, writing, signing, and amdin") – `https://hai.ai/schemas/permission/v1/permission-schema.json`

*   [Signature](./signature.md "Proof of signature, meant to be embedded in other documents") – `https://hai.ai/schemas/signature/v1/signature-schema.json`

*   [Task](./task.md "General schema for a task") – `https://hai.ai/schemas/task/v1/task-schema.json`

*   [Unit](./unit.md "Labels for quantitative values") – `https://hai.ai/schemas/unit/v1/unit.schema.json`

## Other Schemas

### Objects

*   [Untitled object in Agent](./agent-allof-1.md) – `https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1`

*   [Untitled object in File](./files-allof-1.md) – `https://hai.ai/file/agent/v1/file-schema.json#/allOf/1`

### Arrays

*   [Untitled array in Action](./action-properties-units.md "units that can be modified") – `https://hai.ai/schemas/action/v1/action-schema.json#/properties/units`

*   [Untitled array in Agent](./resource-properties-capabilities.md) – `https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/capabilities`

*   [Untitled array in Agent](./resource-properties-modifications.md) – `https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/modifications`

*   [Untitled array in Agent](./resource-properties-quantifications.md "array of quantitative units defining the resource") – `https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/quantifications`

*   [Untitled array in Agent](./resource-properties-quantifications-items.md) – `https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/quantifications/items`

*   [Untitled array in Decision](./decision-properties-messages.md) – `https://hai.ai/schemas/decision/v1/decision-schema.json#/properties/messages`

*   [Untitled array in Message](./message-properties-originalcontent.md) – `https://hai.ai/schemas/message/v1/message-schema.json#/properties/originalContent`

*   [Untitled array in Permission](./permission-properties-fields.md "array of fields for specific permissions") – `https://hai.ai/schemas/permission/v1/permission-schema.json#/properties/fields`

*   [Untitled array in Permission](./permission-properties-fields-items.md) – `https://hai.ai/schemas/permission/v1/permission-schema.json#/properties/fields/items`

*   [Untitled array in Signature](./signature-properties-fields.md "what fields from document were used to generate signature") – `https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/fields`

*   [Untitled array in Task](./task-properties-permissions.md) – `https://hai.ai/schemas/task/v1/task-schema.json#/properties/permissions`

*   [Untitled array in Task](./task-properties-files.md) – `https://hai.ai/schemas/task/v1/task-schema.json#/properties/files`

*   [Untitled array in Task](./task-properties-resources.md) – `https://hai.ai/schemas/task/v1/task-schema.json#/properties/resources`

*   [Untitled array in Task](./task-properties-actionsdesired.md) – `https://hai.ai/schemas/task/v1/task-schema.json#/properties/actionsDesired`

*   [Untitled array in Task](./task-properties-descisions.md) – `https://hai.ai/schemas/task/v1/task-schema.json#/properties/descisions`

*   [Untitled array in Task](./task-properties-subtaskof.md) – `https://hai.ai/schemas/task/v1/task-schema.json#/properties/subTaskOf`

*   [Untitled array in Task](./task-properties-copyof.md) – `https://hai.ai/schemas/task/v1/task-schema.json#/properties/copyOf`

*   [Untitled array in Task](./task-properties-mergedtasks.md) – `https://hai.ai/schemas/task/v1/task-schema.json#/properties/mergedTasks`

## Version Note

The schemas linked above follow the JSON Schema Spec version: `http://json-schema.org/draft-07/schema#`
