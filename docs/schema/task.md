# Task Schema

```txt
https://hai.ai/schemas/task/v1/task-schema.json
```

General schema for a task

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [task.schema.json](../../schemas/task/v1/task.schema.json "open original schema") |

## Task Type

`object` ([Task](task.md))

# Task Properties

| Property                          | Type     | Required | Nullable       | Defined by                                                                                                             |
| :-------------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                         | `string` | Required | cannot be null | [Task](task-properties-id.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/id")                         |
| [name](#name)                     | `string` | Required | cannot be null | [Task](task-properties-name.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/name")                     |
| [description](#description)       | `string` | Required | cannot be null | [Task](task-properties-description.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/description")       |
| [success](#success)               | `string` | Required | cannot be null | [Task](task-properties-success.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/success")               |
| [version](#version)               | `string` | Optional | cannot be null | [Task](task-properties-version.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/version")               |
| [version\_date](#version_date)    | `string` | Optional | cannot be null | [Task](task-properties-version_date.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/version_date")     |
| [registration](#registration)     | `object` | Optional | cannot be null | [Task](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/registration")   |
| [creator](#creator)               | `object` | Optional | cannot be null | [Task](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/creator")        |
| [lockedState](#lockedstate)       | `string` | Optional | cannot be null | [Task](task-properties-lockedstate.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/lockedState")       |
| [lockedBy](#lockedby)             | `string` | Optional | cannot be null | [Task](task-properties-lockedby.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/lockedBy")             |
| [lockedUntil](#lockeduntil)       | `string` | Optional | cannot be null | [Task](task-properties-lockeduntil.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/lockedUntil")       |
| [permissions](#permissions)       | `array`  | Required | cannot be null | [Task](task-properties-permissions.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/permissions")       |
| [files](#files)                   | `array`  | Optional | cannot be null | [Task](task-properties-files.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/files")                   |
| [resources](#resources)           | `array`  | Optional | cannot be null | [Task](task-properties-resources.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/resources")           |
| [actionsDesired](#actionsdesired) | `array`  | Optional | cannot be null | [Task](task-properties-actionsdesired.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/actionsDesired") |
| [descisions](#descisions)         | `array`  | Optional | cannot be null | [Task](task-properties-descisions.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/descisions")         |
| [subTaskOf](#subtaskof)           | `array`  | Optional | cannot be null | [Task](task-properties-subtaskof.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/subTaskOf")           |
| [copyOf](#copyof)                 | `array`  | Optional | cannot be null | [Task](task-properties-copyof.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/copyOf")                 |
| [mergedTasks](#mergedtasks)       | `array`  | Optional | cannot be null | [Task](task-properties-mergedtasks.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/mergedTasks")       |

## id

Resource GUID

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-properties-id.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/id")

### id Type

`string`

### id Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## name

Name of the agent, unique per registrar

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-properties-name.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/name")

### name Type

`string`

## description

General description

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-properties-description.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/description")

### description Type

`string`

## success

Description of success

`success`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-properties-success.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/success")

### success Type

`string`

## version

Semantic of the version of the task

`version`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-properties-version.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/version")

### version Type

`string`

## version\_date

Date

`version_date`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-properties-version_date.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/version_date")

### version\_date Type

`string`

### version\_date Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## registration

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`registration`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Task](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/registration")

### registration Type

`object` ([Signature](signature.md))

## creator

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`creator`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Task](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/creator")

### creator Type

`object` ([Signature](signature.md))

## lockedState

Is the document locked from edits

`lockedState`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-properties-lockedstate.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/lockedState")

### lockedState Type

`string`

### lockedState Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"open"`     |             |
| `"editlock"` |             |
| `"closed"`   |             |

## lockedBy

Agent ID holding lock

`lockedBy`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-properties-lockedby.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/lockedBy")

### lockedBy Type

`string`

### lockedBy Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## lockedUntil

When the lock expires

`lockedUntil`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-properties-lockeduntil.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/lockedUntil")

### lockedUntil Type

`string`

### lockedUntil Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## permissions



`permissions`

*   is required

*   Type: `object[]` ([Permission](permission.md))

*   cannot be null

*   defined in: [Task](task-properties-permissions.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/permissions")

### permissions Type

`object[]` ([Permission](permission.md))

## files



`files`

*   is optional

*   Type: an array of merged types ([File](files.md))

*   cannot be null

*   defined in: [Task](task-properties-files.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/files")

### files Type

an array of merged types ([File](files.md))

## resources



`resources`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Task](task-properties-resources.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/resources")

### resources Type

`string[]`

## actionsDesired



`actionsDesired`

*   is optional

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Task](task-properties-actionsdesired.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/actionsDesired")

### actionsDesired Type

`object[]` ([Action](action.md))

## descisions



`descisions`

*   is optional

*   Type: `object[]` ([Decision](decision.md))

*   cannot be null

*   defined in: [Task](task-properties-descisions.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/descisions")

### descisions Type

`object[]` ([Decision](decision.md))

## subTaskOf



`subTaskOf`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Task](task-properties-subtaskof.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/subTaskOf")

### subTaskOf Type

`string[]`

## copyOf



`copyOf`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Task](task-properties-copyof.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/copyOf")

### copyOf Type

`string[]`

## mergedTasks



`mergedTasks`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Task](task-properties-mergedtasks.md "https://hai.ai/schemas/task/v1/task-schema.json#/properties/mergedTasks")

### mergedTasks Type

`string[]`
