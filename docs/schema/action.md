# Action Schema

```txt
https://hai.ai/schemas/components/action/v1/action-schema.json
```

General type of actions a resource or agent can take, and a set of things that can happen to a resource or agent.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [action.schema.json](../../schemas/components/action/v1/action.schema.json "open original schema") |

## Action Type

`object` ([Action](action.md))

# Action Properties

| Property                | Type     | Required | Nullable       | Defined by                                                                                                                      |
| :---------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------ |
| [id](#id)               | `string` | Required | cannot be null | [Action](action-properties-id.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/id")               |
| [version](#version)     | `string` | Optional | cannot be null | [Action](action-properties-version.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/version")     |
| [name](#name)           | `string` | Required | cannot be null | [Action](action-properties-name.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/name")           |
| [operation](#operation) | `string` | Required | cannot be null | [Action](action-properties-operation.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/operation") |
| [units](#units)         | `array`  | Optional | cannot be null | [Action](action-properties-units.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/units")         |

## id

Action GUID

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-id.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/id")

### id Type

`string`

### id Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## version

Semantic Version number of the action

`version`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-version.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/version")

### version Type

`string`

## name



`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-name.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/name")

### name Type

`string`

## operation

type of change that can happen

`operation`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-operation.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/operation")

### operation Type

`string`

## units

units that can be modified

`units`

*   is optional

*   Type: unknown\[]

*   cannot be null

*   defined in: [Action](action-properties-units.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/units")

### units Type

unknown\[]
