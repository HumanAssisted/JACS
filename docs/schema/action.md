# Action Schema

```txt
https://hai.ai/schemas/agent/v1/action-schema.json
```

General type of actions an agent can take, and a set of things that can happen to a resource.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                           |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [action.schema.json](../../schemas/action/action.schema.json "open original schema") |

## Action Type

`object` ([Action](action.md))

# Action Properties

| Property                                             | Type     | Required | Nullable       | Defined by                                                                                                                                      |
| :--------------------------------------------------- | :------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                                            | `string` | Required | cannot be null | [Action](action-properties-id.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/id")                                           |
| [version](#version)                                  | `string` | Optional | cannot be null | [Action](action-properties-version.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/version")                                 |
| [public\_key](#public_key)                           | `string` | Optional | cannot be null | [Action](action-properties-public_key.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/public_key")                           |
| [registered\_with](#registered_with)                 | `string` | Optional | cannot be null | [Action](action-properties-registered_with.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/registered_with")                 |
| [registeration\_signature](#registeration_signature) | `string` | Optional | cannot be null | [Action](action-properties-registeration_signature.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/registeration_signature") |
| [registered\_date](#registered_date)                 | `string` | Optional | cannot be null | [Action](action-properties-registered_date.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/registered_date")                 |
| [agenttype](#agenttype)                              | `string` | Optional | cannot be null | [Action](action-properties-agenttype.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/agenttype")                             |
| [name](#name)                                        | `string` | Required | cannot be null | [Action](action-properties-name.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/name")                                       |
| [role](#role)                                        | `string` | Required | cannot be null | [Action](action-properties-role.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/role")                                       |
| [actions](#actions)                                  | `array`  | Optional | cannot be null | [Action](action-properties-actions.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/actions")                                 |

## id

Action GUID

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-id.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/id")

### id Type

`string`

## version

Semantic Version number of the Agent

`version`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-version.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/version")

### version Type

`string`

## public\_key

Public key for verifying signatures.

`public_key`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-public_key.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/public_key")

### public\_key Type

`string`

## registered\_with

Organization

`registered_with`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-registered_with.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/registered_with")

### registered\_with Type

`string`

## registeration\_signature

Signature for verifying registration

`registeration_signature`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-registeration_signature.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/registeration_signature")

### registeration\_signature Type

`string`

## registered\_date

Public key for verifying signatures.

`registered_date`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-registered_date.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/registered_date")

### registered\_date Type

`string`

## agenttype



`agenttype`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-agenttype.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/agenttype")

### agenttype Type

`string`

### agenttype Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value       | Explanation |
| :---------- | :---------- |
| `"human"`   |             |
| `"hybrid"`  |             |
| `"ai"`      |             |
| `"unknown"` |             |

## name

Name of the agent, unique

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-name.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/name")

### name Type

`string`

## role

Role of the agent

`role`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-role.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/role")

### role Type

`string`

## actions



`actions`

*   is optional

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Action](action-properties-actions.md "https://hai.ai/schemas/agent/v1/action-schema.json#/properties/actions")

### actions Type

`object[]` ([Action](action.md))
