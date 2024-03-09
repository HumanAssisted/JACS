# Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent-schema.json
```

General schema for human, hybrid, and AI agents

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [agent.schema.json](../../schemas/agent/agent.schema.json "open original schema") |

## Agent Type

`object` ([Agent](agent.md))

# Agent Properties

| Property                                           | Type     | Required | Nullable       | Defined by                                                                                                                                 |
| :------------------------------------------------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                                          | `string` | Required | cannot be null | [Agent](agent-properties-id.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/id")                                         |
| [version](#version)                                | `string` | Optional | cannot be null | [Agent](agent-properties-version.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/version")                               |
| [version\_date](#version_date)                     | `string` | Optional | cannot be null | [Agent](agent-properties-version_date.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/version_date")                     |
| [public\_key](#public_key)                         | `string` | Optional | cannot be null | [Agent](agent-properties-public_key.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/public_key")                         |
| [registered\_with](#registered_with)               | `string` | Optional | cannot be null | [Agent](agent-properties-registered_with.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/registered_with")               |
| [registration\_signature](#registration_signature) | `string` | Optional | cannot be null | [Agent](agent-properties-registration_signature.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/registration_signature") |
| [registered\_date](#registered_date)               | `string` | Optional | cannot be null | [Agent](agent-properties-registered_date.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/registered_date")               |
| [agenttype](#agenttype)                            | `string` | Required | cannot be null | [Agent](agent-properties-agenttype.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/agenttype")                           |
| [name](#name)                                      | `string` | Required | cannot be null | [Agent](agent-properties-name.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/name")                                     |
| [description](#description)                        | `string` | Required | cannot be null | [Agent](agent-properties-description.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/description")                       |
| [actions](#actions)                                | `array`  | Required | cannot be null | [Agent](agent-properties-actions.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/actions")                               |

## id

Agent GUID

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-id.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/id")

### id Type

`string`

## version

Semantic Version number of the Agent

`version`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-version.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/version")

### version Type

`string`

## version\_date

Date

`version_date`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-version_date.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/version_date")

### version\_date Type

`string`

### version\_date Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## public\_key

Public key for verifying signatures.

`public_key`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-public_key.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/public_key")

### public\_key Type

`string`

## registered\_with

Organization

`registered_with`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-registered_with.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/registered_with")

### registered\_with Type

`string`

## registration\_signature

Signature from registrar for verifying

`registration_signature`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-registration_signature.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/registration_signature")

### registration\_signature Type

`string`

## registered\_date

date registred

`registered_date`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-registered_date.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/registered_date")

### registered\_date Type

`string`

### registered\_date Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## agenttype

Type of the agent. 'human' indicates a biological entity; 'hybrid' indicates a combination of human and artificial components; 'ai' indicates a fully artificial intelligence.

`agenttype`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-agenttype.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/agenttype")

### agenttype Type

`string`

### agenttype Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value      | Explanation |
| :--------- | :---------- |
| `"human"`  |             |
| `"hybrid"` |             |
| `"ai"`     |             |

## name

Name of the agent, unique per registrar

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-name.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/name")

### name Type

`string`

## description

General description

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-properties-description.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/description")

### description Type

`string`

## actions



`actions`

*   is required

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Agent](agent-properties-actions.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/actions")

### actions Type

`object[]` ([Action](action.md))
