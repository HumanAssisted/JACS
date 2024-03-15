# Untitled object in Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                             |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [agent.schema.json\*](../../schemas/agent/v1/agent.schema.json "open original schema") |

## 1 Type

`object` ([Details](agent-allof-1.md))

# 1 Properties

| Property                                 | Type     | Required | Nullable       | Defined by                                                                                                                                       |
| :--------------------------------------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------- |
| [agenttype](#agenttype)                  | `string` | Optional | cannot be null | [Agent](agent-allof-1-properties-agenttype.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1/properties/agenttype")                 |
| [publickey](#publickey)                  | `string` | Optional | cannot be null | [Agent](agent-allof-1-properties-publickey.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1/properties/publickey")                 |
| [signing\_algorithm](#signing_algorithm) | `string` | Optional | cannot be null | [Agent](agent-allof-1-properties-signing_algorithm.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1/properties/signing_algorithm") |

## agenttype

Type of the agent. 'human' indicates a biological entity; 'hybrid' indicates a combination of human and artificial components; 'ai' indicates a fully artificial intelligence.

`agenttype`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-allof-1-properties-agenttype.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1/properties/agenttype")

### agenttype Type

`string`

### agenttype Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value      | Explanation |
| :--------- | :---------- |
| `"human"`  |             |
| `"hybrid"` |             |
| `"ai"`     |             |

## publickey

public key to verify signatures. needs mechanism to verify

`publickey`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-allof-1-properties-publickey.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1/properties/publickey")

### publickey Type

`string`

## signing\_algorithm

What signature algorithm should be used

`signing_algorithm`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-allof-1-properties-signing_algorithm.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1/properties/signing_algorithm")

### signing\_algorithm Type

`string`
