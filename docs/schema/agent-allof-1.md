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

| Property                        | Type     | Required | Nullable       | Defined by                                                                                                                               |
| :------------------------------ | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsAgentType](#jacsagenttype) | `string` | Optional | cannot be null | [Agent](agent-allof-1-properties-jacsagenttype.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1/properties/jacsAgentType") |

## jacsAgentType

Type of the agent. 'human' indicates a biological entity; 'hybrid' indicates a combination of human and artificial components; 'ai' indicates a fully artificial intelligence.

`jacsAgentType`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](agent-allof-1-properties-jacsagenttype.md "https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1/properties/jacsAgentType")

### jacsAgentType Type

`string`

### jacsAgentType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"human"`     |             |
| `"human-org"` |             |
| `"hybrid"`    |             |
| `"ai"`        |             |
