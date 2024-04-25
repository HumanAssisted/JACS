# Untitled string in Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsAgentType
```

Type of the agent. 'human' indicates a biological entity, 'human-org' indicates a group of people, hybrid' indicates a combination of human and artificial components, 'ai' indicates a fully artificial intelligence.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                             |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agent.schema.json\*](../../schemas/agent/v1/agent.schema.json "open original schema") |

## jacsAgentType Type

`string`

## jacsAgentType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"human"`     |             |
| `"human-org"` |             |
| `"hybrid"`    |             |
| `"ai"`        |             |
