# Untitled string in Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent-schema.json#/properties/agentType
```

Type of the agent. 'human' indicates a biological entity; 'hybrid' indicates a combination of human and artificial components; 'ai' indicates a fully artificial intelligence.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                          |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agent.schema.json\*](../../schemas/agent/agent.schema.json "open original schema") |

## agentType Type

`string`

## agentType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value      | Explanation |
| :--------- | :---------- |
| `"human"`  |             |
| `"hybrid"` |             |
| `"ai"`     |             |
