# Untitled string in Agent State Document Schema

```txt
https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateType
```

The type of agent state this document wraps. Use 'other' for general-purpose signed documents.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                            |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agentstate.schema.json\*](../../schemas/agentstate/v1/agentstate.schema.json "open original schema") |

## jacsAgentStateType Type

`string`

## jacsAgentStateType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value      | Explanation |
| :--------- | :---------- |
| `"memory"` |             |
| `"skill"`  |             |
| `"plan"`   |             |
| `"config"` |             |
| `"hook"`   |             |
| `"other"`  |             |
