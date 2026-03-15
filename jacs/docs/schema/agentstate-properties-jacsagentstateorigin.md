# Untitled string in Agent State Document Schema

```txt
https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateOrigin
```

How this state document was created. 'authored' = created by the signing agent. 'adopted' = unsigned file found and signed by adopting agent. 'generated' = produced by an AI/automation. 'imported' = brought in from another JACS installation.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                            |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agentstate.schema.json\*](../../schemas/agentstate/v1/agentstate.schema.json "open original schema") |

## jacsAgentStateOrigin Type

`string`

## jacsAgentStateOrigin Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"authored"`  |             |
| `"adopted"`   |             |
| `"generated"` |             |
| `"imported"`  |             |
