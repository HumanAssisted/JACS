# Untitled undefined type in Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent.schema.json#/if
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                             |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [agent.schema.json\*](../../schemas/agent/v1/agent.schema.json "open original schema") |

## if Type

unknown

# if Properties

| Property                        | Type     | Required | Nullable       | Defined by                                                                                                                     |
| :------------------------------ | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------- |
| [jacsAgentType](#jacsagenttype) | `string` | Optional | cannot be null | [Agent](agent-if-properties-jacsagenttype.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/if/properties/jacsAgentType") |

## jacsAgentType



`jacsAgentType`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent](agent-if-properties-jacsagenttype.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/if/properties/jacsAgentType")

### jacsAgentType Type

`string`

### jacsAgentType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"human"`     |             |
| `"human-org"` |             |
| `"hybrid"`    |             |
