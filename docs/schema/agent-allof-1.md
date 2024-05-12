# Untitled object in Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [agent.schema.json\*](../../out/agent/v1/agent.schema.json "open original schema") |

## 1 Type

`object` ([Details](agent-allof-1.md))

# 1 Properties

| Property                        | Type     | Required | Nullable       | Defined by                                                                                                                               |
| :------------------------------ | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsAgentType](#jacsagenttype) | `string` | Required | cannot be null | [Agent](agent-allof-1-properties-jacsagenttype.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsAgentType") |
| [jacsServices](#jacsservices)   | `array`  | Required | cannot be null | [Agent](agent-allof-1-properties-jacsservices.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsServices")   |
| [jacsContacts](#jacscontacts)   | `array`  | Optional | cannot be null | [Agent](agent-allof-1-properties-jacscontacts.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsContacts")   |

## jacsAgentType

Type of the agent. 'human' indicates a biological entity, 'human-org' indicates a group of people, hybrid' indicates a combination of human and artificial components, 'ai' indicates a fully artificial intelligence.

`jacsAgentType`

* is required

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacsagenttype.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsAgentType")

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

## jacsServices

Services the agent can perform.

`jacsServices`

* is required

* Type: unknown\[]

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacsservices.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsServices")

### jacsServices Type

unknown\[]

### jacsServices Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

## jacsContacts

Contact information for the agent

`jacsContacts`

* is optional

* Type: unknown\[]

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacscontacts.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsContacts")

### jacsContacts Type

unknown\[]
