# Agent State Document Schema

```txt
https://hai.ai/schemas/agentstate/v1/agentstate.schema.json
```

A signed wrapper for agent state files (memory, skills, plans, configs, hooks). References the original file by path and hash, optionally embedding content.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                          |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [agentstate.schema.json](../../schemas/agentstate/v1/agentstate.schema.json "open original schema") |

## Agent State Document Type

merged type ([Agent State Document](agentstate.md))

all of

* [Header](todo-allof-header.md "check type definition")

# Agent State Document Properties

| Property                                                | Type     | Required | Nullable       | Defined by                                                                                                                                                                     |
| :------------------------------------------------------ | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsAgentStateType](#jacsagentstatetype)               | `string` | Required | cannot be null | [Agent State Document](agentstate-properties-jacsagentstatetype.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateType")               |
| [jacsAgentStateName](#jacsagentstatename)               | `string` | Required | cannot be null | [Agent State Document](agentstate-properties-jacsagentstatename.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateName")               |
| [jacsAgentStateDescription](#jacsagentstatedescription) | `string` | Optional | cannot be null | [Agent State Document](agentstate-properties-jacsagentstatedescription.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateDescription") |
| [jacsAgentStateFramework](#jacsagentstateframework)     | `string` | Optional | cannot be null | [Agent State Document](agentstate-properties-jacsagentstateframework.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateFramework")     |
| [jacsAgentStateVersion](#jacsagentstateversion)         | `string` | Optional | cannot be null | [Agent State Document](agentstate-properties-jacsagentstateversion.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateVersion")         |
| [jacsAgentStateContentType](#jacsagentstatecontenttype) | `string` | Optional | cannot be null | [Agent State Document](agentstate-properties-jacsagentstatecontenttype.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateContentType") |
| [jacsAgentStateContent](#jacsagentstatecontent)         | `string` | Optional | cannot be null | [Agent State Document](agentstate-properties-jacsagentstatecontent.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateContent")         |
| [jacsAgentStateTags](#jacsagentstatetags)               | `array`  | Optional | cannot be null | [Agent State Document](agentstate-properties-jacsagentstatetags.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateTags")               |
| [jacsAgentStateOrigin](#jacsagentstateorigin)           | `string` | Optional | cannot be null | [Agent State Document](agentstate-properties-jacsagentstateorigin.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateOrigin")           |
| [jacsAgentStateSourceUrl](#jacsagentstatesourceurl)     | `string` | Optional | cannot be null | [Agent State Document](agentstate-properties-jacsagentstatesourceurl.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateSourceUrl")     |

## jacsAgentStateType

The type of agent state this document wraps. Use 'other' for general-purpose signed documents.

`jacsAgentStateType`

* is required

* Type: `string`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstatetype.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateType")

### jacsAgentStateType Type

`string`

### jacsAgentStateType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value      | Explanation |
| :--------- | :---------- |
| `"memory"` |             |
| `"skill"`  |             |
| `"plan"`   |             |
| `"config"` |             |
| `"hook"`   |             |
| `"other"`  |             |

## jacsAgentStateName

Human-readable name for this state document (e.g., 'JACS Project Memory', 'jacs-signing skill').

`jacsAgentStateName`

* is required

* Type: `string`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstatename.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateName")

### jacsAgentStateName Type

`string`

## jacsAgentStateDescription

Description of what this state document contains or does.

`jacsAgentStateDescription`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstatedescription.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateDescription")

### jacsAgentStateDescription Type

`string`

## jacsAgentStateFramework

Which agent framework this state file is for (e.g., 'claude-code', 'openclaw', 'langchain', 'generic').

`jacsAgentStateFramework`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstateframework.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateFramework")

### jacsAgentStateFramework Type

`string`

## jacsAgentStateVersion

Version of the agent state content (distinct from jacsVersion which tracks JACS document versions).

`jacsAgentStateVersion`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstateversion.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateVersion")

### jacsAgentStateVersion Type

`string`

## jacsAgentStateContentType

MIME type of the original content (text/markdown, application/yaml, application/json, text/x-shellscript, etc.).

`jacsAgentStateContentType`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstatecontenttype.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateContentType")

### jacsAgentStateContentType Type

`string`

## jacsAgentStateContent

The full content of the agent state file, inline. Used when embed=true or when the content should be directly in the JACS document (hooks, small configs). For larger files, use jacsFiles reference instead.

`jacsAgentStateContent`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstatecontent.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateContent")

### jacsAgentStateContent Type

`string`

## jacsAgentStateTags

Tags for categorization and search.

`jacsAgentStateTags`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstatetags.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateTags")

### jacsAgentStateTags Type

`string[]`

## jacsAgentStateOrigin

How this state document was created. 'authored' = created by the signing agent. 'adopted' = unsigned file found and signed by adopting agent. 'generated' = produced by an AI/automation. 'imported' = brought in from another JACS installation.

`jacsAgentStateOrigin`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstateorigin.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateOrigin")

### jacsAgentStateOrigin Type

`string`

### jacsAgentStateOrigin Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"authored"`  |             |
| `"adopted"`   |             |
| `"generated"` |             |
| `"imported"`  |             |

## jacsAgentStateSourceUrl

Where the original content was obtained from, if applicable (e.g., AgentSkills.io URL, ClawHub URL, git repo).

`jacsAgentStateSourceUrl`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent State Document](agentstate-properties-jacsagentstatesourceurl.md "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateSourceUrl")

### jacsAgentStateSourceUrl Type

`string`

### jacsAgentStateSourceUrl Constraints

**URI**: the string must be a URI, according to [RFC 3986](https://tools.ietf.org/html/rfc3986 "check the specification")
