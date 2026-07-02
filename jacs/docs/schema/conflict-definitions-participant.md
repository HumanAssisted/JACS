# Untitled object in Conflict Schema

```txt
https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant
```

A participant in a conflict. Party-role participants hold positions. Mediator, notary, and observer roles are listed without becoming parties.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [conflict.schema.json\*](../../schemas/conflict/v1/conflict.schema.json "open original schema") |

## participant Type

`object` ([Details](conflict-definitions-participant.md))

# participant Properties

| Property                      | Type     | Required | Nullable       | Defined by                                                                                                                                                                         |
| :---------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [agentId](#agentid)           | `string` | Required | cannot be null | [Conflict](conflict-definitions-participant-properties-agentid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentId")           |
| [agentVersion](#agentversion) | `string` | Optional | cannot be null | [Conflict](conflict-definitions-participant-properties-agentversion.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentVersion") |
| [agentType](#agenttype)       | `string` | Required | cannot be null | [Conflict](conflict-definitions-participant-properties-agenttype.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentType")       |
| [displayName](#displayname)   | `string` | Optional | cannot be null | [Conflict](conflict-definitions-participant-properties-displayname.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/displayName")   |
| [role](#role)                 | `string` | Required | cannot be null | [Conflict](conflict-definitions-participant-properties-role.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/role")                 |

## agentId



`agentId`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-agentid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentId")

### agentId Type

`string`

### agentId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## agentVersion



`agentVersion`

* is optional

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-agentversion.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentVersion")

### agentVersion Type

`string`

### agentVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## agentType



`agentType`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-agenttype.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentType")

### agentType Type

`string`

### agentType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"human"`     |             |
| `"human-org"` |             |
| `"hybrid"`    |             |
| `"ai"`        |             |

## displayName



`displayName`

* is optional

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-displayname.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/displayName")

### displayName Type

`string`

### displayName Constraints

**maximum length**: the maximum number of characters for this string is: `256`

## role



`role`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-role.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/role")

### role Type

`string`

### role Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"party"`    |             |
| `"mediator"` |             |
| `"notary"`   |             |
| `"observer"` |             |
