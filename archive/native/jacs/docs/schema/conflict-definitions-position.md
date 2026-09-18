# Untitled object in Conflict Schema

```txt
https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position
```

A participant statement in the conflict belief structure. confirmed=true requires a reference to a signed JACS document containing the party confirmation.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [conflict.schema.json\*](../../schemas/conflict/v1/conflict.schema.json "open original schema") |

## position Type

`object` ([Details](conflict-definitions-position.md))

# position Properties

| Property                            | Type      | Required | Nullable       | Defined by                                                                                                                                                                     |
| :---------------------------------- | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                           | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-id.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/id")                       |
| [participantId](#participantid)     | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-participantid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/participantId") |
| [statement](#statement)             | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-statement.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/statement")         |
| [kind](#kind)                       | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-kind.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/kind")                   |
| [statedAt](#statedat)               | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-statedat.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/statedAt")           |
| [confirmed](#confirmed)             | `boolean` | Required | cannot be null | [Conflict](conflict-definitions-position-properties-confirmed.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/confirmed")         |
| [confirmationRef](#confirmationref) | `object`  | Optional | cannot be null | [Conflict](conflict-definitions-jacsdocumentref.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/confirmationRef")                 |

## id



`id`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-id.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/id")

### id Type

`string`

### id Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## participantId



`participantId`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-participantid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/participantId")

### participantId Type

`string`

### participantId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## statement



`statement`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-statement.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/statement")

### statement Type

`string`

### statement Constraints

**maximum length**: the maximum number of characters for this string is: `8192`

**minimum length**: the minimum number of characters for this string is: `1`

## kind



`kind`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-kind.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/kind")

### kind Type

`string`

### kind Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"resource"` |             |
| `"action"`   |             |
| `"request"`  |             |
| `"need"`     |             |
| `"identity"` |             |

## statedAt



`statedAt`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-statedat.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/statedAt")

### statedAt Type

`string`

### statedAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## confirmed



`confirmed`

* is required

* Type: `boolean`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-confirmed.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/confirmed")

### confirmed Type

`boolean`

## confirmationRef

Verifiable reference to a specific signed JACS document version.

`confirmationRef`

* is optional

* Type: `object` ([Details](conflict-definitions-jacsdocumentref.md))

* cannot be null

* defined in: [Conflict](conflict-definitions-jacsdocumentref.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/confirmationRef")

### confirmationRef Type

`object` ([Details](conflict-definitions-jacsdocumentref.md))
