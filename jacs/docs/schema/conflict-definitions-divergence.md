# Untitled object in Conflict Schema

```txt
https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence
```

A typed divergence between participant positions.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [conflict.schema.json\*](../../schemas/conflict/v1/conflict.schema.json "open original schema") |

## divergence Type

`object` ([Details](conflict-definitions-divergence.md))

# divergence Properties

| Property                                      | Type      | Required | Nullable       | Defined by                                                                                                                                                                                       |
| :-------------------------------------------- | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                                     | `string`  | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-id.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/id")                                     |
| [type](#type)                                 | `string`  | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-type.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/type")                                 |
| [summary](#summary)                           | `string`  | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-summary.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/summary")                           |
| [participantPositions](#participantpositions) | `array`   | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-participantpositions.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/participantPositions") |
| [zeroSum](#zerosum)                           | `boolean` | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-zerosum.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/zeroSum")                           |
| [phase](#phase)                               | `string`  | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-phase.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/phase")                               |

## id



`id`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-id.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/id")

### id Type

`string`

### id Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## type



`type`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-type.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/type")

### type Type

`string`

### type Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value               | Explanation |
| :------------------ | :---------- |
| `"resource"`        |             |
| `"factual"`         |             |
| `"identity_safety"` |             |
| `"framing"`         |             |

## summary



`summary`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-summary.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/summary")

### summary Type

`string`

### summary Constraints

**maximum length**: the maximum number of characters for this string is: `4096`

**minimum length**: the minimum number of characters for this string is: `1`

## participantPositions

Position ids participating in this divergence.

`participantPositions`

* is required

* Type: `string[]`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-participantpositions.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/participantPositions")

### participantPositions Type

`string[]`

## zeroSum



`zeroSum`

* is required

* Type: `boolean`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-zerosum.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/zeroSum")

### zeroSum Type

`boolean`

## phase



`phase`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-phase.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/phase")

### phase Type

`string`

### phase Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value          | Explanation |
| :------------- | :---------- |
| `"surfacing"`  |             |
| `"contested"`  |             |
| `"exploring"`  |             |
| `"converging"` |             |
| `"resolved"`   |             |
| `"stalemate"`  |             |
| `"escalated"`  |             |
