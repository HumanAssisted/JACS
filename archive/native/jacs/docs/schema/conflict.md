# Conflict Schema

```txt
https://hai.ai/schemas/conflict/v1/conflict.schema.json
```

A standalone JACS conflict document for signed, versioned tracking of participant positions, divergences, phases, and resolving agreement links. The JACS header owns document identity, versioning, authorship signatures, hashes, files, and visibility. The conflict body owns the belief structure. allPreviousVersions is an append-only ledger of every prior jacsVersion; header jacsPreviousVersion gives the immediate parent.

| Abstract               | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                    |
| :--------------------- | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------------------- |
| Cannot be instantiated | Yes        | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [conflict.schema.json](../../schemas/conflict/v1/conflict.schema.json "open original schema") |

## Conflict Type

merged type ([Conflict](conflict.md))

all of

* [Header](conflict-allof-header.md "check type definition")

* [Untitled object in Conflict](conflict-allof-1.md "check type definition")

# Conflict Definitions

## Definitions group participant

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant"}
```

| Property                      | Type     | Required | Nullable       | Defined by                                                                                                                                                                         |
| :---------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [agentId](#agentid)           | `string` | Required | cannot be null | [Conflict](conflict-definitions-participant-properties-agentid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentId")           |
| [agentVersion](#agentversion) | `string` | Optional | cannot be null | [Conflict](conflict-definitions-participant-properties-agentversion.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentVersion") |
| [agentType](#agenttype)       | `string` | Required | cannot be null | [Conflict](conflict-definitions-participant-properties-agenttype.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentType")       |
| [displayName](#displayname)   | `string` | Optional | cannot be null | [Conflict](conflict-definitions-participant-properties-displayname.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/displayName")   |
| [role](#role)                 | `string` | Required | cannot be null | [Conflict](conflict-definitions-participant-properties-role.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/role")                 |

### agentId



`agentId`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-agentid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentId")

#### agentId Type

`string`

#### agentId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### agentVersion



`agentVersion`

* is optional

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-agentversion.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentVersion")

#### agentVersion Type

`string`

#### agentVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### agentType



`agentType`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-agenttype.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/agentType")

#### agentType Type

`string`

#### agentType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"human"`     |             |
| `"human-org"` |             |
| `"hybrid"`    |             |
| `"ai"`        |             |

### displayName



`displayName`

* is optional

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-displayname.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/displayName")

#### displayName Type

`string`

#### displayName Constraints

**maximum length**: the maximum number of characters for this string is: `256`

### role



`role`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-participant-properties-role.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/participant/properties/role")

#### role Type

`string`

#### role Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"party"`    |             |
| `"mediator"` |             |
| `"notary"`   |             |
| `"observer"` |             |

## Definitions group position

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position"}
```

| Property                            | Type      | Required | Nullable       | Defined by                                                                                                                                                                     |
| :---------------------------------- | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                           | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-id.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/id")                       |
| [participantId](#participantid)     | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-participantid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/participantId") |
| [statement](#statement)             | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-statement.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/statement")         |
| [kind](#kind)                       | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-kind.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/kind")                   |
| [statedAt](#statedat)               | `string`  | Required | cannot be null | [Conflict](conflict-definitions-position-properties-statedat.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/statedAt")           |
| [confirmed](#confirmed)             | `boolean` | Required | cannot be null | [Conflict](conflict-definitions-position-properties-confirmed.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/confirmed")         |
| [confirmationRef](#confirmationref) | `object`  | Optional | cannot be null | [Conflict](conflict-definitions-jacsdocumentref.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/confirmationRef")                 |

### id



`id`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-id.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/id")

#### id Type

`string`

#### id Constraints

**minimum length**: the minimum number of characters for this string is: `1`

### participantId



`participantId`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-participantid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/participantId")

#### participantId Type

`string`

#### participantId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### statement



`statement`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-statement.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/statement")

#### statement Type

`string`

#### statement Constraints

**maximum length**: the maximum number of characters for this string is: `8192`

**minimum length**: the minimum number of characters for this string is: `1`

### kind



`kind`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-kind.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/kind")

#### kind Type

`string`

#### kind Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"resource"` |             |
| `"action"`   |             |
| `"request"`  |             |
| `"need"`     |             |
| `"identity"` |             |

### statedAt



`statedAt`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-statedat.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/statedAt")

#### statedAt Type

`string`

#### statedAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

### confirmed



`confirmed`

* is required

* Type: `boolean`

* cannot be null

* defined in: [Conflict](conflict-definitions-position-properties-confirmed.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/confirmed")

#### confirmed Type

`boolean`

### confirmationRef

Verifiable reference to a specific signed JACS document version.

`confirmationRef`

* is optional

* Type: `object` ([Details](conflict-definitions-jacsdocumentref.md))

* cannot be null

* defined in: [Conflict](conflict-definitions-jacsdocumentref.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/position/properties/confirmationRef")

#### confirmationRef Type

`object` ([Details](conflict-definitions-jacsdocumentref.md))

## Definitions group divergence

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence"}
```

| Property                                      | Type      | Required | Nullable       | Defined by                                                                                                                                                                                       |
| :-------------------------------------------- | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id-1)                                   | `string`  | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-id.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/id")                                     |
| [type](#type)                                 | `string`  | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-type.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/type")                                 |
| [summary](#summary)                           | `string`  | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-summary.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/summary")                           |
| [participantPositions](#participantpositions) | `array`   | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-participantpositions.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/participantPositions") |
| [zeroSum](#zerosum)                           | `boolean` | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-zerosum.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/zeroSum")                           |
| [phase](#phase)                               | `string`  | Required | cannot be null | [Conflict](conflict-definitions-divergence-properties-phase.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/phase")                               |

### id



`id`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-id.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/id")

#### id Type

`string`

#### id Constraints

**minimum length**: the minimum number of characters for this string is: `1`

### type



`type`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-type.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/type")

#### type Type

`string`

#### type Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value               | Explanation |
| :------------------ | :---------- |
| `"resource"`        |             |
| `"factual"`         |             |
| `"identity_safety"` |             |
| `"framing"`         |             |

### summary



`summary`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-summary.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/summary")

#### summary Type

`string`

#### summary Constraints

**maximum length**: the maximum number of characters for this string is: `4096`

**minimum length**: the minimum number of characters for this string is: `1`

### participantPositions

Position ids participating in this divergence.

`participantPositions`

* is required

* Type: `string[]`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-participantpositions.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/participantPositions")

#### participantPositions Type

`string[]`

### zeroSum



`zeroSum`

* is required

* Type: `boolean`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-zerosum.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/zeroSum")

#### zeroSum Type

`boolean`

### phase



`phase`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-divergence-properties-phase.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/divergence/properties/phase")

#### phase Type

`string`

#### phase Constraints

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

## Definitions group phase

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/phase"}
```

| Property | Type | Required | Nullable | Defined by |
| :------- | :--- | :------- | :------- | :--------- |

## Definitions group jacsDocumentRef

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef"}
```

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                                                                               |
| :-------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsId](#jacsid)           | `string` | Required | cannot be null | [Conflict](conflict-definitions-jacsdocumentref-properties-jacsid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsId")           |
| [jacsVersion](#jacsversion) | `string` | Required | cannot be null | [Conflict](conflict-definitions-jacsdocumentref-properties-jacsversion.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsVersion") |
| [jacsSha256](#jacssha256)   | `string` | Required | cannot be null | [Conflict](conflict-definitions-jacsdocumentref-properties-jacssha256.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsSha256")   |

### jacsId



`jacsId`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-jacsdocumentref-properties-jacsid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsId")

#### jacsId Type

`string`

#### jacsId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### jacsVersion



`jacsVersion`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-jacsdocumentref-properties-jacsversion.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsVersion")

#### jacsVersion Type

`string`

#### jacsVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### jacsSha256



`jacsSha256`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-jacsdocumentref-properties-jacssha256.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsSha256")

#### jacsSha256 Type

`string`

#### jacsSha256 Constraints

**minimum length**: the minimum number of characters for this string is: `1`
