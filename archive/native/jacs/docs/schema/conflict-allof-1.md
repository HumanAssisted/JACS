# Untitled object in Conflict Schema

```txt
https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [conflict.schema.json\*](../../schemas/conflict/v1/conflict.schema.json "open original schema") |

## 1 Type

`object` ([Details](conflict-allof-1.md))

# 1 Properties

| Property                                    | Type     | Required | Nullable       | Defined by                                                                                                                                                       |
| :------------------------------------------ | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsType](#jacstype)                       | `string` | Optional | cannot be null | [Conflict](conflict-allof-1-properties-jacstype.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/jacsType")                       |
| [jacsLevel](#jacslevel)                     | `string` | Optional | cannot be null | [Conflict](conflict-allof-1-properties-jacslevel.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/jacsLevel")                     |
| [title](#title)                             | `string` | Required | cannot be null | [Conflict](conflict-allof-1-properties-title.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/title")                             |
| [description](#description)                 | `string` | Required | cannot be null | [Conflict](conflict-allof-1-properties-description.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/description")                 |
| [participants](#participants)               | `array`  | Required | cannot be null | [Conflict](conflict-allof-1-properties-participants.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/participants")               |
| [positions](#positions)                     | `array`  | Required | cannot be null | [Conflict](conflict-allof-1-properties-positions.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/positions")                     |
| [divergences](#divergences)                 | `array`  | Required | cannot be null | [Conflict](conflict-allof-1-properties-divergences.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/divergences")                 |
| [phase](#phase)                             | `string` | Required | cannot be null | [Conflict](conflict-allof-1-properties-phase.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/phase")                             |
| [linkedAgreements](#linkedagreements)       | `array`  | Optional | cannot be null | [Conflict](conflict-allof-1-properties-linkedagreements.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/linkedAgreements")       |
| [allPreviousVersions](#allpreviousversions) | `array`  | Optional | cannot be null | [Conflict](conflict-allof-1-properties-allpreviousversions.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/allPreviousVersions") |

## jacsType



`jacsType`

* is optional

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-jacstype.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/jacsType")

### jacsType Type

`string`

### jacsType Constraints

**constant**: the value of this property must be equal to:

```json
"conflict"
```

## jacsLevel



`jacsLevel`

* is optional

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-jacslevel.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/jacsLevel")

### jacsLevel Type

`string`

### jacsLevel Constraints

**constant**: the value of this property must be equal to:

```json
"artifact"
```

## title



`title`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-title.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/title")

### title Type

`string`

### title Constraints

**maximum length**: the maximum number of characters for this string is: `256`

**minimum length**: the minimum number of characters for this string is: `1`

## description



`description`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-description.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/description")

### description Type

`string`

### description Constraints

**maximum length**: the maximum number of characters for this string is: `4096`

**minimum length**: the minimum number of characters for this string is: `1`

## participants



`participants`

* is required

* Type: `object[]` ([Details](conflict-definitions-participant.md))

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-participants.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/participants")

### participants Type

`object[]` ([Details](conflict-definitions-participant.md))

### participants Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

## positions



`positions`

* is required

* Type: `object[]` ([Details](conflict-definitions-position.md))

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-positions.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/positions")

### positions Type

`object[]` ([Details](conflict-definitions-position.md))

## divergences



`divergences`

* is required

* Type: `object[]` ([Details](conflict-definitions-divergence.md))

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-divergences.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/divergences")

### divergences Type

`object[]` ([Details](conflict-definitions-divergence.md))

## phase



`phase`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-phase.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/phase")

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

## linkedAgreements

JACS document references to agreements that resolve part of this conflict.

`linkedAgreements`

* is optional

* Type: `object[]` ([Details](conflict-definitions-jacsdocumentref.md))

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-linkedagreements.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/linkedAgreements")

### linkedAgreements Type

`object[]` ([Details](conflict-definitions-jacsdocumentref.md))

## allPreviousVersions

Append-only list of every prior jacsVersion of this conflict document, in chronological order. Header jacsPreviousVersion is the immediate parent; this list is the full chain back to the original version. Append-only is enforced operationally.

`allPreviousVersions`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Conflict](conflict-allof-1-properties-allpreviousversions.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/allPreviousVersions")

### allPreviousVersions Type

`string[]`
