# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## subject Type

`object` ([Details](attestation-properties-attestation-properties-subject.md))

# subject Properties

| Property            | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                               |
| :------------------ | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [type](#type)       | `string` | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-subject-properties-type.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/type")       |
| [id](#id)           | `string` | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-subject-properties-id.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/id")           |
| [digests](#digests) | `object` | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-subject-properties-digests.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests") |

## type



`type`

* is required

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-subject-properties-type.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/type")

### type Type

`string`

### type Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"agent"`    |             |
| `"artifact"` |             |
| `"workflow"` |             |
| `"identity"` |             |

## id

Identifier of the subject (JACS document ID, agent ID, etc.)

`id`

* is required

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-subject-properties-id.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/id")

### id Type

`string`

## digests

Content-addressable digests of the subject. For agents: hash of public key. For artifacts: hash of content.

`digests`

* is required

* Type: `object` ([Details](attestation-properties-attestation-properties-subject-properties-digests.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-subject-properties-digests.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests")

### digests Type

`object` ([Details](attestation-properties-attestation-properties-subject-properties-digests.md))
