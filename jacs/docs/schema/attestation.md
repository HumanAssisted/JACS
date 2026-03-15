# Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json
```

A JACS attestation document that proves WHO did WHAT and WHY it should be trusted.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                             |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [attestation.schema.json](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## Attestation Type

`object` ([Attestation](attestation.md))

all of

* [Header](todo-allof-header.md "check type definition")

# Attestation Properties

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                                   |
| :-------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsType](#jacstype)       | `string` | Optional | cannot be null | [Attestation](attestation-properties-jacstype.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/jacsType")       |
| [jacsLevel](#jacslevel)     | `string` | Optional | cannot be null | [Attestation](attestation-properties-jacslevel.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/jacsLevel")     |
| [attestation](#attestation) | `object` | Required | cannot be null | [Attestation](attestation-properties-attestation.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation") |

## jacsType

Attestation document type. Must be 'attestation' or 'attestation-transform-receipt'.

`jacsType`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-jacstype.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/jacsType")

### jacsType Type

`string`

### jacsType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                             | Explanation |
| :-------------------------------- | :---------- |
| `"attestation"`                   |             |
| `"attestation-transform-receipt"` |             |

## jacsLevel

Attestation data level. 'raw' for direct attestations, 'derived' for transform receipts.

`jacsLevel`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-jacslevel.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/jacsLevel")

### jacsLevel Type

`string`

### jacsLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value       | Explanation |
| :---------- | :---------- |
| `"raw"`     |             |
| `"derived"` |             |

## attestation



`attestation`

* is required

* Type: `object` ([Details](attestation-properties-attestation.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation")

### attestation Type

`object` ([Details](attestation-properties-attestation.md))
