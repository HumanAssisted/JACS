# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation
```

Transform receipt: proves what happened between inputs and output.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## derivation Type

`object` ([Details](attestation-properties-attestation-properties-derivation.md))

# derivation Properties

| Property                        | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                 |
| :------------------------------ | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [inputs](#inputs)               | `array`  | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-inputs.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs")               |
| [transform](#transform)         | `object` | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-transform.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform")         |
| [outputDigests](#outputdigests) | `object` | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-outputdigests.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests") |

## inputs



`inputs`

* is required

* Type: `object[]` ([Details](attestation-properties-attestation-properties-derivation-properties-inputs-items.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-inputs.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs")

### inputs Type

`object[]` ([Details](attestation-properties-attestation-properties-derivation-properties-inputs-items.md))

## transform

Content-addressable reference to the transformation.

`transform`

* is required

* Type: `object` ([Details](attestation-properties-attestation-properties-derivation-properties-transform.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-transform.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform")

### transform Type

`object` ([Details](attestation-properties-attestation-properties-derivation-properties-transform.md))

## outputDigests



`outputDigests`

* is required

* Type: `object` ([Details](attestation-properties-attestation-properties-derivation-properties-outputdigests.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-outputdigests.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests")

### outputDigests Type

`object` ([Details](attestation-properties-attestation-properties-derivation-properties-outputdigests.md))
