# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform
```

Content-addressable reference to the transformation.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## transform Type

`object` ([Details](attestation-properties-attestation-properties-derivation-properties-transform.md))

# transform Properties

| Property                      | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                         |
| :---------------------------- | :-------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [name](#name)                 | `string`  | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-transform-properties-name.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform/properties/name")                 |
| [hash](#hash)                 | `string`  | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-transform-properties-hash.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform/properties/hash")                 |
| [reproducible](#reproducible) | `boolean` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-transform-properties-reproducible.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform/properties/reproducible") |
| [environment](#environment)   | `object`  | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-transform-properties-environment.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform/properties/environment")   |

## name

Human-readable name (e.g., 'summarize-v2', 'classify-sentiment').

`name`

* is required

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-transform-properties-name.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform/properties/name")

### name Type

`string`

## hash

Content-addressable hash of the transform code/binary.

`hash`

* is required

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-transform-properties-hash.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform/properties/hash")

### hash Type

`string`

## reproducible

Whether the transform is deterministic.

`reproducible`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-transform-properties-reproducible.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform/properties/reproducible")

### reproducible Type

`boolean`

## environment

Runtime parameters that affect the output.

`environment`

* is optional

* Type: `object` ([Details](attestation-properties-attestation-properties-derivation-properties-transform-properties-environment.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-transform-properties-environment.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform/properties/environment")

### environment Type

`object` ([Details](attestation-properties-attestation-properties-derivation-properties-transform-properties-environment.md))
