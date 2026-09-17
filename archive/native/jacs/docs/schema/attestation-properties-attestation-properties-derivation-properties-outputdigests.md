# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## outputDigests Type

`object` ([Details](attestation-properties-attestation-properties-derivation-properties-outputdigests.md))

# outputDigests Properties

| Property              | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                           |
| :-------------------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [sha256](#sha256)     | `string` | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-outputdigests-properties-sha256.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests/properties/sha256")       |
| [sha512](#sha512)     | `string` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-outputdigests-properties-sha512.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests/properties/sha512")       |
| Additional Properties | `string` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-outputdigests-additionalproperties.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests/additionalProperties") |

## sha256



`sha256`

* is required

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-outputdigests-properties-sha256.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests/properties/sha256")

### sha256 Type

`string`

## sha512



`sha512`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-outputdigests-properties-sha512.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests/properties/sha512")

### sha512 Type

`string`

## Additional Properties

Additional properties are allowed, as long as they follow this schema:



* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-outputdigests-additionalproperties.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests/additionalProperties")

### additionalProperties Type

`string`
