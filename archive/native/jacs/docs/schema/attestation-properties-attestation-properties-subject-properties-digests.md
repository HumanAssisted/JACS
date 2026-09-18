# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests
```

Content-addressable digests of the subject. For agents: hash of public key. For artifacts: hash of content.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## digests Type

`object` ([Details](attestation-properties-attestation-properties-subject-properties-digests.md))

# digests Properties

| Property              | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                         |
| :-------------------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [sha256](#sha256)     | `string` | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-subject-properties-digests-properties-sha256.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests/properties/sha256")       |
| [sha512](#sha512)     | `string` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-subject-properties-digests-properties-sha512.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests/properties/sha512")       |
| Additional Properties | `string` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-subject-properties-digests-additionalproperties.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests/additionalProperties") |

## sha256



`sha256`

* is required

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-subject-properties-digests-properties-sha256.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests/properties/sha256")

### sha256 Type

`string`

## sha512



`sha512`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-subject-properties-digests-properties-sha512.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests/properties/sha512")

### sha512 Type

`string`

## Additional Properties

Additional properties are allowed, as long as they follow this schema:



* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-subject-properties-digests-additionalproperties.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests/additionalProperties")

### additionalProperties Type

`string`
