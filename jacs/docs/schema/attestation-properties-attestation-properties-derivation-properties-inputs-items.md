# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## items Type

`object` ([Details](attestation-properties-attestation-properties-derivation-properties-inputs-items.md))

# items Properties

| Property            | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                     |
| :------------------ | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [digests](#digests) | `object` | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-inputs-items-properties-digests.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs/items/properties/digests") |
| [id](#id)           | `string` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation-properties-inputs-items-properties-id.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs/items/properties/id")           |

## digests



`digests`

* is required

* Type: `object` ([Details](attestation-properties-attestation-properties-derivation-properties-inputs-items-properties-digests.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-inputs-items-properties-digests.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs/items/properties/digests")

### digests Type

`object` ([Details](attestation-properties-attestation-properties-derivation-properties-inputs-items-properties-digests.md))

## id

JACS document ID of the input, if available.

`id`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation-properties-inputs-items-properties-id.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs/items/properties/id")

### id Type

`string`
