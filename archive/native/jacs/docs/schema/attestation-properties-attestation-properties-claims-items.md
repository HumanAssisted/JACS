# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## items Type

`object` ([Details](attestation-properties-attestation-properties-claims-items.md))

# items Properties

| Property                          | Type          | Required | Nullable       | Defined by                                                                                                                                                                                                                                       |
| :-------------------------------- | :------------ | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [name](#name)                     | `string`      | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-claims-items-properties-name.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/name")                     |
| [value](#value)                   | Not specified | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-claims-items-properties-value.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/value")                   |
| [confidence](#confidence)         | `number`      | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-claims-items-properties-confidence.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/confidence")         |
| [assuranceLevel](#assurancelevel) | `string`      | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-claims-items-properties-assurancelevel.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/assuranceLevel") |
| [issuer](#issuer)                 | `string`      | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-claims-items-properties-issuer.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/issuer")                 |
| [issuedAt](#issuedat)             | `string`      | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-claims-items-properties-issuedat.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/issuedAt")             |

## name



`name`

* is required

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-claims-items-properties-name.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/name")

### name Type

`string`

## value



`value`

* is required

* Type: unknown

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-claims-items-properties-value.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/value")

### value Type

unknown

## confidence

Adapter-assigned confidence score.

`confidence`

* is optional

* Type: `number`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-claims-items-properties-confidence.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/confidence")

### confidence Type

`number`

### confidence Constraints

**maximum**: the value of this number must smaller than or equal to: `1`

**minimum**: the value of this number must greater than or equal to: `0`

## assuranceLevel

Categorical assurance level.

`assuranceLevel`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-claims-items-properties-assurancelevel.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/assuranceLevel")

### assuranceLevel Type

`string`

### assuranceLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                      | Explanation |
| :------------------------- | :---------- |
| `"self-asserted"`          |             |
| `"verified"`               |             |
| `"independently-attested"` |             |

## issuer

Agent ID or domain of the claim issuer.

`issuer`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-claims-items-properties-issuer.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/issuer")

### issuer Type

`string`

## issuedAt



`issuedAt`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-claims-items-properties-issuedat.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items/properties/issuedAt")

### issuedAt Type

`string`

### issuedAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")
