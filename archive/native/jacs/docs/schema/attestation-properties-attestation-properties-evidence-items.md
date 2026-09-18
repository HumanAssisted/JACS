# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## items Type

`object` ([Details](attestation-properties-attestation-properties-evidence-items.md))

# items Properties

| Property                      | Type          | Required | Nullable       | Defined by                                                                                                                                                                                                                                       |
| :---------------------------- | :------------ | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [kind](#kind)                 | `string`      | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence-items-properties-kind.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/kind")                 |
| [digests](#digests)           | `object`      | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence-items-properties-digests.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/digests")           |
| [uri](#uri)                   | `string`      | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence-items-properties-uri.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/uri")                   |
| [embedded](#embedded)         | `boolean`     | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence-items-properties-embedded.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/embedded")         |
| [embeddedData](#embeddeddata) | Not specified | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence-items-properties-embeddeddata.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/embeddedData") |
| [collectedAt](#collectedat)   | `string`      | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence-items-properties-collectedat.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/collectedAt")   |
| [resolvedAt](#resolvedat)     | `string`      | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence-items-properties-resolvedat.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/resolvedAt")     |
| [sensitivity](#sensitivity)   | `string`      | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence-items-properties-sensitivity.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/sensitivity")   |
| [verifier](#verifier)         | `object`      | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence-items-properties-verifier.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/verifier")         |

## kind

Type of evidence source.

`kind`

* is required

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence-items-properties-kind.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/kind")

### kind Type

`string`

### kind Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"a2a"`       |             |
| `"email"`     |             |
| `"jwt"`       |             |
| `"tlsnotary"` |             |
| `"custom"`    |             |

## digests

Algorithm-agile content digests of the evidence.

`digests`

* is required

* Type: `object` ([Details](attestation-properties-attestation-properties-evidence-items-properties-digests.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence-items-properties-digests.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/digests")

### digests Type

`object` ([Details](attestation-properties-attestation-properties-evidence-items-properties-digests.md))

## uri

Optional URI for referenced (non-embedded) evidence.

`uri`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence-items-properties-uri.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/uri")

### uri Type

`string`

## embedded

Whether the evidence is embedded in the attestation document.

`embedded`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence-items-properties-embedded.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/embedded")

### embedded Type

`boolean`

## embeddedData

The actual evidence data, present only when embedded=true.

`embeddedData`

* is optional

* Type: unknown

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence-items-properties-embeddeddata.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/embeddedData")

### embeddedData Type

unknown

## collectedAt

When the evidence was collected. Mandatory for freshness checks.

`collectedAt`

* is required

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence-items-properties-collectedat.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/collectedAt")

### collectedAt Type

`string`

### collectedAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## resolvedAt

When a referenced URI was last resolved.

`resolvedAt`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence-items-properties-resolvedat.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/resolvedAt")

### resolvedAt Type

`string`

### resolvedAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## sensitivity

Privacy classification of the evidence.

`sensitivity`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence-items-properties-sensitivity.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/sensitivity")

### sensitivity Type

`string`

### sensitivity Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"public"`       |             |
| `"restricted"`   |             |
| `"confidential"` |             |

### sensitivity Default Value

The default value is:

```json
"public"
```

## verifier



`verifier`

* is required

* Type: `object` ([Details](attestation-properties-attestation-properties-evidence-items-properties-verifier.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence-items-properties-verifier.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/verifier")

### verifier Type

`object` ([Details](attestation-properties-attestation-properties-evidence-items-properties-verifier.md))
