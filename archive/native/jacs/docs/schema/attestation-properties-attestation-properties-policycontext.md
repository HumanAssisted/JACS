# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext
```

Optional policy context. Policy evaluation is deferred to N+2.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## policyContext Type

`object` ([Details](attestation-properties-attestation-properties-policycontext.md))

# policyContext Properties

| Property                                  | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                 |
| :---------------------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [policyId](#policyid)                     | `string` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-policycontext-properties-policyid.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext/properties/policyId")                     |
| [requiredTrustLevel](#requiredtrustlevel) | `string` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-policycontext-properties-requiredtrustlevel.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext/properties/requiredTrustLevel") |
| [maxEvidenceAge](#maxevidenceage)         | `string` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-policycontext-properties-maxevidenceage.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext/properties/maxEvidenceAge")         |

## policyId

Content-addressable hash of the policy document.

`policyId`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-policycontext-properties-policyid.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext/properties/policyId")

### policyId Type

`string`

## requiredTrustLevel



`requiredTrustLevel`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-policycontext-properties-requiredtrustlevel.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext/properties/requiredTrustLevel")

### requiredTrustLevel Type

`string`

### requiredTrustLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"open"`     |             |
| `"verified"` |             |
| `"strict"`   |             |
| `"custom"`   |             |

## maxEvidenceAge

ISO 8601 duration for maximum evidence age (e.g., 'PT5M' for 5 minutes).

`maxEvidenceAge`

* is optional

* Type: `string`

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-policycontext-properties-maxevidenceage.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext/properties/maxEvidenceAge")

### maxEvidenceAge Type

`string`
