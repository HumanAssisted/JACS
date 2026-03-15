# Untitled object in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## attestation Type

`object` ([Details](attestation-properties-attestation.md))

# attestation Properties

| Property                        | Type     | Required | Nullable       | Defined by                                                                                                                                                                                     |
| :------------------------------ | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [subject](#subject)             | `object` | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-subject.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject")             |
| [claims](#claims)               | `array`  | Required | cannot be null | [Attestation](attestation-properties-attestation-properties-claims.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims")               |
| [evidence](#evidence)           | `array`  | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-evidence.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence")           |
| [derivation](#derivation)       | `object` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-derivation.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation")       |
| [policyContext](#policycontext) | `object` | Optional | cannot be null | [Attestation](attestation-properties-attestation-properties-policycontext.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext") |

## subject



`subject`

* is required

* Type: `object` ([Details](attestation-properties-attestation-properties-subject.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-subject.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject")

### subject Type

`object` ([Details](attestation-properties-attestation-properties-subject.md))

## claims



`claims`

* is required

* Type: `object[]` ([Details](attestation-properties-attestation-properties-claims-items.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-claims.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims")

### claims Type

`object[]` ([Details](attestation-properties-attestation-properties-claims-items.md))

### claims Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

## evidence



`evidence`

* is optional

* Type: `object[]` ([Details](attestation-properties-attestation-properties-evidence-items.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-evidence.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence")

### evidence Type

`object[]` ([Details](attestation-properties-attestation-properties-evidence-items.md))

## derivation

Transform receipt: proves what happened between inputs and output.

`derivation`

* is optional

* Type: `object` ([Details](attestation-properties-attestation-properties-derivation.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-derivation.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation")

### derivation Type

`object` ([Details](attestation-properties-attestation-properties-derivation.md))

## policyContext

Optional policy context. Policy evaluation is deferred to N+2.

`policyContext`

* is optional

* Type: `object` ([Details](attestation-properties-attestation-properties-policycontext.md))

* cannot be null

* defined in: [Attestation](attestation-properties-attestation-properties-policycontext.md "https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext")

### policyContext Type

`object` ([Details](attestation-properties-attestation-properties-policycontext.md))
