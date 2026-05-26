# Untitled object in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy
```

Rules for when the agreement is considered complete.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## signaturePolicy Type

`object` ([Details](agreement-definitions-signaturepolicy.md))

# signaturePolicy Properties

| Property                                  | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                 |
| :---------------------------------------- | :-------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [partyQuorum](#partyquorum)               | Merged    | Required | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-partyquorum.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/partyQuorum")               |
| [witnessRequired](#witnessrequired)       | `integer` | Optional | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-witnessrequired.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/witnessRequired")       |
| [timeout](#timeout)                       | `string`  | Optional | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-timeout.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/timeout")                       |
| [requiredAlgorithms](#requiredalgorithms) | `array`   | Optional | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-requiredalgorithms.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/requiredAlgorithms") |
| [minimumStrength](#minimumstrength)       | `string`  | Optional | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-minimumstrength.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/minimumStrength")       |

## partyQuorum

Signer-party consent threshold. 'all' = every signer-role party; 'majority' = more than half; integer N = at least N signer-role party signatures.

`partyQuorum`

* is required

* Type: merged type ([Details](agreement-definitions-signaturepolicy-properties-partyquorum.md))

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-partyquorum.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/partyQuorum")

### partyQuorum Type

merged type ([Details](agreement-definitions-signaturepolicy-properties-partyquorum.md))

one (and only one) of

* [Untitled string in Agreement](agreement-definitions-signaturepolicy-properties-partyquorum-oneof-0.md "check type definition")

* [Untitled integer in Agreement](agreement-definitions-signaturepolicy-properties-partyquorum-oneof-1.md "check type definition")

### partyQuorum Default Value

The default value is:

```json
"all"
```

## witnessRequired

Minimum witness-role party signatures required in addition to signer quorum. Witnesses do not count toward partyQuorum.

`witnessRequired`

* is optional

* Type: `integer`

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-witnessrequired.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/witnessRequired")

### witnessRequired Type

`integer`

### witnessRequired Constraints

**minimum**: the value of this number must greater than or equal to: `0`

## timeout

ISO 8601 deadline after which new signatures are not accepted.

`timeout`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-timeout.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/timeout")

### timeout Type

`string`

### timeout Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## requiredAlgorithms



`requiredAlgorithms`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-requiredalgorithms.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/requiredAlgorithms")

### requiredAlgorithms Type

`string[]`

## minimumStrength



`minimumStrength`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-minimumstrength.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/minimumStrength")

### minimumStrength Type

`string`

### minimumStrength Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"classical"`    |             |
| `"post-quantum"` |             |
