# Signature Schema

```txt
https://hai.ai/schemas/components/signature/v1/signature.schema.json
```

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                                           |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [signature.schema.json](../../https:/hai.ai/schemas/=./schemas/components/signature/v1/signature.schema.json "open original schema") |

## Signature Type

`object` ([Signature](signature.md))

# Signature Properties

| Property                              | Type     | Required | Nullable       | Defined by                                                                                                                                                |
| :------------------------------------ | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [agentID](#agentid)                   | `string` | Required | cannot be null | [Signature](signature-properties-agentid.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/agentID")                   |
| [agentVersion](#agentversion)         | `string` | Required | cannot be null | [Signature](signature-properties-agentversion.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/agentVersion")         |
| [date](#date)                         | `string` | Required | cannot be null | [Signature](signature-properties-date.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/date")                         |
| [signature](#signature)               | `string` | Required | cannot be null | [Signature](signature-properties-signature.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signature")               |
| [publicKeyHash](#publickeyhash)       | `string` | Required | cannot be null | [Signature](signature-properties-publickeyhash.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/publicKeyHash")       |
| [signingAlgorithm](#signingalgorithm) | `string` | Optional | cannot be null | [Signature](signature-properties-signingalgorithm.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signingAlgorithm") |
| [response](#response)                 | `string` | Optional | cannot be null | [Signature](signature-properties-response.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/response")                 |
| [responseType](#responsetype)         | `string` | Optional | cannot be null | [Signature](signature-properties-responsetype.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/responseType")         |
| [fields](#fields)                     | `array`  | Required | cannot be null | [Signature](signature-properties-fields.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/fields")                     |

## agentID

The id of agent that produced signature

`agentID`

* is required

* Type: `string`

* cannot be null

* defined in: [Signature](signature-properties-agentid.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/agentID")

### agentID Type

`string`

### agentID Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## agentVersion

Version of the agent

`agentVersion`

* is required

* Type: `string`

* cannot be null

* defined in: [Signature](signature-properties-agentversion.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/agentVersion")

### agentVersion Type

`string`

### agentVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## date

Date

`date`

* is required

* Type: `string`

* cannot be null

* defined in: [Signature](signature-properties-date.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/date")

### date Type

`string`

### date Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## signature

The actual signature, made from the docid,

`signature`

* is required

* Type: `string`

* cannot be null

* defined in: [Signature](signature-properties-signature.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signature")

### signature Type

`string`

## publicKeyHash

Hash of the public key to verify signature with.

`publicKeyHash`

* is required

* Type: `string`

* cannot be null

* defined in: [Signature](signature-properties-publickeyhash.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/publicKeyHash")

### publicKeyHash Type

`string`

## signingAlgorithm

What signature algorithm was used

`signingAlgorithm`

* is optional

* Type: `string`

* cannot be null

* defined in: [Signature](signature-properties-signingalgorithm.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signingAlgorithm")

### signingAlgorithm Type

`string`

## response

When prompting an agent, is there text provided with the agreement?

`response`

* is optional

* Type: `string`

* cannot be null

* defined in: [Signature](signature-properties-response.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/response")

### response Type

`string`

## responseType

Optional way to track disagreement, or agreement. Reject means question not understood or considered relevant.

`responseType`

* is optional

* Type: `string`

* cannot be null

* defined in: [Signature](signature-properties-responsetype.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/responseType")

### responseType Type

`string`

### responseType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"agree"`    |             |
| `"disagree"` |             |
| `"reject"`   |             |

## fields

fields fields from document which were used to generate signature.

`fields`

* is required

* Type: `string[]`

* cannot be null

* defined in: [Signature](signature-properties-fields.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/fields")

### fields Type

`string[]`
