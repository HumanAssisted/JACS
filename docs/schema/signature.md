# Signature Schema

```txt
https://hai.ai/schemas/signature/v1/signature-schema.json
```

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                       |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [signature.schema.json](../../schemas/signature/v1/signature.schema.json "open original schema") |

## Signature Type

`object` ([Signature](signature.md))

# Signature Properties

| Property                                 | Type     | Required | Nullable       | Defined by                                                                                                                                       |
| :--------------------------------------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------- |
| [agentid](#agentid)                      | `string` | Required | cannot be null | [Signature](signature-properties-agentid.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/agentid")                     |
| [agentversion](#agentversion)            | `string` | Required | cannot be null | [Signature](signature-properties-agentversion.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/agentversion")           |
| [date](#date)                            | `string` | Required | cannot be null | [Signature](signature-properties-date.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/date")                           |
| [signature](#signature)                  | `string` | Required | cannot be null | [Signature](signature-properties-signature.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/signature")                 |
| [signing\_algorithm](#signing_algorithm) | `string` | Optional | cannot be null | [Signature](signature-properties-signing_algorithm.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/signing_algorithm") |
| [fields](#fields)                        | `array`  | Optional | cannot be null | [Signature](signature-properties-fields.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/fields")                       |

## agentid

The id of agent that produced signature

`agentid`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Signature](signature-properties-agentid.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/agentid")

### agentid Type

`string`

### agentid Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## agentversion

Version of the agent

`agentversion`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Signature](signature-properties-agentversion.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/agentversion")

### agentversion Type

`string`

### agentversion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## date

Date

`date`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Signature](signature-properties-date.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/date")

### date Type

`string`

### date Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## signature

The actual signature, made from the docid,

`signature`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Signature](signature-properties-signature.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/signature")

### signature Type

`string`

## signing\_algorithm

What signature algorithm was used

`signing_algorithm`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Signature](signature-properties-signing_algorithm.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/signing_algorithm")

### signing\_algorithm Type

`string`

## fields

what fields from document were used to generate signature. Defaults to id and version of doc.

`fields`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Signature](signature-properties-fields.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/fields")

### fields Type

`string[]`
