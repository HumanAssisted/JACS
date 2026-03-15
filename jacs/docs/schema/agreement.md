# agreement Schema

```txt
https://hai.ai/schemas/components/agreement/v1/agreement.schema.json
```

A set of required signatures signifying an agreement.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                  |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [agreement.schema.json](../../schemas/components/agreement/v1/agreement.schema.json "open original schema") |

## agreement Type

`object` ([agreement](agreement.md))

# agreement Properties

| Property                                  | Type      | Required | Nullable       | Defined by                                                                                                                                                    |
| :---------------------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [signatures](#signatures)                 | `array`   | Optional | cannot be null | [agreement](agreement-properties-signatures.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures")                 |
| [agentIDs](#agentids)                     | `array`   | Required | cannot be null | [agreement](agreement-properties-agentids.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs")                     |
| [question](#question)                     | `string`  | Optional | cannot be null | [agreement](agreement-properties-question.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/question")                     |
| [context](#context)                       | `string`  | Optional | cannot be null | [agreement](agreement-properties-context.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/context")                       |
| [timeout](#timeout)                       | `string`  | Optional | cannot be null | [agreement](agreement-properties-timeout.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/timeout")                       |
| [quorum](#quorum)                         | `integer` | Optional | cannot be null | [agreement](agreement-properties-quorum.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/quorum")                         |
| [requiredAlgorithms](#requiredalgorithms) | `array`   | Optional | cannot be null | [agreement](agreement-properties-requiredalgorithms.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/requiredAlgorithms") |
| [minimumStrength](#minimumstrength)       | `string`  | Optional | cannot be null | [agreement](agreement-properties-minimumstrength.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/minimumStrength")       |

## signatures

Signatures of agents

`signatures`

* is optional

* Type: `object[]` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [agreement](agreement-properties-signatures.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures")

### signatures Type

`object[]` ([Signature](header-properties-signature-1.md))

## agentIDs

The agents which are required in order to sign the document

`agentIDs`

* is required

* Type: `string[]`

* cannot be null

* defined in: [agreement](agreement-properties-agentids.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs")

### agentIDs Type

`string[]`

## question

When prompting an agent, what are they agreeing to?

`question`

* is optional

* Type: `string`

* cannot be null

* defined in: [agreement](agreement-properties-question.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/question")

### question Type

`string`

## context

Context for the question?

`context`

* is optional

* Type: `string`

* cannot be null

* defined in: [agreement](agreement-properties-context.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/context")

### context Type

`string`

## timeout

ISO 8601 deadline after which the agreement expires and no more signatures are accepted.

`timeout`

* is optional

* Type: `string`

* cannot be null

* defined in: [agreement](agreement-properties-timeout.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/timeout")

### timeout Type

`string`

### timeout Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## quorum

Minimum number of signatures required for the agreement to be considered complete (M-of-N). If omitted, all agents in agentIDs must sign.

`quorum`

* is optional

* Type: `integer`

* cannot be null

* defined in: [agreement](agreement-properties-quorum.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/quorum")

### quorum Type

`integer`

### quorum Constraints

**minimum**: the value of this number must greater than or equal to: `1`

## requiredAlgorithms

If specified, only signatures using one of these algorithms are accepted.

`requiredAlgorithms`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [agreement](agreement-properties-requiredalgorithms.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/requiredAlgorithms")

### requiredAlgorithms Type

`string[]`

## minimumStrength

Minimum cryptographic strength tier required for signatures. 'classical' accepts any algorithm; 'post-quantum' requires pq2025.

`minimumStrength`

* is optional

* Type: `string`

* cannot be null

* defined in: [agreement](agreement-properties-minimumstrength.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/minimumStrength")

### minimumStrength Type

`string`

### minimumStrength Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"classical"`    |             |
| `"post-quantum"` |             |
