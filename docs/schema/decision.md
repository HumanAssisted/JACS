# Decision Schema

```txt
https://hai.ai/schemas/components/decision/v1/decision-schema.json
```

descision is a log message of version changes, actions or edits, verified with a signature

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [decision.schema.json](../../schemas/components/decision/v1/decision.schema.json "open original schema") |

## Decision Type

`object` ([Decision](decision.md))

# Decision Properties

| Property                  | Type     | Required | Nullable       | Defined by                                                                                                                                |
| :------------------------ | :------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                 | `string` | Required | cannot be null | [Decision](decision-properties-id.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/id")                 |
| [approvedBy](#approvedby) | `object` | Required | cannot be null | [Decision](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/approvedBy")                    |
| [oldversion](#oldversion) | `string` | Optional | cannot be null | [Decision](decision-properties-oldversion.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/oldversion") |
| [newversion](#newversion) | `string` | Required | cannot be null | [Decision](decision-properties-newversion.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/newversion") |
| [summary](#summary)       | `string` | Required | cannot be null | [Decision](decision-properties-summary.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/summary")       |
| [messages](#messages)     | `array`  | Optional | cannot be null | [Decision](decision-properties-messages.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/messages")     |

## id



`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Decision](decision-properties-id.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/id")

### id Type

`string`

### id Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## approvedBy

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`approvedBy`

*   is required

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Decision](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/approvedBy")

### approvedBy Type

`object` ([Signature](signature.md))

## oldversion

Semantic of the version of the task

`oldversion`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Decision](decision-properties-oldversion.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/oldversion")

### oldversion Type

`string`

## newversion

Semantic of the version of the task

`newversion`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Decision](decision-properties-newversion.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/newversion")

### newversion Type

`string`

## summary

Summary of change

`summary`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Decision](decision-properties-summary.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/summary")

### summary Type

`string`

## messages



`messages`

*   is optional

*   Type: `object[]` ([Message](message.md))

*   cannot be null

*   defined in: [Decision](decision-properties-messages.md "https://hai.ai/schemas/components/decision/v1/decision-schema.json#/properties/messages")

### messages Type

`object[]` ([Message](message.md))
