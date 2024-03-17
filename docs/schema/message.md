# Message Schema

```txt
https://hai.ai/schemas/components/message/v1/message-schema.json
```

A signed, immutable message from a user

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                            |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [message.schema.json](../../schemas/components/message/v1/message.schema.json "open original schema") |

## Message Type

`object` ([Message](message.md))

# Message Properties

| Property                            | Type     | Required | Nullable       | Defined by                                                                                                                                      |
| :---------------------------------- | :------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                           | `string` | Required | cannot be null | [Message](message-properties-id.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/id")                           |
| [signature](#signature)             | `object` | Optional | cannot be null | [Message](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/signature")                            |
| [datetime](#datetime)               | `string` | Optional | cannot be null | [Message](message-properties-datetime.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/datetime")               |
| [content](#content)                 | `string` | Optional | cannot be null | [Message](message-properties-content.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/content")                 |
| [originalContent](#originalcontent) | `array`  | Optional | cannot be null | [Message](message-properties-originalcontent.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/originalContent") |

## id



`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Message](message-properties-id.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/id")

### id Type

`string`

### id Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## signature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`signature`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Message](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/signature")

### signature Type

`object` ([Signature](signature.md))

## datetime

Date

`datetime`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Message](message-properties-datetime.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/datetime")

### datetime Type

`string`

### datetime Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## content

Summary of change

`content`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Message](message-properties-content.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/content")

### content Type

`string`

## originalContent



`originalContent`

*   is optional

*   Type: an array of merged types ([File](files.md))

*   cannot be null

*   defined in: [Message](message-properties-originalcontent.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/originalContent")

### originalContent Type

an array of merged types ([File](files.md))
