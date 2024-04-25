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

| Property                            | Type          | Required | Nullable       | Defined by                                                                                                                                      |
| :---------------------------------- | :------------ | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                           | `string`      | Required | cannot be null | [Message](message-properties-id.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/id")                           |
| [signature](#signature)             | Not specified | Optional | cannot be null | [Message](message-properties-signature.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/signature")             |
| [datetime](#datetime)               | `string`      | Optional | cannot be null | [Message](message-properties-datetime.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/datetime")               |
| [content](#content)                 | `object`      | Optional | cannot be null | [Message](message-properties-content.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/content")                 |
| [originalContent](#originalcontent) | `array`       | Optional | cannot be null | [Message](message-properties-originalcontent.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/originalContent") |

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

signing of message

`signature`

*   is optional

*   Type: unknown

*   cannot be null

*   defined in: [Message](message-properties-signature.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/signature")

### signature Type

unknown

## datetime

Date of message, unverified

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

body , subject etc

`content`

*   is optional

*   Type: `object` ([Details](message-properties-content.md))

*   cannot be null

*   defined in: [Message](message-properties-content.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/content")

### content Type

`object` ([Details](message-properties-content.md))

## originalContent



`originalContent`

*   is optional

*   Type: `object[]` ([File](files.md))

*   cannot be null

*   defined in: [Message](message-properties-originalcontent.md "https://hai.ai/schemas/components/message/v1/message-schema.json#/properties/originalContent")

### originalContent Type

`object[]` ([File](files.md))
