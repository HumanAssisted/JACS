# Untitled object in Message Schema

```txt
https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                   |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [message.schema.json\*](../../schemas/message/v1/message.schema.json "open original schema") |

## 1 Type

`object` ([Details](message-allof-1.md))

# 1 Properties

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                                   |
| :-------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------- |
| [threadID](#threadid)       | `string` | Optional | cannot be null | [Message](message-allof-1-properties-threadid.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/threadID")       |
| [to](#to)                   | `array`  | Optional | cannot be null | [Message](message-allof-1-properties-to.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/to")                   |
| [from](#from)               | `array`  | Optional | cannot be null | [Message](message-allof-1-properties-from.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/from")               |
| [datetime](#datetime)       | `string` | Optional | cannot be null | [Message](message-allof-1-properties-datetime.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/datetime")       |
| [content](#content)         | `object` | Optional | cannot be null | [Message](message-allof-1-properties-content.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/content")         |
| [attachments](#attachments) | `array`  | Optional | cannot be null | [Message](message-allof-1-properties-attachments.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/attachments") |

## threadID



`threadID`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Message](message-allof-1-properties-threadid.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/threadID")

### threadID Type

`string`

## to

list of addressees, optional

`to`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Message](message-allof-1-properties-to.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/to")

### to Type

`string[]`

## from

list of addressees, optional

`from`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Message](message-allof-1-properties-from.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/from")

### from Type

`string[]`

## datetime

Date of message, unverified

`datetime`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Message](message-allof-1-properties-datetime.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/datetime")

### datetime Type

`string`

### datetime Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## content

body , subject etc

`content`

*   is optional

*   Type: `object` ([Details](message-allof-1-properties-content.md))

*   cannot be null

*   defined in: [Message](message-allof-1-properties-content.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/content")

### content Type

`object` ([Details](message-allof-1-properties-content.md))

## attachments

list of files

`attachments`

*   is optional

*   Type: `object[]` ([File](header-properties-jacsfiles-file.md))

*   cannot be null

*   defined in: [Message](message-allof-1-properties-attachments.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/attachments")

### attachments Type

`object[]` ([File](header-properties-jacsfiles-file.md))
