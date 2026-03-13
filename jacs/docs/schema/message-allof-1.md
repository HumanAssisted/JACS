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

| Property                                        | Type     | Required | Nullable       | Defined by                                                                                                                                                       |
| :---------------------------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [threadID](#threadid)                           | `string` | Optional | cannot be null | [Message](message-allof-1-properties-threadid.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/threadID")                           |
| [to](#to)                                       | `array`  | Optional | cannot be null | [Message](message-allof-1-properties-to.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/to")                                       |
| [from](#from)                                   | `array`  | Optional | cannot be null | [Message](message-allof-1-properties-from.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/from")                                   |
| [content](#content)                             | `object` | Optional | cannot be null | [Message](message-allof-1-properties-content.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/content")                             |
| [jacsMessagePreviousId](#jacsmessagepreviousid) | `string` | Optional | cannot be null | [Message](message-allof-1-properties-jacsmessagepreviousid.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/jacsMessagePreviousId") |
| [attachments](#attachments)                     | `array`  | Optional | cannot be null | [Message](message-allof-1-properties-attachments.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/attachments")                     |

## threadID



`threadID`

* is optional

* Type: `string`

* cannot be null

* defined in: [Message](message-allof-1-properties-threadid.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/threadID")

### threadID Type

`string`

## to

list of addressees, optional

`to`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Message](message-allof-1-properties-to.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/to")

### to Type

`string[]`

## from

list of addressees, optional

`from`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Message](message-allof-1-properties-from.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/from")

### from Type

`string[]`

## content

body , subject etc

`content`

* is optional

* Type: `object` ([Details](message-allof-1-properties-content.md))

* cannot be null

* defined in: [Message](message-allof-1-properties-content.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/content")

### content Type

`object` ([Details](message-allof-1-properties-content.md))

## jacsMessagePreviousId

UUID of the previous message in this thread for ordering.

`jacsMessagePreviousId`

* is optional

* Type: `string`

* cannot be null

* defined in: [Message](message-allof-1-properties-jacsmessagepreviousid.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/jacsMessagePreviousId")

### jacsMessagePreviousId Type

`string`

### jacsMessagePreviousId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## attachments

list of files

`attachments`

* is optional

* Type: `object[]` ([File](header-properties-jacsfiles-file.md))

* cannot be null

* defined in: [Message](message-allof-1-properties-attachments.md "https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/attachments")

### attachments Type

`object[]` ([File](header-properties-jacsfiles-file.md))
