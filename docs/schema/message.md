# Message Schema

```txt
schemas/message/v1/message.schema.json
```

A signed, immutable message about a task

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                          |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [message.schema.json](../../https:/hai.ai/schemas/=./schemas/message/v1/message.schema.json "open original schema") |

## Message Type

`object` ([Message](message.md))

# Message Properties

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                |
| :-------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------ |
| [id](#id)                   | `string` | Required | cannot be null | [Message](message-properties-id.md "schemas/message/v1/message.schema.json#/properties/id")                               |
| [signature](#signature)     | `object` | Optional | cannot be null | [Message](header-properties-signature-1.md "schemas/components/signature/v1/signature.schema.json#/properties/signature") |
| [taskID](#taskid)           | `string` | Required | cannot be null | [Message](message-properties-taskid.md "schemas/message/v1/message.schema.json#/properties/taskID")                       |
| [to](#to)                   | `array`  | Optional | cannot be null | [Message](message-properties-to.md "schemas/message/v1/message.schema.json#/properties/to")                               |
| [datetime](#datetime)       | `string` | Required | cannot be null | [Message](message-properties-datetime.md "schemas/message/v1/message.schema.json#/properties/datetime")                   |
| [content](#content)         | `string` | Required | cannot be null | [Message](message-properties-content.md "schemas/message/v1/message.schema.json#/properties/content")                     |
| [attachments](#attachments) | `array`  | Optional | cannot be null | [Message](message-properties-attachments.md "schemas/message/v1/message.schema.json#/properties/attachments")             |

## id



`id`

* is required

* Type: `string`

* cannot be null

* defined in: [Message](message-properties-id.md "schemas/message/v1/message.schema.json#/properties/id")

### id Type

`string`

### id Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## signature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`signature`

* is optional

* Type: `object` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [Message](header-properties-signature-1.md "schemas/components/signature/v1/signature.schema.json#/properties/signature")

### signature Type

`object` ([Signature](header-properties-signature-1.md))

## taskID



`taskID`

* is required

* Type: `string`

* cannot be null

* defined in: [Message](message-properties-taskid.md "schemas/message/v1/message.schema.json#/properties/taskID")

### taskID Type

`string`

### taskID Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## to

list of addressees, optional

`to`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Message](message-properties-to.md "schemas/message/v1/message.schema.json#/properties/to")

### to Type

`string[]`

## datetime

Date of message, unverified

`datetime`

* is required

* Type: `string`

* cannot be null

* defined in: [Message](message-properties-datetime.md "schemas/message/v1/message.schema.json#/properties/datetime")

### datetime Type

`string`

### datetime Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## content

body , subject etc

`content`

* is required

* Type: `string`

* cannot be null

* defined in: [Message](message-properties-content.md "schemas/message/v1/message.schema.json#/properties/content")

### content Type

`string`

## attachments

list of files

`attachments`

* is optional

* Type: `object[]` ([File](header-properties-jacsfiles-file.md))

* cannot be null

* defined in: [Message](message-properties-attachments.md "schemas/message/v1/message.schema.json#/properties/attachments")

### attachments Type

`object[]` ([File](header-properties-jacsfiles-file.md))
