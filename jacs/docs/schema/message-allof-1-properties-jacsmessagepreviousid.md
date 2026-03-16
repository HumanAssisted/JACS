# Untitled string in Message Schema

```txt
https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/jacsMessagePreviousId
```

UUID of the previous message in this thread for ordering.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                   |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [message.schema.json\*](../../schemas/message/v1/message.schema.json "open original schema") |

## jacsMessagePreviousId Type

`string`

## jacsMessagePreviousId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")
