# Untitled string in Todo Item Schema

```txt
https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/itemId
```

Stable UUID for this item. Does not change when the list is re-signed.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                 |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [todoitem.schema.json\*](../../schemas/components/todoitem/v1/todoitem.schema.json "open original schema") |

## itemId Type

`string`

## itemId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")
