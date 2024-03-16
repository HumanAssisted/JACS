# Untitled string in Header Schema

```txt
https://hai.ai/schemas/header/v1/header-schema.json#/properties/originalVersion
```

Original Version id of the object. When documents are copied without merging, this becomes the way to track them.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [header.schema.json\*](../../schemas/header/v1/header.schema.json "open original schema") |

## originalVersion Type

`string`

## originalVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")
