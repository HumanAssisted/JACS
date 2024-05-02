# Untitled string in Header Schema

```txt
schemas/header/v1/header.schema.json#/properties/jacsPreviousVersion
```

Previous Version id of the object. If blank, it's claiming to be the first

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [header.schema.json\*](../../https:/hai.ai/schemas/=./schemas/header/v1/header.schema.json "open original schema") |

## jacsPreviousVersion Type

`string`

## jacsPreviousVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")
