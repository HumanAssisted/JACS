# Untitled string in Header Schema

```txt
schemas/header/v1/header.schema.json#/properties/jacsSha256
```

Hash of every field except this one. During  updates and creation hash is the last thing to occur, as it includes the signature. Not immediatly required, but eventually required.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [header.schema.json\*](../../https:/hai.ai/schemas/=./schemas/header/v1/header.schema.json "open original schema") |

## jacsSha256 Type

`string`
