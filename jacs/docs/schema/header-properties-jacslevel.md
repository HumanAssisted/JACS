# Untitled string in Header Schema

```txt
https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsLevel
```

What is the intended use of the data? Raw data should not change, where as an artifact and config is meant to be updated.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [header.schema.json\*](../../schemas/header/v1/header.schema.json "open original schema") |

## jacsLevel Type

`string`

## jacsLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"raw"`      |             |
| `"config"`   |             |
| `"artifact"` |             |
| `"derived"`  |             |
