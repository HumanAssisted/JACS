# Untitled undefined type in Header Schema

```txt
https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVisibility
```

Document visibility level for access control. Controls who can see and access a document through tool responses and API queries. Default is private (safe by default).

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [header.schema.json\*](../../schemas/header/v1/header.schema.json "open original schema") |

## jacsVisibility Type

merged type ([Details](header-properties-jacsvisibility.md))

one (and only one) of

* [Untitled string in Header](header-properties-jacsvisibility-oneof-0.md "check type definition")

* [Untitled object in Header](header-properties-jacsvisibility-oneof-1.md "check type definition")

## jacsVisibility Default Value

The default value is:

```json
"private"
```
