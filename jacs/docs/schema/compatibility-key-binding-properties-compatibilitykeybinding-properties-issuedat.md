# Untitled string in Compatibility Key Binding Schema

```txt
https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/issuedAt
```

Issuance instant. When multiple bindings exist for the same kid, the latest issuedAt wins.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [compatibility-key-binding.schema.json\*](../../schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json "open original schema") |

## issuedAt Type

`string`

## issuedAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")
