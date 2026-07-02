# Untitled array in Compatibility Key Binding Schema

```txt
https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/scope
```

Exports this key is authorized to produce. Identity scopes are granted by default at issuance; content scopes (ap2-mandate, agreement-vc) require an explicit re-issue by the PQ root.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [compatibility-key-binding.schema.json\*](../../schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json "open original schema") |

## scope Type

`string[]`

## scope Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

**unique items**: all items in this array must be unique. Duplicates are not allowed.
