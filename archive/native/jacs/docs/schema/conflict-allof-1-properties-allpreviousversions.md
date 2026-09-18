# Untitled array in Conflict Schema

```txt
https://hai.ai/schemas/conflict/v1/conflict.schema.json#/allOf/1/properties/allPreviousVersions
```

Append-only list of every prior jacsVersion of this conflict document, in chronological order. Header jacsPreviousVersion is the immediate parent; this list is the full chain back to the original version. Append-only is enforced operationally.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                      |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [conflict.schema.json\*](../../schemas/conflict/v1/conflict.schema.json "open original schema") |

## allPreviousVersions Type

`string[]`
