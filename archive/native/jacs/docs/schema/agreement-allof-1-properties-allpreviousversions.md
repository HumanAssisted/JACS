# Untitled array in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/allPreviousVersions
```

Append-only list of every prior jacsVersion of this agreement document, in chronological order. Header jacsPreviousVersion is the immediate parent; this list is the full chain back to the original version. Append-only is enforced operationally.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## allPreviousVersions Type

`string[]`
