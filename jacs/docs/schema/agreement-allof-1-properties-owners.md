# Untitled array in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/owners
```

Agent IDs making soft copyright or ownership claims over this agreement document. This does not grant read access, edit authority, or signing authority.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## owners Type

`string[]`

## owners Constraints

**unique items**: all items in this array must be unique. Duplicates are not allowed.
