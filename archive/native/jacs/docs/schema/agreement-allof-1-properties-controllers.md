# Untitled array in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/controllers
```

Agent IDs authorized to propose successor versions, append to transcript, change status, or modify parties. Edit authority — distinct from parties (who is bound) and jacsVisibility (who can read).

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## controllers Type

`string[]`

## controllers Constraints

**unique items**: all items in this array must be unique. Duplicates are not allowed.
