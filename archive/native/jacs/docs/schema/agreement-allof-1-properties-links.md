# Untitled array in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/links
```

Links to other JACS document versions. A link is intentionally only {jacsId, jacsVersion}; relationship semantics such as supersedes or terminates are expressed by the successor agreement's terms/status, not by extra link fields.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## links Type

`object[]` ([Details](agreement-definitions-agreementlink.md))
