# Untitled string in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/signedTranscriptHash
```

Canonical hash over the transcript\[] array at the moment of signing. REQUIRED when transcript is non-empty (enforced operationally). If transcript entries are later removed or reordered, the recomputed hash will no longer match this value — the tamper-evidence anchor.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## signedTranscriptHash Type

`string`
