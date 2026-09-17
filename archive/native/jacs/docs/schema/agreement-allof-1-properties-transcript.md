# Untitled array in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/transcript
```

Append-only list of JACS document references — any type of JACS-headed document (messages, statements, evidence, attachments, identity proofs). Each referenced document is itself idempotent (single version). Appending entries does not change jacsAgreementHash and does not invalidate prior agreementSignatures, but DOES change what signedTranscriptHash subsequent signers commit to. Append-only is enforced operationally, not by JSON Schema.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## transcript Type

`object[]` ([Details](agreement-definitions-jacsdocumentref.md))
