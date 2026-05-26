# Untitled array in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/agreementSignatures
```

Consent and attestation signatures over the agreement. Each entry is a JACS signature binding jacsAgreementHash (and signedTranscriptHash when transcript is non-empty).

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## agreementSignatures Type

`object[]` ([Details](agreement-definitions-agreementsignature.md))
