# Untitled string in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/jacsAgreementHash
```

Stable hash of the agreement consent scope. SDKs compute this over: title, description, terms, termsFormat, parties, and signaturePolicy. NOT over: transcript, agreementSignatures, allPreviousVersions, controllers, or any header field. Appending to transcript, appending agreementSignatures, or appending to allPreviousVersions must not change this hash.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## jacsAgreementHash Type

`string`

## jacsAgreementHash Constraints

**minimum length**: the minimum number of characters for this string is: `1`
