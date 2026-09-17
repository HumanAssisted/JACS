# Untitled integer in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/notaryRequired
```

Minimum notary-role party signatures required in addition to signer quorum and witness signatures. HAI-style notaries do not count toward partyQuorum.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## notaryRequired Type

`integer`

## notaryRequired Constraints

**minimum**: the value of this number must greater than or equal to: `0`
