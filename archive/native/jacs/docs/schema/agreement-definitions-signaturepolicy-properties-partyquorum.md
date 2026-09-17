# Untitled undefined type in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/partyQuorum
```

Signer-party consent threshold. 'all' = every signer-role party; 'majority' = more than half; integer N = at least N signer-role party signatures.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## partyQuorum Type

merged type ([Details](agreement-definitions-signaturepolicy-properties-partyquorum.md))

one (and only one) of

* [Untitled string in Agreement](agreement-definitions-signaturepolicy-properties-partyquorum-oneof-0.md "check type definition")

* [Untitled integer in Agreement](agreement-definitions-signaturepolicy-properties-partyquorum-oneof-1.md "check type definition")

## partyQuorum Default Value

The default value is:

```json
"all"
```
