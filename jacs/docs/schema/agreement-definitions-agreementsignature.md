# Untitled object in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature
```

A JACS signature over the agreement. The inner signature object binds jacsAgreementHash (and signedTranscriptHash when transcript is non-empty) and carries the signer's agent identity and timestamp. The wrapper carries only what the JACS signature cannot: the agreement role, the transcript snapshot, and an optional delegation chain.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## agreementSignature Type

`object` ([Details](agreement-definitions-agreementsignature.md))

# agreementSignature Properties

| Property                                      | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                           |
| :-------------------------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [signature](#signature)                       | `object` | Required | cannot be null | [Agreement](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/definitions/agreementSignature/properties/signature")                                            |
| [role](#role)                                 | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementsignature-properties-role.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/role")                                 |
| [signedTranscriptHash](#signedtranscripthash) | `string` | Optional | cannot be null | [Agreement](agreement-definitions-agreementsignature-properties-signedtranscripthash.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/signedTranscriptHash") |
| [delegationChain](#delegationchain)           | `array`  | Optional | cannot be null | [Agreement](agreement-definitions-agreementsignature-properties-delegationchain.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/delegationChain")           |

## signature

SACRED CRYPTOGRAPHIC COMMITMENT: A signature is a permanent, irreversible cryptographic proof binding the signer to document content. Once signed, the signer cannot deny their attestation (non-repudiation). Signatures should only be created after careful review of document content. The signer is forever accountable for what they sign.

`signature`

* is required

* Type: `object` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [Agreement](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/definitions/agreementSignature/properties/signature")

### signature Type

`object` ([Signature](header-properties-signature-1.md))

## role

Signer signatures count toward partyQuorum; witness signatures count toward witnessRequired; notary signatures provide distinct notarial attestation.

`role`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementsignature-properties-role.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/role")

### role Type

`string`

### role Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value       | Explanation |
| :---------- | :---------- |
| `"signer"`  |             |
| `"witness"` |             |
| `"notary"`  |             |

## signedTranscriptHash

Canonical hash over the transcript\[] array at the moment of signing. REQUIRED when transcript is non-empty (enforced operationally). If transcript entries are later removed or reordered, the recomputed hash will no longer match this value — the tamper-evidence anchor.

`signedTranscriptHash`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementsignature-properties-signedtranscripthash.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/signedTranscriptHash")

### signedTranscriptHash Type

`string`

## delegationChain

If signing on behalf of a party, ordered list of signed JACS delegation document references proving authority.

`delegationChain`

* is optional

* Type: `object[]` ([Details](agreement-definitions-jacsdocumentref.md))

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementsignature-properties-delegationchain.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/delegationChain")

### delegationChain Type

`object[]` ([Details](agreement-definitions-jacsdocumentref.md))
