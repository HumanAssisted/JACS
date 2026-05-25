# Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json
```

A standalone JACS agreement document for verifiable consent to terms. The JACS header owns document identity, versioning, authorship signatures, registration, files, hashes, and visibility. This schema adds agreement-specific terms, parties, policy, consent signatures, transcript, and edit-authority controllers.

Signature binding: each agreement signature is a standard JACS signature whose inner preimage is the parent document's jacsAgreementHash. When transcript is non-empty, each signature additionally binds signedTranscriptHash. Agent identity and signing timestamp live inside the JACS signature object; the wrapper does not duplicate them.

Transcript: an inline append-only list of JACS document references — messages, statements, evidence, attachments, identity proofs, anything with a JACS header. Each referenced document is itself idempotent (not meant to have more than one version). The list is append-only by SDK convention; signedTranscriptHash on each agreement signature is the tamper-evidence anchor over the list state at signing time.

allPreviousVersions: append-only ledger of every prior jacsVersion of this agreement. Header jacsPreviousVersion gives the immediate parent; this list gives the full chain back to the original version. Append-only by SDK convention.

| Abstract               | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                       |
| :--------------------- | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------- |
| Cannot be instantiated | Yes        | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## Agreement Type

merged type ([Agreement](agreement.md))

all of

* [Header](attestation-allof-header.md "check type definition")

* [Untitled object in Agreement](agreement-allof-1.md "check type definition")

# Agreement Definitions

## Definitions group party

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party"}
```

| Property                      | Type     | Required | Nullable       | Defined by                                                                                                                                                                 |
| :---------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [agentId](#agentid)           | `string` | Required | cannot be null | [Agreement](agreement-definitions-party-properties-agentid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentId")           |
| [agentVersion](#agentversion) | `string` | Optional | cannot be null | [Agreement](agreement-definitions-party-properties-agentversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentVersion") |
| [agentType](#agenttype)       | `string` | Required | cannot be null | [Agreement](agreement-definitions-party-properties-agenttype.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentType")       |
| [role](#role)                 | `string` | Required | cannot be null | [Agreement](agreement-definitions-party-properties-role.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/role")                 |
| [delegatedBy](#delegatedby)   | `string` | Optional | cannot be null | [Agreement](agreement-definitions-party-properties-delegatedby.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/delegatedBy")   |
| [displayName](#displayname)   | `string` | Optional | cannot be null | [Agreement](agreement-definitions-party-properties-displayname.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/displayName")   |

### agentId



`agentId`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-agentid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentId")

#### agentId Type

`string`

#### agentId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### agentVersion



`agentVersion`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-agentversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentVersion")

#### agentVersion Type

`string`

#### agentVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### agentType



`agentType`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-agenttype.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentType")

#### agentType Type

`string`

#### agentType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"human"`     |             |
| `"human-org"` |             |
| `"hybrid"`    |             |
| `"ai"`        |             |

### role



`role`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-role.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/role")

#### role Type

`string`

#### role Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"signer"`   |             |
| `"witness"`  |             |
| `"notary"`   |             |
| `"observer"` |             |

### delegatedBy

Optional: agent id on whose behalf this party signs. Proof of authority lives in agreementSignature.delegationChain.

`delegatedBy`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-delegatedby.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/delegatedBy")

#### delegatedBy Type

`string`

#### delegatedBy Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### displayName



`displayName`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-displayname.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/displayName")

#### displayName Type

`string`

#### displayName Constraints

**maximum length**: the maximum number of characters for this string is: `256`

## Definitions group signaturePolicy

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy"}
```

| Property                                  | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                 |
| :---------------------------------------- | :-------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [partyQuorum](#partyquorum)               | Merged    | Required | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-partyquorum.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/partyQuorum")               |
| [witnessRequired](#witnessrequired)       | `integer` | Optional | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-witnessrequired.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/witnessRequired")       |
| [notaryRequired](#notaryrequired)         | `integer` | Optional | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-notaryrequired.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/notaryRequired")         |
| [timeout](#timeout)                       | `string`  | Optional | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-timeout.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/timeout")                       |
| [requiredAlgorithms](#requiredalgorithms) | `array`   | Optional | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-requiredalgorithms.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/requiredAlgorithms") |
| [minimumStrength](#minimumstrength)       | `string`  | Optional | cannot be null | [Agreement](agreement-definitions-signaturepolicy-properties-minimumstrength.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/minimumStrength")       |

### partyQuorum

Signer-party consent threshold. 'all' = every signer-role party; 'majority' = more than half; integer N = at least N signer-role party signatures.

`partyQuorum`

* is required

* Type: merged type ([Details](agreement-definitions-signaturepolicy-properties-partyquorum.md))

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-partyquorum.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/partyQuorum")

#### partyQuorum Type

merged type ([Details](agreement-definitions-signaturepolicy-properties-partyquorum.md))

one (and only one) of

* [Untitled string in Agreement](agreement-definitions-signaturepolicy-properties-partyquorum-oneof-0.md "check type definition")

* [Untitled integer in Agreement](agreement-definitions-signaturepolicy-properties-partyquorum-oneof-1.md "check type definition")

#### partyQuorum Default Value

The default value is:

```json
"all"
```

### witnessRequired

Minimum witness-role party signatures required in addition to signer quorum. Witnesses do not count toward partyQuorum.

`witnessRequired`

* is optional

* Type: `integer`

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-witnessrequired.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/witnessRequired")

#### witnessRequired Type

`integer`

#### witnessRequired Constraints

**minimum**: the value of this number must greater than or equal to: `0`

### notaryRequired

Minimum notary-role party signatures required in addition to signer quorum and witness signatures. HAI-style notaries do not count toward partyQuorum.

`notaryRequired`

* is optional

* Type: `integer`

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-notaryrequired.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/notaryRequired")

#### notaryRequired Type

`integer`

#### notaryRequired Constraints

**minimum**: the value of this number must greater than or equal to: `0`

### timeout

ISO 8601 deadline after which new signatures are not accepted.

`timeout`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-timeout.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/timeout")

#### timeout Type

`string`

#### timeout Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

### requiredAlgorithms



`requiredAlgorithms`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-requiredalgorithms.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/requiredAlgorithms")

#### requiredAlgorithms Type

`string[]`

### minimumStrength



`minimumStrength`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy-properties-minimumstrength.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/minimumStrength")

#### minimumStrength Type

`string`

#### minimumStrength Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"classical"`    |             |
| `"post-quantum"` |             |

## Definitions group agreementSignature

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature"}
```

| Property                                      | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                           |
| :-------------------------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [signature](#signature)                       | `object` | Required | cannot be null | [Agreement](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/definitions/agreementSignature/properties/signature")                                            |
| [role](#role-1)                               | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementsignature-properties-role.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/role")                                 |
| [signedTranscriptHash](#signedtranscripthash) | `string` | Optional | cannot be null | [Agreement](agreement-definitions-agreementsignature-properties-signedtranscripthash.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/signedTranscriptHash") |
| [delegationChain](#delegationchain)           | `array`  | Optional | cannot be null | [Agreement](agreement-definitions-agreementsignature-properties-delegationchain.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/delegationChain")           |

### signature

SACRED CRYPTOGRAPHIC COMMITMENT: A signature is a permanent, irreversible cryptographic proof binding the signer to document content. Once signed, the signer cannot deny their attestation (non-repudiation). Signatures should only be created after careful review of document content. The signer is forever accountable for what they sign.

`signature`

* is required

* Type: `object` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [Agreement](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/definitions/agreementSignature/properties/signature")

#### signature Type

`object` ([Signature](header-properties-signature-1.md))

### role

Signer signatures count toward partyQuorum; witness signatures count toward witnessRequired; notary signatures provide distinct notarial attestation.

`role`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementsignature-properties-role.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/role")

#### role Type

`string`

#### role Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value       | Explanation |
| :---------- | :---------- |
| `"signer"`  |             |
| `"witness"` |             |
| `"notary"`  |             |

### signedTranscriptHash

Canonical hash over the transcript\[] array at the moment of signing. REQUIRED when transcript is non-empty (enforced operationally). If transcript entries are later removed or reordered, the recomputed hash will no longer match this value — the tamper-evidence anchor.

`signedTranscriptHash`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementsignature-properties-signedtranscripthash.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/signedTranscriptHash")

#### signedTranscriptHash Type

`string`

### delegationChain

If signing on behalf of a party, ordered list of signed JACS delegation document references proving authority.

`delegationChain`

* is optional

* Type: `object[]` ([Details](agreement-definitions-jacsdocumentref.md))

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementsignature-properties-delegationchain.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature/properties/delegationChain")

#### delegationChain Type

`object[]` ([Details](agreement-definitions-jacsdocumentref.md))

## Definitions group agreementLink

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink"}
```

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                                                                               |
| :-------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [rel](#rel)                 | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-rel.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/rel")                 |
| [jacsId](#jacsid)           | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-jacsid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsId")           |
| [jacsVersion](#jacsversion) | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-jacsversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsVersion") |
| [reason](#reason)           | `string` | Optional | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-reason.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/reason")           |

### rel



`rel`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementlink-properties-rel.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/rel")

#### rel Type

`string`

#### rel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value          | Explanation |
| :------------- | :---------- |
| `"references"` |             |
| `"amends"`     |             |
| `"supersedes"` |             |
| `"terminates"` |             |
| `"renews"`     |             |

### jacsId



`jacsId`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementlink-properties-jacsid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsId")

#### jacsId Type

`string`

#### jacsId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### jacsVersion



`jacsVersion`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementlink-properties-jacsversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsVersion")

#### jacsVersion Type

`string`

#### jacsVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### reason



`reason`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementlink-properties-reason.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/reason")

#### reason Type

`string`

#### reason Constraints

**maximum length**: the maximum number of characters for this string is: `1024`

## Definitions group jacsDocumentRef

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/jacsDocumentRef"}
```

| Property                      | Type     | Required | Nullable       | Defined by                                                                                                                                                                                   |
| :---------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsId](#jacsid-1)           | `string` | Required | cannot be null | [Agreement](agreement-definitions-jacsdocumentref-properties-jacsid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/jacsDocumentRef/properties/jacsId")           |
| [jacsVersion](#jacsversion-1) | `string` | Required | cannot be null | [Agreement](agreement-definitions-jacsdocumentref-properties-jacsversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/jacsDocumentRef/properties/jacsVersion") |
| [jacsSha256](#jacssha256)     | `string` | Required | cannot be null | [Agreement](agreement-definitions-jacsdocumentref-properties-jacssha256.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/jacsDocumentRef/properties/jacsSha256")   |

### jacsId



`jacsId`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-jacsdocumentref-properties-jacsid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/jacsDocumentRef/properties/jacsId")

#### jacsId Type

`string`

#### jacsId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### jacsVersion



`jacsVersion`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-jacsdocumentref-properties-jacsversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/jacsDocumentRef/properties/jacsVersion")

#### jacsVersion Type

`string`

#### jacsVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

### jacsSha256



`jacsSha256`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-jacsdocumentref-properties-jacssha256.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/jacsDocumentRef/properties/jacsSha256")

#### jacsSha256 Type

`string`

#### jacsSha256 Constraints

**minimum length**: the minimum number of characters for this string is: `1`
