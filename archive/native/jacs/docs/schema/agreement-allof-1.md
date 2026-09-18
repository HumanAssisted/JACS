# Untitled object in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## 1 Type

`object` ([Details](agreement-allof-1.md))

# 1 Properties

| Property                                    | Type     | Required | Nullable       | Defined by                                                                                                                                                           |
| :------------------------------------------ | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsType](#jacstype)                       | `string` | Optional | cannot be null | [Agreement](agreement-allof-1-properties-jacstype.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/jacsType")                       |
| [jacsLevel](#jacslevel)                     | `string` | Optional | cannot be null | [Agreement](agreement-allof-1-properties-jacslevel.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/jacsLevel")                     |
| [jacsAgreementHash](#jacsagreementhash)     | `string` | Required | cannot be null | [Agreement](agreement-allof-1-properties-jacsagreementhash.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/jacsAgreementHash")     |
| [title](#title)                             | `string` | Required | cannot be null | [Agreement](agreement-allof-1-properties-title.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/title")                             |
| [description](#description)                 | `string` | Required | cannot be null | [Agreement](agreement-allof-1-properties-description.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/description")                 |
| [terms](#terms)                             | `string` | Required | cannot be null | [Agreement](agreement-allof-1-properties-terms.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/terms")                             |
| [termsFormat](#termsformat)                 | `string` | Optional | cannot be null | [Agreement](agreement-allof-1-properties-termsformat.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/termsFormat")                 |
| [status](#status)                           | `string` | Required | cannot be null | [Agreement](agreement-allof-1-properties-status.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/status")                           |
| [effectiveFrom](#effectivefrom)             | `string` | Optional | cannot be null | [Agreement](agreement-allof-1-properties-effectivefrom.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/effectiveFrom")             |
| [expiresAt](#expiresat)                     | `string` | Optional | cannot be null | [Agreement](agreement-allof-1-properties-expiresat.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/expiresAt")                     |
| [parties](#parties)                         | `array`  | Required | cannot be null | [Agreement](agreement-allof-1-properties-parties.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/parties")                         |
| [signaturePolicy](#signaturepolicy)         | `object` | Required | cannot be null | [Agreement](agreement-definitions-signaturepolicy.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/signaturePolicy")                |
| [agreementSignatures](#agreementsignatures) | `array`  | Required | cannot be null | [Agreement](agreement-allof-1-properties-agreementsignatures.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/agreementSignatures") |
| [transcript](#transcript)                   | `array`  | Optional | cannot be null | [Agreement](agreement-allof-1-properties-transcript.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/transcript")                   |
| [allPreviousVersions](#allpreviousversions) | `array`  | Optional | cannot be null | [Agreement](agreement-allof-1-properties-allpreviousversions.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/allPreviousVersions") |
| [links](#links)                             | `array`  | Optional | cannot be null | [Agreement](agreement-allof-1-properties-links.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/links")                             |
| [controllers](#controllers)                 | `array`  | Optional | cannot be null | [Agreement](agreement-allof-1-properties-controllers.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/controllers")                 |
| [owners](#owners)                           | `array`  | Optional | cannot be null | [Agreement](agreement-allof-1-properties-owners.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/owners")                           |

## jacsType



`jacsType`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-jacstype.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/jacsType")

### jacsType Type

`string`

### jacsType Constraints

**constant**: the value of this property must be equal to:

```json
"agreement"
```

## jacsLevel



`jacsLevel`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-jacslevel.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/jacsLevel")

### jacsLevel Type

`string`

### jacsLevel Constraints

**constant**: the value of this property must be equal to:

```json
"artifact"
```

## jacsAgreementHash

Stable hash of the agreement consent scope. SDKs compute this over: title, description, terms, termsFormat, effectiveFrom, expiresAt, parties, and signaturePolicy. NOT over: transcript, agreementSignatures, allPreviousVersions, controllers, links, or any header field. Appending to transcript, appending agreementSignatures, appending to allPreviousVersions, or updating links must not change this hash.

`jacsAgreementHash`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-jacsagreementhash.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/jacsAgreementHash")

### jacsAgreementHash Type

`string`

### jacsAgreementHash Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## title



`title`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-title.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/title")

### title Type

`string`

### title Constraints

**maximum length**: the maximum number of characters for this string is: `256`

**minimum length**: the minimum number of characters for this string is: `1`

## description



`description`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-description.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/description")

### description Type

`string`

### description Constraints

**maximum length**: the maximum number of characters for this string is: `4096`

**minimum length**: the minimum number of characters for this string is: `1`

## terms

The agreement text the signer parties consent to. Plain text or Markdown for MVP.

`terms`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-terms.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/terms")

### terms Type

`string`

### terms Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## termsFormat



`termsFormat`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-termsformat.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/termsFormat")

### termsFormat Type

`string`

### termsFormat Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value             | Explanation |
| :---------------- | :---------- |
| `"text/plain"`    |             |
| `"text/markdown"` |             |

### termsFormat Default Value

The default value is:

```json
"text/plain"
```

## status



`status`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-status.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/status")

### status Type

`string`

### status Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                | Explanation |
| :------------------- | :---------- |
| `"draft"`            |             |
| `"proposed"`         |             |
| `"partially_signed"` |             |
| `"final"`            |             |
| `"expired"`          |             |
| `"disputed"`         |             |
| `"superseded"`       |             |
| `"terminated"`       |             |

## effectiveFrom

Optional ISO 8601 timestamp when agreement obligations begin. Distinct from agreement signature timestamps and signaturePolicy.timeout.

`effectiveFrom`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-effectivefrom.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/effectiveFrom")

### effectiveFrom Type

`string`

### effectiveFrom Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## expiresAt

Optional ISO 8601 timestamp when this agreement stops governing. Distinct from signaturePolicy.timeout, which is the deadline for collecting signatures.

`expiresAt`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-expiresat.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/expiresAt")

### expiresAt Type

`string`

### expiresAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## parties



`parties`

* is required

* Type: `object[]` ([Details](agreement-definitions-party.md))

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-parties.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/parties")

### parties Type

`object[]` ([Details](agreement-definitions-party.md))

### parties Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

## signaturePolicy

Rules for when the agreement is considered complete.

`signaturePolicy`

* is required

* Type: `object` ([Details](agreement-definitions-signaturepolicy.md))

* cannot be null

* defined in: [Agreement](agreement-definitions-signaturepolicy.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/signaturePolicy")

### signaturePolicy Type

`object` ([Details](agreement-definitions-signaturepolicy.md))

## agreementSignatures

Consent and attestation signatures over the agreement. Each entry is a JACS signature binding jacsAgreementHash (and signedTranscriptHash when transcript is non-empty).

`agreementSignatures`

* is required

* Type: `object[]` ([Details](agreement-definitions-agreementsignature.md))

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-agreementsignatures.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/agreementSignatures")

### agreementSignatures Type

`object[]` ([Details](agreement-definitions-agreementsignature.md))

## transcript

Append-only list of JACS document references — any type of JACS-headed document (messages, statements, evidence, attachments, identity proofs). Each referenced document is itself idempotent (single version). Appending entries does not change jacsAgreementHash and does not invalidate prior agreementSignatures, but DOES change what signedTranscriptHash subsequent signers commit to. Append-only is enforced operationally, not by JSON Schema.

`transcript`

* is optional

* Type: `object[]` ([Details](agreement-definitions-jacsdocumentref.md))

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-transcript.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/transcript")

### transcript Type

`object[]` ([Details](agreement-definitions-jacsdocumentref.md))

## allPreviousVersions

Append-only list of every prior jacsVersion of this agreement document, in chronological order. Header jacsPreviousVersion is the immediate parent; this list is the full chain back to the original version. Append-only is enforced operationally.

`allPreviousVersions`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-allpreviousversions.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/allPreviousVersions")

### allPreviousVersions Type

`string[]`

## links

Links to other JACS document versions. A link is intentionally only {jacsId, jacsVersion}; relationship semantics such as supersedes or terminates are expressed by the successor agreement's terms/status, not by extra link fields.

`links`

* is optional

* Type: `object[]` ([Details](agreement-definitions-agreementlink.md))

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-links.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/links")

### links Type

`object[]` ([Details](agreement-definitions-agreementlink.md))

## controllers

Agent IDs authorized to propose successor versions, append to transcript, change status, or modify parties. Edit authority — distinct from parties (who is bound) and jacsVisibility (who can read).

`controllers`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-controllers.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/controllers")

### controllers Type

`string[]`

### controllers Constraints

**unique items**: all items in this array must be unique. Duplicates are not allowed.

## owners

Agent IDs making soft copyright or ownership claims over this agreement document. This does not grant read access, edit authority, or signing authority.

`owners`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Agreement](agreement-allof-1-properties-owners.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/owners")

### owners Type

`string[]`

### owners Constraints

**unique items**: all items in this array must be unique. Duplicates are not allowed.
