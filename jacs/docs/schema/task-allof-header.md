# Header Schema

```txt
https://hai.ai/schemas/header/v1/header.schema.json#/allOf/0
```

The basis for a JACS document

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                          |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [task.schema.json\*](../../schemas/task/v1/task.schema.json "open original schema") |

## 0 Type

`object` ([Header](task-allof-header.md))

# 0 Properties

| Property                                    | Type     | Required | Nullable       | Defined by                                                                                                                                     |
| :------------------------------------------ | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsId](#jacsid)                           | `string` | Required | cannot be null | [Header](header-properties-jacsid.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsId")                                 |
| [jacsVersion](#jacsversion)                 | `string` | Required | cannot be null | [Header](header-properties-jacsversion.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVersion")                       |
| [jacsVersionDate](#jacsversiondate)         | `string` | Required | cannot be null | [Header](header-properties-jacsversiondate.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVersionDate")               |
| [jacsType](#jacstype)                       | `string` | Required | cannot be null | [Header](header-properties-jacstype.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsType")                             |
| [jacsSignature](#jacssignature)             | `object` | Optional | cannot be null | [Header](header-properties-signature.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/jacsSignature")      |
| [jacsRegistration](#jacsregistration)       | `object` | Optional | cannot be null | [Header](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/jacsRegistration") |
| [jacsAgreement](#jacsagreement)             | `object` | Optional | cannot be null | [Header](header-properties-agreement.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/jacsAgreement")      |
| [jacsAgreementHash](#jacsagreementhash)     | `string` | Optional | cannot be null | [Header](header-properties-jacsagreementhash.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsAgreementHash")           |
| [jacsPreviousVersion](#jacspreviousversion) | `string` | Optional | cannot be null | [Header](header-properties-jacspreviousversion.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsPreviousVersion")       |
| [jacsOriginalVersion](#jacsoriginalversion) | `string` | Required | cannot be null | [Header](header-properties-jacsoriginalversion.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsOriginalVersion")       |
| [jacsOriginalDate](#jacsoriginaldate)       | `string` | Required | cannot be null | [Header](header-properties-jacsoriginaldate.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsOriginalDate")             |
| [jacsSha256](#jacssha256)                   | `string` | Optional | cannot be null | [Header](header-properties-jacssha256.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsSha256")                         |
| [jacsFiles](#jacsfiles)                     | `array`  | Optional | cannot be null | [Header](header-properties-jacsfiles.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsFiles")                           |
| [jacsEmbedding](#jacsembedding)             | `array`  | Optional | cannot be null | [Header](header-properties-jacsembedding.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsEmbedding")                   |
| [jacsLevel](#jacslevel)                     | `string` | Required | cannot be null | [Header](header-properties-jacslevel.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsLevel")                           |

## jacsId

uuid v4 string

`jacsId`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacsid.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsId")

### jacsId Type

`string`

### jacsId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## jacsVersion

Version id of the object. uuid v4 string

`jacsVersion`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacsversion.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVersion")

### jacsVersion Type

`string`

### jacsVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## jacsVersionDate

Date

`jacsVersionDate`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacsversiondate.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVersionDate")

### jacsVersionDate Type

`string`

### jacsVersionDate Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## jacsType

Type of the document

`jacsType`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacstype.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsType")

### jacsType Type

`string`

## jacsSignature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`jacsSignature`

*   is optional

*   Type: `object` ([Signature](header-properties-signature-1.md))

*   cannot be null

*   defined in: [Header](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/jacsSignature")

### jacsSignature Type

`object` ([Signature](header-properties-signature-1.md))

## jacsRegistration

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`jacsRegistration`

*   is optional

*   Type: `object` ([Signature](header-properties-signature-1.md))

*   cannot be null

*   defined in: [Header](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/jacsRegistration")

### jacsRegistration Type

`object` ([Signature](header-properties-signature-1.md))

## jacsAgreement

A set of required signatures signifying an agreement.

`jacsAgreement`

*   is optional

*   Type: `object` ([agreement](header-properties-agreement.md))

*   cannot be null

*   defined in: [Header](header-properties-agreement.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/jacsAgreement")

### jacsAgreement Type

`object` ([agreement](header-properties-agreement.md))

## jacsAgreementHash

A hash that must not change for each signature.

`jacsAgreementHash`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacsagreementhash.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsAgreementHash")

### jacsAgreementHash Type

`string`

## jacsPreviousVersion

Previous Version id of the object. If blank, it's claiming to be the first

`jacsPreviousVersion`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacspreviousversion.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsPreviousVersion")

### jacsPreviousVersion Type

`string`

### jacsPreviousVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## jacsOriginalVersion

Original Version id of the object.

`jacsOriginalVersion`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacsoriginalversion.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsOriginalVersion")

### jacsOriginalVersion Type

`string`

### jacsOriginalVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## jacsOriginalDate

Original creation date of the document.

`jacsOriginalDate`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacsoriginaldate.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsOriginalDate")

### jacsOriginalDate Type

`string`

### jacsOriginalDate Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## jacsSha256

Hash of every field except this one. During  updates and creation hash is the last thing to occur, as it includes the signature. Not immediatly required, but eventually required.

`jacsSha256`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacssha256.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsSha256")

### jacsSha256 Type

`string`

## jacsFiles

A set of files included with the jacs document

`jacsFiles`

*   is optional

*   Type: `object[]` ([File](header-properties-jacsfiles-file.md))

*   cannot be null

*   defined in: [Header](header-properties-jacsfiles.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsFiles")

### jacsFiles Type

`object[]` ([File](header-properties-jacsfiles-file.md))

## jacsEmbedding

A set of precalculated vector embeddings

`jacsEmbedding`

*   is optional

*   Type: `object[]` ([Embedding](header-properties-jacsembedding-embedding.md))

*   cannot be null

*   defined in: [Header](header-properties-jacsembedding.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsEmbedding")

### jacsEmbedding Type

`object[]` ([Embedding](header-properties-jacsembedding-embedding.md))

## jacsLevel

What is the intended use of the data? Raw data should not change, where as an artifact and config is meant to be updated.

`jacsLevel`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-jacslevel.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsLevel")

### jacsLevel Type

`string`

### jacsLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"raw"`      |             |
| `"config"`   |             |
| `"artifact"` |             |
| `"derived"`  |             |
