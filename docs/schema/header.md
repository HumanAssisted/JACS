# Header Schema

```txt
https://hai.ai/schemas/header/v1/header.schema.json
```

The basis for a JACS document

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                              |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [header.schema.json](../../schemas/header/v1/header.schema.json "open original schema") |

## Header Type

`object` ([Header](header.md))

# Header Properties

| Property                                    | Type     | Required | Nullable       | Defined by                                                                                                                               |
| :------------------------------------------ | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsId](#jacsid)                           | `string` | Required | cannot be null | [Header](header-properties-jacsid.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsId")                           |
| [jacsVersion](#jacsversion)                 | `string` | Required | cannot be null | [Header](header-properties-jacsversion.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVersion")                 |
| [jacsVersionDate](#jacsversiondate)         | `string` | Required | cannot be null | [Header](header-properties-jacsversiondate.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVersionDate")         |
| [jacsSignature](#jacssignature)             | `object` | Optional | cannot be null | [Header](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/jacsSignature")                  |
| [jacsPreviousVersion](#jacspreviousversion) | `string` | Optional | cannot be null | [Header](header-properties-jacspreviousversion.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsPreviousVersion") |
| [jacsOriginalVersion](#jacsoriginalversion) | `string` | Required | cannot be null | [Header](header-properties-jacsoriginalversion.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsOriginalVersion") |
| [jacsOriginalDate](#jacsoriginaldate)       | `string` | Required | cannot be null | [Header](header-properties-jacsoriginaldate.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsOriginalDate")       |
| [jacsSha256](#jacssha256)                   | `string` | Optional | cannot be null | [Header](header-properties-jacssha256.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsSha256")                   |
| [jacsFiles](#jacsfiles)                     | `array`  | Optional | cannot be null | [Header](header-properties-jacsfiles.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsFiles")                     |

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

## jacsSignature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`jacsSignature`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Header](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/jacsSignature")

### jacsSignature Type

`object` ([Signature](signature.md))

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

*   Type: `object[]` ([File](files.md))

*   cannot be null

*   defined in: [Header](header-properties-jacsfiles.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsFiles")

### jacsFiles Type

`object[]` ([File](files.md))
