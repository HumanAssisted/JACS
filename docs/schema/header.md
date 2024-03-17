# Header Schema

```txt
https://hai.ai/schemas/header/v1/header-schema.json
```

The basis for a JACS document

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                              |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [header.schema.json](../../schemas/header/v1/header.schema.json "open original schema") |

## Header Type

`object` ([Header](header.md))

# Header Properties

| Property                                    | Type     | Required | Nullable       | Defined by                                                                                                                       |
| :------------------------------------------ | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                                   | `string` | Required | cannot be null | [Header](header-properties-id.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/id")                           |
| [registrars](#registrars)                   | `array`  | Optional | cannot be null | [Header](header-properties-registrars.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/registrars")           |
| [permissions](#permissions)                 | `array`  | Optional | cannot be null | [Header](header-properties-permissions.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/permissions")         |
| [version](#version)                         | `string` | Required | cannot be null | [Header](header-properties-version.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/version")                 |
| [versionDate](#versiondate)                 | `string` | Required | cannot be null | [Header](header-properties-versiondate.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/versionDate")         |
| [versionSignature](#versionsignature)       | `object` | Optional | cannot be null | [Header](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/versionSignature")       |
| [versionRegistration](#versionregistration) | `object` | Optional | cannot be null | [Header](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/versionRegistration")    |
| [previousVersion](#previousversion)         | `string` | Optional | cannot be null | [Header](header-properties-previousversion.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/previousVersion") |
| [originalVersion](#originalversion)         | `string` | Required | cannot be null | [Header](header-properties-originalversion.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/originalVersion") |

## id

GUID

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-id.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/id")

### id Type

`string`

### id Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## registrars

Signing authorities agent is registered with.

`registrars`

*   is optional

*   Type: `object[]` ([Signature](signature.md))

*   cannot be null

*   defined in: [Header](header-properties-registrars.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/registrars")

### registrars Type

`object[]` ([Signature](signature.md))

## permissions

array of permissions

`permissions`

*   is optional

*   Type: `object[]` ([Permission](permission.md))

*   cannot be null

*   defined in: [Header](header-properties-permissions.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/permissions")

### permissions Type

`object[]` ([Permission](permission.md))

## version

Version id of the object

`version`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-version.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/version")

### version Type

`string`

### version Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## versionDate

Date

`versionDate`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-versiondate.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/versionDate")

### versionDate Type

`string`

### versionDate Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## versionSignature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`versionSignature`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Header](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/versionSignature")

### versionSignature Type

`object` ([Signature](signature.md))

## versionRegistration

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`versionRegistration`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Header](signature.md "https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/versionRegistration")

### versionRegistration Type

`object` ([Signature](signature.md))

## previousVersion

Previous Version id of the object. If blank, it's claiming to be the first

`previousVersion`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-previousversion.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/previousVersion")

### previousVersion Type

`string`

### previousVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## originalVersion

Original Version id of the object. When documents are copied without merging, this becomes the way to track them.

`originalVersion`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Header](header-properties-originalversion.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/originalVersion")

### originalVersion Type

`string`

### originalVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")
