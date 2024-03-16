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

| Property                        | Type     | Required | Nullable       | Defined by                                                                                                                   |
| :------------------------------ | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                       | `string` | Required | cannot be null | [Header](header-properties-id.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/id")                       |
| [registrations](#registrations) | `array`  | Optional | cannot be null | [Header](header-properties-registrations.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/registrations") |
| [permissions](#permissions)     | `array`  | Optional | cannot be null | [Header](header-properties-permissions.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/permissions")     |
| [version](#version)             | `string` | Required | cannot be null | [Header](header-properties-version.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/version")             |
| [versionDate](#versiondate)     | `string` | Required | cannot be null | [Header](header-properties-versiondate.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/versionDate")     |

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

## registrations

Signing authorities agent is registered with

`registrations`

*   is optional

*   Type: `object[]` ([Signature](signature.md))

*   cannot be null

*   defined in: [Header](header-properties-registrations.md "https://hai.ai/schemas/header/v1/header-schema.json#/properties/registrations")

### registrations Type

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

Version id of

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
