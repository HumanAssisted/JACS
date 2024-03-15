# Agent Schema

```txt
https://hai.ai/schemas/document/v1/document-schema.json
```

Base schema for all JACS documents.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                    |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [document.schema.json](../../schemas/document/v1/document.schema.json "open original schema") |

## Agent Type

`object` ([Agent](document.md))

# Agent Properties

| Property                              | Type     | Required | Nullable       | Defined by                                                                                                                            |
| :------------------------------------ | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| [id](#id)                             | `string` | Required | cannot be null | [Agent](document-properties-id.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/id")                           |
| [resourcetype](#resourcetype)         | `string` | Required | cannot be null | [Agent](document-properties-resourcetype.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/resourcetype")       |
| [linked\_data\_uri](#linked_data_uri) | `string` | Optional | cannot be null | [Agent](document-properties-linked_data_uri.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/linked_data_uri") |
| [version](#version)                   | `string` | Optional | cannot be null | [Agent](document-properties-version.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/version")                 |
| [version\_date](#version_date)        | `string` | Optional | cannot be null | [Agent](document-properties-version_date.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/version_date")       |
| [registration](#registration)         | `object` | Optional | cannot be null | [Agent](signature.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/registration")                            |
| [creator](#creator)                   | `object` | Optional | cannot be null | [Agent](signature.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/creator")                                 |
| [name](#name)                         | `string` | Required | cannot be null | [Agent](document-properties-name.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/name")                       |
| [description](#description)           | `string` | Required | cannot be null | [Agent](document-properties-description.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/description")         |
| [capabilities](#capabilities)         | `array`  | Required | cannot be null | [Agent](document-properties-capabilities.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/capabilities")       |
| [modifications](#modifications)       | `array`  | Required | cannot be null | [Agent](document-properties-modifications.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/modifications")     |
| [quantifications](#quantifications)   | `array`  | Optional | cannot be null | [Agent](document-properties-quantifications.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/quantifications") |

## id

Resource GUID

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](document-properties-id.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/id")

### id Type

`string`

### id Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## resourcetype

general type of resource

`resourcetype`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](document-properties-resourcetype.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/resourcetype")

### resourcetype Type

`string`

### resourcetype Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value           | Explanation |
| :-------------- | :---------- |
| `"agent"`       |             |
| `"time"`        |             |
| `"physical"`    |             |
| `"monetary"`    |             |
| `"information"` |             |

## linked\_data\_uri

URI of Semantic Web or JSON-LD type

`linked_data_uri`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](document-properties-linked_data_uri.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/linked_data_uri")

### linked\_data\_uri Type

`string`

## version

Semantic Version number of the resource

`version`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](document-properties-version.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/version")

### version Type

`string`

## version\_date

Date

`version_date`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](document-properties-version_date.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/version_date")

### version\_date Type

`string`

### version\_date Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## registration

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`registration`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Agent](signature.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/registration")

### registration Type

`object` ([Signature](signature.md))

## creator

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`creator`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Agent](signature.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/creator")

### creator Type

`object` ([Signature](signature.md))

## name

Name of the agent, unique per registrar

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](document-properties-name.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/name")

### name Type

`string`

## description

General description

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](document-properties-description.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/description")

### description Type

`string`

## capabilities



`capabilities`

*   is required

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Agent](document-properties-capabilities.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/capabilities")

### capabilities Type

`object[]` ([Action](action.md))

## modifications



`modifications`

*   is required

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Agent](document-properties-modifications.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/modifications")

### modifications Type

`object[]` ([Action](action.md))

## quantifications

array of quantitative units defining the resource

`quantifications`

*   is optional

*   Type: an array where each item follows the corresponding schema in the following list:

    1.  [Untitled number in Agent](document-properties-quantifications-items-items-0.md "check type definition")

    2.  [Unit](unit.md "check type definition")

*   cannot be null

*   defined in: [Agent](document-properties-quantifications.md "https://hai.ai/schemas/document/v1/document-schema.json#/properties/quantifications")

### quantifications Type

an array where each item follows the corresponding schema in the following list:

1.  [Untitled number in Agent](document-properties-quantifications-items-items-0.md "check type definition")

2.  [Unit](unit.md "check type definition")