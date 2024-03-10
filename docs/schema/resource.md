# Agent Schema

```txt
https://hai.ai/schemas/resource/v1/resource-schema.json
```

General schema for stateful resources.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                    |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [resource.schema.json](../../schemas/resource/v1/resource.schema.json "open original schema") |

## Agent Type

`object` ([Agent](resource.md))

# Agent Properties

| Property                                           | Type     | Required | Nullable       | Defined by                                                                                                                                          |
| :------------------------------------------------- | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                                          | `string` | Required | cannot be null | [Agent](resource-properties-id.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/id")                                         |
| [resourcetype](#resourcetype)                      | `string` | Required | cannot be null | [Agent](resource-properties-resourcetype.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/resourcetype")                     |
| [linked\_data\_uri](#linked_data_uri)              | `string` | Optional | cannot be null | [Agent](resource-properties-linked_data_uri.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/linked_data_uri")               |
| [version](#version)                                | `string` | Optional | cannot be null | [Agent](resource-properties-version.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/version")                               |
| [version\_date](#version_date)                     | `string` | Optional | cannot be null | [Agent](resource-properties-version_date.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/version_date")                     |
| [registered\_with](#registered_with)               | `string` | Optional | cannot be null | [Agent](resource-properties-registered_with.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/registered_with")               |
| [registration\_signature](#registration_signature) | `string` | Optional | cannot be null | [Agent](resource-properties-registration_signature.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/registration_signature") |
| [registered\_date](#registered_date)               | `string` | Optional | cannot be null | [Agent](resource-properties-registered_date.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/registered_date")               |
| [name](#name)                                      | `string` | Required | cannot be null | [Agent](resource-properties-name.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/name")                                     |
| [description](#description)                        | `string` | Required | cannot be null | [Agent](resource-properties-description.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/description")                       |
| [capabilities](#capabilities)                      | `array`  | Required | cannot be null | [Agent](resource-properties-capabilities.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/capabilities")                     |
| [modifications](#modifications)                    | `array`  | Required | cannot be null | [Agent](resource-properties-modifications.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/modifications")                   |
| [quantifications](#quantifications)                | `array`  | Optional | cannot be null | [Agent](resource-properties-quantifications.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/quantifications")               |

## id

Resource GUID

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-properties-id.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/id")

### id Type

`string`

## resourcetype

general type of resource

`resourcetype`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-properties-resourcetype.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/resourcetype")

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

*   defined in: [Agent](resource-properties-linked_data_uri.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/linked_data_uri")

### linked\_data\_uri Type

`string`

## version

Semantic Version number of the resource

`version`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-properties-version.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/version")

### version Type

`string`

## version\_date

Date

`version_date`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-properties-version_date.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/version_date")

### version\_date Type

`string`

### version\_date Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## registered\_with

Organization

`registered_with`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-properties-registered_with.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/registered_with")

### registered\_with Type

`string`

## registration\_signature

Signature from registrar for verifying

`registration_signature`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-properties-registration_signature.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/registration_signature")

### registration\_signature Type

`string`

## registered\_date

date registred

`registered_date`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-properties-registered_date.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/registered_date")

### registered\_date Type

`string`

### registered\_date Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## name

Name of the agent, unique per registrar

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-properties-name.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/name")

### name Type

`string`

## description

General description

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-properties-description.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/description")

### description Type

`string`

## capabilities



`capabilities`

*   is required

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Agent](resource-properties-capabilities.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/capabilities")

### capabilities Type

`object[]` ([Action](action.md))

## modifications



`modifications`

*   is required

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Agent](resource-properties-modifications.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/modifications")

### modifications Type

`object[]` ([Action](action.md))

## quantifications

array of quantitative units defining the resource

`quantifications`

*   is optional

*   Type: an array where each item follows the corresponding schema in the following list:

    1.  [Untitled number in Agent](resource-properties-quantifications-items-items-0.md "check type definition")

    2.  [Agent](unit.md "check type definition")

*   cannot be null

*   defined in: [Agent](resource-properties-quantifications.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/properties/quantifications")

### quantifications Type

an array where each item follows the corresponding schema in the following list:

1.  [Untitled number in Agent](resource-properties-quantifications-items-items-0.md "check type definition")

2.  [Agent](unit.md "check type definition")
