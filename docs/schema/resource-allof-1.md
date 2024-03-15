# Untitled object in Agent Schema

```txt
https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [resource.schema.json\*](../../schemas/resource/v1/resource.schema.json "open original schema") |

## 1 Type

`object` ([Details](resource-allof-1.md))

# 1 Properties

| Property                              | Type     | Required | Nullable       | Defined by                                                                                                                                            |
| :------------------------------------ | :------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------- |
| [resourcetype](#resourcetype)         | `string` | Optional | cannot be null | [Agent](resource-allof-1-properties-resourcetype.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/resourcetype")       |
| [linked\_data\_uri](#linked_data_uri) | `string` | Optional | cannot be null | [Agent](resource-allof-1-properties-linked_data_uri.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/linked_data_uri") |
| [name](#name)                         | `string` | Optional | cannot be null | [Agent](resource-allof-1-properties-name.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/name")                       |
| [description](#description)           | `string` | Optional | cannot be null | [Agent](resource-allof-1-properties-description.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/description")         |
| [capabilities](#capabilities)         | `array`  | Optional | cannot be null | [Agent](resource-allof-1-properties-capabilities.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/capabilities")       |
| [modifications](#modifications)       | `array`  | Optional | cannot be null | [Agent](resource-allof-1-properties-modifications.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/modifications")     |
| [quantifications](#quantifications)   | `array`  | Optional | cannot be null | [Agent](resource-allof-1-properties-quantifications.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/quantifications") |

## resourcetype

general type of resource

`resourcetype`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-allof-1-properties-resourcetype.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/resourcetype")

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

*   defined in: [Agent](resource-allof-1-properties-linked_data_uri.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/linked_data_uri")

### linked\_data\_uri Type

`string`

## name

Name of the agent, unique per registrar

`name`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-allof-1-properties-name.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/name")

### name Type

`string`

## description

General description

`description`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](resource-allof-1-properties-description.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/description")

### description Type

`string`

## capabilities



`capabilities`

*   is optional

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Agent](resource-allof-1-properties-capabilities.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/capabilities")

### capabilities Type

`object[]` ([Action](action.md))

## modifications



`modifications`

*   is optional

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Agent](resource-allof-1-properties-modifications.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/modifications")

### modifications Type

`object[]` ([Action](action.md))

## quantifications

array of quantitative units defining the resource

`quantifications`

*   is optional

*   Type: an array where each item follows the corresponding schema in the following list:

    1.  [Untitled number in Agent](resource-allof-1-properties-quantifications-items-items-0.md "check type definition")

    2.  [Unit](unit.md "check type definition")

*   cannot be null

*   defined in: [Agent](resource-allof-1-properties-quantifications.md "https://hai.ai/schemas/resource/v1/resource-schema.json#/allOf/1/properties/quantifications")

### quantifications Type

an array where each item follows the corresponding schema in the following list:

1.  [Untitled number in Agent](resource-allof-1-properties-quantifications-items-items-0.md "check type definition")

2.  [Unit](unit.md "check type definition")
