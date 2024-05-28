# Untitled object in Tool Schema

```txt
https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                     |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [tool.schema.json\*](../../schemas/components/tool/v1/tool.schema.json "open original schema") |

## function Type

`object` ([Details](tool-items-properties-function.md))

# function Properties

| Property                                  | Type     | Required | Nullable       | Defined by                                                                                                                                                                                    |
| :---------------------------------------- | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [name](#name)                             | `string` | Required | cannot be null | [Tool](tool-items-properties-function-properties-name.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/name")                             |
| [description](#description)               | `string` | Required | cannot be null | [Tool](tool-items-properties-function-properties-description.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/description")               |
| [descriptionDontUse](#descriptiondontuse) | `string` | Optional | cannot be null | [Tool](tool-items-properties-function-properties-descriptiondontuse.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/descriptionDontUse") |
| [descriptionDoUse](#descriptiondouse)     | `string` | Optional | cannot be null | [Tool](tool-items-properties-function-properties-descriptiondouse.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/descriptionDoUse")     |
| [parameters](#parameters)                 | `object` | Required | cannot be null | [Tool](tool-items-properties-function-properties-parameters.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters")                 |

## name

The name of the function which will be used to call it.

`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Tool](tool-items-properties-function-properties-name.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/name")

### name Type

`string`

## description

A description of what the function does.

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Tool](tool-items-properties-function-properties-description.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/description")

### description Type

`string`

## descriptionDontUse

A description  when the function should not be used.

`descriptionDontUse`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Tool](tool-items-properties-function-properties-descriptiondontuse.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/descriptionDontUse")

### descriptionDontUse Type

`string`

## descriptionDoUse

A description for when the function should be used

`descriptionDoUse`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Tool](tool-items-properties-function-properties-descriptiondouse.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/descriptionDoUse")

### descriptionDoUse Type

`string`

## parameters



`parameters`

*   is required

*   Type: `object` ([Details](tool-items-properties-function-properties-parameters.md))

*   cannot be null

*   defined in: [Tool](tool-items-properties-function-properties-parameters.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters")

### parameters Type

`object` ([Details](tool-items-properties-function-properties-parameters.md))
