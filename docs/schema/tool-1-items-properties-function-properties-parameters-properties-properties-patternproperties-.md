# Untitled object in Tool Schema

```txt
schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                              |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [tool.schema.json\*](../../https:/hai.ai/schemas/=./schemas/components/tool/v1/tool.schema.json "open original schema") |

## ^.\*$ Type

`object` ([Details](tool-1-items-properties-function-properties-parameters-properties-properties-patternproperties-.md))

# ^.\*$ Properties

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                                           |
| :-------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [type](#type)               | `string` | Required | cannot be null | [Tool](tool-1-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-type.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/type")               |
| [enum](#enum)               | `array`  | Optional | cannot be null | [Tool](tool-1-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-enum.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/enum")               |
| [description](#description) | `string` | Optional | cannot be null | [Tool](tool-1-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-description.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/description") |

## type



`type`

* is required

* Type: `string`

* cannot be null

* defined in: [Tool](tool-1-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-type.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/type")

### type Type

`string`

### type Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value       | Explanation |
| :---------- | :---------- |
| `"string"`  |             |
| `"integer"` |             |
| `"boolean"` |             |

## enum



`enum`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Tool](tool-1-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-enum.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/enum")

### enum Type

`string[]`

## description



`description`

* is optional

* Type: `string`

* cannot be null

* defined in: [Tool](tool-1-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-description.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/description")

### description Type

`string`
