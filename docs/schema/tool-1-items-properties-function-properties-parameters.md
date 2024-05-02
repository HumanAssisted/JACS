# Untitled object in Tool Schema

```txt
schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                              |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [tool.schema.json\*](../../https:/hai.ai/schemas/=./schemas/components/tool/v1/tool.schema.json "open original schema") |

## parameters Type

`object` ([Details](tool-1-items-properties-function-properties-parameters.md))

# parameters Properties

| Property                  | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                   |
| :------------------------ | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [type](#type)             | `string` | Required | cannot be null | [Tool](tool-1-items-properties-function-properties-parameters-properties-type.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/type")             |
| [properties](#properties) | `object` | Required | cannot be null | [Tool](tool-1-items-properties-function-properties-parameters-properties-properties.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties") |
| [required](#required)     | `array`  | Required | cannot be null | [Tool](tool-1-items-properties-function-properties-parameters-properties-required.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/required")     |

## type



`type`

* is required

* Type: `string`

* cannot be null

* defined in: [Tool](tool-1-items-properties-function-properties-parameters-properties-type.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/type")

### type Type

`string`

### type Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value      | Explanation |
| :--------- | :---------- |
| `"object"` |             |

## properties



`properties`

* is required

* Type: `object` ([Details](tool-1-items-properties-function-properties-parameters-properties-properties.md))

* cannot be null

* defined in: [Tool](tool-1-items-properties-function-properties-parameters-properties-properties.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties")

### properties Type

`object` ([Details](tool-1-items-properties-function-properties-parameters-properties-properties.md))

## required



`required`

* is required

* Type: `string[]`

* cannot be null

* defined in: [Tool](tool-1-items-properties-function-properties-parameters-properties-required.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/required")

### required Type

`string[]`