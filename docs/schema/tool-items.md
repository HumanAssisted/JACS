# Untitled object in Tool Schema

```txt
schemas/components/tool/v1/tool-schema.json#/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                           |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [tool.schema.json\*](../../https:/hai.ai/schemas/=./schemas/tool.schema.json "open original schema") |

## items Type

`object` ([Details](tool-items.md))

# items Properties

| Property              | Type     | Required | Nullable       | Defined by                                                                                                         |
| :-------------------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------- |
| [type](#type)         | `string` | Required | cannot be null | [Tool](tool-items-properties-type.md "schemas/components/tool/v1/tool-schema.json#/items/properties/type")         |
| [url](#url)           | `string` | Required | cannot be null | [Tool](tool-items-properties-url.md "schemas/components/tool/v1/tool-schema.json#/items/properties/url")           |
| [function](#function) | `object` | Required | cannot be null | [Tool](tool-items-properties-function.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function") |

## type



`type`

* is required

* Type: `string`

* cannot be null

* defined in: [Tool](tool-items-properties-type.md "schemas/components/tool/v1/tool-schema.json#/items/properties/type")

### type Type

`string`

### type Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"function"` |             |

## url

endpoint of the tool

`url`

* is required

* Type: `string`

* cannot be null

* defined in: [Tool](tool-items-properties-url.md "schemas/components/tool/v1/tool-schema.json#/items/properties/url")

### url Type

`string`

### url Constraints

**URI**: the string must be a URI, according to [RFC 3986](https://tools.ietf.org/html/rfc3986 "check the specification")

## function



`function`

* is required

* Type: `object` ([Details](tool-items-properties-function.md))

* cannot be null

* defined in: [Tool](tool-items-properties-function.md "schemas/components/tool/v1/tool-schema.json#/items/properties/function")

### function Type

`object` ([Details](tool-items-properties-function.md))
