# Untitled object in Tool Schema

```txt
https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                     |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [tool.schema.json\*](../../schemas/components/tool/v1/tool.schema.json "open original schema") |

## items Type

`object` ([Details](tool-items.md))

# items Properties

| Property                                  | Type      | Required | Nullable       | Defined by                                                                                                                                            |
| :---------------------------------------- | :-------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------- |
| [url](#url)                               | `string`  | Required | cannot be null | [Tool](tool-items-properties-url.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/url")                               |
| [responseRequired](#responserequired)     | `boolean` | Optional | cannot be null | [Tool](tool-items-properties-responserequired.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/responseRequired")     |
| [reseponseTimeout](#reseponsetimeout)     | `integer` | Optional | cannot be null | [Tool](tool-items-properties-reseponsetimeout.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/reseponseTimeout")     |
| [retryTimes](#retrytimes)                 | `integer` | Optional | cannot be null | [Tool](tool-items-properties-retrytimes.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/retryTimes")                 |
| [pricingDescription](#pricingdescription) | `integer` | Optional | cannot be null | [Tool](tool-items-properties-pricingdescription.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/pricingDescription") |
| [function](#function)                     | `object`  | Required | cannot be null | [Tool](tool-items-properties-function.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function")                     |

## url

endpoint of the tool

`url`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Tool](tool-items-properties-url.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/url")

### url Type

`string`

### url Constraints

**URI**: the string must be a URI, according to [RFC 3986](https://tools.ietf.org/html/rfc3986 "check the specification")

## responseRequired

Will the tool require waiting for a response. Default true.

`responseRequired`

*   is optional

*   Type: `boolean`

*   cannot be null

*   defined in: [Tool](tool-items-properties-responserequired.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/responseRequired")

### responseRequired Type

`boolean`

## reseponseTimeout

How long to wait for a response.

`reseponseTimeout`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Tool](tool-items-properties-reseponsetimeout.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/reseponseTimeout")

### reseponseTimeout Type

`integer`

## retryTimes

How many times to retry on failure.

`retryTimes`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Tool](tool-items-properties-retrytimes.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/retryTimes")

### retryTimes Type

`integer`

## pricingDescription

Is the function expensive, not expensive?

`pricingDescription`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Tool](tool-items-properties-pricingdescription.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/pricingDescription")

### pricingDescription Type

`integer`

## function



`function`

*   is required

*   Type: `object` ([Details](tool-items-properties-function.md))

*   cannot be null

*   defined in: [Tool](tool-items-properties-function.md "https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function")

### function Type

`object` ([Details](tool-items-properties-function.md))
