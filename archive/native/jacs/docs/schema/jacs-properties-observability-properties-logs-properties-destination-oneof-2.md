# Untitled object in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/2
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../schemas/jacs.config.schema.json "open original schema") |

## 2 Type

`object` ([Details](jacs-properties-observability-properties-logs-properties-destination-oneof-2.md))

# 2 Properties

| Property              | Type          | Required | Nullable       | Defined by                                                                                                                                                                                                                                                  |
| :-------------------- | :------------ | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [type](#type)         | Not specified | Required | cannot be null | [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-2-properties-type.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/2/properties/type")         |
| [endpoint](#endpoint) | `string`      | Required | cannot be null | [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-2-properties-endpoint.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/2/properties/endpoint") |
| [headers](#headers)   | `object`      | Optional | cannot be null | [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-2-properties-headers.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/2/properties/headers")   |

## type



`type`

* is required

* Type: unknown

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-2-properties-type.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/2/properties/type")

### type Type

unknown

### type Constraints

**constant**: the value of this property must be equal to:

```json
"otlp"
```

## endpoint



`endpoint`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-2-properties-endpoint.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/2/properties/endpoint")

### endpoint Type

`string`

## headers



`headers`

* is optional

* Type: `object` ([Details](jacs-properties-observability-properties-logs-properties-destination-oneof-2-properties-headers.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-2-properties-headers.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/2/properties/headers")

### headers Type

`object` ([Details](jacs-properties-observability-properties-logs-properties-destination-oneof-2-properties-headers.md))
