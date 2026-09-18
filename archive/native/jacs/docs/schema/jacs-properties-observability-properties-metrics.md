# Untitled object in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../schemas/jacs.config.schema.json "open original schema") |

## metrics Type

`object` ([Details](jacs-properties-observability-properties-metrics.md))

# metrics Properties

| Property                                              | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                        |
| :---------------------------------------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [enabled](#enabled)                                   | `boolean` | Required | cannot be null | [Config](jacs-properties-observability-properties-metrics-properties-enabled.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/enabled")                                 |
| [destination](#destination)                           | Merged    | Required | cannot be null | [Config](jacs-properties-observability-properties-metrics-properties-destination.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/destination")                         |
| [export\_interval\_seconds](#export_interval_seconds) | `integer` | Optional | cannot be null | [Config](jacs-properties-observability-properties-metrics-properties-export_interval_seconds.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/export_interval_seconds") |
| [headers](#headers)                                   | `object`  | Optional | cannot be null | [Config](jacs-properties-observability-properties-metrics-properties-headers.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/headers")                                 |

## enabled



`enabled`

* is required

* Type: `boolean`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-metrics-properties-enabled.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/enabled")

### enabled Type

`boolean`

## destination



`destination`

* is required

* Type: merged type ([Details](jacs-properties-observability-properties-metrics-properties-destination.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-metrics-properties-destination.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/destination")

### destination Type

merged type ([Details](jacs-properties-observability-properties-metrics-properties-destination.md))

one (and only one) of

* [Untitled object in Config](jacs-properties-observability-properties-metrics-properties-destination-oneof-0.md "check type definition")

* [Untitled object in Config](jacs-properties-observability-properties-metrics-properties-destination-oneof-1.md "check type definition")

* [Untitled object in Config](jacs-properties-observability-properties-metrics-properties-destination-oneof-2.md "check type definition")

* [Untitled object in Config](jacs-properties-observability-properties-metrics-properties-destination-oneof-3.md "check type definition")

## export\_interval\_seconds



`export_interval_seconds`

* is optional

* Type: `integer`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-metrics-properties-export_interval_seconds.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/export_interval_seconds")

### export\_interval\_seconds Type

`integer`

### export\_interval\_seconds Constraints

**minimum**: the value of this number must greater than or equal to: `1`

## headers



`headers`

* is optional

* Type: `object` ([Details](jacs-properties-observability-properties-metrics-properties-headers.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-metrics-properties-headers.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/headers")

### headers Type

`object` ([Details](jacs-properties-observability-properties-metrics-properties-headers.md))
