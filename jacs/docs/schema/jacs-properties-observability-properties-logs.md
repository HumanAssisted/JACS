# Untitled object in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../schemas/jacs.config.schema.json "open original schema") |

## logs Type

`object` ([Details](jacs-properties-observability-properties-logs.md))

# logs Properties

| Property                    | Type      | Required | Nullable       | Defined by                                                                                                                                                                                          |
| :-------------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [enabled](#enabled)         | `boolean` | Required | cannot be null | [Config](jacs-properties-observability-properties-logs-properties-enabled.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/enabled")         |
| [level](#level)             | `string`  | Required | cannot be null | [Config](jacs-properties-observability-properties-logs-properties-level.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/level")             |
| [destination](#destination) | Merged    | Required | cannot be null | [Config](jacs-properties-observability-properties-logs-properties-destination.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination") |
| [headers](#headers)         | `object`  | Optional | cannot be null | [Config](jacs-properties-observability-properties-logs-properties-headers.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/headers")         |

## enabled



`enabled`

* is required

* Type: `boolean`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs-properties-enabled.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/enabled")

### enabled Type

`boolean`

## level



`level`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs-properties-level.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/level")

### level Type

`string`

### level Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value     | Explanation |
| :-------- | :---------- |
| `"trace"` |             |
| `"debug"` |             |
| `"info"`  |             |
| `"warn"`  |             |
| `"error"` |             |

## destination



`destination`

* is required

* Type: merged type ([Details](jacs-properties-observability-properties-logs-properties-destination.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs-properties-destination.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination")

### destination Type

merged type ([Details](jacs-properties-observability-properties-logs-properties-destination.md))

one (and only one) of

* [Untitled object in Config](jacs-properties-observability-properties-logs-properties-destination-oneof-0.md "check type definition")

* [Untitled object in Config](jacs-properties-observability-properties-logs-properties-destination-oneof-1.md "check type definition")

* [Untitled object in Config](jacs-properties-observability-properties-logs-properties-destination-oneof-2.md "check type definition")

* [Untitled object in Config](jacs-properties-observability-properties-logs-properties-destination-oneof-3.md "check type definition")

## headers



`headers`

* is optional

* Type: `object` ([Details](jacs-properties-observability-properties-logs-properties-headers.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs-properties-headers.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/headers")

### headers Type

`object` ([Details](jacs-properties-observability-properties-logs-properties-headers.md))
