# Untitled object in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../schemas/jacs.config.schema.json "open original schema") |

## tracing Type

`object` ([Details](jacs-properties-observability-properties-tracing.md))

# tracing Properties

| Property              | Type      | Required | Nullable       | Defined by                                                                                                                                                                                          |
| :-------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [enabled](#enabled)   | `boolean` | Required | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-enabled.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/enabled")   |
| [sampling](#sampling) | `object`  | Optional | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-sampling.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling") |
| [resource](#resource) | `object`  | Optional | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-resource.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource") |

## enabled



`enabled`

* is required

* Type: `boolean`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-enabled.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/enabled")

### enabled Type

`boolean`

## sampling



`sampling`

* is optional

* Type: `object` ([Details](jacs-properties-observability-properties-tracing-properties-sampling.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-sampling.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling")

### sampling Type

`object` ([Details](jacs-properties-observability-properties-tracing-properties-sampling.md))

## resource



`resource`

* is optional

* Type: `object` ([Details](jacs-properties-observability-properties-tracing-properties-resource.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-resource.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource")

### resource Type

`object` ([Details](jacs-properties-observability-properties-tracing-properties-resource.md))
