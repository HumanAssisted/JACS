# Untitled object in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/observability
```

Observability configuration for logging, metrics, and tracing

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../schemas/jacs.config.schema.json "open original schema") |

## observability Type

`object` ([Details](jacs-properties-observability.md))

# observability Properties

| Property            | Type     | Required | Nullable       | Defined by                                                                                                                                                  |
| :------------------ | :------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [logs](#logs)       | `object` | Required | cannot be null | [Config](jacs-properties-observability-properties-logs.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs")       |
| [metrics](#metrics) | `object` | Required | cannot be null | [Config](jacs-properties-observability-properties-metrics.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics") |
| [tracing](#tracing) | `object` | Optional | cannot be null | [Config](jacs-properties-observability-properties-tracing.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing") |

## logs



`logs`

* is required

* Type: `object` ([Details](jacs-properties-observability-properties-logs.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs")

### logs Type

`object` ([Details](jacs-properties-observability-properties-logs.md))

## metrics



`metrics`

* is required

* Type: `object` ([Details](jacs-properties-observability-properties-metrics.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-metrics.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics")

### metrics Type

`object` ([Details](jacs-properties-observability-properties-metrics.md))

## tracing



`tracing`

* is optional

* Type: `object` ([Details](jacs-properties-observability-properties-tracing.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing")

### tracing Type

`object` ([Details](jacs-properties-observability-properties-tracing.md))
