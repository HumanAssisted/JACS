# Untitled object in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../schemas/jacs.config.schema.json "open original schema") |

## sampling Type

`object` ([Details](jacs-properties-observability-properties-tracing-properties-sampling.md))

# sampling Properties

| Property                       | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                                          |
| :----------------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [ratio](#ratio)                | `number`  | Optional | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-sampling-properties-ratio.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling/properties/ratio")               |
| [parent\_based](#parent_based) | `boolean` | Optional | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-sampling-properties-parent_based.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling/properties/parent_based") |
| [rate\_limit](#rate_limit)     | `integer` | Optional | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-sampling-properties-rate_limit.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling/properties/rate_limit")     |

## ratio



`ratio`

* is optional

* Type: `number`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-sampling-properties-ratio.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling/properties/ratio")

### ratio Type

`number`

### ratio Constraints

**maximum**: the value of this number must smaller than or equal to: `1`

**minimum**: the value of this number must greater than or equal to: `0`

## parent\_based



`parent_based`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-sampling-properties-parent_based.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling/properties/parent_based")

### parent\_based Type

`boolean`

## rate\_limit



`rate_limit`

* is optional

* Type: `integer`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-sampling-properties-rate_limit.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling/properties/rate_limit")

### rate\_limit Type

`integer`

### rate\_limit Constraints

**minimum**: the value of this number must greater than or equal to: `1`
