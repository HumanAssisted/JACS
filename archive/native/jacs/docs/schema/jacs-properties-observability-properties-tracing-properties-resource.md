# Untitled object in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../schemas/jacs.config.schema.json "open original schema") |

## resource Type

`object` ([Details](jacs-properties-observability-properties-tracing-properties-resource.md))

# resource Properties

| Property                             | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                |
| :----------------------------------- | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [service\_name](#service_name)       | `string` | Required | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-resource-properties-service_name.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource/properties/service_name")       |
| [service\_version](#service_version) | `string` | Optional | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-resource-properties-service_version.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource/properties/service_version") |
| [environment](#environment)          | `string` | Optional | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-resource-properties-environment.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource/properties/environment")         |
| [attributes](#attributes)            | `object` | Optional | cannot be null | [Config](jacs-properties-observability-properties-tracing-properties-resource-properties-attributes.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource/properties/attributes")           |

## service\_name



`service_name`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-resource-properties-service_name.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource/properties/service_name")

### service\_name Type

`string`

## service\_version



`service_version`

* is optional

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-resource-properties-service_version.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource/properties/service_version")

### service\_version Type

`string`

## environment



`environment`

* is optional

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-resource-properties-environment.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource/properties/environment")

### environment Type

`string`

## attributes



`attributes`

* is optional

* Type: `object` ([Details](jacs-properties-observability-properties-tracing-properties-resource-properties-attributes.md))

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-tracing-properties-resource-properties-attributes.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource/properties/attributes")

### attributes Type

`object` ([Details](jacs-properties-observability-properties-tracing-properties-resource-properties-attributes.md))
