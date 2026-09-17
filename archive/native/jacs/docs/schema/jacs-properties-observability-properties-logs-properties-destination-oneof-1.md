# Untitled object in Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [jacs.config.schema.json\*](../../schemas/jacs.config.schema.json "open original schema") |

## 1 Type

`object` ([Details](jacs-properties-observability-properties-logs-properties-destination-oneof-1.md))

# 1 Properties

| Property      | Type          | Required | Nullable       | Defined by                                                                                                                                                                                                                                          |
| :------------ | :------------ | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [type](#type) | Not specified | Required | cannot be null | [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-1-properties-type.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/1/properties/type") |
| [path](#path) | `string`      | Required | cannot be null | [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-1-properties-path.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/1/properties/path") |

## type



`type`

* is required

* Type: unknown

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-1-properties-type.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/1/properties/type")

### type Type

unknown

### type Constraints

**constant**: the value of this property must be equal to:

```json
"file"
```

## path



`path`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-observability-properties-logs-properties-destination-oneof-1-properties-path.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/1/properties/path")

### path Type

`string`
