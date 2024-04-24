# Action Schema

```txt
https://hai.ai/schemas/components/action/v1/action-schema.json
```

General actions definitions which can comprise a service. Distinct from function calling.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [action.schema.json](../../schemas/components/action/v1/action.schema.json "open original schema") |

## Action Type

`object` ([Action](action.md))

# Action Properties

| Property                | Type     | Required | Nullable       | Defined by                                                                                                                      |
| :---------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------ |
| [name](#name)           | `string` | Optional | cannot be null | [Action](action-properties-name.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/name")           |
| [operation](#operation) | `string` | Required | cannot be null | [Action](action-properties-operation.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/operation") |
| [tools](#tools)         | `array`  | Optional | cannot be null | [Action](action-properties-tools.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/tools")         |
| [units](#units)         | `array`  | Optional | cannot be null | [Action](action-properties-units.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/units")         |

## name



`name`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-name.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/name")

### name Type

`string`

## operation

type of change that can happen

`operation`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-operation.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/operation")

### operation Type

`string`

## tools

units that can be modified

`tools`

*   is optional

*   Type: `object[][]` ([Details](tool-items.md))

*   cannot be null

*   defined in: [Action](action-properties-tools.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/tools")

### tools Type

`object[][]` ([Details](tool-items.md))

## units

units that can be modified

`units`

*   is optional

*   Type: `object[]` ([Unit](unit.md))

*   cannot be null

*   defined in: [Action](action-properties-units.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/units")

### units Type

`object[]` ([Unit](unit.md))
