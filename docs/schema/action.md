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

| Property                                                    | Type      | Required | Nullable       | Defined by                                                                                                                                                          |
| :---------------------------------------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [name](#name)                                               | `string`  | Required | cannot be null | [Action](action-properties-name.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/name")                                               |
| [description](#description)                                 | `string`  | Required | cannot be null | [Action](action-properties-description.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/description")                                 |
| [tools](#tools)                                             | `array`   | Optional | cannot be null | [Action](action-properties-tools.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/tools")                                             |
| [cost](#cost)                                               | `object`  | Optional | cannot be null | [Action](eval-properties-quantifications-unit.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/cost")                                     |
| [duration](#duration)                                       | `object`  | Optional | cannot be null | [Action](eval-properties-quantifications-unit.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/duration")                                 |
| [completionAgreementRequired](#completionagreementrequired) | `boolean` | Optional | cannot be null | [Action](action-properties-completionagreementrequired.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/completionAgreementRequired") |

## name



`name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-name.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/name")

### name Type

`string`

## description

type of change that can happen

`description`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Action](action-properties-description.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/description")

### description Type

`string`

## tools

tools that can be utilized

`tools`

*   is optional

*   Type: `object[][]` ([Details](tool-items.md))

*   cannot be null

*   defined in: [Action](action-properties-tools.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/tools")

### tools Type

`object[][]` ([Details](tool-items.md))

## cost

Labels and quantitative values.

`cost`

*   is optional

*   Type: `object` ([Unit](eval-properties-quantifications-unit.md))

*   cannot be null

*   defined in: [Action](eval-properties-quantifications-unit.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/cost")

### cost Type

`object` ([Unit](eval-properties-quantifications-unit.md))

## duration

Labels and quantitative values.

`duration`

*   is optional

*   Type: `object` ([Unit](eval-properties-quantifications-unit.md))

*   cannot be null

*   defined in: [Action](eval-properties-quantifications-unit.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/duration")

### duration Type

`object` ([Unit](eval-properties-quantifications-unit.md))

## completionAgreementRequired

Do agents need to agree this is completed for task to be.

`completionAgreementRequired`

*   is optional

*   Type: `boolean`

*   cannot be null

*   defined in: [Action](action-properties-completionagreementrequired.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/completionAgreementRequired")

### completionAgreementRequired Type

`boolean`
