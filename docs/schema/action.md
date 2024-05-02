# Action Schema

```txt
https://hai.ai/schemas/components/action/v1/action-schema.json
```

General actions definitions which can comprise a service. Distinct from function calling.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                             |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [action.schema.json](../../https:/hai.ai/schemas/=./schemas/action.schema.json "open original schema") |

## Action Type

`object` ([Action](action.md))

# Action Properties

| Property                                                    | Type      | Required | Nullable       | Defined by                                                                                                                                                          |
| :---------------------------------------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [name](#name)                                               | `string`  | Required | cannot be null | [Action](action-properties-name.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/name")                                               |
| [description](#description)                                 | `string`  | Required | cannot be null | [Action](action-properties-description.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/description")                                 |
| [tools](#tools)                                             | `array`   | Optional | cannot be null | [Action](action-properties-tools.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/tools")                                             |
| [units](#units)                                             | `array`   | Optional | cannot be null | [Action](action-properties-units.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/units")                                             |
| [completionAgreementRequired](#completionagreementrequired) | `boolean` | Optional | cannot be null | [Action](action-properties-completionagreementrequired.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/completionAgreementRequired") |

## name



`name`

* is required

* Type: `string`

* cannot be null

* defined in: [Action](action-properties-name.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/name")

### name Type

`string`

## description

type of change that can happen

`description`

* is required

* Type: `string`

* cannot be null

* defined in: [Action](action-properties-description.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/description")

### description Type

`string`

## tools

tools that can be utilized

`tools`

* is optional

* Type: unknown\[]

* cannot be null

* defined in: [Action](action-properties-tools.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/tools")

### tools Type

unknown\[]

## units

units that can be modified

`units`

* is optional

* Type: `object[]` ([Unit](action-properties-units-unit.md))

* cannot be null

* defined in: [Action](action-properties-units.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/units")

### units Type

`object[]` ([Unit](action-properties-units-unit.md))

## completionAgreementRequired

Do agents need to agree this is completed for task to be.

`completionAgreementRequired`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [Action](action-properties-completionagreementrequired.md "https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/completionAgreementRequired")

### completionAgreementRequired Type

`boolean`
