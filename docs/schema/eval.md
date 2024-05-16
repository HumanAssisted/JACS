# Evaluation Schema

```txt
https://hai.ai/schemas/eval/v1/eval.schema.json
```

A signed, immutable message evaluation an agent's performance on a task

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                    |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [eval.schema.json](../../out/eval/v1/eval.schema.json "open original schema") |

## Evaluation Type

`object` ([Evaluation](eval.md))

# Evaluation Properties

| Property                                  | Type          | Required | Nullable       | Defined by                                                                                                                           |
| :---------------------------------------- | :------------ | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                                 | `string`      | Required | cannot be null | [Evaluation](eval-properties-id.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/id")                                 |
| [signature](#signature)                   | Not specified | Optional | cannot be null | [Evaluation](eval-properties-signature.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/signature")                   |
| [taskID](#taskid)                         | `string`      | Required | cannot be null | [Evaluation](eval-properties-taskid.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/taskID")                         |
| [datetime](#datetime)                     | `string`      | Required | cannot be null | [Evaluation](eval-properties-datetime.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/datetime")                     |
| [qualityDescription](#qualitydescription) | `string`      | Optional | cannot be null | [Evaluation](eval-properties-qualitydescription.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/qualityDescription") |
| [quantifications](#quantifications)       | `array`       | Optional | cannot be null | [Evaluation](eval-properties-quantifications.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/quantifications")       |

## id



`id`

* is required

* Type: `string`

* cannot be null

* defined in: [Evaluation](eval-properties-id.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/id")

### id Type

`string`

### id Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## signature

signing of evaluation by agent evaluating

`signature`

* is optional

* Type: unknown

* cannot be null

* defined in: [Evaluation](eval-properties-signature.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/signature")

### signature Type

unknown

## taskID

task being evaluated

`taskID`

* is required

* Type: `string`

* cannot be null

* defined in: [Evaluation](eval-properties-taskid.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/taskID")

### taskID Type

`string`

### taskID Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## datetime

Date of evaluation

`datetime`

* is required

* Type: `string`

* cannot be null

* defined in: [Evaluation](eval-properties-datetime.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/datetime")

### datetime Type

`string`

### datetime Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## qualityDescription

When prompting an agent, is there text provided with the agreement?

`qualityDescription`

* is optional

* Type: `string`

* cannot be null

* defined in: [Evaluation](eval-properties-qualitydescription.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/qualityDescription")

### qualityDescription Type

`string`

## quantifications

list of evaluation units, informatio labels

`quantifications`

* is optional

* Type: unknown\[]

* cannot be null

* defined in: [Evaluation](eval-properties-quantifications.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/quantifications")

### quantifications Type

unknown\[]
