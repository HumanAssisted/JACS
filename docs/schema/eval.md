# Evaluation Schema

```txt
https://hai.ai/schemas/eval/v1/eval.schema.json
```

A signed, immutable message evaluation an agent's performance on a task

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [eval.schema.json](../../schemas/eval/v1/eval.schema.json "open original schema") |

## Evaluation Type

`object` ([Evaluation](eval.md))

# Evaluation Properties

| Property                                  | Type     | Required | Nullable       | Defined by                                                                                                                                  |
| :---------------------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| [id](#id)                                 | `string` | Required | cannot be null | [Evaluation](eval-properties-id.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/id")                                        |
| [signature](#signature)                   | `object` | Optional | cannot be null | [Evaluation](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signature") |
| [taskID](#taskid)                         | `string` | Required | cannot be null | [Evaluation](eval-properties-taskid.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/taskID")                                |
| [datetime](#datetime)                     | `string` | Required | cannot be null | [Evaluation](eval-properties-datetime.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/datetime")                            |
| [qualityDescription](#qualitydescription) | `string` | Optional | cannot be null | [Evaluation](eval-properties-qualitydescription.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/qualityDescription")        |
| [quantifications](#quantifications)       | `array`  | Optional | cannot be null | [Evaluation](eval-properties-quantifications.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/quantifications")              |

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

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`signature`

* is optional

* Type: `object` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [Evaluation](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signature")

### signature Type

`object` ([Signature](header-properties-signature-1.md))

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

* Type: `object[]` ([Unit](eval-properties-quantifications-unit.md))

* cannot be null

* defined in: [Evaluation](eval-properties-quantifications.md "https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/quantifications")

### quantifications Type

`object[]` ([Unit](eval-properties-quantifications-unit.md))
