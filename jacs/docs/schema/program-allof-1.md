# Untitled undefined type in Program Schema

```txt
https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                   |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [program.schema.json\*](../../schemas/program/v1/program.schema.json "open original schema") |

## 1 Type

unknown

# 1 Properties

| Property                                    | Type     | Required | Nullable       | Defined by                                                                                                                                                 |
| :------------------------------------------ | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [planningSignature](#planningsignature)     | `object` | Optional | cannot be null | [Program](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/planningSignature")   |
| [safetySignature](#safetysignature)         | `object` | Optional | cannot be null | [Program](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/safetySignature")     |
| [evaluationSignature](#evaluationsignature) | `object` | Optional | cannot be null | [Program](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/evaluationSignature") |
| [taskID](#taskid)                           | `string` | Required | cannot be null | [Program](program-allof-1-properties-taskid.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/taskID")                           |
| [activeNodeIDs](#activenodeids)             | `array`  | Optional | cannot be null | [Program](program-allof-1-properties-activenodeids.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/activeNodeIDs")             |
| [datetime](#datetime)                       | `string` | Optional | cannot be null | [Program](program-allof-1-properties-datetime.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/datetime")                       |
| [requirements](#requirements)               | `string` | Required | cannot be null | [Program](program-allof-1-properties-requirements.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/requirements")               |
| [changes](#changes)                         | `array`  | Optional | cannot be null | [Program](program-allof-1-properties-changes.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/changes")                         |
| [nodes](#nodes)                             | `array`  | Required | cannot be null | [Program](program-allof-1-properties-nodes.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/nodes")                             |

## planningSignature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`planningSignature`

* is optional

* Type: `object` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [Program](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/planningSignature")

### planningSignature Type

`object` ([Signature](header-properties-signature-1.md))

## safetySignature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`safetySignature`

* is optional

* Type: `object` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [Program](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/safetySignature")

### safetySignature Type

`object` ([Signature](header-properties-signature-1.md))

## evaluationSignature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`evaluationSignature`

* is optional

* Type: `object` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [Program](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/evaluationSignature")

### evaluationSignature Type

`object` ([Signature](header-properties-signature-1.md))

## taskID

task being processed, a description can be found there.

`taskID`

* is required

* Type: `string`

* cannot be null

* defined in: [Program](program-allof-1-properties-taskid.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/taskID")

### taskID Type

`string`

### taskID Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## activeNodeIDs

task being processed, a description can be found there.

`activeNodeIDs`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Program](program-allof-1-properties-activenodeids.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/activeNodeIDs")

### activeNodeIDs Type

`string[]`

## datetime

Date of evaluation

`datetime`

* is optional

* Type: `string`

* cannot be null

* defined in: [Program](program-allof-1-properties-datetime.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/datetime")

### datetime Type

`string`

### datetime Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## requirements

What are the goals for the program

`requirements`

* is required

* Type: `string`

* cannot be null

* defined in: [Program](program-allof-1-properties-requirements.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/requirements")

### requirements Type

`string`

## changes

What changes were made to the plan along the way and why.

`changes`

* is optional

* Type: `string[]`

* cannot be null

* defined in: [Program](program-allof-1-properties-changes.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/changes")

### changes Type

`string[]`

## nodes

list of evaluation units, informatio labels

`nodes`

* is required

* Type: `object[]` ([Node](program-allof-1-properties-nodes-node.md))

* cannot be null

* defined in: [Program](program-allof-1-properties-nodes.md "https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/nodes")

### nodes Type

`object[]` ([Node](program-allof-1-properties-nodes-node.md))
