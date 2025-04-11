# Node Schema

```txt
https://hai.ai/schemas/node/v1/node.schema.json
```

A a node in a finite state machine. Stateless, a class to be used to instantiate a node.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [node.schema.json](../../schemas/node/v1/node.schema.json "open original schema") |

## Node Type

`object` ([Node](node.md))

# Node Properties

| Property                                                          | Type      | Required | Nullable       | Defined by                                                                                                                                             |
| :---------------------------------------------------------------- | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| [nodeID](#nodeid)                                                 | `string`  | Optional | cannot be null | [Node](node-properties-nodeid.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/nodeID")                                                 |
| [programID](#programid)                                           | `string`  | Optional | cannot be null | [Node](node-properties-programid.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/programID")                                           |
| [programVersion](#programversion)                                 | `string`  | Optional | cannot be null | [Node](node-properties-programversion.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/programVersion")                                 |
| [serviceID](#serviceid)                                           | `string`  | Optional | cannot be null | [Node](node-properties-serviceid.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/serviceID")                                           |
| [serviceVersion](#serviceversion)                                 | `string`  | Optional | cannot be null | [Node](node-properties-serviceversion.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/serviceVersion")                                 |
| [completed](#completed)                                           | `boolean` | Optional | cannot be null | [Node](node-properties-completed.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completed")                                           |
| [completedAt](#completedat)                                       | `string`  | Optional | cannot be null | [Node](node-properties-completedat.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completedAt")                                       |
| [tool](#tool)                                                     | `array`   | Optional | cannot be null | [Node](action-properties-tools-tool.md "https://hai.ai/schemas/components/tool/v1/tool.schema.json#/properties/tool")                                  |
| [preToolPrompt](#pretoolprompt)                                   | `string`  | Optional | cannot be null | [Node](node-properties-pretoolprompt.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/preToolPrompt")                                   |
| [postToolPrompt](#posttoolprompt)                                 | `string`  | Optional | cannot be null | [Node](node-properties-posttoolprompt.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/postToolPrompt")                                 |
| [estimatedCost](#estimatedcost)                                   | `integer` | Optional | cannot be null | [Node](node-properties-estimatedcost.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/estimatedCost")                                   |
| [estimatedTime](#estimatedtime)                                   | `integer` | Optional | cannot be null | [Node](node-properties-estimatedtime.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/estimatedTime")                                   |
| [cost](#cost)                                                     | `integer` | Optional | cannot be null | [Node](node-properties-cost.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/cost")                                                     |
| [time](#time)                                                     | `integer` | Optional | cannot be null | [Node](node-properties-time.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/time")                                                     |
| [runAt](#runat)                                                   | `string`  | Optional | cannot be null | [Node](node-properties-runat.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/runAt")                                                   |
| [humanEvaluatorRequired](#humanevaluatorrequired)                 | `boolean` | Optional | cannot be null | [Node](node-properties-humanevaluatorrequired.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/humanEvaluatorRequired")                 |
| [completedSuccess](#completedsuccess)                             | `boolean` | Optional | cannot be null | [Node](node-properties-completedsuccess.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completedSuccess")                             |
| [completedEvaluation](#completedevaluation)                       | `integer` | Optional | cannot be null | [Node](node-properties-completedevaluation.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completedEvaluation")                       |
| [completedEvaluationDescription](#completedevaluationdescription) | `string`  | Optional | cannot be null | [Node](node-properties-completedevaluationdescription.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completedEvaluationDescription") |
| [signature](#signature)                                           | `object`  | Optional | cannot be null | [Node](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signature")                  |
| [executingAgent](#executingagent)                                 | `string`  | Optional | cannot be null | [Node](node-properties-executingagent.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/executingAgent")                                 |
| [responsibleAgent](#responsibleagent)                             | `string`  | Optional | cannot be null | [Node](node-properties-responsibleagent.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/responsibleAgent")                             |
| [LLMType](#llmtype)                                               | `string`  | Optional | cannot be null | [Node](node-properties-llmtype.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/LLMType")                                               |
| [datetime](#datetime)                                             | `string`  | Required | cannot be null | [Node](node-properties-datetime.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/datetime")                                             |

## nodeID



`nodeID`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-nodeid.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/nodeID")

### nodeID Type

`string`

### nodeID Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## programID

what program it belongs to

`programID`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-programid.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/programID")

### programID Type

`string`

### programID Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## programVersion

what program version created

`programVersion`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-programversion.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/programVersion")

### programVersion Type

`string`

### programVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## serviceID

what service is being used

`serviceID`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-serviceid.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/serviceID")

### serviceID Type

`string`

### serviceID Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## serviceVersion

what service version was  first used

`serviceVersion`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-serviceversion.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/serviceVersion")

### serviceVersion Type

`string`

### serviceVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## completed

is the task completed

`completed`

*   is optional

*   Type: `boolean`

*   cannot be null

*   defined in: [Node](node-properties-completed.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completed")

### completed Type

`boolean`

## completedAt

datetime of completion

`completedAt`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-completedat.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completedAt")

### completedAt Type

`string`

### completedAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## tool

OpenAI function calling definitions <https://platform.openai.com/docs/assistants/tools/function-calling/quickstart>. Has an additional field of URL

`tool`

*   is optional

*   Type: `object[]` ([Details](tool-items.md))

*   cannot be null

*   defined in: [Node](action-properties-tools-tool.md "https://hai.ai/schemas/components/tool/v1/tool.schema.json#/properties/tool")

### tool Type

`object[]` ([Details](tool-items.md))

## preToolPrompt

prompt to run before tool is run

`preToolPrompt`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-pretoolprompt.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/preToolPrompt")

### preToolPrompt Type

`string`

## postToolPrompt

prompt to run after tool is run

`postToolPrompt`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-posttoolprompt.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/postToolPrompt")

### postToolPrompt Type

`string`

## estimatedCost

estimated cost in dollars

`estimatedCost`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Node](node-properties-estimatedcost.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/estimatedCost")

### estimatedCost Type

`integer`

## estimatedTime

estimated time in seconds

`estimatedTime`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Node](node-properties-estimatedtime.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/estimatedTime")

### estimatedTime Type

`integer`

## cost

actual cost in dollars

`cost`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Node](node-properties-cost.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/cost")

### cost Type

`integer`

## time

actual time in seconds

`time`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Node](node-properties-time.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/time")

### time Type

`integer`

## runAt

Run in the future - job queue

`runAt`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-runat.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/runAt")

### runAt Type

`string`

### runAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## humanEvaluatorRequired

Human Evaluator is required

`humanEvaluatorRequired`

*   is optional

*   Type: `boolean`

*   cannot be null

*   defined in: [Node](node-properties-humanevaluatorrequired.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/humanEvaluatorRequired")

### humanEvaluatorRequired Type

`boolean`

## completedSuccess

A binary represenation of if the task completed successfully according to evaluation

`completedSuccess`

*   is optional

*   Type: `boolean`

*   cannot be null

*   defined in: [Node](node-properties-completedsuccess.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completedSuccess")

### completedSuccess Type

`boolean`

## completedEvaluation

A floating scale evaluation of level of success

`completedEvaluation`

*   is optional

*   Type: `integer`

*   cannot be null

*   defined in: [Node](node-properties-completedevaluation.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completedEvaluation")

### completedEvaluation Type

`integer`

## completedEvaluationDescription

A qualitative description of the evaluation.

`completedEvaluationDescription`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-completedevaluationdescription.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/completedEvaluationDescription")

### completedEvaluationDescription Type

`string`

## signature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`signature`

*   is optional

*   Type: `object` ([Signature](header-properties-signature-1.md))

*   cannot be null

*   defined in: [Node](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signature")

### signature Type

`object` ([Signature](header-properties-signature-1.md))

## executingAgent

agent responsible for executing, implies tools and services

`executingAgent`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-executingagent.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/executingAgent")

### executingAgent Type

`string`

### executingAgent Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## responsibleAgent

Agent doing the evaluation, implies tools and services

`responsibleAgent`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-responsibleagent.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/responsibleAgent")

### responsibleAgent Type

`string`

### responsibleAgent Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## LLMType

Which LLM to use when loaded prompts are provided.

`LLMType`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-llmtype.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/LLMType")

### LLMType Type

`string`

## datetime

Date of evaluation

`datetime`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-datetime.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/datetime")

### datetime Type

`string`

### datetime Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")
