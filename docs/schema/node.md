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

| Property                              | Type     | Required | Nullable       | Defined by                                                                                                                            |
| :------------------------------------ | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| [id](#id)                             | `string` | Required | cannot be null | [Node](node-properties-id.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/id")                                        |
| [programID](#programid)               | `string` | Optional | cannot be null | [Node](node-properties-programid.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/programID")                          |
| [programVersion](#programversion)     | `string` | Optional | cannot be null | [Node](node-properties-programversion.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/programVersion")                |
| [signature](#signature)               | `object` | Optional | cannot be null | [Node](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signature") |
| [responsibleAgent](#responsibleagent) | `string` | Optional | cannot be null | [Node](node-properties-responsibleagent.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/responsibleAgent")            |
| [evaluatingAgent](#evaluatingagent)   | `string` | Optional | cannot be null | [Node](node-properties-evaluatingagent.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/evaluatingAgent")              |
| [LLMType](#llmtype)                   | `string` | Optional | cannot be null | [Node](node-properties-llmtype.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/LLMType")                              |
| [datetime](#datetime)                 | `string` | Required | cannot be null | [Node](node-properties-datetime.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/datetime")                            |

## id



`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-id.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/id")

### id Type

`string`

### id Constraints

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



`programVersion`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-programversion.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/programVersion")

### programVersion Type

`string`

### programVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## signature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`signature`

*   is optional

*   Type: `object` ([Signature](header-properties-signature-1.md))

*   cannot be null

*   defined in: [Node](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/signature")

### signature Type

`object` ([Signature](header-properties-signature-1.md))

## responsibleAgent

agent responsible for executing, implies tools and services

`responsibleAgent`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-responsibleagent.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/responsibleAgent")

### responsibleAgent Type

`string`

### responsibleAgent Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## evaluatingAgent

Agent doing the evaluation, implies tools and services

`evaluatingAgent`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Node](node-properties-evaluatingagent.md "https://hai.ai/schemas/node/v1/node.schema.json#/properties/evaluatingAgent")

### evaluatingAgent Type

`string`

### evaluatingAgent Constraints

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
