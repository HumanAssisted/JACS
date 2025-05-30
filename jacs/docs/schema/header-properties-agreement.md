# agreement Schema

```txt
https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/jacsAgreement
```

A set of required signatures signifying an agreement.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [header.schema.json\*](../../schemas/header/v1/header.schema.json "open original schema") |

## jacsAgreement Type

`object` ([agreement](header-properties-agreement.md))

# jacsAgreement Properties

| Property                  | Type     | Required | Nullable       | Defined by                                                                                                                                    |
| :------------------------ | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------- |
| [signatures](#signatures) | `array`  | Optional | cannot be null | [agreement](agreement-properties-signatures.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures") |
| [agentIDs](#agentids)     | `array`  | Required | cannot be null | [agreement](agreement-properties-agentids.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs")     |
| [question](#question)     | `string` | Optional | cannot be null | [agreement](agreement-properties-question.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/question")     |
| [context](#context)       | `string` | Optional | cannot be null | [agreement](agreement-properties-context.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/context")       |

## signatures

Signatures of agents

`signatures`

* is optional

* Type: `object[]` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [agreement](agreement-properties-signatures.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures")

### signatures Type

`object[]` ([Signature](header-properties-signature-1.md))

## agentIDs

The agents which are required in order to sign the document

`agentIDs`

* is required

* Type: `string[]`

* cannot be null

* defined in: [agreement](agreement-properties-agentids.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs")

### agentIDs Type

`string[]`

## question

When prompting an agent, what are they agreeing to?

`question`

* is optional

* Type: `string`

* cannot be null

* defined in: [agreement](agreement-properties-question.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/question")

### question Type

`string`

## context

Context for the question?

`context`

* is optional

* Type: `string`

* cannot be null

* defined in: [agreement](agreement-properties-context.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/context")

### context Type

`string`
