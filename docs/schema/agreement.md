# agreement Schema

```txt
https://hai.ai/schemas/components/agreement/v1/agreement.schema.json
```

A set of required signatures signifying an agreement.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                  |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [agreement.schema.json](../../schemas/components/agreement/v1/agreement.schema.json "open original schema") |

## agreement Type

`object` ([agreement](agreement.md))

# agreement Properties

| Property                  | Type    | Required | Nullable       | Defined by                                                                                                                                    |
| :------------------------ | :------ | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------- |
| [signatures](#signatures) | `array` | Optional | cannot be null | [agreement](agreement-properties-signatures.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures") |
| [agentIDs](#agentids)     | `array` | Required | cannot be null | [agreement](agreement-properties-agentids.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs")     |

## signatures

Signatures of agents

`signatures`

*   is optional

*   Type: `object[]` ([Signature](signature.md))

*   cannot be null

*   defined in: [agreement](agreement-properties-signatures.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures")

### signatures Type

`object[]` ([Signature](signature.md))

## agentIDs

The agents which are required in order to sign the document

`agentIDs`

*   is required

*   Type: `uuid[]`

*   cannot be null

*   defined in: [agreement](agreement-properties-agentids.md "https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs")

### agentIDs Type

`uuid[]`
