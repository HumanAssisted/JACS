# Embedding Schema

```txt
https://hai.ai/schemas/components/embedding/v1/embedding.schema.json
```

Precomputed embedding of content of a document

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                  |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [embedding.schema.json](../../schemas/components/embedding/v1/embedding.schema.json "open original schema") |

## Embedding Type

`object` ([Embedding](embedding.md))

# Embedding Properties

| Property          | Type     | Required | Nullable       | Defined by                                                                                                                            |
| :---------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| [llm](#llm)       | `string` | Required | cannot be null | [Embedding](embedding-properties-llm.md "https://hai.ai/schemas/components/embedding/v1/embedding.schema.json#/properties/llm")       |
| [vector](#vector) | `array`  | Required | cannot be null | [Embedding](embedding-properties-vector.md "https://hai.ai/schemas/components/embedding/v1/embedding.schema.json#/properties/vector") |

## llm

Language model used to generate the embedding

`llm`

* is required

* Type: `string`

* cannot be null

* defined in: [Embedding](embedding-properties-llm.md "https://hai.ai/schemas/components/embedding/v1/embedding.schema.json#/properties/llm")

### llm Type

`string`

## vector

the vector, does not indicate datatype or width (e.g. f32 764)

`vector`

* is required

* Type: `number[]`

* cannot be null

* defined in: [Embedding](embedding-properties-vector.md "https://hai.ai/schemas/components/embedding/v1/embedding.schema.json#/properties/vector")

### vector Type

`number[]`
