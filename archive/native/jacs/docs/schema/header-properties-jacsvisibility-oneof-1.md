# Untitled object in Header Schema

```txt
https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVisibility/oneOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [header.schema.json\*](../../schemas/header/v1/header.schema.json "open original schema") |

## 1 Type

`object` ([Details](header-properties-jacsvisibility-oneof-1.md))

# 1 Properties

| Property                  | Type    | Required | Nullable       | Defined by                                                                                                                                                                                 |
| :------------------------ | :------ | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [restricted](#restricted) | `array` | Required | cannot be null | [Header](header-properties-jacsvisibility-oneof-1-properties-restricted.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVisibility/oneOf/1/properties/restricted") |

## restricted

Agent IDs or roles that can access this document

`restricted`

* is required

* Type: `string[]`

* cannot be null

* defined in: [Header](header-properties-jacsvisibility-oneof-1-properties-restricted.md "https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVisibility/oneOf/1/properties/restricted")

### restricted Type

`string[]`

### restricted Constraints

**minimum number of items**: the minimum number of items for this array is: `1`
