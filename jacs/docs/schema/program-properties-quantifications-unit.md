# Unit Schema

```txt
https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/quantifications/items
```

Labels and quantitative values.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                   |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [program.schema.json\*](../../schemas/program/v1/program.schema.json "open original schema") |

## items Type

`object` ([Unit](program-properties-quantifications-unit.md))

# items Properties

| Property                    | Type      | Required | Nullable       | Defined by                                                                                                                  |
| :-------------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                   | `string`  | Required | cannot be null | [Unit](unit-properties-id.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/id")                   |
| [description](#description) | `string`  | Optional | cannot be null | [Unit](unit-properties-description.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/description") |
| [generalType](#generaltype) | `string`  | Optional | cannot be null | [Unit](unit-properties-generaltype.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/generalType") |
| [unitName](#unitname)       | `string`  | Required | cannot be null | [Unit](unit-properties-unitname.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/unitName")       |
| [quantity](#quantity)       | `integer` | Required | cannot be null | [Unit](unit-properties-quantity.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/quantity")       |
| [label](#label)             | `string`  | Required | cannot be null | [Unit](unit-properties-label.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/label")             |

## id



`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Unit](unit-properties-id.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/id")

### id Type

`string`

### id Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## description

reason this unit is present

`description`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Unit](unit-properties-description.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/description")

### description Type

`string`

## generalType

general type of resource

`generalType`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Unit](unit-properties-generaltype.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/generalType")

### generalType Type

`string`

### generalType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value           | Explanation |
| :-------------- | :---------- |
| `"agent"`       |             |
| `"time"`        |             |
| `"physical"`    |             |
| `"monetary"`    |             |
| `"information"` |             |

## unitName

pounds, square ft, dollars, hours, etc

`unitName`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Unit](unit-properties-unitname.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/unitName")

### unitName Type

`string`

## quantity

the amount

`quantity`

*   is required

*   Type: `integer`

*   cannot be null

*   defined in: [Unit](unit-properties-quantity.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/quantity")

### quantity Type

`integer`

## label

age, weight, net worth etc

`label`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Unit](unit-properties-label.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/label")

### label Type

`string`
