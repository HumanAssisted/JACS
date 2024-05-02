# Unit Schema

```txt
https://hai.ai/schemas/components/unit/v1/unit.schema.json
```

Labels and quantitative values.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                   |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [unit.schema.json](../../schemas/components/unit/v1/unit.schema.json "open original schema") |

## Unit Type

`object` ([Unit](unit.md))

# Unit Properties

| Property                    | Type      | Required | Nullable       | Defined by                                                                                                                  |
| :-------------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------- |
| [description](#description) | `string`  | Optional | cannot be null | [Unit](unit-properties-description.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/description") |
| [generalType](#generaltype) | `string`  | Optional | cannot be null | [Unit](unit-properties-generaltype.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/generalType") |
| [unit\_name](#unit_name)    | `string`  | Required | cannot be null | [Unit](unit-properties-unit_name.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/unit_name")     |
| [quantity](#quantity)       | `integer` | Required | cannot be null | [Unit](unit-properties-quantity.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/quantity")       |
| [label](#label)             | `string`  | Required | cannot be null | [Unit](unit-properties-label.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/label")             |

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

## unit\_name

pounds, square ft, dollars, hours, etc

`unit_name`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Unit](unit-properties-unit_name.md "https://hai.ai/schemas/components/unit/v1/unit.schema.json#/properties/unit_name")

### unit\_name Type

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
