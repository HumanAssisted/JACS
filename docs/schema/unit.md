# Agent Schema

```txt
https://hai.ai/schemas/unit/v1/unit.json
```

General schema for stateful resources.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [unit.schema.json](../../schemas/unit/v1/unit.schema.json "open original schema") |

## Agent Type

`object` ([Agent](unit.md))

# Agent Properties

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                 |
| :-------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------- |
| [id](#id)                   | `string` | Required | cannot be null | [Agent](unit-properties-id.md "https://hai.ai/schemas/unit/v1/unit.json#/properties/id")                   |
| [generaltype](#generaltype) | `string` | Optional | cannot be null | [Agent](unit-properties-generaltype.md "https://hai.ai/schemas/unit/v1/unit.json#/properties/generaltype") |
| [unit\_name](#unit_name)    | `string` | Required | cannot be null | [Agent](unit-properties-unit_name.md "https://hai.ai/schemas/unit/v1/unit.json#/properties/unit_name")     |
| [label](#label)             | `string` | Required | cannot be null | [Agent](unit-properties-label.md "https://hai.ai/schemas/unit/v1/unit.json#/properties/label")             |

## id

Quantification GUID

`id`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](unit-properties-id.md "https://hai.ai/schemas/unit/v1/unit.json#/properties/id")

### id Type

`string`

## generaltype

general type of resource

`generaltype`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Agent](unit-properties-generaltype.md "https://hai.ai/schemas/unit/v1/unit.json#/properties/generaltype")

### generaltype Type

`string`

### generaltype Constraints

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

*   defined in: [Agent](unit-properties-unit_name.md "https://hai.ai/schemas/unit/v1/unit.json#/properties/unit_name")

### unit\_name Type

`string`

## label

age, weight, net worth etc

`label`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Agent](unit-properties-label.md "https://hai.ai/schemas/unit/v1/unit.json#/properties/label")

### label Type

`string`
