# Untitled object in AP2 Mandate Input (UCP checkout) Schema

```txt
https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/totals/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                             |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [ap2-mandate.schema.json\*](../../schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json "open original schema") |

## items Type

`object` ([Details](ap2-mandate-properties-totals-items.md))

# items Properties

| Property                       | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                        |
| :----------------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [type](#type)                  | `string`  | Required | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-totals-items-properties-type.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/totals/items/properties/type")                 |
| [display\_text](#display_text) | `string`  | Optional | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-totals-items-properties-display_text.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/totals/items/properties/display_text") |
| [amount](#amount)              | `integer` | Required | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-totals-items-properties-amount.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/totals/items/properties/amount")             |
| Additional Properties          | Any       | Optional | can be null    |                                                                                                                                                                                                                                   |

## type



`type`

* is required

* Type: `string`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-totals-items-properties-type.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/totals/items/properties/type")

### type Type

`string`

### type Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## display\_text



`display_text`

* is optional

* Type: `string`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-totals-items-properties-display_text.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/totals/items/properties/display_text")

### display\_text Type

`string`

## amount



`amount`

* is required

* Type: `integer`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-totals-items-properties-amount.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/totals/items/properties/amount")

### amount Type

`integer`

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
