# Untitled object in AP2 Mandate Input (UCP checkout) Schema

```txt
https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                             |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [ap2-mandate.schema.json\*](../../schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json "open original schema") |

## items Type

`object` ([Details](ap2-mandate-properties-line_items-items.md))

# items Properties

| Property                       | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                                |
| :----------------------------- | :-------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                      | `string`  | Required | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-id.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/id")                     |
| [title](#title)                | `string`  | Optional | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-title.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/title")               |
| [quantity](#quantity)          | `integer` | Optional | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-quantity.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/quantity")         |
| [base\_amount](#base_amount)   | `integer` | Optional | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-base_amount.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/base_amount")   |
| [total\_amount](#total_amount) | `integer` | Optional | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-total_amount.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/total_amount") |
| Additional Properties          | Any       | Optional | can be null    |                                                                                                                                                                                                                                           |

## id



`id`

* is required

* Type: `string`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-id.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/id")

### id Type

`string`

### id Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## title



`title`

* is optional

* Type: `string`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-title.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/title")

### title Type

`string`

## quantity



`quantity`

* is optional

* Type: `integer`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-quantity.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/quantity")

### quantity Type

`integer`

### quantity Constraints

**minimum**: the value of this number must greater than or equal to: `1`

## base\_amount



`base_amount`

* is optional

* Type: `integer`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-base_amount.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/base_amount")

### base\_amount Type

`integer`

## total\_amount



`total_amount`

* is optional

* Type: `integer`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items-items-properties-total_amount.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items/items/properties/total_amount")

### total\_amount Type

`integer`

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
