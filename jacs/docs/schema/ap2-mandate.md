# AP2 Mandate Input (UCP checkout) Schema

```txt
https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json
```

Typed input boundary for the JACS AP2 merchant-authorization exporter (UCP AP2-Mandates extension, revision 2026-01-23). The exporter validates the checkout object against this schema and rejects anything else: a purpose-built content exporter takes a typed source, never arbitrary documents. The signed payload is this checkout object EXCLUDING the `ap2` field, canonicalized per RFC 8785 (JCS).

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                           |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [ap2-mandate.schema.json](../../schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json "open original schema") |

## AP2 Mandate Input (UCP checkout) Type

`object` ([AP2 Mandate Input (UCP checkout)](ap2-mandate.md))

# AP2 Mandate Input (UCP checkout) Properties

| Property                   | Type     | Required | Nullable       | Defined by                                                                                                                                                                    |
| :------------------------- | :------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [id](#id)                  | `string` | Required | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-id.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/id")                 |
| [status](#status)          | `string` | Optional | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-status.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/status")         |
| [currency](#currency)      | `string` | Required | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-currency.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/currency")     |
| [line\_items](#line_items) | `array`  | Required | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items") |
| [totals](#totals)          | `array`  | Required | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-totals.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/totals")         |
| [ap2](#ap2)                | `object` | Optional | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-ap2.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/ap2")               |
| Additional Properties      | Any      | Optional | can be null    |                                                                                                                                                                               |

## id

Checkout identifier assigned by the merchant/business endpoint.

`id`

* is required

* Type: `string`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-id.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/id")

### id Type

`string`

### id Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## status

UCP checkout status (e.g. ready\_for\_payment).

`status`

* is optional

* Type: `string`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-status.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/status")

### status Type

`string`

## currency

ISO 4217 currency code for all amounts in the checkout.

`currency`

* is required

* Type: `string`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-currency.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/currency")

### currency Type

`string`

### currency Constraints

**maximum length**: the maximum number of characters for this string is: `3`

**minimum length**: the minimum number of characters for this string is: `3`

## line\_items

Items being authorized. Amounts are integer minor units per UCP.

`line_items`

* is required

* Type: `object[]` ([Details](ap2-mandate-properties-line_items-items.md))

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-line_items.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/line_items")

### line\_items Type

`object[]` ([Details](ap2-mandate-properties-line_items-items.md))

### line\_items Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

## totals

Checkout totals (subtotal, tax, total, ...).

`totals`

* is required

* Type: `object[]` ([Details](ap2-mandate-properties-totals-items.md))

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-totals.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/totals")

### totals Type

`object[]` ([Details](ap2-mandate-properties-totals-items.md))

### totals Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

## ap2

AP2-Mandates extension block. EXCLUDED from the signed payload; the exporter writes the merchant\_authorization detached JWS here.

`ap2`

* is optional

* Type: `object` ([Details](ap2-mandate-properties-ap2.md))

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-ap2.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/ap2")

### ap2 Type

`object` ([Details](ap2-mandate-properties-ap2.md))

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
