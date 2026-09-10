# Untitled object in AP2 Mandate Input (UCP checkout) Schema

```txt
https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/ap2
```

AP2-Mandates extension block. EXCLUDED from the signed payload; the exporter writes the merchant\_authorization detached JWS here.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                             |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [ap2-mandate.schema.json\*](../../schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json "open original schema") |

## ap2 Type

`object` ([Details](ap2-mandate-properties-ap2.md))

# ap2 Properties

| Property                                           | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                          |
| :------------------------------------------------- | :------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [merchant\_authorization](#merchant_authorization) | `string` | Optional | cannot be null | [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-ap2-properties-merchant_authorization.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/ap2/properties/merchant_authorization") |
| Additional Properties                              | Any      | Optional | can be null    |                                                                                                                                                                                                                                     |

## merchant\_authorization

Detached compact ES256 JWS (\<BASE64URL(header)>..\<BASE64URL(signature)>) emitted by the exporter.

`merchant_authorization`

* is optional

* Type: `string`

* cannot be null

* defined in: [AP2 Mandate Input (UCP checkout)](ap2-mandate-properties-ap2-properties-merchant_authorization.md "https://hai.ai/schemas/compatibility/ap2-mandate/v1/ap2-mandate.schema.json#/properties/ap2/properties/merchant_authorization")

### merchant\_authorization Type

`string`

## Additional Properties

Additional properties are allowed and do not have to follow a specific schema
