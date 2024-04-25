# Untitled string in Service Schema

```txt
https://hai.ai/schemas/service/v1/service-schema.json#/properties/piiDesired/items
```



| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                              |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [service.schema.json\*](../../schemas/components/service/v1/service.schema.json "open original schema") |

## items Type

`string`

## items Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value             | Explanation |
| :---------------- | :---------- |
| `"signature"`     |             |
| `"cryptoaddress"` |             |
| `"creditcard"`    |             |
| `"govid"`         |             |
| `"social"`        |             |
| `"email"`         |             |
| `"phone"`         |             |
| `"address"`       |             |
| `"zip"`           |             |
| `"PHI"`           |             |
| `"MHI"`           |             |
| `"identity"`      |             |
| `"political"`     |             |
| `"bankaddress"`   |             |
| `"income"`        |             |
