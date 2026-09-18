# Untitled string in Attestation Schema

```txt
https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/jacsLevel
```

Attestation data level. 'raw' for direct attestations, 'derived' for transform receipts.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [attestation.schema.json\*](../../schemas/attestation/v1/attestation.schema.json "open original schema") |

## jacsLevel Type

`string`

## jacsLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value       | Explanation |
| :---------- | :---------- |
| `"raw"`     |             |
| `"derived"` |             |
