# Untitled string in Commitment Schema

```txt
https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentStatus
```

Lifecycle status of the commitment.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                            |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [commitment.schema.json\*](../../schemas/commitment/v1/commitment.schema.json "open original schema") |

## jacsCommitmentStatus Type

`string`

## jacsCommitmentStatus Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"pending"`      |             |
| `"active"`       |             |
| `"completed"`    |             |
| `"failed"`       |             |
| `"renegotiated"` |             |
| `"disputed"`     |             |
| `"revoked"`      |             |
