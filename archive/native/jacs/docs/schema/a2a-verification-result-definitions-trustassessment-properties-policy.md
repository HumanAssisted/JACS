# Untitled string in A2A Verification Result Schema

```txt
https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/policy
```

Trust policy controlling which remote agents are allowed to interact.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                        |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [a2a-verification-result.schema.json\*](../../schemas/a2a-verification-result.schema.json "open original schema") |

## policy Type

`string`

## policy Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"Open"`     |             |
| `"Verified"` |             |
| `"Strict"`   |             |
