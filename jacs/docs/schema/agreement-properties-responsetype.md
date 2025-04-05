# Untitled string in agreement Schema

```txt
https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/responseType
```

Optional way to track disagreement, or agreement. Reject means question not understood or considered relevant.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                    |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/components/agreement/v1/agreement.schema.json "open original schema") |

## responseType Type

`string`

## responseType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"agree"`    |             |
| `"disagree"` |             |
| `"reject"`   |             |
