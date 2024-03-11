# Untitled string in Task Schema

```txt
https://hai.ai/schemas/task/v1/task-schema.json#/properties/lockedState
```

Is the document locked from edits

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                          |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [task.schema.json\*](../../schemas/task/v1/task.schema.json "open original schema") |

## lockedState Type

`string`

## lockedState Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"open"`     |             |
| `"editlock"` |             |
| `"closed"`   |             |
