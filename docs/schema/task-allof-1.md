# Untitled object in Task Schema

```txt
https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                          |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [task.schema.json\*](../../schemas/task/v1/task.schema.json "open original schema") |

## 1 Type

`object` ([Details](task-allof-1.md))

# 1 Properties

| Property                                          | Type     | Required | Nullable       | Defined by                                                                                                                                             |
| :------------------------------------------------ | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsTaskName](#jacstaskname)                     | `string` | Optional | cannot be null | [Task](task-allof-1-properties-jacstaskname.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskName")                     |
| [jacsTaskSuccess](#jacstasksuccess)               | `string` | Optional | cannot be null | [Task](task-allof-1-properties-jacstasksuccess.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskSuccess")               |
| [jacsTaskCustomer](#jacstaskcustomer)             | `object` | Optional | cannot be null | [Task](signature.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/jacsTaskCustomer")                       |
| [jacsTaskService](#jacstaskservice)               | `object` | Optional | cannot be null | [Task](service.md "https://hai.ai/schemas/service/v1/service-schema.json#/allOf/1/properties/jacsTaskService")                                         |
| [jacsTaskState](#jacstaskstate)                   | `string` | Optional | cannot be null | [Task](task-allof-1-properties-jacstaskstate.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskState")                   |
| [jacsTaskStartDate](#jacstaskstartdate)           | `string` | Optional | cannot be null | [Task](task-allof-1-properties-jacstaskstartdate.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskStartDate")           |
| [jacsTaskCompleteDate](#jacstaskcompletedate)     | `string` | Optional | cannot be null | [Task](task-allof-1-properties-jacstaskcompletedate.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskCompleteDate")     |
| [jacsTaskActionsDesired](#jacstaskactionsdesired) | `array`  | Optional | cannot be null | [Task](task-allof-1-properties-jacstaskactionsdesired.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskActionsDesired") |
| [jacsTaskMessages](#jacstaskmessages)             | `array`  | Optional | cannot be null | [Task](task-allof-1-properties-jacstaskmessages.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskMessages")             |
| [jacsTaskSubTaskOf](#jacstasksubtaskof)           | `array`  | Optional | cannot be null | [Task](task-allof-1-properties-jacstasksubtaskof.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskSubTaskOf")           |
| [jacsTaskCopyOf](#jacstaskcopyof)                 | `array`  | Optional | cannot be null | [Task](task-allof-1-properties-jacstaskcopyof.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskCopyOf")                 |
| [jacsTaskMergedTasks](#jacstaskmergedtasks)       | `array`  | Optional | cannot be null | [Task](task-allof-1-properties-jacstaskmergedtasks.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskMergedTasks")       |

## jacsTaskName

Name of the agent, unique per registrar

`jacsTaskName`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstaskname.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskName")

### jacsTaskName Type

`string`

## jacsTaskSuccess

Description of success

`jacsTaskSuccess`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstasksuccess.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskSuccess")

### jacsTaskSuccess Type

`string`

## jacsTaskCustomer

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`jacsTaskCustomer`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Task](signature.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/jacsTaskCustomer")

### jacsTaskCustomer Type

`object` ([Signature](signature.md))

## jacsTaskService

Services that an Agent claims to provide.

`jacsTaskService`

*   is optional

*   Type: `object` ([Service](service.md))

*   cannot be null

*   defined in: [Task](service.md "https://hai.ai/schemas/service/v1/service-schema.json#/allOf/1/properties/jacsTaskService")

### jacsTaskService Type

`object` ([Service](service.md))

## jacsTaskState

Is the document locked from edits

`jacsTaskState`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstaskstate.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskState")

### jacsTaskState Type

`string`

### jacsTaskState Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"open"`     |             |
| `"editlock"` |             |
| `"closed"`   |             |

## jacsTaskStartDate

When the lock expires

`jacsTaskStartDate`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstaskstartdate.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskStartDate")

### jacsTaskStartDate Type

`string`

### jacsTaskStartDate Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## jacsTaskCompleteDate

When the lock expires

`jacsTaskCompleteDate`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstaskcompletedate.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskCompleteDate")

### jacsTaskCompleteDate Type

`string`

### jacsTaskCompleteDate Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## jacsTaskActionsDesired



`jacsTaskActionsDesired`

*   is optional

*   Type: `object[]` ([Action](action.md))

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstaskactionsdesired.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskActionsDesired")

### jacsTaskActionsDesired Type

`object[]` ([Action](action.md))

## jacsTaskMessages



`jacsTaskMessages`

*   is optional

*   Type: `object[]` ([Message](message.md))

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstaskmessages.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskMessages")

### jacsTaskMessages Type

`object[]` ([Message](message.md))

## jacsTaskSubTaskOf



`jacsTaskSubTaskOf`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstasksubtaskof.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskSubTaskOf")

### jacsTaskSubTaskOf Type

`string[]`

## jacsTaskCopyOf



`jacsTaskCopyOf`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstaskcopyof.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskCopyOf")

### jacsTaskCopyOf Type

`string[]`

## jacsTaskMergedTasks



`jacsTaskMergedTasks`

*   is optional

*   Type: `string[]`

*   cannot be null

*   defined in: [Task](task-allof-1-properties-jacstaskmergedtasks.md "https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskMergedTasks")

### jacsTaskMergedTasks Type

`string[]`
