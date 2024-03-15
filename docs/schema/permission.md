# Permission Schema

```txt
https://hai.ai/schemas/permission/v1/permission-schema.json
```

Provides agents access to fields for reading, writing, signing, and amdin.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                          |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [permission.schema.json](../../schemas/permission/v1/permission.schema.json "open original schema") |

## Permission Type

`object` ([Permission](permission.md))

# Permission Properties

| Property                                | Type     | Required | Nullable       | Defined by                                                                                                                       |
| :-------------------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| [fields](#fields)                       | `array`  | Optional | cannot be null | [Permission](permission-properties-fields.md "https://hai.ai/schemas/permission/v1/permission-schema.json#/properties/fields")   |
| [default](#default)                     | `string` | Optional | cannot be null | [Permission](permission-properties-default.md "https://hai.ai/schemas/permission/v1/permission-schema.json#/properties/default") |
| [agentid](#agentid)                     | `string` | Required | cannot be null | [Permission](permission-properties-agentid.md "https://hai.ai/schemas/permission/v1/permission-schema.json#/properties/agentid") |
| [grantingsignature](#grantingsignature) | `object` | Optional | cannot be null | [Permission](signature.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/grantingsignature")             |

## fields

array of fields for specific permissions

`fields`

*   is optional

*   Type: an array where each item follows the corresponding schema in the following list:

    1.  [Untitled string in Permission](permission-properties-fields-items-items-0.md "check type definition")

    2.  [Untitled string in Permission](permission-properties-fields-items-items-1.md "check type definition")

*   cannot be null

*   defined in: [Permission](permission-properties-fields.md "https://hai.ai/schemas/permission/v1/permission-schema.json#/properties/fields")

### fields Type

an array where each item follows the corresponding schema in the following list:

1.  [Untitled string in Permission](permission-properties-fields-items-items-0.md "check type definition")

2.  [Untitled string in Permission](permission-properties-fields-items-items-1.md "check type definition")

## default

default permission admin is  add other admins

`default`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [Permission](permission-properties-default.md "https://hai.ai/schemas/permission/v1/permission-schema.json#/properties/default")

### default Type

`string`

### default Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value     | Explanation |
| :-------- | :---------- |
| `"admin"` |             |
| `"write"` |             |
| `"read"`  |             |
| `"sign"`  |             |

## agentid

The id of agent with permissions.

`agentid`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [Permission](permission-properties-agentid.md "https://hai.ai/schemas/permission/v1/permission-schema.json#/properties/agentid")

### agentid Type

`string`

## grantingsignature

Cryptographic signature to be embedded in other documents. Signature may be validated with registrar.

`grantingsignature`

*   is optional

*   Type: `object` ([Signature](signature.md))

*   cannot be null

*   defined in: [Permission](signature.md "https://hai.ai/schemas/signature/v1/signature-schema.json#/properties/grantingsignature")

### grantingsignature Type

`object` ([Signature](signature.md))
