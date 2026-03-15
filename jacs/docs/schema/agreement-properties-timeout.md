# Untitled string in agreement Schema

```txt
https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/timeout
```

ISO 8601 deadline after which the agreement expires and no more signatures are accepted.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                    |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/components/agreement/v1/agreement.schema.json "open original schema") |

## timeout Type

`string`

## timeout Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")
