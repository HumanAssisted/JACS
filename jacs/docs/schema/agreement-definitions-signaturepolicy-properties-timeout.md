# Untitled string in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/timeout
```

ISO 8601 deadline after which new signatures are not accepted.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## timeout Type

`string`

## timeout Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")
