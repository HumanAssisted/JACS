# Untitled object in A2A Verification Result Schema

```txt
https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/2/properties/Unverified
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [a2a-verification-result.schema.json\*](../../schemas/a2a-verification-result.schema.json "open original schema") |

## Unverified Type

`object` ([Details](a2a-verification-result-definitions-verificationstatus-oneof-2-properties-unverified.md))

# Unverified Properties

| Property          | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                        |
| :---------------- | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [reason](#reason) | `string` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-2-properties-unverified-properties-reason.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/2/properties/Unverified/properties/reason") |

## reason

Explanation of why verification was not possible.

`reason`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-2-properties-unverified-properties-reason.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/2/properties/Unverified/properties/reason")

### reason Type

`string`
