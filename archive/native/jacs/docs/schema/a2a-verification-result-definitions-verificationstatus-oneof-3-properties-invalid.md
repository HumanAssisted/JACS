# Untitled object in A2A Verification Result Schema

```txt
https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/3/properties/Invalid
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [a2a-verification-result.schema.json\*](../../schemas/a2a-verification-result.schema.json "open original schema") |

## Invalid Type

`object` ([Details](a2a-verification-result-definitions-verificationstatus-oneof-3-properties-invalid.md))

# Invalid Properties

| Property          | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                  |
| :---------------- | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [reason](#reason) | `string` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-3-properties-invalid-properties-reason.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/3/properties/Invalid/properties/reason") |

## reason

Explanation of why the signature is invalid.

`reason`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-3-properties-invalid-properties-reason.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/3/properties/Invalid/properties/reason")

### reason Type

`string`
