# Untitled object in A2A Verification Result Schema

```txt
https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult
```

Result of verifying a parent signature in a chain of custody.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [a2a-verification-result.schema.json\*](../../schemas/a2a-verification-result.schema.json "open original schema") |

## ParentVerificationResult Type

`object` ([Details](a2a-verification-result-definitions-parentverificationresult.md))

# ParentVerificationResult Properties

| Property                  | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                                |
| :------------------------ | :-------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [index](#index)           | `integer` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-index.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/index")           |
| [artifactId](#artifactid) | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-artifactid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/artifactId") |
| [signerId](#signerid)     | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-signerid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/signerId")     |
| [status](#status)         | Merged    | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-verificationstatus.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/status")                                 |
| [verified](#verified)     | `boolean` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-verified.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/verified")     |

## index

Index in the parent signatures array.

`index`

* is required

* Type: `integer`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-index.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/index")

### index Type

`integer`

### index Constraints

**minimum**: the value of this number must greater than or equal to: `0`

## artifactId

ID of the parent artifact.

`artifactId`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-artifactid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/artifactId")

### artifactId Type

`string`

## signerId

ID of the agent that signed the parent.

`signerId`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-signerid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/signerId")

### signerId Type

`string`

## status

Verification status enum. Simple variants serialize as strings; Unverified and Invalid serialize as objects with a reason field.

`status`

* is required

* Type: merged type ([Details](a2a-verification-result-definitions-verificationstatus.md))

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-verificationstatus.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/status")

### status Type

merged type ([Details](a2a-verification-result-definitions-verificationstatus.md))

one (and only one) of

* [Untitled undefined type in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-0.md "check type definition")

* [Untitled undefined type in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-1.md "check type definition")

* [Untitled object in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-2.md "check type definition")

* [Untitled object in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-3.md "check type definition")

## verified

Whether the parent signature was verified (convenience field).

`verified`

* is required

* Type: `boolean`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-verified.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/verified")

### verified Type

`boolean`
