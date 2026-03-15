# A2A Verification Result Schema

```txt
https://hai.ai/schemas/a2a-verification-result.schema.json
```

Cross-language schema for A2A artifact verification results. Defines the normalized contract per TR-3 of the ATTESTATION\_A2A\_RESOLUTION PRD. All field names use camelCase.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | Yes        | Unknown status | No           | Forbidden         | Forbidden             | none                | [a2a-verification-result.schema.json](../../schemas/a2a-verification-result.schema.json "open original schema") |

## A2A Verification Result Type

`object` ([A2A Verification Result](a2a-verification-result.md))

# A2A Verification Result Properties

| Property                                                | Type          | Required | Nullable       | Defined by                                                                                                                                                                                    |
| :------------------------------------------------------ | :------------ | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [status](#status)                                       | Merged        | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-verificationstatus.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/status")                          |
| [valid](#valid)                                         | `boolean`     | Required | cannot be null | [A2A Verification Result](a2a-verification-result-properties-valid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/valid")                                         |
| [signerId](#signerid)                                   | `string`      | Required | cannot be null | [A2A Verification Result](a2a-verification-result-properties-signerid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/signerId")                                   |
| [signerVersion](#signerversion)                         | `string`      | Required | cannot be null | [A2A Verification Result](a2a-verification-result-properties-signerversion.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/signerVersion")                         |
| [artifactType](#artifacttype)                           | `string`      | Required | cannot be null | [A2A Verification Result](a2a-verification-result-properties-artifacttype.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/artifactType")                           |
| [timestamp](#timestamp)                                 | `string`      | Required | cannot be null | [A2A Verification Result](a2a-verification-result-properties-timestamp.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/timestamp")                                 |
| [parentSignaturesValid](#parentsignaturesvalid)         | `boolean`     | Required | cannot be null | [A2A Verification Result](a2a-verification-result-properties-parentsignaturesvalid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/parentSignaturesValid")         |
| [parentVerificationResults](#parentverificationresults) | `array`       | Required | cannot be null | [A2A Verification Result](a2a-verification-result-properties-parentverificationresults.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/parentVerificationResults") |
| [originalArtifact](#originalartifact)                   | Not specified | Required | cannot be null | [A2A Verification Result](a2a-verification-result-properties-originalartifact.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/originalArtifact")                   |
| [trustLevel](#trustlevel)                               | `string`      | Optional | cannot be null | [A2A Verification Result](a2a-verification-result-properties-trustlevel.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/trustLevel")                               |
| [trustAssessment](#trustassessment)                     | `object`      | Optional | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/trustAssessment")                    |

## status

Verification status enum. Simple variants serialize as strings; Unverified and Invalid serialize as objects with a reason field.

`status`

* is required

* Type: merged type ([Details](a2a-verification-result-definitions-verificationstatus.md))

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-verificationstatus.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/status")

### status Type

merged type ([Details](a2a-verification-result-definitions-verificationstatus.md))

one (and only one) of

* [Untitled undefined type in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-0.md "check type definition")

* [Untitled undefined type in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-1.md "check type definition")

* [Untitled object in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-2.md "check type definition")

* [Untitled object in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-3.md "check type definition")

## valid

Whether the signature was cryptographically verified. False for both Invalid and Unverified statuses.

`valid`

* is required

* Type: `boolean`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-properties-valid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/valid")

### valid Type

`boolean`

## signerId

ID of the signing agent.

`signerId`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-properties-signerid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/signerId")

### signerId Type

`string`

## signerVersion

Version of the signing agent.

`signerVersion`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-properties-signerversion.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/signerVersion")

### signerVersion Type

`string`

## artifactType

Type of the artifact (e.g., 'a2a-task', 'a2a-message').

`artifactType`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-properties-artifacttype.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/artifactType")

### artifactType Type

`string`

## timestamp

Timestamp when the artifact was signed (RFC 3339).

`timestamp`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-properties-timestamp.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/timestamp")

### timestamp Type

`string`

## parentSignaturesValid

Whether all parent signatures in the chain are valid.

`parentSignaturesValid`

* is required

* Type: `boolean`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-properties-parentsignaturesvalid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/parentSignaturesValid")

### parentSignaturesValid Type

`boolean`

## parentVerificationResults

Individual verification results for each parent signature.

`parentVerificationResults`

* is required

* Type: `object[]` ([Details](a2a-verification-result-definitions-parentverificationresult.md))

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-properties-parentverificationresults.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/parentVerificationResults")

### parentVerificationResults Type

`object[]` ([Details](a2a-verification-result-definitions-parentverificationresult.md))

## originalArtifact

The original A2A artifact that was wrapped.

`originalArtifact`

* is required

* Type: unknown

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-properties-originalartifact.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/originalArtifact")

### originalArtifact Type

unknown

## trustLevel

Assessed trust level of the signing agent.

`trustLevel`

* is optional

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-properties-trustlevel.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/trustLevel")

### trustLevel Type

`string`

### trustLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                 | Explanation |
| :-------------------- | :---------- |
| `"Untrusted"`         |             |
| `"JacsVerified"`      |             |
| `"ExplicitlyTrusted"` |             |

## trustAssessment

Result of assessing a remote agent's trustworthiness.

`trustAssessment`

* is optional

* Type: `object` ([Details](a2a-verification-result-definitions-trustassessment.md))

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/trustAssessment")

### trustAssessment Type

`object` ([Details](a2a-verification-result-definitions-trustassessment.md))

# A2A Verification Result Definitions

## Definitions group VerificationStatus

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus"}
```

| Property | Type | Required | Nullable | Defined by |
| :------- | :--- | :------- | :------- | :--------- |

## Definitions group TrustLevel

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustLevel"}
```

| Property | Type | Required | Nullable | Defined by |
| :------- | :--- | :------- | :------- | :--------- |

## Definitions group TrustAssessment

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment"}
```

| Property                          | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                      |
| :-------------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [allowed](#allowed)               | `boolean` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-allowed.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/allowed")               |
| [trustLevel](#trustlevel-1)       | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-trustlevel.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/trustLevel")         |
| [reason](#reason)                 | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-reason.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/reason")                 |
| [jacsRegistered](#jacsregistered) | `boolean` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-jacsregistered.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/jacsRegistered") |
| [agentId](#agentid)               | `string`  | Required | can be null    | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-agentid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/agentId")               |
| [policy](#policy)                 | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-policy.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/policy")                 |

### allowed

Whether the agent is allowed to interact under the applied policy.

`allowed`

* is required

* Type: `boolean`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-allowed.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/allowed")

#### allowed Type

`boolean`

### trustLevel

Assessed trust level of the signing agent.

`trustLevel`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-trustlevel.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/trustLevel")

#### trustLevel Type

`string`

#### trustLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                 | Explanation |
| :-------------------- | :---------- |
| `"Untrusted"`         |             |
| `"JacsVerified"`      |             |
| `"ExplicitlyTrusted"` |             |

### reason

Human-readable explanation of the assessment.

`reason`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-reason.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/reason")

#### reason Type

`string`

### jacsRegistered

Whether the remote agent declares the JACS provenance extension.

`jacsRegistered`

* is required

* Type: `boolean`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-jacsregistered.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/jacsRegistered")

#### jacsRegistered Type

`boolean`

### agentId

The agent ID from the remote card's metadata (null if unavailable).

`agentId`

* is required

* Type: `string`

* can be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-agentid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/agentId")

#### agentId Type

`string`

### policy

Trust policy controlling which remote agents are allowed to interact.

`policy`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-policy.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/policy")

#### policy Type

`string`

#### policy Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"Open"`     |             |
| `"Verified"` |             |
| `"Strict"`   |             |

## Definitions group A2ATrustPolicy

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/A2ATrustPolicy"}
```

| Property | Type | Required | Nullable | Defined by |
| :------- | :--- | :------- | :------- | :--------- |

## Definitions group ParentVerificationResult

Reference this group by using

```json
{"$ref":"https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult"}
```

| Property                  | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                                |
| :------------------------ | :-------- | :------- | :------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [index](#index)           | `integer` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-index.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/index")           |
| [artifactId](#artifactid) | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-artifactid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/artifactId") |
| [signerId](#signerid-1)   | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-signerid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/signerId")     |
| [status](#status-1)       | Merged    | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-verificationstatus.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/status")                                 |
| [verified](#verified)     | `boolean` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-verified.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/verified")     |

### index

Index in the parent signatures array.

`index`

* is required

* Type: `integer`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-index.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/index")

#### index Type

`integer`

#### index Constraints

**minimum**: the value of this number must greater than or equal to: `0`

### artifactId

ID of the parent artifact.

`artifactId`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-artifactid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/artifactId")

#### artifactId Type

`string`

### signerId

ID of the agent that signed the parent.

`signerId`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-signerid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/signerId")

#### signerId Type

`string`

### status

Verification status enum. Simple variants serialize as strings; Unverified and Invalid serialize as objects with a reason field.

`status`

* is required

* Type: merged type ([Details](a2a-verification-result-definitions-verificationstatus.md))

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-verificationstatus.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/status")

#### status Type

merged type ([Details](a2a-verification-result-definitions-verificationstatus.md))

one (and only one) of

* [Untitled undefined type in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-0.md "check type definition")

* [Untitled undefined type in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-1.md "check type definition")

* [Untitled object in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-2.md "check type definition")

* [Untitled object in A2A Verification Result](a2a-verification-result-definitions-verificationstatus-oneof-3.md "check type definition")

### verified

Whether the parent signature was verified (convenience field).

`verified`

* is required

* Type: `boolean`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-parentverificationresult-properties-verified.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult/properties/verified")

#### verified Type

`boolean`
