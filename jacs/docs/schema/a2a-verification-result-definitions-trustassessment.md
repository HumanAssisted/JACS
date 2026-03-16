# Untitled object in A2A Verification Result Schema

```txt
https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment
```

Result of assessing a remote agent's trustworthiness.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [a2a-verification-result.schema.json\*](../../schemas/a2a-verification-result.schema.json "open original schema") |

## TrustAssessment Type

`object` ([Details](a2a-verification-result-definitions-trustassessment.md))

# TrustAssessment Properties

| Property                          | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                      |
| :-------------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [allowed](#allowed)               | `boolean` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-allowed.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/allowed")               |
| [trustLevel](#trustlevel)         | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustlevel.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/trustLevel")                                    |
| [reason](#reason)                 | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-reason.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/reason")                 |
| [jacsRegistered](#jacsregistered) | `boolean` | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-jacsregistered.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/jacsRegistered") |
| [agentId](#agentid)               | `string`  | Required | can be null    | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-agentid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/agentId")               |
| [policy](#policy)                 | `string`  | Required | cannot be null | [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-policy.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/policy")                 |

## allowed

Whether the agent is allowed to interact under the applied policy.

`allowed`

* is required

* Type: `boolean`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-allowed.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/allowed")

### allowed Type

`boolean`

## trustLevel

Assessed trust level of the signing agent.

`trustLevel`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustlevel.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/trustLevel")

### trustLevel Type

`string`

### trustLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                 | Explanation |
| :-------------------- | :---------- |
| `"Untrusted"`         |             |
| `"JacsVerified"`      |             |
| `"ExplicitlyTrusted"` |             |

## reason

Human-readable explanation of the assessment.

`reason`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-reason.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/reason")

### reason Type

`string`

## jacsRegistered

Whether the remote agent declares the JACS provenance extension.

`jacsRegistered`

* is required

* Type: `boolean`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-jacsregistered.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/jacsRegistered")

### jacsRegistered Type

`boolean`

## agentId

The agent ID from the remote card's metadata (null if unavailable).

`agentId`

* is required

* Type: `string`

* can be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-agentid.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/agentId")

### agentId Type

`string`

## policy

Trust policy controlling which remote agents are allowed to interact.

`policy`

* is required

* Type: `string`

* cannot be null

* defined in: [A2A Verification Result](a2a-verification-result-definitions-trustassessment-properties-policy.md "https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment/properties/policy")

### policy Type

`string`

### policy Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"Open"`     |             |
| `"Verified"` |             |
| `"Strict"`   |             |
