# Untitled object in Commitment Schema

```txt
https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                            |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [commitment.schema.json\*](../../schemas/commitment/v1/commitment.schema.json "open original schema") |

## 1 Type

`object` ([Details](commitment-allof-1.md))

# 1 Properties

| Property                                                              | Type     | Required | Nullable       | Defined by                                                                                                                                                                                         |
| :-------------------------------------------------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsCommitmentDescription](#jacscommitmentdescription)               | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentdescription.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentDescription")               |
| [jacsCommitmentTerms](#jacscommitmentterms)                           | `object` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentterms.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentTerms")                           |
| [jacsCommitmentStatus](#jacscommitmentstatus)                         | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentstatus.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentStatus")                         |
| [jacsCommitmentDisputeReason](#jacscommitmentdisputereason)           | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentdisputereason.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentDisputeReason")           |
| [jacsCommitmentTaskId](#jacscommitmenttaskid)                         | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmenttaskid.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentTaskId")                         |
| [jacsCommitmentConversationRef](#jacscommitmentconversationref)       | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentconversationref.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentConversationRef")       |
| [jacsCommitmentTodoRef](#jacscommitmenttodoref)                       | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmenttodoref.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentTodoRef")                       |
| [jacsCommitmentQuestion](#jacscommitmentquestion)                     | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentquestion.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentQuestion")                     |
| [jacsCommitmentAnswer](#jacscommitmentanswer)                         | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentanswer.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentAnswer")                         |
| [jacsCommitmentCompletionQuestion](#jacscommitmentcompletionquestion) | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentcompletionquestion.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentCompletionQuestion") |
| [jacsCommitmentCompletionAnswer](#jacscommitmentcompletionanswer)     | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentcompletionanswer.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentCompletionAnswer")     |
| [jacsCommitmentStartDate](#jacscommitmentstartdate)                   | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentstartdate.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentStartDate")                   |
| [jacsCommitmentEndDate](#jacscommitmentenddate)                       | `string` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentenddate.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentEndDate")                       |
| [jacsCommitmentRecurrence](#jacscommitmentrecurrence)                 | `object` | Optional | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentrecurrence.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentRecurrence")                 |
| [jacsCommitmentOwner](#jacscommitmentowner)                           | `object` | Optional | cannot be null | [Commitment](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/jacsCommitmentOwner")                                      |

## jacsCommitmentDescription

Human-readable description of what is being committed to.

`jacsCommitmentDescription`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentdescription.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentDescription")

### jacsCommitmentDescription Type

`string`

## jacsCommitmentTerms

Structured terms of the commitment (deliverable, deadline, compensation, etc.). Free-form object.

`jacsCommitmentTerms`

* is optional

* Type: `object` ([Details](commitment-allof-1-properties-jacscommitmentterms.md))

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentterms.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentTerms")

### jacsCommitmentTerms Type

`object` ([Details](commitment-allof-1-properties-jacscommitmentterms.md))

## jacsCommitmentStatus

Lifecycle status of the commitment.

`jacsCommitmentStatus`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentstatus.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentStatus")

### jacsCommitmentStatus Type

`string`

### jacsCommitmentStatus Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"pending"`      |             |
| `"active"`       |             |
| `"completed"`    |             |
| `"failed"`       |             |
| `"renegotiated"` |             |
| `"disputed"`     |             |
| `"revoked"`      |             |

## jacsCommitmentDisputeReason

Reason for dispute when status is 'disputed'.

`jacsCommitmentDisputeReason`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentdisputereason.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentDisputeReason")

### jacsCommitmentDisputeReason Type

`string`

## jacsCommitmentTaskId

Optional reference to a task this commitment serves.

`jacsCommitmentTaskId`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmenttaskid.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentTaskId")

### jacsCommitmentTaskId Type

`string`

### jacsCommitmentTaskId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## jacsCommitmentConversationRef

Optional reference to the conversation thread that produced this commitment.

`jacsCommitmentConversationRef`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentconversationref.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentConversationRef")

### jacsCommitmentConversationRef Type

`string`

### jacsCommitmentConversationRef Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## jacsCommitmentTodoRef

Optional reference to a todo item in format 'list-uuid:item-uuid'.

`jacsCommitmentTodoRef`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmenttodoref.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentTodoRef")

### jacsCommitmentTodoRef Type

`string`

## jacsCommitmentQuestion

Structured question prompt for the commitment.

`jacsCommitmentQuestion`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentquestion.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentQuestion")

### jacsCommitmentQuestion Type

`string`

## jacsCommitmentAnswer

Answer to the commitment question.

`jacsCommitmentAnswer`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentanswer.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentAnswer")

### jacsCommitmentAnswer Type

`string`

## jacsCommitmentCompletionQuestion

Question to verify commitment completion.

`jacsCommitmentCompletionQuestion`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentcompletionquestion.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentCompletionQuestion")

### jacsCommitmentCompletionQuestion Type

`string`

## jacsCommitmentCompletionAnswer

Answer verifying commitment completion.

`jacsCommitmentCompletionAnswer`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentcompletionanswer.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentCompletionAnswer")

### jacsCommitmentCompletionAnswer Type

`string`

## jacsCommitmentStartDate

When the commitment period begins.

`jacsCommitmentStartDate`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentstartdate.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentStartDate")

### jacsCommitmentStartDate Type

`string`

### jacsCommitmentStartDate Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## jacsCommitmentEndDate

When the commitment period ends (deadline).

`jacsCommitmentEndDate`

* is optional

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentenddate.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentEndDate")

### jacsCommitmentEndDate Type

`string`

### jacsCommitmentEndDate Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## jacsCommitmentRecurrence

Recurrence pattern for recurring commitments.

`jacsCommitmentRecurrence`

* is optional

* Type: `object` ([Details](commitment-allof-1-properties-jacscommitmentrecurrence.md))

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentrecurrence.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentRecurrence")

### jacsCommitmentRecurrence Type

`object` ([Details](commitment-allof-1-properties-jacscommitmentrecurrence.md))

## jacsCommitmentOwner

SACRED CRYPTOGRAPHIC COMMITMENT: A signature is a permanent, irreversible cryptographic proof binding the signer to document content. Once signed, the signer cannot deny their attestation (non-repudiation). Signatures should only be created after careful review of document content. The signer is forever accountable for what they sign.

`jacsCommitmentOwner`

* is optional

* Type: `object` ([Signature](header-properties-signature-1.md))

* cannot be null

* defined in: [Commitment](header-properties-signature-1.md "https://hai.ai/schemas/components/signature/v1/signature.schema.json#/allOf/1/properties/jacsCommitmentOwner")

### jacsCommitmentOwner Type

`object` ([Signature](header-properties-signature-1.md))
