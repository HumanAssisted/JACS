# Untitled object in Commitment Schema

```txt
https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentRecurrence
```

Recurrence pattern for recurring commitments.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                            |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [commitment.schema.json\*](../../schemas/commitment/v1/commitment.schema.json "open original schema") |

## jacsCommitmentRecurrence Type

`object` ([Details](commitment-allof-1-properties-jacscommitmentrecurrence.md))

# jacsCommitmentRecurrence Properties

| Property                | Type      | Required | Nullable       | Defined by                                                                                                                                                                                                                   |
| :---------------------- | :-------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [frequency](#frequency) | `string`  | Required | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentrecurrence-properties-frequency.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentRecurrence/properties/frequency") |
| [interval](#interval)   | `integer` | Required | cannot be null | [Commitment](commitment-allof-1-properties-jacscommitmentrecurrence-properties-interval.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentRecurrence/properties/interval")   |

## frequency

How often the commitment recurs.

`frequency`

* is required

* Type: `string`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentrecurrence-properties-frequency.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentRecurrence/properties/frequency")

### frequency Type

`string`

### frequency Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"daily"`     |             |
| `"weekly"`    |             |
| `"biweekly"`  |             |
| `"monthly"`   |             |
| `"quarterly"` |             |
| `"yearly"`    |             |

## interval

Number of frequency units between occurrences.

`interval`

* is required

* Type: `integer`

* cannot be null

* defined in: [Commitment](commitment-allof-1-properties-jacscommitmentrecurrence-properties-interval.md "https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentRecurrence/properties/interval")

### interval Type

`integer`

### interval Constraints

**minimum**: the value of this number must greater than or equal to: `1`
