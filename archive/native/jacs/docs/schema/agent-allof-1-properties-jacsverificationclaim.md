# Untitled string in Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsVerificationClaim
```

Agent's claim about verification status. 'unverified' (default) allows relaxed DNS/TLS settings. 'verified' requires strict DNS with DNSSEC and domain must be set. 'verified-registry' requires registry verification. DEPRECATED: 'verified-hai.ai' is a deprecated alias for 'verified-registry' and will be removed in the next major version.

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                             |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [agent.schema.json\*](../../schemas/agent/v1/agent.schema.json "open original schema") |

## jacsVerificationClaim Type

`string`

## jacsVerificationClaim Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                 | Explanation |
| :-------------------- | :---------- |
| `"unverified"`        |             |
| `"verified"`          |             |
| `"verified-registry"` |             |
| `"verified-hai.ai"`   |             |

## jacsVerificationClaim Default Value

The default value is:

```json
"unverified"
```
