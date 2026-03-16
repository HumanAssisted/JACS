# Untitled object in Agent Schema

```txt
https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                             |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [agent.schema.json\*](../../schemas/agent/v1/agent.schema.json "open original schema") |

## 1 Type

`object` ([Details](agent-allof-1.md))

# 1 Properties

| Property                                        | Type     | Required | Nullable       | Defined by                                                                                                                                               |
| :---------------------------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsAgentType](#jacsagenttype)                 | `string` | Optional | cannot be null | [Agent](agent-allof-1-properties-jacsagenttype.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsAgentType")                 |
| [jacsAgentDomain](#jacsagentdomain)             | `string` | Optional | cannot be null | [Agent](agent-allof-1-properties-jacsagentdomain.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsAgentDomain")             |
| [jacsVerificationClaim](#jacsverificationclaim) | `string` | Optional | cannot be null | [Agent](agent-allof-1-properties-jacsverificationclaim.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsVerificationClaim") |

## jacsAgentType

Type of the agent. 'human' indicates a biological entity, 'human-org' indicates a group of people, hybrid' indicates a combination of human and artificial components, 'ai' indicates a fully artificial intelligence.

`jacsAgentType`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacsagenttype.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsAgentType")

### jacsAgentType Type

`string`

### jacsAgentType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"human"`     |             |
| `"human-org"` |             |
| `"hybrid"`    |             |
| `"ai"`        |             |

## jacsAgentDomain

Optional domain used for DNSSEC-validated public key fingerprint (\_v1.agent.jacs.<domain>.)

`jacsAgentDomain`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacsagentdomain.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsAgentDomain")

### jacsAgentDomain Type

`string`

## jacsVerificationClaim

Agent's claim about verification status. 'unverified' (default) allows relaxed DNS/TLS settings. 'verified' requires strict DNS with DNSSEC and domain must be set. 'verified-registry' requires registry verification. DEPRECATED: 'verified-hai.ai' is a deprecated alias for 'verified-registry' and will be removed in the next major version.

`jacsVerificationClaim`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agent](agent-allof-1-properties-jacsverificationclaim.md "https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsVerificationClaim")

### jacsVerificationClaim Type

`string`

### jacsVerificationClaim Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                 | Explanation |
| :-------------------- | :---------- |
| `"unverified"`        |             |
| `"verified"`          |             |
| `"verified-registry"` |             |
| `"verified-hai.ai"`   |             |

### jacsVerificationClaim Default Value

The default value is:

```json
"unverified"
```
