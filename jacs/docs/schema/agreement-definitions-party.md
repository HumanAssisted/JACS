# Untitled object in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party
```

A participant in an agreement. Signer-role parties consent and are bound. Witness-role parties attest but are not bound. Notary-role parties provide notarial attestation with distinct legal weight from a witness. Observer-role parties are listed without consent or attestation.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## party Type

`object` ([Details](agreement-definitions-party.md))

# party Properties

| Property                      | Type     | Required | Nullable       | Defined by                                                                                                                                                                 |
| :---------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [agentId](#agentid)           | `string` | Required | cannot be null | [Agreement](agreement-definitions-party-properties-agentid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentId")           |
| [agentVersion](#agentversion) | `string` | Optional | cannot be null | [Agreement](agreement-definitions-party-properties-agentversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentVersion") |
| [agentType](#agenttype)       | `string` | Required | cannot be null | [Agreement](agreement-definitions-party-properties-agenttype.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentType")       |
| [role](#role)                 | `string` | Required | cannot be null | [Agreement](agreement-definitions-party-properties-role.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/role")                 |
| [displayName](#displayname)   | `string` | Optional | cannot be null | [Agreement](agreement-definitions-party-properties-displayname.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/displayName")   |

## agentId



`agentId`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-agentid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentId")

### agentId Type

`string`

### agentId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## agentVersion



`agentVersion`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-agentversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentVersion")

### agentVersion Type

`string`

### agentVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## agentType



`agentType`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-agenttype.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/agentType")

### agentType Type

`string`

### agentType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value         | Explanation |
| :------------ | :---------- |
| `"human"`     |             |
| `"human-org"` |             |
| `"hybrid"`    |             |
| `"ai"`        |             |

## role



`role`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-role.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/role")

### role Type

`string`

### role Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value        | Explanation |
| :----------- | :---------- |
| `"signer"`   |             |
| `"witness"`  |             |
| `"notary"`   |             |
| `"observer"` |             |

## displayName



`displayName`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-party-properties-displayname.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party/properties/displayName")

### displayName Type

`string`

### displayName Constraints

**maximum length**: the maximum number of characters for this string is: `256`
