# Untitled object in Compatibility Key Binding Schema

```txt
https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [compatibility-key-binding.schema.json\*](../../schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json "open original schema") |

## compatibilityKeyBinding Type

`object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding.md))

# compatibilityKeyBinding Properties

| Property                              | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                           |
| :------------------------------------ | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [agentId](#agentid)                   | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-agentid.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/agentId")                   |
| [rootKey](#rootkey)                   | `object` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-rootkey.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/rootKey")                   |
| [compatibilityKey](#compatibilitykey) | `object` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey") |
| [scope](#scope)                       | `array`  | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-scope.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/scope")                       |
| [issuedAt](#issuedat)                 | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-issuedat.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/issuedAt")                 |
| [expiresAt](#expiresat)               | `string` | Optional | can be null    | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-expiresat.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/expiresAt")               |

## agentId

The JACS agent this compatibility key belongs to.

`agentId`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-agentid.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/agentId")

### agentId Type

`string`

### agentId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## rootKey

The native root that signs this binding. A binding signed by a rotated-away root is superseded and must be re-issued.

`rootKey`

* is required

* Type: `object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding-properties-rootkey.md))

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-rootkey.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/rootKey")

### rootKey Type

`object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding-properties-rootkey.md))

## compatibilityKey

The ES256 ecosystem key being authorized.

`compatibilityKey`

* is required

* Type: `object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey.md))

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey")

### compatibilityKey Type

`object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey.md))

## scope

Exports this key is authorized to produce. Identity scopes are granted by default at issuance; content scopes (ap2-mandate, agreement-vc) require an explicit re-issue by the PQ root.

`scope`

* is required

* Type: `string[]`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-scope.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/scope")

### scope Type

`string[]`

### scope Constraints

**minimum number of items**: the minimum number of items for this array is: `1`

**unique items**: all items in this array must be unique. Duplicates are not allowed.

## issuedAt

Issuance instant. When multiple bindings exist for the same kid, the latest issuedAt wins.

`issuedAt`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-issuedat.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/issuedAt")

### issuedAt Type

`string`

### issuedAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")

## expiresAt

Optional expiry; an expired binding denies export. null means unbounded (acceptable for P2; revocation/status is a later phase).

`expiresAt`

* is optional

* Type: `string`

* can be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-expiresat.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/expiresAt")

### expiresAt Type

`string`

### expiresAt Constraints

**date time**: the string must be a date time string, according to [RFC 3339, section 5.6](https://tools.ietf.org/html/rfc3339 "check the specification")
