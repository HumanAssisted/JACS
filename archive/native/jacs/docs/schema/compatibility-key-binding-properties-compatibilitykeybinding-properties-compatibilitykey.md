# Untitled object in Compatibility Key Binding Schema

```txt
https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey
```

The ES256 ecosystem key being authorized.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [compatibility-key-binding.schema.json\*](../../schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json "open original schema") |

## compatibilityKey Type

`object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey.md))

# compatibilityKey Properties

| Property                | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                                                                     |
| :---------------------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [algorithm](#algorithm) | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-algorithm.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/algorithm") |
| [kid](#kid)             | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-kid.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/kid")             |
| [publicJwk](#publicjwk) | `object` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk") |

## algorithm



`algorithm`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-algorithm.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/algorithm")

### algorithm Type

`string`

### algorithm Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value     | Explanation |
| :-------- | :---------- |
| `"ES256"` |             |

## kid

RFC 7638 JWK thumbprint (base64url SHA-256).

`kid`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-kid.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/kid")

### kid Type

`string`

### kid Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## publicJwk



`publicJwk`

* is required

* Type: `object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk.md))

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk")

### publicJwk Type

`object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk.md))
