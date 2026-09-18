# Untitled object in Compatibility Key Binding Schema

```txt
https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/rootKey
```

The native root that signs this binding. A binding signed by a rotated-away root is superseded and must be re-issued.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [compatibility-key-binding.schema.json\*](../../schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json "open original schema") |

## rootKey Type

`object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding-properties-rootkey.md))

# rootKey Properties

| Property                | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                                                   |
| :---------------------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [algorithm](#algorithm) | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-rootkey-properties-algorithm.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/rootKey/properties/algorithm") |
| [kid](#kid)             | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-rootkey-properties-kid.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/rootKey/properties/kid")             |

## algorithm



`algorithm`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-rootkey-properties-algorithm.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/rootKey/properties/algorithm")

### algorithm Type

`string`

### algorithm Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"ring-Ed25519"` |             |
| `"pq2025"`       |             |

## kid

JACS public-key hash of the native root.

`kid`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-rootkey-properties-kid.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/rootKey/properties/kid")

### kid Type

`string`

### kid Constraints

**minimum length**: the minimum number of characters for this string is: `1`
