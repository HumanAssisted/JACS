# Untitled object in Compatibility Key Binding Schema

```txt
https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [compatibility-key-binding.schema.json\*](../../schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json "open original schema") |

## publicJwk Type

`object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk.md))

# publicJwk Properties

| Property    | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                                                                                                                                                   |
| :---------- | :------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [kty](#kty) | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk-properties-kty.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk/properties/kty") |
| [crv](#crv) | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk-properties-crv.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk/properties/crv") |
| [x](#x)     | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk-properties-x.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk/properties/x")     |
| [y](#y)     | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk-properties-y.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk/properties/y")     |

## kty



`kty`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk-properties-kty.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk/properties/kty")

### kty Type

`string`

### kty Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value  | Explanation |
| :----- | :---------- |
| `"EC"` |             |

## crv



`crv`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk-properties-crv.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk/properties/crv")

### crv Type

`string`

### crv Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value     | Explanation |
| :-------- | :---------- |
| `"P-256"` |             |

## x



`x`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk-properties-x.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk/properties/x")

### x Type

`string`

### x Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## y



`y`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding-properties-compatibilitykey-properties-publicjwk-properties-y.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding/properties/compatibilityKey/properties/publicJwk/properties/y")

### y Type

`string`

### y Constraints

**minimum length**: the minimum number of characters for this string is: `1`
