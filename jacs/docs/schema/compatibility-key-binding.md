# Compatibility Key Binding Schema

```txt
https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json
```

PQ-root-signed binding that authorizes an ES256 ecosystem compatibility key for explicit export scopes. The trust bridge between a JACS agent's native (post-quantum) identity and W3C/JOSE ecosystems: the native\_root key signs this document, so granting or widening a scope always requires the PQ root. The binding never authorizes native JACS signing.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                                                                       |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [compatibility-key-binding.schema.json](../../schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json "open original schema") |

## Compatibility Key Binding Type

`object` ([Compatibility Key Binding](compatibility-key-binding.md))

all of

* [Header](conflict-allof-header.md "check type definition")

# Compatibility Key Binding Properties

| Property                                            | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                                   |
| :-------------------------------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsType](#jacstype)                               | `string` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-jacstype.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/jacsType")                               |
| [jacsLevel](#jacslevel)                             | `string` | Optional | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-jacslevel.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/jacsLevel")                             |
| [compatibilityKeyBinding](#compatibilitykeybinding) | `object` | Required | cannot be null | [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding") |

## jacsType

Document type discriminator.

`jacsType`

* is required

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-jacstype.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/jacsType")

### jacsType Type

`string`

### jacsType Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value                       | Explanation |
| :-------------------------- | :---------- |
| `"compatibilityKeyBinding"` |             |

## jacsLevel

Bindings are configuration: superseded by re-issue, never silently mutated.

`jacsLevel`

* is optional

* Type: `string`

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-jacslevel.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/jacsLevel")

### jacsLevel Type

`string`

### jacsLevel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value      | Explanation |
| :--------- | :---------- |
| `"config"` |             |

## compatibilityKeyBinding



`compatibilityKeyBinding`

* is required

* Type: `object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding.md))

* cannot be null

* defined in: [Compatibility Key Binding](compatibility-key-binding-properties-compatibilitykeybinding.md "https://hai.ai/schemas/compatibility-key-binding/v1/compatibility-key-binding.schema.json#/properties/compatibilityKeyBinding")

### compatibilityKeyBinding Type

`object` ([Details](compatibility-key-binding-properties-compatibilitykeybinding.md))
