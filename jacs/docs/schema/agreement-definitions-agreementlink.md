# Untitled object in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink
```

Relationship from this agreement to another JACS document version.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## agreementLink Type

`object` ([Details](agreement-definitions-agreementlink.md))

# agreementLink Properties

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                                                                               |
| :-------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [rel](#rel)                 | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-rel.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/rel")                 |
| [jacsId](#jacsid)           | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-jacsid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsId")           |
| [jacsVersion](#jacsversion) | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-jacsversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsVersion") |
| [reason](#reason)           | `string` | Optional | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-reason.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/reason")           |

## rel



`rel`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementlink-properties-rel.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/rel")

### rel Type

`string`

### rel Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value          | Explanation |
| :------------- | :---------- |
| `"references"` |             |
| `"amends"`     |             |
| `"supersedes"` |             |
| `"terminates"` |             |
| `"renews"`     |             |

## jacsId



`jacsId`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementlink-properties-jacsid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsId")

### jacsId Type

`string`

### jacsId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## jacsVersion



`jacsVersion`

* is required

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementlink-properties-jacsversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsVersion")

### jacsVersion Type

`string`

### jacsVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## reason



`reason`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementlink-properties-reason.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/reason")

### reason Type

`string`

### reason Constraints

**maximum length**: the maximum number of characters for this string is: `1024`
