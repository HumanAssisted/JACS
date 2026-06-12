# Untitled object in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink
```

Reference from this agreement to another JACS document version. User-supplied links are slim jacsId and jacsVersion refs; jacsSha256 is set on merge/branch-resolution links to bind merged content.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [agreement.schema.json\*](../../schemas/agreement/v2/agreement.schema.json "open original schema") |

## agreementLink Type

`object` ([Details](agreement-definitions-agreementlink.md))

# agreementLink Properties

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                                                                               |
| :-------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsId](#jacsid)           | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-jacsid.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsId")           |
| [jacsVersion](#jacsversion) | `string` | Required | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-jacsversion.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsVersion") |
| [jacsSha256](#jacssha256)   | `string` | Optional | cannot be null | [Agreement](agreement-definitions-agreementlink-properties-jacssha256.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsSha256")   |

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

## jacsSha256



`jacsSha256`

* is optional

* Type: `string`

* cannot be null

* defined in: [Agreement](agreement-definitions-agreementlink-properties-jacssha256.md "https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink/properties/jacsSha256")

### jacsSha256 Type

`string`

### jacsSha256 Constraints

**minimum length**: the minimum number of characters for this string is: `1`
