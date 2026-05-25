# Untitled object in Agreement Schema

```txt
https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink
```

Reference from this agreement to another JACS document version. Deliberately slim: just jacsId and jacsVersion.

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
