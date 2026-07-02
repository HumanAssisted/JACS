# Untitled object in Conflict Schema

```txt
https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef
```

Verifiable reference to a specific signed JACS document version.

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [conflict.schema.json\*](../../schemas/conflict/v1/conflict.schema.json "open original schema") |

## jacsDocumentRef Type

`object` ([Details](conflict-definitions-jacsdocumentref.md))

# jacsDocumentRef Properties

| Property                    | Type     | Required | Nullable       | Defined by                                                                                                                                                                               |
| :-------------------------- | :------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacsId](#jacsid)           | `string` | Required | cannot be null | [Conflict](conflict-definitions-jacsdocumentref-properties-jacsid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsId")           |
| [jacsVersion](#jacsversion) | `string` | Required | cannot be null | [Conflict](conflict-definitions-jacsdocumentref-properties-jacsversion.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsVersion") |
| [jacsSha256](#jacssha256)   | `string` | Required | cannot be null | [Conflict](conflict-definitions-jacsdocumentref-properties-jacssha256.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsSha256")   |

## jacsId



`jacsId`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-jacsdocumentref-properties-jacsid.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsId")

### jacsId Type

`string`

### jacsId Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## jacsVersion



`jacsVersion`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-jacsdocumentref-properties-jacsversion.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsVersion")

### jacsVersion Type

`string`

### jacsVersion Constraints

**UUID**: the string must be a UUID, according to [RFC 4122](https://tools.ietf.org/html/rfc4122 "check the specification")

## jacsSha256



`jacsSha256`

* is required

* Type: `string`

* cannot be null

* defined in: [Conflict](conflict-definitions-jacsdocumentref-properties-jacssha256.md "https://hai.ai/schemas/conflict/v1/conflict.schema.json#/definitions/jacsDocumentRef/properties/jacsSha256")

### jacsSha256 Type

`string`

### jacsSha256 Constraints

**minimum length**: the minimum number of characters for this string is: `1`
