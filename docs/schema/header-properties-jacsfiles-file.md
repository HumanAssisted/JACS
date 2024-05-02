# File Schema

```txt
schemas/components/files/v1/files.schema.json#/properties/jacsFiles/items
```

General data about unstructured content not in JACS

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                               |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [header.schema.json\*](../../https:/hai.ai/schemas/=./schemas/header.schema.json "open original schema") |

## items Type

`object` ([File](header-properties-jacsfiles-file.md))

# items Properties

| Property              | Type      | Required | Nullable       | Defined by                                                                                                |
| :-------------------- | :-------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------- |
| [mimetype](#mimetype) | `string`  | Required | cannot be null | [File](files-properties-mimetype.md "schemas/components/files/v1/files.schema.json#/properties/mimetype") |
| [path](#path)         | `string`  | Required | cannot be null | [File](files-properties-path.md "schemas/components/files/v1/files.schema.json#/properties/path")         |
| [contents](#contents) | `string`  | Optional | cannot be null | [File](files-properties-contents.md "schemas/components/files/v1/files.schema.json#/properties/contents") |
| [embed](#embed)       | `boolean` | Required | cannot be null | [File](files-properties-embed.md "schemas/components/files/v1/files.schema.json#/properties/embed")       |
| [sha256](#sha256)     | `string`  | Optional | cannot be null | [File](files-properties-sha256.md "schemas/components/files/v1/files.schema.json#/properties/sha256")     |

## mimetype

Type of file. e.g. <https://www.iana.org/assignments/media-types/application/json>

`mimetype`

* is required

* Type: `string`

* cannot be null

* defined in: [File](files-properties-mimetype.md "schemas/components/files/v1/files.schema.json#/properties/mimetype")

### mimetype Type

`string`

## path

where can the file be found on the filesystem. For now no online. ipfs, https, etc. todo "format": "uri"

`path`

* is required

* Type: `string`

* cannot be null

* defined in: [File](files-properties-path.md "schemas/components/files/v1/files.schema.json#/properties/path")

### path Type

`string`

## contents

base64 encoded contents, possibly compressed

`contents`

* is optional

* Type: `string`

* cannot be null

* defined in: [File](files-properties-contents.md "schemas/components/files/v1/files.schema.json#/properties/contents")

### contents Type

`string`

## embed

should JACS embed the file contents?

`embed`

* is required

* Type: `boolean`

* cannot be null

* defined in: [File](files-properties-embed.md "schemas/components/files/v1/files.schema.json#/properties/embed")

### embed Type

`boolean`

## sha256

content checksum to verify contents on download.

`sha256`

* is optional

* Type: `string`

* cannot be null

* defined in: [File](files-properties-sha256.md "schemas/components/files/v1/files.schema.json#/properties/sha256")

### sha256 Type

`string`
