# File Schema

```txt
https://hai.ai/schemas/components/files/v1/files.schema.json
```

General data about unstructured content not in JACS

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                  |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [files.schema.json](../../out/components/files/v1/files.schema.json "open original schema") |

## File Type

`object` ([File](files.md))

# File Properties

| Property              | Type      | Required | Nullable       | Defined by                                                                                                               |
| :-------------------- | :-------- | :------- | :------------- | :----------------------------------------------------------------------------------------------------------------------- |
| [mimetype](#mimetype) | `string`  | Required | cannot be null | [File](files-properties-mimetype.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/mimetype") |
| [path](#path)         | `string`  | Required | cannot be null | [File](files-properties-path.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/path")         |
| [contents](#contents) | `string`  | Optional | cannot be null | [File](files-properties-contents.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/contents") |
| [embed](#embed)       | `boolean` | Required | cannot be null | [File](files-properties-embed.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/embed")       |
| [sha256](#sha256)     | `string`  | Optional | cannot be null | [File](files-properties-sha256.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/sha256")     |

## mimetype

Type of file. e.g. <https://www.iana.org/assignments/media-types/application/json>

`mimetype`

* is required

* Type: `string`

* cannot be null

* defined in: [File](files-properties-mimetype.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/mimetype")

### mimetype Type

`string`

## path

where can the file be found on the filesystem. For now no online. ipfs, https, etc. todo "format": "uri"

`path`

* is required

* Type: `string`

* cannot be null

* defined in: [File](files-properties-path.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/path")

### path Type

`string`

## contents

base64 encoded contents, possibly compressed

`contents`

* is optional

* Type: `string`

* cannot be null

* defined in: [File](files-properties-contents.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/contents")

### contents Type

`string`

## embed

should JACS embed the file contents?

`embed`

* is required

* Type: `boolean`

* cannot be null

* defined in: [File](files-properties-embed.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/embed")

### embed Type

`boolean`

## sha256

content checksum to verify contents on download.

`sha256`

* is optional

* Type: `string`

* cannot be null

* defined in: [File](files-properties-sha256.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/sha256")

### sha256 Type

`string`
