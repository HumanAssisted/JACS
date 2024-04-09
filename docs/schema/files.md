# File Schema

```txt
https://hai.ai/schemas/components/files/v1/files.schema.json
```

General data about unstructured content not in JACS

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                      |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :---------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [files.schema.json](../../schemas/components/files/v1/files.schema.json "open original schema") |

## File Type

`object` ([File](files.md))

one (and only one) of

*   not

    *   [Untitled undefined type in File](files-oneof-0-not.md "check type definition")

*   not

    *   [Untitled undefined type in File](files-oneof-1-not.md "check type definition")

# File Properties

| Property                  | Type      | Required | Nullable       | Defined by                                                                                                                   |
| :------------------------ | :-------- | :------- | :------------- | :--------------------------------------------------------------------------------------------------------------------------- |
| [mimetype](#mimetype)     | `string`  | Required | cannot be null | [File](files-properties-mimetype.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/mimetype")     |
| [path](#path)             | `string`  | Optional | cannot be null | [File](files-properties-path.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/path")             |
| [contents](#contents)     | `string`  | Optional | cannot be null | [File](files-properties-contents.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/contents")     |
| [compressed](#compressed) | `boolean` | Optional | cannot be null | [File](files-properties-compressed.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/compressed") |
| [checksum](#checksum)     | `string`  | Optional | cannot be null | [File](files-properties-checksum.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/checksum")     |

## mimetype

Type of file. e.g. <https://www.iana.org/assignments/media-types/application/json>

`mimetype`

*   is required

*   Type: `string`

*   cannot be null

*   defined in: [File](files-properties-mimetype.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/mimetype")

### mimetype Type

`string`

## path

where can the file be found on the filesystem, online. ipfs, https, etc

`path`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [File](files-properties-path.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/path")

### path Type

`string`

## contents

base64 encoded contents, possibly compressed

`contents`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [File](files-properties-contents.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/contents")

### contents Type

`string`

## compressed

are the base64 contents compressed?

`compressed`

*   is optional

*   Type: `boolean`

*   cannot be null

*   defined in: [File](files-properties-compressed.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/compressed")

### compressed Type

`boolean`

## checksum

sha checksum to verify contents on download

`checksum`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [File](files-properties-checksum.md "https://hai.ai/schemas/components/files/v1/files.schema.json#/properties/checksum")

### checksum Type

`string`
