# Untitled object in File Schema

```txt
https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1
```



| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                        |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------ |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [files.schema.json\*](../../schemas/components/files/v1/files.schema.json "open original schema") |

## 1 Type

`object` ([Details](files-allof-1.md))

# 1 Properties

| Property                  | Type      | Required | Nullable       | Defined by                                                                                                                                  |
| :------------------------ | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| [mimetype](#mimetype)     | `string`  | Optional | cannot be null | [File](files-allof-1-properties-mimetype.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/mimetype")     |
| [url](#url)               | `string`  | Optional | cannot be null | [File](files-allof-1-properties-url.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/url")               |
| [contents](#contents)     | `string`  | Optional | cannot be null | [File](files-allof-1-properties-contents.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/contents")     |
| [compressed](#compressed) | `boolean` | Optional | cannot be null | [File](files-allof-1-properties-compressed.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/compressed") |
| [checksum](#checksum)     | `string`  | Optional | cannot be null | [File](files-allof-1-properties-checksum.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/checksum")     |

## mimetype

Type of file. e.g. <https://www.iana.org/assignments/media-types/application/json>

`mimetype`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [File](files-allof-1-properties-mimetype.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/mimetype")

### mimetype Type

`string`

## url

where can the file be found online. ipfs, https, etc

`url`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [File](files-allof-1-properties-url.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/url")

### url Type

`string`

## contents

base64 encoded contents, possibly compressed

`contents`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [File](files-allof-1-properties-contents.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/contents")

### contents Type

`string`

## compressed

are the base64 contents compressed?

`compressed`

*   is optional

*   Type: `boolean`

*   cannot be null

*   defined in: [File](files-allof-1-properties-compressed.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/compressed")

### compressed Type

`boolean`

## checksum

md5 or sha checksum to verify contents or download

`checksum`

*   is optional

*   Type: `string`

*   cannot be null

*   defined in: [File](files-allof-1-properties-checksum.md "https://hai.ai/schemas/components/agent/v1/file-schema.json#/allOf/1/properties/checksum")

### checksum Type

`string`
