# Config Schema

```txt
https://hai.ai/schemas/jacs.config.schema.json
```

Jacs Configuration File

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                              |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :-------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [jacs.config.schema.json](../../schemas/jacs.config.schema.json "open original schema") |

## Config Type

`object` ([Config](jacs.md))

# Config Properties

| Property                                                                | Type     | Required | Nullable       | Defined by                                                                                                                                                |
| :---------------------------------------------------------------------- | :------- | :------- | :------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jacs\_use\_filesystem](#jacs_use_filesystem)                           | `string` | Optional | cannot be null | [Config](jacs-properties-jacs_use_filesystem.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_use_filesystem")                         |
| [jacs\_use\_security](#jacs_use_security)                               | `string` | Optional | cannot be null | [Config](jacs-properties-jacs_use_security.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_use_security")                             |
| [jacs\_data\_directory](#jacs_data_directory)                           | `string` | Required | cannot be null | [Config](jacs-properties-jacs_data_directory.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_data_directory")                         |
| [jacs\_key\_directory](#jacs_key_directory)                             | `string` | Required | cannot be null | [Config](jacs-properties-jacs_key_directory.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_key_directory")                           |
| [jacs\_agent\_private\_key\_filename](#jacs_agent_private_key_filename) | `string` | Required | cannot be null | [Config](jacs-properties-jacs_agent_private_key_filename.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_agent_private_key_filename") |
| [jacs\_agent\_public\_key\_filename](#jacs_agent_public_key_filename)   | `string` | Required | cannot be null | [Config](jacs-properties-jacs_agent_public_key_filename.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_agent_public_key_filename")   |
| [jacs\_agent\_key\_algorithm](#jacs_agent_key_algorithm)                | `string` | Required | cannot be null | [Config](jacs-properties-jacs_agent_key_algorithm.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_agent_key_algorithm")               |
| [jacs\_agent\_schema\_version](#jacs_agent_schema_version)              | `string` | Optional | cannot be null | [Config](jacs-properties-jacs_agent_schema_version.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_agent_schema_version")             |
| [jacs\_header\_schema\_version](#jacs_header_schema_version)            | `string` | Optional | cannot be null | [Config](jacs-properties-jacs_header_schema_version.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_header_schema_version")           |
| [jacs\_signature\_schema\_version](#jacs_signature_schema_version)      | `string` | Optional | cannot be null | [Config](jacs-properties-jacs_signature_schema_version.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_signature_schema_version")     |
| [jacs\_private\_key\_password](#jacs_private_key_password)              | `string` | Optional | cannot be null | [Config](jacs-properties-jacs_private_key_password.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_private_key_password")             |
| [jacs\_default\_storage](#jacs_default_storage)                         | `string` | Required | cannot be null | [Config](jacs-properties-jacs_default_storage.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_default_storage")                       |

## jacs\_use\_filesystem

write documents to the filesystem - false or 0 or 1 as string

`jacs_use_filesystem`

* is optional

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_use_filesystem.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_use_filesystem")

### jacs\_use\_filesystem Type

`string`

## jacs\_use\_security

use strict security features - false or 0 or 1 as string

`jacs_use_security`

* is optional

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_use_security.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_use_security")

### jacs\_use\_security Type

`string`

## jacs\_data\_directory

path to store documents and agents

`jacs_data_directory`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_data_directory.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_data_directory")

### jacs\_data\_directory Type

`string`

## jacs\_key\_directory

path to store keys

`jacs_key_directory`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_key_directory.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_key_directory")

### jacs\_key\_directory Type

`string`

## jacs\_agent\_private\_key\_filename

name of private key to use. Will include .enc if password is supplied.

`jacs_agent_private_key_filename`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_agent_private_key_filename.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_agent_private_key_filename")

### jacs\_agent\_private\_key\_filename Type

`string`

## jacs\_agent\_public\_key\_filename

name of public key

`jacs_agent_public_key_filename`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_agent_public_key_filename.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_agent_public_key_filename")

### jacs\_agent\_public\_key\_filename Type

`string`

## jacs\_agent\_key\_algorithm

algorithm to use for creating and using keys

`jacs_agent_key_algorithm`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_agent_key_algorithm.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_agent_key_algorithm")

### jacs\_agent\_key\_algorithm Type

`string`

### jacs\_agent\_key\_algorithm Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value            | Explanation |
| :--------------- | :---------- |
| `"RSA-PSS"`      |             |
| `"ring-Ed25519"` |             |
| `"pq-dilithium"` |             |

## jacs\_agent\_schema\_version

version number of the schema used to validate agent

`jacs_agent_schema_version`

* is optional

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_agent_schema_version.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_agent_schema_version")

### jacs\_agent\_schema\_version Type

`string`

## jacs\_header\_schema\_version

version number of the schema used to validate headers

`jacs_header_schema_version`

* is optional

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_header_schema_version.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_header_schema_version")

### jacs\_header\_schema\_version Type

`string`

## jacs\_signature\_schema\_version

version number of the schema used to validate signature

`jacs_signature_schema_version`

* is optional

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_signature_schema_version.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_signature_schema_version")

### jacs\_signature\_schema\_version Type

`string`

## jacs\_private\_key\_password

encryption password. Do not use in production and instead only keep in ENV with JACS\_AGENT\_PRIVATE\_KEY\_PASSWORD

`jacs_private_key_password`

* is optional

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_private_key_password.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_private_key_password")

### jacs\_private\_key\_password Type

`string`

## jacs\_default\_storage

default storage to use

`jacs_default_storage`

* is required

* Type: `string`

* cannot be null

* defined in: [Config](jacs-properties-jacs_default_storage.md "https://hai.ai/schemas/jacs.config.schema.json#/properties/jacs_default_storage")

### jacs\_default\_storage Type

`string`

### jacs\_default\_storage Constraints

**enum**: the value of this property must be equal to one of the following values:

| Value   | Explanation |
| :------ | :---------- |
| `"fs"`  |             |
| `"aws"` |             |
| `"hai"` |             |
