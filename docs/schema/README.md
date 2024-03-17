# README

## Top-level Schemas

*   [Agent](./agent.md "General schema for human, hybrid, and AI agents") – `https://hai.ai/schemas/agent/v1/agent-schema.json`

*   [Header](./header.md "The basis for a JACS document") – `https://hai.ai/schemas/header/v1/header-schema.json`

*   [Permission](./permission.md "Provides agents access to fields for reading, writing, signing, and amdin") – `https://hai.ai/schemas/components/permission/v1/permission-schema.json`

*   [Signature](./signature.md "Cryptographic signature to be embedded in other documents") – `https://hai.ai/schemas/components/signature/v1/signature-schema.json`

## Other Schemas

### Objects

*   [Untitled object in Agent](./agent-allof-1.md) – `https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1`

### Arrays

*   [Untitled array in Header](./header-properties-registrars.md "Signing authorities agent is registered with") – `https://hai.ai/schemas/header/v1/header-schema.json#/properties/registrars`

*   [Untitled array in Header](./header-properties-permissions.md "array of permissions") – `https://hai.ai/schemas/header/v1/header-schema.json#/properties/permissions`

*   [Untitled array in Permission](./permission-properties-fields.md "array of fields for specific permissions") – `https://hai.ai/schemas/components/permission/v1/permission-schema.json#/properties/fields`

*   [Untitled array in Permission](./permission-properties-fields-items.md) – `https://hai.ai/schemas/components/permission/v1/permission-schema.json#/properties/fields/items`

*   [Untitled array in Signature](./signature-properties-fields.md "fields fields from document were used to generate signature") – `https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/fields`

## Version Note

The schemas linked above follow the JSON Schema Spec version: `http://json-schema.org/draft-07/schema#`
