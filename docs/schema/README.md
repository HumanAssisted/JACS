# README

## Top-level Schemas

*   [Agent](./agent.md "General schema for human, hybrid, and AI agents") – `https://hai.ai/schemas/agent/v1/agent-schema.json`

*   [Header](./header.md "The basis for a JACS document") – `https://hai.ai/schemas/header/v1/header.schema.json`

*   [Signature](./signature.md "Cryptographic signature to be embedded in other documents") – `https://hai.ai/schemas/components/signature/v1/signature-schema.json`

## Other Schemas

### Objects

*   [Untitled object in Agent](./agent-allof-1.md) – `https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1`

### Arrays

*   [Untitled array in Header](./header-properties-registrars.md "Signing authorities agent is registered with") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/registrars`

*   [Untitled array in Header](./header-properties-permissions.md "array of permissions") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/permissions`

*   [Untitled array in Signature](./signature-properties-fields.md "fields fields from document which were used to generate signature") – `https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/fields`

## Version Note

The schemas linked above follow the JSON Schema Spec version: `http://json-schema.org/draft-07/schema#`
