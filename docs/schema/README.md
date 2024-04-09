# README

## Top-level Schemas

*   [Agent](./agent.md "General schema for human, hybrid, and AI agents") – `https://hai.ai/schemas/agent/v1/agent-schema.json`

*   [Config](./jacs.md "Jacs Configuration File") – `https://hai.ai/schemas/jacs.config.schema.json`

*   [File](./files.md "General data about unstructured content not in JACS") – `https://hai.ai/schemas/components/files/v1/files.schema.json`

*   [Header](./header.md "The basis for a JACS document") – `https://hai.ai/schemas/header/v1/header.schema.json`

*   [Signature](./signature.md "Cryptographic signature to be embedded in other documents") – `https://hai.ai/schemas/components/signature/v1/signature-schema.json`

## Other Schemas

### Objects

*   [Untitled object in Agent](./agent-allof-1.md) – `https://hai.ai/schemas/agent/v1/agent-schema.json#/allOf/1`

### Arrays

*   [Untitled array in Header](./header-properties-files.md "A set of files included with the jacs document") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/files`

*   [Untitled array in Signature](./signature-properties-fields.md "fields fields from document which were used to generate signature") – `https://hai.ai/schemas/components/signature/v1/signature-schema.json#/properties/fields`

## Version Note

The schemas linked above follow the JSON Schema Spec version: `http://json-schema.org/draft-07/schema#`
