# README

## Top-level Schemas

*   [Action](./action.md "General actions definitions which can comprise a service") – `https://hai.ai/schemas/components/action/v1/action-schema.json`

*   [Agent](./agent.md "General schema for human, hybrid, and AI agents") – `https://hai.ai/schemas/agent/v1/agent.schema.json`

*   [Config](./jacs.md "Jacs Configuration File") – `https://hai.ai/schemas/jacs.config.schema.json`

*   [Contact](./contact.md "How to contact over human channels") – `https://hai.ai/schemas/contact/v1/contact-schema.json`

*   [File](./files.md "General data about unstructured content not in JACS") – `https://hai.ai/schemas/components/files/v1/files.schema.json`

*   [Header](./header.md "The basis for a JACS document") – `https://hai.ai/schemas/header/v1/header.schema.json`

*   [Service](./service.md "Services that an Agent claims to provide") – `https://hai.ai/schemas/service/v1/service-schema.json`

*   [Signature](./signature.md "Cryptographic signature to be embedded in other documents") – `https://hai.ai/schemas/components/signature/v1/signature.schema.json`

*   [Tool](./tool.md "OpenAI function calling definitions https://platform") – `https://hai.ai/schemas/components/tool/v1/tool-schema.json`

*   [Unit](./unit.md "Labels for quantitative values") – `https://hai.ai/schemas/components/unit/v1/unit.schema.json`

*   [agreement](./agreement.md "A set of required signatures signifying an agreement") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json`

## Other Schemas

### Objects

*   [Untitled object in Agent](./agent-allof-1.md) – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1`

*   [Untitled object in Tool](./tool-items.md) – `https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items`

*   [Untitled object in Tool](./tool-items-properties-function.md) – `https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function`

*   [Untitled object in Tool](./tool-items-properties-function-properties-parameters.md) – `https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters`

*   [Untitled object in Tool](./tool-items-properties-function-properties-parameters-properties-properties.md) – `https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties`

*   [Untitled object in Tool](./tool-items-properties-function-properties-parameters-properties-properties-patternproperties-.md) – `https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$`

### Arrays

*   [Untitled array in Action](./action-properties-tools.md "units that can be modified") – `https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/tools`

*   [Untitled array in Action](./action-properties-units.md "units that can be modified") – `https://hai.ai/schemas/components/action/v1/action-schema.json#/properties/units`

*   [Untitled array in Agent](./agent-allof-1-jacsservices.md "Services the agent can perform") – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/jacsServices`

*   [Untitled array in Agent](./agent-allof-1-jacscontacts.md "Contact information for the agent") – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/jacsContacts`

*   [Untitled array in Header](./header-properties-jacsfiles.md "A set of files included with the jacs document") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsFiles`

*   [Untitled array in Service](./service-properties-tools.md "URLs of tools that can be called") – `https://hai.ai/schemas/service/v1/service-schema.json#/properties/tools`

*   [Untitled array in Service](./service-properties-piidesired.md "Sensitive data desired") – `https://hai.ai/schemas/service/v1/service-schema.json#/properties/piiDesired`

*   [Untitled array in Signature](./signature-properties-fields.md "fields fields from document which were used to generate signature") – `https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/fields`

*   [Untitled array in Tool](./tool-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-enum.md) – `https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/enum`

*   [Untitled array in Tool](./tool-items-properties-function-properties-parameters-properties-required.md) – `https://hai.ai/schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/required`

*   [Untitled array in agreement](./agreement-properties-signatures.md "Signatures of agents") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures`

*   [Untitled array in agreement](./agreement-properties-agentids.md "The agents which are required in order to sign the document") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs`

## Version Note

The schemas linked above follow the JSON Schema Spec version: `http://json-schema.org/draft-07/schema#`
