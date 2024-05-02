# README

## Top-level Schemas

* [Action](./action.md "General actions definitions which can comprise a service") – `schemas/components/action/v1/action.schema.json`

* [Action](./action-1.md "General actions definitions which can comprise a service") – `schemas/components/action/v1/action-schema.json`

* [Agent](./agent.md "General schema for human, hybrid, and AI agents") – `schemas/agent/v1/agent.schema.json`

* [Config](./jacs.md "Jacs Configuration File") – `schemas/jacs.config.schema.json`

* [Contact](./contact.md "How to contact over human channels") – `schemas/contact/v1/contact-schema.json`

* [Evaluation](./eval.md "A signed, immutable message evaluation an agent's performance on a task") – `schemas/eval/v1/eval.schema.json`

* [File](./files.md "General data about unstructured content not in JACS") – `schemas/components/files/v1/files.schema.json`

* [Header](./header.md "The basis for a JACS document") – `schemas/header/v1/header.schema.json`

* [Header](./header-1.md "The basis for a JACS document") – `schemas/header/v1/header.schema.json`

* [Message](./message.md "A signed, immutable message about a task") – `schemas/message/v1/message.schema.json`

* [Service](./service.md "Services that an Agent claims to provide") – `schemas/service/v1/service-schema.json`

* [Signature](./signature.md "Cryptographic signature to be embedded in other documents") – `schemas/components/signature/v1/signature.schema.json`

* [Task](./task.md "General schema for stateful resources") – `schemas/task/v1/task-schema.json`

* [Tool](./tool.md "OpenAI function calling definitions https://platform") – `schemas/components/tool/v1/tool-schema.json`

* [Tool](./tool-1.md "OpenAI function calling definitions https://platform") – `schemas/components/tool/v1/tool-schema.json`

* [Unit](./unit.md "Labels and quantitative values") – `schemas/components/unit/v1/unit.schema.json`

* [agreement](./agreement.md "A set of required signatures signifying an agreement") – `schemas/components/agreement/v1/agreement.schema.json`

## Other Schemas

### Objects

* [Untitled object in Agent](./agent-allof-1.md) – `schemas/agent/v1/agent.schema.json#/allOf/1`

* [Untitled object in Task](./task-allof-1.md) – `schemas/task/v1/task-schema.json#/allOf/1`

* [Untitled object in Tool](./tool-items.md) – `schemas/components/tool/v1/tool-schema.json#/items`

* [Untitled object in Tool](./tool-items-properties-function.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function`

* [Untitled object in Tool](./tool-items-properties-function-properties-parameters.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters`

* [Untitled object in Tool](./tool-items-properties-function-properties-parameters-properties-properties.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties`

* [Untitled object in Tool](./tool-items-properties-function-properties-parameters-properties-properties-patternproperties-.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$`

* [Untitled object in Tool](./tool-1-items.md) – `schemas/components/tool/v1/tool-schema.json#/items`

* [Untitled object in Tool](./tool-1-items-properties-function.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function`

* [Untitled object in Tool](./tool-1-items-properties-function-properties-parameters.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters`

* [Untitled object in Tool](./tool-1-items-properties-function-properties-parameters-properties-properties.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties`

* [Untitled object in Tool](./tool-1-items-properties-function-properties-parameters-properties-properties-patternproperties-.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$`

### Arrays

* [Untitled array in Action](./action-properties-tools.md "tools that can be utilized") – `schemas/components/action/v1/action.schema.json#/properties/tools`

* [Untitled array in Action](./action-properties-units.md "units that can be modified") – `schemas/components/action/v1/action.schema.json#/properties/units`

* [Untitled array in Action](./action-1-properties-tools.md "tools that can be utilized") – `schemas/components/action/v1/action-schema.json#/properties/tools`

* [Untitled array in Agent](./agent-allof-1-jacsservices.md "Services the agent can perform") – `schemas/agent/v1/agent.schema.json#/allOf/1/jacsServices`

* [Untitled array in Agent](./agent-allof-1-jacscontacts.md "Contact information for the agent") – `schemas/agent/v1/agent.schema.json#/allOf/1/jacsContacts`

* [Untitled array in Evaluation](./eval-properties-quantifications.md "list of evaluation units, informatio labels") – `schemas/eval/v1/eval.schema.json#/properties/quantifications`

* [Untitled array in Header](./header-properties-jacsfiles.md "A set of files included with the jacs document") – `schemas/header/v1/header.schema.json#/properties/jacsFiles`

* [Untitled array in Header](./header-1-properties-jacsfiles.md "A set of files included with the jacs document") – `schemas/header/v1/header.schema.json#/properties/jacsFiles`

* [Untitled array in Message](./message-properties-to.md "list of addressees, optional") – `schemas/message/v1/message.schema.json#/properties/to`

* [Untitled array in Message](./message-properties-attachments.md "list of files") – `schemas/message/v1/message.schema.json#/properties/attachments`

* [Untitled array in Service](./service-properties-tools.md "URLs and function definitions of of tools that can be called") – `schemas/service/v1/service-schema.json#/properties/tools`

* [Untitled array in Service](./service-properties-piidesired.md "Sensitive data desired") – `schemas/service/v1/service-schema.json#/properties/piiDesired`

* [Untitled array in Signature](./signature-properties-fields.md "fields fields from document which were used to generate signature") – `schemas/components/signature/v1/signature.schema.json#/properties/fields`

* [Untitled array in Task](./task-allof-1-properties-jacstaskactionsdesired.md "list of actions desired, should be a subset of actions in the resources and agents when complete") – `schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskActionsDesired`

* [Untitled array in Task](./task-allof-1-properties-jacstasksubtaskof.md "list of task ids this may be a subtask of") – `schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskSubTaskOf`

* [Untitled array in Task](./task-allof-1-properties-jacstaskcopyof.md "list of task ids this may be a copy of") – `schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskCopyOf`

* [Untitled array in Task](./task-allof-1-properties-jacstaskmergedtasks.md "list of task ids that have been folded into this task") – `schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskMergedTasks`

* [Untitled array in Tool](./tool-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-enum.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/enum`

* [Untitled array in Tool](./tool-items-properties-function-properties-parameters-properties-required.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/required`

* [Untitled array in Tool](./tool-1-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-enum.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/enum`

* [Untitled array in Tool](./tool-1-items-properties-function-properties-parameters-properties-required.md) – `schemas/components/tool/v1/tool-schema.json#/items/properties/function/properties/parameters/properties/required`

* [Untitled array in agreement](./agreement-properties-signatures.md "Signatures of agents") – `schemas/components/agreement/v1/agreement.schema.json#/properties/signatures`

* [Untitled array in agreement](./agreement-properties-agentids.md "The agents which are required in order to sign the document") – `schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs`

## Version Note

The schemas linked above follow the JSON Schema Spec version: `http://json-schema.org/draft-07/schema#`
