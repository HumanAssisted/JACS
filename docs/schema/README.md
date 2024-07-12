# README

## Top-level Schemas

*   [Action](./action.md "General actions definitions which can comprise a service") – `https://hai.ai/schemas/components/action/v1/action.schema.json`

*   [Agent](./agent.md "General schema for human, hybrid, and AI agents") – `https://hai.ai/schemas/agent/v1/agent.schema.json`

*   [Config](./jacs.md "Jacs Configuration File") – `https://hai.ai/schemas/jacs.config.schema.json`

*   [Contact](./contact.md "How to contact over human channels") – `https://hai.ai/schemas/contact/v1/contact.schema.json`

*   [Embedding](./embedding.md "Precomputed embedding of content of a document") – `https://hai.ai/schemas/components/embedding/v1/embedding.schema.json`

*   [Evaluation](./eval.md "A signed, immutable message evaluation an agent's performance on a task") – `https://hai.ai/schemas/eval/v1/eval.schema.json`

*   [File](./files.md "General data about unstructured content not in JACS") – `https://hai.ai/schemas/components/files/v1/files.schema.json`

*   [Header](./header.md "The basis for a JACS document") – `https://hai.ai/schemas/header/v1/header.schema.json`

*   [Message](./message.md "A signed, immutable message about a task") – `https://hai.ai/schemas/message/v1/message.schema.json`

*   [Node](./node.md "A a node in a finite state machine") – `https://hai.ai/schemas/node/v1/node.schema.json`

*   [Program](./program.md "A signed, immutable message evaluation an agent's performance on a task") – `https://hai.ai/schemas/program/v1/eval.program.json`

*   [Service](./service.md "Services that an Agent claims to provide") – `https://hai.ai/schemas/service/v1/service.schema.json`

*   [Signature](./signature.md "Cryptographic signature to be embedded in other documents") – `https://hai.ai/schemas/components/signature/v1/signature.schema.json`

*   [Task](./task.md "General schema for stateful resources") – `https://hai.ai/schemas/task/v1/task-schema.json`

*   [Tool](./tool.md "OpenAI function calling definitions https://platform") – `https://hai.ai/schemas/components/tool/v1/tool.schema.json`

*   [Unit](./unit.md "Labels and quantitative values") – `https://hai.ai/schemas/components/unit/v1/unit.schema.json`

*   [agreement](./agreement.md "A set of required signatures signifying an agreement") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json`

## Other Schemas

### Objects

*   [Untitled object in Agent](./agent-allof-1.md) – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1`

*   [Untitled object in Task](./task-allof-1.md) – `https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1`

*   [Untitled object in Tool](./tool-items.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items`

*   [Untitled object in Tool](./tool-items-properties-function.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function`

*   [Untitled object in Tool](./tool-items-properties-function-properties-parameters.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters`

*   [Untitled object in Tool](./tool-items-properties-function-properties-parameters-properties-properties.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters/properties/properties`

*   [Untitled object in Tool](./tool-items-properties-function-properties-parameters-properties-properties-patternproperties-.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$`

### Arrays

*   [Untitled array in Action](./action-properties-tools.md "tools that can be utilized") – `https://hai.ai/schemas/components/action/v1/action.schema.json#/properties/tools`

*   [Untitled array in Agent](./agent-allof-1-jacsservices.md "Services the agent can perform") – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/jacsServices`

*   [Untitled array in Agent](./agent-allof-1-jacscontacts.md "Contact information for the agent") – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/jacsContacts`

*   [Untitled array in Embedding](./embedding-properties-vector.md "the vector, does not indicate datatype or width (e") – `https://hai.ai/schemas/components/embedding/v1/embedding.schema.json#/properties/vector`

*   [Untitled array in Evaluation](./eval-properties-quantifications.md "list of evaluation units, informatio labels") – `https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/quantifications`

*   [Untitled array in Header](./header-properties-jacsfiles.md "A set of files included with the jacs document") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsFiles`

*   [Untitled array in Header](./header-properties-jacsembedding.md "A set of precalculated vector embeddings") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsEmbedding`

*   [Untitled array in Message](./message-properties-to.md "list of addressees, optional") – `https://hai.ai/schemas/message/v1/message.schema.json#/properties/to`

*   [Untitled array in Message](./message-properties-attachments.md "list of files") – `https://hai.ai/schemas/message/v1/message.schema.json#/properties/attachments`

*   [Untitled array in Program](./program-allof-1-properties-activenodeids.md "task being processed, a description can be found there") – `https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/activeNodeIDs`

*   [Untitled array in Program](./program-allof-1-properties-changes.md "What changes were made to the plan along the way and why") – `https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/changes`

*   [Untitled array in Program](./program-allof-1-properties-nodes.md "list of evaluation units, informatio labels") – `https://hai.ai/schemas/program/v1/eval.program.json#/allOf/1/properties/nodes`

*   [Untitled array in Service](./service-properties-tools.md "URLs and function definitions of of tools that can be called") – `https://hai.ai/schemas/service/v1/service.schema.json#/properties/tools`

*   [Untitled array in Service](./service-properties-piidesired.md "Sensitive data desired") – `https://hai.ai/schemas/service/v1/service.schema.json#/properties/piiDesired`

*   [Untitled array in Signature](./signature-properties-fields.md "fields fields from document which were used to generate signature") – `https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/fields`

*   [Untitled array in Task](./task-allof-1-properties-jacstaskactionsdesired.md "list of actions desired, should be a subset of actions in the resources and agents when complete") – `https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskActionsDesired`

*   [Untitled array in Task](./task-allof-1-properties-jacstasksubtaskof.md "list of task ids this may be a subtask of") – `https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskSubTaskOf`

*   [Untitled array in Task](./task-allof-1-properties-jacstaskcopyof.md "list of task ids this may be a copy of") – `https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskCopyOf`

*   [Untitled array in Task](./task-allof-1-properties-jacstaskmergedtasks.md "list of task ids that have been folded into this task") – `https://hai.ai/schemas/task/v1/task-schema.json#/allOf/1/properties/jacsTaskMergedTasks`

*   [Untitled array in Tool](./tool-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-enum.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/enum`

*   [Untitled array in Tool](./tool-items-properties-function-properties-parameters-properties-required.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters/properties/required`

*   [Untitled array in agreement](./agreement-properties-signatures.md "Signatures of agents") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures`

*   [Untitled array in agreement](./agreement-properties-agentids.md "The agents which are required in order to sign the document") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs`

## Version Note

The schemas linked above follow the JSON Schema Spec version: `http://json-schema.org/draft-07/schema#`
