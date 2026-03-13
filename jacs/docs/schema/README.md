# README

## Top-level Schemas

* [A2A Verification Result](./a2a-verification-result.md "Cross-language schema for A2A artifact verification results") – `https://hai.ai/schemas/a2a-verification-result.schema.json`

* [Action](./action.md "General actions definitions which can comprise a service") – `https://hai.ai/schemas/components/action/v1/action.schema.json`

* [Agent](./agent.md "General schema for human, hybrid, and AI agents") – `https://hai.ai/schemas/agent/v1/agent.schema.json`

* [Agent State Document](./agentstate.md "A signed wrapper for agent state files (memory, skills, plans, configs, hooks)") – `https://hai.ai/schemas/agentstate/v1/agentstate.schema.json`

* [Attestation](./attestation.md "A JACS attestation document that proves WHO did WHAT and WHY it should be trusted") – `https://hai.ai/schemas/attestation/v1/attestation.schema.json`

* [Commitment](./commitment.md "A shared, signed agreement between agents") – `https://hai.ai/schemas/commitment/v1/commitment.schema.json`

* [Config](./jacs.md "Jacs Configuration File") – `https://hai.ai/schemas/jacs.config.schema.json`

* [Contact](./contact.md "How to contact over human channels") – `https://hai.ai/schemas/components/contact/v1/contact.schema.json`

* [Embedding](./embedding.md "Precomputed embedding of content of a document") – `https://hai.ai/schemas/components/embedding/v1/embedding.schema.json`

* [Evaluation](./eval.md "A signed, immutable message evaluation an agent's performance on a task") – `https://hai.ai/schemas/eval/v1/eval.schema.json`

* [File](./files.md "General data about unstructured content not in JACS") – `https://hai.ai/schemas/components/files/v1/files.schema.json`

* [Header](./header.md "The basis for a JACS document") – `https://hai.ai/schemas/header/v1/header.schema.json`

* [Message](./message.md "A signed, immutable message about a task") – `https://hai.ai/schemas/message/v1/message.schema.json`

* [Node](./node.md "A a node in a finite state machine") – `https://hai.ai/schemas/node/v1/node.schema.json`

* [Program](./program.md "A signed, immutable message evaluation an agent's performance on a task") – `https://hai.ai/schemas/program/v1/program.schema.json`

* [Service](./service.md "Services that an Agent claims to provide") – `https://hai.ai/schemas/components/service/v1/service.schema.json`

* [Signature](./signature.md "SACRED CRYPTOGRAPHIC COMMITMENT: A signature is a permanent, irreversible cryptographic proof binding the signer to document content") – `https://hai.ai/schemas/components/signature/v1/signature.schema.json`

* [Task](./task.md "General schema for stateful resources") – `https://hai.ai/schemas/task/v1/task.schema.json`

* [Todo Item](./todoitem.md "An inline item within a todo list") – `https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json`

* [Todo List](./todo.md "A private, signed todo list belonging to a single agent") – `https://hai.ai/schemas/todo/v1/todo.schema.json`

* [Tool](./tool.md "OpenAI function calling definitions https://platform") – `https://hai.ai/schemas/components/tool/v1/tool.schema.json`

* [Unit](./unit.md "Labels and quantitative values") – `https://hai.ai/schemas/components/unit/v1/unit.schema.json`

* [agreement](./agreement.md "A set of required signatures signifying an agreement") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json`

## Other Schemas

### Objects

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-verificationstatus-oneof-2.md "Signature could not be verified because the public key is not available") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/2`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-verificationstatus-oneof-2-properties-unverified.md) – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/2/properties/Unverified`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-verificationstatus-oneof-3.md "Signature verification failed - the signature is invalid") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/3`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-verificationstatus-oneof-3-properties-invalid.md) – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/3/properties/Invalid`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-trustassessment.md "Result of assessing a remote agent's trustworthiness") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-parentverificationresult.md "Result of verifying a parent signature in a chain of custody") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult`

* [Untitled object in Agent](./agent-allof-1.md) – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1`

* [Untitled object in Attestation](./attestation-properties-attestation.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-subject.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-subject-properties-digests.md "Content-addressable digests of the subject") – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/subject/properties/digests`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-claims-items.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims/items`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-evidence-items.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-evidence-items-properties-digests.md "Algorithm-agile content digests of the evidence") – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/digests`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-evidence-items-properties-verifier.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence/items/properties/verifier`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-derivation.md "Transform receipt: proves what happened between inputs and output") – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-derivation-properties-inputs-items.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs/items`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-derivation-properties-inputs-items-properties-digests.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs/items/properties/digests`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-derivation-properties-transform.md "Content-addressable reference to the transformation") – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-derivation-properties-transform-properties-environment.md "Runtime parameters that affect the output") – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/transform/properties/environment`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-derivation-properties-outputdigests.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/outputDigests`

* [Untitled object in Attestation](./attestation-properties-attestation-properties-policycontext.md "Optional policy context") – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/policyContext`

* [Untitled object in Commitment](./commitment-allof-1.md) – `https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1`

* [Untitled object in Commitment](./commitment-allof-1-properties-jacscommitmentterms.md "Structured terms of the commitment (deliverable, deadline, compensation, etc") – `https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentTerms`

* [Untitled object in Commitment](./commitment-allof-1-properties-jacscommitmentrecurrence.md "Recurrence pattern for recurring commitments") – `https://hai.ai/schemas/commitment/v1/commitment.schema.json#/allOf/1/properties/jacsCommitmentRecurrence`

* [Untitled object in Config](./jacs-properties-observability.md "Observability configuration for logging, metrics, and tracing") – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability`

* [Untitled object in Config](./jacs-properties-observability-properties-logs.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs`

* [Untitled object in Config](./jacs-properties-observability-properties-logs-properties-destination-oneof-0.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/0`

* [Untitled object in Config](./jacs-properties-observability-properties-logs-properties-destination-oneof-1.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/1`

* [Untitled object in Config](./jacs-properties-observability-properties-logs-properties-destination-oneof-2.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/2`

* [Untitled object in Config](./jacs-properties-observability-properties-logs-properties-destination-oneof-2-properties-headers.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/2/properties/headers`

* [Untitled object in Config](./jacs-properties-observability-properties-logs-properties-destination-oneof-3.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/destination/oneOf/3`

* [Untitled object in Config](./jacs-properties-observability-properties-logs-properties-headers.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/logs/properties/headers`

* [Untitled object in Config](./jacs-properties-observability-properties-metrics.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics`

* [Untitled object in Config](./jacs-properties-observability-properties-metrics-properties-destination-oneof-0.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/destination/oneOf/0`

* [Untitled object in Config](./jacs-properties-observability-properties-metrics-properties-destination-oneof-0-properties-headers.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/destination/oneOf/0/properties/headers`

* [Untitled object in Config](./jacs-properties-observability-properties-metrics-properties-destination-oneof-1.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/destination/oneOf/1`

* [Untitled object in Config](./jacs-properties-observability-properties-metrics-properties-destination-oneof-1-properties-headers.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/destination/oneOf/1/properties/headers`

* [Untitled object in Config](./jacs-properties-observability-properties-metrics-properties-destination-oneof-2.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/destination/oneOf/2`

* [Untitled object in Config](./jacs-properties-observability-properties-metrics-properties-destination-oneof-3.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/destination/oneOf/3`

* [Untitled object in Config](./jacs-properties-observability-properties-metrics-properties-headers.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/metrics/properties/headers`

* [Untitled object in Config](./jacs-properties-observability-properties-tracing.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing`

* [Untitled object in Config](./jacs-properties-observability-properties-tracing-properties-sampling.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/sampling`

* [Untitled object in Config](./jacs-properties-observability-properties-tracing-properties-resource.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource`

* [Untitled object in Config](./jacs-properties-observability-properties-tracing-properties-resource-properties-attributes.md) – `https://hai.ai/schemas/jacs.config.schema.json#/properties/observability/properties/tracing/properties/resource/properties/attributes`

* [Untitled object in Header](./header-properties-jacsvisibility-oneof-1.md) – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVisibility/oneOf/1`

* [Untitled object in Message](./message-allof-1.md) – `https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1`

* [Untitled object in Message](./message-allof-1-properties-content.md "body , subject etc") – `https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/content`

* [Untitled object in Task](./task-allof-1.md) – `https://hai.ai/schemas/task/v1/task.schema.json#/allOf/1`

* [Untitled object in Todo List](./todo-allof-1.md) – `https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1`

* [Untitled object in Tool](./tool-items.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items`

* [Untitled object in Tool](./tool-items-properties-function.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function`

* [Untitled object in Tool](./tool-items-properties-function-properties-parameters.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters`

* [Untitled object in Tool](./tool-items-properties-function-properties-parameters-properties-properties.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters/properties/properties`

* [Untitled object in Tool](./tool-items-properties-function-properties-parameters-properties-properties-patternproperties-.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$`

### Arrays

* [Untitled array in A2A Verification Result](./a2a-verification-result-properties-parentverificationresults.md "Individual verification results for each parent signature") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/parentVerificationResults`

* [Untitled array in Action](./action-properties-tools.md "tools that can be utilized") – `https://hai.ai/schemas/components/action/v1/action.schema.json#/properties/tools`

* [Untitled array in Agent](./agent-allof-1-jacsservices.md "Services the agent can perform") – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/jacsServices`

* [Untitled array in Agent](./agent-allof-1-jacscontacts.md "Contact information for the agent") – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/jacsContacts`

* [Untitled array in Agent State Document](./agentstate-properties-jacsagentstatetags.md "Tags for categorization and search") – `https://hai.ai/schemas/agentstate/v1/agentstate.schema.json#/properties/jacsAgentStateTags`

* [Untitled array in Attestation](./attestation-properties-attestation-properties-claims.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims`

* [Untitled array in Attestation](./attestation-properties-attestation-properties-evidence.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence`

* [Untitled array in Attestation](./attestation-properties-attestation-properties-derivation-properties-inputs.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs`

* [Untitled array in Embedding](./embedding-properties-vector.md "the vector, does not indicate datatype or width (e") – `https://hai.ai/schemas/components/embedding/v1/embedding.schema.json#/properties/vector`

* [Untitled array in Evaluation](./eval-properties-quantifications.md "list of evaluation units, informatio labels") – `https://hai.ai/schemas/eval/v1/eval.schema.json#/properties/quantifications`

* [Untitled array in Header](./header-properties-jacsfiles.md "A set of files included with the jacs document") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsFiles`

* [Untitled array in Header](./header-properties-jacsembedding.md "A set of precalculated vector embeddings") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsEmbedding`

* [Untitled array in Header](./header-properties-jacsvisibility-oneof-1-properties-restricted.md "Agent IDs or roles that can access this document") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVisibility/oneOf/1/properties/restricted`

* [Untitled array in Message](./message-allof-1-properties-to.md "list of addressees, optional") – `https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/to`

* [Untitled array in Message](./message-allof-1-properties-from.md "list of addressees, optional") – `https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/from`

* [Untitled array in Message](./message-allof-1-properties-attachments.md "list of files") – `https://hai.ai/schemas/message/v1/message.schema.json#/allOf/1/properties/attachments`

* [Untitled array in Program](./program-allof-1-properties-activenodeids.md "task being processed, a description can be found there") – `https://hai.ai/schemas/program/v1/program.schema.json#/allOf/1/properties/activeNodeIDs`

* [Untitled array in Program](./program-allof-1-properties-changes.md "What changes were made to the plan along the way and why") – `https://hai.ai/schemas/program/v1/program.schema.json#/allOf/1/properties/changes`

* [Untitled array in Program](./program-allof-1-properties-nodes.md "list of evaluation units, informatio labels") – `https://hai.ai/schemas/program/v1/program.schema.json#/allOf/1/properties/nodes`

* [Untitled array in Service](./service-properties-tools.md "URLs and function definitions of of tools that can be called") – `https://hai.ai/schemas/components/service/v1/service.schema.json#/properties/tools`

* [Untitled array in Service](./service-properties-piidesired.md "Sensitive data desired") – `https://hai.ai/schemas/components/service/v1/service.schema.json#/properties/piiDesired`

* [Untitled array in Signature](./signature-properties-fields.md "fields fields from document which were used to generate signature") – `https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/fields`

* [Untitled array in Task](./task-allof-1-properties-jacstaskactionsdesired.md "list of actions desired, should be a subset of actions in the resources and agents when complete") – `https://hai.ai/schemas/task/v1/task.schema.json#/allOf/1/properties/jacsTaskActionsDesired`

* [Untitled array in Task](./task-allof-1-properties-jacstasksubtaskof.md "list of task ids this may be a subtask of") – `https://hai.ai/schemas/task/v1/task.schema.json#/allOf/1/properties/jacsTaskSubTaskOf`

* [Untitled array in Task](./task-allof-1-properties-jacstaskcopyof.md "list of task ids this may be a copy of") – `https://hai.ai/schemas/task/v1/task.schema.json#/allOf/1/properties/jacsTaskCopyOf`

* [Untitled array in Task](./task-allof-1-properties-jacstaskmergedtasks.md "list of task ids that have been folded into this task") – `https://hai.ai/schemas/task/v1/task.schema.json#/allOf/1/properties/jacsTaskMergedTasks`

* [Untitled array in Todo Item](./todoitem-properties-childitemids.md "UUIDs of child items (sub-goals or tasks under a goal)") – `https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/childItemIds`

* [Untitled array in Todo Item](./todoitem-properties-tags.md "Tags for categorization") – `https://hai.ai/schemas/components/todoitem/v1/todoitem.schema.json#/properties/tags`

* [Untitled array in Todo List](./todo-allof-1-properties-jacstodoitems.md "Inline items (goals and tasks) in this list") – `https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1/properties/jacsTodoItems`

* [Untitled array in Todo List](./todo-allof-1-properties-jacstodoarchiverefs.md "UUIDs of archived todo lists (previous versions or completed lists)") – `https://hai.ai/schemas/todo/v1/todo.schema.json#/allOf/1/properties/jacsTodoArchiveRefs`

* [Untitled array in Tool](./tool-items-properties-function-properties-parameters-properties-properties-patternproperties--properties-enum.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters/properties/properties/patternProperties/^.*$/properties/enum`

* [Untitled array in Tool](./tool-items-properties-function-properties-parameters-properties-required.md) – `https://hai.ai/schemas/components/tool/v1/tool.schema.json#/items/properties/function/properties/parameters/properties/required`

* [Untitled array in agreement](./agreement-properties-signatures.md "Signatures of agents") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures`

* [Untitled array in agreement](./agreement-properties-agentids.md "The agents which are required in order to sign the document") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs`

* [Untitled array in agreement](./agreement-properties-requiredalgorithms.md "If specified, only signatures using one of these algorithms are accepted") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/requiredAlgorithms`

## Version Note

The schemas linked above follow the JSON Schema Spec version: `http://json-schema.org/draft-07/schema#`
