# README

## Top-level Schemas

* [A2A Verification Result](./a2a-verification-result.md "Cross-language schema for A2A artifact verification results") – `https://hai.ai/schemas/a2a-verification-result.schema.json`

* [Agent](./agent.md "General schema for human, hybrid, and AI agents") – `https://hai.ai/schemas/agent/v1/agent.schema.json`

* [Agreement](./agreement.md "A standalone JACS agreement document for verifiable consent to terms") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json`

* [Attestation](./attestation.md "A JACS attestation document that proves WHO did WHAT and WHY it should be trusted") – `https://hai.ai/schemas/attestation/v1/attestation.schema.json`

* [Config](./jacs.md "Jacs Configuration File") – `https://hai.ai/schemas/jacs.config.schema.json`

* [File](./files.md "General data about unstructured content not in JACS") – `https://hai.ai/schemas/components/files/v1/files.schema.json`

* [Header](./header.md "The basis for a JACS document") – `https://hai.ai/schemas/header/v1/header.schema.json`

* [Signature](./signature.md "SACRED CRYPTOGRAPHIC COMMITMENT: A signature is a permanent, irreversible cryptographic proof binding the signer to document content") – `https://hai.ai/schemas/components/signature/v1/signature.schema.json`

* [agreement](./agreement-1.md "A set of required signatures signifying an agreement") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json`

## Other Schemas

### Objects

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-verificationstatus-oneof-2.md "Signature could not be verified because the public key is not available") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/2`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-verificationstatus-oneof-2-properties-unverified.md) – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/2/properties/Unverified`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-verificationstatus-oneof-3.md "Signature verification failed - the signature is invalid") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/3`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-verificationstatus-oneof-3-properties-invalid.md) – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/VerificationStatus/oneOf/3/properties/Invalid`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-trustassessment.md "Result of assessing a remote agent's trustworthiness") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/TrustAssessment`

* [Untitled object in A2A Verification Result](./a2a-verification-result-definitions-parentverificationresult.md "Result of verifying a parent signature in a chain of custody") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/definitions/ParentVerificationResult`

* [Untitled object in Agent](./agent-allof-1.md) – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1`

* [Untitled object in Agent](./agent-allof-1-properties-jacskeyrotationproof.md "Cryptographic proof that a key rotation was authorized by the previous key holder") – `https://hai.ai/schemas/agent/v1/agent.schema.json#/allOf/1/properties/jacsKeyRotationProof`

* [Untitled object in Agreement](./agreement-allof-1.md) – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1`

* [Untitled object in Agreement](./agreement-definitions-party.md "A participant in an agreement") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/party`

* [Untitled object in Agreement](./agreement-definitions-signaturepolicy.md "Rules for when the agreement is considered complete") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy`

* [Untitled object in Agreement](./agreement-definitions-agreementsignature.md "A JACS signature over the agreement") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementSignature`

* [Untitled object in Agreement](./agreement-definitions-agreementlink.md "Reference from this agreement to another JACS document version") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/agreementLink`

* [Untitled object in Agreement](./agreement-definitions-jacsdocumentref.md "Verifiable reference to a specific signed JACS document version") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/jacsDocumentRef`

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

### Arrays

* [Untitled array in A2A Verification Result](./a2a-verification-result-properties-parentverificationresults.md "Individual verification results for each parent signature") – `https://hai.ai/schemas/a2a-verification-result.schema.json#/properties/parentVerificationResults`

* [Untitled array in Agreement](./agreement-allof-1-properties-parties.md) – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/parties`

* [Untitled array in Agreement](./agreement-definitions-signaturepolicy-properties-requiredalgorithms.md) – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/definitions/signaturePolicy/properties/requiredAlgorithms`

* [Untitled array in Agreement](./agreement-allof-1-properties-agreementsignatures.md "Consent and attestation signatures over the agreement") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/agreementSignatures`

* [Untitled array in Agreement](./agreement-allof-1-properties-transcript.md "Append-only list of JACS document references — any type of JACS-headed document (messages, statements, evidence, attachments, identity proofs)") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/transcript`

* [Untitled array in Agreement](./agreement-allof-1-properties-allpreviousversions.md "Append-only list of every prior jacsVersion of this agreement document, in chronological order") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/allPreviousVersions`

* [Untitled array in Agreement](./agreement-allof-1-properties-links.md "Links to other JACS document versions") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/links`

* [Untitled array in Agreement](./agreement-allof-1-properties-controllers.md "Agent IDs authorized to propose successor versions, append to transcript, change status, or modify parties") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/controllers`

* [Untitled array in Agreement](./agreement-allof-1-properties-owners.md "Agent IDs making soft copyright or ownership claims over this agreement document") – `https://hai.ai/schemas/agreement/v2/agreement.schema.json#/allOf/1/properties/owners`

* [Untitled array in Attestation](./attestation-properties-attestation-properties-claims.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/claims`

* [Untitled array in Attestation](./attestation-properties-attestation-properties-evidence.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/evidence`

* [Untitled array in Attestation](./attestation-properties-attestation-properties-derivation-properties-inputs.md) – `https://hai.ai/schemas/attestation/v1/attestation.schema.json#/properties/attestation/properties/derivation/properties/inputs`

* [Untitled array in Header](./header-properties-jacsfiles.md "A set of files included with the jacs document") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsFiles`

* [Untitled array in Header](./header-properties-jacsvisibility-oneof-1-properties-restricted.md "Agent IDs or roles that can access this document") – `https://hai.ai/schemas/header/v1/header.schema.json#/properties/jacsVisibility/oneOf/1/properties/restricted`

* [Untitled array in Signature](./signature-properties-fields.md "fields fields from document which were used to generate signature") – `https://hai.ai/schemas/components/signature/v1/signature.schema.json#/properties/fields`

* [Untitled array in agreement](./agreement-1-properties-signatures.md "Signatures of agents") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/signatures`

* [Untitled array in agreement](./agreement-1-properties-agentids.md "The agents which are required in order to sign the document") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/agentIDs`

* [Untitled array in agreement](./agreement-1-properties-requiredalgorithms.md "If specified, only signatures using one of these algorithms are accepted") – `https://hai.ai/schemas/components/agreement/v1/agreement.schema.json#/properties/requiredAlgorithms`

## Version Note

The schemas linked above follow the JSON Schema Spec version: `http://json-schema.org/draft-07/schema#`
