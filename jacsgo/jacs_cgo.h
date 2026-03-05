#ifndef JACS_CGO_H
#define JACS_CGO_H

char* jacs_audit(const char* config_path, int recent_n);

// A2A API
char* jacs_agent_export_agent_card(JacsAgentHandle handle);
char* jacs_agent_sign_a2a_artifact(JacsAgentHandle handle, const char* artifact_json, const char* artifact_type);
char* jacs_agent_verify_a2a_artifact(JacsAgentHandle handle, const char* wrapped_json);
char* jacs_agent_verify_a2a_artifact_with_policy(JacsAgentHandle handle, const char* wrapped_json, const char* agent_card_json, const char* policy);
char* jacs_agent_assess_a2a_agent(JacsAgentHandle handle, const char* agent_card_json, const char* policy);

// Attestation API (available when built with --features attestation)
char* jacs_agent_create_attestation(JacsAgentHandle handle, const char* params_json);
char* jacs_agent_verify_attestation(JacsAgentHandle handle, const char* document_key, int full);
char* jacs_agent_lift_to_attestation(JacsAgentHandle handle, const char* signed_doc_json, const char* claims_json);
char* jacs_agent_export_attestation_dsse(JacsAgentHandle handle, const char* attestation_json);

#endif
