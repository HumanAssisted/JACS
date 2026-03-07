#ifndef JACS_CGO_H
#define JACS_CGO_H

char* jacs_audit(const char* config_path, int recent_n);
char* jacs_create_agent(const char* name, const char* password, const char* algorithm, const char* data_directory, const char* key_directory, const char* config_path, const char* agent_type, const char* description, const char* domain, const char* default_storage);

// A2A API
char* jacs_agent_export_agent_card(JacsAgentHandle handle);
char* jacs_agent_sign_a2a_artifact(JacsAgentHandle handle, const char* artifact_json, const char* artifact_type);
char* jacs_agent_verify_a2a_artifact(JacsAgentHandle handle, const char* wrapped_json);
char* jacs_agent_verify_a2a_artifact_with_policy(JacsAgentHandle handle, const char* wrapped_json, const char* agent_card_json, const char* policy);
char* jacs_agent_assess_a2a_agent(JacsAgentHandle handle, const char* agent_card_json, const char* policy);

// Protocol API
char* jacs_agent_build_auth_header(JacsAgentHandle handle);
char* jacs_agent_canonicalize_json(JacsAgentHandle handle, const char* json);
char* jacs_agent_sign_response(JacsAgentHandle handle, const char* payload_json);
char* jacs_agent_encode_verify_payload(JacsAgentHandle handle, const char* document);
char* jacs_agent_decode_verify_payload(JacsAgentHandle handle, const char* encoded);
char* jacs_agent_extract_document_id(JacsAgentHandle handle, const char* document);
char* jacs_agent_unwrap_signed_event(JacsAgentHandle handle, const char* event_json, const char* server_keys_json);

// Attestation API (available when built with --features attestation)
char* jacs_agent_create_attestation(JacsAgentHandle handle, const char* params_json);
char* jacs_agent_verify_attestation(JacsAgentHandle handle, const char* document_key, int full);
char* jacs_agent_lift_to_attestation(JacsAgentHandle handle, const char* signed_doc_json, const char* claims_json);
char* jacs_agent_export_attestation_dsse(JacsAgentHandle handle, const char* attestation_json);

#endif
