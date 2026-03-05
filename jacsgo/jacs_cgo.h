#ifndef JACS_CGO_H
#define JACS_CGO_H

char* jacs_audit(const char* config_path, int recent_n);

// Attestation API (available when built with --features attestation)
char* jacs_agent_create_attestation(JacsAgentHandle handle, const char* params_json);
char* jacs_agent_verify_attestation(JacsAgentHandle handle, const char* document_key, int full);
char* jacs_agent_lift_to_attestation(JacsAgentHandle handle, const char* signed_doc_json, const char* claims_json);
char* jacs_agent_export_attestation_dsse(JacsAgentHandle handle, const char* attestation_json);

#endif
