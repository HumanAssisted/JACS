package jacs

/*
#cgo CFLAGS: -I${SRCDIR}/build
#cgo darwin LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build
#cgo linux LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build

#include <stdlib.h>
#include <stdint.h>

// JacsAgent handle API - Recommended for concurrent usage
#include "jacs_cgo.h"
JacsAgentHandle jacs_agent_new();
void jacs_agent_free(JacsAgentHandle handle);
int jacs_agent_load(JacsAgentHandle handle, const char* config_path);
char* jacs_agent_sign_string(JacsAgentHandle handle, const char* data);
int jacs_agent_verify_string(JacsAgentHandle handle, const char* data, const char* signature_base64, const uint8_t* public_key, size_t public_key_len, const char* public_key_enc_type);
char* jacs_agent_sign_request(JacsAgentHandle handle, const char* payload_json);
char* jacs_agent_verify_response(JacsAgentHandle handle, const char* document_string);
char* jacs_agent_create_agreement(JacsAgentHandle handle, const char* document_string, const char* agentids_json, const char* question, const char* context, const char* agreement_fieldname);
char* jacs_agent_sign_agreement(JacsAgentHandle handle, const char* document_string, const char* agreement_fieldname);
char* jacs_agent_check_agreement(JacsAgentHandle handle, const char* document_string, const char* agreement_fieldname);
int jacs_agent_verify_agent(JacsAgentHandle handle, const char* agentfile);
char* jacs_agent_create_document(JacsAgentHandle handle, const char* document_string, const char* custom_schema, const char* outputfilename, int no_save, const char* attachments, int embed);
int jacs_agent_verify_document(JacsAgentHandle handle, const char* document_string);
int jacs_agent_verify_document_by_id(JacsAgentHandle handle, const char* document_id);
int jacs_agent_reencrypt_key(JacsAgentHandle handle, const char* old_password, const char* new_password);
char* jacs_agent_get_json(JacsAgentHandle handle);
char* jacs_agent_get_public_key_pem(JacsAgentHandle handle);

// Legacy global singleton API - Deprecated, use JacsAgent instead
int jacs_load(const char* config_path);
void jacs_free_string(char* s);
char* jacs_sign_string(const char* data);
char* jacs_hash_string(const char* data);
int jacs_verify_string(const char* data, const char* signature_base64, const uint8_t* public_key, size_t public_key_len, const char* public_key_enc_type);
char* jacs_sign_agent(const char* agent_string, const uint8_t* public_key, size_t public_key_len, const char* public_key_enc_type);
char* jacs_create_config(const char* jacs_use_security, const char* jacs_data_directory, const char* jacs_key_directory, const char* jacs_agent_private_key_filename, const char* jacs_agent_public_key_filename, const char* jacs_agent_key_algorithm, const char* jacs_private_key_password, const char* jacs_agent_id_and_version, const char* jacs_default_storage);
char* jacs_create_agent(const char* name, const char* password, const char* algorithm, const char* data_directory, const char* key_directory, const char* config_path, const char* agent_type, const char* description, const char* domain, const char* default_storage);
int jacs_verify_agent(const char* agentfile);
char* jacs_update_agent(const char* new_agent_string);
int jacs_verify_document(const char* document_string);
char* jacs_update_document(const char* document_key, const char* new_document_string, const char* attachments_json, int embed);
char* jacs_create_document(const char* document_string, const char* custom_schema, const char* outputfilename, int no_save, const char* attachments, int embed);
char* jacs_create_agreement(const char* document_string, const char* agentids_json, const char* question, const char* context, const char* agreement_fieldname);
char* jacs_sign_agreement(const char* document_string, const char* agreement_fieldname);
char* jacs_check_agreement(const char* document_string, const char* agreement_fieldname);
char* jacs_sign_request(const char* payload_json);
char* jacs_verify_response(const char* document_string);
char* jacs_verify_response_with_agent_id(const char* document_string, char** agent_id_out);
int jacs_verify_signature(const char* document_string, const char* signature_field);
char* jacs_verify_document_standalone(const char* signed_document, const char* key_resolution, const char* data_directory, const char* key_directory);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// JACSError represents errors returned by JACS operations
type JACSError struct {
	Code    int
	Message string
}

func (e JACSError) Error() string {
	return fmt.Sprintf("JACS error %d: %s", e.Code, e.Message)
}

// goStringResult collapses the common `*C.char` success tail: on a nil
// result it returns errIfNil (preserving each caller's fixed error
// message); otherwise it frees the C string and returns its Go copy.
func goStringResult(result *C.char, errIfNil error) (string, error) {
	if result == nil {
		return "", errIfNil
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}

// Config represents JACS configuration options
type Config struct {
	UseSecurity         *string `json:"jacs_use_security,omitempty"`
	DataDirectory       *string `json:"jacs_data_directory,omitempty"`
	KeyDirectory        *string `json:"jacs_key_directory,omitempty"`
	AgentPrivateKeyFile *string `json:"jacs_agent_private_key_filename,omitempty"`
	AgentPublicKeyFile  *string `json:"jacs_agent_public_key_filename,omitempty"`
	AgentKeyAlgorithm   *string `json:"jacs_agent_key_algorithm,omitempty"`
	PrivateKeyPassword  *string `json:"jacs_private_key_password,omitempty"`
	AgentIDAndVersion   *string `json:"jacs_agent_id_and_version,omitempty"`
	DefaultStorage      *string `json:"jacs_default_storage,omitempty"`
}

// ============================================================================
// JacsAgent - Recommended API for concurrent usage
// ============================================================================
// Each JacsAgent instance has independent state, allowing multiple agents to
// be used concurrently in the same process. This is the recommended API.

// JacsAgent represents a JACS agent instance with independent state.
// Multiple JacsAgent instances can be used concurrently.
type JacsAgent struct {
	mu     sync.RWMutex
	handle C.JacsAgentHandle
}

// NewJacsAgent creates a new JacsAgent instance.
// Call Close() when done to free resources.
func NewJacsAgent() (*JacsAgent, error) {
	handle := C.jacs_agent_new()
	if handle == nil {
		return nil, errors.New("failed to create JacsAgent")
	}
	return &JacsAgent{handle: handle}, nil
}

// Close releases the resources associated with this JacsAgent.
// After Close, the JacsAgent must not be used.
func (a *JacsAgent) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.handle != nil {
		C.jacs_agent_free(a.handle)
		a.handle = nil
	}
}

// Load initializes this agent with the given configuration file.
func (a *JacsAgent) Load(configPath string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return errAgentClosed
	}

	cPath, freePath := cString(configPath)
	defer freePath()

	result := C.jacs_agent_load(a.handle, cPath)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "load")}
	}
	return nil
}

// SignString signs a string using this agent's private key.
func (a *JacsAgent) SignString(data string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cData, freeData := cString(data)
	defer freeData()

	return goStringResult(C.jacs_agent_sign_string(a.handle, cData), errors.New("failed to sign string"))
}

// VerifyString verifies a string signature using this agent.
func (a *JacsAgent) VerifyString(data, signatureBase64 string, publicKey []byte, publicKeyEncType string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return errAgentClosed
	}

	cData, freeData := cString(data)
	defer freeData()

	cSig, freeSig := cString(signatureBase64)
	defer freeSig()

	cEncType, freeEncType := cString(publicKeyEncType)
	defer freeEncType()

	var cPubKey *C.uint8_t
	if len(publicKey) > 0 {
		cPubKey = (*C.uint8_t)(unsafe.Pointer(&publicKey[0]))
	}

	result := C.jacs_agent_verify_string(a.handle, cData, cSig, cPubKey, C.size_t(len(publicKey)), cEncType)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "verify_string")}
	}
	return nil
}

// SignRequest signs a request payload (wraps in a JACS document).
func (a *JacsAgent) SignRequest(payload interface{}) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	cPayload, freePayload := cString(string(payloadJSON))
	defer freePayload()

	return goStringResult(C.jacs_agent_sign_request(a.handle, cPayload), errors.New("failed to sign request"))
}

// VerifyResponse verifies a response payload.
func (a *JacsAgent) VerifyResponse(documentString string) (map[string]interface{}, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return nil, errAgentClosed
	}

	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	result := C.jacs_agent_verify_response(a.handle, cDoc)
	if result == nil {
		return nil, errors.New("failed to verify response")
	}
	defer C.jacs_free_string(result)

	resultStr := C.GoString(result)
	var payload map[string]interface{}
	err := json.Unmarshal([]byte(resultStr), &payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// CreateAgreement creates an agreement for a document.
func (a *JacsAgent) CreateAgreement(documentString string, agentIDs []string, question, context, agreementFieldname *string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	agentIDsJSON, err := json.Marshal(agentIDs)
	if err != nil {
		return "", err
	}
	cAgentIDs, freeAgentIDs := cString(string(agentIDsJSON))
	defer freeAgentIDs()

	cQuestion, freeQuestion := cStringOpt(question)
	defer freeQuestion()
	cContext, freeContext := cStringOpt(context)
	defer freeContext()
	cFieldname, freeFieldname := cStringOpt(agreementFieldname)
	defer freeFieldname()

	return goStringResult(C.jacs_agent_create_agreement(a.handle, cDoc, cAgentIDs, cQuestion, cContext, cFieldname), errors.New("failed to create agreement"))
}

// SignAgreement signs an agreement.
func (a *JacsAgent) SignAgreement(documentString string, agreementFieldname *string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	cFieldname, freeFieldname := cStringOpt(agreementFieldname)
	defer freeFieldname()

	return goStringResult(C.jacs_agent_sign_agreement(a.handle, cDoc, cFieldname), errors.New("failed to sign agreement"))
}

// CheckAgreement checks an agreement.
func (a *JacsAgent) CheckAgreement(documentString string, agreementFieldname *string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	cFieldname, freeFieldname := cStringOpt(agreementFieldname)
	defer freeFieldname()

	return goStringResult(C.jacs_agent_check_agreement(a.handle, cDoc, cFieldname), errors.New("failed to check agreement"))
}

// VerifyAgent verifies an agent's signature and hash.
func (a *JacsAgent) VerifyAgent(agentFile *string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return errAgentClosed
	}

	cFile, freeFile := cStringOpt(agentFile)
	defer freeFile()

	result := C.jacs_agent_verify_agent(a.handle, cFile)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "verify_agent")}
	}
	return nil
}

// CreateDocument creates a new JACS document.
func (a *JacsAgent) CreateDocument(documentString string, customSchema, outputFilename *string, noSave bool, attachments *string, embed *bool) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	cSchema, freeSchema := cStringOpt(customSchema)
	defer freeSchema()
	cOutput, freeOutput := cStringOpt(outputFilename)
	defer freeOutput()
	cAttach, freeAttach := cStringOpt(attachments)
	defer freeAttach()

	noSaveVal := C.int(0)
	if noSave {
		noSaveVal = 1
	}

	embedVal := C.int(0)
	if embed != nil {
		if *embed {
			embedVal = 1
		} else {
			embedVal = -1
		}
	}

	return goStringResult(C.jacs_agent_create_document(a.handle, cDoc, cSchema, cOutput, noSaveVal, cAttach, embedVal), errors.New("failed to create document"))
}

// VerifyDocument verifies a document's hash and signature.
func (a *JacsAgent) VerifyDocument(documentString string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return errAgentClosed
	}

	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	result := C.jacs_agent_verify_document(a.handle, cDoc)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "verify_document")}
	}
	return nil
}

// VerifyDocumentById verifies a document by its storage ID ("uuid:version" format).
func (a *JacsAgent) VerifyDocumentById(documentID string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return errAgentClosed
	}

	cDocID, freeDocID := cString(documentID)
	defer freeDocID()

	result := C.jacs_agent_verify_document_by_id(a.handle, cDocID)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "verify_document_by_id")}
	}
	return nil
}

// ReencryptKey re-encrypts the agent's private key with a new password.
func (a *JacsAgent) ReencryptKey(oldPassword, newPassword string) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return errAgentClosed
	}

	cOldPw, freeOldPw := cString(oldPassword)
	defer freeOldPw()

	cNewPw, freeNewPw := cString(newPassword)
	defer freeNewPw()

	result := C.jacs_agent_reencrypt_key(a.handle, cOldPw, cNewPw)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "reencrypt_key")}
	}
	return nil
}

// GetJSON returns the agent's JSON representation.
func (a *JacsAgent) GetJSON() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	return goStringResult(C.jacs_agent_get_json(a.handle), errors.New("failed to get agent JSON (agent may not be loaded)"))
}

// GetPublicKeyPEM returns the agent's public key in PEM format.
func (a *JacsAgent) GetPublicKeyPEM() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	return goStringResult(C.jacs_agent_get_public_key_pem(a.handle), errors.New("failed to get public key PEM"))
}

// CreateAttestation creates a signed attestation document.
// paramsJSON is a JSON string with subject, claims, and optional evidence/derivation/policyContext.
// Returns the signed attestation document as a JSON string.
// Requires the library to be built with the attestation feature.
func (a *JacsAgent) CreateAttestation(paramsJSON string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cParams, freeParams := cString(paramsJSON)
	defer freeParams()

	return goStringResult(C.jacs_agent_create_attestation(a.handle, cParams), errors.New("failed to create attestation (feature may not be available)"))
}

// VerifyAttestation verifies an attestation document.
// documentKey is in "jacsId:jacsVersion" format.
// If full is true, performs full-tier verification (evidence + chain checks).
// If full is false, performs local-tier verification (signature + hash only).
// Returns the verification result as a JSON string.
func (a *JacsAgent) VerifyAttestation(documentKey string, full bool) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cKey, freeKey := cString(documentKey)
	defer freeKey()

	fullVal := C.int(0)
	if full {
		fullVal = 1
	}

	return goStringResult(C.jacs_agent_verify_attestation(a.handle, cKey, fullVal), errors.New("failed to verify attestation (feature may not be available)"))
}

// LiftToAttestation lifts an existing signed document into an attestation with additional claims.
// signedDocJSON is the signed JACS document JSON string.
// claimsJSON is a JSON array of claim objects.
// Returns the new attestation document as a JSON string.
func (a *JacsAgent) LiftToAttestation(signedDocJSON, claimsJSON string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cDoc, freeDoc := cString(signedDocJSON)
	defer freeDoc()

	cClaims, freeClaims := cString(claimsJSON)
	defer freeClaims()

	return goStringResult(C.jacs_agent_lift_to_attestation(a.handle, cDoc, cClaims), errors.New("failed to lift to attestation (feature may not be available)"))
}

// ExportAttestationDSSE exports an attestation as a DSSE (Dead Simple Signing Envelope)
// for in-toto/SLSA/Sigstore compatibility.
// attestationJSON is the attestation document JSON string.
// Returns the DSSE envelope as a JSON string.
func (a *JacsAgent) ExportAttestationDSSE(attestationJSON string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cAtt, freeAtt := cString(attestationJSON)
	defer freeAtt()

	return goStringResult(C.jacs_agent_export_attestation_dsse(a.handle, cAtt), errors.New("failed to export attestation DSSE (feature may not be available)"))
}

// ============================================================================
// A2A API - Agent-to-Agent protocol operations
// ============================================================================

// ExportAgentCard exports an A2A Agent Card for this agent.
func (a *JacsAgent) ExportAgentCard() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	return goStringResult(C.jacs_agent_export_agent_card(a.handle), errors.New("failed to export agent card"))
}

// SignA2AArtifact wraps an artifact with a JACS signature for A2A exchange.
func (a *JacsAgent) SignA2AArtifact(artifactJSON string, artifactType string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cArtifact, freeArtifact := cString(artifactJSON)
	defer freeArtifact()

	cType, freeType := cString(artifactType)
	defer freeType()

	return goStringResult(C.jacs_agent_sign_a2a_artifact(a.handle, cArtifact, cType), errors.New("failed to sign A2A artifact"))
}

// VerifyA2AArtifact verifies a JACS-wrapped A2A artifact (crypto-only).
func (a *JacsAgent) VerifyA2AArtifact(wrappedJSON string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cWrapped, freeWrapped := cString(wrappedJSON)
	defer freeWrapped()

	return goStringResult(C.jacs_agent_verify_a2a_artifact(a.handle, cWrapped), errors.New("failed to verify A2A artifact"))
}

// VerifyA2AArtifactWithPolicy verifies a JACS-wrapped artifact with trust policy.
func (a *JacsAgent) VerifyA2AArtifactWithPolicy(wrappedJSON, agentCardJSON, policy string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cWrapped, freeWrapped := cString(wrappedJSON)
	defer freeWrapped()

	cCard, freeCard := cString(agentCardJSON)
	defer freeCard()

	cPolicy, freePolicy := cString(policy)
	defer freePolicy()

	return goStringResult(C.jacs_agent_verify_a2a_artifact_with_policy(a.handle, cWrapped, cCard, cPolicy), errors.New("failed to verify A2A artifact with policy"))
}

// AssessA2AAgent assesses an agent's trustworthiness against a trust policy.
func (a *JacsAgent) AssessA2AAgent(agentCardJSON, policy string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cCard, freeCard := cString(agentCardJSON)
	defer freeCard()

	cPolicy, freePolicy := cString(policy)
	defer freePolicy()

	return goStringResult(C.jacs_agent_assess_a2a_agent(a.handle, cCard, cPolicy), errors.New("failed to assess A2A agent"))
}

// ============================================================================
// Protocol API - auth headers, canonicalization, signing, verification links
// ============================================================================

// BuildAuthHeader builds an Authorization header value for this agent.
// Returns the header value string (e.g. for use in HTTP Authorization headers).
func (a *JacsAgent) BuildAuthHeader() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	return goStringResult(C.jacs_agent_build_auth_header(a.handle), errors.New("failed to build auth header"))
}

// CanonicalizeJson canonicalizes a JSON string using RFC 8785 (JCS).
// Returns the canonicalized JSON string.
func (a *JacsAgent) CanonicalizeJson(jsonStr string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cJSON, freeJSON := cString(jsonStr)
	defer freeJSON()

	return goStringResult(C.jacs_agent_canonicalize_json(a.handle, cJSON), errors.New("failed to canonicalize JSON"))
}

// SignResponse signs a response payload (wraps in a JACS document via the protocol layer).
// payloadJson is the JSON string of the payload to sign.
// Returns the signed response as a JSON string.
func (a *JacsAgent) SignResponse(payloadJson string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cPayload, freePayload := cString(payloadJson)
	defer freePayload()

	return goStringResult(C.jacs_agent_sign_response(a.handle, cPayload), errors.New("failed to sign response"))
}

// GenerateVerifyLink generates a verification link for a signed document.
// EncodeVerifyPayload encodes a document as URL-safe base64 (no padding) for verification.
func (a *JacsAgent) EncodeVerifyPayload(document string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cDoc, freeDoc := cString(document)
	defer freeDoc()

	return goStringResult(C.jacs_agent_encode_verify_payload(a.handle, cDoc), errors.New("failed to encode verify payload"))
}

// DecodeVerifyPayload decodes a URL-safe base64 verification payload back to the original document.
func (a *JacsAgent) DecodeVerifyPayload(encoded string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cEncoded, freeEncoded := cString(encoded)
	defer freeEncoded()

	return goStringResult(C.jacs_agent_decode_verify_payload(a.handle, cEncoded), errors.New("failed to decode verify payload"))
}

// ExtractDocumentId extracts the document ID from a JACS-signed document.
// Checks jacsDocumentId, document_id, id in priority order.
func (a *JacsAgent) ExtractDocumentId(document string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cDoc, freeDoc := cString(document)
	defer freeDoc()

	return goStringResult(C.jacs_agent_extract_document_id(a.handle, cDoc), errors.New("failed to extract document ID"))
}

// UnwrapSignedEvent unwraps and verifies a signed event using the agent and server keys.
// eventJson is the signed event JSON string.
// serverKeysJson is the server public keys JSON string.
// Returns the unwrapped event payload as a JSON string.
func (a *JacsAgent) UnwrapSignedEvent(eventJson, serverKeysJson string) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errAgentClosed
	}

	cEvent, freeEvent := cString(eventJson)
	defer freeEvent()

	cKeys, freeKeys := cString(serverKeysJson)
	defer freeKeys()

	return goStringResult(C.jacs_agent_unwrap_signed_event(a.handle, cEvent, cKeys), errors.New("failed to unwrap signed event"))
}

// Helper function to get error messages for JacsAgent methods
func getAgentErrorMessage(code int, operation string) string {
	switch operation {
	case "load":
		switch code {
		case -1:
			return "null handle or config path"
		case -2:
			return "invalid UTF-8 in config path"
		case -3:
			return "failed to acquire agent lock"
		case -4:
			return "failed to load agent config"
		default:
			return "unknown error"
		}
	case "verify_string":
		switch code {
		case -1:
			return "null parameter"
		case -2:
			return "invalid data string"
		case -3:
			return "invalid signature string"
		case -4:
			return "invalid encryption type string"
		case -5:
			return "failed to acquire agent lock"
		case -6:
			return "signature verification failed"
		default:
			return "unknown error"
		}
	case "verify_agent":
		switch code {
		case -1:
			return "null handle"
		case -2:
			return "failed to acquire agent lock"
		case -3:
			return "invalid agent file path"
		case -4:
			return "failed to load agent from file"
		case -5:
			return "signature verification failed"
		case -6:
			return "hash verification failed"
		default:
			return "unknown error"
		}
	case "verify_document":
		switch code {
		case -1:
			return "null handle or document string"
		case -2:
			return "invalid document string"
		case -3:
			return "failed to acquire agent lock"
		case -4:
			return "failed to load document"
		case -5:
			return "hash verification failed"
		case -6:
			return "signature verification failed"
		default:
			return "unknown error"
		}
	case "verify_document_by_id":
		switch code {
		case -1:
			return "null handle or document ID"
		case -2:
			return "invalid UTF-8 in document ID"
		case -3:
			return "invalid document ID format (expected 'uuid:version')"
		case -4:
			return "failed to initialize storage"
		case -5:
			return "document not found in storage"
		case -6:
			return "failed to serialize document"
		case -7:
			return "failed to acquire agent lock"
		case -8:
			return "failed to load document"
		case -9:
			return "hash verification failed"
		case -10:
			return "signature verification failed"
		default:
			return "unknown error"
		}
	case "reencrypt_key":
		switch code {
		case -1:
			return "null handle or password"
		case -2:
			return "invalid UTF-8 in old password"
		case -3:
			return "invalid UTF-8 in new password"
		case -4:
			return "failed to acquire agent lock"
		case -5:
			return "failed to read private key file"
		case -6:
			return "re-encryption failed (wrong old password or weak new password)"
		case -7:
			return "failed to write re-encrypted key"
		default:
			return "unknown error"
		}
	default:
		return fmt.Sprintf("operation failed with code %d", code)
	}
}

// ============================================================================
// Legacy Global Singleton API - Deprecated, use JacsAgent instead
// ============================================================================
// The following functions use a global singleton for backwards compatibility.
// New code should use the JacsAgent type above.

// LegacyLoad initializes JACS with the given configuration file (legacy C API).
// Deprecated: Use NewJacsAgent() and agent.Load() instead, or the simple API Load(configPath *string).
func LegacyLoad(configPath string) error {
	cPath, freePath := cString(configPath)
	defer freePath()

	result := C.jacs_load(cPath)
	if result != 0 {
		return JACSError{Code: int(result), Message: getErrorMessage(int(result), "load")}
	}
	return nil
}

// SignString signs a string using the loaded JACS agent
func SignString(data string) (string, error) {
	cData, freeData := cString(data)
	defer freeData()

	return goStringResult(C.jacs_sign_string(cData), errors.New("failed to sign string"))
}

// HashString hashes a string using JACS hashing
func HashString(data string) (string, error) {
	cData, freeData := cString(data)
	defer freeData()

	return goStringResult(C.jacs_hash_string(cData), errors.New("failed to hash string"))
}

// VerifyString verifies a string signature
func VerifyString(data, signatureBase64 string, publicKey []byte, publicKeyEncType string) error {
	cData, freeData := cString(data)
	defer freeData()

	cSig, freeSig := cString(signatureBase64)
	defer freeSig()

	cEncType, freeEncType := cString(publicKeyEncType)
	defer freeEncType()

	var cPubKey *C.uint8_t
	if len(publicKey) > 0 {
		cPubKey = (*C.uint8_t)(unsafe.Pointer(&publicKey[0]))
	}

	result := C.jacs_verify_string(cData, cSig, cPubKey, C.size_t(len(publicKey)), cEncType)
	if result != 0 {
		return JACSError{Code: int(result), Message: getErrorMessage(int(result), "verify_string")}
	}
	return nil
}

// SignAgent signs an external agent
func SignAgent(agentString string, publicKey []byte, publicKeyEncType string) (string, error) {
	cAgent, freeAgent := cString(agentString)
	defer freeAgent()

	cEncType, freeEncType := cString(publicKeyEncType)
	defer freeEncType()

	var cPubKey *C.uint8_t
	if len(publicKey) > 0 {
		cPubKey = (*C.uint8_t)(unsafe.Pointer(&publicKey[0]))
	}

	return goStringResult(C.jacs_sign_agent(cAgent, cPubKey, C.size_t(len(publicKey)), cEncType), errors.New("failed to sign agent"))
}

// CreateConfig creates a new JACS configuration
func CreateConfig(config Config) (string, error) {
	// Convert Go pointers to C strings
	cUseSec, freeUseSec := cStringOpt(config.UseSecurity)
	defer freeUseSec()
	cDataDir, freeDataDir := cStringOpt(config.DataDirectory)
	defer freeDataDir()
	cKeyDir, freeKeyDir := cStringOpt(config.KeyDirectory)
	defer freeKeyDir()
	cPrivKeyFile, freePrivKeyFile := cStringOpt(config.AgentPrivateKeyFile)
	defer freePrivKeyFile()
	cPubKeyFile, freePubKeyFile := cStringOpt(config.AgentPublicKeyFile)
	defer freePubKeyFile()
	cKeyAlg, freeKeyAlg := cStringOpt(config.AgentKeyAlgorithm)
	defer freeKeyAlg()
	cPrivKeyPass, freePrivKeyPass := cStringOpt(config.PrivateKeyPassword)
	defer freePrivKeyPass()
	cAgentID, freeAgentID := cStringOpt(config.AgentIDAndVersion)
	defer freeAgentID()
	cDefStorage, freeDefStorage := cStringOpt(config.DefaultStorage)
	defer freeDefStorage()

	return goStringResult(C.jacs_create_config(cUseSec, cDataDir, cKeyDir, cPrivKeyFile, cPubKeyFile, cKeyAlg, cPrivKeyPass, cAgentID, cDefStorage), errors.New("failed to create config"))
}

// CreateAgent creates a JACS agent programmatically and returns its metadata as JSON.
func CreateAgent(name, password string, algorithm, dataDirectory, keyDirectory, configPath, agentType, description, domain, defaultStorage *string) (string, error) {
	cName, freeName := cString(name)
	defer freeName()

	cPassword, freePassword := cString(password)
	defer freePassword()

	cAlgorithm, freeAlgorithm := cStringOpt(algorithm)
	defer freeAlgorithm()
	cDataDir, freeDataDir := cStringOpt(dataDirectory)
	defer freeDataDir()
	cKeyDir, freeKeyDir := cStringOpt(keyDirectory)
	defer freeKeyDir()
	cConfigPath, freeConfigPath := cStringOpt(configPath)
	defer freeConfigPath()
	cAgentType, freeAgentType := cStringOpt(agentType)
	defer freeAgentType()
	cDescription, freeDescription := cStringOpt(description)
	defer freeDescription()
	cDomain, freeDomain := cStringOpt(domain)
	defer freeDomain()
	cDefaultStorage, freeDefaultStorage := cStringOpt(defaultStorage)
	defer freeDefaultStorage()

	return goStringResult(C.jacs_create_agent(
		cName,
		cPassword,
		cAlgorithm,
		cDataDir,
		cKeyDir,
		cConfigPath,
		cAgentType,
		cDescription,
		cDomain,
		cDefaultStorage,
	), errors.New("failed to create agent"))
}

// VerifyAgent verifies an agent's signature and hash
func VerifyAgent(agentFile *string) error {
	cFile, freeFile := cStringOpt(agentFile)
	defer freeFile()

	result := C.jacs_verify_agent(cFile)
	if result != 0 {
		return JACSError{Code: int(result), Message: getErrorMessage(int(result), "verify_agent")}
	}
	return nil
}

// UpdateAgent updates the current agent
func UpdateAgent(newAgentString string) (string, error) {
	cAgent, freeAgent := cString(newAgentString)
	defer freeAgent()

	return goStringResult(C.jacs_update_agent(cAgent), errors.New("failed to update agent"))
}

// VerifyDocument verifies a document's hash and signature
func VerifyDocument(documentString string) error {
	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	result := C.jacs_verify_document(cDoc)
	if result != 0 {
		return JACSError{Code: int(result), Message: getErrorMessage(int(result), "verify_document")}
	}
	return nil
}

// UpdateDocument updates an existing document
func UpdateDocument(documentKey, newDocumentString string, attachments []string, embed *bool) (string, error) {
	cKey, freeKey := cString(documentKey)
	defer freeKey()

	cDoc, freeDoc := cString(newDocumentString)
	defer freeDoc()

	var cAttach *C.char
	if len(attachments) > 0 {
		attachJSON, err := json.Marshal(attachments)
		if err != nil {
			return "", err
		}
		var freeAttach func()
		cAttach, freeAttach = cString(string(attachJSON))
		defer freeAttach()
	}

	embedVal := C.int(0)
	if embed != nil {
		if *embed {
			embedVal = 1
		} else {
			embedVal = -1
		}
	}

	return goStringResult(C.jacs_update_document(cKey, cDoc, cAttach, embedVal), errors.New("failed to update document"))
}

// CreateDocument creates a new JACS document
func CreateDocument(documentString string, customSchema, outputFilename *string, noSave bool, attachments *string, embed *bool) (string, error) {
	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	cSchema, freeSchema := cStringOpt(customSchema)
	defer freeSchema()
	cOutput, freeOutput := cStringOpt(outputFilename)
	defer freeOutput()
	cAttach, freeAttach := cStringOpt(attachments)
	defer freeAttach()

	noSaveVal := C.int(0)
	if noSave {
		noSaveVal = 1
	}

	embedVal := C.int(0)
	if embed != nil {
		if *embed {
			embedVal = 1
		} else {
			embedVal = -1
		}
	}

	return goStringResult(C.jacs_create_document(cDoc, cSchema, cOutput, noSaveVal, cAttach, embedVal), errors.New("failed to create document"))
}

// CreateAgreement creates an agreement for a document
func CreateAgreement(documentString string, agentIDs []string, question, context, agreementFieldname *string) (string, error) {
	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	agentIDsJSON, err := json.Marshal(agentIDs)
	if err != nil {
		return "", err
	}
	cAgentIDs, freeAgentIDs := cString(string(agentIDsJSON))
	defer freeAgentIDs()

	cQuestion, freeQuestion := cStringOpt(question)
	defer freeQuestion()
	cContext, freeContext := cStringOpt(context)
	defer freeContext()
	cFieldname, freeFieldname := cStringOpt(agreementFieldname)
	defer freeFieldname()

	return goStringResult(C.jacs_create_agreement(cDoc, cAgentIDs, cQuestion, cContext, cFieldname), errors.New("failed to create agreement"))
}

// SignAgreement signs an agreement
func SignAgreement(documentString string, agreementFieldname *string) (string, error) {
	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	cFieldname, freeFieldname := cStringOpt(agreementFieldname)
	defer freeFieldname()

	return goStringResult(C.jacs_sign_agreement(cDoc, cFieldname), errors.New("failed to sign agreement"))
}

// CheckAgreement checks an agreement
func CheckAgreement(documentString string, agreementFieldname *string) (string, error) {
	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	cFieldname, freeFieldname := cStringOpt(agreementFieldname)
	defer freeFieldname()

	return goStringResult(C.jacs_check_agreement(cDoc, cFieldname), errors.New("failed to check agreement"))
}

// SignRequest signs a request payload (for MCP)
func SignRequest(payload interface{}) (string, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	cPayload, freePayload := cString(string(payloadJSON))
	defer freePayload()

	return goStringResult(C.jacs_sign_request(cPayload), errors.New("failed to sign request"))
}

// VerifyResponse verifies a response (for MCP)
func VerifyResponse(documentString string) (map[string]interface{}, error) {
	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	result := C.jacs_verify_response(cDoc)
	if result == nil {
		return nil, errors.New("failed to verify response")
	}
	defer C.jacs_free_string(result)

	resultStr := C.GoString(result)
	var payload map[string]interface{}
	err := json.Unmarshal([]byte(resultStr), &payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// VerifyResponseWithAgentID verifies a response and returns the agent ID (for MCP)
func VerifyResponseWithAgentID(documentString string) (payload map[string]interface{}, agentID string, err error) {
	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	var cAgentID *C.char
	result := C.jacs_verify_response_with_agent_id(cDoc, &cAgentID)
	if result == nil {
		return nil, "", errors.New("failed to verify response with agent ID")
	}
	defer C.jacs_free_string(result)

	if cAgentID != nil {
		agentID = C.GoString(cAgentID)
		C.jacs_free_string(cAgentID)
	}

	resultStr := C.GoString(result)
	err = json.Unmarshal([]byte(resultStr), &payload)
	if err != nil {
		return nil, "", err
	}

	return payload, agentID, nil
}

// VerifySignature verifies a signature on a document
func VerifySignature(documentString string, signatureField *string) error {
	cDoc, freeDoc := cString(documentString)
	defer freeDoc()

	cField, freeField := cStringOpt(signatureField)
	defer freeField()

	result := C.jacs_verify_signature(cDoc, cField)
	if result != 0 {
		return JACSError{Code: int(result), Message: getErrorMessage(int(result), "verify_signature")}
	}
	return nil
}

// Helper function to get error messages based on error codes
func getErrorMessage(code int, operation string) string {
	switch operation {
	case "load":
		switch code {
		case -1:
			return "null config path"
		case -2:
			return "invalid UTF-8 in config path"
		case -3:
			return "failed to acquire agent lock"
		case -4:
			return "failed to load agent config"
		default:
			return "unknown error"
		}
	case "verify_string":
		switch code {
		case -1:
			return "null parameter"
		case -2:
			return "invalid data string"
		case -3:
			return "invalid signature string"
		case -4:
			return "invalid encryption type string"
		case -5:
			return "failed to acquire agent lock"
		case -6:
			return "signature verification failed"
		default:
			return "unknown error"
		}
	case "verify_agent":
		switch code {
		case -1:
			return "failed to acquire agent lock"
		case -2:
			return "invalid agent file path"
		case -3:
			return "failed to load agent from file"
		case -4:
			return "signature verification failed"
		case -5:
			return "hash verification failed"
		default:
			return "unknown error"
		}
	case "verify_document":
		switch code {
		case -1:
			return "null document string"
		case -2:
			return "invalid document string"
		case -3:
			return "failed to acquire agent lock"
		case -4:
			return "failed to load document"
		case -5:
			return "hash verification failed"
		case -6:
			return "signature verification failed"
		default:
			return "unknown error"
		}
	case "verify_signature":
		switch code {
		case -1:
			return "null document string"
		case -2:
			return "invalid document string"
		case -3:
			return "failed to acquire agent lock"
		case -4:
			return "failed to load document"
		case -5:
			return "signature verification failed"
		default:
			return "unknown error"
		}
	default:
		return fmt.Sprintf("operation failed with code %d", code)
	}
}

// VerifyDocumentStandalone verifies a signed document without loading an agent.
// Optional keyResolution, dataDirectory, keyDirectory may be empty to use defaults.
// Returns a VerificationResult; does not require Load() to have been called.
func VerifyDocumentStandalone(signedDocument, keyResolution, dataDirectory, keyDirectory string) (*VerificationResult, error) {
	cDoc, freeDoc := cString(signedDocument)
	defer freeDoc()
	var cKR, cDD, cKD *C.char
	if keyResolution != "" {
		var freeKR func()
		cKR, freeKR = cString(keyResolution)
		defer freeKR()
	}
	if dataDirectory != "" {
		var freeDD func()
		cDD, freeDD = cString(dataDirectory)
		defer freeDD()
	}
	if keyDirectory != "" {
		var freeKD func()
		cKD, freeKD = cString(keyDirectory)
		defer freeKD()
	}
	result := C.jacs_verify_document_standalone(cDoc, cKR, cDD, cKD)
	if result == nil {
		return nil, errors.New("verify_document_standalone failed")
	}
	defer C.jacs_free_string(result)
	resultStr := C.GoString(result)
	var out struct {
		Valid    bool   `json:"valid"`
		SignerID string `json:"signer_id"`
	}
	if err := json.Unmarshal([]byte(resultStr), &out); err != nil {
		return nil, fmt.Errorf("parse standalone result: %w", err)
	}
	return &VerificationResult{Valid: out.Valid, SignerID: out.SignerID}, nil
}

// RunAudit calls the jacs_audit FFI function and returns the JSON result string.
// configPath and recentN can be empty/zero for defaults.
func RunAudit(configPath string, recentN int) (string, error) {
	var cConfigPath *C.char
	if configPath != "" {
		var freeConfigPath func()
		cConfigPath, freeConfigPath = cString(configPath)
		defer freeConfigPath()
	}
	return goStringResult(C.jacs_audit(cConfigPath, C.int(recentN)), errors.New("audit failed"))
}
