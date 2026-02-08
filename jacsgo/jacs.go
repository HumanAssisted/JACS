package jacs

/*
#cgo CFLAGS: -I${SRCDIR}/build
#cgo darwin LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build
#cgo linux LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build

#include <stdlib.h>
#include <stdint.h>
#include "jacs_cgo.h"

// JacsAgent handle API - Recommended for concurrent usage
typedef void* JacsAgentHandle;
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

// Legacy global singleton API - Deprecated, use JacsAgent instead
int jacs_load(const char* config_path);
void jacs_free_string(char* s);
char* jacs_sign_string(const char* data);
char* jacs_hash_string(const char* data);
int jacs_verify_string(const char* data, const char* signature_base64, const uint8_t* public_key, size_t public_key_len, const char* public_key_enc_type);
char* jacs_sign_agent(const char* agent_string, const uint8_t* public_key, size_t public_key_len, const char* public_key_enc_type);
char* jacs_create_config(const char* jacs_use_security, const char* jacs_data_directory, const char* jacs_key_directory, const char* jacs_agent_private_key_filename, const char* jacs_agent_public_key_filename, const char* jacs_agent_key_algorithm, const char* jacs_private_key_password, const char* jacs_agent_id_and_version, const char* jacs_default_storage);
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
char* jacs_generate_verify_link(const char* document, const char* base_url);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
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
	if a.handle != nil {
		C.jacs_agent_free(a.handle)
		a.handle = nil
	}
}

// Load initializes this agent with the given configuration file.
func (a *JacsAgent) Load(configPath string) error {
	if a.handle == nil {
		return errors.New("JacsAgent is closed")
	}

	cPath := C.CString(configPath)
	defer C.free(unsafe.Pointer(cPath))

	result := C.jacs_agent_load(a.handle, cPath)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "load")}
	}
	return nil
}

// SignString signs a string using this agent's private key.
func (a *JacsAgent) SignString(data string) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsAgent is closed")
	}

	cData := C.CString(data)
	defer C.free(unsafe.Pointer(cData))

	result := C.jacs_agent_sign_string(a.handle, cData)
	if result == nil {
		return "", errors.New("failed to sign string")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// VerifyString verifies a string signature using this agent.
func (a *JacsAgent) VerifyString(data, signatureBase64 string, publicKey []byte, publicKeyEncType string) error {
	if a.handle == nil {
		return errors.New("JacsAgent is closed")
	}

	cData := C.CString(data)
	defer C.free(unsafe.Pointer(cData))

	cSig := C.CString(signatureBase64)
	defer C.free(unsafe.Pointer(cSig))

	cEncType := C.CString(publicKeyEncType)
	defer C.free(unsafe.Pointer(cEncType))

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
	if a.handle == nil {
		return "", errors.New("JacsAgent is closed")
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	cPayload := C.CString(string(payloadJSON))
	defer C.free(unsafe.Pointer(cPayload))

	result := C.jacs_agent_sign_request(a.handle, cPayload)
	if result == nil {
		return "", errors.New("failed to sign request")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// VerifyResponse verifies a response payload.
func (a *JacsAgent) VerifyResponse(documentString string) (map[string]interface{}, error) {
	if a.handle == nil {
		return nil, errors.New("JacsAgent is closed")
	}

	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

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
	if a.handle == nil {
		return "", errors.New("JacsAgent is closed")
	}

	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	agentIDsJSON, err := json.Marshal(agentIDs)
	if err != nil {
		return "", err
	}
	cAgentIDs := C.CString(string(agentIDsJSON))
	defer C.free(unsafe.Pointer(cAgentIDs))

	var cQuestion, cContext, cFieldname *C.char
	if question != nil {
		cQuestion = C.CString(*question)
		defer C.free(unsafe.Pointer(cQuestion))
	}
	if context != nil {
		cContext = C.CString(*context)
		defer C.free(unsafe.Pointer(cContext))
	}
	if agreementFieldname != nil {
		cFieldname = C.CString(*agreementFieldname)
		defer C.free(unsafe.Pointer(cFieldname))
	}

	result := C.jacs_agent_create_agreement(a.handle, cDoc, cAgentIDs, cQuestion, cContext, cFieldname)
	if result == nil {
		return "", errors.New("failed to create agreement")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// SignAgreement signs an agreement.
func (a *JacsAgent) SignAgreement(documentString string, agreementFieldname *string) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsAgent is closed")
	}

	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	var cFieldname *C.char
	if agreementFieldname != nil {
		cFieldname = C.CString(*agreementFieldname)
		defer C.free(unsafe.Pointer(cFieldname))
	}

	result := C.jacs_agent_sign_agreement(a.handle, cDoc, cFieldname)
	if result == nil {
		return "", errors.New("failed to sign agreement")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// CheckAgreement checks an agreement.
func (a *JacsAgent) CheckAgreement(documentString string, agreementFieldname *string) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsAgent is closed")
	}

	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	var cFieldname *C.char
	if agreementFieldname != nil {
		cFieldname = C.CString(*agreementFieldname)
		defer C.free(unsafe.Pointer(cFieldname))
	}

	result := C.jacs_agent_check_agreement(a.handle, cDoc, cFieldname)
	if result == nil {
		return "", errors.New("failed to check agreement")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// VerifyAgent verifies an agent's signature and hash.
func (a *JacsAgent) VerifyAgent(agentFile *string) error {
	if a.handle == nil {
		return errors.New("JacsAgent is closed")
	}

	var cFile *C.char
	if agentFile != nil {
		cFile = C.CString(*agentFile)
		defer C.free(unsafe.Pointer(cFile))
	}

	result := C.jacs_agent_verify_agent(a.handle, cFile)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "verify_agent")}
	}
	return nil
}

// CreateDocument creates a new JACS document.
func (a *JacsAgent) CreateDocument(documentString string, customSchema, outputFilename *string, noSave bool, attachments *string, embed *bool) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsAgent is closed")
	}

	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	var cSchema, cOutput, cAttach *C.char
	if customSchema != nil {
		cSchema = C.CString(*customSchema)
		defer C.free(unsafe.Pointer(cSchema))
	}
	if outputFilename != nil {
		cOutput = C.CString(*outputFilename)
		defer C.free(unsafe.Pointer(cOutput))
	}
	if attachments != nil {
		cAttach = C.CString(*attachments)
		defer C.free(unsafe.Pointer(cAttach))
	}

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

	result := C.jacs_agent_create_document(a.handle, cDoc, cSchema, cOutput, noSaveVal, cAttach, embedVal)
	if result == nil {
		return "", errors.New("failed to create document")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// VerifyDocument verifies a document's hash and signature.
func (a *JacsAgent) VerifyDocument(documentString string) error {
	if a.handle == nil {
		return errors.New("JacsAgent is closed")
	}

	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	result := C.jacs_agent_verify_document(a.handle, cDoc)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "verify_document")}
	}
	return nil
}

// VerifyDocumentById verifies a document by its storage ID ("uuid:version" format).
func (a *JacsAgent) VerifyDocumentById(documentID string) error {
	if a.handle == nil {
		return errors.New("JacsAgent is closed")
	}

	cDocID := C.CString(documentID)
	defer C.free(unsafe.Pointer(cDocID))

	result := C.jacs_agent_verify_document_by_id(a.handle, cDocID)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "verify_document_by_id")}
	}
	return nil
}

// ReencryptKey re-encrypts the agent's private key with a new password.
func (a *JacsAgent) ReencryptKey(oldPassword, newPassword string) error {
	if a.handle == nil {
		return errors.New("JacsAgent is closed")
	}

	cOldPw := C.CString(oldPassword)
	defer C.free(unsafe.Pointer(cOldPw))

	cNewPw := C.CString(newPassword)
	defer C.free(unsafe.Pointer(cNewPw))

	result := C.jacs_agent_reencrypt_key(a.handle, cOldPw, cNewPw)
	if result != 0 {
		return JACSError{Code: int(result), Message: getAgentErrorMessage(int(result), "reencrypt_key")}
	}
	return nil
}

// GetJSON returns the agent's JSON representation.
func (a *JacsAgent) GetJSON() (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsAgent is closed")
	}

	result := C.jacs_agent_get_json(a.handle)
	if result == nil {
		return "", errors.New("failed to get agent JSON (agent may not be loaded)")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
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
	cPath := C.CString(configPath)
	defer C.free(unsafe.Pointer(cPath))

	result := C.jacs_load(cPath)
	if result != 0 {
		return JACSError{Code: int(result), Message: getErrorMessage(int(result), "load")}
	}
	return nil
}

// SignString signs a string using the loaded JACS agent
func SignString(data string) (string, error) {
	cData := C.CString(data)
	defer C.free(unsafe.Pointer(cData))

	result := C.jacs_sign_string(cData)
	if result == nil {
		return "", errors.New("failed to sign string")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// HashString hashes a string using JACS hashing
func HashString(data string) (string, error) {
	cData := C.CString(data)
	defer C.free(unsafe.Pointer(cData))

	result := C.jacs_hash_string(cData)
	if result == nil {
		return "", errors.New("failed to hash string")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// VerifyString verifies a string signature
func VerifyString(data, signatureBase64 string, publicKey []byte, publicKeyEncType string) error {
	cData := C.CString(data)
	defer C.free(unsafe.Pointer(cData))

	cSig := C.CString(signatureBase64)
	defer C.free(unsafe.Pointer(cSig))

	cEncType := C.CString(publicKeyEncType)
	defer C.free(unsafe.Pointer(cEncType))

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
	cAgent := C.CString(agentString)
	defer C.free(unsafe.Pointer(cAgent))

	cEncType := C.CString(publicKeyEncType)
	defer C.free(unsafe.Pointer(cEncType))

	var cPubKey *C.uint8_t
	if len(publicKey) > 0 {
		cPubKey = (*C.uint8_t)(unsafe.Pointer(&publicKey[0]))
	}

	result := C.jacs_sign_agent(cAgent, cPubKey, C.size_t(len(publicKey)), cEncType)
	if result == nil {
		return "", errors.New("failed to sign agent")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// CreateConfig creates a new JACS configuration
func CreateConfig(config Config) (string, error) {
	// Convert Go pointers to C strings
	var cUseSec, cDataDir, cKeyDir, cPrivKeyFile, cPubKeyFile, cKeyAlg, cPrivKeyPass, cAgentID, cDefStorage *C.char

	if config.UseSecurity != nil {
		cUseSec = C.CString(*config.UseSecurity)
		defer C.free(unsafe.Pointer(cUseSec))
	}
	if config.DataDirectory != nil {
		cDataDir = C.CString(*config.DataDirectory)
		defer C.free(unsafe.Pointer(cDataDir))
	}
	if config.KeyDirectory != nil {
		cKeyDir = C.CString(*config.KeyDirectory)
		defer C.free(unsafe.Pointer(cKeyDir))
	}
	if config.AgentPrivateKeyFile != nil {
		cPrivKeyFile = C.CString(*config.AgentPrivateKeyFile)
		defer C.free(unsafe.Pointer(cPrivKeyFile))
	}
	if config.AgentPublicKeyFile != nil {
		cPubKeyFile = C.CString(*config.AgentPublicKeyFile)
		defer C.free(unsafe.Pointer(cPubKeyFile))
	}
	if config.AgentKeyAlgorithm != nil {
		cKeyAlg = C.CString(*config.AgentKeyAlgorithm)
		defer C.free(unsafe.Pointer(cKeyAlg))
	}
	if config.PrivateKeyPassword != nil {
		cPrivKeyPass = C.CString(*config.PrivateKeyPassword)
		defer C.free(unsafe.Pointer(cPrivKeyPass))
	}
	if config.AgentIDAndVersion != nil {
		cAgentID = C.CString(*config.AgentIDAndVersion)
		defer C.free(unsafe.Pointer(cAgentID))
	}
	if config.DefaultStorage != nil {
		cDefStorage = C.CString(*config.DefaultStorage)
		defer C.free(unsafe.Pointer(cDefStorage))
	}

	result := C.jacs_create_config(cUseSec, cDataDir, cKeyDir, cPrivKeyFile, cPubKeyFile, cKeyAlg, cPrivKeyPass, cAgentID, cDefStorage)
	if result == nil {
		return "", errors.New("failed to create config")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// VerifyAgent verifies an agent's signature and hash
func VerifyAgent(agentFile *string) error {
	var cFile *C.char
	if agentFile != nil {
		cFile = C.CString(*agentFile)
		defer C.free(unsafe.Pointer(cFile))
	}

	result := C.jacs_verify_agent(cFile)
	if result != 0 {
		return JACSError{Code: int(result), Message: getErrorMessage(int(result), "verify_agent")}
	}
	return nil
}

// UpdateAgent updates the current agent
func UpdateAgent(newAgentString string) (string, error) {
	cAgent := C.CString(newAgentString)
	defer C.free(unsafe.Pointer(cAgent))

	result := C.jacs_update_agent(cAgent)
	if result == nil {
		return "", errors.New("failed to update agent")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// VerifyDocument verifies a document's hash and signature
func VerifyDocument(documentString string) error {
	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	result := C.jacs_verify_document(cDoc)
	if result != 0 {
		return JACSError{Code: int(result), Message: getErrorMessage(int(result), "verify_document")}
	}
	return nil
}

// UpdateDocument updates an existing document
func UpdateDocument(documentKey, newDocumentString string, attachments []string, embed *bool) (string, error) {
	cKey := C.CString(documentKey)
	defer C.free(unsafe.Pointer(cKey))

	cDoc := C.CString(newDocumentString)
	defer C.free(unsafe.Pointer(cDoc))

	var cAttach *C.char
	if len(attachments) > 0 {
		attachJSON, err := json.Marshal(attachments)
		if err != nil {
			return "", err
		}
		cAttach = C.CString(string(attachJSON))
		defer C.free(unsafe.Pointer(cAttach))
	}

	embedVal := C.int(0)
	if embed != nil {
		if *embed {
			embedVal = 1
		} else {
			embedVal = -1
		}
	}

	result := C.jacs_update_document(cKey, cDoc, cAttach, embedVal)
	if result == nil {
		return "", errors.New("failed to update document")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// CreateDocument creates a new JACS document
func CreateDocument(documentString string, customSchema, outputFilename *string, noSave bool, attachments *string, embed *bool) (string, error) {
	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	var cSchema, cOutput, cAttach *C.char
	if customSchema != nil {
		cSchema = C.CString(*customSchema)
		defer C.free(unsafe.Pointer(cSchema))
	}
	if outputFilename != nil {
		cOutput = C.CString(*outputFilename)
		defer C.free(unsafe.Pointer(cOutput))
	}
	if attachments != nil {
		cAttach = C.CString(*attachments)
		defer C.free(unsafe.Pointer(cAttach))
	}

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

	result := C.jacs_create_document(cDoc, cSchema, cOutput, noSaveVal, cAttach, embedVal)
	if result == nil {
		return "", errors.New("failed to create document")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// CreateAgreement creates an agreement for a document
func CreateAgreement(documentString string, agentIDs []string, question, context, agreementFieldname *string) (string, error) {
	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	agentIDsJSON, err := json.Marshal(agentIDs)
	if err != nil {
		return "", err
	}
	cAgentIDs := C.CString(string(agentIDsJSON))
	defer C.free(unsafe.Pointer(cAgentIDs))

	var cQuestion, cContext, cFieldname *C.char
	if question != nil {
		cQuestion = C.CString(*question)
		defer C.free(unsafe.Pointer(cQuestion))
	}
	if context != nil {
		cContext = C.CString(*context)
		defer C.free(unsafe.Pointer(cContext))
	}
	if agreementFieldname != nil {
		cFieldname = C.CString(*agreementFieldname)
		defer C.free(unsafe.Pointer(cFieldname))
	}

	result := C.jacs_create_agreement(cDoc, cAgentIDs, cQuestion, cContext, cFieldname)
	if result == nil {
		return "", errors.New("failed to create agreement")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// SignAgreement signs an agreement
func SignAgreement(documentString string, agreementFieldname *string) (string, error) {
	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	var cFieldname *C.char
	if agreementFieldname != nil {
		cFieldname = C.CString(*agreementFieldname)
		defer C.free(unsafe.Pointer(cFieldname))
	}

	result := C.jacs_sign_agreement(cDoc, cFieldname)
	if result == nil {
		return "", errors.New("failed to sign agreement")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// CheckAgreement checks an agreement
func CheckAgreement(documentString string, agreementFieldname *string) (string, error) {
	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	var cFieldname *C.char
	if agreementFieldname != nil {
		cFieldname = C.CString(*agreementFieldname)
		defer C.free(unsafe.Pointer(cFieldname))
	}

	result := C.jacs_check_agreement(cDoc, cFieldname)
	if result == nil {
		return "", errors.New("failed to check agreement")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// SignRequest signs a request payload (for MCP)
func SignRequest(payload interface{}) (string, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	cPayload := C.CString(string(payloadJSON))
	defer C.free(unsafe.Pointer(cPayload))

	result := C.jacs_sign_request(cPayload)
	if result == nil {
		return "", errors.New("failed to sign request")
	}
	defer C.jacs_free_string(result)

	return C.GoString(result), nil
}

// VerifyResponse verifies a response (for MCP)
func VerifyResponse(documentString string) (map[string]interface{}, error) {
	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

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
	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

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
	cDoc := C.CString(documentString)
	defer C.free(unsafe.Pointer(cDoc))

	var cField *C.char
	if signatureField != nil {
		cField = C.CString(*signatureField)
		defer C.free(unsafe.Pointer(cField))
	}

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
	cDoc := C.CString(signedDocument)
	defer C.free(unsafe.Pointer(cDoc))
	var cKR, cDD, cKD *C.char
	if keyResolution != "" {
		cKR = C.CString(keyResolution)
		defer C.free(unsafe.Pointer(cKR))
	}
	if dataDirectory != "" {
		cDD = C.CString(dataDirectory)
		defer C.free(unsafe.Pointer(cDD))
	}
	if keyDirectory != "" {
		cKD = C.CString(keyDirectory)
		defer C.free(unsafe.Pointer(cKD))
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
		cConfigPath = C.CString(configPath)
		defer C.free(unsafe.Pointer(cConfigPath))
	}
	result := C.jacs_audit(cConfigPath, C.int(recentN))
	if result == nil {
		return "", errors.New("audit failed")
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}
