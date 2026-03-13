package jacs

/*
#cgo CFLAGS: -I${SRCDIR}/build
#cgo darwin LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build
#cgo linux LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build

#include <stdlib.h>
#include <stdint.h>
#include "jacs_cgo.h"
*/
import "C"
import (
	"encoding/json"
	"errors"
	"unsafe"
)

// ============================================================================
// JacsSimpleAgent — narrow contract wrapper via SimpleAgentWrapper
// ============================================================================
// JacsSimpleAgent provides the same FFI contract as the Python (PyO3) and
// Node.js (NAPI) SimpleAgent classes. It wraps the Rust SimpleAgentWrapper
// from jacs-binding-core, giving Go callers a clean, JSON-in/JSON-out API.
//
// For advanced features (agreements, A2A, attestation), use JacsAgent instead.

// JacsSimpleAgent represents a JACS agent via the narrow simple contract.
// Multiple JacsSimpleAgent instances can be used concurrently.
type JacsSimpleAgent struct {
	handle C.SimpleAgentHandle
}

// NewSimpleAgent creates a new agent with persistent identity.
// Returns the agent and AgentInfo metadata.
func NewSimpleAgent(name string, purpose, keyAlgorithm *string) (*JacsSimpleAgent, *AgentInfo, error) {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	var cPurpose, cAlgo *C.char
	if purpose != nil {
		cPurpose = C.CString(*purpose)
		defer C.free(unsafe.Pointer(cPurpose))
	}
	if keyAlgorithm != nil {
		cAlgo = C.CString(*keyAlgorithm)
		defer C.free(unsafe.Pointer(cAlgo))
	}

	var cInfoOut *C.char
	handle := C.jacs_simple_create(cName, cPurpose, cAlgo, &cInfoOut)
	if handle == nil {
		return nil, nil, errors.New("failed to create simple agent")
	}

	var info AgentInfo
	if cInfoOut != nil {
		infoStr := C.GoString(cInfoOut)
		C.jacs_free_string(cInfoOut)
		if err := json.Unmarshal([]byte(infoStr), &info); err != nil {
			// Best-effort; info may be partial
			info.Name = name
		}
	}
	info.Name = name

	return &JacsSimpleAgent{handle: handle}, &info, nil
}

// LoadSimpleAgent loads an existing agent from a config file.
// configPath is optional (nil for default). strict: nil for default, non-nil to set.
func LoadSimpleAgent(configPath *string, strict *bool) (*JacsSimpleAgent, error) {
	var cPath *C.char
	if configPath != nil {
		cPath = C.CString(*configPath)
		defer C.free(unsafe.Pointer(cPath))
	}

	// -1 = None, 0 = false, 1 = true
	strictVal := C.int(-1)
	if strict != nil {
		if *strict {
			strictVal = 1
		} else {
			strictVal = 0
		}
	}

	handle := C.jacs_simple_load(cPath, strictVal)
	if handle == nil {
		return nil, errors.New("failed to load simple agent")
	}

	return &JacsSimpleAgent{handle: handle}, nil
}

// EphemeralSimpleAgent creates an ephemeral (in-memory) agent.
// algorithm is optional (nil for default).
func EphemeralSimpleAgent(algorithm *string) (*JacsSimpleAgent, *AgentInfo, error) {
	var cAlgo *C.char
	if algorithm != nil {
		cAlgo = C.CString(*algorithm)
		defer C.free(unsafe.Pointer(cAlgo))
	}

	var cInfoOut *C.char
	handle := C.jacs_simple_ephemeral(cAlgo, &cInfoOut)
	if handle == nil {
		return nil, nil, errors.New("failed to create ephemeral simple agent")
	}

	var info AgentInfo
	if cInfoOut != nil {
		infoStr := C.GoString(cInfoOut)
		C.jacs_free_string(cInfoOut)
		_ = json.Unmarshal([]byte(infoStr), &info)
	}

	return &JacsSimpleAgent{handle: handle}, &info, nil
}

// CreateSimpleAgentWithParams creates an agent with full programmatic control via JSON parameters.
// paramsJSON is a JSON string of CreateAgentParams fields.
func CreateSimpleAgentWithParams(paramsJSON string) (*JacsSimpleAgent, *AgentInfo, error) {
	cParams := C.CString(paramsJSON)
	defer C.free(unsafe.Pointer(cParams))

	var cInfoOut *C.char
	handle := C.jacs_simple_create_with_params(cParams, &cInfoOut)
	if handle == nil {
		return nil, nil, errors.New("failed to create simple agent with params")
	}

	var info AgentInfo
	if cInfoOut != nil {
		infoStr := C.GoString(cInfoOut)
		C.jacs_free_string(cInfoOut)
		_ = json.Unmarshal([]byte(infoStr), &info)
	}

	return &JacsSimpleAgent{handle: handle}, &info, nil
}

// Close releases resources. After Close, the agent must not be used.
func (a *JacsSimpleAgent) Close() {
	if a.handle != nil {
		C.jacs_simple_free(a.handle)
		a.handle = nil
	}
}

// =========================================================================
// Identity / Introspection
// =========================================================================

// GetAgentID returns the agent's unique identifier.
func (a *JacsSimpleAgent) GetAgentID() (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	result := C.jacs_simple_get_agent_id(a.handle)
	if result == nil {
		return "", errors.New("failed to get agent ID")
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}

// KeyID returns the JACS signing key identifier.
func (a *JacsSimpleAgent) KeyID() (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	result := C.jacs_simple_key_id(a.handle)
	if result == nil {
		return "", errors.New("failed to get key ID")
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}

// IsStrict returns whether the agent is in strict mode.
func (a *JacsSimpleAgent) IsStrict() bool {
	if a.handle == nil {
		return false
	}
	return C.jacs_simple_is_strict(a.handle) != 0
}

// ExportAgent exports the agent's identity JSON for P2P exchange.
func (a *JacsSimpleAgent) ExportAgent() (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	result := C.jacs_simple_export_agent(a.handle)
	if result == nil {
		return "", errors.New("failed to export agent")
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}

// GetPublicKeyPEM returns the public key in PEM format.
func (a *JacsSimpleAgent) GetPublicKeyPEM() (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	result := C.jacs_simple_get_public_key_pem(a.handle)
	if result == nil {
		return "", errors.New("failed to get public key PEM")
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}

// GetPublicKeyBase64 returns the public key as base64-encoded raw bytes.
func (a *JacsSimpleAgent) GetPublicKeyBase64() (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	result := C.jacs_simple_get_public_key_base64(a.handle)
	if result == nil {
		return "", errors.New("failed to get public key base64")
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}

// Diagnostics returns runtime diagnostic info as a JSON string.
func (a *JacsSimpleAgent) Diagnostics() string {
	if a.handle == nil {
		return "{}"
	}
	result := C.jacs_simple_diagnostics(a.handle)
	if result == nil {
		return "{}"
	}
	defer C.jacs_free_string(result)
	return C.GoString(result)
}

// =========================================================================
// Verification
// =========================================================================

// VerifySelf verifies the agent's own document signature.
// Returns a VerificationResult.
func (a *JacsSimpleAgent) VerifySelf() (*VerificationResult, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	result := C.jacs_simple_verify_self(a.handle)
	if result == nil {
		return nil, errors.New("failed to verify self")
	}
	defer C.jacs_free_string(result)

	resultStr := C.GoString(result)
	var vr VerificationResult
	if err := json.Unmarshal([]byte(resultStr), &vr); err != nil {
		return nil, err
	}
	return &vr, nil
}

// Verify verifies a signed document JSON string.
// Returns a VerificationResult.
func (a *JacsSimpleAgent) Verify(signedDocument string) (*VerificationResult, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	cDoc := C.CString(signedDocument)
	defer C.free(unsafe.Pointer(cDoc))

	result := C.jacs_simple_verify_json(a.handle, cDoc)
	if result == nil {
		return nil, errors.New("failed to verify document")
	}
	defer C.jacs_free_string(result)

	resultStr := C.GoString(result)
	var vr VerificationResult
	if err := json.Unmarshal([]byte(resultStr), &vr); err != nil {
		return nil, err
	}
	return &vr, nil
}

// VerifyByID verifies a stored document by its ID (e.g., "uuid:version").
// Returns a VerificationResult.
func (a *JacsSimpleAgent) VerifyByID(documentID string) (*VerificationResult, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	cID := C.CString(documentID)
	defer C.free(unsafe.Pointer(cID))

	result := C.jacs_simple_verify_by_id(a.handle, cID)
	if result == nil {
		return nil, errors.New("failed to verify document by ID")
	}
	defer C.jacs_free_string(result)

	resultStr := C.GoString(result)
	var vr VerificationResult
	if err := json.Unmarshal([]byte(resultStr), &vr); err != nil {
		return nil, err
	}
	return &vr, nil
}

// =========================================================================
// Signing
// =========================================================================

// SignMessage signs a JSON message. Returns a SignedDocument.
func (a *JacsSimpleAgent) SignMessage(data interface{}) (*SignedDocument, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}

	// Marshal data to JSON
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, NewSimpleError("sign_message", err)
	}

	cData := C.CString(string(jsonBytes))
	defer C.free(unsafe.Pointer(cData))

	result := C.jacs_simple_sign_message(a.handle, cData)
	if result == nil {
		return nil, errors.New("failed to sign message")
	}
	defer C.jacs_free_string(result)

	raw := C.GoString(result)

	// Parse result to extract standard fields
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, NewSimpleError("sign_message", err)
	}

	return &SignedDocument{
		Raw:        raw,
		DocumentID: getStringField(doc, "jacsId"),
		Timestamp:  getNestedStringField(doc, "jacsSignature", "date"),
		AgentID:    getNestedStringField(doc, "jacsSignature", "agentID"),
	}, nil
}

// SignRawBytes signs raw bytes and returns the signature as base64.
func (a *JacsSimpleAgent) SignRawBytes(data []byte) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	if len(data) == 0 {
		return "", errors.New("data must not be empty")
	}

	cData := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	result := C.jacs_simple_sign_raw_bytes(a.handle, cData, C.size_t(len(data)))
	if result == nil {
		return "", errors.New("failed to sign raw bytes")
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}

// SignFile signs a file with optional content embedding. Returns a SignedDocument.
func (a *JacsSimpleAgent) SignFile(filePath string, embed bool) (*SignedDocument, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}

	cPath := C.CString(filePath)
	defer C.free(unsafe.Pointer(cPath))

	embedVal := C.int(0)
	if embed {
		embedVal = 1
	}

	result := C.jacs_simple_sign_file(a.handle, cPath, embedVal)
	if result == nil {
		return nil, errors.New("failed to sign file")
	}
	defer C.jacs_free_string(result)

	raw := C.GoString(result)

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, NewSimpleError("sign_file", err)
	}

	return &SignedDocument{
		Raw:        raw,
		DocumentID: getStringField(doc, "jacsId"),
		Timestamp:  getNestedStringField(doc, "jacsSignature", "date"),
		AgentID:    getNestedStringField(doc, "jacsSignature", "agentID"),
	}, nil
}
