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
	"sync"
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
	mu     sync.RWMutex
	handle C.SimpleAgentHandle
}

// simpleLastError retrieves the last error message from the Rust FFI layer.
// Returns a detailed error if available, otherwise returns the fallback message.
func simpleLastError(fallback string) error {
	errPtr := C.jacs_simple_last_error()
	if errPtr != nil {
		defer C.jacs_free_string(errPtr)
		return errors.New(C.GoString(errPtr))
	}
	return errors.New(fallback)
}

// NewSimpleAgent creates a new agent with persistent identity.
// Returns the agent and AgentInfo metadata.
func NewSimpleAgent(name string, purpose, keyAlgorithm *string) (*JacsSimpleAgent, *AgentInfo, error) {
	cName, freeName := cString(name)
	defer freeName()

	cPurpose, freePurpose := cStringOpt(purpose)
	defer freePurpose()
	cAlgo, freeAlgo := cStringOpt(keyAlgorithm)
	defer freeAlgo()

	var cInfoOut *C.char
	handle := C.jacs_simple_create(cName, cPurpose, cAlgo, &cInfoOut)
	if handle == nil {
		return nil, nil, simpleLastError("failed to create simple agent")
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
	cPath, freePath := cStringOpt(configPath)
	defer freePath()

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
		return nil, simpleLastError("failed to load simple agent")
	}

	return &JacsSimpleAgent{handle: handle}, nil
}

// EphemeralSimpleAgent creates an ephemeral (in-memory) agent.
// algorithm is optional (nil for default).
func EphemeralSimpleAgent(algorithm *string) (*JacsSimpleAgent, *AgentInfo, error) {
	cAlgo, freeAlgo := cStringOpt(algorithm)
	defer freeAlgo()

	var cInfoOut *C.char
	handle := C.jacs_simple_ephemeral(cAlgo, &cInfoOut)
	if handle == nil {
		return nil, nil, simpleLastError("failed to create ephemeral simple agent")
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
	cParams, freeParams := cString(paramsJSON)
	defer freeParams()

	var cInfoOut *C.char
	handle := C.jacs_simple_create_with_params(cParams, &cInfoOut)
	if handle == nil {
		return nil, nil, simpleLastError("failed to create simple agent with params")
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
	a.mu.Lock()
	defer a.mu.Unlock()
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
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	return simpleStringResult(C.jacs_simple_get_agent_id(a.handle), "failed to get agent ID")
}

// KeyID returns the JACS signing key identifier.
func (a *JacsSimpleAgent) KeyID() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	return simpleStringResult(C.jacs_simple_key_id(a.handle), "failed to get key ID")
}

// IsStrict returns whether the agent is in strict mode.
func (a *JacsSimpleAgent) IsStrict() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return false
	}
	return C.jacs_simple_is_strict(a.handle) != 0
}

// ExportAgent exports the agent's identity JSON for P2P exchange.
func (a *JacsSimpleAgent) ExportAgent() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	return simpleStringResult(C.jacs_simple_export_agent(a.handle), "failed to export agent")
}

// GetPublicKeyPEM returns the public key in PEM format.
func (a *JacsSimpleAgent) GetPublicKeyPEM() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	return simpleStringResult(C.jacs_simple_get_public_key_pem(a.handle), "failed to get public key PEM")
}

// GetPublicKeyBase64 returns the public key as base64-encoded raw bytes.
func (a *JacsSimpleAgent) GetPublicKeyBase64() (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	return simpleStringResult(C.jacs_simple_get_public_key_base64(a.handle), "failed to get public key base64")
}

// ConfigPath returns the config file path, or nil if ephemeral/not loaded from disk.
func (a *JacsSimpleAgent) ConfigPath() *string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return nil
	}
	result := C.jacs_simple_config_path(a.handle)
	if result == nil {
		return nil
	}
	defer C.jacs_free_string(result)
	s := C.GoString(result)
	return &s
}

// Diagnostics returns runtime diagnostic info as a JSON string.
func (a *JacsSimpleAgent) Diagnostics() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
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
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return nil, errSimpleAgentClosed
	}
	return callJSON[VerificationResult](C.jacs_simple_verify_self(a.handle), "failed to verify self")
}

// Verify verifies a signed document JSON string.
// Returns a VerificationResult.
func (a *JacsSimpleAgent) Verify(signedDocument string) (*VerificationResult, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return nil, errSimpleAgentClosed
	}
	cDoc, freeDoc := cString(signedDocument)
	defer freeDoc()

	return callJSON[VerificationResult](C.jacs_simple_verify_json(a.handle, cDoc), "failed to verify document")
}

// VerifyByID verifies a stored document by its ID (e.g., "uuid:version").
// Returns a VerificationResult.
func (a *JacsSimpleAgent) VerifyByID(documentID string) (*VerificationResult, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return nil, errSimpleAgentClosed
	}
	cID, freeID := cString(documentID)
	defer freeID()

	return callJSON[VerificationResult](C.jacs_simple_verify_by_id(a.handle, cID), "failed to verify document by ID")
}

// VerifyWithKey verifies a signed document with an explicit public key (base64-encoded).
// Returns a VerificationResult.
func (a *JacsSimpleAgent) VerifyWithKey(signedDocument, publicKeyBase64 string) (*VerificationResult, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return nil, errSimpleAgentClosed
	}
	cDoc, freeDoc := cString(signedDocument)
	defer freeDoc()
	cKey, freeKey := cString(publicKeyBase64)
	defer freeKey()

	return callJSON[VerificationResult](C.jacs_simple_verify_with_key(a.handle, cDoc, cKey), "failed to verify with key")
}

// =========================================================================
// Signing
// =========================================================================

// SignMessage signs a JSON message. Returns a SignedDocument.
func (a *JacsSimpleAgent) SignMessage(data interface{}) (*SignedDocument, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return nil, errSimpleAgentClosed
	}

	// Marshal data to JSON
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, NewSimpleError("sign_message", err)
	}

	cData, freeData := cString(string(jsonBytes))
	defer freeData()

	result := C.jacs_simple_sign_message(a.handle, cData)
	if result == nil {
		return nil, simpleLastError("failed to sign message")
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
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	if len(data) == 0 {
		return "", errors.New("data must not be empty")
	}

	cData := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	return simpleStringResult(C.jacs_simple_sign_raw_bytes(a.handle, cData, C.size_t(len(data))), "failed to sign raw bytes")
}

// SignFile signs a file with optional content embedding. Returns a SignedDocument.
func (a *JacsSimpleAgent) SignFile(filePath string, embed bool) (*SignedDocument, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.handle == nil {
		return nil, errSimpleAgentClosed
	}

	cPath, freePath := cString(filePath)
	defer freePath()

	embedVal := C.int(0)
	if embed {
		embedVal = 1
	}

	result := C.jacs_simple_sign_file(a.handle, cPath, embedVal)
	if result == nil {
		return nil, simpleLastError("failed to sign file")
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
