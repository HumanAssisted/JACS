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
)

// W3cRequestProofParams describes the request-bound DID authentication proof
// input. It mirrors binding-core's JSON contract.
type W3cRequestProofParams struct {
	Method  string  `json:"method"`
	URL     string  `json:"url"`
	Body    *string `json:"body,omitempty"`
	Nonce   *string `json:"nonce,omitempty"`
	Created *string `json:"created,omitempty"`
	Origin  *string `json:"origin,omitempty"`
}

func parseJSONObject(payload string, op string) (map[string]interface{}, error) {
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return nil, NewSimpleError(op, err)
	}
	return out, nil
}

// ExportW3cDid exports this agent's did:wba identifier.
func (a *JacsSimpleAgent) ExportW3cDid(origin *string) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	cOrigin, freeOrigin := cStringOpt(origin)
	defer freeOrigin()
	result := C.jacs_simple_export_w3c_did(a.handle, cOrigin)
	if result == nil {
		return "", simpleLastError("failed to export W3C DID")
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}

// ExportW3cDidDocument exports this agent's did:wba DID document.
func (a *JacsSimpleAgent) ExportW3cDidDocument(origin *string) (map[string]interface{}, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	cOrigin, freeOrigin := cStringOpt(origin)
	defer freeOrigin()
	result := C.jacs_simple_export_w3c_did_document(a.handle, cOrigin)
	if result == nil {
		return nil, simpleLastError("failed to export W3C DID document")
	}
	defer C.jacs_free_string(result)
	return parseJSONObject(C.GoString(result), "export_w3c_did_document")
}

// ExportW3cAgentDescription exports this agent's W3C agent description.
func (a *JacsSimpleAgent) ExportW3cAgentDescription(origin *string) (map[string]interface{}, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	cOrigin, freeOrigin := cStringOpt(origin)
	defer freeOrigin()
	result := C.jacs_simple_export_w3c_agent_description(a.handle, cOrigin)
	if result == nil {
		return nil, simpleLastError("failed to export W3C agent description")
	}
	defer C.jacs_free_string(result)
	return parseJSONObject(C.GoString(result), "export_w3c_agent_description")
}

// GenerateW3cWellKnown generates W3C discovery documents keyed by URL path.
func (a *JacsSimpleAgent) GenerateW3cWellKnown(origin *string) (map[string]interface{}, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	cOrigin, freeOrigin := cStringOpt(origin)
	defer freeOrigin()
	result := C.jacs_simple_generate_w3c_well_known(a.handle, cOrigin)
	if result == nil {
		return nil, simpleLastError("failed to generate W3C well-known documents")
	}
	defer C.jacs_free_string(result)
	return parseJSONObject(C.GoString(result), "generate_w3c_well_known")
}

// SignW3cRequest creates a request-bound DID authentication proof.
func (a *JacsSimpleAgent) SignW3cRequest(params W3cRequestProofParams) (map[string]interface{}, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, NewSimpleError("sign_w3c_request", err)
	}
	cParams, freeParams := cString(string(paramsJSON))
	defer freeParams()
	result := C.jacs_simple_sign_w3c_request(a.handle, cParams)
	if result == nil {
		return nil, simpleLastError("failed to sign W3C request proof")
	}
	defer C.jacs_free_string(result)
	return parseJSONObject(C.GoString(result), "sign_w3c_request")
}

// VerifyW3cRequest verifies a request-bound DID authentication proof.
func (a *JacsSimpleAgent) VerifyW3cRequest(proofJSON, didDocumentJSON string, body *string, maxAgeSeconds uint64, expectedMethod *string, expectedURL *string) (map[string]interface{}, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	cProof, freeProof := cString(proofJSON)
	defer freeProof()
	cDidDocument, freeDidDocument := cString(didDocumentJSON)
	defer freeDidDocument()
	cBody, freeBody := cStringOpt(body)
	defer freeBody()
	cExpectedMethod, freeExpectedMethod := cStringOpt(expectedMethod)
	defer freeExpectedMethod()
	cExpectedURL, freeExpectedURL := cStringOpt(expectedURL)
	defer freeExpectedURL()
	result := C.jacs_simple_verify_w3c_request(a.handle, cProof, cDidDocument, cBody, C.uint64_t(maxAgeSeconds), cExpectedMethod, cExpectedURL)
	if result == nil {
		return nil, simpleLastError("failed to verify W3C request proof")
	}
	defer C.jacs_free_string(result)
	return parseJSONObject(C.GoString(result), "verify_w3c_request")
}
