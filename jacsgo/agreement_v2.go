package jacs

/*
#cgo CFLAGS: -I${SRCDIR}/build
#cgo darwin LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build
#cgo linux LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build

#include <stdlib.h>
#include "jacs_cgo.h"
*/
import "C"
import (
	"encoding/json"
	"errors"
	"unsafe"
)

func simpleStringResult(result *C.char, fallback string) (string, error) {
	if result == nil {
		return "", simpleLastError(fallback)
	}
	defer C.jacs_free_string(result)
	return C.GoString(result), nil
}

// callJSON runs a *C.char-returning FFI result through simpleStringResult
// (nil -> simpleLastError(fallback); otherwise GoString + free) and unmarshals
// the JSON payload into T. Returns the raw json.Unmarshal error on malformed
// JSON, matching the prior inline behavior of the verification accessors.
func callJSON[T any](result *C.char, fallback string) (*T, error) {
	s, err := simpleStringResult(result, fallback)
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateAgreementV2 creates a standalone JACS agreement v2 document.
// inputJSON must match the Rust CreateAgreementV2 wire shape.
func (a *JacsSimpleAgent) CreateAgreementV2(inputJSON string) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	cInput := C.CString(inputJSON)
	defer C.free(unsafe.Pointer(cInput))
	return simpleStringResult(
		C.jacs_simple_create_agreement_v2(a.handle, cInput),
		"failed to create agreement v2",
	)
}

// ApplyAgreementV2 applies an agreement v2 mutation and returns the successor document JSON.
func (a *JacsSimpleAgent) ApplyAgreementV2(documentJSON, mutationJSON string) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	cDocument := C.CString(documentJSON)
	defer C.free(unsafe.Pointer(cDocument))
	cMutation := C.CString(mutationJSON)
	defer C.free(unsafe.Pointer(cMutation))
	return simpleStringResult(
		C.jacs_simple_apply_agreement_v2(a.handle, cDocument, cMutation),
		"failed to update agreement v2",
	)
}

// SignAgreementV2 adds this agent's signer, witness, or notary agreement signature.
// Empty role defaults to "signer".
func (a *JacsSimpleAgent) SignAgreementV2(documentJSON, role string) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	if role == "" {
		role = "signer"
	}
	cDocument := C.CString(documentJSON)
	defer C.free(unsafe.Pointer(cDocument))
	cRole := C.CString(role)
	defer C.free(unsafe.Pointer(cRole))
	return simpleStringResult(
		C.jacs_simple_sign_agreement_v2(a.handle, cDocument, cRole),
		"failed to sign agreement v2",
	)
}

// VerifyAgreementV2 verifies agreement v2 hash, role, status, transcript, and signature invariants.
func (a *JacsSimpleAgent) VerifyAgreementV2(documentJSON string) (*AgreementV2VerificationReport, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	cDocument := C.CString(documentJSON)
	defer C.free(unsafe.Pointer(cDocument))
	raw, err := simpleStringResult(
		C.jacs_simple_verify_agreement_v2(a.handle, cDocument),
		"failed to verify agreement v2",
	)
	if err != nil {
		return nil, err
	}
	var report AgreementV2VerificationReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return nil, err
	}
	return &report, nil
}

// DetectAgreementV2BranchConflict reports whether two successor versions are transcript-only mergeable.
func (a *JacsSimpleAgent) DetectAgreementV2BranchConflict(baseJSON, leftJSON, rightJSON string) (*AgreementV2MergeAnalysis, error) {
	if a.handle == nil {
		return nil, errors.New("JacsSimpleAgent is closed")
	}
	cBase := C.CString(baseJSON)
	defer C.free(unsafe.Pointer(cBase))
	cLeft := C.CString(leftJSON)
	defer C.free(unsafe.Pointer(cLeft))
	cRight := C.CString(rightJSON)
	defer C.free(unsafe.Pointer(cRight))
	raw, err := simpleStringResult(
		C.jacs_simple_detect_agreement_v2_branch_conflict(a.handle, cBase, cLeft, cRight),
		"failed to detect agreement v2 branch conflict",
	)
	if err != nil {
		return nil, err
	}
	var analysis AgreementV2MergeAnalysis
	if err := json.Unmarshal([]byte(raw), &analysis); err != nil {
		return nil, err
	}
	return &analysis, nil
}

// MergeAgreementV2TranscriptBranches auto-merges two transcript-only branches.
func (a *JacsSimpleAgent) MergeAgreementV2TranscriptBranches(baseJSON, leftJSON, rightJSON string) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	cBase := C.CString(baseJSON)
	defer C.free(unsafe.Pointer(cBase))
	cLeft := C.CString(leftJSON)
	defer C.free(unsafe.Pointer(cLeft))
	cRight := C.CString(rightJSON)
	defer C.free(unsafe.Pointer(cRight))
	return simpleStringResult(
		C.jacs_simple_merge_agreement_v2_transcript_branches(a.handle, cBase, cLeft, cRight),
		"failed to merge agreement v2 transcript branches",
	)
}

// ResolveAgreementV2BranchConflict resolves a conflicting branch with an explicit mutation.
func (a *JacsSimpleAgent) ResolveAgreementV2BranchConflict(baseJSON, previousJSON, sideBranchJSON, mutationJSON string) (string, error) {
	if a.handle == nil {
		return "", errors.New("JacsSimpleAgent is closed")
	}
	cBase := C.CString(baseJSON)
	defer C.free(unsafe.Pointer(cBase))
	cPrevious := C.CString(previousJSON)
	defer C.free(unsafe.Pointer(cPrevious))
	cSideBranch := C.CString(sideBranchJSON)
	defer C.free(unsafe.Pointer(cSideBranch))
	cMutation := C.CString(mutationJSON)
	defer C.free(unsafe.Pointer(cMutation))
	return simpleStringResult(
		C.jacs_simple_resolve_agreement_v2_branch_conflict(a.handle, cBase, cPrevious, cSideBranch, cMutation),
		"failed to resolve agreement v2 branch conflict",
	)
}
