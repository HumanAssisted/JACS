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
		return "", errSimpleAgentClosed
	}
	cInput, freeInput := cString(inputJSON)
	defer freeInput()
	return simpleStringResult(
		C.jacs_simple_create_agreement_v2(a.handle, cInput),
		"failed to create agreement v2",
	)
}

// ApplyAgreementV2 applies an agreement v2 mutation and returns the successor document JSON.
func (a *JacsSimpleAgent) ApplyAgreementV2(documentJSON, mutationJSON string) (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	cDocument, freeDocument := cString(documentJSON)
	defer freeDocument()
	cMutation, freeMutation := cString(mutationJSON)
	defer freeMutation()
	return simpleStringResult(
		C.jacs_simple_apply_agreement_v2(a.handle, cDocument, cMutation),
		"failed to update agreement v2",
	)
}

// SignAgreementV2 adds this agent's signer, witness, or notary agreement signature.
// Empty role defaults to "signer".
func (a *JacsSimpleAgent) SignAgreementV2(documentJSON, role string) (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	if role == "" {
		role = "signer"
	}
	cDocument, freeDocument := cString(documentJSON)
	defer freeDocument()
	cRole, freeRole := cString(role)
	defer freeRole()
	return simpleStringResult(
		C.jacs_simple_sign_agreement_v2(a.handle, cDocument, cRole),
		"failed to sign agreement v2",
	)
}

// VerifyAgreementV2 verifies agreement v2 hash, role, status, transcript, and signature invariants.
func (a *JacsSimpleAgent) VerifyAgreementV2(documentJSON string) (*AgreementV2VerificationReport, error) {
	if a.handle == nil {
		return nil, errSimpleAgentClosed
	}
	cDocument, freeDocument := cString(documentJSON)
	defer freeDocument()
	return callJSON[AgreementV2VerificationReport](
		C.jacs_simple_verify_agreement_v2(a.handle, cDocument),
		"failed to verify agreement v2",
	)
}

// DetectAgreementV2BranchConflict reports whether two successor versions are transcript-only mergeable.
func (a *JacsSimpleAgent) DetectAgreementV2BranchConflict(baseJSON, leftJSON, rightJSON string) (*AgreementV2MergeAnalysis, error) {
	if a.handle == nil {
		return nil, errSimpleAgentClosed
	}
	cBase, freeBase := cString(baseJSON)
	defer freeBase()
	cLeft, freeLeft := cString(leftJSON)
	defer freeLeft()
	cRight, freeRight := cString(rightJSON)
	defer freeRight()
	return callJSON[AgreementV2MergeAnalysis](
		C.jacs_simple_detect_agreement_v2_branch_conflict(a.handle, cBase, cLeft, cRight),
		"failed to detect agreement v2 branch conflict",
	)
}

// MergeAgreementV2TranscriptBranches auto-merges two transcript-only branches.
func (a *JacsSimpleAgent) MergeAgreementV2TranscriptBranches(baseJSON, leftJSON, rightJSON string) (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	cBase, freeBase := cString(baseJSON)
	defer freeBase()
	cLeft, freeLeft := cString(leftJSON)
	defer freeLeft()
	cRight, freeRight := cString(rightJSON)
	defer freeRight()
	return simpleStringResult(
		C.jacs_simple_merge_agreement_v2_transcript_branches(a.handle, cBase, cLeft, cRight),
		"failed to merge agreement v2 transcript branches",
	)
}

// ResolveAgreementV2BranchConflict resolves a conflicting branch with an explicit mutation.
func (a *JacsSimpleAgent) ResolveAgreementV2BranchConflict(baseJSON, previousJSON, sideBranchJSON, mutationJSON string) (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	cBase, freeBase := cString(baseJSON)
	defer freeBase()
	cPrevious, freePrevious := cString(previousJSON)
	defer freePrevious()
	cSideBranch, freeSideBranch := cString(sideBranchJSON)
	defer freeSideBranch()
	cMutation, freeMutation := cString(mutationJSON)
	defer freeMutation()
	return simpleStringResult(
		C.jacs_simple_resolve_agreement_v2_branch_conflict(a.handle, cBase, cPrevious, cSideBranch, cMutation),
		"failed to resolve agreement v2 branch conflict",
	)
}
