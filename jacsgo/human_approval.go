package jacs

/*
#cgo CFLAGS: -I${SRCDIR}/build
#cgo darwin LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build
#cgo linux LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build

#include "jacs_cgo.h"
*/
import "C"
import (
	"errors"
	"runtime"
	"strings"
)

// VerifyHumanApprovedDocument verifies retained public evidence and JACS
// provenance without constructing an agent, unlocking a private key, or using
// a local key store. It returns the complete native verification report JSON.
//
// expectedJSON is the independently expected HumanApprovalExpectationV1.
// authorityJSON and provenanceJSON are separately selected public-key pins for
// the enrollment authority and document signer. Do not select these arguments
// from the submitted bundle or treat successful verification as live action
// authorization: both report current fields remain "not_evaluated". Schema and
// application policy, external media, lifecycle status, one-use execution and
// trusted approval time remain caller responsibilities.
//
// The native library must be built with the human-approval Cargo feature.
func VerifyHumanApprovedDocument(bundleJSON, expectedJSON, authorityJSON, provenanceJSON string) (string, error) {
	for _, input := range []string{bundleJSON, expectedJSON, authorityJSON, provenanceJSON} {
		if strings.IndexByte(input, 0) >= 0 {
			return "", errors.New("JACS_ERROR_KIND=InvalidArgument: human approval JSON arguments must not contain NUL bytes")
		}
	}
	cBundle, freeBundle := cString(bundleJSON)
	defer freeBundle()
	cExpected, freeExpected := cString(expectedJSON)
	defer freeExpected()
	cAuthority, freeAuthority := cString(authorityJSON)
	defer freeAuthority()
	cProvenance, freeProvenance := cString(provenanceJSON)
	defer freeProvenance()
	// The existing native error channel is thread-local. Keep the verification
	// call and last-error retrieval on the same OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return simpleStringResult(
		C.jacs_verify_human_approved_document(cBundle, cExpected, cAuthority, cProvenance),
		"failed to verify human-approved document",
	)
}
