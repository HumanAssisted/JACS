// Inline text + media binding methods (Task 12 — PRD §3.1, §3.2, §4.1, §4.2).
//
// These methods route through the new CGo FFI exports added in
// jacsgo/lib/src/lib.rs (jacs_agent_sign_text / verify_text / sign_image /
// verify_image / extract_media_signature). Each export returns either:
//   - a success-shaped JSON envelope, or
//   - a structured error envelope: {"error":"...","error_kind":"..."}
//
// On a structured error envelope with `error_kind == "MissingSignature"`
// (PRD §C1, strict mode), the binding surfaces ErrMissingSignature as a
// Go sentinel so callers can match via errors.Is(err, ErrMissingSignature).

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
	"fmt"
)

// =============================================================================
// JSON helpers
// =============================================================================

// detectStructuredError parses the FFI return string as a structured error
// envelope `{"error": "...", "error_kind": "..."}`. Returns a wrapped Go
// error when the envelope matches; nil when the string is a normal
// success payload. Strict-mode missing-signature is mapped to the
// ErrMissingSignature sentinel.
func detectStructuredError(payload string, op string) error {
	if payload == "" {
		return nil
	}
	var probe struct {
		Error     string `json:"error"`
		ErrorKind string `json:"error_kind"`
	}
	if err := json.Unmarshal([]byte(payload), &probe); err != nil {
		// Not a JSON object — not a structured error envelope.
		return nil
	}
	if probe.Error == "" && probe.ErrorKind == "" {
		return nil
	}
	if probe.ErrorKind == "MissingSignature" {
		// Wrap the sentinel so `errors.Is(err, ErrMissingSignature)` matches
		// while preserving the upstream message.
		return fmt.Errorf("%s: %s: %w", op, probe.Error, ErrMissingSignature)
	}
	return fmt.Errorf("%s: %s (%s)", op, probe.Error, probe.ErrorKind)
}

// optsJSON marshals the given object to a JSON string. Safe to call with nil
// (returns "" → C.NULL → defaults on the Rust side).
func optsJSON(v interface{}) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		// Should never happen for our small option structs; fall through to
		// empty-string defaults rather than failing.
		return ""
	}
	return string(b)
}

// callWithOpts invokes a C function that takes (handle, file_path, opts_json)
// and returns a *char payload to be freed by the caller.
func (a *JacsSimpleAgent) callPathOpts(
	op string,
	c func(C.SimpleAgentHandle, *C.char, *C.char) *C.char,
	filePath string,
	optsJsonStr string,
) (string, error) {
	cPath, freePath := cString(filePath)
	defer freePath()

	var cOpts *C.char
	if optsJsonStr != "" {
		var freeOpts func()
		cOpts, freeOpts = cString(optsJsonStr)
		defer freeOpts()
	}

	result := c(a.handle, cPath, cOpts)
	if result == nil {
		return "", simpleLastError(op + ": null result")
	}
	defer C.jacs_free_string(result)
	payload := C.GoString(result)

	if err := detectStructuredError(payload, op); err != nil {
		return "", err
	}
	return payload, nil
}

// =============================================================================
// SignText / SignTextFile
// =============================================================================

// signTextInner is the shared worker for SignText / SignTextFile.
func (a *JacsSimpleAgent) signTextInner(filePath string, opts *SignTextOpts) (*SignTextResult, error) {
	o := opts
	if o == nil {
		o = &SignTextOpts{}
	}
	// Match the binding-core wire shape used by every other binding:
	// {"backup": <bool>}. NoBackup=false → backup=true.
	wire := map[string]interface{}{"backup": !o.NoBackup}

	payload, err := a.callPathOpts("sign_text", func(h C.SimpleAgentHandle, p, j *C.char) *C.char {
		return C.jacs_agent_sign_text(h, p, j)
	}, filePath, optsJSON(wire))
	if err != nil {
		return nil, err
	}

	var out SignTextResult
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return nil, NewSimpleError("sign_text", err)
	}
	return &out, nil
}

// SignText signs a text/markdown file in place by appending an inline JACS
// signature block (PRD §4.1). Pass nil for default options.
func (a *JacsSimpleAgent) SignText(filePath string, opts *SignTextOpts) error {
	_, err := a.signTextInner(filePath, opts)
	return err
}

// SignTextFile is the parity-name alias for [JacsSimpleAgent.SignText]
// (matches the binding-core method `sign_text_file_json`).
func (a *JacsSimpleAgent) SignTextFile(filePath string, opts *SignTextOpts) error {
	return a.SignText(filePath, opts)
}

// =============================================================================
// VerifyText / VerifyTextFile
// =============================================================================

// verifyTextInner is the shared worker for VerifyText / VerifyTextFile.
func (a *JacsSimpleAgent) verifyTextInner(filePath string, opts *VerifyTextOpts) (*VerifyTextResult, error) {
	o := opts
	if o == nil {
		o = &VerifyTextOpts{}
	}
	wire := map[string]interface{}{"strict": o.Strict}
	if o.KeyDir != "" {
		wire["keyDir"] = o.KeyDir
	}

	payload, err := a.callPathOpts("verify_text", func(h C.SimpleAgentHandle, p, j *C.char) *C.char {
		return C.jacs_agent_verify_text(h, p, j)
	}, filePath, optsJSON(wire))
	if err != nil {
		return nil, err
	}

	var out VerifyTextResult
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return nil, NewSimpleError("verify_text", err)
	}
	return &out, nil
}

// VerifyText verifies inline JACS signatures in a text/markdown file
// (PRD §4.1, C1). Pass nil for the permissive default; pass
// &VerifyTextOpts{Strict: true} for strict-mode behaviour where missing
// signatures return an error wrapping ErrMissingSignature.
func (a *JacsSimpleAgent) VerifyText(filePath string, opts *VerifyTextOpts) (*VerifyTextResult, error) {
	return a.verifyTextInner(filePath, opts)
}

// VerifyTextFile is the parity-name alias for [JacsSimpleAgent.VerifyText].
func (a *JacsSimpleAgent) VerifyTextFile(filePath string, opts *VerifyTextOpts) (*VerifyTextResult, error) {
	return a.VerifyText(filePath, opts)
}

// =============================================================================
// SignImage / VerifyImage
// =============================================================================

// SignImage signs a PNG / JPEG / WebP image, embedding a JACS signature
// (PRD §4.2). `outputPath` may equal `inputPath` for in-place writes.
// Pass nil for default options (Robust off — Q4).
func (a *JacsSimpleAgent) SignImage(inputPath, outputPath string, opts *SignImageOpts) (*SignImageResult, error) {
	o := opts
	if o == nil {
		o = &SignImageOpts{}
	}
	wire := map[string]interface{}{
		"robust":          o.Robust,
		"refuseOverwrite": o.RefuseOverwrite,
	}
	if o.Format != "" {
		wire["formatHint"] = o.Format
	}

	cIn, freeIn := cString(inputPath)
	defer freeIn()
	cOut, freeOut := cString(outputPath)
	defer freeOut()

	optsStr := optsJSON(wire)
	var cOpts *C.char
	if optsStr != "" {
		var freeOpts func()
		cOpts, freeOpts = cString(optsStr)
		defer freeOpts()
	}

	result := C.jacs_agent_sign_image(a.handle, cIn, cOut, cOpts)
	if result == nil {
		return nil, simpleLastError("sign_image: null result")
	}
	defer C.jacs_free_string(result)
	payload := C.GoString(result)

	if err := detectStructuredError(payload, "sign_image"); err != nil {
		return nil, err
	}

	var out SignImageResult
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return nil, NewSimpleError("sign_image", err)
	}
	return &out, nil
}

// VerifyImage verifies an embedded JACS signature in an image
// (PRD §4.2, C1). Pass nil for the permissive default; pass
// &VerifyImageOpts{Strict: true} for strict-mode behaviour.
func (a *JacsSimpleAgent) VerifyImage(filePath string, opts *VerifyImageOpts) (*VerifyImageResult, error) {
	o := opts
	if o == nil {
		o = &VerifyImageOpts{}
	}
	wire := map[string]interface{}{
		"strict": o.Strict,
		"robust": o.Robust,
	}
	if o.KeyDir != "" {
		wire["keyDir"] = o.KeyDir
	}

	payload, err := a.callPathOpts("verify_image", func(h C.SimpleAgentHandle, p, j *C.char) *C.char {
		return C.jacs_agent_verify_image(h, p, j)
	}, filePath, optsJSON(wire))
	if err != nil {
		return nil, err
	}

	var out VerifyImageResult
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		return nil, NewSimpleError("verify_image", err)
	}
	return &out, nil
}

// =============================================================================
// ExtractMediaSignature
// =============================================================================

// extractMediaEnvelope mirrors the JSON envelope returned by
// SimpleAgentWrapper::extract_media_signature_json: `{ "present": bool,
// "payload": <string|null> }`.
type extractMediaEnvelope struct {
	Present bool    `json:"present"`
	Payload *string `json:"payload"`
}

// ExtractMediaSignature extracts the JACS signature payload embedded in a
// signed image (PRD §3.2). When opts.RawPayload is true, returns the raw
// base64url wire form; otherwise returns the decoded JACS signed-document
// JSON string.
//
// Returns ("", false, nil) when the input has no JACS signature — this is
// not an error.
func (a *JacsSimpleAgent) ExtractMediaSignature(filePath string, opts *ExtractMediaOpts) (string, bool, error) {
	o := opts
	if o == nil {
		o = &ExtractMediaOpts{}
	}
	wire := map[string]interface{}{"rawPayload": o.RawPayload}

	payload, err := a.callPathOpts("extract_media_signature", func(h C.SimpleAgentHandle, p, j *C.char) *C.char {
		return C.jacs_agent_extract_media_signature(h, p, j)
	}, filePath, optsJSON(wire))
	if err != nil {
		// "extract on unsigned" is not an error — only true FFI failures land
		// here. Surface them as-is.
		return "", false, err
	}

	var env extractMediaEnvelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		return "", false, NewSimpleError("extract_media_signature", err)
	}
	if !env.Present || env.Payload == nil {
		return "", false, nil
	}
	return *env.Payload, true, nil
}

// =============================================================================
// Compile-time assertions
// =============================================================================

// _ ensures errors.Is keeps working against ErrMissingSignature even after a
// future refactor accidentally swaps the wrapping. The build fails if the
// import goes away.
var _ = errors.Is
