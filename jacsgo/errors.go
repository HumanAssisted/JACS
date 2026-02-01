package jacs

import "errors"

// Common errors returned by the simplified JACS API.
var (
	// ErrConfigNotFound is returned when the configuration file is not found.
	ErrConfigNotFound = errors.New("config file not found: run 'jacs create' first")

	// ErrConfigInvalid is returned when the configuration file is invalid.
	ErrConfigInvalid = errors.New("config file is invalid")

	// ErrAgentNotLoaded is returned when no agent is currently loaded.
	ErrAgentNotLoaded = errors.New("no agent loaded: call Load() first")

	// ErrKeyNotFound is returned when a required key file is not found.
	ErrKeyNotFound = errors.New("key file not found")

	// ErrSigningFailed is returned when signing a document fails.
	ErrSigningFailed = errors.New("failed to sign document")

	// ErrVerificationFailed is returned when signature verification fails.
	ErrVerificationFailed = errors.New("signature verification failed")

	// ErrHashMismatch is returned when the content hash doesn't match.
	ErrHashMismatch = errors.New("content hash mismatch")

	// ErrFileNotFound is returned when a file to sign is not found.
	ErrFileNotFound = errors.New("file not found")

	// ErrAgentNotTrusted is returned when an agent is not in the trust store.
	ErrAgentNotTrusted = errors.New("agent is not trusted")

	// ErrInvalidDocument is returned when a document is malformed.
	ErrInvalidDocument = errors.New("invalid document format")
)

// SimpleError wraps an error with additional context.
type SimpleError struct {
	Op      string // Operation that failed
	Path    string // Path involved (if any)
	Wrapped error  // Underlying error
}

func (e *SimpleError) Error() string {
	if e.Path != "" {
		return e.Op + " " + e.Path + ": " + e.Wrapped.Error()
	}
	return e.Op + ": " + e.Wrapped.Error()
}

func (e *SimpleError) Unwrap() error {
	return e.Wrapped
}

// NewSimpleError creates a new SimpleError.
func NewSimpleError(op string, err error) *SimpleError {
	return &SimpleError{Op: op, Wrapped: err}
}

// NewSimpleErrorWithPath creates a new SimpleError with a path.
func NewSimpleErrorWithPath(op, path string, err error) *SimpleError {
	return &SimpleError{Op: op, Path: path, Wrapped: err}
}
