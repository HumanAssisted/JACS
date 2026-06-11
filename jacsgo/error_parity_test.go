package jacs

// Error kind parity test for the Go binding.
//
// Validates that all error kinds listed in the `error_kinds` array of
// binding-core/tests/fixtures/parity_inputs.json are recognized by the
// Go binding's error handling.
//
// Go maps Rust ErrorKind variants through:
// 1. Named sentinel errors in errors.go (ErrSigningFailed, etc.)
// 2. Error message strings from the CGo FFI layer
//
// This test complements, not duplicates, the behavioral error tests in
// simple_agent_parity_test.go.
//
// KNOWN LIMITATION: 8 of 13 error kinds are validated structurally only
// (mapping existence in errorKindMap), not behaviorally (actually triggered
// at runtime). Untriggerable kinds require states impractical in unit tests
// (e.g., mutex poisoning, network calls, trust store setup).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

type parityInputsForErrors struct {
	ErrorKinds []string `json:"error_kinds"`
}

func loadErrorKindsFromFixture(t *testing.T) []string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixturePath := filepath.Join(filepath.Dir(thisFile), fixtureRelPath)

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read parity_inputs.json at %s: %v", fixturePath, err)
	}

	var p parityInputsForErrors
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("failed to parse parity_inputs.json: %v", err)
	}

	if len(p.ErrorKinds) == 0 {
		t.Fatal("error_kinds array is empty in parity_inputs.json")
	}

	return p.ErrorKinds
}

// errorKindInfo documents how each Rust ErrorKind is represented in Go.
type errorKindInfo struct {
	// goSentinel is the name of the Go sentinel error variable (if any).
	// Empty string means no dedicated Go sentinel exists.
	goSentinel string
	// messagePattern is a substring expected in error messages for this kind.
	messagePattern string
	// triggerable indicates if this error can be reliably triggered in tests.
	triggerable bool
}

// errorKindMap documents how each Rust ErrorKind variant maps to Go.
// This must be updated when a new ErrorKind variant is added.
var errorKindMap = map[string]errorKindInfo{
	"LockFailed": {
		goSentinel:     "",
		messagePattern: "lock",
		triggerable:    false, // Requires concurrent mutex poisoning
	},
	"AgentLoad": {
		goSentinel:     "ErrConfigNotFound",
		messagePattern: "config",
		triggerable:    true,
	},
	"Validation": {
		goSentinel:     "ErrConfigInvalid",
		messagePattern: "invalid",
		triggerable:    true,
	},
	"SigningFailed": {
		goSentinel:     "ErrSigningFailed",
		messagePattern: "sign",
		triggerable:    true,
	},
	"VerificationFailed": {
		goSentinel:     "ErrVerificationFailed",
		messagePattern: "verification",
		triggerable:    true,
	},
	"DocumentFailed": {
		goSentinel:     "ErrInvalidDocument",
		messagePattern: "document",
		triggerable:    false,
	},
	"AgreementFailed": {
		goSentinel:     "",
		messagePattern: "agreement",
		triggerable:    false,
	},
	"SerializationFailed": {
		goSentinel:     "",
		messagePattern: "serialization",
		triggerable:    false,
	},
	"InvalidArgument": {
		goSentinel:     "",
		messagePattern: "invalid",
		triggerable:    true,
	},
	"TrustFailed": {
		goSentinel:     "ErrAgentNotTrusted",
		messagePattern: "trust",
		triggerable:    false,
	},
	"NetworkFailed": {
		goSentinel:     "",
		messagePattern: "network",
		triggerable:    false,
	},
	"KeyNotFound": {
		goSentinel:     "ErrKeyNotFound",
		messagePattern: "key",
		triggerable:    false,
	},
	"Generic": {
		goSentinel:     "",
		messagePattern: "",
		triggerable:    false,
	},
	"MissingSignature": {
		// C1: strict-mode VerifyText / VerifyImage return this sentinel; permissive
		// mode returns a typed status, not the sentinel.
		goSentinel:     "ErrMissingSignature",
		messagePattern: "no JACS signature found",
		triggerable:    true,
	},
}

// TestErrorKindParityFromFixture validates all error kinds from the fixture
// are mapped in the Go binding.
func TestErrorKindParityFromFixture(t *testing.T) {
	errorKinds := loadErrorKindsFromFixture(t)

	unmapped := []string{}
	for _, kind := range errorKinds {
		if _, ok := errorKindMap[kind]; !ok {
			unmapped = append(unmapped, kind)
		}
	}

	if len(unmapped) > 0 {
		sort.Strings(unmapped)
		t.Errorf("Error kinds from fixture not mapped in Go: %v.\n"+
			"Add entries to errorKindMap in error_parity_test.go.", unmapped)
	}
}

// TestErrorKindMapHasNoStaleEntries validates the Go map doesn't have extras.
func TestErrorKindMapHasNoStaleEntries(t *testing.T) {
	errorKinds := loadErrorKindsFromFixture(t)
	fixtureSet := make(map[string]bool)
	for _, k := range errorKinds {
		fixtureSet[k] = true
	}

	stale := []string{}
	for kind := range errorKindMap {
		if !fixtureSet[kind] {
			stale = append(stale, kind)
		}
	}

	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("errorKindMap contains stale entries not in fixture: %v. Remove them.", stale)
	}
}

// TestErrorKindCount validates there are exactly 14 error kinds.
func TestErrorKindCount(t *testing.T) {
	errorKinds := loadErrorKindsFromFixture(t)

	if len(errorKinds) != 14 {
		t.Errorf("expected 14 error kinds in fixture, got %d", len(errorKinds))
	}
	if len(errorKindMap) != 14 {
		t.Errorf("expected 14 entries in errorKindMap, got %d", len(errorKindMap))
	}
}

// TestMissingSignatureKindInFixture validates the new C1/Q2 MissingSignature
// kind lands in the parity fixture and in errorKindMap.
func TestMissingSignatureKindInFixture(t *testing.T) {
	errorKinds := loadErrorKindsFromFixture(t)
	var found bool
	for _, k := range errorKinds {
		if k == "MissingSignature" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("MissingSignature missing from parity_inputs.json (PRD §4.1.2)")
	}
	if _, ok := errorKindMap["MissingSignature"]; !ok {
		t.Fatal("MissingSignature missing from errorKindMap")
	}
}

// TestGoSentinelErrorsExist validates that referenced Go sentinel errors
// are actually defined (compile-time check via reference).
func TestGoSentinelErrorsExist(t *testing.T) {
	// These references ensure the sentinel errors exist at compile time.
	sentinels := map[string]error{
		"ErrConfigNotFound":     ErrConfigNotFound,
		"ErrConfigInvalid":      ErrConfigInvalid,
		"ErrSigningFailed":      ErrSigningFailed,
		"ErrVerificationFailed": ErrVerificationFailed,
		"ErrInvalidDocument":    ErrInvalidDocument,
		"ErrAgentNotTrusted":    ErrAgentNotTrusted,
		"ErrKeyNotFound":        ErrKeyNotFound,
		"ErrMissingSignature":   ErrMissingSignature,
	}

	for name, sentinel := range sentinels {
		if sentinel == nil {
			t.Errorf("sentinel error %s should not be nil", name)
		}
		if sentinel.Error() == "" {
			t.Errorf("sentinel error %s should have a non-empty message", name)
		}
	}
}
