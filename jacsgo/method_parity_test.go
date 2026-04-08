package jacs

// Method enumeration parity test for the Go binding.
//
// Validates that all methods listed in
// binding-core/tests/fixtures/method_parity.json are exposed on the
// Go JacsSimpleAgent struct, with documented exclusions and Go-style
// name mappings.
//
// This is a *structural* test (method names), not a *behavioral* test.
// It complements, not duplicates, simple_agent_parity_test.go.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
)

const methodFixtureRelPath = "../binding-core/tests/fixtures/method_parity.json"

type methodParityFixture struct {
	AllMethodsFlat []string `json:"all_methods_flat"`
}

func loadMethodParityFixture(t *testing.T) methodParityFixture {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixturePath := filepath.Join(filepath.Dir(thisFile), methodFixtureRelPath)

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read method_parity.json at %s: %v", fixturePath, err)
	}

	var f methodParityFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("failed to parse method_parity.json: %v", err)
	}
	return f
}

// Methods that are intentionally not exposed in Go (with reasons).
var excludedFromGo = map[string]string{
	// inner_ref returns a raw Rust reference; not meaningful across CGo FFI
	"inner_ref": "raw Rust reference, not FFI-safe",
	// from_agent wraps a Rust SimpleAgent; not callable from Go
	"from_agent": "Rust-internal constructor",
	// load_with_info is an internal Rust helper; Go uses LoadSimpleAgent()
	"load_with_info": "internal helper, Go uses LoadSimpleAgent",
	// Conversion methods are not exposed via the CGo FFI layer.
	// They would require additional C wrapper functions.
	"to_yaml":     "not exposed via CGo FFI",
	"from_yaml":   "not exposed via CGo FFI",
	"to_html":     "not exposed via CGo FFI",
	"from_html":   "not exposed via CGo FFI",
	"rotate_keys": "not exposed via CGo FFI",
}

// Rust snake_case -> Go PascalCase method name mapping.
// Constructors are package-level functions, not methods on *JacsSimpleAgent.
var goNameMap = map[string]string{
	"create":              "NewSimpleAgent",          // constructor (package-level)
	"load":                "LoadSimpleAgent",         // constructor (package-level)
	"ephemeral":           "EphemeralSimpleAgent",    // constructor (package-level)
	"create_with_params":  "CreateSimpleAgentWithParams", // constructor (package-level)
	"get_agent_id":        "GetAgentID",
	"key_id":              "KeyID",
	"is_strict":           "IsStrict",
	"config_path":         "ConfigPath",
	"export_agent":        "ExportAgent",
	"get_public_key_pem":  "GetPublicKeyPEM",
	"get_public_key_base64": "GetPublicKeyBase64",
	"diagnostics":         "Diagnostics",
	"verify_self":         "VerifySelf",
	"verify_json":         "Verify",
	"verify_with_key_json": "VerifyWithKey",
	"verify_by_id_json":   "VerifyByID",
	"sign_message_json":   "SignMessage",
	"sign_raw_bytes_base64": "SignRawBytes",
	"sign_file_json":      "SignFile",
}

// Constructors are package-level functions, not methods on *JacsSimpleAgent.
var goConstructors = map[string]bool{
	"NewSimpleAgent":              true,
	"LoadSimpleAgent":             true,
	"EphemeralSimpleAgent":        true,
	"CreateSimpleAgentWithParams": true,
}

// goConstructorFuncs references actual constructor functions so the compiler
// catches removals. If any constructor is renamed or deleted, this file fails
// to compile -- no runtime test needed.
var goConstructorFuncs = map[string]interface{}{
	"NewSimpleAgent":              NewSimpleAgent,
	"LoadSimpleAgent":             LoadSimpleAgent,
	"EphemeralSimpleAgent":        EphemeralSimpleAgent,
	"CreateSimpleAgentWithParams": CreateSimpleAgentWithParams,
}

// TestMethodParityAgainstFixture validates that all expected methods exist
// on Go's JacsSimpleAgent.
func TestMethodParityAgainstFixture(t *testing.T) {
	fixture := loadMethodParityFixture(t)

	// Get all methods on *JacsSimpleAgent via reflection
	agentType := reflect.TypeOf(&JacsSimpleAgent{})
	instanceMethods := make(map[string]bool)
	for i := 0; i < agentType.NumMethod(); i++ {
		instanceMethods[agentType.Method(i).Name] = true
	}

	missing := []string{}
	for _, rustName := range fixture.AllMethodsFlat {
		if _, excluded := excludedFromGo[rustName]; excluded {
			continue
		}

		goName, mapped := goNameMap[rustName]
		if !mapped {
			missing = append(missing, rustName+" (no goNameMap entry)")
			continue
		}

		if goConstructors[goName] {
			// Constructors are package-level functions, verified at
			// compile time via goConstructorFuncs (references the actual
			// functions). If a constructor is removed, this file fails
			// to compile.
			continue
		}

		if !instanceMethods[goName] {
			missing = append(missing, rustName+" -> "+goName)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("Go JacsSimpleAgent is missing %d methods from method_parity.json:\n%s\n\n"+
			"If a method was intentionally excluded, add it to excludedFromGo.\n"+
			"If it has a different Go name, add it to goNameMap.",
			len(missing), formatLines(missing))
	}
}

// TestMethodParityExclusionsAreValid verifies every excluded method exists in the fixture.
func TestMethodParityExclusionsAreValid(t *testing.T) {
	fixture := loadMethodParityFixture(t)
	allMethods := make(map[string]bool)
	for _, m := range fixture.AllMethodsFlat {
		allMethods[m] = true
	}

	invalid := []string{}
	for excluded := range excludedFromGo {
		if !allMethods[excluded] {
			invalid = append(invalid, excluded)
		}
	}

	if len(invalid) > 0 {
		t.Errorf("excludedFromGo contains methods not in the fixture: %v. Remove stale exclusions.", invalid)
	}
}

// TestMethodParityNameMapCoversAll verifies the name map covers all non-excluded methods.
func TestMethodParityNameMapCoversAll(t *testing.T) {
	fixture := loadMethodParityFixture(t)

	unmapped := []string{}
	for _, rustName := range fixture.AllMethodsFlat {
		if _, excluded := excludedFromGo[rustName]; excluded {
			continue
		}
		if _, mapped := goNameMap[rustName]; !mapped {
			unmapped = append(unmapped, rustName)
		}
	}

	if len(unmapped) > 0 {
		t.Errorf("Methods without goNameMap entry: %v. Add a mapping.", unmapped)
	}
}

// TestMethodParityExclusionsAreStillNeeded checks if excluded methods
// have since been exposed on *JacsSimpleAgent. If a method was excluded
// because it wasn't in the CGo FFI layer but has since been added, this
// test fails to prompt removal of the exclusion.
func TestMethodParityExclusionsAreStillNeeded(t *testing.T) {
	agentType := reflect.TypeOf(&JacsSimpleAgent{})

	// Only check conversion-method exclusions (the ones likely to change).
	// internal-only exclusions (inner_ref, from_agent, load_with_info) will
	// never appear as Go methods.
	conversionExclusions := map[string]string{
		"to_yaml":  "ToYaml",
		"from_yaml": "FromYaml",
		"to_html":  "ToHtml",
		"from_html": "FromHtml",
	}

	newlyAvailable := []string{}
	for rustName, goName := range conversionExclusions {
		_, found := agentType.MethodByName(goName)
		if found {
			newlyAvailable = append(newlyAvailable, rustName+" -> "+goName)
		}
	}

	if len(newlyAvailable) > 0 {
		sort.Strings(newlyAvailable)
		t.Errorf("Excluded methods are now available on *JacsSimpleAgent. "+
			"Remove them from excludedFromGo and verify they work:\n%s",
			formatLines(newlyAvailable))
	}
}

func formatLines(items []string) string {
	result := ""
	for _, item := range items {
		result += "  - " + item + "\n"
	}
	return result
}
