//go:build human_approval

package jacs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// This shared fixture contains public verification evidence, not a private key
// or an enrollment/live-session substitute.
func loadHumanApprovalFixture(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "../binding-core/tests/fixtures/human_approved_document_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"bundle", "expected", "authority", "provenance", "report"} {
		if len(fixture[field]) == 0 {
			t.Fatalf("shared public fixture is missing %s", field)
		}
	}
	return fixture
}

func TestHumanApprovedDocumentVerifiesPublicEvidenceFromDiskWithoutAgent(t *testing.T) {
	fixture := loadHumanApprovalFixture(t)
	directory := t.TempDir()
	bundlePath := filepath.Join(directory, "approval.json")
	if err := os.WriteFile(bundlePath, fixture["bundle"], 0600); err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	// No agent construction, key unlock, implicit config or disk store is needed.
	t.Setenv("JACS_CONFIG", filepath.Join(directory, "missing-config.json"))
	t.Setenv("JACS_PRIVATE_KEY_PASSWORD", "")
	reportJSON, err := VerifyHumanApprovedDocument(string(bundle), string(fixture["expected"]), string(fixture["authority"]), string(fixture["provenance"]))
	if err != nil {
		t.Fatal(err)
	}
	var actual, expected map[string]interface{}
	if err := json.Unmarshal([]byte(reportJSON), &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fixture["report"], &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("public verifier must preserve the complete native verification report")
	}
	approval, ok := actual["approval"].(map[string]interface{})
	if !ok || actual["current"] != "not_evaluated" || approval["current"] != "not_evaluated" {
		t.Fatal("retained public proof must not become a live authorization verdict")
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 1 || files[0].Name() != "approval.json" {
		t.Fatalf("verification should not create a local signing identity: files=%v err=%v", files, err)
	}
}

func TestHumanApprovedDocumentRequiresExplicitContextAndBothPins(t *testing.T) {
	for _, changed := range []struct{ field, property string }{
		{"expected", "audience"},
		{"authority", "publicKeyHash"},
		{"provenance", "publicKeyHash"},
	} {
		t.Run(changed.field, func(t *testing.T) {
			fixture := loadHumanApprovalFixture(t)
			var input map[string]interface{}
			if err := json.Unmarshal(fixture[changed.field], &input); err != nil {
				t.Fatal(err)
			}
			input[changed.property] = "different-independent-expectation"
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			fixture[changed.field] = encoded
			report, err := VerifyHumanApprovedDocument(string(fixture["bundle"]), string(fixture["expected"]), string(fixture["authority"]), string(fixture["provenance"]))
			if err == nil || report != "" {
				t.Fatal("mismatched caller expectations must fail without a success report")
			}
			if !strings.Contains(err.Error(), loadPortableErrorContract(t).MessagePrefix+"VerificationFailed:") {
				t.Fatalf("wrong-pin error must retain the shared VerificationFailed category: %v", err)
			}
		})
	}
}

func TestHumanApprovedDocumentRejectsMalformedArguments(t *testing.T) {
	for _, field := range []string{"bundle", "expected", "authority", "provenance"} {
		for _, invalid := range []string{"", "{", "null", "nul_suffix"} {
			t.Run(field+"/"+invalid, func(t *testing.T) {
				fixture := loadHumanApprovalFixture(t)
				if invalid == "nul_suffix" {
					fixture[field] = append(fixture[field], []byte("\x00ignored")...)
				} else {
					fixture[field] = json.RawMessage(invalid)
				}
				report, err := VerifyHumanApprovedDocument(string(fixture["bundle"]), string(fixture["expected"]), string(fixture["authority"]), string(fixture["provenance"]))
				if err == nil || report != "" {
					t.Fatal("invalid arguments must fail without truncation or a success report")
				}
				kind := "InvalidArgument"
				if field == "bundle" && invalid != "nul_suffix" {
					kind = "VerificationFailed"
				}
				if !strings.Contains(err.Error(), loadPortableErrorContract(t).MessagePrefix+kind+":") {
					t.Fatalf("argument error must retain the shared %s category: %v", kind, err)
				}
			})
		}
	}
}
