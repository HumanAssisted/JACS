package jacs

// Parity tests for the jacsgo (Go/CGo) binding.
//
// These tests verify the same behavior as the Rust parity tests in
// binding-core/tests/parity.rs. They use shared fixture inputs from
// ../binding-core/tests/fixtures/parity_inputs.json and verify:
//
// 1. Structural parity: signed documents contain the same field names/types
// 2. Roundtrip parity: sign -> verify succeeds for all fixture inputs
// 3. Identity parity: agent identity methods return expected types
// 4. Error parity: all bindings reject the same invalid inputs
// 5. Sign raw bytes parity: raw byte signing produces valid base64
// 6. Sign file parity: file signing produces verifiable documents
// 7. Verification result structure parity
//
// Note: Exact crypto output bytes differ per invocation (nonce/randomness),
// so we verify structure and verifiability, not byte-equality.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// =============================================================================
// Helpers
// =============================================================================

const fixtureRelPath = "../binding-core/tests/fixtures/parity_inputs.json"

// parityFixtures holds the deserialized parity_inputs.json.
type parityFixtures struct {
	SignMessageInputs  []signMessageInput  `json:"sign_message_inputs"`
	SignRawBytesInputs []signRawBytesInput `json:"sign_raw_bytes_inputs"`
	ExpectedSignedDoc  expectedSignedDoc   `json:"expected_signed_document_fields"`
	ExpectedVerifyRes  expectedVerifyRes   `json:"expected_verification_result_fields"`
	Algorithms         []string            `json:"algorithms"`
}

type signMessageInput struct {
	Name string      `json:"name"`
	Data interface{} `json:"data"`
}

type signRawBytesInput struct {
	Name       string `json:"name"`
	DataBase64 string `json:"data_base64"`
}

type expectedSignedDoc struct {
	RequiredTopLevel       []string `json:"required_top_level"`
	RequiredSignatureFields []string `json:"required_signature_fields"`
}

type expectedVerifyRes struct {
	Required []string `json:"required"`
	Optional []string `json:"optional"`
}

// loadParityFixtures reads and parses the shared fixture file.
func loadParityFixtures(t *testing.T) parityFixtures {
	t.Helper()

	// Resolve path relative to this test file's location.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixturePath := filepath.Join(filepath.Dir(thisFile), fixtureRelPath)

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read parity fixtures at %s: %v", fixturePath, err)
	}

	var f parityFixtures
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("failed to parse parity fixtures: %v", err)
	}
	return f
}

// skipIfLibraryMissing checks for the CGo shared library and skips the test
// if it has not been built yet.
func skipIfLibraryMissing(t *testing.T) {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	buildDir := filepath.Join(filepath.Dir(thisFile), "build")

	// Check for the platform-appropriate library file.
	var libName string
	switch runtime.GOOS {
	case "darwin":
		libName = "libjacsgo.dylib"
	case "windows":
		libName = "jacsgo.dll"
	default:
		libName = "libjacsgo.so"
	}

	libPath := filepath.Join(buildDir, libName)
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("CGo library not found at %s; build the Rust library first", libPath)
	}
}

// ephemeral creates an ephemeral JacsSimpleAgent with the given algorithm.
func ephemeral(t *testing.T, algo string) *JacsSimpleAgent {
	t.Helper()
	agent, info, err := EphemeralSimpleAgent(&algo)
	if err != nil {
		t.Fatalf("EphemeralSimpleAgent(%q) failed: %v", algo, err)
	}
	if agent == nil {
		t.Fatalf("EphemeralSimpleAgent(%q) returned nil agent", algo)
	}
	t.Cleanup(func() { agent.Close() })
	_ = info
	return agent
}

// =============================================================================
// 1. Structural parity: signed documents have required fields
// =============================================================================

func TestParitySignedDocumentStructure(t *testing.T) {
	skipIfLibraryMissing(t)
	fixtures := loadParityFixtures(t)
	agent := ephemeral(t, "ed25519")

	for _, input := range fixtures.SignMessageInputs {
		t.Run(input.Name, func(t *testing.T) {
			signed, err := agent.SignMessage(input.Data)
			if err != nil {
				t.Fatalf("SignMessage failed for %q: %v", input.Name, err)
			}
			if signed == nil || signed.Raw == "" {
				t.Fatalf("SignMessage returned empty result for %q", input.Name)
			}

			// Parse the raw signed JSON to check field presence.
			var doc map[string]interface{}
			if err := json.Unmarshal([]byte(signed.Raw), &doc); err != nil {
				t.Fatalf("signed output for %q is not valid JSON: %v", input.Name, err)
			}

			// Check required top-level fields.
			for _, field := range fixtures.ExpectedSignedDoc.RequiredTopLevel {
				if _, ok := doc[field]; !ok {
					t.Errorf("signed document for %q missing required field %q", input.Name, field)
				}
			}

			// Check required signature fields.
			sigObj, ok := doc["jacsSignature"].(map[string]interface{})
			if !ok {
				t.Fatalf("signed document for %q: jacsSignature is not an object", input.Name)
			}
			for _, field := range fixtures.ExpectedSignedDoc.RequiredSignatureFields {
				if _, ok := sigObj[field]; !ok {
					t.Errorf("jacsSignature for %q missing required field %q", input.Name, field)
				}
			}
		})
	}
}

// =============================================================================
// 2. Roundtrip parity: sign -> verify succeeds for all fixture inputs
// =============================================================================

func TestParitySignVerifyRoundtrip(t *testing.T) {
	skipIfLibraryMissing(t)
	fixtures := loadParityFixtures(t)
	agent := ephemeral(t, "ed25519")

	for _, input := range fixtures.SignMessageInputs {
		t.Run(input.Name, func(t *testing.T) {
			signed, err := agent.SignMessage(input.Data)
			if err != nil {
				t.Fatalf("SignMessage failed for %q: %v", input.Name, err)
			}

			result, err := agent.Verify(signed.Raw)
			if err != nil {
				t.Fatalf("Verify failed for %q: %v", input.Name, err)
			}
			if !result.Valid {
				t.Errorf("roundtrip verification failed for %q: errors=%v", input.Name, result.Errors)
			}
		})
	}
}

// =============================================================================
// 3. Sign raw bytes parity
// =============================================================================

func TestParitySignRawBytes(t *testing.T) {
	skipIfLibraryMissing(t)
	fixtures := loadParityFixtures(t)
	agent := ephemeral(t, "ed25519")

	for _, input := range fixtures.SignRawBytesInputs {
		t.Run(input.Name, func(t *testing.T) {
			data, err := base64.StdEncoding.DecodeString(input.DataBase64)
			if err != nil {
				t.Fatalf("fixture %q has invalid base64: %v", input.Name, err)
			}

			sigB64, err := agent.SignRawBytes(data)
			if err != nil {
				t.Fatalf("SignRawBytes failed for %q: %v", input.Name, err)
			}

			// Result should be valid base64.
			sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
			if err != nil {
				// Some implementations use URL-safe or raw base64; try those too.
				sigBytes, err = base64.RawStdEncoding.DecodeString(sigB64)
				if err != nil {
					sigBytes, err = base64.URLEncoding.DecodeString(sigB64)
					if err != nil {
						t.Fatalf("SignRawBytes result for %q is not valid base64: %q", input.Name, sigB64)
					}
				}
			}
			if len(sigBytes) == 0 {
				t.Errorf("signature for %q should be non-empty", input.Name)
			}
		})
	}
}

// =============================================================================
// 4. Identity parity: agent_id, key_id, public_key, diagnostics, etc.
// =============================================================================

func TestParityIdentityMethods(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")

	t.Run("GetAgentID", func(t *testing.T) {
		agentID, err := agent.GetAgentID()
		if err != nil {
			t.Fatalf("GetAgentID failed: %v", err)
		}
		if agentID == "" {
			t.Error("agent_id should be non-empty")
		}
	})

	t.Run("KeyID", func(t *testing.T) {
		keyID, err := agent.KeyID()
		if err != nil {
			t.Fatalf("KeyID failed: %v", err)
		}
		if keyID == "" {
			t.Error("key_id should be non-empty")
		}
	})

	t.Run("GetPublicKeyPEM", func(t *testing.T) {
		pem, err := agent.GetPublicKeyPEM()
		if err != nil {
			t.Fatalf("GetPublicKeyPEM failed: %v", err)
		}
		if !strings.Contains(pem, "-----BEGIN") && !strings.Contains(pem, "PUBLIC KEY") {
			t.Errorf("expected PEM format, got: %s", truncate(pem, 80))
		}
	})

	t.Run("GetPublicKeyBase64", func(t *testing.T) {
		keyB64, err := agent.GetPublicKeyBase64()
		if err != nil {
			t.Fatalf("GetPublicKeyBase64 failed: %v", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			// Try raw or URL-safe base64.
			decoded, err = base64.RawStdEncoding.DecodeString(keyB64)
			if err != nil {
				t.Fatalf("public key base64 is invalid: %v (value: %q)", err, truncate(keyB64, 80))
			}
		}
		if len(decoded) == 0 {
			t.Error("decoded public key should be non-empty")
		}
	})

	t.Run("ExportAgent", func(t *testing.T) {
		exported, err := agent.ExportAgent()
		if err != nil {
			t.Fatalf("ExportAgent failed: %v", err)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(exported), &parsed); err != nil {
			t.Fatalf("ExportAgent output is not valid JSON: %v", err)
		}
		if _, ok := parsed["jacsId"]; !ok {
			t.Error("exported agent should have jacsId")
		}
	})

	t.Run("Diagnostics", func(t *testing.T) {
		diag := agent.Diagnostics()
		var diagMap map[string]interface{}
		if err := json.Unmarshal([]byte(diag), &diagMap); err != nil {
			t.Fatalf("Diagnostics is not valid JSON: %v", err)
		}
		if _, ok := diagMap["jacs_version"]; !ok {
			t.Error("diagnostics should have jacs_version")
		}
		if loaded, ok := diagMap["agent_loaded"].(bool); !ok || !loaded {
			t.Errorf("diagnostics should show agent_loaded=true, got %v", diagMap["agent_loaded"])
		}
	})

	t.Run("VerifySelf", func(t *testing.T) {
		result, err := agent.VerifySelf()
		if err != nil {
			t.Fatalf("VerifySelf failed: %v", err)
		}
		if !result.Valid {
			t.Errorf("VerifySelf should be valid, errors=%v", result.Errors)
		}
	})

	t.Run("IsStrict", func(t *testing.T) {
		if agent.IsStrict() {
			t.Error("ephemeral agent should not be strict")
		}
	})
}

// =============================================================================
// 5. Error parity: all bindings must reject these inputs
// =============================================================================

func TestParityVerifyRejectsInvalidJSON(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")

	result, err := agent.Verify("not-valid-json{{{")
	// Either an error return or valid=false is acceptable.
	if err == nil && result != nil && result.Valid {
		t.Error("Verify should reject invalid JSON input")
	}
}

func TestParityVerifyRejectsTamperedDocument(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")

	signed, err := agent.SignMessage(map[string]interface{}{"original": true})
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	// Tamper with the content.
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(signed.Raw), &parsed); err != nil {
		t.Fatalf("failed to parse signed doc: %v", err)
	}
	if content, ok := parsed["content"]; ok {
		_ = content
		parsed["content"] = map[string]interface{}{"original": false, "tampered": true}
	}
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("failed to marshal tampered doc: %v", err)
	}

	// Verification should return valid=false or an error -- either is acceptable.
	result, verifyErr := agent.Verify(string(tampered))
	if verifyErr != nil {
		// Error is acceptable for tampered input.
		return
	}
	if result.Valid {
		t.Error("tampered document should verify as invalid")
	}
}

func TestParitySignMessageRejectsInvalidJSON(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")

	// SignMessage takes interface{}, so we cannot directly pass invalid JSON.
	// However, we can pass a value that, when marshaled to JSON and sent to Rust,
	// simulates the error. The Go API marshals the data internally, so passing
	// a channel (which json.Marshal rejects) tests the Go-side error path.
	_, err := agent.SignMessage(make(chan int))
	if err == nil {
		t.Error("SignMessage should reject un-marshalable data")
	}
}

func TestParityVerifyByIDRejectsBadFormat(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")

	result, err := agent.VerifyByID("not-a-valid-id")
	// Either an error or valid=false is acceptable.
	if err == nil && result != nil && result.Valid {
		t.Error("VerifyByID should reject malformed document ID")
	}
}

// =============================================================================
// 6. Sign file parity
// =============================================================================

func TestParitySignFile(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "parity_test_file.txt")
	if err := os.WriteFile(filePath, []byte("parity test content"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	signed, err := agent.SignFile(filePath, true)
	if err != nil {
		t.Fatalf("SignFile failed: %v", err)
	}

	// Check structure.
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(signed.Raw), &doc); err != nil {
		t.Fatalf("SignFile output is not valid JSON: %v", err)
	}
	if _, ok := doc["jacsSignature"]; !ok {
		t.Error("signed file should have jacsSignature")
	}
	if _, ok := doc["jacsId"]; !ok {
		t.Error("signed file should have jacsId")
	}

	// Verify the signed file.
	result, err := agent.Verify(signed.Raw)
	if err != nil {
		t.Fatalf("Verify signed file failed: %v", err)
	}
	if !result.Valid {
		t.Errorf("signed file should verify, errors=%v", result.Errors)
	}
}

// =============================================================================
// 7. Verification result structure parity
// =============================================================================

func TestParityVerificationResultStructure(t *testing.T) {
	skipIfLibraryMissing(t)
	fixtures := loadParityFixtures(t)
	agent := ephemeral(t, "ed25519")

	signed, err := agent.SignMessage(map[string]interface{}{"structure_test": true})
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	result, err := agent.Verify(signed.Raw)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// The Go VerificationResult is a typed struct, so we re-marshal it to JSON
	// and check field presence against the fixture expectations.
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal VerificationResult: %v", err)
	}
	var resultMap map[string]interface{}
	if err := json.Unmarshal(resultJSON, &resultMap); err != nil {
		t.Fatalf("failed to unmarshal VerificationResult JSON: %v", err)
	}

	for _, field := range fixtures.ExpectedVerifyRes.Required {
		if _, ok := resultMap[field]; !ok {
			t.Errorf("verification result missing required field %q", field)
		}
	}
}

// =============================================================================
// 8. CreateSimpleAgentWithParams parity
// =============================================================================

func TestParityCreateWithParams(t *testing.T) {
	skipIfLibraryMissing(t)

	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	keyDir := filepath.Join(tmpDir, "keys")
	configPath := filepath.Join(tmpDir, "config.json")

	// Set password env var for the signing step.
	t.Setenv("JACS_PRIVATE_KEY_PASSWORD", "TestP@ss123!#")

	params := map[string]interface{}{
		"name":           "parity-agent",
		"password":       "TestP@ss123!#",
		"algorithm":      "ring-Ed25519",
		"data_directory": dataDir,
		"key_directory":  keyDir,
		"config_path":    configPath,
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal params: %v", err)
	}

	agent, info, err := CreateSimpleAgentWithParams(string(paramsJSON))
	if err != nil {
		t.Fatalf("CreateSimpleAgentWithParams failed: %v", err)
	}
	defer agent.Close()

	// info should have agent_id.
	if info == nil || info.AgentID == "" {
		t.Error("agent_id from CreateSimpleAgentWithParams should be non-empty")
	}

	// Agent should be functional: sign and verify.
	signed, err := agent.SignMessage(map[string]interface{}{"params_parity": true})
	if err != nil {
		t.Fatalf("agent from CreateSimpleAgentWithParams should be able to sign: %v", err)
	}
	if signed == nil || signed.Raw == "" {
		t.Fatal("signed document should not be empty")
	}

	result, err := agent.Verify(signed.Raw)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !result.Valid {
		t.Errorf("should verify, errors=%v", result.Errors)
	}
}

// =============================================================================
// 9. Signed document fields populated in Go wrapper
// =============================================================================

func TestParitySignedDocumentGoFields(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")

	signed, err := agent.SignMessage(map[string]interface{}{"field_check": true})
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if signed.DocumentID == "" {
		t.Error("SignedDocument.DocumentID should not be empty")
	}
	if signed.AgentID == "" {
		t.Error("SignedDocument.AgentID should not be empty")
	}
	if signed.Timestamp == "" {
		t.Error("SignedDocument.Timestamp should not be empty")
	}
	if signed.Raw == "" {
		t.Error("SignedDocument.Raw should not be empty")
	}

	// AgentID from the signed doc should match the agent's own ID.
	agentID, err := agent.GetAgentID()
	if err != nil {
		t.Fatalf("GetAgentID failed: %v", err)
	}
	if signed.AgentID != agentID {
		t.Errorf("signed AgentID %q should match agent ID %q", signed.AgentID, agentID)
	}
}

// =============================================================================
// 10. EphemeralSimpleAgent returns usable AgentInfo
// =============================================================================

func TestParityEphemeralAgentInfo(t *testing.T) {
	skipIfLibraryMissing(t)

	algo := "ed25519"
	agent, info, err := EphemeralSimpleAgent(&algo)
	if err != nil {
		t.Fatalf("EphemeralSimpleAgent failed: %v", err)
	}
	defer agent.Close()

	if info == nil {
		t.Fatal("EphemeralSimpleAgent should return non-nil AgentInfo")
	}
	// AgentInfo.AgentID may or may not be populated from the ephemeral FFI;
	// the key contract is that GetAgentID() works on the agent itself.
	agentID, err := agent.GetAgentID()
	if err != nil {
		t.Fatalf("GetAgentID failed: %v", err)
	}
	if agentID == "" {
		t.Error("ephemeral agent should have a non-empty agent ID")
	}
}

// =============================================================================
// Helpers
// =============================================================================

// truncate returns the first n characters of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
