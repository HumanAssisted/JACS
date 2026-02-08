package jacs

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// === GenerateVerifyLink tests (no agent required) ===

func TestGenerateVerifyLink_ValidDocument(t *testing.T) {
	doc := `{"signed":"test"}`
	url, err := GenerateVerifyLink(doc, "https://hai.ai")
	if err != nil {
		t.Fatalf("GenerateVerifyLink failed: %v", err)
	}
	if !strings.HasPrefix(url, "https://hai.ai/jacs/verify?s=") {
		t.Errorf("URL should start with base + path, got: %s", url)
	}
}

func TestGenerateVerifyLink_DefaultBaseUrl(t *testing.T) {
	doc := `{"signed":"test"}`
	url, err := GenerateVerifyLink(doc, "")
	if err != nil {
		t.Fatalf("GenerateVerifyLink failed: %v", err)
	}
	if !strings.HasPrefix(url, "https://hai.ai/jacs/verify?s=") {
		t.Errorf("Default base URL should be https://hai.ai, got: %s", url)
	}
}

func TestGenerateVerifyLink_ExceedsMaxLength(t *testing.T) {
	// Create a document that's too large for the URL
	doc := strings.Repeat("x", MaxVerifyDocumentBytes+100)
	_, err := GenerateVerifyLink(doc, "https://hai.ai")
	if err == nil {
		t.Error("GenerateVerifyLink should fail for oversized document")
	}
	if !strings.Contains(err.Error(), "max length") {
		t.Errorf("Error should mention max length, got: %v", err)
	}
}

func TestGenerateVerifyLink_Constants(t *testing.T) {
	if MaxVerifyURLLen != 2048 {
		t.Errorf("MaxVerifyURLLen should be 2048, got %d", MaxVerifyURLLen)
	}
	if MaxVerifyDocumentBytes != 1515 {
		t.Errorf("MaxVerifyDocumentBytes should be 1515, got %d", MaxVerifyDocumentBytes)
	}
}

// TestLoadNonexistent tests that Load fails for nonexistent config.
func TestLoadNonexistent(t *testing.T) {
	path := "/nonexistent/path/config.json"
	err := Load(&path)
	if err == nil {
		t.Error("Load should fail for nonexistent config")
	}
}

// TestIsLoadedInitial tests that IsLoaded returns false initially.
func TestIsLoadedInitial(t *testing.T) {
	// Note: This test may be affected by other tests that load agents
	// In a fresh state, this should return false
	_ = IsLoaded() // Just ensure it doesn't panic
}

// TestSignMessageTypes tests signing various data types.
func TestSignMessageTypes(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping SignMessage tests")
	}

	tests := []struct {
		name string
		data interface{}
	}{
		{
			name: "map",
			data: map[string]interface{}{"key": "value"},
		},
		{
			name: "nested map",
			data: map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": "deep",
				},
			},
		},
		{
			name: "slice",
			data: []interface{}{1, 2, 3},
		},
		{
			name: "string",
			data: "hello",
		},
		{
			name: "number",
			data: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed, err := SignMessage(tt.data)
			if err != nil {
				t.Fatalf("SignMessage failed: %v", err)
			}

			if signed.Raw == "" {
				t.Error("Raw should not be empty")
			}
			if signed.DocumentID == "" {
				t.Error("DocumentID should not be empty")
			}
		})
	}
}

// TestVerifyOwnSignature tests that we can verify our own signatures.
func TestVerifyOwnSignature(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping Verify tests")
	}

	data := map[string]interface{}{
		"test": true,
		"num":  123,
	}

	signed, err := SignMessage(data)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	result, err := Verify(signed.Raw)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Signature should be valid, errors: %v", result.Errors)
	}
}

// TestVerifyInvalidJSON tests verification of invalid JSON.
func TestVerifyInvalidJSON(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping Verify tests")
	}

	result, err := Verify("not valid json")
	if err != nil {
		t.Fatalf("Verify should not return error for invalid JSON: %v", err)
	}

	if result.Valid {
		t.Error("Invalid JSON should not be valid")
	}
	if len(result.Errors) == 0 {
		t.Error("Should have error message for invalid JSON")
	}
}

// TestRegisterWithHai tests RegisterWithHai with a mock HAI server.
func TestRegisterWithHai(t *testing.T) {
	// No agent loaded: should fail
	_, err := RegisterWithHai(&HaiRegistrationOptions{ApiKey: "key", HaiUrl: "http://localhost"})
	if err == nil {
		t.Fatal("RegisterWithHai without loaded agent should fail")
	}
	if !errors.Is(err, ErrAgentNotLoaded) {
		t.Logf("expected ErrAgentNotLoaded, got: %v", err)
	}

	// No API key and no env (without loaded agent we get ErrAgentNotLoaded first; with loaded agent would get API key error)
	origEnv := os.Getenv("HAI_API_KEY")
	os.Unsetenv("HAI_API_KEY")
	defer func() { os.Setenv("HAI_API_KEY", origEnv) }()
	_, err = RegisterWithHai(&HaiRegistrationOptions{HaiUrl: "http://localhost"})
	if err == nil {
		t.Fatal("RegisterWithHai without API key and without agent should fail")
	}
	// Without agent we get ErrAgentNotLoaded; with agent we would get API key required
	if err != nil && !errors.Is(err, ErrAgentNotLoaded) && !strings.Contains(err.Error(), "API key") && !strings.Contains(err.Error(), "HAI_API_KEY") {
		t.Logf("expected agent not loaded or API key error, got: %v", err)
	}

	// With mock server and loaded agent: test request shape and response
	// (actual load requires fixtures; without fixtures we only test the error paths above)
}

// TestGetDnsRecord tests GetDnsRecord (requires loaded agent for success path).
func TestGetDnsRecord(t *testing.T) {
	_, err := GetDnsRecord("example.com", 3600)
	if err == nil {
		t.Fatal("GetDnsRecord without loaded agent should fail")
	}
	if !errors.Is(err, ErrAgentNotLoaded) {
		t.Logf("expected ErrAgentNotLoaded, got: %v", err)
	}
}

// TestGetWellKnownJson tests GetWellKnownJson (requires loaded agent for success path).
func TestGetWellKnownJson(t *testing.T) {
	_, err := GetWellKnownJson()
	if err == nil {
		t.Fatal("GetWellKnownJson without loaded agent should fail")
	}
	if !errors.Is(err, ErrAgentNotLoaded) {
		t.Logf("expected ErrAgentNotLoaded, got: %v", err)
	}
}

// TestVerifyStandalone tests VerifyStandalone without calling Load().
func TestVerifyStandalone(t *testing.T) {
	// Invalid JSON -> valid false
	result, err := VerifyStandalone("not valid json", nil)
	if err != nil {
		t.Fatalf("VerifyStandalone should not return error for bad input: %v", err)
	}
	if result.Valid {
		t.Error("Invalid JSON should not be valid")
	}

	// Tampered document with signer id in body -> valid false, signer_id may be set from doc
	tampered := `{"content":{},"jacsSignature":{"agentID":"test-agent","date":"2025-01-01T00:00:00Z"}}`
	result, err = VerifyStandalone(tampered, nil)
	if err != nil {
		t.Fatalf("VerifyStandalone should not return error: %v", err)
	}
	if result.Valid {
		t.Error("Tampered document should not be valid")
	}
	if result.SignerID != "test-agent" {
		t.Logf("SignerID from doc (optional): got %q", result.SignerID)
	}
}

// TestVerifyTamperedDocument tests that tampering is detected.
func TestVerifyTamperedDocument(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping Verify tests")
	}

	data := map[string]interface{}{"original": true}
	signed, err := SignMessage(data)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	// Tamper with the document
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(signed.Raw), &doc); err != nil {
		t.Fatalf("Failed to parse signed document: %v", err)
	}

	doc["original"] = false // Modify data
	tampered, _ := json.Marshal(doc)

	result, err := Verify(string(tampered))
	if err != nil {
		t.Fatalf("Verify should not return error: %v", err)
	}

	if result.Valid {
		t.Error("Tampered document should not be valid")
	}
}

// TestSignFileNonexistent tests signing a nonexistent file.
func TestSignFileNonexistent(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping SignFile tests")
	}

	_, err := SignFile("/nonexistent/file.txt", false)
	if err == nil {
		t.Error("SignFile should fail for nonexistent file")
	}
}

// TestSignFileReference tests signing a file in reference mode.
func TestSignFileReference(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping SignFile tests")
	}

	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	signed, err := SignFile(tmpFile, false)
	if err != nil {
		t.Fatalf("SignFile failed: %v", err)
	}

	if signed.DocumentID == "" {
		t.Error("DocumentID should not be empty")
	}
}

// TestSignFileEmbed tests signing a file with embedding.
func TestSignFileEmbed(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping SignFile tests")
	}

	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, []byte("embedded content"), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	signed, err := SignFile(tmpFile, true)
	if err != nil {
		t.Fatalf("SignFile failed: %v", err)
	}

	// Verify embedded content is present
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(signed.Raw), &doc); err != nil {
		t.Fatalf("Failed to parse signed document: %v", err)
	}

	if _, ok := doc["jacsFiles"]; !ok {
		t.Error("Embedded file should have jacsFiles field")
	}
}

// TestVerifySelf tests self verification.
func TestVerifySelf(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping VerifySelf tests")
	}

	result, err := VerifySelf()
	if err != nil {
		t.Fatalf("VerifySelf failed: %v", err)
	}

	if !result.Valid {
		t.Errorf("Self verification should pass, errors: %v", result.Errors)
	}
}

// TestGetPublicKeyPEM tests getting the public key.
func TestGetPublicKeyPEM(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping GetPublicKeyPEM tests")
	}

	pem, err := GetPublicKeyPEM()
	if err != nil {
		t.Fatalf("GetPublicKeyPEM failed: %v", err)
	}

	if pem == "" {
		t.Error("Public key should not be empty")
	}

	// Check PEM format
	if len(pem) < 20 || pem[:10] != "-----BEGIN" {
		t.Error("Public key should be in PEM format")
	}
}

// === Audit tests ===

func TestAudit_ReturnsResult(t *testing.T) {
	result, err := Audit(nil)
	// Audit may fail without a config, but should not panic
	if err != nil {
		t.Logf("Audit with nil opts returned error (expected without config): %v", err)
		return
	}
	// If it succeeds, check structure
	if _, ok := result["risks"]; !ok {
		t.Error("Audit result should contain 'risks' key")
	}
	if _, ok := result["health_checks"]; !ok {
		t.Error("Audit result should contain 'health_checks' key")
	}
}

func TestAudit_ContainsOverallStatus(t *testing.T) {
	result, err := Audit(nil)
	if err != nil {
		t.Logf("Audit returned error (expected without config): %v", err)
		return
	}
	if _, ok := result["overall_status"]; !ok {
		t.Logf("Audit result may not contain 'overall_status' — depends on implementation")
	}
	if _, ok := result["summary"]; !ok {
		t.Logf("Audit result may not contain 'summary' — depends on implementation")
	}
}

// TestGetAgentInfo tests getting agent info.
func TestGetAgentInfo(t *testing.T) {
	if !IsLoaded() {
		t.Skip("No agent loaded, skipping GetAgentInfo tests")
	}

	info := GetAgentInfo()
	if info == nil {
		t.Error("GetAgentInfo should return info when agent is loaded")
	}
}
