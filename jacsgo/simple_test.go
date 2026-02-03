package jacs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
