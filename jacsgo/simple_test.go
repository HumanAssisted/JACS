package jacs

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPrivateKeyPassword = "TestP@ss123!#"

func resetSimpleState() {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent != nil {
		globalAgent.Close()
		globalAgent = nil
	}
	agentInfo = nil
}

func withLoadedAgent(t *testing.T, fn func(t *testing.T, info *AgentInfo)) {
	t.Helper()

	resetSimpleState()

	tmpDir := t.TempDir()
	originalCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	originalPassword, hadPassword := os.LookupEnv("JACS_PRIVATE_KEY_PASSWORD")

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to temp dir: %v", err)
	}

	t.Cleanup(func() {
		if hadPassword {
			_ = os.Setenv("JACS_PRIVATE_KEY_PASSWORD", originalPassword)
		} else {
			_ = os.Unsetenv("JACS_PRIVATE_KEY_PASSWORD")
		}
		if err := os.Chdir(originalCwd); err != nil {
			t.Fatalf("failed to restore cwd: %v", err)
		}
		resetSimpleState()
	})

	if err := os.Setenv("JACS_PRIVATE_KEY_PASSWORD", testPrivateKeyPassword); err != nil {
		t.Fatalf("failed to set password env var: %v", err)
	}

	info, err := Create("go-test-agent", &CreateAgentOptions{
		Password:      testPrivateKeyPassword,
		Algorithm:     "RSA-PSS",
		DataDirectory: "jacs_data",
		KeyDirectory:  "jacs_keys",
		ConfigPath:    "jacs.config.json",
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if !IsLoaded() {
		t.Fatal("Create should leave the simplified API loaded")
	}
	if info == nil {
		t.Fatal("Create returned nil AgentInfo")
	}
	if info.AgentID == "" {
		t.Fatal("Create should populate AgentID")
	}

	fn(t, info)
}

func assertAuditReport(t *testing.T, result map[string]interface{}) {
	t.Helper()

	if result == nil {
		t.Fatal("audit result should not be nil")
	}

	overallStatus, ok := result["overall_status"].(string)
	if !ok || overallStatus == "" {
		t.Fatalf("overall_status should be a non-empty string, got %#v", result["overall_status"])
	}
	switch overallStatus {
	case "Healthy", "Degraded", "Unhealthy", "Unavailable":
	default:
		t.Fatalf("unexpected overall_status %q", overallStatus)
	}

	summary, ok := result["summary"].(string)
	if !ok || summary == "" {
		t.Fatalf("summary should be a non-empty string, got %#v", result["summary"])
	}

	healthChecks, ok := result["health_checks"].([]interface{})
	if !ok {
		t.Fatalf("health_checks should be an array, got %#v", result["health_checks"])
	}
	if len(healthChecks) == 0 {
		t.Fatal("health_checks should not be empty")
	}

	firstHealth, ok := healthChecks[0].(map[string]interface{})
	if !ok {
		t.Fatalf("health_checks[0] should be an object, got %#v", healthChecks[0])
	}
	name, ok := firstHealth["name"].(string)
	if !ok || name == "" {
		t.Fatalf("health check name should be a non-empty string, got %#v", firstHealth["name"])
	}
	status, ok := firstHealth["status"].(string)
	if !ok || status == "" {
		t.Fatalf("health check status should be a non-empty string, got %#v", firstHealth["status"])
	}
	switch status {
	case "Healthy", "Degraded", "Unhealthy", "Unavailable":
	default:
		t.Fatalf("unexpected health status %q", status)
	}
	message, ok := firstHealth["message"].(string)
	if !ok || message == "" {
		t.Fatalf("health check message should be a non-empty string, got %#v", firstHealth["message"])
	}

	if _, ok := result["checked_at"].(float64); !ok {
		t.Fatalf("checked_at should be a unix timestamp number, got %#v", result["checked_at"])
	}

	risks, ok := result["risks"].([]interface{})
	if !ok {
		t.Fatalf("risks should be an array, got %#v", result["risks"])
	}
	if len(risks) > 0 {
		firstRisk, ok := risks[0].(map[string]interface{})
		if !ok {
			t.Fatalf("risks[0] should be an object, got %#v", risks[0])
		}
		category, ok := firstRisk["category"].(string)
		if !ok || category == "" {
			t.Fatalf("risk category should be a non-empty string, got %#v", firstRisk["category"])
		}
		severity, ok := firstRisk["severity"].(string)
		if !ok || severity == "" {
			t.Fatalf("risk severity should be a non-empty string, got %#v", firstRisk["severity"])
		}
		switch severity {
		case "low", "medium", "high":
		default:
			t.Fatalf("unexpected risk severity %q", severity)
		}
		riskMessage, ok := firstRisk["message"].(string)
		if !ok || riskMessage == "" {
			t.Fatalf("risk message should be a non-empty string, got %#v", firstRisk["message"])
		}
	}
}

// TestLoadNonexistent tests that Load fails for nonexistent config.
func TestLoadNonexistent(t *testing.T) {
	resetSimpleState()
	path := "/nonexistent/path/config.json"
	err := Load(&path)
	if err == nil {
		t.Error("Load should fail for nonexistent config")
	}
}

// TestIsLoadedInitial tests that IsLoaded returns false initially.
func TestIsLoadedInitial(t *testing.T) {
	resetSimpleState()
	if IsLoaded() {
		t.Error("IsLoaded should be false after resetting the simplified API state")
	}
}

// TestSignMessageTypes tests signing various data types.
func TestSignMessageTypes(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, info *AgentInfo) {
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
				if signed.AgentID != info.AgentID {
					t.Fatalf("expected signed AgentID %q, got %q", info.AgentID, signed.AgentID)
				}
				if signed.Timestamp == "" {
					t.Error("Timestamp should not be empty")
				}
			})
		}
	})
}

// TestVerifyOwnSignature tests that we can verify our own signatures.
func TestVerifyOwnSignature(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, info *AgentInfo) {
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
		if result.SignerID != info.AgentID {
			t.Fatalf("expected signer ID %q, got %q", info.AgentID, result.SignerID)
		}
		if result.Timestamp == "" {
			t.Error("Verify should return the signing timestamp")
		}
	})
}

// TestVerifyInvalidJSON tests verification of invalid JSON.
func TestVerifyInvalidJSON(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, _ *AgentInfo) {
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
	})
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
	withLoadedAgent(t, func(t *testing.T, _ *AgentInfo) {
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
	})
}

// TestSignFileNonexistent tests signing a nonexistent file.
func TestSignFileNonexistent(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, _ *AgentInfo) {
		_, err := SignFile("missing.txt", false)
		if err == nil {
			t.Error("SignFile should fail for nonexistent file")
		}
	})
}

// TestSignFileReference tests signing a file in reference mode.
func TestSignFileReference(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, info *AgentInfo) {
		tmpFile := filepath.Join("files", "test.txt")
		if err := os.MkdirAll(filepath.Dir(tmpFile), 0755); err != nil {
			t.Fatalf("Failed to create temp file directory: %v", err)
		}
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
		if signed.AgentID != info.AgentID {
			t.Fatalf("expected signed AgentID %q, got %q", info.AgentID, signed.AgentID)
		}
		var doc map[string]interface{}
		if err := json.Unmarshal([]byte(signed.Raw), &doc); err != nil {
			t.Fatalf("Failed to parse signed document: %v", err)
		}
		if _, ok := doc["jacsSignature"]; !ok {
			t.Fatal("reference-mode signed file should contain jacsSignature metadata")
		}
	})
}

// TestSignFileEmbed tests signing a file with embedding.
func TestSignFileEmbed(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, _ *AgentInfo) {
		tmpFile := filepath.Join("files", "embedded.txt")
		if err := os.MkdirAll(filepath.Dir(tmpFile), 0755); err != nil {
			t.Fatalf("Failed to create temp file directory: %v", err)
		}
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

		files, ok := doc["jacsFiles"].([]interface{})
		if !ok || len(files) == 0 {
			t.Fatal("embedded file should produce at least one jacsFiles entry")
		}
	})
}

// TestVerifySelf tests self verification.
func TestVerifySelf(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, info *AgentInfo) {
		result, err := VerifySelf()
		if err != nil {
			t.Fatalf("VerifySelf failed: %v", err)
		}

		if !result.Valid {
			t.Errorf("Self verification should pass, errors: %v", result.Errors)
		}
		if result.SignerID != info.AgentID {
			t.Fatalf("expected signer ID %q, got %q", info.AgentID, result.SignerID)
		}
	})
}

// TestGetPublicKeyPEM tests getting the public key.
func TestGetPublicKeyPEM(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, info *AgentInfo) {
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

		filePEM, err := os.ReadFile(info.PublicKeyPath)
		if err != nil {
			t.Fatalf("failed to read public key path from AgentInfo: %v", err)
		}
		if pem != string(filePEM) {
			t.Fatal("GetPublicKeyPEM should return the contents of the public key file")
		}
	})
}

// === Audit tests ===

func TestAudit_ReturnsResult(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, info *AgentInfo) {
		result, err := Audit(&AuditOptions{ConfigPath: info.ConfigPath, RecentN: 1})
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}
		assertAuditReport(t, result)
	})
}

func TestAudit_ContainsOverallStatus(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, info *AgentInfo) {
		result, err := Audit(&AuditOptions{ConfigPath: info.ConfigPath, RecentN: 1})
		if err != nil {
			t.Fatalf("Audit failed: %v", err)
		}

		assertAuditReport(t, result)

		summary := result["summary"].(string)
		healthChecks := result["health_checks"].([]interface{})
		firstHealth := healthChecks[0].(map[string]interface{})
		name := firstHealth["name"].(string)
		if !containsSubstring(summary, name+":") {
			t.Fatalf("summary should include a line for component %q, got %q", name, summary)
		}
		if !containsSubstring(summary, "risk(s)") && !containsSubstring(summary, "risks: 0") {
			t.Fatalf("summary should include risk totals, got %q", summary)
		}
	})
}

// TestGetAgentInfo tests getting agent info.
func TestGetAgentInfo(t *testing.T) {
	withLoadedAgent(t, func(t *testing.T, created *AgentInfo) {
		info := GetAgentInfo()
		if info == nil {
			t.Fatal("GetAgentInfo should return info when agent is loaded")
		}
		if info.AgentID != created.AgentID {
			t.Fatalf("expected AgentID %q, got %q", created.AgentID, info.AgentID)
		}
		if info.ConfigPath != created.ConfigPath {
			t.Fatalf("expected ConfigPath %q, got %q", created.ConfigPath, info.ConfigPath)
		}
	})
}

func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}
