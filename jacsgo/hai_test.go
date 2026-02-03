package jacs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewHaiClient(t *testing.T) {
	client := NewHaiClient("https://api.hai.ai")
	if client.Endpoint() != "https://api.hai.ai" {
		t.Errorf("expected endpoint 'https://api.hai.ai', got '%s'", client.Endpoint())
	}
}

func TestNewHaiClientTrimsTrailingSlash(t *testing.T) {
	client := NewHaiClient("https://api.hai.ai/")
	if client.Endpoint() != "https://api.hai.ai" {
		t.Errorf("expected endpoint 'https://api.hai.ai', got '%s'", client.Endpoint())
	}
}

func TestNewHaiClientWithOptions(t *testing.T) {
	client := NewHaiClient("https://api.hai.ai",
		WithAPIKey("test-key"),
		WithTimeout(60*time.Second))

	if client.apiKey != "test-key" {
		t.Errorf("expected API key 'test-key', got '%s'", client.apiKey)
	}
}

func TestTestConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("expected path '/health', got '%s'", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewHaiClient(server.URL)
	ok, err := client.TestConnection()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected connection test to succeed")
	}
}

func TestTestConnectionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewHaiClient(server.URL)
	_, err := client.TestConnection()
	if err == nil {
		t.Error("expected error for 500 response")
	}

	haiErr, ok := err.(*HaiError)
	if !ok {
		t.Fatalf("expected HaiError, got %T", err)
	}
	if haiErr.Kind != HaiErrorConnection {
		t.Errorf("expected HaiErrorConnection, got %v", haiErr.Kind)
	}
}

func TestStatusSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"registered":      true,
			"agent_id":        "test-agent",
			"registration_id": "reg-123",
			"registered_at":   "2024-01-15T10:30:00Z",
			"hai_signatures":  []string{"sig-1", "sig-2"},
		})
	}))
	defer server.Close()

	client := NewHaiClient(server.URL, WithAPIKey("test-key"))
	result, err := client.Status("test-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Registered {
		t.Error("expected Registered to be true")
	}
	if result.AgentID != "test-agent" {
		t.Errorf("expected AgentID 'test-agent', got '%s'", result.AgentID)
	}
	if result.RegistrationID != "reg-123" {
		t.Errorf("expected RegistrationID 'reg-123', got '%s'", result.RegistrationID)
	}
	if len(result.HaiSignatures) != 2 {
		t.Errorf("expected 2 signatures, got %d", len(result.HaiSignatures))
	}
}

func TestStatusNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewHaiClient(server.URL, WithAPIKey("test-key"))
	result, err := client.Status("unknown-agent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Registered {
		t.Error("expected Registered to be false for 404")
	}
	if result.AgentID != "unknown-agent" {
		t.Errorf("expected AgentID 'unknown-agent', got '%s'", result.AgentID)
	}
}

func TestStatusRequiresAPIKey(t *testing.T) {
	client := NewHaiClient("https://api.hai.ai")
	_, err := client.Status("test-agent")
	if err == nil {
		t.Error("expected error when API key is not set")
	}

	haiErr, ok := err.(*HaiError)
	if !ok {
		t.Fatalf("expected HaiError, got %T", err)
	}
	if haiErr.Kind != HaiErrorAuthRequired {
		t.Errorf("expected HaiErrorAuthRequired, got %v", haiErr.Kind)
	}
}

func TestRegisterWithJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/agents/register" {
			t.Errorf("expected path '/api/v1/agents/register', got '%s'", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var reqBody struct {
			AgentJSON string `json:"agent_json"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if reqBody.AgentJSON == "" {
			t.Error("expected non-empty agent_json")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"agent_id":     "agent-123",
			"jacs_id":      "jacs-456",
			"dns_verified": true,
			"signatures": []map[string]string{
				{
					"key_id":    "key-1",
					"algorithm": "Ed25519",
					"signature": "c2lnbmF0dXJl",
					"signed_at": "2024-01-15T10:30:00Z",
				},
			},
		})
	}))
	defer server.Close()

	client := NewHaiClient(server.URL, WithAPIKey("test-key"))
	result, err := client.RegisterWithJSON(`{"jacsId": "test-agent"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.AgentID != "agent-123" {
		t.Errorf("expected AgentID 'agent-123', got '%s'", result.AgentID)
	}
	if result.JacsID != "jacs-456" {
		t.Errorf("expected JacsID 'jacs-456', got '%s'", result.JacsID)
	}
	if !result.DNSVerified {
		t.Error("expected DNSVerified to be true")
	}
	if len(result.Signatures) != 1 {
		t.Errorf("expected 1 signature, got %d", len(result.Signatures))
	}
}

func TestBenchmark(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/benchmarks/run" {
			t.Errorf("expected path '/api/v1/benchmarks/run', got '%s'", r.URL.Path)
		}

		var reqBody struct {
			AgentID string `json:"agent_id"`
			Suite   string `json:"suite"`
		}
		json.NewDecoder(r.Body).Decode(&reqBody)

		if reqBody.AgentID != "agent-123" {
			t.Errorf("expected agent_id 'agent-123', got '%s'", reqBody.AgentID)
		}
		if reqBody.Suite != "latency" {
			t.Errorf("expected suite 'latency', got '%s'", reqBody.Suite)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"run_id":       "run-123",
			"suite":        "latency",
			"score":        0.95,
			"completed_at": "2024-01-15T10:30:00Z",
			"results": []map[string]interface{}{
				{
					"name":   "test-1",
					"passed": true,
					"score":  1.0,
				},
			},
		})
	}))
	defer server.Close()

	client := NewHaiClient(server.URL, WithAPIKey("test-key"))
	result, err := client.Benchmark("agent-123", "latency")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.RunID != "run-123" {
		t.Errorf("expected RunID 'run-123', got '%s'", result.RunID)
	}
	if result.Suite != "latency" {
		t.Errorf("expected Suite 'latency', got '%s'", result.Suite)
	}
	if result.Score != 0.95 {
		t.Errorf("expected Score 0.95, got %f", result.Score)
	}
	if len(result.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Results))
	}
}

func TestFetchRemoteKeyFromURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/jacs/v1/agents/test-agent/keys/latest"
		if r.URL.Path != expectedPath {
			t.Errorf("expected path '%s', got '%s'", expectedPath, r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"public_key":      "dGVzdC1rZXk=", // base64("test-key")
			"algorithm":       "ed25519",
			"public_key_hash": "abc123",
			"agent_id":        "test-agent",
			"version":         "1",
		})
	}))
	defer server.Close()

	result, err := FetchRemoteKeyFromURL(server.URL, "test-agent", "latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(result.PublicKey) != "test-key" {
		t.Errorf("expected PublicKey 'test-key', got '%s'", string(result.PublicKey))
	}
	if result.Algorithm != "ed25519" {
		t.Errorf("expected Algorithm 'ed25519', got '%s'", result.Algorithm)
	}
	if result.PublicKeyHash != "abc123" {
		t.Errorf("expected PublicKeyHash 'abc123', got '%s'", result.PublicKeyHash)
	}
}

func TestFetchRemoteKeyFromURLNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchRemoteKeyFromURL(server.URL, "unknown-agent", "latest")
	if err == nil {
		t.Error("expected error for 404")
	}

	haiErr, ok := err.(*HaiError)
	if !ok {
		t.Fatalf("expected HaiError, got %T", err)
	}
	if haiErr.Kind != HaiErrorKeyNotFound {
		t.Errorf("expected HaiErrorKeyNotFound, got %v", haiErr.Kind)
	}
}

func TestFetchKeyByHashFromURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/jacs/v1/keys/by-hash/abc123"
		if r.URL.Path != expectedPath {
			t.Errorf("expected path '%s', got '%s'", expectedPath, r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"public_key":      "dGVzdC1rZXk=",
			"algorithm":       "ed25519",
			"public_key_hash": "abc123",
			"agent_id":        "test-agent",
			"version":         "1",
		})
	}))
	defer server.Close()

	result, err := FetchKeyByHashFromURL(server.URL, "abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PublicKeyHash != "abc123" {
		t.Errorf("expected PublicKeyHash 'abc123', got '%s'", result.PublicKeyHash)
	}
}

func TestHaiErrorError(t *testing.T) {
	err := newHaiError(HaiErrorConnection, "connection failed: %s", "timeout")
	if err.Error() != "connection failed: timeout" {
		t.Errorf("expected 'connection failed: timeout', got '%s'", err.Error())
	}
}

func TestHaiSignatureSerialization(t *testing.T) {
	sig := HaiSignature{
		KeyID:     "key-1",
		Algorithm: "Ed25519",
		Signature: "c2lnbmF0dXJl",
		SignedAt:  "2024-01-15T10:30:00Z",
	}

	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed HaiSignature
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.KeyID != sig.KeyID {
		t.Errorf("KeyID mismatch: expected '%s', got '%s'", sig.KeyID, parsed.KeyID)
	}
}
