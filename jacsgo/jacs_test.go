package jacs

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestHashString tests the string hashing functionality
func TestHashString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string // We'll check if hash is non-empty since exact hash depends on algorithm
	}{
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "simple string",
			input: "Hello, JACS!",
		},
		{
			name:  "unicode string",
			input: "Hello, 世界! 🚀",
		},
		{
			name:  "long string",
			input: "This is a much longer string that contains multiple sentences. It should still hash correctly regardless of length.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := HashString(tc.input)
			if err != nil {
				t.Fatalf("HashString failed: %v", err)
			}

			if hash == "" {
				t.Error("Expected non-empty hash")
			}

			// Hash same string again - should be deterministic
			hash2, err := HashString(tc.input)
			if err != nil {
				t.Fatalf("Second HashString failed: %v", err)
			}

			if hash != hash2 {
				t.Errorf("Hash not deterministic: %s != %s", hash, hash2)
			}
		})
	}
}

// TestBinaryDataConversion tests binary data encoding/decoding
func TestBinaryDataConversion(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "empty bytes",
			data: []byte{},
		},
		{
			name: "simple bytes",
			data: []byte("Hello"),
		},
		{
			name: "binary data",
			data: []byte{0x00, 0xFF, 0x42, 0x13, 0x37},
		},
		{
			name: "all byte values",
			data: func() []byte {
				b := make([]byte, 256)
				for i := range b {
					b[i] = byte(i)
				}
				return b
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded := EncodeBinaryData(tc.data)

			// Verify it's the right structure
			bd, ok := encoded.(BinaryData)
			if !ok {
				t.Fatalf("Expected BinaryData type, got %T", encoded)
			}

			if bd.Type != "bytes" {
				t.Errorf("Expected type 'bytes', got '%s'", bd.Type)
			}

			// Decode
			decoded, err := DecodeBinaryData(encoded)
			if err != nil {
				t.Fatalf("DecodeBinaryData failed: %v", err)
			}

			// Compare
			if len(decoded) != len(tc.data) {
				t.Fatalf("Length mismatch: expected %d, got %d", len(tc.data), len(decoded))
			}

			for i := range tc.data {
				if decoded[i] != tc.data[i] {
					t.Errorf("Byte mismatch at index %d: expected %x, got %x", i, tc.data[i], decoded[i])
				}
			}
		})
	}

	// Test decoding from map[string]interface{} (common when unmarshaling JSON)
	t.Run("decode from map", func(t *testing.T) {
		m := map[string]interface{}{
			"__type__": "bytes",
			"data":     "SGVsbG8=", // "Hello" in base64
		}

		decoded, err := DecodeBinaryData(m)
		if err != nil {
			t.Fatalf("DecodeBinaryData from map failed: %v", err)
		}

		expected := "Hello"
		if string(decoded) != expected {
			t.Errorf("Expected '%s', got '%s'", expected, string(decoded))
		}
	})

	// Test invalid data
	t.Run("invalid data", func(t *testing.T) {
		invalidCases := []interface{}{
			"not an object",
			42,
			[]byte("raw bytes"),
			map[string]interface{}{"wrong": "structure"},
			map[string]interface{}{"__type__": "wrong", "data": "test"},
		}

		for i, invalid := range invalidCases {
			_, err := DecodeBinaryData(invalid)
			if err == nil {
				t.Errorf("Case %d: Expected error for invalid data, got nil", i)
			}
		}
	})
}

// TestComplexDataConversion tests the conversion of complex data structures
func TestComplexDataConversion(t *testing.T) {
	testData := map[string]interface{}{
		"string": "test",
		"number": 42,
		"float":  3.14,
		"bool":   true,
		"null":   nil,
		"bytes":  []byte("binary data"),
		"array":  []interface{}{1, "two", false},
		"nested": map[string]interface{}{
			"inner_bytes": []byte{0xFF, 0x00},
			"inner_array": []interface{}{
				[]byte("nested bytes"),
			},
		},
	}

	// Convert to JSON
	jsonStr, err := ToJSON(testData)
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Parse back
	restored, err := FromJSON(jsonStr)
	if err != nil {
		t.Fatalf("FromJSON failed: %v", err)
	}

	// Verify structure
	restoredMap, ok := restored.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map, got %T", restored)
	}

	// Check simple values
	if restoredMap["string"] != "test" {
		t.Errorf("String mismatch: %v", restoredMap["string"])
	}

	// Numbers might be float64 after JSON round-trip
	if num, ok := restoredMap["number"].(float64); !ok || num != 42 {
		t.Errorf("Number mismatch: %v", restoredMap["number"])
	}

	// Check that bytes were properly restored
	if bytes, ok := restoredMap["bytes"].([]byte); !ok || string(bytes) != "binary data" {
		t.Errorf("Bytes not properly restored: %v", restoredMap["bytes"])
	}

	// Check nested structure
	nested, ok := restoredMap["nested"].(map[string]interface{})
	if !ok {
		t.Fatalf("Nested not a map: %T", restoredMap["nested"])
	}

	innerBytes, ok := nested["inner_bytes"].([]byte)
	if !ok {
		t.Errorf("Inner bytes not restored: %T", nested["inner_bytes"])
	} else if len(innerBytes) != 2 || innerBytes[0] != 0xFF || innerBytes[1] != 0x00 {
		t.Errorf("Inner bytes incorrect: %v", innerBytes)
	}
}

// TestConfigCreation tests creating JACS configuration
func TestConfigCreation(t *testing.T) {
	useSecurity := "true"
	dataDir := "./test_data"
	keyDir := "./test_keys"
	privKey := "test.private.pem"
	pubKey := "test.public.pem"
	keyAlg := "RSA"
	password := "test123"
	agentID := "test-agent:v1.0.0"
	storage := "local"

	config := Config{
		UseSecurity:         &useSecurity,
		DataDirectory:       &dataDir,
		KeyDirectory:        &keyDir,
		AgentPrivateKeyFile: &privKey,
		AgentPublicKeyFile:  &pubKey,
		AgentKeyAlgorithm:   &keyAlg,
		PrivateKeyPassword:  &password,
		AgentIDAndVersion:   &agentID,
		DefaultStorage:      &storage,
	}

	configJSON, err := CreateConfig(config)
	if err != nil {
		t.Fatalf("CreateConfig failed: %v", err)
	}

	// Parse the JSON to verify it's valid
	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(configJSON), &parsed)
	if err != nil {
		t.Fatalf("Invalid JSON from CreateConfig: %v", err)
	}

	// Check some fields
	expectedFields := []string{
		"jacs_use_security",
		"jacs_data_directory",
		"jacs_key_directory",
		"jacs_agent_private_key_filename",
		"jacs_agent_public_key_filename",
		"jacs_agent_key_algorithm",
		"jacs_private_key_password",
		"jacs_agent_id_and_version",
		"jacs_default_storage",
	}

	for _, field := range expectedFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("Missing field: %s", field)
		}
	}

	// Verify specific values
	if parsed["jacs_use_security"] != useSecurity {
		t.Errorf("UseSecurity mismatch: expected %s, got %v", useSecurity, parsed["jacs_use_security"])
	}

	if parsed["jacs_agent_id_and_version"] != agentID {
		t.Errorf("AgentID mismatch: expected %s, got %v", agentID, parsed["jacs_agent_id_and_version"])
	}
}

// TestErrorHandling tests error handling for various functions
func TestErrorHandling(t *testing.T) {
	// Test loading non-existent config
	t.Run("load non-existent config", func(t *testing.T) {
		err := Load("/non/existent/path/config.json")
		if err == nil {
			t.Error("Expected error loading non-existent config")
		}
	})

	// Test operations that require loaded agent
	t.Run("operations without loaded agent", func(t *testing.T) {
		// These operations might fail if no agent is loaded
		// The exact behavior depends on the Rust implementation

		_, err := SignString("test")
		if err == nil {
			// If it succeeds, it means there's a default agent
			t.Log("SignString succeeded - agent might be pre-loaded")
		}

		err = VerifyString("data", "signature", []byte("key"), "RSA")
		if err == nil {
			t.Error("Expected error verifying with invalid signature")
		}
	})
}

// TestJSONRoundTrip tests that various data types survive JSON serialization
func TestJSONRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		data interface{}
	}{
		{
			name: "simple map",
			data: map[string]interface{}{
				"key": "value",
				"num": 123,
			},
		},
		{
			name: "array with bytes",
			data: []interface{}{
				"string",
				42,
				[]byte("bytes"),
			},
		},
		{
			name: "deeply nested",
			data: map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": map[string]interface{}{
						"level3": []byte("deep bytes"),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert to JSON
			jsonStr, err := ToJSON(tc.data)
			if err != nil {
				t.Fatalf("ToJSON failed: %v", err)
			}

			// Convert back
			restored, err := FromJSON(jsonStr)
			if err != nil {
				t.Fatalf("FromJSON failed: %v", err)
			}

			// For deep comparison, convert both to JSON and compare
			// (this handles the fact that numbers might change type)
			originalJSON, _ := json.Marshal(ConvertValue(tc.data))
			restoredJSON, _ := json.Marshal(ConvertValue(restored))

			if string(originalJSON) != string(restoredJSON) {
				t.Errorf("Data mismatch after round trip:\nOriginal: %s\nRestored: %s",
					originalJSON, restoredJSON)
			}
		})
	}
}

// ============================================================================
// JacsAgent Tests - Testing the recommended handle-based API
// ============================================================================

// TestJacsAgentCreation tests creating and closing JacsAgent instances
func TestJacsAgentCreation(t *testing.T) {
	t.Run("create single agent", func(t *testing.T) {
		agent, err := NewJacsAgent()
		if err != nil {
			t.Fatalf("NewJacsAgent failed: %v", err)
		}
		if agent == nil {
			t.Fatal("Expected non-nil agent")
		}
		agent.Close()
	})

	t.Run("create multiple agents", func(t *testing.T) {
		// This tests that multiple independent agents can be created
		agents := make([]*JacsAgent, 5)
		for i := 0; i < 5; i++ {
			agent, err := NewJacsAgent()
			if err != nil {
				t.Fatalf("NewJacsAgent %d failed: %v", i, err)
			}
			agents[i] = agent
		}

		// Close all agents
		for i, agent := range agents {
			if agent == nil {
				t.Errorf("Agent %d is nil", i)
			} else {
				agent.Close()
			}
		}
	})

	t.Run("double close is safe", func(t *testing.T) {
		agent, err := NewJacsAgent()
		if err != nil {
			t.Fatalf("NewJacsAgent failed: %v", err)
		}
		agent.Close()
		agent.Close() // Should not panic
	})
}

// TestJacsAgentErrorsWhenClosed tests that methods return errors after Close
func TestJacsAgentErrorsWhenClosed(t *testing.T) {
	agent, err := NewJacsAgent()
	if err != nil {
		t.Fatalf("NewJacsAgent failed: %v", err)
	}
	agent.Close()

	t.Run("Load after close", func(t *testing.T) {
		err := agent.Load("/some/path")
		if err == nil {
			t.Error("Expected error when calling Load on closed agent")
		}
	})

	t.Run("SignString after close", func(t *testing.T) {
		_, err := agent.SignString("test")
		if err == nil {
			t.Error("Expected error when calling SignString on closed agent")
		}
	})

	t.Run("SignRequest after close", func(t *testing.T) {
		_, err := agent.SignRequest(map[string]string{"test": "data"})
		if err == nil {
			t.Error("Expected error when calling SignRequest on closed agent")
		}
	})

	t.Run("VerifyResponse after close", func(t *testing.T) {
		_, err := agent.VerifyResponse("{}")
		if err == nil {
			t.Error("Expected error when calling VerifyResponse on closed agent")
		}
	})
}

// TestJacsAgentLoadError tests loading with invalid config
func TestJacsAgentLoadError(t *testing.T) {
	agent, err := NewJacsAgent()
	if err != nil {
		t.Fatalf("NewJacsAgent failed: %v", err)
	}
	defer agent.Close()

	err = agent.Load("/non/existent/config.json")
	if err == nil {
		t.Error("Expected error loading non-existent config")
	}
}

// TestJacsAgentConcurrency tests that multiple agents can be used concurrently
func TestJacsAgentConcurrency(t *testing.T) {
	const numAgents = 10
	const hashesPerAgent = 100

	// Create multiple agents
	agents := make([]*JacsAgent, numAgents)
	for i := 0; i < numAgents; i++ {
		agent, err := NewJacsAgent()
		if err != nil {
			t.Fatalf("NewJacsAgent %d failed: %v", i, err)
		}
		agents[i] = agent
	}

	// Use goroutines to hash strings concurrently
	// (Note: HashString is a static function, but this tests that
	// multiple agent handles don't interfere with each other)
	done := make(chan bool, numAgents)

	for i := 0; i < numAgents; i++ {
		go func(agentIdx int) {
			defer func() { done <- true }()

			for j := 0; j < hashesPerAgent; j++ {
				data := fmt.Sprintf("agent-%d-hash-%d", agentIdx, j)
				hash, err := HashString(data)
				if err != nil {
					t.Errorf("HashString failed for agent %d: %v", agentIdx, err)
					return
				}
				if hash == "" {
					t.Errorf("Empty hash for agent %d", agentIdx)
					return
				}
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numAgents; i++ {
		<-done
	}

	// Close all agents
	for _, agent := range agents {
		agent.Close()
	}
}

// TestJacsAgentIndependentState tests that agents have independent state
func TestJacsAgentIndependentState(t *testing.T) {
	// Create two agents
	agent1, err := NewJacsAgent()
	if err != nil {
		t.Fatalf("NewJacsAgent 1 failed: %v", err)
	}
	defer agent1.Close()

	agent2, err := NewJacsAgent()
	if err != nil {
		t.Fatalf("NewJacsAgent 2 failed: %v", err)
	}
	defer agent2.Close()

	// Try to load invalid config on agent1 - should fail but not affect agent2
	err1 := agent1.Load("/invalid/path/1")
	err2 := agent2.Load("/invalid/path/2")

	// Both should fail independently
	if err1 == nil {
		t.Error("Expected error for agent1 load")
	}
	if err2 == nil {
		t.Error("Expected error for agent2 load")
	}

	// agent1's error shouldn't affect agent2's state
	// (We can't fully test this without valid configs, but the pattern is established)
}

// Benchmark functions
func BenchmarkHashString(b *testing.B) {
	data := "This is a test string for benchmarking"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := HashString(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBinaryDataEncode(b *testing.B) {
	data := make([]byte, 1024) // 1KB of data
	for i := range data {
		data[i] = byte(i % 256)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = EncodeBinaryData(data)
	}
}

func BenchmarkBinaryDataDecode(b *testing.B) {
	data := make([]byte, 1024) // 1KB of data
	for i := range data {
		data[i] = byte(i % 256)
	}
	encoded := EncodeBinaryData(data)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := DecodeBinaryData(encoded)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJacsAgentCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		agent, err := NewJacsAgent()
		if err != nil {
			b.Fatal(err)
		}
		agent.Close()
	}
}

func BenchmarkJacsAgentConcurrent(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			agent, err := NewJacsAgent()
			if err != nil {
				b.Fatal(err)
			}
			agent.Close()
		}
	})
}

// TestMain provides setup and teardown for all tests
func TestMain(m *testing.M) {
	// Setup
	fmt.Println("Running JACS Go binding tests...")

	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "jacs-go-test-*")
	if err != nil {
		fmt.Printf("Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}

	// Change to temp directory
	originalDir, _ := os.Getwd()
	os.Chdir(tempDir)

	// Run tests
	code := m.Run()

	// Cleanup
	os.Chdir(originalDir)
	os.RemoveAll(tempDir)

	os.Exit(code)
}
