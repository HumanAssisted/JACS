package jacs

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// Global agent instance for simplified API
var (
	globalAgent *JacsAgent
	globalMutex sync.Mutex
	agentInfo   *AgentInfo
)

// Create creates a new JACS agent with cryptographic keys.
//
// This generates keys, creates configuration files, and saves them to the
// current working directory.
//
// Parameters:
//   - name: Human-readable name for the agent
//   - purpose: Optional description of the agent's purpose (can be empty)
//   - keyAlgorithm: Signing algorithm ("ed25519", "rsa-pss", or "pq2025")
//
// Returns AgentInfo containing the agent ID and file paths.
func Create(name, purpose, keyAlgorithm string) (*AgentInfo, error) {
	// For now, this uses the existing CreateConfig + initialization flow
	// A full implementation would call the Rust simple::create via FFI

	algorithm := keyAlgorithm
	if algorithm == "" {
		algorithm = "ed25519"
	}

	// Create config
	dataDir := "./jacs_data"
	keyDir := "./jacs_keys"

	_, err := CreateConfig(&Config{
		DataDirectory:     &dataDir,
		KeyDirectory:      &keyDir,
		AgentKeyAlgorithm: &algorithm,
	})
	if err != nil {
		return nil, NewSimpleError("create", err)
	}

	// Load the created agent
	if err := Load(nil); err != nil {
		return nil, NewSimpleError("create", err)
	}

	info := &AgentInfo{
		AgentID:       "", // Would be populated from agent
		Name:          name,
		PublicKeyPath: "./jacs_keys/jacs.public.pem",
		ConfigPath:    "./jacs.config.json",
	}

	agentInfo = info
	return info, nil
}

// Load loads an existing agent from a configuration file.
//
// Parameters:
//   - configPath: Path to jacs.config.json (nil for default "./jacs.config.json")
func Load(configPath *string) error {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	path := "./jacs.config.json"
	if configPath != nil {
		path = *configPath
	}

	// Check if config exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return NewSimpleErrorWithPath("load", path, ErrConfigNotFound)
	}

	// Create new agent instance
	agent, err := NewJacsAgent()
	if err != nil {
		return NewSimpleError("load", err)
	}

	// Load config
	if err := agent.Load(path); err != nil {
		agent.Close()
		return NewSimpleError("load", err)
	}

	// Close old agent if exists
	if globalAgent != nil {
		globalAgent.Close()
	}

	globalAgent = agent
	agentInfo = &AgentInfo{
		ConfigPath: path,
	}

	return nil
}

// VerifySelf verifies the loaded agent's own integrity.
//
// This checks:
// - Self-signature validity
// - Document hash integrity
func VerifySelf() (*VerificationResult, error) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent == nil {
		return nil, ErrAgentNotLoaded
	}

	if err := globalAgent.VerifyAgent(nil); err != nil {
		return &VerificationResult{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	return &VerificationResult{
		Valid:    true,
		SignerID: agentInfo.AgentID,
	}, nil
}

// SignMessage signs arbitrary data as a JACS message.
//
// Parameters:
//   - data: The data to sign (will be JSON-serialized if not already a string)
//
// Returns a SignedDocument containing the full signed document.
func SignMessage(data interface{}) (*SignedDocument, error) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent == nil {
		return nil, ErrAgentNotLoaded
	}

	// Convert data to JSON if needed
	var jsonData string
	switch v := data.(type) {
	case string:
		jsonData = v
	case []byte:
		jsonData = string(v)
	default:
		jsonBytes, err := json.Marshal(data)
		if err != nil {
			return nil, NewSimpleError("sign_message", err)
		}
		jsonData = string(jsonBytes)
	}

	// Create document structure
	docStruct := map[string]interface{}{
		"jacsType":  "message",
		"jacsLevel": "raw",
		"content":   json.RawMessage(jsonData),
	}

	docJSON, err := json.Marshal(docStruct)
	if err != nil {
		return nil, NewSimpleError("sign_message", err)
	}

	// Sign using agent
	noSave := true
	result, err := globalAgent.CreateDocument(string(docJSON), nil, nil, &noSave, nil, nil)
	if err != nil {
		return nil, NewSimpleError("sign_message", err)
	}

	// Parse result to extract fields
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(result), &doc); err != nil {
		return nil, NewSimpleError("sign_message", err)
	}

	signed := &SignedDocument{
		Raw:        result,
		DocumentID: getStringField(doc, "jacsId"),
		Timestamp:  getNestedStringField(doc, "jacsSignature", "date"),
		AgentID:    getNestedStringField(doc, "jacsSignature", "agentID"),
	}

	return signed, nil
}

// SignFile signs a file with optional content embedding.
//
// Parameters:
//   - filePath: Path to the file to sign
//   - embed: If true, embed file content in the document
//
// Returns a SignedDocument containing the signed file reference.
func SignFile(filePath string, embed bool) (*SignedDocument, error) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent == nil {
		return nil, ErrAgentNotLoaded
	}

	// Check file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, NewSimpleErrorWithPath("sign_file", filePath, ErrFileNotFound)
	}

	// Create document structure
	docStruct := map[string]interface{}{
		"jacsType":  "file",
		"jacsLevel": "raw",
		"filename":  filePath,
	}

	docJSON, err := json.Marshal(docStruct)
	if err != nil {
		return nil, NewSimpleError("sign_file", err)
	}

	// Sign with attachment
	noSave := true
	embedPtr := &embed
	result, err := globalAgent.CreateDocument(string(docJSON), nil, nil, &noSave, &filePath, embedPtr)
	if err != nil {
		return nil, NewSimpleError("sign_file", err)
	}

	// Parse result to extract fields
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(result), &doc); err != nil {
		return nil, NewSimpleError("sign_file", err)
	}

	signed := &SignedDocument{
		Raw:        result,
		DocumentID: getStringField(doc, "jacsId"),
		Timestamp:  getNestedStringField(doc, "jacsSignature", "date"),
		AgentID:    getNestedStringField(doc, "jacsSignature", "agentID"),
	}

	return signed, nil
}

// Verify verifies a signed document and extracts its content.
//
// Parameters:
//   - signedDocument: The JSON string of the signed document
//
// Returns a VerificationResult with the verification status and extracted content.
func Verify(signedDocument string) (*VerificationResult, error) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent == nil {
		return nil, ErrAgentNotLoaded
	}

	// Parse document first
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(signedDocument), &doc); err != nil {
		return &VerificationResult{
			Valid:  false,
			Errors: []string{"invalid JSON: " + err.Error()},
		}, nil
	}

	// Verify using agent
	err := globalAgent.VerifyDocument(signedDocument)

	result := &VerificationResult{
		Valid:     err == nil,
		SignerID:  getNestedStringField(doc, "jacsSignature", "agentID"),
		Timestamp: getNestedStringField(doc, "jacsSignature", "date"),
		Data:      doc["content"],
	}

	if err != nil {
		result.Errors = []string{err.Error()}
	}

	return result, nil
}

// ExportAgent exports the current agent's identity JSON for P2P exchange.
func ExportAgent() (string, error) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent == nil {
		return "", ErrAgentNotLoaded
	}

	// Read agent file from config location
	// This is a simplified implementation
	return "", NewSimpleError("export_agent", errors.New("not yet implemented"))
}

// GetPublicKeyPEM returns the current agent's public key in PEM format.
func GetPublicKeyPEM() (string, error) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent == nil {
		return "", ErrAgentNotLoaded
	}

	// Read public key file
	keyPath := "./jacs_keys/jacs.public.pem"
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return "", NewSimpleErrorWithPath("get_public_key", keyPath, ErrKeyNotFound)
	}

	return string(data), nil
}

// GetAgentInfo returns information about the currently loaded agent.
func GetAgentInfo() *AgentInfo {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return agentInfo
}

// IsLoaded returns true if an agent is currently loaded.
func IsLoaded() bool {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	return globalAgent != nil
}

// Helper functions

func getStringField(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getNestedStringField(m map[string]interface{}, keys ...string) string {
	current := m
	for i, key := range keys {
		if i == len(keys)-1 {
			return getStringField(current, key)
		}
		if nested, ok := current[key].(map[string]interface{}); ok {
			current = nested
		} else {
			return ""
		}
	}
	return ""
}
