package jacs

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
)

// Global agent instance for simplified API
var (
	globalAgent *JacsAgent
	globalMutex sync.Mutex
	agentInfo   *AgentInfo
)

// CreateAgentOptions contains options for programmatic agent creation.
type CreateAgentOptions struct {
	// Password for encrypting the private key. Required unless JACS_AGENT_PRIVATE_KEY_PASSWORD is set.
	Password string
	// Algorithm is the signing algorithm: "pq2025" (default), "ring-Ed25519", or "RSA-PSS".
	// "pq-dilithium" is deprecated.
	Algorithm string
	// DataDirectory is the directory for agent data (default: "./jacs_data").
	DataDirectory string
	// KeyDirectory is the directory for cryptographic keys (default: "./jacs_keys").
	KeyDirectory string
	// ConfigPath is the path to write the config file (default: "./jacs.config.json").
	ConfigPath string
	// AgentType is the agent type: "ai" (default), "human", or "hybrid".
	AgentType string
	// Description of the agent's purpose.
	Description string
	// Domain for DNS-based agent discovery.
	Domain string
	// DefaultStorage is the storage backend: "fs" (default).
	DefaultStorage string
}

// Create creates a new JACS agent with cryptographic keys.
//
// This is a fully programmatic API. If opts is nil, default options are used.
// The password must be provided in opts or via JACS_AGENT_PRIVATE_KEY_PASSWORD env var.
//
// Parameters:
//   - name: Human-readable name for the agent
//   - opts: Optional creation options (nil for defaults)
//
// Returns AgentInfo containing the agent ID and file paths.
func Create(name string, opts *CreateAgentOptions) (*AgentInfo, error) {
	if opts == nil {
		opts = &CreateAgentOptions{}
	}

	algorithm := opts.Algorithm
	if algorithm == "" {
		algorithm = "pq2025"
	}

	password := opts.Password
	if password == "" {
		password = os.Getenv("JACS_AGENT_PRIVATE_KEY_PASSWORD")
	}
	if password == "" {
		return nil, NewSimpleError("create", errors.New(
			"password is required: provide it in CreateAgentOptions.Password or set JACS_AGENT_PRIVATE_KEY_PASSWORD env var",
		))
	}

	dataDir := opts.DataDirectory
	if dataDir == "" {
		dataDir = "./jacs_data"
	}
	keyDir := opts.KeyDirectory
	if keyDir == "" {
		keyDir = "./jacs_keys"
	}
	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = "./jacs.config.json"
	}
	defaultStorage := opts.DefaultStorage
	if defaultStorage == "" {
		defaultStorage = "fs"
	}

	_, err := CreateConfig(Config{
		DataDirectory:      &dataDir,
		KeyDirectory:       &keyDir,
		AgentKeyAlgorithm:  &algorithm,
		PrivateKeyPassword: &password,
		DefaultStorage:     &defaultStorage,
	})
	if err != nil {
		return nil, NewSimpleError("create", err)
	}

	// Load the created agent
	if err := Load(&configPath); err != nil {
		return nil, NewSimpleError("create", err)
	}

	// Read the config file to extract the agent ID
	agentID := ""
	if cfgData, err := os.ReadFile(configPath); err == nil {
		var cfg map[string]interface{}
		if err := json.Unmarshal(cfgData, &cfg); err == nil {
			if idStr, ok := cfg["jacs_agent_id_and_version"].(string); ok {
				agentID = idStr
			}
		}
	}

	info := &AgentInfo{
		AgentID:       agentID,
		Name:          name,
		PublicKeyPath: keyDir + "/jacs.public.pem",
		ConfigPath:    configPath,
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
	result, err := globalAgent.CreateDocument(string(docJSON), nil, nil, noSave, nil, nil)
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
	result, err := globalAgent.CreateDocument(string(docJSON), nil, nil, noSave, &filePath, &embed)
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

	// Detect non-JSON input and provide helpful error
	trimmed := strings.TrimSpace(signedDocument)
	if len(trimmed) > 0 && trimmed[0] != '{' && trimmed[0] != '[' {
		preview := trimmed
		if len(preview) > 50 {
			preview = preview[:50] + "..."
		}
		return &VerificationResult{
			Valid: false,
			Errors: []string{
				"Input does not appear to be a JSON document. If you have a document ID (e.g., 'uuid:version'), use VerifyById() instead. Received: '" + preview + "'",
			},
		}, nil
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

// VerifyById verifies a document by its storage ID.
//
// Use this when you have a document ID (e.g., "uuid:version") rather than
// the full JSON string. The document will be loaded from storage and verified.
//
// Parameters:
//   - documentId: The document ID in "uuid:version" format
func VerifyById(documentId string) (*VerificationResult, error) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent == nil {
		return nil, ErrAgentNotLoaded
	}

	if !strings.Contains(documentId, ":") {
		return &VerificationResult{
			Valid: false,
			Errors: []string{
				"Document ID must be in 'uuid:version' format, got '" + documentId + "'. Use Verify() with the full JSON string instead.",
			},
		}, nil
	}

	err := globalAgent.VerifyDocumentById(documentId)
	if err != nil {
		return &VerificationResult{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	return &VerificationResult{
		Valid: true,
	}, nil
}

// ReencryptKey re-encrypts the agent's private key with a new password.
//
// Parameters:
//   - oldPassword: The current password for the private key
//   - newPassword: The new password (must meet password requirements: 8+ chars, mixed case, number, special)
func ReencryptKey(oldPassword, newPassword string) error {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent == nil {
		return ErrAgentNotLoaded
	}

	// Read config to find key path
	configPath := "./jacs.config.json"
	if agentInfo != nil && agentInfo.ConfigPath != "" {
		configPath = agentInfo.ConfigPath
	}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		return NewSimpleError("reencrypt_key", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(configData, &config); err != nil {
		return NewSimpleError("reencrypt_key", err)
	}

	keyDir := "./jacs_keys"
	if dir, ok := config["jacs_key_directory"].(string); ok && dir != "" {
		keyDir = dir
	}
	keyFile := "jacs.private.pem.enc"
	if file, ok := config["jacs_agent_private_key_filename"].(string); ok && file != "" {
		keyFile = file
	}
	keyPath := keyDir + "/" + keyFile

	// Read encrypted key
	encryptedData, err := os.ReadFile(keyPath)
	if err != nil {
		return NewSimpleErrorWithPath("reencrypt_key", keyPath, err)
	}

	_ = encryptedData

	return globalAgent.ReencryptKey(oldPassword, newPassword)
}

// ExportAgent exports the current agent's identity JSON for P2P exchange.
func ExportAgent() (string, error) {
	globalMutex.Lock()
	defer globalMutex.Unlock()

	if globalAgent == nil {
		return "", ErrAgentNotLoaded
	}

	return globalAgent.GetJSON()
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
