package jacs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// =============================================================================
// HAI Error Types
// =============================================================================

// HaiError represents errors from HAI operations.
type HaiError struct {
	Kind    HaiErrorKind
	Message string
}

// HaiErrorKind categorizes HAI errors.
type HaiErrorKind int

const (
	// HaiErrorConnection indicates a network connection failure.
	HaiErrorConnection HaiErrorKind = iota
	// HaiErrorRegistration indicates agent registration failed.
	HaiErrorRegistration
	// HaiErrorAuthRequired indicates authentication is required.
	HaiErrorAuthRequired
	// HaiErrorInvalidResponse indicates the server returned an invalid response.
	HaiErrorInvalidResponse
	// HaiErrorKeyNotFound indicates the requested key was not found.
	HaiErrorKeyNotFound
)

func (e *HaiError) Error() string {
	return e.Message
}

func newHaiError(kind HaiErrorKind, format string, args ...interface{}) *HaiError {
	return &HaiError{
		Kind:    kind,
		Message: fmt.Sprintf(format, args...),
	}
}

// =============================================================================
// HAI Response Types
// =============================================================================

// HaiSignature represents a signature from HAI.
type HaiSignature struct {
	// KeyID is the identifier of the key used for signing.
	KeyID string `json:"key_id"`
	// Algorithm is the signing algorithm (e.g., "Ed25519", "ECDSA-P256").
	Algorithm string `json:"algorithm"`
	// Signature is the base64-encoded signature.
	Signature string `json:"signature"`
	// SignedAt is the ISO 8601 timestamp of when the signature was created.
	SignedAt string `json:"signed_at"`
}

// RegistrationResult contains the result of registering an agent with HAI.
type RegistrationResult struct {
	// AgentID is the agent's unique identifier.
	AgentID string `json:"agent_id"`
	// JacsID is the JACS document ID assigned by HAI.
	JacsID string `json:"jacs_id"`
	// DNSVerified indicates whether DNS verification was successful.
	DNSVerified bool `json:"dns_verified"`
	// Signatures contains HAI attestation signatures.
	Signatures []HaiSignature `json:"signatures"`
}

// StatusResult contains the registration status of an agent with HAI.
type StatusResult struct {
	// Registered indicates whether the agent is registered with HAI.
	Registered bool `json:"registered"`
	// AgentID is the agent's JACS ID.
	AgentID string `json:"agent_id"`
	// RegistrationID is the HAI registration ID.
	RegistrationID string `json:"registration_id"`
	// RegisteredAt is the ISO 8601 timestamp of when the agent was registered.
	RegisteredAt string `json:"registered_at"`
	// HaiSignatures contains the list of HAI signature IDs.
	HaiSignatures []string `json:"hai_signatures"`
}

// PublicKeyInfo contains information about a public key fetched from HAI.
type PublicKeyInfo struct {
	// PublicKey contains the raw public key bytes (DER encoded).
	PublicKey []byte `json:"public_key"`
	// Algorithm is the cryptographic algorithm (e.g., "ed25519", "rsa-pss-sha256").
	Algorithm string `json:"algorithm"`
	// PublicKeyHash is the SHA-256 hash of the public key.
	PublicKeyHash string `json:"public_key_hash"`
	// AgentID is the agent ID the key belongs to.
	AgentID string `json:"agent_id"`
	// Version is the version of the key.
	Version string `json:"version"`
}

// BenchmarkResult contains the result of a benchmark run.
type BenchmarkResult struct {
	// RunID is the unique identifier for the benchmark run.
	RunID string `json:"run_id"`
	// Suite is the benchmark suite that was run.
	Suite string `json:"suite"`
	// Score is the overall score (0.0 to 1.0).
	Score float64 `json:"score"`
	// Results contains individual test results.
	Results []BenchmarkTestResult `json:"results"`
	// CompletedAt is the ISO 8601 timestamp of when the benchmark completed.
	CompletedAt string `json:"completed_at"`
}

// BenchmarkTestResult contains an individual test result within a benchmark.
type BenchmarkTestResult struct {
	// Name is the test name.
	Name string `json:"name"`
	// Passed indicates whether the test passed.
	Passed bool `json:"passed"`
	// Score is the test score (0.0 to 1.0).
	Score float64 `json:"score"`
	// Message contains optional details (e.g., error message).
	Message string `json:"message,omitempty"`
}

// =============================================================================
// HAI Client
// =============================================================================

// HaiClient provides methods for interacting with HAI.ai services.
type HaiClient struct {
	endpoint   string
	apiKey     string
	httpClient *http.Client
}

// HaiClientOption is a functional option for configuring HaiClient.
type HaiClientOption func(*HaiClient)

// WithAPIKey sets the API key for authentication.
func WithAPIKey(apiKey string) HaiClientOption {
	return func(c *HaiClient) {
		c.apiKey = apiKey
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) HaiClientOption {
	return func(c *HaiClient) {
		c.httpClient = client
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) HaiClientOption {
	return func(c *HaiClient) {
		c.httpClient.Timeout = timeout
	}
}

// NewHaiClient creates a new HAI client.
//
// Parameters:
//   - endpoint: Base URL of the HAI API (e.g., "https://api.hai.ai")
//   - opts: Optional configuration options
//
// Example:
//
//	client := jacs.NewHaiClient("https://api.hai.ai",
//	    jacs.WithAPIKey("your-api-key"),
//	    jacs.WithTimeout(30 * time.Second))
func NewHaiClient(endpoint string, opts ...HaiClientOption) *HaiClient {
	// Trim trailing slash
	if len(endpoint) > 0 && endpoint[len(endpoint)-1] == '/' {
		endpoint = endpoint[:len(endpoint)-1]
	}

	client := &HaiClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

// Endpoint returns the base endpoint URL.
func (c *HaiClient) Endpoint() string {
	return c.endpoint
}

// TestConnection verifies connectivity to the HAI server.
//
// Returns true if the server is reachable and healthy.
func (c *HaiClient) TestConnection() (bool, error) {
	url := fmt.Sprintf("%s/health", c.endpoint)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return false, newHaiError(HaiErrorConnection, "connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, newHaiError(HaiErrorConnection, "server returned status: %d", resp.StatusCode)
	}

	// Try to parse health response
	var health struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		// 2xx without JSON body is still success
		return true, nil
	}

	return health.Status == "ok" || health.Status == "healthy", nil
}

// Note: Register(agent *JacsAgent) is not provided because extracting
// agent JSON from the FFI-based JacsAgent is not yet implemented.
// Use RegisterWithJSON(agentJSON string) instead.

// RegisterWithJSON registers a JACS agent with HAI using raw agent JSON.
//
// This is the preferred method when you have the agent JSON available.
func (c *HaiClient) RegisterWithJSON(agentJSON string) (*RegistrationResult, error) {
	if c.apiKey == "" {
		return nil, newHaiError(HaiErrorAuthRequired, "authentication required: provide an API key")
	}

	url := fmt.Sprintf("%s/api/v1/agents/register", c.endpoint)

	reqBody := struct {
		AgentJSON string `json:"agent_json"`
	}{
		AgentJSON: agentJSON,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, newHaiError(HaiErrorInvalidResponse, "failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, newHaiError(HaiErrorConnection, "failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, newHaiError(HaiErrorConnection, "connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, newHaiError(HaiErrorRegistration, "status %d: %s", resp.StatusCode, string(body))
	}

	var result RegistrationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, newHaiError(HaiErrorInvalidResponse, "failed to decode response: %v", err)
	}

	return &result, nil
}

// Status checks the registration status of an agent with HAI.
func (c *HaiClient) Status(agentID string) (*StatusResult, error) {
	if c.apiKey == "" {
		return nil, newHaiError(HaiErrorAuthRequired, "authentication required: provide an API key")
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/status", c.endpoint, agentID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, newHaiError(HaiErrorConnection, "failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, newHaiError(HaiErrorConnection, "connection failed: %v", err)
	}
	defer resp.Body.Close()

	// Handle 404 as "not registered"
	if resp.StatusCode == http.StatusNotFound {
		return &StatusResult{
			Registered: false,
			AgentID:    agentID,
		}, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, newHaiError(HaiErrorInvalidResponse, "status %d: %s", resp.StatusCode, string(body))
	}

	var result StatusResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, newHaiError(HaiErrorInvalidResponse, "failed to decode response: %v", err)
	}

	result.Registered = true
	if result.AgentID == "" {
		result.AgentID = agentID
	}

	return &result, nil
}

// Benchmark runs a benchmark suite for an agent.
func (c *HaiClient) Benchmark(agentID, suite string) (*BenchmarkResult, error) {
	if c.apiKey == "" {
		return nil, newHaiError(HaiErrorAuthRequired, "authentication required: provide an API key")
	}

	url := fmt.Sprintf("%s/api/v1/benchmarks/run", c.endpoint)

	reqBody := struct {
		AgentID string `json:"agent_id"`
		Suite   string `json:"suite"`
	}{
		AgentID: agentID,
		Suite:   suite,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, newHaiError(HaiErrorInvalidResponse, "failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, newHaiError(HaiErrorConnection, "failed to create request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, newHaiError(HaiErrorConnection, "connection failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, newHaiError(HaiErrorInvalidResponse, "status %d: %s", resp.StatusCode, string(body))
	}

	var result BenchmarkResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, newHaiError(HaiErrorInvalidResponse, "failed to decode response: %v", err)
	}

	return &result, nil
}

// =============================================================================
// Remote Key Fetch Functions
// =============================================================================

// Default base URL for HAI key service
const defaultHaiKeysBaseURL = "https://keys.hai.ai"

// FetchRemoteKey fetches a public key from HAI's key distribution service.
//
// This function retrieves the public key for a specific agent and version
// from the HAI key distribution service. It is used to obtain trusted public
// keys for verifying agent signatures without requiring local key storage.
//
// Parameters:
//   - agentID: The unique identifier of the agent whose key to fetch
//   - version: The version of the agent's key to fetch. Use "latest" for
//     the most recent version.
//
// Returns PublicKeyInfo containing the public key, algorithm, and hash on success.
//
// Environment Variables:
//   - HAI_KEYS_BASE_URL: Base URL for the key service. Defaults to "https://keys.hai.ai"
//
// Example:
//
//	keyInfo, err := jacs.FetchRemoteKey("550e8400-e29b-41d4-a716-446655440000", "latest")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Algorithm: %s\n", keyInfo.Algorithm)
func FetchRemoteKey(agentID, version string) (*PublicKeyInfo, error) {
	baseURL := os.Getenv("HAI_KEYS_BASE_URL")
	if baseURL == "" {
		baseURL = defaultHaiKeysBaseURL
	}

	return FetchRemoteKeyFromURL(baseURL, agentID, version)
}

// FetchRemoteKeyFromURL fetches a public key from a specific key service URL.
//
// This is useful for testing or using alternative key distribution services.
func FetchRemoteKeyFromURL(baseURL, agentID, version string) (*PublicKeyInfo, error) {
	// Trim trailing slash
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}

	url := fmt.Sprintf("%s/jacs/v1/agents/%s/keys/%s", baseURL, agentID, version)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, newHaiError(HaiErrorConnection, "failed to fetch key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, newHaiError(HaiErrorKeyNotFound, "public key not found for agent '%s' version '%s'", agentID, version)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, newHaiError(HaiErrorConnection, "status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response - HAI returns the key in a JSON envelope
	var keyResp struct {
		PublicKey     string `json:"public_key"`      // Base64-encoded DER
		Algorithm     string `json:"algorithm"`       // e.g., "ed25519"
		PublicKeyHash string `json:"public_key_hash"` // SHA-256 hash
		AgentID       string `json:"agent_id"`
		Version       string `json:"version"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, newHaiError(HaiErrorInvalidResponse, "failed to decode key response: %v", err)
	}

	// Decode base64 public key
	publicKey, err := base64.StdEncoding.DecodeString(keyResp.PublicKey)
	if err != nil {
		return nil, newHaiError(HaiErrorInvalidResponse, "invalid public key encoding: %v", err)
	}

	return &PublicKeyInfo{
		PublicKey:     publicKey,
		Algorithm:     keyResp.Algorithm,
		PublicKeyHash: keyResp.PublicKeyHash,
		AgentID:       keyResp.AgentID,
		Version:       keyResp.Version,
	}, nil
}

// FetchKeyByHash fetches a public key by its hash from HAI's key service.
//
// Parameters:
//   - publicKeyHash: The SHA-256 hash of the public key to fetch
//
// This is useful when you have a signature that includes the key hash
// but not the full key.
func FetchKeyByHash(publicKeyHash string) (*PublicKeyInfo, error) {
	baseURL := os.Getenv("HAI_KEYS_BASE_URL")
	if baseURL == "" {
		baseURL = defaultHaiKeysBaseURL
	}

	return FetchKeyByHashFromURL(baseURL, publicKeyHash)
}

// FetchKeyByHashFromURL fetches a public key by hash from a specific URL.
func FetchKeyByHashFromURL(baseURL, publicKeyHash string) (*PublicKeyInfo, error) {
	// Trim trailing slash
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}

	url := fmt.Sprintf("%s/jacs/v1/keys/by-hash/%s", baseURL, publicKeyHash)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, newHaiError(HaiErrorConnection, "failed to fetch key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, newHaiError(HaiErrorKeyNotFound, "public key not found for hash '%s'", publicKeyHash)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, newHaiError(HaiErrorConnection, "status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var keyResp struct {
		PublicKey     string `json:"public_key"`
		Algorithm     string `json:"algorithm"`
		PublicKeyHash string `json:"public_key_hash"`
		AgentID       string `json:"agent_id"`
		Version       string `json:"version"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&keyResp); err != nil {
		return nil, newHaiError(HaiErrorInvalidResponse, "failed to decode key response: %v", err)
	}

	// Decode base64 public key
	publicKey, err := base64.StdEncoding.DecodeString(keyResp.PublicKey)
	if err != nil {
		return nil, newHaiError(HaiErrorInvalidResponse, "invalid public key encoding: %v", err)
	}

	return &PublicKeyInfo{
		PublicKey:     publicKey,
		Algorithm:     keyResp.Algorithm,
		PublicKeyHash: keyResp.PublicKeyHash,
		AgentID:       keyResp.AgentID,
		Version:       keyResp.Version,
	}, nil
}

// =============================================================================
// Convenience Functions (use default HAI endpoint)
// =============================================================================

// DefaultHaiEndpoint is the default HAI API endpoint.
const DefaultHaiEndpoint = "https://api.hai.ai"

// VerifyAgentWithHai verifies an agent's registration status with HAI.
//
// This is a convenience function that creates a temporary client.
// For multiple operations, create a HaiClient instance instead.
func VerifyAgentWithHai(apiKey, agentID string) (*StatusResult, error) {
	client := NewHaiClient(DefaultHaiEndpoint, WithAPIKey(apiKey))
	return client.Status(agentID)
}

// RegisterAgentWithHai registers an agent with HAI.
//
// This is a convenience function that creates a temporary client.
// For multiple operations, create a HaiClient instance instead.
func RegisterAgentWithHai(apiKey, agentJSON string) (*RegistrationResult, error) {
	client := NewHaiClient(DefaultHaiEndpoint, WithAPIKey(apiKey))
	return client.RegisterWithJSON(agentJSON)
}
