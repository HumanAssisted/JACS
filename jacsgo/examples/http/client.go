package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	jacs "github.com/HumanAssisted/JACS/jacsgo"
)

// Client represents a JACS HTTP client
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new JACS HTTP client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: &http.Client{},
	}
}

// doRequest performs an HTTP request with optional JACS signing
func (c *Client) doRequest(method, path string, data interface{}) ([]byte, error) {
	var body io.Reader

	if data != nil {
		// Convert data to JSON
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %v", err)
		}

		// Try to sign the request with JACS
		signed, err := jacs.SignRequest(data)
		if err == nil {
			// Use JACS-signed request
			body = bytes.NewBufferString(signed)
			log.Printf("Sending JACS-signed request")
		} else {
			// Send unsigned request
			body = bytes.NewBuffer(jsonData)
			log.Printf("Sending unsigned request (signing failed: %v)", err)
		}
	}

	// Create request
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Check if response is JACS-signed
	if resp.Header.Get("X-JACS-Signed") == "true" {
		log.Printf("Received JACS-signed response")

		// Try to verify the response
		payload, err := jacs.VerifyResponse(string(respBody))
		if err == nil {
			log.Printf("Successfully verified JACS response")
			// Convert payload back to JSON
			verifiedJSON, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal verified payload: %v", err)
			}
			return verifiedJSON, nil
		} else {
			log.Printf("Failed to verify JACS response: %v", err)
		}
	}

	return respBody, nil
}

// Echo sends data to the echo endpoint
func (c *Client) Echo(data interface{}) error {
	resp, err := c.doRequest("POST", "/echo", data)
	if err != nil {
		return err
	}

	fmt.Printf("Echo response: %s\n", string(resp))
	return nil
}

// CreateDocument sends data to create a JACS document
func (c *Client) CreateDocument(data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %v", err)
	}

	resp, err := c.doRequest("POST", "/document", json.RawMessage(jsonData))
	if err != nil {
		return err
	}

	fmt.Printf("Document response: %s\n", string(resp))
	return nil
}

// Hash sends data to be hashed
func (c *Client) Hash(data string) error {
	resp, err := c.doRequest("POST", "/hash", data)
	if err != nil {
		return err
	}

	fmt.Printf("Hash response: %s\n", string(resp))
	return nil
}

// HealthCheck performs a health check
func (c *Client) HealthCheck() error {
	resp, err := c.doRequest("GET", "/health", nil)
	if err != nil {
		return err
	}

	fmt.Printf("Health check: %s\n", string(resp))
	return nil
}

func main() {
	// Try to load JACS configuration for client
	configPath := os.Getenv("JACS_CONFIG")
	if configPath == "" {
		configPath = "jacs.client.config.json"
	}

	fmt.Printf("Loading JACS configuration from: %s\n", configPath)
	err := jacs.Load(configPath)
	if err != nil {
		log.Printf("Warning: Failed to load JACS config: %v", err)
		log.Printf("Client will run without JACS signing capabilities")
	} else {
		log.Printf("JACS configuration loaded successfully")
	}

	// Get server URL from environment or use default
	serverURL := os.Getenv("SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}

	// Create client
	client := NewClient(serverURL)
	fmt.Printf("Connecting to server at: %s\n\n", serverURL)

	// Example 1: Health check
	fmt.Println("=== Health Check ===")
	if err := client.HealthCheck(); err != nil {
		log.Printf("Health check failed: %v", err)
	}
	fmt.Println()

	// Example 2: Echo request
	fmt.Println("=== Echo Request ===")
	echoData := map[string]interface{}{
		"message":   "Hello from JACS Go client!",
		"timestamp": "2025-01-01T00:00:00Z",
		"data": map[string]interface{}{
			"numbers": []int{1, 2, 3, 4, 5},
			"active":  true,
		},
	}
	if err := client.Echo(echoData); err != nil {
		log.Printf("Echo failed: %v", err)
	}
	fmt.Println()

	// Example 3: Create document
	fmt.Println("=== Create Document ===")
	documentData := map[string]interface{}{
		"title":   "Test Document",
		"content": "This document was created by the JACS Go HTTP client",
		"author":  "JACS Client",
		"metadata": map[string]interface{}{
			"version": "1.0",
			"tags":    []string{"test", "client", "go"},
		},
	}
	if err := client.CreateDocument(documentData); err != nil {
		log.Printf("Create document failed: %v", err)
	}
	fmt.Println()

	// Example 4: Hash data
	fmt.Println("=== Hash Data ===")
	if err := client.Hash("This is some data to hash"); err != nil {
		log.Printf("Hash failed: %v", err)
	}
	fmt.Println()

	fmt.Println("=== Client example completed ===")
}
