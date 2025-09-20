package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	jacs "github.com/HumanAssisted/JACS/jacsgo"
)

// MCPRequest represents a Model Context Protocol request
type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      interface{} `json:"id"`
}

// MCPResponse represents a Model Context Protocol response
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// MCPError represents an MCP error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// JACSMCPTransport wraps MCP messages with JACS authentication
type JACSMCPTransport struct {
	// In a real implementation, this would wrap an actual MCP transport
}

// SendRequest sends a JACS-signed MCP request
func (t *JACSMCPTransport) SendRequest(request MCPRequest) (string, error) {
	// Sign the request with JACS
	signed, err := jacs.SignRequest(request)
	if err != nil {
		return "", fmt.Errorf("failed to sign request: %v", err)
	}

	fmt.Printf("Signed MCP request:\n%s\n", signed)
	return signed, nil
}

// VerifyResponse verifies a JACS-signed MCP response
func (t *JACSMCPTransport) VerifyResponse(signedResponse string) (*MCPResponse, error) {
	// Verify the response
	payload, err := jacs.VerifyResponse(signedResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to verify response: %v", err)
	}

	// Convert to MCPResponse
	var response MCPResponse
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	err = json.Unmarshal(payloadJSON, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return &response, nil
}

// Example MCP server implementation
type ExampleMCPServer struct {
	transport *JACSMCPTransport
}

// HandleRequest processes an MCP request
func (s *ExampleMCPServer) HandleRequest(signedRequest string) (string, error) {
	// Verify the request
	payload, err := jacs.VerifyResponse(signedRequest)
	if err != nil {
		return "", fmt.Errorf("failed to verify request: %v", err)
	}

	// Parse as MCP request
	var request MCPRequest
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(payloadJSON, &request)
	if err != nil {
		return "", err
	}

	fmt.Printf("Received MCP request: method=%s, id=%v\n", request.Method, request.ID)

	// Process the request based on method
	var result interface{}
	var mcpError *MCPError

	switch request.Method {
	case "tools/list":
		result = map[string]interface{}{
			"tools": []map[string]interface{}{
				{
					"name":        "example_tool",
					"description": "An example tool for demonstration",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"input": map[string]string{
								"type":        "string",
								"description": "Input data",
							},
						},
					},
				},
			},
		}

	case "tools/call":
		result = map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": "Tool executed successfully",
				},
			},
		}

	default:
		mcpError = &MCPError{
			Code:    -32601,
			Message: "Method not found",
		}
	}

	// Create response
	response := MCPResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
	}

	if mcpError != nil {
		response.Error = mcpError
	} else {
		response.Result = result
	}

	// Sign the response
	signed, err := jacs.SignRequest(response)
	if err != nil {
		return "", fmt.Errorf("failed to sign response: %v", err)
	}

	return signed, nil
}

func main() {
	fmt.Println("=== JACS MCP Integration Example ===")
	fmt.Println("Note: This is a demonstration of how JACS would integrate with MCP")
	fmt.Println("A real implementation would require an actual Go MCP SDK\n")

	// Load JACS configuration
	configPath := os.Getenv("JACS_CONFIG")
	if configPath == "" {
		configPath = "jacs.config.json"
	}

	fmt.Printf("Loading JACS configuration from: %s\n", configPath)
	err := jacs.Load(configPath)
	if err != nil {
		log.Printf("Warning: Failed to load JACS config: %v", err)
		log.Printf("Running without JACS capabilities\n")
	} else {
		log.Printf("JACS configuration loaded successfully\n")
	}

	// Create transport
	transport := &JACSMCPTransport{}

	// Example 1: Client sending a request
	fmt.Println("=== Client Example ===")

	// Create an MCP request
	request := MCPRequest{
		JSONRPC: "2.0",
		Method:  "tools/list",
		ID:      "1",
	}

	// Send the request
	signedRequest, err := transport.SendRequest(request)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
	} else {
		fmt.Printf("Client sent signed request (length: %d bytes)\n\n", len(signedRequest))
	}

	// Example 2: Server handling a request
	fmt.Println("=== Server Example ===")
	server := &ExampleMCPServer{transport: transport}

	// Simulate receiving the signed request
	if signedRequest != "" {
		signedResponse, err := server.HandleRequest(signedRequest)
		if err != nil {
			log.Printf("Server failed to handle request: %v", err)
		} else {
			fmt.Printf("Server created signed response (length: %d bytes)\n\n", len(signedResponse))

			// Client verifying the response
			fmt.Println("=== Client Verifying Response ===")
			response, err := transport.VerifyResponse(signedResponse)
			if err != nil {
				log.Printf("Failed to verify response: %v", err)
			} else {
				fmt.Printf("Verified response: %+v\n", response)
			}
		}
	}

	// Example 3: Demonstrate MCP message patterns
	fmt.Println("\n=== MCP Message Patterns ===")

	examples := []MCPRequest{
		{
			JSONRPC: "2.0",
			Method:  "initialize",
			Params: map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"clientInfo": map[string]interface{}{
					"name":    "example-client",
					"version": "1.0.0",
				},
			},
			ID: "init-1",
		},
		{
			JSONRPC: "2.0",
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "example_tool",
				"arguments": map[string]interface{}{
					"input": "test data",
				},
			},
			ID: 42,
		},
	}

	for _, example := range examples {
		fmt.Printf("\nExample %s request:\n", example.Method)

		// Show original
		original, _ := json.MarshalIndent(example, "", "  ")
		fmt.Printf("Original:\n%s\n", original)

		// Sign it
		signed, err := jacs.SignRequest(example)
		if err != nil {
			log.Printf("Failed to sign: %v", err)
		} else {
			fmt.Printf("Signed (first 100 chars):\n%s...\n", signed[:min(100, len(signed))])
		}
	}

	fmt.Println("\n=== MCP Integration Example Completed ===")
	fmt.Println("This demonstrates how JACS would wrap MCP protocol messages")
	fmt.Println("In a real implementation, this would integrate with an MCP transport layer")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
