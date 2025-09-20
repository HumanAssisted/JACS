package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
	// Example 1: Create a JACS configuration
	fmt.Println("=== Creating JACS Configuration ===")

	useSecurity := "true"
	dataDir := "./jacs_data"
	keyDir := "./jacs_keys"
	privateKeyFile := "jacs.private.pem.enc"
	publicKeyFile := "jacs.public.pem"
	keyAlgorithm := "RSA"
	password := "test_password"
	agentID := "example-agent:v0.1.0"
	storage := "local"

	config := jacs.Config{
		UseSecurity:         &useSecurity,
		DataDirectory:       &dataDir,
		KeyDirectory:        &keyDir,
		AgentPrivateKeyFile: &privateKeyFile,
		AgentPublicKeyFile:  &publicKeyFile,
		AgentKeyAlgorithm:   &keyAlgorithm,
		PrivateKeyPassword:  &password,
		AgentIDAndVersion:   &agentID,
		DefaultStorage:      &storage,
	}

	configJSON, err := jacs.CreateConfig(config)
	if err != nil {
		log.Fatalf("Failed to create config: %v", err)
	}

	fmt.Printf("Generated config:\n%s\n\n", configJSON)

	// Save config to file
	err = os.WriteFile("jacs.config.json", []byte(configJSON), 0644)
	if err != nil {
		log.Fatalf("Failed to write config file: %v", err)
	}

	// Example 2: Load JACS configuration
	fmt.Println("=== Loading JACS Configuration ===")
	err = jacs.Load("jacs.config.json")
	if err != nil {
		// Note: This might fail if the config references non-existent keys
		fmt.Printf("Warning: Failed to load config (this is expected if keys don't exist): %v\n\n", err)
	} else {
		fmt.Println("Configuration loaded successfully\n")
	}

	// Example 3: Hash a string
	fmt.Println("=== Hashing a String ===")
	testData := "Hello, JACS!"
	hash, err := jacs.HashString(testData)
	if err != nil {
		log.Fatalf("Failed to hash string: %v", err)
	}
	fmt.Printf("Original: %s\n", testData)
	fmt.Printf("Hash: %s\n\n", hash)

	// Example 4: Sign and verify a string (requires loaded agent with keys)
	fmt.Println("=== Sign and Verify String ===")
	fmt.Println("Note: This example requires a properly configured agent with keys")

	// Example 5: Create a document
	fmt.Println("=== Creating a Document ===")
	documentData := map[string]interface{}{
		"title":     "Example Document",
		"content":   "This is a test document created with JACS Go bindings",
		"timestamp": "2025-01-01T00:00:00Z",
		"author":    "JACS Example",
		"tags":      []string{"example", "test", "go"},
		"metadata": map[string]interface{}{
			"version": "1.0",
			"public":  true,
		},
	}

	documentJSON, err := json.Marshal(documentData)
	if err != nil {
		log.Fatalf("Failed to marshal document: %v", err)
	}

	// Note: This might fail without a properly loaded agent
	noSave := true
	createdDoc, err := jacs.CreateDocument(string(documentJSON), nil, nil, noSave, nil, nil)
	if err != nil {
		fmt.Printf("Warning: Failed to create document (expected without loaded agent): %v\n\n", err)
	} else {
		fmt.Printf("Created document:\n%s\n\n", createdDoc)
	}

	// Example 6: Working with binary data
	fmt.Println("=== Binary Data Conversion ===")
	binaryData := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f} // "Hello" in bytes

	// Encode binary data for cross-language compatibility
	encoded := jacs.EncodeBinaryData(binaryData)
	fmt.Printf("Original bytes: %v\n", binaryData)
	fmt.Printf("Encoded: %+v\n", encoded)

	// Decode it back
	decoded, err := jacs.DecodeBinaryData(encoded)
	if err != nil {
		log.Fatalf("Failed to decode binary data: %v", err)
	}
	fmt.Printf("Decoded bytes: %v\n", decoded)
	fmt.Printf("Decoded string: %s\n\n", string(decoded))

	// Example 7: Convert complex data structures
	fmt.Println("=== Complex Data Conversion ===")
	complexData := map[string]interface{}{
		"text":   "Regular string",
		"number": 42,
		"binary": []byte("Binary data here"),
		"nested": map[string]interface{}{
			"array": []interface{}{1, 2, 3},
			"bool":  true,
		},
	}

	// Convert to JSON with special type handling
	jsonStr, err := jacs.ToJSON(complexData)
	if err != nil {
		log.Fatalf("Failed to convert to JSON: %v", err)
	}
	fmt.Printf("JSON with special types:\n%s\n", jsonStr)

	// Parse back from JSON
	restored, err := jacs.FromJSON(jsonStr)
	if err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}
	fmt.Printf("Restored data: %+v\n", restored)

	fmt.Println("\n=== Example completed successfully ===")
}
