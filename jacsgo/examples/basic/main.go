package main

import (
	"encoding/json"
	"fmt"
	"log"

	jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func main() {
	// ===========================================
	// JACS Simplified API Example
	// ===========================================

	fmt.Println("=== JACS Go Quickstart ===")
	fmt.Println()

	// Load an existing agent
	// Run `jacs create --name "my-agent"` first if you don't have one
	configPath := "./jacs.config.json"
	if err := jacs.Load(&configPath); err != nil {
		log.Printf("No agent found. Creating one...")

		// Create a new agent
		info, err := jacs.Create("example-agent", "Demo agent for Go", "ed25519")
		if err != nil {
			log.Fatalf("Failed to create agent: %v", err)
		}
		fmt.Printf("Created agent: %s\n", info.Name)
	} else {
		fmt.Println("Agent loaded successfully")
	}

	// Verify the agent's integrity
	result, err := jacs.VerifySelf()
	if err != nil {
		log.Fatalf("Self verification error: %v", err)
	}
	if result.Valid {
		fmt.Println("Agent integrity: VERIFIED")
	} else {
		fmt.Printf("Agent integrity: FAILED - %v\n", result.Errors)
	}
	fmt.Println()

	// ===========================================
	// Sign a message
	// ===========================================
	fmt.Println("=== Signing a Message ===")

	messageData := map[string]interface{}{
		"action":   "approve",
		"amount":   100.50,
		"currency": "USD",
		"metadata": map[string]interface{}{
			"approver": "finance-bot",
			"category": "expenses",
		},
	}

	signed, err := jacs.SignMessage(messageData)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	fmt.Printf("Document ID: %s\n", signed.DocumentID)
	fmt.Printf("Signed by: %s\n", signed.AgentID)
	fmt.Printf("Timestamp: %s\n", signed.Timestamp)
	fmt.Println()

	// ===========================================
	// Verify the signed message
	// ===========================================
	fmt.Println("=== Verifying Signature ===")

	verifyResult, err := jacs.Verify(signed.Raw)
	if err != nil {
		log.Fatalf("Verification error: %v", err)
	}

	fmt.Printf("Valid: %t\n", verifyResult.Valid)
	fmt.Printf("Signer: %s\n", verifyResult.SignerID)
	fmt.Printf("Timestamp: %s\n", verifyResult.Timestamp)

	// Access the original data
	if verifyResult.Data != nil {
		dataJSON, _ := json.MarshalIndent(verifyResult.Data, "", "  ")
		fmt.Printf("Data:\n%s\n", dataJSON)
	}
	fmt.Println()

	// ===========================================
	// Get public key for sharing
	// ===========================================
	fmt.Println("=== Public Key (for sharing) ===")

	pem, err := jacs.GetPublicKeyPEM()
	if err != nil {
		fmt.Printf("Could not get public key: %v\n", err)
	} else {
		// Just show first 80 chars
		if len(pem) > 80 {
			fmt.Printf("%s...\n", pem[:80])
		} else {
			fmt.Println(pem)
		}
	}

	fmt.Println()
	fmt.Println("=== Example Complete ===")
}
