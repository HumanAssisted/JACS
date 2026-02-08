//go:build server

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

// Response represents a server response
type Response struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// JACSMiddleware wraps HTTP handlers with JACS authentication
func JACSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			sendError(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		r.Body.Close()

		// Try to verify JACS signature if present
		if len(body) > 0 {
			// Try to verify as JACS document
			payload, err := jacs.VerifyResponse(string(body))
			if err == nil {
				// Successfully verified JACS document
				log.Printf("Verified JACS request from agent")

				// Convert payload to JSON for the handler
				payloadJSON, err := json.Marshal(payload)
				if err != nil {
					sendError(w, "Failed to process verified payload", http.StatusInternalServerError)
					return
				}

				// Replace body with verified payload
				r.Body = io.NopCloser(bytes.NewReader(payloadJSON))
			} else {
				// Not a JACS document or verification failed, pass through original
				log.Printf("Request is not JACS signed or verification failed: %v", err)
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		// Call the next handler
		next(w, r)
	}
}

// sendError sends an error response
func sendError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Status:  "error",
		Message: message,
	})
}

// sendResponse sends a success response, optionally JACS-signed
func sendResponse(w http.ResponseWriter, data interface{}) {
	response := Response{
		Status:  "success",
		Message: "Request processed successfully",
		Data:    data,
	}

	// Try to sign the response with JACS
	signed, err := jacs.SignRequest(response)
	if err == nil {
		// Send JACS-signed response
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-JACS-Signed", "true")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, signed)
	} else {
		// Send unsigned response
		log.Printf("Failed to sign response: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// echoHandler echoes back the request data
func echoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data interface{}
	body, _ := io.ReadAll(r.Body)

	if len(body) > 0 {
		if err := json.Unmarshal(body, &data); err != nil {
			sendError(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
	}

	sendResponse(w, data)
}

// documentHandler creates a JACS document
func documentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendError(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Create a JACS document
	noSave := true
	doc, err := jacs.CreateDocument(string(body), nil, nil, noSave, nil, nil)
	if err != nil {
		sendError(w, fmt.Sprintf("Failed to create document: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, doc)
}

// hashHandler hashes the provided data. Accepts JSON {"data": "string to hash"} or raw body.
func hashHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendError(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	toHash := string(body)
	if len(body) > 0 && (body[0] == '{' || body[0] == '[') {
		var req struct {
			Data string `json:"data"`
		}
		if err := json.Unmarshal(body, &req); err == nil && req.Data != "" {
			toHash = req.Data
		}
	}

	hash, err := jacs.HashString(toHash)
	if err != nil {
		sendError(w, fmt.Sprintf("Failed to hash data: %v", err), http.StatusInternalServerError)
		return
	}

	sendResponse(w, map[string]string{
		"hash":      hash,
		"algorithm": "JACS",
	})
}

func main() {
	// Try to load JACS configuration
	configPath := os.Getenv("JACS_CONFIG")
	if configPath == "" {
		configPath = "jacs.server.config.json"
	}

	fmt.Printf("Loading JACS configuration from: %s\n", configPath)
	err := jacs.Load(&configPath)
	if err != nil {
		log.Printf("Warning: Failed to load JACS config: %v", err)
		log.Printf("Server will run without JACS signing capabilities")
	} else {
		log.Printf("JACS configuration loaded successfully")
	}

	// Set up routes
	http.HandleFunc("/echo", JACSMiddleware(echoHandler))
	http.HandleFunc("/document", JACSMiddleware(documentHandler))
	http.HandleFunc("/hash", JACSMiddleware(hashHandler))

	// Health check endpoint (no JACS middleware)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "JACS HTTP Server",
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Starting JACS HTTP server on port %s\n", port)
	fmt.Println("Endpoints:")
	fmt.Println("  POST /echo     - Echo back request (with optional JACS verification/signing)")
	fmt.Println("  POST /document - Create a JACS document")
	fmt.Println("  POST /hash     - Hash data using JACS")
	fmt.Println("  GET  /health   - Health check")

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
