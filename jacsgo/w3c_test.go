package jacs

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	w3cOrigin        = "https://agent.example.com"
	w3cRequestURL    = "https://api.example.com/tasks?priority=high"
	w3cRequestBody   = "{\"task\":\"review proposal\",\"ok\":true}"
	w3cCreated       = "2026-01-01T00:00:00Z"
	w3cMaxAgeSeconds = uint64(4_000_000_000)
)

func TestW3cDidDiscoveryAndRequestProofRoundTrip(t *testing.T) {
	agent, _, err := EphemeralSimpleAgent(strPtr("ed25519"))
	if err != nil {
		t.Fatalf("EphemeralSimpleAgent: %v", err)
	}
	defer agent.Close()

	did, err := agent.ExportW3cDid(strPtr(w3cOrigin))
	if err != nil {
		t.Fatalf("ExportW3cDid: %v", err)
	}
	if !strings.HasPrefix(did, "did:wba:agent.example.com:agent:") {
		t.Fatalf("unexpected DID: %s", did)
	}

	didDocument, err := agent.ExportW3cDidDocument(strPtr(w3cOrigin))
	if err != nil {
		t.Fatalf("ExportW3cDidDocument: %v", err)
	}
	if didDocument["id"] != did {
		t.Fatalf("DID document id mismatch: %#v", didDocument["id"])
	}
	jacsMeta := didDocument["jacs"].(map[string]interface{})
	if jacsMeta["jacsId"] == "" {
		t.Fatal("DID document must preserve canonical jacsId")
	}

	agentDescription, err := agent.ExportW3cAgentDescription(strPtr(w3cOrigin))
	if err != nil {
		t.Fatalf("ExportW3cAgentDescription: %v", err)
	}
	if agentDescription["did"] != did {
		t.Fatalf("agent description did mismatch: %#v", agentDescription["did"])
	}

	wellKnown, err := agent.GenerateW3cWellKnown(strPtr(w3cOrigin))
	if err != nil {
		t.Fatalf("GenerateW3cWellKnown: %v", err)
	}
	if _, ok := wellKnown["/.well-known/agent-descriptions"]; !ok {
		t.Fatalf("missing well-known collection: %#v", wellKnown)
	}

	proof, err := agent.SignW3cRequest(W3cRequestProofParams{
		Method:  "POST",
		URL:     w3cRequestURL,
		Body:    strPtr(w3cRequestBody),
		Nonce:   strPtr("go-w3c-smoke-nonce"),
		Created: strPtr(w3cCreated),
		Origin:  strPtr(w3cOrigin),
	})
	if err != nil {
		t.Fatalf("SignW3cRequest: %v", err)
	}
	if proof["did"] != did {
		t.Fatalf("proof did mismatch: %#v", proof["did"])
	}
	if !strings.HasPrefix(proof["contentDigest"].(string), "sha-256=:") {
		t.Fatalf("missing contentDigest: %#v", proof["contentDigest"])
	}

	proofJSON, _ := json.Marshal(proof)
	didDocumentJSON, _ := json.Marshal(didDocument)

	_, err = agent.VerifyW3cRequest(
		string(proofJSON),
		string(didDocumentJSON),
		strPtr(w3cRequestBody),
		w3cMaxAgeSeconds,
		strPtr("POST"),
		strPtr("https://api.example.com/other"),
	)
	if err == nil {
		t.Fatal("VerifyW3cRequest should reject mismatched actual URL")
	}

	verification, err := agent.VerifyW3cRequest(
		string(proofJSON),
		string(didDocumentJSON),
		strPtr(w3cRequestBody),
		w3cMaxAgeSeconds,
		strPtr("POST"),
		strPtr(w3cRequestURL),
	)
	if err != nil {
		t.Fatalf("VerifyW3cRequest: %v", err)
	}
	if verification["valid"] != true {
		t.Fatalf("verification invalid: %#v", verification)
	}
	if verification["expectedRequestChecked"] != true {
		t.Fatalf("expected request binding check: %#v", verification)
	}
}
