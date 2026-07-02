package jacs

// Tests for the ES256 compatibility key + ecosystem exports (P2 Tasks
// 002-004c) on JacsSimpleAgent.
//
// New persistent agents mint the ES256 `ecosystem_signing` compatibility
// key eagerly at creation (native root stays pq2025). Identity exports
// (JWKS, key binding) auto-issue the default identity binding; content
// exports (AP2 mandate) require the explicit `ap2-mandate` binding scope
// and must be denied on a fresh agent.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// sampleAp2Checkout is a minimal UCP checkout that passes the ap2-mandate
// input schema, so a failure exercises the binding-scope gate, not parsing.
const sampleAp2Checkout = `{"id":"c1","currency":"USD","line_items":[{"id":"li1"}],"totals":[{"type":"total","amount":100}]}`

// newCompatTestAgent creates a persistent SimpleAgent in a temp directory
// with the default (pq2025) native algorithm, so the eager ES256 compat key
// is minted and binding signatures chain to the post-quantum root.
func newCompatTestAgent(t *testing.T) *JacsSimpleAgent {
	t.Helper()
	skipIfLibraryMissing(t)

	tmpDir := canonicalTempDir(t)
	t.Setenv("JACS_PRIVATE_KEY_PASSWORD", testPrivateKeyPassword)

	params := map[string]interface{}{
		"name":     "compat-test-agent",
		"password": testPrivateKeyPassword,
		// No "algorithm": use the Rust default (pq2025) — the compat
		// binding assertions below check the PQ-root chain.
		"data_directory": filepath.Join(tmpDir, "data"),
		"key_directory":  filepath.Join(tmpDir, "keys"),
		"config_path":    filepath.Join(tmpDir, "config.json"),
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal params: %v", err)
	}

	agent, info, err := CreateSimpleAgentWithParams(string(paramsJSON))
	if err != nil {
		t.Fatalf("CreateSimpleAgentWithParams failed: %v", err)
	}
	t.Cleanup(func() { agent.Close() })

	if info == nil || info.AgentID == "" {
		t.Fatal("agent_id from CreateSimpleAgentWithParams should be non-empty")
	}
	return agent
}

// TestCompatExportJwksReturnsP256Jwk verifies the identity JWKS export
// auto-issues the default binding on a fresh agent and publishes exactly
// the ES256 public key as an EC/P-256 JWK (never PQ material).
func TestCompatExportJwksReturnsP256Jwk(t *testing.T) {
	agent := newCompatTestAgent(t)

	jwksJSON, err := agent.ExportCompatibilityJwks()
	if err != nil {
		t.Fatalf("ExportCompatibilityJwks failed: %v", err)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwksJSON), &jwks); err != nil {
		t.Fatalf("JWKS export is not valid JSON: %v\n%s", err, jwksJSON)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("JWKS should hold exactly the ES256 key, got %d keys", len(jwks.Keys))
	}

	key := jwks.Keys[0]
	if kty := key["kty"]; kty != "EC" {
		t.Errorf("kty should be EC, got %#v", kty)
	}
	if crv := key["crv"]; crv != "P-256" {
		t.Errorf("crv should be P-256, got %#v", crv)
	}
	if alg := key["alg"]; alg != "ES256" {
		t.Errorf("alg should be ES256, got %#v", alg)
	}
	kid, _ := key["kid"].(string)
	if kid == "" {
		t.Error("kid should be a non-empty string")
	}
	x, _ := key["x"].(string)
	y, _ := key["y"].(string)
	if x == "" || y == "" {
		t.Error("x and y coordinates should be non-empty strings")
	}
}

// TestCompatExportKeyBindingIsPqRootSigned verifies the exported binding
// document is signed by the native pq2025 root and binds the ES256 key.
func TestCompatExportKeyBindingIsPqRootSigned(t *testing.T) {
	agent := newCompatTestAgent(t)

	bindingJSON, err := agent.ExportCompatibilityKeyBinding()
	if err != nil {
		t.Fatalf("ExportCompatibilityKeyBinding failed: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(bindingJSON), &doc); err != nil {
		t.Fatalf("binding export is not valid JSON: %v\n%s", err, bindingJSON)
	}

	sig, ok := doc["jacsSignature"].(map[string]interface{})
	if !ok {
		t.Fatalf("binding should carry a jacsSignature object, got %#v", doc["jacsSignature"])
	}
	if algo := sig["signingAlgorithm"]; algo != "pq2025" {
		t.Errorf("binding signingAlgorithm should be pq2025, got %#v", algo)
	}

	binding, ok := doc["compatibilityKeyBinding"].(map[string]interface{})
	if !ok {
		t.Fatalf("compatibilityKeyBinding should be an object, got %#v", doc["compatibilityKeyBinding"])
	}
	rootKey, ok := binding["rootKey"].(map[string]interface{})
	if !ok {
		t.Fatalf("rootKey should be an object, got %#v", binding["rootKey"])
	}
	if algo := rootKey["algorithm"]; algo != "pq2025" {
		t.Errorf("rootKey.algorithm should be pq2025, got %#v", algo)
	}
	compatKey, ok := binding["compatibilityKey"].(map[string]interface{})
	if !ok {
		t.Fatalf("compatibilityKey should be an object, got %#v", binding["compatibilityKey"])
	}
	if algo := compatKey["algorithm"]; algo != "ES256" {
		t.Errorf("compatibilityKey.algorithm should be ES256, got %#v", algo)
	}
}

// TestCompatAp2MandateRequiresBindingScope verifies the content-export gate:
// AP2 mandates are denied without the explicit `ap2-mandate` binding scope,
// both before any binding exists and after the identity binding auto-issues.
func TestCompatAp2MandateRequiresBindingScope(t *testing.T) {
	agent := newCompatTestAgent(t)

	// Fresh agent: no binding issued yet.
	if _, err := agent.ExportAp2Mandate(sampleAp2Checkout); err == nil {
		t.Fatal("ExportAp2Mandate should fail without the ap2-mandate binding scope")
	} else if !strings.Contains(err.Error(), "binding") {
		t.Errorf("denial should mention the compatibility binding, got: %v", err)
	}

	// Identity export auto-issues the DEFAULT identity binding...
	if _, err := agent.ExportCompatibilityJwks(); err != nil {
		t.Fatalf("ExportCompatibilityJwks failed: %v", err)
	}
	// ...which still must not grant the ap2-mandate content scope.
	if _, err := agent.ExportAp2Mandate(sampleAp2Checkout); err == nil {
		t.Fatal("ExportAp2Mandate should fail: identity binding must not grant ap2-mandate")
	} else if !strings.Contains(err.Error(), "binding") {
		t.Errorf("denial should mention the compatibility binding, got: %v", err)
	}
}

// TestCompatIssueBindingGrantsAp2MandateScope is the bindings-level happy
// path for a content export (deep-review Issue 003): grant the `ap2-mandate`
// scope explicitly via IssueCompatBinding (PQ root signs the binding), then
// ExportAp2Mandate SUCCEEDS — no CLI shell-out required.
func TestCompatIssueBindingGrantsAp2MandateScope(t *testing.T) {
	agent := newCompatTestAgent(t)

	// An unknown scope must be rejected, never silently granted.
	if _, err := agent.IssueCompatBinding(`["jwks","not-a-scope"]`, ""); err == nil {
		t.Fatal("IssueCompatBinding should reject an unknown scope")
	}

	// Explicit grant including the ap2-mandate content scope.
	bindingJSON, err := agent.IssueCompatBinding(`["jwks","did","a2a-agent-card","w3c-agent-identity","ap2-mandate"]`, "")
	if err != nil {
		t.Fatalf("IssueCompatBinding failed: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(bindingJSON), &doc); err != nil {
		t.Fatalf("binding is not valid JSON: %v\n%s", err, bindingJSON)
	}
	binding, ok := doc["compatibilityKeyBinding"].(map[string]interface{})
	if !ok {
		t.Fatalf("compatibilityKeyBinding should be an object, got %#v", doc["compatibilityKeyBinding"])
	}
	scopeList, ok := binding["scope"].([]interface{})
	if !ok {
		t.Fatalf("binding scope should be an array, got %#v", binding["scope"])
	}
	granted := false
	for _, s := range scopeList {
		if s == "ap2-mandate" {
			granted = true
		}
	}
	if !granted {
		t.Fatalf("granted binding must include ap2-mandate, got %v", scopeList)
	}
	sig, ok := doc["jacsSignature"].(map[string]interface{})
	if !ok {
		t.Fatalf("binding should carry a jacsSignature object, got %#v", doc["jacsSignature"])
	}
	if algo := sig["signingAlgorithm"]; algo != "pq2025" {
		t.Errorf("binding signingAlgorithm should be pq2025, got %#v", algo)
	}

	// The content export now succeeds through the binding.
	mandateJSON, err := agent.ExportAp2Mandate(sampleAp2Checkout)
	if err != nil {
		t.Fatalf("ExportAp2Mandate should succeed after granting ap2-mandate: %v", err)
	}
	var mandate map[string]interface{}
	if err := json.Unmarshal([]byte(mandateJSON), &mandate); err != nil {
		t.Fatalf("mandate is not valid JSON: %v\n%s", err, mandateJSON)
	}
	if format := mandate["format"]; format != "ap2-mandate" {
		t.Errorf("mandate format should be ap2-mandate, got %#v", format)
	}
	detached, _ := mandate["detachedJws"].(string)
	if detached == "" {
		t.Fatal("mandate should carry a non-empty detachedJws")
	}
	parts := strings.Split(detached, ".")
	if len(parts) != 3 {
		t.Fatalf("detached JWS should be compact 3-part serialization, got %d parts", len(parts))
	}
	if parts[1] != "" {
		t.Error("payload segment must be detached (empty)")
	}
}

// TestCompatAddCompatKeyDuplicateFails verifies no silent re-mint: new
// agents get the compat key eagerly, so an explicit AddCompatKey errors.
func TestCompatAddCompatKeyDuplicateFails(t *testing.T) {
	agent := newCompatTestAgent(t)

	if _, err := agent.AddCompatKey(); err == nil {
		t.Fatal("AddCompatKey should fail when the compat key already exists")
	} else if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("duplicate denial should mention the existing key, got: %v", err)
	}
}
