package jacs

// MCP contract drift test for the Go binding.
//
// This test loads the canonical Rust MCP contract from
// jacs-mcp/contract/jacs-mcp-contract.json and validates that Go's
// understanding of the available MCP tools matches the contract.
//
// Go does not have a native MCP adapter with tool definitions; it
// consumes the Rust MCP server via the CLI binary. This test ensures
// that if Rust adds, removes, or renames an MCP tool, the Go
// ecosystem is aware of the change.
//
// Pattern matches: jacspy/tests/test_mcp_contract_drift.py and
// jacsnpm/test/mcp-contract.test.js.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

const mcpContractRelPath = "../jacs-mcp/contract/jacs-mcp-contract.json"

// mcpContract represents the top-level structure of the MCP contract JSON.
type mcpContract struct {
	SchemaVersion int       `json:"schema_version"`
	Server        mcpServer `json:"server"`
	Tools         []mcpTool `json:"tools"`
}

type mcpServer struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Version string `json:"version"`
}

type mcpTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"input_schema"`
}

func loadMcpContract(t *testing.T) mcpContract {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	contractPath := filepath.Join(filepath.Dir(thisFile), mcpContractRelPath)

	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("failed to read MCP contract at %s: %v", contractPath, err)
	}

	var c mcpContract
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("failed to parse MCP contract: %v", err)
	}
	return c
}

// expectedMcpTools returns the canonical list of expected MCP tool names.
// This is the single source of truth -- both TestMcpContractDrift and
// TestMcpContractToolCount use it, so there is only one place to update
// when tools are added or removed.
//
// MAINTENANCE NOTE (Issue 015): Unlike Python and Node drift tests which
// dynamically discover tools from their native MCP adapters, Go has no
// native MCP adapter. This hardcoded list IS the test. When a tool is
// added to or removed from jacs-mcp/contract/jacs-mcp-contract.json,
// this list must be manually updated. The contract_snapshot.rs test in
// Rust will fail first, signaling that this list also needs updating.
func expectedMcpTools() []string {
	tools := []string{
		"jacs_assess_a2a_agent",
		"jacs_attest_create",
		"jacs_attest_export_dsse",
		"jacs_attest_lift",
		"jacs_attest_verify",
		"jacs_apply_agreement_v2",
		"jacs_check_agreement",
		"jacs_create_agent",
		"jacs_create_agreement",
		"jacs_create_agreement_v2",
		"jacs_detect_agreement_v2_branch_conflict",
		"jacs_export_agent",
		"jacs_export_agent_card",
		"jacs_extract_media_signature",
		"jacs_generate_well_known",
		"jacs_get_trusted_agent",
		"jacs_is_trusted",
		"jacs_list_trusted_agents",
		"jacs_merge_agreement_v2_transcript_branches",
		"jacs_reencrypt_key",
		"jacs_resolve_agreement_v2_branch_conflict",
		"jacs_rotate_keys",
		"jacs_search",
		"jacs_sign_agreement",
		"jacs_sign_agreement_v2",
		"jacs_sign_document",
		"jacs_sign_image",
		"jacs_sign_text",
		"jacs_trust_agent",
		"jacs_untrust_agent",
		"jacs_verify_a2a_artifact",
		"jacs_verify_agreement_v2",
		"jacs_verify_document",
		"jacs_verify_image",
		"jacs_verify_text",
		"jacs_w3c_export_agent_description",
		"jacs_w3c_export_did",
		"jacs_w3c_export_did_document",
		"jacs_w3c_generate_well_known",
		"jacs_w3c_sign_request",
		"jacs_w3c_verify_request",
		"jacs_wrap_a2a_artifact",
	}
	sort.Strings(tools)
	return tools
}

// TestMcpContractDrift validates that the canonical MCP contract tool names
// match the expected set known to Go. If a tool is added or removed from the
// Rust contract, this test fails until expectedMcpTools() is updated.
func TestMcpContractDrift(t *testing.T) {
	contract := loadMcpContract(t)

	// Extract tool names from contract
	var contractTools []string
	for _, tool := range contract.Tools {
		contractTools = append(contractTools, tool.Name)
	}
	sort.Strings(contractTools)

	expectedTools := expectedMcpTools()

	if len(contractTools) != len(expectedTools) {
		t.Errorf("MCP contract has %d tools, expected %d.\nContract tools: %v\nExpected tools: %v",
			len(contractTools), len(expectedTools), contractTools, expectedTools)
	}

	// Find differences
	inContractOnly := diff(contractTools, expectedTools)
	inExpectedOnly := diff(expectedTools, contractTools)

	if len(inContractOnly) > 0 {
		t.Errorf("Tools in MCP contract but not in Go expected set (need to add): %v", inContractOnly)
	}
	if len(inExpectedOnly) > 0 {
		t.Errorf("Tools in Go expected set but not in MCP contract (need to remove): %v", inExpectedOnly)
	}
}

// TestMcpContractStructure validates the contract JSON structure is well-formed.
func TestMcpContractStructure(t *testing.T) {
	contract := loadMcpContract(t)

	if contract.SchemaVersion != 1 {
		t.Errorf("expected schema_version 1, got %d", contract.SchemaVersion)
	}
	if contract.Server.Name != "jacs-mcp" {
		t.Errorf("expected server.name 'jacs-mcp', got %q", contract.Server.Name)
	}
	if contract.Server.Version == "" {
		t.Error("server.version should not be empty")
	}
	if len(contract.Tools) == 0 {
		t.Error("contract should have at least one tool")
	}

	// Every tool should have a name and description
	for i, tool := range contract.Tools {
		if tool.Name == "" {
			t.Errorf("tool[%d] has empty name", i)
		}
		if tool.Description == "" {
			t.Errorf("tool[%d] (%s) has empty description", i, tool.Name)
		}
	}
}

// TestMcpContractToolCount validates the total number of tools.
// The expected count is derived from the expectedTools list in
// TestMcpContractDrift, so there is only one place to update.
func TestMcpContractToolCount(t *testing.T) {
	contract := loadMcpContract(t)

	// Use the same expected tool list as TestMcpContractDrift
	expectedCount := len(expectedMcpTools())
	if len(contract.Tools) != expectedCount {
		t.Errorf("expected %d MCP tools, got %d. If tools were added/removed, update expectedMcpTools() and TestMcpContractDrift.",
			expectedCount, len(contract.Tools))
	}
}

// diff returns elements in a that are not in b.
func diff(a, b []string) []string {
	bSet := make(map[string]bool, len(b))
	for _, s := range b {
		bSet[s] = true
	}
	var result []string
	for _, s := range a {
		if !bSet[s] {
			result = append(result, s)
		}
	}
	return result
}
