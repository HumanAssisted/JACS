package jacs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type agreementV2ScenarioFixture struct {
	BaseInput      map[string]interface{}            `json:"base_input"`
	TranscriptRefs map[string]map[string]interface{} `json:"transcript_refs"`
	TermsConflict  map[string]string                 `json:"terms_conflict"`
}

func loadAgreementV2Fixture(t *testing.T) agreementV2ScenarioFixture {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixturePath := filepath.Join(filepath.Dir(thisFile), "../binding-core/tests/fixtures/agreement_v2_scenarios.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read agreement v2 fixture failed: %v", err)
	}
	var fixture agreementV2ScenarioFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse agreement v2 fixture failed: %v", err)
	}
	return fixture
}

func agreementV2AgentID(t *testing.T, agent *JacsSimpleAgent) string {
	t.Helper()
	agentID, err := agent.GetAgentID()
	if err != nil {
		t.Fatalf("GetAgentID failed: %v", err)
	}
	return agentID
}

func agreementV2JSON(t *testing.T, value interface{}) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON failed: %v", err)
	}
	return string(data)
}

func agreementV2Doc(t *testing.T, raw string) map[string]interface{} {
	t.Helper()
	var document map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		t.Fatalf("parse agreement JSON failed: %v\n%s", err, raw)
	}
	return document
}

func agreementV2BaseInput(t *testing.T, agentID string) map[string]interface{} {
	t.Helper()
	fixture := loadAgreementV2Fixture(t)
	data, err := json.Marshal(fixture.BaseInput)
	if err != nil {
		t.Fatalf("marshal base fixture failed: %v", err)
	}
	var input map[string]interface{}
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatalf("copy base fixture failed: %v", err)
	}
	input["parties"] = []map[string]interface{}{
		{"agentId": agentID, "agentType": "ai", "role": "signer"},
	}
	input["controllers"] = []string{agentID}
	return input
}

func agreementV2Create(t *testing.T, agent *JacsSimpleAgent, agentID string) string {
	t.Helper()
	created, err := agent.CreateAgreementV2(agreementV2JSON(t, agreementV2BaseInput(t, agentID)))
	if err != nil {
		t.Fatalf("CreateAgreementV2 failed: %v", err)
	}
	return created
}

func agreementV2Apply(t *testing.T, agent *JacsSimpleAgent, document string, mutation map[string]interface{}) string {
	t.Helper()
	updated, err := agent.ApplyAgreementV2(document, agreementV2JSON(t, mutation))
	if err != nil {
		t.Fatalf("ApplyAgreementV2 failed: %v", err)
	}
	return updated
}

func agreementV2TranscriptRef(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	ref := loadAgreementV2Fixture(t).TranscriptRefs[name]
	if ref == nil {
		t.Fatalf("missing transcript ref %q", name)
	}
	return ref
}

func TestAgreementV2CreateSignVerifyParity(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")
	agentID := agreementV2AgentID(t, agent)

	created := agreementV2Create(t, agent, agentID)
	signed, err := agent.SignAgreementV2(created, "signer")
	if err != nil {
		t.Fatalf("SignAgreementV2 failed: %v", err)
	}
	report, err := agent.VerifyAgreementV2(signed)
	if err != nil {
		t.Fatalf("VerifyAgreementV2 failed: %v", err)
	}

	if !report.Valid {
		t.Fatalf("expected valid report: %#v", report)
	}
	if report.ExpectedStatus != "final" {
		t.Fatalf("expected final status, got %q", report.ExpectedStatus)
	}
	if report.SignerCount != 1 {
		t.Fatalf("expected one signer, got %d", report.SignerCount)
	}
}

func TestAgreementV2NotaryRoleParity(t *testing.T) {
	skipIfLibraryMissing(t)
	signer := ephemeral(t, "ed25519")
	notary := ephemeral(t, "ed25519")
	signerID := agreementV2AgentID(t, signer)
	notaryID := agreementV2AgentID(t, notary)
	input := agreementV2BaseInput(t, signerID)
	input["parties"] = []map[string]interface{}{
		{"agentId": signerID, "agentType": "ai", "role": "signer"},
		{"agentId": notaryID, "agentType": "ai", "role": "notary"},
	}
	input["signaturePolicy"].(map[string]interface{})["notaryRequired"] = 1

	created, err := signer.CreateAgreementV2(agreementV2JSON(t, input))
	if err != nil {
		t.Fatalf("CreateAgreementV2 failed: %v", err)
	}
	notarized, err := notary.SignAgreementV2(created, "notary")
	if err != nil {
		t.Fatalf("SignAgreementV2 notary failed: %v", err)
	}
	document := agreementV2Doc(t, notarized)
	signatures := document["agreementSignatures"].([]interface{})
	entry := signatures[0].(map[string]interface{})
	if entry["role"] != "notary" {
		t.Fatalf("expected notary role, got %#v", entry["role"])
	}
}

func TestAgreementV2TranscriptBranchMergeParity(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")
	agentID := agreementV2AgentID(t, agent)
	base := agreementV2Create(t, agent, agentID)

	left := agreementV2Apply(t, agent, base, map[string]interface{}{
		"type":  "appendTranscript",
		"entry": agreementV2TranscriptRef(t, "left"),
	})
	right := agreementV2Apply(t, agent, base, map[string]interface{}{
		"type":  "appendTranscript",
		"entry": agreementV2TranscriptRef(t, "right"),
	})
	analysis, err := agent.DetectAgreementV2BranchConflict(base, left, right)
	if err != nil {
		t.Fatalf("DetectAgreementV2BranchConflict failed: %v", err)
	}
	if !analysis.SameDocument || !analysis.SameParent || !analysis.AutoMergeable {
		t.Fatalf("expected transcript-only auto-mergeable analysis: %#v", analysis)
	}
	merged, err := agent.MergeAgreementV2TranscriptBranches(base, left, right)
	if err != nil {
		t.Fatalf("MergeAgreementV2TranscriptBranches failed: %v", err)
	}
	mergedDoc := agreementV2Doc(t, merged)
	if len(mergedDoc["transcript"].([]interface{})) != 2 {
		t.Fatalf("expected two transcript entries: %s", merged)
	}
}

func TestAgreementV2TermsConflictResolutionParity(t *testing.T) {
	skipIfLibraryMissing(t)
	agent := ephemeral(t, "ed25519")
	agentID := agreementV2AgentID(t, agent)
	fixture := loadAgreementV2Fixture(t)
	base := agreementV2Create(t, agent, agentID)
	left := agreementV2Apply(t, agent, base, map[string]interface{}{
		"type":  "updateTerms",
		"terms": fixture.TermsConflict["left"],
	})
	right := agreementV2Apply(t, agent, base, map[string]interface{}{
		"type":  "updateTerms",
		"terms": fixture.TermsConflict["right"],
	})

	analysis, err := agent.DetectAgreementV2BranchConflict(base, left, right)
	if err != nil {
		t.Fatalf("DetectAgreementV2BranchConflict failed: %v", err)
	}
	if analysis.AutoMergeable {
		t.Fatalf("terms conflicts must not auto-merge: %#v", analysis)
	}
	if len(analysis.ConflictFields) != 1 || analysis.ConflictFields[0] != "terms" {
		t.Fatalf("expected terms conflict, got %#v", analysis.ConflictFields)
	}
	resolved, err := agent.ResolveAgreementV2BranchConflict(
		base,
		left,
		right,
		agreementV2JSON(t, map[string]interface{}{
			"type":  "updateTerms",
			"terms": fixture.TermsConflict["resolved"],
		}),
	)
	if err != nil {
		t.Fatalf("ResolveAgreementV2BranchConflict failed: %v", err)
	}
	resolvedDoc := agreementV2Doc(t, resolved)
	rightDoc := agreementV2Doc(t, right)
	link := resolvedDoc["links"].([]interface{})[0].(map[string]interface{})
	if resolvedDoc["terms"] != fixture.TermsConflict["resolved"] {
		t.Fatalf("unexpected resolved terms: %#v", resolvedDoc["terms"])
	}
	if link["jacsId"] != rightDoc["jacsId"] || link["jacsVersion"] != rightDoc["jacsVersion"] {
		t.Fatalf("expected slim link to side branch, got %#v", link)
	}
}
