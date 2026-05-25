package jacs

import (
	"encoding/json"
	"testing"
)

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

func agreementV2BaseInput(agentID string) map[string]interface{} {
	return map[string]interface{}{
		"title":       "Agreement v2 parity",
		"description": "Portable agreement v2 workflow test.",
		"terms":       "The binding must delegate agreement v2 behavior to Rust core.",
		"termsFormat": "text/plain",
		"status":      "proposed",
		"parties": []map[string]interface{}{
			{"agentId": agentID, "agentType": "ai", "role": "signer"},
		},
		"signaturePolicy": map[string]interface{}{
			"partyQuorum":        "all",
			"witnessRequired":    0,
			"notaryRequired":     0,
			"requiredAlgorithms": []string{"ring-Ed25519"},
			"minimumStrength":    "classical",
		},
		"controllers": []string{agentID},
	}
}

func agreementV2Create(t *testing.T, agent *JacsSimpleAgent, agentID string) string {
	t.Helper()
	created, err := agent.CreateAgreementV2(agreementV2JSON(t, agreementV2BaseInput(agentID)))
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

func agreementV2DocumentRef(t *testing.T, agent *JacsSimpleAgent, message string) map[string]interface{} {
	t.Helper()
	signed, err := agent.SignMessage(map[string]string{"message": message})
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}
	raw := agreementV2Doc(t, signed.Raw)
	return map[string]interface{}{
		"jacsId":      raw["jacsId"],
		"jacsVersion": raw["jacsVersion"],
		"jacsSha256":  raw["jacsSha256"],
	}
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
	input := agreementV2BaseInput(signerID)
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
		"entry": agreementV2DocumentRef(t, agent, "left transcript"),
	})
	right := agreementV2Apply(t, agent, base, map[string]interface{}{
		"type":  "appendTranscript",
		"entry": agreementV2DocumentRef(t, agent, "right transcript"),
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
	base := agreementV2Create(t, agent, agentID)
	left := agreementV2Apply(t, agent, base, map[string]interface{}{
		"type":  "updateTerms",
		"terms": "Left branch terms.",
	})
	right := agreementV2Apply(t, agent, base, map[string]interface{}{
		"type":  "updateTerms",
		"terms": "Right branch terms.",
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
			"terms": "Resolved terms.",
		}),
	)
	if err != nil {
		t.Fatalf("ResolveAgreementV2BranchConflict failed: %v", err)
	}
	resolvedDoc := agreementV2Doc(t, resolved)
	rightDoc := agreementV2Doc(t, right)
	link := resolvedDoc["links"].([]interface{})[0].(map[string]interface{})
	if resolvedDoc["terms"] != "Resolved terms." {
		t.Fatalf("unexpected resolved terms: %#v", resolvedDoc["terms"])
	}
	if link["jacsId"] != rightDoc["jacsId"] || link["jacsVersion"] != rightDoc["jacsVersion"] {
		t.Fatalf("expected slim link to side branch, got %#v", link)
	}
}
