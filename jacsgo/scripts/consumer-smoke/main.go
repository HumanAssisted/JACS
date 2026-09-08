// This consumer is copied unchanged into both staged and published release
// smoke modules. The public fixture stays in binding-core as the single source
// of truth; neither smoke path regenerates evidence or rebuilds the native asset.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	jacs "github.com/HumanAssisted/JACS/jacsgo"
)

func decodeReport(raw string) map[string]interface{} {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var report map[string]interface{}
	if err := decoder.Decode(&report); err != nil {
		panic(err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		panic("verification report must contain exactly one JSON value")
	}
	return report
}

func verifyPublicProof(fixturePath string) {
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		panic(err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(data, &fixture); err != nil {
		panic(err)
	}
	for _, field := range []string{"bundle", "expected", "authority", "provenance", "report"} {
		if len(fixture[field]) == 0 {
			panic("public proof fixture is missing " + field)
		}
	}
	// No signing identity, private key, password, or key store is constructed.
	// A missing method or feature-disabled native stub must fail this smoke.
	reportJSON, err := jacs.VerifyHumanApprovedDocument(
		string(fixture["bundle"]), string(fixture["expected"]),
		string(fixture["authority"]), string(fixture["provenance"]),
	)
	if err != nil {
		panic(fmt.Errorf("release native library must verify public human approval: %w", err))
	}
	actual := decodeReport(reportJSON)
	if !reflect.DeepEqual(actual, decodeReport(string(fixture["report"]))) {
		panic("public verifier did not preserve the complete shared report")
	}
	approval, ok := actual["approval"].(map[string]interface{})
	if !ok || actual["current"] != "not_evaluated" || approval["current"] != "not_evaluated" {
		panic("retained public proof must not become live action authorization")
	}

	var wrongExpected map[string]json.RawMessage
	if err := json.Unmarshal(fixture["expected"], &wrongExpected); err != nil {
		panic(err)
	}
	wrongExpected["audience"] = json.RawMessage(`"different-independent-expectation"`)
	wrongJSON, err := json.Marshal(wrongExpected)
	if err != nil {
		panic(err)
	}
	reportJSON, err = jacs.VerifyHumanApprovedDocument(
		string(fixture["bundle"]), string(wrongJSON),
		string(fixture["authority"]), string(fixture["provenance"]),
	)
	if err == nil || reportJSON != "" {
		panic("mismatched independent expectations must fail without a success report")
	}
	fmt.Println("jacsgo public proof: complete report, current=not_evaluated, wrong context rejected")
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: consumer-smoke /path/to/human_approved_document_v1.json")
	}
	verifyPublicProof(os.Args[1])

	// Keep the ordinary signing contract as a separate, subsequent check.
	algorithm := "ed25519"
	agent, _, err := jacs.EphemeralSimpleAgent(&algorithm)
	if err != nil {
		panic(err)
	}
	defer agent.Close()

	signed, err := agent.SignMessage(map[string]interface{}{
		"action": "approve",
		"amount": 100,
	})
	if err != nil {
		panic(err)
	}
	verified, err := agent.Verify(signed.Raw)
	if err != nil {
		panic(err)
	}
	if !verified.Valid || verified.SignerID == "" {
		panic("external sign/verify contract did not authenticate a signer")
	}
	fmt.Printf("jacsgo external consumer: valid=%t signer=%s\n", verified.Valid, verified.SignerID)
}
