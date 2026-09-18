package jacs

import (
	"encoding/json"
	"testing"
)

func TestVerificationResultBindingStatusDefaultsUnavailable(t *testing.T) {
	for _, input := range []string{
		`{"valid":true,"identity_bound":true}`,
		`{"valid":false,"identity_binding_status":"locally_enrolled","identity_bound":true}`,
		`{"valid":true,"identity_binding_status":"unknown","identity_bound":true}`,
	} {
		var result VerificationResult
		if err := json.Unmarshal([]byte(input), &result); err != nil {
			t.Fatal(err)
		}
		if result.IdentityBound || result.IdentityBindingStatus != "unavailable" {
			t.Fatalf("missing or inapplicable binding evidence must remain unavailable: %+v", result)
		}
	}
}

func TestVerificationResultBindingBooleanIsDerived(t *testing.T) {
	var result VerificationResult
	if err := json.Unmarshal([]byte(`{"valid":true,"identity_binding_status":"locally_enrolled","identity_bound":false}`), &result); err != nil {
		t.Fatal(err)
	}
	if !result.IdentityBound || result.PolicyAccepted {
		t.Fatal("local binding evidence must not become policy acceptance")
	}
}
