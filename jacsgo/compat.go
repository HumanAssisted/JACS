package jacs

/*
#cgo CFLAGS: -I${SRCDIR}/build
#cgo darwin LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build
#cgo linux LDFLAGS: -L${SRCDIR}/build -ljacsgo -Wl,-rpath,${SRCDIR}/build

#include <stdlib.h>
#include "jacs_cgo.h"
*/
import "C"

// ============================================================================
// ES256 compatibility key + ecosystem exports (P2 Tasks 002–004c)
// ============================================================================
// Native JACS signing stays post-quantum (pq2025); these methods manage the
// ES256 `ecosystem_signing` compatibility key and its exports for W3C/JOSE
// ecosystems. Identity exports (JWKS, key binding) auto-issue the default
// identity binding; content exports (AP2 mandate, Agreement-v2 VC) require
// the explicit `ap2-mandate` / `agreement-vc` scope granted via
// IssueCompatBinding (or `jacs agent issue-compat-binding` on the CLI).

// AddCompatKey adds the ES256 ecosystem compatibility key to an EXISTING
// agent (explicit migration; new agents get the key eagerly at creation).
// Returns CompatKeyInfo JSON. Errors if the key already exists or the agent
// is ephemeral.
func (a *JacsSimpleAgent) AddCompatKey() (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	return simpleStringResult(
		C.jacs_simple_add_compat_key(a.handle),
		"failed to add compatibility key",
	)
}

// IssueCompatBinding issues (or re-issues) the native-root-signed compatibility
// key binding (P2 Task 003, FR11/FR24). Content scopes (`ap2-mandate`,
// `agreement-vc`) are never auto-issued: they require this explicit grant,
// and every grant is signed by the current native root. This is also the re-issue path
// after key rotation.
//
// scopesJSON is either "" (grant the default identity scopes) or a JSON
// array of scope strings, e.g. `["jwks","did","ap2-mandate"]` — an unknown
// scope is rejected. expiresAt is an optional RFC 3339 timestamp; "" means
// no expiry. Returns the binding document JSON.
func (a *JacsSimpleAgent) IssueCompatBinding(scopesJSON string, expiresAt string) (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	cScopes, freeScopes := cString(scopesJSON)
	defer freeScopes()
	var expiresPtr *string
	if expiresAt != "" {
		expiresPtr = &expiresAt
	}
	cExpires, freeExpires := cStringOpt(expiresPtr)
	defer freeExpires()
	return simpleStringResult(
		C.jacs_simple_issue_compat_binding(a.handle, cScopes, cExpires),
		"failed to issue compatibility key binding",
	)
}

// ExportCompatibilityJwks exports the agent's compatibility JWKS (ES256
// public key only — native-root material is never published here) as JSON.
func (a *JacsSimpleAgent) ExportCompatibilityJwks() (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	return simpleStringResult(
		C.jacs_simple_export_compatibility_jwks(a.handle),
		"failed to export compatibility JWKS",
	)
}

// ExportCompatibilityKeyBinding exports the current verified native-root-signed
// compatibility key binding document as JSON, so relying parties can trace
// the ES256 key back to the agent's native root.
func (a *JacsSimpleAgent) ExportCompatibilityKeyBinding() (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	return simpleStringResult(
		C.jacs_simple_export_compatibility_key_binding(a.handle),
		"failed to export compatibility key binding",
	)
}

// ExportAp2Mandate exports the AP2 merchant-authorization mandate for a UCP
// checkout as a detached ES256 JWS. Requires the explicit `ap2-mandate`
// binding scope — content exports never auto-issue a binding.
func (a *JacsSimpleAgent) ExportAp2Mandate(checkoutJSON string) (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	cCheckout, freeCheckout := cString(checkoutJSON)
	defer freeCheckout()
	return simpleStringResult(
		C.jacs_simple_export_ap2_mandate(a.handle, cCheckout),
		"failed to export AP2 mandate",
	)
}

// ExportA2aAgentCard exports the A2A agent card signed with the ES256
// compatibility key (feature-gated in Rust under "a2a", enabled in the
// default Go native lib).
func (a *JacsSimpleAgent) ExportA2aAgentCard() (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	return simpleStringResult(
		C.jacs_simple_export_a2a_agent_card(a.handle),
		"failed to export A2A agent card",
	)
}

// ExportAgreementV2AsVc exports an Agreement-v2 JSON document as a Verifiable
// Credential with an `ecdsa-jcs-2019` Data Integrity proof. Requires the
// explicit `agreement-vc` binding scope (feature-gated in Rust under
// "agreements", enabled in the default Go native lib).
func (a *JacsSimpleAgent) ExportAgreementV2AsVc(agreementJSON string) (string, error) {
	if a.handle == nil {
		return "", errSimpleAgentClosed
	}
	cAgreement, freeAgreement := cString(agreementJSON)
	defer freeAgreement()
	return simpleStringResult(
		C.jacs_simple_export_agreement_v2_as_vc(a.handle, cAgreement),
		"failed to export Agreement-v2 VC",
	)
}
