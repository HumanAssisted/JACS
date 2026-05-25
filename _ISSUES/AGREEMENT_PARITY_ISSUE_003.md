# Issue 003: WASM agreement v2 parity is not tracked by the canonical method fixture
## Status - Resolved
## Severity - Medium
## Category - Test Gap
## Description
WASM exposes the agreement v2 methods, but it is not covered by the canonical `method_parity.json` fixture used by Rust, Python, Node, and Go. The current WASM test only exercises create/sign/verify; it does not verify the rest of the agreement v2 surface or enforce declaration drift between Rust wasm-bindgen exports and the TypeScript declaration stub.
## Evidence
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/binding-core/tests/fixtures/method_parity.json:13` - agreement v2 canonical method list exists for binding surfaces.
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/jacs-wasm/tests/native_sanity.rs:130` - WASM agreement v2 test covers only create/sign/verify happy path.
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/jacs-wasm/jacs_wasm.d.ts:44` - TypeScript declaration lists agreement v2 methods, but there is no fixture-based drift test analogous to Python/Node/Go method parity.
PRD: `/Users/jonathan.hendler/personal/hai/docs/jacs/JACS_AGREEMENT_NEW_SCHEMA.md` - includes a human signing workflow using the JACS WASM signer, making WASM parity a product-critical surface.
## Suggested Fix
Add a WASM parity test that maps `method_parity.json.feature_gated_methods.agreements` to wasm-bindgen method names and checks `CoreAgentHandle`/declaration coverage. Add behavior coverage for `applyAgreementV2Json`, `detectAgreementV2BranchConflictJson`, `mergeAgreementV2TranscriptBranchesJson`, `resolveAgreementV2BranchConflictJson`, and `signAgreementV2Json(..., "notary")`.
## Affected Files
`jacs-wasm/tests/`
`jacs-wasm/jacs_wasm.d.ts`
`binding-core/tests/fixtures/method_parity.json`

## Resolution
Added a WASM declaration drift test against `method_parity.json` and expanded native WASM behavior coverage for apply, detect-conflict, merge-transcript, resolve-conflict, and notary signing.
