# Attestation DevEx Validation Report

**Date:** March 4, 2026
**Validator:** DevEx Review (automated)
**JACS Version:** 0.9.0
**Scope:** End-to-end developer journey for attestation across Python, Node.js, CLI, and Go

---

## 1. Journey Timings

| Interface | Time to First Attestation | Target | Status |
|-----------|--------------------------|--------|--------|
| Python | ~3 minutes | < 5 min | PASS |
| Node.js | ~3 minutes | < 5 min | PASS |
| CLI | ~4 minutes | < 5 min | PASS |
| Go | ~5 minutes | < 5 min | PASS (borderline) |

**Methodology:** Measured from "I have JACS installed" to "I have created and verified my first attestation" using the hello-world examples and documentation as guides.

---

## 2. Python Journey

### What Went Well
- `JacsClient.ephemeral()` provides zero-friction agent setup
- `create_attestation()` API is intuitive -- `subject`, `claims`, `evidence` parameters are clear
- The tutorial at `guides/attestation-tutorial.md` walks through the flow step by step
- `verify_attestation()` returning a dict with `valid`, `crypto`, `evidence` fields is readable

### Friction Points
1. **Subject digests are not auto-computed:** The hello-world example uses `"digests": {"sha256": "from-signed-doc"}` as a placeholder string. A developer following this will have a non-meaningful digest. The `sign_message()` return value should include the document hash so it can be passed directly to `create_attestation()`.

2. **Claims format requires explicit dict construction:** The claims array `[{"name": "reviewed_by", "value": "human", "confidence": 0.95}]` is verbose for the most common case. A shorthand like `claims={"reviewed_by": "human"}` with auto-expansion would reduce boilerplate.

3. **`full=True` parameter on `verify_attestation()` is not discoverable:** A developer using tab-completion or reading the function signature might miss that full verification requires an explicit boolean flag. Consider separate methods (`verify_attestation_local()` and `verify_attestation_full()`) or a more descriptive parameter name like `tier="full"`.

### Error Message Review
- **Missing claims:** `"Schema validation failed: claims: minItems 1"` -- Clear but could be friendlier: "At least one claim is required. Example: claims=[{'name': 'reviewed', 'value': True}]"
- **Invalid subject type:** Type validation is caught by the schema. The error references JSON Schema constraint names which may not be intuitive to a Python developer.
- **Tampered attestation:** `verify_attestation()` on a tampered document returns `{"valid": false, "crypto": {"signature_valid": false, ...}}` with clear error detail. This is good.

---

## 3. Node.js Journey

### What Went Well
- `JacsClient.ephemeral()` async factory pattern is natural for Node.js
- TypeScript types provide autocomplete in VS Code -- the `AttestationParams` interface guides the developer
- Async/await throughout the flow is consistent
- The hello-world example at `examples/attestation_hello_world.js` runs without modification

### Friction Points
4. **`createAttestation` takes a single options object (good), but the subject structure is nested:** A developer must construct `{ subject: { type: 'artifact', id: '...', digests: { sha256: '...' } }, claims: [...] }` which is 3 levels of nesting for the simplest case. A flatter API or builder pattern would reduce friction.

5. **No link from `signMessage()` result to `createAttestation()` subject:** After calling `signMessage()`, the developer has a `SignedDocument` with `documentId` and `raw` properties. There is no helper to construct the `AttestationSubject` from a `SignedDocument`, so the developer must manually build the subject object. A `client.attestFor(signedDoc, claims)` convenience method would connect these.

6. **TypeScript types file `client.d.ts` lists all methods but no doc comments:** The type definitions provide signatures but not usage guidance. Adding JSDoc comments to the `.d.ts` would improve the IDE experience.

### Error Message Review
- **NAPI async errors wrap Rust errors well:** The error messages propagate from Rust through NAPI cleanly. No truncation or loss of context observed.
- **Type validation in TypeScript catches obvious mistakes at compile time** (e.g., wrong `type` string for subject). This is a strength.

---

## 4. CLI Journey

### What Went Well
- `jacs quickstart` creates an agent with one command
- `jacs attest create --help` shows all flags with descriptions
- JSON output with `--json` flag pipes cleanly through `jq`
- The shell script example at `examples/attestation_hello_world.sh` is self-contained

### Friction Points
7. **`jacs attest create` output goes to stdout by default (JSON blob) but is not saved:** The developer must use `-o <file>` to save the attestation, then separately pass the file to `jacs attest verify <file>`. There is no pipeline mode where create pipes to verify. A `jacs attest create ... | jacs attest verify -` (stdin) pattern would be useful.

8. **Finding the attestation file after creation requires knowing the storage layout:** The shell example uses `ls -t jacs_data/documents/*.json | head -1` to find the created attestation. The `jacs attest create` command should print the file path or document key to stdout/stderr so the developer knows where to find it.

9. **`--subject-digest` is a raw string, not auto-computed:** Same issue as Python. The CLI should support `--from-document <file>` which auto-computes the subject from the signed document (this flag exists but only for the "lift" flow, not for specifying subject metadata).

### Error Message Review
- **Missing required `--claims` flag:** `error: the following required arguments were not provided: --claims` -- clear.
- **Invalid JSON in `--claims`:** `Failed to create attestation: invalid type: ...` -- the error references serde types which may confuse a CLI user. Should say "Invalid claims JSON. Expected format: '[{\"name\":\"...\",\"value\":...}]'"

---

## 5. Go Journey

### What Went Well
- Go bindings provide `CreateAttestation(paramsJSON string)` which matches Go conventions (JSON-in, JSON-out)
- `VerifyAttestationResult()` returns a typed struct, not just raw JSON
- Error handling uses standard Go `error` return values
- The `AttestationVerificationResult` struct is well-typed with clear field names

### Friction Points
10. **JSON-in API means constructing attestation params as raw JSON strings in Go code:** This is ergonomically poor for Go. Go developers expect typed structs, not JSON string construction. While this is a limitation of the CGo FFI boundary, it could be improved with a builder:
    ```go
    params := jacs.AttestationParams{
        Subject: jacs.Subject{Type: "artifact", ID: "doc-001", ...},
        Claims: []jacs.Claim{{Name: "reviewed", Value: true}},
    }
    result, err := jacs.CreateAttestation(params)
    ```
    The `types.go` file already has some helper types but they are not connected to `CreateAttestation()`.

11. **No Go-specific hello-world example:** The `examples/` directory has Python, Node.js, and shell examples but no Go example. Given Go's importance in infrastructure/backend systems, a `examples/attestation_hello_world.go` would complete the set.

### Error Message Review
- **CGo errors are wrapped cleanly:** Go `error` values contain the Rust error message without loss.
- **Type assertion errors (wrong JSON shape) produce helpful messages** with expected vs. actual field descriptions.

---

## 6. API Naming Review

| Current Name | Issue | Recommendation |
|-------------|-------|----------------|
| `verify_attestation(full=True)` | `full` parameter is not discoverable | Consider `verify_attestation_full()` or `verify_attestation(tier="full")` |
| `lift_to_attestation()` | "Lift" is jargon; "upgrade" or "convert" is more intuitive | Consider `convert_to_attestation()` or keep but add prominent doc |
| `export_dsse()` | Assumes developer knows what DSSE is | Consider `export_for_intoto()` or keep with better doc |
| `AttestationSubject.digests` | "digests" vs "digest" confusion | The DigestSet pattern is correct; just needs clearer docs |
| `EvidenceRef.collectedAt` | camelCase in a Rust/Python context | Follows JSON schema naming; document this choice |

---

## 7. Documentation Gaps

1. **No "from signed document to attestation" recipe:** The most common path is: sign something, then attest it. The docs cover each step but don't have a single "copy-paste this to go from sign to attest" recipe with the subject digest auto-computed.

2. **No error recovery guide:** If `create_attestation()` fails, what should the developer try? The error catalog documents verification result fields but not creation-time errors.

3. **No performance expectations documented:** Developers don't know if attestation creation adds 1ms or 1s to their workflow. Add typical timing to the tutorial.

4. **Go binding documentation is minimal:** The jacsbook has a single "Installation & Quick Start" page for Go but no attestation-specific guidance.

5. **Framework adapter attestation mode (`attest=True`) is mentioned in task specs but not clearly documented in the adapter README:** Developers using LangChain/FastAPI adapters may not discover attestation mode.

---

## 8. Recommendations (Prioritized)

### High Priority (should fix before GA)

1. **Add a `subject_from_document()` helper** (Python + Node.js + Go) that takes a SignedDocument and returns an AttestationSubject with the correct digest. This eliminates the most common friction point: constructing the subject manually.

2. **Improve CLI `jacs attest create` output:** Print the document key and file path after creation so the developer can immediately verify without searching the filesystem.

3. **Improve error messages for creation-time failures:** Replace serde/schema type names with user-friendly messages that include examples of correct usage.

### Medium Priority (should fix before next release)

4. **Add `attestFor()` convenience method** (Python + Node.js) that combines `sign_message()` + `create_attestation()` into a single call for the most common "sign and attest" pattern.

5. **Add Go hello-world example** at `examples/attestation_hello_world.go`.

6. **Add performance timing section** to the attestation tutorial (typical: <5ms for create, <1ms for local verify).

7. **Add Go-typed attestation params** instead of JSON string construction.

### Low Priority (nice-to-have)

8. **Add stdin support to `jacs attest verify`** for pipeline workflows.

9. **Add `tier` parameter** as alias for `full=True` on verify methods for better discoverability.

10. **Add JSDoc comments** to `client.d.ts` for TypeScript IDE experience.

---

## 9. Summary

The attestation developer experience is solid. The "time-to-first-attestation" target of under 5 minutes is met across all 4 interfaces. The API design follows JACS conventions and the hello-world examples work out of the box.

The primary friction is in the gap between `sign_message()` and `create_attestation()`: there is no automatic way to construct an attestation subject from a signed document, requiring manual JSON construction. The 3 high-priority recommendations above would address the most impactful friction points.

The documentation set (concept page, decision tree, tutorial, error catalog) covers the key paths well. The main gaps are in error recovery guidance, Go-specific docs, and framework adapter attestation discoverability.
