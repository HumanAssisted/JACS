# Task 001 - Native PQ Signing Policy

**Depends on:** none  
**Unlocks:** 002, 006  
**Reversible:** one commit; restore prior user-facing algorithm selection

## Objective

Make new native JACS signatures always use `pq2025`. Do not add ES256 to native JACS signing. Preserve legacy verification for already-supported algorithms.

This task defines the boundary: ES256 is not a JACS native signing algorithm. It will appear later only as an ecosystem compatibility key.

## TDD: Tests First (Red)

Add or update tests before implementation:

- `jacs-core/tests/sign_pq2025.rs`
  - `new_native_signatures_use_pq2025`
  - `signing_algorithm_parser_does_not_accept_es256`
  - `signature_schema_rejects_ring_es256`
- `binding-core/tests/contract.rs`
  - `default_ephemeral_agent_uses_pq2025`
  - `new_public_agent_creation_rejects_ed25519_algorithm_selection`
  - `new_public_agent_creation_rejects_es256_algorithm_selection`
- `jacs/tests/config_signing_integration.rs`
  - `config_ed25519_does_not_create_new_native_signing_agent`
  - `config_es256_does_not_create_new_native_signing_agent`
- Existing legacy fixture tests still verify Ed25519 fixtures.

The tests should prove the distinction between "legacy verify" and "new native sign".

## Implementation Notes

Touch only the native signing policy surface:

- `jacs-core/src/sign.rs`
  - keep `SigningAlgorithm` limited to existing native verifier algorithms
  - do not add `SigningAlgorithm::Es256`
  - do not accept `"es256"` or `"ring-ES256"` in native parse paths
- `jacs-core/schemas/components/signature/v1/signature.schema.json`
  - do not add `"ring-ES256"`
- `jacs-core/schemas/header/v1/header.schema.json`
  - keep native signature expectations PQ-compatible
- `jacs/src/config/mod.rs`
  - stop treating algorithm config as a user-facing selector for new native signing
  - load legacy config clearly, but new signing resolves to `pq2025`
- `binding-core/src/lib.rs`
  - remove public creation behavior that maps user input to new Ed25519 signing
  - return a typed error for ES256/native-sign attempts
- `binding-core/src/simple_wrapper.rs`
  - keep public binding behavior aligned with `binding-core/src/lib.rs`

If internal test helpers still need Ed25519 signing to build legacy fixtures, keep them private and name them as legacy-only.

## TDD: Tests Pass (Green)

Run the focused tests:

```bash
cargo test -p jacs-core --test sign_pq2025 -- --nocapture native
cargo test -p jacs-binding-core --test contract -- --nocapture algorithm
cargo test -p jacs --test config_signing_integration -- --nocapture algorithm
```

Expected result:

- new native signatures report `pq2025`
- native ES256 is rejected
- legacy Ed25519 verification tests still pass

## Acceptance Criteria

- No native JACS schema accepts `"ring-ES256"`.
- No public new-signing path creates ES256 native signatures.
- No public new-signing path creates Ed25519 native signatures unless explicitly documented as a legacy fixture/test-only path.
- Existing supported legacy documents can still verify.

