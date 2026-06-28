# Task 006 - Legacy Verification and Scope Guardrails

**Depends on:** 001, 005  
**Unlocks:** 007  
**Reversible:** one commit; remove guardrail tests and any compatibility checks added here

## Objective

Prove P2 did not expand into the old broad projection design.

This task is mostly tests and cleanup. It protects the product boundary after public APIs are added.

## TDD: Tests First (Red)

Add tests before implementation:

- `jacs/tests/legacy_verify_guardrails.rs`
  - `legacy_ed25519_fixture_still_verifies`
  - `legacy_pq2025_fixture_still_verifies`
  - `new_native_es256_signing_is_unavailable`
  - `native_schema_does_not_accept_ring_es256`
  - `native_documents_do_not_accept_jacs_projections`
- `binding-core/tests/contract.rs`
  - `simple_wrapper_has_no_generic_sign_jws_method`
  - `simple_wrapper_has_no_generic_sign_es256_method`
- `jacs-cli/tests/cli_command_snapshot.rs`
  - no `sign-jws`, `sign-data-integrity`, or `export-dsse-document` command exists
- `jacs-mcp/tests/contract_snapshot.rs`
  - no generic projection tools exist

## Implementation Notes

Remove any accidental broad surface introduced while implementing Tasks 001-005.

Check these areas explicitly:

- `jacs-core/schemas/components/signature/v1/signature.schema.json`
- `jacs-core/schemas/header/v1/header.schema.json`
- `jacs/schemas/components/signature/v1/signature.schema.json`
- `binding-core/src/simple_wrapper.rs`
- `jacs-cli/src/cli_builder.rs`
- `jacs-mcp/contract/jacs-mcp-contract.json`

If an old helper remains internally for A2A compatibility, ensure it is scoped and not exposed as generic JACS document projection.

## TDD: Tests Pass (Green)

Run:

```bash
cargo test -p jacs --test legacy_verify_guardrails -- --nocapture
cargo test -p jacs-binding-core --test contract -- --nocapture guardrail
cargo test -p jacs-cli --test cli_command_snapshot -- --nocapture
cargo test -p jacs-mcp --test contract_snapshot -- --nocapture
```

Expected result:

- legacy verification remains green
- old broad projection requirements are absent
- public surface stays narrow

## Acceptance Criteria

- ES256 cannot be used as native `jacsSignature`.
- `jacsProjections` is not part of native JACS documents.
- Generic JWS/Data Integrity/DSSE commands and methods are absent.
- Legacy verification is explicitly tested.

