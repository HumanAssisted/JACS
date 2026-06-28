# Task 007 - Observability and Documentation

**Depends on:** 003, 005, 006  
**Unlocks:** execution completion  
**Reversible:** one commit; remove docs/logging additions

## Objective

Document the PQ-root compatibility model and make export/binding failures visible to operators.

The docs should make the answer to "what does a JACS agent do?" obvious:

- signs native JACS documents with PQ signatures
- verifies native JACS documents
- exports compatibility identity views with ES256 when other ecosystems require them
- binds those compatibility keys back to the PQ root

## TDD: Tests First (Red)

Add tests before implementation:

- `jacs/tests/compatibility_observability.rs`
  - `missing_compatibility_key_logs_warn`
  - `binding_verify_failure_logs_warn`
  - `ecosystem_export_logs_info_with_format_and_kid`
- `jacs-cli/tests/mcp_observability_tests.rs`
  - compatibility export command emits structured failure diagnostics
- `jacs-mcp/tests/tool_surface.rs`
  - compatibility export errors include actionable typed error data

Docs checks:

- `rg "ring-ES256|jacsProjections|sign-jws|sign-data-integrity|export-dsse-document" README.md jacs/docs/jacsbook/src jacs-cli/README.md jacs-mcp/README.md`
  - should not find new P2 docs presenting these as public native features
- `rg "PQ root|compatibility key binding|ES256 compatibility" README.md jacs/docs/jacsbook/src`
  - should find the new model in user-facing docs

## Implementation Notes

Add structured events:

- `native_non_pq_sign_rejected`
- `compatibility_key_missing`
- `compatibility_binding_created`
- `ecosystem_export_generated`
- `compatibility_binding_verify_failed`

Fields should include:

- `jacs_id`
- `kid` when known
- `format` or `requested_export`
- `binding_hash` when a binding exists
- `reason` on failure

Update docs:

- `README.md`
- `jacs/README.md`
- `jacs-cli/README.md`
- `jacs-mcp/README.md`
- `jacs/docs/jacsbook/src/advanced/crypto.md`
- `jacs/docs/jacsbook/src/integrations/a2a.md`
- `jacs/docs/jacsbook/src/integrations/did.md`
- `jacs/docs/jacsbook/src/reference/cli-commands.md`

Document the sysadmin view:

- which log event appears
- which metric increments
- what the likely fix is

## TDD: Tests Pass (Green)

Run:

```bash
cargo test -p jacs --test compatibility_observability -- --nocapture
cargo test -p jacs-cli --test mcp_observability_tests -- --nocapture compatibility
cargo test -p jacs-mcp --test tool_surface -- --nocapture compatibility
```

Then run the docs `rg` checks listed above.

## Acceptance Criteria

- Operators can distinguish native-signing failures from compatibility-export failures.
- Docs do not present ES256 as native JACS signing.
- Docs explain why the ES256 private key uses the existing encrypted-at-rest envelope.
- Docs tell users which commands/functions export JWKS and compatibility binding documents.
