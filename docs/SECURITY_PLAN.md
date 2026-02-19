# SECURITY_PLAN

Last updated: 2026-02-19

## Scope
This plan covers security work for JACS core (`jacs/`) that is realistic to execute now, plus explicit items to defer.

## What Was Addressed Now
These fixes/tests are implemented in this change set:

1. Signature content hardening:
- Added canonical signature payload construction that includes non-string JSON fields.
- Default field selection is now deterministic (sorted) when fields are auto-selected.
- Signature field name validation now rejects reserved fields directly.

2. Backward compatibility while hardening:
- Verification now prefers canonical payload reconstruction.
- Legacy string-only reconstruction is used only as a compatibility fallback.
- Fallback can be disabled with `JACS_DISABLE_LEGACY_SIGNATURE_FALLBACK=true`.

3. Verification correctness:
- Verification now uses `jacsSignature.fields` by default when explicit fields are not provided.

4. Added/extended tests:
- Canonical payload behavior tests in `jacs/src/agent/mod.rs`.
- ML-DSA-87 negative/edge tests in `jacs/src/crypt/pq2025.rs`.
- Unix file/dir permission tests (0600/0700) in `jacs/src/keystore/mod.rs`.
- Windows UNC/device-path path-safety regression test in `jacs/tests/path_validation_tests.rs`.

## What We Should Do Now (P0/P1)

### P0 (next 1-2 weeks)
1. Keep compatibility fallback enabled short-term, but schedule removal:
- Announce deprecation window for legacy signature reconstruction.
- Add CI run with fallback disabled (`JACS_DISABLE_LEGACY_SIGNATURE_FALLBACK=true`) to detect remaining legacy dependencies.

2. PQ migration containment:
- Keep `pq-dilithium` as legacy-verify compatibility only.
- Prefer `pq2025` for all new key generation and examples.
- Add a release note stating `pq-dilithium` is deprecated and migration is required.

3. Key protection defaults:
- Require encrypted private-key defaults in quickstart/onboarding paths.
- Ensure guidance and examples never suggest plaintext private key storage.

4. Dependency/Supply chain gates in CI:
- Add/require `cargo audit`, `cargo deny`, and lockfile review gates.

### P1 (next 2-6 weeks)
1. Strict canonicalization compliance:
- Move from current deterministic canonicalization to full RFC 8785/JCS-compatible canonicalization for signed payloads and hash-critical paths.

2. Formalized crypto vector testing:
- Add KAT/Wycheproof-style vector suites for all supported algorithms.

3. Full filesystem call-site audit:
- Verify every path construction for key/config/schema/trust/storage flows is gated by path-safety checks.

## What We Should Not Do Now

1. Do not start FIPS/Common Criteria certification work yet:
- First finish crypto migration, canonicalization hardening, and CI security gates.

2. Do not remove legacy verification fallback immediately:
- Removing now is likely to break existing signed artifacts and cross-language fixtures.

3. Do not expand network trust defaults:
- Keep fail-closed behavior; avoid broadening remote key resolution without stronger pinning/DNSSEC/test coverage.

4. Do not treat `pq-dilithium` as production-forward:
- Keep it strictly legacy compatibility until removed.

## Execution Plan

### Phase 1 (this release)
- Ship canonical payload signing + compatibility fallback.
- Ship new regression tests (done).
- Document migration flags and deprecation timeline.

### Phase 2 (next release)
- Turn on CI security gates (`cargo audit`/`deny`).
- Add strict-mode CI job with legacy fallback disabled.
- Update quickstarts to enforce encrypted key workflow.

### Phase 3 (following release)
- Remove legacy signature fallback by default (or behind explicit compatibility flag only).
- Narrow/remove `pq-dilithium` signing paths.
- Begin external security audit prep package.

## Exit Criteria
1. New signatures never depend on legacy string-only payload reconstruction.
2. CI proves strict verification mode passes for supported workflows.
3. New agent creation defaults to encrypted private-key storage.
4. Legacy PQ path is clearly documented as deprecated and migration-complete for maintained examples.

## Questions To Confirm
1. Should we set `JACS_DISABLE_LEGACY_SIGNATURE_FALLBACK=true` as the default in the next minor release, or keep default compatibility for one additional release?
2. Do you want `pq-dilithium` generation/signing disabled now (verify-only), or deferred one release with a hard deprecation warning?
3. Should quickstart fail hard when no private-key password is set, or continue with an explicit unsafe-development override flag?
