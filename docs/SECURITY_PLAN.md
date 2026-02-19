# SECURITY_PLAN

Last updated: 2026-02-19

## Locked Decisions (Do Not Revisit In This Phase)

1. No legacy signature fallback paths.
2. No `pq-dilithium` compatibility path.
3. Fail hard if `JACS_PRIVATE_KEY_PASSWORD` is missing.
4. Keep `pq2025` as the only supported post-quantum algorithm path for now.

## Completed Now (Addressable + Done)

1. Legacy PQ removal and rejection behavior
- Removed `pq-dilithium` implementation path in core.
- Added/kept explicit rejection tests for legacy algorithm use.

2. Password-required key lifecycle
- Key generation/loading now fails explicitly when password is absent.
- Updated tests to set required password env where appropriate.

3. Cargo audit as a development requirement and CI gate
- Added metadata requirement in both:
  - workspace: `/Users/jonathan.hendler/personal/JACS/Cargo.toml`
  - package: `/Users/jonathan.hendler/personal/JACS/jacs/Cargo.toml`
- CI now installs pinned `cargo-audit` and enforces it as a failing gate.
- Makefile includes `audit-jacs` target and tool presence check.

4. Test coverage improvements (not reductions)
- Expanded `pq2025` test coverage for:
  - supported algorithm set
  - legacy algorithm rejection
  - password-required behavior
- Fixed cross-language fixture flow to respect fail-hard password policy and regenerated fixtures.

5. Current audit gate behavior
- `cargo audit` enforced with temporary ignore for `RUSTSEC-2023-0071` only.
- Ignore is documented as temporary until upstream mitigation/replacement exists.

6. Suite stability after hardening
- Full maintained `jacs` test suite passes after fail-hard/password + PQ + fixture updates.
- Cross-language fixture generation now sets required password explicitly (no policy bypass).

## P0 (Block Next Release)

1. Zeroization and secret-memory handling
- Add `zeroize`-based handling to private-key buffers and sensitive temporary key material.
- Add explicit drop/cleanup tests in Rust core for secret-bearing types.
- Define binding-core/FFI policy for minimizing secret copies at Python/Node/Go boundaries.

2. Path-safety full call-site audit (elevated from P1)
- Verify all filesystem touch points route through centralized path validation.
- Add regression tests for symlink/device/absolute-path edge cases across platforms.

3. Canonicalization + cryptographic vector coverage
- Add RFC 8785/JCS edge-case vectors (ordering, numeric forms, whitespace equivalence).
- Add ML-DSA-87 official KAT/negative vectors and classical verification rejection vectors.
- Add differential verification tests against canonical reference outputs.

4. PQ implementation lock and side-channel review criteria
- Pin and document exact PQ crate + version used by `pq2025`.
- Record CVE posture and minimum accepted version policy.
- Add side-channel review checklist and test harness entry criteria.

5. Strict CI posture
- Keep `cargo-audit` mandatory in CI and local dev flow.
- Revisit and remove `RUSTSEC-2023-0071` ignore as soon as upstream allows.
- Add strict verification CI lane (`JACS_DISABLE_LEGACY_SIGNATURE_FALLBACK=true`) as always-on gate.

## P1 (Next Release Window)

1. Key lifecycle primitives
- Add revocation/rotation/expiry skeleton APIs and test scaffolding.

2. Fuzzing and memory-safety lanes
- Add initial `cargo-fuzz` coverage on signing/verification/path validation entry points.
- Add miri/sanitizer checks for high-risk modules.

3. Binding and network hardening
- Add cross-language secret-handling tests for bindings (copy/ownership boundaries).
- Add MCP/A2A black-box abuse tests (rate-limit/load/auth-bypass regression set).

## Should Not Do Now

1. Do not reintroduce compatibility for `pq-dilithium`.
2. Do not add password auto-generation or plaintext password-file defaults.
3. Do not weaken fail-closed behavior to preserve convenience workflows.
4. Do not start formal certification work (FIPS/CC) before hardening/test backlog above is complete.

## P2 (Pre-Audit Readiness)

1. Reproducible builds, signed releases, and SLSA-oriented provenance.
2. External cryptography-focused audit preparation package.
3. Formal compliance planning (FIPS/Common Criteria) once core behavior is stable.

## Exit Criteria For This Phase

1. Full maintained Rust test suite passes with fail-hard password and no legacy PQ path.
2. `cargo-audit` is mandatory in CI with only explicitly documented temporary ignores.
3. P0 hardening is complete and verified in CI:
- zeroization/memory-handling controls,
- full path call-site audit coverage,
- canonicalization + ML-DSA vectors,
- strict verification lane.
4. Security docs/tests consistently enforce:
- no legacy PQ compatibility,
- password-required key operations,
- canonical verification expectations.
