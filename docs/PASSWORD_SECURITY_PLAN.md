# PASSWORD_SECURITY_PLAN

Last updated: 2026-02-19

## Purpose
Define and implement secure password-supply options for JACS with one rule:

- A task is **not done** until it is **verified** by tests.
- "Implemented but unverified" is tracked as **NOT DONE**.

This plan is intentionally execution-focused and DRY/TDD-oriented.

## Status Model (Strict)
Use only these statuses for every task:

- `NOT_DONE`: not implemented, or implemented without passing verification.
- `IN_PROGRESS`: code changes started, verification not complete.
- `VERIFIED`: implementation complete and verification checks passed.

Rule:
- There is no separate "done" state. `VERIFIED` is done.

## Current Verified Baseline
These are already verified in current repo state:

1. Fail-hard password requirement remains in place (`JACS_PRIVATE_KEY_PASSWORD` required when needed).
2. No `pq-dilithium` compatibility in wrapper-facing security posture.
3. Wrapper suites currently pass after alignment (`jacspy`, `jacsnpm`, `jacsgo`, `jacs-mcp`).

## Password Security Options (Target Architecture)

| Option | Summary | Primary Context | Status |
|---|---|---|---|
| `O0` Explicit/API password | Pass password directly to create/load APIs | Programmatic calls | `VERIFIED` |
| `O1` Env var (`JACS_PRIVATE_KEY_PASSWORD`) | Existing universal fallback | CI/dev compatibility | `VERIFIED` |
| `O2` Password file (`JACS_PASSWORD_FILE`) | Read-once from secret mount/pipe | Containers/CI/prod | `NOT_DONE` |
| `O3` TTY prompt (no echo) | Interactive prompt when terminal available | Local CLI/dev | `NOT_DONE` |
| `O4` OS keychain | Retrieve password from Keychain/libsecret/DPAPI | Desktop developer UX | `NOT_DONE` |
| `O5` External secrets manager | Pull password via Vault/AWS/GCP/Azure provider | Production cloud | `NOT_DONE` |
| `O6` HSM/KMS signing backend | Remove local private key decryption path | High-assurance deployments | `NOT_DONE` |

Recommended order:
1. `O2` Password file
2. `O3` TTY prompt
3. `O4` Keychain
4. `O5` Secrets manager
5. `O6` HSM/KMS (separate crypto architecture project)

## DRY Design Principles (Non-Negotiable)

1. Single resolution path in core.
- Introduce one resolver module, e.g. `jacs/src/crypt/password_resolver.rs`.
- All password reads (encrypt/decrypt/quickstart/load/CLI) route through it.

2. Single precedence definition.
- Precedence implemented once, reused everywhere.
- Proposed precedence (local-key path):
  1. Explicit API password
  2. Password file (`JACS_PASSWORD_FILE` or explicit param)
  3. TTY prompt (interactive only)
  4. Env var (`JACS_PRIVATE_KEY_PASSWORD`)

3. Provider interface over conditionals.
- Use a provider abstraction to avoid duplicate branching logic.
- Start minimal trait/interface in core; wrappers pass parameters, not policy.

4. Wrapper pass-through only.
- `jacspy`, `jacsnpm`, `jacsgo`, `jacs-mcp` should not reimplement precedence logic.
- They only pass explicit inputs to core.

## TDD Strategy

### Test-first workflow
For each feature slice:
1. Add/extend tests first (expected fail).
2. Implement minimal code to pass tests.
3. Refactor for DRY.
4. Re-run targeted tests.
5. Re-run package full suite.

### Test layers

1. Unit tests (core resolver)
- precedence behavior
- empty/whitespace handling
- file read edge cases
- non-TTY behavior

2. Security unit tests
- rejects insecure password file perms in strict mode
- never logs password values
- trims trailing newline from file inputs

3. Integration tests (core + CLI)
- `quickstart` using password file
- create/load/sign/verify flows with password file
- TTY path only when interactive

4. Wrapper contract tests
- Python/Node/Go/MCP pass-through of password file option
- all wrappers exhibit same precedence outcomes

5. Regression suite
- existing suites remain green
- no test deletions to force pass

## Execution Plan

## Phase 1: Core Resolver + Password File (`O2`)
Goal: secure non-env supply path for CI/containers with no wrapper-specific logic.

### P1.1 Add resolver module
- Status: `NOT_DONE`
- Deliverable:
  - one resolver function and provider abstraction in core
  - migration of existing password callsites to resolver
- Verification:
  - unit tests for precedence pass
  - no direct `env::var("JACS_PRIVATE_KEY_PASSWORD")` callsites outside resolver (except intentional compatibility wrappers)

### P1.2 Add password file support
- Status: `NOT_DONE`
- Deliverable:
  - `JACS_PASSWORD_FILE` support
  - explicit file-path API support where needed
  - newline trimming
  - secure-permission checks
- Verification:
  - file-based integration tests pass
  - permission policy tests pass

### P1.3 CLI support
- Status: `NOT_DONE`
- Deliverable:
  - `--password-file` on relevant commands
  - CLI delegates to core resolver
- Verification:
  - CLI tests for `--password-file` pass

## Phase 2: TTY Prompt (`O3`)
Goal: remove need for env var during interactive local use.

### P2.1 Interactive prompt path
- Status: `NOT_DONE`
- Deliverable:
  - no-echo prompt in interactive contexts
  - disabled automatically in non-interactive contexts
- Verification:
  - unit/integration tests for TTY detection path pass
  - non-TTY tests confirm no prompt attempt

## Phase 3: Wrapper Pass-through (DRY enforcement)
Goal: wrappers expose options without duplicating policy.

### P3.1 Python
- Status: `NOT_DONE`
- Deliverable:
  - add `password_file` args to relevant `quickstart/create/client` entry points
- Verification:
  - `jacspy` targeted tests + full suite pass

### P3.2 Node
- Status: `NOT_DONE`
- Deliverable:
  - add `passwordFile` options in `simple/client` entry points
- Verification:
  - `jacsnpm` targeted tests + full suite pass

### P3.3 Go
- Status: `NOT_DONE`
- Deliverable:
  - add password file option in simple API options struct
- Verification:
  - `go test ./...` passes

### P3.4 MCP
- Status: `NOT_DONE`
- Deliverable:
  - password file support in relevant tool params and execution path
- Verification:
  - `cargo test -p jacs-mcp` passes

## Phase 4: Keychain + External Secrets (`O4`, `O5`)
Goal: stronger production/desktop paths, feature-gated.

### P4.1 Keychain support
- Status: `NOT_DONE`
- Deliverable:
  - gated feature, cross-platform fallbacks, clear docs
- Verification:
  - feature-specific tests pass where available

### P4.2 Secrets manager provider interface
- Status: `NOT_DONE`
- Deliverable:
  - provider trait + one provider first (do not start with all providers)
- Verification:
  - provider integration tests pass
  - precedence tests confirm provider position

## Phase 5: HSM/KMS Delegated Signing (`O6`)
- Status: `NOT_DONE`
- Note:
  - treated as separate architecture track after phases 1-4 are verified.

## Verification Gates (Must Pass)

A task cannot move to `VERIFIED` unless all relevant checks pass.

Core:
- `cargo test -p jacs`

Python:
- `cd jacspy && JACS_PRIVATE_KEY_PASSWORD='***' uv run python -m pytest tests/ -q`

Node:
- `cd jacsnpm && npm test`

Go:
- `cd jacsgo && go test ./...`

MCP:
- `cargo test -p jacs-mcp`

Security check:
- no plaintext passwords in docs/examples recommending insecure project-file storage.

## Tracking Checklist (update each PR)

- [ ] Added failing tests first.
- [ ] Implemented minimal code to pass tests.
- [ ] Refactored to remove duplication.
- [ ] Ran targeted tests for touched area.
- [ ] Ran full package suite.
- [ ] Updated docs and examples.
- [ ] Marked task `VERIFIED` only after all gates pass.

## Open Decisions (Need Confirmation)

1. Should `JACS_PASSWORD_FILE` be allowed to point at `-` (stdin) for pipe-based secrets?
2. For insecure file permissions, should strict mode fail hard and non-strict warn, or should all modes fail hard?
3. Do we want `O4` keychain in the same release train as `O2/O3`, or keep keychain in a follow-up release?

