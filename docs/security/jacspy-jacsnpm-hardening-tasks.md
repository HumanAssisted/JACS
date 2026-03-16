# Jacspy and Jacsnpm Hardening Tasks

Date: March 10, 2026

Scope: High and medium issues from the wrapper security, parity, usability, correctness, and test-quality review.

## Task Tracker

| ID | Severity | Area | Task | Status | TDD Coverage |
| --- | --- | --- | --- | --- | --- |
| WRAP-SEC-001 | High | Installer integrity | Verify downloaded CLI archives before execution and reject unsafe archive members instead of extracting whole archives blindly. | Done | `jacspy/tests/test_cli_runner.py`, `jacsnpm/test/install-cli.test.js` |
| WRAP-SEC-002 | Medium | Secret handling | Stop leaking generated private-key passwords into process-global environment variables; scope them to native calls and in-memory client state. | Done | `jacspy/tests/test_client.py`, `jacsnpm/test/client.test.js`, `jacsnpm/test/simple.test.js` |
| WRAP-COR-003 | Medium | Persistent config paths | Make persistent quickstart/load work when `config_path`/`configPath` is nested and config-relative directories resolve correctly. | Done | `jacs/src/storage/mod.rs`, `jacspy/tests/test_client.py`, `jacsnpm/test/client.test.js`, `jacsnpm/test/simple.test.js` |
| WRAP-COR-004 | Medium | Storage abstraction | Make `verify_by_id` / `verifyById` use native storage lookup instead of manually reading `jacs_data/documents/<id>.json`. | Done | `jacspy/tests/test_client.py`, `jacsnpm/test/client.test.js`, `jacsnpm/test/simple.test.js` |
| WRAP-TEST-005 | Medium | Attestation contract tests | Align wrapper attestation tests with the canonical contract and pin camelCase JSON fields such as `signatureValid`, `hashValid`, and `payloadType`. | Done | `jacspy/tests/test_attestation.py`, `jacsnpm/test/attestation.test.js`, `jacsnpm/test/attestation-cross-lang.test.js` |

## Implementation Notes

- `WRAP-SEC-001`: Python now verifies release checksums before install and validates archive members before extraction. Node now validates checksums and extracts only the expected binary entry instead of expanding the full archive.
- `WRAP-SEC-002`: Python and Node wrappers retain generated passwords in wrapper state and temporarily project them into the environment only for native calls that require private-key access.
- `WRAP-COR-003`: Core filesystem storage now preserves absolute paths and resolves relative paths against the storage creation working directory, which fixes nested persistent wrapper configs.
- `WRAP-COR-004`: Both wrappers now obtain saved documents and signing metadata through the native agent APIs, so alternate storage backends and config layouts are respected.
- `WRAP-TEST-005`: Attestation contract tests now follow the canonical JSON contract already enforced in core Rust types and fixtures.

## Protocol JSON Casing Rule

Protocol-bound JSON emitted by JACS wrappers should preserve the owning protocol's canonical field names. Do not rewrite protocol JSON into wrapper-local snake_case keys.

- A2A JSON should stay camelCase. The official A2A specification says JSON serializations of the data model must use camelCase names such as `protocolVersion`, `contextId`, and `defaultInputModes`.
- DSSE envelopes should stay camelCase. The DSSE envelope definition uses `payloadType`, `signatures`, `sig`, and `keyid`.
- in-toto statements should stay camelCase in JSON ecosystems that serialize them as JSON objects, including fields such as `subject` and `predicateType`.
- Python method names may remain snake_case for ergonomics, but protocol JSON returned to callers should match the protocol contract, fixture files, and schemas.

## Sources

- A2A specification, JSON field naming convention: <https://a2a-protocol.org/latest/specification/>
- DSSE envelope definition: <https://github.com/secure-systems-lab/dsse/blob/master/envelope.proto>
- DSSE overview and design goals: <https://github.com/secure-systems-lab/dsse>
- Python Packaging hosted attestations spec, which normatively uses a JSON in-toto Statement with `predicateType` and DSSE `application/vnd.in-toto+json`: <https://packaging.python.org/specifications/index-hosted-attestations/>

## Follow-Up

- Low: tighten the legacy wrapper-only A2A trust fallback so extension presence is not described as cryptographic verification when native A2A policy APIs are unavailable.
