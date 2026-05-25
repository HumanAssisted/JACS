# Issue 001: Agreement v2 language parity tests are structural only outside Rust
## Status - Resolved
## Severity - High
## Category - Test Gap
## Description
Python, Node, and Go now expose the agreement v2 methods, but their parity tests only verify method names. The actual agreement workflows are behavior-tested in Rust binding-core, so language-specific return parsing, argument normalization, CGo error propagation, PyO3 dict/string handling, and Node async/sync wrapper behavior can drift without a failing cross-language test.
## Evidence
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/binding-core/tests/agreement_v2_json.rs:59` - Rust binding-core tests exercise create/sign/verify, notary, transcript-only merge, and explicit conflict resolution behavior.
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/jacspy/tests/test_method_parity.py:9` - Python parity test explicitly states it is structural, not behavioral.
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/jacsnpm/test/method-parity.test.js:8` - Node parity test explicitly states it is structural, not behavioral.
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/jacsgo/method_parity_test.go:10` - Go parity test explicitly states it is structural, not behavioral.
PRD: `/Users/jonathan.hendler/personal/hai/docs/jacs/JACS_AGREEMENT_NEW_SCHEMA.md` - requires SDK functions across Python/Go/npm surfaces and portable workflows for agents and humans.
## Suggested Fix
Add one shared JSON fixture/scenario set for agreement v2 and run it in Python, Node, and Go:
- create agreement
- sign as signer
- sign as notary
- verify final status
- append transcript and verify transcript hash behavior
- detect transcript-only branch merge
- resolve terms conflict

Keep expected JSON assertions small and reusable so Rust remains the source of truth, but each binding proves its FFI/API normalization actually works.
## Affected Files
`jacspy/tests/`
`jacsnpm/test/`
`jacsgo/`
`binding-core/tests/fixtures/`

## Resolution
Added behavioral parity tests for Python, Node, and Go covering create/sign/verify, notary signatures, transcript-only branch merge, and explicit terms-conflict resolution through each public binding API. The scenario data now comes from `binding-core/tests/fixtures/agreement_v2_scenarios.json` so the language tests share one source of truth.
