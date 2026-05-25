# Issue 002: CLI and MCP agreement v2 coverage proves registration, not execution
## Status - Resolved
## Severity - Medium
## Category - Test Gap
## Description
The CLI and MCP parity tests confirm the agreement v2 commands/tools are registered and present in contract fixtures, but they do not execute the new agreement v2 workflows. A broken parameter parse, bad stdin/file handling, malformed MCP response shape, or handler-to-wrapper wiring bug could pass the current snapshot tests.
## Evidence
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/jacs-cli/tests/cli_command_snapshot.rs:1` - CLI test validates command fixture parity against the Clap tree.
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/jacs-cli/tests/cli_command_snapshot.rs:72` - the main assertion compares fixture command paths to Clap command paths, not behavior.
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/jacs-mcp/tests/tool_surface.rs:111` - MCP full-tools test validates the registered tool names.
File: `/Users/jonathan.hendler/personal/JACS-agreement-v2-code/jacs-mcp/tests/contract_snapshot.rs:12` - MCP contract test compares generated schema snapshot to checked-in artifact.
PRD: `/Users/jonathan.hendler/personal/hai/docs/jacs/JACS_AGREEMENT_NEW_SCHEMA.md` - calls for developer workflows and functions across CLI/MCP surfaces, not just command discovery.
## Suggested Fix
Add focused execution tests:
- CLI: temp agent, `agreement-v2 create`, `sign`, `verify`, plus one `apply appendTranscript` and one conflict command using JSON files and stdin.
- MCP: instantiate `JacsMcpServer` with an ephemeral agent and call `jacs_create_agreement_v2`, `jacs_sign_agreement_v2`, `jacs_verify_agreement_v2`, and branch tools directly, asserting success envelopes and parseable agreement/report JSON.

These should stay narrow; the Rust core tests already own deep agreement semantics.
## Affected Files
`jacs-cli/tests/`
`jacs-mcp/tests/`
`binding-core/tests/fixtures/cli_mcp_alignment.json`

## Resolution
Added CLI execution coverage for `agreement-v2 create/apply/sign/verify/detect-conflict/merge-transcript/resolve-conflict` and MCP stdio execution coverage for the same v2 workflow through the registered tools.
