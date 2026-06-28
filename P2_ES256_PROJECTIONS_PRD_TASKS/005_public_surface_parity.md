# Task 005 - CLI, SDK, and MCP Public Surface Parity

**Depends on:** 004  
**Unlocks:** 006, 007  
**Reversible:** one commit; remove new public commands/methods and fixture entries

## Objective

Expose the compatibility identity through the smallest useful public surface across Rust bindings, Python, Node, Go, CLI, and MCP.

Add export/inspection functions only. Do not expose generic ES256 signing APIs.

## TDD: Tests First (Red)

Add or update fixture-backed tests before implementation:

- `binding-core/tests/fixtures/method_parity.json`
  - add only the new `SimpleAgentWrapper` methods
- `binding-core/tests/method_parity.rs`
  - fails until Rust method list matches fixture
- Python/Node/Go parity tests
  - fail until bindings expose the same method names or documented exclusions
- `jacs-cli/contract/cli_commands.json`
  - add CLI commands
- `binding-core/tests/fixtures/cli_mcp_alignment.json`
  - align CLI and MCP tools
- `jacs-mcp/contract/jacs-mcp-contract.json`
  - add MCP tools only if they mirror CLI behavior
- `jacs-cli/tests/cli_command_snapshot.rs`
  - fails until Clap tree matches command fixture
- `jacs-mcp/tests/contract_snapshot.rs`
  - fails until MCP contract matches implementation

## Implementation Notes

Public binding API belongs here:

- `binding-core/src/simple_wrapper.rs`
  - `export_compatibility_jwks_json()`
  - `export_compatibility_key_binding_json()`
  - `export_a2a_agent_card_json()` only if existing A2A export cannot be reused

Then update language binding shims as needed:

- `jacspy/`
- `jacsnpm/`
- `jacsgo/`

CLI surface:

- `jacs agent export-jwks`
- `jacs agent export-compat-binding`
- reuse existing W3C/A2A commands where possible

MCP surface:

- mirror CLI export commands only if remote tools need them
- keep CLI/MCP alignment fixture accurate

Do not add:

- `sign_es256`
- `sign_jws`
- `verify_jws`
- `sign_data_integrity`
- `export_dsse_document`

## TDD: Tests Pass (Green)

Run the parity-focused tests:

```bash
cargo test -p jacs-binding-core --test method_parity -- --nocapture
cargo test -p jacs-cli --test cli_command_snapshot -- --nocapture
cargo test -p jacs-binding-core --test cli_mcp_alignment -- --nocapture
cargo test -p jacs-mcp --test contract_snapshot -- --nocapture
```

Then run language parity tests according to the repo's standard binding commands.

## Acceptance Criteria

- Every new public method is in `SimpleAgentWrapper`, not only `AgentWrapper`.
- Canonical fixtures are updated before implementation goes green.
- CLI and MCP command/tool lists match fixtures.
- No arbitrary-document ES256 signing method appears in public API.

