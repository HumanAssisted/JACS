# Schema Consolidation TODO

All items are complete in this branch.

## Schema Surface

- [x] Preserve the supported schema families: A2A, agreements, signatures, agent, config, document, header, key, and related trust metadata.
- [x] Remove retired workflow schemas: message, task, commitment, todo, agentstate, program, node, and eval.
- [x] Remove retired component schemas: action, service, tool, unit, contact, embedding, and todoitem.
- [x] Update the generic header schema so it no longer depends on retired embedded components.
- [x] Update agent schema expectations so A2A capabilities are represented explicitly instead of through service/contact/action component references.

## Core Rust

- [x] Remove retired schema CRUD modules and registry entries.
- [x] Remove tests that exercise retired schema families.
- [x] Update document, agent, storage, and search paths to use generic documents where old schema-specific behavior was unnecessary.
- [x] Preserve the public `sign_message` compatibility contract, including signed-email `jacsType: "message"` output, while removing the retired message schema files.
- [x] Keep agreement and signature behavior intact for arbitrary document payloads.

## Bindings

- [x] Keep Python, Node, and Go `sign_message` behavior aligned with Rust while removing retired state/schema-specific payload helpers.
- [x] Update A2A helpers to advertise explicit skills.
- [x] Refresh binding tests and generated TypeScript outputs.

## CLI And MCP

- [x] Remove task-specific CLI commands.
- [x] Remove MCP tools for retired state, message, memory, and audit surfaces.
- [x] Refresh CLI and MCP contract fixtures.
- [x] Update profile, tool-surface, and contract snapshot tests.

## Docs And Generated References

- [x] Remove retired schema pages from source mdBook navigation and schema docs.
- [x] Regenerate mdBook output.
- [x] Regenerate generated schema reference output.
- [x] Update examples so generated agents do not contain retired service/contact fields.
- [x] Add this change to the changelog.

## Verification

- [x] Format Rust code.
- [x] Run core Rust, binding-core, CLI, MCP, Node, and Python targeted checks.
- [x] Run generated-doc build checks.
- [x] Run `git diff --check`.
