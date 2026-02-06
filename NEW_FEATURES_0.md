# Phase 0: Signed Agent State Documents

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)
**Status**: Design complete, ready for implementation
**Steps**: 0.1 - 0.40 (40 steps)
**Priority**: FIRST -- this is the foundation that all agent frameworks need

---

## Motivation

Every modern AI agent framework stores persistent state as **unsigned files**:

| Framework | Memory File | Skill File | Plan File | Config File | Hook File |
|-----------|------------|------------|-----------|-------------|-----------|
| **Claude Code** | MEMORY.md, CLAUDE.md | SKILL.md (AgentSkills.io) | plans/*.md | settings.json | hooks in settings |
| **OpenAI Codex** | AGENTS.md | -- | PLANS.md | -- | -- |
| **OpenClaw** | workspace memory | SKILL.md + scripts/ | -- | openclaw.plugin.json | -- |
| **LangGraph** | checkpoints (JSON/DB) | tool definitions | -- | -- | -- |
| **AutoGPT** | AutoGpt.json | -- | -- | ai_settings.yaml | -- |

**None of these sign their files.** Any process can modify a MEMORY.md, a SKILL.md, or a hook script without detection. For agent-to-agent trust, this is unacceptable. JACS should be the standard way to cryptographically sign agent state files.

### What This Phase Delivers

A **generic signed document wrapper** (`agentstate.schema.json`) that can sign ANY agent state file type. The original file stays in place for backwards compatibility. JACS creates a signed document alongside it that:

1. References the original file by path and SHA-256 hash
2. Optionally embeds the file content (for hooks, small configs)
3. Is signed by the agent that created/adopted it
4. Records the agent state type (memory, skill, plan, config, hook)
5. Supports re-signing on every update (like todo lists)
6. Works with all existing JACS infrastructure (storage, MCP, bindings)

### Design Principles

1. **Original files stay in place.** A SKILL.md must remain at its original path for Claude Code, OpenClaw, and other frameworks to read it. JACS does NOT move or modify the original.

2. **Signing is triggered by CRUD operations.** When an MCP tool or API call creates or updates an agent state file, JACS automatically creates/updates the signed version. The MCP CRUD operations REPLACE the default file loading -- agents should use JACS tools to read and write state files, getting signing for free.

3. **We can advise but not enforce.** Agent frameworks may read unsigned files directly. JACS documentation must clearly explain why signed state files matter and how to integrate JACS signing into existing workflows. Developer documentation is a first-class deliverable.

4. **Author-signed or adopter-signed.** If a SKILL.md has an original author (published to ClawHub, AgentSkills.io), the author signs it. If an agent adopts an unsigned skill from the internet, the adopting agent signs it for their local filesystem -- proving "I chose to use this skill at this time."

5. **File naming: `{TYPE}.jacs.json`.** Example: `SKILL.md` has a signed counterpart `SKILL.jacs.json` stored in JACS's configured storage location. The JACS document references `SKILL.md` via `jacsFiles[0].path`.

---

## Architecture: The Agent State Document

### Schema: `agentstate.schema.json`

A new top-level schema extending `header.schema.json` via `allOf`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
  "title": "Agent State Document",
  "description": "A signed wrapper for agent state files (memory, skills, plans, configs, hooks). References the original file by path and hash, optionally embedding content.",
  "allOf": [
    { "$ref": "https://hai.ai/schemas/header/v1/header.schema.json" }
  ],
  "properties": {
    "jacsAgentStateType": {
      "type": "string",
      "enum": ["memory", "skill", "plan", "config", "hook"],
      "description": "The type of agent state this document wraps."
    },
    "jacsAgentStateName": {
      "type": "string",
      "description": "Human-readable name for this state document (e.g., 'JACS Project Memory', 'jacs-signing skill')."
    },
    "jacsAgentStateDescription": {
      "type": "string",
      "description": "Description of what this state document contains or does."
    },
    "jacsAgentStateFramework": {
      "type": "string",
      "description": "Which agent framework this state file is for (e.g., 'claude-code', 'openclaw', 'langchain', 'generic')."
    },
    "jacsAgentStateVersion": {
      "type": "string",
      "description": "Version of the agent state content (distinct from jacsVersion which tracks JACS document versions)."
    },
    "jacsAgentStateContentType": {
      "type": "string",
      "description": "MIME type of the original content (text/markdown, application/yaml, application/json, text/x-shellscript, etc.)."
    },
    "jacsAgentStateContent": {
      "type": "string",
      "description": "The full content of the agent state file, inline. Used when embed=true or when the content should be directly in the JACS document (hooks, small configs). For larger files, use jacsFiles reference instead."
    },
    "jacsAgentStateTags": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Tags for categorization and search."
    },
    "jacsAgentStateOrigin": {
      "type": "string",
      "enum": ["authored", "adopted", "generated", "imported"],
      "description": "How this state document was created. 'authored' = created by the signing agent. 'adopted' = unsigned file found and signed by adopting agent. 'generated' = produced by an AI/automation. 'imported' = brought in from another JACS installation."
    },
    "jacsAgentStateSourceUrl": {
      "type": "string",
      "format": "uri",
      "description": "Where the original content was obtained from, if applicable (e.g., AgentSkills.io URL, ClawHub URL, git repo)."
    }
  },
  "required": [
    "jacsAgentStateType",
    "jacsAgentStateName"
  ]
}
```

### How `jacsFiles` Provides the File Reference

The existing `jacsFiles` array from `header.schema.json` handles file references:

```json
{
  "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
  "jacsId": "uuid-of-signed-doc",
  "jacsVersion": "version-uuid",
  "jacsType": "agentstate",
  "jacsLevel": "config",
  "jacsAgentStateType": "skill",
  "jacsAgentStateName": "jacs-signing",
  "jacsAgentStateDescription": "Cryptographic document signing and verification with JACS",
  "jacsAgentStateFramework": "openclaw",
  "jacsAgentStateContentType": "text/markdown",
  "jacsAgentStateOrigin": "authored",
  "jacsAgentStateSourceUrl": "https://agentskills.io/skills/jacs-signing",
  "jacsAgentStateTags": ["crypto", "signing", "security"],
  "jacsFiles": [
    {
      "mimetype": "text/markdown",
      "path": "./skills/jacs/SKILL.md",
      "embed": false,
      "sha256": "a1b2c3d4..."
    }
  ],
  "jacsSignature": { "..." : "..." }
}
```

### How Embedded Content Works (for Hooks)

Hooks contain executable code that MUST be signed in full. The content is embedded:

```json
{
  "$schema": "https://hai.ai/schemas/agentstate/v1/agentstate.schema.json",
  "jacsType": "agentstate",
  "jacsLevel": "config",
  "jacsAgentStateType": "hook",
  "jacsAgentStateName": "pre-commit-lint",
  "jacsAgentStateDescription": "Runs linting before every commit",
  "jacsAgentStateFramework": "claude-code",
  "jacsAgentStateContentType": "application/json",
  "jacsAgentStateOrigin": "authored",
  "jacsAgentStateContent": "{\"event\":\"PreToolUse\",\"matcher\":{\"tool_name\":\"Bash\"},\"command\":\"npm run lint\"}",
  "jacsFiles": [
    {
      "mimetype": "application/json",
      "path": "./.claude/settings.json",
      "embed": true,
      "contents": "base64-encoded-full-settings-file",
      "sha256": "e5f6g7h8..."
    }
  ],
  "jacsSignature": { "..." : "..." }
}
```

### How Adoption Works (Unsigned -> Signed)

When an agent finds an unsigned SKILL.md and decides to use it:

1. Agent reads the SKILL.md content
2. Agent creates a JACS agentstate document with `jacsAgentStateOrigin: "adopted"`
3. Agent signs the document -- proving "I chose to adopt this skill at this time"
4. The `jacsFiles` reference includes the SHA-256 hash of the original file
5. If the SKILL.md is later modified, JACS can detect the hash mismatch
6. The agent re-signs after reviewing the changes (or rejects them)

### The Agent State Lifecycle

```
1. CREATE: Agent writes SKILL.md (or receives one)
      |
      v
2. SIGN: JACS MCP tool creates agentstate document
         - References SKILL.md by path + SHA-256
         - Signs with agent's key
         - Stores in JACS storage (filesystem, database, etc.)
      |
      v
3. READ: Agent needs to use the skill
         - JACS MCP tool loads the signed document
         - Verifies signature is valid
         - Verifies SHA-256 of original file matches
         - Returns content (from file or embedded)
      |
      v
4. UPDATE: Agent modifies SKILL.md
         - JACS detects hash mismatch on next read
         - Agent re-signs (new jacsVersion, new SHA-256)
         - Previous version preserved via jacsPreviousVersion chain
      |
      v
5. VERIFY: Another agent or auditor checks the file
         - Loads signed document
         - Verifies signing agent's identity
         - Verifies file hash matches current content
         - Reports: "Agent X signed this file at time T, content is [unchanged|modified]"
```

---

## Type-Specific Details

### MEMORY Documents

**What they wrap**: MEMORY.md, CLAUDE.md, AGENTS.md -- project context files.

**Key properties**:
- `jacsAgentStateType: "memory"`
- `jacsLevel: "config"` (mutable, re-signed on change)
- Typically NOT embedded (markdown files can be large)
- Re-signed frequently as context evolves
- Version chain provides memory evolution history

**Example use cases**:
- Claude Code's MEMORY.md containing project-specific patterns
- CLAUDE.md with team coding conventions
- Project-specific context that an agent accumulates over time

**Framework mapping**:
| Framework | File | JACS Wraps |
|-----------|------|------------|
| Claude Code | `~/.claude/projects/.../memory/MEMORY.md` | Memory doc referencing the file |
| Claude Code | `./CLAUDE.md` | Memory doc referencing project root file |
| OpenAI Codex | `./AGENTS.md` | Memory doc referencing project root file |
| LangGraph | checkpoint JSON | Memory doc embedding checkpoint data |

### SKILL Documents

**What they wrap**: SKILL.md files, tool definitions, capability declarations.

**Key properties**:
- `jacsAgentStateType: "skill"`
- `jacsLevel: "config"` (versioned, updated when skill changes)
- Can reference the entire skill directory (SKILL.md + scripts/ + references/ + assets/)
- `jacsFiles` array can include multiple entries (main SKILL.md + supporting files)
- `jacsAgentStateOrigin` distinguishes authored vs adopted skills

**Supporting files**:
```json
"jacsFiles": [
  { "mimetype": "text/markdown", "path": "./skills/jacs/SKILL.md", "embed": false, "sha256": "..." },
  { "mimetype": "text/x-shellscript", "path": "./skills/jacs/scripts/sign.sh", "embed": true, "contents": "...", "sha256": "..." },
  { "mimetype": "text/markdown", "path": "./skills/jacs/references/api-docs.md", "embed": false, "sha256": "..." }
]
```

**Framework mapping**:
| Framework | File | JACS Wraps |
|-----------|------|------------|
| Claude Code / AgentSkills.io | `SKILL.md` + directory | Skill doc with multi-file refs |
| OpenClaw | `SKILL.md` in plugin | Skill doc referencing plugin skill |
| LangChain | Tool definition (Python) | Skill doc embedding definition |

### PLAN Documents

**What they wrap**: Plan files, structured task lists, project roadmaps.

**Key properties**:
- `jacsAgentStateType: "plan"`
- `jacsLevel: "config"` (mutable, re-signed as plan evolves)
- Plans are conceptually close to JACS todo lists but can also wrap any planning format
- When the JACS native todo.schema.json is available (Phase 1), plans can be expressed as JACS todo lists directly -- but the agentstate wrapper still works for non-JACS plan formats

**Framework mapping**:
| Framework | File | JACS Wraps |
|-----------|------|------------|
| Claude Code | `~/.claude/plans/*.md` | Plan doc referencing plan file |
| OpenAI Codex | `PLANS.md` | Plan doc referencing plan file |
| Generic | Any structured plan | Plan doc with embedded content |

### CONFIG Documents

**What they wrap**: Configuration files, settings, environment templates.

**Key properties**:
- `jacsAgentStateType: "config"`
- `jacsLevel: "config"`
- Often JSON or YAML
- Signing configs proves WHO set the configuration and WHEN
- Useful for audit trails: "Agent X configured this system at time T with these settings"
- **SECURITY NOTE**: Configs may contain sensitive values. The `embed` field controls whether content is stored in the JACS document. For sensitive configs, reference by path + hash without embedding.

**Framework mapping**:
| Framework | File | JACS Wraps |
|-----------|------|------------|
| Claude Code | `settings.json` | Config doc referencing settings |
| OpenClaw | `openclaw.plugin.json` | Config doc referencing plugin config |
| JACS | `jacs.config.json` | Config doc referencing JACS config |
| Generic | `.env.template`, `config.yaml` | Config doc (NOT `.env` -- never sign secrets) |

### HOOK Documents

**What they wrap**: Hook definitions, automated triggers, pre/post-operation scripts.

**Key properties**:
- `jacsAgentStateType: "hook"`
- `jacsLevel: "config"`
- **ALWAYS embedded** -- hook code must be signed in full because it's executable
- Signing proves WHO authorized this code to run in the agent's environment
- Critical security feature: prevents unauthorized hook injection
- Hook definitions include trigger conditions AND the code to execute

**Why full embedding is essential for hooks**:
A hook like "on every Bash command, run this shell script" has security implications. If only the file path + hash is stored, an attacker could replace the script between signing and execution. Embedding the full code in the signed document ensures the EXACT code that was authorized is what runs. The hash of the original file is ALSO stored for cross-verification.

**Framework mapping**:
| Framework | File | JACS Wraps |
|-----------|------|------------|
| Claude Code | hooks in `settings.json` | Hook doc embedding hook definition |
| OpenClaw | PreToolUse/PostToolUse hooks | Hook doc embedding hook code |
| Generic | git hooks, CI triggers | Hook doc embedding script content |

---

## MCP Tools for Agent State

### New MCP Tools (jacs-mcp and moltyjacs)

**Tool: `jacs_sign_state`** -- Sign an agent state file
- Input: `file_path` (path to original file), `state_type` (memory/skill/plan/config/hook), `name`, `description`, optional `framework`, optional `tags`
- Behavior: Reads file, computes SHA-256, creates agentstate document, signs with agent key, stores in JACS storage
- For hooks: always embeds content. For other types: embeds if file is small (<10KB) or `embed: true` specified
- Returns: JACS document ID

**Tool: `jacs_verify_state`** -- Verify a signed agent state file
- Input: `file_path` (path to original file) OR `jacs_id` (JACS document ID)
- Behavior: Loads signed document, verifies signature, compares SHA-256 with current file content
- Returns: verification status, signing agent ID, sign time, hash match status, content match status

**Tool: `jacs_load_state`** -- Load a signed agent state file with verification
- Input: `file_path` OR `jacs_id`, optional `require_verified` (default: true)
- Behavior: Loads signed document, verifies if required, returns content. If hash mismatch detected, returns warning with diff summary
- Returns: content, verification status, warnings

**Tool: `jacs_update_state`** -- Update and re-sign an agent state file
- Input: `file_path`, `new_content` (optional -- if omitted, re-signs current content)
- Behavior: Writes new content to original file, recomputes SHA-256, creates new version of signed document, signs
- Returns: new JACS document version ID

**Tool: `jacs_list_state`** -- List signed agent state documents
- Input: optional `state_type` filter, optional `framework` filter, optional `tags` filter
- Returns: list of signed state documents with metadata

**Tool: `jacs_adopt_state`** -- Adopt an unsigned file by signing it
- Input: `file_path`, `state_type`, `name`, optional `source_url`
- Behavior: Like `jacs_sign_state` but sets `jacsAgentStateOrigin: "adopted"` and records source URL
- Returns: JACS document ID

---

## Implementation Steps

### Phase 0A: Schema and CRUD (Steps 0.1 - 0.15)

**Step 0.1.** Write test `test_create_minimal_agentstate` in `jacs/tests/agentstate_tests.rs`.
- **Why**: TDD. Test the simplest signed agent state document.
- **What**: Call `create_minimal_agentstate("memory", "Project Memory", None)`, assert `jacsType` = "agentstate", `jacsAgentStateType` = "memory", `jacsAgentStateName` = "Project Memory".

**Step 0.2.** Write test `test_agentstate_all_valid_types` -- every state type accepted.
- **Why**: Positive test covering all 5 types.
- **What**: For each of `memory`, `skill`, `plan`, `config`, `hook`: create agentstate, validate, assert success.

**Step 0.3.** Write test `test_agentstate_invalid_type` -- rejects unknown state type.
- **Why**: Negative test for enum validation.
- **What**: Set `jacsAgentStateType` to "invalid", validate, expect error.

**Step 0.4.** Write test `test_agentstate_with_file_reference` -- references an external file.
- **Why**: Core use case: signed wrapper references original file.
- **What**: Create agentstate with `jacsFiles` containing path and SHA-256 of a test fixture file. Validate.

**Step 0.5.** Write test `test_agentstate_with_embedded_content` -- inline content for hooks.
- **Why**: Hooks must embed their content.
- **What**: Create agentstate with `jacsAgentStateContent` containing a shell script. `jacsFiles[0].embed: true`. Validate.

**Step 0.6.** Write test `test_agentstate_file_hash_verification` -- SHA-256 matches file content.
- **Why**: The integrity check that makes signing meaningful.
- **What**: Create agentstate referencing a file, modify the file, verify hash mismatch detected.

**Step 0.7.** Write test `test_agentstate_all_valid_origins` -- every origin type accepted.
- **Why**: Positive test for origin enum.
- **What**: For each of `authored`, `adopted`, `generated`, `imported`: create, validate.

**Step 0.8.** Write test `test_agentstate_with_source_url` -- URL reference for adopted skills.
- **Why**: Tracking where adopted content came from.
- **What**: Create agentstate with `jacsAgentStateSourceUrl: "https://agentskills.io/skills/foo"`, validate.

**Step 0.9.** Write test `test_agentstate_with_tags` -- tag array.
- **Why**: Tags enable search and categorization.
- **What**: Create agentstate with tags, validate.

**Step 0.10.** Write test `test_agentstate_missing_required_name` -- rejects missing name.
- **Why**: Negative test. Name is required.
- **What**: Create without `jacsAgentStateName`, validate, expect error.

**Step 0.11.** Write test `test_agentstate_missing_required_type` -- rejects missing state type.
- **Why**: Negative test. State type is required.
- **What**: Create without `jacsAgentStateType`, validate, expect error.

**Step 0.12.** Create schema file `jacs/schemas/agentstate/v1/agentstate.schema.json`.
- **Why**: Define the JSON Schema for agent state documents.
- **What**: As specified in the Architecture section above.

**Step 0.13.** Add agentstate schema to `Cargo.toml` include list, `DEFAULT_SCHEMA_STRINGS`, `SCHEMA_SHORT_NAME`.

**Step 0.14.** Add `agentstateschema: Validator` to `Schema` struct, compile in `Schema::new()`, add `validate_agentstate()` method.

**Step 0.15.** Create `src/schema/agentstate_crud.rs`:
- `create_minimal_agentstate(state_type: &str, name: &str, description: Option<&str>) -> Result<Value, String>`
- `create_agentstate_with_file(state_type: &str, name: &str, file_path: &str, embed: bool) -> Result<Value, String>` -- reads file, computes SHA-256, creates document with jacsFiles reference
- `create_agentstate_with_content(state_type: &str, name: &str, content: &str, content_type: &str) -> Result<Value, String>` -- inline content
- `set_agentstate_framework(doc: &mut Value, framework: &str) -> Result<(), String>`
- `set_agentstate_origin(doc: &mut Value, origin: &str, source_url: Option<&str>) -> Result<(), String>`
- `set_agentstate_tags(doc: &mut Value, tags: Vec<&str>) -> Result<(), String>`
- `verify_agentstate_file_hash(doc: &Value) -> Result<bool, String>` -- checks SHA-256 of referenced file
- Add `pub mod agentstate_crud;` to `src/schema/mod.rs`.

### Phase 0B: Signing and Verification Pipeline (Steps 0.16 - 0.25)

**Step 0.16.** Write test `test_agentstate_signing_and_verification` -- full signing pipeline.
- **Why**: Agent state docs must participate in standard JACS signing.
- **What**: Create agentstate, sign via agent, verify signature.

**Step 0.17.** Write test `test_agentstate_resign_on_content_change` -- update and re-sign.
- **Why**: When the original file changes, the signed document must be re-signed.
- **What**: Create and sign agentstate, modify referenced file, re-sign (new jacsVersion), verify new hash and signature.

**Step 0.18.** Write test `test_agentstate_version_chain` -- version history preserved.
- **Why**: Version chain tracks evolution of agent state over time.
- **What**: Create, sign, update content, re-sign. Verify `jacsPreviousVersion` points to first version.

**Step 0.19.** Write test `test_agentstate_adoption_workflow` -- adopt unsigned file.
- **Why**: Core use case: agent finds unsigned SKILL.md and signs it.
- **What**: Create unsigned test file. Call adoption CRUD. Verify origin = "adopted", file hash matches, agent signed.

**Step 0.20.** Write test `test_agentstate_hook_always_embeds` -- hook content always embedded.
- **Why**: Security requirement: hook code must be in the signed document.
- **What**: Create hook agentstate. Verify `jacsAgentStateContent` is populated even when `embed: false` was requested. Verify `jacsFiles[0].embed: true`.

**Step 0.21.** Write test `test_agentstate_multi_file_skill` -- skill with directory of files.
- **Why**: Skills have supporting files (scripts/, references/, assets/).
- **What**: Create skill agentstate with 3 jacsFiles entries (SKILL.md, script, reference). Verify all hashes.

**Step 0.22.** Write test `test_agentstate_detect_tampered_file` -- modified file detected.
- **Why**: Critical security test. Proves that file modification after signing is detectable.
- **What**: Sign a file. Modify the file without re-signing. Call verify. Expect hash mismatch warning.

**Step 0.23.** Write test `test_agentstate_header_fields_present` -- verify all header fields.
- **Why**: Ensure agentstate properly inherits header fields.
- **What**: Create and sign. Verify jacsId, jacsVersion, jacsVersionDate, etc.

**Step 0.24.** Write test `test_agentstate_different_content_types` -- various MIME types.
- **Why**: Agent state files span many formats.
- **What**: Create agentstate for each: text/markdown (MEMORY.md), application/yaml (SKILL.md frontmatter), application/json (settings.json), text/x-shellscript (hook script). Verify all sign correctly.

**Step 0.25.** Run all agentstate tests + regression: `cargo test`.

### Phase 0C: MCP Tools (Steps 0.26 - 0.35)

**Step 0.26.** Add MCP tool `jacs_sign_state` to jacs-mcp.
- **What**: Accepts file path + type + name, creates signed agentstate document. Auto-embeds for hooks.

**Step 0.27.** Add MCP tool `jacs_verify_state` to jacs-mcp.
- **What**: Accepts file path or JACS ID, returns verification status including hash comparison.

**Step 0.28.** Add MCP tool `jacs_load_state` to jacs-mcp.
- **What**: Loads signed state file with optional verification. Returns content and status.

**Step 0.29.** Add MCP tool `jacs_update_state` to jacs-mcp.
- **What**: Updates file content and re-signs. Creates new jacsVersion.

**Step 0.30.** Add MCP tool `jacs_list_state` to jacs-mcp.
- **What**: Lists all signed state documents with filters (type, framework, tags).

**Step 0.31.** Add MCP tool `jacs_adopt_state` to jacs-mcp.
- **What**: Adopts unsigned file. Sets origin to "adopted", records source URL.

**Step 0.32.** Write MCP integration test `test_mcp_sign_and_verify_memory`.
- **What**: Full round-trip: sign MEMORY.md, verify, load content.

**Step 0.33.** Write MCP integration test `test_mcp_sign_and_verify_skill`.
- **What**: Full round-trip with multi-file skill directory.

**Step 0.34.** Write MCP integration test `test_mcp_sign_and_detect_tampered_hook`.
- **What**: Sign hook, modify hook file, verify detects tampering.

**Step 0.35.** Add same tools to moltyjacs (OpenClaw plugin).
- **What**: Mirror MCP tools in OpenClaw plugin format: `jacs_sign_state`, `jacs_verify_state`, `jacs_load_state`, `jacs_update_state`, `jacs_adopt_state`.

### Phase 0D: Developer Documentation and Examples (Steps 0.36 - 0.40)

**Step 0.36.** Create `docs/signed-agent-state.md` -- comprehensive developer guide.
- **Why**: Documentation is a first-class deliverable. Devs need to understand WHY and HOW to use signed state files.
- **What**: Sections: Why Sign Agent State, Quick Start (3 commands to sign a SKILL.md), Framework Integration Guide (Claude Code, OpenClaw, LangChain), Security Model (what signing proves, threat model), Migration Guide (moving from unsigned to signed files).

**Step 0.37.** Create example: `examples/sign-claude-memory/` -- sign a CLAUDE.md file.
- **What**: Minimal example showing: create CLAUDE.md, sign with JACS, verify, modify, re-sign.

**Step 0.38.** Create example: `examples/sign-skill-directory/` -- sign a SKILL.md with scripts.
- **What**: Full skill directory example with SKILL.md + scripts/ + references/. Shows multi-file signing.

**Step 0.39.** Create example: `examples/adopt-unsigned-skill/` -- adopt an unsigned skill.
- **What**: Shows the adoption workflow: find unsigned file, sign as adopter, verify later.

**Step 0.40.** Add agentstate CRUD to Python bindings (`jacspy/`), Node bindings (`jacsnpm/`), and update MCP server README.
- **What**: Expose `create_agentstate`, `sign_state`, `verify_state`, `load_state` in all language bindings.

---

## Key Design Decisions for Phase 0

### Decision P0-1: Generic Schema, Not Per-Type Schemas
**Choice**: One `agentstate.schema.json` with `jacsAgentStateType` enum, not separate `memory.schema.json`, `skill.schema.json`, etc.
**Why**: All agent state types share the same signing mechanics (file reference, hash, embed). Per-type schemas would create 5 schemas with 90% identical fields. The `jacsAgentStateType` enum provides type discrimination without schema proliferation.

### Decision P0-2: `jacsFiles` for File References, Not Custom Fields
**Choice**: Reuse the existing `jacsFiles` array from header for file path + hash + embed, not new custom fields.
**Why**: `jacsFiles` already has exactly the right structure: `path`, `sha256`, `mimetype`, `embed`, `contents`. Reusing it means no schema changes to header and consistent file handling across all JACS document types.

### Decision P0-3: Hooks Always Embed Content
**Choice**: Hook-type agentstate documents MUST embed their code content, regardless of the `embed` flag.
**Why**: Hooks are executable code. If only referenced by path + hash, the file could be swapped between signing and execution (TOCTOU attack). Embedding ensures the signed document contains the exact code that was authorized. The hash of the original file is also stored for cross-verification.

### Decision P0-4: Origin Tracking for Trust Differentiation
**Choice**: `jacsAgentStateOrigin` distinguishes authored, adopted, generated, and imported content.
**Why**: "I wrote this skill" (authored) is a different trust statement than "I found this skill and decided to use it" (adopted) or "My AI generated this memory" (generated). Mediation and audit trails need to know the provenance of agent state.

### Decision P0-5: Framework Field for Cross-Platform Compatibility
**Choice**: `jacsAgentStateFramework` records which agent framework the file is for.
**Why**: The same agent might use skills from Claude Code AND OpenClaw. The framework field enables filtering ("show me all my Claude Code memories") and helps tooling know how to interpret the content (SKILL.md format vs Python tool definition).

---

## Test Coverage Matrix (Phase 0)

| Category | Positive Tests | Negative Tests | Integration Tests |
|----------|---------------|----------------|-------------------|
| Schema | minimal, all 5 types, all 4 origins, file ref, embedded, multi-file, tags, source URL, content types | invalid type, invalid origin, missing name, missing type | signing, resign, version chain, adoption, tamper detection, header fields |
| MCP | sign + verify memory, sign + verify skill, tamper detection hook | (invalid inputs via MCP) | full round-trip for each type |
| Bindings | Python create/sign/verify, Node create/sign/verify | -- | cross-language verification |
