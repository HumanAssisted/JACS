# Phase 4: MCP & Bindings Integration (Steps 226-261)

**Parent**: [NEW_FEATURES.md](./NEW_FEATURES.md) (Index)

**Status**: Not started
**Step Range**: 226-261
**Summary**: Expose all new todo/commitment/update/conversation functionality as MCP tools, implement language bindings for Python/Node/Go, and add CLI integration for all document types.

---

## Phase 4A: MCP Server Tools (Steps 226-242)

**Step 226.** Add MCP tool: `create_todo_list` -- creates and signs a new todo list.

**Step 227.** Add MCP tool: `add_todo_item` -- adds item to list, re-signs.

**Step 228.** Add MCP tool: `complete_todo_item` -- marks complete, re-signs.

**Step 229.** Add MCP tool: `get_todo_list` -- retrieves a todo list by ID.

**Step 230.** Add MCP tool: `archive_completed_items` -- moves completed items to archive list.

**Step 231.** Add MCP tool: `create_commitment` -- creates a commitment document.

**Step 232.** Add MCP tool: `sign_commitment` -- agent signs agreement.

**Step 233.** Add MCP tool: `verify_commitment` -- verifies all signatures.

**Step 234.** Add MCP tool: `list_commitments` -- list with optional status filter.

**Step 235.** Add MCP tool: `create_update` -- creates a semantic update document.

**Step 236.** Add MCP tool: `get_updates_for_target` -- all updates targeting a document.

**Step 237.** Add MCP tool: `get_update_chain` -- ordered update chain for a target.

**Step 238.** Add MCP tool: `send_message` -- signed message in conversation thread.

**Step 239.** Add MCP tool: `get_conversation` -- all messages in a thread.

**Step 240.** Add MCP tool: `find_overdue_commitments` -- query for past-deadline commitments.

**Step 241.** Add MCP tool: `search_documents` -- text/semantic search.

**Step 242.** Write MCP integration tests for all tools.

---

## Phase 4B: Language Bindings (Steps 243-257)

**Step 243-247.** Python bindings (`jacspy/`): implement all todo/commitment/update/conversation functions + MCP server examples.

**Step 248-252.** Node bindings (`jacsnpm/`): implement all functions + MCP server examples.

**Step 253-255.** Go bindings (`jacsgo/`): implement core functions.

**Step 256-257.** Run all binding test suites.

---

## Phase 4C: CLI Integration (Steps 258-261)

**Step 258.** CLI: `jacs todo create/list/complete/archive`
**Step 259.** CLI: `jacs commitment create/list/sign/verify/dispute`
**Step 260.** CLI: `jacs update create/list/chain`
**Step 261.** CLI: `jacs conversation start/reply/list`
