"""Tests for jacs.adapters.mcp — MCP tool registration and middleware."""

import json
import os
from unittest.mock import MagicMock

import pytest

fastmcp = pytest.importorskip("fastmcp")

from jacs.adapters.mcp import (  # noqa: E402
    register_jacs_tools,
    register_a2a_tools,
    register_trust_tools,
    JacsMCPMiddleware,
    _validate_mcp_file_path,
    _is_untrust_allowed,
)
from jacs.client import JacsClient  # noqa: E402
from conftest import TEST_ALGORITHM, TEST_ALGORITHM_INTERNAL  # noqa: E402


@pytest.fixture
def client():
    return JacsClient.ephemeral(algorithm=TEST_ALGORITHM)


# ---------------------------------------------------------------------------
# Fake FastMCP server for testing tool registration
# ---------------------------------------------------------------------------


class FakeMCP:
    """Minimal stand-in for FastMCP that captures tool registrations."""

    def __init__(self):
        self.tools = {}

    def tool(self, name: str = "", description: str = ""):
        def decorator(fn):
            self.tools[name] = {"fn": fn, "description": description}
            return fn

        return decorator

    def add_middleware(self, mw):
        self.middleware = mw


# ---------------------------------------------------------------------------
# register_jacs_tools — tool registration
# ---------------------------------------------------------------------------


class TestRegisterJacsTools:
    def test_registers_all_tools_by_default(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        expected = {
            "jacs_sign_document",
            "jacs_verify_document",
            "jacs_sign_file",
            "jacs_verify_self",
            "jacs_create_agreement",
            "jacs_sign_agreement",
            "jacs_check_agreement",
            "jacs_agent_info",
            "jacs_share_public_key",
            "jacs_export_agent",
            "jacs_share_agent",
            # v0.10.0 inline-text + media tools
            "jacs_sign_text",
            "jacs_verify_text",
            "jacs_sign_image",
            "jacs_verify_image",
            "jacs_extract_media_signature",
        }
        assert set(mcp.tools.keys()) == expected

    def test_registers_subset_of_tools(self, client):
        mcp = FakeMCP()
        register_jacs_tools(
            mcp, client=client, tools=["sign_document", "verify_document"]
        )
        assert "jacs_sign_document" in mcp.tools
        assert "jacs_verify_document" in mcp.tools
        assert len(mcp.tools) == 2

    def test_unknown_tool_raises_value_error(self, client):
        mcp = FakeMCP()
        with pytest.raises(ValueError, match="Unknown tool names"):
            register_jacs_tools(mcp, client=client, tools=["nonexistent"])

    def test_returns_mcp_server(self, client):
        mcp = FakeMCP()
        result = register_jacs_tools(mcp, client=client)
        assert result is mcp

    @pytest.mark.parametrize(
        ("registrar", "tool_name", "client_method", "arguments"),
        [
            (register_jacs_tools, "jacs_sign_document", "sign_message", ("{}",)),
            (register_a2a_tools, "jacs_export_agent_card", "export_agent_card", ()),
            (register_trust_tools, "jacs_trust_agent", "trust_agent", ("{}",)),
        ],
    )
    def test_strict_registration_reraises_tool_failures(
        self, registrar, tool_name, client_method, arguments
    ):
        failing_client = MagicMock()
        getattr(failing_client, client_method).side_effect = ValueError(
            "operation unavailable"
        )
        mcp = FakeMCP()
        registrar(mcp, client=failing_client, strict=True)

        with pytest.raises(ValueError, match="operation unavailable"):
            mcp.tools[tool_name]["fn"](*arguments)


# ---------------------------------------------------------------------------
# jacs_sign_document tool
# ---------------------------------------------------------------------------


class TestSignDocumentTool:
    def test_signs_json_content(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_document"]["fn"]

        result = fn(json.dumps({"message": "hello"}))
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_signed_content_is_verifiable(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        sign_fn = mcp.tools["jacs_sign_document"]["fn"]
        verify_fn = mcp.tools["jacs_verify_document"]["fn"]

        signed = sign_fn(json.dumps({"data": "test"}))
        result = json.loads(verify_fn(signed))
        assert result["success"] is True
        assert result["valid"] is True

    def test_invalid_json_returns_error(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_document"]["fn"]

        result = fn("not valid json")
        parsed = json.loads(result)
        assert parsed["success"] is False

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            '{"plain":true}',
            '{"jacsId":"d","jacsVersion":"1","jacsSignature":'
            '{"signature":"s","agentID":"a","agentVersion":"1",'
            '"publicKeyHash":"h","date":"now",'
            '"signatureContentVersion":"jacs-signature-v1"}}',
        ],
    )
    def test_sign_document_rejects_malformed_native_output(self, raw):
        malformed_client = MagicMock()
        malformed_client.sign_message.return_value.raw = raw
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=malformed_client, strict=True)

        with pytest.raises(ValueError, match="portable v2"):
            mcp.tools["jacs_sign_document"]["fn"]("{}")


# ---------------------------------------------------------------------------
# jacs_verify_document tool
# ---------------------------------------------------------------------------


class TestVerifyDocumentTool:
    def test_verifies_valid_document(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        signed = client.sign_message({"test": True})

        fn = mcp.tools["jacs_verify_document"]["fn"]
        result = json.loads(fn(signed.raw))
        assert result["success"] is True
        assert result["valid"] is True
        assert result["signer_id"] == client.agent_id

    def test_rejects_invalid_json(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_verify_document"]["fn"]
        result = json.loads(fn("not a signed document"))
        assert result.get("valid") is False or result.get("success") is False


# ---------------------------------------------------------------------------
# jacs_verify_self tool
# ---------------------------------------------------------------------------


class TestVerifySelfTool:
    def test_verify_self_succeeds(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_verify_self"]["fn"]

        result = json.loads(fn())
        assert result["success"] is True
        assert result["valid"] is True
        assert result["agent_id"] == client.agent_id


# ---------------------------------------------------------------------------
# jacs_agent_info tool
# ---------------------------------------------------------------------------


class TestAgentInfoTool:
    def test_returns_agent_info(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_agent_info"]["fn"]

        result = json.loads(fn())
        assert result["success"] is True
        assert result["agent_id"] == client.agent_id
        assert "config_path" not in result
        assert "public_key_path" not in result

    def test_export_agent_alias_returns_agent_info(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_export_agent"]["fn"]

        result = json.loads(fn())
        assert result["success"] is True
        assert "agent_json" in result


# ---------------------------------------------------------------------------
# jacs_create_agreement / jacs_sign_agreement / jacs_check_agreement
# ---------------------------------------------------------------------------


class TestAgreementTools:
    @pytest.fixture
    def persistent_client(self, tmp_path, monkeypatch):
        """Agreements require a persistent (non-ephemeral) client."""
        monkeypatch.chdir(tmp_path)
        return JacsClient.quickstart(
            name="mcp-agreement-agent",
            domain="mcp-agreement.example",
            algorithm=TEST_ALGORITHM_INTERNAL,
            config_path=str(tmp_path / "jacs.config.json"),
        )

    def test_create_agreement(self, persistent_client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=persistent_client)
        fn = mcp.tools["jacs_create_agreement"]["fn"]

        result = fn(
            document=json.dumps({"proposal": "test"}),
            agent_ids=json.dumps([persistent_client.agent_id]),
        )
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_sign_and_check_agreement(self, persistent_client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=persistent_client)

        # Create
        create_fn = mcp.tools["jacs_create_agreement"]["fn"]
        agreement = create_fn(
            document=json.dumps({"proposal": "sign me"}),
            agent_ids=json.dumps([persistent_client.agent_id]),
        )

        # Sign
        sign_fn = mcp.tools["jacs_sign_agreement"]["fn"]
        signed = sign_fn(agreement)
        assert json.loads(signed)  # valid JSON

        # Check
        check_fn = mcp.tools["jacs_check_agreement"]["fn"]
        status = json.loads(check_fn(signed))
        assert status["success"] is True
        assert status["complete"] is True
        assert isinstance(status["signers"], list)


# ---------------------------------------------------------------------------
# JacsMCPMiddleware
# ---------------------------------------------------------------------------


class TestJacsMCPMiddleware:
    def test_can_instantiate(self, client):
        mw = JacsMCPMiddleware(client=client)
        assert mw._sign is True
        assert mw._verify is False

    def test_can_disable_signing(self, client):
        mw = JacsMCPMiddleware(client=client, sign_tool_results=False)
        assert mw._sign is False

    def test_can_enable_verification(self, client):
        mw = JacsMCPMiddleware(client=client, verify_tool_inputs=True)
        assert mw._verify is True

    @pytest.mark.parametrize(
        "signed_argument",
        [
            '{ "jacsSignature" : {"signature":"test"}, "content": 1 }',
            {"jacsSignature": {"signature": "test"}, "content": 1},
        ],
    )
    async def test_real_fastmcp_context_dispatches_and_structurally_verifies_inputs(
        self, client, signed_argument
    ):
        from fastmcp.server.middleware import MiddlewareContext
        from mcp.types import CallToolRequestParams

        mw = JacsMCPMiddleware(
            client=client,
            verify_tool_inputs=True,
            sign_tool_results=False,
        )
        mw._adapter.verify_input = MagicMock(return_value={"verified": "payload"})
        context = MiddlewareContext(
            message=CallToolRequestParams(
                name="example",
                arguments={"input": signed_argument},
            ),
            method="tools/call",
        )

        async def call_next(received_context):
            assert received_context.message.arguments == {
                "input": {"verified": "payload"}
            }
            return "tool-result"

        assert await mw(context, call_next) == "tool-result"
        mw._adapter.verify_input.assert_called_once()

    async def test_real_tool_result_remains_fastmcp_compatible_and_signed(
        self, client
    ):
        from fastmcp.server.middleware import MiddlewareContext
        from fastmcp.tools.tool import ToolResult
        from mcp.types import CallToolRequestParams

        mw = JacsMCPMiddleware(client=client)
        context = MiddlewareContext(
            message=CallToolRequestParams(name="example", arguments={}),
            method="tools/call",
        )

        async def call_next(_context):
            return ToolResult(
                content="raw output",
                structured_content={"value": 7},
                meta={"source": "test"},
            )

        result = await mw(context, call_next)

        assert isinstance(result, ToolResult)
        assert result.structured_content == {"value": 7}
        assert result.content[0].text == "raw output"
        assert result.meta["source"] == "test"
        signed_document = result.meta["jacsSignedDocument"]
        signed_json = json.dumps(signed_document)
        assert client.verify(signed_json).valid is True
        verified_payload = mw._adapter.verify_input(signed_json)
        assert verified_payload["jacsDocument"]["content"] == {
            "content": [
                {"type": "text", "text": "raw output"},
            ],
            "structuredContent": {"value": 7},
            "meta": {"source": "test"},
        }
        mcp_result = result.to_mcp_result()
        assert mcp_result.structuredContent == {"value": 7}
        assert mcp_result.meta["jacsSignedDocument"] == signed_document

    async def test_create_task_result_keeps_protocol_type_and_attaches_proof(
        self, client
    ):
        from datetime import datetime, timezone

        from fastmcp.server.middleware import MiddlewareContext
        from mcp.types import CallToolRequestParams, CreateTaskResult, Task

        mw = JacsMCPMiddleware(client=client)
        context = MiddlewareContext(
            message=CallToolRequestParams(name="example", arguments={}),
            method="tools/call",
        )
        now = datetime.now(timezone.utc)
        original = CreateTaskResult(
            task=Task(
                taskId="task-1",
                status="working",
                createdAt=now,
                lastUpdatedAt=now,
                ttl=None,
            ),
            _meta={"source": "task-test"},
        )

        async def call_next(_context):
            return original

        result = await mw(context, call_next)

        assert isinstance(result, CreateTaskResult)
        assert result.task == original.task
        assert result.meta["source"] == "task-test"
        proof = result.meta["jacsSignedDocument"]
        assert client.verify(json.dumps(proof)).valid is True
        verified_payload = mw._adapter.verify_input(json.dumps(proof))
        assert verified_payload["jacsDocument"]["content"] == original.model_dump(
            by_alias=True,
            mode="json",
            exclude_none=True,
        )

    async def test_on_call_tool_signs_result(self, client):
        mw = JacsMCPMiddleware(client=client)

        class FakeContext:
            arguments = {}

        async def call_next(ctx):
            return json.dumps({"result": "data"})

        result = await mw.on_call_tool(FakeContext(), call_next)
        # Result should be a signed string
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    async def test_on_call_tool_passthrough_when_disabled(self, client):
        mw = JacsMCPMiddleware(client=client, sign_tool_results=False)

        class FakeContext:
            arguments = {}

        original = json.dumps({"result": "data"})

        async def call_next(ctx):
            return original

        result = await mw.on_call_tool(FakeContext(), call_next)
        assert result == original

    async def test_signing_failure_fails_closed_by_default(self, client):
        mw = JacsMCPMiddleware(client=client)
        mw._adapter.sign_output = lambda _value: (_ for _ in ()).throw(
            ValueError("signing unavailable")
        )

        class FakeContext:
            arguments = {}

        async def call_next(ctx):
            return '{"secret":"downstream output"}'

        with pytest.raises(ValueError, match="signing unavailable"):
            await mw.on_call_tool(FakeContext(), call_next)

    async def test_unsigned_output_requires_explicit_opt_in(self, client):
        mw = JacsMCPMiddleware(client=client, allow_unsigned_output=True)
        mw._adapter.sign_output = lambda _value: (_ for _ in ()).throw(
            ValueError("signing unavailable")
        )

        class FakeContext:
            arguments = {}

        async def call_next(ctx):
            return "legacy unsigned output"

        assert (
            await mw.on_call_tool(FakeContext(), call_next) == "legacy unsigned output"
        )

    async def test_strict_overrides_unsigned_output_opt_in(self, client):
        mw = JacsMCPMiddleware(
            client=client,
            strict=True,
            allow_unsigned_output=True,
        )
        mw._adapter.sign_output = lambda _value: (_ for _ in ()).throw(
            ValueError("signing unavailable")
        )

        class FakeContext:
            arguments = {}

        async def call_next(ctx):
            return "must-not-escape"

        with pytest.raises(ValueError, match="signing unavailable"):
            await mw.on_call_tool(FakeContext(), call_next)

    async def test_enabled_verification_fails_closed_by_default(self, client):
        mw = JacsMCPMiddleware(
            client=client,
            verify_tool_inputs=True,
            sign_tool_results=False,
        )
        mw._adapter.verify_input = lambda _value: (_ for _ in ()).throw(
            ValueError("invalid signature")
        )

        class FakeContext:
            arguments = {"input": '{"jacsSignature":{"signature":"bad"}}'}

        called = False

        async def call_next(ctx):
            nonlocal called
            called = True
            return "must-not-run"

        with pytest.raises(ValueError, match="invalid signature"):
            await mw.on_call_tool(FakeContext(), call_next)
        assert called is False

    async def test_unverified_input_passthrough_requires_explicit_opt_in(self, client):
        mw = JacsMCPMiddleware(
            client=client,
            verify_tool_inputs=True,
            sign_tool_results=False,
            allow_unverified_passthrough=True,
        )
        mw._adapter.verify_input = lambda _value: (_ for _ in ()).throw(
            ValueError("invalid signature")
        )

        class FakeContext:
            arguments = {"input": '{"jacsSignature":{"signature":"bad"}}'}

        async def call_next(ctx):
            return "legacy-result"

        result = await mw.on_call_tool(FakeContext(), call_next)
        assert result == "legacy-result"


# ---------------------------------------------------------------------------
# register_a2a_tools
# ---------------------------------------------------------------------------


class TestRegisterA2ATools:
    def test_registers_all_a2a_tools(self, client):
        mcp = FakeMCP()
        register_a2a_tools(mcp, client=client)
        expected = {
            "jacs_export_agent_card",
            "jacs_get_agent_card",
            "jacs_wrap_a2a_artifact",
            "jacs_sign_artifact",
            "jacs_verify_a2a_artifact",
            "jacs_assess_a2a_agent",
            "jacs_assess_remote_agent",
        }
        assert set(mcp.tools.keys()) == expected

    def test_export_agent_card_alias_returns_card(self, client):
        mcp = FakeMCP()
        register_a2a_tools(mcp, client=client)
        fn = mcp.tools["jacs_export_agent_card"]["fn"]

        result = json.loads(fn())
        assert result["success"] is True
        assert "agent_card" in result

    def test_get_agent_card_returns_card(self, client):
        mcp = FakeMCP()
        register_a2a_tools(mcp, client=client)
        fn = mcp.tools["jacs_get_agent_card"]["fn"]

        result = json.loads(fn())
        assert result["success"] is True
        assert "agent_card" in result
        card = result["agent_card"]
        assert "name" in card
        assert "capabilities" in card

    def test_sign_artifact_returns_signed(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cl = JacsClient.quickstart(
            name="mcp-a2a-agent",
            domain="mcp-a2a.example",
            algorithm=TEST_ALGORITHM_INTERNAL,
            config_path=str(tmp_path / "jacs.config.json"),
        )
        mcp = FakeMCP()
        register_a2a_tools(mcp, client=cl)
        fn = mcp.tools["jacs_sign_artifact"]["fn"]

        artifact = json.dumps({"task": "test", "data": "hello"})
        result = json.loads(fn(artifact, "task"))
        assert result["success"] is True
        signed = result["signed_artifact"]
        assert "jacsSignature" in signed or "jacsId" in signed

    def test_assess_remote_agent_open_policy(self, client):
        mcp = FakeMCP()
        register_a2a_tools(mcp, client=client)
        fn = mcp.tools["jacs_assess_remote_agent"]["fn"]

        card = json.dumps({"name": "Test", "capabilities": {}})
        result = json.loads(fn(card, "open"))
        assert result["success"] is True
        assert result["allowed"] is True

    def test_assess_remote_agent_verified_rejects_non_jacs(self, client):
        mcp = FakeMCP()
        register_a2a_tools(mcp, client=client)
        fn = mcp.tools["jacs_assess_remote_agent"]["fn"]

        card = json.dumps({"name": "Plain Agent", "capabilities": {}})
        result = json.loads(fn(card, "verified"))
        assert result["success"] is True
        assert result["allowed"] is False
        assert result["jacs_registered"] is False


# ---------------------------------------------------------------------------
# register_trust_tools
# ---------------------------------------------------------------------------


class TestRegisterTrustTools:
    def test_registers_all_trust_tools(self, client):
        mcp = FakeMCP()
        register_trust_tools(mcp, client=client)
        expected = {
            "jacs_trust_agent",
            "jacs_trust_agent_with_key",
            "jacs_untrust_agent",
            "jacs_list_trusted_agents",
            "jacs_list_trusted",
            "jacs_get_trusted_agent",
            "jacs_is_trusted",
        }
        assert set(mcp.tools.keys()) == expected

    def test_list_trusted_returns_list(self, client):
        mcp = FakeMCP()
        register_trust_tools(mcp, client=client)
        fn = mcp.tools["jacs_list_trusted"]["fn"]

        result = json.loads(fn())
        assert result["success"] is True
        assert isinstance(result["trusted_agents"], list)

    def test_is_trusted_returns_bool(self, client):
        mcp = FakeMCP()
        register_trust_tools(mcp, client=client)
        fn = mcp.tools["jacs_is_trusted"]["fn"]

        result = json.loads(fn("nonexistent-agent-id"))
        # May succeed with False or return error — either is acceptable
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# JacsMCPMiddleware with a2a=True
# ---------------------------------------------------------------------------


class TestJacsMCPMiddlewareA2A:
    def test_a2a_flag_stored(self, client):
        mw = JacsMCPMiddleware(client=client, a2a=True)
        assert mw._a2a is True

    def test_register_tools_adds_a2a_and_trust(self, client):
        mcp = FakeMCP()
        mw = JacsMCPMiddleware(client=client, a2a=True)
        mw.register_tools(mcp)

        # Should have all 8 tools (4 A2A + 4 trust)
        assert "jacs_get_agent_card" in mcp.tools
        assert "jacs_sign_artifact" in mcp.tools
        assert "jacs_verify_a2a_artifact" in mcp.tools
        assert "jacs_assess_remote_agent" in mcp.tools
        assert "jacs_trust_agent" in mcp.tools
        assert "jacs_untrust_agent" in mcp.tools
        assert "jacs_list_trusted" in mcp.tools
        assert "jacs_is_trusted" in mcp.tools

    def test_register_tools_noop_without_a2a(self, client):
        mcp = FakeMCP()
        mw = JacsMCPMiddleware(client=client, a2a=False)
        mw.register_tools(mcp)
        assert len(mcp.tools) == 0


# ---------------------------------------------------------------------------
# Security: Path traversal prevention in jacs_sign_file (Vuln 1)
# ---------------------------------------------------------------------------


class TestSignFilePathTraversal:
    """Confirm jacs_sign_file rejects path traversal attempts."""

    def test_rejects_absolute_unix_path(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]

        result = json.loads(fn("/etc/passwd"))
        assert result["success"] is False
        # New path-policy wording: leading "/" splits into an empty first segment.
        assert "empty segment" in result["error"]

    def test_rejects_parent_directory_traversal(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]

        result = json.loads(fn("data/../../../etc/shadow", embed=True))
        assert result["success"] is False
        assert "path traversal" in result["error"].lower()

    def test_rejects_windows_drive_path(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]

        result = json.loads(fn("C:\\Windows\\System32\\drivers\\etc\\hosts"))
        assert result["success"] is False
        assert "Windows drive prefix" in result["error"]

    def test_rejects_null_byte(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]

        result = json.loads(fn("safe\x00/etc/passwd"))
        assert result["success"] is False
        assert "null byte" in result["error"]

    def test_allows_safe_relative_path(self, client, tmp_path):
        """A safe relative path should not be blocked by path validation
        (it may fail because file doesn't exist, but NOT with a path error)."""
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]

        result = json.loads(fn("data/my-file.json"))
        # Should fail because file doesn't exist — NOT because of path validation
        assert result["success"] is False
        assert "Absolute paths" not in result["error"]
        assert "Path traversal" not in result["error"]


class TestValidateMcpFilePath:
    """Unit tests for the _validate_mcp_file_path helper.

    PRD §4.2.6 / Issue 022: the Python helper now delegates to the Rust
    ``jacs_mcp_resolve_input_path`` PyO3 export. Test assertions match
    the Rust rejection envelope (rejection messages contain "rejected"
    or a layer-specific keyword like "symlink") rather than the previous
    Python-local heuristic strings, so the two layers can never drift.

    The accept tests pre-create the file in a tempdir and point
    ``JACS_MCP_BASE_DIR`` there, because the Rust policy enforces
    base-dir confinement (a layer the old Python heuristic skipped).
    """

    def _with_base_dir(self, body):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            prev = os.environ.get("JACS_MCP_BASE_DIR")
            os.environ["JACS_MCP_BASE_DIR"] = td
            try:
                body(td)
            finally:
                if prev is None:
                    os.environ.pop("JACS_MCP_BASE_DIR", None)
                else:
                    os.environ["JACS_MCP_BASE_DIR"] = prev

    def test_accepts_simple_filename(self):
        import os

        def body(base):
            with open(os.path.join(base, "state.json"), "w") as f:
                f.write("{}")
            _validate_mcp_file_path("state.json")  # should not raise

        self._with_base_dir(body)

    def test_accepts_relative_path(self):
        import os

        def body(base):
            os.makedirs(os.path.join(base, "data"))
            with open(os.path.join(base, "data", "state.json"), "w") as f:
                f.write("{}")
            _validate_mcp_file_path("data/state.json")  # should not raise

        self._with_base_dir(body)

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _validate_mcp_file_path("")

    def test_rejects_absolute_path(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("/etc/passwd")

    def test_rejects_double_dot(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("a/../../etc/passwd")

    def test_rejects_dot_segment(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("a/./b")

    def test_rejects_windows_drive(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("C:\\Windows\\foo")

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("foo\x00bar")


# ---------------------------------------------------------------------------
# Security: Untrust permission gate (Vuln 3)
# ---------------------------------------------------------------------------


class TestUntrustPermissionGate:
    """Confirm jacs_untrust_agent is blocked unless JACS_MCP_ALLOW_UNTRUST is set."""

    def test_untrust_blocked_by_default(self, client):
        """Without env var, untrust should return UNTRUST_DISABLED."""
        # Ensure the env var is not set
        os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)

        mcp = FakeMCP()
        register_trust_tools(mcp, client=client)
        fn = mcp.tools["jacs_untrust_agent"]["fn"]

        result = json.loads(fn("some-agent-id"))
        assert result["success"] is False
        assert result["error"] == "UNTRUST_DISABLED"
        assert "JACS_MCP_ALLOW_UNTRUST" in result["message"]

    def test_untrust_allowed_when_env_set(self, client):
        """With env var set to 'true', untrust should proceed (may fail for
        other reasons like agent not found, but NOT with UNTRUST_DISABLED)."""
        os.environ["JACS_MCP_ALLOW_UNTRUST"] = "true"
        try:
            mcp = FakeMCP()
            register_trust_tools(mcp, client=client)
            fn = mcp.tools["jacs_untrust_agent"]["fn"]

            result = json.loads(fn("nonexistent-agent-id"))
            # Should NOT be blocked by the permission gate
            assert result.get("error") != "UNTRUST_DISABLED"
        finally:
            os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)

    def test_untrust_allowed_with_value_1(self, client):
        """JACS_MCP_ALLOW_UNTRUST=1 should also work."""
        os.environ["JACS_MCP_ALLOW_UNTRUST"] = "1"
        try:
            mcp = FakeMCP()
            register_trust_tools(mcp, client=client)
            fn = mcp.tools["jacs_untrust_agent"]["fn"]

            result = json.loads(fn("nonexistent-agent-id"))
            assert result.get("error") != "UNTRUST_DISABLED"
        finally:
            os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)

    def test_is_untrust_allowed_false_by_default(self):
        os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)
        assert _is_untrust_allowed() is False

    def test_is_untrust_allowed_true(self):
        os.environ["JACS_MCP_ALLOW_UNTRUST"] = "true"
        try:
            assert _is_untrust_allowed() is True
        finally:
            os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)


# ---------------------------------------------------------------------------
# Security: Path traversal prevention in jacs_sign_file
# ---------------------------------------------------------------------------


class TestSignFilePathTraversalSecond:
    """Vuln 1: Ensure jacs_sign_file rejects path traversal attempts."""

    def test_rejects_absolute_unix_path(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]
        result = json.loads(fn("/etc/passwd", embed=True))
        assert result["success"] is False
        # New path-policy wording: leading "/" splits into an empty first segment.
        assert "empty segment" in result["error"]

    def test_rejects_parent_directory_traversal(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]
        result = json.loads(fn("data/../../../etc/shadow", embed=True))
        assert result["success"] is False
        assert "path traversal" in result["error"].lower()

    def test_rejects_windows_drive_path(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]
        result = json.loads(fn("C:\\Windows\\System32\\drivers\\etc\\hosts"))
        assert result["success"] is False
        assert "Windows drive prefix" in result["error"]

    def test_rejects_null_byte(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]
        result = json.loads(fn("data/file\x00.json"))
        assert result["success"] is False
        assert "null byte" in result["error"]

    def test_allows_safe_relative_path(self, client):
        """A safe relative path should not be blocked by path validation
        (it may fail for other reasons like file-not-found)."""
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client)
        fn = mcp.tools["jacs_sign_file"]["fn"]
        result = json.loads(fn("data/my-file.json"))
        # Should NOT contain path traversal error — may have a different error
        assert "Absolute paths" not in result.get("error", "")
        assert "Path traversal" not in result.get("error", "")
        assert "Windows drive" not in result.get("error", "")


class TestValidateMcpFilePathSecond:
    """Second batch of unit tests for the _validate_mcp_file_path helper.

    PRD §4.2.6 / Issue 022: assertions match the Rust delegate's rejection
    envelope (case-insensitive "rejected") rather than the prior Python
    heuristic strings, since the helper now delegates to Rust.
    """

    def _with_base_dir(self, body):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            prev = os.environ.get("JACS_MCP_BASE_DIR")
            os.environ["JACS_MCP_BASE_DIR"] = td
            try:
                body(td)
            finally:
                if prev is None:
                    os.environ.pop("JACS_MCP_BASE_DIR", None)
                else:
                    os.environ["JACS_MCP_BASE_DIR"] = prev

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            _validate_mcp_file_path("")

    def test_rejects_absolute_unix(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("/etc/passwd")

    def test_rejects_absolute_backslash(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("\\server\\share")

    def test_rejects_windows_drive(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("C:\\Users\\test")

    def test_rejects_parent_traversal(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("foo/../../bar")

    def test_rejects_dot_segment(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("./foo")

    def test_rejects_null_byte(self):
        with pytest.raises(ValueError, match="(?i)rejected"):
            _validate_mcp_file_path("foo\x00bar")

    def test_accepts_simple_relative(self):
        import os

        def body(base):
            os.makedirs(os.path.join(base, "data"))
            with open(os.path.join(base, "data", "state.json"), "w") as f:
                f.write("{}")
            _validate_mcp_file_path("data/state.json")  # no exception

        self._with_base_dir(body)

    def test_accepts_filename_only(self):
        _validate_mcp_file_path("myfile.txt")  # no exception

    def test_accepts_nested_relative(self):
        _validate_mcp_file_path("a/b/c/d.json")  # no exception


# ---------------------------------------------------------------------------
# Security: Untrust permission gate
# ---------------------------------------------------------------------------


class TestUntrustPermissionGate:
    """Vuln 3: Ensure jacs_untrust_agent requires JACS_MCP_ALLOW_UNTRUST=true."""

    def test_untrust_blocked_by_default(self, client):
        """Without JACS_MCP_ALLOW_UNTRUST, untrust should be rejected."""
        # Ensure the env var is not set
        old = os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)
        try:
            mcp = FakeMCP()
            register_trust_tools(mcp, client=client)
            fn = mcp.tools["jacs_untrust_agent"]["fn"]
            result = json.loads(fn("some-agent-id"))
            assert result["success"] is False
            assert result["error"] == "UNTRUST_DISABLED"
            assert "disabled for security" in result["message"]
        finally:
            if old is not None:
                os.environ["JACS_MCP_ALLOW_UNTRUST"] = old

    def test_untrust_allowed_when_env_set(self, client):
        """With JACS_MCP_ALLOW_UNTRUST=true, untrust should proceed."""
        old = os.environ.get("JACS_MCP_ALLOW_UNTRUST")
        os.environ["JACS_MCP_ALLOW_UNTRUST"] = "true"
        try:
            mcp = FakeMCP()
            register_trust_tools(mcp, client=client)
            fn = mcp.tools["jacs_untrust_agent"]["fn"]
            result = json.loads(fn("nonexistent-agent-id"))
            # Should NOT contain UNTRUST_DISABLED — may succeed or fail for
            # other reasons (agent not found), but not the permission gate.
            assert result.get("error") != "UNTRUST_DISABLED"
        finally:
            if old is None:
                os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)
            else:
                os.environ["JACS_MCP_ALLOW_UNTRUST"] = old

    def test_untrust_blocked_with_false_value(self, client):
        """JACS_MCP_ALLOW_UNTRUST=false should still block."""
        old = os.environ.get("JACS_MCP_ALLOW_UNTRUST")
        os.environ["JACS_MCP_ALLOW_UNTRUST"] = "false"
        try:
            mcp = FakeMCP()
            register_trust_tools(mcp, client=client)
            fn = mcp.tools["jacs_untrust_agent"]["fn"]
            result = json.loads(fn("some-agent-id"))
            assert result["success"] is False
            assert result["error"] == "UNTRUST_DISABLED"
        finally:
            if old is None:
                os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)
            else:
                os.environ["JACS_MCP_ALLOW_UNTRUST"] = old

    def test_is_untrust_allowed_helper(self):
        """Direct test of the _is_untrust_allowed helper."""
        old = os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)
        try:
            assert _is_untrust_allowed() is False

            os.environ["JACS_MCP_ALLOW_UNTRUST"] = "true"
            assert _is_untrust_allowed() is True

            os.environ["JACS_MCP_ALLOW_UNTRUST"] = "1"
            assert _is_untrust_allowed() is True

            os.environ["JACS_MCP_ALLOW_UNTRUST"] = "TRUE"
            assert _is_untrust_allowed() is True

            os.environ["JACS_MCP_ALLOW_UNTRUST"] = "false"
            assert _is_untrust_allowed() is False

            os.environ["JACS_MCP_ALLOW_UNTRUST"] = ""
            assert _is_untrust_allowed() is False
        finally:
            if old is None:
                os.environ.pop("JACS_MCP_ALLOW_UNTRUST", None)
            else:
                os.environ["JACS_MCP_ALLOW_UNTRUST"] = old
