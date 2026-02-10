"""Tests for jacs.adapters.mcp — MCP tool registration and middleware."""

import json

import pytest

fastmcp = pytest.importorskip("fastmcp")

from jacs.adapters.mcp import register_jacs_tools, JacsMCPMiddleware  # noqa: E402
from jacs.client import JacsClient  # noqa: E402


@pytest.fixture
def client():
    return JacsClient.ephemeral()


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
            "jacs_audit",
            "jacs_agent_info",
        }
        assert set(mcp.tools.keys()) == expected

    def test_registers_subset_of_tools(self, client):
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=client, tools=["sign_document", "verify_document"])
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


# ---------------------------------------------------------------------------
# jacs_create_agreement / jacs_sign_agreement / jacs_check_agreement
# ---------------------------------------------------------------------------


class TestAgreementTools:
    @pytest.fixture
    def persistent_client(self, tmp_path):
        """Agreements require a persistent (non-ephemeral) client."""
        return JacsClient.quickstart(config_path=str(tmp_path / "jacs.config.json"))

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
# jacs_audit tool
# ---------------------------------------------------------------------------


class TestAuditTool:
    def test_audit_returns_json(self, tmp_path):
        cl = JacsClient.quickstart(config_path=str(tmp_path / "jacs.config.json"))
        mcp = FakeMCP()
        register_jacs_tools(mcp, client=cl)
        fn = mcp.tools["jacs_audit"]["fn"]

        result = fn()
        # audit returns JSON string — should be parseable
        parsed = json.loads(result)
        assert isinstance(parsed, dict)


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
