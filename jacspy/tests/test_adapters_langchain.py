"""Tests for jacs.adapters.langchain -- LangChain/LangGraph integration.

langchain-core, langchain, and langgraph are optional dependencies.
Tests that exercise adapter logic use mock objects so they run without
those packages installed.
"""

import json
import logging
from unittest.mock import MagicMock

import pytest

from jacs.adapters.langchain import (
    JacsSigningMiddleware,
    jacs_awrap_tool_call,
    jacs_wrap_tool_call,
)
from jacs.client import JacsClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Ephemeral JacsClient for zero-config test setup."""
    return JacsClient.ephemeral()


@pytest.fixture
def second_client():
    """A second ephemeral JacsClient for multi-identity tests."""
    return JacsClient.ephemeral()


class FakeToolMessage:
    """Mock for langchain_core.messages.ToolMessage."""

    def __init__(self, content: str, tool_call_id: str = "call_123", name: str = None):
        self.content = content
        self.tool_call_id = tool_call_id
        self.name = name


class FakeToolCallRequest:
    """Mock for langchain ToolCallRequest."""

    def __init__(self, tool_name: str = "search", args: dict = None, call_id: str = "call_abc"):
        self.tool_call = {
            "name": tool_name,
            "args": args or {},
            "id": call_id,
        }


# ---------------------------------------------------------------------------
# JacsSigningMiddleware (class-based, LangChain 1.0)
# ---------------------------------------------------------------------------


class TestJacsSigningMiddleware:
    """Test the class-based middleware for LangChain 1.0 create_agent."""

    def test_has_wrap_tool_call_method(self, client):
        mw = JacsSigningMiddleware(client=client)
        assert hasattr(mw, "wrap_tool_call")
        assert callable(mw.wrap_tool_call)

    def test_adapter_property(self, client):
        mw = JacsSigningMiddleware(client=client)
        assert mw.adapter is not None
        assert mw.adapter.client is client

    def test_signs_tool_message_content(self, client):
        mw = JacsSigningMiddleware(client=client)
        request = FakeToolCallRequest()

        def handler(req):
            return FakeToolMessage(content="tool output", tool_call_id="call_1")

        result = mw.wrap_tool_call(request, handler)
        assert hasattr(result, "content")
        parsed = json.loads(result.content)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_preserves_tool_call_id(self, client):
        mw = JacsSigningMiddleware(client=client)
        request = FakeToolCallRequest()

        def handler(req):
            return FakeToolMessage(content="data", tool_call_id="call_xyz")

        result = mw.wrap_tool_call(request, handler)
        assert result.tool_call_id == "call_xyz"

    def test_extracts_tool_call_id_from_request(self, client):
        """When result has no tool_call_id, extract from request."""
        mw = JacsSigningMiddleware(client=client)
        request = FakeToolCallRequest(call_id="req_id_123")

        def handler(req):
            return FakeToolMessage(content="data", tool_call_id="")

        result = mw.wrap_tool_call(request, handler)
        assert result.tool_call_id == "req_id_123"

    def test_passthrough_non_tool_message(self, client):
        mw = JacsSigningMiddleware(client=client)
        request = FakeToolCallRequest()
        sentinel = {"raw": "value"}

        def handler(req):
            return sentinel

        result = mw.wrap_tool_call(request, handler)
        assert result is sentinel

    def test_signed_content_is_verifiable(self, client):
        mw = JacsSigningMiddleware(client=client)
        request = FakeToolCallRequest()

        def handler(req):
            return FakeToolMessage(content="verify me", tool_call_id="c1")

        result = mw.wrap_tool_call(request, handler)
        vr = client.verify(result.content)
        assert vr.valid is True

    def test_strict_raises_on_signing_failure(self):
        cl = JacsClient.ephemeral()
        mw = JacsSigningMiddleware(client=cl, strict=True)
        cl.reset()

        request = FakeToolCallRequest()

        def handler(req):
            return FakeToolMessage(content="data", tool_call_id="c1")

        with pytest.raises(Exception):
            mw.wrap_tool_call(request, handler)

    def test_permissive_passthrough_on_signing_failure(self):
        cl = JacsClient.ephemeral()
        mw = JacsSigningMiddleware(client=cl, strict=False)
        cl.reset()

        request = FakeToolCallRequest()

        def handler(req):
            return FakeToolMessage(content="original", tool_call_id="c1")

        result = mw.wrap_tool_call(request, handler)
        assert result.content == "original"


# ---------------------------------------------------------------------------
# jacs_signing_middleware (decorator-based, LangChain 1.0)
# ---------------------------------------------------------------------------


class TestJacsSigningMiddlewareDecorator:
    """Test the @wrap_tool_call decorator-based factory."""

    def test_requires_langchain_1_0(self):
        """jacs_signing_middleware raises ImportError if langchain is missing."""
        try:
            import langchain.agents.middleware  # noqa: F401
            pytest.skip("langchain>=1.0 is installed, cannot test ImportError")
        except (ImportError, ModuleNotFoundError):
            from jacs.adapters.langchain import jacs_signing_middleware

            with pytest.raises(ImportError, match="langchain>=1.0.0"):
                jacs_signing_middleware()


# ---------------------------------------------------------------------------
# jacs_wrap_tool_call tests (LangGraph ToolNode)
# ---------------------------------------------------------------------------


class TestJacsWrapToolCall:
    """Test the sync wrap_tool_call factory for LangGraph ToolNode."""

    def test_returns_callable(self, client):
        wrapper = jacs_wrap_tool_call(client=client)
        assert callable(wrapper)

    def test_signs_tool_message_content(self, client):
        wrapper = jacs_wrap_tool_call(client=client)

        def execute(request):
            return FakeToolMessage(content="tool output", tool_call_id="call_1")

        result = wrapper("some_request", execute)
        assert hasattr(result, "content")
        parsed = json.loads(result.content)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_preserves_tool_call_id(self, client):
        wrapper = jacs_wrap_tool_call(client=client)

        def execute(request):
            return FakeToolMessage(content="data", tool_call_id="call_abc")

        result = wrapper("req", execute)
        assert result.tool_call_id == "call_abc"

    def test_preserves_name(self, client):
        wrapper = jacs_wrap_tool_call(client=client)

        def execute(request):
            return FakeToolMessage(content="data", tool_call_id="c1", name="search")

        result = wrapper("req", execute)
        assert result.name == "search"

    def test_passthrough_non_tool_message(self, client):
        """Results without .content are returned unchanged."""
        wrapper = jacs_wrap_tool_call(client=client)
        sentinel = {"raw": "value"}

        def execute(request):
            return sentinel

        result = wrapper("req", execute)
        assert result is sentinel

    def test_signed_content_is_verifiable(self, client):
        wrapper = jacs_wrap_tool_call(client=client)

        def execute(request):
            return FakeToolMessage(content="verify me", tool_call_id="c1")

        result = wrapper("req", execute)
        vr = client.verify(result.content)
        assert vr.valid is True

    def test_strict_raises_on_signing_failure(self):
        cl = JacsClient.ephemeral()
        wrapper = jacs_wrap_tool_call(client=cl, strict=True)
        cl.reset()

        def execute(request):
            return FakeToolMessage(content="data", tool_call_id="c1")

        with pytest.raises(Exception):
            wrapper("req", execute)

    def test_permissive_passthrough_on_signing_failure(self):
        cl = JacsClient.ephemeral()
        wrapper = jacs_wrap_tool_call(client=cl, strict=False)
        cl.reset()

        def execute(request):
            return FakeToolMessage(content="original data", tool_call_id="c1")

        result = wrapper("req", execute)
        assert result.content == "original data"

    def test_permissive_logs_warning(self, caplog):
        cl = JacsClient.ephemeral()
        wrapper = jacs_wrap_tool_call(client=cl, strict=False)
        cl.reset()

        def execute(request):
            return FakeToolMessage(content="data", tool_call_id="c1")

        with caplog.at_level(logging.WARNING, logger="jacs.adapters"):
            wrapper("req", execute)
        assert any("signing failed" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# jacs_awrap_tool_call tests (async LangGraph)
# ---------------------------------------------------------------------------


class TestJacsAwrapToolCall:
    """Test the async wrap_tool_call factory."""

    @pytest.mark.asyncio
    async def test_returns_callable(self, client):
        wrapper = jacs_awrap_tool_call(client=client)
        assert callable(wrapper)

    @pytest.mark.asyncio
    async def test_signs_tool_message_content(self, client):
        wrapper = jacs_awrap_tool_call(client=client)

        async def execute(request):
            return FakeToolMessage(content="async output", tool_call_id="c1")

        result = await wrapper("req", execute)
        assert hasattr(result, "content")
        parsed = json.loads(result.content)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    @pytest.mark.asyncio
    async def test_signed_content_is_verifiable(self, client):
        wrapper = jacs_awrap_tool_call(client=client)

        async def execute(request):
            return FakeToolMessage(content="async verify", tool_call_id="c1")

        result = await wrapper("req", execute)
        vr = client.verify(result.content)
        assert vr.valid is True

    @pytest.mark.asyncio
    async def test_passthrough_non_tool_message(self, client):
        wrapper = jacs_awrap_tool_call(client=client)
        sentinel = 42

        async def execute(request):
            return sentinel

        result = await wrapper("req", execute)
        assert result is sentinel

    @pytest.mark.asyncio
    async def test_strict_raises_on_failure(self):
        cl = JacsClient.ephemeral()
        wrapper = jacs_awrap_tool_call(client=cl, strict=True)
        cl.reset()

        async def execute(request):
            return FakeToolMessage(content="data", tool_call_id="c1")

        with pytest.raises(Exception):
            await wrapper("req", execute)


# ---------------------------------------------------------------------------
# signed_tool tests (requires langchain-core)
# ---------------------------------------------------------------------------


class TestSignedTool:
    """Test the signed_tool BaseTool wrapper."""

    def test_signed_tool_requires_langchain_core(self):
        """signed_tool raises ImportError if langchain-core is missing."""
        try:
            import langchain_core  # noqa: F401
            pytest.skip("langchain-core is installed, cannot test ImportError")
        except ImportError:
            from jacs.adapters.langchain import signed_tool

            mock_tool = MagicMock()
            with pytest.raises(ImportError, match="langchain-core"):
                signed_tool(mock_tool)

    def test_signed_tool_wraps_and_signs(self):
        """If langchain-core is available, signed_tool wraps a BaseTool."""
        pytest.importorskip("langchain_core")
        from langchain_core.tools import StructuredTool

        from jacs.adapters.langchain import signed_tool

        client = JacsClient.ephemeral()

        def my_func(query: str) -> str:
            return f"result for {query}"

        base_tool = StructuredTool.from_function(
            func=my_func,
            name="search",
            description="search tool",
        )

        wrapped = signed_tool(base_tool, client=client)
        assert wrapped.name == "search"

        result = wrapped.invoke({"query": "test"})
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_signed_tool_verifiable(self):
        """Signed tool output is verifiable by the same client."""
        pytest.importorskip("langchain_core")
        from langchain_core.tools import StructuredTool

        from jacs.adapters.langchain import signed_tool

        client = JacsClient.ephemeral()

        def my_func(x: str) -> str:
            return f"value: {x}"

        base_tool = StructuredTool.from_function(
            func=my_func, name="calc", description="calc"
        )
        wrapped = signed_tool(base_tool, client=client)
        result = wrapped.invoke({"x": "42"})

        vr = client.verify(result)
        assert vr.valid is True

    def test_signed_tool_preserves_inner_reference(self):
        """The wrapped tool keeps a reference to the inner tool."""
        pytest.importorskip("langchain_core")
        from langchain_core.tools import StructuredTool

        from jacs.adapters.langchain import signed_tool

        client = JacsClient.ephemeral()

        def noop(x: str) -> str:
            return x

        base_tool = StructuredTool.from_function(
            func=noop, name="noop", description="noop"
        )
        wrapped = signed_tool(base_tool, client=client)
        assert wrapped._inner_tool is base_tool


# ---------------------------------------------------------------------------
# with_jacs_signing tests
# ---------------------------------------------------------------------------


class TestWithJacsSigning:
    """Test the with_jacs_signing convenience function."""

    def test_requires_langgraph(self):
        """with_jacs_signing raises ImportError if langgraph is missing."""
        try:
            import langgraph  # noqa: F401
            pytest.skip("langgraph is installed, cannot test ImportError")
        except ImportError:
            from jacs.adapters.langchain import with_jacs_signing

            with pytest.raises(ImportError, match="langgraph"):
                with_jacs_signing([])

    def test_creates_tool_node(self):
        """If langgraph is available, returns a ToolNode."""
        pytest.importorskip("langgraph")
        from langgraph.prebuilt import ToolNode

        from jacs.adapters.langchain import with_jacs_signing

        client = JacsClient.ephemeral()
        node = with_jacs_signing([], client=client)
        assert isinstance(node, ToolNode)


# ---------------------------------------------------------------------------
# Multi-identity tests
# ---------------------------------------------------------------------------


class TestMultiIdentity:
    """Test with two different JacsClient instances (different keys)."""

    def test_two_clients_produce_different_signatures(self, client, second_client):
        wrapper1 = jacs_wrap_tool_call(client=client)
        wrapper2 = jacs_wrap_tool_call(client=second_client)

        def execute(request):
            return FakeToolMessage(content="same content", tool_call_id="c1")

        result1 = wrapper1("req", execute)
        result2 = wrapper2("req", execute)

        parsed1 = json.loads(result1.content)
        parsed2 = json.loads(result2.content)

        sig1 = parsed1.get("jacsSignature", {})
        sig2 = parsed2.get("jacsSignature", {})
        signer1 = sig1.get("agentId", sig1.get("agentID", ""))
        signer2 = sig2.get("agentId", sig2.get("agentID", ""))
        if signer1 and signer2:
            assert signer1 != signer2

    def test_each_client_verifies_own_output(self, client, second_client):
        wrapper1 = jacs_wrap_tool_call(client=client)
        wrapper2 = jacs_wrap_tool_call(client=second_client)

        def execute(request):
            return FakeToolMessage(content="data", tool_call_id="c1")

        result1 = wrapper1("req", execute)
        result2 = wrapper2("req", execute)

        assert client.verify(result1.content).valid is True
        assert second_client.verify(result2.content).valid is True

    def test_middleware_two_clients_different_sigs(self, client, second_client):
        """JacsSigningMiddleware with different clients = different signers."""
        mw1 = JacsSigningMiddleware(client=client)
        mw2 = JacsSigningMiddleware(client=second_client)
        request = FakeToolCallRequest()

        def handler(req):
            return FakeToolMessage(content="same data", tool_call_id="c1")

        result1 = mw1.wrap_tool_call(request, handler)
        result2 = mw2.wrap_tool_call(request, handler)

        parsed1 = json.loads(result1.content)
        parsed2 = json.loads(result2.content)

        sig1 = parsed1.get("jacsSignature", {})
        sig2 = parsed2.get("jacsSignature", {})
        signer1 = sig1.get("agentId", sig1.get("agentID", ""))
        signer2 = sig2.get("agentId", sig2.get("agentID", ""))
        if signer1 and signer2:
            assert signer1 != signer2


# ---------------------------------------------------------------------------
# Coverage: wrap N tools, run each, verify ALL outputs signed
# ---------------------------------------------------------------------------


class TestCoverage:
    """100% coverage: wrap N tools, run each, verify ALL outputs signed."""

    def test_wrap_multiple_tools_all_signed(self, client):
        wrapper = jacs_wrap_tool_call(client=client)

        tools_data = [
            ("search", "search result"),
            ("calculator", "42"),
            ("weather", "sunny"),
            ("translator", "hola"),
        ]

        for name, output in tools_data:
            def execute(request, _output=output, _name=name):
                return FakeToolMessage(
                    content=_output, tool_call_id=f"call_{_name}", name=_name
                )

            result = wrapper("req", execute)
            parsed = json.loads(result.content)
            assert "jacsSignature" in parsed or "jacsHash" in parsed, (
                f"Tool '{name}' output was not signed"
            )
            vr = client.verify(result.content)
            assert vr.valid is True, f"Tool '{name}' output failed verification"

    def test_middleware_wraps_multiple_tools(self, client):
        """JacsSigningMiddleware signs outputs for multiple tools."""
        mw = JacsSigningMiddleware(client=client)

        tools_data = [
            ("search", "search result"),
            ("calculator", "42"),
            ("weather", "sunny"),
        ]

        for name, output in tools_data:
            request = FakeToolCallRequest(tool_name=name, call_id=f"call_{name}")

            def handler(req, _output=output):
                return FakeToolMessage(content=_output, tool_call_id=req.tool_call["id"])

            result = mw.wrap_tool_call(request, handler)
            parsed = json.loads(result.content)
            assert "jacsSignature" in parsed or "jacsHash" in parsed, (
                f"Middleware: tool '{name}' output was not signed"
            )
            vr = client.verify(result.content)
            assert vr.valid is True, (
                f"Middleware: tool '{name}' output failed verification"
            )
