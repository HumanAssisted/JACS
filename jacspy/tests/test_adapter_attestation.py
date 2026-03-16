"""Tests for attestation mode in framework adapters.

Verifies that adapters can optionally produce attestations instead of
plain signatures when attest=True is passed.

NOTE: These tests work even when the Rust attestation feature is not
compiled in. They test the Python-level adapter wiring (parameter
acceptance, dispatch logic, fallback behavior). The actual attestation
Rust code path is tested separately in the Rust and binding-core test
suites.
"""

import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from jacs.adapters.base import BaseJacsAdapter
from jacs.client import JacsClient


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def ephemeral_client():
    """Create an ephemeral JacsClient for testing."""
    return JacsClient.ephemeral(algorithm="ed25519")


@pytest.fixture
def adapter(ephemeral_client):
    """Create a BaseJacsAdapter in normal (non-attest) mode."""
    return BaseJacsAdapter(client=ephemeral_client)


@pytest.fixture
def attest_adapter(ephemeral_client):
    """Create a BaseJacsAdapter with attest=True."""
    return BaseJacsAdapter(client=ephemeral_client, attest=True)


@pytest.fixture
def attest_adapter_with_claims(ephemeral_client):
    """Create a BaseJacsAdapter with attest=True and default_claims."""
    claims = [
        {"name": "origin", "value": "unit-test", "confidence": 1.0},
    ]
    return BaseJacsAdapter(
        client=ephemeral_client,
        attest=True,
        default_claims=claims,
    )


# --------------------------------------------------------------------------
# BaseJacsAdapter attestation mode tests
# --------------------------------------------------------------------------

class TestBaseAdapterAttestMode:
    """Test that BaseJacsAdapter supports attest=True mode."""

    def test_attest_defaults_false(self, adapter):
        """attest should default to False for backward compatibility."""
        assert adapter.attest is False

    def test_attest_mode_enabled(self, attest_adapter):
        """attest=True should be accessible via property."""
        assert attest_adapter.attest is True

    def test_default_claims_empty_by_default(self, adapter):
        """default_claims should be an empty list by default."""
        assert adapter.default_claims == []

    def test_default_claims_stored(self, attest_adapter_with_claims):
        """default_claims should be stored when provided."""
        assert len(attest_adapter_with_claims.default_claims) == 1
        assert attest_adapter_with_claims.default_claims[0]["name"] == "origin"

    def test_attest_off_produces_plain_signature(self, adapter):
        """When attest=False, sign_output produces a plain signed document."""
        data = {"action": "approve"}
        signed = adapter.sign_output(data)
        parsed = json.loads(signed)
        # Plain signatures have jacsSignature
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_attest_on_falls_back_to_signature_when_unavailable(self, attest_adapter):
        """When attest=True but attestation is not available, fall back to plain signing."""
        data = {"action": "approve", "amount": 42}
        # The ephemeral client may not have attestation compiled in, but
        # sign_output should still succeed by falling back to plain signing.
        signed = attest_adapter.sign_output(data)
        parsed = json.loads(signed)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_attest_with_claims_still_produces_output(self, attest_adapter_with_claims):
        """When default_claims are provided, sign_output still produces output."""
        data = {"result": "success"}
        signed = attest_adapter_with_claims.sign_output(data)
        parsed = json.loads(signed)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_attest_passthrough_on_error(self, ephemeral_client):
        """In permissive attest mode, errors fall through gracefully."""
        adapter = BaseJacsAdapter(
            client=ephemeral_client,
            attest=True,
            strict=False,
        )
        # Break the client
        ephemeral_client.reset()
        data = {"still": "works"}
        result = adapter.sign_output_or_passthrough(data)
        assert json.loads(result) == data

    def test_attest_with_mock_client(self):
        """When attestation succeeds on the client, sign_output returns it."""
        mock_client = MagicMock()
        mock_signed_doc = MagicMock()
        mock_signed_doc.raw_json = json.dumps({
            "jacsSignature": {"agentID": "test-agent"},
            "jacsAttestation": {"claims": [{"name": "verified", "value": "true"}]},
        })
        mock_client.create_attestation.return_value = mock_signed_doc
        mock_client.sign_message.return_value = mock_signed_doc

        adapter = BaseJacsAdapter(client=mock_client, attest=True)
        result = adapter.sign_output({"data": "test"})
        parsed = json.loads(result)
        assert "jacsSignature" in parsed

        # Verify create_attestation was called (not sign_message)
        mock_client.create_attestation.assert_called_once()

    def test_attest_false_uses_sign_message(self):
        """When attest=False, sign_output uses sign_message, not create_attestation."""
        mock_client = MagicMock()
        mock_signed_doc = MagicMock()
        mock_signed_doc.raw_json = json.dumps({
            "jacsSignature": {"agentID": "test-agent"},
        })
        mock_client.sign_message.return_value = mock_signed_doc

        adapter = BaseJacsAdapter(client=mock_client, attest=False)
        result = adapter.sign_output({"data": "test"})

        mock_client.sign_message.assert_called_once()
        mock_client.create_attestation.assert_not_called()

    def test_attest_fallback_on_attestation_error(self):
        """When create_attestation raises, fall back to sign_message."""
        mock_client = MagicMock()
        mock_client.create_attestation.side_effect = Exception("attestation not available")
        mock_signed_doc = MagicMock()
        mock_signed_doc.raw_json = json.dumps({"jacsSignature": {"agentID": "fallback"}})
        mock_client.sign_message.return_value = mock_signed_doc

        adapter = BaseJacsAdapter(client=mock_client, attest=True, strict=False)
        result = adapter.sign_output({"data": "test"})
        parsed = json.loads(result)
        assert "jacsSignature" in parsed

        # Both should have been called: create_attestation first (failed), then sign_message
        mock_client.create_attestation.assert_called_once()
        mock_client.sign_message.assert_called_once()

    def test_attest_fallback_raises_in_strict(self):
        """In strict mode, attestation failure does NOT fall back to signing."""
        mock_client = MagicMock()
        mock_client.create_attestation.side_effect = Exception("attestation not available")

        adapter = BaseJacsAdapter(client=mock_client, attest=True, strict=True)
        with pytest.raises(Exception, match="attestation not available"):
            adapter.sign_output({"data": "test"})


# --------------------------------------------------------------------------
# LangChain adapter attestation tests
# --------------------------------------------------------------------------

class TestLangchainAdapterAttest:
    """Test LangChain adapter with attest mode."""

    def test_signed_tool_accepts_attest(self, ephemeral_client):
        """signed_tool accepts attest=True parameter."""
        try:
            from langchain_core.tools import StructuredTool
        except ImportError:
            pytest.skip("langchain-core not installed")

        from jacs.adapters.langchain import signed_tool

        def dummy_tool(query: str) -> str:
            return f"result for {query}"

        tool = StructuredTool.from_function(
            func=dummy_tool,
            name="dummy",
            description="A dummy tool",
        )
        # Should not raise
        wrapped = signed_tool(tool, client=ephemeral_client, attest=True)
        result = wrapped.invoke({"query": "hello"})
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_jacs_wrap_accepts_attest(self, ephemeral_client):
        """jacs_wrap_tool_call accepts attest=True parameter."""
        from jacs.adapters.langchain import jacs_wrap_tool_call

        wrapper = jacs_wrap_tool_call(client=ephemeral_client, attest=True)
        assert callable(wrapper)

    def test_signing_middleware_accepts_attest(self, ephemeral_client):
        """JacsSigningMiddleware accepts attest=True parameter."""
        from jacs.adapters.langchain import JacsSigningMiddleware

        middleware = JacsSigningMiddleware(
            client=ephemeral_client, attest=True
        )
        assert middleware.adapter.attest is True

    def test_with_jacs_signing_accepts_attest(self, ephemeral_client):
        """with_jacs_signing accepts attest=True parameter."""
        try:
            from langgraph.prebuilt import ToolNode  # noqa: F401
        except ImportError:
            pytest.skip("langgraph not installed")

        from jacs.adapters.langchain import with_jacs_signing

        # Should not raise even with attest=True
        node = with_jacs_signing(
            tools=[],
            client=ephemeral_client,
            attest=True,
        )
        assert node is not None


# --------------------------------------------------------------------------
# FastAPI adapter attestation tests
# --------------------------------------------------------------------------

class TestFastapiAdapterAttest:
    """Test FastAPI adapter with attest mode."""

    def test_middleware_accepts_attest(self, ephemeral_client):
        """JacsMiddleware accepts attest=True parameter."""
        try:
            from starlette.applications import Starlette
        except ImportError:
            pytest.skip("starlette not installed")

        from jacs.adapters.fastapi import JacsMiddleware

        app = Starlette()
        middleware = JacsMiddleware(
            app,
            client=ephemeral_client,
            attest=True,
        )
        assert middleware._adapter.attest is True

    def test_jacs_route_accepts_attest(self, ephemeral_client):
        """jacs_route accepts attest=True parameter."""
        try:
            from starlette.applications import Starlette  # noqa: F401
        except ImportError:
            pytest.skip("starlette not installed")

        from jacs.adapters.fastapi import jacs_route

        @jacs_route(client=ephemeral_client, attest=True)
        def my_endpoint():
            return {"result": "data"}

        assert callable(my_endpoint)


# --------------------------------------------------------------------------
# CrewAI adapter attestation tests
# --------------------------------------------------------------------------

class TestCrewaiAdapterAttest:
    """Test CrewAI adapter with attest mode."""

    def test_guardrail_accepts_attest(self, ephemeral_client):
        """jacs_guardrail with attest=True produces output."""
        from jacs.adapters.crewai import jacs_guardrail

        guardrail = jacs_guardrail(client=ephemeral_client, attest=True)
        assert callable(guardrail)

        # Simulate a TaskOutput-like object
        class FakeOutput:
            raw = "This is the task output"

        ok, result = guardrail(FakeOutput())
        assert ok is True
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_signed_tool_wrapper_accepts_attest(self, ephemeral_client):
        """JacsSignedTool accepts attest=True parameter."""
        from jacs.adapters.crewai import JacsSignedTool

        class FakeTool:
            name = "test_tool"
            description = "A test tool"
            args_schema = None

            def _run(self, **kwargs):
                return "result"

        wrapped = JacsSignedTool(FakeTool(), client=ephemeral_client, attest=True)
        assert wrapped._adapter.attest is True


# --------------------------------------------------------------------------
# Anthropic adapter attestation tests
# --------------------------------------------------------------------------

class TestAnthropicAdapterAttest:
    """Test Anthropic adapter with attest mode."""

    def test_tool_hook_accepts_attest(self, ephemeral_client):
        """JacsToolHook with attest=True stores the setting."""
        import asyncio
        from jacs.adapters.anthropic import JacsToolHook

        hook = JacsToolHook(client=ephemeral_client, attest=True)
        assert hook._adapter.attest is True

        result = asyncio.get_event_loop().run_until_complete(
            hook({"tool_response": "weather is sunny"})
        )
        assert "hookSpecificOutput" in result
        tool_result = result["hookSpecificOutput"]["toolResult"]
        parsed = json.loads(tool_result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_signed_tool_accepts_attest(self, ephemeral_client):
        """signed_tool decorator with attest=True produces output."""
        from jacs.adapters.anthropic import signed_tool

        @signed_tool(client=ephemeral_client, attest=True)
        def get_weather(location: str) -> str:
            return f"Weather in {location}: sunny"

        result = get_weather("Paris")
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed
