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
from unittest.mock import MagicMock

import pytest

from jacs.adapters.base import BaseJacsAdapter
from jacs.client import JacsClient
from conftest import TEST_ALGORITHM


def _portable_v2_raw(agent_id="test-agent", **extra):
    document = {
        "jacsId": "document-id",
        "jacsVersion": "version-id",
        "jacsSignature": {
            "agentID": agent_id,
            "agentVersion": "agent-version",
            "publicKeyHash": "key-hash",
            "date": "2026-07-10T00:00:00Z",
            "signature": "signature",
            "signatureContentVersion": "jacs-signature-v2",
        },
        **extra,
    }
    return json.dumps(document)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def ephemeral_client():
    """Create an ephemeral JacsClient for testing."""
    return JacsClient.ephemeral(algorithm=TEST_ALGORITHM)


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

    def test_attest_on_produces_attestation_or_fails_closed(self, attest_adapter):
        """Attestation requests never silently downgrade to plain signing."""
        data = {"action": "approve", "amount": 42}
        try:
            signed = attest_adapter.sign_output(data)
        except Exception as exc:
            assert "attest" in str(exc).lower() or "feature" in str(exc).lower()
        else:
            parsed = json.loads(signed)
            assert "jacsAttestation" in parsed

    def test_attest_with_claims_never_silently_downgrades(
        self, attest_adapter_with_claims
    ):
        data = {"result": "success"}
        try:
            signed = attest_adapter_with_claims.sign_output(data)
        except Exception as exc:
            assert "attest" in str(exc).lower() or "feature" in str(exc).lower()
        else:
            parsed = json.loads(signed)
            assert "jacsAttestation" in parsed

    def test_attest_signing_failure_fails_closed(self, ephemeral_client):
        adapter = BaseJacsAdapter(
            client=ephemeral_client,
            attest=True,
            strict=False,
        )
        # Break the client
        ephemeral_client.reset()
        data = {"still": "works"}
        with pytest.raises(Exception):
            adapter.sign_output_or_passthrough(data)

    def test_attest_with_mock_client(self):
        """When attestation succeeds on the client, sign_output returns it."""
        mock_client = MagicMock()
        mock_signed_doc = MagicMock()
        mock_signed_doc.raw_json = _portable_v2_raw(
            jacsAttestation={"claims": [{"name": "verified", "value": "true"}]}
        )
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
        mock_signed_doc.raw_json = _portable_v2_raw()
        mock_client.sign_message.return_value = mock_signed_doc

        adapter = BaseJacsAdapter(client=mock_client, attest=False)
        adapter.sign_output({"data": "test"})

        mock_client.sign_message.assert_called_once()
        mock_client.create_attestation.assert_not_called()

    def test_attest_failure_does_not_downgrade_by_default(self):
        """Requested claims cannot silently disappear into a plain signature."""
        mock_client = MagicMock()
        mock_client.create_attestation.side_effect = Exception(
            "attestation not available"
        )

        adapter = BaseJacsAdapter(client=mock_client, attest=True, strict=False)
        with pytest.raises(Exception, match="attestation not available"):
            adapter.sign_output({"data": "test"})

        mock_client.create_attestation.assert_called_once()
        mock_client.sign_message.assert_not_called()

    def test_attest_plain_signature_fallback_requires_explicit_opt_in(self):
        mock_client = MagicMock()
        mock_client.create_attestation.side_effect = Exception(
            "attestation not available"
        )
        mock_signed_doc = MagicMock()
        mock_signed_doc.raw_json = _portable_v2_raw(agent_id="fallback")
        mock_client.sign_message.return_value = mock_signed_doc

        adapter = BaseJacsAdapter(
            client=mock_client,
            attest=True,
            allow_plain_signature_fallback=True,
        )
        result = adapter.sign_output({"data": "test"})
        assert "jacsSignature" in json.loads(result)
        mock_client.create_attestation.assert_called_once()
        mock_client.sign_message.assert_called_once()

    def test_strict_overrides_plain_signature_fallback(self):
        mock_client = MagicMock()
        mock_client.create_attestation.side_effect = Exception(
            "attestation not available"
        )

        adapter = BaseJacsAdapter(
            client=mock_client,
            attest=True,
            strict=True,
            allow_plain_signature_fallback=True,
        )
        assert adapter.allow_plain_signature_fallback is False
        with pytest.raises(Exception, match="attestation not available"):
            adapter.sign_output({"data": "test"})
        mock_client.sign_message.assert_not_called()

    def test_attest_fallback_raises_in_strict(self):
        """In strict mode, attestation failure does NOT fall back to signing."""
        mock_client = MagicMock()
        mock_client.create_attestation.side_effect = Exception(
            "attestation not available"
        )

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
        wrapped = signed_tool(
            tool,
            client=ephemeral_client,
            attest=True,
            allow_plain_signature_fallback=True,
        )
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

        middleware = JacsSigningMiddleware(client=ephemeral_client, attest=True)
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

        guardrail = jacs_guardrail(
            client=ephemeral_client,
            attest=True,
            allow_plain_signature_fallback=True,
        )
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

        hook = JacsToolHook(
            client=ephemeral_client,
            attest=True,
            allow_plain_signature_fallback=True,
        )
        assert hook._adapter.attest is True

        result = asyncio.run(hook({"tool_response": "weather is sunny"}))
        assert "hookSpecificOutput" in result
        tool_result = result["hookSpecificOutput"]["toolResult"]
        parsed = json.loads(tool_result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_signed_tool_accepts_attest(self, ephemeral_client):
        """signed_tool decorator with attest=True produces output."""
        from jacs.adapters.anthropic import signed_tool

        @signed_tool(
            client=ephemeral_client,
            attest=True,
            allow_plain_signature_fallback=True,
        )
        def get_weather(location: str) -> str:
            return f"Weather in {location}: sunny"

        result = get_weather("Paris")
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed
