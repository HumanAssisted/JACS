"""Tests for jacs.adapters.anthropic (signed_tool + JacsToolHook)."""

import asyncio
import json

import pytest

from jacs.adapters.anthropic import JacsToolHook, signed_tool
from jacs.client import JacsClient


@pytest.fixture
def ephemeral_client():
    """Create an ephemeral JacsClient for testing."""
    return JacsClient.ephemeral()


# ------------------------------------------------------------------
# signed_tool -- sync
# ------------------------------------------------------------------


class TestSignedToolSync:
    """Tests for signed_tool wrapping synchronous functions."""

    def test_decorator_with_kwargs(self, ephemeral_client):
        """signed_tool as decorator with keyword args signs return value."""

        @signed_tool(client=ephemeral_client)
        def get_weather(location: str) -> str:
            return f"Weather in {location}: sunny"

        result = get_weather("Paris")
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_direct_wrapper(self, ephemeral_client):
        """signed_tool as direct wrapper (positional func arg)."""

        def get_price(item: str) -> str:
            return f"{item}: $42"

        signed_get_price = signed_tool(get_price, client=ephemeral_client)
        result = signed_get_price("widget")
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_preserves_function_name(self, ephemeral_client):
        """Wrapped function retains original __name__."""

        @signed_tool(client=ephemeral_client)
        def my_tool() -> str:
            return "ok"

        assert my_tool.__name__ == "my_tool"

    def test_dict_return_value(self, ephemeral_client):
        """Dict return values are signed correctly."""

        @signed_tool(client=ephemeral_client)
        def get_data() -> dict:
            return {"status": "ok", "count": 7}

        result = get_data()
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed


# ------------------------------------------------------------------
# signed_tool -- async
# ------------------------------------------------------------------


class TestSignedToolAsync:
    """Tests for signed_tool wrapping async functions."""

    def test_async_decorator(self, ephemeral_client):
        """signed_tool wraps async function and signs return value."""

        @signed_tool(client=ephemeral_client)
        async def async_weather(location: str) -> str:
            return f"Weather in {location}: rainy"

        result = asyncio.get_event_loop().run_until_complete(
            async_weather("London")
        )
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_async_preserves_coroutine(self, ephemeral_client):
        """Wrapped async function is still a coroutine function."""

        @signed_tool(client=ephemeral_client)
        async def async_tool() -> str:
            return "ok"

        assert asyncio.iscoroutinefunction(async_tool)


# ------------------------------------------------------------------
# signed_tool -- strict / permissive
# ------------------------------------------------------------------


class TestSignedToolModes:
    """Tests for strict and permissive modes of signed_tool."""

    def test_strict_raises_on_broken_client(self):
        """In strict mode, signing failure raises an exception."""
        client = JacsClient.ephemeral()

        @signed_tool(client=client, strict=True)
        def my_tool() -> str:
            return "data"

        # Break the client so signing fails
        client.reset()

        with pytest.raises(Exception):
            my_tool()

    def test_permissive_passes_through(self):
        """In permissive mode, signing failure returns original value."""
        client = JacsClient.ephemeral()

        @signed_tool(client=client, strict=False)
        def my_tool() -> str:
            return "raw data"

        client.reset()
        result = my_tool()
        assert result == "raw data"

    def test_permissive_dict_passes_through(self):
        """In permissive mode, dict is JSON-serialized on failure."""
        client = JacsClient.ephemeral()

        @signed_tool(client=client, strict=False)
        def my_tool() -> dict:
            return {"key": "val"}

        client.reset()
        result = my_tool()
        assert json.loads(result) == {"key": "val"}


# ------------------------------------------------------------------
# JacsToolHook
# ------------------------------------------------------------------


class TestJacsToolHook:
    """Tests for the Claude Agent SDK PostToolUse hook."""

    def test_signs_tool_response(self, ephemeral_client):
        """Hook signs the tool_response string."""
        hook = JacsToolHook(client=ephemeral_client)
        input_data = {"tool_response": "The answer is 42"}

        result = asyncio.get_event_loop().run_until_complete(
            hook(input_data)
        )

        assert "hookSpecificOutput" in result
        output = result["hookSpecificOutput"]
        assert output["hookEventName"] == "PostToolUse"
        # toolResult should be a signed JACS document
        parsed = json.loads(output["toolResult"])
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_returns_hook_output_format(self, ephemeral_client):
        """Hook returns the expected envelope structure."""
        hook = JacsToolHook(client=ephemeral_client)
        result = asyncio.get_event_loop().run_until_complete(
            hook({"tool_response": "test"})
        )

        assert set(result.keys()) == {"hookSpecificOutput"}
        assert set(result["hookSpecificOutput"].keys()) == {
            "hookEventName",
            "toolResult",
        }

    def test_handles_empty_tool_response(self, ephemeral_client):
        """Hook handles empty tool_response gracefully."""
        hook = JacsToolHook(client=ephemeral_client)
        result = asyncio.get_event_loop().run_until_complete(
            hook({"tool_response": ""})
        )

        assert "hookSpecificOutput" in result
        # Should still produce a signed result (empty string signed)
        assert isinstance(result["hookSpecificOutput"]["toolResult"], str)

    def test_handles_missing_tool_response(self, ephemeral_client):
        """Hook handles missing tool_response key."""
        hook = JacsToolHook(client=ephemeral_client)
        result = asyncio.get_event_loop().run_until_complete(
            hook({})
        )

        assert "hookSpecificOutput" in result
        assert isinstance(result["hookSpecificOutput"]["toolResult"], str)

    def test_optional_params_accepted(self, ephemeral_client):
        """Hook __call__ accepts tool_use_id and context."""
        hook = JacsToolHook(client=ephemeral_client)
        result = asyncio.get_event_loop().run_until_complete(
            hook(
                {"tool_response": "data"},
                tool_use_id="tu_123",
                context={"agent": "test"},
            )
        )

        assert "hookSpecificOutput" in result

    def test_adapter_property(self, ephemeral_client):
        """Hook exposes its underlying adapter."""
        hook = JacsToolHook(client=ephemeral_client)
        assert hook.adapter.client is ephemeral_client

    def test_strict_mode_raises(self):
        """Hook in strict mode raises on signing failure."""
        client = JacsClient.ephemeral()
        hook = JacsToolHook(client=client, strict=True)
        client.reset()

        with pytest.raises(Exception):
            asyncio.get_event_loop().run_until_complete(
                hook({"tool_response": "data"})
            )

    def test_permissive_passes_through(self):
        """Hook in permissive mode passes through on failure."""
        client = JacsClient.ephemeral()
        hook = JacsToolHook(client=client, strict=False)
        client.reset()

        result = asyncio.get_event_loop().run_until_complete(
            hook({"tool_response": "raw output"})
        )

        assert result["hookSpecificOutput"]["toolResult"] == "raw output"
