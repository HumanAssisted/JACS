"""Tests for jacs.adapters.crewai — CrewAI integration adapter.

CrewAI is an optional dependency and may not be installed. Tests that
exercise adapter logic use mock objects for CrewAI types so they run
without crewai installed.
"""

import json
import logging
from unittest.mock import MagicMock

import pytest

from jacs.adapters.crewai import (
    JacsSignedTool,
    JacsVerifiedInput,
    jacs_guardrail,
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


class FakeTaskOutput:
    """Mock for crewai.tasks.task_output.TaskOutput."""

    def __init__(self, raw: str):
        self.raw = raw
        self.pydantic = None
        self.json_dict = None

    def __str__(self):
        return self.raw


class FakeTool:
    """Mock for a CrewAI BaseTool."""

    def __init__(self, name="fake_tool", output="tool result"):
        self.name = name
        self.description = f"A fake tool named {name}"
        self.args_schema = None
        self._output = output

    def _run(self, **kwargs):
        return self._output


# ---------------------------------------------------------------------------
# jacs_guardrail tests
# ---------------------------------------------------------------------------


class TestJacsGuardrail:
    """Test the jacs_guardrail factory function."""

    def test_guardrail_returns_callable(self, client):
        gd = jacs_guardrail(client=client)
        assert callable(gd)

    def test_guardrail_signs_task_output(self, client):
        gd = jacs_guardrail(client=client)
        task_output = FakeTaskOutput("The answer is 42")
        ok, result = gd(task_output)
        assert ok is True
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_guardrail_signs_string_fallback(self, client):
        """When .raw is None, guardrail uses str() on the result."""
        gd = jacs_guardrail(client=client)
        # Object without .raw attribute
        ok, result = gd("plain string")
        assert ok is True
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_guardrail_strict_rejects_on_failure(self):
        """Strict guardrail returns (False, error) when signing fails."""
        client = JacsClient.ephemeral()
        gd = jacs_guardrail(client=client, strict=True)
        client.reset()  # break the client

        task_output = FakeTaskOutput("data")
        ok, result = gd(task_output)
        assert ok is False
        assert "JACS signing failed" in result

    def test_guardrail_permissive_passthrough_on_failure(self):
        """Permissive guardrail returns (True, original) when signing fails."""
        client = JacsClient.ephemeral()
        gd = jacs_guardrail(client=client, strict=False)
        client.reset()

        task_output = FakeTaskOutput("original data")
        ok, result = gd(task_output)
        assert ok is True
        assert result == "original data"

    def test_guardrail_permissive_logs_warning(self, caplog):
        """Permissive guardrail logs a warning on failure."""
        client = JacsClient.ephemeral()
        gd = jacs_guardrail(client=client, strict=False)
        client.reset()

        with caplog.at_level(logging.WARNING, logger="jacs.adapters.crewai"):
            gd(FakeTaskOutput("data"))
        assert any("signing failed" in r.message.lower() for r in caplog.records)

    def test_guardrail_result_is_verifiable(self, client):
        """Signed guardrail output should be verifiable by the same client."""
        gd = jacs_guardrail(client=client)
        task_output = FakeTaskOutput("verifiable data")
        ok, signed = gd(task_output)
        assert ok is True

        vr = client.verify(signed)
        assert vr.valid is True


# ---------------------------------------------------------------------------
# JacsSignedTool tests
# ---------------------------------------------------------------------------


class TestJacsSignedTool:
    """Test the JacsSignedTool wrapper."""

    def test_wraps_tool_metadata(self, client):
        inner = FakeTool(name="search", output="results")
        wrapped = JacsSignedTool(inner, client=client)
        assert wrapped.name == "search"
        assert "search" in wrapped.description

    def test_run_signs_output(self, client):
        inner = FakeTool(output="raw tool output")
        wrapped = JacsSignedTool(inner, client=client)
        result = wrapped._run()
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_run_passthrough_on_failure(self):
        """When signing fails in permissive mode, return original output."""
        client = JacsClient.ephemeral()
        inner = FakeTool(output="fallback output")
        wrapped = JacsSignedTool(inner, client=client, strict=False)
        client.reset()

        result = wrapped._run()
        assert result == "fallback output"

    def test_run_strict_raises_on_failure(self):
        """When signing fails in strict mode, raise."""
        client = JacsClient.ephemeral()
        inner = FakeTool(output="data")
        wrapped = JacsSignedTool(inner, client=client, strict=True)
        client.reset()

        with pytest.raises(Exception):
            wrapped._run()

    def test_inner_tool_property(self, client):
        inner = FakeTool()
        wrapped = JacsSignedTool(inner, client=client)
        assert wrapped.inner_tool is inner

    def test_signed_output_is_verifiable(self, client):
        inner = FakeTool(output="verify me")
        wrapped = JacsSignedTool(inner, client=client)
        signed = wrapped._run()
        vr = client.verify(signed)
        assert vr.valid is True


# ---------------------------------------------------------------------------
# JacsVerifiedInput tests
# ---------------------------------------------------------------------------


class TestJacsVerifiedInput:
    """Test the JacsVerifiedInput wrapper."""

    def test_wraps_tool_metadata(self, client):
        inner = FakeTool(name="processor")
        wrapped = JacsVerifiedInput(inner, client=client)
        assert wrapped.name == "processor"

    def test_verified_input_delegates(self, client):
        """Verify input, then delegate to inner tool with extracted payload."""
        inner = MagicMock()
        inner.name = "mock_tool"
        inner.description = "mock"
        inner.args_schema = None
        inner._run.return_value = "processed"

        wrapped = JacsVerifiedInput(inner, client=client)

        # Create signed data to pass in
        signed = client.sign_message("hello").raw_json
        result = wrapped._run(signed_input=signed)
        assert inner._run.called

    def test_passthrough_on_bad_input(self, client):
        """Permissive mode passes through unverifiable input."""
        inner = MagicMock()
        inner.name = "mock_tool"
        inner.description = "mock"
        inner.args_schema = None
        inner._run.return_value = "ok"

        wrapped = JacsVerifiedInput(inner, client=client, strict=False)
        wrapped._run(signed_input="not signed json")
        assert inner._run.called


# ---------------------------------------------------------------------------
# Multi-identity tests
# ---------------------------------------------------------------------------


class TestMultiIdentity:
    """Test with two different JacsClient instances (different keys)."""

    def test_two_clients_sign_independently(self, client, second_client):
        """Each client signs with its own key."""
        gd1 = jacs_guardrail(client=client)
        gd2 = jacs_guardrail(client=second_client)

        ok1, signed1 = gd1(FakeTaskOutput("from client 1"))
        ok2, signed2 = gd2(FakeTaskOutput("from client 2"))

        assert ok1 is True
        assert ok2 is True

        # Each can verify its own output
        assert client.verify(signed1).valid is True
        assert second_client.verify(signed2).valid is True

    def test_signed_tool_different_identities(self, client, second_client):
        """Two JacsSignedTool instances with different clients."""
        tool1 = JacsSignedTool(FakeTool(output="a"), client=client)
        tool2 = JacsSignedTool(FakeTool(output="b"), client=second_client)

        signed1 = tool1._run()
        signed2 = tool2._run()

        # Both are valid signed documents
        parsed1 = json.loads(signed1)
        parsed2 = json.loads(signed2)
        assert "jacsSignature" in parsed1 or "jacsHash" in parsed1
        assert "jacsSignature" in parsed2 or "jacsHash" in parsed2

        # Different signers
        sig1 = parsed1.get("jacsSignature", {})
        sig2 = parsed2.get("jacsSignature", {})
        signer1 = sig1.get("agentId", sig1.get("agentID", ""))
        signer2 = sig2.get("agentId", sig2.get("agentID", ""))
        if signer1 and signer2:
            assert signer1 != signer2


# ---------------------------------------------------------------------------
# signed_task tests (requires crewai)
# ---------------------------------------------------------------------------


class TestSignedTask:
    """Test signed_task decorator/factory — requires crewai installed."""

    def test_signed_task_import_error_without_crewai(self):
        """signed_task should fail with ImportError if crewai not installed."""
        try:
            import crewai  # noqa: F401
            pytest.skip("crewai is installed, cannot test ImportError")
        except ImportError:
            from jacs.adapters.crewai import signed_task

            with pytest.raises(ImportError, match="crewai is required"):
                signed_task(description="test")
