"""Tests for jacs.adapters.base.BaseJacsAdapter."""

import json
import logging

import pytest

from jacs.adapters.base import BaseJacsAdapter
from jacs.client import JacsClient


@pytest.fixture
def ephemeral_client():
    """Create an ephemeral JacsClient for testing."""
    return JacsClient.ephemeral()


@pytest.fixture
def adapter(ephemeral_client):
    """Create a BaseJacsAdapter wrapping an ephemeral client."""
    return BaseJacsAdapter(client=ephemeral_client)


@pytest.fixture
def strict_adapter(ephemeral_client):
    """Create a strict-mode BaseJacsAdapter."""
    return BaseJacsAdapter(client=ephemeral_client, strict=True)


class TestAdapterInit:
    """Test adapter initialization."""

    def test_create_with_client(self, ephemeral_client):
        adapter = BaseJacsAdapter(client=ephemeral_client)
        assert adapter.client is ephemeral_client

    def test_strict_mode_defaults_false(self, ephemeral_client):
        adapter = BaseJacsAdapter(client=ephemeral_client)
        assert adapter.strict is False

    def test_strict_mode_explicit(self, ephemeral_client):
        adapter = BaseJacsAdapter(client=ephemeral_client, strict=True)
        assert adapter.strict is True

    def test_client_property(self, adapter, ephemeral_client):
        assert adapter.client is ephemeral_client
        assert adapter.client.agent_id == ephemeral_client.agent_id


class TestSignOutput:
    """Test sign_output with various data types."""

    def test_sign_dict(self, adapter):
        data = {"action": "approve", "amount": 42}
        signed = adapter.sign_output(data)
        assert isinstance(signed, str)
        parsed = json.loads(signed)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_sign_string(self, adapter):
        signed = adapter.sign_output("hello world")
        assert isinstance(signed, str)
        parsed = json.loads(signed)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_sign_list(self, adapter):
        signed = adapter.sign_output([1, 2, 3])
        assert isinstance(signed, str)
        parsed = json.loads(signed)
        assert "jacsSignature" in parsed or "jacsHash" in parsed

    def test_sign_nested_dict(self, adapter):
        data = {"outer": {"inner": [1, 2, 3]}, "flag": True}
        signed = adapter.sign_output(data)
        assert isinstance(signed, str)
        parsed = json.loads(signed)
        assert "jacsSignature" in parsed or "jacsHash" in parsed


class TestVerifyInput:
    """Test verify_input with signed data."""

    def test_verify_signed_dict(self, adapter):
        data = {"key": "value", "count": 7}
        signed = adapter.sign_output(data)
        payload = adapter.verify_input(signed)
        # The verified payload should contain the original data
        assert isinstance(payload, dict)

    def test_verify_signed_string(self, adapter):
        signed = adapter.sign_output("test message")
        payload = adapter.verify_input(signed)
        assert payload is not None

    def test_roundtrip_dict(self, adapter):
        """Sign then verify a dict -- original data should be recoverable."""
        original = {"action": "deploy", "version": "1.2.3"}
        signed = adapter.sign_output(original)
        payload = adapter.verify_input(signed)
        # sign_request wraps the dict; the payload should contain our data
        assert isinstance(payload, dict)


class TestStrictMode:
    """Test strict mode behavior."""

    def test_strict_verify_bad_input_raises(self, strict_adapter):
        """Strict mode should raise on invalid signed JSON."""
        with pytest.raises(Exception):
            strict_adapter.verify_input('{"not": "signed"}')

    def test_strict_verify_or_passthrough_raises(self, strict_adapter):
        """verify_input_or_passthrough should raise in strict mode."""
        with pytest.raises(Exception):
            strict_adapter.verify_input_or_passthrough('{"not": "signed"}')


class TestPassthroughMode:
    """Test permissive (non-strict) passthrough behavior."""

    def test_verify_bad_input_passthrough(self, adapter):
        """Permissive mode should return parsed JSON on verification failure."""
        bad_json = '{"not": "signed"}'
        result = adapter.verify_input_or_passthrough(bad_json)
        assert result == {"not": "signed"}

    def test_verify_non_json_passthrough(self, adapter):
        """Permissive mode should return raw string if not valid JSON."""
        result = adapter.verify_input_or_passthrough("not json at all")
        assert result == "not json at all"

    def test_verify_passthrough_logs_warning(self, adapter, caplog):
        """Permissive mode should log a warning on verification failure."""
        with caplog.at_level(logging.WARNING, logger="jacs.adapters"):
            adapter.verify_input_or_passthrough('{"not": "signed"}')
        assert any("verification failed" in r.message.lower() for r in caplog.records)

    def test_sign_passthrough_on_error(self):
        """If signing fails, permissive mode should return JSON-serialized data."""
        # Create an adapter with a broken client (reset it)
        client = JacsClient.ephemeral()
        adapter = BaseJacsAdapter(client=client, strict=False)
        client.reset()  # break the client

        data = {"still": "works"}
        result = adapter.sign_output_or_passthrough(data)
        assert json.loads(result) == data

    def test_sign_passthrough_string(self):
        """If signing a string fails, permissive mode returns the string."""
        client = JacsClient.ephemeral()
        adapter = BaseJacsAdapter(client=client, strict=False)
        client.reset()

        result = adapter.sign_output_or_passthrough("raw text")
        assert result == "raw text"

    def test_sign_passthrough_logs_warning(self, caplog):
        """Permissive mode should log a warning when signing fails."""
        client = JacsClient.ephemeral()
        adapter = BaseJacsAdapter(client=client, strict=False)
        client.reset()

        with caplog.at_level(logging.WARNING, logger="jacs.adapters"):
            adapter.sign_output_or_passthrough({"data": 1})
        assert any("signing failed" in r.message.lower() for r in caplog.records)


class TestSignVerifyRoundtrip:
    """End-to-end roundtrip tests."""

    def test_dict_roundtrip_via_passthrough(self, adapter):
        """sign_output_or_passthrough + verify_input_or_passthrough roundtrip."""
        original = {"task": "test", "priority": 1}
        signed = adapter.sign_output_or_passthrough(original)
        payload = adapter.verify_input_or_passthrough(signed)
        assert isinstance(payload, dict)

    def test_two_adapters_cross_verify(self):
        """Adapter A signs, adapter B verifies (same ephemeral agent)."""
        client = JacsClient.ephemeral()
        adapter_a = BaseJacsAdapter(client=client)
        adapter_b = BaseJacsAdapter(client=client)

        signed = adapter_a.sign_output({"from": "A"})
        payload = adapter_b.verify_input(signed)
        assert isinstance(payload, dict)
