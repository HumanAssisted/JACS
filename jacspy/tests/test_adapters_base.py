"""Tests for jacs.adapters.base.BaseJacsAdapter."""

import json
import logging
from copy import deepcopy
from unittest.mock import MagicMock

import pytest

from jacs.adapters.base import BaseJacsAdapter
from jacs.client import JacsClient
from jacs.types import SigningError
from conftest import TEST_ALGORITHM


def _portable_v2_document():
    return {
        "jacsId": "document-id",
        "jacsVersion": "1",
        "jacsDocument": {"result": "ok"},
        "jacsSignature": {
            "signature": "c2lnbmF0dXJl",
            "agentID": "agent-id",
            "agentVersion": "1",
            "publicKeyHash": "sha256:public-key",
            "date": "2026-07-10T00:00:00Z",
            "signatureContentVersion": "jacs-signature-v2",
        },
    }


@pytest.fixture(scope="module")
def ephemeral_client():
    """Create an ephemeral JacsClient for testing."""
    return JacsClient.ephemeral(algorithm=TEST_ALGORITHM)


@pytest.fixture
def adapter(ephemeral_client):
    """Create a BaseJacsAdapter wrapping an ephemeral client."""
    return BaseJacsAdapter(client=ephemeral_client)


@pytest.fixture
def strict_adapter(ephemeral_client):
    """Create a strict-mode BaseJacsAdapter."""
    return BaseJacsAdapter(client=ephemeral_client, strict=True)


@pytest.fixture
def unverified_passthrough_adapter(ephemeral_client):
    """Create an adapter with the explicitly dangerous compatibility opt-in."""
    return BaseJacsAdapter(
        client=ephemeral_client,
        allow_unverified_passthrough=True,
    )


@pytest.fixture
def unsigned_output_adapter(ephemeral_client):
    """Create an adapter with the explicitly dangerous unsigned-output opt-in."""
    return BaseJacsAdapter(
        client=ephemeral_client,
        allow_unsigned_output=True,
    )


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

    def test_unverified_passthrough_defaults_false(self, ephemeral_client):
        adapter = BaseJacsAdapter(client=ephemeral_client)
        assert adapter.allow_unverified_passthrough is False

    def test_unsigned_output_defaults_false(self, ephemeral_client):
        adapter = BaseJacsAdapter(client=ephemeral_client)
        assert adapter.allow_unsigned_output is False

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

    @pytest.mark.parametrize(
        ("label", "raw_json"),
        [
            ("empty", ""),
            ("plain", '{"result":"not signed"}'),
            (
                "legacy",
                json.dumps(
                    {
                        **_portable_v2_document(),
                        "jacsSignature": {
                            **_portable_v2_document()["jacsSignature"],
                            "signatureContentVersion": "jacs-signature-v1",
                        },
                    }
                ),
            ),
            (
                "incomplete",
                json.dumps(
                    {
                        **_portable_v2_document(),
                        "jacsSignature": {
                            **_portable_v2_document()["jacsSignature"],
                            "publicKeyHash": "",
                        },
                    }
                ),
            ),
        ],
    )
    def test_rejects_non_portable_signer_output(self, label, raw_json):
        client = MagicMock()
        client.sign_message.return_value.raw_json = raw_json
        adapter = BaseJacsAdapter(client=client)

        with pytest.raises(SigningError, match="portable v2"):
            adapter.sign_output({"label": label})

    def test_accepts_complete_portable_v2_signer_output(self):
        client = MagicMock()
        expected = json.dumps(deepcopy(_portable_v2_document()))
        client.sign_message.return_value.raw_json = expected

        assert BaseJacsAdapter(client=client).sign_output({"ok": True}) == expected


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

    def test_truthy_non_boolean_valid_flag_fails_closed(self):
        class MalformedClient:
            def verify(self, _signed_json):
                return type(
                    "MalformedResult",
                    (),
                    {"valid": "false", "errors": []},
                )()

        adapter = BaseJacsAdapter(client=MalformedClient(), strict=True)
        with pytest.raises(Exception, match="Verification failed"):
            adapter.verify_input('{"jacsDocument":{"role":"admin"}}')

    def test_tampered_exact_input_is_never_returned_as_verified(self, adapter):
        """The verifier and payload parser consume the same immutable JSON string."""
        signed = adapter.sign_output({"role": "user"})
        tampered = json.loads(signed)
        payload = tampered.get("content", tampered.get("jacsDocument"))
        assert isinstance(payload, dict), (
            "signed adapter output must expose an object payload"
        )
        payload["role"] = "admin"

        with pytest.raises(Exception, match="Verification failed"):
            adapter.verify_input(json.dumps(tampered))


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

    def test_verify_bad_input_fails_closed_by_default(self, adapter):
        """Signing permissiveness must not silently make verification permissive."""
        with pytest.raises(Exception, match="Verification failed"):
            adapter.verify_input_or_passthrough('{"not": "signed"}')

    def test_verify_bad_input_passthrough_requires_explicit_opt_in(
        self, unverified_passthrough_adapter
    ):
        """The legacy passthrough behavior requires a dangerous explicit opt-in."""
        bad_json = '{"not": "signed"}'
        result = unverified_passthrough_adapter.verify_input_or_passthrough(bad_json)
        assert result == {"not": "signed"}

    def test_verify_non_json_passthrough(self, unverified_passthrough_adapter):
        """Permissive mode should return raw string if not valid JSON."""
        result = unverified_passthrough_adapter.verify_input_or_passthrough(
            "not json at all"
        )
        assert result == "not json at all"

    def test_verify_passthrough_logs_warning(
        self, unverified_passthrough_adapter, caplog
    ):
        """Permissive mode should log a warning on verification failure."""
        with caplog.at_level(logging.WARNING, logger="jacs.adapters"):
            unverified_passthrough_adapter.verify_input_or_passthrough(
                '{"not": "signed"}'
            )
        assert any("verification failed" in r.message.lower() for r in caplog.records)

    def test_sign_failure_fails_closed_by_default(self):
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        adapter = BaseJacsAdapter(client=client, strict=False)
        client.reset()

        with pytest.raises(Exception):
            adapter.sign_output_or_passthrough({"must": "not escape"})

    def test_sign_passthrough_on_error_requires_explicit_opt_in(self):
        """Unsigned output requires a dangerous compatibility opt-in."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        adapter = BaseJacsAdapter(client=client, allow_unsigned_output=True)
        client.reset()

        data = {"still": "works"}
        result = adapter.sign_output_or_passthrough(data)
        assert json.loads(result) == data

    def test_sign_passthrough_string(self):
        """If signing a string fails, permissive mode returns the string."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        adapter = BaseJacsAdapter(client=client, allow_unsigned_output=True)
        client.reset()

        result = adapter.sign_output_or_passthrough("raw text")
        assert result == "raw text"

    def test_sign_passthrough_logs_warning(self, caplog):
        """Permissive mode should log a warning when signing fails."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        adapter = BaseJacsAdapter(client=client, allow_unsigned_output=True)
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
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        adapter_a = BaseJacsAdapter(client=client)
        adapter_b = BaseJacsAdapter(client=client)

        signed = adapter_a.sign_output({"from": "A"})
        payload = adapter_b.verify_input(signed)
        assert isinstance(payload, dict)
