"""Tests for jacs.client.JacsClient instance-based API."""

import json
import os
from pathlib import Path

import pytest

from jacs.client import JacsClient
from jacs.types import SignedDocument, VerificationResult, AgentInfo, AgentNotLoadedError
import jacs.simple as jacs_simple
import jacs.client as jacs_client
from conftest import TEST_ALGORITHM, TEST_ALGORITHM_INTERNAL


class TestEphemeralClients:
    """Tests using ephemeral (in-memory) clients."""

    def test_two_clients_different_ids(self):
        """Two ephemeral JacsClient instances must have different agent_ids."""
        client_a = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        client_b = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)

        assert client_a.agent_id != client_b.agent_id
        assert client_a.agent_id  # non-empty
        assert client_b.agent_id  # non-empty

    def test_client_sign_verify(self):
        """Sign a message and verify it round-trips correctly."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        signed = client.sign_message({"action": "approve", "amount": 42})

        assert isinstance(signed, SignedDocument)
        assert signed.document_id  # non-empty
        assert signed.raw_json  # non-empty

        result = client.verify(signed.raw_json)
        assert isinstance(result, VerificationResult)
        assert result.valid

    def test_client_context_manager(self):
        """Context manager should yield a usable client and reset on exit."""
        with JacsClient.ephemeral(algorithm=TEST_ALGORITHM) as client:
            assert client.agent_id  # usable inside block
            signed = client.sign_message("test")
            assert signed.document_id

        # After exiting, the client should be reset
        with pytest.raises((AgentNotLoadedError, AttributeError)):
            client.sign_message("should fail")

    def test_client_properties(self):
        """agent_id and name properties should be accessible."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        assert isinstance(client.agent_id, str)
        assert len(client.agent_id) > 0
        # name may be "ephemeral" or similar
        assert client.name is not None

    def test_client_verify_self(self):
        """verify_self should return valid for a freshly created ephemeral agent."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        result = client.verify_self()
        assert isinstance(result, VerificationResult)
        assert result.valid

    def test_client_reset(self):
        """After reset(), operations should raise."""
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        assert client.agent_id  # works before reset
        client.reset()
        with pytest.raises((AgentNotLoadedError, AttributeError)):
            _ = client.agent_id


class TestAgreements:
    """Tests for agreement methods on JacsClient (ephemeral agents)."""

    def test_client_agreement_with_options(self):
        """Create an agreement with timeout + quorum (flat kwargs).

        Note: ephemeral agents may not support full agreement workflows.
        This test verifies the method signature and argument passing.
        """
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        # Ephemeral agents raise JacsError for agreement operations
        # (agreements need persistent storage). Verify the method exists
        # and accepts the right kwargs.
        from jacs.types import JacsError

        with pytest.raises(JacsError):
            client.create_agreement(
                document={"proposal": "Merge repos"},
                agent_ids=["agent-1", "agent-2"],
                question="Do you approve?",
                timeout="2026-12-31T23:59:59Z",
                quorum=1,
            )


class TestGenerateVerifyLink:
    """Tests for JacsClient.generate_verify_link()."""

    def test_returns_url_with_default_base(self):
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        link = client.generate_verify_link('{"hello":"world"}')
        assert link.startswith("https://hai.ai/jacs/verify?s=")

    def test_custom_base_url(self):
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        link = client.generate_verify_link("test", base_url="https://example.com/verify")
        assert link.startswith("https://example.com/verify?s=")

    def test_round_trip_decode(self):
        import base64
        client = JacsClient.ephemeral(algorithm=TEST_ALGORITHM)
        original = '{"signed":"document","data":123}'
        link = client.generate_verify_link(original)
        encoded = link.split("?s=")[1]
        decoded = base64.urlsafe_b64decode(encoded).decode("utf-8")
        assert decoded == original


class TestGlobalReset:
    """Tests for the global reset function in simple.py."""

    def test_global_reset(self):
        """After jacs.reset(), the global agent should be None."""
        # Ensure it's clean first
        jacs_simple.reset()
        assert not jacs_simple.is_loaded()

        # The global _global_agent should be None after reset
        assert jacs_simple._global_agent is None
        assert jacs_simple._agent_info is None


def _resolved_config_path(config_path: Path, candidate: str) -> Path:
    if os.path.isabs(candidate):
        return Path(candidate)
    return (config_path.parent / candidate).resolve()


class TestPersistentQuickstart:
    def test_client_quickstart_uses_nested_config_path_and_restores_generated_password(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("JACS_PRIVATE_KEY_PASSWORD", raising=False)
        monkeypatch.delenv("JACS_SAVE_PASSWORD_FILE", raising=False)

        client = JacsClient.quickstart(
            name="client-test-agent",
            domain="client-test.example.com",
            algorithm=TEST_ALGORITHM_INTERNAL,
            config_path="nested/jacs.config.json",
        )

        config_path = tmp_path / "nested" / "jacs.config.json"
        assert client.agent_id
        assert config_path.exists()
        assert os.environ.get("JACS_PRIVATE_KEY_PASSWORD") is None

        config = json.loads(config_path.read_text(encoding="utf-8"))
        data_dir = _resolved_config_path(config_path, config["jacs_data_directory"])
        key_dir = _resolved_config_path(config_path, config["jacs_key_directory"])
        assert data_dir.exists()
        assert key_dir.exists()

        signed = client.sign_message({"quickstart": True})
        assert signed.document_id

    def test_simple_quickstart_uses_nested_config_path_and_restores_generated_password(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("JACS_PRIVATE_KEY_PASSWORD", raising=False)
        monkeypatch.delenv("JACS_SAVE_PASSWORD_FILE", raising=False)
        jacs_simple.reset()

        info = jacs_simple.quickstart(
            name="simple-test-agent",
            domain="simple-test.example.com",
            algorithm=TEST_ALGORITHM_INTERNAL,
            config_path="nested/jacs.config.json",
        )

        config_path = tmp_path / "nested" / "jacs.config.json"
        assert info.agent_id
        assert config_path.exists()
        assert os.environ.get("JACS_PRIVATE_KEY_PASSWORD") is None

        config = json.loads(config_path.read_text(encoding="utf-8"))
        data_dir = _resolved_config_path(config_path, config["jacs_data_directory"])
        key_dir = _resolved_config_path(config_path, config["jacs_key_directory"])
        assert data_dir.exists()
        assert key_dir.exists()

        signed = jacs_simple.sign_message({"quickstart": True})
        assert signed.document_id
        jacs_simple.reset()


class TestVerifyByIdUsesNativeStorage:
    def test_client_verify_by_id_uses_native_document_lookup(self, monkeypatch):
        class FakeAgent:
            def verify_document_by_id(self, doc_id):
                assert doc_id == "doc-1:1"
                return True

            def get_document_by_id(self, doc_id):
                assert doc_id == "doc-1:1"
                return json.dumps(
                    {
                        "jacsSignature": {
                            "agentID": "agent-1",
                            "publicKeyHash": "pkh-1",
                            "date": "2026-03-10T00:00:00Z",
                        }
                    }
                )

        def fail_read(*_args, **_kwargs):
            raise AssertionError("_read_document_by_id should not be used")

        monkeypatch.setattr(jacs_client, "_read_document_by_id", fail_read)
        client = JacsClient.__new__(JacsClient)
        client._strict = False
        client._agent = FakeAgent()
        client._agent_info = AgentInfo(agent_id="agent-1", version="1", config_path=None)

        result = client.verify_by_id("doc-1:1")

        assert result.valid is True
        assert result.signer_id == "agent-1"
        assert result.signer_public_key_hash == "pkh-1"
        assert result.timestamp == "2026-03-10T00:00:00Z"

    def test_simple_verify_by_id_uses_native_document_lookup(self, monkeypatch):
        class FakeAgent:
            def verify_document_by_id(self, doc_id):
                assert doc_id == "doc-2:1"
                return True

            def get_document_by_id(self, doc_id):
                assert doc_id == "doc-2:1"
                return json.dumps(
                    {
                        "jacsSignature": {
                            "agentID": "agent-2",
                            "publicKeyHash": "pkh-2",
                            "date": "2026-03-10T00:00:01Z",
                        }
                    }
                )

        def fail_read(*_args, **_kwargs):
            raise AssertionError("_read_document_by_id should not be used")

        monkeypatch.setattr(jacs_simple, "_read_document_by_id", fail_read)
        monkeypatch.setattr(jacs_simple, "_global_agent", FakeAgent())
        monkeypatch.setattr(
            jacs_simple,
            "_agent_info",
            AgentInfo(agent_id="agent-2", version="1", config_path=None),
        )
        monkeypatch.setattr(jacs_simple, "_strict", False)

        result = jacs_simple.verify_by_id("doc-2:1")

        assert result.valid is True
        assert result.signer_id == "agent-2"
        assert result.signer_public_key_hash == "pkh-2"
        assert result.timestamp == "2026-03-10T00:00:01Z"
