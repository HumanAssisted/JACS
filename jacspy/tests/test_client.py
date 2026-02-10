"""Tests for jacs.client.JacsClient instance-based API."""

import json

import pytest

from jacs.client import JacsClient
from jacs.types import SignedDocument, VerificationResult, AgentNotLoadedError
import jacs.simple as jacs_simple


class TestEphemeralClients:
    """Tests using ephemeral (in-memory) clients."""

    def test_two_clients_different_ids(self):
        """Two ephemeral JacsClient instances must have different agent_ids."""
        client_a = JacsClient.ephemeral()
        client_b = JacsClient.ephemeral()

        assert client_a.agent_id != client_b.agent_id
        assert client_a.agent_id  # non-empty
        assert client_b.agent_id  # non-empty

    def test_client_sign_verify(self):
        """Sign a message and verify it round-trips correctly."""
        client = JacsClient.ephemeral()
        signed = client.sign_message({"action": "approve", "amount": 42})

        assert isinstance(signed, SignedDocument)
        assert signed.document_id  # non-empty
        assert signed.raw_json  # non-empty

        result = client.verify(signed.raw_json)
        assert isinstance(result, VerificationResult)
        assert result.valid

    def test_client_context_manager(self):
        """Context manager should yield a usable client and reset on exit."""
        with JacsClient.ephemeral() as client:
            assert client.agent_id  # usable inside block
            signed = client.sign_message("test")
            assert signed.document_id

        # After exiting, the client should be reset
        with pytest.raises((AgentNotLoadedError, AttributeError)):
            client.sign_message("should fail")

    def test_client_properties(self):
        """agent_id and name properties should be accessible."""
        client = JacsClient.ephemeral()
        assert isinstance(client.agent_id, str)
        assert len(client.agent_id) > 0
        # name may be "ephemeral" or similar
        assert client.name is not None

    def test_client_verify_self(self):
        """verify_self should return valid for a freshly created ephemeral agent."""
        client = JacsClient.ephemeral()
        result = client.verify_self()
        assert isinstance(result, VerificationResult)
        assert result.valid

    def test_client_reset(self):
        """After reset(), operations should raise."""
        client = JacsClient.ephemeral()
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
        client = JacsClient.ephemeral()
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
