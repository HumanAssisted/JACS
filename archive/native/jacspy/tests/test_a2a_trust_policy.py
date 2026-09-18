"""Tests for JACSA2AIntegration trust policy API.

Tests assess_remote_agent(), trust_a2a_agent(), trust_policy constructor
param, and verify_wrapped_artifact with assess_trust=True.
"""

import json
from unittest.mock import MagicMock

import pytest

from jacs.a2a import JACSA2AIntegration

JACS_EXTENSION_URI = "urn:jacs:provenance-v1"


def _make_mock_client():
    """Create a mock JacsClient."""
    client = MagicMock()
    agent_data = {
        "jacsId": "agent-abc",
        "jacsVersion": "1",
        "jacsName": "Test Agent",
        "jacsDescription": "Test",
        "jacsAgentType": "ai",
    }
    client._agent.get_agent_json.return_value = json.dumps(agent_data)
    return client


def _card_with_jacs(agent_id="remote-agent-xyz"):
    """Agent Card JSON with the JACS provenance extension."""
    return json.dumps({
        "name": "Remote JACS Agent",
        "description": "Has JACS provenance",
        "capabilities": {
            "extensions": [
                {"uri": JACS_EXTENSION_URI, "description": "JACS provenance"}
            ]
        },
        "metadata": {"jacsId": agent_id},
    })


def _card_without_jacs():
    """Agent Card JSON without JACS extension."""
    return json.dumps({
        "name": "Plain Agent",
        "capabilities": {},
    })


# ------------------------------------------------------------------
# Constructor trust_policy param
# ------------------------------------------------------------------


class TestTrustPolicyConstructor:
    def test_default_is_verified(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)
        assert a2a.trust_policy == "verified"

    def test_accepts_open(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client, trust_policy="open")
        assert a2a.trust_policy == "open"

    def test_accepts_strict(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client, trust_policy="strict")
        assert a2a.trust_policy == "strict"

    def test_rejects_invalid_policy(self):
        client = _make_mock_client()
        with pytest.raises(ValueError, match="Invalid trust_policy"):
            JACSA2AIntegration(client, trust_policy="permissive")


# ------------------------------------------------------------------
# assess_remote_agent
# ------------------------------------------------------------------


class TestAssessRemoteAgent:
    def test_native_assessment_surfaces_first_contact_tofu_state(self):
        client = _make_mock_client()
        client._agent.assess_a2a_agent.return_value = json.dumps({
            "allowed": True,
            "trustLevel": "JacsVerified",
            "jacsRegistered": True,
            "reason": "origin key pinned on first contact",
            "policy": "Verified",
            "firstContact": True,
        })
        a2a = JACSA2AIntegration(client)

        result = a2a.assess_remote_agent(_card_with_jacs())
        assert result["allowed"] is True
        assert result["first_contact"] is True

    def test_native_assessment_truthy_strings_do_not_become_security_booleans(self):
        client = _make_mock_client()
        client._agent.assess_a2a_agent.return_value = json.dumps({
            "allowed": "false",
            "trustLevel": "JacsVerified",
            "jacsRegistered": "true",
            "reason": "malformed native result",
            "policy": "Verified",
            "firstContact": "true",
        })
        a2a = JACSA2AIntegration(client)

        result = a2a.assess_remote_agent(_card_with_jacs())

        assert result["allowed"] is False
        assert result["jacs_registered"] is False
        assert result["first_contact"] is False

    def test_denied_native_assessment_cannot_report_trusted_level(self):
        client = _make_mock_client()
        client._agent.assess_a2a_agent.return_value = json.dumps({
            "allowed": False,
            "trustLevel": "ExplicitlyTrusted",
            "jacsRegistered": True,
            "reason": "policy denied",
            "policy": "Strict",
            "firstContact": False,
        })
        a2a = JACSA2AIntegration(client, trust_policy="strict")

        result = a2a.assess_remote_agent(_card_with_jacs())

        assert result["allowed"] is False
        assert result["trust_level"] == "untrusted"

    def test_open_always_allows(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client, trust_policy="open")

        result = a2a.assess_remote_agent(_card_without_jacs())
        assert result["allowed"] is True
        assert result["jacs_registered"] is False
        assert result["trust_level"] == "untrusted"

    def test_verified_fails_closed_without_native_cryptographic_assessment(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)  # default "verified"

        result = a2a.assess_remote_agent(_card_with_jacs())
        assert result["allowed"] is False
        assert result["jacs_registered"] is True
        assert result["trust_level"] == "untrusted"
        assert "native cryptographic assessment" in result["reason"]

    def test_verified_rejects_non_jacs(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)

        result = a2a.assess_remote_agent(_card_without_jacs())
        assert result["allowed"] is False
        assert result["jacs_registered"] is False

    def test_strict_does_not_accept_an_unverified_trust_store_boolean(self):
        client = _make_mock_client()
        client.is_trusted.return_value = True
        a2a = JACSA2AIntegration(client, trust_policy="strict")

        result = a2a.assess_remote_agent(_card_with_jacs(agent_id="trusted-id"))
        assert result["allowed"] is False
        assert result["trust_level"] == "untrusted"
        assert "native cryptographic assessment" in result["reason"]

    def test_strict_denies_when_not_in_store(self):
        client = _make_mock_client()
        client.is_trusted.return_value = False
        a2a = JACSA2AIntegration(client, trust_policy="strict")

        result = a2a.assess_remote_agent(_card_with_jacs(agent_id="unknown-id"))
        assert result["allowed"] is False
        assert result["trust_level"] == "untrusted"

    def test_policy_override(self):
        """Passing policy= overrides the instance trust_policy."""
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client, trust_policy="verified")

        # Without override: verified rejects non-JACS
        result = a2a.assess_remote_agent(_card_without_jacs())
        assert result["allowed"] is False

        # With override: open allows anything
        result = a2a.assess_remote_agent(_card_without_jacs(), policy="open")
        assert result["allowed"] is True

    def test_invalid_policy_raises(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)

        with pytest.raises(ValueError, match="Invalid trust policy"):
            a2a.assess_remote_agent(_card_without_jacs(), policy="custom")

    def test_card_returned_in_result(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client, trust_policy="open")

        result = a2a.assess_remote_agent(_card_with_jacs())
        assert result["card"]["name"] == "Remote JACS Agent"


# ------------------------------------------------------------------
# trust_a2a_agent
# ------------------------------------------------------------------


class TestTrustA2AAgent:
    def test_requires_native_agent_document_and_explicit_key(self):
        client = _make_mock_client()
        client.trust_agent_with_key.return_value = "ok"
        a2a = JACSA2AIntegration(client)

        native_agent = json.dumps({
            "jacsId": "agent-to-trust",
            "jacsVersion": "version-1",
            "jacsSignature": {"publicKeyHash": "sha256-placeholder"},
        })
        public_key = "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----"
        result = a2a.trust_a2a_agent(native_agent, public_key)
        assert result == "ok"
        client.trust_agent.assert_not_called()
        client.trust_agent_with_key.assert_called_once_with(native_agent, public_key)

    def test_rejects_unauthenticated_agent_card(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)

        with pytest.raises(ValueError, match="full native JACS agent document"):
            a2a.trust_a2a_agent(_card_with_jacs(), "public-key")
        client.trust_agent_with_key.assert_not_called()

    def test_rejects_missing_explicit_public_key(self):
        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)
        native_agent = json.dumps({
            "jacsId": "agent-to-trust",
            "jacsVersion": "version-1",
            "jacsSignature": {},
        })

        with pytest.raises(ValueError, match="explicit public key"):
            a2a.trust_a2a_agent(native_agent, "")
        client.trust_agent_with_key.assert_not_called()


# ------------------------------------------------------------------
# verify_wrapped_artifact with assess_trust
# ------------------------------------------------------------------


class TestVerifyWithTrustAssessment:
    def _make_fake_artifact(self):
        """Build a fake wrapped artifact for testing."""
        return {
            "jacsId": "artifact-123",
            "jacsVersion": "v1",
            "jacsType": "a2a-task",
            "jacsLevel": "artifact",
            "jacsVersionDate": "2026-01-01T00:00:00Z",
            "a2aArtifact": {"data": "hello"},
            "jacsSignature": {
                "agentID": "signer-agent-1",
                "agentVersion": "v1",
                "signature": "fakesig",
            },
        }

    def test_without_assess_trust_no_trust_key(self):
        client = _make_mock_client()
        client._agent.verify_response.side_effect = Exception("mock fail")
        a2a = JACSA2AIntegration(client)

        result = a2a.verify_wrapped_artifact(self._make_fake_artifact())
        assert "trust" not in result

    def test_with_assess_trust_adds_trust_key(self):
        client = _make_mock_client()
        client._agent.verify_response.side_effect = Exception("mock fail")
        a2a = JACSA2AIntegration(client, trust_policy="open")

        result = a2a.verify_wrapped_artifact(
            self._make_fake_artifact(),
            assess_trust=True,
        )
        assert "trust" in result
        assert result["trust"]["allowed"] is False
        assert result["trust"]["trust_level"] == "untrusted"
        assert "cannot elevate trust" in result["trust"]["reason"]

    def test_with_assess_trust_verified_policy(self):
        client = _make_mock_client()
        client._agent.verify_response.return_value = True
        a2a = JACSA2AIntegration(client, trust_policy="verified")

        artifact = self._make_fake_artifact()
        result = a2a.verify_wrapped_artifact(artifact, assess_trust=True)

        # A synthetic card may declare the extension, but without native
        # card/JWKS/binding assessment it cannot establish identity trust.
        assert result["trust"]["jacs_registered"] is False
        assert result["trust"]["allowed"] is False

    def test_with_assess_trust_policy_override(self):
        client = _make_mock_client()
        client._agent.verify_response.return_value = True
        a2a = JACSA2AIntegration(client, trust_policy="strict")

        result = a2a.verify_wrapped_artifact(
            self._make_fake_artifact(),
            assess_trust=True,
            trust_policy="open",
        )
        assert result["trust"]["allowed"] is False
        assert result["trust"]["trust_level"] == "untrusted"

    @pytest.mark.parametrize("policy", ["verified", "strict"])
    def test_identity_policy_never_uses_legacy_artifact_verifier(self, policy):
        client = _make_mock_client()
        client._agent.verify_response.return_value = True
        a2a = JACSA2AIntegration(client, trust_policy=policy)

        result = a2a.verify_wrapped_artifact(
            self._make_fake_artifact(),
            assess_trust=True,
        )

        assert result["valid"] is False
        assert result["trust"]["allowed"] is False
        client._agent.verify_response.assert_not_called()
