"""Tests for BaseJacsAdapter A2A methods: export_agent_card and assess_trust."""

import json
from unittest.mock import MagicMock, patch

import pytest

from jacs.adapters.base import BaseJacsAdapter
from jacs.a2a import A2AAgentCard, A2AAgentInterface, A2AAgentCapabilities, A2AAgentExtension, A2AAgentSkill

JACS_EXTENSION_URI = "urn:hai.ai:jacs-provenance-v1"

SAMPLE_AGENT_DATA = {
    "jacsId": "agent-abc-123",
    "jacsVersion": "1",
    "jacsName": "Test Agent",
    "jacsDescription": "A test agent",
    "jacsAgentType": "ai",
}


def _make_mock_client(agent_data=None):
    """Create a mock JacsClient with a minimal agent JSON response."""
    client = MagicMock()
    data = agent_data or SAMPLE_AGENT_DATA
    client._agent.get_agent_json.return_value = json.dumps(data)

    # Wire up export_agent_card to produce a real A2AAgentCard
    def _export_agent_card(url=None, skills=None):
        from jacs.a2a import JACSA2AIntegration
        ad = dict(data)
        if url:
            ad["jacsAgentDomain"] = url
        if skills:
            ad["jacsServices"] = skills
        integration = JACSA2AIntegration(client)
        return integration.export_agent_card(ad)

    client.export_agent_card.side_effect = _export_agent_card
    return client


def _make_adapter(client=None):
    """Build a BaseJacsAdapter with a mock client."""
    if client is None:
        client = _make_mock_client()
    with patch("jacs.adapters.base.BaseJacsAdapter.__init__", return_value=None):
        adapter = BaseJacsAdapter.__new__(BaseJacsAdapter)
        adapter._client = client
        adapter._strict = False
    return adapter


# ------------------------------------------------------------------
# export_agent_card
# ------------------------------------------------------------------


class TestExportAgentCard:
    def test_returns_dict_with_required_fields(self):
        adapter = _make_adapter()
        card = adapter.export_agent_card()

        assert isinstance(card, dict)
        assert card["name"] == "Test Agent"
        assert card["description"] == "A test agent"
        assert "protocolVersions" in card
        assert "supportedInterfaces" in card
        assert "capabilities" in card
        assert "skills" in card

    def test_url_injected_into_interfaces(self):
        adapter = _make_adapter()
        card = adapter.export_agent_card(url="myhost.example.com")

        interfaces = card["supportedInterfaces"]
        assert len(interfaces) >= 1
        assert "myhost.example.com" in interfaces[0]["url"]

    def test_skills_injected(self):
        adapter = _make_adapter()
        skills = [
            {
                "name": "Custom Service",
                "serviceDescription": "Does custom things",
                "tools": [
                    {
                        "function": {
                            "name": "custom_fn",
                            "description": "A custom function",
                        }
                    }
                ],
            }
        ]
        card = adapter.export_agent_card(skills=skills)

        skill_names = [s["name"] for s in card["skills"]]
        assert "custom_fn" in skill_names

    def test_jacs_extension_present(self):
        adapter = _make_adapter()
        card = adapter.export_agent_card()

        extensions = card.get("capabilities", {}).get("extensions", [])
        uris = [ext.get("uri") for ext in extensions]
        assert JACS_EXTENSION_URI in uris


# ------------------------------------------------------------------
# assess_trust
# ------------------------------------------------------------------


def _card_with_jacs_extension(agent_id="agent-xyz"):
    """Build a minimal Agent Card JSON with the JACS extension."""
    return json.dumps({
        "name": "Remote Agent",
        "capabilities": {
            "extensions": [
                {"uri": JACS_EXTENSION_URI, "description": "JACS provenance"}
            ]
        },
        "metadata": {"jacsId": agent_id},
    })


def _card_without_jacs():
    """Build a minimal Agent Card JSON without JACS extension."""
    return json.dumps({
        "name": "Plain Agent",
        "capabilities": {},
    })


class TestAssessTrust:
    def test_open_always_allows(self):
        adapter = _make_adapter()
        result = adapter.assess_trust(_card_without_jacs(), policy="open")

        assert result["allowed"] is True
        assert result["jacs_registered"] is False
        assert result["trust_level"] == "untrusted"

    def test_verified_allows_jacs_registered(self):
        adapter = _make_adapter()
        result = adapter.assess_trust(_card_with_jacs_extension(), policy="verified")

        assert result["allowed"] is True
        assert result["jacs_registered"] is True
        assert result["trust_level"] == "jacs_registered"

    def test_verified_rejects_non_jacs(self):
        adapter = _make_adapter()
        result = adapter.assess_trust(_card_without_jacs(), policy="verified")

        assert result["allowed"] is False
        assert result["jacs_registered"] is False

    def test_strict_requires_trust_store(self):
        client = _make_mock_client()
        client.is_trusted.return_value = True
        adapter = _make_adapter(client)

        result = adapter.assess_trust(
            _card_with_jacs_extension(agent_id="trusted-agent"),
            policy="strict",
        )

        assert result["allowed"] is True
        assert result["trust_level"] == "trusted"
        client.is_trusted.assert_called_once_with("trusted-agent")

    def test_strict_denies_untrusted(self):
        client = _make_mock_client()
        client.is_trusted.return_value = False
        adapter = _make_adapter(client)

        result = adapter.assess_trust(
            _card_with_jacs_extension(agent_id="unknown-agent"),
            policy="strict",
        )

        assert result["allowed"] is False
        assert result["trust_level"] == "jacs_registered"

    def test_invalid_policy_raises(self):
        adapter = _make_adapter()
        with pytest.raises(ValueError, match="Invalid trust policy"):
            adapter.assess_trust(_card_without_jacs(), policy="custom")

    def test_card_returned_in_result(self):
        adapter = _make_adapter()
        card_json = _card_with_jacs_extension()
        result = adapter.assess_trust(card_json, policy="open")

        assert result["card"]["name"] == "Remote Agent"
