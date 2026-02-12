"""
Tests for JacsClient A2A convenience methods (Task #7 / [2.1.1]).

Verifies:
- get_a2a() returns a JACSA2AIntegration wired to the client
- export_agent_card() builds an A2AAgentCard from agent JSON
- url and skills parameters are propagated correctly
- Both methods work with mock agents (no Rust required)
"""

import json

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from jacs.client import JacsClient
from jacs.a2a import JACSA2AIntegration, A2AAgentCard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client_with_mock_agent(agent_json: dict) -> JacsClient:
    """Create a JacsClient with a mock _agent that returns the given agent JSON."""
    client = JacsClient.__new__(JacsClient)
    client._strict = False
    client._agent = MagicMock()
    client._agent.get_agent_json.return_value = json.dumps(agent_json)
    client._agent_info = MagicMock()
    client._agent_info.agent_id = agent_json.get("jacsId", "test-id")
    return client


SAMPLE_AGENT_JSON = {
    "jacsId": "agent-abc-123",
    "jacsVersion": "v2.0",
    "jacsName": "Test Bot",
    "jacsDescription": "An agent for testing A2A",
    "jacsAgentType": "ai",
    "jacsServices": [
        {
            "name": "Greeting",
            "serviceDescription": "Says hello",
            "tools": [
                {
                    "url": "/greet",
                    "function": {
                        "name": "greet",
                        "description": "Greet a user by name",
                    },
                }
            ],
        }
    ],
}


# ---------------------------------------------------------------------------
# Tests: get_a2a
# ---------------------------------------------------------------------------

class TestGetA2A:
    def test_returns_integration_wired_to_client(self):
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)
        a2a = client.get_a2a()

        assert isinstance(a2a, JACSA2AIntegration)
        assert a2a.client is client

    def test_stores_default_url(self):
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)
        a2a = client.get_a2a(url="https://mybot.example.com")

        assert a2a.default_url == "https://mybot.example.com"

    def test_stores_default_skills(self):
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)
        skills = [{"name": "custom_skill"}]
        a2a = client.get_a2a(skills=skills)

        assert a2a.default_skills == skills

    def test_defaults_to_none(self):
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)
        a2a = client.get_a2a()

        assert a2a.default_url is None
        assert a2a.default_skills is None


# ---------------------------------------------------------------------------
# Tests: export_agent_card
# ---------------------------------------------------------------------------

class TestExportAgentCard:
    def test_returns_agent_card(self):
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)
        card = client.export_agent_card()

        assert isinstance(card, A2AAgentCard)
        assert card.name == "Test Bot"
        assert card.description == "An agent for testing A2A"
        assert card.version == "v2.0"
        assert card.protocol_versions == ["0.4.0"]

    def test_card_includes_skills_from_agent(self):
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)
        card = client.export_agent_card()

        assert len(card.skills) == 1
        assert card.skills[0].name == "greet"

    def test_url_sets_domain_in_interface(self):
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)
        card = client.export_agent_card(url="mybot.example.com")

        iface = card.supported_interfaces[0]
        assert "mybot.example.com" in iface.url

    def test_skills_override(self):
        agent_json = dict(SAMPLE_AGENT_JSON)
        agent_json.pop("jacsServices", None)
        client = _make_client_with_mock_agent(agent_json)

        custom_services = [
            {
                "name": "Custom",
                "serviceDescription": "Custom service",
                "tools": [
                    {
                        "function": {
                            "name": "do_stuff",
                            "description": "Does stuff",
                        }
                    }
                ],
            }
        ]
        card = client.export_agent_card(skills=custom_services)

        assert len(card.skills) == 1
        assert card.skills[0].name == "do_stuff"

    def test_no_agent_raises(self):
        client = JacsClient.__new__(JacsClient)
        client._strict = False
        client._agent = None
        client._agent_info = None

        from jacs.types import AgentNotLoadedError

        with pytest.raises(AgentNotLoadedError):
            client.export_agent_card()

    def test_round_trip_sign_and_verify(self):
        """get_a2a -> sign_artifact -> verify_wrapped_artifact round trip (mocked)."""
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)

        signed_doc = {
            "jacsId": "art-99",
            "jacsType": "a2a-task",
            "a2aArtifact": {"action": "greet"},
            "jacsSignature": {"agentID": "agent-abc-123"},
        }
        client._agent.sign_request.return_value = json.dumps(signed_doc)
        client._agent.verify_response.return_value = {"action": "greet"}

        a2a = client.get_a2a()
        wrapped = a2a.sign_artifact({"action": "greet"}, "task")
        result = a2a.verify_wrapped_artifact(wrapped)

        assert result["valid"] is True
        assert result["signer_id"] == "agent-abc-123"


# ---------------------------------------------------------------------------
# Tests: sign_artifact convenience on JacsClient
# ---------------------------------------------------------------------------

class TestClientSignArtifact:
    def test_sign_artifact_delegates_to_a2a(self):
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)
        client._agent.sign_request.return_value = json.dumps({
            "jacsId": "sa-1",
            "jacsType": "a2a-message",
            "a2aArtifact": {"text": "hello"},
            "jacsSignature": {"agentID": "agent-abc-123"},
        })

        result = client.sign_artifact({"text": "hello"}, "message")

        assert result["jacsId"] == "sa-1"
        assert result["a2aArtifact"] == {"text": "hello"}
        client._agent.sign_request.assert_called_once()

    def test_sign_artifact_passes_parent_signatures(self):
        client = _make_client_with_mock_agent(SAMPLE_AGENT_JSON)
        client._agent.sign_request.return_value = json.dumps({
            "jacsId": "sa-2",
            "jacsParentSignatures": [{"jacsId": "parent-1"}],
        })

        result = client.sign_artifact(
            {"step": 2}, "workflow-step", parent_signatures=[{"jacsId": "parent-1"}]
        )

        call_args = client._agent.sign_request.call_args
        wrapped_input = call_args[0][0]
        assert wrapped_input["jacsParentSignatures"] == [{"jacsId": "parent-1"}]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
