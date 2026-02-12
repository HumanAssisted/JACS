"""
Tests for jacs.a2a_server — FastAPI A2A routes (Task #18 / [2.3.1]).

Verifies:
- jacs_a2a_routes() returns a router with all 5 well-known endpoints
- CORS headers are present on responses
- ?signed=true query param works on agent-card.json
- create_a2a_app() builds a complete FastAPI application
- serve_a2a() delegates to uvicorn.run
- Routes return correct content for each well-known document
"""

import json

import pytest
from unittest.mock import MagicMock, patch


def _has_fastapi() -> bool:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        return True
    except ImportError:
        return False


def _make_mock_client(agent_data: dict | None = None) -> MagicMock:
    """Create a mock JacsClient with a mock _agent."""
    if agent_data is None:
        agent_data = {
            "jacsId": "test-agent-1",
            "jacsName": "Test A2A Bot",
            "jacsDescription": "A test agent for A2A server",
            "jacsVersion": "v2.0",
            "jacsAgentType": "ai",
            "jacsServices": [
                {
                    "name": "Greeting",
                    "serviceDescription": "Says hello",
                    "tools": [
                        {
                            "function": {
                                "name": "greet",
                                "description": "Greet a user",
                            }
                        }
                    ],
                }
            ],
        }
    client = MagicMock()
    client._agent = MagicMock()
    client._agent.get_agent_json.return_value = json.dumps(agent_data)
    client._agent_info = MagicMock()
    client._agent_info.agent_id = agent_data.get("jacsId", "test-id")
    client._agent_info.public_key_path = None
    return client


# ---------------------------------------------------------------------------
# All tests require fastapi
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(
    not _has_fastapi(), reason="fastapi/uvicorn not installed"
)


class TestJacsA2ARoutes:
    """Tests for jacs_a2a_routes()."""

    def _get_test_client(self, client=None, skills=None):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from jacs.a2a_server import jacs_a2a_routes

        mock_client = client or _make_mock_client()
        app = FastAPI()
        router = jacs_a2a_routes(mock_client, skills=skills)
        app.include_router(router)
        return TestClient(app)

    def test_agent_card_endpoint(self):
        tc = self._get_test_client()
        resp = tc.get("/.well-known/agent-card.json")

        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Test A2A Bot"
        assert body["protocolVersions"] == ["0.4.0"]
        assert body["description"] == "A test agent for A2A server"

    def test_agent_card_has_skills(self):
        tc = self._get_test_client()
        resp = tc.get("/.well-known/agent-card.json")

        body = resp.json()
        assert len(body["skills"]) == 1
        assert body["skills"][0]["name"] == "greet"

    def test_jacs_extension_endpoint(self):
        tc = self._get_test_client()
        resp = tc.get("/.well-known/jacs-extension.json")

        assert resp.status_code == 200
        body = resp.json()
        assert body["uri"] == "urn:hai.ai:jacs-provenance-v1"
        assert "documentSigning" in body["capabilities"]
        assert body["capabilities"]["documentSigning"]["algorithms"] == [
            "ring-Ed25519",
            "RSA-PSS",
            "pq-dilithium",
            "pq2025",
        ]

    def test_jwks_endpoint(self):
        tc = self._get_test_client()
        resp = tc.get("/.well-known/jwks.json")

        assert resp.status_code == 200
        body = resp.json()
        assert "keys" in body

    def test_jacs_agent_endpoint(self):
        tc = self._get_test_client()
        resp = tc.get("/.well-known/jacs-agent.json")

        assert resp.status_code == 200
        body = resp.json()
        assert body.get("agentId") == "test-agent-1"

    def test_jacs_pubkey_endpoint(self):
        tc = self._get_test_client()
        resp = tc.get("/.well-known/jacs-pubkey.json")

        assert resp.status_code == 200
        body = resp.json()
        assert body.get("agentId") == "test-agent-1"

    def test_cors_headers(self):
        tc = self._get_test_client()
        resp = tc.get("/.well-known/agent-card.json")

        assert resp.headers.get("access-control-allow-origin") == "*"
        assert "GET" in resp.headers.get("access-control-allow-methods", "")

    def test_signed_query_param(self):
        """?signed=true returns the card (same content since no JWS configured)."""
        tc = self._get_test_client()
        resp = tc.get("/.well-known/agent-card.json?signed=true")

        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Test A2A Bot"

    def test_skills_override(self):
        """Custom skills are used instead of agent's own services."""
        custom_skills = [
            {
                "name": "Custom",
                "serviceDescription": "Custom service",
                "tools": [
                    {
                        "function": {
                            "name": "do_custom",
                            "description": "Does custom stuff",
                        }
                    }
                ],
            }
        ]
        tc = self._get_test_client(skills=custom_skills)
        resp = tc.get("/.well-known/agent-card.json")

        body = resp.json()
        assert len(body["skills"]) == 1
        assert body["skills"][0]["name"] == "do_custom"


class TestCreateA2AApp:
    """Tests for create_a2a_app()."""

    def test_creates_fastapi_app(self):
        from jacs.a2a_server import create_a2a_app

        client = _make_mock_client()
        app = create_a2a_app(client, title="My Test Agent")

        assert app.title == "My Test Agent"

    def test_app_has_all_routes(self):
        from fastapi.testclient import TestClient
        from jacs.a2a_server import create_a2a_app

        client = _make_mock_client()
        app = create_a2a_app(client)
        tc = TestClient(app)

        paths = [
            "/.well-known/agent-card.json",
            "/.well-known/jwks.json",
            "/.well-known/jacs-agent.json",
            "/.well-known/jacs-pubkey.json",
            "/.well-known/jacs-extension.json",
        ]
        for path in paths:
            resp = tc.get(path)
            assert resp.status_code == 200, f"Failed for {path}"


class TestServeA2A:
    """Tests for serve_a2a()."""

    def test_serve_calls_uvicorn_run(self):
        from jacs.a2a_server import serve_a2a

        client = _make_mock_client()

        with patch("uvicorn.run") as mock_run:
            serve_a2a(client, port=9999, host="127.0.0.1")

        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[1]["port"] == 9999
        assert call_args[1]["host"] == "127.0.0.1"

    def test_serve_passes_skills(self):
        from fastapi.testclient import TestClient
        from jacs.a2a_server import create_a2a_app

        custom_skills = [
            {
                "name": "Skill",
                "serviceDescription": "A skill",
                "tools": [
                    {
                        "function": {
                            "name": "my_skill",
                            "description": "My skill",
                        }
                    }
                ],
            }
        ]
        client = _make_mock_client()
        app = create_a2a_app(client, skills=custom_skills)
        tc = TestClient(app)

        resp = tc.get("/.well-known/agent-card.json")
        body = resp.json()
        assert body["skills"][0]["name"] == "my_skill"


class TestServeRefactoring:
    """Verify that JACSA2AIntegration.serve() delegates to a2a_server."""

    def test_serve_delegates_to_serve_a2a(self):
        from jacs.a2a import JACSA2AIntegration

        client = _make_mock_client()
        a2a = JACSA2AIntegration(client)

        with patch("jacs.a2a_server.serve_a2a") as mock_serve:
            a2a.serve(port=7777, host="0.0.0.0")

        mock_serve.assert_called_once()
        call_args = mock_serve.call_args
        assert call_args[1]["port"] == 7777
        assert call_args[1]["host"] == "0.0.0.0"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
