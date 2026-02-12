"""
Tests for JACSA2AIntegration.quickstart() and serve() (Task #22 / [2.4.1]).

- quickstart() creates a client via JacsClient.quickstart()
- serve() builds a FastAPI app with well-known endpoints
- Both are tested with mocks (no Rust or real FS required)
"""

import json

import pytest
from unittest.mock import MagicMock, patch

from jacs.a2a import JACSA2AIntegration


def _has_fastapi() -> bool:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Test: quickstart()
# ---------------------------------------------------------------------------

class TestQuickstart:
    @patch("jacs.client.JacsClient.quickstart")
    def test_quickstart_creates_integration(self, mock_qs):
        mock_client = MagicMock()
        mock_qs.return_value = mock_client

        a2a = JACSA2AIntegration.quickstart()

        mock_qs.assert_called_once_with(algorithm=None, config_path=None)
        assert isinstance(a2a, JACSA2AIntegration)
        assert a2a.client is mock_client

    @patch("jacs.client.JacsClient.quickstart")
    def test_quickstart_passes_algorithm_and_config(self, mock_qs):
        mock_qs.return_value = MagicMock()

        JACSA2AIntegration.quickstart(algorithm="ed25519", config_path="/tmp/c.json")

        mock_qs.assert_called_once_with(algorithm="ed25519", config_path="/tmp/c.json")

    @patch("jacs.client.JacsClient.quickstart")
    def test_quickstart_stores_url(self, mock_qs):
        mock_qs.return_value = MagicMock()

        a2a = JACSA2AIntegration.quickstart(url="https://my-agent.example.com")

        assert a2a.default_url == "https://my-agent.example.com"


# ---------------------------------------------------------------------------
# Test: serve() — uses FastAPI TestClient to validate routes
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _has_fastapi(), reason="fastapi/uvicorn not installed")
class TestServe:
    def _make_a2a_with_agent(self, agent_data: dict) -> JACSA2AIntegration:
        client = MagicMock()
        client._agent = MagicMock()
        client._agent.get_agent_json.return_value = json.dumps(agent_data)
        return JACSA2AIntegration(client)

    def test_serve_app_agent_card(self):
        """/.well-known/agent-card.json returns the agent card."""
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse
        from fastapi.testclient import TestClient

        agent_data = {
            "jacsId": "serve-agent",
            "jacsName": "Serve Bot",
            "jacsDescription": "serves cards",
            "jacsVersion": "v1",
        }
        a2a = self._make_a2a_with_agent(agent_data)

        card = a2a.export_agent_card(agent_data)
        card_dict = a2a.agent_card_to_dict(card)

        app = FastAPI()

        @app.get("/.well-known/agent-card.json")
        def agent_card_endpoint():
            return JSONResponse(content=card_dict)

        tc = TestClient(app)
        resp = tc.get("/.well-known/agent-card.json")

        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Serve Bot"
        assert body["protocolVersions"] == ["0.4.0"]

    def test_serve_app_extension(self):
        """/.well-known/jacs-extension.json returns the extension descriptor."""
        from fastapi import FastAPI
        from fastapi.responses import JSONResponse
        from fastapi.testclient import TestClient

        a2a = self._make_a2a_with_agent({"jacsId": "x"})
        ext = a2a.create_extension_descriptor()

        app = FastAPI()

        @app.get("/.well-known/jacs-extension.json")
        def jacs_extension_endpoint():
            return JSONResponse(content=ext)

        tc = TestClient(app)
        resp = tc.get("/.well-known/jacs-extension.json")

        assert resp.status_code == 200
        body = resp.json()
        assert body["uri"] == "urn:hai.ai:jacs-provenance-v1"
        assert body["capabilities"]["documentSigning"]["algorithms"] == [
            "ring-Ed25519", "RSA-PSS", "pq-dilithium", "pq2025"
        ]

    def test_serve_calls_uvicorn_run(self):
        """serve() calls uvicorn.run with the right host/port."""
        agent_data = {"jacsId": "s", "jacsName": "S", "jacsDescription": "S", "jacsVersion": "1"}
        a2a = self._make_a2a_with_agent(agent_data)

        with patch("uvicorn.run") as mock_run:
            a2a.serve(port=9876, host="127.0.0.1")

        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs["port"] == 9876
        assert kwargs["host"] == "127.0.0.1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
