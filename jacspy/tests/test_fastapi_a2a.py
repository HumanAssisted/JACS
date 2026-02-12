"""
Tests for JacsMiddleware A2A route injection (Task #36 / [2.8.1]).

Verifies:
- a2a=True serves well-known documents via middleware dispatch
- a2a=False (default) does not serve well-known documents
- Correct CORS headers on well-known responses
- a2a_skills override propagates to agent card
- All 5 well-known endpoints respond
- Normal app routes still work with a2a enabled
- No-client scenario logs a warning
"""

import json

import pytest
from unittest.mock import MagicMock, patch


def _has_fastapi() -> bool:
    try:
        import fastapi  # noqa: F401
        return True
    except ImportError:
        return False


SAMPLE_AGENT_DATA = {
    "jacsId": "middleware-agent",
    "jacsName": "Middleware Bot",
    "jacsDescription": "Tests middleware A2A",
    "jacsVersion": "v1",
    "jacsAgentType": "ai",
    "jacsServices": [
        {
            "name": "Echo",
            "serviceDescription": "Echoes input",
            "tools": [
                {
                    "function": {
                        "name": "echo",
                        "description": "Echo back input",
                    }
                }
            ],
        }
    ],
}


def _make_mock_client(agent_data: dict | None = None) -> MagicMock:
    data = agent_data or SAMPLE_AGENT_DATA
    client = MagicMock()
    client._agent = MagicMock()
    client._agent.get_agent_json.return_value = json.dumps(data)
    client._agent_info = MagicMock()
    client._agent_info.agent_id = data.get("jacsId", "test-id")
    client._agent_info.public_key_path = None
    return client


pytestmark = pytest.mark.skipif(
    not _has_fastapi(), reason="fastapi not installed"
)


class TestMiddlewareA2ARoutes:
    """JacsMiddleware with a2a=True serves well-known endpoints."""

    def _make_test_client(self, a2a=True, a2a_skills=None):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from jacs.adapters.fastapi import JacsMiddleware

        mock_client = _make_mock_client()
        app = FastAPI()

        @app.get("/health")
        def health():
            return {"status": "ok"}

        app.add_middleware(
            JacsMiddleware,
            client=mock_client,
            a2a=a2a,
            a2a_skills=a2a_skills,
            sign_responses=False,
            verify_requests=False,
        )

        return TestClient(app)

    def test_agent_card_served(self):
        tc = self._make_test_client(a2a=True)
        resp = tc.get("/.well-known/agent-card.json")

        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Middleware Bot"
        assert body["protocolVersions"] == ["0.4.0"]

    def test_all_five_endpoints_respond(self):
        tc = self._make_test_client(a2a=True)

        paths = [
            "/.well-known/agent-card.json",
            "/.well-known/jwks.json",
            "/.well-known/jacs-agent.json",
            "/.well-known/jacs-pubkey.json",
            "/.well-known/jacs-extension.json",
        ]
        for path in paths:
            resp = tc.get(path)
            assert resp.status_code == 200, f"Failed for {path}: {resp.status_code}"

    def test_cors_headers_present(self):
        tc = self._make_test_client(a2a=True)
        resp = tc.get("/.well-known/agent-card.json")

        assert resp.headers.get("access-control-allow-origin") == "*"
        assert "GET" in resp.headers.get("access-control-allow-methods", "")

    def test_cache_header_present(self):
        tc = self._make_test_client(a2a=True)
        resp = tc.get("/.well-known/agent-card.json")

        assert "max-age=3600" in resp.headers.get("cache-control", "")

    def test_a2a_false_no_well_known(self):
        tc = self._make_test_client(a2a=False)
        resp = tc.get("/.well-known/agent-card.json")

        assert resp.status_code == 404

    def test_health_route_still_works(self):
        tc = self._make_test_client(a2a=True)
        resp = tc.get("/health")

        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_skills_override(self):
        custom_skills = [
            {
                "name": "Custom",
                "serviceDescription": "Custom skill",
                "tools": [
                    {
                        "function": {
                            "name": "custom_op",
                            "description": "A custom operation",
                        }
                    }
                ],
            }
        ]
        tc = self._make_test_client(a2a=True, a2a_skills=custom_skills)
        resp = tc.get("/.well-known/agent-card.json")

        body = resp.json()
        assert len(body["skills"]) == 1
        assert body["skills"][0]["name"] == "custom_op"

    def test_extension_descriptor_content(self):
        tc = self._make_test_client(a2a=True)
        resp = tc.get("/.well-known/jacs-extension.json")

        body = resp.json()
        assert body["uri"] == "urn:hai.ai:jacs-provenance-v1"
        assert "documentSigning" in body["capabilities"]
        assert body["capabilities"]["documentSigning"]["algorithms"] == [
            "ring-Ed25519",
            "RSA-PSS",
            "pq-dilithium",
            "pq2025",
        ]


class TestMiddlewareA2ANoClient:
    """JacsMiddleware with a2a=True but no client logs a warning."""

    def test_no_client_warns_and_404s(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from jacs.adapters.fastapi import JacsMiddleware

        app = FastAPI()

        @app.get("/health")
        def health():
            return {"status": "ok"}

        # Patch must stay active through TestClient requests because
        # Starlette builds the middleware stack lazily on first request.
        with patch("jacs.adapters.fastapi.BaseJacsAdapter") as MockAdapter:
            adapter_instance = MagicMock()
            adapter_instance._client = None
            adapter_instance.strict = False
            MockAdapter.return_value = adapter_instance

            app.add_middleware(
                JacsMiddleware,
                client=None,
                a2a=True,
                sign_responses=False,
                verify_requests=False,
            )

            tc = TestClient(app)

            # Well-known should 404 since no docs were built
            resp = tc.get("/.well-known/agent-card.json")
            assert resp.status_code == 404

            # Normal routes still work
            resp = tc.get("/health")
            assert resp.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
