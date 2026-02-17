"""Tests for jacs.adapters.fastapi — JacsMiddleware and @jacs_route."""

import json
from datetime import datetime, timedelta, timezone

import pytest

fastapi = pytest.importorskip("fastapi")
from starlette.testclient import TestClient  # noqa: E402

from jacs.adapters.fastapi import JacsMiddleware, jacs_route  # noqa: E402
from jacs.client import JacsClient  # noqa: E402


@pytest.fixture
def ephemeral_client():
    return JacsClient.ephemeral()


# ---------------------------------------------------------------------------
# Helpers — tiny FastAPI apps for testing
# ---------------------------------------------------------------------------


def _make_app(client, **middleware_kwargs):
    """Return a FastAPI app with JacsMiddleware attached."""
    app = fastapi.FastAPI()
    app.add_middleware(
        JacsMiddleware, client=client, **middleware_kwargs
    )

    @app.get("/json")
    def get_json():
        return {"status": "ok", "value": 42}

    @app.get("/text")
    def get_text():
        from starlette.responses import PlainTextResponse
        return PlainTextResponse("plain text body")

    @app.post("/echo")
    async def echo(request: fastapi.Request):
        body = await request.json()
        return body

    return app


# ---------------------------------------------------------------------------
# JacsMiddleware tests
# ---------------------------------------------------------------------------


class TestMiddlewareSignsResponses:
    """Middleware should sign outgoing JSON responses."""

    def test_json_response_is_signed(self, ephemeral_client):
        app = _make_app(ephemeral_client)
        client = TestClient(app)
        resp = client.get("/json")
        assert resp.status_code == 200
        data = resp.json()
        # A signed JACS envelope contains jacsSignature or jacsHash
        assert "jacsSignature" in data or "jacsHash" in data

    def test_signed_response_is_verifiable(self, ephemeral_client):
        app = _make_app(ephemeral_client)
        client = TestClient(app)
        resp = client.get("/json")
        data = resp.json()
        result = ephemeral_client.verify(json.dumps(data))
        assert result.valid


class TestMiddlewareVerifiesRequests:
    """Middleware should verify incoming signed POST bodies."""

    def test_signed_post_passes_verification(self, ephemeral_client):
        app = _make_app(ephemeral_client)
        client = TestClient(app)
        # Sign a payload, then POST it
        signed_doc = ephemeral_client.sign_message({"action": "test"})
        resp = client.post(
            "/echo",
            content=signed_doc.raw_json,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 200

    def test_unsigned_post_passes_in_permissive_mode(self, ephemeral_client):
        app = _make_app(ephemeral_client, strict=False)
        client = TestClient(app)
        resp = client.post(
            "/echo",
            json={"action": "unsigned"},
        )
        assert resp.status_code == 200


class TestMiddlewareStrict:
    """Strict mode should reject invalid signatures."""

    def test_invalid_signature_returns_401(self, ephemeral_client):
        app = _make_app(ephemeral_client, strict=True)
        client = TestClient(app)
        # Post a body that claims to be signed but isn't valid
        bad_body = json.dumps({
            "jacsSignature": {"signature": "INVALID"},
            "jacsDocument": {"action": "bad"},
        })
        resp = client.post(
            "/echo",
            content=bad_body,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 401


class TestMiddlewarePassthrough:
    """Middleware should pass through non-JSON responses untouched."""

    def test_plain_text_not_signed(self, ephemeral_client):
        app = _make_app(ephemeral_client)
        client = TestClient(app)
        resp = client.get("/text")
        assert resp.status_code == 200
        assert resp.text == "plain text body"


class TestMiddlewareSignResponsesDisabled:
    """sign_responses=False should skip signing."""

    def test_no_signing_when_disabled(self, ephemeral_client):
        app = _make_app(ephemeral_client, sign_responses=False)
        client = TestClient(app)
        resp = client.get("/json")
        assert resp.status_code == 200
        data = resp.json()
        # Should be the raw endpoint response, not a JACS envelope
        assert data == {"status": "ok", "value": 42}


class TestMiddlewareVerifyDisabled:
    """verify_requests=False should skip verification."""

    def test_no_verify_when_disabled(self, ephemeral_client):
        app = _make_app(ephemeral_client, verify_requests=False)
        client = TestClient(app)
        bad_body = json.dumps({
            "jacsSignature": {"signature": "INVALID"},
            "jacsDocument": {"action": "bad"},
        })
        # Should pass through without verification even though signature is bad
        resp = client.post(
            "/echo",
            content=bad_body,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 200


class TestMiddlewareAuthReplayProtection:
    """Replay protection for auth-style signed request flows."""

    def test_replay_rejected_when_enabled(self, ephemeral_client):
        app = _make_app(
            ephemeral_client,
            strict=True,
            auth_replay_protection=True,
            auth_max_age_seconds=60,
            auth_clock_skew_seconds=5,
        )
        client = TestClient(app)

        signed_doc = ephemeral_client.sign_message({"action": "replay-test"})
        headers = {"Content-Type": "application/json"}

        first = client.post("/echo", content=signed_doc.raw_json, headers=headers)
        assert first.status_code == 200

        second = client.post("/echo", content=signed_doc.raw_json, headers=headers)
        assert second.status_code == 401
        assert "replay" in second.text.lower()

    def test_replay_allowed_when_disabled(self, ephemeral_client):
        app = _make_app(
            ephemeral_client,
            strict=True,
            auth_replay_protection=False,
        )
        client = TestClient(app)

        signed_doc = ephemeral_client.sign_message({"action": "duplicate-ok"})
        headers = {"Content-Type": "application/json"}

        first = client.post("/echo", content=signed_doc.raw_json, headers=headers)
        second = client.post("/echo", content=signed_doc.raw_json, headers=headers)

        assert first.status_code == 200
        assert second.status_code == 200

    def test_future_timestamp_rejected_when_enabled(self, ephemeral_client):
        future_iso = (
            datetime.now(timezone.utc) + timedelta(seconds=60)
        ).isoformat().replace("+00:00", "Z")

        # Keep this as a middleware-path test by stubbing verify() to return
        # a successful cryptographic result with a future signature timestamp.
        ephemeral_client.verify = lambda _raw: {
            "valid": True,
            "data": {"action": "future"},
            "signerId": "agent-future",
            "timestamp": future_iso,
            "attachments": [],
            "errors": [],
        }

        app = _make_app(
            ephemeral_client,
            strict=True,
            auth_replay_protection=True,
            auth_max_age_seconds=60,
            auth_clock_skew_seconds=0,
        )
        client = TestClient(app)

        body = json.dumps(
            {
                "jacsId": "doc-future:1",
                "jacsSignature": {
                    "agentID": "agent-future",
                    "date": future_iso,
                    "signature": "future-signature",
                },
                "jacsDocument": {"action": "future"},
            }
        )
        headers = {"Content-Type": "application/json"}

        response = client.post("/echo", content=body, headers=headers)
        assert response.status_code == 401
        assert "future" in response.text.lower()


# ---------------------------------------------------------------------------
# @jacs_route decorator tests
# ---------------------------------------------------------------------------


class TestJacsRouteDecorator:
    """Per-endpoint @jacs_route decorator."""

    def test_decorator_signs_response(self, ephemeral_client):
        app = fastapi.FastAPI()

        @app.get("/signed")
        @jacs_route(client=ephemeral_client)
        def signed_endpoint():
            return {"result": "decorated"}

        client = TestClient(app)
        resp = client.get("/signed")
        assert resp.status_code == 200
        data = resp.json()
        assert "jacsSignature" in data or "jacsHash" in data

    def test_decorator_with_async_endpoint(self, ephemeral_client):
        app = fastapi.FastAPI()

        @app.get("/async-signed")
        @jacs_route(client=ephemeral_client)
        async def async_signed():
            return {"async": True}

        client = TestClient(app)
        resp = client.get("/async-signed")
        assert resp.status_code == 200
        data = resp.json()
        assert "jacsSignature" in data or "jacsHash" in data


# ---------------------------------------------------------------------------
# Dependency injection compatibility
# ---------------------------------------------------------------------------


class TestMiddlewareWithDependencyInjection:
    """Middleware works alongside FastAPI dependency injection."""

    def test_dependency_injection_still_works(self, ephemeral_client):
        app = fastapi.FastAPI()
        app.add_middleware(JacsMiddleware, client=ephemeral_client)

        def get_db():
            return {"db": "mock"}

        @app.get("/with-dep")
        def with_dep(db=fastapi.Depends(get_db)):
            return {"db_status": db["db"]}

        client = TestClient(app)
        resp = client.get("/with-dep")
        assert resp.status_code == 200
        data = resp.json()
        # Response should be signed AND contain our data
        assert "jacsSignature" in data or "jacsHash" in data
