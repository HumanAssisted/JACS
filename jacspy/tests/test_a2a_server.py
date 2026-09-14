"""
Tests for jacs.a2a_server — FastAPI A2A routes (Task #18 / [2.3.1]).

Verifies:
- jacs_a2a_routes() returns a router with all 6 identity-bound endpoints
- CORS headers are present on responses
- ?signed=true query param works on agent-card.json
- create_a2a_app() builds a complete FastAPI application
- serve_a2a() delegates to uvicorn.run
- Routes return correct content for each well-known document
"""

import json
from datetime import datetime, timezone

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
            "skills": [
                {
                    "id": "greet",
                    "name": "greet",
                    "description": "Greet a user",
                    "tags": ["jacs", "greeting"],
                }
            ],
        }
    client = MagicMock()
    client._agent = MagicMock()
    client._agent.get_agent_json.return_value = json.dumps(agent_data)
    compat_kid = "compat-kid"
    binding_hash = "binding-hash"
    native_documents = {
        "/.well-known/agent-card.json": {
            "name": agent_data.get("jacsName", "JACS Agent"),
            "description": agent_data.get("jacsDescription", ""),
            "version": agent_data.get("jacsVersion", "1"),
            "protocolVersions": ["0.4.0"],
            "supportedInterfaces": [
                {"url": "https://agent.example.com", "protocolBinding": "jsonrpc"}
            ],
            "skills": agent_data.get("skills", []),
            "metadata": {
                "jacsId": agent_data.get("jacsId"),
                "jacsVersion": agent_data.get("jacsVersion", "1"),
                "jacsCompatKid": compat_kid,
                "jacsCompatBindingHash": binding_hash,
                "jacsCompatBindingPath": "/.well-known/jacs-compat-binding.json",
            },
            "signatures": [{"keyId": compat_kid, "jws": "native-es256-jws"}],
        },
        "/.well-known/jwks.json": {
            "keys": [{"kid": compat_kid, "alg": "ES256", "use": "sig"}]
        },
        "/.well-known/jacs-compat-binding.json": {
            "jacsSha256": binding_hash,
            "compatibilityKeyBinding": {
                "issuedAt": datetime.now(timezone.utc).isoformat(),
                "expiresAt": None,
            },
        },
        "/.well-known/jacs-agent.json": {"agentId": agent_data.get("jacsId")},
        "/.well-known/jacs-pubkey.json": {"agentId": agent_data.get("jacsId")},
        "/.well-known/jacs-extension.json": {
            "uri": "urn:jacs:provenance-v1",
            "capabilities": {
                "documentSigning": {"algorithms": ["ring-Ed25519", "pq2025"]}
            },
        },
    }
    client._agent.generate_well_known_documents.return_value = json.dumps([
        {"path": path, "document": document}
        for path, document in native_documents.items()
    ])
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
        assert body["uri"] == "urn:jacs:provenance-v1"
        assert "documentSigning" in body["capabilities"]
        assert body["capabilities"]["documentSigning"]["algorithms"] == [
            "ring-Ed25519",
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
        """The legacy query parameter still returns the signed native card."""
        tc = self._get_test_client()
        resp = tc.get("/.well-known/agent-card.json?signed=true")

        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "Test A2A Bot"
        assert body["signatures"][0]["jws"] == "native-es256-jws"

    def test_skills_override(self):
        """Custom skills are used for the exported agent card."""
        custom_skills = [
            {
                "id": "do-custom",
                "name": "do_custom",
                "description": "Does custom stuff",
                "tags": ["jacs"],
            }
        ]
        agent_data = {
            "jacsId": "test-agent-1",
            "jacsName": "Test A2A Bot",
            "jacsDescription": "A test agent for A2A server",
            "jacsVersion": "v2.0",
            "jacsAgentType": "ai",
            "skills": custom_skills,
        }
        tc = self._get_test_client(
            client=_make_mock_client(agent_data),
            skills=custom_skills,
        )
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
            "/.well-known/jacs-compat-binding.json",
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
                "id": "my-skill",
                "name": "my_skill",
                "description": "My skill",
                "tags": ["jacs"],
            }
        ]
        client = _make_mock_client({
            "jacsId": "test-agent-1",
            "jacsName": "Test A2A Bot",
            "jacsDescription": "A test agent for A2A server",
            "jacsVersion": "v2.0",
            "jacsAgentType": "ai",
            "skills": custom_skills,
        })
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


# These controlled native-builder fixtures exercise mounted FastAPI handlers.
# They do not claim cryptographic native integration.
_DAY = 86400
_START = datetime(2026, 9, 14, tzinfo=timezone.utc).timestamp()
_BINDING = "/.well-known/jacs-compat-binding.json"
_CARD = "/.well-known/agent-card.json"


def _snapshot_pairs(generation, issued, expires=None):
    pairs = json.loads(
        _make_mock_client()._agent.generate_well_known_documents.return_value
    )
    documents = {pair["path"]: pair["document"] for pair in pairs}
    for document in documents.values():
        document["snapshot"] = generation
    binding = documents[_BINDING]
    binding["compatibilityKeyBinding"] = {
        "issuedAt": datetime.fromtimestamp(issued, timezone.utc).isoformat(),
        "expiresAt": (
            None
            if expires is None
            else datetime.fromtimestamp(expires, timezone.utc).isoformat()
        ),
    }
    binding["jacsSha256"] = f"binding-{generation}"
    documents[_CARD]["metadata"]["jacsCompatBindingHash"] = f"binding-{generation}"
    return pairs


@pytest.fixture
def discovery_clock(monkeypatch):
    from jacs import a2a_server

    now = [_START]
    # Mock wallclock only: threadpool, HTTP and lock scheduling remain real.
    monkeypatch.setattr(a2a_server.time, "time", lambda: now[0])
    return now


def _mount_lifecycle(now, initial=None, next_builder=None):
    client = _make_mock_client()
    generator = client._agent.generate_well_known_documents

    def build():
        if generator.call_count == 1:
            return json.dumps(
                initial if initial is not None else _snapshot_pairs(1, now[0])
            )
        return json.dumps(
            next_builder() if next_builder else _snapshot_pairs(2, now[0])
        )

    generator.side_effect = build
    tc = TestJacsA2ARoutes()._get_test_client(
        client, skills=json.loads(client._agent.get_agent_json.return_value)["skills"]
    )
    return tc, generator


class TestDiscoverySnapshotLifetime:

    def test_refreshes_all_six_at_six_days_and_avoids_ordinary_regeneration(
        self, discovery_clock
    ):
        now = discovery_clock
        tc, generator = _mount_lifecycle(now)
        original = tc.get(_CARD).json()
        now[0] += 6 * _DAY - 1
        cached_at = now[0]
        near_renewal = tc.get(_CARD)
        assert (
            near_renewal.headers["cache-control"]
            == "public, max-age=1, must-revalidate"
        )
        max_age = int(
            near_renewal.headers["cache-control"].split("max-age=")[1].split(",")[0]
        )
        assert cached_at + max_age <= _START + 6 * _DAY
        now[0] = _START + 6 * _DAY - 0.001
        before_renewal = tc.get(_CARD)
        assert before_renewal.json() == original
        assert before_renewal.headers["cache-control"] == "no-store"
        assert generator.call_count == 1
        now[0] = _START + 6 * _DAY
        renewed_binding = tc.get(_BINDING)
        assert (
            near_renewal.json()["metadata"]["jacsCompatBindingHash"]
            != renewed_binding.json()["jacsSha256"]
        )
        documents = {}
        for pair in _snapshot_pairs(0, now[0]):
            response = tc.get(pair["path"])
            documents[pair["path"]] = response.json()
            assert response.status_code == 200
            assert response.json()["snapshot"] == 2
            assert (
                response.headers["cache-control"]
                == "public, max-age=3600, must-revalidate"
            )
        assert (
            documents[_CARD]["metadata"]["jacsCompatBindingHash"]
            == documents[_BINDING]["jacsSha256"]
        )
        assert (
            documents[_CARD]["signatures"][0]["keyId"]
            == documents["/.well-known/jwks.json"]["keys"][0]["kid"]
        )
        assert generator.call_count == 2
        assert original["snapshot"] == 1

    def test_refreshes_after_more_than_seven_idle_days(self, discovery_clock):
        tc, generator = _mount_lifecycle(discovery_clock)
        discovery_clock[0] += 8 * _DAY
        assert tc.get(_CARD).json()["snapshot"] == 2
        assert generator.call_count == 2

    def test_uses_preexisting_issuance_not_mount_time(self, discovery_clock):
        tc, generator = _mount_lifecycle(
            discovery_clock, _snapshot_pairs(1, _START - 6 * _DAY + 1)
        )
        assert tc.get(_CARD).json()["snapshot"] == 1
        discovery_clock[0] += 1
        assert tc.get(_CARD).json()["snapshot"] == 2
        assert generator.call_count == 2

    def test_failure_retry_cache_deadline_refusal_and_recovery(
        self, discovery_clock, caplog
    ):
        def fail():
            raise RuntimeError("PRIVATE SIGNED PAYLOAD /private/key")

        now = discovery_clock
        initial = _snapshot_pairs(1, now[0])
        tc, generator = _mount_lifecycle(now, initial, next_builder=fail)
        now[0] = _START + 6 * _DAY
        for pair in initial:
            response = tc.get(pair["path"])
            assert response.status_code == 200
            assert response.json() == pair["document"]
            assert response.headers["cache-control"] == "no-store"
        assert generator.call_count == 2
        now[0] += 59
        tc.get(_CARD)
        assert generator.call_count == 2
        now[0] += 1
        tc.get(_CARD)
        assert generator.call_count == 3
        now[0] = _START + 7 * _DAY - 1.5
        assert tc.get(_CARD).headers["cache-control"] == "no-store"
        now[0] += 1
        assert tc.get(_CARD).headers["cache-control"] == "no-store"
        now[0] += 0.5
        response = tc.get(_CARD)
        assert response.status_code == 503
        assert response.json() == {"error": "A2A discovery unavailable"}
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["access-control-allow-origin"] == "*"
        calls = generator.call_count
        tc.get(_BINDING)
        assert generator.call_count == calls
        generator.side_effect = lambda: json.dumps(_snapshot_pairs(3, now[0]))
        now[0] += 60
        recovered = tc.get(_CARD)
        assert recovered.json()["snapshot"] == 3
        assert (
            recovered.headers["cache-control"]
            == "public, max-age=3600, must-revalidate"
        )
        assert (
            recovered.json()["metadata"]["jacsCompatBindingHash"]
            == tc.get(_BINDING).json()["jacsSha256"]
        )
        assert "PRIVATE" not in caplog.text
        assert "a2a_discovery_refresh_failed" in caplog.text

    def test_explicit_expiry_stops_without_regeneration(self, discovery_clock, caplog):
        now = discovery_clock
        tc, generator = _mount_lifecycle(now, _snapshot_pairs(1, _START, _START + 2.5))
        assert (
            tc.get(_CARD).headers["cache-control"]
            == "public, max-age=2, must-revalidate"
        )
        for delay in [0, 60, 8 * _DAY]:
            now[0] = _START + 2.5 + delay
            response = tc.get(_BINDING)
            assert response.status_code == 503
            assert response.headers["cache-control"] == "no-store"
        assert generator.call_count == 1
        assert caplog.text.count("a2a_discovery_expired") == 1

    @pytest.mark.parametrize(
        "damage",
        [
            "missing document",
            "mismatched binding",
            "bad date",
            "expiry extension",
            "skill override",
        ],
    )
    def test_invalid_replacement_cannot_partially_publish(
        self, discovery_clock, damage
    ):
        now = discovery_clock

        def damaged():
            pairs = _snapshot_pairs(2, now[0], _START + 10 * _DAY)
            binding = next(
                pair["document"] for pair in pairs if pair["path"] == _BINDING
            )
            if damage == "missing document":
                pairs.pop()
            if damage == "mismatched binding":
                binding["jacsSha256"] = "mismatch"
            if damage == "bad date":
                binding["compatibilityKeyBinding"]["issuedAt"] = "not a date"
            if damage == "expiry extension":
                binding["compatibilityKeyBinding"]["expiresAt"] = None
            if damage == "skill override":
                next(pair["document"] for pair in pairs if pair["path"] == _CARD)[
                    "skills"
                ] = [{"id": "unauthorized"}]
            return pairs

        tc, generator = _mount_lifecycle(
            now, _snapshot_pairs(1, _START, _START + 10 * _DAY), damaged
        )
        now[0] += 6 * _DAY
        for pair in _snapshot_pairs(0, now[0]):
            response = tc.get(pair["path"])
            assert response.status_code == 200
            assert response.json()["snapshot"] == 1
        assert generator.call_count == 2

    @pytest.mark.parametrize(
        "issued",
        [
            None,
            123,
            "",
            "2026-02-30T00:00:00Z",
            "2026-09-14",
            "2026-09-14T00:00:00",
            "2026-09-14T00:00:00+01:60",
        ],
    )
    def test_invalid_initial_issuance_fails_closed(self, discovery_clock, issued):
        pairs = _snapshot_pairs(1, _START)
        next(pair["document"] for pair in pairs if pair["path"] == _BINDING)[
            "compatibilityKeyBinding"
        ]["issuedAt"] = issued
        with pytest.raises(
            RuntimeError, match="Cannot build identity-bound A2A routes"
        ):
            _mount_lifecycle(discovery_clock, pairs)

    def test_future_skew_and_wallclock_rollback(self, discovery_clock):
        with pytest.raises(RuntimeError):
            _mount_lifecycle(discovery_clock, _snapshot_pairs(1, _START + 301))
        fractional = _snapshot_pairs(1, _START)
        binding = next(
            pair["document"] for pair in fractional if pair["path"] == _BINDING
        )
        binding["compatibilityKeyBinding"][
            "issuedAt"
        ] = "2026-09-14T00:05:00.000000001Z"
        with pytest.raises(RuntimeError):
            _mount_lifecycle(discovery_clock, fractional)
        tc, generator = _mount_lifecycle(
            discovery_clock, _snapshot_pairs(1, _START + 300)
        )
        assert tc.get(_CARD).status_code == 200
        generator.side_effect = RuntimeError("failed")
        discovery_clock[0] -= 1
        assert tc.get(_CARD).status_code == 503

    def test_concurrent_threadpool_requests_share_one_complete_refresh(
        self, discovery_clock, monkeypatch
    ):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier, Event
        from jacs.a2a_server import _DiscoveryCache

        entered, release = Event(), Event()
        arrived = Barrier(7)
        now = discovery_clock

        original_get = _DiscoveryCache.get

        def simultaneous_get(cache):
            # All six actual route handlers reach the cache in separate
            # threadpool workers before any is allowed to refresh.
            arrived.wait(timeout=5)
            return original_get(cache)

        monkeypatch.setattr(_DiscoveryCache, "get", simultaneous_get)

        def slow_builder():
            entered.set()
            assert release.wait(5), "refresh was not released"
            return _snapshot_pairs(2, now[0])

        tc, generator = _mount_lifecycle(now, next_builder=slow_builder)
        now[0] += 6 * _DAY
        paths = [pair["path"] for pair in _snapshot_pairs(0, now[0])]
        with tc, ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(tc.get, path) for path in paths]
            arrived.wait(timeout=5)
            assert entered.wait(5), "refresh never started"
            release.set()
            responses = [future.result(timeout=5) for future in futures]
        assert generator.call_count == 2
        assert all(response.status_code == 200 for response in responses)
        assert [response.json()["snapshot"] for response in responses] == [2] * 6

    def test_refresh_preserves_finite_expiry_and_rejects_malformed_expiry(
        self, discovery_clock
    ):
        now = discovery_clock
        expiry = _START + 6 * _DAY + 2.5
        tc, generator = _mount_lifecycle(
            now,
            _snapshot_pairs(1, _START, expiry),
            lambda: _snapshot_pairs(2, now[0], expiry),
        )
        now[0] += 6 * _DAY
        renewed = tc.get(_BINDING)
        assert (
            renewed.json()["compatibilityKeyBinding"]["expiresAt"]
            == datetime.fromtimestamp(expiry, timezone.utc).isoformat()
        )
        assert renewed.headers["cache-control"] == "public, max-age=2, must-revalidate"
        for expires in [False, 123, "bad", "2026-02-30T00:00:00Z"]:
            pairs = _snapshot_pairs(0, now[0])
            next(pair["document"] for pair in pairs if pair["path"] == _BINDING)[
                "compatibilityKeyBinding"
            ]["expiresAt"] = expires
            with pytest.raises(RuntimeError):
                _mount_lifecycle(now, pairs)
        now[0] = expiry
        assert tc.get(_CARD).status_code == 503
        assert generator.call_count == 2

    def test_rfc3339_instants_preserve_signed_timestamp_strings(self, discovery_clock):
        pairs = _snapshot_pairs(1, _START)
        binding = next(pair["document"] for pair in pairs if pair["path"] == _BINDING)[
            "compatibilityKeyBinding"
        ]
        binding["issuedAt"] = "2026-09-13T19:00:00-05:00"
        binding["expiresAt"] = "2026-09-14T02:00:02.999999999+02:00"
        tc, generator = _mount_lifecycle(discovery_clock, pairs)
        response = tc.get(_BINDING)
        assert response.json()["compatibilityKeyBinding"] == binding
        assert response.headers["cache-control"] == "public, max-age=2, must-revalidate"
        discovery_clock[0] += 3
        assert tc.get(_CARD).status_code == 503
        assert generator.call_count == 1

    def test_missing_issuance_fails_closed(self, discovery_clock):
        pairs = _snapshot_pairs(1, _START)
        binding = next(pair["document"] for pair in pairs if pair["path"] == _BINDING)
        del binding["compatibilityKeyBinding"]["issuedAt"]
        with pytest.raises(
            RuntimeError, match="Cannot build identity-bound A2A routes"
        ):
            _mount_lifecycle(discovery_clock, pairs)

    def test_slow_failure_rechecks_lifetime_and_delays_retry_from_completion(
        self, discovery_clock, caplog
    ):
        now = discovery_clock

        def fail_slowly():
            now[0] = _START + 7 * _DAY + 1
            raise RuntimeError("PRIVATE slow native failure")

        tc, generator = _mount_lifecycle(now, next_builder=fail_slowly)
        now[0] += 6 * _DAY
        response = tc.get(_CARD)
        assert response.status_code == 503
        assert response.headers["cache-control"] == "no-store"
        assert tc.get(_BINDING).status_code == 503
        assert generator.call_count == 2
        generator.side_effect = lambda: json.dumps(_snapshot_pairs(3, now[0]))
        now[0] += 60
        assert tc.get(_CARD).json()["snapshot"] == 3
        assert generator.call_count == 3
        assert "PRIVATE" not in caplog.text
